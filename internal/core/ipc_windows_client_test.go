//go:build windows && !service

package core

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// publishTestPipeName points the client at a key of the test's own under
// HKEY_CURRENT_USER holding pipeName, or holding nothing when it is empty.
func publishTestPipeName(t *testing.T, pipeName string) {
	t.Helper()
	// The same test key as service_registry_windows_test.go, which builds only
	// with the service tag.
	location := registryLocation{root: registry.CURRENT_USER, path: fmt.Sprintf(`Software\glitch_vpn_core_test_%d`, os.Getpid())}
	key, _, err := registry.CreateKey(location.root, location.path, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	if pipeName != "" {
		if err := key.SetStringValue(commandPipeValueName, pipeName); err != nil {
			t.Fatal(err)
		}
	}
	previousLocation := servicePipesLocation
	servicePipesLocation = location
	t.Cleanup(func() {
		servicePipesLocation = previousLocation
		registry.DeleteKey(location.root, location.path)
	})
}

func TestServiceDialRefusesAPipeAnOrdinaryAccountOwns(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("a pipe an elevated process creates belongs to the Administrators group")
	}
	name := fmt.Sprintf(`%sowner_test_%d`, servicePipePrefix, os.Getpid())
	listener, err := winio.ListenPipe(name, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		if conn, err := listener.Accept(); err == nil {
			conn.Close()
		}
	}()
	publishTestPipeName(t, name)

	conn, err := dialService(commandPipeValueName, 2*time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("dialled a pipe the service does not own")
	}
	if !errors.Is(err, errNotTheServicePipe) {
		t.Fatalf("dial failed with %v, want an owner refusal", err)
	}
}

func TestServiceDialReportsAServiceThatPublishedNoPipes(t *testing.T) {
	publishTestPipeName(t, "")

	_, err := dialService(commandPipeValueName, 2*time.Second)
	if !errors.Is(err, errServicePipesNotPublished) {
		t.Fatalf("dial failed with %v, want the not-published error", err)
	}
}

func TestServiceDialRefusesAPublishedNameOutsideTheServicePipes(t *testing.T) {
	publishTestPipeName(t, `\\elsewhere\pipe\glitch_vpn_core_cmd`)

	_, err := dialService(commandPipeValueName, 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "not a local pipe of its own") {
		t.Fatalf("dial failed with %v, want a refusal of the name", err)
	}
}

func TestServicePipeOwnerIsLocalSystemOrTheAdministrators(t *testing.T) {
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	administrators, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	user, err := windows.StringToSid("S-1-5-21-1111111111-2222222222-3333333333-1001")
	if err != nil {
		t.Fatal(err)
	}
	for owner, want := range map[*windows.SID]bool{system: true, administrators: true, user: false} {
		if got := ownedByTheService(owner); got != want {
			t.Errorf("a pipe owned by %s passes as the service's: %v, want %v", owner, got, want)
		}
	}
}

func TestServiceDialChecksThePipeIsServedByTheServiceProcess(t *testing.T) {
	name := fmt.Sprintf(`%sserver_test_%d`, servicePipePrefix, os.Getpid())
	listener, err := winio.ListenPipe(name, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	previousProcessID := lookUpServiceProcessID
	t.Cleanup(func() { lookUpServiceProcessID = previousProcessID })

	for serviceProcessID, want := range map[uint32]error{uint32(os.Getpid()): nil, uint32(os.Getpid()) + 4: errNotTheServicePipe} {
		lookUpServiceProcessID = func() (uint32, error) { return serviceProcessID, nil }
		conn, err := dialPipeAtIdentification(name, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if got := verifyServicePipeServer(conn); !errors.Is(got, want) {
			t.Errorf("with the service as process %d: %v, want %v", serviceProcessID, got, want)
		}
		conn.Close()
	}
}

// Reads the installed service's state, which needs no more than a standard
// account holds; skipped where no service is installed.
func TestServiceProcessIDIsReadableWithQueryStatusAccess(t *testing.T) {
	_, err := runningServiceProcessID()
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		t.Skip("no service installed")
	}
	if err != nil && !errors.Is(err, errServiceNotRunning) {
		t.Fatal(err)
	}
}

// A subscription to the service's events says ServiceReattached once when it
// follows an earlier one, and says nothing the first time or when a dial fails.
func TestServiceEventLoopSaysReattachedOncePerResubscription(t *testing.T) {
	replaceController(t, &CoreController{})

	var mu sync.Mutex
	var reattached []string
	setStatusSink(func(code int32, message string) {
		if code == ServiceReattached {
			mu.Lock()
			reattached = append(reattached, message)
			mu.Unlock()
		}
	})
	t.Cleanup(func() { setStatusSink(nil) })
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(reattached)
	}

	// Each dial answers with a service that takes the subscription and hangs up.
	quit := make(chan struct{})
	var seen []int
	dials := 0
	dial := func() (net.Conn, error) {
		dials++
		// A subscription is announced before the next dial; wait for it to land.
		want := []int{0, 0, 0, 1, 2}[dials-1]
		for deadline := time.Now().Add(2 * time.Second); count() < want && time.Now().Before(deadline); {
			time.Sleep(time.Millisecond)
		}
		seen = append(seen, count())
		switch dials {
		case 2:
			return nil, errors.New("the service is not up")
		case 5:
			close(quit)
			return nil, errors.New("end of the test")
		}
		client, server := net.Pipe()
		go func() {
			_, _ = server.Read(make([]byte, 1))
			_ = server.Close()
		}()
		return client, nil
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		runServiceEventLoop(dial, time.Millisecond, quit)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the loop did not end")
	}

	// Before dial 1 none; before dial 2 the first subscription had said nothing;
	// dial 2 failed; dial 3's subscription follows an earlier one and says it
	// once; so does dial 4's.
	if want := []int{0, 0, 0, 1, 2}; fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Errorf("announcements before each dial = %v, want %v", seen, want)
	}
	if fmt.Sprint(reattached) != "[[service] Reattached [service] Reattached]" {
		t.Errorf("messages = %q", reattached)
	}
}
