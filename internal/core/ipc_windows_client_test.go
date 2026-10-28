//go:build windows && !service

package core

import (
	"errors"
	"fmt"
	"os"
	"strings"
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
	if !errors.Is(err, errServicePipeNotOwned) {
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
	previousProcessID := serviceProcessID
	t.Cleanup(func() { serviceProcessID = previousProcessID })

	for servicePID, want := range map[uint32]error{uint32(os.Getpid()): nil, uint32(os.Getpid()) + 4: errServicePipeNotOwned} {
		serviceProcessID = func() (uint32, error) { return servicePID, nil }
		conn, err := dialPipeAtIdentification(name, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if got := verifyServicePipeServer(conn); !errors.Is(got, want) {
			t.Errorf("with the service as process %d: %v, want %v", servicePID, got, want)
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
	if err != nil && !errors.Is(err, errServicePipesNotPublished) {
		t.Fatal(err)
	}
}
