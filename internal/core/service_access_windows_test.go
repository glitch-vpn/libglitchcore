//go:build service && windows

package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const fileCreatePipeInstance = 0x4

func madeUpUserSID(t *testing.T, rid string) *windows.SID {
	t.Helper()
	sid, err := windows.StringToSid("S-1-5-21-1111111111-2222222222-3333333333-" + rid)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

func TestServicePipeDescriptorAdmitsSystemAdministratorsAndTheServedUser(t *testing.T) {
	servedUser := madeUpUserSID(t, "1001")
	descriptor, err := windows.SecurityDescriptorFromString(servicePipeSDDL(servedUser))
	if err != nil {
		t.Fatal(err)
	}

	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("the DACL inherits entries")
	}

	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl.AceCount != 3 {
		t.Fatalf("the DACL has %d entries, want 3", dacl.AceCount)
	}
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	administrators, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	want := []struct {
		sid  *windows.SID
		mask windows.ACCESS_MASK
	}{
		{system, windows.GENERIC_ALL},
		{administrators, windows.GENERIC_ALL},
		{servedUser, pipeClientAccessMask},
	}
	for i, entry := range want {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Errorf("entry %d is of type %d, not an allow", i, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(entry.sid) {
			t.Errorf("entry %d names %s, want %s", i, sid, entry.sid)
		}
		if ace.Mask != entry.mask {
			t.Errorf("entry %d grants %#x, want %#x", i, ace.Mask, entry.mask)
		}
	}
	if pipeClientAccessMask&fileCreatePipeInstance != 0 {
		t.Error("the served user may create pipe instances")
	}
}

func TestServicePipeDescriptorWithNobodyServedAdmitsOnlySystemAndAdministrators(t *testing.T) {
	descriptor, err := windows.SecurityDescriptorFromString(servicePipeSDDL(nil))
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl.AceCount != 2 {
		t.Fatalf("the DACL has %d entries, want 2", dacl.AceCount)
	}
}

func setServedUser(access *pipeAccess, user *windows.SID) bool {
	return access.changeServedUser(user, func() {})
}

func servedAccess(t *testing.T, user *windows.SID) *pipeAccess {
	t.Helper()
	access := newPipeAccess()
	setServedUser(access, user)
	return access
}

func TestServedUserChangeSignalsOnlyOnAChange(t *testing.T) {
	access := servedAccess(t, madeUpUserSID(t, "1001"))
	_, changed := access.current()

	if setServedUser(access, madeUpUserSID(t, "1001")) {
		t.Error("the same user reported a change")
	}
	select {
	case <-changed:
		t.Fatal("the same user signalled a change")
	default:
	}

	if !setServedUser(access, nil) {
		t.Error("a logoff reported no change")
	}
	select {
	case <-changed:
	default:
		t.Fatal("a logoff did not signal a change")
	}
}

func shortenActiveUserRetries(t *testing.T) {
	t.Helper()
	previousRead, previousDelay, previousMaxDelay, previousGrace := readActiveUser, activeUserRetryDelay, activeUserMaxRetryDelay, activeUserReadGrace
	activeUserRetryDelay, activeUserMaxRetryDelay, activeUserReadGrace = time.Millisecond, 4*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() {
		readActiveUser, activeUserRetryDelay, activeUserMaxRetryDelay, activeUserReadGrace = previousRead, previousDelay, previousMaxDelay, previousGrace
	})
}

func TestServedUserIsKeptWhileTheActiveUserCannotBeRead(t *testing.T) {
	shortenActiveUserRetries(t)
	served := madeUpUserSID(t, "1001")
	next := madeUpUserSID(t, "1002")
	access := servedAccess(t, served)

	failures := 0
	readActiveUser = func() (*windows.SID, error) {
		if failures < 3 {
			failures++
			if user, _ := access.current(); !sameSID(user, served) {
				t.Errorf("the served user is %v during failed reads, want %s", user, served)
			}
			return nil, windows.ERROR_ACCESS_DENIED
		}
		return next, nil
	}
	hidden := 0
	access.refresh(context.Background(), func() {}, func() { hidden++ })
	if user, _ := access.current(); !sameSID(user, next) {
		t.Fatalf("the served user is %v once a read succeeded, want %s", user, next)
	}
	if hidden != 1 {
		t.Fatalf("the traffic was hidden %d times over three failed reads, want once", hidden)
	}
}

func TestNobodyIsServedOnceTheActiveUserStaysUnreadableForTheGrace(t *testing.T) {
	shortenActiveUserRetries(t)
	activeUserMaxRetryDelay = time.Minute
	access := servedAccess(t, madeUpUserSID(t, "1001"))

	readActiveUser = func() (*windows.SID, error) { return nil, windows.ERROR_ACCESS_DENIED }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changed := make(chan time.Time, 1)
	started := time.Now()
	go access.refresh(ctx, func() { changed <- time.Now() }, func() {})

	select {
	case at := <-changed:
		if user, _ := access.current(); user != nil {
			t.Fatalf("the served user is %v after the grace, want nobody", user)
		}
		if late := at.Sub(started) - activeUserReadGrace; late > time.Second {
			t.Fatalf("nobody was served %v after the grace ended", late)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the served user outlasted the grace")
	}
}

func TestActiveUserIsStillReadAfterFallingBackToNobody(t *testing.T) {
	shortenActiveUserRetries(t)
	next := madeUpUserSID(t, "1002")
	access := servedAccess(t, madeUpUserSID(t, "1001"))

	fellBack := make(chan struct{})
	readActiveUser = func() (*windows.SID, error) {
		select {
		case <-fellBack:
			return next, nil
		default:
			return nil, windows.ERROR_ACCESS_DENIED
		}
	}
	changes := 0
	access.refresh(context.Background(), func() {
		changes++
		if changes == 1 {
			close(fellBack)
		}
	}, func() {})
	if user, _ := access.current(); !sameSID(user, next) || changes != 2 {
		t.Fatalf("the served user is %v after %d changes, want %s after two", user, changes, next)
	}
}

func sessionUsers(t *testing.T, users map[uint32]*windows.SID, failures map[uint32]error) func(uint32) (*windows.SID, error) {
	t.Helper()
	return func(session uint32) (*windows.SID, error) {
		if err, ok := failures[session]; ok {
			return nil, err
		}
		if user, ok := users[session]; ok {
			return user, nil
		}
		return nil, windows.ERROR_NO_TOKEN
	}
}

func TestActiveUserSelection(t *testing.T) {
	consoleUser := madeUpUserSID(t, "1001")
	remoteUser := madeUpUserSID(t, "1002")
	otherRemoteUser := madeUpUserSID(t, "1003")
	const noConsole = 0xFFFFFFFF
	tests := []struct {
		name     string
		console  uint32
		sessions []sessionState
		users    map[uint32]*windows.SID
		failures map[uint32]error
		want     *windows.SID
		wantErr  bool
	}{
		{name: "the console user, whoever else is signed in", console: 1,
			sessions: []sessionState{{id: 1, active: true}, {id: 2, active: true}},
			users:    map[uint32]*windows.SID{1: consoleUser, 2: remoteUser}, want: consoleUser},
		{name: "the one active remote user when nobody is at the console", console: 1,
			sessions: []sessionState{{id: 1, active: true}, {id: 2, active: true}, {id: 3}},
			users:    map[uint32]*windows.SID{2: remoteUser, 3: otherRemoteUser}, want: remoteUser},
		{name: "the one active remote user when no session is at the console", console: noConsole,
			sessions: []sessionState{{id: 2, active: true}},
			users:    map[uint32]*windows.SID{2: remoteUser}, want: remoteUser},
		{name: "nobody when several remote users are active", console: 1,
			sessions: []sessionState{{id: 2, active: true}, {id: 3, active: true}},
			users:    map[uint32]*windows.SID{2: remoteUser, 3: otherRemoteUser}},
		{name: "nobody when nobody is signed in", console: 1,
			sessions: []sessionState{{id: 0}, {id: 1, active: true}}},
		{name: "a session that ended since the listing is skipped", console: 1,
			sessions: []sessionState{{id: 2, active: true}, {id: 3, active: true}},
			users:    map[uint32]*windows.SID{3: remoteUser},
			failures: map[uint32]error{2: windows.ERROR_CTX_WINSTATION_NOT_FOUND}, want: remoteUser},
		{name: "a failed read of the console session is an error", console: 1,
			failures: map[uint32]error{1: windows.ERROR_ACCESS_DENIED}, wantErr: true},
		{name: "a failed read of a remote session is an error", console: 1,
			sessions: []sessionState{{id: 2, active: true}},
			failures: map[uint32]error{2: windows.ERROR_ACCESS_DENIED}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			list := func() ([]sessionState, error) { return test.sessions, nil }
			got, err := selectActiveUser(test.console, list, sessionUsers(t, test.users, test.failures))
			if (err != nil) != test.wantErr {
				t.Fatalf("error %v, want an error: %v", err, test.wantErr)
			}
			if !sameSID(got, test.want) {
				t.Fatalf("selected %v, want %v", got, test.want)
			}
		})
	}
}

func TestChangeOfServedUserWaitsForTheCommandInFlight(t *testing.T) {
	first := madeUpUserSID(t, "1001")
	access := servedAccess(t, first)

	running := make(chan struct{})
	release := make(chan struct{})
	go access.runAdmitted(pipeCaller{user: first}, func() {
		close(running)
		<-release
	})
	<-running

	changed := make(chan struct{})
	go access.changeServedUser(madeUpUserSID(t, "1002"), func() { close(changed) })
	select {
	case <-changed:
		t.Fatal("the served user changed while a command of the previous one ran")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case <-changed:
	case <-time.After(5 * time.Second):
		t.Fatal("the change never ran")
	}
	if access.runAdmitted(pipeCaller{user: first}, func() { t.Error("a command of the previous user ran") }) {
		t.Error("the previous user is still admitted")
	}
}

var testPipeSequence atomic.Int32

func testPipeName() string {
	return fmt.Sprintf("%stest_%d_%d", servicePipePrefix, os.Getpid(), testPipeSequence.Add(1))
}

func currentProcessUser(t *testing.T) (*windows.SID, bool) {
	t.Helper()
	token := windows.GetCurrentProcessToken()
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	user, err := tokenUser.User.Sid.Copy()
	if err != nil {
		t.Fatal(err)
	}
	return user, token.IsElevated()
}

// createSingleInstancePipe opens one server instance under the given
// descriptor. A listener would open more instances on accept, and that takes
// FILE_CREATE_PIPE_INSTANCE, which the descriptor grants only to SYSTEM and
// administrators, while the test runs as an ordinary user.
func createSingleInstancePipe(t *testing.T, name, sddl string) windows.Handle {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	attributes := &windows.SecurityAttributes{SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(*attributes))
	name16, _ := windows.UTF16PtrFromString(name)
	pipe, err := windows.CreateNamedPipe(name16, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT, 1, 512, 512, 0, attributes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CloseHandle(pipe) })
	return pipe
}

type pipeHandleConn struct {
	net.Conn
	handle windows.Handle
}

func (c pipeHandleConn) Fd() uintptr { return uintptr(c.handle) }

func TestServedUserOpensThePipeAndIsReadAsTheCaller(t *testing.T) {
	user, elevated := currentProcessUser(t)
	name := testPipeName()
	server := createSingleInstancePipe(t, name, servicePipeSDDL(user))

	client, err := dialPipeAtIdentification(name, 2*time.Second)
	if err != nil {
		t.Fatalf("the served user cannot open the pipe: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}

	if err := windows.ConnectNamedPipe(server, nil); err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		t.Fatal(err)
	}
	var read uint32
	if err := windows.ReadFile(server, make([]byte, 1), &read, nil); err != nil {
		t.Fatal(err)
	}

	caller, err := pipeClientIdentity(pipeHandleConn{handle: server})
	if err != nil {
		t.Fatal(err)
	}
	if !caller.user.Equals(user) {
		t.Errorf("the caller reads as %s, want %s", caller.user, user)
	}
	if caller.administrator != elevated {
		t.Errorf("administrator = %v in a process elevated = %v", caller.administrator, elevated)
	}
}

func TestServicePipeShutsOutAUserItDoesNotServe(t *testing.T) {
	if _, elevated := currentProcessUser(t); elevated {
		t.Skip("an elevated process is admitted as an administrator")
	}
	name := testPipeName()
	createSingleInstancePipe(t, name, servicePipeSDDL(madeUpUserSID(t, "1001")))

	client, err := dialPipeAtIdentification(name, 2*time.Second)
	if err == nil {
		client.Close()
		t.Fatal("a user the pipe does not serve opened it")
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("dial failed with %v, want access denied", err)
	}
}

func TestDescriptorRewriteShutsOutAUserOnAPipeAlreadyListening(t *testing.T) {
	user, elevated := currentProcessUser(t)
	if elevated {
		t.Skip("an elevated process is admitted as an administrator")
	}
	name := testPipeName()
	listener, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;" + user.String() + ")"})
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

	if err := setPipeDescriptor(name, servicePipeSDDL(madeUpUserSID(t, "1001"))); err != nil {
		t.Fatal(err)
	}
	client, err := dialPipeAtIdentification(name, 2*time.Second)
	if err == nil {
		client.Close()
		t.Fatal("the user the pipe served before still opens it")
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("dial failed with %v, want access denied", err)
	}
}

func TestServicePipesAreOpenedUnderFreshNamesWhenANameIsTaken(t *testing.T) {
	taken := testPipeName()
	squatter, err := winio.ListenPipe(taken, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer squatter.Close()

	fresh := servicePipeNames{command: testPipeName(), event: testPipeName()}
	draws := []servicePipeNames{{command: taken, event: testPipeName()}, fresh}
	previousDraw := drawServicePipeNames
	drawServicePipeNames = func() (servicePipeNames, error) {
		names := draws[0]
		draws = draws[1:]
		return names, nil
	}
	t.Cleanup(func() { drawServicePipeNames = previousDraw })

	user, _ := currentProcessUser(t)
	access := servedAccess(t, user)
	command, event, err := openServicePipes(access)
	if err != nil {
		t.Fatal(err)
	}
	defer command.listener.Close()
	defer event.listener.Close()
	if command.name != fresh.command || event.name != fresh.event {
		t.Fatalf("listening on %s and %s, want the fresh %s and %s", command.name, event.name, fresh.command, fresh.event)
	}
}

func TestAnonymousCallerIsNotIdentified(t *testing.T) {
	user, _ := currentProcessUser(t)
	name := testPipeName()
	server := createSingleInstancePipe(t, name, servicePipeSDDL(user))

	client, err := winio.DialPipe(name, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := windows.ConnectNamedPipe(server, nil); err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		t.Fatal(err)
	}
	var read uint32
	if err := windows.ReadFile(server, make([]byte, 1), &read, nil); err != nil {
		t.Fatal(err)
	}

	if caller, err := pipeClientIdentity(pipeHandleConn{handle: server}); err == nil {
		t.Fatalf("an anonymous dial reads as %s", caller.user)
	}
}
