//go:build service && windows

package core

import (
	"bufio"
	"context"
	"encoding/json"
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

type commandPipeClient struct {
	conn    net.Conn
	replies *bufio.Scanner
	done    chan struct{}
}

func startCommandPipe(t *testing.T, access *pipeAccess, caller pipeCaller) *commandPipeClient {
	t.Helper()
	Initialize()
	previousIdentify := identifyPipeClient
	identifyPipeClient = func(net.Conn) (pipeCaller, error) { return caller, nil }
	t.Cleanup(func() { identifyPipeClient = previousIdentify })
	server, client := net.Pipe()
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer close(done)
		handleCommandConnection(ctx, server, access)
	}()
	t.Cleanup(func() {
		cancel()
		client.Close()
		<-done
	})
	return &commandPipeClient{conn: client, replies: bufio.NewScanner(client), done: done}
}

func (c *commandPipeClient) ping(t *testing.T) pipeResponse {
	t.Helper()
	c.conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintln(c.conn, `{"action":"ping"}`); err != nil {
		t.Fatalf("send ping: %v", err)
	}
	if !c.replies.Scan() {
		t.Fatalf("no reply: %v", c.replies.Err())
	}
	var resp pipeResponse
	if err := json.Unmarshal(c.replies.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func (c *commandPipeClient) waitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection stayed open")
	}
}

func TestCommandPipeAnswersTheServedUser(t *testing.T) {
	servedUser := madeUpUserSID(t, "1001")
	access := newPipeAccess()
	access.setServedUser(servedUser)

	client := startCommandPipe(t, access, pipeCaller{user: servedUser})
	if resp := client.ping(t); !resp.OK {
		t.Fatalf("ping refused: %s", resp.Error)
	}
}

func TestCommandPipeRefusesAnotherUser(t *testing.T) {
	access := newPipeAccess()
	access.setServedUser(madeUpUserSID(t, "1001"))

	client := startCommandPipe(t, access, pipeCaller{user: madeUpUserSID(t, "1002")})
	if resp := client.ping(t); resp.OK || resp.Error != accessDeniedReply {
		t.Fatalf("got %+v, want access denied", resp)
	}
	client.waitClosed(t)
}

func TestCommandPipeRefusesEveryUserWhenNobodyIsServed(t *testing.T) {
	client := startCommandPipe(t, newPipeAccess(), pipeCaller{user: madeUpUserSID(t, "1001")})
	if resp := client.ping(t); resp.OK {
		t.Fatal("a command passed with nobody served")
	}
}

func TestCommandPipeAnswersSystemAndAdministrators(t *testing.T) {
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	for name, caller := range map[string]pipeCaller{
		"system":        {user: system},
		"administrator": {user: madeUpUserSID(t, "500"), administrator: true},
	} {
		t.Run(name, func(t *testing.T) {
			access := newPipeAccess()
			access.setServedUser(madeUpUserSID(t, "1001"))
			client := startCommandPipe(t, access, caller)
			if resp := client.ping(t); !resp.OK {
				t.Fatalf("ping refused: %s", resp.Error)
			}
		})
	}
}

func TestCommandPipeChecksEveryCommandAgainstTheUserServedNow(t *testing.T) {
	first := madeUpUserSID(t, "1001")
	access := newPipeAccess()
	access.setServedUser(first)

	client := startCommandPipe(t, access, pipeCaller{user: first})
	if resp := client.ping(t); !resp.OK {
		t.Fatalf("ping refused: %s", resp.Error)
	}
	access.setServedUser(madeUpUserSID(t, "1002"))
	if resp := client.ping(t); resp.OK {
		t.Fatal("a command passed after the served user changed")
	}
}

func TestServedUserChangeSignalsOnlyOnAChange(t *testing.T) {
	access := newPipeAccess()
	access.setServedUser(madeUpUserSID(t, "1001"))
	_, changed := access.current()

	if access.setServedUser(madeUpUserSID(t, "1001")) {
		t.Error("the same user reported a change")
	}
	select {
	case <-changed:
		t.Fatal("the same user signalled a change")
	default:
	}

	if !access.setServedUser(nil) {
		t.Error("a logoff reported no change")
	}
	select {
	case <-changed:
	default:
		t.Fatal("a logoff did not signal a change")
	}
}

var testPipeSequence atomic.Int32

func testPipeName() string {
	return fmt.Sprintf(`\\.\pipe\glitch_vpn_core_test_%d_%d`, os.Getpid(), testPipeSequence.Add(1))
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

func TestDroppedEventSubscribersAreDisconnected(t *testing.T) {
	hub := newServiceEventHub()
	server, client := net.Pipe()
	defer client.Close()
	hub.Subscribe(context.Background(), server)

	hub.dropSubscribers()
	hub.Publish("after the drop")

	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := client.Read(make([]byte, 64)); err == nil {
		t.Fatalf("a dropped subscriber read %d bytes", n)
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("a dropped subscriber stayed connected")
	}
}
