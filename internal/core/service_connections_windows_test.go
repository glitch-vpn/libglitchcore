//go:build service && windows

package core

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// fakeIdentities stands in for the token read: each server end of an
// in-memory pipe is registered with the caller it plays.
type fakeIdentities struct {
	callers sync.Map
}

func injectIdentities(t *testing.T) *fakeIdentities {
	t.Helper()
	identities := &fakeIdentities{}
	previousIdentify := identifyPipeClient
	identifyPipeClient = func(conn net.Conn) (pipeCaller, error) {
		caller, ok := identities.callers.Load(conn)
		if !ok {
			return pipeCaller{}, errors.New("unknown connection")
		}
		return caller.(pipeCaller), nil
	}
	t.Cleanup(func() { identifyPipeClient = previousIdentify })
	return identities
}

type commandPipeClient struct {
	conn    net.Conn
	replies *bufio.Scanner
	done    chan struct{}
}

func startCommandPipe(t *testing.T, access *pipeAccess, connections *pipeConnections, identities *fakeIdentities, caller pipeCaller) *commandPipeClient {
	t.Helper()
	Initialize()
	server, client := net.Pipe()
	identities.callers.Store(server, caller)
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer close(done)
		handleCommandConnection(ctx, server, access, connections)
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
	// The service may refuse before it reads, and an in-memory pipe has no
	// buffer to hold the ping meanwhile.
	go fmt.Fprintln(c.conn, `{"action":"ping"}`)
	return c.reply(t)
}

func (c *commandPipeClient) reply(t *testing.T) pipeResponse {
	t.Helper()
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

func newCommandPipeConnections() *pipeConnections {
	return newPipeConnections(maxCommandConnections, maxCommandConnectionsPerCaller)
}

func newEventPipeConnections() *pipeConnections {
	return newPipeConnections(maxEventConnections, maxEventConnectionsPerCaller)
}

func TestCommandPipeAnswersTheServedUser(t *testing.T) {
	servedUser := madeUpUserSID(t, "1001")
	client := startCommandPipe(t, servedAccess(t, servedUser), newCommandPipeConnections(), injectIdentities(t), pipeCaller{user: servedUser})
	if resp := client.ping(t); !resp.OK {
		t.Fatalf("ping refused: %s", resp.Error)
	}
}

func TestCommandPipeRefusesAnotherUser(t *testing.T) {
	access := servedAccess(t, madeUpUserSID(t, "1001"))
	client := startCommandPipe(t, access, newCommandPipeConnections(), injectIdentities(t), pipeCaller{user: madeUpUserSID(t, "1002")})
	if resp := client.ping(t); resp.OK || resp.Error != accessDeniedReply {
		t.Fatalf("got %+v, want access denied", resp)
	}
	client.waitClosed(t)
}

func TestCommandPipeRefusesEveryUserWhenNobodyIsServed(t *testing.T) {
	client := startCommandPipe(t, newPipeAccess(), newCommandPipeConnections(), injectIdentities(t), pipeCaller{user: madeUpUserSID(t, "1001")})
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
			access := servedAccess(t, madeUpUserSID(t, "1001"))
			client := startCommandPipe(t, access, newCommandPipeConnections(), injectIdentities(t), caller)
			if resp := client.ping(t); !resp.OK {
				t.Fatalf("ping refused: %s", resp.Error)
			}
		})
	}
}

func TestCommandPipeChecksEveryCommandAgainstTheUserServedNow(t *testing.T) {
	first := madeUpUserSID(t, "1001")
	access := servedAccess(t, first)
	client := startCommandPipe(t, access, newCommandPipeConnections(), injectIdentities(t), pipeCaller{user: first})
	if resp := client.ping(t); !resp.OK {
		t.Fatalf("ping refused: %s", resp.Error)
	}
	setServedUser(access, madeUpUserSID(t, "1002"))
	if resp := client.ping(t); resp.OK {
		t.Fatal("a command passed after the served user changed")
	}
}

// showTraffic turns on what a change of served user turns off.
func showTraffic(t *testing.T) {
	t.Helper()
	previousInspector := connInspectEnabled.Load()
	previousVerbosity := atomic.LoadInt32(&statusVerbosity)
	applyConnInspector(true)
	applyStatusVerbosity(2)
	t.Cleanup(func() {
		connInspectEnabled.Store(previousInspector)
		atomic.StoreInt32(&statusVerbosity, previousVerbosity)
	})
}

func servedService(t *testing.T, user *windows.SID) *glitchService {
	t.Helper()
	service := newGlitchService()
	setServedUser(service.access, user)
	return service
}

func TestServedUserChangeHidesTheTrafficAndClosesWhatIsNoLongerAdmitted(t *testing.T) {
	first := madeUpUserSID(t, "1001")
	administratorCaller := pipeCaller{user: madeUpUserSID(t, "500"), administrator: true}
	service := servedService(t, first)
	identities := injectIdentities(t)
	showTraffic(t)

	switchedAwayCommands := startCommandPipe(t, service.access, service.commandConnections, identities, pipeCaller{user: first})
	if resp := switchedAwayCommands.ping(t); !resp.OK {
		t.Fatalf("ping refused: %s", resp.Error)
	}
	administratorCommands := startCommandPipe(t, service.access, service.commandConnections, identities, administratorCaller)
	if resp := administratorCommands.ping(t); !resp.OK {
		t.Fatalf("ping refused: %s", resp.Error)
	}
	unidentifiedCommands := startCommandPipe(t, service.access, service.commandConnections, identities, pipeCaller{user: madeUpUserSID(t, "1002")})
	waitForOpenConnections(t, service.commandConnections, 3)

	switchedAwayEvents := startEventPipe(t, service.hub, service.access, service.eventConnections, identities, pipeCaller{user: first})
	switchedAwayEvents.subscribe(t)
	if !switchedAwayEvents.receives(t, service.hub) {
		t.Fatal("the served user received no event")
	}
	administratorEvents := startEventPipe(t, service.hub, service.access, service.eventConnections, identities, administratorCaller)
	administratorEvents.subscribe(t)
	if !administratorEvents.receives(t, service.hub) {
		t.Fatal("an administrator received no event")
	}

	service.access.changeServedUser(madeUpUserSID(t, "1002"), service.onServedUserChange)

	if connInspectEnabled.Load() {
		t.Error("the connection inspector stayed on")
	}
	if verbosity := atomic.LoadInt32(&statusVerbosity); verbosity != -1 {
		t.Errorf("logging stayed at level %d", verbosity)
	}
	switchedAwayCommands.waitClosed(t)
	unidentifiedCommands.waitClosed(t)
	switchedAwayEvents.waitClosed(t)
	if resp := administratorCommands.ping(t); !resp.OK {
		t.Fatalf("an administrator lost the command pipe: %s", resp.Error)
	}
	if !administratorEvents.receives(t, service.hub) {
		t.Fatal("an administrator lost the event pipe")
	}
}

func TestDroppedEventSubscriberThatNeverReadsLosesItsConnection(t *testing.T) {
	first := madeUpUserSID(t, "1001")
	service := servedService(t, first)
	client := startEventPipe(t, service.hub, service.access, service.eventConnections, injectIdentities(t), pipeCaller{user: first})
	client.subscribe(t)
	waitForSubscribers(t, service.hub, 1)
	for range 100 {
		service.hub.Publish("event")
	}

	service.access.changeServedUser(madeUpUserSID(t, "1002"), service.onServedUserChange)

	client.waitClosed(t)
	waitForSubscribers(t, service.hub, 0)
}

func waitForSubscribers(t *testing.T, hub *serviceEventHub, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		hub.mu.RLock()
		subscribed := len(hub.subscribers)
		hub.mu.RUnlock()
		if subscribed == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d subscribers, want %d", subscribed, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCommandPipeRefusesConnectionsPastTheTotal(t *testing.T) {
	servedUser := madeUpUserSID(t, "1001")
	access := servedAccess(t, servedUser)
	connections := newPipeConnections(2, maxCommandConnectionsPerCaller)
	identities := injectIdentities(t)
	for range 2 {
		client := startCommandPipe(t, access, connections, identities, pipeCaller{user: servedUser})
		if resp := client.ping(t); !resp.OK {
			t.Fatalf("ping refused: %s", resp.Error)
		}
	}
	startCommandPipe(t, access, connections, identities, pipeCaller{user: servedUser}).waitClosed(t)
}

func TestCommandPipeRefusesACallerPastItsShare(t *testing.T) {
	servedUser := madeUpUserSID(t, "1001")
	access := servedAccess(t, servedUser)
	connections := newPipeConnections(maxCommandConnections, 1)
	identities := injectIdentities(t)
	if resp := startCommandPipe(t, access, connections, identities, pipeCaller{user: servedUser}).ping(t); !resp.OK {
		t.Fatalf("ping refused: %s", resp.Error)
	}
	second := startCommandPipe(t, access, connections, identities, pipeCaller{user: servedUser})
	if resp := second.ping(t); resp.Error != tooManyConnectionsReply {
		t.Fatalf("got %+v, want the refusal for too many connections", resp)
	}
	second.waitClosed(t)
	administrator := pipeCaller{user: madeUpUserSID(t, "500"), administrator: true}
	if resp := startCommandPipe(t, access, connections, identities, administrator).ping(t); !resp.OK {
		t.Fatalf("another caller was refused with the first one's share: %s", resp.Error)
	}
}

func TestEventPipeRefusesACallerPastItsShare(t *testing.T) {
	servedUser := madeUpUserSID(t, "1001")
	hub := newServiceEventHub()
	access := servedAccess(t, servedUser)
	connections := newPipeConnections(maxEventConnections, 1)
	identities := injectIdentities(t)
	first := startEventPipe(t, hub, access, connections, identities, pipeCaller{user: servedUser})
	first.subscribe(t)
	if !first.receives(t, hub) {
		t.Fatal("the served user received no event")
	}
	second := startEventPipe(t, hub, access, connections, identities, pipeCaller{user: servedUser})
	second.subscribe(t)
	second.waitClosed(t)
}

func shortenFirstMessageTimeout(t *testing.T) {
	previousTimeout := firstMessageTimeout
	firstMessageTimeout = 50 * time.Millisecond
	t.Cleanup(func() { firstMessageTimeout = previousTimeout })
}

func limitCommandsTo64Bytes(t *testing.T) {
	previousLimit := maxCommandBytes
	maxCommandBytes = 64
	t.Cleanup(func() { maxCommandBytes = previousLimit })
}

func waitForOpenConnections(t *testing.T, connections *pipeConnections, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		connections.mu.Lock()
		open := len(connections.open)
		connections.mu.Unlock()
		if open == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d connections open, want %d", open, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCommandPipeClosesAConnectionSilentPastTheFirstMessageTimeout(t *testing.T) {
	shortenFirstMessageTimeout(t)

	client := startCommandPipe(t, newPipeAccess(), newCommandPipeConnections(), injectIdentities(t), pipeCaller{})
	client.waitClosed(t)
}

func TestCommandPipeRefusesACommandOverTheLimit(t *testing.T) {
	limitCommandsTo64Bytes(t)

	servedUser := madeUpUserSID(t, "1001")
	client := startCommandPipe(t, servedAccess(t, servedUser), newCommandPipeConnections(), injectIdentities(t), pipeCaller{user: servedUser})
	client.conn.SetDeadline(time.Now().Add(5 * time.Second))
	go fmt.Fprintf(client.conn, `{"action":"ping","payload":"%s"}`+"\n", strings.Repeat("x", 200))

	resp := client.reply(t)
	if resp.OK || !strings.Contains(resp.Error, "limited to 64 bytes") {
		t.Fatalf("got %+v, want the size refusal", resp)
	}
	client.waitClosed(t)
}

func TestCommandPipeRefusesAnotherUserBeforeReadingTheCommand(t *testing.T) {
	limitCommandsTo64Bytes(t)

	access := servedAccess(t, madeUpUserSID(t, "1001"))
	client := startCommandPipe(t, access, newCommandPipeConnections(), injectIdentities(t), pipeCaller{user: madeUpUserSID(t, "1002")})
	client.conn.SetDeadline(time.Now().Add(5 * time.Second))
	go fmt.Fprintf(client.conn, `{"action":"ping","payload":"%s"}`+"\n", strings.Repeat("x", 200))

	resp := client.reply(t)
	if resp.Error != accessDeniedReply {
		t.Fatalf("got %+v, want access denied before the size refusal", resp)
	}
	client.waitClosed(t)
}

type eventPipeClient struct {
	conn  net.Conn
	lines *bufio.Scanner
	done  chan struct{}
}

func startEventPipe(t *testing.T, hub *serviceEventHub, access *pipeAccess, connections *pipeConnections, identities *fakeIdentities, caller pipeCaller) *eventPipeClient {
	t.Helper()
	server, client := net.Pipe()
	identities.callers.Store(server, caller)
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer close(done)
		handleEventConnection(ctx, server, hub, access, connections)
	}()
	t.Cleanup(func() {
		cancel()
		client.Close()
		<-done
	})
	return &eventPipeClient{conn: client, lines: bufio.NewScanner(client), done: done}
}

func (c *eventPipeClient) waitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection stayed open")
	}
}

func (c *eventPipeClient) subscribe(t *testing.T) {
	t.Helper()
	c.conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.conn.Write([]byte{'\n'}); err != nil {
		t.Fatalf("send the first byte: %v", err)
	}
}

// receives publishes until the subscriber reads a line or loses the pipe.
func (c *eventPipeClient) receives(t *testing.T, hub *serviceEventHub) bool {
	t.Helper()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
				hub.Publish("event")
			}
		}
	}()
	return c.lines.Scan()
}

func TestEventPipeSubscribesTheServedUserAfterItsFirstByte(t *testing.T) {
	servedUser := madeUpUserSID(t, "1001")
	hub := newServiceEventHub()
	client := startEventPipe(t, hub, servedAccess(t, servedUser), newEventPipeConnections(), injectIdentities(t), pipeCaller{user: servedUser})
	client.subscribe(t)
	if !client.receives(t, hub) {
		t.Fatalf("the served user received no event: %v", client.lines.Err())
	}
}

func TestEventPipeRefusesAnotherUser(t *testing.T) {
	hub := newServiceEventHub()
	access := servedAccess(t, madeUpUserSID(t, "1001"))
	client := startEventPipe(t, hub, access, newEventPipeConnections(), injectIdentities(t), pipeCaller{user: madeUpUserSID(t, "1002")})
	client.subscribe(t)
	if client.receives(t, hub) {
		t.Fatal("another user received an event")
	}
}

func TestEventPipeClosesAConnectionSilentPastTheFirstMessageTimeout(t *testing.T) {
	shortenFirstMessageTimeout(t)

	client := startEventPipe(t, newServiceEventHub(), newPipeAccess(), newEventPipeConnections(), injectIdentities(t), pipeCaller{})
	client.waitClosed(t)
}
