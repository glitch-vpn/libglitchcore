//go:build service && windows

package core

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
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

func startCommandPipe(t *testing.T, access *pipeAccess, connections *commandConnections, identities *fakeIdentities, caller pipeCaller) *commandPipeClient {
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

func TestCommandPipeAnswersTheServedUser(t *testing.T) {
	servedUser := madeUpUserSID(t, "1001")
	client := startCommandPipe(t, servedAccess(t, servedUser), newCommandConnections(), injectIdentities(t), pipeCaller{user: servedUser})
	if resp := client.ping(t); !resp.OK {
		t.Fatalf("ping refused: %s", resp.Error)
	}
}

func TestCommandPipeRefusesAnotherUser(t *testing.T) {
	access := servedAccess(t, madeUpUserSID(t, "1001"))
	client := startCommandPipe(t, access, newCommandConnections(), injectIdentities(t), pipeCaller{user: madeUpUserSID(t, "1002")})
	if resp := client.ping(t); resp.OK || resp.Error != accessDeniedReply {
		t.Fatalf("got %+v, want access denied", resp)
	}
	client.waitClosed(t)
}

func TestCommandPipeRefusesEveryUserWhenNobodyIsServed(t *testing.T) {
	client := startCommandPipe(t, newPipeAccess(), newCommandConnections(), injectIdentities(t), pipeCaller{user: madeUpUserSID(t, "1001")})
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
			client := startCommandPipe(t, access, newCommandConnections(), injectIdentities(t), caller)
			if resp := client.ping(t); !resp.OK {
				t.Fatalf("ping refused: %s", resp.Error)
			}
		})
	}
}

func TestCommandPipeChecksEveryCommandAgainstTheUserServedNow(t *testing.T) {
	first := madeUpUserSID(t, "1001")
	access := servedAccess(t, first)
	client := startCommandPipe(t, access, newCommandConnections(), injectIdentities(t), pipeCaller{user: first})
	if resp := client.ping(t); !resp.OK {
		t.Fatalf("ping refused: %s", resp.Error)
	}
	setServedUser(access, madeUpUserSID(t, "1002"))
	if resp := client.ping(t); resp.OK {
		t.Fatal("a command passed after the served user changed")
	}
}

func TestServedUserChangeClosesCommandConnectionsNoLongerAdmitted(t *testing.T) {
	first := madeUpUserSID(t, "1001")
	access := servedAccess(t, first)
	connections := newCommandConnections()
	identities := injectIdentities(t)

	switchedAwayClient := startCommandPipe(t, access, connections, identities, pipeCaller{user: first})
	if resp := switchedAwayClient.ping(t); !resp.OK {
		t.Fatalf("ping refused: %s", resp.Error)
	}
	administrator := startCommandPipe(t, access, connections, identities, pipeCaller{user: madeUpUserSID(t, "500"), administrator: true})
	if resp := administrator.ping(t); !resp.OK {
		t.Fatalf("ping refused: %s", resp.Error)
	}
	unidentified := startCommandPipe(t, access, connections, identities, pipeCaller{user: madeUpUserSID(t, "1002")})
	waitForOpenConnections(t, connections, 3)

	setServedUser(access, madeUpUserSID(t, "1002"))
	connections.closeNotAdmitted(access.admits)

	switchedAwayClient.waitClosed(t)
	unidentified.waitClosed(t)
	if resp := administrator.ping(t); !resp.OK {
		t.Fatalf("an administrator lost the pipe: %s", resp.Error)
	}
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

func waitForOpenConnections(t *testing.T, connections *commandConnections, want int) {
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

	client := startCommandPipe(t, newPipeAccess(), newCommandConnections(), injectIdentities(t), pipeCaller{})
	client.waitClosed(t)
}

func TestCommandPipeRefusesACommandOverTheLimit(t *testing.T) {
	limitCommandsTo64Bytes(t)

	servedUser := madeUpUserSID(t, "1001")
	client := startCommandPipe(t, servedAccess(t, servedUser), newCommandConnections(), injectIdentities(t), pipeCaller{user: servedUser})
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
	client := startCommandPipe(t, access, newCommandConnections(), injectIdentities(t), pipeCaller{user: madeUpUserSID(t, "1002")})
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

func startEventPipe(t *testing.T, hub *serviceEventHub, access *pipeAccess, identities *fakeIdentities, caller pipeCaller) *eventPipeClient {
	t.Helper()
	server, client := net.Pipe()
	identities.callers.Store(server, caller)
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer close(done)
		handleEventConnection(ctx, server, hub, access)
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
	client := startEventPipe(t, hub, servedAccess(t, servedUser), injectIdentities(t), pipeCaller{user: servedUser})
	client.subscribe(t)
	if !client.receives(t, hub) {
		t.Fatalf("the served user received no event: %v", client.lines.Err())
	}
}

func TestEventPipeRefusesAnotherUser(t *testing.T) {
	hub := newServiceEventHub()
	access := servedAccess(t, madeUpUserSID(t, "1001"))
	client := startEventPipe(t, hub, access, injectIdentities(t), pipeCaller{user: madeUpUserSID(t, "1002")})
	client.subscribe(t)
	if client.receives(t, hub) {
		t.Fatal("another user received an event")
	}
}

func TestEventPipeClosesAConnectionSilentPastTheFirstMessageTimeout(t *testing.T) {
	shortenFirstMessageTimeout(t)

	client := startEventPipe(t, newServiceEventHub(), newPipeAccess(), injectIdentities(t), pipeCaller{})
	client.waitClosed(t)
}

func TestServedUserChangeDropsOnlyEventSubscribersNoLongerAdmitted(t *testing.T) {
	first := madeUpUserSID(t, "1001")
	hub := newServiceEventHub()
	access := servedAccess(t, first)
	identities := injectIdentities(t)

	switchedAwayClient := startEventPipe(t, hub, access, identities, pipeCaller{user: first})
	switchedAwayClient.subscribe(t)
	if !switchedAwayClient.receives(t, hub) {
		t.Fatal("the served user received no event")
	}
	administrator := startEventPipe(t, hub, access, identities, pipeCaller{user: madeUpUserSID(t, "500"), administrator: true})
	administrator.subscribe(t)
	if !administrator.receives(t, hub) {
		t.Fatal("an administrator received no event")
	}

	setServedUser(access, madeUpUserSID(t, "1002"))
	hub.dropSubscribersNotAdmitted(access.admits)

	for switchedAwayClient.lines.Scan() {
		// Events queued before the drop may still arrive.
	}
	if err := switchedAwayClient.lines.Err(); errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("the previous user stayed subscribed")
	} else if err != nil && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("the previous user's pipe failed with %v", err)
	}
	if !administrator.receives(t, hub) {
		t.Fatal("an administrator lost the event pipe")
	}
}
