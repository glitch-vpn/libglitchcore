//go:build service && windows

package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

const pipeBufferSizeBytes = 64 * 1024

// maxCommandBytes bounds one command line. The largest real command is an
// engine_start whose request carries the app's config and routing, each under
// the app's 8 MiB payload cap, as a JSON string nested in JSON, where escaping
// can nearly double it.
var maxCommandBytes int64 = 32 << 20

// firstMessageTimeout is how long a connection may stay silent before its
// caller is known.
var firstMessageTimeout = 10 * time.Second

type serviceEventHub struct {
	mu          sync.RWMutex
	nextID      int
	subscribers map[int]eventSubscriber
}

type eventSubscriber struct {
	messages chan string
	caller   pipeCaller
}

func newServiceEventHub() *serviceEventHub {
	return &serviceEventHub{
		subscribers: make(map[int]eventSubscriber),
	}
}

func (h *serviceEventHub) addSubscriber(caller pipeCaller) (int, chan string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := h.nextID
	h.nextID++
	messages := make(chan string, 64)
	h.subscribers[id] = eventSubscriber{messages: messages, caller: caller}
	return id, messages
}

func (h *serviceEventHub) removeSubscriber(id int) {
	h.mu.Lock()
	subscriber, ok := h.subscribers[id]
	if ok {
		delete(h.subscribers, id)
	}
	h.mu.Unlock()
	if ok {
		close(subscriber.messages)
	}
}

// dropSubscribersNotAdmitted runs within a change of served user, under its
// write lock, with admits reading that state without locking it again.
func (h *serviceEventHub) dropSubscribersNotAdmitted(admits func(pipeCaller) bool) {
	var dropped []chan string
	h.mu.Lock()
	for id, subscriber := range h.subscribers {
		if !admits(subscriber.caller) {
			delete(h.subscribers, id)
			dropped = append(dropped, subscriber.messages)
		}
	}
	h.mu.Unlock()
	for _, messages := range dropped {
		close(messages)
	}
}

func (h *serviceEventHub) Publish(msg string) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, subscriber := range h.subscribers {
		select {
		case subscriber.messages <- msg:
		default:
		}
	}
}

func (h *serviceEventHub) Subscribe(ctx context.Context, conn net.Conn, caller pipeCaller) {
	id, messages := h.addSubscriber(caller)
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	go func() {
		defer func() {
			h.removeSubscriber(id)
			conn.Close()
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-messages:
				if !ok {
					return
				}
				if _, err := io.WriteString(conn, msg+"\n"); err != nil {
					return
				}
			}
		}
	}()
}

type serviceStatusEvent struct {
	Type      string `json:"type"`
	Code      int32  `json:"code"`
	Message   string `json:"message"`
	Timestamp string `json:"ts"`
}

type pipeCommand struct {
	Action  string          `json:"action"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type pipeResponse struct {
	OK    bool        `json:"ok"`
	Error string      `json:"error,omitempty"`
	Data  interface{} `json:"data,omitempty"`
}

type glitchService struct {
	hub         *serviceEventHub
	access      *pipeAccess
	connections *commandConnections
}

func runServiceMain() {
	svc := &glitchService{hub: newServiceEventHub(), access: newPipeAccess(), connections: newCommandConnections()}
	if err := svc.Run(); err != nil {
		log.Fatalf("glitch service run failed: %v", err)
	}
}

func (s *glitchService) Run() error {
	return svc.Run(serviceName, s)
}

func (s *glitchService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	Initialize()
	setStatusSink(func(code int32, message string) {
		evt := serviceStatusEvent{
			Type:      "status",
			Code:      code,
			Message:   message,
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		}
		if b, err := json.Marshal(evt); err == nil {
			s.hub.Publish(string(b))
		}
	})

	// One read only: retries wait for the Running status, which the service
	// manager expects soon.
	if user, err := readActiveUser(); err == nil {
		s.access.changeServedUser(user, s.onServedUserChange)
	}
	commandPipe, eventPipe, err := openServicePipes(s.access)
	if err != nil {
		logfmt.Errorf("[service] cannot open the pipes: %v", err)
		return true, 1
	}
	go func() {
		<-ctx.Done()
		commandPipe.listener.Close()
		eventPipe.listener.Close()
	}()
	go followServedUser(ctx, commandPipe, s.access)
	go followServedUser(ctx, eventPipe, s.access)
	go serveCommandPipe(ctx, commandPipe.listener, s.access, s.connections)
	go serveEventPipe(ctx, eventPipe.listener, s.hub, s.access)
	if err := publishServicePipes(servicePipesLocation, servicePipeNames{command: commandPipe.name, event: eventPipe.name}); err != nil {
		logfmt.Errorf("[service] cannot publish the pipe names: %v", err)
	}
	defer func() {
		if err := withdrawServicePipes(servicePipesLocation); err != nil {
			logfmt.Errorf("[service] cannot withdraw the pipe names: %v", err)
		}
	}()

	// A change of served user waits for the commands in flight, and a failed
	// read of the active user is retried, so both run apart from the loop that
	// answers the service manager.
	refreshes := make(chan struct{}, 1)
	refreshDone := make(chan struct{})
	defer func() {
		cancel()
		<-refreshDone
	}()
	go func() {
		defer close(refreshDone)
		for {
			select {
			case <-ctx.Done():
				return
			case <-refreshes:
				s.access.refresh(ctx, s.onServedUserChange)
			}
		}
	}()
	requestRefresh := func() {
		select {
		case refreshes <- struct{}{}:
		default:
		}
	}

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptSessionChange}
	// A logon before session changes were accepted sends no notice.
	requestRefresh()

	for {
		select {
		case <-ctx.Done():
			return
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				return
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.SessionChange:
				requestRefresh()
			default:
			}
		}
	}
}

// onServedUserChange runs under the write lock of the change. The tunnel
// outlives a switch of users; what shows its traffic does not, and neither do
// the connections of a caller no longer admitted.
func (s *glitchService) onServedUserChange() {
	applyConnInspector(false)
	applyStatusVerbosity(-1)
	s.connections.closeNotAdmitted(s.access.admitsLocked)
	s.hub.dropSubscribersNotAdmitted(s.access.admitsLocked)
}

func servicePipeConfig(servedUser *windows.SID, messageMode bool) *winio.PipeConfig {
	return &winio.PipeConfig{
		SecurityDescriptor: servicePipeSDDL(servedUser),
		MessageMode:        messageMode,
		InputBufferSize:    pipeBufferSizeBytes,
		OutputBufferSize:   pipeBufferSizeBytes,
	}
}

// servicePipe is held for the service's whole life: a listener closed even for
// a moment frees its name for any account to take.
type servicePipe struct {
	name     string
	listener net.Listener
	changed  <-chan struct{} // of the served user the descriptor was made for
}

func listenServicePipe(name string, access *pipeAccess, messageMode bool) (servicePipe, error) {
	servedUser, changed := access.current()
	listener, err := winio.ListenPipe(name, servicePipeConfig(servedUser, messageMode))
	if err != nil {
		return servicePipe{}, err
	}
	return servicePipe{name: name, listener: listener, changed: changed}, nil
}

const servicePipeOpenAttempts = 5

var drawServicePipeNames = newServicePipeNames

// openServicePipes listens under fresh names, and draws new ones when a name
// is taken: anyone may create a pipe under a name nobody holds, and the names
// are published only once both are held.
func openServicePipes(access *pipeAccess) (command, event servicePipe, err error) {
	for attempt := 0; attempt < servicePipeOpenAttempts; attempt++ {
		var names servicePipeNames
		if names, err = drawServicePipeNames(); err != nil {
			return
		}
		if command, err = listenServicePipe(names.command, access, true); err != nil {
			logfmt.Warnf("[service] %s listen error: %v", names.command, err)
			continue
		}
		if event, err = listenServicePipe(names.event, access, false); err != nil {
			logfmt.Warnf("[service] %s listen error: %v", names.event, err)
			command.listener.Close()
			continue
		}
		return command, event, nil
	}
	return
}

// followServedUser rewrites the pipe's descriptor in place after each change
// of served user, retrying a failed rewrite until it holds: until then the
// descriptor still lets the previous user open the pipe, though no longer use
// it.
func followServedUser(ctx context.Context, pipe servicePipe, access *pipeAccess) {
	changed := pipe.changed
	for {
		select {
		case <-ctx.Done():
			return
		case <-changed:
		}
		for {
			var servedUser *windows.SID
			servedUser, changed = access.current()
			err := setPipeDescriptor(pipe.name, servicePipeSDDL(servedUser))
			if err == nil {
				break
			}
			logfmt.Errorf("[service] cannot rewrite the descriptor of %s: %v", pipe.name, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}
}

type commandConnection struct {
	conn   net.Conn
	caller atomic.Pointer[pipeCaller] // nil until the first command is read
}

type commandConnections struct {
	mu   sync.Mutex
	open map[*commandConnection]struct{}
}

func newCommandConnections() *commandConnections {
	return &commandConnections{open: make(map[*commandConnection]struct{})}
}

func (c *commandConnections) add(conn net.Conn) *commandConnection {
	connection := &commandConnection{conn: conn}
	c.mu.Lock()
	c.open[connection] = struct{}{}
	c.mu.Unlock()
	return connection
}

func (c *commandConnections) remove(connection *commandConnection) {
	c.mu.Lock()
	delete(c.open, connection)
	c.mu.Unlock()
}

// closeNotAdmitted closes every connection whose caller is not known yet or is
// no longer admitted. It runs within a change of served user, like
// dropSubscribersNotAdmitted.
func (c *commandConnections) closeNotAdmitted(admits func(pipeCaller) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for connection := range c.open {
		if caller := connection.caller.Load(); caller == nil || !admits(*caller) {
			connection.conn.Close()
		}
	}
}

func serveCommandPipe(ctx context.Context, listener net.Listener, access *pipeAccess, connections *commandConnections) {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logfmt.Errorf("[service] command pipe accept error: %v", err)
			continue
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			handleCommandConnection(ctx, c, access, connections)
		}(conn)
	}
}

func serveEventPipe(ctx context.Context, listener net.Listener, hub *serviceEventHub, access *pipeAccess) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logfmt.Errorf("[service] event pipe accept error: %v", err)
			continue
		}
		go handleEventConnection(ctx, conn, hub, access)
	}
}

// handleEventConnection subscribes a caller once it has written its first
// byte, which is what lets the service read who it is.
func handleEventConnection(ctx context.Context, conn net.Conn, hub *serviceEventHub, access *pipeAccess) {
	conn.SetReadDeadline(time.Now().Add(firstMessageTimeout))
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})
	caller, err := identifyPipeClient(conn)
	if err != nil {
		logfmt.Errorf("[service] cannot identify an event pipe client: %v", err)
		conn.Close()
		return
	}

	sessionCtx, sessionCancel := context.WithCancel(ctx)
	if !access.runAdmitted(caller, func() { hub.Subscribe(sessionCtx, conn, caller) }) {
		logfmt.Warnf("[service] refused an event subscriber %s", caller.user)
		sessionCancel()
		conn.Close()
		return
	}
	buf := make([]byte, 1)
	for {
		if _, err := conn.Read(buf); err != nil {
			sessionCancel()
			return
		}
	}
}

var identifyPipeClient = pipeClientIdentity

// handleCommandConnection checks the caller on every command, since the served
// user can change while a connection stays open.
func handleCommandConnection(ctx context.Context, conn net.Conn, access *pipeAccess, connections *commandConnections) {
	connection := connections.add(conn)
	defer connections.remove(connection)
	connCtx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		<-connCtx.Done()
		conn.Close()
	}()

	limited := &io.LimitedReader{R: conn, N: maxCommandBytes}
	reader := bufio.NewReader(limited)
	emitter := json.NewEncoder(conn)

	emit := func(resp pipeResponse) bool {
		if err := emitter.Encode(resp); err != nil {
			logfmt.Errorf("[service] write response error: %v", err)
			return false
		}
		return true
	}
	refuse := func(caller *pipeCaller) {
		logfmt.Warnf("[service] refused a command from %s", caller.user)
		emit(pipeResponse{OK: false, Error: accessDeniedReply})
	}

	conn.SetReadDeadline(time.Now().Add(firstMessageTimeout))
	if _, err := reader.Peek(1); err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})
	// The first byte is enough to read who is calling, so a caller who is not
	// admitted is refused before the service buffers a whole command.
	identity, err := identifyPipeClient(conn)
	if err != nil {
		logfmt.Errorf("[service] cannot identify a command pipe client: %v", err)
		emit(pipeResponse{OK: false, Error: accessDeniedReply})
		return
	}
	caller := &identity
	connection.caller.Store(caller)

	for {
		if !access.admits(*caller) {
			refuse(caller)
			return
		}
		limited.N = maxCommandBytes
		line, err := reader.ReadBytes('\n')
		if limited.N == 0 && err != nil {
			emit(pipeResponse{OK: false, Error: fmt.Sprintf("a command is limited to %d bytes", maxCommandBytes)})
			return
		}
		if err != nil && (!errors.Is(err, io.EOF) || len(bytes.TrimSpace(line)) == 0) {
			return
		}

		var cmd pipeCommand
		if err := json.Unmarshal(line, &cmd); err != nil {
			emit(pipeResponse{OK: false, Error: fmt.Sprintf("decode error: %v", err)})
			return
		}

		var resp pipeResponse
		if !access.runAdmitted(*caller, func() { resp = dispatchCommand(cmd) }) {
			refuse(caller)
			return
		}
		if !emit(resp) || errors.Is(err, io.EOF) {
			return
		}
	}
}

func dispatchCommand(cmd pipeCommand) pipeResponse {
	if globalController == nil {
		return pipeResponse{OK: false, Error: "controller not initialized"}
	}

	action := strings.ToLower(strings.TrimSpace(cmd.Action))
	switch action {
	case "ping":
		return pipeResponse{OK: true, Data: map[string]string{"message": "pong"}}
	case "engine_start":
		var payload struct {
			EngineID      string `json:"engineId"`
			Request       string `json:"request"`
			MTU           int    `json:"mtu"`
			UDPTimeoutSec int    `json:"udpTimeoutSec"`
		}
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
			return pipeResponse{OK: false, Error: fmt.Sprintf("invalid payload: %v", err)}
		}
		var req EngineStartRequest
		if err := json.Unmarshal([]byte(payload.Request), &req); err != nil {
			return pipeResponse{OK: false, Error: fmt.Sprintf("invalid request: %v", err)}
		}
		applyTun2SocksConfig(payload.MTU, payload.UDPTimeoutSec)
		// In the service build useServiceIPC is false, so engineStart runs
		// locally and dispatches to the engine's own Handle*Start.
		result := runFFICall(func() int32 {
			return globalController.engineStart(payload.EngineID, req)
		})
		if result != glitchCoreResultSuccess {
			return pipeResponse{OK: false, Error: fmt.Sprintf("engine %q start failed: code %d", payload.EngineID, result)}
		}
		return pipeResponse{OK: true}
	case "engine_stop":
		var payload struct {
			EngineID string `json:"engineId"`
		}
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
			return pipeResponse{OK: false, Error: fmt.Sprintf("invalid payload: %v", err)}
		}
		result := runFFICall(func() int32 {
			return globalController.engineStop(payload.EngineID)
		})
		if result != glitchCoreResultSuccess {
			return pipeResponse{OK: false, Error: fmt.Sprintf("engine %q stop failed: code %d", payload.EngineID, result)}
		}
		return pipeResponse{OK: true}
	case "engine_status":
		var payload struct {
			EngineID string `json:"engineId"`
		}
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
			return pipeResponse{OK: false, Error: fmt.Sprintf("invalid payload: %v", err)}
		}
		running := globalController.engineIsRunning(payload.EngineID) == glitchCoreResultSuccess
		return pipeResponse{OK: true, Data: map[string]bool{"running": running}}
	case "set_status_verbosity":
		var payload struct {
			Level int `json:"level"`
		}
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
			return pipeResponse{OK: false, Error: fmt.Sprintf("invalid payload: %v", err)}
		}
		applyStatusVerbosity(payload.Level)
		return pipeResponse{OK: true}
	case "set_conn_inspector":
		var payload struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
			return pipeResponse{OK: false, Error: fmt.Sprintf("invalid payload: %v", err)}
		}
		applyConnInspector(payload.Enabled)
		return pipeResponse{OK: true}
	case "set_memory_limit":
		var payload struct {
			Bytes int64 `json:"bytes"`
		}
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
			return pipeResponse{OK: false, Error: fmt.Sprintf("invalid payload: %v", err)}
		}
		applyMemoryLimit(payload.Bytes)
		return pipeResponse{OK: true}
	case "listen_stats":
		var payload struct {
			IntervalMS int `json:"interval_ms"`
		}
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
			return pipeResponse{OK: false, Error: fmt.Sprintf("invalid payload: %v", err)}
		}
		if payload.IntervalMS <= 0 {
			return pipeResponse{OK: false, Error: "interval_ms must be > 0"}
		}
		globalController.startStats(time.Duration(payload.IntervalMS) * time.Millisecond)
		return pipeResponse{OK: true}
	case "stop_stats":
		globalController.stopStats()
		return pipeResponse{OK: true}
	case "replay_session":
		globalController.replaySession()
		return pipeResponse{OK: true}
	default:
		return pipeResponse{OK: false, Error: fmt.Sprintf("unknown action: %s", cmd.Action)}
	}
}
