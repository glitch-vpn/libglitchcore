//go:build service && windows

package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

const (
	serviceName         = "GlitchVpnCore"
	commandPipeName     = `\\.\pipe\glitch_vpn_core_cmd`
	eventPipeName       = `\\.\pipe\glitch_vpn_core_events`
	pipeBufferSizeBytes = 64 * 1024
)

type serviceEventHub struct {
	mu          sync.RWMutex
	nextID      int
	subscribers map[int]chan string
}

func newServiceEventHub() *serviceEventHub {
	return &serviceEventHub{
		subscribers: make(map[int]chan string),
	}
}

func (h *serviceEventHub) addSubscriber() (int, chan string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := h.nextID
	h.nextID++
	ch := make(chan string, 64)
	h.subscribers[id] = ch
	return id, ch
}

func (h *serviceEventHub) removeSubscriber(id int) {
	h.mu.Lock()
	ch, ok := h.subscribers[id]
	if ok {
		delete(h.subscribers, id)
	}
	h.mu.Unlock()
	if ok {
		close(ch)
	}
}

func (h *serviceEventHub) dropSubscribers() {
	h.mu.Lock()
	dropped := h.subscribers
	h.subscribers = make(map[int]chan string)
	h.mu.Unlock()
	for _, ch := range dropped {
		close(ch)
	}
}

func (h *serviceEventHub) Publish(msg string) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, ch := range h.subscribers {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (h *serviceEventHub) Subscribe(ctx context.Context, conn net.Conn) {
	id, ch := h.addSubscriber()
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
			case msg, ok := <-ch:
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
	hub    *serviceEventHub
	access *pipeAccess
}

func runServiceMain() {
	svc := &glitchService{hub: newServiceEventHub(), access: newPipeAccess()}
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

	s.refreshServedUser()
	go serveCommandPipe(ctx, s.access)
	go serveEventPipe(ctx, s.hub, s.access)

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptSessionChange}
	// A logon before session changes were accepted sends no notice.
	s.refreshServedUser()

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
				s.refreshServedUser()
			default:
			}
		}
	}
}

// refreshServedUser turns off what shows the tunnel's traffic when the user it
// is shown to changes: the tunnel itself outlives a switch of users.
func (s *glitchService) refreshServedUser() {
	if s.access.refresh() {
		applyConnInspector(false)
		applyStatusVerbosity(-1)
	}
}

func servicePipeConfig(servedUser *windows.SID, messageMode bool) *winio.PipeConfig {
	return &winio.PipeConfig{
		SecurityDescriptor: servicePipeSDDL(servedUser),
		MessageMode:        messageMode,
		InputBufferSize:    pipeBufferSizeBytes,
		OutputBufferSize:   pipeBufferSizeBytes,
	}
}

// listenServicePipe holds the pipe name for as long as ctx lives: a listener
// closed even for a moment frees the name for any account to take. A change of
// served user rewrites the descriptor in place and then runs
// onServedUserChange. It returns nil only when ctx ends first.
func listenServicePipe(ctx context.Context, name string, access *pipeAccess, messageMode bool, onServedUserChange func()) net.Listener {
	for {
		servedUser, changed := access.current()
		listener, err := winio.ListenPipe(name, servicePipeConfig(servedUser, messageMode))
		if err == nil {
			go func() {
				<-ctx.Done()
				listener.Close()
			}()
			go followServedUser(ctx, name, access, changed, onServedUserChange)
			return listener
		}
		logfmt.Errorf("[service] %s listen error: %v", name, err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
	}
}

func followServedUser(ctx context.Context, name string, access *pipeAccess, changed <-chan struct{}, onChange func()) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-changed:
		}
		var servedUser *windows.SID
		servedUser, changed = access.current()
		if err := setPipeDescriptor(name, servicePipeSDDL(servedUser)); err != nil {
			logfmt.Errorf("[service] cannot rewrite the descriptor of %s: %v", name, err)
		}
		onChange()
	}
}

func serveCommandPipe(ctx context.Context, access *pipeAccess) {
	listener := listenServicePipe(ctx, commandPipeName, access, true, func() {})
	if listener == nil {
		return
	}
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
			handleCommandConnection(ctx, c, access)
		}(conn)
	}
}

// serveEventPipe drops every subscriber when the served user changes; the
// descriptor then decides who may subscribe again.
func serveEventPipe(ctx context.Context, hub *serviceEventHub, access *pipeAccess) {
	listener := listenServicePipe(ctx, eventPipeName, access, false, hub.dropSubscribers)
	if listener == nil {
		return
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logfmt.Errorf("[service] event pipe accept error: %v", err)
			continue
		}
		sessionCtx, sessionCancel := context.WithCancel(ctx)
		hub.Subscribe(sessionCtx, conn)
		go func() {
			buf := make([]byte, 1)
			for {
				if _, err := conn.Read(buf); err != nil {
					sessionCancel()
					return
				}
			}
		}()
	}
}

var identifyPipeClient = pipeClientIdentity

// handleCommandConnection checks the caller on every command, since the served
// user can change while a connection stays open.
func handleCommandConnection(ctx context.Context, conn net.Conn, access *pipeAccess) {
	connCtx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		<-connCtx.Done()
		conn.Close()
	}()

	decoder := json.NewDecoder(conn)
	emitter := json.NewEncoder(conn)

	emit := func(resp pipeResponse) bool {
		if err := emitter.Encode(resp); err != nil {
			logfmt.Errorf("[service] write response error: %v", err)
			return false
		}
		return true
	}

	var caller *pipeCaller
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		var cmd pipeCommand
		if err := decoder.Decode(&cmd); err != nil {
			if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			emit(pipeResponse{OK: false, Error: fmt.Sprintf("decode error: %v", err)})
			return
		}

		if caller == nil {
			identity, err := identifyPipeClient(conn)
			if err != nil {
				logfmt.Errorf("[service] cannot identify a command pipe client: %v", err)
				emit(pipeResponse{OK: false, Error: accessDeniedReply})
				return
			}
			caller = &identity
		}
		if !access.admits(*caller) {
			logfmt.Warnf("[service] refused a command from %s", caller.user)
			emit(pipeResponse{OK: false, Error: accessDeniedReply})
			return
		}

		resp := dispatchCommand(cmd)
		if !emit(resp) {
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
