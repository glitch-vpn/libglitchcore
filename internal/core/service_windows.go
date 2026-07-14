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
	"golang.org/x/sys/windows/svc"
)

const (
	serviceName         = "GlitchVpnCore"
	commandPipeName     = `\\.\pipe\glitch_vpn_core_cmd`
	eventPipeName       = `\\.\pipe\glitch_vpn_core_events`
	servicePipeSDDL     = "D:(A;;GA;;;WD)"
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
	hub *serviceEventHub
}

func runServiceMain() {
	svc := &glitchService{hub: newServiceEventHub()}
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

	go serveCommandPipe(ctx, s.hub)
	go serveEventPipe(ctx, s.hub)

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

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
			default:
			}
		}
	}
}

func serveCommandPipe(ctx context.Context, hub *serviceEventHub) {
	cfg := &winio.PipeConfig{
		SecurityDescriptor: servicePipeSDDL,
		MessageMode:        true,
		InputBufferSize:    pipeBufferSizeBytes,
		OutputBufferSize:   pipeBufferSizeBytes,
	}

	for {
		listener, err := winio.ListenPipe(commandPipeName, cfg)
		if err != nil {
			log.Printf("[service] command pipe listen error: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
				continue
			}
		}

		var wg sync.WaitGroup
		acceptCtx, cancel := context.WithCancel(ctx)
		go func() {
			<-acceptCtx.Done()
			listener.Close()
		}()

		for {
			conn, err := listener.Accept()
			if err != nil {
				if acceptCtx.Err() != nil {
					break
				}
				log.Printf("[service] command pipe accept error: %v", err)
				continue
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				handleCommandConnection(acceptCtx, c)
			}(conn)
		}

		wg.Wait()
		cancel()
		listener.Close()
		if ctx.Err() != nil {
			return
		}
	}
}

func serveEventPipe(ctx context.Context, hub *serviceEventHub) {
	cfg := &winio.PipeConfig{
		SecurityDescriptor: servicePipeSDDL,
		MessageMode:        false,
		InputBufferSize:    pipeBufferSizeBytes,
		OutputBufferSize:   pipeBufferSizeBytes,
	}

	for {
		listener, err := winio.ListenPipe(eventPipeName, cfg)
		if err != nil {
			log.Printf("[service] event pipe listen error: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
				continue
			}
		}

		acceptCtx, cancel := context.WithCancel(ctx)
		go func() {
			<-acceptCtx.Done()
			listener.Close()
		}()

		for {
			conn, err := listener.Accept()
			if err != nil {
				if acceptCtx.Err() != nil {
					break
				}
				log.Printf("[service] event pipe accept error: %v", err)
				continue
			}
			sessionCtx, sessionCancel := context.WithCancel(acceptCtx)
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

		cancel()
		listener.Close()
		if ctx.Err() != nil {
			return
		}
	}
}

func handleCommandConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	emitter := json.NewEncoder(conn)

	emit := func(resp pipeResponse) bool {
		if err := emitter.Encode(resp); err != nil {
			log.Printf("[service] write response error: %v", err)
			return false
		}
		return true
	}

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
		connInspectEnabled.Store(payload.Enabled)
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
	default:
		return pipeResponse{OK: false, Error: fmt.Sprintf("unknown action: %s", cmd.Action)}
	}
}
