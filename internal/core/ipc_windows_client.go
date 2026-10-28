//go:build windows && !service

package core

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

const (
	serviceCommandPipe = `\\.\pipe\glitch_vpn_core_cmd`
	serviceEventPipe   = `\\.\pipe\glitch_vpn_core_events`
)

var (
	serviceIPCOnce sync.Once

	errServicePipeNotOwned = errors.New("the pipe does not belong to the service")
)

type serviceResponse struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

type serviceStatusEvent struct {
	Type      string `json:"type"`
	Code      int32  `json:"code"`
	Message   string `json:"message"`
	Timestamp string `json:"ts"`
}

func ensureServiceIPC() {
	serviceIPCOnce.Do(func() {
		go serviceEventLoop()
	})
}

func serviceEventLoop() {
	retryDelay := time.Second
	for {
		conn, err := dialService(serviceEventPipe, 2*time.Second)
		if err != nil {
			logfmt.Warnf("[IPC] dial event pipe failed: %v", err)
			time.Sleep(retryDelay)
			continue
		}
		scanner := bufio.NewScanner(conn)
		scanner.Buffer(make([]byte, 0, 64*1024), 512*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			var evt serviceStatusEvent
			if err := json.Unmarshal(line, &evt); err != nil {
				logfmt.Warnf("[IPC] parse event failed: %v", err)
				continue
			}
			if globalController != nil && relayedLogPasses(evt.Code, evt.Message) {
				globalController.emitStatus(evt.Code, evt.Message)
			}
		}
		if err := scanner.Err(); err != nil {
			logfmt.Warnf("[IPC] event pipe read error: %v", err)
		}
		_ = conn.Close()
		time.Sleep(retryDelay)
	}
}

// dialService opens one of the service's pipes only if it belongs to
// LocalSystem or the Administrators group: any account can create a pipe under
// a name that is free, as these are while the service is stopped or reopening
// them.
func dialService(pipeName string, timeout time.Duration) (net.Conn, error) {
	conn, err := dialPipeAtIdentification(pipeName, timeout)
	if err != nil {
		return nil, err
	}
	if err := verifyServicePipeOwner(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func verifyServicePipeOwner(conn net.Conn) error {
	pipe, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return errors.New("not a named pipe")
	}
	descriptor, err := windows.GetSecurityInfo(windows.Handle(pipe.Fd()), windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read the pipe owner: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("read the pipe owner: %w", err)
	}
	if owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return nil
	}
	return fmt.Errorf("%w: its owner is %s", errServicePipeNotOwned, owner)
}

func callService(action string, payload map[string]any) (serviceResponse, error) {
	conn, err := dialService(serviceCommandPipe, 5*time.Second)
	if err != nil {
		return serviceResponse{}, fmt.Errorf("dial command pipe: %w", err)
	}
	defer conn.Close()

	message := map[string]any{"action": action}
	if payload != nil {
		message["payload"] = payload
	}
	if err := json.NewEncoder(conn).Encode(message); err != nil {
		return serviceResponse{}, fmt.Errorf("write command: %w", err)
	}

	var resp serviceResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return serviceResponse{}, fmt.Errorf("read response: %w", err)
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "service reported failure"
		}
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// serviceEngineStart/Stop/Status forward the engine-neutral request to the
// service, which dispatches via its own registry (tun2socks config rides along,
// separate process).
func serviceEngineStart(id string, req EngineStartRequest) error {
	mtu, udpTimeoutSec := currentTun2SocksConfig()
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal engine request: %w", err)
	}
	_, err = callService("engine_start", map[string]any{
		"engineId":      id,
		"request":       string(reqJSON),
		"mtu":           mtu,
		"udpTimeoutSec": udpTimeoutSec,
	})
	return err
}

func serviceEngineStop(id string) error {
	_, err := callService("engine_stop", map[string]any{"engineId": id})
	return err
}

func serviceEngineStatus(id string) (bool, error) {
	resp, err := callService("engine_status", map[string]any{"engineId": id})
	if err != nil {
		return false, err
	}
	var payload struct {
		Running bool `json:"running"`
	}
	if len(resp.Data) > 0 {
		if err := json.Unmarshal(resp.Data, &payload); err != nil {
			return false, err
		}
	}
	return payload.Running, nil
}

func serviceSetVerbosity(level int) error {
	_, err := callService("set_status_verbosity", map[string]any{"level": level})
	return err
}

func serviceSetConnInspector(enabled bool) error {
	_, err := callService("set_conn_inspector", map[string]any{"enabled": enabled})
	return err
}

func serviceSetMemoryLimit(bytes int64) error {
	_, err := callService("set_memory_limit", map[string]any{"bytes": bytes})
	return err
}

func serviceListenStats(interval time.Duration) error {
	_, err := callService("listen_stats", map[string]any{"interval_ms": int(interval / time.Millisecond)})
	return err
}

func serviceStopStats() error {
	_, err := callService("stop_stats", nil)
	return err
}

func serviceReplaySession() error {
	_, err := callService("replay_session", nil)
	return err
}
