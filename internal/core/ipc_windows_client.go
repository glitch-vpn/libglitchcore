//go:build windows && !service

package core

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

var (
	serviceIPCOnce sync.Once

	errNotTheServicePipe        = errors.New("the pipe is not the service's")
	errServicePipesNotPublished = errors.New("the service has published no pipes; it is not running")
	errServiceNotRunning        = errors.New("the service is not running")
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
		conn, err := dialService(eventPipeValueName, 2*time.Second)
		if err != nil {
			logfmt.Warnf("[IPC] dial event pipe failed: %v", err)
			time.Sleep(retryDelay)
			continue
		}
		// The service reads who subscribes once a byte has arrived.
		if _, err := conn.Write([]byte{'\n'}); err != nil {
			logfmt.Warnf("[IPC] event pipe write error: %v", err)
			_ = conn.Close()
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

// dialService opens the pipe the service published under valueName, and only
// if LocalSystem or the Administrators group owns it and the service's own
// process serves it.
func dialService(valueName string, timeout time.Duration) (net.Conn, error) {
	pipeName, err := readServicePipeName(valueName)
	if err != nil {
		return nil, err
	}
	conn, err := dialPipeAtIdentification(pipeName, timeout)
	if err != nil {
		return nil, err
	}
	if err := verifyServicePipeOwner(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%s: %w", pipeName, err)
	}
	if err := verifyServicePipeServer(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%s: %w", pipeName, err)
	}
	return conn, nil
}

func readServicePipeName(valueName string) (string, error) {
	key, err := registry.OpenKey(servicePipesLocation.root, servicePipesLocation.path, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return "", errServicePipesNotPublished
	}
	if err != nil {
		return "", fmt.Errorf("read the service's pipe names: %w", err)
	}
	defer key.Close()
	pipeName, _, err := key.GetStringValue(valueName)
	if errors.Is(err, registry.ErrNotExist) {
		return "", errServicePipesNotPublished
	}
	if err != nil {
		return "", fmt.Errorf("read the service's pipe names: %w", err)
	}
	if !strings.HasPrefix(pipeName, servicePipePrefix) {
		return "", fmt.Errorf("the service published %q, which is not a local pipe of its own", pipeName)
	}
	return pipeName, nil
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
	if ownedByTheService(owner) {
		return nil
	}
	return fmt.Errorf("%w: it is owned by %s", errNotTheServicePipe, owner)
}

// ownedByTheService admits the Administrators group too, since LocalSystem
// creates objects with that group as their owner.
func ownedByTheService(owner *windows.SID) bool {
	return owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

var lookUpServiceProcessID = runningServiceProcessID

// runningServiceProcessID asks the service manager with query-status access
// only, which a standard account holds.
func runningServiceProcessID() (uint32, error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, fmt.Errorf("open the service manager: %w", err)
	}
	defer windows.CloseServiceHandle(manager)
	name, err := windows.UTF16PtrFromString(serviceName)
	if err != nil {
		return 0, err
	}
	service, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, fmt.Errorf("open the service: %w", err)
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if err := windows.QueryServiceStatusEx(service, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed); err != nil {
		return 0, fmt.Errorf("query the service: %w", err)
	}
	if status.ProcessId == 0 {
		return 0, errServiceNotRunning
	}
	return status.ProcessId, nil
}

func verifyServicePipeServer(conn net.Conn) error {
	pipe, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return errors.New("not a named pipe")
	}
	var serverProcessID uint32
	if err := windows.GetNamedPipeServerProcessId(windows.Handle(pipe.Fd()), &serverProcessID); err != nil {
		return fmt.Errorf("read the pipe's server: %w", err)
	}
	serviceProcessID, err := lookUpServiceProcessID()
	if err != nil {
		return err
	}
	if serverProcessID != serviceProcessID {
		return fmt.Errorf("%w: process %d serves it, and the service runs as process %d", errNotTheServicePipe, serverProcessID, serviceProcessID)
	}
	return nil
}

func callService(action string, payload map[string]any) (serviceResponse, error) {
	conn, err := dialService(commandPipeValueName, 5*time.Second)
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
