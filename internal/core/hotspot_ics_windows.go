//go:build windows

package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

// ICS keeps what it shared in a WMI store (root\Microsoft\HomeNet) that
// outlives the adapters it names. A connection that is gone and still marked
// as ICS's public side leaves ICS without a DHCP address on the hotspot, and
// a Windows Mobile hotspot comes up with clients that get none.

const (
	homeNetNamespace    = `root\Microsoft\HomeNet`
	icsSettingsKeyPath  = `SYSTEM\CurrentControlSet\Services\icssvc\Settings`
	icsPreferredPublic  = "PreferredPublicInterface"
	sharedAccessService = "SharedAccess"
	sharedAccessTimeout = 30 * time.Second
	// sharedAccessSettle is how long ICS takes to be ready after a start.
	sharedAccessSettle = 3 * time.Second
)

var guidInText = regexp.MustCompile(`\{[0-9A-Fa-f-]{36}\}`)

// homeNetFlag is a HomeNet row that marks a connection as ICS's public or
// private side.
type homeNetFlag struct {
	guid    string
	public  bool
	private bool
}

type icsSnapshot struct {
	present         map[string]bool // adapter GUIDs
	flags           []homeNetFlag
	preferredPublic string // "" when absent
}

// stale says whether ICS names an adapter that no longer exists.
func (s icsSnapshot) stale() bool {
	for _, flag := range s.flags {
		if !s.present[flag.guid] {
			return true
		}
	}
	return s.preferredPublic != "" && !s.present[s.preferredPublic]
}

func prepareHotspot() int32 {
	if hotspotRunning() {
		return hotspotResultRunning
	}
	var snapshot icsSnapshot
	err := withCOM(func() (err error) {
		snapshot, err = readICS()
		return err
	})
	if err != nil {
		logfmt.Warnf("[hotspot] read ICS state failed: %v", err)
		return hotspotResultRepairFailed
	}
	if !snapshot.stale() {
		return ResultSuccess
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return hotspotResultNeedsAdmin
	}
	if err := withCOM(func() error { return repairICS(snapshot) }); err != nil {
		logfmt.Warnf("[hotspot] repair ICS failed: %v", err)
		return hotspotResultRepairFailed
	}
	return ResultSuccess
}

// hotspotRunning: ICS shares a pair whose private side is an adapter that
// is up. Restarting SharedAccess then turns the hotspot off.
func hotspotRunning() bool {
	_, private, err := (&windowsHotspotOS{}).SharedPair()
	if err != nil || !validInterfaceIndex(private) {
		return false
	}
	luid, err := winipcfg.LUIDFromIndex(private)
	if err != nil {
		return false
	}
	row, err := luid.Interface()
	return err == nil && row.OperStatus == winipcfg.IfOperStatusUp
}

func withCOM(run func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		// S_FALSE: this thread already holds the apartment.
		var oleError *ole.OleError
		if !errors.As(err, &oleError) || oleError.Code() != 1 {
			return fmt.Errorf("start COM: %w", err)
		}
	}
	defer ole.CoUninitialize()
	return run()
}

func normalizedGUID(text string) string {
	return strings.ToUpper(guidInText.FindString(text))
}

func readICS() (icsSnapshot, error) {
	snapshot := icsSnapshot{present: map[string]bool{}}
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeAllInterfaces)
	if err != nil {
		return snapshot, fmt.Errorf("list adapters: %w", err)
	}
	for _, adapter := range adapters {
		snapshot.present[strings.ToUpper(adapter.AdapterName())] = true
	}
	if err := forEachHomeNetRow(func(row *ole.IDispatch) error {
		public, private, err := homeNetRowFlags(row)
		if err != nil {
			return err
		}
		if public || private {
			reference, err := oleutil.GetProperty(row, "Connection")
			if err != nil {
				return err
			}
			defer reference.Clear()
			snapshot.flags = append(snapshot.flags, homeNetFlag{guid: normalizedGUID(reference.ToString()), public: public, private: private})
		}
		return nil
	}); err != nil {
		return snapshot, fmt.Errorf("read HomeNet: %w", err)
	}
	snapshot.preferredPublic = preferredPublicInterface()
	return snapshot, nil
}

func homeNetRowFlags(row *ole.IDispatch) (public, private bool, err error) {
	publicValue, err := oleutil.GetProperty(row, "IsIcsPublic")
	if err != nil {
		return false, false, err
	}
	privateValue, err := oleutil.GetProperty(row, "IsIcsPrivate")
	if err != nil {
		return false, false, err
	}
	return publicValue.Val != 0, privateValue.Val != 0, nil
}

// forEachHomeNetRow runs over HNet_ConnectionProperties through WMI's own
// objects, which Put back what they changed (CIM cannot resolve the rows'
// references).
func forEachHomeNetRow(visit func(row *ole.IDispatch) error) error {
	locator, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return err
	}
	defer locator.Release()
	locatorDispatch, err := locator.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return err
	}
	defer locatorDispatch.Release()
	service, err := oleutil.CallMethod(locatorDispatch, "ConnectServer", ".", homeNetNamespace)
	if err != nil {
		return err
	}
	defer service.Clear()
	rows, err := oleutil.CallMethod(service.ToIDispatch(), "ExecQuery", "SELECT * FROM HNet_ConnectionProperties")
	if err != nil {
		return err
	}
	defer rows.Clear()
	return oleutil.ForEach(rows.ToIDispatch(), func(item *ole.VARIANT) error {
		return visit(item.ToIDispatch())
	})
}

// forEachSharingConnection runs over every connection INetSharingManager
// enumerates, with its INetSharingConfiguration.
func forEachSharingConnection(visit func(guid string, configuration *ole.IDispatch) error) error {
	manager, err := oleutil.CreateObject("HNetCfg.HNetShare")
	if err != nil {
		return err
	}
	defer manager.Release()
	share, err := manager.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return err
	}
	defer share.Release()
	connections, err := oleutil.GetProperty(share, "EnumEveryConnection")
	if err != nil {
		return err
	}
	defer connections.Clear()
	return oleutil.ForEach(connections.ToIDispatch(), func(item *ole.VARIANT) error {
		connection := item.Value()
		props, err := oleutil.GetProperty(share, "NetConnectionProps", connection)
		if err != nil {
			return err
		}
		defer props.Clear()
		guid, err := oleutil.GetProperty(props.ToIDispatch(), "Guid")
		if err != nil {
			return err
		}
		defer guid.Clear()
		configuration, err := oleutil.GetProperty(share, "INetSharingConfigurationForINetConnection", connection)
		if err != nil {
			return err
		}
		defer configuration.Clear()
		return visit(normalizedGUID(guid.ToString()), configuration.ToIDispatch())
	})
}

func preferredPublicInterface() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, icsSettingsKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	raw, _, err := key.GetBinaryValue(icsPreferredPublic)
	if err != nil || len(raw) != 16 {
		return ""
	}
	guid := windows.GUID{
		Data1: binary.LittleEndian.Uint32(raw[0:4]),
		Data2: binary.LittleEndian.Uint16(raw[4:6]),
		Data3: binary.LittleEndian.Uint16(raw[6:8]),
	}
	copy(guid.Data4[:], raw[8:16])
	return strings.ToUpper(guid.String())
}

// repairICS puts ICS back to nothing shared: sharing off on every connection,
// the rows' flags cleared, a preferred public side that is gone dropped, and
// SharedAccess started afresh.
func repairICS(snapshot icsSnapshot) error {
	var problems []error
	// INetSharingManager answers only an elevated caller. A failure here is
	// logged and does not stop the rest, which is what clears ICS's stale names.
	if err := forEachSharingConnection(func(guid string, configuration *ole.IDispatch) error {
		enabled, err := oleutil.GetProperty(configuration, "SharingEnabled")
		if err != nil {
			return err
		}
		if enabled.Val == 0 {
			return nil
		}
		_, err = oleutil.CallMethod(configuration, "DisableSharing")
		return err
	}); err != nil {
		logfmt.Warnf("[hotspot] turn sharing off failed: %v", err)
	}
	if err := forEachHomeNetRow(func(row *ole.IDispatch) error {
		public, private, err := homeNetRowFlags(row)
		if err != nil || (!public && !private) {
			return err
		}
		if _, err := oleutil.PutProperty(row, "IsIcsPublic", false); err != nil {
			return err
		}
		if _, err := oleutil.PutProperty(row, "IsIcsPrivate", false); err != nil {
			return err
		}
		_, err = oleutil.CallMethod(row, "Put_")
		return err
	}); err != nil {
		problems = append(problems, fmt.Errorf("clear the HomeNet flags: %w", err))
	}
	if snapshot.preferredPublic != "" && !snapshot.present[snapshot.preferredPublic] {
		if err := dropPreferredPublicInterface(); err != nil {
			problems = append(problems, fmt.Errorf("drop the preferred public interface: %w", err))
		}
	}
	if len(problems) > 0 {
		return errors.Join(problems...)
	}
	return restartSharedAccess()
}

func dropPreferredPublicInterface() error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, icsSettingsKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.DeleteValue(icsPreferredPublic)
}

func sharedAccessStatus(service windows.Handle) (windows.SERVICE_STATUS_PROCESS, error) {
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	err := windows.QueryServiceStatusEx(service, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed)
	return status, err
}

// restartSharedAccess stops and starts the service. A stop can report a
// failure and still happen, so the restart is judged by the process id.
func restartSharedAccess() error {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("open the service manager: %w", err)
	}
	defer windows.CloseServiceHandle(manager)
	name, err := windows.UTF16PtrFromString(sharedAccessService)
	if err != nil {
		return err
	}
	service, err := windows.OpenService(manager, name, windows.SERVICE_START|windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return fmt.Errorf("open %s: %w", sharedAccessService, err)
	}
	defer windows.CloseServiceHandle(service)

	before, err := sharedAccessStatus(service)
	if err != nil {
		return fmt.Errorf("query %s: %w", sharedAccessService, err)
	}
	if before.CurrentState != windows.SERVICE_STOPPED {
		var stopped windows.SERVICE_STATUS
		_ = windows.ControlService(service, windows.SERVICE_CONTROL_STOP, &stopped)
		if err := waitSharedAccess(service, func(status windows.SERVICE_STATUS_PROCESS) bool {
			return status.CurrentState == windows.SERVICE_STOPPED || (status.ProcessId != 0 && status.ProcessId != before.ProcessId)
		}); err != nil {
			return fmt.Errorf("stop %s: %w", sharedAccessService, err)
		}
	}
	if status, err := sharedAccessStatus(service); err == nil && status.CurrentState == windows.SERVICE_STOPPED {
		if err := windows.StartService(service, 0, nil); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return fmt.Errorf("start %s: %w", sharedAccessService, err)
		}
	}
	if err := waitSharedAccess(service, func(status windows.SERVICE_STATUS_PROCESS) bool {
		return status.CurrentState == windows.SERVICE_RUNNING
	}); err != nil {
		return fmt.Errorf("start %s: %w", sharedAccessService, err)
	}
	time.Sleep(sharedAccessSettle)
	after, err := sharedAccessStatus(service)
	if err != nil {
		return fmt.Errorf("query %s: %w", sharedAccessService, err)
	}
	if before.ProcessId != 0 && after.ProcessId == before.ProcessId {
		return fmt.Errorf("%s was not restarted: process %d still runs it", sharedAccessService, after.ProcessId)
	}
	return nil
}

func waitSharedAccess(service windows.Handle, done func(windows.SERVICE_STATUS_PROCESS) bool) error {
	deadline := time.Now().Add(sharedAccessTimeout)
	for {
		status, err := sharedAccessStatus(service)
		if err != nil {
			return err
		}
		if done(status) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("still in state %d after %s", status.CurrentState, sharedAccessTimeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
