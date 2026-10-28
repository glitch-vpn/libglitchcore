//go:build service && windows

package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

// pipeClientAccessMask is FILE_GENERIC_READ | FILE_GENERIC_WRITE without
// FILE_CREATE_PIPE_INSTANCE, so an admitted user cannot open a server end of
// their own under the service's pipe names.
const pipeClientAccessMask windows.ACCESS_MASK = 0x12019b

const accessDeniedReply = "access denied"

// servicePipeSDDL admits LocalSystem and the Administrators group in full and
// the served user as a client; with no served user only the first two remain.
func servicePipeSDDL(servedUser *windows.SID) string {
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
	if servedUser != nil {
		sddl += fmt.Sprintf("(A;;%#x;;;%s)", pipeClientAccessMask, servedUser)
	}
	return sddl
}

type pipeCaller struct {
	user          *windows.SID
	administrator bool // the Administrators group is enabled in the caller's token
}

// pipeAccess holds the user the service serves: the user of the session
// attached to the console, or of the one active remote session when nobody is
// at the console. The tunnel is machine-wide, so it belongs to whoever is at
// the machine; a user switched away from loses the pipes.
type pipeAccess struct {
	// Held for reading across a command's check and its dispatch, and for
	// writing across a change of served user and what the change resets, so no
	// command of the previous user runs after it.
	mu         sync.RWMutex
	servedUser *windows.SID
	changed    chan struct{} // closed when servedUser changes, then replaced
}

func newPipeAccess() *pipeAccess {
	return &pipeAccess{changed: make(chan struct{})}
}

func (a *pipeAccess) current() (*windows.SID, <-chan struct{}) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.servedUser, a.changed
}

// changeServedUser runs onChange under the write lock when user differs from
// the one served.
func (a *pipeAccess) changeServedUser(user *windows.SID, onChange func()) (changed bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if sameSID(a.servedUser, user) {
		return false
	}
	a.servedUser = user
	close(a.changed)
	a.changed = make(chan struct{})
	onChange()
	return true
}

var readActiveUser = activeUserSID

var (
	activeUserRetryDelay    = time.Second
	activeUserMaxRetryDelay = 8 * time.Second
	activeUserReadGrace     = 30 * time.Second
)

// refresh reads the active user until a read succeeds. Meanwhile it keeps the
// served user, since a failed read says nothing about who is at the machine,
// but not past activeUserReadGrace: a user who left could keep the pipes.
func (a *pipeAccess) refresh(ctx context.Context, onChange func()) {
	delay := activeUserRetryDelay
	failingSince := time.Now()
	for {
		user, err := readActiveUser()
		if err == nil {
			a.changeServedUser(user, onChange)
			return
		}
		if time.Since(failingSince) >= activeUserReadGrace {
			logfmt.Errorf("[service] cannot read the active user, serving nobody: %v", err)
			a.changeServedUser(nil, onChange)
			return
		}
		logfmt.Warnf("[service] cannot read the active user, keeping the one served: %v", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, activeUserMaxRetryDelay)
	}
}

func (a *pipeAccess) admits(caller pipeCaller) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.admitsLocked(caller)
}

func (a *pipeAccess) admitsLocked(caller pipeCaller) bool {
	if caller.administrator || caller.user.IsWellKnown(windows.WinLocalSystemSid) {
		return true
	}
	return a.servedUser != nil && caller.user.Equals(a.servedUser)
}

// runAdmitted runs action only if caller is admitted, and holds off any change
// of served user until it returns: an action that never returns stalls the
// change, and once the change waits, every other command.
func (a *pipeAccess) runAdmitted(caller pipeCaller, action func()) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.admitsLocked(caller) {
		return false
	}
	action()
	return true
}

func sameSID(a, b *windows.SID) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equals(b)
}

// activeUserSID returns nil with no error when nobody is at the machine, or
// when several remote users are and none of them is the machine's.
func activeUserSID() (*windows.SID, error) {
	consoleSession := windows.WTSGetActiveConsoleSessionId()
	if consoleSession != 0xFFFFFFFF {
		user, err := sessionUserSID(consoleSession)
		if err == nil {
			return user, nil
		}
		if !errors.Is(err, windows.ERROR_NO_TOKEN) {
			return nil, fmt.Errorf("console session %d: %w", consoleSession, err)
		}
	}

	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return nil, fmt.Errorf("enumerate sessions: %w", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))

	var found *windows.SID
	for _, session := range unsafe.Slice(sessions, count) {
		if session.State != windows.WTSActive || session.SessionID == consoleSession {
			continue
		}
		user, err := sessionUserSID(session.SessionID)
		if errors.Is(err, windows.ERROR_NO_TOKEN) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_CTX_WINSTATION_NOT_FOUND) {
			// Nobody signed in there, or the session ended since the listing.
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("session %d: %w", session.SessionID, err)
		}
		if found != nil {
			return nil, nil
		}
		found = user
	}
	return found, nil
}

func sessionUserSID(session uint32) (*windows.SID, error) {
	var token windows.Token
	if err := windows.WTSQueryUserToken(session, &token); err != nil {
		return nil, err
	}
	defer token.Close()
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return tokenUser.User.Sid.Copy()
}

// setPipeDescriptor rewrites the DACL of a pipe this process listens on. A
// handle to a pipe is always a client end, so the rewrite takes one waiting
// instance for a moment: its accept loop sees a client that leaves at once.
func setPipeDescriptor(name, sddl string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := winio.DialPipeAccess(ctx, name, windows.GENERIC_READ|windows.READ_CONTROL|windows.WRITE_DAC)
	if err != nil {
		return err
	}
	defer conn.Close()
	pipe, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return errors.New("not a named pipe")
	}
	return setProtectedDACL(windows.Handle(pipe.Fd()), windows.SE_KERNEL_OBJECT, sddl)
}

// setProtectedDACL replaces the object's DACL with the one in sddl and stops
// it inheriting entries from its parent.
func setProtectedDACL(handle windows.Handle, objectType windows.SE_OBJECT_TYPE, sddl string) error {
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(handle, objectType,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

var procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

// pipeClientIdentity reads the token the client opened the pipe with. Windows
// lets a server impersonate only after it has read from the pipe, and only a
// client that dialled at identification level or above gives a token to read.
func pipeClientIdentity(conn net.Conn) (pipeCaller, error) {
	pipe, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return pipeCaller{}, errors.New("not a named pipe")
	}

	runtime.LockOSThread()
	if impersonated, _, err := procImpersonateNamedPipeClient.Call(pipe.Fd()); impersonated == 0 {
		runtime.UnlockOSThread()
		return pipeCaller{}, fmt.Errorf("impersonate the client: %w", err)
	}
	var token windows.Token
	openErr := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if err := windows.RevertToSelf(); err != nil {
		// The thread still wears the client's token: it stays locked, so the
		// runtime retires it when this goroutine ends.
		if openErr == nil {
			token.Close()
		}
		return pipeCaller{}, fmt.Errorf("revert the impersonation: %w", err)
	}
	runtime.UnlockOSThread()
	if openErr != nil {
		return pipeCaller{}, fmt.Errorf("open the client token: %w", openErr)
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return pipeCaller{}, err
	}
	user, err := tokenUser.User.Sid.Copy()
	if err != nil {
		return pipeCaller{}, err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return pipeCaller{}, err
	}
	administrator, err := token.IsMember(administrators)
	if err != nil {
		return pipeCaller{}, err
	}
	return pipeCaller{user: user, administrator: administrator}, nil
}
