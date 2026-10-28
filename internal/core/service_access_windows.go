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

const (
	accessDeniedReply       = "access denied"
	tooManyConnectionsReply = "too many connections"
	trafficHiddenReply      = "the active user cannot be read"
)

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
	// From the first failed read of the active user until a read succeeds,
	// only LocalSystem and elevated administrators may show the traffic.
	trafficHidden bool
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
	return a.changeServedUserLocked(user, onChange)
}

func (a *pipeAccess) changeServedUserLocked(user *windows.SID, onChange func()) (changed bool) {
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

// refresh reads the active user until a read succeeds. The first failure runs
// onUnreadable under the write lock and keeps the served user, since a failed
// read says nothing about who is at the machine; a user who left could keep
// the pipes, though, so after activeUserReadGrace nobody is served, and the
// reads go on so that whoever is at the console gets the pipes back.
func (a *pipeAccess) refresh(ctx context.Context, onChange, onUnreadable func()) {
	delay := activeUserRetryDelay
	failingSince := time.Now()
	hidden, fellBack := false, false
	for {
		user, err := readActiveUser()
		if err == nil {
			a.mu.Lock()
			a.trafficHidden = false
			a.changeServedUserLocked(user, onChange)
			a.mu.Unlock()
			return
		}
		if !hidden {
			hidden = true
			logfmt.Warnf("[service] cannot read the active user, keeping the one served: %v", err)
			a.mu.Lock()
			a.trafficHidden = true
			onUnreadable()
			a.mu.Unlock()
		}
		wait := delay
		if !fellBack {
			remaining := activeUserReadGrace - time.Since(failingSince)
			if remaining <= 0 {
				logfmt.Errorf("[service] cannot read the active user, serving nobody: %v", err)
				a.changeServedUser(nil, onChange)
				fellBack = true
			} else {
				wait = min(wait, remaining)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
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
	if caller.privileged() {
		return true
	}
	return a.servedUser != nil && caller.user.Equals(a.servedUser)
}

func (a *pipeAccess) mayShowTrafficLocked(caller pipeCaller) bool {
	return !a.trafficHidden || caller.privileged()
}

func (c pipeCaller) privileged() bool {
	return c.administrator || c.user.IsWellKnown(windows.WinLocalSystemSid)
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

func activeUserSID() (*windows.SID, error) {
	return selectActiveUser(windows.WTSGetActiveConsoleSessionId(), listSessions, sessionUserSID)
}

type sessionState struct {
	id     uint32
	active bool
}

func listSessions() ([]sessionState, error) {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return nil, fmt.Errorf("enumerate sessions: %w", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	states := make([]sessionState, 0, count)
	for _, session := range unsafe.Slice(sessions, count) {
		states = append(states, sessionState{id: session.SessionID, active: session.State == windows.WTSActive})
	}
	return states, nil
}

// selectActiveUser picks the user of the console session, or else the one user
// of an active remote session. It returns nil with no error when nobody is at
// the machine, or when several remote users are and none of them is the
// machine's.
func selectActiveUser(consoleSession uint32, list func() ([]sessionState, error), userOf func(uint32) (*windows.SID, error)) (*windows.SID, error) {
	if consoleSession != 0xFFFFFFFF {
		user, err := userOf(consoleSession)
		if err == nil {
			return user, nil
		}
		if !errors.Is(err, windows.ERROR_NO_TOKEN) {
			return nil, fmt.Errorf("console session %d: %w", consoleSession, err)
		}
	}

	sessions, err := list()
	if err != nil {
		return nil, err
	}
	var found *windows.SID
	for _, session := range sessions {
		if !session.active || session.id == consoleSession {
			continue
		}
		user, err := userOf(session.id)
		if errors.Is(err, windows.ERROR_NO_TOKEN) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_CTX_WINSTATION_NOT_FOUND) {
			// Nobody signed in there, or the session ended since the listing.
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("session %d: %w", session.id, err)
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
