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
	mu         sync.Mutex
	servedUser *windows.SID
	changed    chan struct{} // closed when servedUser changes, then replaced
}

func newPipeAccess() *pipeAccess {
	return &pipeAccess{changed: make(chan struct{})}
}

func (a *pipeAccess) current() (*windows.SID, <-chan struct{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.servedUser, a.changed
}

func (a *pipeAccess) setServedUser(user *windows.SID) (changed bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if sameSID(a.servedUser, user) {
		return false
	}
	a.servedUser = user
	close(a.changed)
	a.changed = make(chan struct{})
	return true
}

func (a *pipeAccess) refresh() (changed bool) {
	user, err := activeUserSID()
	if err != nil {
		logfmt.Errorf("[service] cannot read the active user: %v", err)
	}
	return a.setServedUser(user)
}

func (a *pipeAccess) admits(caller pipeCaller) bool {
	if caller.administrator || caller.user.IsWellKnown(windows.WinLocalSystemSid) {
		return true
	}
	served, _ := a.current()
	return served != nil && caller.user.Equals(served)
}

func sameSID(a, b *windows.SID) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equals(b)
}

func activeUserSID() (*windows.SID, error) {
	consoleSession := windows.WTSGetActiveConsoleSessionId()
	if consoleSession != 0xFFFFFFFF {
		if user, err := sessionUserSID(consoleSession); err == nil {
			return user, nil
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
		if err != nil {
			continue
		}
		if found != nil {
			// Several remote users at once: none of them is the machine's.
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
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
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
	return windows.SetSecurityInfo(windows.Handle(pipe.Fd()), windows.SE_KERNEL_OBJECT,
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
