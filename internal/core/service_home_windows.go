//go:build service && windows

package core

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

// serviceHomeSDDL holds the service's data folder to LocalSystem and the
// Administrators.
const serviceHomeSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

const (
	serviceHomeUnavailableReply  = "the service's data folder is not its own"
	geoAssetsRefusedReply        = "the geo assets folder cannot be read as a plain folder"
	proxyWithoutCredentialsReply = "a proxy port needs proxyUser and proxyPass"
)

const serviceSessionsFolder = "sessions"

// geoAssetFileSizeLimit bounds what the service copies of a caller's file: a
// sparse file reads as any size the caller likes, and the copy is not sparse.
const geoAssetFileSizeLimit = 256 << 20

var geoAssetFileNames = []string{"geoip.dat", "geosite.dat"}

// serviceHome is the service's data folder, where every engine runs: mihomo's
// home and the geo files of the session. Zero means every start is refused.
// owners are the accounts a folder under it may be owned by: ProgramData
// lets any user create folders, and a root made by hand holds its DACL only
// from the service's first start on.
type serviceHome struct {
	root   string
	owners []*windows.SID
}

// Assigned in Execute before the pipes open.
var serviceDataHome serviceHome

func serviceHomeRoot() (string, error) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(programData, serviceName), nil
}

// prepareServiceHome creates root with the descriptor in sddl, or takes an
// existing root only when it is a plain folder owned by one of owners, and
// then puts that DACL on it. A root somebody else made is refused rather
// than used.
func prepareServiceHome(root, sddl string, owners []*windows.SID) (serviceHome, error) {
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return serviceHome{}, err
	}
	name, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return serviceHome{}, err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	err = windows.CreateDirectory(name, &attributes)
	if err == nil {
		return serviceHome{root: root, owners: owners}, nil
	}
	if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return serviceHome{}, err
	}
	handle, err := openOwnFolder(root, owners, windows.WRITE_DAC)
	if err != nil {
		return serviceHome{}, err
	}
	defer windows.CloseHandle(handle)
	if err := setProtectedDACL(handle, windows.SE_FILE_OBJECT, sddl); err != nil {
		return serviceHome{}, err
	}
	return serviceHome{root: root, owners: owners}, nil
}

// openOwnFolder opens a folder the service writes under, and refuses one
// that is a reparse point or owned by anybody but owners.
func openOwnFolder(path string, owners []*windows.SID, access uint32) (windows.Handle, error) {
	handle, err := openWithoutFollowing(path, windows.READ_CONTROL|access, true)
	if err != nil {
		return windows.InvalidHandle, err
	}
	security, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		windows.CloseHandle(handle)
		return windows.InvalidHandle, err
	}
	owner, _, err := security.Owner()
	if err != nil {
		windows.CloseHandle(handle)
		return windows.InvalidHandle, err
	}
	if !ownedByOneOf(owner, owners) {
		windows.CloseHandle(handle)
		return windows.InvalidHandle, fmt.Errorf("%s is not owned by the service", path)
	}
	return handle, nil
}

func ownedByOneOf(owner *windows.SID, owners []*windows.SID) bool {
	for _, candidate := range owners {
		if sameSID(owner, candidate) {
			return true
		}
	}
	return false
}

// serviceHomeOwners are the accounts a folder the service did not create may
// be owned by: the service's own, or an administrator who made it.
func serviceHomeOwners() ([]*windows.SID, error) {
	var owners []*windows.SID
	for _, kind := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			return nil, err
		}
		owners = append(owners, sid)
	}
	return owners, nil
}

// isLocalDrivePath admits `X:\...` alone: opening a UNC or a device path
// connects where the caller chose before any check runs.
func isLocalDrivePath(path string) bool {
	if len(path) < 3 || path[1] != ':' || path[2] != '\\' {
		return false
	}
	letter := path[0] | 0x20
	return letter >= 'a' && letter <= 'z'
}

// openWithoutFollowing opens path itself, refusing a reparse point anywhere on
// the way. It walks from the volume's root one name at a time, each opened as
// itself relative to the handle of the folder above, so the check holds for
// the objects read whatever names spell them, short or long, and a junction
// planted behind an opened folder is never reached.
func openWithoutFollowing(path string, access uint32, directory bool) (windows.Handle, error) {
	if !isLocalDrivePath(path) {
		return windows.InvalidHandle, fmt.Errorf("%s is not on a local drive", path)
	}
	clean := filepath.Clean(path)
	volume, rest := clean[:len(`X:\`)], clean[len(`X:\`):]
	var names []string
	if rest != "" {
		names = strings.Split(rest, `\`)
	}
	walkAccess := uint32(windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE)
	rootAccess := walkAccess
	if len(names) == 0 {
		rootAccess |= access
	}
	handle, err := openComponent(0, `\??\`+volume, rootAccess, true)
	if err != nil {
		return windows.InvalidHandle, err
	}
	for i, name := range names {
		leaf := i == len(names)-1
		if err := refuseReparsePoint(handle, path, "reached through a reparse point"); err != nil {
			windows.CloseHandle(handle)
			return windows.InvalidHandle, err
		}
		childAccess, childDirectory := walkAccess, true
		if leaf {
			childAccess, childDirectory = walkAccess|access, directory
		}
		child, err := openComponent(handle, name, childAccess, childDirectory)
		windows.CloseHandle(handle)
		if err != nil {
			return windows.InvalidHandle, err
		}
		handle = child
	}
	if err := refuseReparsePoint(handle, path, "a reparse point"); err != nil {
		windows.CloseHandle(handle)
		return windows.InvalidHandle, err
	}
	return handle, nil
}

// openComponent opens name, relative to folder unless folder is zero, as
// itself rather than what it points to.
func openComponent(folder windows.Handle, name string, access uint32, directory bool) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	// Identification level: a pipe server at the leaf cannot act as the
	// service.
	qualityOfService := windows.SECURITY_QUALITY_OF_SERVICE{
		Length:             uint32(unsafe.Sizeof(windows.SECURITY_QUALITY_OF_SERVICE{})),
		ImpersonationLevel: windows.SecurityIdentification,
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: folder,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE,
		SecurityQoS:   &qualityOfService,
	}
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_NON_DIRECTORY_FILE)
	if directory {
		options = windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_DIRECTORY_FILE
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access, &attributes, &status, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN, options, 0, 0)
	if err != nil {
		var ntStatus windows.NTStatus
		if errors.As(err, &ntStatus) {
			err = ntStatus.Errno()
		}
		return windows.InvalidHandle, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return handle, nil
}

func refuseReparsePoint(handle windows.Handle, path, what string) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is %s", path, what)
	}
	return nil
}

// stageSession makes the folder the next start runs in, under root, holding
// copies of the caller's geo files when a folder was named. A named folder
// must give both files; the engines read nothing else from it. Each start
// gets a fresh folder, since both engines drop their geo matchers only when
// the folder changes; earlier starts' folders are removed first, as far as
// nothing holds them open.
func (h serviceHome) stageSession(callerGeoDir string) (string, error) {
	if h.root == "" {
		return "", errors.New(serviceHomeUnavailableReply)
	}
	sessions := filepath.Join(h.root, serviceSessionsFolder)
	if err := os.Mkdir(sessions, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	handle, err := openOwnFolder(sessions, h.owners, 0)
	if err != nil {
		return "", err
	}
	windows.CloseHandle(handle)
	removeEarlierSessions(sessions)
	session, err := os.MkdirTemp(sessions, "")
	if err != nil {
		return "", err
	}
	if callerGeoDir == "" {
		return session, nil
	}
	for _, fileName := range geoAssetFileNames {
		if err := copyWithoutFollowing(filepath.Join(callerGeoDir, fileName), filepath.Join(session, fileName)); err != nil {
			os.RemoveAll(session)
			return "", err
		}
	}
	return session, nil
}

// removeEarlierSessions empties the sessions folder. An entry that is not a
// plain folder is unlinked as itself, never walked into.
func removeEarlierSessions(sessions string) {
	entries, err := os.ReadDir(sessions)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path := filepath.Join(sessions, entry.Name())
		if !entry.Type().IsDir() {
			os.Remove(path)
			continue
		}
		// mihomo holds the first session's cache.db open for the life of the
		// process, so that folder stays until the service restarts.
		os.RemoveAll(path)
	}
}

func copyWithoutFollowing(src, dst string) error {
	handle, err := openWithoutFollowing(src, windows.GENERIC_READ, false)
	if err != nil {
		return err
	}
	source := os.NewFile(uintptr(handle), src)
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return err
	}
	if info.Size() > geoAssetFileSizeLimit {
		return fmt.Errorf("%s is over %d bytes", src, geoAssetFileSizeLimit)
	}
	target, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	// A file can grow after the look, so the read is bounded too.
	if _, err := io.Copy(target, io.LimitReader(source, geoAssetFileSizeLimit)); err != nil {
		target.Close()
		return err
	}
	return target.Close()
}

// stageGeoAssets rewrites a start request to run in the service's own folder,
// and answers the reply a refused request gets. The cause goes nowhere: a log
// line reaches the caller's event pipe as the reply does, and either would
// tell the caller what lies behind a path of theirs the service could not
// take.
func stageGeoAssets(req *EngineStartRequest) (refusal string) {
	callerGeoDir := geoAssetsDirOpt(req.Opts["geoAssetsDir"])
	session, err := serviceDataHome.stageSession(callerGeoDir)
	if err != nil {
		refusal = geoAssetsRefusedReply
		if serviceDataHome.root == "" {
			refusal = serviceHomeUnavailableReply
		}
		logfmt.Errorf("[service] refused a start: %s", refusal)
		return refusal
	}
	if req.Opts == nil {
		req.Opts = map[string]string{}
	}
	req.Opts["geoAssetsDir"] = session
	return ""
}

// proxyWithoutCredentials is true of a start that would bind a loopback
// inbound every local account could use.
func proxyWithoutCredentials(req EngineStartRequest) bool {
	return proxyPortFromOpts(req.Opts) > 0 &&
		(strings.TrimSpace(req.Opts["proxyUser"]) == "" || strings.TrimSpace(req.Opts["proxyPass"]) == "")
}
