//go:build service && windows

package core

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A junction needs no privilege, so an unelevated test can plant one the way
// a served user would.
func makeJunction(t *testing.T, link, target string) {
	t.Helper()
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		t.Skipf("mklink /J is not available here: %v: %s", err, out)
	}
}

// tokenOwner is TOKEN_OWNER, which x/sys/windows does not declare.
type tokenOwner struct {
	Owner *windows.SID
}

// createdObjectOwner is the owner a folder the test creates gets: the token's
// default owner, which is the user unelevated and the Administrators group
// elevated, as on the GitHub runner.
func createdObjectOwner(t *testing.T) *windows.SID {
	t.Helper()
	token := windows.GetCurrentProcessToken()
	var size uint32
	windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &size)
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &buffer[0], size, &size); err != nil {
		t.Fatal(err)
	}
	owner, err := (*tokenOwner)(unsafe.Pointer(&buffer[0])).Owner.Copy()
	if err != nil {
		t.Fatal(err)
	}
	return owner
}

// writePlaceholderGeoFiles writes the two names the copy reads, with bytes no
// engine parses.
func writePlaceholderGeoFiles(t *testing.T, dir string) {
	t.Helper()
	for _, name := range geoAssetFileNames {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("geo "+name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// ownSDDL admits the test's created-object owner alone, as the service's
// descriptor admits LocalSystem and the Administrators: what the service's
// would lock an unelevated test out of.
func ownSDDL(t *testing.T) string {
	return fmt.Sprintf("D:P(A;OICI;FA;;;%s)", createdObjectOwner(t))
}

// testServiceHome gives the service a root the test owns, as the installed
// service owns its own under ProgramData. mihomo holds its cache.db open for
// the life of the process, so the root's removal is best effort.
func testServiceHome(t *testing.T) serviceHome {
	t.Helper()
	base, err := os.MkdirTemp("", "glitch-service-home-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	root := filepath.Join(base, "root")
	home, err := prepareServiceHome(root, ownSDDL(t), []*windows.SID{createdObjectOwner(t)})
	if err != nil {
		t.Fatal(err)
	}
	previous := serviceDataHome
	serviceDataHome = home
	t.Cleanup(func() { serviceDataHome = previous })
	return home
}

func TestServiceHome_PrepareCreatesOrAdoptsOwnRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	me := createdObjectOwner(t)
	if _, err := prepareServiceHome(root, ownSDDL(t), nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := prepareServiceHome(root, ownSDDL(t), []*windows.SID{me}); err != nil {
		t.Fatalf("adopt a root of the owner's: %v", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareServiceHome(root, ownSDDL(t), []*windows.SID{system}); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("a root owned by somebody else must be refused, got %v", err)
	}
}

func TestServiceHome_PrepareRefusesAJunctionAsRoot(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "root")
	makeJunction(t, link, target)
	if _, err := prepareServiceHome(link, ownSDDL(t), []*windows.SID{createdObjectOwner(t)}); err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("a junction as root must be refused, got %v", err)
	}
}

func TestServiceHome_StageCopiesTheCallersGeoFiles(t *testing.T) {
	home := testServiceHome(t)
	caller := t.TempDir()
	writePlaceholderGeoFiles(t, caller)

	session, err := home.stageSession(caller)
	if err != nil {
		t.Fatal(err)
	}
	if rel, err := filepath.Rel(home.root, session); err != nil || !filepath.IsLocal(rel) {
		t.Fatalf("session %q is not under the root %q", session, home.root)
	}
	for _, name := range geoAssetFileNames {
		got, err := os.ReadFile(filepath.Join(session, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "geo "+name {
			t.Fatalf("%s: copied %q", name, got)
		}
	}
	entries, _ := os.ReadDir(caller)
	if len(entries) != len(geoAssetFileNames) {
		t.Fatalf("the caller's folder gained a file: %v", entries)
	}
}

func TestServiceHome_StageRefusesAGeoFolderBehindAJunction(t *testing.T) {
	home := testServiceHome(t)
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	writePlaceholderGeoFiles(t, real)
	link := filepath.Join(base, "link")
	makeJunction(t, link, real)

	if _, err := home.stageSession(link); err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("a folder reached through a junction must be refused, got %v", err)
	}
	if _, err := home.stageSession(filepath.Join(link, "..", "real")); err != nil {
		t.Fatalf("the same folder by its own path: %v", err)
	}
}

func TestServiceHome_StageRefusesAFolderMissingAGeoFile(t *testing.T) {
	home := testServiceHome(t)
	caller := t.TempDir()
	if err := os.WriteFile(filepath.Join(caller, "geoip.dat"), []byte("ip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := home.stageSession(caller); err == nil {
		t.Fatal("a folder without geosite.dat must be refused")
	}
	sessions, _ := os.ReadDir(filepath.Join(home.root, serviceSessionsFolder))
	if len(sessions) != 0 {
		t.Fatalf("a refused start left a session folder: %v", sessions)
	}
}

func TestServiceHome_StageWithoutAFolderGivesAnEmptySession(t *testing.T) {
	home := testServiceHome(t)
	session, err := home.stageSession("")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(session)
	if err != nil || len(entries) != 0 {
		t.Fatalf("expected an empty session folder, got %v, %v", entries, err)
	}
}

func TestServiceHome_StageRemovesEarlierSessions(t *testing.T) {
	home := testServiceHome(t)
	first, err := home.stageSession("")
	if err != nil {
		t.Fatal(err)
	}
	second, err := home.stageSession("")
	if err != nil {
		t.Fatal(err)
	}
	// A removed folder keeps its name while something still holds a handle
	// to it, so the removal is given a moment to settle.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(first); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the earlier session %q remains", first)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := os.Stat(second); err != nil {
		t.Fatal(err)
	}
}

func TestServiceHome_UnpreparedRefusesEveryStart(t *testing.T) {
	previous := serviceDataHome
	serviceDataHome = serviceHome{}
	t.Cleanup(func() { serviceDataHome = previous })
	req := EngineStartRequest{Opts: map[string]string{}}
	if got := stageGeoAssets(&req); got != serviceHomeUnavailableReply {
		t.Fatalf("got %q", got)
	}
}

func TestServiceHome_StageRewritesTheRequestToTheSession(t *testing.T) {
	home := testServiceHome(t)
	caller := t.TempDir()
	writePlaceholderGeoFiles(t, caller)
	req := EngineStartRequest{Opts: map[string]string{"geoAssetsDir": caller}}
	if got := stageGeoAssets(&req); got != "" {
		t.Fatalf("refused: %s", got)
	}
	if rel, err := filepath.Rel(home.root, req.Opts["geoAssetsDir"]); err != nil || !filepath.IsLocal(rel) {
		t.Fatalf("the request still names %q", req.Opts["geoAssetsDir"])
	}
}

func TestServiceDispatch_EngineStart_RefusesAProxyPortWithoutCredentials(t *testing.T) {
	Initialize()
	testServiceHome(t)
	for name, opts := range map[string]map[string]string{
		"none":         {"proxyPort": "1080"},
		"user only":    {"proxyPort": "1080", "proxyUser": "u"},
		"blank secret": {"proxyPort": "1080", "proxyUser": "u", "proxyPass": " "},
	} {
		req, _ := json.Marshal(EngineStartRequest{Config: "vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:1?security=none&type=tcp", Opts: opts})
		payload, _ := json.Marshal(map[string]any{"engineId": "xray", "request": string(req)})
		resp := dispatchCommand(pipeCommand{Action: "engine_start", Payload: payload})
		if resp.OK || resp.Error != proxyWithoutCredentialsReply {
			t.Fatalf("%s: got %+v", name, resp)
		}
		if globalController.Load().engineIsRunning("xray") == glitchCoreResultSuccess {
			t.Fatalf("%s: the engine runs", name)
		}
	}
}

func TestServiceHome_StageRefusesASessionsFolderPlantedAsAJunction(t *testing.T) {
	home := testServiceHome(t)
	victim := t.TempDir()
	if err := os.WriteFile(filepath.Join(victim, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	makeJunction(t, filepath.Join(home.root, serviceSessionsFolder), victim)

	if _, err := home.stageSession(""); err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("a planted sessions junction must be refused, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(victim, "keep.txt")); err != nil {
		t.Fatalf("the junction's target lost a file: %v", err)
	}
}

func TestServiceHome_StageUnlinksAJunctionInsideSessionsWithoutWalkingIt(t *testing.T) {
	home := testServiceHome(t)
	victim := t.TempDir()
	if err := os.WriteFile(filepath.Join(victim, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	sessions := filepath.Join(home.root, serviceSessionsFolder)
	if err := os.Mkdir(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(sessions, "planted")
	makeJunction(t, link, victim)

	if _, err := home.stageSession(""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(victim, "keep.txt")); err != nil {
		t.Fatalf("the junction's target lost a file: %v", err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("the planted junction remains: %v", err)
	}
}

func TestServiceHome_StageRefusesASessionsFolderOwnedByAnother(t *testing.T) {
	home := testServiceHome(t)
	if err := os.Mkdir(filepath.Join(home.root, serviceSessionsFolder), 0o700); err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	home.owners = []*windows.SID{system}
	if _, err := home.stageSession(""); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("a sessions folder of another owner must be refused, got %v", err)
	}
}

func TestServiceHome_StageRefusesAnOversizedGeoFile(t *testing.T) {
	home := testServiceHome(t)
	caller := t.TempDir()
	writePlaceholderGeoFiles(t, caller)
	oversized := filepath.Join(caller, "geoip.dat")
	if out, err := exec.Command("fsutil", "sparse", "setflag", oversized).CombinedOutput(); err != nil {
		t.Skipf("cannot make a sparse file here: %v: %s", err, out)
	}
	if err := os.Truncate(oversized, geoAssetFileSizeLimit+1); err != nil {
		t.Fatal(err)
	}
	if _, err := home.stageSession(caller); err == nil || !strings.Contains(err.Error(), "over") {
		t.Fatalf("an oversized file must be refused, got %v", err)
	}
}

func TestServiceHome_StageRefusesAPathOffALocalDrive(t *testing.T) {
	home := testServiceHome(t)
	for _, dir := range []string{
		`\\localhost\c$\geo`,
		`\\.\pipe\glitch-b0306-probe`,
		`\\?\C:\geo`,
		`\\?\UNC\localhost\c$\geo`,
		`C:geo`,
		`\geo`,
	} {
		if _, err := home.stageSession(dir); err == nil || !strings.Contains(err.Error(), "local drive") {
			t.Fatalf("%s must be refused before any open, got %v", dir, err)
		}
	}
}

func shortPathOf(t *testing.T, path string) string {
	t.Helper()
	long, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(long, &buffer[0], uint32(len(buffer)))
	if err != nil {
		t.Fatal(err)
	}
	return windows.UTF16ToString(buffer[:n])
}

// The GitHub runner's TEMP is itself spelled with short names.
func TestServiceHome_TakesAPathSpelledWithShortNames(t *testing.T) {
	base := filepath.Join(t.TempDir(), "a folder with a long name")
	if err := os.Mkdir(base, 0o700); err != nil {
		t.Fatal(err)
	}
	short := shortPathOf(t, base)
	if strings.EqualFold(short, base) {
		t.Skipf("this volume gives %s no short name", base)
	}
	home, err := prepareServiceHome(filepath.Join(short, "root"), ownSDDL(t), []*windows.SID{createdObjectOwner(t)})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := prepareServiceHome(home.root, ownSDDL(t), home.owners); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	caller := filepath.Join(short, "geo")
	if err := os.Mkdir(caller, 0o700); err != nil {
		t.Fatal(err)
	}
	writePlaceholderGeoFiles(t, caller)
	if _, err := home.stageSession(caller); err != nil {
		t.Fatalf("stage: %v", err)
	}
	link := filepath.Join(base, "a junction with a long name")
	makeJunction(t, link, caller)
	if _, err := home.stageSession(shortPathOf(t, link)); err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("a junction spelled by its short name must be refused, got %v", err)
	}
}

// The tests expect what a created folder really gets as its owner, which
// differs between an unelevated run and the elevated GitHub runner.
func TestServiceHome_CreatedObjectOwnerIsWhatAFolderGets(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "owned")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	security, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := security.Owner()
	if err != nil {
		t.Fatal(err)
	}
	want := createdObjectOwner(t)
	if !got.Equals(want) {
		t.Fatalf("a created folder is owned by %s, the token's default owner is %s", got, want)
	}
}
