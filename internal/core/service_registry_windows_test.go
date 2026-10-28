//go:build service && windows

package core

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestServicePipeNamesAreDrawnAfreshEachStart(t *testing.T) {
	first, err := newServicePipeNames()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newServicePipeNames()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two starts drew the same names")
	}
	for _, name := range []string{first.command, first.event} {
		if !strings.HasPrefix(name, servicePipePrefix) {
			t.Errorf("%s is not under %s", name, servicePipePrefix)
		}
	}
}

// removeProtectedKey grants the test's own account the key back, which its
// owner may always do, so the key can be deleted.
func removeProtectedKey(t *testing.T, location registryLocation) {
	t.Helper()
	user, _ := currentProcessUser(t)
	key, err := registry.OpenKey(location.root, location.path, windows.WRITE_DAC)
	if err != nil {
		t.Errorf("open the test key: %v", err)
		return
	}
	err = setProtectedDACL(windows.Handle(key), windows.SE_REGISTRY_KEY, "D:P(A;OICI;KA;;;"+user.String()+")")
	key.Close()
	if err != nil {
		t.Errorf("take the test key back: %v", err)
		return
	}
	if err := registry.DeleteKey(location.root, location.path); err != nil {
		t.Errorf("delete the test key: %v", err)
	}
}

func TestPublishedPipeNamesAreReadableAndOnlyLocalSystemWritesThem(t *testing.T) {
	if _, elevated := currentProcessUser(t); elevated {
		t.Skip("an elevated process may write the key as an administrator")
	}
	// The same test key as publishTestPipeName in ipc_windows_client_test.go,
	// which builds without the service tag.
	location := registryLocation{root: registry.CURRENT_USER, path: fmt.Sprintf(`Software\glitch_vpn_core_test_%d`, os.Getpid())}
	names, err := newServicePipeNames()
	if err != nil {
		t.Fatal(err)
	}
	if err := publishServicePipes(location, names); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeProtectedKey(t, location) })

	key, err := registry.OpenKey(location.root, location.path, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("a signed-in account cannot read the names: %v", err)
	}
	defer key.Close()
	for value, want := range map[string]string{commandPipeValueName: names.command, eventPipeValueName: names.event} {
		if got, _, err := key.GetStringValue(value); err != nil || got != want {
			t.Errorf("%s = %q (%v), want %q", value, got, err, want)
		}
	}

	writable, err := registry.OpenKey(location.root, location.path, registry.SET_VALUE)
	if err == nil {
		writable.Close()
		t.Fatal("an ordinary account may write the names")
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("open for writing failed with %v, want access denied", err)
	}
}
