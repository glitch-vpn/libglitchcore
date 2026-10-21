package mihomoconfig

import (
	"os"
	"strings"
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// The link lives in testdata: Defender on Windows quarantines a test binary
// that embeds some share links.
func TestBuildConfig_ParseErrorDropsTheLink(t *testing.T) {
	data, err := os.ReadFile("testdata/unparsable_link.txt")
	if err != nil {
		t.Fatal(err)
	}
	var link string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			link = line
		}
	}
	_, err = BuildConfig([]string{link}, Inbound{MixedPort: 7890}, Options{}, routing.Profile{})
	if err == nil {
		t.Fatal("BuildConfig accepted a link with a bad port")
	}
	for _, secret := range []string{"Hy2SmokePass", "ObfsSmokePass"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error carries %q: %v", secret, err)
		}
	}
	if !strings.Contains(err.Error(), "invalid port") {
		t.Errorf("error lost its reason: %v", err)
	}
}
