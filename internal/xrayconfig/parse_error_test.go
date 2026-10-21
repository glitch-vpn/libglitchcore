package xrayconfig

import (
	"os"
	"strings"
	"testing"
)

// The link lives in testdata: Defender on Windows quarantines a test binary
// that embeds some share links.
func readUnparsableLink(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/unparsable_link.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			return line
		}
	}
	t.Fatal("no link in testdata/unparsable_link.txt")
	return ""
}

func TestBuildConfig_ParseErrorDropsTheLink(t *testing.T) {
	link := readUnparsableLink(t)
	_, err := BuildConfig([]string{link}, BalancerOptions{}, RoutingProfile{}, "warning")
	if err == nil {
		t.Fatal("BuildConfig accepted a link with a bad port")
	}
	for _, secret := range []string{"b831381d-6324-4d53-ad4f-8cda48b30811", "Qzm3mXq2Gk5n0yR7vT1cF8hJ4pL6sW9aBxDeNuIoKtE", "6ba85179e30d4fc2"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error carries %q: %v", secret, err)
		}
	}
	if !strings.Contains(err.Error(), "invalid port") {
		t.Errorf("error lost its reason: %v", err)
	}
}
