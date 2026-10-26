package logfmt

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// The made-up credentials in testdata/engine_lines.txt; the smoke run that
// recorded it defines them (internal/smoke/secrets_smoke_test.go, testUUID).
var recordedSecrets = []string{
	"b831381d-6324-4d53-ad4f-8cda48b30811",
	"Qzm3mXq2Gk5n0yR7vT1cF8hJ4pL6sW9aBxDeNuIoKtE",
	"6ba85179e30d4fc2",
	"Hy2SmokePass",
	"ObfsSmokePass",
	"k3fZ0qLmX9aB2cD4",
	"Wq9rT2yU4iO6pA8sD0fG2hJ4kL6zX8cV0bN2mQ4wE6r",
	"cHJpdmF0ZV9rZXk9WUJrM2pSbUt2Wlo5aEo2c1dEcU9McnpQb1RqN0ZnMXg=",
	"58e6a6a7f6d4c3b2a1908f7e6d5c4b3a29180f7e6d5c4b3a29180f7e6d5c4b3a",
	"0d1c2b3a49586776859a4b3c2d1e0f1a2b3c4d5e6f708192a3b4c5d6e7f80910",
}

func readRecordedLines(t *testing.T) []string {
	t.Helper()
	f, err := os.Open("testdata/engine_lines.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimRight(sc.Text(), "\r"); line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}

func TestScrub_RecordedEngineLines(t *testing.T) {
	lines := readRecordedLines(t)
	withSecret := 0
	for _, line := range lines {
		got := Scrub(line)
		carried := false
		for _, secret := range recordedSecrets {
			if strings.Contains(line, secret) {
				carried = true
			}
			if strings.Contains(got, secret) {
				t.Errorf("Scrub kept %q:\n  in:  %s\n  out: %s", secret, line, got)
			}
		}
		if carried {
			withSecret++
		} else if got != line {
			t.Errorf("Scrub changed a line with no credential:\n  in:  %s\n  out: %s", line, got)
		}
		if again := Scrub(got); again != got {
			t.Errorf("Scrub is not idempotent:\n  once:  %s\n  twice: %s", got, again)
		}
	}
	if withSecret < 6 || len(lines)-withSecret < 40 {
		t.Fatalf("fixture too thin: %d lines with a credential, %d without", withSecret, len(lines)-withSecret)
	}
}

// testdata/scrub_cases.txt pairs an "in:" line with the "out:" line Scrub must
// make of it. The cases live outside the test binary: on Windows, Defender
// quarantines a binary that embeds some of these links.
func TestScrub_Cases(t *testing.T) {
	data, err := os.ReadFile("testdata/scrub_cases.txt")
	if err != nil {
		t.Fatal(err)
	}
	var in string
	cases := 0
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "in: "):
			in = strings.TrimPrefix(line, "in: ")
		case strings.HasPrefix(line, "out: "):
			want := strings.TrimPrefix(line, "out: ")
			cases++
			got := Scrub(in)
			if got != want {
				t.Errorf("Scrub(%s)\n  = %s\n want %s", in, got, want)
			}
			if again := Scrub(got); again != got {
				t.Errorf("Scrub is not idempotent on %s: %s", got, again)
			}
		}
	}
	if cases < 15 {
		t.Fatalf("only %d cases read", cases)
	}
}

func TestScrub_VLESSEncryptionValue(t *testing.T) {
	key := "adGhUAyxxTYcoUlMXPFrYxmBFBXLOoZXcLTLcWyiZmc"
	value := "mlkem768x25519plus.native.0rtt." + key
	for name, line := range map[string]string{
		"xray":          `failed to build outbound handler for protocol vless > VLESS users: unsupported "encryption": ` + value,
		"xray_inbound":  `VLESS users: unsupported "decryption": ` + value,
		"mihomo":        "invaild vless encryption value: " + value,
		"mihomo_assign": "proxy 0: vless: encryption=" + value,
		"json":          `{"encryption":"` + value + `"}`,
	} {
		got := Scrub(line)
		if strings.Contains(got, key) {
			t.Errorf("%s: Scrub kept the key:\n  in:  %s\n  out: %s", name, line, got)
		}
	}
}
