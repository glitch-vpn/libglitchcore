package awgconfig

import (
	"strings"
	"testing"
)

const legacyAwgConfig = `
[Interface]
PrivateKey = a6xUoLqmrM8M6u1rPz4CWlZjv8M8IuB+V4d7R8m9Q2E=
Address = 10.10.0.2/32
DNS = 1.1.1.1
ListenPort = 92
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 93
S2 = 39
H1 = 2040038216
H2 = 204946629
H3 = 1494114136
H4 = 1794200446

[Peer]
PublicKey = PWEhTF7yxU0YzM0mEi2p734Y5arywtdKKQ9D15BQLkY=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 198.51.100.10:92
PersistentKeepalive = 25
`

const awg2Config = `
[Interface]
PrivateKey = a6xUoLqmrM8M6u1rPz4CWlZjv8M8IuB+V4d7R8m9Q2E=
Address = 10.10.0.2/32
DNS = 9.9.9.9
ListenPort = 585
Jc = 7
Jmin = 12
Jmax = 48
S1 = 32
S2 = 48
S3 = 64
S4 = 96
H1 = 1500000000-1500000999
H2 = 1500001000-1500001999
H3 = 1500002000-1500002999
H4 = 1500003000-1500003999
I1 = <b 0xf6ab3267fa><c><b 0xf6ab><t><r 10>

[Peer]
PublicKey = PWEhTF7yxU0YzM0mEi2p734Y5arywtdKKQ9D15BQLkY=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = awg.example.com:585
PersistentKeepalive = 25
`

const awg3Config = `
[Interface]
PrivateKey = UqX1+GfjpHXk0TC7KI4s11YRL3WKJudP0ebnvmVu4aY=
Address = 10.10.0.2/32
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 18
S3 = 20
S4 = 23
H1 = 100-200
H2 = 300-400
H3 = 500-600
H4 = 700-800
I1 = <b 0xc30000000108><rc 8><t>
HeaderProtectionKey = 13BhOBYHDAUF1VgW2f3cb4dXGHSSSCwSk5YeuSP6OSU=
ContentPaddingAddition = 0-64
RekeyAfterTime = 110-130
RekeyTimeout = 4-6
RejectAfterTime = 170-190
KeepaliveTimeout = 9-11
MaxHandshakeAttempts = 15-20
RandomTrailers = on
DisableCookies = off

[Peer]
PublicKey = ys6ln6BOSOotjcRKGYel/HW/HQ65w+bAg8ac9VVtLWo=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.9:51820
PersistentKeepalive = 22-30
`

func TestKeyBytesAndCheckRange(t *testing.T) {
	hexKey := strings.Repeat("ab", 32)
	if b, err := KeyBytes(hexKey); err != nil || len(b) != 32 {
		t.Errorf("KeyBytes(hex) = %d bytes, %v", len(b), err)
	}
	for _, bad := range []string{"c2hvcnQ=", strings.Repeat("ab", 33), "not a key"} {
		if _, err := KeyBytes(bad); err == nil {
			t.Errorf("KeyBytes(%q): want an error", bad)
		}
	}
	for _, good := range []string{"0", "4294967295", "10-20", "7-7"} {
		if err := CheckRange(good); err != nil {
			t.Errorf("CheckRange(%q): %v", good, err)
		}
	}
	for _, bad := range []string{"", "-", "20-10", "4294967296", "1-2-3", "a-b", " 5"} {
		if err := CheckRange(bad); err == nil {
			t.Errorf("CheckRange(%q): want an error", bad)
		}
	}
}

func TestParseBool(t *testing.T) {
	for in, want := range map[string]bool{"on": true, "OFF": false, "true": true, "false": false, "1": true, "0": false, " 2 ": true} {
		if got, err := ParseBool(in); err != nil || got != want {
			t.Errorf("ParseBool(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "yes", "-1"} {
		if _, err := ParseBool(in); err == nil {
			t.Errorf("ParseBool(%q): want an error", in)
		}
	}
}

func TestNormalizeToINI_PassthroughAndLink(t *testing.T) {
	if got, err := NormalizeToINI(awg2Config); err != nil || got != awg2Config {
		t.Fatalf("raw INI must pass through unchanged (err=%v, changed=%v)", err, got != awg2Config)
	}

	link := EncodeLink(awg2Config, "My Server")
	if !strings.HasPrefix(link, LinkScheme) {
		t.Fatalf("EncodeLink produced %q, want %s prefix", link, LinkScheme)
	}
	ini, err := NormalizeToINI(link)
	if err != nil {
		t.Fatalf("NormalizeToINI(link): %v", err)
	}
	if ini != awg2Config {
		t.Fatalf("round-trip mismatch:\n got: %q\nwant: %q", ini, awg2Config)
	}
}

func TestNormalizeToINI_Errors(t *testing.T) {
	if _, err := NormalizeToINI("awg://!!!not-base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64 link")
	}
}
