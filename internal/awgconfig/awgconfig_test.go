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

func TestParseToUAPI_LegacyConfig(t *testing.T) {
	uapi, err := ParseToUAPI(legacyAwgConfig)
	if err != nil {
		t.Fatalf("ParseToUAPI(legacy): %v", err)
	}

	required := []string{
		"replace_peers=true",
		"listen_port=92",
		"jc=5",
		"jmin=50",
		"jmax=1000",
		"s1=93",
		"s2=39",
		"h1=2040038216",
		"h2=204946629",
		"h3=1494114136",
		"h4=1794200446",
		"endpoint=198.51.100.10:92",
		"persistent_keepalive_interval=25",
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
	}
	for _, want := range required {
		if !strings.Contains(uapi, want) {
			t.Fatalf("legacy UAPI missing %q\n%s", want, uapi)
		}
	}
}

func TestParseToUAPI_AWG2Config(t *testing.T) {
	uapi, err := ParseToUAPI(awg2Config)
	if err != nil {
		t.Fatalf("ParseToUAPI(awg2): %v", err)
	}

	required := []string{
		"listen_port=585",
		"jc=7",
		"jmin=12",
		"jmax=48",
		"s1=32",
		"s2=48",
		"s3=64",
		"s4=96",
		"h1=1500000000-1500000999",
		"h2=1500001000-1500001999",
		"h3=1500002000-1500002999",
		"h4=1500003000-1500003999",
		"i1=<b 0xf6ab3267fa><c><b 0xf6ab><t><r 10>",
		"endpoint=awg.example.com:585",
	}
	for _, want := range required {
		if !strings.Contains(uapi, want) {
			t.Fatalf("AWG2 UAPI missing %q\n%s", want, uapi)
		}
	}
}

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

func TestParseToUAPI_AWG3Config(t *testing.T) {
	uapi, err := ParseToUAPI(awg3Config)
	if err != nil {
		t.Fatalf("ParseToUAPI(awg3): %v", err)
	}

	required := []string{
		"s4=23",
		"i1=<b 0xc30000000108><rc 8><t>",
		"header_protection_key=d770613816070c0505d55816d9fddc6f8757187492482c1293961eb923fa3925",
		"content_padding_addition=0-64",
		"rekey_after_time=110-130",
		"rekey_timeout=4-6",
		"reject_after_time=170-190",
		"keepalive_timeout=9-11",
		"max_handshake_attempts=15-20",
		"random_trailers=true",
		"disable_cookies=false",
		"persistent_keepalive_interval=22-30",
	}
	for _, want := range required {
		if !strings.Contains(uapi, want+"\n") {
			t.Fatalf("AWG3 UAPI missing %q\n%s", want, uapi)
		}
	}
}

func TestParseToUAPI_Refusals(t *testing.T) {
	for name, cfg := range map[string]string{
		"AWG 1.5 itime": strings.Replace(awg2Config, "S4 = 96", "S4 = 96\nItime = 12", 1),
		"AWG 1.5 j1":    strings.Replace(awg2Config, "S4 = 96", "S4 = 96\nJ1 = <r 16>", 1),
		"bad boolean":   strings.Replace(awg3Config, "RandomTrailers = on", "RandomTrailers = maybe", 1),
		"short key":     strings.Replace(awg3Config, "13BhOBYHDAUF1VgW2f3cb4dXGHSSSCwSk5YeuSP6OSU=", "c2hvcnQ=", 1),
		"bad range":     strings.Replace(awg3Config, "RekeyTimeout = 4-6", "RekeyTimeout = 6-4", 1),
		"word timing":   strings.Replace(awg3Config, "KeepaliveTimeout = 9-11", "KeepaliveTimeout = ten", 1),
	} {
		if uapi, err := ParseToUAPI(cfg); err == nil {
			t.Errorf("%s: want an error, got\n%s", name, uapi)
		}
	}
}

// UAPI is line-based and the device quotes a line it cannot read, so a value
// with a control character is refused before it could carry a key into an error.
func TestParseToUAPI_RefusesControlCharacters(t *testing.T) {
	const privateKey = "UqX1+GfjpHXk0TC7KI4s11YRL3WKJudP0ebnvmVu4aY="
	for name, cfg := range map[string]string{
		"carriage return": strings.Replace(awg3Config, "Jc = 4", "Jc = 4\rprivate_key=00", 1),
		"NUL":             strings.Replace(awg3Config, "I1 = <b 0xc30000000108>", "I1 = <b 0xc3\x00>", 1),
		"escape":          strings.Replace(awg3Config, "S4 = 23", "S4 = 2\x1b3", 1),
	} {
		uapi, err := ParseToUAPI(cfg)
		if err == nil {
			t.Errorf("%s: want an error, got\n%s", name, uapi)
			continue
		}
		if strings.Contains(err.Error(), privateKey) {
			t.Errorf("%s: the error quotes the private key: %v", name, err)
		}
	}

	if _, err := ParseToUAPI(strings.Replace(awg2Config, "0.0.0.0/0, ::/0", "0.0.0.0/0,\t::/0", 1)); err != nil {
		t.Errorf("a tab inside a value: %v", err)
	}
}

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

func TestParseToUAPI_KeepaliveOff(t *testing.T) {
	uapi, err := ParseToUAPI(strings.Replace(awg2Config, "PersistentKeepalive = 25", "PersistentKeepalive = off", 1))
	if err != nil {
		t.Fatalf("ParseToUAPI: %v", err)
	}
	if strings.Contains(uapi, "persistent_keepalive_interval") {
		t.Fatalf("keepalive off must send no interval:\n%s", uapi)
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

func TestParseToUAPI_PreservesSpecialPacketSignature(t *testing.T) {
	custom := strings.Replace(awg2Config, "<b 0xf6ab3267fa><c><b 0xf6ab><t><r 10>", "<q 0xf6ab3267fa>", 1)

	uapi, err := ParseToUAPI(custom)
	if err != nil {
		t.Fatalf("ParseToUAPI(custom i1): %v", err)
	}
	if !strings.Contains(uapi, "i1=<q 0xf6ab3267fa>") {
		t.Fatalf("custom I1 was not preserved in UAPI output\n%s", uapi)
	}
}

func TestAddress_PrefersFirstAddress(t *testing.T) {
	cfg := `
[Interface]
Address = 10.10.0.2/32, fddd:1194:1194:1196::2/128
`

	if got := Address(cfg); got != "10.10.0.2/32" {
		t.Fatalf("Address() = %q, want %q", got, "10.10.0.2/32")
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
	if _, err := ParseToUAPI(ini); err != nil {
		t.Fatalf("ParseToUAPI on decoded link config: %v", err)
	}
}

func TestNormalizeToINI_Errors(t *testing.T) {
	if _, err := NormalizeToINI("awg://!!!not-base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64 link")
	}
}

func TestEndpointHostAndDNS(t *testing.T) {
	if got := EndpointHost(awg2Config); got != "awg.example.com" {
		t.Fatalf("EndpointHost() = %q, want %q", got, "awg.example.com")
	}
	if got := DNS(awg2Config); got != "9.9.9.9" {
		t.Fatalf("DNS() = %q, want %q", got, "9.9.9.9")
	}
}

func TestLastHandshakeUnix(t *testing.T) {
	dump := "private_key=ab\npublic_key=cd\nlast_handshake_time_sec=1751900000\nlast_handshake_time_nsec=12345\nrx_bytes=10\npublic_key=ef\nlast_handshake_time_sec=1751900555\ntx_bytes=20\n"
	if got := LastHandshakeUnix(dump); got != 1751900555 {
		t.Fatalf("LastHandshakeUnix = %d, want newest peer 1751900555", got)
	}
	if got := LastHandshakeUnix("public_key=ab\nrx_bytes=1\n"); got != 0 {
		t.Fatalf("LastHandshakeUnix(no handshake) = %d, want 0", got)
	}
}
