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

func TestParseToUAPI_QuicCpsI1WithItime(t *testing.T) {
	cfg := strings.Replace(
		awg2Config,
		"I1 = <b 0xf6ab3267fa><c><b 0xf6ab><t><r 10>",
		"I1 = <b 0xf6ab3267fa><c><b 0xf6ab><t><r 10>\nItime = 12",
		1,
	)

	uapi, err := ParseToUAPI(cfg)
	if err != nil {
		t.Fatalf("ParseToUAPI(awg2+itime): %v", err)
	}
	if !strings.Contains(uapi, "i1=<b 0xf6ab3267fa><c><b 0xf6ab><t><r 10>") {
		t.Fatalf("CPS-encoded I1 missing in UAPI:\n%s", uapi)
	}
	if !strings.Contains(uapi, "itime=12") {
		t.Fatalf("itime missing in UAPI:\n%s", uapi)
	}
}

func TestParseToUAPI_OmitsItimeWhenAbsent(t *testing.T) {
	uapi, err := ParseToUAPI(awg2Config)
	if err != nil {
		t.Fatalf("ParseToUAPI(awg2): %v", err)
	}
	if strings.Contains(uapi, "itime=") {
		t.Fatalf("itime must not be present when omitted from input config:\n%s", uapi)
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
