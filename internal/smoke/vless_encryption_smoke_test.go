//go:build integration

package smoke

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
)

// vlessEncryptionPair returns the server's decryption string and the client's
// encryption value for one key pair, the mode and ticket named.
func vlessEncryptionPair(t *testing.T, postQuantum bool, mode, serverTicket, clientTicket string) (decryption, encryption string) {
	t.Helper()
	var serverKey, clientKey []byte
	if postQuantum {
		seed := make([]byte, mlkem.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			t.Fatal(err)
		}
		private, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			t.Fatal(err)
		}
		serverKey, clientKey = seed, private.EncapsulationKey().Bytes()
	} else {
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serverKey, clientKey = private.Bytes(), private.PublicKey().Bytes()
	}
	encode := base64.RawURLEncoding.EncodeToString
	decryption = fmt.Sprintf("mlkem768x25519plus.%s.%s.%s", mode, serverTicket, encode(serverKey))
	encryption = fmt.Sprintf("mlkem768x25519plus.%s.%s.%s", mode, clientTicket, encode(clientKey))
	return decryption, encryption
}

// A link naming VLESS encryption runs it: the exit address echo crosses the
// encrypted hop on a loopback server that refuses plain VLESS, with no TLS.
func TestSmoke_VLESSEncryption(t *testing.T) {
	cases := []struct {
		name         string
		postQuantum  bool
		mode         string
		serverTicket string
		clientTicket string
	}{
		{"x25519_native_0rtt", false, "native", "600s", "0rtt"},
		{"x25519_xorpub_1rtt", false, "xorpub", "600s", "1rtt"},
		{"mlkem_random_0rtt", true, "random", "600s", "0rtt"},
		{"mlkem_native_1rtt", true, "native", "600s", "1rtt"},
	}
	for _, engine := range []string{"xray", "mihomo"} {
		for _, tc := range cases {
			t.Run(engine+"/"+tc.name, func(t *testing.T) {
				core.Initialize()
				ev := captureEvents(t)

				decryption, encryption := vlessEncryptionPair(t, tc.postQuantum, tc.mode, tc.serverTicket, tc.clientTicket)
				upstream := startVlessServerWithDecryption(t, decryption)
				probe := echoBody(t, "probe")
				echo := echoBody(t, "198.51.100.48")
				link := fmt.Sprintf("vless://%s@127.0.0.1:%d?type=tcp&encryption=%s#Encrypted", testUUID, upstream, encryption)
				startEngineInProxyMode(t, engine, link, map[string]string{
					"probeUrl":    probe.URL,
					"ipv4EchoUrl": echo.URL,
					"disableIPv6": "1",
				}, nil)
				ev.waitFor(t, core.EngineConnected, 30*time.Second)

				var ip struct {
					IPv4      string `json:"ipv4"`
					IPv4Error string `json:"ipv4Error"`
				}
				if err := json.Unmarshal([]byte(ev.waitFor(t, core.IPEvent, 45*time.Second)), &ip); err != nil {
					t.Fatalf("IPEvent JSON: %v", err)
				}
				if ip.IPv4 != "198.51.100.48" {
					t.Fatalf("ipv4 = %q (err %q)", ip.IPv4, ip.IPv4Error)
				}
			})
		}
	}
}
