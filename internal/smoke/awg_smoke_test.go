//go:build integration

package smoke

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/crypto/curve25519"

	"github.com/glitch-vpn/libglitchcore/internal/core"
	"github.com/glitch-vpn/libglitchcore/internal/pinger"
)

const awgServerAddr = "10.66.0.1"

// The AWG 3.x settings both ends must share, in UAPI form. Header protection
// needs S1-S4 of 12 or more; random trailers on one end only drop every
// handshake.
const awg3SharedUAPI = "s1=15\ns2=18\ns3=20\ns4=23\nh1=100-200\nh2=300-400\nh3=500-600\nh4=700-800\nrandom_trailers=true\n"

// awg3SharedINI is awg3SharedUAPI as the client's config writes it.
const awg3SharedINI = "S1 = 15\nS2 = 18\nS3 = 20\nS4 = 23\nH1 = 100-200\nH2 = 300-400\nH3 = 500-600\nH4 = 700-800\nRandomTrailers = on\n"

type awgKey [32]byte

func newAwgKey(t *testing.T) (private, public awgKey) {
	t.Helper()
	if _, err := rand.Read(private[:]); err != nil {
		t.Fatal(err)
	}
	private[0] &= 248
	private[31] = private[31]&127 | 64
	pub, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(public[:], pub)
	return private, public
}

func (k awgKey) hex() string    { return hex.EncodeToString(k[:]) }
func (k awgKey) base64() string { return base64.StdEncoding.EncodeToString(k[:]) }

// startAwg3Server runs an amneziawg-go 3.x peer on loopback UDP whose own
// netstack answers HTTP at awgServerAddr with body: a reply proves the request
// crossed the tunnel, since nothing else can reach that address. It returns
// the client config.
func startAwg3Server(t *testing.T, body string) string {
	t.Helper()
	serverPrivate, serverPublic := newAwgKey(t)
	clientPrivate, clientPublic := newAwgKey(t)
	var headerKey awgKey
	if _, err := rand.Read(headerKey[:]); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)

	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(awgServerAddr)}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\n"+awg3SharedUAPI+
		"header_protection_key=%s\npublic_key=%s\nallowed_ip=10.66.0.2/32\n",
		serverPrivate.hex(), port, headerKey.hex(), clientPublic.hex())
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatalf("server IpcSet: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	ln, err := tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP(awgServerAddr), Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.66.0.2/32\nJc = 3\nJmin = 40\nJmax = 70\n"+awg3SharedINI+
		"HeaderProtectionKey = %s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:%d\nPersistentKeepalive = 20-25\n",
		clientPrivate.base64(), headerKey.base64(), serverPublic.base64(), port)
}

// An AWG 3.x config with header protection reaches its server through
// mihomo's 3.x device, and the ping reaches it the same way.
func TestSmoke_Mihomo_AmneziaWG3(t *testing.T) {
	core.Initialize()
	ini := startAwg3Server(t, "198.51.100.66")
	echoURL := "http://" + awgServerAddr + "/"
	ev := captureEvents(t)

	startEngineInProxyMode(t, "mihomo", ini, map[string]string{
		"probeUrl":    echoURL,
		"ipv4EchoUrl": echoURL,
		"disableIPv6": "1",
	}, nil)
	ev.waitFor(t, core.EngineConnected, 30*time.Second)

	var ip struct {
		IPv4      string `json:"ipv4"`
		IPv4Error string `json:"ipv4Error"`
	}
	if err := json.Unmarshal([]byte(ev.waitFor(t, core.IPEvent, 30*time.Second)), &ip); err != nil {
		t.Fatalf("IPEvent JSON: %v", err)
	}
	if ip.IPv4 != "198.51.100.66" {
		t.Fatalf("ipv4 = %q (err %q)", ip.IPv4, ip.IPv4Error)
	}

	results := pinger.Measure(pinger.Request{Links: []string{ini}, ProbeURL: echoURL, TimeoutMs: 5000})
	if len(results) != 1 || !results[0].Alive {
		t.Fatalf("ping = %+v", results)
	}
}
