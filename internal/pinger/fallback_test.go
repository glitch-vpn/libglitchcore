package pinger

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A VMess link xray refuses (alterId above 0) is pinged on mihomo, the engine
// the start would carry it on; the server is closed, so the probe fails, but
// the report names the engine and carries no xray refusal.
func TestMeasureRoutesALinkXrayRefusesToMihomo(t *testing.T) {
	if fallback == nil || fallback.engine != "mihomo" {
		t.Skip("needs the mihomo fallback")
	}
	var hasXray bool
	for _, m := range measurers {
		hasXray = hasXray || m.engine == "xray"
	}
	if !hasXray {
		t.Skip("needs xray")
	}

	payload := fmt.Sprintf(`{"v":"2","ps":"legacy","add":"127.0.0.1","port":"1","id":"%s","aid":"2","net":"tcp","type":"none","tls":""}`,
		"49c8fb89-9418-4ff4-8505-7a2772fc4b71")
	legacy := "vmess://" + base64.StdEncoding.EncodeToString([]byte(payload))
	modern := "vmess://" + base64.StdEncoding.EncodeToString([]byte(
		`{"v":"2","ps":"aead","add":"127.0.0.1","port":"1","id":"49c8fb89-9418-4ff4-8505-7a2772fc4b71","aid":"0","net":"tcp","type":"none","tls":""}`))

	got := Measure(Request{Links: []string{legacy, modern}, TimeoutMs: 1500})
	if got[0].Engine != "mihomo" {
		t.Errorf("alterId 2 link: engine = %q, want mihomo", got[0].Engine)
	}
	if got[1].Engine != "xray" {
		t.Errorf("alterId 0 link: engine = %q, want xray", got[1].Engine)
	}
	for _, r := range got {
		if r.Alive {
			t.Errorf("result %d alive against a closed port", r.Index)
		}
	}
	if got[0].Error == "" || strings.Contains(got[0].Error, "legacy handshake") {
		t.Errorf("alterId 2 error = %q, want a dial failure, not xray's refusal", got[0].Error)
	}
}

// A link xray refuses for its safety is not tried on the fallback engine: that
// engine would carry it, with the certificate unchecked or in the clear.
func TestMeasureKeepsASafetyRefusalOnXray(t *testing.T) {
	if fallback == nil || fallback.engine != "mihomo" {
		t.Skip("needs the mihomo fallback")
	}
	var hasXray bool
	for _, m := range measurers {
		hasXray = hasXray || m.engine == "xray"
	}
	if !hasXray {
		t.Skip("needs xray")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var received atomic.Int64
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				n, _ := io.Copy(io.Discard, conn)
				received.Add(n)
			}()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port

	cases := map[string]string{
		"insecure trojan":             fmt.Sprintf("trojan://secret@127.0.0.1:%d?security=tls&sni=a.example&allowInsecure=1", port),
		"plaintext vless":             "vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@8.8.8.8:443?type=tcp&security=none",
		"plaintext trojan":            "trojan://secret@8.8.8.8:443?security=none",
		"insecure trojan, tcp header": fmt.Sprintf("trojan://secret@127.0.0.1:%d?security=tls&allowInsecure=1&headerType=http", port),
		"insecure vless, tcp header":  fmt.Sprintf("vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@127.0.0.1:%d?type=tcp&headerType=http&security=tls&allowInsecure=1", port),
		"insecure vless, h2":          fmt.Sprintf("vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@127.0.0.1:%d?type=h2&security=tls&allowInsecure=1", port),
		"insecure vmess, alterId":     vmessLink(port, `"aid":"2","net":"tcp","tls":"tls","insecure":"1"`),
		"plaintext vless, tcp header": "vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@8.8.8.8:443?type=tcp&headerType=http&security=none",
		"plaintext vless, h2":         "vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@8.8.8.8:443?type=h2&security=none",
	}
	for name, link := range cases {
		got := Measure(Request{Links: []string{link}, TimeoutMs: 1500})[0]
		if got.Engine != "xray" || got.Alive || got.Error == "" {
			t.Errorf("%s: result = %+v, want a refusal reported on xray", name, got)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if n := received.Load(); n != 0 {
		t.Errorf("a refused link sent %d bytes to its server", n)
	}
}

func vmessLink(port int, fields string) string {
	return "vmess://" + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"v":"2","ps":"t","add":"127.0.0.1","port":"%d","id":"49c8fb89-9418-4ff4-8505-7a2772fc4b71",%s}`, port, fields)))
}
