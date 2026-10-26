//go:build integration

package smoke

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"testing"

	xrayCore "github.com/xtls/xray-core/core"
)

const wrongUUID = "0e1d2c3b-4a59-4687-9a0b-1c2d3e4f5a6b"

// startVMessServer runs xray's VMess inbound on loopback, over plain TCP or
// over WebSocket at /vm.
func startVMessServer(t *testing.T, network string) int {
	t.Helper()
	port := freePort(t)
	stream := `{"network": "tcp"}`
	if network == "ws" {
		stream = `{"network": "ws", "wsSettings": {"path": "/vm"}}`
	}
	cfg := fmt.Sprintf(`{
		"log": {"loglevel": "warning"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": %d,
			"protocol": "vmess",
			"settings": {"clients": [{"id": %q}]},
			"streamSettings": %s
		}],
		"outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]
	}`, port, testUUID, stream)
	inst, err := xrayCore.StartInstance("json", []byte(cfg))
	if err != nil {
		t.Fatalf("vmess server: %v", err)
	}
	t.Cleanup(func() { _ = inst.Close() })
	return port
}

// Both link forms on both engines: v2rayN's base64 JSON over TCP, and the
// URI form over WebSocket with early data in the path.
func TestSmoke_VMess(t *testing.T) {
	tcpPort := startVMessServer(t, "tcp")
	wsPort := startVMessServer(t, "ws")
	sharedJSON := func(id string) string {
		body := fmt.Sprintf(`{"v":"2","ps":"VMess JSON","add":"127.0.0.1","port":"%d","id":%q,"aid":"0","scy":"auto","net":"tcp","type":"none","tls":""}`, tcpPort, id)
		return "vmess://" + base64.StdEncoding.EncodeToString([]byte(body))
	}
	uriForm := func(id string) string {
		return "vmess://" + id + "@127.0.0.1:" + strconv.Itoa(wsPort) +
			"?type=ws&path=" + url.QueryEscape("/vm?ed=2048") + "&encryption=aes-128-gcm#VMess%20URI"
	}
	for _, engine := range []string{"xray", "mihomo"} {
		t.Run(engine+"/shared_json", func(t *testing.T) {
			assertSessionThrough(t, protocolSession{
				engine: engine, link: sharedJSON(testUUID), protocol: "vmess", port: tcpPort, name: "VMess JSON",
				wrongCredentialLink: sharedJSON(wrongUUID), pingEngine: "xray",
			})
		})
		t.Run(engine+"/uri_ws", func(t *testing.T) {
			assertSessionThrough(t, protocolSession{
				engine: engine, link: uriForm(testUUID), protocol: "vmess", port: wsPort, name: "VMess URI",
				wrongCredentialLink: uriForm(wrongUUID), pingEngine: "xray",
			})
		})
	}
}
