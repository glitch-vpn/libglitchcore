//go:build integration

package smoke

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"testing"
)

const wrongUUID = "0e1d2c3b-4a59-4687-9a0b-1c2d3e4f5a6b"

// Both link forms on both engines: v2rayN's base64 JSON over TCP, and the
// URI form over WebSocket with early data in the path.
func TestSmoke_VMess(t *testing.T) {
	tcpPort := startVMessServer(t, "")
	wsPort := startVMessServer(t, "/vm")
	sharedJSON := func(id string) string {
		body := fmt.Sprintf(`{"v":"2","ps":"VMess JSON","add":"127.0.0.1","port":"%d","id":%q,"aid":"0","scy":"auto","net":"tcp","type":"none","tls":""}`, tcpPort, id)
		return "vmess://" + base64.StdEncoding.EncodeToString([]byte(body))
	}
	uriForm := func(id string) string {
		return "vmess://" + id + "@127.0.0.1:" + strconv.Itoa(wsPort) +
			"?type=ws&path=" + url.QueryEscape("/vm?ed=2048") + "&encryption=aes-128-gcm#VMess%20URI"
	}
	for _, engine := range smokeEngines {
		t.Run(engine+"/shared_json", func(t *testing.T) {
			assertSessionThrough(t, protocolSession{
				engine: engine, link: sharedJSON(testUUID), protocol: "vmess", port: tcpPort, name: "VMess JSON",
				wrongCredentialLink: sharedJSON(wrongUUID), pingEngine: smokeEngines[0],
			})
		})
		t.Run(engine+"/uri_ws", func(t *testing.T) {
			assertSessionThrough(t, protocolSession{
				engine: engine, link: uriForm(testUUID), protocol: "vmess", port: wsPort, name: "VMess URI",
				wrongCredentialLink: uriForm(wrongUUID), pingEngine: smokeEngines[0],
			})
		})
	}
}
