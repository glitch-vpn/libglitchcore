//go:build integration

package smoke

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
	"github.com/glitch-vpn/libglitchcore/internal/pinger"
)

// The AWG 2.0 settings both ends share, in UAPI form and as a link's query.
const (
	awg2SharedUAPI  = "s1=15\ns2=18\nh1=100-200\nh2=300-400\nh3=500-600\nh4=700-800\n"
	awg2SharedQuery = "&jc=3&jmin=40&jmax=70&s1=15&s2=18&h1=100-200&h2=300-400&h3=500-600&h4=700-800"
)

// A wireguard:// link in v2rayNG's form and a wg:// link in Hiddify's, with
// AmneziaWG keys, ping on mihomo and carry a session through it to their server.
func TestSmoke_Mihomo_WireGuardLinks(t *testing.T) {
	cases := []struct {
		name, deviceUAPI string
		link             func(serverPublic, clientPrivate awgKey, port int) string
	}{
		{
			name: "v2rayNG wireguard://",
			link: func(serverPublic, clientPrivate awgKey, port int) string {
				return "wireguard://" + url.QueryEscape(clientPrivate.base64()) + "@127.0.0.1:" + strconv.Itoa(port) +
					"?publickey=" + url.QueryEscape(serverPublic.base64()) + "&reserved=0,0,0&address=10.66.0.2%2F32&mtu=1280#WG%20Smoke"
			},
		},
		{
			name:       "Hiddify wg:// with AmneziaWG keys",
			deviceUAPI: awg2SharedUAPI,
			link: func(serverPublic, clientPrivate awgKey, port int) string {
				return "wg://127.0.0.1:" + strconv.Itoa(port) + "?pk=" + clientPrivate.base64() + "&pub=" + serverPublic.base64() +
					"&ip=10.66.0.2&keepalive=25" + awg2SharedQuery
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			core.Initialize()
			link := c.link(startWireGuardPeer(t, "198.51.100.67", c.deviceUAPI))
			echoURL := "http://" + awgServerAddr + "/"

			// Before the session: the ping's device and the session's share one
			// key, and the peer answers only the endpoint it heard from last.
			results := pinger.Measure(pinger.Request{Links: []string{link}, ProbeURL: echoURL, TimeoutMs: 5000})
			if len(results) != 1 || !results[0].Alive || results[0].Engine != "awg" {
				t.Fatalf("ping = %+v", results)
			}

			ev := captureEvents(t)
			startEngineInProxyMode(t, "mihomo", link, map[string]string{
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
			if ip.IPv4 != "198.51.100.67" {
				t.Fatalf("ipv4 = %q (err %q)", ip.IPv4, ip.IPv4Error)
			}
			if sel, _ := ev.last(core.ServerEvent); !strings.Contains(sel, `"protocol":"awg"`) {
				t.Fatalf("ServerEvent = %s, want protocol awg", sel)
			}
		})
	}
}
