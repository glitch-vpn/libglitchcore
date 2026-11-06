package xrayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func outboundAddressText(t *testing.T, res *BuildResult) string {
	t.Helper()
	raw, err := json.Marshal(res.Config.OutboundConfigs[0].Settings)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestBuildConfigResolvingAtDialKeepsTheServersName(t *testing.T) {
	resolveAs(t, map[string]string{"server.example": "198.19.0.7"})
	link := "vless://" + testVMessUUID + "@server.example:443?type=tcp&security=tls&sni=server.example"

	resolvedOnce, err := BuildConfig([]string{link}, BalancerOptions{}, RoutingProfile{}, "none")
	if err != nil {
		t.Fatal(err)
	}
	if text := outboundAddressText(t, resolvedOnce); !strings.Contains(text, "198.19.0.7") || strings.Contains(text, "server.example") {
		t.Errorf("BuildConfig outbound = %s, want the address it resolved", text)
	}

	atDial, err := BuildConfigResolvingAtDial(link)
	if err != nil {
		t.Fatal(err)
	}
	if text := outboundAddressText(t, atDial); !strings.Contains(text, "server.example") || strings.Contains(text, "198.19.0.7") {
		t.Errorf("BuildConfigResolvingAtDial outbound = %s, want the name left to the dial", text)
	}
	if len(atDial.DialIPv4s) != 0 {
		t.Errorf("DialIPv4s = %v, want none: a name is no address to route around", atDial.DialIPv4s)
	}
	if _, err := atDial.Config.Build(); err != nil {
		t.Errorf("the config does not build: %v", err)
	}
}

func TestBuildConfigResolvingAtDialKeepsTheSafetyChecks(t *testing.T) {
	resolveAs(t, nil)
	_, err := BuildConfigResolvingAtDial("vless://" + testVMessUUID + "@vpn.example.org:443?type=grpc&serviceName=s")
	if err == nil || !strings.Contains(err.Error(), "no TLS, REALITY or VLESS encryption") {
		t.Errorf("err = %v, want the plaintext refusal a public server gets from BuildConfig", err)
	}
}
