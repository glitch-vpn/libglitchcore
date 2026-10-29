package mihomoconfig

import (
	"errors"

	"github.com/glitch-vpn/libglitchcore/internal/proxylink"
)

// An http proxy has no UDP, and mihomo skips a rule whose target lacks UDP and
// sends the flow on to the next one, which ends at DIRECT; xray drops it.
var errHTTPProxyOnMihomo = errors.New("http: an http or https proxy carries no UDP, which mihomo would send direct; it runs on xray")

func socksProxy(link, name string) (map[string]any, error) {
	l, err := proxylink.Parse(link)
	if err != nil {
		return nil, err
	}
	p := map[string]any{
		"name":   name,
		"type":   "socks5",
		"server": l.Host,
		"port":   l.Port,
		"udp":    true,
	}
	if l.Username != "" || l.Password != "" {
		p["username"] = l.Username
		p["password"] = l.Password
	}
	return p, nil
}
