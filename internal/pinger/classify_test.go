package pinger

import "testing"

func TestClassifyMatchesRegistrations(t *testing.T) {
	registered := func(engine string) bool {
		for _, m := range measurers {
			if m.engine == engine {
				return true
			}
		}
		return false
	}
	hasXray := registered("xray")
	hasAwg := registered("awg")
	hasMihomo := fallback != nil

	check := func(link, want string) {
		t.Helper()
		got, m := classify(link)
		if got != want {
			t.Errorf("classify(%q) engine = %q, want %q", link, got, want)
		}
		if want == "" && m != nil {
			t.Errorf("classify(%q): want nil measurer", link)
		}
		if want != "" && m == nil {
			t.Errorf("classify(%q): want a measurer", link)
		}
	}

	vless := ""
	switch {
	case hasXray:
		vless = "xray"
	case hasMihomo:
		vless = "mihomo"
	}
	check("vless://uuid@host:443?type=tcp", vless)
	check("vmess://eyJhZGQiOiJob3N0In0", vless)
	check("ss://YWVzOnB3QGhvc3Q6ODM4OA", vless)
	check("trojan://pass@host:443", vless)
	check("socks://YWxpY2U6czNjcmV0@host:1080", vless)
	check("socks5://alice:s3cret@host:1080", vless)
	check("socks5h://host:1080", vless)

	// mihomo would send an http proxy's UDP direct, so only xray carries it.
	xrayOnly := ""
	if hasXray {
		xrayOnly = "xray"
	}
	check("http://YWxpY2U6czNjcmV0@host:8080", xrayOnly)
	check("https://alice:s3cret@host:443?sni=x", xrayOnly)

	awg := ""
	if hasAwg {
		awg = "awg"
	}
	check("awg://YWJj#tokyo", awg)
	check("[Interface]\nPrivateKey = k\n[Peer]\nEndpoint = h:51820", awg)
	check("wireguard://k@host:51820?publickey=p", awg)
	check("wg://host:51820?pk=k&pub=p", awg)

	mihomoOnly := ""
	if hasMihomo {
		mihomoOnly = "mihomo"
	}
	check("hysteria2://pass@host:443", mihomoOnly)
	check("tuic://uuid:pass@host:443", mihomoOnly)
	check("anytls://pass@host:443", mihomoOnly)

	check("nonsense://whatever", "")
	check("socks4://host:1080", "")
}
