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
	check("ss://YWVzOnB3QGhvc3Q6ODM4OA", vless)
	check("trojan://pass@host:443", vless)

	awg := ""
	if hasAwg {
		awg = "awg"
	}
	check("awg://YWJj#tokyo", awg)
	check("[Interface]\nPrivateKey = k\n[Peer]\nEndpoint = h:51820", awg)

	hy2 := ""
	if hasMihomo {
		hy2 = "mihomo"
	}
	check("hysteria2://pass@host:443", hy2)

	check("nonsense://whatever", "")
}
