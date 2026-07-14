package mihomoconfig

import (
	"strings"
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/awgconfig"
	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
	C "github.com/metacubex/mihomo/constant"

	// config.ParseRawConfig reaches temporaryUpdateGeneral via //go:linkname,
	// whose body lives in hub/executor; without it the test binary won't link.
	// Real consumers (engine_mihomo) import executor anyway.
	_ "github.com/metacubex/mihomo/hub/executor"
)

func TestBuildConfig_ForceProxyListener(t *testing.T) {
	link := "vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@1.2.3.4:443?type=tcp&security=reality&encryption=none&sni=www.bing.com&fp=chrome&pbk=gdtgDEXry6dpwsJIyDnd6qVxUDMk9jRAthZnqHyDIUI&sid=455f9e232c6fb72d&flow=xtls-rprx-vision#r"
	cfg, err := BuildConfig([]string{link},
		Inbound{MixedPort: 17890, ForceProxyPort: 17891},
		Options{}, routing.Profile{Mode: routing.ModeDirectAll, Proxy: []string{"process:chrome.exe"}})
	if err != nil {
		t.Fatalf("BuildConfig with ForceProxyPort: %v", err)
	}
	if _, ok := cfg.Listeners[forceProxyListenerName]; !ok {
		t.Fatalf("forceproxy listener missing; have %v", cfg.Listeners)
	}
	var found bool
	for _, r := range cfg.Rules {
		if r.RuleType() == C.InName && strings.Contains(r.Payload(), forceProxyListenerName) {
			found = true
		}
	}
	if !found {
		t.Fatal("IN-NAME,forceproxy rule missing")
	}
}

func TestBuildConfig_DisableIPv6AndUDP(t *testing.T) {
	link := "vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@1.2.3.4:443?type=tcp&security=tls&sni=a.example.com"
	cfg, err := BuildConfig([]string{link}, Inbound{MixedPort: 17890}, Options{},
		routing.Profile{Block: []string{"ads.example"}, DisableIPv6: true, DisableUDP: true})
	if err != nil {
		t.Fatalf("BuildConfig with disable flags: %v", err)
	}
	if len(cfg.Rules) < 3 {
		t.Fatalf("want >=3 rules, got %d", len(cfg.Rules))
	}
	if cfg.Rules[0].RuleType() != C.IPCIDR || cfg.Rules[0].Payload() != "::/0" {
		t.Fatalf("first rule must be IP-CIDR ::/0 REJECT, got %s %q", cfg.Rules[0].RuleType(), cfg.Rules[0].Payload())
	}
	if cfg.Rules[0].Adapter() != "REJECT" || cfg.Rules[1].Adapter() != "REJECT" {
		t.Fatalf("kill-switch rules must target REJECT: %s / %s", cfg.Rules[0].Adapter(), cfg.Rules[1].Adapter())
	}
	if cfg.Rules[1].RuleType() != C.AND {
		t.Fatalf("second rule must be the AND(udp, NOT :53) logic rule, got %s", cfg.Rules[1].RuleType())
	}
	if cfg.General.IPv6 {
		t.Fatal("general ipv6 must be off when DisableIPv6 is set")
	}
}

func TestBuildConfig_SnifferToggle(t *testing.T) {
	link := "vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@1.2.3.4:443?type=tcp&security=tls&sni=a.example.com"
	on, err := BuildConfig([]string{link}, Inbound{MixedPort: 17890}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatalf("BuildConfig(default): %v", err)
	}
	if on.Sniffer == nil || !on.Sniffer.Enable {
		t.Fatal("sniffer must be enabled by default")
	}
	off, err := BuildConfig([]string{link}, Inbound{MixedPort: 17890}, Options{DisableSniffing: true}, routing.Profile{})
	if err != nil {
		t.Fatalf("BuildConfig(DisableSniffing): %v", err)
	}
	if off.Sniffer != nil && off.Sniffer.Enable {
		t.Fatal("sniffer must be off with DisableSniffing")
	}
}

func TestBuildConfig_ProxyAuth(t *testing.T) {
	link := "vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@1.2.3.4:443?type=tcp&security=tls&sni=a.example.com"

	authed, err := BuildConfig([]string{link}, Inbound{MixedPort: 17890, Auth: "bob:secret"}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatalf("BuildConfig(auth): %v", err)
	}
	if len(authed.Users) == 0 {
		t.Fatal("proxy Auth set but no inbound users parsed")
	}

	open, err := BuildConfig([]string{link}, Inbound{MixedPort: 17890}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatalf("BuildConfig(open): %v", err)
	}
	if len(open.Users) != 0 {
		t.Fatalf("bridge inbound must stay open, got %d users", len(open.Users))
	}
}

func TestBuildConfig_Fingerprint(t *testing.T) {
	links := []string{
		"vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@1.2.3.4:443?type=ws&security=tls&sni=a.example.com&fp=chrome#v",
		"ss://aes-128-gcm:pass@5.6.7.8:8388#s",
	}
	cfg, err := BuildConfig(links, Inbound{MixedPort: 17890}, Options{Fingerprint: "safari"}, routing.Profile{})
	if err != nil {
		t.Fatalf("BuildConfig(fp): %v", err)
	}
	if _, ok := cfg.Proxies["v"]; !ok {
		t.Fatalf("vless proxy missing; have %v", cfg.Proxies)
	}
	// The ss proxy must still parse (client-fingerprint was not injected onto it).
	if _, ok := cfg.Proxies["s"]; !ok {
		t.Fatalf("ss proxy missing (fp wrongly applied?); have %v", cfg.Proxies)
	}

	// An unaccepted fp is dropped: config still builds (link's own fp survives).
	if _, err := BuildConfig(links, Inbound{MixedPort: 17890}, Options{Fingerprint: "unsafe"}, routing.Profile{}); err != nil {
		t.Fatalf("BuildConfig(invalid fp dropped): %v", err)
	}
	if !ValidFingerprint("chrome120") || ValidFingerprint("unsafe") {
		t.Fatal("ValidFingerprint: chrome120 valid for mihomo, unsafe (xray-only) invalid")
	}
}

func TestBalancerGroup_ProbeURL(t *testing.T) {
	g, err := balancerGroup([]string{"a", "b"}, "", "https://probe.example/health")
	if err != nil {
		t.Fatalf("balancerGroup: %v", err)
	}
	if g["url"] != "https://probe.example/health" {
		t.Fatalf("group url = %v, want custom", g["url"])
	}
	g, err = balancerGroup([]string{"a", "b"}, "fallback", "")
	if err != nil {
		t.Fatalf("balancerGroup(default): %v", err)
	}
	if g["url"] != probeURL {
		t.Fatalf("group url = %v, want default %q", g["url"], probeURL)
	}
}

// config.ParseRawConfig builds the real mihomo outbound adapters, so a successful
// build validates the config without needing a live server.
func TestBuildConfig_ValidatesViaMihomoParser(t *testing.T) {
	cases := []struct {
		name    string
		links   []string
		proxies int
		group   bool
	}{
		{
			name:    "vless_reality_vision",
			links:   []string{"vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@1.2.3.4:443?type=tcp&security=reality&encryption=none&sni=www.bing.com&fp=chrome&pbk=gdtgDEXry6dpwsJIyDnd6qVxUDMk9jRAthZnqHyDIUI&sid=455f9e232c6fb72d&flow=xtls-rprx-vision#r"},
			proxies: 1,
		},
		{
			name:    "vless_ws_tls",
			links:   []string{"vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@1.2.3.4:443?type=ws&security=tls&sni=cdn.example.com&path=%2Fws&host=cdn.example.com"},
			proxies: 1,
		},
		{
			name:    "shadowsocks_plain",
			links:   []string{"ss://aes-128-gcm:pass@1.2.3.4:8388#ss"},
			proxies: 1,
		},
		{
			name:    "trojan_tls",
			links:   []string{"trojan://secret@1.2.3.4:443?sni=example.com&type=tcp#t"},
			proxies: 1,
		},
		{
			name:    "hysteria2",
			links:   []string{"hysteria2://pass@1.2.3.4:443?sni=example.com&obfs=salamander&obfs-password=x#h"},
			proxies: 1,
		},
		{
			name: "multi_link_url_test_group",
			links: []string{
				"vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@1.2.3.4:443?type=tcp&security=reality&pbk=gdtgDEXry6dpwsJIyDnd6qVxUDMk9jRAthZnqHyDIUI&sid=455f&sni=a.com&flow=xtls-rprx-vision",
				"ss://aes-128-gcm:pass@5.6.7.8:8388",
			},
			proxies: 2,
			group:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := BuildConfig(tc.links, Inbound{MixedPort: 17890}, Options{}, routing.Profile{})
			if err != nil {
				t.Fatalf("BuildConfig: %v", err)
			}
			if len(cfg.Proxies) < tc.proxies {
				// cfg.Proxies also includes built-ins (DIRECT/REJECT/COMPATIBLE).
				t.Fatalf("Proxies = %d, want >= %d", len(cfg.Proxies), tc.proxies)
			}
			if tc.group {
				if _, ok := cfg.Proxies[groupTag]; !ok {
					t.Fatalf("expected url-test group %q in proxies", groupTag)
				}
			}
			if len(cfg.Rules) == 0 {
				t.Fatal("no rules built")
			}
		})
	}
}

func TestBuildConfig_Rejects(t *testing.T) {
	if _, err := BuildConfig([]string{"wireguard://nope"}, Inbound{MixedPort: 17890}, Options{}, routing.Profile{}); err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
	if _, err := BuildConfig(nil, Inbound{MixedPort: 17890}, Options{}, routing.Profile{}); err == nil {
		t.Fatal("expected error for no links")
	}
	if _, err := BuildConfig([]string{"ss://aes-128-gcm:p@h:1"}, Inbound{}, Options{}, routing.Profile{}); err == nil {
		t.Fatal("expected error for no inbound")
	}
}

func TestBuildConfig_AmneziaWG(t *testing.T) {
	const ini = `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.10.0.51/32
MTU = 1280
Jc = 7
Jmin = 8
Jmax = 80
S1 = 70
S2 = 72
S3 = 0
S4 = 0
H1 = 1132937382-1132947381
H2 = 755668662-755669661
H3 = 1370832753-1370833752
H4 = 1848625494-1848626493
I1 = <b 0xc30000000108>

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 144.31.233.161:585
PersistentKeepalive = 25`

	cfg, err := BuildConfig([]string{ini}, Inbound{MixedPort: 17890}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatalf("BuildConfig(awg): %v", err)
	}
	if _, ok := cfg.Proxies["proxy-0"]; !ok {
		t.Fatalf("wireguard proxy not built: %v", cfg.Proxies)
	}

	if _, err := BuildConfig([]string{awgconfig.EncodeLink(ini, "demo")}, Inbound{MixedPort: 17890}, Options{}, routing.Profile{}); err != nil {
		t.Fatalf("BuildConfig(awg link): %v", err)
	}
}

func TestBuildConfig_MixedVlessAndAwg(t *testing.T) {
	const awgINI = `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.10.0.51/32
Jc = 7
S1 = 70
S2 = 72
H1 = 1132937382-1132947381
H2 = 755668662-755669661
H3 = 1370832753-1370833752
H4 = 1848625494-1848626493
[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 144.31.233.161:585`

	links := []string{
		"vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@1.2.3.4:443?type=tcp&security=reality&pbk=gdtgDEXry6dpwsJIyDnd6qVxUDMk9jRAthZnqHyDIUI&sid=455f&sni=a.com&flow=xtls-rprx-vision",
		awgconfig.EncodeLink(awgINI, "wg"),
	}
	cfg, err := BuildConfig(links, Inbound{MixedPort: 17890}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatalf("BuildConfig(mixed): %v", err)
	}
	// vless link carries no fragment -> proxy-0; awg:// carries #wg -> "wg";
	// both sit under the url-test group.
	for _, tag := range []string{"proxy-0", "wg", groupTag} {
		if _, ok := cfg.Proxies[tag]; !ok {
			t.Fatalf("missing %q in proxies (have %d)", tag, len(cfg.Proxies))
		}
	}
}

func TestLinkNames(t *testing.T) {
	links := []string{
		"vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@1.2.3.4:443?type=tcp&security=reality&pbk=gdtgDEXry6dpwsJIyDnd6qVxUDMk9jRAthZnqHyDIUI&sid=455f&sni=a.com&flow=xtls-rprx-vision#%F0%9F%87%B3%F0%9F%87%B1%20NL",
		"ss://aes-128-gcm:pass@5.6.7.8:8388#\U0001F1F3\U0001F1F1 NL", // same display name -> deduped
		"ss://aes-128-gcm:pass@9.9.9.9:8388",                         // no fragment -> proxy-2
	}
	cfg, err := BuildConfig(links, Inbound{MixedPort: 17890}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	for _, tag := range []string{"🇳🇱 NL", "🇳🇱 NL (2)", "proxy-2"} {
		if _, ok := cfg.Proxies[tag]; !ok {
			t.Fatalf("missing proxy %q (have %d)", tag, len(cfg.Proxies))
		}
	}
}

func TestBuildRules(t *testing.T) {
	p := routing.Profile{
		Mode:          routing.ModeProxyAll,
		Direct:        []string{"geosite:category-ru", "geoip:ru", "domain:gov.ru", "10.1.0.0/16", "process:Discord.exe"},
		Block:         []string{"ads.example"},
		LocalNetworks: true,
	}
	joined := strings.Join(buildRules(p, "vpn"), "\n")
	for _, want := range []string{
		"DOMAIN-SUFFIX,ads.example,REJECT",
		"PROCESS-NAME,Discord.exe,DIRECT",
		"GEOSITE,category-ru,DIRECT",
		"GEOIP,ru,DIRECT,no-resolve",
		"DOMAIN-SUFFIX,gov.ru,DIRECT",
		"IP-CIDR,10.1.0.0/16,DIRECT,no-resolve",
		"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
		"MATCH,vpn",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing rule %q in:\n%s", want, joined)
		}
	}

	// A bare IP is normalized to a /32 CIDR; full:/keyword:/regexp: map to the
	// matching mihomo domain rule types.
	kinds := strings.Join(buildRules(routing.Profile{
		Proxy: []string{"48.123.243.123", "full:exact.example", "keyword:ads", "regexp:.*\\.cn$"},
	}, "vpn"), "\n")
	for _, want := range []string{
		"IP-CIDR,48.123.243.123/32,vpn,no-resolve",
		"DOMAIN,exact.example,vpn",
		"DOMAIN-KEYWORD,ads,vpn",
		"DOMAIN-REGEX,.*\\.cn$,vpn",
	} {
		if !strings.Contains(kinds, want) {
			t.Fatalf("missing rule %q in:\n%s", want, kinds)
		}
	}

	// direct-all flips the catch-all and forces the proxy list to the proxy.
	da := strings.Join(buildRules(routing.Profile{
		Mode:  routing.ModeDirectAll,
		Proxy: []string{"domain:youtube.com"},
	}, "vpn"), "\n")
	if !strings.Contains(da, "DOMAIN-SUFFIX,youtube.com,vpn") || !strings.Contains(da, "MATCH,DIRECT") {
		t.Fatalf("direct-all rules wrong:\n%s", da)
	}

	// Empty profile -> everything to the proxy.
	if empty := buildRules(routing.Profile{}, "proxy-0"); len(empty) != 1 || empty[0] != "MATCH,proxy-0" {
		t.Fatalf("empty profile rules = %v", empty)
	}

	// Invalid (non-ASCII) geo code "geoip:рф" is dropped, not emitted - otherwise
	// it would fail the whole mihomo config at load. "domain:рф" (a zone) and a
	// valid geosite alongside still work.
	inv := strings.Join(buildRules(routing.Profile{
		Block: []string{"geosite:category-ru", "geoip:рф", "domain:рф"},
	}, "vpn"), "\n")
	if strings.Contains(inv, "GEOIP,рф") {
		t.Fatalf("invalid geo code leaked:\n%s", inv)
	}
	if !strings.Contains(inv, "GEOSITE,category-ru,REJECT") || !strings.Contains(inv, "DOMAIN-SUFFIX,рф,REJECT") {
		t.Fatalf("valid matchers dropped:\n%s", inv)
	}
}

func TestBalancerStrategy(t *testing.T) {
	cases := map[string]struct{ typ, strat string }{
		"":                  {"url-test", ""},
		"url-test":          {"url-test", ""},
		"fallback":          {"fallback", ""},
		"load-balance":      {"load-balance", "round-robin"},
		"load-balance-hash": {"load-balance", "consistent-hashing"},
	}
	for strategy, want := range cases {
		g, err := balancerGroup([]string{"a", "b"}, strategy, "")
		if err != nil {
			t.Fatalf("strategy %q: %v", strategy, err)
		}
		if g["type"] != want.typ {
			t.Fatalf("strategy %q -> type %v, want %v", strategy, g["type"], want.typ)
		}
		if want.strat != "" && g["strategy"] != want.strat {
			t.Fatalf("strategy %q -> strategy %v, want %v", strategy, g["strategy"], want.strat)
		}
	}

	if _, err := balancerGroup([]string{"a", "b"}, "leastping", ""); err == nil {
		t.Fatal("expected error for xray-only strategy 'leastping' on mihomo")
	}
}

func TestBuildConfig_TunInbound(t *testing.T) {
	link := "vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@1.2.3.4:443?type=tcp&security=reality&pbk=gdtgDEXry6dpwsJIyDnd6qVxUDMk9jRAthZnqHyDIUI&sid=455f&sni=a.com&flow=xtls-rprx-vision"

	dns := dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"https://dns.google/dns-query"}}
	fd, err := BuildConfig([]string{link}, Inbound{Tun: &TunInbound{FileDescriptor: 42, DNS: dns}}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatalf("fd tun: %v", err)
	}
	if !fd.General.Tun.Enable || fd.General.Tun.FileDescriptor != 42 {
		t.Fatalf("fd tun not configured: %+v", fd.General.Tun)
	}

	desktop, err := BuildConfig([]string{link}, Inbound{Tun: &TunInbound{Device: "GlitchVPN", DNS: dns}}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatalf("desktop tun: %v", err)
	}
	if !desktop.General.Tun.Enable || !desktop.General.Tun.AutoRoute {
		t.Fatalf("desktop tun not auto-routed: %+v", desktop.General.Tun)
	}
}

func TestBuildConfig_BridgeFakeIP(t *testing.T) {
	link := "vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@1.2.3.4:443?type=tcp&security=reality&pbk=gdtgDEXry6dpwsJIyDnd6qVxUDMk9jRAthZnqHyDIUI&sid=455f&sni=a.com&flow=xtls-rprx-vision"
	dns := dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"https://dns.google/dns-query"}}

	cfg, err := BuildConfig([]string{link},
		Inbound{MixedPort: 17890, DNS: dns, DNSListenPort: 17899}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatalf("BuildConfig(bridge fake-ip): %v", err)
	}
	if cfg.DNS == nil || !cfg.DNS.Enable {
		t.Fatalf("bridge DNS server not enabled: %+v", cfg.DNS)
	}
	if cfg.DNS.Listen != "127.0.0.1:17899" {
		t.Fatalf("DNS listen = %q, want 127.0.0.1:17899", cfg.DNS.Listen)
	}
	if got := cfg.DNS.FakeIPRange.String(); got != fakeIPRangeBridge {
		t.Fatalf("fake-ip range = %q, want %q", got, fakeIPRangeBridge)
	}

	plain, err := BuildConfig([]string{link},
		Inbound{MixedPort: 17890, DNS: dnsconfig.Config{Mode: dnsconfig.ModeNormal}, DNSListenPort: 17899}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatalf("BuildConfig(bridge normal): %v", err)
	}
	if plain.DNS != nil && plain.DNS.Listen == "127.0.0.1:17899" {
		t.Fatalf("normal mode must not run the bridge DNS server on our port: %+v", plain.DNS)
	}
}

func TestHysteria2Proxy(t *testing.T) {
	cases := []struct {
		name  string
		link  string
		check func(t *testing.T, p map[string]any)
	}{
		{
			name: "minimal_default_port",
			link: "hy2://pass@example.com",
			check: func(t *testing.T, p map[string]any) {
				if p["type"] != "hysteria2" {
					t.Fatalf("type = %v", p["type"])
				}
				if p["server"] != "example.com" {
					t.Fatalf("server = %v", p["server"])
				}
				if p["port"] != 443 {
					t.Fatalf("port = %v, want 443", p["port"])
				}
				if _, ok := p["ports"]; ok {
					t.Fatalf("ports unexpected: %v", p["ports"])
				}
				if p["password"] != "pass" {
					t.Fatalf("password = %v", p["password"])
				}
			},
		},
		{
			name: "userpass_auth",
			link: "hysteria2://alice:s3cret@1.2.3.4:443",
			check: func(t *testing.T, p map[string]any) {
				if p["password"] != "alice:s3cret" {
					t.Fatalf("password = %v, want alice:s3cret", p["password"])
				}
				if p["port"] != 443 {
					t.Fatalf("port = %v", p["port"])
				}
			},
		},
		{
			name: "pin_and_insecure",
			link: "hysteria2://pass@host:8443?pinSHA256=deadbeef&insecure=1",
			check: func(t *testing.T, p map[string]any) {
				if p["fingerprint"] != "deadbeef" {
					t.Fatalf("fingerprint = %v", p["fingerprint"])
				}
				if p["skip-cert-verify"] != true {
					t.Fatalf("skip-cert-verify = %v", p["skip-cert-verify"])
				}
				if p["port"] != 8443 {
					t.Fatalf("port = %v", p["port"])
				}
			},
		},
		{
			name: "port_hopping",
			link: "hysteria2://pass@host:443,5000-6000",
			check: func(t *testing.T, p map[string]any) {
				if p["ports"] != "443,5000-6000" {
					t.Fatalf("ports = %v", p["ports"])
				}
				if p["port"] != 443 {
					t.Fatalf("port = %v, want first hopping port 443", p["port"])
				}
			},
		},
		{
			name: "full_salamander",
			link: "hysteria2://pass@1.2.3.4:443?sni=example.com&obfs=salamander&obfs-password=x&alpn=h3,h3-29&up=100&down=500 Mbps&hop-interval=30s#h",
			check: func(t *testing.T, p map[string]any) {
				if p["sni"] != "example.com" {
					t.Fatalf("sni = %v", p["sni"])
				}
				if p["obfs"] != "salamander" {
					t.Fatalf("obfs = %v", p["obfs"])
				}
				if p["obfs-password"] != "x" {
					t.Fatalf("obfs-password = %v", p["obfs-password"])
				}
				alpn, ok := p["alpn"].([]string)
				if !ok || len(alpn) != 2 || alpn[0] != "h3" || alpn[1] != "h3-29" {
					t.Fatalf("alpn = %#v", p["alpn"])
				}
				if p["up"] != "100" {
					t.Fatalf("up = %v", p["up"])
				}
				if p["down"] != "500 Mbps" {
					t.Fatalf("down = %v", p["down"])
				}
				if p["hop-interval"] != "30s" {
					t.Fatalf("hop-interval = %v", p["hop-interval"])
				}
			},
		},
		{
			name: "gecko_packet_sizes",
			link: "hy2://pass@host:443?obfs=gecko&obfs-password=g&obfs-min-packet-size=512&obfs-max-packet-size=1200&insecure=true",
			check: func(t *testing.T, p map[string]any) {
				if p["obfs"] != "gecko" {
					t.Fatalf("obfs = %v", p["obfs"])
				}
				if p["obfs-min-packet-size"] != 512 {
					t.Fatalf("obfs-min-packet-size = %v", p["obfs-min-packet-size"])
				}
				if p["obfs-max-packet-size"] != 1200 {
					t.Fatalf("obfs-max-packet-size = %v", p["obfs-max-packet-size"])
				}
				if p["skip-cert-verify"] != true {
					t.Fatalf("skip-cert-verify = %v", p["skip-cert-verify"])
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ProxyMapFromLink(tc.link)
			if err != nil {
				t.Fatalf("ProxyMapFromLink: %v", err)
			}
			tc.check(t, p)
		})
	}
}

func TestHy2Ports(t *testing.T) {
	port, ports, err := hy2Ports("")
	if err != nil || port != 443 || ports != "" {
		t.Fatalf("empty: port=%d ports=%q err=%v", port, ports, err)
	}
	port, ports, err = hy2Ports("8443")
	if err != nil || port != 8443 || ports != "" {
		t.Fatalf("single: port=%d ports=%q err=%v", port, ports, err)
	}
	port, ports, err = hy2Ports("20000-20100")
	if err != nil || port != 20000 || ports != "20000-20100" {
		t.Fatalf("range: port=%d ports=%q err=%v", port, ports, err)
	}
	if _, _, err := hy2Ports("nope"); err == nil {
		t.Fatal("expected error for invalid ports")
	}
}
