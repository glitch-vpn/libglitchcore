package mihomoconfig

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	mihomoDNS "github.com/metacubex/mihomo/dns"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

func wantDials(t *testing.T, what string, servers []mihomoDNS.NameServer, addrs []string, through string) {
	t.Helper()
	if len(servers) != len(addrs) {
		t.Fatalf("%s = %+v, want %v", what, servers, addrs)
	}
	for i, ns := range servers {
		if ns.Addr != addrs[i] || ns.ProxyName != through {
			t.Fatalf("%s[%d] = %s through %q, want %s through %q", what, i, ns.Addr, ns.ProxyName, addrs[i], through)
		}
	}
}

func policyFor(t *testing.T, policies []mihomoDNS.Policy, domain string) []mihomoDNS.NameServer {
	t.Helper()
	for _, p := range policies {
		if p.Domain == domain {
			return p.NameServers
		}
	}
	t.Fatalf("no nameserver policy for %q in %+v", domain, policies)
	return nil
}

// With fake-ip off every app query goes upstream, so it travels as its flow
// would: through the target where the catch-all proxies, with the names a
// tier sends direct taking the direct resolvers; the other way round where
// the catch-all is direct. The target's own address, and a resolver's own
// name, resolve plain: those queries cannot travel through it.
func TestBuildConfig_NormalModeQueriesTravelWithTheirFlows(t *testing.T) {
	general := []string{"10.0.0.53:53", "9.9.9.9:853"}
	direct := []string{"77.88.8.8:53"}
	dns := dnsconfig.Config{Mode: dnsconfig.ModeNormal, Servers: []string{"10.0.0.53", "tls://9.9.9.9"}, DirectServers: []string{"77.88.8.8"}}
	proxyAll := routing.Profile{Tiers: []routing.Tier{{Direct: []string{"domain:ru", "full:bank.local", "10.0.0.0/8", "keyword:cdn"}}}}
	bootstrap := []string{"10.0.0.53:53", "9.9.9.9:853", "77.88.8.8:53"}
	for name, in := range map[string]Inbound{
		"tun":    {Tun: &TunInbound{FileDescriptor: 42, DNS: dns}},
		"bridge": {Bridge: true, DNS: dns},
	} {
		t.Run(name, func(t *testing.T) {
			for _, links := range [][]string{{namedLinkThr}, {namedLinkThr, namedLinkOne}} {
				target := Target(links)
				cfg, err := BuildConfig(links, in, Options{}, proxyAll)
				if err != nil {
					t.Fatalf("%d links: %v", len(links), err)
				}
				if !cfg.DNS.Enable || cfg.DNS.EnhancedMode != C.DNSNormal {
					t.Fatalf("dns enable %v mode %s, want on and normal", cfg.DNS.Enable, cfg.DNS.EnhancedMode)
				}
				if _, ok := cfg.Proxies[target]; !ok {
					t.Fatalf("no proxy %q for the queries to travel through", target)
				}
				wantDials(t, "nameserver", cfg.DNS.NameServer, general, target)
				wantDials(t, "proxy-server-nameserver", cfg.DNS.ProxyServerNameserver, general, "")
				wantDials(t, "default-nameserver", cfg.DNS.DefaultNameserver, bootstrap, "")
				wantDials(t, "direct-nameserver", cfg.DNS.DirectNameServer, direct, "")
				for _, domain := range []string{"+.ru", "bank.local"} {
					wantDials(t, "policy "+domain, policyFor(t, cfg.DNS.NameServerPolicy, domain), direct, "")
				}
				if n := len(cfg.DNS.NameServerPolicy); n != 2 {
					t.Fatalf("policies = %+v, want the two names only", cfg.DNS.NameServerPolicy)
				}
			}
		})
	}

	directAll := routing.Profile{Mode: routing.ModeDirectAll, Tiers: []routing.Tier{
		{Proxy: []string{"domain:youtube.com"}, Routes: []routing.Route{{Match: []string{"full:api.example.com"}, To: "rt"}}},
	}, Targets: &routing.Targets{Version: 1, Servers: []routing.TargetServer{{ID: "rt", Link: namedLinkOne}}}}
	cfg, err := BuildConfig([]string{namedLinkThr}, Inbound{Bridge: true, DNS: dns}, Options{}, directAll)
	if err != nil {
		t.Fatal(err)
	}
	wantDials(t, "nameserver", cfg.DNS.NameServer, direct, "")
	wantDials(t, "proxy-server-nameserver", cfg.DNS.ProxyServerNameserver, general, "")
	for _, domain := range []string{"+.youtube.com", "api.example.com"} {
		wantDials(t, "policy "+domain, policyFor(t, cfg.DNS.NameServerPolicy, domain), general, "three")
	}

	// The tiers' order decides a name's query as it decides its flow. mihomo
	// answers from the deepest suffix listed, so a name under an earlier,
	// broader rule is not listed at all: the broader rule's resolvers answer
	// it, as its rule routes it.
	for _, c := range []struct {
		mode    string
		tiers   []routing.Tier
		through []string // per listed policy, in order: the target or ""
	}{
		{routing.ModeProxyAll, []routing.Tier{{Proxy: []string{"domain:vk.ru"}}, {Direct: []string{"domain:ru"}}}, []string{"three", ""}},
		{routing.ModeProxyAll, []routing.Tier{{Direct: []string{"domain:vk.ru"}}, {Proxy: []string{"domain:ru"}}}, []string{"", "three"}},
		{routing.ModeDirectAll, []routing.Tier{{Proxy: []string{"domain:vk.ru"}}, {Direct: []string{"domain:ru"}}}, []string{"three", ""}},
		{routing.ModeProxyAll, []routing.Tier{{Proxy: []string{"domain:ru"}}, {Direct: []string{"domain:vk.ru", "full:mail.ru", "full:bank.local"}}}, []string{"three", ""}},
		{routing.ModeDirectAll, []routing.Tier{{Direct: []string{"domain:ru"}}, {Proxy: []string{"domain:vk.ru"}}}, []string{""}},
	} {
		cfg, err := BuildConfig([]string{namedLinkThr}, Inbound{Bridge: true, DNS: dns}, Options{}, routing.Profile{Mode: c.mode, Tiers: c.tiers})
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.DNS.NameServerPolicy) != len(c.through) {
			t.Fatalf("%s %v: policies = %+v, want %d", c.mode, c.tiers, cfg.DNS.NameServerPolicy, len(c.through))
		}
		for i, through := range c.through {
			servers := general
			if through == "" {
				servers = direct
			}
			wantDials(t, c.mode+" policy "+cfg.DNS.NameServerPolicy[i].Domain, cfg.DNS.NameServerPolicy[i].NameServers, servers, through)
		}
		if c.tiers[0].Proxy != nil && c.tiers[0].Proxy[0] == "domain:ru" {
			if cfg.DNS.NameServerPolicy[0].Domain != "+.ru" || len(cfg.DNS.NameServerPolicy) != 2 || cfg.DNS.NameServerPolicy[1].Domain != "bank.local" {
				t.Fatalf("policies = %+v, want +.ru and bank.local only", cfg.DNS.NameServerPolicy)
			}
		}
	}

	// A resolver given by name is found through the session's resolvers that
	// are addresses, or the default one.
	cfg, err = BuildConfig([]string{namedLinkThr}, Inbound{Bridge: true, DNS: dnsconfig.Config{Servers: []string{"https://dns.google/dns-query"}}}, Options{}, proxyAll)
	if err != nil {
		t.Fatal(err)
	}
	wantDials(t, "default-nameserver", cfg.DNS.DefaultNameserver, []string{"1.1.1.1:53"}, "")

	// No direct resolvers: the general ones answer by default in direct-all,
	// and a proxied tier's names resolve through the target.
	dns.DirectServers = nil
	cfg, err = BuildConfig([]string{namedLinkThr}, Inbound{Tun: &TunInbound{FileDescriptor: 42, DNS: dns}}, Options{}, directAll)
	if err != nil {
		t.Fatal(err)
	}
	wantDials(t, "nameserver", cfg.DNS.NameServer, general, "")
	wantDials(t, "policy +.youtube.com", policyFor(t, cfg.DNS.NameServerPolicy, "+.youtube.com"), general, "three")
	// And in proxy-all, with no direct resolvers, a direct name's query has
	// nowhere else to go: no policy, every query through the target. A direct
	// dial still resolves its name plain, through the general resolvers.
	cfg, err = BuildConfig([]string{namedLinkThr}, Inbound{Bridge: true, DNS: dns}, Options{}, proxyAll)
	if err != nil {
		t.Fatal(err)
	}
	wantDials(t, "nameserver", cfg.DNS.NameServer, general, "three")
	if len(cfg.DNS.NameServerPolicy) != 0 {
		t.Fatalf("policies = %+v, want none", cfg.DNS.NameServerPolicy)
	}
	wantDials(t, "direct-nameserver", cfg.DNS.DirectNameServer, general, "")
}

// Fake-ip answers the app's A and AAAA from the pool, and what still goes
// upstream - the filter's names, every other record type - travels as its
// flow would, as with fake-ip off: through the target where the catch-all
// proxies, with a tier's direct names taking the direct resolvers. mihomo's
// own filter gives way to the caller's, empty included.
func TestBuildConfig_FakeIPUpstreamQueriesTravelWithTheirFlows(t *testing.T) {
	general := []string{"10.0.0.53:53"}
	direct := []string{"77.88.8.8:53"}
	dns := dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"10.0.0.53"}, DirectServers: []string{"77.88.8.8"}, FakeIPFilter: []string{"outside.test"}}
	proxyAll := routing.Profile{Tiers: []routing.Tier{{Direct: []string{"domain:ru"}}}}
	for name, in := range map[string]Inbound{
		"tun":    {Tun: &TunInbound{FileDescriptor: 42, DNS: dns}},
		"bridge": {Bridge: true, DNS: dns},
	} {
		t.Run(name, func(t *testing.T) {
			raw, _, err := buildRaw([]string{namedLinkThr}, in, Options{}, proxyAll)
			if err != nil {
				t.Fatal(err)
			}
			if raw.DNS.EnhancedMode != C.DNSFakeIP || len(raw.DNS.FakeIPFilter) != 1 || raw.DNS.FakeIPFilter[0] != "outside.test" {
				t.Fatalf("mode %s filter %v, want fake-ip with the caller's filter", raw.DNS.EnhancedMode, raw.DNS.FakeIPFilter)
			}
			cfg, err := BuildConfig([]string{namedLinkThr}, in, Options{}, proxyAll)
			if err != nil {
				t.Fatal(err)
			}
			wantDials(t, "nameserver", cfg.DNS.NameServer, general, "three")
			wantDials(t, "proxy-server-nameserver", cfg.DNS.ProxyServerNameserver, general, "")
			wantDials(t, "default-nameserver", cfg.DNS.DefaultNameserver, []string{"10.0.0.53:53", "77.88.8.8:53"}, "")
			wantDials(t, "direct-nameserver", cfg.DNS.DirectNameServer, direct, "")
			wantDials(t, "policy +.ru", policyFor(t, cfg.DNS.NameServerPolicy, "+.ru"), direct, "")
			if n := len(cfg.DNS.NameServerPolicy); n != 1 {
				t.Fatalf("policies = %+v, want the direct tier's name only", cfg.DNS.NameServerPolicy)
			}
		})
	}

	directAll := routing.Profile{Mode: routing.ModeDirectAll, Tiers: []routing.Tier{{Proxy: []string{"domain:youtube.com"}}}}
	cfg, err := BuildConfig([]string{namedLinkThr}, Inbound{Bridge: true, DNS: dns}, Options{}, directAll)
	if err != nil {
		t.Fatal(err)
	}
	wantDials(t, "nameserver", cfg.DNS.NameServer, direct, "")
	wantDials(t, "policy +.youtube.com", policyFor(t, cfg.DNS.NameServerPolicy, "+.youtube.com"), general, "three")

	// No filter sent: none applies, not mihomo's own.
	for name, in := range map[string]Inbound{
		"tun":    {Tun: &TunInbound{FileDescriptor: 42, DNS: dnsconfig.Config{Mode: dnsconfig.ModeFakeIP}}},
		"bridge": {Bridge: true, DNS: dnsconfig.Config{Mode: dnsconfig.ModeFakeIP}},
	} {
		raw, _, err := buildRaw([]string{namedLinkThr}, in, Options{}, routing.Profile{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(raw.DNS.FakeIPFilter) != 0 {
			t.Fatalf("%s: fake-ip-filter = %v, want none", name, raw.DNS.FakeIPFilter)
		}
		cfg, err := BuildConfig([]string{namedLinkThr}, in, Options{}, routing.Profile{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		wantDials(t, name+" nameserver", cfg.DNS.NameServer, []string{"1.1.1.1:53"}, "three")
		wantDials(t, name+" proxy-server-nameserver", cfg.DNS.ProxyServerNameserver, []string{"1.1.1.1:53"}, "")
	}
}

// addressRule matches an address condition in a rule line, alone or as an
// operand of a logic rule, up to its closing parenthesis or the line's end.
var addressRule = regexp.MustCompile(`(?:GEOIP|IP-CIDR6?|IP-ASN|IP-SUFFIX),[^()]*`)

// An address rule met by a flow that still carries its name would have mihomo
// resolve the name before routing, through a resolver the name's own rule
// has not chosen yet: every address rule takes no-resolve. The one exception
// is the force-direct flows' sub-rule, whose flows DIRECT dials by name anyway.
func TestBuildConfig_EveryAddressRuleKeepsItsName(t *testing.T) {
	tiers := []routing.Tier{
		{Block: []string{"geoip:ir", "192.0.2.0/24"}, Direct: []string{"geoip:ru", "10.0.0.0/8", "domain:ru"}, Proxy: []string{"geoip:us", "198.51.100.0/24"}},
		{Routes: []routing.Route{{Match: []string{"geoip:de", "203.0.113.0/24"}, To: "rt"}}, Direct: []string{"full:bank.local"}},
		{Block: []string{"geoip:private"}, Direct: []string{"geosite:cn"}},
	}
	targets := &routing.Targets{Version: 1, Servers: []routing.TargetServer{{ID: "rt", Link: namedLinkOne}}}
	for _, mode := range []string{routing.ModeProxyAll, routing.ModeDirectAll} {
		for _, dnsMode := range []string{dnsconfig.ModeFakeIP, dnsconfig.ModeNormal} {
			prof := routing.Profile{Mode: mode, Tiers: tiers, Targets: targets, LocalNetworks: true, DisableIPv6: true}
			dns := dnsconfig.Config{Mode: dnsMode, Servers: []string{"1.1.1.1"}}
			for name, in := range map[string]Inbound{
				"tun":    {Tun: &TunInbound{FileDescriptor: 42, DNS: dns}},
				"bridge": {Bridge: true, DNS: dns, ForceProxy: true, ForceDirect: true},
			} {
				raw, _, err := buildRaw([]string{namedLinkThr}, in, Options{}, prof)
				if err != nil {
					t.Fatalf("%s %s %s: %v", mode, dnsMode, name, err)
				}
				lines := append([]string{}, raw.Rule...)
				lines = append(lines, raw.SubRules[forceFlowsSubRule]...)
				matched := 0
				for _, line := range lines {
					for _, m := range addressRule.FindAllString(line, -1) {
						matched++
						if !strings.Contains(m, "no-resolve") {
							t.Fatalf("%s %s %s: %q resolves a name", mode, dnsMode, name, line)
						}
					}
				}
				// The tiers hold ten address entries, and the pool and IPv6
				// kill-switch add one each: fewer means a rule went missing.
				if matched < 12 {
					t.Fatalf("%s %s %s: %d address rules in %v, want at least 12", mode, dnsMode, name, matched, lines)
				}
				for _, line := range raw.SubRules[directFlowsSubRule] {
					for _, m := range addressRule.FindAllString(line, -1) {
						if strings.Contains(m, "no-resolve") {
							t.Fatalf("%s: force-direct block %q cannot meet a name it does not resolve", name, line)
						}
					}
				}
			}
		}
	}
}

// A nameserver names the proxy it dials through in a URL fragment, where
// '&' and '=' separate and '%' escapes: a remark holding one would make the
// query dial plain, or bind it to an interface of that name.
func TestBuildConfig_ProxyNameIsSafeInANameserver(t *testing.T) {
	for _, link := range []string{
		"vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@192.0.2.1:443?type=tcp&security=none#speed%3Dfast%26DE%26NL%20100%2525",
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"speed=fast&DE&NL 100%","add":"192.0.2.1","port":"443","id":"49c8fb89-9418-4ff4-8505-7a2772fc4b71","net":"tcp"}`)),
	} {
		dns := dnsconfig.Config{Mode: dnsconfig.ModeNormal, Servers: []string{"1.1.1.1"}}
		cfg, err := BuildConfig([]string{link}, Inbound{Bridge: true, DNS: dns}, Options{}, routing.Profile{})
		if err != nil {
			t.Fatal(err)
		}
		name := Target([]string{link})
		if _, ok := cfg.Proxies[name]; !ok || strings.ContainsAny(name, "&=%") {
			t.Fatalf("proxy %q, want a name without &, = or %%", name)
		}
		wantDials(t, "nameserver", cfg.DNS.NameServer, []string{"1.1.1.1:53"}, name)
	}
}

// A bare IPv6 resolver takes brackets before the proxy reference, as a URL
// wants it.
func TestBuildConfig_NormalModeBracketsABareIPv6Resolver(t *testing.T) {
	dns := dnsconfig.Config{Mode: dnsconfig.ModeNormal, Servers: []string{"2001:4860:4860::8888", "[2001:4860:4860::8844]:5353"}}
	cfg, err := BuildConfig([]string{namedLinkThr}, Inbound{Bridge: true, DNS: dns}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatal(err)
	}
	wantDials(t, "nameserver", cfg.DNS.NameServer, []string{"[2001:4860:4860::8888]:53", "[2001:4860:4860::8844]:5353"}, "three")
}

// RULES names mihomo's follow-the-rules sentinel where a nameserver names
// its proxy, so a remark of RULES does not become the proxy's name.
func TestBuildConfig_RemarkRULESIsNotTheProxyName(t *testing.T) {
	link := reservedNamesTestLink("1.2.3.4", "RULES")
	dns := dnsconfig.Config{Mode: dnsconfig.ModeNormal, Servers: []string{"1.1.1.1"}}
	cfg, err := BuildConfig([]string{link}, Inbound{Bridge: true, DNS: dns}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatal(err)
	}
	target := Target([]string{link})
	if target == "RULES" {
		t.Fatalf("proxy named %q", target)
	}
	wantDials(t, "nameserver", cfg.DNS.NameServer, []string{"1.1.1.1:53"}, target)
}
