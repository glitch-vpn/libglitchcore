package mihomoconfig

import (
	"encoding/base64"
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

	// The tiers' order decides a name's query as it decides its flow: an
	// earlier tier's proxied name under a later, broader direct rule keeps
	// the target, and the other way round.
	for _, c := range []struct {
		mode   string
		tiers  []routing.Tier
		first  string
		second string
	}{
		{routing.ModeProxyAll, []routing.Tier{{Proxy: []string{"domain:vk.ru"}}, {Direct: []string{"domain:ru"}}}, "three", ""},
		{routing.ModeProxyAll, []routing.Tier{{Direct: []string{"domain:vk.ru"}}, {Proxy: []string{"domain:ru"}}}, "", "three"},
		{routing.ModeDirectAll, []routing.Tier{{Proxy: []string{"domain:vk.ru"}}, {Direct: []string{"domain:ru"}}}, "three", ""},
	} {
		cfg, err := BuildConfig([]string{namedLinkThr}, Inbound{Bridge: true, DNS: dns}, Options{Strategy: ""}, routing.Profile{Mode: c.mode, Tiers: c.tiers})
		if err != nil {
			t.Fatal(err)
		}
		if n := len(cfg.DNS.NameServerPolicy); n != 2 || cfg.DNS.NameServerPolicy[0].Domain != "+.vk.ru" || cfg.DNS.NameServerPolicy[1].Domain != "+.ru" {
			t.Fatalf("%s %v: policies = %+v, want +.vk.ru then +.ru", c.mode, c.tiers, cfg.DNS.NameServerPolicy)
		}
		for i, through := range []string{c.first, c.second} {
			servers := general
			if through == "" {
				servers = direct
			}
			wantDials(t, c.mode+" policy "+cfg.DNS.NameServerPolicy[i].Domain, cfg.DNS.NameServerPolicy[i].NameServers, servers, through)
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
	// And in proxy-all, with no direct resolvers, a direct name has nowhere
	// else to go: no policy, every query through the target.
	cfg, err = BuildConfig([]string{namedLinkThr}, Inbound{Bridge: true, DNS: dns}, Options{}, proxyAll)
	if err != nil {
		t.Fatal(err)
	}
	wantDials(t, "nameserver", cfg.DNS.NameServer, general, "three")
	if len(cfg.DNS.NameServerPolicy) != 0 {
		t.Fatalf("policies = %+v, want none", cfg.DNS.NameServerPolicy)
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
