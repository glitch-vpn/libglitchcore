package dnsconfig

import (
	"strings"
	"testing"
)

func TestScheme(t *testing.T) {
	cases := map[string]string{
		"1.1.1.1":                      "",
		"8.8.8.8:53":                   "",
		"tls://1.1.1.1":                "tls",
		"https://dns.google/dns-query": "https",
		"quic://dns.adguard.com":       "quic",
		"tcp://9.9.9.9":                "tcp",
	}
	for in, want := range cases {
		if got := Scheme(in); got != want {
			t.Fatalf("Scheme(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFirstPlainServer(t *testing.T) {
	// DoH/DoT first, a plain one later -> the plain one wins (awg can't do DoH/DoT).
	c := Config{Servers: []string{"https://dns.google/dns-query", "tls://1.1.1.1", " 9.9.9.9 "}}
	if got := c.FirstPlainServer(); got != "9.9.9.9" {
		t.Fatalf("FirstPlainServer = %q, want 9.9.9.9", got)
	}
	// Only encrypted -> none applicable to awg.
	if got := (Config{Servers: []string{"https://x/dns-query"}}).FirstPlainServer(); got != "" {
		t.Fatalf("FirstPlainServer = %q, want empty", got)
	}
}

func TestNormalizedServersFallback(t *testing.T) {
	if got := (Config{}).NormalizedServers("1.1.1.1"); len(got) != 1 || got[0] != "1.1.1.1" {
		t.Fatalf("fallback = %v, want [1.1.1.1]", got)
	}
	if got := (Config{Servers: []string{" ", ""}}).NormalizedServers(""); len(got) != 0 {
		t.Fatalf("empty = %v, want none", got)
	}
}

func TestNormalizedDirectServers(t *testing.T) {
	c := Config{DirectServers: []string{" 77.88.8.8 ", "", "https://dns.local/q"}}
	ds := c.NormalizedDirectServers()
	if len(ds) != 2 || ds[0] != "77.88.8.8" || ds[1] != "https://dns.local/q" {
		t.Fatalf("direct servers = %v", ds)
	}
	if got := (Config{}).NormalizedDirectServers(); len(got) != 0 {
		t.Fatalf("empty direct = %v", got)
	}
}

// One bad value must cost the caller that value, not the connect: mihomo fails
// the whole config on a value it cannot parse, and xray drops the whole table.
func TestNormalizedHosts(t *testing.T) {
	hosts := Config{Hosts: map[string][]string{
		" doh.example ":   {" 1.2.3.4 ", ""},
		"":                {"5.6.7.8"},
		"empty.example":   {" ", ""},
		"pair.example":    {"1.1.1.1", "not-an-ip", "2.2.2.2"},
		"alias.example":   {"target.example"},
		"lan.example":     {"lan"},
		"garbage.example": {"a b/c"},
	}}.NormalizedHosts()

	want := map[string][]string{
		"doh.example":   {"1.2.3.4"},
		"pair.example":  {"1.1.1.1", "2.2.2.2"}, // multi-value keeps IPs only
		"alias.example": {"target.example"},     // single value may be a name
		"lan.example":   {"lan"},                // mihomo's own special value
	}
	if len(hosts) != len(want) {
		t.Fatalf("hosts = %v, want %v", hosts, want)
	}
	for k, vals := range want {
		got := hosts[k]
		if len(got) != len(vals) {
			t.Fatalf("hosts[%q] = %v, want %v", k, got, vals)
		}
		for i := range vals {
			if got[i] != vals[i] {
				t.Fatalf("hosts[%q] = %v, want %v", k, got, vals)
			}
		}
	}
	if got := (Config{}).NormalizedHosts(); len(got) != 0 {
		t.Fatalf("empty hosts = %v", got)
	}
}

func TestFakeIP(t *testing.T) {
	if !(Config{Mode: "fake-ip"}).FakeIP() {
		t.Fatal("fake-ip not detected")
	}
	if (Config{Mode: "normal"}).FakeIP() || (Config{}).FakeIP() {
		t.Fatal("non-fake-ip misdetected")
	}
}

func TestValidateFakeIPFilterMihomo(t *testing.T) {
	refused := map[string]string{
		"a*b":            `"*" must be a whole label`,
		"*foo.com":       `"*" must be a whole label`,
		"foo*.com":       `"*" must be a whole label`,
		"a.+.com":        `"+" is only allowed as the first label`,
		"a+b.com":        `"+" must be a whole label`,
		"+":              `"+" must be followed by another label`,
		"example.com.":   "trailing dot",
		"a..example.com": "label 2 is empty",
		"rule-set:ads":   "rule-set is not supported",
		"geosite:рф":     "invalid geosite code",
		"geosite:cn,a b": "invalid geosite code",
	}
	for entry, want := range refused {
		err := Config{Mode: ModeFakeIP, FakeIPFilter: []string{"+.ok.example", entry}}.Validate("mihomo")
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), entry) {
			t.Errorf("Validate(%q) = %v, want an error naming the entry and %q", entry, err, want)
		}
	}
	accepted := []string{
		"+.lan", "*.example.com", "a.*.example.com", ".example.com", "time.windows.com",
		"geosite:category-ads", "geosite:cn,geolocation-!cn", "  *.local  ",
	}
	if err := (Config{Mode: ModeFakeIP, FakeIPFilter: accepted}).Validate("mihomo"); err != nil {
		t.Errorf("Validate(%v) = %v, want nil", accepted, err)
	}
}

func TestValidateFakeIPFilterXray(t *testing.T) {
	refused := map[string]string{
		"keyword:domain:example.com": "another matcher",
		"keyword:full:a.b":           "another matcher",
		"geosite:рф":                 "invalid geosite code",
	}
	for entry, want := range refused {
		err := Config{Mode: ModeFakeIP, FakeIPFilter: []string{entry}}.Validate("xray")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Validate(%q) = %v, want an error naming %q", entry, err, want)
		}
	}
	// Entries xray takes that mihomo's domain trie would not.
	accepted := []string{"regexp:^a.*b$", "keyword:a+b", "a*b", "*foo.com", "+.lan", "geosite:cn@ads", "domain:example.com"}
	if err := (Config{Mode: ModeFakeIP, FakeIPFilter: accepted}).Validate("xray"); err != nil {
		t.Errorf("Validate(%v) = %v, want nil", accepted, err)
	}
}

func TestValidateFakeIPFilterOnlyWhereItIsRead(t *testing.T) {
	bad := []string{"a*b", "rule-set:x"}
	for name, c := range map[string]struct {
		cfg    Config
		engine string
	}{
		"normal mode": {Config{Mode: ModeNormal, FakeIPFilter: bad}, "mihomo"},
		"unset mode":  {Config{FakeIPFilter: bad}, "mihomo"},
		"awg":         {Config{Mode: ModeFakeIP, FakeIPFilter: bad}, "awg"},
	} {
		if err := c.cfg.Validate(c.engine); err != nil {
			t.Errorf("%s: Validate = %v, want nil", name, err)
		}
	}
}
