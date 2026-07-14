package dnsconfig

import "testing"

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

func TestFakeIP(t *testing.T) {
	if !(Config{Mode: "fake-ip"}).FakeIP() {
		t.Fatal("fake-ip not detected")
	}
	if (Config{Mode: "normal"}).FakeIP() || (Config{}).FakeIP() {
		t.Fatal("non-fake-ip misdetected")
	}
}
