package mihomoconfig

import "testing"

// ProxyNames must reproduce BuildConfig's naming exactly - the selection
// watcher maps a group's Now() back to a link index through it.
func TestProxyNames(t *testing.T) {
	names := ProxyNames([]string{
		"vless://u@a.example.com:443#Alpha",
		"",
		"vless://u@b.example.com:443",       // no fragment -> positional fallback
		"vless://u@c.example.com:443#Alpha", // duplicate remark -> uniquified
	})
	want := []string{"Alpha", "proxy-2", "Alpha (2)"}
	if len(names) != len(want) {
		t.Fatalf("names = %v", names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("names[%d] = %q, want %q (all: %v)", i, names[i], want[i], names)
		}
	}
}

func TestTarget_ProxyOrBalancerGroup(t *testing.T) {
	one := []string{"ss://aes-128-gcm:pass@5.6.7.8:8388#solo"}
	if got := Target(one); got != "solo" {
		t.Fatalf("Target(one link) = %q, want the proxy's name", got)
	}
	if got := Target(append(one, "ss://aes-128-gcm:pass@5.6.7.9:8388#other")); got != GroupTag {
		t.Fatalf("Target(two links) = %q, want %q", got, GroupTag)
	}
}
