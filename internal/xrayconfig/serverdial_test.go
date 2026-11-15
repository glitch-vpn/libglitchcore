package xrayconfig

import (
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
	xrayConf "github.com/xtls/xray-core/infra/conf"
)

func interfaceOf(ob xrayConf.OutboundDetourConfig) string {
	if ob.StreamSetting == nil || ob.StreamSetting.SocketSettings == nil {
		return ""
	}
	return ob.StreamSetting.SocketSettings.Interface
}

// A server's own dial leaves through the physical adapter whatever its
// address family; a hop after the first dials through the hop before it.
func TestServerDials_LeaveThroughThePhysicalInterface(t *testing.T) {
	resolveAs(t, map[string]string{"one.example": "192.0.2.11", "two.example": "192.0.2.12"})
	prof := namedProfile(
		routing.Route{To: "s1", Match: []string{"full:a.example"}},
		routing.Route{To: "g1", Match: []string{"full:b.example"}},
		routing.Route{To: "c1", Match: []string{"full:c.example"}},
	)
	prof.DirectInterface = "Ethernet"
	v6Link := "ss://chacha20-ietf-poly1305:pw@[2001:db8::7]:8388#six"
	res, err := BuildConfig([]string{v6Link, poolLink}, BalancerOptions{}, prof, "none")
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"proxy-0", "proxy-1", "rt-s1", "rg-g1-0", "rg-g1-1", "rc-c1-0"} {
		if got := interfaceOf(outboundByTag(t, res.Config, tag)); got != "Ethernet" {
			t.Errorf("%s: interface %q", tag, got)
		}
	}
	for _, tag := range []string{"rc-c1-1", "rc-c1-2"} {
		if got := interfaceOf(outboundByTag(t, res.Config, tag)); got != "" {
			t.Errorf("%s: a later hop bound to %q", tag, got)
		}
	}
}

func TestServerDials_UnboundWithoutAPhysicalInterface(t *testing.T) {
	res, err := BuildConfig([]string{poolLink}, BalancerOptions{}, routing.Profile{}, "none")
	if err != nil {
		t.Fatal(err)
	}
	if got := interfaceOf(outboundByTag(t, res.Config, OutboundTag)); got != "" {
		t.Errorf("interface %q", got)
	}
}

func TestServerDials_LoopbackServerStaysUnbound(t *testing.T) {
	prof := routing.Profile{DirectInterface: "Ethernet"}
	for _, link := range []string{"ss://chacha20-ietf-poly1305:pw@127.0.0.5:8388#local", "ss://chacha20-ietf-poly1305:pw@[::1]:8388#local"} {
		res, err := BuildConfig([]string{link}, BalancerOptions{}, prof, "none")
		if err != nil {
			t.Fatal(err)
		}
		if got := interfaceOf(outboundByTag(t, res.Config, OutboundTag)); got != "" {
			t.Errorf("%s: interface %q", link, got)
		}
	}
}
