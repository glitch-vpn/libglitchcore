//go:build !no_mihomo && (!no_xray || !no_awg)

package core

import (
	"log"
	"os"
	"runtime"
	"strings"

	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// Windows needs the tun2socks bridge - mihomo's Wintun conflicts with tun2socks'.
// Android uses native sing-tun: through the bridge, mihomo's fake-ip stopped
// resolving addresses (GLITCH_MIHOMO_ANDROID_BRIDGE=1 forces the bridge).
func (x *CoreController) mihomoUsesBridge(proxyPort int) bool {
	if proxyPort > 0 {
		return false
	}
	if runtime.GOOS == "android" {
		return os.Getenv("GLITCH_MIHOMO_ANDROID_BRIDGE") == "1"
	}
	return runtime.GOOS == "windows"
}

// Bridge inbound + plan; defaults dns to fake-ip (like native path).
func mihomoBridgeInbound(dns *dnsconfig.Config, prof routing.Profile) (mihomoconfig.Inbound, *bridgeSetup) {
	if strings.TrimSpace(dns.Mode) == "" {
		dns.Mode = dnsconfig.ModeFakeIP
	}
	if len(dns.NormalizedServers("")) == 0 {
		dns.Servers = []string{xrayDefaultDnsServer}
	}
	b := &bridgeSetup{
		hijackDNS:   dns.FakeIP(),
		forceProxy:  routingHasForceProxy(prof),
		forceDirect: routingHasForceDirect(prof),
	}
	in := mihomoconfig.Inbound{
		Bridge:      true,
		Interface:   physicalInterfaceName(),
		DNS:         *dns,
		ForceProxy:  b.forceProxy,
		ForceDirect: b.forceDirect,
	}
	return in, b
}

// serverIPv4s empty: Windows binds by interface, Android excludes our package.
func (x *CoreController) mihomoStartBridge(b *bridgeSetup, prof routing.Profile, dns dnsconfig.Config, tunFd int, mark int64) error {
	dnsServer := dns.FirstPlainServer()
	if dnsServer == "" {
		dnsServer = xrayDefaultDnsServer
	}
	app, forceProxy, forceDirect := mihomoBridgeProxies(x, b, mark)
	if err := x.startTun2socks(tun2socksParams{
		proxy:       app,
		forceProxy:  forceProxy,
		forceDirect: forceDirect,
		tunFd:       tunFd,
		dnsServer:   dnsServer,
		logLevel:    "warning",
		routing:     prof,
	}); err != nil {
		x.stopTun2socks()
		return err
	}
	log.Printf("[mihomo] bridge (%s): tun2socks TUN into mihomo's tunnel", runtime.GOOS)
	return nil
}

// mihomoBridgeProxies are what tun2socks hands flows to; force is nil when
// no process->proxy rule needs flows that always tunnel, and direct when no
// process->direct rule needs flows that meet the blocks.
func mihomoBridgeProxies(x *CoreController, b *bridgeSetup, mark int64) (app, force, direct t2sproxy.Proxy) {
	app = &mihomoBridgeProxy{x: x, mark: mark, hijackDNS: b.hijackDNS}
	if b.forceProxy {
		force = &mihomoBridgeProxy{x: x, mark: mark, inName: mihomoconfig.ForceProxyInName}
	}
	if b.forceDirect {
		direct = &mihomoBridgeProxy{x: x, mark: mark, inName: mihomoconfig.ForceDirectInName}
	}
	return app, force, direct
}

func (x *CoreController) mihomoStopBridge() { x.stopTun2socks() }
