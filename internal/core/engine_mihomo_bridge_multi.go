//go:build !no_mihomo && (!no_xray || !no_awg)

package core

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// Windows needs the tun2socks bridge - mihomo's Wintun conflicts with tun2socks'.
// Android uses native sing-tun (GLITCH_MIHOMO_ANDROID_BRIDGE=1 forces bridge).
func (x *CoreController) mihomoUsesBridge(proxyPort int) bool {
	if proxyPort > 0 {
		return false
	}
	if runtime.GOOS == "android" {
		return os.Getenv("GLITCH_MIHOMO_ANDROID_BRIDGE") == "1"
	}
	return runtime.GOOS == "windows"
}

// Loopback mixed inbound + bridge plan; defaults dns to fake-ip (like native path).
func (x *CoreController) mihomoBuildBridgeInbound(dns *dnsconfig.Config, prof routing.Profile) (mihomoconfig.Inbound, *bridgeSetup, error) {
	p, perr := pickLoopbackPort()
	if perr != nil {
		return mihomoconfig.Inbound{}, nil, fmt.Errorf("[mihomo] pick bridge port: %w", perr)
	}
	b := &bridgeSetup{mixedPort: p}
	in := mihomoconfig.Inbound{MixedPort: p, Interface: physicalInterfaceName()}

	if strings.TrimSpace(dns.Mode) == "" {
		dns.Mode = dnsconfig.ModeFakeIP
	}
	if len(dns.NormalizedServers("")) == 0 {
		dns.Servers = []string{xrayDefaultDnsServer}
	}
	// mihomo can't dns-hijack without a TUN, so run its DNS server on loopback and
	// have the tun2socks bridge redirect the app's :53 to it.
	if dns.FakeIP() {
		dp, derr := pickLoopbackPort()
		if derr != nil {
			return mihomoconfig.Inbound{}, nil, fmt.Errorf("[mihomo] pick dns port: %w", derr)
		}
		in.DNS = *dns
		in.DNSListenPort = dp
		b.dnsRedirect = fmt.Sprintf("127.0.0.1:%d", dp)
	}
	// process->proxy needs a mode-independent force-proxy inbound so "route only
	// this app via VPN" holds even in direct-all mode.
	if routingHasForceProxy(prof) {
		fp, ferr := pickLoopbackPort()
		if ferr != nil {
			return mihomoconfig.Inbound{}, nil, fmt.Errorf("[mihomo] pick force-proxy port: %w", ferr)
		}
		in.ForceProxyPort = fp
		b.forceProxyURL = fmt.Sprintf("socks5://127.0.0.1:%d", fp)
	}
	return in, b, nil
}

// serverIPv4s empty: Windows binds by interface, Android excludes our package.
func (x *CoreController) mihomoStartBridge(b *bridgeSetup, prof routing.Profile, dns dnsconfig.Config, tunFd int) error {
	dnsServer := dns.FirstPlainServer()
	if dnsServer == "" {
		dnsServer = xrayDefaultDnsServer
	}
	if err := x.startTun2socks(tun2socksParams{
		proxyURL:        fmt.Sprintf("socks5://127.0.0.1:%d", b.mixedPort),
		tunFd:           tunFd,
		dnsServer:       dnsServer,
		logLevel:        "warning",
		routing:         prof,
		forceProxyURL:   b.forceProxyURL,
		dnsRedirectAddr: b.dnsRedirect,
	}); err != nil {
		x.stopTun2socks()
		return err
	}
	log.Printf("[mihomo] bridge (%s): mixed proxy 127.0.0.1:%d + tun2socks TUN", runtime.GOOS, b.mixedPort)
	return nil
}

func (x *CoreController) mihomoStopBridge() { x.stopTun2socks() }
