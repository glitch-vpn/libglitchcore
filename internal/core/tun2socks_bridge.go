//go:build !no_xray || (!no_mihomo && !no_awg)

package core

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
	"github.com/xjasonlyu/tun2socks/v2/proxy/reject"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// tun2socksParams configures the shared TUN->loopback-proxy bridge used by xray
// and Windows-desktop mihomo. One wireguard/Wintun TUN fronting a local proxy
// avoids the Wintun cross-binding conflict mihomo's own sing-tun caused on
// Windows ("duplicate name" / device-installation-mutex).
type tun2socksParams struct {
	proxyURL      string   // socks5://[user:pass@]host:port
	tunFd         int      // fd path (non-Windows)
	serverIPv4s   []string // proxy server IPs pinned off the TUN (Windows)
	dnsServer     string
	logLevel      string
	routing       routing.Profile
	forceProxyURL string // xray force-proxy inbound URL (empty for mihomo)
	// dnsRedirectAddr diverts the app's :53 to a local resolver. Used by
	// mihomo fake-ip on Windows: it runs its own DNS server but can't dns-hijack
	// without a TUN, so the bridge redirects DNS to it. xray leaves this empty.
	dnsRedirectAddr string
}

func tun2socksMTU() int {
	mtu := defaultTunMTU
	if s := os.Getenv("GLITCH_TUN2SOCKS_MTU"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 1200 && v <= 1500 {
			mtu = v
		}
	}
	return mtu
}

func tun2socksUDPTimeout() time.Duration {
	udpTimeout := 30 * time.Second
	if s := os.Getenv("GLITCH_TUN2SOCKS_UDP_TIMEOUT_SEC"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 5 && v <= 300 {
			udpTimeout = time.Duration(v) * time.Second
		}
	}
	return udpTimeout
}

// startTun2socks bridges the platform TUN to params.proxyURL. On the fd path it
// dup's the fd so Go owns its own copy - disconnect must not double-close the
// platform-owned (ParcelFileDescriptor) fd.
func (x *CoreController) startTun2socks(p tun2socksParams) error {
	var devURI string
	if runtime.GOOS == "windows" {
		devURI = "tun://GlitchVPN"
	} else {
		dupFd, err := dupTunFd(p.tunFd)
		if err != nil {
			return fmt.Errorf("dup TUN fd: %w", err)
		}
		devURI = fmt.Sprintf("fd://%d", dupFd)
		log.Printf("[tun2socks] dup'd TUN fd %d -> %d", p.tunFd, dupFd)
	}

	key := &engine.Key{
		Device:                   devURI,
		Proxy:                    p.proxyURL,
		LogLevel:                 p.logLevel,
		MTU:                      tun2socksMTU(),
		UDPTimeout:               tun2socksUDPTimeout(),
		Interface:                "",
		TCPModerateReceiveBuffer: true,
		TCPSendBufferSize:        "4m",
		TCPReceiveBufferSize:     "4m",
	}
	engine.Insert(key)
	go engine.Start()
	x.isTun2socksRunning.Store(true)
	x.tun2socksKey = key
	x.maybeInstallBridgeProxy(p.routing, p.forceProxyURL, p.dnsRedirectAddr)
	log.Println("[tun2socks] started")

	if runtime.GOOS == "windows" {
		if err := configureTunV3("GlitchVPN", "", p.serverIPv4s, p.dnsServer); err != nil {
			return fmt.Errorf("configure tun: %w", err)
		}
	}
	return nil
}

func (x *CoreController) stopTun2socks() {
	if !x.isTun2socksRunning.Load() {
		return
	}
	done := make(chan struct{})
	go func() {
		engine.Stop()
		close(done)
	}()
	select {
	case <-done:
		log.Println("[tun2socks] stopped gracefully")
	case <-time.After(5 * time.Second):
		log.Println("[tun2socks] WARNING: stop timed out after 5s, forcing cleanup")
	}
	x.tun2socksKey = nil
	x.isTun2socksRunning.Store(false)
	x.xraySocksAddress.Store("")
	// Reset the tunnel proxy so the next connect's installBridgeProxy doesn't see
	// our stale wrapper (base points at the now-dead SOCKS) and bail - it must
	// wait for engine.Start to install the fresh base, then re-wrap.
	tunnel.T().SetProxy(&reject.Reject{})
	if runtime.GOOS == "windows" {
		cleanupTun("GlitchVPN")
	}
}
