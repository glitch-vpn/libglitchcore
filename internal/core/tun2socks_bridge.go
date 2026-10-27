//go:build !no_xray || (!no_mihomo && !no_awg)

package core

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"
	"github.com/xjasonlyu/tun2socks/v2/proxy/reject"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// tun2socksParams configures the shared TUN bridge used by xray and
// Windows-desktop mihomo. One wireguard/Wintun TUN in front of the engine
// avoids the Wintun cross-binding conflict mihomo's own sing-tun caused on
// Windows ("duplicate name" / device-installation-mutex). The bridge hands
// each flow to the engine in process, so the TUN path opens no listener.
type tun2socksParams struct {
	proxy       t2sproxy.Proxy
	forceProxy  t2sproxy.Proxy // always tunnels: where process->proxy flows go (may be nil)
	tunFd       int            // fd path (non-Windows): a copy this start owns
	serverIPv4s []string       // proxy server IPs pinned off the TUN (Windows)
	dnsServer   string
	logLevel    string
	routing     routing.Profile
}

// tun2socks builds its proxy from Key.Proxy before it creates the stack, so
// the session's proxy rides a scheme only the core registers: no flow ever
// meets a default.
const bridgeProxyURL = "inprocess://engine"

var (
	bridgeProxyMu sync.Mutex
	bridgeProxy   t2sproxy.Proxy
)

func init() {
	t2sproxy.RegisterProtocol("inprocess", func(*url.URL) (t2sproxy.Proxy, error) {
		bridgeProxyMu.Lock()
		defer bridgeProxyMu.Unlock()
		if bridgeProxy == nil {
			return nil, errors.New("no session proxy")
		}
		return bridgeProxy, nil
	})
}

func setBridgeProxy(p t2sproxy.Proxy) {
	bridgeProxyMu.Lock()
	bridgeProxy = p
	bridgeProxyMu.Unlock()
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

// startTun2socks bridges the platform TUN to params.proxy. On the fd path it
// takes the start's own copy of the fd, made in the FFI call: disconnect must
// not double-close the platform-owned (ParcelFileDescriptor) fd.
func (x *CoreController) startTun2socks(p tun2socksParams) error {
	var devURI string
	if runtime.GOOS == "windows" {
		devURI = "tun://GlitchVPN"
	} else {
		if p.tunFd < 0 {
			return errors.New("no TUN fd")
		}
		devURI = fmt.Sprintf("fd://%d", p.tunFd)
	}

	logLevel := capTun2socksLogLevel(p.logLevel)
	setBridgeProxy(sessionBridgeProxy(p))
	key := &engine.Key{
		Device:                   devURI,
		Proxy:                    bridgeProxyURL,
		LogLevel:                 logLevel,
		MTU:                      tun2socksMTU(),
		UDPTimeout:               tun2socksUDPTimeout(),
		Interface:                "",
		TCPModerateReceiveBuffer: true,
		TCPSendBufferSize:        "4m",
		TCPReceiveBufferSize:     "4m",
	}
	// engine.Start owns the dup from here, whether it succeeds or not.
	engine.Insert(key)
	startErr := engine.Start()
	useTun2socksSink(logLevel)
	if startErr != nil {
		setBridgeProxy(nil)
		return fmt.Errorf("start tun2socks: %w", startErr)
	}
	x.isTun2socksRunning.Store(true)
	x.tun2socksKey = key
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
		logfmt.Warnf("[tun2socks] stop timed out after 5s, forcing cleanup")
	}
	x.tun2socksKey = nil
	x.isTun2socksRunning.Store(false)
	// The tunnel outlives the engine: a flow tun2socks still holds must not
	// reach the session's engine once it is stopped.
	tunnel.T().SetProxy(&reject.Reject{})
	setBridgeProxy(nil)
	if runtime.GOOS == "windows" {
		cleanupTun("GlitchVPN")
	}
}
