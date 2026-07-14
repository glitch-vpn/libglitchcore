//go:build !no_xray

package core

import (
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
	xrayCore "github.com/xtls/xray-core/core"
	xrayStats "github.com/xtls/xray-core/features/stats"
	xrayConf "github.com/xtls/xray-core/infra/conf"
)

type xrayEngine struct{}

func (xrayEngine) ID() string { return "xray" }

func (xrayEngine) Start(x *CoreController, req EngineStartRequest) int32 {
	return x.HandleXrayStart(req.Config, req.TunFD, req.DNS, req.LogLevel, optsFromRequest(req))
}

func (xrayEngine) Stop(x *CoreController) int32 { return x.HandleXrayStop() }

func (xrayEngine) IsRunning(x *CoreController) int32 { return x.HandleXrayIsRunning() }

func (xrayEngine) Traffic(x *CoreController) (uint64, uint64, bool) {
	if !x.isXrayRunning.Load() {
		return 0, 0, false
	}
	rx, tx := x.getXrayTraffic()
	return rx, tx, true
}

func init() {
	registerEngine(xrayEngine{})
	registerEngineVersion("xray_core", func() string { return builtXrayCoreVersion })
}

func (x *CoreController) HandleXrayStart(rawconfig string, tunFd int, dnsServer string, logLevel int, o engineOpts) int32 {
	if x == nil {
		return glitchCoreResultError
	}
	if x.isAwgRunning.Load() || x.isMihomoRunning.Load() {
		x.emitStatus(EngineConflictOtherCore, "[Xray] Start rejected: another engine is running")
		return glitchCoreResultError
	}
	if x.isXrayRunning.Load() {
		x.emitStatus(EngineAlreadyRunning, "[Xray] Already running")
		x.startStats(time.Second)
		x.emitStatus(EngineConnected, "[Xray] Connected (already running)")
		return glitchCoreResultSuccess
	}

	x.emitStatus(EngineConnecting, "[Xray] Connecting")

	go func() {
		if err := x.xrayStart(rawconfig, tunFd, dnsServer, logLevel, o); err != nil {
			log.Printf("[Xray] Failed to start Xray: %v", err)
			x.emitStatus(EngineError, fmt.Sprintf("[Xray] Failed to start: %v", err))
			return
		}
		x.startStats(time.Second)
		x.emitStatus(EngineConnected, "[Xray] Connected")
	}()

	return glitchCoreResultSuccess
}

func (x *CoreController) HandleXrayStop() int32 {
	if x == nil {
		return glitchCoreResultError
	}
	if !x.isXrayRunning.Load() {
		x.emitStatus(EngineStopRejectedNotRunning, "[Xray] Stop rejected: not running")
		return glitchCoreResultError
	}

	x.stopStats()
	x.stopHealthCheck()
	x.stopLiveness()
	x.emitStatus(EngineDisconnecting, "[Xray] Disconnecting")

	go func() {
		if err := x.xrayStop(); err != nil {
			log.Printf("[Xray] Failed to stop Xray: %v", err)
			x.emitStatus(EngineError, fmt.Sprintf("[Xray] Failed to stop: %v", err))
			return
		}
		x.emitStatus(EngineDisconnected, "[Xray] Disconnected")
	}()

	return glitchCoreResultSuccess
}

func (x *CoreController) HandleXrayIsRunning() int32 {
	if x == nil {
		return glitchCoreResultError
	}
	if x.xrayRunning() {
		return glitchCoreResultSuccess
	}
	return glitchCoreResultError
}

func (x *CoreController) xrayStart(rawconfig string, tunFd int, dnsServer string, logLevel int, o engineOpts) (err error) {
	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()

	if x.isXrayRunning.Load() {
		log.Println("[Xray] Core is already running")
		return nil
	}
	if x.isAwgRunning.Load() || x.isMihomoRunning.Load() {
		return fmt.Errorf("[Xray] another engine is already running")
	}
	log.Println("[Xray] Initializing core")

	// Master switch off (default) forces xray + tun2socks silent regardless of
	// the connect logLevel.
	effectiveLogLevel := logLevel
	if atomic.LoadInt32(&statusVerbosity) < 0 {
		effectiveLogLevel = 0
	}
	xrayLogLevel, tun2socksLogLevel := xrayconfig.LogLevels(effectiveLogLevel)
	tun2socksLogLevel = xrayconfig.CapTun2socksLogLevel(tun2socksLogLevel)
	var proxyAddress string
	var proxyURL string
	var forceProxyURL string
	var cfg xrayConf.Config

	log.Printf("[Xray] Parsing link(s)")
	links := splitLinks(rawconfig)
	routing := o.routing
	// Windows: direct egress must bind the physical NIC (IP_UNICAST_IF), else it
	// loops back through the TUN - a source-IP bind is not enough.
	routing.DirectSendThrough = physicalInterfaceIP()
	routing.DirectInterface = physicalInterfaceName()
	res, err := xrayconfig.BuildConfig(links, xrayconfig.BalancerOptions{Strategy: o.strategy, ProbeURL: o.probeURL}, routing, xrayLogLevel)
	if err != nil {
		return fmt.Errorf("[Xray] Link parse error: %w", err)
	}
	cfg = *res.Config

	if len(cfg.OutboundConfigs) == 0 {
		return fmt.Errorf("[Xray] No outbound built from link")
	}

	x.xrayOutboundTags.Store(res.OutboundTags)
	serverDialIPv4s := res.DialIPv4s
	if res.RouteIsBalancer {
		log.Printf("[Xray] Load balancing across %d servers via tags %v", len(res.OutboundTags), res.OutboundTags)
	}

	if cfg.LogConfig == nil {
		cfg.LogConfig = &xrayConf.LogConfig{LogLevel: xrayLogLevel, AccessLog: "", ErrorLog: "", DNSLog: false}
	} else {
		cfg.LogConfig.LogLevel = xrayLogLevel
		cfg.LogConfig.AccessLog = ""
		cfg.LogConfig.ErrorLog = ""
		cfg.LogConfig.DNSLog = false
	}
	xrayconfig.ApplyDNS(&cfg, o.dns)
	xrayconfig.ApplyMux(&cfg, res.OutboundTags, res.VisionTags, o.muxConcurrency, o.xudpConcurrency)
	xrayconfig.ApplyFingerprint(&cfg, res.OutboundTags, o.fingerprint)

	cfg.Stats = &xrayConf.StatsConfig{}
	cfg.Policy = &xrayConf.PolicyConfig{
		System: &xrayConf.SystemPolicy{
			StatsInboundUplink:    true,
			StatsInboundDownlink:  true,
			StatsOutboundUplink:   true,
			StatsOutboundDownlink: true,
		},
	}

	// Proxy mode: loopback SOCKS, no tun2socks/TUN - lets the caller verify a
	// config (curl/browser) without admin rights.
	if o.proxyPort > 0 {
		endpoint, perr := xrayconfig.ApplyProxyInbound(&cfg, o.proxyPort, o.proxyUser, o.proxyPass)
		if perr != nil {
			return fmt.Errorf("[Xray] proxy inbound: %w", perr)
		}
		xrayconfig.ApplySniffing(&cfg, o.sniffing)
		builtCfg, berr := cfg.Build()
		if berr != nil {
			return fmt.Errorf("[Xray] Config build failed: %w", berr)
		}
		if x.xrayCoreInstance, err = xrayCore.New(builtCfg); err != nil {
			return fmt.Errorf("[Xray] Core init failed: %w", err)
		}
		x.xrayStatsManager = x.xrayCoreInstance.GetFeature(xrayStats.ManagerType()).(xrayStats.Manager)
		x.isXrayRunning.Store(true)
		if err = x.xrayCoreInstance.Start(); err != nil {
			x.isXrayRunning.Store(false)
			x.xrayStatsManager = nil
			_ = x.xrayCoreInstance.Close()
			x.xrayCoreInstance = nil
			return fmt.Errorf("[Xray] Startup failed: %w", err)
		}
		ready := false
		for i := 0; i < 50; i++ {
			if c, derr := net.DialTimeout("tcp", endpoint, 300*time.Millisecond); derr == nil {
				_ = c.Close()
				ready = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !ready {
			return fmt.Errorf("[Xray] proxy SOCKS not ready at %s", endpoint)
		}
		x.xraySocksAddress.Store(endpoint)
		if x.xrayStatsManager != nil {
			_ = x.xrayStatsManager.Start()
		}
		x.startLiveness(livenessParams{
			engine:   "xray",
			interval: livenessInterval(o.livenessSec),
			probe:    socksProber(loopbackSocksURL(endpoint, o.proxyUser, o.proxyPass), o.probeURL),
		})
		log.Printf("[Xray] Proxy mode: SOCKS5 at %s (no TUN)", endpoint)
		return nil
	}

	const socksStartAttempts = 2
	for attempt := 1; attempt <= socksStartAttempts; attempt++ {
		socksSession, sessionProxyURL, sessionErr := xrayconfig.ApplyLocalSocksInbound(&cfg)
		if sessionErr != nil {
			return fmt.Errorf("[Xray] Failed to apply local SOCKS bridge: %w", sessionErr)
		}
		proxyAddress = socksSession.Endpoint()
		proxyURL = sessionProxyURL
		// force-proxy inbound so process->proxy apps tunnel even in direct-all
		// mode; idempotent across retries (findInboundIdx replaces).
		forceProxyURL = forceProxyInboundURL(&cfg, routing)
		xrayconfig.ApplySniffing(&cfg, o.sniffing)

		log.Printf("[Xray] Ensuring authenticated tun2socks inbound at %s", proxyAddress)
		builtCfg, err := cfg.Build()
		if err != nil {
			return fmt.Errorf("[Xray] Config build failed: %w", err)
		}

		x.xrayCoreInstance, err = xrayCore.New(builtCfg)
		if err != nil {
			return fmt.Errorf("[Xray] Core init failed: %w", err)
		}

		x.xrayStatsManager = x.xrayCoreInstance.GetFeature(xrayStats.ManagerType()).(xrayStats.Manager)

		log.Println("[Xray] Starting core")
		x.isXrayRunning.Store(true)

		if err := x.xrayCoreInstance.Start(); err != nil {
			x.isXrayRunning.Store(false)
			x.xrayStatsManager = nil
			if x.xrayCoreInstance != nil {
				_ = x.xrayCoreInstance.Close()
				x.xrayCoreInstance = nil
			}
			if attempt < socksStartAttempts {
				log.Printf("[Xray] Startup failed on local SOCKS %s, retrying with a new port: %v", proxyAddress, err)
				continue
			}
			return fmt.Errorf("[Xray] Startup failed: %w", err)
		}
		break
	}
	log.Println("[Xray] Core initialized")

	log.Println("[Xray] Waiting for SOCKS5 proxy to be ready")
	var socksReady bool
	startWait := time.Now()
	attempts := 0
	timeoutEnv := os.Getenv("GLITCH_SOCKS_READY_TIMEOUT_SEC")
	maxWait := 5 * time.Second
	if timeoutEnv != "" {
		if v, err := strconv.Atoi(timeoutEnv); err == nil && v > 0 && v <= 60 {
			maxWait = time.Duration(v) * time.Second
		}
	}
	for time.Since(startWait) < maxWait {
		attempts++
		c, err := net.DialTimeout("tcp", proxyAddress, 300*time.Millisecond)
		if err == nil {
			_ = c.Close()
			socksReady = true
			log.Printf("[Xray] SOCKS5 proxy is ready at %s (after %d attempts, %.1fs)", proxyAddress, attempts, time.Since(startWait).Seconds())
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !socksReady {
		log.Printf("[Xray] ERROR: SOCKS5 inbound (%s) not ready within %.1fs", proxyAddress, time.Since(startWait).Seconds())
		return fmt.Errorf("[Xray] Socks inbound not ready in time budget")
	}

	log.Println("[Xray] SOCKS5 proxy is ready")
	x.xraySocksAddress.Store(proxyAddress)

	log.Println("[Xray] Starting tun2socks")
	if err := x.startTun2socks(tun2socksParams{
		proxyURL:      proxyURL,
		tunFd:         tunFd,
		serverIPv4s:   serverDialIPv4s,
		dnsServer:     dnsServer,
		logLevel:      tun2socksLogLevel,
		routing:       routing,
		forceProxyURL: forceProxyURL,
	}); err != nil {
		// tun2socks failed but the core is already up - roll back.
		_ = x.xrayCoreInstance.Close()
		x.xrayCoreInstance = nil
		x.isXrayRunning.Store(false)
		return fmt.Errorf("[Xray] %w", err)
	}

	if x.xrayStatsManager != nil {
		if err := x.xrayStatsManager.Start(); err != nil {
			log.Printf("[Xray] Stats manager start error: %v", err)
		}
	}

	log.Println("[Xray] Started successfully, running")

	x.startHealthCheck(15 * time.Second)
	// Probe via the loopback SOCKS (the same path as user traffic) so liveness
	// works on Android, where our own sockets bypass the VPN.
	x.startLiveness(livenessParams{
		engine:   "xray",
		interval: livenessInterval(o.livenessSec),
		probe:    socksProber(proxyURL, o.probeURL),
	})

	return nil
}
func (x *CoreController) xrayStop() error {
	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()

	x.stopTun2socks()

	if x.isXrayRunning.Load() {
		done := make(chan struct{})
		go func() {
			if cerr := x.xrayCoreInstance.Close(); cerr != nil {
				log.Printf("[Xray] Core shutdown error: %v", cerr)
			}
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			log.Println("[Xray] WARNING: Xray core close timed out after 5s")
		}
		x.xrayCoreInstance = nil
		x.isXrayRunning.Store(false)
		x.xrayStatsManager = nil
		x.xrayOutboundTags.Store([]string(nil))
	}

	log.Println("[Xray] Core stopped")
	return nil
}

// process:->proxy needs an always-tunnel inbound so the rule holds in direct-all
// mode; Android routes per-app via VpnService, not here.
func forceProxyInboundURL(cfg *xrayConf.Config, prof routing.Profile) string {
	if runtime.GOOS == "android" || !routingHasForceProxy(prof) {
		return ""
	}
	u, err := xrayconfig.ApplyForceProxyInbound(cfg)
	if err != nil {
		log.Printf("[Xray] force-proxy inbound: %v", err)
		return ""
	}
	return u
}

func (x *CoreController) getXrayTraffic() (uint64, uint64) {
	tags, _ := x.xrayOutboundTags.Load().([]string)
	if len(tags) == 0 {
		tags = []string{xrayconfig.OutboundTag}
	}

	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()

	if x.xrayStatsManager == nil {
		return 0, 0
	}

	var rx, tx uint64
	for _, tag := range tags {
		if uplink := x.xrayStatsManager.GetCounter(fmt.Sprintf(
			"outbound>>>%s>>>traffic>>>uplink", tag)); uplink != nil {
			tx += uint64(uplink.Value())
		}
		if downlink := x.xrayStatsManager.GetCounter(fmt.Sprintf(
			"outbound>>>%s>>>traffic>>>downlink", tag)); downlink != nil {
			rx += uint64(downlink.Value())
		}
	}
	return rx, tx
}
