//go:build !no_xray

package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"
	xrayNet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	xrayCore "github.com/xtls/xray-core/core"
	xrayStats "github.com/xtls/xray-core/features/stats"
	xrayConf "github.com/xtls/xray-core/infra/conf"
)

type xrayEngine struct{}

func (xrayEngine) ID() string { return "xray" }

func (xrayEngine) Start(x *CoreController, req EngineStartRequest) int32 {
	return x.HandleXrayStart(req)
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

func (x *CoreController) HandleXrayStart(req EngineStartRequest) int32 {
	if x == nil {
		return glitchCoreResultError
	}
	if x.isAwgRunning.Load() || x.isMihomoRunning.Load() {
		x.emitStatus(EngineConflictOtherCore, "[Xray] Start rejected: another engine is running")
		return glitchCoreResultError
	}
	// An instance a stop has since ended is not this session's: the start
	// goes ahead and replaces it.
	if x.isXrayRunning.Load() && x.xrayInstanceGen.Load() == x.sessionGen.Load() {
		x.emitStatus(EngineAlreadyRunning, "[Xray] Already running")
		x.startStats(time.Second)
		x.emitStatus(EngineConnected, "[Xray] Connected (already running)")
		x.reemitSessionState()
		return glitchCoreResultSuccess
	}

	// After the guards: a malformed request must not tear down the live
	// session they protect (EngineError clears client session state).
	o, err := optsFromRequest(req, "xray")
	if err != nil {
		x.emitStatus(EngineError, fmt.Sprintf("[Xray] invalid opts: %v", err))
		return glitchCoreResultError
	}

	x.emitStatus(EngineConnecting, "[Xray] Connecting")

	mark := x.sessionGen.Load()
	x.xrayStartsInFlight.Add(1)
	go func() {
		defer x.xrayStartsInFlight.Add(-1)
		err := x.xrayStart(req.Config, req.TunFD, req.DNS, req.LogLevel, o, mark)
		if errors.Is(err, errSessionEnded) {
			log.Println("[Xray] stopped before startup; not starting")
			return
		}
		if err != nil {
			logfmt.Errorf("[Xray] Failed to start Xray: %v", err)
			x.clearSessionState()
			x.emitStatus(EngineError, fmt.Sprintf("[Xray] Failed to start: %v", err))
			return
		}
		if x.abortStaleXraySession(mark) {
			log.Println("[Xray] stopped during startup; not publishing connected state")
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
	if !x.xrayEngaged() {
		x.emitStatus(EngineStopRejectedNotRunning, "[Xray] Stop rejected: not running")
		return glitchCoreResultError
	}

	x.stopStats()
	x.stopLiveness()
	stopGen := x.clearSessionState()
	x.emitStatus(EngineDisconnecting, "[Xray] Disconnecting")

	go func() {
		err := x.xrayStop(stopGen)
		if errors.Is(err, errStopSuperseded) {
			log.Println("[Xray] a start after this stop owns the engine; leaving it")
			return
		}
		if err != nil {
			logfmt.Errorf("[Xray] Failed to stop Xray: %v", err)
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
	if x.xrayEngaged() {
		return glitchCoreResultSuccess
	}
	return glitchCoreResultError
}

// xrayEngaged: running or starting, read without coreMutex, which a start or
// a stop holds for its whole run; callers reach it from the UI thread.
func (x *CoreController) xrayEngaged() bool {
	return x.isXrayRunning.Load() || x.xrayStartsInFlight.Load() > 0
}

// xrayStartGate and xrayStopGate run before a start or a stop takes
// coreMutex; tests hold them there to order them against each other.
var (
	xrayStartGate = func(mark int64) {}
	xrayStopGate  = func(stopGen int64) {}
)

// abortStaleXraySession: true when a stop came in after the start at mark.
// The session's loops are torn down only while its own instance runs: a
// later start that replaced it armed the loops running now.
func (x *CoreController) abortStaleXraySession(mark int64) bool {
	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()
	if x.sessionGen.Load() == mark {
		return false
	}
	if x.isXrayRunning.Load() && x.xrayInstanceGen.Load() == mark {
		x.abortStaleSession(mark)
	}
	return true
}

func (x *CoreController) xrayStart(rawconfig string, tunFd int, dnsServer string, logLevel int, o engineOpts, mark int64) (err error) {
	xrayStartGate(mark)
	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()

	// A stop that came in before this start took the lock has already run.
	if x.sessionGen.Load() != mark {
		return errSessionEnded
	}
	if x.isXrayRunning.Load() {
		if x.xrayInstanceGen.Load() == mark {
			log.Println("[Xray] Core is already running")
			return nil
		}
		// A start before the stop this one was queued behind: replace it, or
		// this session would report connected on that one's TUN.
		log.Println("[Xray] Replacing the instance of an ended session")
		x.stopLiveness()
		x.stopSelectionWatch()
		x.stopIPResolve()
		x.xrayStopLocked()
	}
	if x.isAwgRunning.Load() || x.isMihomoRunning.Load() {
		return fmt.Errorf("[Xray] another engine is already running")
	}
	log.Println("[Xray] Initializing core")

	// Before cfg.Build(): xray resolves geoip.dat/geosite.dat lazily from the
	// env during the build.
	applyGeoAssetsDir(o.geoAssetsDir)

	// Master switch off (default) forces xray + tun2socks silent regardless of
	// the connect logLevel.
	effectiveLogLevel := logLevel
	if atomic.LoadInt32(&statusVerbosity) < 0 {
		effectiveLogLevel = 0
	}
	xrayLogLevel, tun2socksLogLevel := xrayconfig.LogLevels(effectiveLogLevel)
	var cfg xrayConf.Config

	log.Printf("[Xray] Parsing link(s)")
	links := splitLinks(rawconfig)
	routing := o.routing
	// Windows: direct egress must bind the physical NIC (IP_UNICAST_IF), else it
	// loops back through the TUN - a source-IP bind is not enough.
	routing.DirectSendThrough = physicalInterfaceIP()
	routing.DirectInterface = physicalInterfaceName()
	ds, ok := xrayconfig.NormalizeDomainStrategy(routing.DomainStrategy)
	if !ok {
		return fmt.Errorf("[Xray] invalid domainStrategy %q (want asis|ipifnonmatch|ipondemand)", routing.DomainStrategy)
	}
	routing.DomainStrategy = ds
	res, err := xrayconfig.BuildConfig(links, xrayconfig.BalancerOptions{Strategy: o.strategy, ProbeURL: o.probeURL}, routing, xrayLogLevel)
	if err != nil {
		return fmt.Errorf("[Xray] Link parse error: %w", err)
	}
	cfg = *res.Config

	if len(cfg.OutboundConfigs) == 0 {
		return fmt.Errorf("[Xray] No outbound built from link")
	}

	serverDialIPv4s := res.DialIPv4s
	if res.RouteIsBalancer {
		log.Printf("[Xray] Load balancing across %d servers via tags %v", len(res.OutboundTags), res.OutboundTags)
	}

	if cfg.LogConfig == nil {
		cfg.LogConfig = &xrayConf.LogConfig{}
	}
	cfg.LogConfig.LogLevel = xrayLogLevel
	cfg.LogConfig.AccessLog = ""
	cfg.LogConfig.ErrorLog = ""
	cfg.LogConfig.DNSLog = false
	// xray's lines name the addresses it dials and resolves; "half" keeps
	// the /16 (IPv6 /32) a support reader needs to tell networks apart.
	// mihomo has no such option, so its lines keep theirs.
	cfg.LogConfig.MaskAddress = "half"
	xrayconfig.ApplyDNS(&cfg, o.dns, routing)
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
		stats := x.xrayCoreInstance.GetFeature(xrayStats.ManagerType()).(xrayStats.Manager)
		x.xrayTraffic.Store(&xrayTrafficSource{stats: stats, tags: res.OutboundTags})
		x.xrayInstanceGen.Store(mark)
		x.isXrayRunning.Store(true)
		if err = x.xrayCoreInstance.Start(); err != nil {
			x.xrayRollback()
			return fmt.Errorf("[Xray] Startup failed: %w", err)
		}
		if !waitSocksReady(endpoint) {
			x.xrayRollback()
			return fmt.Errorf("[Xray] proxy SOCKS not ready at %s", endpoint)
		}
		_ = stats.Start()
		x.startLiveness(livenessParams{
			engine:   "xray",
			interval: livenessInterval(o.livenessSec),
			probe:    socksProber(loopbackSocksURL(endpoint, o.proxyUser, o.proxyPass), o.probeURL),
		})
		x.initXrayServerState(res, links, o, stats)
		x.configureIPResolve(ipResolveConfig{
			enabled: o.resolveIP,
			urlV4:   o.ipEchoV4,
			urlV6:   o.ipEchoV6,
			skipV6:  o.dns.DisableIPv6,
			dial:    x.xrayTunnelDial(x.xrayCoreInstance, xrayconfig.ExitEchoTag, mark),
		})
		log.Printf("[Xray] Proxy mode: SOCKS5 at %s (no TUN)", endpoint)
		return nil
	}

	builtCfg, err := cfg.Build()
	if err != nil {
		return fmt.Errorf("[Xray] Config build failed: %w", err)
	}
	x.xrayCoreInstance, err = xrayCore.New(builtCfg)
	if err != nil {
		return fmt.Errorf("[Xray] Core init failed: %w", err)
	}
	stats := x.xrayCoreInstance.GetFeature(xrayStats.ManagerType()).(xrayStats.Manager)
	x.xrayTraffic.Store(&xrayTrafficSource{stats: stats, tags: res.OutboundTags})

	log.Println("[Xray] Starting core")
	x.xrayInstanceGen.Store(mark)
	x.isXrayRunning.Store(true)
	if err := x.xrayCoreInstance.Start(); err != nil {
		x.xrayRollback()
		return fmt.Errorf("[Xray] Startup failed: %w", err)
	}
	log.Println("[Xray] Core initialized")

	sniffing := xrayconfig.AppSniffing(o.sniffing)
	appProxy, err := x.newXrayBridgeProxy(x.xrayCoreInstance, xrayconfig.AppTrafficTag, sniffing, mark)
	if err != nil {
		x.xrayRollback()
		return fmt.Errorf("[Xray] bridge: %w", err)
	}
	var forceProxy t2sproxy.Proxy
	if routingHasForceProxy(routing) {
		if forceProxy, err = x.newXrayBridgeProxy(x.xrayCoreInstance, xrayconfig.ForceProxyTag, sniffing, mark); err != nil {
			x.xrayRollback()
			return fmt.Errorf("[Xray] bridge: %w", err)
		}
	}

	log.Println("[Xray] Starting tun2socks")
	if err := x.startTun2socks(tun2socksParams{
		proxy:       appProxy,
		forceProxy:  forceProxy,
		tunFd:       tunFd,
		serverIPv4s: serverDialIPv4s,
		dnsServer:   dnsServer,
		logLevel:    tun2socksLogLevel,
		routing:     routing,
	}); err != nil {
		x.stopTun2socks()
		x.xrayRollback()
		return fmt.Errorf("[Xray] %w", err)
	}

	if err := stats.Start(); err != nil {
		logfmt.Errorf("[Xray] Stats manager start error: %v", err)
	}

	log.Println("[Xray] Started successfully, running")

	// Probe inside xray as app traffic, so liveness follows the user's path
	// and works on Android, where our own sockets bypass the VPN.
	x.startLiveness(livenessParams{
		engine:   "xray",
		interval: livenessInterval(o.livenessSec),
		probe:    tunnelProber(x.xrayTunnelDial(x.xrayCoreInstance, xrayconfig.AppTrafficTag, mark), o.probeURL),
	})
	x.initXrayServerState(res, links, o, stats)
	x.configureIPResolve(ipResolveConfig{
		enabled: o.resolveIP,
		urlV4:   o.ipEchoV4,
		urlV6:   o.ipEchoV6,
		skipV6:  o.dns.DisableIPv6,
		dial:    x.xrayTunnelDial(x.xrayCoreInstance, xrayconfig.ExitEchoTag, mark),
	})

	return nil
}

// waitSocksReady waits for the proxy-mode inbound to accept, for
// GLITCH_SOCKS_READY_TIMEOUT_SEC (SetSocksReadyTimeoutSec) or 5s.
func waitSocksReady(endpoint string) bool {
	budget := 5 * time.Second
	if v, err := strconv.Atoi(os.Getenv("GLITCH_SOCKS_READY_TIMEOUT_SEC")); err == nil && v > 0 && v <= 60 {
		budget = time.Duration(v) * time.Second
	}
	for start := time.Now(); time.Since(start) < budget; time.Sleep(100 * time.Millisecond) {
		if c, err := net.DialTimeout("tcp", endpoint, 300*time.Millisecond); err == nil {
			_ = c.Close()
			return true
		}
	}
	return false
}

// xrayRollback undoes a start that got as far as creating the instance.
func (x *CoreController) xrayRollback() {
	x.isXrayRunning.Store(false)
	x.xrayTraffic.Store(nil)
	if x.xrayCoreInstance != nil {
		_ = x.xrayCoreInstance.Close()
		x.xrayCoreInstance = nil
	}
}

// errStopSuperseded: the instance running was started after the stop was
// asked for, by a start queued behind it; the stop leaves it to that session.
var errStopSuperseded = errors.New("a later start owns the engine")

// xrayStop stops the instance a start before stopGen brought up.
func (x *CoreController) xrayStop(stopGen int64) error {
	xrayStopGate(stopGen)
	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()

	if x.isXrayRunning.Load() && x.xrayInstanceGen.Load() >= stopGen {
		return errStopSuperseded
	}
	x.xrayStopLocked()
	return nil
}

// xrayStopLocked closes the bridge and the instance. The caller holds
// coreMutex.
func (x *CoreController) xrayStopLocked() {
	x.stopTun2socks()

	if x.isXrayRunning.Load() {
		done := make(chan struct{})
		go func() {
			if cerr := x.xrayCoreInstance.Close(); cerr != nil {
				logfmt.Errorf("[Xray] Core shutdown error: %v", cerr)
			}
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			logfmt.Warnf("[Xray] Xray core close timed out after 5s")
		}
		x.xrayCoreInstance = nil
		x.isXrayRunning.Store(false)
		x.xrayTraffic.Store(nil)
	}

	log.Println("[Xray] Core stopped")
}

// xrayTunnelDial dials inside the instance as the inbound tag names:
// ExitEchoTag takes the proxy ahead of the routing tiers,
// AppTrafficTag routes like the user's traffic. Like mihomoTunnelDial it
// refuses once the session that started at mark has ended.
func (x *CoreController) xrayTunnelDial(inst *xrayCore.Instance, tag string, mark int64) tunnelDialFunc {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		if x.sessionGen.Load() != mark {
			return nil, errSessionEnded
		}
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, err := xrayNet.PortFromString(portStr)
		if err != nil {
			return nil, err
		}
		ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: tag})
		return xrayCore.Dial(ctx, inst, xrayNet.TCPDestination(xrayNet.ParseAddress(host), port))
	}
}

func (x *CoreController) getXrayTraffic() (uint64, uint64) {
	src := x.xrayTraffic.Load()
	if src == nil {
		return 0, 0
	}
	return sumOutboundTraffic(xrayStatsSource{src.stats}, src.tags)
}

func sumOutboundTraffic(src statsSource, tags []string) (rx, tx uint64) {
	if len(tags) == 0 {
		tags = []string{xrayconfig.OutboundTag}
	}
	for _, tag := range tags {
		up, down := outboundTraffic(src, tag)
		rx += down
		tx += up
	}
	return rx, tx
}
