//go:build !no_xray

package core

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"
	"github.com/xtls/xray-core/common/geodata"
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
	if !x.xraySession.running.Load() {
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
	if x.awgSession.running.Load() || x.mihomoSession.running.Load() {
		x.emitStatus(EngineConflictOtherCore, "[Xray] Start rejected: another engine is running")
		return glitchCoreResultError
	}
	if x.xraySession.runsSession(x.sessionGen.Load()) {
		return x.replyAlreadyRunning("Xray")
	}

	// After the guards: a malformed request must not tear down the live
	// session they protect (EngineError clears client session state).
	o, err := optsFromRequest(req, "xray")
	if err != nil {
		x.emitStatus(EngineError, fmt.Sprintf("[Xray] invalid opts: %v", err))
		return glitchCoreResultError
	}

	x.emitStatus(EngineConnecting, "[Xray] Connecting")

	mark, tun, done, err := x.beginStart(&x.xraySession, req.TunFD)
	if err != nil {
		x.emitStatus(EngineError, fmt.Sprintf("[Xray] Failed to start: %v", err))
		return glitchCoreResultError
	}
	go func() {
		defer done()
		x.finishStart(&x.xraySession, "Xray", mark, x.xrayStart(req.Config, tun, req.DNS, req.LogLevel, o, mark))
	}()

	return glitchCoreResultSuccess
}

func (x *CoreController) HandleXrayStop() int32 {
	if x == nil {
		return glitchCoreResultError
	}
	return x.stopEngineSession(&x.xraySession, "Xray", x.xrayStop)
}

func (x *CoreController) HandleXrayIsRunning() int32 {
	if x == nil {
		return glitchCoreResultError
	}
	if x.xraySession.engaged() {
		return glitchCoreResultSuccess
	}
	return glitchCoreResultError
}

// xrayGeoFolder is the geo folder the process-wide matcher caches of xray were
// last filled from. Guarded by coreMutex.
var xrayGeoFolder string

// dropXrayGeoMatchersOnFolderChange makes a session on a new geo folder read
// that folder's files. xray caches built matchers per process, keyed by list
// code without the folder, and drops one only when the collector frees it, so
// a session would otherwise match a list an earlier folder's file gave. The
// collector runs first so matchers of ended sessions are not rebuilt, then
// xray's own Reload swaps in empty caches. A reload that fails ends the start:
// continuing would route by the old lists.
func dropXrayGeoMatchersOnFolderChange() error {
	folder := os.Getenv(xrayAsset)
	if folder == xrayGeoFolder {
		return nil
	}
	runtime.GC()
	runtime.GC()
	if err := geodata.IPReg.Reload(); err != nil {
		return fmt.Errorf("[Xray] reset geoip lists for %q: %w", folder, err)
	}
	if err := geodata.DomainReg.Reload(); err != nil {
		return fmt.Errorf("[Xray] reset geosite lists for %q: %w", folder, err)
	}
	xrayGeoFolder = folder
	return nil
}

func (x *CoreController) xrayStart(rawconfig string, tun *tunCopy, dnsServer string, logLevel int, o engineOpts, mark int64) (err error) {
	engineStartGate("xray", mark)
	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()

	if already, err := x.prepareStartLocked(&x.xraySession, mark, x.xrayStopLocked); err != nil || already {
		return err
	}
	if x.awgSession.running.Load() || x.mihomoSession.running.Load() {
		return fmt.Errorf("[Xray] another engine is already running")
	}
	log.Println("[Xray] Initializing core")

	// Before cfg.Build(): xray resolves geoip.dat/geosite.dat lazily from the
	// env during the build.
	applyGeoAssetsDir(o.geoAssetsDir)
	if err := dropXrayGeoMatchersOnFolderChange(); err != nil {
		return err
	}

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
		if x.xrayCoreInstance, err = x.newXrayInstance(builtCfg); err != nil {
			return fmt.Errorf("[Xray] Core init failed: %w", err)
		}
		stats := x.xrayCoreInstance.GetFeature(xrayStats.ManagerType()).(xrayStats.Manager)
		x.xrayTraffic.Store(&xrayTrafficSource{stats: stats, tags: res.OutboundTags})
		x.xraySession.up(mark)
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
	x.xrayCoreInstance, err = x.newXrayInstance(builtCfg)
	if err != nil {
		return fmt.Errorf("[Xray] Core init failed: %w", err)
	}
	stats := x.xrayCoreInstance.GetFeature(xrayStats.ManagerType()).(xrayStats.Manager)
	x.xrayTraffic.Store(&xrayTrafficSource{stats: stats, tags: res.OutboundTags})

	log.Println("[Xray] Starting core")
	x.xraySession.up(mark)
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
		tunFd:       tun.take(),
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

func (x *CoreController) newXrayInstance(cfg *xrayCore.Config) (*xrayCore.Instance, error) {
	life, cancel := context.WithCancel(context.Background())
	inst, err := xrayCore.NewWithContext(life, cfg)
	if err != nil {
		cancel()
		return nil, err
	}
	x.xrayLife, x.xrayLifeCancel = life, cancel
	return inst, nil
}

func (x *CoreController) endXrayLife() {
	if x.xrayLifeCancel != nil {
		x.xrayLifeCancel()
		x.xrayLife, x.xrayLifeCancel = nil, nil
	}
}

// xrayRollback undoes a start that got as far as creating the instance.
func (x *CoreController) xrayRollback() {
	x.xraySession.running.Store(false)
	x.xrayTraffic.Store(nil)
	x.endXrayLife()
	if x.xrayCoreInstance != nil {
		_ = x.xrayCoreInstance.Close()
		x.xrayCoreInstance = nil
	}
}

func (x *CoreController) xrayStop(stopGen int64) error {
	return x.stopEngineInstance("xray", &x.xraySession, stopGen, x.xrayStopLocked)
}

// xrayStopLocked closes the bridge, the connections xray holds and the
// instance. The caller holds coreMutex.
func (x *CoreController) xrayStopLocked() {
	x.stopTun2socks()
	x.endXrayLife()

	if x.xraySession.running.Load() {
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
		x.xraySession.running.Store(false)
		x.xrayTraffic.Store(nil)
	}

	log.Println("[Xray] Core stopped")
}

// xrayTunnelDial dials inside the instance as the inbound tag names:
// ExitEchoTag takes the proxy ahead of the routing tiers,
// AppTrafficTag routes like the user's traffic. Like mihomoTunnelDial it
// refuses once the session that started at mark has ended.
func (x *CoreController) xrayTunnelDial(inst *xrayCore.Instance, tag string, mark int64) tunnelDialFunc {
	life := x.xrayLife
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
		// xray ends the flow when its context is cancelled: the caller's, or
		// the instance's with the session.
		ctx, cancel := context.WithCancel(ctx)
		endWithInstance := context.AfterFunc(life, cancel)
		conn, err := xrayCore.Dial(ctx, inst, xrayNet.TCPDestination(xrayNet.ParseAddress(host), port))
		if err != nil {
			endWithInstance()
			cancel()
			return nil, err
		}
		return &xrayDialConn{Conn: conn, release: func() {
			endWithInstance()
			cancel()
		}}, nil
	}
}

// xrayDialConn gives up its context when closed.
type xrayDialConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *xrayDialConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
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
