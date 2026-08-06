//go:build !no_mihomo

package core

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/conninspect"
	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/serverinfo"
	"github.com/metacubex/mihomo/common/observable"
	"github.com/metacubex/mihomo/component/geodata"
	mihomoCfg "github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/listener"
	mihomoLog "github.com/metacubex/mihomo/log"
	mihomoTunnel "github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

type mihomoEngine struct{}

func (mihomoEngine) ID() string { return "mihomo" }

func (mihomoEngine) Start(x *CoreController, req EngineStartRequest) int32 {
	return x.HandleMihomoStart(req)
}

// Compiles without the tun2socks bridge (plain fields only).
type bridgeSetup struct {
	mixedPort     int
	forceProxyURL string
	dnsRedirect   string
}

func (mihomoEngine) Stop(x *CoreController) int32 { return x.HandleMihomoStop() }

func (mihomoEngine) IsRunning(x *CoreController) int32 { return x.HandleMihomoIsRunning() }

func (mihomoEngine) Traffic(x *CoreController) (uint64, uint64, bool) {
	if !x.isMihomoRunning.Load() {
		return 0, 0, false
	}
	rx, tx := x.getMihomoTraffic()
	return rx, tx, true
}

func init() {
	registerEngine(mihomoEngine{})
	registerEngineVersion("mihomo", func() string { return builtMihomoVersion })
}

func mihomoConfigLinks(raw string) []string {
	return splitEngineLinks(raw)
}

var mihomoLogSub observable.Subscription[mihomoLog.Event]

func startMihomoLogBridge() {
	stopMihomoLogBridge()
	mihomoLog.SetLevel(mihomoLogLevel())
	sub := mihomoLog.Subscribe()
	mihomoLogSub = sub
	go func(s observable.Subscription[mihomoLog.Event]) {
		for ev := range s {
			if logSink == nil || inFFICall.Load() || !shouldEmitStatusMessage(ev.Payload) {
				continue
			}
			logSink(logfmt.BuildJSON(ev.Type(), "mihomo", ev.Payload))
		}
	}(sub)
}

func stopMihomoLogBridge() {
	if mihomoLogSub != nil {
		mihomoLog.UnSubscribe(mihomoLogSub) // closes the channel -> goroutine exits
		mihomoLogSub = nil
	}
}

func applyMihomoLogLevel() {
	mihomoLog.SetLevel(mihomoLogLevel())
}

func mihomoLogLevel() mihomoLog.LogLevel {
	switch v := atomic.LoadInt32(&statusVerbosity); {
	case v < 0:
		return mihomoLog.SILENT
	case v >= 2:
		return mihomoLog.DEBUG
	default:
		return mihomoLog.INFO
	}
}

var mihomoConnQuit chan struct{}

// Polls mihomo's tracker into ConnEvent. seen advances even when disabled so
// enabling mid-session doesn't dump a backlog.
func startMihomoConnInspector() {
	stopMihomoConnInspector()
	quit := make(chan struct{})
	mihomoConnQuit = quit
	go func(quit chan struct{}) {
		seen := map[string]struct{}{}
		ticker := time.NewTicker(700 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-quit:
				return
			case <-ticker.C:
				emit := connInspectEnabled.Load()
				current := make(map[string]struct{})
				statistic.DefaultManager.Range(func(t statistic.Tracker) bool {
					info := t.Info()
					id := info.UUID.String()
					current[id] = struct{}{}
					if _, ok := seen[id]; ok {
						return true
					}
					seen[id] = struct{}{}
					if emit && globalController != nil {
						globalController.emitConn(mihomoConnRecord(info))
					}
					return true
				})
				for id := range seen {
					if _, ok := current[id]; !ok {
						delete(seen, id)
					}
				}
			}
		}
	}(quit)
}

func stopMihomoConnInspector() {
	if mihomoConnQuit != nil {
		close(mihomoConnQuit)
		mihomoConnQuit = nil
	}
}

func mihomoConnRecord(info *statistic.TrackerInfo) conninspect.Record {
	m := info.Metadata
	host := m.Host
	if host == "" && m.DstIP.IsValid() {
		host = m.DstIP.String()
	}
	rule := strings.TrimSpace(info.Rule + " " + info.RulePayload)
	return conninspect.Record{
		Engine:   "mihomo",
		Src:      m.SourceAddress(),
		Status:   "accepted", // trackers are established conns; REJECT never becomes one
		Network:  m.NetWork.String(),
		Host:     host,
		Port:     strconv.Itoa(int(m.DstPort)),
		Outbound: info.Chain.String(),
		Rule:     rule,
	}
}

// Guarded by coreMutex (only mihomoStart touches it, one engine at a time).
var mihomoHomeDir string

// Points mihomo home at the per-connection dir (falling back to
// xray.location.asset, then a temp default) so GEOSITE/GEOIP find the .dat
// files. Re-applied on change: mihomo memoizes geo matchers by list name
// only, so a stale cache would keep serving the previous dir's files. An
// unusable dir fails the start - proceeding would silently serve the
// previous home's geo data.
func ensureMihomoHome(optDir string) error {
	dir, own := strings.TrimSpace(optDir), false
	if dir == "" {
		dir = strings.TrimSpace(os.Getenv(xrayAsset))
	}
	if dir == "" {
		dir, own = filepath.Join(os.TempDir(), "glitch_vpn_mihomo"), true
	}
	if dir == mihomoHomeDir {
		return nil
	}
	// Only the fallback dir is ours to create. A caller-supplied path is
	// applied inside the LocalSystem service, where creating directories on
	// request would hand the (unauthenticated) command pipe a filesystem
	// primitive.
	if own {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("home dir: %w", err)
		}
	} else if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return fmt.Errorf("home dir %q is not an existing directory", dir)
	}
	C.SetHomeDir(dir)
	geodata.ClearGeoSiteCache()
	geodata.ClearGeoIPCache()
	mihomoHomeDir = dir
	return nil
}

func (x *CoreController) HandleMihomoStart(req EngineStartRequest) int32 {
	if x == nil {
		return glitchCoreResultError
	}
	if x.isXrayRunning.Load() || x.isAwgRunning.Load() {
		x.emitStatus(EngineConflictOtherCore, "[mihomo] Start rejected: another engine is running")
		return glitchCoreResultError
	}
	if x.isMihomoRunning.Load() {
		x.emitStatus(EngineAlreadyRunning, "[mihomo] Already running")
		x.startStats(time.Second)
		x.emitStatus(EngineConnected, "[mihomo] Connected (already running)")
		x.reemitSessionState()
		return glitchCoreResultSuccess
	}

	// After the guards: a malformed request must not tear down the live
	// session they protect (EngineError clears client session state).
	o, err := optsFromRequest(req)
	if err != nil {
		x.emitStatus(EngineError, fmt.Sprintf("[mihomo] invalid opts: %v", err))
		return glitchCoreResultError
	}

	x.emitStatus(EngineConnecting, "[mihomo] Connecting")
	go func() {
		mark := x.sessionGen.Load()
		if err := x.mihomoStart(req.Config, req.TunFD, o); err != nil {
			log.Printf("[mihomo] start failed: %v", err)
			x.clearSessionState()
			x.emitStatus(EngineError, fmt.Sprintf("[mihomo] Failed to start: %v", err))
			return
		}
		if x.abortStaleSession(mark) {
			log.Println("[mihomo] stopped during startup; not publishing connected state")
			return
		}
		x.startStats(time.Second)
		x.emitStatus(EngineConnected, "[mihomo] Connected")
	}()
	return glitchCoreResultSuccess
}

func (x *CoreController) mihomoStart(rawconfig string, tunFd int, o engineOpts) error {
	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()

	dns, prof, proxyPort := o.dns, o.routing, o.proxyPort

	if x.isMihomoRunning.Load() {
		return nil
	}
	if x.isXrayRunning.Load() || x.isAwgRunning.Load() {
		return fmt.Errorf("[mihomo] another engine is already running")
	}

	// Inbound: proxyPort>0 = loopback mixed, no TUN. Bridge (when tun2socks is
	// linked; Windows + Android via env) = mihomo as a loopback proxy behind a
	// tun2socks-bridged platform TUN, avoiding mihomo's sing-tun (Wintun
	// conflict / Android packages.xml block). Else native sing-tun.
	var inbound mihomoconfig.Inbound
	var bridge *bridgeSetup
	var livenessPort int
	switch {
	case proxyPort > 0:
		// No DNS server in proxy mode (no listener, no fake-ip), but the intent
		// still carries the hosts table, which mihomo honours through its
		// resolver either way.
		inbound = mihomoconfig.Inbound{MixedPort: proxyPort, DNS: dns}
		if o.proxyUser != "" && o.proxyPass != "" {
			inbound.Auth = o.proxyUser + ":" + o.proxyPass
		}
		livenessPort = proxyPort
	case x.mihomoUsesBridge(proxyPort):
		in, b, berr := x.mihomoBuildBridgeInbound(&dns, prof)
		if berr != nil {
			return berr
		}
		inbound, bridge, livenessPort = in, b, b.mixedPort
	default:
		if strings.TrimSpace(dns.Mode) == "" {
			dns.Mode = dnsconfig.ModeFakeIP
		}
		if len(dns.NormalizedServers("")) == 0 {
			dns.Servers = []string{xrayDefaultDnsServer}
		}
		tin := &mihomoconfig.TunInbound{MTU: defaultTunMTU, DNS: dns}
		if tunFd > 0 {
			// DUP the platform fd: sing-tun closes the fd it's given on teardown,
			// but ParcelFileDescriptor/NE still owns the original - double-close
			// fdsan-aborts (see dupTunFd).
			dupFd, derr := dupTunFd(tunFd)
			if derr != nil {
				return fmt.Errorf("[mihomo] dup tun fd: %w", derr)
			}
			tin.FileDescriptor = dupFd
			// Android cmfa: seed mihomo's system resolver so bootstrap/proxy
			// hostname resolution works (no-op elsewhere).
			seedMihomoSystemDNS(plainDNSServers(dns))
		} else {
			tin.Device = "GlitchVPNMeta" // Linux desktop: mihomo creates the adapter
		}
		inbound = mihomoconfig.Inbound{Tun: tin}
		if p, perr := pickLoopbackPort(); perr == nil {
			inbound.MixedPort = p
			livenessPort = p
		} else {
			log.Printf("[mihomo] liveness inbound port: %v", perr)
		}
	}

	// Home dir must be set before BuildConfig - ParseRawConfig loads geo at parse
	// time for GEOSITE/GEOIP rules. The env snapshot/restore runs here too, or
	// ensureMihomoHome's env fallback would inherit a previous xray session's
	// override.
	applyGeoAssetsDir(o.geoAssetsDir)
	if err := ensureMihomoHome(o.geoAssetsDir); err != nil {
		return fmt.Errorf("[mihomo] %w", err)
	}
	startMihomoLogBridge()

	cfg, err := mihomoconfig.BuildConfig(mihomoConfigLinks(rawconfig), inbound,
		mihomoconfig.Options{Strategy: o.strategy, DisableSniffing: !o.sniffing, ProbeURL: o.probeURL, Fingerprint: o.fingerprint}, prof)
	if err != nil {
		stopMihomoLogBridge()
		return fmt.Errorf("[mihomo] config build: %w", err)
	}

	log.Println("[mihomo] applying config")
	// ApplyConfig is void but blocks through TUN creation; a cleared TUN Enable
	// flag is the only success signal (checked below, native TUN mode only).
	executor.ApplyConfig(cfg, true)
	if bridge == nil && proxyPort <= 0 && !listener.GetTunConf().Enable {
		mihomoTeardown()
		return fmt.Errorf("[mihomo] TUN listener failed to start (see mihomo logs)")
	}
	if bridge != nil {
		if err := x.mihomoStartBridge(bridge, prof, dns, tunFd); err != nil {
			mihomoTeardown()
			return fmt.Errorf("[mihomo] tun2socks bridge: %w", err)
		}
	} else if proxyPort > 0 {
		log.Printf("[mihomo] Proxy mode: mixed SOCKS/HTTP at 127.0.0.1:%d (no TUN)", proxyPort)
	}

	x.isMihomoRunning.Store(true)
	startMihomoConnInspector()
	var tunnelDial tunnelDialFunc
	if livenessPort > 0 {
		// Only the explicit proxy inbound is auth-gated; pass creds only then.
		user, pass := "", ""
		if proxyPort > 0 {
			user, pass = o.proxyUser, o.proxyPass
		}
		socksURL := loopbackSocksURL(fmt.Sprintf("127.0.0.1:%d", livenessPort), user, pass)
		tunnelDial = socksTunnelDial(socksURL)
		x.startLiveness(livenessParams{
			engine:   "mihomo",
			interval: livenessInterval(o.livenessSec),
			probe:    socksProber(socksURL, o.probeURL),
		})
	}
	x.initMihomoServerState(mihomoConfigLinks(rawconfig), o)
	x.configureIPResolve(ipResolveConfig{
		enabled: o.resolveIP,
		urlV4:   o.ipEchoV4,
		urlV6:   o.ipEchoV6,
		skipV6:  o.dns.DisableIPv6,
		dial:    tunnelDial,
	})
	log.Println("[mihomo] started")
	return nil
}

// url-test/fallback groups are followed via Now(); load-balance dispatches
// per connection, so its Selected stays nil.
func (x *CoreController) initMihomoServerState(links []string, o engineOpts) {
	servers := serverinfo.FromLinks(links)
	names := mihomoconfig.ProxyNames(links)
	if len(servers) == 0 || len(servers) != len(names) {
		return
	}
	sel := serverinfo.Selection{Engine: "mihomo", Total: len(servers), Servers: servers}
	if len(servers) == 1 {
		s := servers[0]
		sel.Selected = &s
		x.setServerSelection(&sel)
		return
	}
	strat, ok := mihomoconfig.NormalizeStrategy(o.strategy)
	if !ok {
		strat = o.strategy
	}
	sel.Strategy = strat
	x.setServerSelection(&sel)
	if strat != "url-test" && strat != "fallback" {
		return
	}
	nameIdx := make(map[string]int, len(names))
	for i, n := range names {
		nameIdx[n] = i
	}
	x.startSelectionWatch(sel, func() int {
		p, ok := mihomoTunnel.Proxies()[mihomoconfig.GroupTag]
		if !ok || p == nil {
			return -1
		}
		g, ok := p.Adapter().(interface{ Now() string })
		if !ok {
			return -1
		}
		idx, ok := nameIdx[g.Now()]
		if !ok {
			return -1
		}
		return idx
	})
}

// Safe under coreMutex - no controller re-entry.
func mihomoTeardown() {
	if empty, err := mihomoCfg.Parse([]byte("{}")); err == nil {
		executor.ApplyConfig(empty, true)
	}
	executor.Shutdown()
	stopMihomoLogBridge()
	stopMihomoConnInspector()
}

func (x *CoreController) HandleMihomoStop() int32 {
	if x == nil {
		return glitchCoreResultError
	}
	if !x.isMihomoRunning.Load() {
		x.emitStatus(EngineStopRejectedNotRunning, "[mihomo] Stop rejected: not running")
		return glitchCoreResultError
	}

	x.stopStats()
	x.stopLiveness()
	x.clearSessionState()
	x.emitStatus(EngineDisconnecting, "[mihomo] Disconnecting")
	go func() {
		if err := x.mihomoStop(); err != nil {
			log.Printf("[mihomo] stop failed: %v", err)
			x.emitStatus(EngineError, fmt.Sprintf("[mihomo] Failed to stop: %v", err))
			return
		}
		x.emitStatus(EngineDisconnected, "[mihomo] Disconnected")
	}()
	return glitchCoreResultSuccess
}

func (x *CoreController) mihomoStop() error {
	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()

	if !x.isMihomoRunning.Load() {
		return nil
	}
	x.mihomoStopBridge()
	mihomoTeardown()
	x.isMihomoRunning.Store(false)
	log.Println("[mihomo] stopped")
	return nil
}

func (x *CoreController) HandleMihomoIsRunning() int32 {
	if x == nil {
		return glitchCoreResultError
	}
	if x.isMihomoRunning.Load() {
		return glitchCoreResultSuccess
	}
	return glitchCoreResultError
}

// (rx=down, tx=up), per the xray/awg convention.
func (x *CoreController) getMihomoTraffic() (uint64, uint64) {
	up, down := statistic.DefaultManager.Total()
	if up < 0 {
		up = 0
	}
	if down < 0 {
		down = 0
	}
	return uint64(down), uint64(up)
}
