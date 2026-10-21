//go:build !no_mihomo

package core

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/conninspect"
	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
	"github.com/glitch-vpn/libglitchcore/internal/loopbackauth"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/serverinfo"
	"github.com/metacubex/mihomo/common/observable"
	"github.com/metacubex/mihomo/component/geodata"
	mihomoCfg "github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/listener/inner"
	mihomoLog "github.com/metacubex/mihomo/log"
	mihomoTunnel "github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

type mihomoEngine struct{}

func (mihomoEngine) ID() string { return "mihomo" }

func (mihomoEngine) Start(x *CoreController, req EngineStartRequest) int32 {
	return x.HandleMihomoStart(req)
}

// Compiles without the tun2socks bridge (plain fields only). The URLs carry
// the session's credentials.
type bridgeSetup struct {
	mixedPort     int
	proxyURL      string
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

var mihomoLogSub observable.Subscription[mihomoLog.Event]

// mihomo publishes every event to its subscribers whatever its own level;
// that level only gates its stdout printer, which the core keeps off so the
// bridge is the one way out.
func startMihomoLogBridge() {
	stopMihomoLogBridge()
	sub := mihomoLog.Subscribe()
	mihomoLogSub = sub
	go func(s observable.Subscription[mihomoLog.Event]) {
		for ev := range s {
			emitLog(mihomoEventLevel(ev.LogLevel), "mihomo", ev.Payload)
			if ev.LogLevel == mihomoLog.INFO && connInspectEnabled.Load() && globalController != nil {
				if rec, ok := mihomoRejectRecord(ev.Payload); ok {
					globalController.emitConn(rec)
				}
			}
		}
	}(sub)
}

func mihomoEventLevel(l mihomoLog.LogLevel) logfmt.Level {
	switch l {
	case mihomoLog.DEBUG:
		return logfmt.Debug
	case mihomoLog.WARNING:
		return logfmt.Warn
	case mihomoLog.ERROR:
		return logfmt.Error
	default:
		return logfmt.Info
	}
}

func stopMihomoLogBridge() {
	if mihomoLogSub != nil {
		mihomoLog.UnSubscribe(mihomoLogSub) // closes the channel -> goroutine exits
		mihomoLogSub = nil
	}
}

// ApplyConfig sets the printer to the config's level, so every config the core
// applies says silent too (mihomoconfig.BuildConfig, mihomoTeardown).
func silenceMihomoPrinter() {
	mihomoLog.SetLevel(mihomoLog.SILENT)
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
					if emit && globalController != nil && !mihomoRejected(info.Chain) {
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
	src := ""
	if m.SrcIP.IsValid() { // the core's own in-tunnel dials have no source
		src = m.SourceAddress()
	}
	host := m.Host
	if host == "" && m.DstIP.IsValid() {
		host = m.DstIP.String()
	}
	inbound := m.InName
	if inbound == "" {
		inbound = m.Type.String()
	}
	rule := strings.TrimSpace(info.Rule + " " + info.RulePayload)
	return conninspect.Record{
		Engine:   "mihomo",
		Src:      src,
		Status:   "accepted",
		Network:  m.NetWork.String(),
		Host:     host,
		Port:     strconv.Itoa(int(m.DstPort)),
		Inbound:  inbound,
		Outbound: info.Chain.String(),
		Rule:     rule,
	}
}

// A chain lists the outbound first and the groups that picked it after.
func mihomoRejected(chain C.Chain) bool {
	return len(chain) > 0 && isMihomoReject(chain[0])
}

func isMihomoReject(outbound string) bool {
	return outbound == "REJECT" || outbound == "REJECT-DROP"
}

// A rejected connection's tracker closes at once, before the inspector's next
// poll, so it is reported from the rule-match line mihomo writes for it:
//
//	[TCP] 127.0.0.1:50000(app.exe) --> ads.example:443 match DomainSuffix(ads.example) using REJECT
//
// The line names no inbound. The core's rules name REJECT directly, never
// through a group, so the outbound must be REJECT itself: a proxy can be
// named "x[REJECT]".
var mihomoMatchLine = regexp.MustCompile(`^\[(TCP|UDP)\] (\S+?)(?:\([^)]*\))? --> (\S+) match (\S+?)(?:\((.*)\))? using (\S+)$`)

func mihomoRejectRecord(line string) (conninspect.Record, bool) {
	m := mihomoMatchLine.FindStringSubmatch(line)
	if m == nil {
		return conninspect.Record{}, false
	}
	outbound := m[6]
	if !isMihomoReject(outbound) {
		return conninspect.Record{}, false
	}
	host, port, err := net.SplitHostPort(m[3])
	if err != nil {
		host, port = m[3], ""
	}
	return conninspect.Record{
		Engine:   "mihomo",
		Src:      m[2],
		Status:   "rejected",
		Network:  strings.ToLower(m[1]),
		Host:     host,
		Port:     port,
		Outbound: outbound,
		Rule:     strings.TrimSpace(m[4] + " " + m[5]),
	}, true
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
	links, err := splitEngineLinks(req.Config)
	if err != nil {
		x.emitStatus(EngineError, fmt.Sprintf("[mihomo] invalid config: %v", err))
		return glitchCoreResultError
	}

	x.emitStatus(EngineConnecting, "[mihomo] Connecting")
	go func() {
		mark := x.sessionGen.Load()
		if err := x.mihomoStart(links, req.TunFD, o); err != nil {
			logfmt.Errorf("[mihomo] start failed: %v", err)
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

func (x *CoreController) mihomoStart(links []string, tunFd int, o engineOpts) error {
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
	switch {
	case proxyPort > 0:
		// No DNS server in proxy mode (no listener, no fake-ip), but the intent
		// still carries the hosts table, which mihomo honours through its
		// resolver either way.
		inbound = mihomoconfig.Inbound{
			MixedPort: proxyPort,
			DNS:       dns,
			Auth:      loopbackauth.Credentials{User: o.proxyUser, Pass: o.proxyPass},
		}
	case x.mihomoUsesBridge(proxyPort):
		in, b, berr := x.mihomoBuildBridgeInbound(&dns, prof)
		if berr != nil {
			return berr
		}
		inbound, bridge = in, b
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

	cfg, err := mihomoconfig.BuildConfig(links, inbound,
		mihomoconfig.Options{Strategy: o.strategy, DisableSniffing: !o.sniffing, ProbeURL: o.probeURL, Fingerprint: o.fingerprint}, prof)
	if err != nil {
		stopMihomoLogBridge()
		return fmt.Errorf("[mihomo] config build: %w", err)
	}

	countMihomoDirect(cfg, &mihomoSessionTraffic)
	mihomoSessionTraffic.startSession()

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
	x.startLiveness(livenessParams{
		engine:   "mihomo",
		interval: livenessInterval(o.livenessSec),
		probe:    tunnelProber(x.mihomoTunnelDial(""), o.probeURL),
	})
	x.initMihomoServerState(links, o)
	x.configureIPResolve(ipResolveConfig{
		enabled: o.resolveIP,
		urlV4:   o.ipEchoV4,
		urlV6:   o.ipEchoV6,
		skipV6:  o.dns.DisableIPv6,
		dial:    x.mihomoTunnelDial(mihomoconfig.Target(links)),
	})
	log.Println("[mihomo] started")
	return nil
}

// mihomoTunnelDial dials inside mihomo's tunnel, so the core's own probes need
// no loopback listener: proxy "" follows the rules like user traffic, a proxy
// name pins the flow to that proxy or group ahead of every rule. xray's
// liveness probe uses its tun2socks inbound instead, which its TUN path opens
// anyway. The dial refuses once its session has ended: mihomo's tunnel
// outlives the session with only DIRECT left, and an echo retried then would
// leave from the user's own address.
func (x *CoreController) mihomoTunnelDial(proxy string) tunnelDialFunc {
	gen := x.sessionGen.Load()
	return func(_ context.Context, _, addr string) (net.Conn, error) {
		if x.sessionGen.Load() != gen {
			return nil, errSessionEnded
		}
		return inner.HandleTcp(mihomoTunnel.Tunnel, addr, proxy)
	}
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

const mihomoTeardownConfig = "log-level: silent"

// Safe under coreMutex - no controller re-entry.
func mihomoTeardown() {
	if empty, err := mihomoCfg.Parse([]byte(mihomoTeardownConfig)); err == nil {
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
			logfmt.Errorf("[mihomo] stop failed: %v", err)
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
	return mihomoSessionTraffic.proxied()
}
