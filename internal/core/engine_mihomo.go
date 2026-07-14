//go:build !no_mihomo

package core

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/conninspect"
	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/metacubex/mihomo/common/observable"
	mihomoCfg "github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/listener"
	mihomoLog "github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

type mihomoEngine struct{}

func (mihomoEngine) ID() string { return "mihomo" }

func (mihomoEngine) Start(x *CoreController, req EngineStartRequest) int32 {
	return x.HandleMihomoStart(req.Config, req.TunFD, optsFromRequest(req))
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

var (
	mihomoHomeOnce sync.Once
	mihomoLogSub   observable.Subscription[mihomoLog.Event]
)

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

// Points mihomo home at xray.location.asset so GEOSITE/GEOIP find the .dat files.
func ensureMihomoHome() {
	mihomoHomeOnce.Do(func() {
		dir := os.Getenv("xray.location.asset")
		if strings.TrimSpace(dir) == "" {
			dir = filepath.Join(os.TempDir(), "glitch_vpn_mihomo")
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Printf("[mihomo] home dir: %v", err)
			return
		}
		C.SetHomeDir(dir)
	})
}

func (x *CoreController) HandleMihomoStart(rawconfig string, tunFd int, o engineOpts) int32 {
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
		return glitchCoreResultSuccess
	}

	x.emitStatus(EngineConnecting, "[mihomo] Connecting")
	go func() {
		if err := x.mihomoStart(rawconfig, tunFd, o); err != nil {
			log.Printf("[mihomo] start failed: %v", err)
			x.emitStatus(EngineError, fmt.Sprintf("[mihomo] Failed to start: %v", err))
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
		inbound = mihomoconfig.Inbound{MixedPort: proxyPort}
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
	// time for GEOSITE/GEOIP rules.
	ensureMihomoHome()
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
	if livenessPort > 0 {
		// Only the explicit proxy inbound is auth-gated; pass creds only then.
		user, pass := "", ""
		if proxyPort > 0 {
			user, pass = o.proxyUser, o.proxyPass
		}
		x.startLiveness(livenessParams{
			engine:   "mihomo",
			interval: livenessInterval(o.livenessSec),
			probe:    socksProber(loopbackSocksURL(fmt.Sprintf("127.0.0.1:%d", livenessPort), user, pass), o.probeURL),
		})
	}
	log.Println("[mihomo] started")
	return nil
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
