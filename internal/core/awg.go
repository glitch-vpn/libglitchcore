//go:build !no_awg

package core

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"

	"github.com/glitch-vpn/libglitchcore/internal/awgconfig"
	"github.com/glitch-vpn/libglitchcore/internal/liveness"
	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
	"github.com/glitch-vpn/libglitchcore/internal/pinger"
	"github.com/glitch-vpn/libglitchcore/internal/serverinfo"
)

type awgEngine struct{}

func (awgEngine) ID() string { return "awg" }

func (awgEngine) Start(x *CoreController, req EngineStartRequest) int32 {
	return x.HandleAwgStart(req)
}

func (awgEngine) Stop(x *CoreController) int32 { return x.HandleAwgStop() }

func (awgEngine) IsRunning(x *CoreController) int32 { return x.HandleAwgIsRunning() }

func (awgEngine) Traffic(x *CoreController) (uint64, uint64, bool) {
	if !x.awgSession.running.Load() {
		return 0, 0, false
	}
	rx, tx := x.getAwgTraffic()
	return rx, tx, true
}

func init() {
	registerEngine(awgEngine{})
	registerEngineVersion("amneziawg", func() string { return builtAmneziawgVersion })
}

// The gate is read per line, so a verbosity change reaches a running device.
// The device writes a verbose line for every packet it cannot parse, before
// any authentication, so those lines are held to a budget a sender cannot
// flood the event stream past.
func awgDeviceLogger() *device.Logger {
	budget := &lineBudget{perSecond: 20}
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			if logEnabled(logfmt.Debug) && budget.take(time.Now()) {
				emitLogf(logfmt.Debug, "AWG", format, args...)
			}
		},
		Errorf: func(format string, args ...any) { emitLogf(logfmt.Error, "AWG", format, args...) },
	}
}

type lineBudget struct {
	perSecond int
	mu        sync.Mutex
	second    int64
	used      int
}

func (b *lineBudget) take(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s := now.Unix(); s != b.second {
		b.second, b.used = s, 0
	}
	b.used++
	return b.used <= b.perSecond
}

// Android liveness via UAPI counters - our package is excluded from the VPN there.
func (x *CoreController) awgPassiveSampler() func() (liveness.WGSample, error) {
	var lastRx, lastTx uint64
	var seeded bool
	return func() (liveness.WGSample, error) {
		dump, err := x.awgDeviceState()
		if err != nil {
			return liveness.WGSample{}, err
		}
		rx, tx := awgconfig.SumRxTx(dump)
		hs := awgconfig.LastHandshakeUnix(dump)

		sample := liveness.WGSample{HasHandshake: hs > 0}
		if hs > 0 {
			sample.HandshakeAge = time.Since(time.Unix(hs, 0))
		}
		if seeded {
			if rx >= lastRx {
				sample.RxDelta = rx - lastRx
			}
			if tx >= lastTx {
				sample.TxDelta = tx - lastTx
			}
		}
		lastRx, lastTx, seeded = rx, tx, true
		return sample, nil
	}
}

func (x *CoreController) HandleAwgStart(req EngineStartRequest) int32 {
	// IPC routing lives in engineStart; this handler always runs locally.
	if x == nil {
		return glitchCoreResultError
	}
	log.Println("[AWG] AwgStart")

	if x.xraySettledRunning() || x.mihomoSession.running.Load() {
		x.emitStatus(EngineConflictOtherCore, "[AWG] Start rejected: another engine is running")
		return glitchCoreResultError
	}

	if x.awgSession.runsSession(x.sessionGen.Load()) {
		return x.replyAlreadyRunning("AWG")
	}

	// After the guards: a malformed request must not tear down the live
	// session they protect (EngineError clears client session state).
	o, err := optsFromRequest(req, "awg")
	if err != nil {
		x.emitStatus(EngineError, fmt.Sprintf("[AWG] invalid opts: %v", err))
		return glitchCoreResultError
	}
	// awg has no proxy inbound: honouring the start would bring up a TUN the
	// caller did not ask for, and in this process rather than the service's.
	if o.proxyPort > 0 {
		x.emitStatus(EngineError, "[AWG] Start rejected: proxy mode (proxyPort) is not supported; awg runs as a TUN only")
		return glitchCoreResultError
	}
	links, err := splitEngineLinks(req.Config)
	if err != nil {
		x.emitStatus(EngineError, fmt.Sprintf("[AWG] invalid config: %v", err))
		return glitchCoreResultError
	}

	x.emitStatus(EngineConnecting, "[AWG] Connecting")

	const ifaceName = "GlitchVPN"

	// Counted from here, the link pick included: a stop during the pick is
	// taken, and the start then finds its session ended.
	mark, done := x.beginStart(&x.awgSession)
	go func() {
		defer done()
		chosen, idx, err := chooseAwgLink(links, o)
		if err != nil {
			x.clearSessionState()
			x.emitStatus(EngineError, fmt.Sprintf("[AWG] %v", err))
			return
		}
		x.finishStart(&x.awgSession, "AWG", mark, x.awgStart(ifaceName, req.TunFD, chosen, links, idx, o, mark))
	}()

	return glitchCoreResultSuccess
}

var measureAwgLinks = pinger.Measure

// Multilink: probe each awg:// link, pick by strategy; fall back to first if none alive.
func pickAwgConfig(links []string, o engineOpts) (string, int) {
	if len(links) == 0 {
		return "", 0
	}
	if len(links) == 1 {
		return links[0], 0
	}

	res := measureAwgLinks(pinger.Request{Links: links, ProbeURL: o.probeURL})
	idx := pickAwgWinner(res, o.strategy)
	if idx < 0 || idx >= len(links) {
		idx = 0
	}
	delay := "unreachable"
	if res[idx].Alive {
		delay = fmt.Sprintf("%dms", res[idx].DelayMs)
	}
	log.Printf("[AWG] multilink: %d links, strategy=%q -> picked #%d (%s)", len(links), o.strategy, idx, delay)
	return links[idx], idx
}

// chooseAwgLink takes the link a caller already picked through PickAwg when
// the start names one, so the pool is probed once per connect.
func chooseAwgLink(links []string, o engineOpts) (string, int, error) {
	if o.awgPicked == "" {
		chosen, idx := pickAwgConfig(links, o)
		return chosen, idx, nil
	}
	idx, err := strconv.Atoi(o.awgPicked)
	if err != nil || idx < 0 || idx >= len(links) {
		return "", 0, fmt.Errorf("awgPicked %q is not an index into the %d links", o.awgPicked, len(links))
	}
	return links[idx], idx, nil
}

// awg is pick-a-winner: the selection is final for the session.
func (x *CoreController) initAwgServerState(links []string, idx int, o engineOpts) {
	servers := serverinfo.FromLinks(links)
	if len(servers) == 0 || idx < 0 || idx >= len(servers) {
		return
	}
	sel := serverinfo.Selection{Engine: "awg", Total: len(servers), Servers: servers}
	if len(servers) > 1 {
		strat := strings.ToLower(strings.TrimSpace(o.strategy))
		if strat == "" {
			strat = "leastping"
		}
		sel.Strategy = strat
	}
	s := servers[idx]
	sel.Selected = &s
	x.setServerSelection(&sel)
}

// Desktop reaches the tunnel via the OS default route; on Android our package
// is excluded from the VPN, so there is no HTTP path.
func (x *CoreController) configureAwgIPResolve(o engineOpts) {
	cfg := ipResolveConfig{
		enabled: o.resolveIP,
		urlV4:   o.ipEchoV4,
		urlV6:   o.ipEchoV6,
		skipV6:  o.dns.DisableIPv6,
	}
	if runtime.GOOS != "android" {
		cfg.dial = (&net.Dialer{Timeout: livenessProbeTimeout}).DialContext
	}
	x.configureIPResolve(cfg)
}

func pickAwgWinner(res []pinger.Result, strategy string) int {
	var alive []int
	for i, r := range res {
		if r.Alive {
			alive = append(alive, i)
		}
	}
	if len(alive) == 0 {
		return 0
	}
	switch strings.ToLower(strings.TrimSpace(strategy)) {
	case "random":
		return alive[rand.Intn(len(alive))]
	case "fallback", "roundrobin":
		return alive[0]
	default: // "" / "leastping"
		best := alive[0]
		for _, i := range alive[1:] {
			if res[i].DelayMs < res[best].DelayMs {
				best = i
			}
		}
		return best
	}
}

// Android: package excluded from VPN -> passive WG heuristic; desktop: active probe.
func (x *CoreController) startAwgLiveness(o engineOpts) {
	p := livenessParams{engine: "awg", interval: livenessInterval(o.livenessSec)}
	if runtime.GOOS == "android" {
		p.passive = x.awgPassiveSampler()
	} else {
		p.probe = directProber(o.probeURL)
	}
	x.startLiveness(p)
}

func (x *CoreController) HandleAwgStop() int32 {
	if x == nil {
		return glitchCoreResultError
	}
	return x.stopEngineSession(&x.awgSession, "AWG", x.awgStop)
}

func (x *CoreController) HandleAwgIsRunning() int32 {
	if x == nil {
		return glitchCoreResultError
	}
	if x.awgSession.engaged() {
		return glitchCoreResultSuccess
	}
	return glitchCoreResultError
}

// The device's bring-up and tear-down; tests stand in for them, as the real
// ones create a system TUN.
var (
	awgDeviceUp   = (*CoreController).awgDeviceUpPlatform
	awgDeviceDown = (*CoreController).awgDeviceDownPlatform
)

// awgStart brings the chosen link up and arms the session, all under
// coreMutex so a start queued behind it finds either nothing of this session
// or all of it.
func (x *CoreController) awgStart(ifName string, tunFd int, rawConfig string, links []string, idx int, o engineOpts, mark int64) error {
	engineStartGate("awg", mark)
	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()

	if already, err := x.prepareStartLocked(&x.awgSession, mark, x.awgStopLocked); err != nil || already {
		return err
	}
	if x.xraySession.running.Load() || x.mihomoSession.running.Load() {
		return fmt.Errorf("[AWG] another engine is already running")
	}

	rawConfig, err := awgconfig.NormalizeToINI(rawConfig)
	if err != nil {
		return fmt.Errorf("[AWG] %w", err)
	}
	uapiCfg, err := awgconfig.ParseToUAPI(rawConfig)
	if err != nil {
		return fmt.Errorf("[AWG] parse config: %w", err)
	}
	// awg (L3) takes only a plain resolver; empty -> INI DNS field.
	handle, err := awgDeviceUp(x, ifName, tunFd, rawConfig, uapiCfg, o.dns.FirstPlainServer())
	if err != nil {
		return err
	}
	x.currentAwgHandle = handle
	x.awgSession.up(mark)
	log.Println("[AWG] Started successfully")

	x.startAwgLiveness(o)
	x.initAwgServerState(links, idx, o)
	x.configureAwgIPResolve(o)
	return nil
}

func (x *CoreController) awgDeviceUpPlatform(ifName string, tunFd int, rawConfig, uapiCfg, dnsOverride string) (int, error) {
	handle, err := x.platformAwgStart(ifName, tunFd, uapiCfg)
	if err != nil {
		return -1, err
	}
	if runtime.GOOS == "windows" {
		server := awgconfig.EndpointHost(rawConfig)
		// dnsConfig plain server overrides the INI DNS field.
		dns := dnsOverride
		if dns == "" {
			dns = awgconfig.DNS(rawConfig)
		}
		if dns == "" {
			dns = xrayDefaultDnsServer
		}
		addr := awgconfig.Address(rawConfig)
		if err := configureTunV3(ifName, addr, []string{server}, dns); err != nil {
			_ = x.awgStopHandleLocked(handle)
			return -1, fmt.Errorf("configure tun: %w", err)
		}
	}
	return handle, nil
}

func (x *CoreController) awgDeviceDownPlatform(handle int) error {
	if err := x.awgStopHandleLocked(handle); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		cleanupTun("GlitchVPN")
	}
	return nil
}

func (x *CoreController) awgStop(stopGen int64) error {
	return x.stopEngineInstance("awg", &x.awgSession, stopGen, x.awgStopLocked)
}

// awgStopLocked tears the running device down. The caller holds coreMutex.
func (x *CoreController) awgStopLocked() {
	if !x.awgSession.running.Load() {
		return
	}
	if err := awgDeviceDown(x, x.currentAwgHandle); err != nil {
		logfmt.Errorf("[AWG] stop: %v", err)
	}
	x.awgSession.running.Store(false)
	x.currentAwgHandle = 0
	log.Println("[AWG] Stopped")
}

// awgStopHandleLocked closes one handle's device. The caller holds coreMutex.
func (x *CoreController) awgStopHandleLocked(handle int) error {
	awgHandle, exists := x.awgHandles[handle]
	if !exists {
		return fmt.Errorf("AWG handle %d not found", handle)
	}
	// A reader that loads the device after this sees none; one that loaded it
	// just before waits on the device lock Close holds.
	x.awgDevice.CompareAndSwap(awgHandle.Device, nil)

	if awgHandle.UAPI != nil {
		awgHandle.UAPI.Close()
	}
	if awgHandle.Device != nil {
		awgHandle.Device.Down()
		awgHandle.Device.Close() // closes the TUN internally
	}

	delete(x.awgHandles, handle)
	if len(x.awgHandles) == 0 {
		x.awgTunnel = nil
	}

	awgHandle.Running = false

	return nil
}

// awgDeviceState is the running device's UAPI dump, its peers' counters and
// handshakes included.
func (x *CoreController) awgDeviceState() (string, error) {
	dev := x.awgDevice.Load()
	if dev == nil {
		return "", errors.New("no running awg device")
	}
	dump, err := dev.IpcGet()
	if err != nil {
		return "", fmt.Errorf("failed to get AWG config: %w", err)
	}
	return dump, nil
}

func (x *CoreController) getAwgTraffic() (uint64, uint64) {
	dump, err := x.awgDeviceState()
	if err != nil {
		logfmt.Warnf("[Generic] Failed to get AWG config for stats: %v", err)
		return 0, 0
	}
	rx, tx := awgconfig.SumRxTx(dump)
	return rx, tx
}
