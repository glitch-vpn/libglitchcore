package core

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// EngineStartRequest: engine-specific knobs go in Opts to keep the FFI ABI stable.
type EngineStartRequest struct {
	Config    string            `json:"config"`
	TunFD     int               `json:"tunFd"`
	DNS       string            `json:"dns"`
	LogLevel  int               `json:"logLevel"`
	Opts      map[string]string `json:"opts,omitempty"`
	DNSConfig *dnsconfig.Config `json:"dnsConfig,omitempty"`
}

// dnsFromRequest: falls back to the legacy DNS string; disableIPv6 rides on the DNS intent.
// An entry the engines would fail the start on is refused here, naming it.
func dnsFromRequest(req EngineStartRequest, engine string) (dnsconfig.Config, error) {
	var cfg dnsconfig.Config
	switch {
	case req.DNSConfig != nil:
		cfg = *req.DNSConfig
	case strings.TrimSpace(req.DNS) != "":
		cfg = dnsconfig.Config{Servers: []string{req.DNS}}
	}
	cfg.DisableIPv6 = boolOpt(req.Opts["disableIPv6"])
	// mihomo's proxy-mode inbound never applies the filter, and a mihomo tunnel
	// start with no mode runs fake-ip; xray takes the mode as given.
	effective := cfg
	if engine == "mihomo" {
		if proxyPortFromOpts(req.Opts) > 0 {
			return cfg, nil
		}
		if strings.TrimSpace(effective.Mode) == "" {
			effective.Mode = dnsconfig.ModeFakeIP
		}
	}
	if err := effective.Validate(engine); err != nil {
		return dnsconfig.Config{}, fmt.Errorf("dnsConfig: %w", err)
	}
	return cfg, nil
}

func boolOpt(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// engineOpts parsed from Opts; engines ignore unsupported fields.
type engineOpts struct {
	routing   routing.Profile
	dns       dnsconfig.Config
	strategy  string // balancer strategy ("" = engine default)
	proxyPort int    // >0 = loopback proxy mode, no TUN
	// fake-IP->domain mapping is never disabled (fake-ip can't route without it).
	sniffing    bool
	probeURL    string
	awgPicked   string
	livenessSec int
	// xray Mux (mihomo ignores); muxConcurrency==0 = off.
	muxConcurrency  int
	xudpConcurrency int
	fingerprint     string
	// Caller-supplied dir with geoip.dat/geosite.dat, applied in the process
	// that runs the engine (crosses the service IPC inside the request).
	// "" = the Initialize-time default. awg ignores (no rule engine).
	geoAssetsDir string
	proxyUser    string // both empty = open inbound
	proxyPass    string
	// External-IP resolution (IPEvent); on unless explicitly disabled.
	resolveIP bool
	ipEchoV4  string // "" = default echo service
	ipEchoV6  string
}

func optsFromRequest(req EngineStartRequest, engine string) (engineOpts, error) {
	o := req.Opts
	sniffing := true
	if v, ok := o["sniffing"]; ok && strings.TrimSpace(v) != "" {
		sniffing = boolOpt(v)
	}
	resolveIP := true
	if v, ok := o["resolveExternalIp"]; ok && strings.TrimSpace(v) != "" {
		resolveIP = boolOpt(v)
	}
	prof, err := routingFromOpts(o)
	if err != nil {
		return engineOpts{}, err
	}
	dns, err := dnsFromRequest(req, engine)
	if err != nil {
		return engineOpts{}, err
	}
	return engineOpts{
		routing:         prof,
		dns:             dns,
		strategy:        o["balancerStrategy"],
		proxyPort:       proxyPortFromOpts(o),
		sniffing:        sniffing,
		probeURL:        probeURLOpt(o["probeUrl"]),
		awgPicked:       strings.TrimSpace(o["awgPicked"]),
		livenessSec:     intOpt(o["livenessIntervalSec"]),
		muxConcurrency:  intOpt(o["muxConcurrency"]),
		xudpConcurrency: intOpt(o["xudpConcurrency"]),
		fingerprint:     strings.TrimSpace(o["fingerprint"]),
		geoAssetsDir:    geoAssetsDirOpt(o["geoAssetsDir"]),
		proxyUser:       o["proxyUser"],
		proxyPass:       o["proxyPass"],
		resolveIP:       resolveIP,
		ipEchoV4:        probeURLOpt(o["ipv4EchoUrl"]),
		ipEchoV6:        probeURLOpt(o["ipv6EchoUrl"]),
	}, nil
}

func intOpt(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// geoAssetsDirOpt rejects relative paths - the engine may run in a service
// process whose working directory the caller cannot know.
func geoAssetsDirOpt(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !filepath.IsAbs(s) {
		logfmt.Warnf("[Engine] ignoring relative geoAssetsDir %q (want an absolute path)", s)
		return ""
	}
	return s
}

// probeURLOpt rejects non-http(s) URLs so a typo can't break health checks.
func probeURLOpt(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		logfmt.Warnf("[Engine] ignoring invalid probeUrl %q (want http(s)://...)", s)
		return ""
	}
	return s
}

// Engine: one-at-a-time is enforced by handlers, not the registry.
type Engine interface {
	ID() string
	Start(x *CoreController, req EngineStartRequest) int32
	Stop(x *CoreController) int32
	IsRunning(x *CoreController) int32
	Traffic(x *CoreController) (rx, tx uint64, ok bool) // never IPC-forwarded
}

var engineRegistry = map[string]Engine{}

func registerEngine(e Engine) { engineRegistry[e.ID()] = e }

func (x *CoreController) readEngineTraffic() (rx, tx uint64, running bool) {
	for _, e := range engineRegistry {
		if rx, tx, ok := e.Traffic(x); ok {
			return rx, tx, true
		}
	}
	return 0, 0, false
}

func proxyPortFromOpts(o map[string]string) int {
	n, err := strconv.Atoi(strings.TrimSpace(o["proxyPort"]))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// CSV rule keys the core does not read. A caller sending them would connect
// without the rules it means, so their presence fails the start.
var legacyRuleKeys = []string{"proxyRules", "directRules", "blockRules", "bypassCountries"}

// routingFromOpts: "routingTiers" is a JSON array of {block,direct,proxy}.
// Malformed tiers fail the start instead of degrading - silently dropping
// block rules would bypass the kill-switch.
func routingFromOpts(o map[string]string) (routing.Profile, error) {
	for _, key := range legacyRuleKeys {
		if _, ok := o[key]; ok {
			return routing.Profile{}, fmt.Errorf("%s is not read; send the rules as routingTiers", key)
		}
	}
	p := routing.Profile{
		Mode: o["routingMode"],
		// Raw: only xray knows the value set, and engine.go cannot import
		// xrayconfig (untagged file), so xrayStart normalizes it in place.
		DomainStrategy: strings.TrimSpace(o["domainStrategy"]),
		LocalNetworks:  boolOpt(o["localNetworksDirect"]),
		DisableIPv6:    boolOpt(o["disableIPv6"]),
		DisableUDP:     boolOpt(o["disableUDP"]),
	}
	if raw := strings.TrimSpace(o["routingTiers"]); raw != "" {
		// DisallowUnknownFields: a misspelled "block" would otherwise parse as
		// an empty tier and drop the kill-switch rules it was meant to carry.
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p.Tiers); err != nil {
			return routing.Profile{}, fmt.Errorf("routingTiers: %w", err)
		}
		if dec.More() {
			return routing.Profile{}, fmt.Errorf("routingTiers: trailing data after the tier list")
		}
		// "null" decodes without error into no tiers, which would drop every
		// rule - including the kill-switch ones - as quietly as a typo.
		if p.Tiers == nil {
			return routing.Profile{}, fmt.Errorf("routingTiers: null is not a tier list")
		}
		if err := p.Validate(); err != nil {
			return routing.Profile{}, fmt.Errorf("routingTiers: %w", err)
		}
	}
	return p, nil
}

func (x *CoreController) localEngineRunning(e Engine) bool {
	return e.IsRunning(x) == glitchCoreResultSuccess
}

func (x *CoreController) anyLocalEngineRunning() bool {
	return x.localRunningEngineID() != ""
}

// Casing the engines use in their own lifecycle messages; clients may match it.
func engineDisplayName(id string) string {
	switch id {
	case "xray":
		return "Xray"
	case "awg":
		return "AWG"
	default:
		return id
	}
}

func (x *CoreController) localRunningEngineID() string {
	for id, e := range engineRegistry {
		if x.localEngineRunning(e) {
			return id
		}
	}
	return ""
}

// Forwards to the Windows service when useServiceIPC is set; proxy mode stays in-process.
func (x *CoreController) engineStart(id string, req EngineStartRequest) int32 {
	e, ok := engineRegistry[id]
	if !ok {
		logfmt.Errorf("[Engine] start rejected: unknown engine %q", id)
		return glitchCoreResultError
	}
	if useServiceIPC && proxyPortFromOpts(req.Opts) <= 0 {
		if err := serviceEngineStart(id, req); err != nil {
			logfmt.Errorf("[Engine] service start failed for %q: %v", id, err)
			if x != nil {
				x.emitStatus(EngineError, fmt.Sprintf("[%s] Failed to start: %v", id, err))
			}
			return glitchCoreResultError
		}
		return glitchCoreResultSuccess
	}
	return e.Start(x, req)
}

// Stops whichever process actually runs the engine: an in-process (proxy-mode)
// session must never translate into a stop of the service's session.
func (x *CoreController) engineStop(id string) int32 {
	e, ok := engineRegistry[id]
	if !ok {
		logfmt.Errorf("[Engine] stop rejected: unknown engine %q", id)
		return glitchCoreResultError
	}
	if useServiceIPC && !x.localEngineRunning(e) {
		if err := serviceEngineStop(id); err != nil {
			logfmt.Errorf("[Engine] service stop failed for %q: %v", id, err)
			return glitchCoreResultError
		}
		return glitchCoreResultSuccess
	}
	return e.Stop(x)
}

func (x *CoreController) engineIsRunning(id string) int32 {
	e, ok := engineRegistry[id]
	if !ok {
		return glitchCoreResultError
	}
	if x.localEngineRunning(e) {
		return glitchCoreResultSuccess
	}
	if useServiceIPC {
		running, err := serviceEngineStatus(id)
		if err != nil {
			logfmt.Warnf("[Engine] service status failed for %q: %v", id, err)
			return glitchCoreResultError
		}
		if running {
			return glitchCoreResultSuccess
		}
	}
	return glitchCoreResultError
}

func (x *CoreController) activeEngineID() string {
	for id := range engineRegistry {
		if x.engineIsRunning(id) == glitchCoreResultSuccess {
			return id
		}
	}
	return ""
}

func coreCapabilities() string {
	ids := make([]string, 0, len(engineRegistry))
	for id := range engineRegistry {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	payload := struct {
		Engines  []string          `json:"engines"`
		Versions map[string]string `json:"versions"`
		Features []string          `json:"features"`
	}{
		Engines:  ids,
		Versions: engineVersions(),
		Features: []string{"serverEvent", "ipEvent"},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return `{"engines":[]}`
	}
	return string(b)
}
