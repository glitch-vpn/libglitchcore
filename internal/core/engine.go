package core

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
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
func dnsFromRequest(req EngineStartRequest) dnsconfig.Config {
	var cfg dnsconfig.Config
	switch {
	case req.DNSConfig != nil:
		cfg = *req.DNSConfig
	case strings.TrimSpace(req.DNS) != "":
		cfg = dnsconfig.Config{Servers: []string{req.DNS}}
	}
	cfg.DisableIPv6 = boolOpt(req.Opts["disableIPv6"])
	return cfg
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
	livenessSec int
	// xray Mux (mihomo ignores); muxConcurrency==0 = off.
	muxConcurrency  int
	xudpConcurrency int
	fingerprint     string
	proxyUser       string // both empty = open inbound
	proxyPass       string
}

func optsFromRequest(req EngineStartRequest) engineOpts {
	o := req.Opts
	sniffing := true
	if v, ok := o["sniffing"]; ok && strings.TrimSpace(v) != "" {
		sniffing = boolOpt(v)
	}
	return engineOpts{
		routing:         routingFromOpts(o),
		dns:             dnsFromRequest(req),
		strategy:        o["balancerStrategy"],
		proxyPort:       proxyPortFromOpts(o),
		sniffing:        sniffing,
		probeURL:        probeURLOpt(o["probeUrl"]),
		livenessSec:     intOpt(o["livenessIntervalSec"]),
		muxConcurrency:  intOpt(o["muxConcurrency"]),
		xudpConcurrency: intOpt(o["xudpConcurrency"]),
		fingerprint:     strings.TrimSpace(o["fingerprint"]),
		proxyUser:       o["proxyUser"],
		proxyPass:       o["proxyPass"],
	}
}

func intOpt(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// probeURLOpt rejects non-http(s) URLs so a typo can't break health checks.
func probeURLOpt(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		log.Printf("[Engine] ignoring invalid probeUrl %q (want http(s)://...)", s)
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

// routingFromOpts: "bypassCountries" is a legacy alias -> Direct geoip: entries.
func routingFromOpts(o map[string]string) routing.Profile {
	direct := csv(o["directRules"])
	for _, cc := range lowerCSV(o["bypassCountries"]) {
		direct = append(direct, "geoip:"+cc)
	}
	return routing.Profile{
		Mode:          o["routingMode"],
		Proxy:         csv(o["proxyRules"]),
		Direct:        direct,
		Block:         csv(o["blockRules"]),
		LocalNetworks: boolOpt(o["localNetworksDirect"]),
		DisableIPv6:   boolOpt(o["disableIPv6"]),
		DisableUDP:    boolOpt(o["disableUDP"]),
	}
}

func csv(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func lowerCSV(s string) []string {
	out := csv(s)
	for i := range out {
		out[i] = strings.ToLower(out[i])
	}
	return out
}

// Forwards to the Windows service when useServiceIPC is set; proxy mode stays in-process.
func (x *CoreController) engineStart(id string, req EngineStartRequest) int32 {
	e, ok := engineRegistry[id]
	if !ok {
		log.Printf("[Engine] start rejected: unknown engine %q", id)
		return glitchCoreResultError
	}
	if useServiceIPC && proxyPortFromOpts(req.Opts) <= 0 {
		if err := serviceEngineStart(id, req); err != nil {
			log.Printf("[Engine] service start failed for %q: %v", id, err)
			if x != nil {
				x.emitStatus(EngineError, fmt.Sprintf("[%s] Failed to start: %v", id, err))
			}
			return glitchCoreResultError
		}
		return glitchCoreResultSuccess
	}
	return e.Start(x, req)
}

func (x *CoreController) engineStop(id string) int32 {
	e, ok := engineRegistry[id]
	if !ok {
		log.Printf("[Engine] stop rejected: unknown engine %q", id)
		return glitchCoreResultError
	}
	if useServiceIPC {
		if err := serviceEngineStop(id); err != nil {
			log.Printf("[Engine] service stop failed for %q: %v", id, err)
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
	if useServiceIPC {
		running, err := serviceEngineStatus(id)
		if err != nil {
			log.Printf("[Engine] service status failed for %q: %v", id, err)
			return glitchCoreResultError
		}
		if running {
			return glitchCoreResultSuccess
		}
		return glitchCoreResultError
	}
	return e.IsRunning(x)
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
	}{
		Engines:  ids,
		Versions: engineVersions(),
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return `{"engines":[]}`
	}
	return string(b)
}
