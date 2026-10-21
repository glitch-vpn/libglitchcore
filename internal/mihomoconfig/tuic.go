package mihomoconfig

import (
	"fmt"
	"slices"
	"strings"
)

// tuicCongestionControls are the controllers mihomo's TUIC client sets; it
// silently keeps QUIC's default for any other name.
var tuicCongestionControls = []string{"cubic", "new_reno", "bbr", "bbr_meta_v1", "bbr_meta_v2"}

// tuicProxy reads tuic://uuid:password@host:port (TUIC v5) and
// tuic://token@host:port (v4), with the query keys v2rayN, NekoBox, Hiddify
// and mihomo's own converter write. fp is ignored: TUIC runs over QUIC, and
// no client offers a uTLS fingerprint there.
func tuicProxy(link, name string) (map[string]any, error) {
	u, err := parseShareLink(link, "tuic")
	if err != nil {
		return nil, err
	}
	port, err := portOrDefault(u, "tuic")
	if err != nil {
		return nil, err
	}
	user := ""
	if u.User != nil {
		user = u.User.Username()
	}
	if user == "" {
		return nil, fmt.Errorf("tuic: missing uuid")
	}

	p := map[string]any{
		"name":   name,
		"type":   "tuic",
		"server": u.Hostname(),
		"port":   port,
		"udp":    true,
	}
	if password, v5 := u.User.Password(); v5 {
		p["uuid"] = user
		p["password"] = password
	} else {
		p["token"] = user
	}

	q := u.Query()
	if err := requireTLSSecurity(q, "tuic"); err != nil {
		return nil, err
	}
	if sni := q.Get("sni"); sni != "" {
		p["sni"] = sni
	}
	if flagSet(q.Get("disable_sni")) {
		p["disable-sni"] = true
	}
	if alpn := splitCSV(q.Get("alpn")); len(alpn) > 0 {
		p["alpn"] = alpn
	}
	if cc := strings.ToLower(strings.TrimSpace(q.Get("congestion_control"))); cc != "" {
		if !slices.Contains(tuicCongestionControls, cc) {
			return nil, fmt.Errorf("tuic: congestion control %q is not supported", cc)
		}
		p["congestion-controller"] = cc
	}
	if mode := strings.ToLower(strings.TrimSpace(q.Get("udp_relay_mode"))); mode != "" {
		if mode != "native" && mode != "quic" {
			return nil, fmt.Errorf("tuic: udp relay mode %q is not supported", mode)
		}
		p["udp-relay-mode"] = mode
	}
	if err := applyCertChecks(p, q, "tuic"); err != nil {
		return nil, err
	}
	return p, nil
}
