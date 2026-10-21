package mihomoconfig

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/glitch-vpn/libglitchcore/internal/sharelink"
)

func parseShareLink(link, protocol string) (*url.URL, error) {
	u, err := sharelink.ParseURL(link, protocol)
	if err != nil {
		return nil, err
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("%s: missing server host", protocol)
	}
	return u, nil
}

// portOrDefault reads the link's port; a link that names none means 443.
func portOrDefault(u *url.URL, protocol string) (int, error) {
	s := u.Port()
	if s == "" {
		return 443, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > 65535 {
		return 0, fmt.Errorf("%s: invalid port %q", protocol, s)
	}
	return n, nil
}

func flagSet(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true":
		return true
	}
	return false
}

// Share-link generators spell "skip certificate verification" three ways.
func insecureRequested(q url.Values) bool {
	return flagSet(q.Get("insecure")) || flagSet(q.Get("allowInsecure")) || flagSet(q.Get("allow_insecure"))
}

// applyCertChecks maps the certificate options a TLS link may carry: skip
// verification, a pinned certificate hash (pcs in v2rayN, hpkp in mihomo's
// converter), the name to verify the certificate against, and ECH.
func applyCertChecks(p map[string]any, q url.Values, protocol string) error {
	if insecureRequested(q) {
		p["skip-cert-verify"] = true
	}
	pin := q.Get("pcs")
	if pin == "" {
		pin = q.Get("hpkp")
	}
	if pin = strings.TrimSpace(pin); pin != "" {
		if strings.Contains(pin, ",") {
			return fmt.Errorf("%s: more than one pinned certificate is not supported", protocol)
		}
		p["fingerprint"] = pin
	}
	if name := strings.TrimSpace(q.Get("vcn")); name != "" {
		if strings.Contains(name, ",") {
			return fmt.Errorf("%s: more than one certificate name to verify is not supported", protocol)
		}
		p["name-cert-verify"] = name
	}
	ech, err := echOptions(q.Get("ech"), protocol)
	if err != nil {
		return err
	}
	if ech != nil {
		p["ech-opts"] = ech
	}
	return nil
}

// echOptions takes ech as a switch (Hiddify) or as a base64 ECHConfigList
// (v2rayN, xray). xray's other form, a domain and a DNS server to query,
// has no mihomo equivalent.
func echOptions(v, protocol string) (map[string]any, error) {
	v = strings.TrimSpace(v)
	switch strings.ToLower(v) {
	case "", "0", "false":
		return nil, nil
	case "1", "true":
		return map[string]any{"enable": true}, nil
	}
	if _, err := base64.StdEncoding.DecodeString(v); err != nil {
		return nil, fmt.Errorf("%s: ech must be a base64 ECHConfigList", protocol)
	}
	return map[string]any{"enable": true, "config": v}, nil
}

// Only plain TLS: a link asking for REALITY or no TLS at all names a
// security layer the protocol's mihomo outbound does not have.
func requireTLSSecurity(q url.Values, protocol string) error {
	switch s := strings.ToLower(strings.TrimSpace(q.Get("security"))); s {
	case "", "tls":
		return nil
	default:
		return fmt.Errorf("%s: security %q is not supported", protocol, s)
	}
}
