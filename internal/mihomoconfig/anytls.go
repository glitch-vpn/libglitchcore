package mihomoconfig

import (
	"fmt"
	"strings"
)

// anytlsProxy reads anytls://password@host:port, the scheme anytls-go
// documents, plus the TLS keys v2rayN and Hiddify add. The whole userinfo is
// the password, as v2rayN and Hiddify read it; mihomo's converter alone drops
// what precedes a colon.
func anytlsProxy(link, name string) (map[string]any, error) {
	u, err := parseShareLink(link, "anytls")
	if err != nil {
		return nil, err
	}
	port, err := portOrDefault(u, "anytls")
	if err != nil {
		return nil, err
	}
	password := ""
	if u.User != nil {
		password = u.User.Username()
		if rest, ok := u.User.Password(); ok {
			password += ":" + rest
		}
	}
	if password == "" {
		return nil, fmt.Errorf("anytls: missing password")
	}

	q := u.Query()
	if err := requireTLSSecurity(q, "anytls"); err != nil {
		return nil, err
	}
	switch network := strings.ToLower(strings.TrimSpace(q.Get("type"))); network {
	case "", "tcp", "raw":
	default:
		return nil, fmt.Errorf("anytls: transport %q is not supported", network)
	}

	p := map[string]any{
		"name":     name,
		"type":     "anytls",
		"server":   u.Hostname(),
		"port":     port,
		"password": password,
		"udp":      true,
	}
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	if sni != "" {
		p["sni"] = sni
	}
	if fp := q.Get("fp"); fp != "" {
		p["client-fingerprint"] = fp
	}
	if alpn := splitCSV(q.Get("alpn")); len(alpn) > 0 {
		p["alpn"] = alpn
	}
	if err := applyCertChecks(p, q, "anytls"); err != nil {
		return nil, err
	}
	return p, nil
}
