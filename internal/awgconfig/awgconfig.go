// Package awgconfig parses AmneziaWG/WireGuard INI into UAPI (WireGuard, AWG 1.0, 2.0 and 3.x fields).
package awgconfig

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// LinkScheme prefixes the AmneziaWG share-link format: awg://<base64url(INI)>[#name].
// AWG has no share-link standard; wrapping the whole INI in base64 (not a
// query-param mapping) lets the additive INI parser handle new fields with no
// link-format change.
const LinkScheme = "awg://"

func EncodeLink(ini, name string) string {
	link := LinkScheme + base64.RawURLEncoding.EncodeToString([]byte(ini))
	if name != "" {
		link += "#" + url.PathEscape(name)
	}
	return link
}

func LinkName(link string) string {
	s := strings.TrimSpace(link)
	if !strings.HasPrefix(s, LinkScheme) {
		return ""
	}
	i := strings.IndexByte(s, '#')
	if i < 0 || i == len(s)-1 {
		return ""
	}
	name, err := url.PathUnescape(s[i+1:])
	if err != nil {
		return s[i+1:]
	}
	return name
}

// NormalizeToINI returns the INI for either an awg:// link or a raw INI config
// (passed through unchanged), so callers accept both.
func NormalizeToINI(input string) (string, error) {
	s := strings.TrimSpace(input)
	if !strings.HasPrefix(s, LinkScheme) {
		return input, nil
	}
	payload := strings.TrimPrefix(s, LinkScheme)
	if i := strings.IndexByte(payload, '#'); i >= 0 {
		payload = payload[:i]
	}
	ini, err := DecodeBase64Flexible(payload)
	if err != nil {
		return "", fmt.Errorf("awg link: %w", err)
	}
	return ini, nil
}

// DecodeBase64Flexible tries every base64 alphabet/padding combination share
// links appear with in the wild.
func DecodeBase64Flexible(s string) (string, error) {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(strings.TrimSpace(s)); err == nil {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("not valid base64")
}

// KeyBytes decodes a WireGuard-style key from base64 or hex, and refuses
// anything but exactly 32 bytes.
func KeyBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "hex:")
	s = strings.TrimPrefix(s, "0x")

	isHex := true
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			isHex = false
			break
		}
	}
	if isHex && len(s)%2 == 0 {
		if len(s) != 64 {
			return nil, fmt.Errorf("expected 32-byte hex key, got %d hex chars", len(s))
		}
		return hex.DecodeString(s)
	}

	var b []byte
	var err error
	if b, err = base64.StdEncoding.DecodeString(s); err != nil {
		if b, err = base64.RawStdEncoding.DecodeString(s); err != nil {
			if b, err = base64.RawURLEncoding.DecodeString(s); err != nil {
				return nil, fmt.Errorf("key is neither hex nor base64: %w", err)
			}
		}
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("expected 32-byte key, got %d bytes", len(b))
	}
	return b, nil
}

// normalizeKeyToHex gives a key as the lowercase 64-char hex UAPI expects.
func normalizeKeyToHex(s string) (string, error) {
	b, err := KeyBytes(s)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// AWG15Keys are AWG 1.5's extra junk packets, lowercased, which amneziawg-go
// 2.0 and later refuse; dropping them would weaken the obfuscation unannounced.
var AWG15Keys = []string{"j1", "j2", "j3", "itime"}

// AWG3Keys maps the [Interface] keys only AWG 3.x reads, lowercased, to their
// UAPI names.
var AWG3Keys = map[string]string{
	"headerprotectionkey":    "header_protection_key",
	"contentpaddingaddition": "content_padding_addition",
	"rekeyaftertime":         "rekey_after_time",
	"rekeytimeout":           "rekey_timeout",
	"rejectaftertime":        "reject_after_time",
	"keepalivetimeout":       "keepalive_timeout",
	"maxhandshakeattempts":   "max_handshake_attempts",
	"randomtrailers":         "random_trailers",
	"disablecookies":         "disable_cookies",
}

// deviceKeys maps every [Interface] key amneziawg-go reads, lowercased, to
// its UAPI name.
var deviceKeys = func() map[string]string {
	keys := map[string]string{}
	for _, k := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
		"h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"} {
		keys[k] = k
	}
	for k, uapi := range AWG3Keys {
		keys[k] = uapi
	}
	return keys
}()

// ParseBool reads an AWG boolean the way amneziawg-tools does: on/off or a
// number, plus true/false.
func ParseBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true":
		return true, nil
	case "off", "false":
		return false, nil
	}
	n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
	if err != nil {
		return false, fmt.Errorf("%q is neither on/off nor a number", v)
	}
	return n != 0, nil
}

// CheckRange accepts what amneziawg-go's UintRange reads: "lo" or "lo-hi",
// both unsigned 32-bit, lo <= hi.
func CheckRange(v string) error {
	lo, hi, isRange := strings.Cut(v, "-")
	low, err := strconv.ParseUint(lo, 10, 32)
	if err != nil {
		return fmt.Errorf("%q is not a number or a lo-hi range", v)
	}
	if isRange {
		high, err := strconv.ParseUint(hi, 10, 32)
		if err != nil || high < low {
			return fmt.Errorf("%q is not a number or a lo-hi range", v)
		}
	}
	return nil
}

// AWG3Value checks an AWG 3.x [Interface] value and gives it in UAPI form.
func AWG3Value(key, val string) (string, error) {
	switch key {
	case "headerprotectionkey":
		return normalizeKeyToHex(val)
	case "randomtrailers", "disablecookies":
		b, err := ParseBool(val)
		return strconv.FormatBool(b), err
	}
	return val, CheckRange(val)
}

func deviceValue(key, val string) (string, error) {
	if _, ok := AWG3Keys[key]; ok {
		return AWG3Value(key, val)
	}
	return val, nil
}

// hasControl reports a control character other than tab. UAPI is line-based,
// and the device quotes a line it cannot read in its error.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r != '\t' && unicode.IsControl(r) })
}

// ParseToUAPI converts an INI AmneziaWG config into UAPI "set" format.
func ParseToUAPI(cfg string) (string, error) {
	type peer struct {
		pub       string
		psk       string
		endpoint  string
		keepalive string
		allowed   []string
	}

	var (
		devicePriv   string
		deviceListen string
		peers        []peer
		curPeer      *peer
		section      string
		deviceExtras []string
	)

	for _, rawLine := range strings.Split(cfg, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			switch strings.ToLower(strings.Trim(line, "[] \t")) {
			case "interface":
				section = "interface"
				curPeer = nil
			case "peer":
				section = "peer"
				peers = append(peers, peer{})
				curPeer = &peers[len(peers)-1]
			default:
				section = ""
				curPeer = nil
			}
			continue
		}

		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		if hasControl(val) {
			return "", fmt.Errorf("%s.%s: the value holds a control character", section, key)
		}

		switch section {
		case "interface":
			switch key {
			case "privatekey":
				h, err := normalizeKeyToHex(val)
				if err != nil {
					return "", fmt.Errorf("interface.private_key: %w", err)
				}
				devicePriv = h
			case "listenport":
				deviceListen = val
			default:
				if slices.Contains(AWG15Keys, key) {
					return "", fmt.Errorf("interface.%s: AmneziaWG 1.5 keys J1-J3 and Itime are not supported", key)
				}
				if uapiKey, ok := deviceKeys[key]; ok {
					v, err := deviceValue(key, val)
					if err != nil {
						return "", fmt.Errorf("interface.%s: %w", uapiKey, err)
					}
					deviceExtras = append(deviceExtras, uapiKey+"="+v)
				}
			}

		case "peer":
			if curPeer == nil {
				continue
			}
			switch key {
			case "publickey":
				h, err := normalizeKeyToHex(val)
				if err != nil {
					return "", fmt.Errorf("peer.public_key: %w", err)
				}
				curPeer.pub = h
			case "presharedkey":
				h, err := normalizeKeyToHex(val)
				if err != nil {
					return "", fmt.Errorf("peer.preshared_key: %w", err)
				}
				curPeer.psk = h
			case "endpoint":
				curPeer.endpoint = val
			case "persistentkeepalive", "persistent_keepalive":
				// AWG 3.x takes a range ("22-30") as well as one interval.
				if !strings.EqualFold(val, "off") {
					curPeer.keepalive = val
				}
			case "allowedips":
				for _, ip := range strings.Split(val, ",") {
					ip = strings.TrimSpace(ip)
					if ip != "" {
						curPeer.allowed = append(curPeer.allowed, ip)
					}
				}
			}
		}
	}

	// Emit UAPI in the required order.
	var sb strings.Builder
	sb.WriteString("replace_peers=true\n")
	if devicePriv == "" {
		return "", fmt.Errorf("missing interface private key")
	}
	sb.WriteString("private_key=" + devicePriv + "\n")
	if deviceListen != "" {
		sb.WriteString("listen_port=" + deviceListen + "\n")
	}
	for _, kv := range deviceExtras {
		sb.WriteString(kv + "\n")
	}

	if len(peers) == 0 {
		return "", fmt.Errorf("no peers defined")
	}

	for i, p := range peers {
		if p.pub == "" {
			return "", fmt.Errorf("peer[%d]: missing public key", i)
		}
		sb.WriteString("public_key=" + p.pub + "\n")
		if p.psk != "" {
			sb.WriteString("preshared_key=" + p.psk + "\n")
		}
		if p.endpoint != "" {
			sb.WriteString("endpoint=" + p.endpoint + "\n")
		}
		if p.keepalive != "" {
			sb.WriteString("persistent_keepalive_interval=" + p.keepalive + "\n")
		}
		// IMPORTANT: must come after public_key.
		sb.WriteString("replace_allowed_ips=true\n")
		for _, ip := range p.allowed {
			sb.WriteString("allowed_ip=" + ip + "\n")
		}
	}

	return sb.String(), nil
}

// Address returns the first Interface Address from a WireGuard config.
func Address(cfg string) string {
	lines := strings.Split(cfg, "\n")
	section := ""
	for _, l := range lines {
		line := strings.TrimSpace(l)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[] \t"))
			continue
		}
		if section != "interface" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(line), "address") {
			continue
		}
		if idx := strings.Index(line, "="); idx >= 0 {
			val := strings.TrimSpace(line[idx+1:])
			val = strings.ReplaceAll(val, ",", " ")
			fields := strings.Fields(val)
			if len(fields) > 0 {
				return fields[0]
			}
		}
	}
	return ""
}

// Addresses returns every Interface Address of a WireGuard config in order,
// the IPv4 and IPv6 entries alike.
func Addresses(cfg string) []string {
	var out []string
	forEachKey(cfg, "interface", "address", func(fields []string) {
		out = append(out, fields...)
	})
	return out
}

// TunnelAddresses is Addresses cut to what a TUN can carry: a prefix that
// parses for its family, and an address that is not loopback, unspecified,
// multicast or link-local. A config is untrusted input, and a TUN builder
// that refuses every address leaves no tunnel at all.
func TunnelAddresses(cfg string) []string {
	var out []string
	for _, a := range Addresses(cfg) {
		prefix, err := netip.ParsePrefix(a)
		if err != nil {
			continue
		}
		ip := prefix.Addr()
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, a)
	}
	return out
}

// PeersCarryIPv6 reports whether any Peer routes an IPv6 prefix in AllowedIPs.
func PeersCarryIPv6(cfg string) bool {
	carries := false
	forEachKey(cfg, "peer", "allowedips", func(fields []string) {
		for _, f := range fields {
			if strings.Contains(f, ":") {
				carries = true
			}
		}
	})
	return carries
}

func forEachKey(cfg, wantSection, wantKey string, fn func(fields []string)) {
	section := ""
	for _, l := range strings.Split(cfg, "\n") {
		line := strings.TrimSpace(l)
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[] \t"))
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok || section != wantSection || strings.ToLower(strings.TrimSpace(key)) != wantKey {
			continue
		}
		fn(strings.FieldsFunc(val, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' }))
	}
}

// SumRxTx sums rx_bytes/tx_bytes counters from a UAPI get dump.
func SumRxTx(dump string) (rx, tx uint64) {
	// UAPI dump lines hold several key=value pairs each.
	lines := strings.Split(dump, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		for _, f := range fields {
			if !strings.Contains(f, "=") {
				continue
			}
			kv := strings.SplitN(f, "=", 2)
			if len(kv) != 2 {
				continue
			}
			key, val := kv[0], kv[1]
			switch key {
			case "rx_bytes":
				if n, err := strconv.ParseUint(val, 10, 64); err == nil {
					rx += n
				}
			case "tx_bytes":
				if n, err := strconv.ParseUint(val, 10, 64); err == nil {
					tx += n
				}
			}
		}
	}
	return
}

// LastHandshakeUnix returns the newest last_handshake_time_sec across all
// peers in a UAPI get dump, or 0 when no peer has completed a handshake yet.
func LastHandshakeUnix(dump string) int64 {
	var newest int64
	for _, line := range strings.Split(dump, "\n") {
		for _, f := range strings.Fields(line) {
			kv := strings.SplitN(f, "=", 2)
			if len(kv) != 2 || kv[0] != "last_handshake_time_sec" {
				continue
			}
			if n, err := strconv.ParseInt(kv[1], 10, 64); err == nil && n > newest {
				newest = n
			}
		}
	}
	return newest
}

func EndpointHost(cfg string) string {
	val := endpointValue(cfg)
	if colon := strings.LastIndex(val, ":"); colon >= 0 {
		return val[:colon]
	}
	return val
}

// Port 0 when absent/invalid; bracketed IPv6 loses the brackets.
func EndpointHostPort(cfg string) (string, int) {
	val := endpointValue(cfg)
	if val == "" {
		return "", 0
	}
	if h, p, err := net.SplitHostPort(val); err == nil {
		port, _ := strconv.Atoi(p)
		if port < 0 || port > 65535 {
			port = 0
		}
		return h, port
	}
	return strings.Trim(val, "[]"), 0
}

func endpointValue(cfg string) string {
	for _, l := range strings.Split(cfg, "\n") {
		line := strings.TrimSpace(l)
		if strings.HasPrefix(strings.ToLower(line), "endpoint") {
			if idx := strings.Index(line, "="); idx >= 0 {
				return strings.TrimSpace(line[idx+1:])
			}
		}
	}
	return ""
}

func DNS(cfg string) string {
	lines := strings.Split(cfg, "\n")
	for _, l := range lines {
		line := strings.TrimSpace(l)
		if strings.HasPrefix(strings.ToLower(line), "dns") {
			if idx := strings.Index(line, "="); idx >= 0 {
				return strings.TrimSpace(line[idx+1:])
			}
		}
	}
	return ""
}
