// Package awgconfig parses AmneziaWG/WireGuard INI into UAPI (additive: 1.x + 2.0 fields).
package awgconfig

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
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
	ini, err := decodeBase64Flexible(strings.TrimSpace(payload))
	if err != nil {
		return "", fmt.Errorf("awg link: %w", err)
	}
	return ini, nil
}

func decodeBase64Flexible(s string) (string, error) {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("not valid base64")
}

// normalizeKeyToHex normalizes a WireGuard key from base64 or hex into the
// lowercase 64-char hex (32 bytes) UAPI expects.
func normalizeKeyToHex(s string) (string, error) {
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
		out := strings.ToLower(s)
		if len(out) != 64 {
			return "", fmt.Errorf("expected 32-byte hex key, got %d hex chars", len(out))
		}
		return out, nil
	}

	var b []byte
	var err error
	if b, err = base64.StdEncoding.DecodeString(s); err != nil {
		if b, err = base64.RawStdEncoding.DecodeString(s); err != nil {
			if b, err = base64.RawURLEncoding.DecodeString(s); err != nil {
				return "", fmt.Errorf("key is neither hex nor base64: %w", err)
			}
		}
	}
	if len(b) != 32 {
		return "", fmt.Errorf("expected 32-byte key, got %d bytes", len(b))
	}
	return hex.EncodeToString(b), nil
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

	isAllowedDeviceKey := func(k string) bool {
		switch k {
		case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "itime":
			return true
		}
		if len(k) == 2 {
			switch k[0] {
			case 'i':
				return k[1] >= '1' && k[1] <= '5'
			case 'j':
				return k[1] >= '1' && k[1] <= '3'
			}
		}
		return false
	}

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
				if isAllowedDeviceKey(key) {
					deviceExtras = append(deviceExtras, key+"="+val)
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
				curPeer.keepalive = val
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
	lines := strings.Split(cfg, "\n")
	for _, l := range lines {
		line := strings.TrimSpace(l)
		if strings.HasPrefix(strings.ToLower(line), "endpoint") {
			if idx := strings.Index(line, "="); idx >= 0 {
				val := strings.TrimSpace(line[idx+1:])
				if colon := strings.LastIndex(val, ":"); colon >= 0 {
					return val[:colon]
				}
				return val
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
