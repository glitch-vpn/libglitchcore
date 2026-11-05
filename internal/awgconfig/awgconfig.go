// Package awgconfig reads AmneziaWG and WireGuard configs: the INI, and the
// awg://, wireguard:// and wg:// links that carry it. mihomo builds its
// WireGuard outbound from the INI this package returns.
package awgconfig

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
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

// LinkName is a link's #name, "" for a raw INI. A wireguard:// remark is
// URL-encoded, where '+' is a space.
func LinkName(link string) string {
	s := strings.TrimSpace(link)
	lower := strings.ToLower(s)
	uri := isURILink(lower)
	if !uri && !strings.HasPrefix(lower, LinkScheme) {
		return ""
	}
	i := strings.IndexByte(s, '#')
	if i < 0 || i == len(s)-1 {
		return ""
	}
	name, err := url.PathUnescape(s[i+1:])
	if err != nil {
		name = s[i+1:]
	}
	if uri {
		name = strings.TrimSpace(strings.ReplaceAll(name, "+", " "))
	}
	return name
}

// NormalizeToINI returns the INI for an awg://, wireguard:// or wg:// link,
// and passes a raw INI config through unchanged, so callers accept all of them.
func NormalizeToINI(input string) (string, error) {
	s := strings.TrimSpace(input)
	lower := strings.ToLower(s)
	if isURILink(lower) {
		return linkToINI(s)
	}
	if !strings.HasPrefix(lower, LinkScheme) {
		return input, nil
	}
	payload := s[len(LinkScheme):]
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
