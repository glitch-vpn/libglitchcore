package awgconfig

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/glitch-vpn/libglitchcore/internal/sharelink"
)

// uriSchemes are the WireGuard share links v2rayNG, v2rayN and Hiddify write:
// wireguard://<private key>@host:port?publickey=...&address=...#name.
var uriSchemes = []string{"wireguard://", "wg://"}

func isURILink(lower string) bool {
	for _, s := range uriSchemes {
		if strings.HasPrefix(lower, s) {
			return true
		}
	}
	return false
}

// IsLink reports a config the WireGuard path reads: an awg://, wireguard://
// or wg:// link, or a raw INI.
func IsLink(link string) bool {
	trimmed := strings.TrimSpace(link)
	lower := strings.ToLower(trimmed)
	return strings.HasPrefix(lower, LinkScheme) || isURILink(lower) || strings.Contains(trimmed, "[Interface]")
}

// awgLinkKeys are the AmneziaWG keys a link may carry, as the query names them
// (lowercase), with the INI key each becomes.
var awgLinkKeys = []struct{ query, ini string }{
	{"jc", "Jc"}, {"jmin", "Jmin"}, {"jmax", "Jmax"},
	{"s1", "S1"}, {"s2", "S2"}, {"s3", "S3"}, {"s4", "S4"},
	{"h1", "H1"}, {"h2", "H2"}, {"h3", "H3"}, {"h4", "H4"},
	{"i1", "I1"}, {"i2", "I2"}, {"i3", "I3"}, {"i4", "I4"}, {"i5", "I5"},
	{"j1", "J1"}, {"j2", "J2"}, {"j3", "J3"}, {"itime", "Itime"},
	{"headerprotectionkey", "HeaderProtectionKey"},
	{"contentpaddingaddition", "ContentPaddingAddition"},
	{"rekeyaftertime", "RekeyAfterTime"},
	{"rekeytimeout", "RekeyTimeout"},
	{"rejectaftertime", "RejectAfterTime"},
	{"keepalivetimeout", "KeepaliveTimeout"},
	{"maxhandshakeattempts", "MaxHandshakeAttempts"},
	{"randomtrailers", "RandomTrailers"},
	{"disablecookies", "DisableCookies"},
}

// firstOf reads the first of a key's spellings the link carries.
func firstOf(q map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := q[k]; v != "" {
			return v
		}
	}
	return ""
}

// linkQuery reads a query's keys case-folded, the first value of each.
// Values keep '+': a base64 key is written with it unescaped as often as not.
// In i1-i5 it is a space, which a tag chain separates with and never holds.
func linkQuery(raw string) (map[string]string, error) {
	q := map[string]string{}
	for _, pair := range strings.Split(raw, "&") {
		k, v, _ := strings.Cut(pair, "=")
		key, kerr := url.PathUnescape(k)
		val, verr := url.PathUnescape(v)
		if kerr != nil || verr != nil {
			return nil, errors.New("wireguard: malformed query")
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if len(key) == 2 && key[0] == 'i' && key[1] >= '1' && key[1] <= '5' {
			val = strings.ReplaceAll(val, "+", " ")
		}
		if _, seen := q[key]; key != "" && !seen {
			q[key] = strings.TrimSpace(val)
		}
	}
	return q, nil
}

// linkKey gives a key as the padded standard base64 mihomo decodes.
func linkKey(v, what string) (string, error) {
	if v == "" {
		return "", fmt.Errorf("wireguard: missing %s", what)
	}
	b, err := KeyBytes(v)
	if err != nil {
		return "", fmt.Errorf("wireguard: %s: %w", what, err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func linkList(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' })
}

// linkAddresses gives a bare address its host prefix, which the INI readers
// need to take it as a tunnel address.
func linkAddresses(v string) ([]string, error) {
	var out []string
	for _, f := range linkList(v) {
		if _, err := netip.ParsePrefix(f); err == nil {
			out = append(out, f)
			continue
		}
		addr, err := netip.ParseAddr(f)
		if err != nil {
			return nil, errors.New("wireguard: an address is neither an IP nor a prefix")
		}
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()).String())
	}
	return out, nil
}

// ReservedBytes reads WireGuard's three reserved header bytes, written as
// "a,b,c" or as the base64 of the three bytes.
func ReservedBytes(v string) ([3]byte, error) {
	var out [3]byte
	parts := linkList(v)
	if len(parts) == 3 {
		for i, p := range parts {
			n, err := strconv.ParseUint(p, 10, 8)
			if err != nil {
				return out, errors.New("reserved is not three bytes")
			}
			out[i] = byte(n)
		}
		return out, nil
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil || len(b) != 3 {
		return out, errors.New("reserved is not three bytes")
	}
	copy(out[:], b)
	return out, nil
}

// linkToINI reads the keys of v2rayNG and v2rayN (publickey, presharedkey,
// address, mtu, reserved, dns) and of Hiddify (privatekey or pk, peerpublickey
// or pub, ip or localaddress, allowedips, psk, keepalive), plus the AmneziaWG
// keys. The private key is the userinfo when the link has one.
func linkToINI(link string) (string, error) {
	p, err := sharelink.Split(link, "wireguard")
	if err != nil {
		return "", err
	}
	if p.Port == 0 {
		return "", errors.New("wireguard: missing port")
	}
	q, err := linkQuery(p.RawQuery)
	if err != nil {
		return "", err
	}

	privateKey := p.UserInfo
	if privateKey == "" {
		privateKey = firstOf(q, "privatekey", "pk")
	}
	if privateKey, err = linkKey(privateKey, "private key"); err != nil {
		return "", err
	}
	publicKey, err := linkKey(firstOf(q, "publickey", "peerpublickey", "pub", "peerpub"), "public key")
	if err != nil {
		return "", err
	}
	addresses, err := linkAddresses(firstOf(q, "address", "ip", "localaddress"))
	if err != nil {
		return "", err
	}

	var ini strings.Builder
	ini.WriteString("[Interface]\nPrivateKey = " + privateKey + "\n")
	if len(addresses) > 0 {
		ini.WriteString("Address = " + strings.Join(addresses, ", ") + "\n")
	}
	if dns := linkList(q["dns"]); len(dns) > 0 {
		ini.WriteString("DNS = " + strings.Join(dns, ", ") + "\n")
	}
	if v := q["mtu"]; v != "" {
		if mtu, err := strconv.Atoi(v); err != nil || mtu <= 0 {
			return "", errors.New("wireguard: mtu is not a positive number")
		}
		ini.WriteString("MTU = " + v + "\n")
	}
	for _, k := range awgLinkKeys {
		if v := q[k.query]; v != "" {
			ini.WriteString(k.ini + " = " + v + "\n")
		}
	}

	ini.WriteString("\n[Peer]\nPublicKey = " + publicKey + "\n")
	if psk := firstOf(q, "presharedkey", "psk"); psk != "" {
		if psk, err = linkKey(psk, "preshared key"); err != nil {
			return "", err
		}
		ini.WriteString("PresharedKey = " + psk + "\n")
	}
	allowed := linkList(q["allowedips"])
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	ini.WriteString("AllowedIPs = " + strings.Join(allowed, ", ") + "\n")
	ini.WriteString("Endpoint = " + net.JoinHostPort(p.Host, strconv.Itoa(p.Port)) + "\n")
	if v := q["keepalive"]; v != "" {
		if err := CheckRange(v); err != nil {
			return "", fmt.Errorf("wireguard: keepalive: %w", err)
		}
		ini.WriteString("PersistentKeepalive = " + v + "\n")
	}
	// v2rayNG writes 0,0,0 on every link; only bytes that say something go on.
	if v := q["reserved"]; v != "" {
		b, err := ReservedBytes(v)
		if err != nil {
			return "", fmt.Errorf("wireguard: %w", err)
		}
		if b != [3]byte{} {
			ini.WriteString(fmt.Sprintf("Reserved = %d, %d, %d\n", b[0], b[1], b[2]))
		}
	}
	return ini.String(), nil
}
