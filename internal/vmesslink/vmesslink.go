// Package vmesslink reads vmess:// share links in the two forms clients
// write: v2rayN's base64 JSON and the URI form Xray-core proposed
// (XTLS/Xray-core discussion 716). The engines' builders and serverinfo read
// a link through it, so they agree on what it says; it imports no engine.
package vmesslink

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/glitch-vpn/libglitchcore/internal/awgconfig"
	"github.com/glitch-vpn/libglitchcore/internal/sharelink"
)

const scheme = "vmess://"

// maxSharedJSON bounds the base64 payload; a real one is well under 2 KiB.
const maxSharedJSON = 64 << 10

type Link struct {
	Name    string
	Host    string
	Port    int // 0 when the link's port is unreadable
	ID      string
	AlterID int
	Cipher  string // the link's own value, "auto" when it names none
	// Params holds the transport and TLS settings under the URI form's keys
	// whichever form the link came in: type (tcp | kcp | ws | h2 | quic |
	// grpc | httpupgrade | xhttp), headerType, host, path, serviceName,
	// authority, mode, seed, security, sni, alpn, fp, allowInsecure, pcs, vcn.
	Params url.Values
}

func IsLink(link string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(link)), scheme)
}

// Parse fills what it can read even when it fails, so a caller that only
// names the server can still use the result.
func Parse(link string) (Link, error) {
	link = strings.TrimSpace(link)
	if !IsLink(link) {
		return Link{}, errors.New("vmess: not a vmess:// link")
	}
	body := link[len(scheme):]
	// base64 has no '@'; the URI form always has one before the host. A
	// remark after '#' may hold one in either form.
	payload, _, _ := strings.Cut(body, "#")
	if strings.Contains(payload, "@") {
		return parseURI(link)
	}
	return parseJSON(payload)
}

// The URI form: vmess://uuid@host:port?type=ws&security=tls&encryption=auto#name.
func parseURI(link string) (Link, error) {
	u, err := sharelink.ParseURL(link, "vmess")
	if err != nil {
		return Link{}, err
	}
	l := Link{
		Name:   strings.TrimSpace(strings.ReplaceAll(u.Fragment, "+", " ")),
		Host:   u.Hostname(),
		Cipher: "auto",
		Params: u.Query(),
	}
	if u.User != nil {
		l.ID = u.User.Username()
	}
	if c := strings.TrimSpace(l.Params.Get("encryption")); c != "" {
		l.Cipher = c
	}
	l.Port, err = port(u.Port())
	normalizeNetwork(l.Params)
	return l, err
}

func parseJSON(payload string) (Link, error) {
	payload = strings.TrimSpace(payload)
	if len(payload) > maxSharedJSON {
		return Link{}, fmt.Errorf("vmess: the base64 payload is over %d KiB", maxSharedJSON>>10)
	}
	decoded, err := awgconfig.DecodeBase64Flexible(payload)
	if err != nil {
		return Link{}, errors.New("vmess: neither base64 JSON nor a uuid@host:port link")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(decoded), &fields); err != nil {
		return Link{}, errors.New("vmess: the base64 payload is not a JSON object")
	}
	var errs []error
	// v2rayN writes numbers as strings or as numbers, depending on version.
	field := func(key string) string {
		raw, ok := fields[key]
		if !ok || string(raw) == "null" {
			return ""
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return strings.TrimSpace(s)
		}
		var n json.Number
		if json.Unmarshal(raw, &n) == nil {
			return n.String()
		}
		errs = append(errs, fmt.Errorf("vmess: JSON field %q is neither a string nor a number", key))
		return ""
	}

	// The fields of v2rayN's share-link JSON (its wiki, "分享链接格式说明(ver
	// 2)", plus the keys later versions added). ps is the remark as written:
	// a '+' in it is a plus, not a URL-encoded space.
	l := Link{
		Name:   field("ps"),
		Host:   field("add"),
		ID:     field("id"),
		Cipher: "auto",
		Params: url.Values{},
	}
	if c := field("scy"); c != "" {
		l.Cipher = c
	}
	if aid := field("aid"); aid != "" {
		if l.AlterID, err = strconv.Atoi(aid); err != nil || l.AlterID < 0 {
			errs = append(errs, fmt.Errorf("vmess: invalid alterId %q", aid))
		}
	}
	l.Port, err = port(field("port"))
	errs = append(errs, err)

	p := l.Params
	set := func(k, v string) {
		if v != "" {
			p.Set(k, v)
		}
	}
	network := canonicalNetwork(field("net"))
	// "type", "host" and "path" mean different things per network.
	switch network {
	case "grpc":
		set("serviceName", field("path"))
		set("authority", field("host"))
		set("mode", field("type"))
	case "kcp":
		set("seed", field("path"))
		set("headerType", field("type"))
	case "xhttp":
		set("host", field("host"))
		set("path", field("path"))
		set("mode", field("type"))
	default:
		set("headerType", field("type"))
		set("host", field("host"))
		set("path", field("path"))
	}
	set("security", field("tls"))
	set("sni", field("sni"))
	set("alpn", field("alpn"))
	set("fp", field("fp"))
	set("allowInsecure", field("insecure"))
	set("pcs", field("pcs"))
	set("vcn", field("vcn"))
	set("type", network)
	normalizeNetwork(p)
	return l, errors.Join(errs...)
}

// normalizeNetwork puts the network under its one name and lowercases the
// keys the builders switch on.
func normalizeNetwork(p url.Values) {
	p.Set("type", canonicalNetwork(p.Get("type")))
	for _, k := range []string{"headerType", "security"} {
		if v := p.Get(k); v != "" {
			p.Set(k, strings.ToLower(strings.TrimSpace(v)))
		}
	}
}

// canonicalNetwork folds the aliases both link forms use: raw is tcp, and
// http means HTTP/2.
func canonicalNetwork(network string) string {
	network = strings.ToLower(strings.TrimSpace(network))
	switch network {
	case "", "raw":
		return "tcp"
	case "http":
		return "h2"
	case "mkcp":
		return "kcp"
	case "websocket":
		return "ws"
	case "splithttp":
		return "xhttp"
	}
	return network
}

func port(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 || n > 65535 {
		return 0, fmt.Errorf("vmess: invalid port %q", s)
	}
	return n, nil
}
