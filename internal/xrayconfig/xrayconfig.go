// Package xrayconfig builds Xray configs from vless://|ss://|trojan:// links.
// Multiple links -> balancer + Observatory (every balancing strategy requires it).
package xrayconfig

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	xrayNet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf/cfgcommon/duration"

	xrayConf "github.com/xtls/xray-core/infra/conf"
)

const (
	OutboundTag = "proxy"
	// Per-server tags "proxy-0","proxy-1",...; xray matches balancer and
	// observatory selectors by tag prefix, so this value selects them all.
	proxyTagPrefix = "proxy-"
	balancerTag    = "vpn"
)

const (
	StrategyLeastPing  = "leastping"
	StrategyRandom     = "random"
	StrategyRoundRobin = "roundrobin"
)

const (
	defaultProbeURL         = "https://www.gstatic.com/generate_204"
	defaultProbeIntervalSec = 60
)

// BalancerOptions controls multi-server load balancing; ignored for a single link.
type BalancerOptions struct {
	Strategy         string // "leastping" (default) | "random" | "roundrobin"
	ProbeURL         string
	ProbeIntervalSec int
}

func (o BalancerOptions) normalized() (BalancerOptions, error) {
	s := strings.ToLower(strings.TrimSpace(o.Strategy))
	switch s {
	case "":
		s = StrategyLeastPing
	case StrategyLeastPing, StrategyRandom, StrategyRoundRobin:
	default:
		return o, fmt.Errorf("unknown balancer strategy %q", o.Strategy)
	}
	o.Strategy = s
	if strings.TrimSpace(o.ProbeURL) == "" {
		o.ProbeURL = defaultProbeURL
	}
	if o.ProbeIntervalSec <= 0 {
		o.ProbeIntervalSec = defaultProbeIntervalSec
	}
	return o, nil
}

type BuildResult struct {
	Config          *xrayConf.Config
	OutboundTags    []string // proxy-traffic-carrying tags, summed for stats
	DialIPv4s       []string // pre-resolved server IPv4s (route exclusion on Windows)
	Servers         []string // server hostnames, in link order
	RouteTarget     string   // tag the tun2socks rule routes to
	RouteIsBalancer bool
	VisionTags      map[string]bool // proxy tags whose link uses XTLS Vision flow (mux-incompatible)
}

// Vision flow ↔ TCP mux are mutually exclusive.
func linkHasVision(link string) bool {
	u, err := url.Parse(link)
	if err != nil || !strings.EqualFold(u.Scheme, "vless") {
		return false
	}
	return strings.Contains(strings.ToLower(u.Query().Get("flow")), "vision")
}

// BuildConfig: tun2socks inbound is added later by ApplyLocalSocksInbound.
func BuildConfig(links []string, opts BalancerOptions, routing RoutingProfile, xrayLogLevel string) (*BuildResult, error) {
	clean := make([]string, 0, len(links))
	for _, l := range links {
		if t := strings.TrimSpace(l); t != "" {
			clean = append(clean, t)
		}
	}
	if len(clean) == 0 {
		return nil, fmt.Errorf("no links provided")
	}

	cfg := &xrayConf.Config{
		LogConfig: &xrayConf.LogConfig{
			LogLevel:  xrayLogLevel,
			AccessLog: "",
			ErrorLog:  "",
			DNSLog:    false,
		},
	}
	res := &BuildResult{Config: cfg, VisionTags: map[string]bool{}}

	if len(clean) == 1 {
		ob, server, dialIP, err := outboundFromLink(clean[0], OutboundTag)
		if err != nil {
			return nil, err
		}
		cfg.OutboundConfigs = []xrayConf.OutboundDetourConfig{*ob}
		res.OutboundTags = []string{OutboundTag}
		res.Servers = []string{server}
		if dialIP != "" {
			res.DialIPv4s = []string{dialIP}
		}
		if linkHasVision(clean[0]) {
			res.VisionTags[OutboundTag] = true
		}
		res.RouteTarget = OutboundTag
		applyRouting(routing, cfg, OutboundTag, false)
		return res, nil
	}

	o, err := opts.normalized()
	if err != nil {
		return nil, err
	}

	for i, link := range clean {
		tag := fmt.Sprintf("%s%d", proxyTagPrefix, i)
		ob, server, dialIP, berr := outboundFromLink(link, tag)
		if berr != nil {
			return nil, fmt.Errorf("link %d: %w", i, berr)
		}
		cfg.OutboundConfigs = append(cfg.OutboundConfigs, *ob)
		res.OutboundTags = append(res.OutboundTags, tag)
		res.Servers = append(res.Servers, server)
		if dialIP != "" {
			res.DialIPv4s = append(res.DialIPv4s, dialIP)
		}
		if linkHasVision(link) {
			res.VisionTags[tag] = true
		}
	}

	cfg.RouterConfig = &xrayConf.RouterConfig{
		Balancers: []*xrayConf.BalancingRule{{
			Tag:         balancerTag,
			Selectors:   xrayConf.StringList{proxyTagPrefix},
			Strategy:    xrayConf.StrategyConfig{Type: o.Strategy},
			FallbackTag: res.OutboundTags[0],
		}},
	}
	// Mandatory: core.New rejects the config without it; also feeds leastping latency.
	cfg.Observatory = &xrayConf.ObservatoryConfig{
		SubjectSelector:   []string{proxyTagPrefix},
		ProbeURL:          o.ProbeURL,
		ProbeInterval:     duration.Duration(time.Duration(o.ProbeIntervalSec) * time.Second),
		EnableConcurrency: true,
	}
	res.RouteTarget = balancerTag
	res.RouteIsBalancer = true
	applyRouting(routing, cfg, balancerTag, true)
	return res, nil
}

// outboundFromLink also returns the server host and its pre-resolved IPv4 dial address.
func outboundFromLink(link, tag string) (*xrayConf.OutboundDetourConfig, string, string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, "", "", fmt.Errorf("parse link: %w", err)
	}

	switch strings.ToLower(u.Scheme) {
	case "vless":
		ob, server, dialIP := outboundFromVLESS(u, tag)
		if ob == nil {
			return nil, "", "", fmt.Errorf("unsupported or invalid vless link")
		}
		return ob, server, dialIP, nil
	case "ss":
		ob, server, dialIP, perr := outboundFromSS(u, tag)
		if perr != nil {
			return nil, "", "", perr
		}
		return ob, server, dialIP, nil
	case "trojan":
		ob, server, dialIP, perr := outboundFromTrojan(u, tag)
		if perr != nil {
			return nil, "", "", perr
		}
		return ob, server, dialIP, nil
	default:
		return nil, "", "", fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}
}

func outboundFromVLESS(u *url.URL, tag string) (*xrayConf.OutboundDetourConfig, string, string) {
	// vless://<uuid>@host:port?type=ws&security=tls&path=/xxx&host=example.com&sni=example.com&alpn=h2,http/1.1&fp=chrome
	userID := ""
	if u.User != nil {
		userID = u.User.Username()
	}
	host := u.Hostname()
	portStr := u.Port()
	port := uint16(0)
	if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
		port = uint16(p)
	}
	if userID == "" || host == "" || port == 0 {
		return nil, "", ""
	}

	q := u.Query()
	vlessUser := map[string]string{
		"id":         userID,
		"encryption": "none",
	}
	if flow := strings.TrimSpace(q.Get("flow")); flow != "" {
		vlessUser["flow"] = flow
	}
	userJSON, _ := json.Marshal(vlessUser)

	addrForDial := preResolveIPv4(host)
	vnext := &xrayConf.VLessOutboundVnext{
		Address: &xrayConf.Address{Address: xrayNet.ParseAddress(addrForDial)},
		Port:    port,
		Users:   []json.RawMessage{json.RawMessage(userJSON)},
	}
	vlessSettings := &xrayConf.VLessOutboundConfig{Vnext: []*xrayConf.VLessOutboundVnext{vnext}}
	settingsBytes, _ := json.Marshal(vlessSettings)
	settingsRaw := json.RawMessage(settingsBytes)

	ob := &xrayConf.OutboundDetourConfig{
		Protocol: "vless",
		Tag:      tag,
		Settings: &settingsRaw,
	}

	stream := buildStreamSettings(host, q)
	if stream.Security != "" || stream.Network != nil {
		ob.StreamSetting = stream
	}
	return ob, host, addrForDial
}

// buildStreamSettings maps the transport (type=) and security (security=) query
// params common to VLESS and Trojan links into an Xray StreamConfig.
func buildStreamSettings(host string, q url.Values) *xrayConf.StreamConfig {
	stream := &xrayConf.StreamConfig{}
	switch strings.ToLower(q.Get("type")) {
	case "tcp", "":
		proto := xrayConf.TransportProtocol("tcp")
		stream.Network = &proto
	case "ws", "websocket":
		proto := xrayConf.TransportProtocol("websocket")
		stream.Network = &proto
		ws := &xrayConf.WebSocketConfig{Path: q.Get("path")}
		if h := q.Get("host"); h != "" {
			ws.Host = h
		} else {
			ws.Host = host
		}
		// Don't force the Host header: some origins/nginx strip non-standard headers.
		stream.WSSettings = ws
	case "grpc":
		proto := xrayConf.TransportProtocol("grpc")
		stream.Network = &proto
		stream.GRPCSettings = &xrayConf.GRPCConfig{ServiceName: q.Get("serviceName")}
	case "httpupgrade":
		proto := xrayConf.TransportProtocol("httpupgrade")
		stream.Network = &proto
		stream.HTTPUPGRADESettings = &xrayConf.HttpUpgradeConfig{Path: q.Get("path"), Host: q.Get("host")}
	case "xhttp":
		proto := xrayConf.TransportProtocol("xhttp")
		stream.Network = &proto
		xhttp := &xrayConf.SplitHTTPConfig{
			Path: q.Get("path"),
			Mode: q.Get("mode"), // "packet-up", "stream-up", "auto"
		}
		if extra := q.Get("extra"); extra != "" {
			if decodedExtra, err := url.QueryUnescape(extra); err == nil {
				xhttp.Extra = json.RawMessage(decodedExtra)
			}
		}
		if h := q.Get("host"); h != "" {
			xhttp.Host = h
		} else {
			xhttp.Host = host
		}
		stream.XHTTPSettings = xhttp
	}

	switch strings.ToLower(q.Get("security")) {
	case "tls":
		stream.Security = "tls"
		tls := &xrayConf.TLSConfig{}
		sni := q.Get("sni")
		if sni != "" {
			tls.ServerName = sni
		}
		if tls.ServerName == "" {
			if stream.WSSettings != nil && stream.WSSettings.Host != "" {
				tls.ServerName = stream.WSSettings.Host
			} else if h := q.Get("host"); h != "" {
				tls.ServerName = h
			} else {
				tls.ServerName = host
			}
		}
		if alpn := q.Get("alpn"); alpn != "" {
			lst := xrayConf.StringList(strings.Split(alpn, ","))
			stream.TLSSettings = tls
			tls.ALPN = &lst
		} else {
			stream.TLSSettings = tls
		}
		if fp := q.Get("fp"); fp != "" {
			tls.Fingerprint = fp
		}
		if ai := q.Get("allowInsecure"); ai == "1" || strings.EqualFold(ai, "true") {
			tls.AllowInsecure = true
		}
		if tls.ServerName == "" {
			if h := q.Get("host"); h != "" {
				tls.ServerName = h
			}
		}
	case "reality":
		stream.Security = "reality"
		r := &xrayConf.REALITYConfig{}
		if sni := q.Get("sni"); sni != "" {
			r.ServerName = sni
		}
		if pbk := q.Get("pbk"); pbk != "" {
			r.PublicKey = pbk
		}
		if sid := q.Get("sid"); sid != "" {
			r.ShortId = sid
		}
		if spx := q.Get("spx"); spx != "" {
			r.SpiderX = spx
		}
		if fp := q.Get("fp"); fp != "" {
			r.Fingerprint = fp
		}
		stream.REALITYSettings = r
	}

	// TCP keepalive to prevent carrier NAT timeout on idle connections.
	stream.SocketSettings = &xrayConf.SocketConfig{
		TCPKeepAliveInterval: 15,
	}
	return stream
}

// preResolveIPv4 returns host's first IPv4 (short DNS timeout) for use as the
// dial address, leaving TLS SNI / WS Host as the original domain. Returns host
// unchanged if it is already an IP or resolution fails.
func preResolveIPv4(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host); err == nil && len(ips) > 0 {
		return ips[0].String()
	}
	return host
}

// outboundFromTrojan parses trojan://password@host:port?security=tls&sni=...
func outboundFromTrojan(u *url.URL, tag string) (*xrayConf.OutboundDetourConfig, string, string, error) {
	password := ""
	if u.User != nil {
		password = u.User.Username()
	}
	host := u.Hostname()
	port := uint16(0)
	if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 && p <= 65535 {
		port = uint16(p)
	}
	if password == "" || host == "" || port == 0 {
		return nil, "", "", fmt.Errorf("incomplete trojan link")
	}

	q := u.Query()
	addrForDial := preResolveIPv4(host)

	// Flow removed in xray-core for Trojan - leave unset.
	trojanSettings := &xrayConf.TrojanClientConfig{
		Servers: []*xrayConf.TrojanServerTarget{{
			Address:  &xrayConf.Address{Address: xrayNet.ParseAddress(addrForDial)},
			Port:     port,
			Password: password,
		}},
	}
	settingsBytes, _ := json.Marshal(trojanSettings)
	settingsRaw := json.RawMessage(settingsBytes)

	ob := &xrayConf.OutboundDetourConfig{
		Protocol: "trojan",
		Tag:      tag,
		Settings: &settingsRaw,
	}
	stream := buildStreamSettings(host, q)
	// Trojan without explicit security= still implies TLS in practice; default to it.
	if stream.Security == "" {
		stream.Security = "tls"
		tlsCfg := &xrayConf.TLSConfig{ServerName: host}
		if sni := q.Get("sni"); sni != "" {
			tlsCfg.ServerName = sni
		}
		stream.TLSSettings = tlsCfg
	}
	ob.StreamSetting = stream
	return ob, host, addrForDial, nil
}

func outboundFromSS(u *url.URL, tag string) (*xrayConf.OutboundDetourConfig, string, string, error) {
	// Supports both plain form ss://method:password@host:port and base64 ss://BASE64(method:password@host:port)
	method := ""
	password := ""
	host := ""
	port := uint16(0)

	if u.User != nil && u.Hostname() != "" && u.Port() != "" {
		method = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			password = pw
		}
		host = u.Hostname()
		if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 && p <= 65535 {
			port = uint16(p)
		}
	} else {
		raw := strings.TrimPrefix(u.String(), "ss://")
		raw = strings.SplitN(raw, "#", 2)[0]
		raw = strings.SplitN(raw, "?", 2)[0]
		decoded, derr := tryDecodeBase64(raw)
		if derr != nil {
			return nil, "", "", fmt.Errorf("invalid ss base64: %w", derr)
		}
		at := strings.LastIndex(decoded, "@")
		if at <= 0 {
			return nil, "", "", fmt.Errorf("invalid ss payload")
		}
		creds := decoded[:at]
		addr := decoded[at+1:]
		col := strings.Index(creds, ":")
		if col <= 0 {
			return nil, "", "", fmt.Errorf("invalid ss creds")
		}
		method = creds[:col]
		password = creds[col+1:]
		h, pstr, ok := strings.Cut(addr, ":")
		if !ok {
			return nil, "", "", fmt.Errorf("invalid ss addr")
		}
		host = h
		if p, err := strconv.Atoi(pstr); err == nil && p > 0 && p <= 65535 {
			port = uint16(p)
		}
	}

	if method == "" || password == "" || host == "" || port == 0 {
		return nil, "", "", fmt.Errorf("incomplete ss link")
	}

	server := &xrayConf.ShadowsocksServerTarget{
		Address:  &xrayConf.Address{Address: xrayNet.ParseAddress(host)},
		Port:     port,
		Cipher:   method,
		Password: password,
	}

	q := u.Query()
	if v := q.Get("uot"); v == "1" || strings.EqualFold(v, "true") {
		server.UoT = true
	}
	if v := q.Get("uotVersion"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			server.UoTVersion = n
		}
	}

	ssSettings := &xrayConf.ShadowsocksClientConfig{Servers: []*xrayConf.ShadowsocksServerTarget{server}}
	settingsBytes, _ := json.Marshal(ssSettings)
	settingsRaw := json.RawMessage(settingsBytes)

	ob := &xrayConf.OutboundDetourConfig{
		Protocol: "shadowsocks",
		Tag:      tag,
		Settings: &settingsRaw,
		StreamSetting: &xrayConf.StreamConfig{
			SocketSettings: &xrayConf.SocketConfig{
				TCPKeepAliveInterval: 15,
			},
		},
	}
	return ob, host, preResolveIPv4(host), nil
}

func tryDecodeBase64(s string) (string, error) {
	if decoded, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return string(decoded), nil
	}
	if decoded, err := base64.URLEncoding.DecodeString(padBase64(s)); err == nil {
		return string(decoded), nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(padBase64(s)); err == nil {
		return string(decoded), nil
	}
	return "", fmt.Errorf("unable to decode base64")
}

func padBase64(s string) string {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return s
}
