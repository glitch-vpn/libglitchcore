package xrayconfig

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/xtls/xray-core/common/session"
	xrayConf "github.com/xtls/xray-core/infra/conf"
)

const (
	defaultProxyAddress = "127.0.0.1"

	// AppTrafficTag is the inbound app traffic arrives as: the TUN path dials
	// in process under it, proxy mode listens under it, and the routing rules
	// key on it.
	AppTrafficTag = "tun2socks"

	// ForceProxyTag is what the per-process dialer sends process->proxy flows
	// as; applyRouting gives it a rule that always tunnels (mode-independent),
	// so "route only this app through the VPN" works even in direct-all mode.
	ForceProxyTag = "forceproxy"
)

// Sniffing recovers the domain for connections arriving as IP literals or fake
// IPs so domain rules match them - without it a host's v4 and v6 flows can
// route differently ("IPv4 direct, IPv6 leaked"). routeOnly: the domain drives
// routing only, not the dial. "fakedns" is inert when fake-ip is off (xray
// swallows the sniffer-init error), so it is safe unconditionally. Without
// content sniffing only "fakedns" stays: the fake-IP->domain mapping lives
// inside xray's sniffing framework, so switching sniffing fully off would kill
// fake-ip mode.
func sniffedProtocols(contentSniffing bool) xrayConf.StringList {
	if !contentSniffing {
		return xrayConf.StringList{"fakedns"}
	}
	return xrayConf.StringList{"fakedns", "http", "tls", "quic"}
}

func sniffingConfig() *xrayConf.SniffingConfig {
	dest := sniffedProtocols(true)
	return &xrayConf.SniffingConfig{
		Enabled:      true,
		DestOverride: &dest,
		RouteOnly:    true,
	}
}

// ApplySniffing (call after ApplyProxyInbound) trims destOverride to just
// "fakedns" when contentSniffing=false.
func ApplySniffing(cfg *xrayConf.Config, contentSniffing bool) {
	if contentSniffing {
		return // ApplyProxyInbound already installed the full sniffer set
	}
	dest := sniffedProtocols(false)
	for i := range cfg.InboundConfigs {
		if cfg.InboundConfigs[i].SniffingConfig == nil {
			continue
		}
		cfg.InboundConfigs[i].SniffingConfig = &xrayConf.SniffingConfig{
			Enabled:      true,
			DestOverride: &dest,
			RouteOnly:    true,
		}
	}
}

// AppSniffing is the sniffing an in-process dial of app traffic carries: the
// set ApplySniffing leaves on an inbound.
func AppSniffing(contentSniffing bool) session.SniffingRequest {
	return session.SniffingRequest{
		Enabled:                        true,
		OverrideDestinationForProtocol: sniffedProtocols(contentSniffing),
		RouteOnly:                      true,
	}
}

func findInboundIdx(inbounds []xrayConf.InboundDetourConfig, tag string) int {
	for i, inbound := range inbounds {
		if inbound.Tag == tag {
			return i
		}
	}
	return -1
}

// Marshaled (not fmt'd) so credentials containing quotes can't break the JSON.
// With credentials UDP is off: xray admits SOCKS5 UDP by source address once
// any client has associated, so the credentials could not cover it.
func proxyInboundSettings(addr, user, pass string) (*json.RawMessage, error) {
	type account struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	s := struct {
		Auth     string    `json:"auth"`
		Accounts []account `json:"accounts,omitempty"`
		UDP      bool      `json:"udp"`
		IP       string    `json:"ip"`
	}{Auth: "noauth", UDP: true, IP: addr}
	if user != "" && pass != "" {
		s.Auth = "password"
		s.Accounts = []account{{User: user, Pass: pass}}
		s.UDP = false
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	raw := json.RawMessage(b)
	return &raw, nil
}

// ApplyProxyInbound injects a SOCKS5 inbound on 127.0.0.1:port, tagged
// AppTrafficTag so the routing rules apply. Proxy mode: expose a local SOCKS
// proxy instead of bridging a TUN - no tun2socks, no admin. Returns the listen
// endpoint.
func ApplyProxyInbound(cfg *xrayConf.Config, port int, user, pass string) (string, error) {
	if port <= 0 || port > 65535 {
		return "", fmt.Errorf("invalid proxy port %d", port)
	}
	addr := defaultProxyAddress
	settings, err := proxyInboundSettings(addr, user, pass)
	if err != nil {
		return "", fmt.Errorf("proxy inbound settings: %w", err)
	}
	inbound := xrayConf.InboundDetourConfig{
		Protocol:       "socks",
		PortList:       &xrayConf.PortList{Range: []xrayConf.PortRange{{From: uint32(port), To: uint32(port)}}},
		ListenOn:       xrayConf.ParseSendThough(&addr),
		Tag:            AppTrafficTag,
		Settings:       settings,
		SniffingConfig: sniffingConfig(),
	}
	if idx := findInboundIdx(cfg.InboundConfigs, AppTrafficTag); idx == -1 {
		cfg.InboundConfigs = append(cfg.InboundConfigs, inbound)
	} else {
		cfg.InboundConfigs[idx] = inbound
	}
	return net.JoinHostPort(addr, strconv.Itoa(port)), nil
}
