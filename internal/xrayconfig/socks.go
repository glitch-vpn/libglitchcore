package xrayconfig

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"

	xrayConf "github.com/xtls/xray-core/infra/conf"

	"github.com/glitch-vpn/libglitchcore/internal/loopbackauth"
)

const (
	defaultProxyAddress = "127.0.0.1"
	// defaultProxyPort is the legacy exposed port; the bridge avoids reusing it.
	defaultProxyPort = uint32(10808)

	// On Windows, Hyper-V/WinNAT reserves large ephemeral UDP ranges (bind ->
	// WSAEACCES); a low retry count can exhaust before finding a bindable port.
	localSocksPortPickAttempts = 128
)

type localSocksSession struct {
	Address     string
	Port        uint32
	Credentials loopbackauth.Credentials
}

func newLocalSocksSession() (localSocksSession, error) {
	port, err := pickLocalSocksPort()
	if err != nil {
		return localSocksSession{}, err
	}

	return localSocksSession{
		Address:     defaultProxyAddress,
		Port:        port,
		Credentials: loopbackauth.New(),
	}, nil
}

func pickLocalSocksPort() (uint32, error) {
	for attempt := 0; attempt < localSocksPortPickAttempts; attempt++ {
		listener, err := net.Listen("tcp", net.JoinHostPort(defaultProxyAddress, "0"))
		if err != nil {
			continue
		}
		tcpAddr, ok := listener.Addr().(*net.TCPAddr)
		if !ok {
			_ = listener.Close()
			return 0, fmt.Errorf("unexpected local socks listener address type %T", listener.Addr())
		}
		port := tcpAddr.Port

		udpConn, udpErr := net.ListenPacket("udp", net.JoinHostPort(defaultProxyAddress, strconv.Itoa(port)))
		_ = listener.Close()
		if udpErr != nil {
			continue
		}
		_ = udpConn.Close()

		if port <= 0 || port > 65535 || uint32(port) == defaultProxyPort {
			continue
		}
		return uint32(port), nil
	}

	return 0, fmt.Errorf("unable to reserve a TCP+UDP-bindable local socks port")
}

func (s localSocksSession) Endpoint() string {
	return net.JoinHostPort(s.Address, fmt.Sprintf("%d", s.Port))
}

func (s localSocksSession) proxyURL() string {
	u := url.URL{
		Scheme: "socks5",
		User: url.UserPassword(
			s.Credentials.User,
			s.Credentials.Pass,
		),
		Host: s.Endpoint(),
	}
	return u.String()
}

func (s localSocksSession) settings() (*json.RawMessage, error) {
	type socksAccount struct {
		Username string `json:"user"`
		Password string `json:"pass"`
	}
	type socksSettings struct {
		Auth     string         `json:"auth"`
		Accounts []socksAccount `json:"accounts"`
		UDP      bool           `json:"udp"`
		IP       string         `json:"ip"`
	}

	raw, err := json.Marshal(socksSettings{
		Auth: "password",
		Accounts: []socksAccount{
			{
				Username: s.Credentials.User,
				Password: s.Credentials.Pass,
			},
		},
		UDP: true,
		IP:  s.Address,
	})
	if err != nil {
		return nil, err
	}

	msg := json.RawMessage(raw)
	return &msg, nil
}

// Sniffing recovers the domain for connections arriving as IP literals or fake
// IPs so domain rules match them - without it a host's v4 and v6 flows can
// route differently ("IPv4 direct, IPv6 leaked"). routeOnly: the domain drives
// routing only, not the dial. "fakedns" is inert when fake-ip is off (xray
// swallows the sniffer-init error), so it is safe unconditionally.
func sniffingConfig() *xrayConf.SniffingConfig {
	dest := xrayConf.StringList{"fakedns", "http", "tls", "quic"}
	return &xrayConf.SniffingConfig{
		Enabled:      true,
		DestOverride: &dest,
		RouteOnly:    true,
	}
}

// ApplySniffing (call after the last Apply*Inbound) trims destOverride to just
// "fakedns" when contentSniffing=false: the fake-IP->domain mapping lives inside
// xray's sniffing framework, so switching sniffing fully off would kill fake-ip
// mode.
func ApplySniffing(cfg *xrayConf.Config, contentSniffing bool) {
	if contentSniffing {
		return // Apply*Inbound already installed the full sniffer set
	}
	dest := xrayConf.StringList{"fakedns"}
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

func findInboundIdx(inbounds []xrayConf.InboundDetourConfig, tag string) int {
	for i, inbound := range inbounds {
		if inbound.Tag == tag {
			return i
		}
	}
	return -1
}

// forceProxyTag is the inbound the per-process dialer sends process->proxy flows
// to; applyRouting gives it a rule that always tunnels (mode-independent), so
// "route only this app through the VPN" works even in direct-all mode.
const forceProxyTag = "forceproxy"

// ApplyForceProxyInbound adds a loopback SOCKS inbound tagged "forceproxy",
// gated by per-session credentials, and returns its socks5:// URL (credentials
// included) for the tun2socks dialer.
func ApplyForceProxyInbound(cfg *xrayConf.Config) (string, error) {
	session, err := newLocalSocksSession()
	if err != nil {
		return "", fmt.Errorf("force-proxy inbound: %w", err)
	}
	settings, err := session.settings()
	if err != nil {
		return "", fmt.Errorf("force-proxy inbound settings: %w", err)
	}
	inbound := xrayConf.InboundDetourConfig{
		Protocol:       "socks",
		PortList:       &xrayConf.PortList{Range: []xrayConf.PortRange{{From: session.Port, To: session.Port}}},
		ListenOn:       xrayConf.ParseSendThough(&session.Address),
		Tag:            forceProxyTag,
		Settings:       settings,
		SniffingConfig: sniffingConfig(),
	}
	if idx := findInboundIdx(cfg.InboundConfigs, forceProxyTag); idx == -1 {
		cfg.InboundConfigs = append(cfg.InboundConfigs, inbound)
	} else {
		cfg.InboundConfigs[idx] = inbound
	}
	return session.proxyURL(), nil
}

// Marshaled (not fmt'd) so credentials containing quotes can't break the JSON.
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
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	raw := json.RawMessage(b)
	return &raw, nil
}

// ApplyProxyInbound injects a SOCKS5 inbound on 127.0.0.1:port, tagged
// "tun2socks" so the routing rules apply. Proxy mode: expose a local SOCKS
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
		Tag:            "tun2socks",
		Settings:       settings,
		SniffingConfig: sniffingConfig(),
	}
	if idx := findInboundIdx(cfg.InboundConfigs, "tun2socks"); idx == -1 {
		cfg.InboundConfigs = append(cfg.InboundConfigs, inbound)
	} else {
		cfg.InboundConfigs[idx] = inbound
	}
	return net.JoinHostPort(addr, strconv.Itoa(port)), nil
}

func ApplyLocalSocksInbound(cfg *xrayConf.Config) (localSocksSession, string, error) {
	socksSession, err := newLocalSocksSession()
	if err != nil {
		return localSocksSession{}, "", fmt.Errorf("prepare local SOCKS bridge: %w", err)
	}

	socksSettings, err := socksSession.settings()
	if err != nil {
		return localSocksSession{}, "", fmt.Errorf("build local SOCKS settings: %w", err)
	}

	socksInbound := xrayConf.InboundDetourConfig{
		Protocol: "socks",
		PortList: &xrayConf.PortList{
			Range: []xrayConf.PortRange{{
				From: socksSession.Port,
				To:   socksSession.Port,
			}},
		},
		ListenOn:       xrayConf.ParseSendThough(&socksSession.Address),
		Tag:            "tun2socks",
		Settings:       socksSettings,
		SniffingConfig: sniffingConfig(),
	}

	socksInx := findInboundIdx(cfg.InboundConfigs, "tun2socks")
	if socksInx == -1 {
		cfg.InboundConfigs = append(cfg.InboundConfigs, socksInbound)
	} else {
		cfg.InboundConfigs[socksInx] = socksInbound
	}

	return socksSession, socksSession.proxyURL(), nil
}
