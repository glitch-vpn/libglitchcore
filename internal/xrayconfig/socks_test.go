package xrayconfig

import (
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"testing"

	xrayConf "github.com/xtls/xray-core/infra/conf"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
)

func TestPickLocalSocksPort_TCPAndUDPBindable(t *testing.T) {
	port, err := pickLocalSocksPort()
	if err != nil {
		t.Fatalf("pickLocalSocksPort: %v", err)
	}
	addr := net.JoinHostPort(defaultProxyAddress, strconv.Itoa(int(port)))
	// The SOCKS inbound needs both; the picker must guarantee both are bindable.
	tcpL, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("picked port %d not TCP-bindable: %v", port, err)
	}
	defer tcpL.Close()
	udpC, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("picked port %d not UDP-bindable: %v", port, err)
	}
	defer udpC.Close()
}

func TestNewLocalSocksSessionUsesRandomAuthenticatedEndpoint(t *testing.T) {
	session, err := newLocalSocksSession()
	if err != nil {
		t.Fatalf("newLocalSocksSession() error = %v", err)
	}

	if session.Address != defaultProxyAddress {
		t.Fatalf("Address = %q, want %q", session.Address, defaultProxyAddress)
	}
	if session.Port == 0 {
		t.Fatal("Port is empty")
	}
	if session.Port == defaultProxyPort {
		t.Fatalf("Port = %d, must not use default exposed port", session.Port)
	}
	if session.Credentials.Username == "" {
		t.Fatal("Username is empty")
	}
	if session.Credentials.Password == "" {
		t.Fatal("Password is empty")
	}
}

func TestLocalSocksSessionSettingsRequirePasswordAuth(t *testing.T) {
	session := localSocksSession{
		Address: defaultProxyAddress,
		Port:    23456,
		Credentials: localSocksCredentials{
			Username: "user",
			Password: "pass",
		},
	}

	settings, err := session.settings()
	if err != nil {
		t.Fatalf("settings() error = %v", err)
	}

	var decoded struct {
		Auth     string `json:"auth"`
		Accounts []struct {
			Username string `json:"user"`
			Password string `json:"pass"`
		} `json:"accounts"`
		UDP bool   `json:"udp"`
		IP  string `json:"ip"`
	}
	if err := json.Unmarshal(*settings, &decoded); err != nil {
		t.Fatalf("settings JSON did not unmarshal: %v", err)
	}

	if decoded.Auth != "password" {
		t.Fatalf("Auth = %q, want password", decoded.Auth)
	}
	if len(decoded.Accounts) != 1 {
		t.Fatalf("len(Accounts) = %d, want 1", len(decoded.Accounts))
	}
	if decoded.Accounts[0].Username != "user" || decoded.Accounts[0].Password != "pass" {
		t.Fatalf("Accounts[0] = %#v, want user/pass", decoded.Accounts[0])
	}
	if !decoded.UDP {
		t.Fatal("UDP = false, want true")
	}
	if decoded.IP != defaultProxyAddress {
		t.Fatalf("IP = %q, want %q", decoded.IP, defaultProxyAddress)
	}
}

func TestLocalSocksSessionProxyURLCarriesCredentials(t *testing.T) {
	session := localSocksSession{
		Address: defaultProxyAddress,
		Port:    23456,
		Credentials: localSocksCredentials{
			Username: "user",
			Password: "pass",
		},
	}

	parsed, err := url.Parse(session.proxyURL())
	if err != nil {
		t.Fatalf("proxyURL() did not parse: %v", err)
	}

	if parsed.Scheme != "socks5" {
		t.Fatalf("Scheme = %q, want socks5", parsed.Scheme)
	}
	if parsed.Host != "127.0.0.1:23456" {
		t.Fatalf("Host = %q, want 127.0.0.1:23456", parsed.Host)
	}
	if parsed.User.Username() != "user" {
		t.Fatalf("Username = %q, want user", parsed.User.Username())
	}
	password, ok := parsed.User.Password()
	if !ok || password != "pass" {
		t.Fatalf("Password = %q, ok = %t; want pass/true", password, ok)
	}
}

func TestCapTun2socksLogLevelPreventsProxyURLLeak(t *testing.T) {
	for _, level := range []string{
		tun2socksLogInfoLevel,
		tun2socksLogDebugLevel,
		tun2socksLogTraceLevel,
	} {
		if got := CapTun2socksLogLevel(level); got != tun2socksLogWarnLevel {
			t.Fatalf("CapTun2socksLogLevel(%q) = %q, want %q", level, got, tun2socksLogWarnLevel)
		}
	}

	for _, level := range []string{
		tun2socksLogSilentLevel,
		tun2socksLogWarnLevel,
		tun2socksLogErrorLevel,
		tun2socksLogFatalLevel,
		tun2socksLogPanicLevel,
	} {
		if got := CapTun2socksLogLevel(level); got != level {
			t.Fatalf("CapTun2socksLogLevel(%q) = %q, want unchanged", level, got)
		}
	}
}

func TestApplyLocalSocksInboundReplacesExistingInbound(t *testing.T) {
	oldAddress := "0.0.0.0"
	oldSettings := json.RawMessage(`{"auth":"noauth","udp":true,"ip":"0.0.0.0"}`)
	cfg := &xrayConf.Config{
		InboundConfigs: []xrayConf.InboundDetourConfig{
			{
				Protocol: "http",
				PortList: &xrayConf.PortList{
					Range: []xrayConf.PortRange{{
						From: defaultProxyPort,
						To:   defaultProxyPort,
					}},
				},
				ListenOn: xrayConf.ParseSendThough(&oldAddress),
				Tag:      "tun2socks",
				Settings: &oldSettings,
			},
		},
	}

	session, proxyURL, err := ApplyLocalSocksInbound(cfg)
	if err != nil {
		t.Fatalf("ApplyLocalSocksInbound() error = %v", err)
	}

	if len(cfg.InboundConfigs) != 1 {
		t.Fatalf("len(InboundConfigs) = %d, want 1", len(cfg.InboundConfigs))
	}
	inbound := cfg.InboundConfigs[0]
	if inbound.Protocol != "socks" {
		t.Fatalf("Protocol = %q, want socks", inbound.Protocol)
	}
	if inbound.Tag != "tun2socks" {
		t.Fatalf("Tag = %q, want tun2socks", inbound.Tag)
	}
	if inbound.ListenOn == nil {
		t.Fatalf("ListenOn = nil, want %s", defaultProxyAddress)
	}
	listenAddress := inbound.ListenOn.Build().AsAddress()
	if listenAddress == nil ||
		!listenAddress.Family().IsIP() ||
		listenAddress.IP().String() != defaultProxyAddress {
		t.Fatalf("ListenOn = %#v, want %s", inbound.ListenOn, defaultProxyAddress)
	}
	if inbound.PortList == nil || len(inbound.PortList.Range) != 1 {
		t.Fatalf("PortList = %#v, want single port range", inbound.PortList)
	}
	if inbound.PortList.Range[0].From != session.Port || inbound.PortList.Range[0].To != session.Port {
		t.Fatalf("PortList.Range[0] = %#v, want session port %d", inbound.PortList.Range[0], session.Port)
	}
	if proxyURL != session.proxyURL() {
		t.Fatalf("proxyURL = %q, want %q", proxyURL, session.proxyURL())
	}

	var decoded struct {
		Auth string `json:"auth"`
	}
	if err := json.Unmarshal(*inbound.Settings, &decoded); err != nil {
		t.Fatalf("settings JSON did not unmarshal: %v", err)
	}
	if decoded.Auth != "password" {
		t.Fatalf("Auth = %q, want password", decoded.Auth)
	}
}

func TestApplyProxyInbound_Auth(t *testing.T) {
	openCfg := &xrayConf.Config{OutboundConfigs: []xrayConf.OutboundDetourConfig{{Protocol: "freedom", Tag: "proxy"}}}
	if _, err := ApplyProxyInbound(openCfg, 10810, "", ""); err != nil {
		t.Fatalf("ApplyProxyInbound(open): %v", err)
	}
	if got := inboundAuth(t, openCfg); got != "noauth" {
		t.Fatalf("no creds -> auth %q, want noauth", got)
	}
	if _, err := openCfg.Build(); err != nil {
		t.Fatalf("xray rejected open proxy inbound: %v", err)
	}

	authCfg := &xrayConf.Config{OutboundConfigs: []xrayConf.OutboundDetourConfig{{Protocol: "freedom", Tag: "proxy"}}}
	if _, err := ApplyProxyInbound(authCfg, 10811, "alice", `p"ass`); err != nil {
		t.Fatalf("ApplyProxyInbound(auth): %v", err)
	}
	var s struct {
		Auth     string `json:"auth"`
		Accounts []struct {
			User string `json:"user"`
			Pass string `json:"pass"`
		} `json:"accounts"`
	}
	idx := findInboundIdx(authCfg.InboundConfigs, "tun2socks")
	if err := json.Unmarshal(*authCfg.InboundConfigs[idx].Settings, &s); err != nil {
		t.Fatalf("settings unmarshal: %v", err)
	}
	if s.Auth != "password" || len(s.Accounts) != 1 || s.Accounts[0].User != "alice" || s.Accounts[0].Pass != `p"ass` {
		t.Fatalf("auth settings = %+v, want password alice/p\"ass (quote preserved)", s)
	}
	if _, err := authCfg.Build(); err != nil {
		t.Fatalf("xray rejected authed proxy inbound: %v", err)
	}
}

func inboundAuth(t *testing.T, cfg *xrayConf.Config) string {
	t.Helper()
	idx := findInboundIdx(cfg.InboundConfigs, "tun2socks")
	if idx < 0 {
		t.Fatal("tun2socks inbound not found")
	}
	var s struct {
		Auth string `json:"auth"`
	}
	if err := json.Unmarshal(*cfg.InboundConfigs[idx].Settings, &s); err != nil {
		t.Fatalf("settings unmarshal: %v", err)
	}
	return s.Auth
}

func TestApplySniffing(t *testing.T) {
	cfg := &xrayConf.Config{
		OutboundConfigs: []xrayConf.OutboundDetourConfig{{Protocol: "freedom", Tag: "proxy"}},
	}
	if _, _, err := ApplyLocalSocksInbound(cfg); err != nil {
		t.Fatalf("ApplyLocalSocksInbound: %v", err)
	}
	if _, err := ApplyForceProxyInbound(cfg); err != nil {
		t.Fatalf("ApplyForceProxyInbound: %v", err)
	}

	ApplySniffing(cfg, true)
	for _, in := range cfg.InboundConfigs {
		if got := len(*in.SniffingConfig.DestOverride); got != 4 {
			t.Fatalf("sniffing on: inbound %q destOverride = %v, want full set", in.Tag, *in.SniffingConfig.DestOverride)
		}
	}

	ApplySniffing(cfg, false)
	for _, in := range cfg.InboundConfigs {
		sc := in.SniffingConfig
		if sc == nil || !sc.Enabled || !sc.RouteOnly {
			t.Fatalf("sniffing off: inbound %q must keep Enabled+RouteOnly: %+v", in.Tag, sc)
		}
		if len(*sc.DestOverride) != 1 || (*sc.DestOverride)[0] != "fakedns" {
			t.Fatalf("sniffing off: inbound %q destOverride = %v, want [fakedns]", in.Tag, *sc.DestOverride)
		}
	}

	// The trimmed sniffer set must be valid to xray in fake-ip mode.
	res, err := BuildConfig([]string{dnsTestLink}, BalancerOptions{}, RoutingProfile{}, "warning")
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	full := res.Config
	ApplyDNS(full, dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}})
	if _, _, err := ApplyLocalSocksInbound(full); err != nil {
		t.Fatalf("ApplyLocalSocksInbound: %v", err)
	}
	ApplySniffing(full, false)
	if _, err := full.Build(); err != nil {
		t.Fatalf("cfg.Build() with fakedns-only sniffing failed: %v", err)
	}
}
