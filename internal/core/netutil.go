package core

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// process:->proxy rules need a mode-independent always-tunnel inbound; lives
// here (not with xray) because the mihomo bridge checks it too.
func routingHasForceProxy(prof routing.Profile) bool {
	for _, t := range routing.ProcessRules(prof) {
		if t == routing.TargetProxy {
			return true
		}
	}
	return false
}

// plainDNSServers returns the schemeless (UDP) resolvers - the only form usable
// to bootstrap mihomo's system resolver.
func plainDNSServers(dns dnsconfig.Config) []string {
	var out []string
	for _, s := range dns.Servers {
		if s = strings.TrimSpace(s); s != "" && dnsconfig.Scheme(s) == "" {
			out = append(out, s)
		}
	}
	return out
}

func splitLinks(raw string) []string {
	return strings.Split(raw, "\n")
}

// splitEngineLinks splits one-per-line, except a raw INI AmneziaWG config
// ("[Interface]") is a single unit (its lines aren't links). awg:// links split
// per line, which enables awg multilink.
func splitEngineLinks(raw string) []string {
	if strings.Contains(raw, "[Interface]") {
		return []string{strings.TrimSpace(raw)}
	}
	var out []string
	for _, l := range splitLinks(raw) {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// pickLoopbackPort finds a 127.0.0.1 port bindable on both TCP and UDP - a mixed
// inbound needs both, and Windows WinNAT reserves ephemeral UDP ranges.
func pickLoopbackPort() (int, error) {
	for i := 0; i < 128; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		port := l.Addr().(*net.TCPAddr).Port
		uc, uerr := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		_ = l.Close()
		if uerr != nil {
			continue
		}
		_ = uc.Close()
		return port, nil
	}
	return 0, fmt.Errorf("no bindable loopback port")
}
