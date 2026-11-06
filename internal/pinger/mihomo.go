//go:build !no_mihomo

package pinger

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	mihomoAdapter "github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"

	"github.com/glitch-vpn/libglitchcore/internal/awgconfig"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/proxylink"
)

func openMihomoDialer(link string, _ bool) (dialFunc, func(), error) {
	pmap, err := mihomoconfig.ProxyMapFromLink(link)
	if err != nil {
		return nil, nil, fmt.Errorf("parse link: %w", err)
	}
	proxy, err := mihomoAdapter.ParseProxy(pmap)
	if err != nil {
		return nil, nil, fmt.Errorf("build proxy: %w", err)
	}

	dial := func(dialCtx context.Context, _, addr string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
		}
		// Host (not a pre-resolved IP): mihomo's proxy resolves it remotely.
		md := &C.Metadata{NetWork: C.TCP, Host: host, DstPort: uint16(port)}
		return proxy.DialContext(dialCtx, md)
	}
	return dial, func() { _ = proxy.Close() }, nil
}

func init() {
	setFallbackLinkEngine(linkEngine{
		engine: "mihomo",
		match: func(trimmed, lower string) bool {
			return strings.HasPrefix(lower, "vless://") ||
				strings.HasPrefix(lower, "vmess://") ||
				strings.HasPrefix(lower, "ss://") ||
				strings.HasPrefix(lower, "trojan://") ||
				strings.HasPrefix(lower, "hysteria2://") ||
				strings.HasPrefix(lower, "hy2://") ||
				strings.HasPrefix(lower, "tuic://") ||
				strings.HasPrefix(lower, "anytls://") ||
				proxylink.Protocol(trimmed) == proxylink.Socks ||
				awgconfig.IsLink(trimmed)
		},
		open: openMihomoDialer,
	})
}
