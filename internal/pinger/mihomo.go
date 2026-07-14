//go:build !no_mihomo

package pinger

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	mihomoAdapter "github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"

	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
)

func measureMihomo(ctx context.Context, link, probeURL string) (time.Duration, error) {
	pmap, err := mihomoconfig.ProxyMapFromLink(link)
	if err != nil {
		return 0, fmt.Errorf("parse link: %w", err)
	}
	proxy, err := mihomoAdapter.ParseProxy(pmap)
	if err != nil {
		return 0, fmt.Errorf("build proxy: %w", err)
	}
	defer proxy.Close()

	dial := func(dialCtx context.Context, _, addr string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid probe port %q: %w", portStr, err)
		}
		// Host (not a pre-resolved IP): mihomo's proxy resolves it remotely.
		md := &C.Metadata{NetWork: C.TCP, Host: host, DstPort: uint16(port)}
		return proxy.DialContext(dialCtx, md)
	}
	return probe(ctx, probeURL, dial)
}

func init() {
	setFallbackMeasurer(engineMeasurer{
		engine: "mihomo",
		match: func(trimmed, lower string) bool {
			return strings.HasPrefix(lower, "vless://") ||
				strings.HasPrefix(lower, "ss://") ||
				strings.HasPrefix(lower, "trojan://") ||
				strings.HasPrefix(lower, "hysteria2://") ||
				strings.HasPrefix(lower, "hy2://") ||
				strings.HasPrefix(lower, "awg://") ||
				strings.Contains(trimmed, "[Interface]")
		},
		measure: measureMihomo,
	})
}
