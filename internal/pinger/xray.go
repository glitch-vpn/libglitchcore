//go:build !no_xray

package pinger

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	xrayAppLog "github.com/xtls/xray-core/app/log"
	xrayNet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	xrayCore "github.com/xtls/xray-core/core"

	"github.com/glitch-vpn/libglitchcore/internal/proxylink"
	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
	"github.com/glitch-vpn/libglitchcore/internal/xraydialer"
)

func init() {
	registerLinkEngine(linkEngine{
		engine: "xray",
		match: func(trimmed, lower string) bool {
			return strings.HasPrefix(lower, "vless://") ||
				strings.HasPrefix(lower, "vmess://") ||
				strings.HasPrefix(lower, "ss://") ||
				strings.HasPrefix(lower, "trojan://") ||
				proxylink.IsLink(trimmed)
		},
		open: openXrayDialer,
	})
}

// A link xray refuses for a capability it lacks (xrayconfig.NotCarriedError)
// is dialled on the fallback engine by the caller; one it refuses for safety is not. core.Dial dispatches through
// the proxy outbound, so the dial needs no SOCKS inbound or TUN.
//
// xray connects on the first byte written, so a server that cannot be reached
// shows as a closed connection, not as a failed dial.
func openXrayDialer(link string, resolveAtDial bool) (dialFunc, func(), error) {
	var res *xrayconfig.BuildResult
	var err error
	if resolveAtDial {
		res, err = xrayconfig.BuildConfigResolvingAtDial(link)
	} else {
		res, err = xrayconfig.BuildConfig(
			[]string{link},
			xrayconfig.BalancerOptions{},
			xrayconfig.RoutingProfile{},
			"none",
		)
	}
	if err != nil {
		var lacking xrayconfig.NotCarriedError
		if errors.As(err, &lacking) {
			return nil, nil, fallsBack{fmt.Errorf("build config: %w", err)}
		}
		return nil, nil, fmt.Errorf("build config: %w", err)
	}

	built, err := res.Config.Build()
	if err != nil {
		return nil, nil, fmt.Errorf("build core config: %w", err)
	}
	// An instance registers its log app's handler with xray's log package and
	// leaves it there after it closes, which would take the running session's
	// lines with it.
	logApp := string((&xrayAppLog.Config{}).ProtoReflect().Descriptor().FullName())
	built.App = slices.DeleteFunc(built.App, func(app *serial.TypedMessage) bool { return app.Type == logApp })
	inst, err := xraydialer.NewProbe(built)
	if err != nil {
		return nil, nil, fmt.Errorf("new instance: %w", err)
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		return nil, nil, fmt.Errorf("start instance: %w", err)
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
		dest := xrayNet.TCPDestination(xrayNet.ParseAddress(host), xrayNet.Port(port))
		return xrayCore.Dial(dialCtx, inst, dest)
	}
	return dial, func() { _ = inst.Close() }, nil
}
