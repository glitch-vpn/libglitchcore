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
	"time"

	xrayAppLog "github.com/xtls/xray-core/app/log"
	xrayNet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	xrayCore "github.com/xtls/xray-core/core"

	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
)

func init() {
	registerMeasurer(engineMeasurer{
		engine: "xray",
		match: func(_, lower string) bool {
			return strings.HasPrefix(lower, "vless://") ||
				strings.HasPrefix(lower, "vmess://") ||
				strings.HasPrefix(lower, "ss://") ||
				strings.HasPrefix(lower, "trojan://")
		},
		measure: measureXray,
	})
}

// A link xray refuses for a capability it lacks (xrayconfig.NotCarriedError)
// is pinged on the fallback engine by the caller; one it refuses for safety is not. core.Dial dispatches through
// the proxy outbound, so the probe needs no SOCKS inbound or TUN.
func measureXray(ctx context.Context, link, probeURL string) (time.Duration, error) {
	res, err := xrayconfig.BuildConfig(
		[]string{link},
		xrayconfig.BalancerOptions{},
		xrayconfig.RoutingProfile{},
		"none",
	)
	if err != nil {
		var lacking xrayconfig.NotCarriedError
		if errors.As(err, &lacking) {
			return 0, fallsBack{fmt.Errorf("build config: %w", err)}
		}
		return 0, fmt.Errorf("build config: %w", err)
	}

	built, err := res.Config.Build()
	if err != nil {
		return 0, fmt.Errorf("build core config: %w", err)
	}
	// An instance registers its log app's handler with xray's log package and
	// leaves it there after it closes, which would take the running session's
	// lines with it.
	logApp := string((&xrayAppLog.Config{}).ProtoReflect().Descriptor().FullName())
	built.App = slices.DeleteFunc(built.App, func(app *serial.TypedMessage) bool { return app.Type == logApp })
	inst, err := xrayCore.New(built)
	if err != nil {
		return 0, fmt.Errorf("new instance: %w", err)
	}
	if err := inst.Start(); err != nil {
		return 0, fmt.Errorf("start instance: %w", err)
	}
	defer inst.Close()

	dial := func(dialCtx context.Context, _, addr string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid probe port %q: %w", portStr, err)
		}
		dest := xrayNet.TCPDestination(xrayNet.ParseAddress(host), xrayNet.Port(port))
		return xrayCore.Dial(dialCtx, inst, dest)
	}

	return probe(ctx, probeURL, dial)
}
