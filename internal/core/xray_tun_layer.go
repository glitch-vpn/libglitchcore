//go:build !no_xray

package core

import (
	"github.com/xtls/xray-core/common/session"
	xrayCore "github.com/xtls/xray-core/core"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// xrayTunParams is what a TUN layer needs to put the platform TUN in front of
// a started instance. The layer is chosen at build time: sing-tun in the main
// variant, the tun2socks bridge with the with_tun2socks tag.
type xrayTunParams struct {
	instance *xrayCore.Instance
	sniffing session.SniffingRequest
	routing  routing.Profile
	mark     int64
	// tunFd is the start's own copy of the platform's TUN fd; unused on Windows.
	tunFd int
	// serverHosts are the proxy servers' addresses or names, kept off the TUN
	// on Windows.
	serverHosts []string
	dnsServer   string
	logLevel    int
}
