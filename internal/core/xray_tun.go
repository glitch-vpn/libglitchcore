//go:build !no_xray && !with_tun2socks

package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"runtime"
	"time"

	tun "github.com/metacubex/sing-tun"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
)

// xrayTunName is the adapter's name on Windows.
const xrayTunName = "GlitchVPN"

// The TUN's own addresses, the pair mihomo's native TUN takes.
var (
	xrayTunPrefix4 = netip.MustParsePrefix("198.18.0.1/30")
	xrayTunPrefix6 = netip.MustParsePrefix("fdfe:dcba:9876::1/126")
)

// xrayTunSession is the TUN device and the stack in front of one xray session.
type xrayTunSession struct {
	device  tun.Tun // nil when the caller owns it (tests)
	stack   tun.Stack
	handler *xrayTunHandler
}

func (s *xrayTunSession) close() {
	_ = s.stack.Close()
	s.handler.closeUDPFlows()
	if s.device != nil {
		_ = s.device.Close()
	}
}

// startXrayTunStack runs sing-tun's gVisor stack over device, handing every
// flow to handler.
func startXrayTunStack(device tun.Tun, options tun.Options, handler *xrayTunHandler) (*xrayTunSession, error) {
	stack, err := tun.NewStack("gvisor", tun.StackOptions{
		Context:    context.Background(),
		Tun:        device,
		TunOptions: options,
		UDPTimeout: handler.udpTimeout,
		Handler:    handler,
	})
	if err != nil {
		return nil, err
	}
	if err := stack.Start(); err != nil {
		_ = stack.Close()
		return nil, err
	}
	return &xrayTunSession{stack: stack, handler: handler}, nil
}

// xrayTunOptions is what sing-tun gets for one session on goos. Windows has
// sing-tun create the adapter and its routes and DNS, and strict route keeps
// DNS and IPv6 from leaving by another interface; everywhere else the
// platform handed over an fd it has already routed.
//
// With auto route, the proxy servers and, when the profile keeps local
// networks direct, the private ranges are left out of the TUN's routes, so
// they take the physical adapter's default.
func xrayTunOptions(goos string, p xrayTunParams, servers []netip.Addr) (tun.Options, error) {
	mtu, _ := currentTun2SocksConfig()
	options := tun.Options{
		Name:         xrayTunName,
		MTU:          uint32(mtu),
		Inet4Address: []netip.Prefix{xrayTunPrefix4},
	}
	if goos != "windows" {
		if p.tunFd < 0 {
			return options, errors.New("no TUN fd")
		}
		options.FileDescriptor = p.tunFd
		return options, nil
	}
	options.AutoRoute = true
	options.StrictRoute = true
	if !p.routing.DisableIPv6 {
		options.Inet6Address = []netip.Prefix{xrayTunPrefix6}
	}
	// The adapter's DNS is the core's resolver, where xray's DNS rule meets
	// the query, in place of the TUN's own next address.
	options.DNSMode = tun.DNSModeHijack
	options.DNSServers = parseDNSListToAddrs(p.dnsServer)
	for _, server := range servers {
		options.Inet4RouteExcludeAddress = append(options.Inet4RouteExcludeAddress, netip.PrefixFrom(server, 32))
	}
	if p.routing.LocalNetworks {
		for _, cidr := range localNetworkBypass {
			options.Inet4RouteExcludeAddress = append(options.Inet4RouteExcludeAddress, netip.MustParsePrefix(cidr))
		}
	}
	return options, nil
}

// serverAddresses resolves the proxy servers to IPv4 through the system
// resolver, which runs before the TUN's routes exist and so does not depend
// on them. A server that does not resolve stays out; the connection to it
// would then loop into the TUN, which the log line says.
func serverAddresses(hosts []string, lookup func(ctx context.Context, host string) ([]net.IP, error)) []netip.Addr {
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, host := range hosts {
		if host == "" {
			continue
		}
		var found []netip.Addr
		if ip, err := netip.ParseAddr(host); err == nil {
			found = append(found, ip)
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			ips, err := lookup(ctx, host)
			cancel()
			if err != nil || len(ips) == 0 {
				log.Printf("[tun] server %q did not resolve: %v", host, err)
				continue
			}
			for _, ip := range ips {
				if addr, ok := netip.AddrFromSlice(ip); ok {
					found = append(found, addr.Unmap())
				}
			}
		}
		for _, addr := range found {
			if addr.Is4() && !seen[addr] {
				seen[addr] = true
				out = append(out, addr)
			}
		}
	}
	return out
}

func lookupIPv4(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip4", host)
}

// startXrayTunLayer opens the platform TUN through sing-tun and runs the
// gVisor stack on it, handing every flow to the instance.
func (x *CoreController) startXrayTunLayer(p xrayTunParams) error {
	handler, err := x.newXrayTunHandler(p)
	if err != nil {
		return err
	}
	var servers []netip.Addr
	if runtime.GOOS == "windows" {
		servers = serverAddresses(p.serverHosts, lookupIPv4)
	}
	options, err := xrayTunOptions(runtime.GOOS, p, servers)
	if err != nil {
		return err
	}
	device, err := tun.New(options)
	if err != nil {
		return fmt.Errorf("open tun: %w", err)
	}
	session, err := startXrayTunStack(device, options, handler)
	if err != nil {
		_ = device.Close()
		return fmt.Errorf("start tun stack: %w", err)
	}
	session.device = device
	x.xrayTun = session
	log.Println("[tun] sing-tun stack started")
	return nil
}

func (x *CoreController) stopXrayTunLayer() {
	session := x.xrayTun
	if session == nil {
		return
	}
	x.xrayTun = nil
	done := make(chan struct{})
	go func() {
		session.close()
		close(done)
	}()
	select {
	case <-done:
		log.Println("[tun] sing-tun stack stopped")
	case <-time.After(5 * time.Second):
		log.Println("[tun] sing-tun stack stop timed out after 5s")
	}
}

// newXrayTunHandler builds the inbounds a session's flows enter by.
func (x *CoreController) newXrayTunHandler(p xrayTunParams) (*xrayTunHandler, error) {
	_, udpTimeoutSec := currentTun2SocksConfig()
	h := &xrayTunHandler{x: x, mark: p.mark, udpTimeout: time.Duration(udpTimeoutSec) * time.Second}
	var err error
	newInbound := func(tag string) (*xrayInbound, error) { return newXrayInbound(p.instance, tag, p.sniffing) }
	if h.app, err = newInbound(xrayconfig.AppTrafficTag); err != nil {
		return nil, err
	}
	if routingHasForceProxy(p.routing) {
		if h.forceProxy, err = newInbound(xrayconfig.ForceProxyTag); err != nil {
			return nil, err
		}
	}
	if routingHasForceDirect(p.routing) {
		if h.forceDirect, err = newInbound(xrayconfig.ForceDirectTag); err != nil {
			return nil, err
		}
	}
	// Android routes per app in VpnService instead.
	if runtime.GOOS != "android" {
		h.split.rules = routing.ProcessRules(p.routing)
	}
	return h, nil
}
