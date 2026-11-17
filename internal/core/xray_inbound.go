//go:build !no_xray

package core

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common"
	xrayCtx "github.com/xtls/xray-core/common/ctx"
	xrayLog "github.com/xtls/xray-core/common/log"
	xrayNet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	xrayCore "github.com/xtls/xray-core/core"
	xrayRouting "github.com/xtls/xray-core/features/routing"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
	"github.com/glitch-vpn/libglitchcore/internal/procname"
)

// Both TUN layers hand a flow to the instance through an xrayInbound, so
// the tag, the sniffing and the access record are the same in either.

// A direct flow with no force-direct inbound is refused rather than sent
// through the engine's tiers, where a proxy rule could tunnel it.
var errNoForceDirect = errors.New("process split: no force-direct inbound")

// A refused flow's error reaches the log, so it does not name the destination.
var errProcessBlocked = errors.New("process split: blocked")

type xrayInstanceContext struct{}

func init() {
	common.Must(common.RegisterConfig((*xrayInstanceContext)(nil), func(ctx context.Context, _ interface{}) (interface{}, error) {
		return ctx, nil
	}))
}

// xrayInbound hands a flow to xray in process, as the inbound tagged tag would.
type xrayInbound struct {
	ctx        context.Context
	dispatcher xrayRouting.Dispatcher
	tag        string
	sniffing   session.SniffingRequest
}

func newXrayInbound(inst *xrayCore.Instance, tag string, sniffing session.SniffingRequest) (*xrayInbound, error) {
	// The instance's own context, which xray's inbounds derive a connection's
	// from: per-connection code such as the fake-DNS sniffer reads the
	// instance out of it.
	instCtx, err := xrayCore.CreateObject(inst, (*xrayInstanceContext)(nil))
	if err != nil {
		return nil, err
	}
	dispatcher, ok := inst.GetFeature(xrayRouting.DispatcherType()).(xrayRouting.Dispatcher)
	if !ok {
		return nil, fmt.Errorf("xray has no dispatcher")
	}
	return &xrayInbound{ctx: instCtx.(context.Context), dispatcher: dispatcher, tag: tag, sniffing: sniffing}, nil
}

// flowContext is the context xray's inbound worker would give the flow from
// src to dest. xray ends the flow when it is cancelled, so it outlives the
// dial and only the caller's cancel ends it.
func (in *xrayInbound) flowContext(src, dest xrayNet.Destination) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(in.ctx)
	ctx = xrayCtx.ContextWithID(ctx, session.NewID())
	// CanSpliceCopy 3: no raw socket backs the flow, so xray must copy.
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Source: src, Tag: in.tag, CanSpliceCopy: 3})
	ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: in.sniffing})
	outbound := &session.Outbound{}
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})
	ctx = xrayLog.ContextWithAccessMessage(ctx, &xrayLog.AccessMessage{From: src, To: sniffedTarget{dest: dest, outbound: outbound}, Status: xrayLog.AccessAccepted})
	return ctx, cancel
}

func xrayAddrDestination(network xrayNet.Network, addr netip.AddrPort) xrayNet.Destination {
	return xrayNet.Destination{Network: network, Address: xrayNet.IPAddress(addr.Addr().AsSlice()), Port: xrayNet.Port(addr.Port())}
}

// xraySender is the address a reply came from, or invalid when xray names it
// by domain (fake-ip) or not at all.
func xraySender(from *xrayNet.Destination) netip.AddrPort {
	if from == nil || !from.Address.Family().IsIP() {
		return netip.AddrPort{}
	}
	ip, ok := netip.AddrFromSlice(from.Address.IP())
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(from.Port))
}

// sniffedTarget is the access message's destination: the address the flow
// came in on until xray's sniffer finds a domain in it. A fake-IP result
// replaces the destination itself; route-only sniffing keeps the dialed
// address and records the domain apart. The message reads both when it is
// written, after the route is picked.
type sniffedTarget struct {
	dest     xrayNet.Destination
	outbound *session.Outbound
}

func (t sniffedTarget) String() string {
	dest := t.dest
	for _, found := range []xrayNet.Destination{t.outbound.Target, t.outbound.RouteTarget} {
		if found.IsValid() && found.Address.Family().IsDomain() {
			dest.Address = found.Address
			break
		}
	}
	return dest.String()
}

// processSplit names the target the process rules give a flow, by the
// executable behind its source port.
type processSplit struct {
	rules map[string]string
	// processName is the executable behind a flow; the host's lookup by source
	// port when nil.
	processName func(network string, src netip.AddrPort) (string, error)
	logged      sync.Map
}

// target is the rule's target for the flow from src, or "" when no rule names
// its process or the process is not found.
func (p *processSplit) target(network string, src netip.AddrPort) string {
	if len(p.rules) == 0 {
		return ""
	}
	lookup := p.processName
	if lookup == nil {
		lookup = func(network string, src netip.AddrPort) (string, error) {
			return procname.FindProcessName(network, src.Addr(), int(src.Port()))
		}
	}
	name, err := lookup(network, src)
	if err != nil || name == "" {
		if _, seen := p.logged.LoadOrStore("ERR", true); !seen {
			logfmt.Warnf("[process-split] lookup of %s %s failed: %v - per-process won't match", network, src, err)
		}
		return ""
	}
	exe := strings.ToLower(filepath.Base(name))
	target := p.rules[exe]
	if _, seen := p.logged.LoadOrStore(exe+"|"+target, true); !seen {
		logfmt.Debugf("[process-split] saw %s -> rule=%q", exe, target)
	}
	return target
}
