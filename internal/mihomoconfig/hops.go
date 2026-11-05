package mihomoconfig

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	D "github.com/miekg/dns"
)

// hopLookupTimeout bounds one name's lookup through the hops before it.
const hopLookupTimeout = 10 * time.Second

// udpProxyTypes dial their server over UDP, where mihomo looks the host up
// with its own resolver and so outside the hop before it.
var udpProxyTypes = []any{"hysteria2", "tuic", "wireguard"}

// DefaultHopResolver is the DNS server (TCP, port 53) a later hop's name is
// asked of, through the hop before it, when the caller names none.
const DefaultHopResolver = "1.1.1.1:53"

var errEchLookup = errors.New("a hop after the first cannot look up its ECH config, which would leave outside the hop before it; give the config list in the link")

// refuseEchLookup: ech=1 with no config list makes mihomo look the name up
// with its own resolver.
func refuseEchLookup(proxy map[string]any) error {
	if ech, ok := proxy["ech-opts"].(map[string]any); ok && ech["enable"] == true && ech["config"] == nil {
		return errEchLookup
	}
	return nil
}

// resolveLaterHop replaces the host names of a UDP-based hop after the first
// with addresses asked of resolver through via, the chain up to the hop before
// it, so the name never leaves outside the tunnel. A name TLS verifies stays as
// sni. A lookup that fails fails the hop. A TCP hop is left as it is: its name
// is handed to the hop before it, which resolves it.
func resolveLaterHop(proxy map[string]any, before []map[string]any, resolver string) error {
	if !slices.Contains(udpProxyTypes, proxy["type"]) || !namesAHost(proxy) {
		return nil
	}
	via, err := dialerThrough(before)
	if err != nil {
		return err
	}
	answers := map[string]string{}
	resolve := func(entry map[string]any) error {
		host, _ := entry["server"].(string)
		if host == "" {
			return nil
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return nil
		}
		if _, ok := answers[host]; !ok {
			ctx, cancel := context.WithTimeout(context.Background(), hopLookupTimeout)
			defer cancel()
			addr, err := lookupThrough(ctx, via, resolver, host)
			if err != nil {
				return fmt.Errorf("resolve the hop's host through the hop before it: %w", err)
			}
			answers[host] = addr.String()
		}
		entry["server"] = answers[host]
		if proxy["type"] != "wireguard" && proxy["sni"] == nil {
			proxy["sni"] = host
		}
		return nil
	}
	if err := resolve(proxy); err != nil {
		return err
	}
	if peers, ok := proxy["peers"].([]map[string]any); ok {
		for _, peer := range peers {
			if err := resolve(peer); err != nil {
				return err
			}
		}
	}
	return nil
}

// namesAHost: the hop, or one of its WireGuard peers, is given by name.
func namesAHost(proxy map[string]any) bool {
	isName := func(entry map[string]any) bool {
		host, _ := entry["server"].(string)
		_, err := netip.ParseAddr(host)
		return host != "" && err != nil
	}
	if isName(proxy) {
		return true
	}
	peers, _ := proxy["peers"].([]map[string]any)
	return slices.ContainsFunc(peers, isName)
}

// lookupThrough asks resolver for host's A record, then its AAAA, over TCP
// dialled through via.
func lookupThrough(ctx context.Context, via C.Dialer, resolver, host string) (netip.Addr, error) {
	var last error
	for _, qtype := range []uint16{D.TypeA, D.TypeAAAA} {
		addr, err := queryThrough(ctx, via, resolver, host, qtype)
		if err == nil {
			return addr, nil
		}
		last = err
	}
	return netip.Addr{}, last
}

func queryThrough(ctx context.Context, via C.Dialer, resolver, host string, qtype uint16) (netip.Addr, error) {
	conn, err := via.DialContext(ctx, "tcp", resolver)
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	co := &D.Conn{Conn: conn}
	query := new(D.Msg)
	query.SetQuestion(D.Fqdn(host), qtype)
	query.RecursionDesired = true
	if err := co.WriteMsg(query); err != nil {
		return netip.Addr{}, err
	}
	reply, err := co.ReadMsg()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, rr := range reply.Answer {
		switch rr := rr.(type) {
		case *D.A:
			if addr, ok := netip.AddrFromSlice(rr.A.To4()); ok {
				return addr, nil
			}
		case *D.AAAA:
			if addr, ok := netip.AddrFromSlice(rr.AAAA); ok {
				return addr, nil
			}
		}
	}
	return netip.Addr{}, errors.New("no address in the answer")
}

// dialerThrough is a dialer that leaves from the last of hops, each reached
// through the one before it. The maps are the hops as built, resolved ones
// included, with their dialer-proxy left out: the chain is wired here.
func dialerThrough(hops []map[string]any) (C.Dialer, error) {
	var via C.Dialer
	for _, hop := range hops {
		own := maps.Clone(hop)
		delete(own, "dialer-proxy")
		var options []adapter.ProxyOption
		if via != nil {
			options = append(options, adapter.WithDialerForAPI(via))
		}
		proxy, err := adapter.ParseProxy(own, options...)
		if err != nil {
			return nil, err
		}
		via = proxydialer.New(proxy, false)
	}
	return via, nil
}
