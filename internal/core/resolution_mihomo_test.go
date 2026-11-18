//go:build !no_mihomo

package core

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	mihomoDNS "github.com/metacubex/mihomo/dns"
	D "github.com/miekg/dns"
)

// slowAAAAServer answers an A query with no address and an AAAA query after
// aaaaDelay, with none if aaaaEmpty.
type slowAAAAServer struct {
	aaaaDelay time.Duration
	aaaaEmpty bool
}

func (h slowAAAAServer) ServeDNS(w D.ResponseWriter, q *D.Msg) {
	m := new(D.Msg)
	m.SetReply(q)
	if q.Question[0].Qtype == D.TypeAAAA {
		time.Sleep(h.aaaaDelay)
		if !h.aaaaEmpty {
			rr, _ := D.NewRR(q.Question[0].Name + " 300 IN AAAA 2001:db8::1")
			m.Answer = append(m.Answer, rr)
		}
	}
	m.Ns = append(m.Ns, &D.SOA{Hdr: D.RR_Header{Name: "test.", Rrtype: D.TypeSOA, Class: D.ClassINET, Ttl: 300}, Ns: "ns.test.", Mbox: "h.test.", Minttl: 300})
	_ = w.WriteMsg(m)
}

// The errors mihomo's own dialer gives for a name that resolved to nothing, as
// an echo meets them through its HTTP client, are resolution failures.
func TestIsResolutionFailure_RecognisesWhatMihomosDialerReturns(t *testing.T) {
	for _, c := range []struct {
		name string
		h    slowAAAAServer
	}{
		{"empty answers", slowAAAAServer{aaaaEmpty: true}},
		{"AAAA later than the resolver waits for it", slowAAAAServer{aaaaDelay: 300 * time.Millisecond}},
	} {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := &D.Server{PacketConn: pc, Handler: c.h}
		go func() { _ = server.ActivateAndServe() }()
		t.Cleanup(func() { _ = server.Shutdown() })
		resolver := mihomoDNS.NewResolver(mihomoDNS.Config{Main: []mihomoDNS.NameServer{{Net: "udp", Addr: pc.LocalAddr().String()}}})
		dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.NewDialer(dialer.WithResolver(resolver)).DialContext(ctx, "tcp", addr)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = fetchIPEcho(ctx, "https://api6.test", dial, true)
		cancel()
		if err == nil || !isResolutionFailure(err) {
			t.Errorf("%s: %v is not a resolution failure", c.name, err)
		}
	}
}
