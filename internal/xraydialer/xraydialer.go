//go:build !no_xray

// Package xraydialer keeps xray's system dialer on the running session's
// instance. The dialer, the DNS client it resolves through and the outbound
// manager it hands a dialer proxy to are process globals, which every xray
// instance overwrites with its own when it is built and leaves behind when it
// closes; a session's direct outbounds resolve names through them.
package xraydialer

import (
	"context"
	"sync"

	xrayCore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport/internet"
)

var (
	mu      sync.Mutex
	session *xrayCore.Instance
)

// NewSession builds the session's instance, which keeps the system dialer
// until EndSession.
func NewSession(ctx context.Context, cfg *xrayCore.Config) (*xrayCore.Instance, error) {
	mu.Lock()
	defer mu.Unlock()
	inst, err := xrayCore.NewWithContext(ctx, cfg)
	if err == nil {
		session = inst
	}
	return inst, err
}

// EndSession is called before the session's instance closes.
func EndSession(inst *xrayCore.Instance) {
	mu.Lock()
	defer mu.Unlock()
	if session == inst {
		session = nil
	}
}

// NewProbe builds an instance whose outbounds resolve nothing through the
// system dialer and use no dialer proxy, as a ping's do, and gives the dialer
// back to the running session.
func NewProbe(cfg *xrayCore.Config) (*xrayCore.Instance, error) {
	mu.Lock()
	defer mu.Unlock()
	inst, err := xrayCore.New(cfg)
	if session != nil {
		client, _ := session.GetFeature(dns.ClientType()).(dns.Client)
		manager, _ := session.GetFeature(outbound.ManagerType()).(outbound.Manager)
		internet.InitSystemDialer(client, manager)
	}
	return inst, err
}

// Release lets go of the last instance's DNS client and outbound manager, and
// with them every list its outbounds hold, while no session runs.
func Release() {
	mu.Lock()
	defer mu.Unlock()
	if session == nil {
		internet.InitSystemDialer(nil, nil)
	}
}
