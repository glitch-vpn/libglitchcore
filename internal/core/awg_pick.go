//go:build !no_awg

package core

import (
	"errors"
	"fmt"

	"github.com/glitch-vpn/libglitchcore/internal/awgconfig"
)

// AwgPick names the link an awg start will use and what a caller needs to
// build the tunnel for it before the engine starts. The link stays here: it
// carries the private key, and the caller already holds the pool.
type AwgPick struct {
	Index          int      `json:"index"`
	Addresses      []string `json:"addresses"`
	PeersCarryIPv6 bool     `json:"peersCarryV6"`
}

// PickAwg runs the pool pick that HandleAwgStart would run and reads the
// chosen link's own tunnel addresses. A pool whose probes all fail yields its
// first link the engine accepts, as a start does; a link with no Interface
// address is an error rather than a guess.
func PickAwg(req EngineStartRequest) (AwgPick, error) {
	o, err := optsFromRequest(req, "awg")
	if err != nil {
		return AwgPick{}, fmt.Errorf("invalid opts: %w", err)
	}
	links, err := splitEngineLinks(req.Config)
	if err != nil {
		return AwgPick{}, fmt.Errorf("invalid config: %w", err)
	}
	if len(links) == 0 {
		return AwgPick{}, errors.New("no awg link")
	}
	link, idx, err := pickAwgConfig(links, o)
	if err != nil {
		return AwgPick{}, err
	}
	ini, err := awgconfig.NormalizeToINI(link)
	if err != nil {
		return AwgPick{}, err
	}
	addresses := awgconfig.TunnelAddresses(ini)
	if len(addresses) == 0 {
		return AwgPick{}, errors.New("chosen awg link has no usable Interface address")
	}
	return AwgPick{
		Index:          idx,
		Addresses:      addresses,
		PeersCarryIPv6: awgconfig.PeersCarryIPv6(ini),
	}, nil
}
