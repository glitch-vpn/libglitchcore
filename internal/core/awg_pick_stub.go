//go:build no_awg

package core

import "errors"

type AwgPick struct {
	Index          int      `json:"index"`
	Addresses      []string `json:"addresses"`
	PeersCarryIPv6 bool     `json:"peersCarryV6"`
}

func PickAwg(EngineStartRequest) (AwgPick, error) {
	return AwgPick{}, errors.New("awg is not built into this core")
}
