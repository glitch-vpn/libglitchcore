//go:build !no_mihomo

package pinger

import (
	"context"
	"errors"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/awgconfig"
)

func init() {
	registerMeasurer(engineMeasurer{
		engine:  "awg",
		match:   matchAwgLink,
		measure: measureAwgOnMihomo,
	})
}

// measureAwgOnMihomo answers as the awg engine would start: a link with
// reserved bytes, which amneziawg-go cannot send, is refused, and an unpinned
// ping takes it to the fallback engine.
func measureAwgOnMihomo(ctx context.Context, link, probeURL string) (time.Duration, error) {
	if ini, err := awgconfig.NormalizeToINI(link); err == nil {
		if _, err := awgconfig.ParseToUAPI(ini); errors.Is(err, awgconfig.ErrReservedBytes) {
			return 0, fallsBack{err}
		}
	}
	return measureMihomo(ctx, link, probeURL)
}
