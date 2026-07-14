//go:build !no_mihomo

package pinger

func init() {
	registerMeasurer(engineMeasurer{
		engine:  "awg",
		match:   matchAwgLink,
		measure: measureMihomo,
	})
}
