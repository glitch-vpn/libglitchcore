//go:build race

package xrayconfig

import "testing"

// xray's observatory hands its result slice to a balancer's picker without a
// lock, so any route a balancer picks after a probe has written is a race inside
// xray. Only a test that routes through a balancer with an observatory skips
// here, so the run under -race stays clean; the skip is for the test run only.
func skipWhereObservatoryRaces(t *testing.T) {
	t.Helper()
	t.Skip("xray's observatory results are read by the balancer without a lock")
}
