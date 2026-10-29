//go:build !race

package xrayconfig

import "testing"

func skipWhereObservatoryRaces(t *testing.T) { t.Helper() }
