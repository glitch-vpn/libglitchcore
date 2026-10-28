//go:build !race

package core

import "testing"

func skipWhereMihomoRaces(t *testing.T) { t.Helper() }
