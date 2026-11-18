//go:build !no_mihomo

package core

import mihomoResolver "github.com/metacubex/mihomo/component/resolver"

// mihomo's resolver reads DisableIPv6, which defaults to true, from lookup
// goroutines that outlive the call that started them. The package sets it once,
// before any test runs, to the value its resolution tests need, and no test
// writes it again: a write from a test would race a goroutine still looking a
// name up.
func init() {
	mihomoResolver.DisableIPv6 = false
}
