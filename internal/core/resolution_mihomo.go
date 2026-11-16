//go:build !no_mihomo

package core

import (
	"errors"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
)

func init() {
	resolutionFailureKinds = append(resolutionFailureKinds, func(err error) bool {
		return errors.Is(err, dialer.ErrorNoIpAddress) || errors.Is(err, resolver.ErrIPNotFound)
	})
}
