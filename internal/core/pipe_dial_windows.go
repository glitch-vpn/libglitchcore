//go:build windows

package core

import (
	"context"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// dialPipeAtIdentification lets the server read the caller's token; go-winio
// dials anonymously by default, which gives the server none.
func dialPipeAtIdentification(pipeName string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return winio.DialPipeAccessImpLevel(ctx, pipeName, windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
}
