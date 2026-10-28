//go:build windows

package core

import (
	"context"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// servicePipesLocation is where the service publishes the pipe names it draws
// at each start, under a key only LocalSystem may write: a client never dials a
// name that another account could have created before the service did.
var servicePipesLocation = registryLocation{root: registry.LOCAL_MACHINE, path: `SOFTWARE\glitch_vpn_core`}

type registryLocation struct {
	root registry.Key
	path string
}

const (
	commandPipeValueName = "CommandPipe"
	eventPipeValueName   = "EventPipe"
	servicePipePrefix    = `\\.\pipe\glitch_vpn_core_`
)

// dialPipeAtIdentification lets the server read the caller's token; go-winio
// dials anonymously by default, which gives the server none.
func dialPipeAtIdentification(pipeName string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return winio.DialPipeAccessImpLevel(ctx, pipeName, windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
}
