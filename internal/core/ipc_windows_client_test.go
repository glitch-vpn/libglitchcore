//go:build windows && !service

package core

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func TestServiceDialRefusesAPipeAnOrdinaryAccountOwns(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("a pipe an elevated process creates belongs to the Administrators group")
	}
	name := fmt.Sprintf(`\\.\pipe\glitch_vpn_core_test_%d_owner`, os.Getpid())
	listener, err := winio.ListenPipe(name, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		if conn, err := listener.Accept(); err == nil {
			conn.Close()
		}
	}()

	conn, err := dialService(name, 2*time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("dialled a pipe the service does not own")
	}
	if !errors.Is(err, errServicePipeNotOwned) {
		t.Fatalf("dial failed with %v, want an owner refusal", err)
	}
}
