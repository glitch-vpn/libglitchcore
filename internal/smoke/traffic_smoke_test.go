//go:build integration

package smoke

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	xproxy "golang.org/x/net/proxy"
)

const trafficBodyBytes = 2 << 20

func fetchThroughSocks(t *testing.T, socksPort int, url string) int64 {
	t.Helper()
	body, err := socksGet(fmt.Sprintf("127.0.0.1:%d", socksPort), nil, url)
	if err != nil {
		t.Fatalf("GET %s through the engine: %v", url, err)
	}
	return int64(len(body))
}

// socksGet is a GET whose connections go to the SOCKS5 listener at socksAddress,
// with its login when auth is set.
func socksGet(socksAddress string, auth *xproxy.Auth, url string) ([]byte, error) {
	dialer, err := xproxy.SOCKS5("tcp", socksAddress, auth, xproxy.Direct)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.(xproxy.ContextDialer).DialContext(ctx, network, addr)
		},
		DisableKeepAlives: true,
	}}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
