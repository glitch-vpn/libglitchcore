package core

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

const loopbackTestVlessLink = "vless://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=tcp&security=none#t"

func loopbackDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	var lastErr error
	for i := 0; i < 50; i++ {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			return c
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("dial %s: %v", addr, lastErr)
	return nil
}

// A SOCKS5 client offering only "no authentication" must not be granted it.
// Servers differ in how they say no: xray answers 0xFF, mihomo demands
// username/password regardless of the offer.
func requireSocksRefusesAnonymous(t *testing.T, addr string) {
	t.Helper()
	c := loopbackDial(t, addr)
	defer c.Close()
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("%s: greeting: %v", addr, err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		return
	}
	if reply[1] == 0 {
		t.Fatalf("%s accepted an anonymous SOCKS5 client (method %#x)", addr, reply[1])
	}
}

// SOCKS4 has no password, so a gated listener must refuse every SOCKS4
// CONNECT (granted = 0x5A).
func requireSocks4RefusesAnonymous(t *testing.T, addr string) {
	t.Helper()
	c := loopbackDial(t, addr)
	defer c.Close()
	if _, err := c.Write([]byte{4, 1, 1, 187, 192, 0, 2, 1, 'a', 0}); err != nil {
		t.Fatalf("%s: socks4 connect: %v", addr, err)
	}
	reply := make([]byte, 8)
	if _, err := io.ReadFull(c, reply); err != nil {
		return
	}
	if reply[1] == 0x5A {
		t.Fatalf("%s granted an anonymous SOCKS4 CONNECT", addr)
	}
}

func requireHTTPConnectRefusesAnonymous(t *testing.T, addr string) {
	t.Helper()
	c := loopbackDial(t, addr)
	defer c.Close()
	if _, err := c.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")); err != nil {
		t.Fatalf("%s: connect: %v", addr, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("%s answered an anonymous CONNECT with %d", addr, resp.StatusCode)
	}
}

// The credentials a socks5:// URL carries must pass the listener's
// username/password sub-negotiation.
func requireSocksAcceptsURL(t *testing.T, socksURL string) {
	t.Helper()
	u, err := url.Parse(socksURL)
	if err != nil {
		t.Fatalf("socks url %q: %v", socksURL, err)
	}
	if u.User == nil {
		t.Fatalf("socks url %s carries no credentials", u.Redacted())
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	c := loopbackDial(t, u.Host)
	defer c.Close()
	if _, err := c.Write([]byte{5, 1, 2}); err != nil {
		t.Fatalf("%s: greeting: %v", u.Host, err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 2 {
		t.Fatalf("%s: method reply %v, err %v; want username/password", u.Host, reply, err)
	}
	sub := []byte{1, byte(len(user))}
	sub = append(sub, user...)
	sub = append(sub, byte(len(pass)))
	sub = append(sub, pass...)
	if _, err := c.Write(sub); err != nil {
		t.Fatalf("%s: auth: %v", u.Host, err)
	}
	if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0 {
		t.Fatalf("%s rejected its own credentials: reply %v, err %v", u.Host, reply, err)
	}
}
