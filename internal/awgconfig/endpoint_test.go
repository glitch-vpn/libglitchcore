package awgconfig

import "testing"

func TestEndpointHostPort(t *testing.T) {
	cfg := "[Peer]\nEndpoint = wg.example.com:51820\n"
	host, port := EndpointHostPort(cfg)
	if host != "wg.example.com" || port != 51820 {
		t.Fatalf("got %q:%d", host, port)
	}

	v6 := "[Peer]\nEndpoint = [2001:db8::1]:51820\n"
	host, port = EndpointHostPort(v6)
	if host != "2001:db8::1" || port != 51820 {
		t.Fatalf("v6: got %q:%d", host, port)
	}

	noPort := "[Peer]\nEndpoint = bare.example.com\n"
	host, port = EndpointHostPort(noPort)
	if host != "bare.example.com" || port != 0 {
		t.Fatalf("no port: got %q:%d", host, port)
	}

	if host, port = EndpointHostPort("[Peer]\nPublicKey = x\n"); host != "" || port != 0 {
		t.Fatalf("missing endpoint: got %q:%d", host, port)
	}
}

func TestEndpointHostPort_NamesThePeerThatCarriesTheDefaultRoute(t *testing.T) {
	const head = "[Interface]\nPrivateKey = x\n\n"
	cases := map[string]struct {
		cfg  string
		host string
		port int
	}{
		"default route over the first peer": {
			head + "[Peer]\nEndpoint = a.example:1\nAllowedIPs = 10.0.0.0/8\n[Peer]\nEndpoint = b.example:2\nAllowedIPs = 10.1.0.0/16, ::/0\n",
			"b.example", 2,
		},
		"widest prefix without a default route": {
			head + "[Peer]\nEndpoint = a.example:1\nAllowedIPs = 10.1.0.0/16\n[Peer]\nEndpoint = b.example:2\nAllowedIPs = 10.0.0.0/8\n",
			"b.example", 2,
		},
		"a lone peer": {
			head + "[Peer]\nEndpoint = a.example:1\n",
			"a.example", 1,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if host, port := EndpointHostPort(c.cfg); host != c.host || port != c.port {
				t.Errorf("got %q:%d, want %q:%d", host, port, c.host, c.port)
			}
		})
	}
}

// IPv4 and IPv6 default routes are different prefixes: the peer that owns
// 0.0.0.0/0 carries IPv4 whatever peer owns ::/0, and a tie breaks to the
// last peer only for one identical prefix.
func TestEndpointHostPort_PrefersTheIPv4DefaultRoute(t *testing.T) {
	const head = "[Interface]\nPrivateKey = x\n\n"
	cases := map[string]struct {
		cfg  string
		host string
	}{
		"v4 default first, v6 default second": {
			head + "[Peer]\nEndpoint = a.example:1\nAllowedIPs = 0.0.0.0/0\n[Peer]\nEndpoint = b.example:2\nAllowedIPs = ::/0\n", "a.example",
		},
		"v6 default first, v4 default second": {
			head + "[Peer]\nEndpoint = a.example:1\nAllowedIPs = ::/0\n[Peer]\nEndpoint = b.example:2\nAllowedIPs = 0.0.0.0/0\n", "b.example",
		},
		"the same default twice goes to the last": {
			head + "[Peer]\nEndpoint = a.example:1\nAllowedIPs = 0.0.0.0/0\n[Peer]\nEndpoint = b.example:2\nAllowedIPs = 0.0.0.0/0, ::/0\n", "b.example",
		},
		"only a v6 default": {
			head + "[Peer]\nEndpoint = a.example:1\nAllowedIPs = 10.0.0.0/8\n[Peer]\nEndpoint = b.example:2\nAllowedIPs = ::/0\n", "b.example",
		},
		"a wider v4 prefix beats a wider v6 one": {
			head + "[Peer]\nEndpoint = a.example:1\nAllowedIPs = 10.0.0.0/16\n[Peer]\nEndpoint = b.example:2\nAllowedIPs = fd00::/8\n", "a.example",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if host, _ := EndpointHostPort(c.cfg); host != c.host {
				t.Errorf("got %q, want %q", host, c.host)
			}
		})
	}
}
