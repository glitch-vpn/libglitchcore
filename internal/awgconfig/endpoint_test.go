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
