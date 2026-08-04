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

// Windows route exclusion consumes EndpointHost's exact shape.
func TestEndpointHostUnchanged(t *testing.T) {
	if got := EndpointHost("[Peer]\nEndpoint = wg.example.com:51820\n"); got != "wg.example.com" {
		t.Fatalf("got %q", got)
	}
}
