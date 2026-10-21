package loopbackauth

import (
	"net/url"
	"testing"
)

func TestNewDrawsDistinctURLSafeCredentials(t *testing.T) {
	a, b := New(), New()
	if !a.Set() || a == b {
		t.Fatalf("credentials must be set and fresh per call: %+v %+v", a, b)
	}
	u := url.URL{Scheme: "socks5", User: url.UserPassword(a.User, a.Pass), Host: "127.0.0.1:1"}
	if want := "socks5://" + a.User + ":" + a.Pass + "@127.0.0.1:1"; u.String() != want {
		t.Fatalf("credentials need escaping in a URL: %s", u.String())
	}
}
