package sharelink

import (
	"net/url"
	"strings"
	"testing"
)

func TestParseURL_ErrorKeepsTheLinkOut(t *testing.T) {
	for _, link := range []string{
		"tuic://uuid:Pa55word#rest@h.example.com:443",
		"tuic://uuid:Pa55/word@h.example.com:443",
		"tuic://uuid:Pa55?word@h.example.com:443",
		"tuic://uuid:Pa55word",
	} {
		_, err := ParseURL(link, "tuic")
		if err == nil {
			t.Fatalf("%q: want an error", link)
		}
		if strings.Contains(err.Error(), "Pa55") || strings.Contains(err.Error(), "uuid") {
			t.Fatalf("%q: error carries the link: %v", link, err)
		}
	}
}

func TestSkipsVerification(t *testing.T) {
	for query, want := range map[string]bool{
		"allowInsecure=1":     true,
		"insecure=TRUE":       true,
		"allow_insecure=+1+":  true,
		"allowInsecure=0":     false,
		"insecure=false":      false,
		"pcs=00&security=tls": false,
	} {
		q, err := url.ParseQuery(query)
		if err != nil {
			t.Fatal(err)
		}
		if got := SkipsVerification(q); got != want {
			t.Errorf("%s: SkipsVerification = %v, want %v", query, got, want)
		}
	}
}

func TestSplit(t *testing.T) {
	cases := map[string]struct {
		link string
		want Parts
	}{
		"base64 userinfo holding a slash": {
			"socks://Ym9i/OnBhc3M=@203.0.113.7:1080#Home+Socks",
			Parts{Scheme: "socks", UserInfo: "Ym9i/OnBhc3M=", Host: "203.0.113.7", Port: 1080, Fragment: "Home+Socks"},
		},
		"unescaped @ in the password": {
			"SOCKS5://alice:p@ss@proxy.example.com:1080/?x=1",
			Parts{Scheme: "socks5", UserInfo: "alice:p@ss", Host: "proxy.example.com", Port: 1080, RawQuery: "x=1"},
		},
		"percent-encoded userinfo keeps its plus": {
			"wireguard://gTsOy%2FCY9+Q%3D@[2001:db8::1]:51820?publickey=a+b#WARP%20One",
			Parts{Scheme: "wireguard", UserInfo: "gTsOy/CY9+Q=", Host: "2001:db8::1", Port: 51820, RawQuery: "publickey=a+b", Fragment: "WARP One"},
		},
		"no userinfo and no port": {
			"http://proxy.example.com",
			Parts{Scheme: "http", Host: "proxy.example.com"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := Split(c.link, "test")
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("Split = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestSplit_ErrorKeepsTheLinkOut(t *testing.T) {
	for _, link := range []string{
		"socks://Pa55word@203.0.113.7:notaport",
		"socks://Pa55word@203.0.113.7:70000",
		"socks://Pa55word@:1080",
		"socks://Pa55%zzword@203.0.113.7:1080",
		"Pa55word@203.0.113.7:1080",
		"wireguard://Pa55word@203.0.113.7\n[Peer]:51820",
	} {
		_, err := Split(link, "socks")
		if err == nil {
			t.Fatalf("%q: want an error", link)
		}
		if strings.Contains(err.Error(), "Pa55") {
			t.Fatalf("%q: error carries the link: %v", link, err)
		}
	}
}
