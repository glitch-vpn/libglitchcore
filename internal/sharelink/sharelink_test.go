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
		"base64 login holding a slash": {
			"socks://Ym9iOj8/Pz8=@203.0.113.7:1080#Home+Socks",
			Parts{Scheme: "socks", UserInfo: "Ym9iOj8/Pz8=", Host: "203.0.113.7", Port: 1080, Fragment: "Home+Socks"},
		},
		"base64 key holding a slash": {
			"wg://gTsOy/CY9QScEmonjo7Wt6yF7WxLJXOBgpd24MmUH0Y=@203.0.113.7:51820",
			Parts{Scheme: "wg", UserInfo: "gTsOy/CY9QScEmonjo7Wt6yF7WxLJXOBgpd24MmUH0Y=", Host: "203.0.113.7", Port: 51820},
		},
		"plain userinfo": {
			"SOCKS5://alice:s3cret@proxy.example.com:1080/?x=1",
			Parts{Scheme: "socks5", UserInfo: "alice:s3cret", Host: "proxy.example.com", Port: 1080, RawQuery: "x=1"},
		},
		"escaped @ and / in the password": {
			"socks5://alice:p%40ss%2Fw@proxy.example.com:1080",
			Parts{Scheme: "socks5", UserInfo: "alice:p@ss/w", Host: "proxy.example.com", Port: 1080},
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

func TestSplit_Refusals(t *testing.T) {
	for name, link := range map[string]string{
		"a path that names another server":  "http://alice:x@good.example:8080/@evil.example:8080",
		"an unescaped @ in the password":    "socks5://alice:p@ss@proxy.example.com:1080",
		"a slash in a plain login":          "socks5://alice:p/ss@proxy.example.com:1080",
		"a dotless host before /@":          "http://goodexample/@evil:8080",
		"base64 of a login with no colon":   "socks://Ym9iPz8/Pw==@203.0.113.7:1080",
		"base64 of a short key":             "wireguard://Ym9iOj8/Pz8=@203.0.113.7:51820",
		"base64 on a scheme taking none":    "vless://Ym9iOj8/Pz8=@203.0.113.7:443",
		"a decoded line break in the login": "socks5://a%0Ab:c@h.example:1080",
		"a decoded line break in the name":  "socks5://alice:s3cret@h.example:1080#a%0A[Xray]",
		"a decoded line break in the query": "https://h.example:443?sni=a%0Ab",
		"a decoded line break as a plus":    "https://h.example:443?sni=a%0D+b",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := Split(link, "test"); err == nil {
				t.Fatalf("Split = %+v, want an error", got)
			}
		})
	}
}
