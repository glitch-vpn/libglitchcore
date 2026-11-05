package proxylink

import (
	"strings"
	"testing"
)

// Made-up credentials: YWxpY2U6czNjcmV0 is base64 of alice:s3cret.
func TestParse_ReadsEachClientsSpelling(t *testing.T) {
	cases := []struct {
		name, link string
		want       Link
	}{
		{
			name: "v2rayN socks, base64 userinfo",
			link: "socks://YWxpY2U6czNjcmV0@203.0.113.7:1080#Home+Socks",
			want: Link{Protocol: Socks, Host: "203.0.113.7", Port: 1080, Username: "alice", Password: "s3cret", Name: "Home Socks"},
		},
		{
			name: "v2rayN socks without a login, base64 of a colon",
			link: "socks://Og%3D%3D@203.0.113.7:1080",
			want: Link{Protocol: Socks, Host: "203.0.113.7", Port: 1080},
		},
		{
			name: "socks without userinfo",
			link: "socks5://203.0.113.7:1080",
			want: Link{Protocol: Socks, Host: "203.0.113.7", Port: 1080},
		},
		{
			name: "Hiddify socks5, plain userinfo",
			link: "SOCKS5://alice:s3cret@[2001:db8::7]:1080#Office",
			want: Link{Protocol: Socks, Host: "2001:db8::7", Port: 1080, Username: "alice", Password: "s3cret", Name: "Office"},
		},
		{
			name: "socks5h, a password holding an escaped '@' and '/' and a ':'",
			link: "socks5h://alice:p%40ss:w%2Ford@proxy.example.com:1080",
			want: Link{Protocol: Socks, Host: "proxy.example.com", Port: 1080, Username: "alice", Password: "p@ss:w/ord"},
		},
		{
			name: "base64 userinfo holding a slash",
			link: "socks://Ym9iOj8/Pz8=@203.0.113.7:1080",
			want: Link{Protocol: Socks, Host: "203.0.113.7", Port: 1080, Username: "bob", Password: "????"},
		},
		{
			name: "v2rayN http, base64 userinfo",
			link: "http://YWxpY2U6czNjcmV0@203.0.113.7:8080#Web",
			want: Link{Protocol: HTTP, Host: "203.0.113.7", Port: 8080, Username: "alice", Password: "s3cret", Name: "Web"},
		},
		{
			name: "https with an sni and a pinned certificate",
			link: "https://alice:s3cret@proxy.example.com:443/?sni=front.example.com&pcs=0123abcd#TLS",
			want: Link{Protocol: HTTP, TLS: true, Host: "proxy.example.com", Port: 443, Username: "alice", Password: "s3cret",
				SNI: "front.example.com", Pin: "0123abcd", Name: "TLS"},
		},
		{
			name: "plain http ignores the TLS keys",
			link: "http://proxy.example.com:3128?sni=x.example.com&insecure=1",
			want: Link{Protocol: HTTP, Host: "proxy.example.com", Port: 3128},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !IsLink(c.link) {
				t.Fatal("IsLink = false")
			}
			got, err := Parse(c.link)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got != c.want {
				t.Fatalf("Parse = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestParse_RefusalsKeepTheCredentialOut(t *testing.T) {
	cases := map[string]string{
		"socks4":                       "socks4://Pa55word@203.0.113.7:1080",
		"socks4a":                      "socks4a://Pa55word@203.0.113.7:1080",
		"no port":                      "socks5://alice:Pa55word@203.0.113.7",
		"no host":                      "http://alice:Pa55word@:8080",
		"userinfo neither form":        "socks://Pa55word!@203.0.113.7:1080",
		"base64 of no colon":           "socks://UGE1NXdvcmQ=@203.0.113.7:1080",
		"https skipping verification":  "https://alice:Pa55word@proxy.example.com:443?insecure=1",
		"https allowInsecure":          "https://alice:Pa55word@proxy.example.com:443?allowInsecure=true",
		"https allow_insecure":         "https://alice:Pa55word@proxy.example.com:443?allow_insecure=1",
		"an escape that does not read": "socks5://alice:Pa55%zz@203.0.113.7:1080",
	}
	for name, link := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(link)
			if err == nil {
				t.Fatal("want an error")
			}
			if strings.Contains(err.Error(), "Pa55") || strings.Contains(err.Error(), "alice") {
				t.Fatalf("error carries the credential: %v", err)
			}
		})
	}
}

// A login or password that decodes to a control character is refused, as in
// every other decoded part of a link.
func TestParse_RefusesAControlCharacterInADecodedLogin(t *testing.T) {
	for name, link := range map[string]string{
		"socks, a newline password": "socks://YToK@good.example:80",
		"http, a 0x01 password":     "http://YToB@good.example:80",
		"a tab in the login":        "socks://CTpi@good.example:80",
		"a C1 control, U+0085":      "socks://YTrChQ@good.example:80",
		"a C1 control, U+009B":      "socks://YTrCmw@good.example:80",
		"a C1 control in the login": "socks://woB4OmI@good.example:80",
		"invalid UTF-8":             "socks://YTr__g@good.example:80",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(link); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func TestProtocol_FoldsTheSchemes(t *testing.T) {
	for link, want := range map[string]string{
		"socks://h:1":    Socks,
		"Socks5://h:1":   Socks,
		" socks5h://h:1": Socks,
		"http://h:1":     HTTP,
		"HTTPS://h:1":    HTTP,
		"socks4://h:1":   "",
		"vless://id@h:1": "",
		"httpx://h:1":    "",
		"socks":          "",
	} {
		if got := Protocol(link); got != want {
			t.Errorf("Protocol(%q) = %q, want %q", link, got, want)
		}
	}
}
