package awgconfig

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

// Made-up keys.
const (
	linkPrivateKey    = "gTsOy/CY9QScEmonjo7Wt6yF7WxLJXOBgpd24MmUH0Y="
	linkPrivateKeyHex = "813b0ecbf098f5049c126a278e8ed6b7ac85ed6c4b257381829776e0c9941f46"
	linkPublicKey     = "kVNWJ0pOFM11/p62BQNCmJQIffiVca8AipT6DTXxeVA="
	linkPresharedKey  = "Vl19HfL05ZncotJbmutyz3Pq3OnDgD8NFaoeTP4L4NQ="
)

func TestNormalizeToINI_ReadsEachClientsWireGuardLink(t *testing.T) {
	esc := url.QueryEscape
	cases := []struct {
		name, link, want string
		// reservedBytes: ParseToUAPI refuses the INI, as the awg engine does.
		reservedBytes bool
	}{
		{
			name: "v2rayNG, escaped keys and an all-zero reserved",
			link: "wireguard://" + esc(linkPrivateKey) + "@203.0.113.7:51820?address=" + esc("172.16.0.2/32,2606:4700:110:8a36::2/128") +
				"&reserved=0,0,0&publickey=" + esc(linkPublicKey) + "&mtu=1280#WARP",
			want: "[Interface]\nPrivateKey = " + linkPrivateKey + "\nAddress = 172.16.0.2/32, 2606:4700:110:8a36::2/128\nMTU = 1280\n\n" +
				"[Peer]\nPublicKey = " + linkPublicKey + "\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.7:51820\n",
		},
		{
			name: "v2rayN, raw base64 in the userinfo and the query",
			link: "WireGuard://" + linkPrivateKey + "@203.0.113.7:51820/?PublicKey=" + linkPublicKey + "&presharedkey=" + linkPresharedKey +
				"&reserved=1,2,3&address=10.0.0.2&dns=1.1.1.1,8.8.8.8#Office",
			want: "[Interface]\nPrivateKey = " + linkPrivateKey + "\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1, 8.8.8.8\n\n" +
				"[Peer]\nPublicKey = " + linkPublicKey + "\nPresharedKey = " + linkPresharedKey +
				"\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.7:51820\nReserved = 1, 2, 3\n",
			reservedBytes: true,
		},
		{
			name: "Hiddify wg://, keys in the query",
			link: "wg://[2001:db8::1]:51820?pk=" + linkPrivateKey + "&peerpublickey=" + linkPublicKey + "&ip=10.0.0.2/32,fd00::2&psk=" + linkPresharedKey +
				"&keepalive=25&allowedips=0.0.0.0/0",
			want: "[Interface]\nPrivateKey = " + linkPrivateKey + "\nAddress = 10.0.0.2/32, fd00::2/128\n\n" +
				"[Peer]\nPublicKey = " + linkPublicKey + "\nPresharedKey = " + linkPresharedKey +
				"\nAllowedIPs = 0.0.0.0/0\nEndpoint = [2001:db8::1]:51820\nPersistentKeepalive = 25\n",
		},
		{
			name: "Hiddify's other spellings, a hex key and a base64 reserved",
			link: "wireguard://203.0.113.7:2408?privatekey=" + linkPrivateKeyHex + "&pub=" + esc(linkPublicKey) +
				"&localaddress=10.0.0.2/32&reserved=AQID",
			want: "[Interface]\nPrivateKey = " + linkPrivateKey + "\nAddress = 10.0.0.2/32\n\n" +
				"[Peer]\nPublicKey = " + linkPublicKey + "\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.7:2408\nReserved = 1, 2, 3\n",
			reservedBytes: true,
		},
		{
			name: "AmneziaWG keys",
			link: "wireguard://" + esc(linkPrivateKey) + "@203.0.113.7:51820?publickey=" + esc(linkPublicKey) + "&address=10.8.0.2/32" +
				"&jc=4&jmin=40&jmax=70&s1=15&s2=18&s3=20&s4=23&h1=100-200&h2=300-400&h3=500-600&h4=700-800&i1=<b+0xf6ab3267fa><r+16>&i2=%3Cr%2010%3E",
			want: "[Interface]\nPrivateKey = " + linkPrivateKey + "\nAddress = 10.8.0.2/32\n" +
				"Jc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 18\nS3 = 20\nS4 = 23\nH1 = 100-200\nH2 = 300-400\nH3 = 500-600\nH4 = 700-800\n" +
				"I1 = <b 0xf6ab3267fa><r 16>\nI2 = <r 10>\n\n" +
				"[Peer]\nPublicKey = " + linkPublicKey + "\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.7:51820\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !IsLink(c.link) {
				t.Fatal("IsLink = false")
			}
			ini, err := NormalizeToINI(c.link)
			if err != nil {
				t.Fatalf("NormalizeToINI: %v", err)
			}
			if ini != c.want {
				t.Fatalf("INI =\n%s\nwant\n%s", ini, c.want)
			}
			uapi, err := ParseToUAPI(ini)
			if c.reservedBytes {
				if !errors.Is(err, ErrReservedBytes) {
					t.Fatalf("ParseToUAPI = %v, want the reserved-bytes refusal", err)
				}
			} else if err != nil || !strings.Contains(uapi, "endpoint=") {
				t.Fatalf("ParseToUAPI = %q, %v", uapi, err)
			}
		})
	}
}

func TestNormalizeToINI_WireGuardLinkRefusals(t *testing.T) {
	base := "wireguard://" + linkPrivateKey + "@203.0.113.7:51820?publickey=" + linkPublicKey
	cases := map[string]string{
		"no port":                "wireguard://" + linkPrivateKey + "@203.0.113.7?publickey=" + linkPublicKey,
		"no public key":          "wireguard://" + linkPrivateKey + "@203.0.113.7:51820?address=10.0.0.2/32",
		"no private key":         "wireguard://203.0.113.7:51820?publickey=" + linkPublicKey,
		"a short private key":    "wireguard://Pa55word@203.0.113.7:51820?publickey=" + linkPublicKey,
		"a line in a value":      base + "&address=10.0.0.2/32%0A[Peer]",
		"an address of nothing":  base + "&address=nowhere",
		"two reserved bytes":     base + "&reserved=1,2",
		"a reserved byte of 256": base + "&reserved=1,2,256",
		"a word for the mtu":     base + "&mtu=auto",
		"a word for keepalive":   base + "&keepalive=often",
	}
	for name, link := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NormalizeToINI(link)
			if err == nil {
				t.Fatal("want an error")
			}
			for _, secret := range []string{linkPrivateKey, linkPublicKey, "Pa55"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error carries key material: %v", err)
				}
			}
		})
	}
}

func TestIsLink(t *testing.T) {
	for link, want := range map[string]bool{
		"awg://YWJj#tokyo":                       true,
		"  WG://k@203.0.113.7:51820":             true,
		"wireguard://k@203.0.113.7:51820":        true,
		"[Interface]\nPrivateKey = k\n[Peer]":    true,
		"vless://id@203.0.113.7:443":             false,
		"wireguards://k@203.0.113.7:51820":       false,
		"socks://YWxpY2U6czNjcmV0@203.0.113.7:1": false,
	} {
		if got := IsLink(link); got != want {
			t.Errorf("IsLink(%q) = %v, want %v", link, got, want)
		}
	}
}

func TestLinkName_WireGuardLink(t *testing.T) {
	for link, want := range map[string]string{
		"wireguard://k@203.0.113.7:51820?publickey=p#Home+WG%20One": "Home WG One",
		"wg://203.0.113.7:51820?pk=k":                               "",
		EncodeLink("[Interface]", "a+b"):                            "a+b",
	} {
		if got := LinkName(link); got != want {
			t.Errorf("LinkName(%q) = %q, want %q", link, got, want)
		}
	}
}

func TestParseToUAPI_ReservedBytes(t *testing.T) {
	ini := "[Interface]\nPrivateKey = " + linkPrivateKey + "\n[Peer]\nPublicKey = " + linkPublicKey + "\nAllowedIPs = 0.0.0.0/0\n"
	if _, err := ParseToUAPI(ini + "Reserved = 0, 0, 0\n"); err != nil {
		t.Fatalf("all-zero reserved: %v", err)
	}
	if _, err := ParseToUAPI(ini + "Reserved = 1, 2, 3\n"); !errors.Is(err, ErrReservedBytes) {
		t.Fatalf("reserved 1,2,3: err = %v, want ErrReservedBytes", err)
	}
	if _, err := ParseToUAPI(ini + "Reserved = 1, 2\n"); err == nil || errors.Is(err, ErrReservedBytes) {
		t.Fatalf("unreadable reserved: err = %v", err)
	}
}
