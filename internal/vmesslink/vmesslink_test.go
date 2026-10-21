package vmesslink

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const testUUID = "6f4b7a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b"

func sharedLink(t *testing.T, fields map[string]any) string {
	t.Helper()
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func TestParse_SharedJSON(t *testing.T) {
	link := sharedLink(t, map[string]any{
		"v": "2", "ps": "🇩🇪 Frankfurt+1", "add": "vm.example.com", "port": "443", "id": testUUID,
		"aid": "0", "scy": "chacha20-poly1305", "net": "ws", "type": "none", "host": "cdn.example.com",
		"path": "/vm?ed=2048", "tls": "tls", "sni": "sni.example.com", "alpn": "h2,http/1.1",
		"fp": "chrome", "insecure": "1",
	})
	l, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if l.Name != "🇩🇪 Frankfurt+1" || l.Host != "vm.example.com" || l.Port != 443 || l.ID != testUUID ||
		l.AlterID != 0 || l.Cipher != "chacha20-poly1305" {
		t.Fatalf("link = %+v", l)
	}
	want := map[string]string{
		"type": "ws", "headerType": "none", "host": "cdn.example.com", "path": "/vm?ed=2048",
		"security": "tls", "sni": "sni.example.com", "alpn": "h2,http/1.1", "fp": "chrome", "allowInsecure": "1",
	}
	for k, v := range want {
		if got := l.Params.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

// Older v2rayN versions write the numbers as JSON numbers.
func TestParse_SharedJSONNumbers(t *testing.T) {
	l, err := Parse(sharedLink(t, map[string]any{"v": 2, "add": "203.0.113.5", "port": 8080, "id": testUUID, "aid": 64}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if l.Port != 8080 || l.AlterID != 64 || l.Cipher != "auto" || l.Params.Get("type") != "tcp" {
		t.Fatalf("link = %+v", l)
	}
}

func TestParse_SharedJSONNetworkFields(t *testing.T) {
	cases := []struct {
		name   string
		fields map[string]any
		want   map[string]string
	}{
		{
			name:   "http_is_h2",
			fields: map[string]any{"net": "http", "host": "a.example.com", "path": "/h2"},
			want:   map[string]string{"type": "h2", "host": "a.example.com", "path": "/h2"},
		},
		{
			name:   "tcp_http_header",
			fields: map[string]any{"net": "tcp", "type": "http", "host": "a.example.com", "path": "/"},
			want:   map[string]string{"type": "tcp", "headerType": "http", "host": "a.example.com"},
		},
		{
			name:   "grpc_path_is_service",
			fields: map[string]any{"net": "grpc", "type": "multi", "host": "auth.example.com", "path": "svc"},
			want:   map[string]string{"type": "grpc", "serviceName": "svc", "authority": "auth.example.com", "mode": "multi", "path": ""},
		},
		{
			name:   "kcp_path_is_seed",
			fields: map[string]any{"net": "kcp", "type": "wechat-video", "path": "seed"},
			want:   map[string]string{"type": "kcp", "seed": "seed", "headerType": "wechat-video"},
		},
		{
			name:   "raw_alias",
			fields: map[string]any{"net": "raw", "tls": "TLS"},
			want:   map[string]string{"type": "tcp", "security": "tls"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.fields["add"], tc.fields["port"], tc.fields["id"] = "203.0.113.5", "443", testUUID
			l, err := Parse(sharedLink(t, tc.fields))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			for k, v := range tc.want {
				if got := l.Params.Get(k); got != v {
					t.Errorf("%s = %q, want %q", k, got, v)
				}
			}
		})
	}
}

func TestParse_URIForm(t *testing.T) {
	l, err := Parse("vmess://" + testUUID + "@[2001:db8::5]:8443?type=http&security=tls&encryption=aes-128-gcm&sni=a.example.com&path=%2Fh2#Frankfurt+%231")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if l.Name != "Frankfurt #1" || l.Host != "2001:db8::5" || l.Port != 8443 || l.ID != testUUID || l.Cipher != "aes-128-gcm" {
		t.Fatalf("link = %+v", l)
	}
	if l.Params.Get("type") != "h2" || l.Params.Get("path") != "/h2" || l.Params.Get("sni") != "a.example.com" {
		t.Fatalf("params = %v", l.Params)
	}
}

func TestParse_Refuses(t *testing.T) {
	cases := map[string]string{
		"not_base64":   "vmess://%%%",
		"not_json":     "vmess://" + base64.StdEncoding.EncodeToString([]byte("not json")),
		"oversized":    "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"ps":"`+strings.Repeat("a", 64<<10)+`"}`)),
		"uri_bad_port": "vmess://" + testUUID + "@h.example.com:x",
		"not_vmess":    "vless://" + testUUID + "@h.example.com:443",
	}
	for name, link := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(link); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

// serverinfo names a server from a link the engine refuses.
func TestParse_FillsWhatItReads(t *testing.T) {
	l, err := Parse(sharedLink(t, map[string]any{"ps": "Named", "add": "vm.example.com", "port": "0", "id": testUUID}))
	if err == nil {
		t.Fatal("want an error for port 0")
	}
	if l.Name != "Named" || l.Host != "vm.example.com" {
		t.Fatalf("link = %+v", l)
	}
}

// A remark after '#' may hold '@'; the payload before it decides the form.
func TestParse_SharedJSONWithAtInRemark(t *testing.T) {
	l, err := Parse(sharedLink(t, map[string]any{"add": "vm.example.com", "port": "443", "id": testUUID}) + "#me@home")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if l.Host != "vm.example.com" || l.Port != 443 {
		t.Fatalf("link = %+v", l)
	}
}

func TestParse_WrongTypedFieldIsNamed(t *testing.T) {
	_, err := Parse(sharedLink(t, map[string]any{"add": "vm.example.com", "port": "443", "id": testUUID, "tls": true}))
	if err == nil || !strings.Contains(err.Error(), `"tls"`) {
		t.Fatalf("err = %v, want one naming the tls field", err)
	}
}

func TestParse_URIErrorKeepsTheLinkOut(t *testing.T) {
	_, err := Parse("vmess://" + testUUID + ":Pa55/word@h.example.com:443")
	if err == nil || strings.Contains(err.Error(), testUUID) || strings.Contains(err.Error(), "Pa55") {
		t.Fatalf("err = %v", err)
	}
}
