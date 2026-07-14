package logfmt

import (
	"encoding/json"
	"testing"
)

func TestParseAccess(t *testing.T) {
	cases := []struct {
		line                                  string
		ok                                    bool
		net, host, port, out, status, inbound string
	}{
		{
			line: "from tcp:127.0.0.1:52341 accepted tcp:www.google.com:443 [tun2socks -> proxy]",
			ok:   true, net: "tcp", host: "www.google.com", port: "443", out: "proxy", status: "accepted", inbound: "tun2socks",
		},
		{
			line: "from tcp:127.0.0.1:5000 accepted udp:[2001:db8::1]:53 [tun2socks -> direct]",
			ok:   true, net: "udp", host: "2001:db8::1", port: "53", out: "direct", status: "accepted", inbound: "tun2socks",
		},
		{
			line: "from tcp:127.0.0.1:6000 rejected tcp:ads.example:443 [tun2socks -> block]",
			ok:   true, net: "tcp", host: "ads.example", port: "443", out: "block", status: "rejected", inbound: "tun2socks",
		},
		{line: "some ordinary [app] log line", ok: false},
		{line: "from nowhere in particular", ok: false},
	}
	for _, c := range cases {
		a, ok := ParseAccess(c.line)
		if ok != c.ok {
			t.Fatalf("ParseAccess(%q) ok=%v, want %v", c.line, ok, c.ok)
		}
		if !ok {
			continue
		}
		if a.Network != c.net || a.Host != c.host || a.Port != c.port ||
			a.Outbound != c.out || a.Status != c.status || a.Inbound != c.inbound {
			t.Errorf("ParseAccess(%q) = %+v", c.line, a)
		}
	}
}

func TestShouldEmit(t *testing.T) {
	cases := []struct {
		lvl  int32
		msg  string
		want bool
	}{
		{2, "anything debug trace", true},
		{1, "normal info message", true},
		{1, "a debug line", false},
		{1, "a trace line", false},
		{0, "connection error here", true},
		{0, "operation failed", true},
		{0, "panic: boom", true},
		{0, "fatal shutdown", true},
		{0, "ordinary info message", false},
	}
	for _, c := range cases {
		if got := ShouldEmit(c.lvl, c.msg); got != c.want {
			t.Errorf("ShouldEmit(%d, %q) = %v, want %v", c.lvl, c.msg, got, c.want)
		}
	}
}

func TestComponent(t *testing.T) {
	cases := []struct {
		raw      string
		wantComp string
		wantMsg  string
	}{
		{"[Xray] Connected", "Xray", "Connected"},
		{"[App][DNS] resolved", "App/DNS", "resolved"},
		{"DEBUG: [core] hello", "core", "hello"},
		{"no brackets here", "core", "no brackets here"},
		{"prefix [tag] tail", "tag", "tail"},
	}
	for _, c := range cases {
		comp, msg := Component(c.raw)
		if comp != c.wantComp || msg != c.wantMsg {
			t.Errorf("Component(%q) = (%q, %q), want (%q, %q)", c.raw, comp, msg, c.wantComp, c.wantMsg)
		}
	}
}

func TestInferLevel(t *testing.T) {
	cases := map[string]string{
		"fatal crash":           "fatal",
		"some error occurred":   "error",
		"warn: low disk":        "warn",
		"debug details":         "debug",
		"trace span":            "trace",
		"just an ordinary line": "info",
	}
	for msg, want := range cases {
		if got := InferLevel(msg); got != want {
			t.Errorf("InferLevel(%q) = %q, want %q", msg, got, want)
		}
	}
}

func TestBuildJSON(t *testing.T) {
	out := BuildJSON("error", "Xray", "boom")
	var decoded struct {
		TS        string `json:"ts"`
		Level     string `json:"level"`
		Component string `json:"component"`
		Message   string `json:"message"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("BuildJSON output is not valid JSON: %v (%s)", err, out)
	}
	if decoded.Level != "error" || decoded.Component != "Xray" || decoded.Message != "boom" {
		t.Errorf("BuildJSON fields = %+v", decoded)
	}
	if decoded.TS == "" {
		t.Error("BuildJSON ts is empty")
	}
}
