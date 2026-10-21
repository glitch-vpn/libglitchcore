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
		{
			line: "from tcp:127.0.0.1:6001 accepted tcp:example.com:443 [tun2socks ==> proxy-2]",
			ok:   true, net: "tcp", host: "example.com", port: "443", out: "proxy-2", status: "accepted", inbound: "tun2socks",
		},
		{
			line: "from tcp:127.0.0.1:6002 accepted udp:1.1.1.1:53 [tun2socks >> direct]",
			ok:   true, net: "udp", host: "1.1.1.1", port: "53", out: "direct", status: "accepted", inbound: "tun2socks",
		},
		{
			line: "from tcp:127.0.0.1:6003 accepted tcp:example.org:80 [proxy]",
			ok:   true, net: "tcp", host: "example.org", port: "80", out: "proxy", status: "accepted", inbound: "",
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

func TestPasses_GatesByLevel(t *testing.T) {
	cases := []struct {
		verbosity int32
		level     Level
		want      bool
	}{
		{-1, Fatal, false},
		{-1, Error, false},
		{0, Fatal, true},
		{0, Error, true},
		{0, Warn, false},
		{0, Info, false},
		{1, Warn, true},
		{1, Info, true},
		{1, Debug, false},
		{2, Debug, true},
	}
	for _, c := range cases {
		if got := Passes(c.verbosity, c.level); got != c.want {
			t.Errorf("Passes(%d, %q) = %v, want %v", c.verbosity, c.level, got, c.want)
		}
	}
}

// The words in a message never set its level; only a leading token does.
func TestSplitLine_LevelFromLeadingTokenOnly(t *testing.T) {
	cases := []struct {
		raw       string
		wantLevel Level
		wantComp  string
		wantMsg   string
	}{
		{"[Xray] Connected", Info, "Xray", "Connected"},
		{"[App][DNS] resolved", Info, "App/DNS", "resolved"},
		{"DEBUG: [core] hello", Debug, "core", "hello"},
		{"WARNING: low disk", Warn, "core", "low disk"},
		{"no brackets here", Info, "core", "no brackets here"},
		{"prefix [tag] tail", Info, "tag", "tail"},
		{"[Xray] upstream error: connection failed", Info, "Xray", "upstream error: connection failed"},
		{"[AWG] fatal-looking text, panic included", Info, "AWG", "fatal-looking text, panic included"},
	}
	for _, c := range cases {
		level, comp, msg := SplitLine(c.raw)
		if level != c.wantLevel || comp != c.wantComp || msg != c.wantMsg {
			t.Errorf("SplitLine(%q) = (%q, %q, %q), want (%q, %q, %q)",
				c.raw, level, comp, msg, c.wantLevel, c.wantComp, c.wantMsg)
		}
	}
}

func TestBuildJSON(t *testing.T) {
	out := BuildJSON(Error, "Xray", "boom")
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
