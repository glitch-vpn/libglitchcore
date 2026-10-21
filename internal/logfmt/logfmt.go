// Package logfmt writes, parses and formats core log lines.
package logfmt

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// Level is a line's severity as its engine reported it. The names are the
// payload's "level" values.
type Level string

const (
	Debug Level = "debug"
	Info  Level = "info"
	Warn  Level = "warn"
	Error Level = "error"
	Fatal Level = "fatal"
)

// IsError reports whether the line travels as LogError rather than LogEvent.
func (l Level) IsError() bool { return l == Error || l == Fatal }

// Passes reports whether a line at level l passes the verbosity gate:
//
//	verbosity <  0 -> nothing (logging fully off - the default)
//	verbosity == 0 -> error and fatal
//	verbosity == 1 -> everything but debug
//	verbosity >= 2 -> everything
func Passes(verbosity int32, l Level) bool {
	switch {
	case verbosity < 0:
		return false
	case verbosity == 0:
		return l.IsError()
	case verbosity == 1:
		return l != Debug
	default:
		return true
	}
}

// SplitLine reads a line written through the standard log package: a leading
// severity token ("ERROR:", "debug:") is its level, Info when it has none, and
// leading [COMP]...[COMP] prefixes join into a "/"-separated component, "core"
// when there are none.
func SplitLine(raw string) (level Level, component string, msg string) {
	s := strings.TrimSpace(raw)
	level = Info

	for {
		idx := strings.Index(s, ":")
		if idx <= 0 {
			break
		}
		token, ok := severityTokens[strings.ToLower(strings.TrimSpace(s[:idx]))]
		if !ok {
			break
		}
		level = token
		s = strings.TrimSpace(s[idx+1:])
	}

	var parts []string
	if !strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "["); i >= 0 {
			s = strings.TrimSpace(s[i:])
		}
	}

	for strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end <= 1 {
			break
		}
		parts = append(parts, strings.TrimSpace(s[1:end]))
		s = strings.TrimSpace(s[end+1:])
	}
	if len(parts) == 0 {
		component = "core"
	} else {
		component = strings.Join(parts, "/")
	}
	return level, component, s
}

// Warnf and Errorf write through the standard log package with the level as
// the leading token SplitLine reads; a plain log.Printf line is Info.
func Warnf(format string, args ...any) {
	_ = log.Output(2, string(Warn)+": "+fmt.Sprintf(format, args...))
}

func Errorf(format string, args ...any) {
	_ = log.Output(2, string(Error)+": "+fmt.Sprintf(format, args...))
}

var severityTokens = map[string]Level{
	"trace":   Debug,
	"debug":   Debug,
	"info":    Info,
	"warn":    Warn,
	"warning": Warn,
	"error":   Error,
	"fatal":   Fatal,
	"panic":   Fatal,
}

// Access from an xray access-log line (caller maps into conninspect.Record).
type Access struct {
	Src      string
	Status   string // accepted | rejected
	Network  string
	Host     string // domain or IP the client asked for
	Port     string
	Inbound  string
	Outbound string
}

// xray's dispatcher writes the detour as "in -> out", "in ==> out" or
// "in >> out" by how the route was picked, or as the outbound alone.
var detourSeparators = []string{" -> ", " ==> ", " >> "}

// ParseAccess: "from <net:src:port> accepted|rejected <net:host:port> [detour]".
// ok=false for non-access lines.
func ParseAccess(line string) (Access, bool) {
	s := strings.TrimSpace(line)
	if !strings.HasPrefix(s, "from ") {
		return Access{}, false
	}
	var a Access
	if i := strings.Index(s, " ["); i >= 0 {
		if j := strings.Index(s[i:], "]"); j > 1 {
			a.Inbound, a.Outbound = splitDetour(s[i+2 : i+j])
			s = strings.TrimSpace(s[:i])
		}
	}
	f := strings.Fields(s)
	if len(f) < 3 {
		return Access{}, false
	}
	a.Status = f[2]
	if a.Status != "accepted" && a.Status != "rejected" {
		return Access{}, false
	}
	_, sh, sp := splitDest(f[1])
	a.Src = sh
	if sp != "" {
		a.Src = net.JoinHostPort(sh, sp)
	}
	if len(f) >= 4 {
		a.Network, a.Host, a.Port = splitDest(f[3])
	}
	return a, true
}

func splitDetour(detour string) (inbound, outbound string) {
	for _, sep := range detourSeparators {
		if k := strings.Index(detour, sep); k >= 0 {
			return strings.TrimSpace(detour[:k]), strings.TrimSpace(detour[k+len(sep):])
		}
	}
	return "", strings.TrimSpace(detour)
}

// splitDest breaks a net.Destination string ("tcp:host:port", "udp:[v6]:port",
// or a bare "host:port") into its parts. The network prefix is only recognized
// for tcp/udp so an IPv6 literal without a scheme isn't mis-split.
func splitDest(d string) (network, host, port string) {
	rest := d
	if i := strings.Index(d, ":"); i > 0 {
		if head := d[:i]; head == "tcp" || head == "udp" {
			network = head
			rest = d[i+1:]
		}
	}
	if h, p, err := net.SplitHostPort(rest); err == nil {
		return network, h, p
	}
	return network, rest, ""
}

func BuildJSON(level Level, component, message string) string {
	entry := map[string]string{
		"ts":        time.Now().UTC().Format(time.RFC3339Nano),
		"level":     string(level),
		"component": component,
		"message":   message,
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return message
	}
	return string(b)
}
