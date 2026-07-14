// Package logfmt parses and formats core log lines (xray/tun2socks).
package logfmt

import (
	"encoding/json"
	"net"
	"strings"
	"time"
)

// ShouldEmit reports whether a message passes the given verbosity level:
//
//	lvl <  0 -> nothing (logging fully off - the default)
//	lvl == 0 -> only error/failed/panic/fatal messages
//	lvl == 1 -> everything except debug/trace noise
//	lvl >= 2 -> everything
func ShouldEmit(lvl int32, s string) bool {
	if lvl < 0 {
		return false
	}
	if lvl >= 2 {
		return true
	}
	lower := strings.ToLower(s)
	if lvl <= 0 {
		return strings.Contains(lower, "error") || strings.Contains(lower, "failed") || strings.Contains(lower, "panic") || strings.Contains(lower, "fatal")
	}
	if strings.Contains(lower, "debug") || strings.Contains(lower, "trace") {
		return false
	}
	return true
}

// Component extracts leading [COMP]...[COMP] prefixes as a "/"-joined component
// name and returns the remaining message. A leading severity token (e.g.
// "DEBUG:", "INFO:") is stripped first. Defaults to "core" when no bracketed
// component is present.
func Component(raw string) (component string, msg string) {
	s := strings.TrimSpace(raw)

	for {
		if idx := strings.Index(s, ":"); idx > 0 {
			head := strings.TrimSpace(s[:idx])
			l := strings.ToLower(head)
			if l == "debug" || l == "info" || l == "warn" || l == "warning" || l == "error" || l == "fatal" || l == "panic" || l == "trace" {
				s = strings.TrimSpace(s[idx+1:])
				continue
			}
		}
		break
	}

	var parts []string
	if !strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "["); i >= 0 {
			tail := strings.TrimSpace(s[i:])
			s = tail
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
	return component, s
}

func InferLevel(msg string) string {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, " fatal") || strings.HasPrefix(m, "fatal"):
		return "fatal"
	case strings.Contains(m, " error") || strings.HasPrefix(m, "error"):
		return "error"
	case strings.Contains(m, " warn") || strings.HasPrefix(m, "warn"):
		return "warn"
	case strings.Contains(m, " debug") || strings.HasPrefix(m, "debug"):
		return "debug"
	case strings.Contains(m, " trace") || strings.HasPrefix(m, "trace"):
		return "trace"
	default:
		return "info"
	}
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

// ParseAccess: "from <net:src:port> accepted|rejected <net:host:port> [in -> out]".
// ok=false for non-access lines.
func ParseAccess(line string) (Access, bool) {
	s := strings.TrimSpace(line)
	if !strings.HasPrefix(s, "from ") {
		return Access{}, false
	}
	var a Access
	if i := strings.Index(s, " ["); i >= 0 {
		if j := strings.Index(s[i:], "]"); j > 1 {
			detour := s[i+2 : i+j]
			if k := strings.Index(detour, " -> "); k >= 0 {
				a.Inbound = strings.TrimSpace(detour[:k])
				a.Outbound = strings.TrimSpace(detour[k+4:])
			} else {
				a.Outbound = strings.TrimSpace(detour)
			}
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

func BuildJSON(level, component, message string) string {
	entry := map[string]string{
		"ts":        time.Now().UTC().Format(time.RFC3339Nano),
		"level":     level,
		"component": component,
		"message":   message,
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return message
	}
	return string(b)
}
