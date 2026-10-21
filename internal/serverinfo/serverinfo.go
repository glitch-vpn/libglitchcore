// Package serverinfo extracts server identity from share links for the
// ServerEvent payload. Parsing is lenient - a bad link still yields an entry,
// so indexes always align with the engine's link order.
package serverinfo

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/glitch-vpn/libglitchcore/internal/awgconfig"
)

type Server struct {
	// Position in the cleaned link list - the same order as outbound tags,
	// mihomo proxy names and pinger results.
	Index    int    `json:"index"`
	Name     string `json:"name,omitempty"` // #fragment remark, "" if none
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"` // vless | trojan | ss | hysteria2 | tuic | anytls | awg
}

// ServerEvent payload. Selected is nil while the pick is per-connection
// (xray random/roundrobin, mihomo load-balance) or unknown.
type Selection struct {
	Engine   string   `json:"engine"`
	Strategy string   `json:"strategy,omitempty"` // "" for a single link
	Total    int      `json:"total"`
	Selected *Server  `json:"selected,omitempty"`
	Servers  []Server `json:"servers,omitempty"`
}

func (s *Selection) JSON() (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// FromLinks mirrors the engines' link cleaning (trim, drop empties).
func FromLinks(links []string) []Server {
	out := make([]Server, 0, len(links))
	for _, l := range links {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		out = append(out, FromLink(l, len(out)))
	}
	return out
}

// FromLink never fails: unparseable fields stay zero.
func FromLink(link string, idx int) Server {
	link = strings.TrimSpace(link)
	s := Server{Index: idx}

	if strings.HasPrefix(strings.ToLower(link), awgconfig.LinkScheme) || strings.Contains(link, "[Interface]") {
		s.Protocol = "awg"
		s.Name = awgconfig.LinkName(link)
		if ini, err := awgconfig.NormalizeToINI(link); err == nil {
			s.Host, s.Port = awgconfig.EndpointHostPort(ini)
		}
		return s
	}

	u, err := url.Parse(link)
	if err != nil {
		return s
	}
	switch scheme := strings.ToLower(u.Scheme); scheme {
	case "hy2", "hysteria2":
		s.Protocol = "hysteria2"
	case "ss":
		s.Protocol = "ss"
	default:
		s.Protocol = scheme
	}
	// url.Parse %-decodes the fragment but keeps '+'; share-link generators
	// (v2rayN-style UrlEncode) use '+' for spaces in remarks.
	s.Name = strings.TrimSpace(strings.ReplaceAll(u.Fragment, "+", " "))

	// Legacy ss://BASE64(method:pass@host:port) keeps the address inside the
	// base64 payload - url.Parse then mistakes the payload for a hostname.
	// Same plain-form test as xrayconfig's outboundFromSS.
	if s.Protocol == "ss" && (u.User == nil || u.Hostname() == "" || u.Port() == "") {
		s.Host, s.Port = ssLegacyHostPort(link)
		return s
	}
	s.Host = u.Hostname()
	if p, perr := strconv.Atoi(u.Port()); perr == nil && p > 0 && p <= 65535 {
		s.Port = p
	} else if u.Port() == "" && defaultsTo443(s.Protocol) {
		s.Port = 443
	}
	return s
}

// The mihomo builders' portOrDefault: these links may leave the port out.
func defaultsTo443(protocol string) bool {
	return protocol == "tuic" || protocol == "anytls"
}

func ssLegacyHostPort(link string) (string, int) {
	raw := strings.TrimPrefix(link, "ss://")
	raw = strings.SplitN(raw, "#", 2)[0]
	raw = strings.SplitN(raw, "?", 2)[0]
	decoded, err := awgconfig.DecodeBase64Flexible(raw)
	if err != nil {
		return "", 0
	}
	at := strings.LastIndex(decoded, "@")
	if at < 0 || at == len(decoded)-1 {
		return "", 0
	}
	host, portStr, ok := strings.Cut(decoded[at+1:], ":")
	if !ok {
		return decoded[at+1:], 0
	}
	port, _ := strconv.Atoi(strings.TrimSpace(portStr))
	if port < 0 || port > 65535 {
		port = 0
	}
	return host, port
}
