// Package sharelink parses URL-shaped share links without letting their
// credentials into an error. It imports no engine.
package sharelink

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// ParseURL fails with a fixed message: url.Parse quotes its whole input,
// and even its inner error quotes part of the authority, which in a
// malformed link can be the password.
func ParseURL(link, protocol string) (*url.URL, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("%s: malformed link", protocol)
	}
	return u, nil
}

// Parts is a share link cut by hand. UserInfo and Fragment are
// percent-decoded with '+' kept, as a base64 credential needs.
type Parts struct {
	Scheme   string // lowercased
	UserInfo string
	Host     string // without IPv6 brackets
	Port     int    // 0 when the link names none
	RawQuery string
	Fragment string
}

// Split reads the userinfo up to the last '@' before the query, so a
// credential holding '/' or an unescaped '@' stays whole, where url.Parse
// would end the authority at the first '/'; logfmt's scrubber cuts a URL the
// same way. The path is dropped. A control character fails the link: a
// caller may write a part of it into a line-based config. Errors carry no part
// of the link.
func Split(link, protocol string) (Parts, error) {
	link = strings.TrimSpace(link)
	scheme, rest, ok := strings.Cut(link, "://")
	if !ok || strings.ContainsFunc(link, unicode.IsControl) {
		return Parts{}, fmt.Errorf("%s: malformed link", protocol)
	}
	rest, fragment, _ := strings.Cut(rest, "#")
	rest, rawQuery, _ := strings.Cut(rest, "?")
	p := Parts{Scheme: strings.ToLower(scheme), RawQuery: rawQuery}
	var err error
	if p.Fragment, err = url.PathUnescape(fragment); err != nil {
		return Parts{}, fmt.Errorf("%s: malformed link", protocol)
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		if p.UserInfo, err = url.PathUnescape(rest[:at]); err != nil {
			return Parts{}, fmt.Errorf("%s: malformed link", protocol)
		}
		rest = rest[at+1:]
	}
	hostPort, _, _ := strings.Cut(rest, "/")
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		host, port = strings.Trim(hostPort, "[]"), ""
	}
	if p.Host = host; host == "" {
		return Parts{}, fmt.Errorf("%s: missing server host", protocol)
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n <= 0 || n > 65535 {
			return Parts{}, fmt.Errorf("%s: invalid port", protocol)
		}
		p.Port = n
	}
	return p, nil
}

// SkipsVerification reports whether a link asks to skip certificate checks;
// share-link generators spell it three ways.
func SkipsVerification(q url.Values) bool {
	for _, k := range []string{"allowInsecure", "insecure", "allow_insecure"} {
		switch strings.ToLower(strings.TrimSpace(q.Get(k))) {
		case "1", "true":
			return true
		}
	}
	return false
}
