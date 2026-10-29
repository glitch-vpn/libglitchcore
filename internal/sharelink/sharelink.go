// Package sharelink parses URL-shaped share links without letting their
// credentials into an error. It imports no engine.
package sharelink

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
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

var base64Userinfo = regexp.MustCompile(`^[A-Za-z0-9+/_-]+={0,2}$`)

// readsAsBase64Userinfo reports whether a userinfo holding a '/' or an '@' as
// written is v2rayNG's base64 one: bare base64 that decodes, for a proxy link,
// to a printable login holding a ':', and for a WireGuard link to a 32-byte
// key. Another scheme takes no such userinfo.
func readsAsBase64Userinfo(scheme, raw string) bool {
	if !base64Userinfo.MatchString(raw) {
		return false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		b, err := enc.DecodeString(raw)
		if err != nil {
			continue
		}
		switch scheme {
		case "socks", "socks5", "socks5h", "http", "https":
			login := string(b)
			return utf8.ValidString(login) && strings.Contains(login, ":") && !strings.ContainsFunc(login, unicode.IsControl)
		case "wireguard", "wg":
			return len(b) == 32
		}
		return false
	}
	return false
}

// Split cuts a link as follows, and the app reads links the same way:
//   - the fragment starts at the first '#', and the query at the first '?'
//     before it;
//   - the userinfo runs to the last '@' before the query. When it holds a '/'
//     or an '@' as written, it must be bare base64 (letters, digits, '+', '/',
//     '-', '_', then up to two '=') that decodes, in the standard or the URL
//     alphabet, padded or not, to a valid UTF-8 login with a ':' and no
//     control character for socks, socks5, socks5h, http and https, and to
//     exactly 32 bytes for wireguard and wg; any other link holding one is
//     refused. Otherwise "user:pass@good:80/@evil:80" or "goodexample/@evil:80"
//     would dial evil where a URL parser shows good;
//   - the host and port run to the first '/' after it, and the path is dropped.
//
// A control character fails the link, as written or once the userinfo, the
// fragment or a query value is percent-decoded: a caller may write a part
// into a line-based config or a log line. logfmt's scrubber also takes the
// userinfo to the last '@'. Errors carry no part of the link.
func Split(link, protocol string) (Parts, error) {
	link = strings.TrimSpace(link)
	malformed := fmt.Errorf("%s: malformed link", protocol)
	scheme, rest, ok := strings.Cut(link, "://")
	if !ok || strings.ContainsFunc(link, unicode.IsControl) {
		return Parts{}, malformed
	}
	rest, fragment, _ := strings.Cut(rest, "#")
	rest, rawQuery, _ := strings.Cut(rest, "?")
	p := Parts{Scheme: strings.ToLower(scheme), RawQuery: rawQuery}
	var err error
	if p.Fragment, err = url.PathUnescape(fragment); err != nil || strings.ContainsFunc(p.Fragment, unicode.IsControl) {
		return Parts{}, malformed
	}
	if query, err := url.QueryUnescape(rawQuery); err != nil || strings.ContainsFunc(query, unicode.IsControl) {
		return Parts{}, malformed
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		raw := rest[:at]
		if strings.ContainsAny(raw, "/@") && !readsAsBase64Userinfo(p.Scheme, raw) {
			return Parts{}, fmt.Errorf("%s: the server address is ambiguous; escape '/' and '@' in the login", protocol)
		}
		if p.UserInfo, err = url.PathUnescape(raw); err != nil || strings.ContainsFunc(p.UserInfo, unicode.IsControl) {
			return Parts{}, malformed
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
