// Package proxylink reads socks and http proxy links: socks://, socks5://,
// socks5h://, http:// and https://. The engines' builders and serverinfo read
// a link through it, so they agree on what it says; it imports no engine.
package proxylink

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/glitch-vpn/libglitchcore/internal/awgconfig"
	"github.com/glitch-vpn/libglitchcore/internal/sharelink"
)

const (
	Socks = "socks"
	HTTP  = "http"
)

// socks4:// is not here: no engine has a SOCKS4 outbound, and reading it as
// SOCKS5 would talk a protocol the server does not speak.
var schemes = map[string]string{
	"socks": Socks, "socks5": Socks, "socks5h": Socks,
	"http": HTTP, "https": HTTP,
}

type Link struct {
	Protocol string // socks | http
	TLS      bool   // https://
	Host     string
	Port     int
	Username string
	Password string
	SNI      string
	Pin      string // pcs, the certificate's hex SHA-256
	Name     string
}

// Protocol is the proxy a link's scheme names, "" for any other link.
func Protocol(link string) string {
	scheme, _, ok := strings.Cut(strings.ToLower(strings.TrimSpace(link)), "://")
	if !ok {
		return ""
	}
	return schemes[scheme]
}

func IsLink(link string) bool {
	return Protocol(link) != ""
}

// Parse needs an explicit port: a proxy has no port its scheme implies. It
// fills the server's name, host and port even when it refuses the link, so a
// caller that only names the server can still use the result.
func Parse(link string) (Link, error) {
	protocol := Protocol(link)
	if protocol == "" {
		return Link{}, errors.New("not a socks or http proxy link")
	}
	p, err := sharelink.Split(link, protocol)
	if err != nil {
		return Link{}, err
	}
	server := Link{
		Protocol: protocol,
		TLS:      p.Scheme == "https",
		Host:     p.Host,
		Port:     p.Port,
		Name:     strings.TrimSpace(strings.ReplaceAll(p.Fragment, "+", " ")),
	}
	if p.Port == 0 {
		return server, fmt.Errorf("%s: missing port", protocol)
	}
	l := server
	if l.Username, l.Password, err = credentials(p.UserInfo, protocol); err != nil {
		return server, err
	}
	if !l.TLS {
		return l, nil
	}
	q, err := url.ParseQuery(p.RawQuery)
	if err != nil {
		return server, fmt.Errorf("%s: malformed query", protocol)
	}
	if sharelink.SkipsVerification(q) {
		return server, errors.New("https: skipping certificate verification is not supported; pin the certificate with pcs")
	}
	l.SNI = strings.TrimSpace(q.Get("sni"))
	l.Pin = strings.TrimSpace(q.Get("pcs"))
	return l, nil
}

// credentials reads the userinfo as user:pass when it holds a colon, and as
// the base64 of user:pass, the form v2rayN and v2rayNG write, when it does not.
func credentials(userinfo, protocol string) (user, pass string, err error) {
	if userinfo == "" {
		return "", "", nil
	}
	if !strings.Contains(userinfo, ":") {
		decoded, err := awgconfig.DecodeBase64Flexible(userinfo)
		if err != nil || !strings.Contains(decoded, ":") {
			return "", "", fmt.Errorf("%s: the userinfo is neither user:pass nor its base64", protocol)
		}
		if !utf8.ValidString(decoded) || strings.ContainsFunc(decoded, unicode.IsControl) {
			return "", "", fmt.Errorf("%s: the decoded userinfo holds a control character or invalid text", protocol)
		}
		userinfo = decoded
	}
	user, pass, _ = strings.Cut(userinfo, ":")
	return user, pass, nil
}
