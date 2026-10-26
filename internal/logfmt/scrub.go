package logfmt

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const (
	redacted   = "[redacted]"
	secretKeys = `password|passwd|pwd|pass|psk|pre[_-]?shared[_-]?key|private[_-]?key|public[_-]?key|pbk|secret|token|auth[_-]?str|auth|obfs[_-]?password|encryption|decryption|uuid|short[_-]?id|sid`
)

var (
	// A URL inside Go's %q quoting (url.Parse's error) runs to the closing
	// quote: the characters that made it unparsable, a space in a password
	// say, would end the unquoted match early.
	quotedURLPattern = regexp.MustCompile(`(?i)"\b([a-z][a-z0-9+.-]*://(?:[^"\\]|\\.)*)"`)
	urlPattern       = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s"<>\x60]+`)
	// "key=value" loses any value; "key: value" only a quoted one, so an error
	// such as "private_key: key is neither hex nor base64" keeps its words -
	// unless the key itself is quoted, as in xray's `invalid "shortId": X`.
	secretAssignPattern    = regexp.MustCompile(`(?i)\b(` + secretKeys + `)(\s*=\s*)(\[redacted\]|"[^"]*"|'[^']*'|[^\s,;&"'})\]]+)`)
	secretQuotedPattern    = regexp.MustCompile(`(?i)\b(` + secretKeys + `)("?\s*:\s*)(\[redacted\]|"[^"]*"|'[^']*')`)
	secretQuotedKeyPattern = regexp.MustCompile(`(?i)"(` + secretKeys + `)("\s*:\s*)(\[redacted\]|[^\s,;&"'})\]]+)`)
	// A VLESS encryption value carries the server's public keys wherever an
	// engine's message quotes it.
	vlessEncryptionPattern = regexp.MustCompile(`mlkem768x25519plus(?:\.[A-Za-z0-9_-]*)+`)
	uuidPattern            = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	// Key material and tokens: base64, base64url or hex, at least 32 long.
	tokenPattern = regexp.MustCompile(`[A-Za-z0-9+/_-]{32,}={0,2}`)
)

// Share-link schemes carry the credential anywhere in the link (vmess and ss
// encode it whole), so such a link is dropped entire.
var shareLinkSchemes = map[string]bool{
	"vless": true, "vmess": true, "trojan": true, "ss": true, "ssr": true,
	"hysteria": true, "hysteria2": true, "hy2": true, "tuic": true,
	"anytls": true, "awg": true, "wireguard": true, "wg": true,
	"juicity": true, "mieru": true, "snell": true, "naive": true, "ssh": true,
}

// Scrub removes credentials from a line: whole share links, the userinfo,
// path, query and fragment of any other URL, values of credential-named
// fields, UUIDs, and runs that look like key material or tokens. Scrubbing a
// scrubbed line changes nothing.
func Scrub(s string) string {
	s = quotedURLPattern.ReplaceAllStringFunc(s, func(quoted string) string {
		return `"` + scrubURL(quoted[1:len(quoted)-1]) + `"`
	})
	s = urlPattern.ReplaceAllStringFunc(s, scrubURL)
	s = secretAssignPattern.ReplaceAllString(s, "${1}${2}"+redacted)
	s = secretQuotedPattern.ReplaceAllString(s, "${1}${2}"+redacted)
	s = secretQuotedKeyPattern.ReplaceAllString(s, `"${1}${2}`+redacted)
	s = vlessEncryptionPattern.ReplaceAllString(s, redacted)
	s = uuidPattern.ReplaceAllString(s, redacted)
	return tokenPattern.ReplaceAllStringFunc(s, func(run string) string {
		if looksLikeKeyMaterial(strings.TrimRight(run, "=")) {
			return redacted
		}
		return run
	})
}

// WithoutURL drops the URL a url.Parse error quotes: for a share link, that
// URL is the credential.
func WithoutURL(err error) error {
	var parseErr *url.Error
	if errors.As(err, &parseErr) {
		return fmt.Errorf("%s: %w", parseErr.Op, parseErr.Err)
	}
	return err
}

func scrubURL(u string) string {
	i := strings.Index(u, "://")
	scheme, rest := u[:i], u[i+3:]
	if shareLinkSchemes[strings.ToLower(scheme)] {
		return scheme + "://" + redacted
	}
	authority, tail := rest, ""
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		authority, tail = rest[:end], rest[end:]
	}
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = redacted + "@" + authority[at+1:]
	}
	if tail != "" && tail != "/" {
		tail = tail[:1] + redacted
	}
	return scheme + "://" + authority + tail
}

// Hex of that length is a key or a digest; anything else must mix upper case,
// lower case and digits, which a path or an identifier rarely does.
func looksLikeKeyMaterial(run string) bool {
	var upper, lower, digit, nonHex bool
	for _, r := range run {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
			nonHex = nonHex || r > 'F'
		case r >= 'a' && r <= 'z':
			lower = true
			nonHex = nonHex || r > 'f'
		case r >= '0' && r <= '9':
			digit = true
		default:
			nonHex = true
		}
	}
	if !nonHex && !(upper && lower) {
		return true
	}
	return upper && lower && digit
}
