// Package loopbackauth makes the per-session credentials that gate the
// loopback listeners the core opens for itself.
package loopbackauth

import (
	"crypto/rand"
	"encoding/base64"
)

type Credentials struct {
	User string
	Pass string
}

// New draws fresh credentials; both halves are URL-safe, so they ride in a
// socks5:// URL unescaped.
func New() Credentials {
	return Credentials{User: token(12), Pass: token(32)}
}

func (c Credentials) Set() bool { return c.User != "" && c.Pass != "" }

func token(byteLen int) string {
	buf := make([]byte, byteLen)
	_, _ = rand.Read(buf) // crypto/rand.Read never returns an error; it crashes the program instead
	return base64.RawURLEncoding.EncodeToString(buf)
}
