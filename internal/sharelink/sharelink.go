// Package sharelink parses URL-shaped share links without letting their
// credentials into an error. It imports no engine.
package sharelink

import (
	"fmt"
	"net/url"
	"strings"
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
