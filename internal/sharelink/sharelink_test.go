package sharelink

import (
	"net/url"
	"strings"
	"testing"
)

func TestParseURL_ErrorKeepsTheLinkOut(t *testing.T) {
	for _, link := range []string{
		"tuic://uuid:Pa55word#rest@h.example.com:443",
		"tuic://uuid:Pa55/word@h.example.com:443",
		"tuic://uuid:Pa55?word@h.example.com:443",
		"tuic://uuid:Pa55word",
	} {
		_, err := ParseURL(link, "tuic")
		if err == nil {
			t.Fatalf("%q: want an error", link)
		}
		if strings.Contains(err.Error(), "Pa55") || strings.Contains(err.Error(), "uuid") {
			t.Fatalf("%q: error carries the link: %v", link, err)
		}
	}
}

func TestSkipsVerification(t *testing.T) {
	for query, want := range map[string]bool{
		"allowInsecure=1":     true,
		"insecure=TRUE":       true,
		"allow_insecure=+1+":  true,
		"allowInsecure=0":     false,
		"insecure=false":      false,
		"pcs=00&security=tls": false,
	} {
		q, err := url.ParseQuery(query)
		if err != nil {
			t.Fatal(err)
		}
		if got := SkipsVerification(q); got != want {
			t.Errorf("%s: SkipsVerification = %v, want %v", query, got, want)
		}
	}
}
