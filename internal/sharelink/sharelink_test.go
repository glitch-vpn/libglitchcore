package sharelink

import (
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
