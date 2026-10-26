package vlessencryption

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func x25519Key(t *testing.T) string {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
}

func mlkemKey(t *testing.T) string {
	t.Helper()
	private, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(private.EncapsulationKey().Bytes())
}

func TestNormalize_AbsentAndNoneAreNone(t *testing.T) {
	for _, raw := range []string{"", "  ", "none", "None"} {
		got, err := Normalize(raw)
		if err != nil || got != None {
			t.Errorf("Normalize(%q) = %q, %v; want none", raw, got, err)
		}
	}
}

func TestNormalize_AcceptsTheForms(t *testing.T) {
	x, pq := x25519Key(t), mlkemKey(t)
	for name, value := range map[string]string{
		"x25519_native_0rtt": "mlkem768x25519plus.native.0rtt." + x,
		"mlkem_1rtt":         "mlkem768x25519plus.native.1rtt." + pq,
		"xorpub":             "mlkem768x25519plus.xorpub.0rtt." + x,
		"random_two_keys":    "mlkem768x25519plus.random.0rtt." + x + "." + pq,
		"empty_padding":      "mlkem768x25519plus.native.0rtt.." + x,
		"padding":            "mlkem768x25519plus.native.0rtt.100-111-1111.75-0-111.50-0-3333." + x,
	} {
		got, err := Normalize(value)
		if err != nil || got != value {
			t.Errorf("%s: Normalize = %q, %v; want the value unchanged", name, got, err)
		}
	}
}

func TestNormalize_RefusesWithAReasonThatDoesNotQuoteTheValue(t *testing.T) {
	x := x25519Key(t)
	short := base64.RawURLEncoding.EncodeToString(make([]byte, 31))
	outOfRange := make([]byte, 1184)
	for i := range outOfRange {
		outOfRange[i] = 0xff
	}
	badPQ := base64.RawURLEncoding.EncodeToString(outOfRange)
	for name, value := range map[string]string{
		"aes":             "aes-128-gcm",
		"wrong_scheme":    "mlkem768x25519plus2.native.0rtt." + x,
		"no_key":          "mlkem768x25519plus.native.0rtt",
		"only_padding":    "mlkem768x25519plus.native.0rtt.100-111-1111",
		"bad_mode":        "mlkem768x25519plus.quic.0rtt." + x,
		"bad_ticket":      "mlkem768x25519plus.native.2rtt." + x,
		"short_key":       "mlkem768x25519plus.native.0rtt." + short,
		"not_base64":      "mlkem768x25519plus.native.0rtt." + strings.Repeat("!", 43),
		"invalid_mlkem":   "mlkem768x25519plus.native.0rtt." + badPQ,
		"padding_after":   "mlkem768x25519plus.native.0rtt." + x + ".100-111-1111",
		"padding_shape":   "mlkem768x25519plus.native.0rtt.100-111." + x,
		"padding_chance":  "mlkem768x25519plus.native.0rtt.99-111-1111." + x,
		"padding_number":  "mlkem768x25519plus.native.0rtt.a-b-c." + x,
		"padding_small":   "mlkem768x25519plus.native.0rtt.99-111-1111." + x,
		"padding_too_big": "mlkem768x25519plus.native.0rtt.100-70000-70000." + x,
	} {
		_, err := Normalize(value)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.HasPrefix(err.Error(), "vless encryption:") || strings.Contains(err.Error(), x) || strings.Contains(err.Error(), "mlkem768x25519plus.") {
			t.Errorf("%s: error %q is unclear or quotes the value", name, err)
		}
	}
}
