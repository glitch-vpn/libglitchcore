// Package vlessencryption checks the "encryption" value of a vless:// link,
// the post-quantum form xray and mihomo both accept:
//
//	mlkem768x25519plus.<native|xorpub|random>.<0rtt|1rtt>[.<padding>...].<key>[.<key>...]
//
// A padding is "chance-min-max" and shorter than 20 characters, an empty one
// meaning none; a key is
// base64url without padding, 32 bytes (X25519) or 1184 bytes (ML-KEM-768).
// The engines read the same string, so the core refuses a value either would
// refuse instead of letting the engine fail on start. Errors never quote the
// value.
package vlessencryption

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// None is the value of a link that names no encryption.
	None = "none"

	scheme       = "mlkem768x25519plus"
	paddingLimit = 20
	// The engines refuse a padding that sums past this.
	maxTotalPadding = 18 + 65535
)

// Normalize returns None for an empty or "none" value, the value itself when
// it is a form both engines run, and an error naming what is wrong otherwise.
func Normalize(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || strings.EqualFold(value, None) {
		return None, nil
	}
	parts := strings.Split(value, ".")
	if len(parts) < 4 || parts[0] != scheme {
		return "", errors.New("vless encryption: not a mlkem768x25519plus value")
	}
	switch parts[1] {
	case "native", "xorpub", "random":
	default:
		return "", errors.New("vless encryption: the second field must be native, xorpub or random")
	}
	switch parts[2] {
	case "0rtt", "1rtt":
	default:
		return "", errors.New("vless encryption: the third field must be 0rtt or 1rtt")
	}

	var paddings []string
	keys := 0
	for _, field := range parts[3:] {
		if field == "" {
			continue
		}
		if len(field) < paddingLimit {
			if keys > 0 {
				return "", errors.New("vless encryption: padding must come before the keys")
			}
			paddings = append(paddings, field)
			continue
		}
		if err := checkKey(field); err != nil {
			return "", err
		}
		keys++
	}
	if keys == 0 {
		return "", errors.New("vless encryption: no key")
	}
	if err := checkPadding(paddings); err != nil {
		return "", err
	}
	return value, nil
}

func checkKey(field string) error {
	key, err := base64.RawURLEncoding.DecodeString(field)
	if err != nil {
		return errors.New("vless encryption: a key is not base64url")
	}
	switch len(key) {
	case 32:
		if _, err := ecdh.X25519().NewPublicKey(key); err != nil {
			return errors.New("vless encryption: an X25519 key is invalid")
		}
	case 1184:
		if _, err := mlkem.NewEncapsulationKey768(key); err != nil {
			return errors.New("vless encryption: an ML-KEM-768 key is invalid")
		}
	default:
		return errors.New("vless encryption: a key is neither 32 nor 1184 bytes")
	}
	return nil
}

// checkPadding applies the engines' rules: segments of "chance-min-max"
// alternating padding and gap, the first with chance 100 and both lengths at
// least 35.
func checkPadding(paddings []string) error {
	if len(paddings) == 0 {
		return nil
	}
	total := 0
	for index, segment := range paddings {
		fields := strings.Split(segment, "-")
		if len(fields) < 3 || fields[0] == "" || fields[1] == "" || fields[2] == "" {
			return errors.New("vless encryption: a padding is not chance-min-max")
		}
		var numbers [3]int
		for i := range numbers {
			n, err := strconv.Atoi(fields[i])
			if err != nil {
				return errors.New("vless encryption: a padding has a field that is not a number")
			}
			numbers[i] = n
		}
		if index == 0 && (numbers[0] < 100 || numbers[1] < 35 || numbers[2] < 35) {
			return errors.New("vless encryption: the first padding needs chance 100 and lengths of at least 35")
		}
		if index%2 == 0 {
			total += max(numbers[1], numbers[2])
		}
	}
	if total > maxTotalPadding {
		return fmt.Errorf("vless encryption: the padding totals more than %d", maxTotalPadding)
	}
	return nil
}
