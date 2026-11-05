package mihomoconfig

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/metacubex/amneziawg-go/device_v1/awg"
)

// maxChainTagSize bounds a size argument of a tag chain; amneziawg-go's legacy
// device refuses above it, its 3.x device does not.
const maxChainTagSize = 1000

type chainTag struct{ name, param string }

// splitChain reads a value that is nothing but tags, "<name>" or "<name param>".
func splitChain(value string) ([]chainTag, error) {
	rest := strings.TrimSpace(value)
	var tags []chainTag
	for rest != "" {
		if rest[0] != '<' {
			return nil, errors.New("text outside a tag")
		}
		end := strings.IndexByte(rest, '>')
		if end < 0 {
			return nil, errors.New("tag is not closed")
		}
		fields := strings.Fields(rest[1:end])
		if len(fields) == 0 || strings.ContainsRune(rest[1:end], '<') {
			return nil, errors.New("empty or malformed tag")
		}
		if len(fields) > 2 {
			return nil, fmt.Errorf("tag <%s> has more than one argument", fields[0])
		}
		tag := chainTag{name: fields[0]}
		if len(fields) == 2 {
			tag.param = fields[1]
		}
		tags = append(tags, tag)
		rest = strings.TrimSpace(rest[end+1:])
	}
	if len(tags) == 0 {
		return nil, errors.New("no tag")
	}
	return tags, nil
}

func chainSize(tag chainTag) error {
	n, err := strconv.Atoi(tag.param)
	if err != nil || n < 0 || n > maxChainTagSize {
		return fmt.Errorf("<%s %s>: want a size from 0 to %d", tag.name, tag.param, maxChainTagSize)
	}
	return nil
}

func chainHex(tag chainTag, trimPrefix bool) error {
	digits := tag.param
	if trimPrefix {
		digits = strings.TrimPrefix(strings.TrimPrefix(digits, "0x"), "0X")
	} else if !strings.HasPrefix(digits, "0x") && !strings.HasPrefix(digits, "0X") {
		return fmt.Errorf("<b %s>: want hex starting 0x", tag.param)
	} else {
		digits = digits[2:]
	}
	if digits == "" {
		return fmt.Errorf("<b %s>: no bytes", tag.param)
	}
	if len(digits)%2 != 0 && trimPrefix {
		return fmt.Errorf("<b %s>: odd count of hex digits", tag.param)
	}
	if len(digits)%2 != 0 {
		digits = "0" + digits
	}
	if _, err := hex.DecodeString(digits); err != nil {
		return fmt.Errorf("<b %s>: %w", tag.param, err)
	}
	return nil
}

// checkLegacyChain holds a chain to what amneziawg-go's legacy device builds
// a packet from (I1-I5, J1-J3): b, c, t, r, rc, rd, wt. Its own tag parser
// indexes a failed match and panics on a tag with no name, so it only ever
// sees a chain that already passed.
func checkLegacyChain(value string) error {
	tags, err := splitChain(value)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, tag := range tags {
		switch tag.name {
		case "b":
			err = chainHex(tag, false)
		case "c", "t":
			if tag.param != "" {
				err = fmt.Errorf("<%s> takes no argument", tag.name)
			} else if seen[tag.name] {
				err = fmt.Errorf("<%s> may appear once", tag.name)
			}
			seen[tag.name] = true
		case "r", "rc", "rd":
			err = chainSize(tag)
		case "wt":
			if n, convErr := strconv.Atoi(tag.param); convErr != nil || n < 0 || n > 5000 {
				err = fmt.Errorf("<wt %s>: want milliseconds from 0 to 5000", tag.param)
			}
		default:
			err = fmt.Errorf("unknown tag <%s>", tag.name)
		}
		if err != nil {
			return err
		}
	}
	return parseLegacyChain(value)
}

// parseLegacyChain asks the device's own parser, so a grammar rule the check
// above lacks is refused here and never reaches a running session.
func parseLegacyChain(value string) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("malformed tag chain")
		}
	}()
	_, err = awg.ParseTagJunkGenerator("i1", value)
	return err
}

// checkV3Chain holds a chain to amneziawg-go's 3.x obfuscation tags: b, t, d,
// ds, dz, r, rc, rd. The device ignores text between tags and reads a chain
// with no tag as no packet; both are a config that does not say what it does.
func checkV3Chain(value string) error {
	tags, err := splitChain(value)
	if err != nil {
		return err
	}
	for _, tag := range tags {
		switch tag.name {
		case "b":
			err = chainHex(tag, true)
		case "t", "d", "ds":
			if tag.param != "" {
				err = fmt.Errorf("<%s> takes no argument", tag.name)
			}
		case "r", "rc", "rd", "dz":
			err = chainSize(tag)
		default:
			err = fmt.Errorf("unknown tag <%s>", tag.name)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
