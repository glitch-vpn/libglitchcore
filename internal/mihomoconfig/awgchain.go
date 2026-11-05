package mihomoconfig

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/metacubex/amneziawg-go/device_v1/awg"
)

// maxJunkPacketCount caps Jc: each junk packet is one more datagram before
// every handshake. Neither amneziawg-go nor its docs set a maximum, so 128 is
// this core's own ceiling, far above the 4-12 the projects recommend.
const maxJunkPacketCount = 128

// maxJunkPacketSize caps Jmax. It is the ceiling the AmneziaWG documentation
// recommends, not a limit amneziawg-go enforces.
const maxJunkPacketSize = 1280

// maxItimeSeconds caps Itime, which the legacy device multiplies into a
// time.Duration of nanoseconds; a day is far past any real interval and far
// below the overflow.
const maxItimeSeconds = 86400

// maxLegacyTagSize bounds a size argument of a tag in the legacy device, which
// refuses above it.
const maxLegacyTagSize = 1000

// maxChainWireSize bounds what a chain's fixed-size tags add up to, and the
// size argument of one tag on the 3.x device, which sets none: a UDP datagram
// holds no more, and a larger size is allocated before it fails.
const maxChainWireSize = 65535

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

// chainSize reads a size argument no larger than limit.
func chainSize(tag chainTag, limit int) (int, error) {
	n, err := strconv.Atoi(tag.param)
	if err != nil || n < 0 || n > limit {
		return 0, fmt.Errorf("<%s %s>: want a size from 0 to %d", tag.name, tag.param, limit)
	}
	return n, nil
}

// chainBytes is how many bytes a <b> argument holds, once chainHex passed it.
func chainBytes(tag chainTag) int {
	digits := strings.TrimPrefix(strings.TrimPrefix(tag.param, "0x"), "0X")
	return (len(digits) + 1) / 2
}

func checkChainWireSize(total int) error {
	if total > maxChainWireSize {
		return fmt.Errorf("fixed-size tags add up to %d bytes, more than a datagram holds (%d)", total, maxChainWireSize)
	}
	return nil
}

// chainHex reads a <b> argument the way the device does. The legacy device
// wants 0x or 0X, pads an odd count with a leading zero and takes no bytes at
// all; the 3.x device trims a lowercase 0x if there is one, and wants a whole,
// non-empty byte string.
func chainHex(tag chainTag, legacy bool) error {
	digits := tag.param
	if legacy {
		if !strings.HasPrefix(digits, "0x") && !strings.HasPrefix(digits, "0X") {
			return fmt.Errorf("<b %s>: want hex starting 0x", tag.param)
		}
		digits = digits[2:]
		if len(digits)%2 != 0 {
			digits = "0" + digits
		}
	} else {
		digits = strings.TrimPrefix(digits, "0x")
		if digits == "" {
			return fmt.Errorf("<b %s>: no bytes", tag.param)
		}
		if len(digits)%2 != 0 {
			return fmt.Errorf("<b %s>: odd count of hex digits", tag.param)
		}
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
	total := 0
	for _, tag := range tags {
		var n int
		switch tag.name {
		case "b":
			err = chainHex(tag, true)
			n = chainBytes(tag)
		case "c", "t":
			n = 8
			if tag.param != "" {
				err = fmt.Errorf("<%s> takes no argument", tag.name)
			} else if seen[tag.name] {
				err = fmt.Errorf("<%s> may appear once", tag.name)
			}
			seen[tag.name] = true
		case "r", "rc", "rd":
			n, err = chainSize(tag, maxLegacyTagSize)
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
		total += n
	}
	if err := checkChainWireSize(total); err != nil {
		return err
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
	total := 0
	for _, tag := range tags {
		var n int
		switch tag.name {
		case "b":
			err = chainHex(tag, false)
			n = chainBytes(tag)
		case "t", "d", "ds":
			if tag.param != "" {
				err = fmt.Errorf("<%s> takes no argument", tag.name)
			}
			if tag.name == "t" {
				n = 4
			}
		case "r", "rc", "rd", "dz":
			n, err = chainSize(tag, maxChainWireSize)
		default:
			err = fmt.Errorf("unknown tag <%s>", tag.name)
		}
		if err != nil {
			return err
		}
		total += n
	}
	return checkChainWireSize(total)
}

// checkJunkSizes holds Jmin and Jmax to 0 <= Jmin <= Jmax <= maxJunkPacketSize.
func checkJunkSizes(opt map[string]any) error {
	jmin, hasMin := opt["jmin"].(int)
	jmax, hasMax := opt["jmax"].(int)
	if jmin < 0 || jmax < 0 || jmax > maxJunkPacketSize {
		return fmt.Errorf("awg jmin/jmax: want 0 to %d", maxJunkPacketSize)
	}
	if hasMin && hasMax && jmin > jmax {
		return errors.New("awg jmin: exceeds jmax")
	}
	return nil
}
