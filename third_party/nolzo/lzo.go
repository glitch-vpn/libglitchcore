// Package lzo stands in for github.com/rasky/go-lzo, which is GPL-2.0 only and
// cannot link into a GPL-3.0 combined work. It has the one function mihomo's
// transport/openvpn calls, and that function refuses: a server's compressed
// packets fail to read, uncompressed framing never reaches it.
package lzo

import (
	"errors"
	"io"
)

// ErrNotSupported is what every decompression returns.
var ErrNotSupported = errors.New("LZO compression is not supported")

// Decompress1X refuses to decompress.
func Decompress1X(r io.Reader, inLen int, outLen int) ([]byte, error) {
	return nil, ErrNotSupported
}
