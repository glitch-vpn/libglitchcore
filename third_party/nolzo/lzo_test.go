package lzo

import (
	"bytes"
	"errors"
	"testing"
)

func TestDecompress1XRefuses(t *testing.T) {
	out, err := Decompress1X(bytes.NewReader([]byte{0x01, 0x02, 0x03}), 3, 0)
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("err = %v, want ErrNotSupported", err)
	}
	if out != nil {
		t.Fatalf("out = %v, want nil", out)
	}
}
