//go:build linux

package core

import (
	"os"
	"syscall"
	"testing"
)

func TestDupTunFd_ReturnsDifferentFd(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	origFd := int(r.Fd())
	dupFd, err := dupTunFd(origFd)
	if err != nil {
		t.Fatalf("dupTunFd(%d): %v", origFd, err)
	}
	defer syscall.Close(dupFd)

	if dupFd == origFd {
		t.Errorf("dupTunFd returned same fd %d, want different", origFd)
	}
	if dupFd < 0 {
		t.Errorf("dupTunFd returned negative fd: %d", dupFd)
	}
}

func TestDupTunFd_IndependentClose(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer w.Close()

	origFd := int(r.Fd())
	dupFd, err := dupTunFd(origFd)
	if err != nil {
		t.Fatalf("dupTunFd(%d): %v", origFd, err)
	}

	if err := syscall.Close(dupFd); err != nil {
		t.Fatalf("close dup'd fd %d: %v", dupFd, err)
	}

	var stat syscall.Stat_t
	if err := syscall.Fstat(origFd, &stat); err != nil {
		t.Errorf("original fd %d invalid after closing dup: %v", origFd, err)
	}

	r.Close()
}

func TestDupTunFd_SharesFileDescription(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer w.Close()
	defer r.Close()

	origFd := int(r.Fd())
	dupFd, err := dupTunFd(origFd)
	if err != nil {
		t.Fatalf("dupTunFd(%d): %v", origFd, err)
	}
	defer syscall.Close(dupFd)

	msg := []byte("glitch")
	if _, err := w.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	n, err := syscall.Read(dupFd, buf)
	if err != nil {
		t.Fatalf("read from dup'd fd %d: %v", dupFd, err)
	}
	if string(buf[:n]) != "glitch" {
		t.Errorf("read %q from dup'd fd, want %q", string(buf[:n]), "glitch")
	}
}

func TestDupTunFd_OriginalCloseDoesNotAffectDup(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer w.Close()

	origFd := int(r.Fd())
	dupFd, err := dupTunFd(origFd)
	if err != nil {
		t.Fatalf("dupTunFd(%d): %v", origFd, err)
	}
	defer syscall.Close(dupFd)

	r.Close()

	var stat syscall.Stat_t
	if err := syscall.Fstat(dupFd, &stat); err != nil {
		t.Errorf("dup'd fd %d invalid after closing original: %v", dupFd, err)
	}

	msg := []byte("vpn")
	if _, err := w.Write(msg); err != nil {
		t.Fatalf("write after original close: %v", err)
	}
	buf := make([]byte, len(msg))
	n, err := syscall.Read(dupFd, buf)
	if err != nil {
		t.Fatalf("read from dup'd fd after original close: %v", err)
	}
	if string(buf[:n]) != "vpn" {
		t.Errorf("read %q, want %q", string(buf[:n]), "vpn")
	}
}

func TestDupTunFd_InvalidFd(t *testing.T) {
	_, err := dupTunFd(-1)
	if err == nil {
		t.Error("dupTunFd(-1) returned nil error, want EBADF")
	}
}
