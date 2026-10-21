//go:build !no_mihomo && (!no_xray || !no_awg)

package core

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// bridgePipe is a synchronous in-memory connection whose ends can half-close:
// CloseWrite on one end is EOF to the other's reads while the other way keeps
// flowing, so an app's half-close crosses the bridge as it would a socket.
// Only reads take a deadline.
func bridgePipe() (*bridgePipeEnd, *bridgePipeEnd) {
	aToB, bToA := make(chan []byte), make(chan []byte)
	aRead, bRead := make(chan int), make(chan int)
	aDone, bDone := make(chan struct{}), make(chan struct{})
	aWriteDone, bWriteDone := make(chan struct{}), make(chan struct{})
	a := &bridgePipeEnd{
		rdRx: bToA, rdTx: aRead, wrTx: aToB, wrRx: bRead,
		localDone: aDone, remoteDone: bDone,
		writeDone: aWriteDone, peerWriteDone: bWriteDone,
		readDeadline: bridgeDeadline{expired: make(chan struct{})},
	}
	b := &bridgePipeEnd{
		rdRx: aToB, rdTx: bRead, wrTx: bToA, wrRx: aRead,
		localDone: bDone, remoteDone: aDone,
		writeDone: bWriteDone, peerWriteDone: aWriteDone,
		readDeadline: bridgeDeadline{expired: make(chan struct{})},
	}
	return a, b
}

type bridgePipeEnd struct {
	wrMu sync.Mutex

	// A receive on rdRx is always answered on rdTx with the bytes taken.
	rdRx <-chan []byte
	rdTx chan<- int
	wrTx chan<- []byte
	wrRx <-chan int

	closeOnce     sync.Once
	localDone     chan struct{}
	remoteDone    <-chan struct{}
	writeOnce     sync.Once
	writeDone     chan struct{}
	peerWriteDone <-chan struct{}

	readDeadline bridgeDeadline
}

func (p *bridgePipeEnd) Read(b []byte) (int, error) {
	expired := p.readDeadline.wait()
	switch {
	case isClosedChan(p.localDone):
		return 0, io.ErrClosedPipe
	case isClosedChan(p.remoteDone), isClosedChan(p.peerWriteDone):
		return 0, io.EOF
	case isClosedChan(expired):
		return 0, os.ErrDeadlineExceeded
	}
	select {
	case chunk := <-p.rdRx:
		n := copy(b, chunk)
		p.rdTx <- n
		return n, nil
	case <-p.localDone:
		return 0, io.ErrClosedPipe
	case <-p.remoteDone:
		return 0, io.EOF
	case <-p.peerWriteDone:
		return 0, io.EOF
	case <-expired:
		return 0, os.ErrDeadlineExceeded
	}
}

func (p *bridgePipeEnd) Write(b []byte) (int, error) {
	p.wrMu.Lock()
	defer p.wrMu.Unlock()
	n := 0
	for first := true; first || len(b) > 0; first = false {
		if isClosedChan(p.localDone) || isClosedChan(p.writeDone) || isClosedChan(p.remoteDone) {
			return n, io.ErrClosedPipe
		}
		select {
		case p.wrTx <- b:
			taken := <-p.wrRx
			b = b[taken:]
			n += taken
		case <-p.localDone:
			return n, io.ErrClosedPipe
		case <-p.writeDone:
			return n, io.ErrClosedPipe
		case <-p.remoteDone:
			return n, io.ErrClosedPipe
		}
	}
	return n, nil
}

func (p *bridgePipeEnd) CloseWrite() error {
	p.writeOnce.Do(func() { close(p.writeDone) })
	return nil
}

func (p *bridgePipeEnd) Close() error {
	p.closeOnce.Do(func() { close(p.localDone) })
	return nil
}

func (p *bridgePipeEnd) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (p *bridgePipeEnd) RemoteAddr() net.Addr { return &net.TCPAddr{} }

func (p *bridgePipeEnd) SetDeadline(t time.Time) error { return p.SetReadDeadline(t) }

func (p *bridgePipeEnd) SetReadDeadline(t time.Time) error {
	p.readDeadline.set(t)
	return nil
}

func (p *bridgePipeEnd) SetWriteDeadline(time.Time) error { return nil }
