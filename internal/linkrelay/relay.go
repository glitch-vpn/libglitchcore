// Package linkrelay opens a loopback SOCKS5 listener whose connections leave
// through one share link. It starts no session, creates no TUN and posts no
// status event, so it runs beside a tunnel, beside a proxy-mode session or
// alone.
package linkrelay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/pinger"
)

const (
	maxRelays          = 8
	defaultIdleSec     = 60
	maxIdleSec         = 3600
	defaultDialTimeout = 15 * time.Second
	maxDialTimeout     = 2 * time.Minute
	handshakeTimeout   = 10 * time.Second
)

var (
	// idleUnit is the unit of Request.IdleSec.
	idleUnit = time.Second
	// A direction that outlives its peer is closed after this long without a byte.
	lingerTimeout = 10 * time.Second
)

type Request struct {
	Link string `json:"link"`
	// Engine is the engine the caller pinned: "xray" or "mihomo". Empty keeps
	// the link's own choice.
	Engine string `json:"engine,omitempty"`
	// TimeoutMs bounds each outbound dial; 0 takes the default. xray connects
	// on the first byte, so on xray a server that cannot be reached shows as
	// a closed connection after the SOCKS reply, not as a failed dial.
	TimeoutMs int `json:"timeoutMs,omitempty"`
	// IdleSec closes the relay this long after its last connection ended, or
	// after it opened with none; 0 takes the default.
	IdleSec int `json:"idleSec,omitempty"`
}

// Info is the answer to Open. A relay that closes itself, idle or on a broken
// listener, posts nothing: a later connection to Port is refused.
type Info struct {
	ID string `json:"id"`
	// Port is on 127.0.0.1.
	Port int `json:"port"`
	// User and Password are the relay's SOCKS5 login.
	User     string `json:"user"`
	Password string `json:"pass"`
	// Engine is "xray" or "mihomo".
	Engine string `json:"engine"`
}

var (
	registryMu sync.Mutex
	relays     = map[string]*relay{}
)

var (
	errNoLink        = errors.New("no link")
	errTooManyRelays = errors.New("too many relays open")
)

// Open dials nothing until a client connects.
func Open(req Request) (Info, error) {
	link := strings.TrimSpace(req.Link)
	if link == "" {
		return Info{}, errNoLink
	}

	registryMu.Lock()
	full := len(relays) >= maxRelays
	registryMu.Unlock()
	if full {
		return Info{}, errTooManyRelays
	}

	dialer, err := pinger.NewDialer(req.Engine, link)
	if err != nil {
		return Info{}, err
	}
	return start(dialer, req)
}

// Close ends the relay and the connections it carries, and returns once its
// link is released. An unknown id is ignored.
func Close(id string) {
	registryMu.Lock()
	r := relays[id]
	registryMu.Unlock()
	if r != nil {
		closeRelay(r)
	}
}

func start(dialer *pinger.Dialer, req Request) (Info, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		dialer.Release()
		return Info{}, fmt.Errorf("listen: %w", err)
	}

	dialTimeout := defaultDialTimeout
	if req.TimeoutMs > 0 {
		dialTimeout = min(time.Duration(req.TimeoutMs)*time.Millisecond, maxDialTimeout)
	}
	idleSec := req.IdleSec
	if idleSec <= 0 {
		idleSec = defaultIdleSec
	}

	ctx, cancel := context.WithCancel(context.Background())
	r := &relay{
		id:          randomHex(8),
		listener:    listener,
		dialer:      dialer,
		user:        randomHex(12),
		password:    randomHex(24),
		dialTimeout: dialTimeout,
		idleTimeout: time.Duration(min(idleSec, maxIdleSec)) * idleUnit,
		ctx:         ctx,
		cancel:      cancel,
		openConns:   map[net.Conn]struct{}{},
		serveDone:   make(chan struct{}),
		stopped:     make(chan struct{}),
	}
	registryMu.Lock()
	if len(relays) >= maxRelays {
		registryMu.Unlock()
		cancel()
		_ = listener.Close()
		dialer.Release()
		return Info{}, errTooManyRelays
	}
	relays[r.id] = r
	registryMu.Unlock()

	go r.serve()
	r.mu.Lock()
	r.armIdleTimerLocked()
	r.mu.Unlock()

	log.Printf("[relay] open on %s", dialer.Engine)
	return Info{
		ID:       r.id,
		Port:     listener.Addr().(*net.TCPAddr).Port,
		User:     r.user,
		Password: r.password,
		Engine:   dialer.Engine,
	}, nil
}

// closeRelay also ends a relay on its own: idle, or a listener that failed. It
// stays listed until its link is released, so a second Close waits for the first.
func closeRelay(r *relay) {
	r.shutdown()
	registryMu.Lock()
	if relays[r.id] == r {
		delete(relays, r.id)
	}
	registryMu.Unlock()
}

type relay struct {
	id          string
	listener    net.Listener
	dialer      *pinger.Dialer
	user        string
	password    string
	dialTimeout time.Duration
	idleTimeout time.Duration

	// ctx ends when the relay does, so a dial in flight does not outlive it.
	ctx    context.Context
	cancel context.CancelFunc

	mu          sync.Mutex
	openConns   map[net.Conn]struct{} // client and outbound connections alike
	clientCount int
	closed      bool
	idleTimer   *time.Timer

	serveDone chan struct{}
	handlers  sync.WaitGroup
	// stopped closes when shutdown has released the link.
	stopped chan struct{}
}

func (r *relay) serve() {
	defer close(r.serveDone)
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			if r.ctx.Err() == nil {
				go closeRelay(r)
			}
			return
		}
		if !r.begin(conn) {
			_ = conn.Close()
			continue
		}
		go r.handle(conn)
	}
}

// armIdleTimerLocked starts the countdown to closing an unused relay.
func (r *relay) armIdleTimerLocked() {
	if r.closed || r.clientCount > 0 {
		return
	}
	if r.idleTimer == nil {
		r.idleTimer = time.AfterFunc(r.idleTimeout, func() { closeRelay(r) })
		return
	}
	r.idleTimer.Reset(r.idleTimeout)
}

func (r *relay) begin(client net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	r.openConns[client] = struct{}{}
	r.clientCount++
	if r.idleTimer != nil {
		r.idleTimer.Stop()
	}
	r.handlers.Add(1)
	return true
}

func (r *relay) end(client net.Conn) {
	r.mu.Lock()
	delete(r.openConns, client)
	r.clientCount--
	r.armIdleTimerLocked()
	r.mu.Unlock()
	_ = client.Close()
	r.handlers.Done()
}

func (r *relay) track(conn net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	r.openConns[conn] = struct{}{}
	return true
}

func (r *relay) untrack(conn net.Conn) {
	r.mu.Lock()
	delete(r.openConns, conn)
	r.mu.Unlock()
	_ = conn.Close()
}

func (r *relay) handle(client net.Conn) {
	defer r.end(client)

	_ = client.SetDeadline(time.Now().Add(handshakeTimeout))
	target, err := r.negotiate(client)
	if err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})

	outbound, err := r.dialWithin(target)
	if err != nil {
		reply(client, replyFor(err))
		return
	}
	if !r.track(outbound) {
		_ = outbound.Close()
		return
	}
	defer r.untrack(outbound)

	reply(client, replySucceeded)
	carry(client, outbound)
}

// dialWithin dials target and bounds the dial by dialTimeout. A connection
// stays bound to the context its dial was given (xray ends it with that
// context), so the context outlives the dial and ends with the connection.
func (r *relay) dialWithin(target string) (net.Conn, error) {
	connCtx, cancel := context.WithCancel(r.ctx)
	var timedOut atomic.Bool
	timer := time.AfterFunc(r.dialTimeout, func() {
		timedOut.Store(true)
		cancel()
	})
	conn, err := r.dialer.Dial(connCtx, "tcp", target)
	timer.Stop()
	if timedOut.Load() {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, context.DeadlineExceeded
	}
	if err != nil {
		cancel()
		return nil, err
	}
	return &dialScopedConn{Conn: conn, endDial: cancel}, nil
}

// dialScopedConn ends the context its dial was given when it closes.
type dialScopedConn struct {
	net.Conn
	endDial context.CancelFunc
}

func (c *dialScopedConn) Close() error {
	err := c.Conn.Close()
	c.endDial()
	return err
}

func (c *dialScopedConn) CloseWrite() error { return closeWrite(c.Conn) }

// closeWrite ends the write half where the connection has one. A connection
// without one stays open: closing it would cut the answer still coming back.
func closeWrite(conn net.Conn) error {
	if half, ok := conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

// carry copies both directions until each has finished. Once one has, the
// other is closed after lingerTimeout without a byte in either direction.
func carry(client, outbound net.Conn) {
	var lastByteAt atomic.Int64
	touch := func() { lastByteAt.Store(time.Now().UnixNano()) }
	touch()

	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(activityWriter{Conn: dst, touch: touch}, src)
		_ = closeWrite(dst)
		done <- struct{}{}
	}
	go pipe(outbound, client)
	go pipe(client, outbound)

	<-done
	for {
		select {
		case <-done:
			return
		case <-time.After(lingerTimeout):
			if time.Since(time.Unix(0, lastByteAt.Load())) >= lingerTimeout {
				_ = client.Close()
				_ = outbound.Close()
				<-done
				return
			}
		}
	}
}

type activityWriter struct {
	net.Conn
	touch func()
}

func (w activityWriter) Write(p []byte) (int, error) {
	w.touch()
	return w.Conn.Write(p)
}

// shutdown returns once the link is released, also when another goroutine began
// the shutdown first.
func (r *relay) shutdown() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		<-r.stopped
		return
	}
	r.closed = true
	if r.idleTimer != nil {
		r.idleTimer.Stop()
	}
	open := make([]net.Conn, 0, len(r.openConns))
	for conn := range r.openConns {
		open = append(open, conn)
	}
	r.mu.Unlock()

	r.cancel()
	_ = r.listener.Close()
	for _, conn := range open {
		_ = conn.Close()
	}
	<-r.serveDone
	r.handlers.Wait()
	r.dialer.Release()
	log.Printf("[relay] closed on %s", r.dialer.Engine)
	close(r.stopped)
}

// replyFor names a failed dial by what the client can act on. The engine's
// own text may quote the link, so none of it reaches the client.
func replyFor(err error) byte {
	var timeout interface{ Timeout() bool }
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return replyHostUnreachable
	}
	return replyGeneralFailure
}

func randomHex(byteCount int) string {
	raw := make([]byte, byteCount)
	_, _ = rand.Read(raw)
	return hex.EncodeToString(raw)
}
