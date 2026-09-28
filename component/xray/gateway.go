// SPDX-License-Identifier: AGPL-3.0-only
package xray

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// gateway gives Xray the *existing* dae dialer. DNS policy, marks, proxy
// chaining and sticky IP selection therefore remain on dae's normal path.
// Xray has no direct outbound: even its transport connects through this gate.
type gateway struct {
	listener        net.Listener
	next            netproxy.Dialer
	network, secret string
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	conns           map[io.Closer]struct{}
}

func newGateway(next netproxy.Dialer, network, secret string) (*gateway, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := &gateway{listener: l, next: next, network: network, secret: secret, ctx: ctx, cancel: cancel, conns: map[io.Closer]struct{}{}}
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			if g.track(c) {
				go g.serve(c)
			}
		}
	}()
	return g, nil
}

func (g *gateway) track(c io.Closer) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ctx.Err() != nil {
		c.Close()
		return false
	}
	g.conns[c] = struct{}{}
	return true
}
func (g *gateway) untrack(c io.Closer) { c.Close(); g.mu.Lock(); delete(g.conns, c); g.mu.Unlock() }
func (g *gateway) Close() {
	g.cancel()
	g.listener.Close()
	g.mu.Lock()
	conns := g.conns
	g.conns = map[io.Closer]struct{}{}
	g.mu.Unlock()
	for c := range conns {
		c.Close()
	}
}

func readBytes(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	_, e := io.ReadFull(r, b)
	return b, e
}
func readString(r io.Reader) (string, error) {
	b, e := readBytes(r, 1)
	if e != nil {
		return "", e
	}
	b, e = readBytes(r, int(b[0]))
	return string(b), e
}

func (g *gateway) serve(c net.Conn) {
	defer g.untrack(c)
	c.SetDeadline(time.Now().Add(10 * time.Second))
	h, e := readBytes(c, 2)
	if e != nil || h[0] != 5 || h[1] == 0 {
		return
	}
	methods, e := readBytes(c, int(h[1]))
	if e != nil {
		return
	}
	auth := false
	for _, m := range methods {
		if m == 2 {
			auth = true
		}
	}
	if !auth {
		c.Write([]byte{5, 255})
		return
	}
	if _, e = c.Write([]byte{5, 2}); e != nil {
		return
	}
	v, e := readBytes(c, 1)
	if e != nil || v[0] != 1 {
		return
	}
	user, e := readString(c)
	if e != nil {
		return
	}
	pass, e := readString(c)
	if e != nil {
		return
	}
	if user != "daed" || subtle.ConstantTimeCompare([]byte(pass), []byte(g.secret)) != 1 {
		c.Write([]byte{1, 1})
		return
	}
	if _, e = c.Write([]byte{1, 0}); e != nil {
		return
	}
	h, e = readBytes(c, 4)
	if e != nil || h[0] != 5 || h[1] != 1 || h[2] != 0 {
		return
	}
	var host string
	switch h[3] {
	case 1:
		b, e := readBytes(c, 4)
		if e != nil {
			return
		}
		host = net.IP(b).String()
	case 4:
		b, e := readBytes(c, 16)
		if e != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		host, e = readString(c)
		if e != nil {
			return
		}
	default:
		return
	}
	b, e := readBytes(c, 2)
	if e != nil {
		return
	}
	address := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(b))))
	ctx, cancel := context.WithTimeout(g.ctx, 10*time.Second)
	remote, e := g.next.DialContext(ctx, g.network, address)
	cancel()
	if e != nil {
		c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	if !g.track(remote) {
		return
	}
	defer g.untrack(remote)
	if _, e = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); e != nil {
		return
	}
	c.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() { io.Copy(remote, c); remote.Close(); c.Close(); close(done) }()
	io.Copy(c, remote)
	remote.Close()
	c.Close()
	<-done
}

// readiness authenticates without dialing a remote destination.
func authenticate(ctx context.Context, address, secret string) error {
	c, e := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
	if e != nil {
		return e
	}
	defer c.Close()
	deadline := time.Now().Add(200 * time.Millisecond)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	if _, e = c.Write([]byte{5, 1, 2}); e != nil {
		return e
	}
	b, e := readBytes(c, 2)
	if e != nil {
		return e
	}
	if b[0] != 5 || b[1] != 2 {
		return errors.New("unexpected SOCKS authentication")
	}
	req := append([]byte{1, 4}, []byte("daed")...)
	req = append(req, byte(len(secret)))
	req = append(req, []byte(secret)...)
	if _, e = c.Write(req); e != nil {
		return e
	}
	b, e = readBytes(c, 2)
	if e != nil {
		return e
	}
	if b[0] != 1 || b[1] != 0 {
		return errors.New("SOCKS authentication failed")
	}
	return nil
}
