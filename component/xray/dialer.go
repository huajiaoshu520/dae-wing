// SPDX-License-Identifier: AGPL-3.0-only
package xray

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"strconv"
	"sync"
	"time"

	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/dialer/v2ray"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/socks5"
)

func init() { D.FromLinkRegister("vless", NewVLESS) }

// NewVLESS preserves the native implementation for every non-XHTTP node.
// Importing or inspecting a node never starts a process or opens a socket.
func NewVLESS(option *D.ExtraOption, next netproxy.Dialer, link string) (netproxy.Dialer, *D.Property, error) {
	u, e := url.Parse(link)
	if e != nil {
		return nil, nil, errors.New("invalid VLESS URL")
	}
	if u.Query().Get("type") != "xhttp" {
		return v2ray.NewV2Ray(option, next, link)
	}
	config, e := parseNode(link)
	if e != nil {
		return nil, nil, e
	}
	life, cancel := context.WithCancel(context.Background())
	return &Dialer{node: config, next: next, workers: map[string]*worker{}, life: life, cancel: cancel}, &D.Property{Name: config.name, Address: config.address, Protocol: "vless", Link: link}, nil
}

type Dialer struct {
	life    context.Context
	cancel  context.CancelFunc
	node    *nodeConfig
	next    netproxy.Dialer
	mu      sync.Mutex
	closed  bool
	workers map[string]*worker
}
type worker struct {
	cmd  *exec.Cmd
	done chan struct{}
	gate *gateway
	link string
}

func (w *worker) stop() { w.gate.Close(); _ = w.cmd.Process.Kill(); <-w.done }

func (d *Dialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mn, e := netproxy.ParseMagicNetwork(network)
	if e != nil {
		return nil, e
	}
	if mn.Network != "tcp" && mn.Network != "udp" {
		return nil, net.UnknownNetworkError(mn.Network)
	}
	mn.Network = "tcp" // Both TCP and UDP payloads use XHTTP's TCP transport.
	key := mn.Encode()
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, net.ErrClosed
	}
	w := d.workers[key]
	if w != nil {
		select {
		case <-w.done:
			w.stop()
			delete(d.workers, key)
			w = nil
		default:
		}
	}
	if w == nil {
		w, e = d.start(ctx, key)
		if e == nil {
			d.workers[key] = w
		}
	}
	d.mu.Unlock()
	if e != nil {
		return nil, e
	}
	// The local hop is always IPv4; the remote IP-family constraint belongs
	// exclusively to the gateway and must not forbid the loopback connection.
	local, _ := netproxy.ParseMagicNetwork(network)
	local.IPVersion = ""
	hop := &localHop{ctx: ctx}
	proxy, err := socks5.NewSocks5Dialer(w.link, hop)
	if err != nil {
		return nil, err
	}
	conn, err := proxy.DialContext(ctx, local.Encode(), address)
	hop.finish()
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (d *Dialer) Close() error {
	d.cancel()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	for _, w := range d.workers {
		w.stop()
	}
	d.workers = nil
	return nil
}

func (d *Dialer) start(ctx context.Context, network string) (*worker, error) {
	binary, e := exec.LookPath("xray")
	if e != nil {
		return nil, errors.New("XHTTP requires the bundled xray executable; update the daed image")
	}
	secretBytes := make([]byte, 24)
	if _, e = rand.Read(secretBytes); e != nil {
		return nil, e
	}
	secret := hex.EncodeToString(secretBytes)
	gate, e := newGateway(d.next, network, secret)
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			gate.Close()
		}
	}()
	// Reserve an available local port. Xray owns it after Start; readiness is
	// authenticated, so another process winning the bind race cannot be used.
	reserve, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return nil, e
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	config, e := d.node.config(port, gate.listener.Addr().String(), secret)
	if e != nil {
		return nil, e
	}
	cmd := exec.Command(binary, "run", "-config", "stdin:")
	cmd.Stdin = bytes.NewReader(config)
	// No secrets in argv, files, or process logs. Detailed link values must not
	// leak through an upstream config-parser error.
	setProcessAttributes(cmd)
	if e = cmd.Start(); e != nil {
		return nil, fmt.Errorf("start Xray: %w", e)
	}
	w := &worker{cmd: cmd, done: make(chan struct{}), gate: gate}
	go func() { _ = cmd.Wait(); gate.Close(); close(w.done) }()
	startup, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	stop := context.AfterFunc(d.life, cancel)
	defer stop()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if authenticate(startup, addr, secret) == nil {
			break
		}
		select {
		case <-w.done:
			w.stop()
			return nil, errors.New("Xray exited during startup; check XHTTP/REALITY settings and bundled Xray version")
		case <-startup.Done():
			w.stop()
			return nil, fmt.Errorf("Xray startup: %w", startup.Err())
		case <-ticker.C:
		}
	}
	link := (&url.URL{Scheme: "socks5", Host: addr, User: url.UserPassword("daed", secret)}).String()
	w.link = link
	success = true
	return w, nil
}
