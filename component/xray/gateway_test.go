package xray

import (
	"context"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/outbound/protocol/socks5"
)

type dialFunc func(context.Context, string, string) (netproxy.Conn, error)

func (f dialFunc) DialContext(c context.Context, n, a string) (netproxy.Conn, error) {
	return f(c, n, a)
}

func TestGatewayPreservesNetworkAndCloses(t *testing.T) {
	network := (netproxy.MagicNetwork{Network: "tcp", Mark: 0x8000000, Mptcp: true, IPVersion: "4"}).Encode()
	called := make(chan string, 1)
	peerClosed := make(chan struct{})
	next := dialFunc(func(ctx context.Context, n, a string) (netproxy.Conn, error) {
		if n != network {
			t.Error("gateway changed network metadata")
		}
		called <- a
		aConn, bConn := net.Pipe()
		go func() { defer close(peerClosed); defer bConn.Close(); io.Copy(io.Discard, bConn) }()
		return aConn, nil
	})
	g, e := newGateway(next, network, "secret")
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	link := (&url.URL{Scheme: "socks5", Host: g.listener.Addr().String(), User: url.UserPassword("daed", "secret")}).String()
	proxy, e := socks5.NewSocks5Dialer(link, direct.SymmetricDirect)
	if e != nil {
		t.Fatal(e)
	}
	c, e := proxy.DialContext(context.Background(), "tcp", "node.example:443")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	select {
	case a := <-called:
		if a != "node.example:443" {
			t.Fatal(a)
		}
	case <-time.After(time.Second):
		t.Fatal("missing gateway dial")
	}
	g.Close()
	select {
	case <-peerClosed:
	case <-time.After(time.Second):
		t.Fatal("remote connection leaked")
	}
	if e = authenticate(context.Background(), g.listener.Addr().String(), "secret"); e == nil {
		t.Fatal("closed gateway accepted client")
	}
}

func TestGatewayRejectsWrongPassword(t *testing.T) {
	next := dialFunc(func(context.Context, string, string) (netproxy.Conn, error) {
		t.Error("unauthenticated dial")
		return nil, net.ErrClosed
	})
	g, e := newGateway(next, "tcp", "secret")
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	if e = authenticate(context.Background(), g.listener.Addr().String(), "wrong"); e == nil {
		t.Fatal("accepted wrong password")
	}
}
