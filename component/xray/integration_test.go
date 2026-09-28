package xray

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os/exec"
	"sync"
	"testing"
	"time"

	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
)

type recordingDialer struct {
	mu        sync.Mutex
	addresses []string
	networks  []string
}

func (r *recordingDialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	r.mu.Lock()
	r.addresses = append(r.addresses, address)
	r.networks = append(r.networks, network)
	r.mu.Unlock()
	return direct.SymmetricDirect.DialContext(ctx, network, address)
}

func TestXrayEndToEnd(t *testing.T) {
	if _, e := exec.LookPath("xray"); e != nil {
		t.Skip("install pinned Xray to run integration tests")
	}
	for _, security := range []string{"none", "reality", "reality-encrypted"} {
		t.Run(security, func(t *testing.T) {
			server, key, encryption := startServer(t, security)
			if security == "reality-encrypted" {
				security = "reality"
			}
			q := url.Values{"type": {"xhttp"}, "security": {security}, "path": {"/test"}, "sni": {"localhost"}, "pbk": {key}, "mode": {"auto"}, "encryption": {encryption}}
			link := "vless://" + testID + "@" + server + "?" + q.Encode()
			recorder := &recordingDialer{}
			raw, _, e := NewVLESS(&D.ExtraOption{}, recorder, link)
			if e != nil {
				t.Fatal(e)
			}
			d := raw.(*Dialer)
			t.Cleanup(func() { d.Close() })
			tcp, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer tcp.Close()
			go func() {
				for {
					c, e := tcp.Accept()
					if e != nil {
						return
					}
					go func() { defer c.Close(); io.Copy(c, c) }()
				}
			}()
			checkTCP := func() {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				c, e := d.DialContext(ctx, "tcp", tcp.Addr().String())
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				payload := bytes.Repeat([]byte("hello"), 8192)
				if _, e = c.Write(payload); e != nil {
					t.Fatal(e)
				}
				got := make([]byte, len(payload))
				if _, e = io.ReadFull(c, got); e != nil {
					t.Fatal(e)
				}
				if !bytes.Equal(got, payload) {
					t.Fatal("TCP mismatch")
				}
			}
			checkTCP()
			udp, e := net.ListenPacket("udp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer udp.Close()
			go func() {
				b := make([]byte, 65535)
				for {
					n, a, e := udp.ReadFrom(b)
					if e != nil {
						return
					}
					udp.WriteTo(b[:n], a)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, e := d.DialContext(ctx, "udp", udp.LocalAddr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			pc, ok := conn.(netproxy.PacketConn)
			if !ok {
				t.Fatal("missing packet interface")
			}
			pc.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte("udp"), 1000)
			if _, e = pc.WriteTo(payload, udp.LocalAddr().String()); e != nil {
				t.Fatal(e)
			}
			b := make([]byte, 65535)
			n, a, e := pc.ReadFrom(b)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(payload, b[:n]) || a != netip.MustParseAddrPort(udp.LocalAddr().String()) {
				t.Fatal("UDP packet or source mismatch", n, a)
			}
			conn.Close()
			// A dead worker is reaped and recreated on the next request.
			d.mu.Lock()
			for _, w := range d.workers {
				w.cmd.Process.Kill()
				<-w.done
			}
			d.mu.Unlock()
			checkTCP()
			recorder.mu.Lock()
			for _, a := range recorder.addresses {
				if a != server {
					t.Errorf("unexpected gateway destination %s", a)
				}
			}
			count := len(recorder.addresses)
			recorder.mu.Unlock()
			if count < 2 {
				t.Fatal("Xray bypassed dae dialer")
			}
			d.Close()
			if _, e = d.DialContext(ctx, "tcp", tcp.Addr().String()); e == nil {
				t.Fatal("dial after Close")
			}
		})
	}
}

func startServer(t *testing.T, security string) (string, string, string) {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := l.Addr().String()
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	encryption, decryption := "none", "none"
	if security == "reality-encrypted" {
		security = "reality"
		k, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		encryption = "mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
		decryption = "mlkem768x25519plus.native.600s." + base64.RawURLEncoding.EncodeToString(k.Bytes())
	}
	stream := map[string]any{"network": "xhttp", "security": security, "xhttpSettings": map[string]any{"path": "/test"}}
	public := ""
	if security == "reality" {
		k, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		public = base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
		target := tlsTarget(t)
		stream["realitySettings"] = map[string]any{"dest": target, "serverNames": []string{"localhost"}, "privateKey": base64.RawURLEncoding.EncodeToString(k.Bytes()), "shortIds": []string{""}}
	}
	config := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "vless", "settings": map[string]any{"decryption": decryption, "clients": []any{map[string]any{"id": testID}}}, "streamSettings": stream}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
	b, _ := json.Marshal(config)
	cmd := exec.Command("xray", "run", "-config", "stdin:")
	cmd.Stdin = bytes.NewReader(b)
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	t.Cleanup(func() { cmd.Process.Kill(); <-done })
	for i := 0; i < 200; i++ {
		c, e := net.DialTimeout("tcp4", address, 50*time.Millisecond)
		if e == nil {
			c.Close()
			return address, public, encryption
		}
		select {
		case <-done:
			t.Fatal("server exited", logs.String())
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server not ready")
	return "", "", ""
}

func tlsTarget(t *testing.T) string {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	pair, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	if e != nil {
		t.Fatal(e)
	}
	l, e := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, CurvePreferences: []tls.CurveID{tls.X25519}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				c.(*tls.Conn).Handshake()
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return l.Addr().String()
}
