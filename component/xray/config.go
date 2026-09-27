// SPDX-License-Identifier: AGPL-3.0-only
// Package xray supplies VLESS/XHTTP through a supervised Xray process.
package xray

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

type nodeConfig struct {
	name, address string
	outbound      map[string]any
}

func parseNode(link string) (*nodeConfig, error) {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "vless" || u.User == nil || u.Hostname() == "" {
		return nil, errors.New("invalid VLESS XHTTP URL")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("invalid XHTTP query")
	}
	for _, values := range q {
		if len(values) != 1 {
			return nil, errors.New("duplicate XHTTP query parameter")
		}
	}
	if _, err := uuid.Parse(u.User.Username()); err != nil {
		return nil, errors.New("XHTTP requires a valid VLESS UUID")
	}
	if _, ok := u.User.Password(); ok {
		return nil, errors.New("unexpected password in VLESS URL")
	}
	port := 443
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
	}
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid VLESS port")
	}
	if flow := q.Get("flow"); flow != "" && flow != "none" {
		return nil, errors.New("XHTTP does not support a VLESS flow; clear the flow field")
	}
	encryption := q.Get("encryption")
	if encryption == "" {
		encryption = "none"
	}
	if encryption != "none" && !strings.HasPrefix(encryption, "mlkem768x25519plus.") {
		return nil, errors.New("unsupported VLESS encryption")
	}
	mode := q.Get("mode")
	switch mode {
	case "", "auto", "packet-up", "stream-up", "stream-one":
	default:
		return nil, errors.New("unsupported XHTTP mode")
	}
	xhttp := map[string]any{"host": q.Get("host"), "path": q.Get("path"), "mode": mode}
	if extra := q.Get("extra"); extra != "" {
		var v map[string]json.RawMessage
		if json.Unmarshal([]byte(extra), &v) != nil || v == nil {
			return nil, errors.New("XHTTP extra must be a JSON object")
		}
		// A separate download transport needs its own protected dialer. Reject it
		// rather than accidentally permitting a connection outside dae's dialer.
		for key := range v {
			if strings.EqualFold(key, "downloadSettings") {
				return nil, errors.New("XHTTP downloadSettings is not supported yet")
			}
		}
		xhttp["extra"] = v
	}
	security := q.Get("security")
	if security == "" {
		security = "none"
	}
	stream := map[string]any{"network": "xhttp", "security": security, "xhttpSettings": xhttp}
	sni := q.Get("sni")
	if sni == "" {
		sni = u.Hostname()
	}
	fp := q.Get("fp")
	if fp == "" {
		fp = "chrome"
	}
	switch security {
	case "reality":
		key, e := base64.RawURLEncoding.DecodeString(q.Get("pbk"))
		if e != nil || len(key) != 32 {
			return nil, errors.New("REALITY public key must encode 32 bytes")
		}
		sid, e := hex.DecodeString(q.Get("sid"))
		if e != nil || len(sid) > 8 {
			return nil, errors.New("REALITY short ID must be even-length hexadecimal, at most 16 characters")
		}
		stream["realitySettings"] = map[string]any{"serverName": sni, "fingerprint": fp, "publicKey": q.Get("pbk"), "shortId": q.Get("sid"), "spiderX": q.Get("spx"), "mldsa65Verify": q.Get("pqv")}
	case "tls":
		if q.Get("ech") != "" {
			return nil, errors.New("XHTTP ECH is not supported yet")
		}
		tls := map[string]any{"serverName": sni, "fingerprint": fp}
		if alpn := q.Get("alpn"); alpn != "" {
			protocols := strings.Split(alpn, ",")
			for _, p := range protocols {
				if p != "h2" && p != "http/1.1" {
					return nil, errors.New("XHTTP supports h2 and http/1.1 ALPN only")
				}
			}
			tls["alpn"] = protocols
		}
		stream["tlsSettings"] = tls
	case "none":
	default:
		return nil, errors.New("unsupported XHTTP security")
	}
	address := net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
	name := u.Fragment
	if name == "" {
		name = address
	}
	return &nodeConfig{name: name, address: address, outbound: map[string]any{
		"tag": "proxy", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": u.Hostname(), "port": port, "users": []any{map[string]any{"id": u.User.Username(), "encryption": encryption}}}}}, "streamSettings": stream,
	}}, nil
}

func (n *nodeConfig) config(port int, gateway, secret string) ([]byte, error) {
	// Deep copy: starting or restarting one dialer must not mutate another.
	b, _ := json.Marshal(n.outbound)
	var outbound map[string]any
	if err := json.Unmarshal(b, &outbound); err != nil {
		return nil, err
	}
	outbound["streamSettings"].(map[string]any)["sockopt"] = map[string]any{"dialerProxy": "dae-exit"}
	host, p, err := net.SplitHostPort(gateway)
	if err != nil {
		return nil, err
	}
	gp, _ := strconv.Atoi(p)
	return json.Marshal(map[string]any{
		"log":       map[string]any{"loglevel": "none"},
		"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "password", "accounts": []any{map[string]any{"user": "daed", "pass": secret}}, "udp": true, "ip": "127.0.0.1"}}},
		"outbounds": []any{outbound, map[string]any{"tag": "dae-exit", "protocol": "socks", "settings": map[string]any{"servers": []any{map[string]any{"address": host, "port": gp, "users": []any{map[string]any{"user": "daed", "pass": secret}}}}}}},
	})
}
