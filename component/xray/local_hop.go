// SPDX-License-Identifier: AGPL-3.0-only
package xray

import (
	"context"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
)

// The SOCKS library's handshake has no context of its own. Bound every socket
// opened for that handshake, then detach cancellation after it has succeeded.
type localHop struct {
	ctx   context.Context
	conns []netproxy.Conn
	stops []func() bool
}

func (h *localHop) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	c, e := direct.SymmetricDirect.DialContext(ctx, network, address)
	if e != nil {
		return nil, e
	}
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := h.ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if e = c.SetDeadline(deadline); e != nil {
		c.Close()
		return nil, e
	}
	h.conns = append(h.conns, c)
	h.stops = append(h.stops, context.AfterFunc(h.ctx, func() { c.Close() }))
	return c, nil
}
func (h *localHop) finish() {
	for _, stop := range h.stops {
		stop()
	}
	for _, c := range h.conns {
		c.SetDeadline(time.Time{})
	}
}
