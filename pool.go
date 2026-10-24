// Copyright (C) 2017 Michał Matczuk
// Use of this source code is governed by an AGPL-style
// license that can be found in the LICENSE file.

package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/mmatczuk/go-http-tunnel/id"
)

type connPair struct {
	conn       net.Conn
	clientConn *http2.ClientConn
	identifier id.ID
	tag        string
	ctx        context.Context
	cancel     context.CancelFunc
}

type connPool struct {
	t      *http2.Transport
	conns  map[string]*connPair // key is host:port
	free   func(identifier id.ID, tag string)
	closed bool
	mu     sync.RWMutex
}

func newConnPool(t *http2.Transport, f func(identifier id.ID, tag string)) *connPool {
	return &connPool{
		t:     t,
		free:  f,
		conns: make(map[string]*connPair),
	}
}

func (p *connPool) URL(identifier id.ID) string {
	return fmt.Sprint("https://", identifier)
}

func (p *connPool) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if cp, ok := p.conns[addr]; ok && cp.clientConn.CanTakeNewRequest() {
		return cp.clientConn, nil
	}

	return nil, errClientNotConnected
}

func (p *connPool) MarkDead(c *http2.ClientConn) {
	p.mu.Lock()
	for _, cp := range p.conns {
		if cp.clientConn == c {
			p.removeLocked(cp)
			p.mu.Unlock()
			cp.conn.Close()
			return
		}
	}
	p.mu.Unlock()
}

func (p *connPool) AddConn(conn net.Conn, identifier id.ID, tag string) (*connPair, error) {
	addr := p.addr(identifier)

	for {
		p.mu.RLock()
		cp, ok := p.conns[addr]
		closed := p.closed
		p.mu.RUnlock()
		if closed {
			return nil, errClientNotConnected
		}
		if !ok {
			break
		}

		err := p.ping(cp)
		p.mu.Lock()
		if p.conns[addr] != cp {
			p.mu.Unlock()
			continue
		}
		if err == nil {
			p.mu.Unlock()
			return nil, errClientAlreadyConnected
		}
		p.removeLocked(cp)
		p.mu.Unlock()
		cp.conn.Close()
		break
	}

	c, err := p.t.NewClientConn(conn)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	switch {
	case p.closed:
		err = errClientNotConnected
	case p.conns[addr] != nil:
		err = errClientAlreadyConnected
	case !c.CanTakeNewRequest():
		err = errClientNotConnected
	}
	if err != nil {
		p.mu.Unlock()
		conn.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	cp := &connPair{
		conn:       conn,
		clientConn: c,
		identifier: identifier,
		tag:        tag,
		ctx:        ctx,
		cancel:     cancel,
	}
	p.conns[addr] = cp
	p.mu.Unlock()

	return cp, nil
}

func (p *connPool) DeleteConn(identifier id.ID) {
	p.mu.Lock()
	cp := p.conns[p.addr(identifier)]
	if cp != nil {
		p.removeLocked(cp)
	}
	p.mu.Unlock()
	if cp != nil {
		cp.conn.Close()
	}
}

func (p *connPool) remove(cp *connPair) {
	p.mu.Lock()
	removed := p.removeLocked(cp)
	p.mu.Unlock()
	if removed {
		cp.conn.Close()
	}
}

func (p *connPool) removeLocked(cp *connPair) bool {
	addr := p.addr(cp.identifier)
	if p.conns[addr] != cp {
		return false
	}
	delete(p.conns, addr)
	cp.cancel()
	if p.free != nil {
		p.free(cp.identifier, cp.tag)
	}
	return true
}

func (p *connPool) Close() {
	p.mu.Lock()
	p.closed = true
	conns := make([]*connPair, 0, len(p.conns))
	for _, cp := range p.conns {
		p.removeLocked(cp)
		conns = append(conns, cp)
	}
	p.mu.Unlock()
	for _, cp := range conns {
		cp.conn.Close()
	}
}

func (p *connPool) Ping(identifier id.ID) (time.Duration, error) {
	addr := p.addr(identifier)
	p.mu.RLock()
	cp, ok := p.conns[addr]
	p.mu.RUnlock()

	if ok {
		start := time.Now()
		err := p.ping(cp)
		return time.Since(start), err
	}

	return 0, errClientNotConnected
}

func (p *connPool) ping(cp *connPair) error {
	ctx, cancel := context.WithTimeout(cp.ctx, DefaultPingTimeout)
	defer cancel()

	return cp.clientConn.Ping(ctx)
}

func (p *connPool) addr(identifier id.ID) string {
	return fmt.Sprint(identifier.String(), ":443")
}
