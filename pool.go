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
	conn         net.Conn
	clientConn   *http2.ClientConn
	identifier   id.ID
	tag          string
	ctx          context.Context
	cancel       context.CancelFunc
	registration *RegistryItem
}

type connPool struct {
	t        *http2.Transport
	conns    map[string]*connPair // key is host:port
	registry *registry
	retiring map[id.ID]chan struct{}
	closed   bool
	done     chan struct{}
	mu       sync.RWMutex
}

type detachedSession struct {
	session    *connPair
	item       *RegistryItem
	identifier id.ID
	retired    chan struct{}
}

func newConnPool(t *http2.Transport, r *registry) *connPool {
	return &connPool{
		t:        t,
		registry: r,
		conns:    make(map[string]*connPair),
		retiring: make(map[id.ID]chan struct{}),
		done:     make(chan struct{}),
	}
}

func (p *connPool) URL(identifier id.ID) string {
	return fmt.Sprint("https://", identifier)
}

func (p *connPool) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if cp, ok := p.conns[addr]; ok && cp.clientConn.ReserveNewRequest() {
		return cp.clientConn, nil
	}

	return nil, errClientNotConnected
}

func (p *connPool) MarkDead(c *http2.ClientConn) {
	p.mu.Lock()
	var detached detachedSession
	for _, cp := range p.conns {
		if cp.clientConn == c {
			detached = p.detachLocked(cp)
			break
		}
	}
	p.mu.Unlock()
	p.release(detached)
}

func (p *connPool) AddConn(conn net.Conn, identifier id.ID, tag string) (*connPair, error) {
	addr := p.addr(identifier)
	for {
		p.mu.RLock()
		cp := p.conns[addr]
		closed := p.closed
		retiring := p.retiring[identifier]
		p.mu.RUnlock()
		if closed {
			return nil, errClientNotConnected
		}
		if retiring != nil {
			select {
			case <-retiring:
			case <-p.done:
				return nil, errClientNotConnected
			}
			continue
		}
		if cp == nil {
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
		detached := p.detachLocked(cp)
		p.mu.Unlock()
		p.release(detached)
	}

	c, err := p.t.NewClientConn(conn)
	if err != nil {
		return nil, err
	}
	for {
		p.mu.Lock()
		if retiring := p.retiring[identifier]; !p.closed && retiring != nil {
			p.mu.Unlock()
			select {
			case <-retiring:
			case <-p.done:
			}
			continue
		}
		switch {
		case p.closed:
			err = errClientNotConnected
		case p.conns[addr] != nil:
			err = errClientAlreadyConnected
		case c.State().Closed || !c.CanTakeNewRequest():
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
}

func (p *connPool) commit(cp *connPair, item *RegistryItem) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conns[p.addr(cp.identifier)] != cp {
		return errClientNotConnected
	}
	if err := cp.ctx.Err(); err != nil {
		return err
	}
	p.registry.mu.Lock()
	defer p.registry.mu.Unlock()
	if err := p.registry.publishLocked(item, cp.identifier); err != nil {
		return err
	}
	cp.registration = item
	return nil
}

func (p *connPool) remove(cp *connPair) {
	p.mu.Lock()
	detached := p.detachLocked(cp)
	p.mu.Unlock()
	p.release(detached)
}

func (p *connPool) detachLocked(cp *connPair) detachedSession {
	addr := p.addr(cp.identifier)
	if p.conns[addr] != cp {
		return detachedSession{}
	}
	delete(p.conns, addr)
	cp.cancel()
	item := cp.registration
	cp.registration = nil
	if item != nil {
		p.registry.mu.Lock()
		p.registry.detachLocked(cp.identifier, item)
		p.registry.mu.Unlock()
	}
	retired := make(chan struct{})
	p.retiring[cp.identifier] = retired
	return detachedSession{session: cp, item: item, identifier: cp.identifier, retired: retired}
}

func (p *connPool) release(detached detachedSession) {
	if detached.retired == nil {
		return
	}
	if detached.session != nil {
		detached.session.conn.Close()
	}
	if detached.item != nil {
		p.registry.logger.Log("level", 1, "action", "disconnected", "identifier", detached.identifier, "tag", detached.item.Tag)
	}
	p.registry.release(detached.identifier, detached.item)
	p.mu.Lock()
	if p.retiring[detached.identifier] == detached.retired {
		delete(p.retiring, detached.identifier)
		close(detached.retired)
	}
	p.mu.Unlock()
}

func (p *connPool) unsubscribe(identifier id.ID) *RegistryItem {
	p.mu.Lock()
	retiring := p.retiring[identifier]
	var detached detachedSession
	if cp := p.conns[p.addr(identifier)]; cp != nil {
		detached = p.detachLocked(cp)
	}
	p.registry.mu.Lock()
	item := p.registry.unsubscribeLocked(identifier)
	p.registry.mu.Unlock()
	if detached.item != nil {
		item = detached.item
	} else if item != nil && item != voidRegistryItem {
		detached.item = item
		if detached.retired == nil {
			detached.identifier = identifier
			detached.retired = make(chan struct{})
			p.retiring[identifier] = detached.retired
		}
	}
	p.mu.Unlock()
	p.release(detached)
	if retiring != nil {
		<-retiring
	}
	if item != nil {
		p.registry.logger.Log("level", 1, "action", "unsubscribe", "identifier", identifier)
	}
	return item
}

func (p *connPool) Close() {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.done)
	}
	retiring := make([]chan struct{}, 0, len(p.retiring))
	for _, done := range p.retiring {
		retiring = append(retiring, done)
	}
	detached := make([]detachedSession, 0, len(p.conns))
	for _, cp := range p.conns {
		detached = append(detached, p.detachLocked(cp))
	}
	p.mu.Unlock()
	for _, session := range detached {
		p.release(session)
	}
	for _, done := range retiring {
		<-done
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
