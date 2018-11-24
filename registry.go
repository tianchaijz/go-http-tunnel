// Copyright (C) 2017 Michał Matczuk
// Use of this source code is governed by an AGPL-style
// license that can be found in the LICENSE file.

package tunnel

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/mmatczuk/go-http-tunnel/id"
	"github.com/mmatczuk/go-http-tunnel/log"
)

type PortPool struct {
	port uint64
	pool chan uint64
}

func NewPortPool(port uint64, max int) *PortPool {
	return &PortPool{
		port: port,
		pool: make(chan uint64, max),
	}
}

func (pp *PortPool) Get() uint64 {
	var port uint64
	select {
	case port = <-pp.pool:
	default:
		port = atomic.AddUint64(&pp.port, 1)
	}
	return port
}

func (pp *PortPool) Put(port uint64) {
	select {
	case pp.pool <- port:
	default:
		// let it go, let it go...
	}
}

type Listener struct {
	net.Listener
	TunnelName string
}

// RegistryItem holds information about hosts and listeners associated with a
// client.
type RegistryItem struct {
	Tag       string
	Hosts     []*HostAuth
	Listeners []Listener
	Ports     []uint64
}

// HostAuth holds host and authentication info.
type HostAuth struct {
	Host string
	Auth *Auth
}

type hostInfo struct {
	identifier id.ID
	auth       *Auth
}

type registry struct {
	items    map[id.ID]*RegistryItem
	hosts    map[string]*hostInfo
	mu       sync.RWMutex
	logger   log.Logger
	portPool *PortPool
}

func newRegistry(logger log.Logger, startPort uint64) *registry {
	if logger == nil {
		logger = log.NewNopLogger()
	}

	return &registry{
		items:    make(map[id.ID]*RegistryItem),
		hosts:    make(map[string]*hostInfo),
		logger:   logger,
		portPool: NewPortPool(startPort, 1024*128),
	}
}

var voidRegistryItem = &RegistryItem{}

// Subscribe allows to connect client with a given identifier.
func (r *registry) Subscribe(identifier id.ID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.items[identifier]; ok {
		return
	}

	r.logger.Log(
		"level", 1,
		"action", "subscribe",
		"identifier", identifier,
	)

	r.items[identifier] = voidRegistryItem
}

// IsSubscribed returns true if client is subscribed.
func (r *registry) IsSubscribed(identifier id.ID) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.items[identifier]
	return ok
}

// Subscriber returns client identifier assigned to given host.
func (r *registry) Subscriber(hostPort string) (id.ID, *Auth, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	h, ok := r.hosts[trimPort(hostPort)]
	if !ok {
		return id.ID{}, nil, false
	}

	return h.identifier, h.auth, ok
}

// Unsubscribe removes client from registry and returns it's RegistryItem.
func (r *registry) Unsubscribe(identifier id.ID) *RegistryItem {
	r.mu.Lock()
	defer r.mu.Unlock()

	i, ok := r.items[identifier]
	if !ok {
		return nil
	}

	r.logger.Log(
		"level", 1,
		"action", "unsubscribe",
		"identifier", identifier,
	)

	if i.Hosts != nil {
		for _, h := range i.Hosts {
			delete(r.hosts, h.Host)
		}
	}

	delete(r.items, identifier)

	return i
}

func (r *registry) set(i *RegistryItem, identifier id.ID) error {
	r.logger.Log(
		"level", 2,
		"action", "set registry item",
		"identifier", identifier,
	)

	r.mu.Lock()
	defer r.mu.Unlock()

	j, ok := r.items[identifier]
	if !ok {
		return errClientNotSubscribed
	}
	if j != voidRegistryItem {
		return fmt.Errorf("attempt to overwrite registry item")
	}

	if i.Hosts != nil {
		for _, h := range i.Hosts {
			if h.Auth != nil && h.Auth.User == "" {
				return fmt.Errorf("missing auth user")
			}
			if _, ok := r.hosts[trimPort(h.Host)]; ok {
				return fmt.Errorf("host %q is occupied", h.Host)
			}
		}

		for _, h := range i.Hosts {
			r.hosts[trimPort(h.Host)] = &hostInfo{
				identifier: identifier,
				auth:       h.Auth,
			}
		}
	}

	r.items[identifier] = i

	return nil
}

func (r *registry) clear(identifier id.ID, tag string) *RegistryItem {
	r.logger.Log(
		"level", 2,
		"action", "clear registry item",
		"identifier", identifier,
	)

	r.mu.Lock()
	defer r.mu.Unlock()

	i, ok := r.items[identifier]
	if !ok || i == voidRegistryItem || (tag != "" && i.Tag != tag) {
		return nil
	}

	if i.Hosts != nil {
		for _, h := range i.Hosts {
			delete(r.hosts, trimPort(h.Host))
		}
	}

	r.items[identifier] = voidRegistryItem

	return i
}

func trimPort(hostPort string) (host string) {
	host, _, _ = net.SplitHostPort(hostPort)
	if host == "" {
		host = hostPort
	}
	return
}
