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
	dashboard []dashboardTunnel
	hostKeys  []hostKey
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
	hosts    map[hostKey]*hostInfo
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
		hosts:    make(map[hostKey]*hostInfo),
		logger:   logger,
		portPool: NewPortPool(startPort, 1024*128),
	}
}

var voidRegistryItem = &RegistryItem{}

// Subscribe allows to connect client with a given identifier.
func (r *registry) Subscribe(identifier id.ID) {
	r.mu.Lock()
	if _, ok := r.items[identifier]; ok {
		r.mu.Unlock()
		return
	}
	r.items[identifier] = voidRegistryItem
	r.mu.Unlock()
	r.logger.Log("level", 1, "action", "subscribe", "identifier", identifier)
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

	h, ok := r.hosts[canonicalHost(hostPort)]
	if !ok {
		return id.ID{}, nil, false
	}

	return h.identifier, h.auth, ok
}

func (r *registry) unsubscribeLocked(identifier id.ID) *RegistryItem {
	i := r.items[identifier]
	if i != nil {
		for _, key := range i.hostKeys {
			delete(r.hosts, key)
		}
		delete(r.items, identifier)
	}
	return i
}

func (r *registry) publishLocked(i *RegistryItem, identifier id.ID) error {
	j, ok := r.items[identifier]
	if !ok {
		return errClientNotSubscribed
	}
	if j != voidRegistryItem {
		return fmt.Errorf("attempt to overwrite registry item")
	}
	for _, key := range i.hostKeys {
		if _, ok := r.hosts[key]; ok {
			return fmt.Errorf("host %q is occupied", key)
		}
	}
	for n, key := range i.hostKeys {
		r.hosts[key] = &hostInfo{identifier: identifier, auth: i.Hosts[n].Auth}
	}
	r.items[identifier] = i
	return nil
}

func (r *registry) detachLocked(identifier id.ID, expected *RegistryItem) {
	if r.items[identifier] != expected {
		return
	}
	for _, key := range expected.hostKeys {
		delete(r.hosts, key)
	}
	r.items[identifier] = voidRegistryItem
}

func (r *registry) release(identifier id.ID, item *RegistryItem) {
	if item == nil {
		return
	}
	for _, l := range item.Listeners {
		r.logger.Log("level", 2, "action", "close listener", "identifier", identifier, "addr", l.Addr())
		l.Close()
	}
	for _, port := range item.Ports {
		r.portPool.Put(port)
	}
}

func trimPort(hostPort string) (host string) {
	host, _, _ = net.SplitHostPort(hostPort)
	if host == "" {
		host = hostPort
	}
	return
}
