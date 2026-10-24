package tunnel

import (
	"bytes"
	"context"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mmatczuk/go-http-tunnel/id"
	"github.com/mmatczuk/go-http-tunnel/proto"
	"golang.org/x/net/http2"
)

type retirementListener struct {
	net.Listener
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	closes  atomic.Int32
}

func (l *retirementListener) Close() error {
	l.closes.Add(1)
	l.once.Do(func() { close(l.entered); <-l.release })
	return l.Listener.Close()
}

func gateRegistrationListener(t *testing.T, item *RegistryItem) *retirementListener {
	t.Helper()
	gate := &retirementListener{Listener: item.Listeners[0].Listener, entered: make(chan struct{}), release: make(chan struct{})}
	item.Listeners[0].Listener = gate
	t.Cleanup(func() {
		select {
		case <-gate.release:
		default:
			close(gate.release)
		}
	})
	return gate
}

func TestUnsubscribeReturnsOriginalRegistration(t *testing.T) {
	for _, connected := range []bool{false, true} {
		t.Run(map[bool]string{false: "subscribed", true: "connected"}[connected], func(t *testing.T) {
			s, session := portTestServer(t, 30000)
			if connected {
				if err := s.addTunnels(map[string]*proto.Tunnel{
					"web": {Protocol: proto.HTTP, Host: "example.test:8080"},
					"tcp": {Protocol: proto.TCP, RemoteAddr: "127.0.0.1:0"},
				}, session); err != nil {
					t.Fatal(err)
				}
			} else {
				s.connPool.remove(session)
			}
			original := s.registry.items[session.identifier]
			metadata := append([]dashboardTunnel(nil), original.dashboard...)
			removed := s.Unsubscribe(session.identifier)
			if removed != original {
				t.Fatalf("Unsubscribe returned %#v, want original %#v", removed, original)
			}
			if !reflect.DeepEqual(removed.dashboard, metadata) {
				t.Fatalf("unsubscribe changed dashboard metadata: %v", removed.dashboard)
			}
			if s.IsSubscribed(session.identifier) {
				t.Fatal("unsubscribe retained subscription")
			}
			if _, _, ok := s.Subscriber("example.test"); ok {
				t.Fatal("unsubscribe retained canonical route")
			}
			if connected {
				probe, err := net.Listen("tcp", original.Listeners[0].Addr().String())
				if err != nil {
					t.Fatalf("unsubscribe retained listener: %v", err)
				}
				probe.Close()
			}
		})
	}
}

func TestRetirementDetachesBeforeClosingAndPreservesReplacement(t *testing.T) {
	s, old := portTestServer(t, 30000)
	if err := s.addTunnels(map[string]*proto.Tunnel{
		"web": {Protocol: proto.HTTP, Host: "old.test:8080"},
		"tcp": {Protocol: proto.TCP, RemoteAddr: "127.0.0.1:0"},
	}, old); err != nil {
		t.Fatal(err)
	}
	item := s.registry.items[old.identifier]
	gate := gateRegistrationListener(t, item)
	removed := make(chan struct{})
	go func() { s.connPool.remove(old); close(removed) }()
	awaitPoolSignal(t, gate.entered, "old listener was not closed")
	awaitPoolSignal(t, old.ctx.Done(), "retiring session was not canceled")

	progress := make(chan error, 1)
	otherID := id.New([]byte("other"))
	go func() {
		if _, _, ok := s.Subscriber("old.test"); ok {
			progress <- errClientAlreadyConnected
			return
		}
		if len(s.registry.dashboardSnapshot()) != 0 {
			progress <- errClientAlreadyConnected
			return
		}
		s.Subscribe(otherID)
		other, err := s.connPool.AddConn(poolTestConn(t, nil, nil), otherID, "other")
		if err == nil {
			err = s.addTunnels(map[string]*proto.Tunnel{"web": {Protocol: proto.HTTP, Host: "other.test"}}, other)
		}
		progress <- err
	}()
	select {
	case err := <-progress:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Error("route reads and unrelated registration blocked during listener Close")
	}

	var preface *poolWriteGate
	candidate := poolTestConn(t, func(conn net.Conn) net.Conn {
		preface = gatePoolWrites(t, conn, func(b []byte) bool { return bytes.HasPrefix(b, []byte(http2.ClientPreface)) })
		close(preface.release)
		return preface
	}, nil)
	added := make(chan *connPair, 1)
	addErr := make(chan error, 1)
	go func() {
		current, err := s.connPool.AddConn(candidate, old.identifier, "current")
		added <- current
		addErr <- err
	}()
	select {
	case <-preface.entered:
		t.Error("same-id admission started transport before retirement completed")
	case <-time.After(50 * time.Millisecond):
	}
	close(gate.release)
	awaitPoolSignal(t, removed, "old cleanup did not finish")
	current := <-added
	if err := <-addErr; err != nil {
		t.Fatal(err)
	}
	if err := s.addTunnels(map[string]*proto.Tunnel{
		"web": {Protocol: proto.HTTP, Host: "old.test:443"},
		"tcp": {Protocol: proto.TCP, RemoteAddr: gate.Addr().String()},
	}, current); err != nil {
		t.Fatalf("replacement could not reuse fixed port: %v", err)
	}
	s.connPool.remove(old)
	s.connPool.MarkDead(old.clientConn)
	if got, _, ok := s.Subscriber("old.test"); !ok || got != current.identifier {
		t.Fatal("stale removal cleared current route")
	}
	if current.ctx.Err() != nil {
		t.Fatal("stale removal canceled replacement")
	}
	if got := gate.closes.Load(); got != 1 {
		t.Fatalf("old listener closed %d times", got)
	}
	if got := s.registry.portPool.Get(); got != item.Ports[0] {
		t.Fatalf("returned port = %d, want %d", got, item.Ports[0])
	}
	if got := s.registry.portPool.Get(); got == item.Ports[0] {
		t.Fatal("port returned twice")
	}
}

func TestStopWaitsForExistingRetirementAndWakesAdmission(t *testing.T) {
	s, old := portTestServer(t, 30000)
	if err := s.addTunnels(map[string]*proto.Tunnel{"tcp": {Protocol: proto.TCP, RemoteAddr: "127.0.0.1:0"}}, old); err != nil {
		t.Fatal(err)
	}
	gate := gateRegistrationListener(t, s.registry.items[old.identifier])
	removed := make(chan struct{})
	go func() { s.connPool.remove(old); close(removed) }()
	awaitPoolSignal(t, gate.entered, "old listener was not closed")
	admitted := make(chan error, 1)
	go func() {
		_, err := s.connPool.AddConn(poolTestConn(t, nil, nil), old.identifier, "late")
		admitted <- err
	}()
	stopped := make(chan struct{})
	go func() { s.Stop(); close(stopped) }()
	unsubscribed := make(chan struct{})
	go func() { s.Unsubscribe(old.identifier); close(unsubscribed) }()
	select {
	case err := <-admitted:
		if err != errClientNotConnected {
			t.Errorf("admission during Stop = %v", err)
		}
	case <-time.After(time.Second):
		t.Error("Stop did not wake retiring admission")
	}
	select {
	case <-stopped:
		t.Error("Stop returned before listener cleanup")
	default:
	}
	select {
	case <-unsubscribed:
		t.Error("concurrent Unsubscribe returned before listener cleanup")
	default:
	}
	close(gate.release)
	awaitPoolSignal(t, removed, "old cleanup did not finish")
	awaitPoolSignal(t, stopped, "Stop did not finish after cleanup")
	awaitPoolSignal(t, unsubscribed, "concurrent Unsubscribe did not finish after cleanup")
	if got := gate.closes.Load(); got != 1 {
		t.Fatalf("listener closed %d times", got)
	}
}

func TestUnsubscribeWaitsForExistingRetirement(t *testing.T) {
	s, old := portTestServer(t, 30000)
	if err := s.addTunnels(map[string]*proto.Tunnel{"tcp": {Protocol: proto.TCP, RemoteAddr: "127.0.0.1:0"}}, old); err != nil {
		t.Fatal(err)
	}
	gate := gateRegistrationListener(t, s.registry.items[old.identifier])
	removed := make(chan struct{})
	go func() { s.connPool.remove(old); close(removed) }()
	awaitPoolSignal(t, gate.entered, "old listener was not closed")
	unsubscribed := make(chan struct{})
	go func() { s.Unsubscribe(old.identifier); close(unsubscribed) }()
	select {
	case <-unsubscribed:
		t.Error("Unsubscribe returned before listener cleanup")
	case <-time.After(50 * time.Millisecond):
	}
	close(gate.release)
	awaitPoolSignal(t, removed, "old cleanup did not finish")
	awaitPoolSignal(t, unsubscribed, "Unsubscribe did not finish after cleanup")
	if s.IsSubscribed(old.identifier) {
		t.Fatal("Unsubscribe retained subscription")
	}
	if got := gate.closes.Load(); got != 1 {
		t.Fatalf("listener closed %d times", got)
	}
}

func TestAdmissionRechecksRetirementAfterTransportSetup(t *testing.T) {
	s, initial := portTestServer(t, 30000)
	s.connPool.remove(initial)
	var preface *poolWriteGate
	candidate := poolTestConn(t, func(conn net.Conn) net.Conn {
		preface = gatePoolWrites(t, conn, func(b []byte) bool { return bytes.HasPrefix(b, []byte(http2.ClientPreface)) })
		return preface
	}, nil)
	added := make(chan *connPair, 1)
	addErr := make(chan error, 1)
	go func() {
		cp, err := s.connPool.AddConn(candidate, initial.identifier, "pending")
		added <- cp
		addErr <- err
	}()
	awaitPoolSignal(t, preface.entered, "candidate did not start transport setup")
	old, err := s.connPool.AddConn(poolTestConn(t, nil, nil), initial.identifier, "old")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.addTunnels(map[string]*proto.Tunnel{"tcp": {Protocol: proto.TCP, RemoteAddr: "127.0.0.1:0"}}, old); err != nil {
		t.Fatal(err)
	}
	gate := gateRegistrationListener(t, s.registry.items[old.identifier])
	removed := make(chan struct{})
	go func() { s.connPool.remove(old); close(removed) }()
	awaitPoolSignal(t, gate.entered, "old listener was not closed")
	close(preface.release)
	var current *connPair
	select {
	case current = <-added:
		t.Error("pending transport admitted before listener cleanup")
	case <-time.After(50 * time.Millisecond):
	}
	close(gate.release)
	awaitPoolSignal(t, removed, "old cleanup did not finish")
	if current == nil {
		current = <-added
	}
	if err := <-addErr; err != nil {
		t.Fatal(err)
	}
	if err := s.addTunnels(map[string]*proto.Tunnel{"tcp": {Protocol: proto.TCP, RemoteAddr: gate.Addr().String()}}, current); err != nil {
		t.Fatalf("pending admission could not reuse retired listener port: %v", err)
	}
}

func poolTestRegistration(t *testing.T, p *connPool, cp *connPair) *retirementListener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	item := &RegistryItem{Tag: cp.tag, Listeners: []Listener{{Listener: listener, TunnelName: "test"}}}
	gate := gateRegistrationListener(t, item)
	close(gate.release)
	p.registry.Subscribe(cp.identifier)
	if err := p.commit(cp, item); err != nil {
		t.Fatal(err)
	}
	return gate
}

type lifecycleLockProbe struct {
	pool       *connPool
	registry   *registry
	violations atomic.Int32
}

func (l *lifecycleLockProbe) Log(...interface{}) error {
	if l.pool.mu.TryLock() {
		l.pool.mu.Unlock()
	} else {
		l.violations.Add(1)
	}
	if l.registry.mu.TryLock() {
		l.registry.mu.Unlock()
	} else {
		l.violations.Add(1)
	}
	return nil
}

func TestRegistrationLifecycleLogsOutsideLocks(t *testing.T) {
	probe := &lifecycleLockProbe{}
	r := newRegistry(probe, 30000)
	p := newConnPool(nil, r)
	probe.pool, probe.registry = p, r
	s := &Server{registry: r, connPool: p, logger: probe}
	client, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := &connPair{conn: client, identifier: id.New([]byte("logging")), tag: "current", ctx: ctx, cancel: cancel}
	p.conns[p.addr(cp.identifier)] = cp
	defer p.Close()
	s.Subscribe(cp.identifier)
	if err := s.addTunnels(map[string]*proto.Tunnel{"web": {Protocol: proto.HTTP, Host: "logging.test"}}, cp); err != nil {
		t.Fatal(err)
	}
	s.Unsubscribe(cp.identifier)
	if got := probe.violations.Load(); got != 0 {
		t.Fatalf("logging ran under lifecycle locks %d times", got)
	}
}
