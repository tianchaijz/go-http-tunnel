package tunnel

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mmatczuk/go-http-tunnel/id"
	"github.com/mmatczuk/go-http-tunnel/log"
	"github.com/mmatczuk/go-http-tunnel/proto"
	"golang.org/x/net/http2"
)

func heartbeatTestServer(t *testing.T, interval time.Duration) (*Server, id.ID) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("testdata/selfsigned.crt", "testdata/selfsigned.key")
	if err != nil {
		t.Fatal(err)
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert,
		InsecureSkipVerify: true, NextProtos: []string{"h2"},
	}
	s, err := NewServer(&ServerConfig{
		Addr: "127.0.0.1:0", TLSConfig: config, AutoSubscribe: true, HeartbeatInterval: interval,
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); s.Start() }()
	t.Cleanup(func() { s.Stop(); <-done })
	return s, id.New(cert.Certificate[0])
}

func heartbeatTestPeer(t *testing.T, s *Server, heartbeat http.HandlerFunc) net.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", s.Addr(), s.config.TLSConfig)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		new(http2.Server).ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(proto.HeaderHeartbeat) != "" {
				heartbeat(w, r)
				return
			}
			json.NewEncoder(w).Encode(map[string]*proto.Tunnel{"web": {Protocol: proto.HTTP, Host: "heartbeat.test"}})
		})})
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	deadline := time.After(2 * time.Second)
	for {
		if _, _, ok := s.Subscriber("heartbeat.test"); ok {
			return conn
		}
		select {
		case <-deadline:
			t.Fatal("peer did not register its tunnel")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestServerHeartbeatReconnect(t *testing.T) {
	s, identifier := heartbeatTestServer(t, time.Second)
	var beats int32
	heartbeat := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&beats, 1)
		w.WriteHeader(http.StatusOK)
	}
	old := heartbeatTestPeer(t, s, heartbeat)
	s.Unsubscribe(identifier)
	old.Close()
	heartbeatTestPeer(t, s, heartbeat)
	time.Sleep(2300 * time.Millisecond)
	if n := atomic.LoadInt32(&beats); n != 2 {
		t.Fatalf("heartbeats after one reconnect = %d, want 2", n)
	}
}

func TestServerStopCancelsHeartbeat(t *testing.T) {
	s, _ := heartbeatTestServer(t, 10*time.Millisecond)
	started, canceled := make(chan struct{}), make(chan struct{})
	heartbeatTestPeer(t, s, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(canceled)
	})
	awaitPoolSignal(t, started, "heartbeat did not start")
	s.Stop()
	awaitPoolSignal(t, canceled, "server Stop left heartbeat request running")
	if _, _, ok := s.Subscriber("heartbeat.test"); ok {
		t.Fatal("server Stop left tunnel registered")
	}
}

func TestServerUnsubscribeCancelsHeartbeat(t *testing.T) {
	s, identifier := heartbeatTestServer(t, 10*time.Millisecond)
	started, canceled := make(chan struct{}), make(chan struct{})
	heartbeatTestPeer(t, s, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(canceled)
	})
	awaitPoolSignal(t, started, "heartbeat did not start")
	s.Unsubscribe(identifier)
	awaitPoolSignal(t, canceled, "Unsubscribe left heartbeat request running")
	if _, err := s.Ping(identifier); err != errClientNotConnected {
		t.Fatalf("Ping after Unsubscribe = %v, want client not connected", err)
	}
}

func TestServerHeartbeatResponseFailureDisconnects(t *testing.T) {
	for _, failure := range []string{"status", "truncated body"} {
		t.Run(failure, func(t *testing.T) {
			s, identifier := heartbeatTestServer(t, 10*time.Millisecond)
			heartbeatTestPeer(t, s, func(w http.ResponseWriter, r *http.Request) {
				if failure == "status" {
					w.WriteHeader(http.StatusServiceUnavailable)
					io.WriteString(w, strings.Repeat("error", 16384))
				} else {
					w.Header().Set("Content-Length", "10")
					io.WriteString(w, "short")
				}
			})
			deadline := time.After(time.Second)
			for {
				if _, _, ok := s.Subscriber("heartbeat.test"); !ok {
					break
				}
				select {
				case <-deadline:
					t.Fatal("failed heartbeat left tunnel registered")
				case <-time.After(time.Millisecond):
				}
			}
			if _, err := s.Ping(identifier); err != errClientNotConnected {
				t.Fatalf("Ping after failed heartbeat = %v, want client not connected", err)
			}
		})
	}
}

type listenerPreparationGate struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	addr    net.Addr
}

func (g *listenerPreparationGate) Log(keyvals ...interface{}) error {
	var action string
	var addr net.Addr
	for i := 0; i < len(keyvals); i += 2 {
		switch keyvals[i] {
		case "action":
			action, _ = keyvals[i+1].(string)
		case "addr":
			addr, _ = keyvals[i+1].(net.Addr)
		}
	}
	if action == "open listener" {
		g.once.Do(func() { g.addr = addr; close(g.entered); <-g.release })
	}
	return nil
}

func TestServerRemovedHandshakeCannotPublishTunnels(t *testing.T) {
	gate := &listenerPreparationGate{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-gate.release:
		default:
			close(gate.release)
		}
	})
	s := &Server{registry: newRegistry(log.NewNopLogger(), 0), logger: gate}
	s.connPool = newConnPool(new(http2.Transport), s.disconnectedWithTag)
	defer s.connPool.Close()
	identifier := id.New([]byte("same"))
	s.Subscribe(identifier)
	old, err := s.connPool.AddConn(poolTestConn(t, nil, nil), identifier, "old")
	if err != nil {
		t.Fatal(err)
	}
	registered := make(chan error, 1)
	go func() {
		registered <- s.addTunnels(map[string]*proto.Tunnel{
			"old": {Protocol: proto.TCP, RemoteAddr: "127.0.0.1:"},
		}, old)
	}()
	awaitPoolSignal(t, gate.entered, "old handshake did not prepare listener")
	s.connPool.remove(old)
	current, err := s.connPool.AddConn(poolTestConn(t, nil, nil), identifier, "current")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.addTunnels(map[string]*proto.Tunnel{
		"web": {Protocol: proto.HTTP, Host: "current.test"},
	}, current); err != nil {
		t.Fatal(err)
	}
	close(gate.release)
	if err := <-registered; err != errClientNotConnected {
		t.Fatalf("removed handshake registration = %v, want client not connected", err)
	}
	s.connPool.remove(old)
	if _, _, ok := s.Subscriber("current.test"); !ok {
		t.Fatal("stale handshake removed replacement tunnel")
	}
	listener, err := net.Listen("tcp", gate.addr.String())
	if err != nil {
		t.Fatalf("removed handshake left prepared listener open: %v", err)
	}
	listener.Close()
}

func TestServerReconnectReusesListenerPort(t *testing.T) {
	s := &Server{registry: newRegistry(nil, 0), logger: log.NewNopLogger()}
	s.connPool = newConnPool(new(http2.Transport), s.disconnectedWithTag)
	defer s.connPool.Close()
	identifier := id.New([]byte("same"))
	s.Subscribe(identifier)
	addr := "127.0.0.1:"
	for _, tag := range []string{"old", "replacement"} {
		session, err := s.connPool.AddConn(poolTestConn(t, nil, nil), identifier, tag)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.addTunnels(map[string]*proto.Tunnel{
			"tcp": {Protocol: proto.TCP, RemoteAddr: addr},
		}, session); err != nil {
			t.Fatalf("%s failed to bind listener at %s: %v", tag, addr, err)
		}
		s.registry.mu.RLock()
		addr = s.registry.items[identifier].Listeners[0].Addr().String()
		s.registry.mu.RUnlock()
		s.connPool.remove(session)
	}
}

type controlResponseBody struct {
	io.Reader
	closed bool
}

func (b *controlResponseBody) Close() error {
	b.closed = true
	return nil
}

func TestDrainResponseClosesBody(t *testing.T) {
	for _, readErr := range []error{nil, io.ErrUnexpectedEOF} {
		body := &controlResponseBody{Reader: strings.NewReader("control response")}
		if readErr != nil {
			reader, writer := io.Pipe()
			writer.CloseWithError(readErr)
			body.Reader = reader
		}
		err := drainResponse(&http.Response{Body: body})
		if !errors.Is(err, readErr) {
			t.Errorf("drain response = %v, want %v", err, readErr)
		}
		if !body.closed {
			t.Error("control response body was not closed")
		}
	}
}
