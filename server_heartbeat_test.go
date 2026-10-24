package tunnel

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mmatczuk/go-http-tunnel/id"
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
