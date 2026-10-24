package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/mmatczuk/go-http-tunnel/id"
	"github.com/mmatczuk/go-http-tunnel/proto"
)

func portTestServer(t *testing.T, startPort uint64) (*Server, *connPair) {
	t.Helper()
	s, err := NewServer(&ServerConfig{
		Addr: "127.0.0.1:0", TLSConfig: &tls.Config{}, StartPort: startPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	identifier := id.New([]byte(t.Name()))
	s.Subscribe(identifier)
	session, err := s.connPool.AddConn(poolTestConn(t, nil, nil), identifier, "test")
	if err != nil {
		t.Fatal(err)
	}
	return s, session
}

func TestServerDynamicPortFailureReturns(t *testing.T) {
	for _, tt := range []struct {
		name      string
		startPort uint64
		protocol  string
		addr      string
	}{
		{"exhausted", 65535, proto.TCP, "127.0.0.1:0"},
		{"overflow", ^uint64(0), proto.TCP, "127.0.0.1:0"},
		{"invalid bind address", 30000, proto.TCP6, "127.0.0.1:0"},
		{"IPv6 exhausted", 65535, proto.TCP6, "[::1]:0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, session := portTestServer(t, tt.startPort)
			done := make(chan error, 1)
			go func() {
				done <- s.addTunnels(map[string]*proto.Tunnel{
					"tcp": {Protocol: tt.protocol, RemoteAddr: tt.addr},
				}, session)
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("invalid dynamic port allocation succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("dynamic port allocation did not return")
			}
		})
	}
}

func TestServerCanceledTunnelSetup(t *testing.T) {
	s, session := portTestServer(t, 30000)
	session.cancel()
	err := s.addTunnels(map[string]*proto.Tunnel{
		"tcp": {Protocol: proto.TCP, RemoteAddr: "127.0.0.1:0"},
	}, session)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled setup = %v, want context canceled", err)
	}
}

func TestServerDynamicPortRetryAndRollbackReuse(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port
	if port == 65535 {
		t.Skip("no port available above the occupied port")
	}
	s, session := portTestServer(t, uint64(port-1))
	s.registry.Unsubscribe(session.identifier)
	tunnel := &proto.Tunnel{Protocol: proto.TCP, RemoteAddr: "127.0.0.1:0"}
	if err := s.addTunnels(map[string]*proto.Tunnel{"tcp": tunnel}, session); err != errClientNotSubscribed {
		t.Fatalf("unsubscribed setup = %v, want client not subscribed", err)
	}
	_, allocated, err := net.SplitHostPort(tunnel.RemoteAddr)
	if err != nil {
		t.Fatal(err)
	}
	allocatedPort, err := strconv.Atoi(allocated)
	if err != nil || allocatedPort <= port || allocatedPort > 65535 {
		t.Fatalf("allocated port = %q, want a valid port above occupied %d", allocated, port)
	}
	probe, err := net.Listen("tcp", tunnel.RemoteAddr)
	if err != nil {
		t.Fatalf("rollback left allocated listener open: %v", err)
	}
	probe.Close()
	s.Subscribe(session.identifier)
	retry := &proto.Tunnel{Protocol: proto.TCP, RemoteAddr: "127.0.0.1:0"}
	if err := s.addTunnels(map[string]*proto.Tunnel{"tcp": retry}, session); err != nil {
		t.Fatal(err)
	}
	if retry.RemoteAddr != tunnel.RemoteAddr {
		t.Fatalf("retry allocated %s, want rolled-back address %s", retry.RemoteAddr, tunnel.RemoteAddr)
	}
}
