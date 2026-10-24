package tunnel

import (
	"net"
	"strings"
	"testing"

	"github.com/mmatczuk/go-http-tunnel/id"
	"github.com/mmatczuk/go-http-tunnel/proto"
)

func TestRegistrationRejectsInvalidBatch(t *testing.T) {
	for _, tt := range []struct {
		name    string
		tunnels map[string]*proto.Tunnel
	}{
		{"empty", nil},
		{"null", map[string]*proto.Tunnel{"bad": nil}},
		{"unsupported", map[string]*proto.Tunnel{"bad": {Protocol: "udp", RemoteAddr: "127.0.0.1:0"}}},
		{"missing protocol", map[string]*proto.Tunnel{"bad": {Host: "example.test"}}},
		{"missing host", map[string]*proto.Tunnel{"bad": {Protocol: proto.HTTP}}},
		{"missing auth user", map[string]*proto.Tunnel{"bad": {Protocol: proto.HTTP, Host: "example.test", Auth: ":password"}}},
		{"missing TCP address", map[string]*proto.Tunnel{"bad": {Protocol: proto.TCP}}},
		{"missing UNIX address", map[string]*proto.Tunnel{"bad": {Protocol: proto.UNIX}}},
		{"missing port", map[string]*proto.Tunnel{"bad": {Protocol: proto.TCP, RemoteAddr: "127.0.0.1:"}}},
		{"malformed address", map[string]*proto.Tunnel{"bad": {Protocol: proto.TCP, RemoteAddr: "127.0.0.1"}}},
		{"duplicate canonical hosts", map[string]*proto.Tunnel{
			"first":  {Protocol: proto.HTTP, Host: "example.test:80"},
			"second": {Protocol: proto.HTTP, Host: "example.test:443"},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, session := portTestServer(t, 30000)
			if err := s.addTunnels(tt.tunnels, session); err == nil {
				t.Fatal("invalid registration succeeded")
			}
			if got := s.registry.dashboardSnapshot(); len(got) != 0 {
				t.Fatalf("invalid registration published %v", got)
			}
		})
	}
}

func TestRegistrationValidatesBeforeAllocation(t *testing.T) {
	s, session := portTestServer(t, 65535)
	err := s.addTunnels(map[string]*proto.Tunnel{
		"listener": {Protocol: proto.TCP, RemoteAddr: "127.0.0.1:0"},
		"bad-auth": {Protocol: proto.HTTP, Host: "example.test", Auth: ":password"},
	}, session)
	if err == nil || !strings.Contains(err.Error(), "auth") {
		t.Errorf("registration error = %v, want invalid auth", err)
	}
	if next := s.registry.portPool.Get(); next != 65536 {
		t.Errorf("invalid registration consumed port %d", next-1)
	}
}

func TestRegistrationCanonicalHostRemoval(t *testing.T) {
	s, session := portTestServer(t, 30000)
	const host = "example.test:8080"
	if err := s.addTunnels(map[string]*proto.Tunnel{"http": {Protocol: proto.HTTP, Host: host}}, session); err != nil {
		t.Fatal(err)
	}
	if got, _, ok := s.Subscriber("example.test:443"); !ok || got != session.identifier {
		t.Fatalf("canonical subscriber = %s, %v", got, ok)
	}
	s.Unsubscribe(session.identifier)
	if _, _, ok := s.Subscriber(host); ok {
		t.Fatal("unsubscribe retained canonical route")
	}
	other := id.New([]byte("other"))
	s.Subscribe(other)
	next, err := s.connPool.AddConn(poolTestConn(t, nil, nil), other, "next")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.addTunnels(map[string]*proto.Tunnel{"http": {Protocol: proto.HTTP, Host: host}}, next); err != nil {
		t.Fatalf("canonical route was not reusable: %v", err)
	}
}

func TestRegistrationPreservesInputAndAuth(t *testing.T) {
	s, session := portTestServer(t, 30000)
	raw := &proto.Tunnel{Protocol: proto.TCP, RemoteAddr: "127.0.0.1:0"}
	if err := s.addTunnels(map[string]*proto.Tunnel{
		"tcp":  raw,
		"http": {Protocol: proto.HTTP, Host: "example.test:8080", Auth: "user"},
	}, session); err != nil {
		t.Fatal(err)
	}
	if raw.RemoteAddr != "127.0.0.1:0" {
		t.Errorf("registration changed input to %q", raw.RemoteAddr)
	}
	_, auth, ok := s.Subscriber("example.test")
	if !ok || auth == nil || auth.User != "user" || auth.Password != "" {
		t.Fatalf("username-only auth = %#v, %v", auth, ok)
	}
	for _, row := range s.registry.dashboardSnapshot() {
		if row.Protocol == proto.TCP {
			_, port, err := net.SplitHostPort(row.Address)
			if err != nil || port == "0" {
				t.Fatalf("allocated address = %q", row.Address)
			}
		}
	}
}
