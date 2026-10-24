package tunnel

import (
	"net"
	"strconv"
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

func TestRegistrationEmptyPortUsesOSAllocation(t *testing.T) {
	s, session := portTestServer(t, 30000)
	raw := &proto.Tunnel{Protocol: proto.TCP, RemoteAddr: "127.0.0.1:"}
	if err := s.addTunnels(map[string]*proto.Tunnel{"tcp": raw}, session); err != nil {
		t.Fatalf("empty port must retain net.Listen allocation: %v", err)
	}
	rows := s.registry.dashboardSnapshot()
	if len(rows) != 1 {
		t.Fatalf("registered tunnels = %v", rows)
	}
	_, port, err := net.SplitHostPort(rows[0].Address)
	if err != nil || port == "" || port == "0" {
		t.Fatalf("OS allocated address = %q", rows[0].Address)
	}
	if next := s.registry.portPool.Get(); next != 30001 {
		t.Fatalf("OS allocation consumed a pooled port: next = %d", next)
	}
	if raw.RemoteAddr != "127.0.0.1:" {
		t.Fatalf("registration changed input to %q", raw.RemoteAddr)
	}
}

func TestRegistrationOccupiedHostRollsBackOnlyDraft(t *testing.T) {
	s, owner := portTestServer(t, 30000)
	if err := s.addTunnels(map[string]*proto.Tunnel{"web": {Protocol: proto.HTTP, Host: "occupied.test:80", Auth: "owner:secret"}}, owner); err != nil {
		t.Fatal(err)
	}
	otherID := id.New([]byte("other"))
	s.Subscribe(otherID)
	other, err := s.connPool.AddConn(poolTestConn(t, nil, nil), otherID, "other")
	if err != nil {
		t.Fatal(err)
	}
	prepared := &listenerPreparationGate{entered: make(chan struct{}), release: make(chan struct{})}
	close(prepared.release)
	s.logger = prepared
	err = s.addTunnels(map[string]*proto.Tunnel{
		"new":      {Protocol: proto.HTTP, Host: "new.test"},
		"occupied": {Protocol: proto.HTTP, Host: "occupied.test:443"},
		"tcp":      {Protocol: proto.TCP, RemoteAddr: "127.0.0.1:0"},
	}, other)
	if err == nil || !strings.Contains(err.Error(), "occupied") {
		t.Fatalf("occupied registration = %v", err)
	}
	if got, auth, ok := s.Subscriber("occupied.test"); !ok || got != owner.identifier || auth == nil || auth.User != "owner" {
		t.Fatalf("occupied route changed to %s, %#v, %v", got, auth, ok)
	}
	if _, _, ok := s.Subscriber("new.test"); ok {
		t.Fatal("failed batch published a new route")
	}
	if rows := s.registry.dashboardSnapshot(); len(rows) != 1 || rows[0].Client != owner.identifier {
		t.Fatalf("failed batch changed dashboard: %v", rows)
	}
	port := s.registry.portPool.Get()
	if prepared.addr == nil || port != uint64(prepared.addr.(*net.TCPAddr).Port) {
		t.Fatalf("failed draft returned port %d, prepared address %v", port, prepared.addr)
	}
	probe, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.FormatUint(port, 10)))
	if err != nil {
		t.Fatalf("failed draft retained its listener: %v", err)
	}
	probe.Close()
}
