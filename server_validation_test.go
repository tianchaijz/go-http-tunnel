package tunnel

import (
	"strings"
	"testing"

	"github.com/mmatczuk/go-http-tunnel/proto"
)

func TestServerRejectsNilTunnelBeforeAllocation(t *testing.T) {
	s, session := portTestServer(t, 65535)
	for _, tunnels := range []map[string]*proto.Tunnel{
		{"missing": nil},
		{
			"missing": nil,
			"tcp":     {Protocol: proto.TCP, RemoteAddr: "127.0.0.1:0"},
		},
	} {
		err := s.addTunnels(tunnels, session)
		if err == nil || !strings.Contains(err.Error(), "missing") {
			t.Fatalf("null tunnel error = %v, want error naming missing tunnel", err)
		}
		if rows := s.registry.dashboardSnapshot(); len(rows) != 0 {
			t.Fatalf("rejected batch registered tunnels: %v", rows)
		}
	}
	if port := s.registry.portPool.Get(); port != 65536 {
		t.Fatalf("rejected batch consumed dynamic ports: next port = %d, want 65536", port)
	}
}
