package tunnel_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mmatczuk/go-http-tunnel"
)

func TestDashboardPreservesPublicApplicationRoutes(t *testing.T) {
	backendHTTP, backendTCP := makeEcho(t)
	defer backendHTTP.Close()
	defer backendTCP.Close()
	s := makeTunnelServer(t)
	defer s.Stop()
	public := httptest.NewServer(s)
	defer public.Close()
	public.Client().Timeout = 3 * time.Second
	client := makeTunnelClient(t, s.Addr(), public.Listener.Addr(), backendHTTP.Addr(), freeAddr(), backendTCP.Addr())
	defer client.Stop()
	handler, err := s.DashboardHandler(tunnel.Auth{User: "admin", Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.SetBasicAuth("admin", "secret")
		handler.ServeHTTP(w, req)
		if strings.Contains(w.Body.String(), "共 2 条隧道") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("client did not register")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, path := range []string{"/", "/dashboard"} {
		req, err := http.NewRequest("POST", public.URL+path, strings.NewReader("application response"))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "localhost:" + port(public.Listener.Addr())
		req.SetBasicAuth("user", "password")
		response, err := public.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 200 || string(body) != "application response" {
			t.Fatalf("route %s status %d body %q", path, response.StatusCode, body)
		}
	}
}
