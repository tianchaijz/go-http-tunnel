package tunnel

import (
	"html"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/mmatczuk/go-http-tunnel/proto"
)

func dashboardResponse(t *testing.T, s *Server, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	t.Helper()
	handler, err := s.DashboardHandler(Auth{User: "admin", Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, nil)
	req.SetBasicAuth("admin", "secret")
	handler.ServeHTTP(w, req)
	return w
}

func TestDashboardRegistrationLifecycle(t *testing.T) {
	s, session := portTestServer(t, 30000)
	if rows := s.registry.dashboardSnapshot(); len(rows) != 0 {
		t.Fatal(rows)
	}
	fixed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixedAddr := fixed.Addr().String()
	fixed.Close()
	tunnels := map[string]*proto.Tunnel{
		"dynamic": {Protocol: proto.TCP, RemoteAddr: "127.0.0.1:0"},
		"fixed":   {Protocol: proto.TCP4, RemoteAddr: fixedAddr},
		"web":     {Protocol: proto.HTTP, Host: "app.example"},
		"socket":  {Protocol: proto.UNIX, RemoteAddr: filepath.Join(t.TempDir(), "tunnel.sock")},
	}
	if err := s.addTunnels(tunnels, session); err != nil {
		t.Fatal(err)
	}
	rows := s.registry.dashboardSnapshot()
	if len(rows) != 4 {
		t.Fatal(rows)
	}
	actual := map[string]string{}
	for _, listener := range s.registry.items[session.identifier].Listeners {
		actual[listener.TunnelName] = listener.Addr().String()
	}
	for _, row := range rows {
		if row.Name == "web" {
			if row.Address != "app.example" || row.Port != "" {
				t.Fatal(row)
			}
			continue
		}
		if row.Address != actual[row.Name] {
			t.Fatalf("%+v actual %q", row, actual[row.Name])
		}
		if row.Protocol == proto.UNIX {
			if row.Port != "" {
				t.Fatal(row)
			}
		} else {
			_, port, _ := net.SplitHostPort(actual[row.Name])
			if row.Port != port || port == "0" {
				t.Fatal(row)
			}
		}
	}
	if !reflect.DeepEqual(rows, s.registry.dashboardSnapshot()) {
		t.Fatal("unstable ordering")
	}
	s.disconnectedWithTag(session.identifier, "stale")
	if len(s.registry.dashboardSnapshot()) != 4 {
		t.Fatal("stale disconnect removed registrations")
	}
	s.disconnectedWithTag(session.identifier, session.tag)
	if len(s.registry.dashboardSnapshot()) != 0 {
		t.Fatal("disconnect retained registrations")
	}
}

func TestDashboardFailedRegistrationAndRemoval(t *testing.T) {
	for _, action := range []string{"failure", "unsubscribe", "stop"} {
		t.Run(action, func(t *testing.T) {
			s, session := portTestServer(t, 30000)
			tunnels := map[string]*proto.Tunnel{"web": {Protocol: proto.HTTP, Host: "app.example"}}
			if action == "failure" {
				tunnels["bad"] = &proto.Tunnel{Protocol: "invalid"}
			}
			err := s.addTunnels(tunnels, session)
			switch action {
			case "failure":
				if err == nil {
					t.Fatal("expected failure")
				}
			case "unsubscribe":
				if err != nil {
					t.Fatal(err)
				}
				s.Unsubscribe(session.identifier)
			case "stop":
				if err != nil {
					t.Fatal(err)
				}
				s.Stop()
			}
			if len(s.registry.dashboardSnapshot()) != 0 {
				t.Fatal("removed or failed registration visible")
			}
		})
	}
}

func TestDashboardHTTPContractAndEscaping(t *testing.T) {
	s, session := portTestServer(t, 30000)
	empty := dashboardResponse(t, s, "GET", "/")
	if !strings.Contains(empty.Body.String(), "暂无已注册隧道") {
		t.Fatal(empty.Body.String())
	}
	name := `<script>alert("name")</script>`
	host := `<img src=x onerror=alert(1)>`
	if err := s.addTunnels(map[string]*proto.Tunnel{name: {Protocol: proto.HTTP, Host: host, Auth: "UNIQUE_USER:UNIQUE_PASSWORD", Addr: "PRIVATE_BACKEND_MARKER"}}, session); err != nil {
		t.Fatal(err)
	}
	w := dashboardResponse(t, s, "GET", "/")
	body := w.Body.String()
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatal(w.Result())
	}
	for _, value := range []string{name, host, "UNIQUE_USER", "UNIQUE_PASSWORD", "PRIVATE_BACKEND_MARKER"} {
		if strings.Contains(body, value) {
			t.Fatalf("unescaped or secret content %q", value)
		}
	}
	for _, value := range []string{html.EscapeString(name), html.EscapeString(host), "共享 HTTP/HTTPS 入口，无独立端口"} {
		if !strings.Contains(body, value) {
			t.Fatalf("missing %q", value)
		}
	}
	if head := dashboardResponse(t, s, "HEAD", "/"); head.Code != 200 || head.Body.Len() != 0 {
		t.Fatal(head)
	}
	if other := dashboardResponse(t, s, "GET", "/dashboard"); other.Code != 404 {
		t.Fatal(other)
	}
	if post := dashboardResponse(t, s, "POST", "/"); post.Code != 405 || post.Header().Get("Allow") != "GET, HEAD" {
		t.Fatal(post)
	}
	for _, path := range []string{"/", "/dashboard"} {
		req := httptest.NewRequest("GET", path, nil)
		req.Host = host
		response := httptest.NewRecorder()
		s.ServeHTTP(response, req)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("public %s = %d", path, response.Code)
		}
	}
}

func TestDashboardConcurrentSnapshots(t *testing.T) {
	s, session := portTestServer(t, 30000)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if w := dashboardResponse(t, s, "GET", "/"); w.Code != 200 {
				t.Errorf("status %d", w.Code)
			}
		}
	}()
	for i := 0; i < 100; i++ {
		if err := s.addTunnels(map[string]*proto.Tunnel{"web": {Protocol: proto.HTTP, Host: "app.example"}}, session); err != nil {
			t.Fatal(err)
		}
		s.disconnectedWithTag(session.identifier, session.tag)
	}
	wg.Wait()
}

func TestDashboardInvalidCredentials(t *testing.T) {
	for _, auth := range []Auth{{}, {User: "admin"}, {Password: "secret"}, {User: "ad:min", Password: "secret"}} {
		var s Server
		handler, err := s.DashboardHandler(auth)
		if err == nil || handler != nil {
			t.Fatalf("invalid credentials returned handler %v, error %v", handler, err)
		}
	}
}

func TestDashboardAuthentication(t *testing.T) {
	s, session := portTestServer(t, 30000)
	const marker = "PRIVATE_TUNNEL_MARKER"
	if err := s.addTunnels(map[string]*proto.Tunnel{marker: {Protocol: proto.HTTP, Host: marker + ".example"}}, session); err != nil {
		t.Fatal(err)
	}
	auth := Auth{User: "admin", Password: " secret:with:colons "}
	handler, err := s.DashboardHandler(auth)
	if err != nil {
		t.Fatal(err)
	}
	auth.User, auth.Password = "changed", "changed"
	for _, route := range []struct{ method, path string }{{"GET", "/"}, {"HEAD", "/"}, {"POST", "/"}, {"GET", "/missing"}, {"DELETE", "/missing"}} {
		for _, authorization := range []string{"", "Basic !!!", "Basic YWRtaW4=", "Bearer secret", "Basic OmFkbWlu", "Basic YWRtaW46d3Jvbmc=", "Basic d3Jvbmc6IHNlY3JldDp3aXRoOmNvbG9ucyA="} {
			req := httptest.NewRequest(route.method, route.path, nil)
			req.Header.Set("Authorization", authorization)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != `Basic realm="Tunnel dashboard"` || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("%s %s unauthorized response: %v", route.method, route.path, w.Result())
			}
			if w.Body.String() != "Unauthorized\n" || strings.Contains(w.Body.String(), marker) {
				t.Fatalf("unexpected denial body %q", w.Body.String())
			}
		}
	}
	for _, credentials := range []Auth{{User: "admin", Password: " secret:with:colons "}, auth} {
		req := httptest.NewRequest("GET", "/", nil)
		req.SetBasicAuth(credentials.User, credentials.Password)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if credentials.User == "admin" {
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), marker) {
				t.Fatalf("original credentials failed: %v", w.Result())
			}
		} else if w.Code != http.StatusUnauthorized {
			t.Fatalf("mutated credentials accepted: %v", w.Result())
		}
	}
}
