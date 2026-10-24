package tunnel

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mmatczuk/go-http-tunnel/proto"
)

func TestProxySetupErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		proxy    ProxyFunc
		protocol string
		request  string
		status   int
	}{
		{"unconfigured HTTP", Proxy(ProxyFuncs{}), proto.HTTP, "", http.StatusBadGateway},
		{"unconfigured TCP", Proxy(ProxyFuncs{}), proto.TCP, "", http.StatusBadGateway},
		{"unsupported dispatcher", Proxy(ProxyFuncs{}), "unknown", "", http.StatusBadRequest},
		{"unsupported HTTP", NewHTTPProxy(nil, nil).Proxy, proto.TCP, "", http.StatusBadRequest},
		{"malformed HTTP", NewHTTPProxy(nil, nil).Proxy, proto.HTTP, "bad request", http.StatusBadRequest},
		{"missing HTTP target", NewHTTPProxy(nil, nil).Proxy, proto.HTTP, "GET / HTTP/1.1\r\nHost: public.example\r\n\r\n", http.StatusBadGateway},
		{"unsupported TCP", NewTCPProxy("", nil).Proxy, proto.HTTP, "", http.StatusBadRequest},
		{"missing TCP target", NewTCPProxy("", nil).Proxy, proto.TCP, "", http.StatusBadGateway},
		{"failed TCP dial", NewTCPProxy("invalid address", nil).Proxy, proto.TCP, "", http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &halfCloseReader{ReadCloser: io.NopCloser(strings.NewReader(tc.request))}
			response := httptest.NewRecorder()
			tc.proxy(response, body, &proto.ControlMessage{ForwardedProto: tc.protocol})
			if response.Code != tc.status {
				t.Errorf("status = %d, want %d; body = %q", response.Code, tc.status, response.Body.String())
			}
			if !body.closed {
				t.Error("upload body left open")
			}
		})
	}
}

func TestHTTPProxyMissingTarget(t *testing.T) {
	p := NewMultiHTTPProxy(map[string]*url.URL{}, nil)
	called := false
	p.Transport = halfCloseTransport(func(*http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
	})
	response := httptest.NewRecorder()
	p.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://missing.example/path", nil))
	if response.Code != http.StatusBadGateway || called {
		t.Fatalf("status = %d, transport called = %v", response.Code, called)
	}
}

func TestHTTPProxyDirectorMissingTargetCancelsRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://missing.example/path", nil)
	NewHTTPProxy(nil, nil).Director(req)
	if req.Context().Err() != context.Canceled {
		t.Fatalf("context error = %v, want canceled", req.Context().Err())
	}
}

func TestHTTPProxyURLRewrite(t *testing.T) {
	for _, tc := range []struct{ name, target, request, want string }{
		{"trailing slash", "/base/", "/child/", "/base/child/"},
		{"root slash", "/base", "/", "/base/"},
		{"repeated slash", "/base/", "/child//leaf", "/base/child//leaf"},
		{"escaped path", "/base%2Fprefix/", "/child%2Fleaf/", "/base%2Fprefix/child%2Fleaf/"},
		{"query", "/base/?a=1", "/child/?b=2", "/base/child/?a=1&b=2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type received struct{ uri, host, userAgent, forwardedFor string }
			got := make(chan received, 1)
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got <- received{r.RequestURI, r.Host, r.Header.Get("User-Agent"), r.Header.Get("X-Forwarded-For")}
				w.WriteHeader(http.StatusCreated)
			}))
			defer backend.Close()
			target, err := url.Parse(backend.URL + tc.target)
			if err != nil {
				t.Fatal(err)
			}
			p := NewHTTPProxy(target, nil)
			response := httptest.NewRecorder()
			p.Proxy(response, io.NopCloser(strings.NewReader("GET "+tc.request+" HTTP/1.1\r\nHost: public.example\r\n\r\n")), &proto.ControlMessage{ForwardedProto: proto.HTTP, ForwardedHost: "public.example", RemoteAddr: "192.0.2.1:1234"})
			if response.Code != http.StatusCreated {
				t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
			}
			request := <-got
			if request.uri != tc.want || request.host != target.Host || request.userAgent != "" || request.forwardedFor != "192.0.2.1" {
				t.Errorf("backend request = %+v, want URI %q, host %q, empty user agent, forwarded client", request, tc.want, target.Host)
			}
		})
	}
}
