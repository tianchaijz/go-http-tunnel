package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/mmatczuk/go-http-tunnel/id"
	"golang.org/x/net/http2"
)

func handshakeTimeout(t *testing.T) {
	t.Helper()
	previous := DefaultTimeout
	DefaultTimeout = 250 * time.Millisecond
	t.Cleanup(func() { DefaultTimeout = previous })
}

func TestClient_TLSHandshakeTimeout(t *testing.T) {
	handshakeTimeout(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	c := lifecycleClient(t)
	c.config.ServerAddr = listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := c.dial(ctx)
		if conn != nil {
			conn.Close()
		}
		result <- err
	}()
	t.Cleanup(func() { cancel(); <-done })
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := peer.Read(make([]byte, 4096)); err != nil {
		t.Fatal("client did not send TLS handshake:", err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("stalled TLS handshake = %v, want deadline exceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client TLS handshake exceeded DefaultTimeout without returning")
	}
}

func TestServer_TLSHandshakeTimeout(t *testing.T) {
	handshakeTimeout(t)
	s, err := NewServer(&ServerConfig{Addr: "127.0.0.1:0", TLSConfig: &tls.Config{}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.listener.Close()
	peer, err := net.Dial("tcp", s.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := s.listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleClient(tls.Server(conn, s.config.TLSConfig))
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server TLS handshake exceeded DefaultTimeout without returning")
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := peer.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("timed-out peer read = %d, %v, want 0, EOF", n, err)
	}
}

func TestTLSHandshakeTimeoutLeavesSessionUsable(t *testing.T) {
	handshakeTimeout(t)
	cert, err := tls.LoadX509KeyPair("testdata/selfsigned.crt", "testdata/selfsigned.key")
	if err != nil {
		t.Fatal(err)
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert,
		InsecureSkipVerify: true, NextProtos: []string{"h2"},
	}
	s, err := NewServer(&ServerConfig{Addr: "127.0.0.1:0", TLSConfig: config, AutoSubscribe: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := s.listener.Accept()
		if err == nil {
			s.handleClient(tls.Server(conn, config))
		}
	}()
	c := lifecycleClient(t)
	c.config.ServerAddr = s.listener.Addr().String()
	c.config.TLSClientConfig = config
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := c.dial(ctx)
	if err != nil {
		s.listener.Close()
		<-serverDone
		t.Fatal(err)
	}
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		h2 := &http2.Server{}
		h2.ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"test":{"protocol":"http","host":"timeout.test"}}`)
		})})
	}()
	t.Cleanup(func() { conn.Close(); <-clientDone; <-serverDone })
	select {
	case <-serverDone:
	case <-ctx.Done():
		t.Fatal("server did not finish connection setup")
	}
	time.Sleep(2 * DefaultTimeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, s.connPool.URL(id.New(cert.Certificate[0])), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		t.Fatal("HTTP/2 session failed after TLS handshake timeout elapsed:", err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/2 response status = %d, want 200", resp.StatusCode)
	}
}
