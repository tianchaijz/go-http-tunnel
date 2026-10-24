package tunnel_test

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	tunnel "github.com/mmatczuk/go-http-tunnel"
	"github.com/mmatczuk/go-http-tunnel/proto"
)

func TestPublicTCPHalfClose(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("testdata/selfsigned.crt", "testdata/selfsigned.key")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert, InsecureSkipVerify: true}
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				body, err := io.ReadAll(conn)
				if err == nil {
					io.WriteString(conn, "reply:"+string(body))
				}
			}()
		}
	}()
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	public := reservation.Addr().String()
	reservation.Close()
	server, err := tunnel.NewServer(&tunnel.ServerConfig{Addr: "127.0.0.1:0", TLSConfig: cfg, AutoSubscribe: true})
	if err != nil {
		t.Fatal(err)
	}
	go server.Start()
	defer server.Stop()
	client, err := tunnel.NewClient(&tunnel.ClientConfig{
		ServerAddr: server.Addr(), TLSClientConfig: cfg,
		Tunnels: map[string]*proto.Tunnel{"echo": {Protocol: proto.TCP, RemoteAddr: public}},
		Proxy:   tunnel.Proxy(tunnel.ProxyFuncs{TCP: tunnel.NewTCPProxy(backend.Addr().String(), nil).Proxy}),
	})
	if err != nil {
		t.Fatal(err)
	}
	go client.Start()
	defer client.Stop()
	var conn net.Conn
	for i := 0; i < 100; i++ {
		conn, err = net.DialTimeout("tcp", public, 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = io.WriteString(conn, "request"); err != nil {
		t.Fatal(err)
	}
	if err = conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(conn)
	if err != nil || string(body) != "reply:request" {
		t.Fatalf("half-close response = %q, %v; want reply:request", body, err)
	}
	t.Log("PASS: client CloseWrite preserves the backend response")
}
