package tunnel

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mmatczuk/go-http-tunnel/proto"
)

type notifiedBackoff struct {
	waiting chan struct{}
}

func (b *notifiedBackoff) NextBackOff() time.Duration {
	b.waiting <- struct{}{}
	return time.Hour
}

func (b *notifiedBackoff) Reset() {}

func lifecycleClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(&ClientConfig{
		ServerAddr:              "localhost:443",
		TLSClientConfig:         &tls.Config{InsecureSkipVerify: true},
		Tunnels:                 map[string]*proto.Tunnel{"test": {}},
		Proxy:                   Proxy(ProxyFuncs{}),
		ServerHeartbeatInterval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func startClient(c *Client) <-chan error {
	done := make(chan error, 1)
	go func() { done <- c.Start() }()
	return done
}

func awaitClient(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start after Stop = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

func stopClient(t *testing.T, c *Client) {
	t.Helper()
	done := make(chan struct{})
	go func() { c.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop blocked")
	}
}

func TestClient_StopBackoff(t *testing.T) {
	for _, phase := range []string{"dial", "serve"} {
		t.Run(phase, func(t *testing.T) {
			c := lifecycleClient(t)
			b := &notifiedBackoff{waiting: make(chan struct{}, 1)}
			c.config.DialTLS = func(string, string, *tls.Config) (net.Conn, error) {
				if phase == "dial" {
					return nil, errors.New("dial failed")
				}
				conn, peer := net.Pipe()
				peer.Close()
				return conn, nil
			}
			if phase == "dial" {
				c.config.DialBackoff = b
			} else {
				c.config.ServeBackoff = b
			}
			done := startClient(c)
			select {
			case <-b.waiting:
			case <-time.After(2 * time.Second):
				t.Fatal("client did not enter backoff")
			}
			stopClient(t, c)
			awaitClient(t, done)
		})
	}
}

func TestClient_StopDuringDialCallback(t *testing.T) {
	c := lifecycleClient(t)
	entered, release := make(chan struct{}), make(chan struct{})
	conn, peer := net.Pipe()
	defer peer.Close()
	c.config.DialTLS = func(string, string, *tls.Config) (net.Conn, error) {
		close(entered)
		<-release
		return conn, nil
	}
	done := startClient(c)
	<-entered
	stopClient(t, c)
	duplicate := startClient(c)
	select {
	case err := <-duplicate:
		if err == nil {
			t.Fatal("duplicate Start succeeded while callback is pending")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("duplicate Start blocked")
	}
	select {
	case <-done:
		t.Fatal("Start returned before synchronous callback completed")
	default:
	}
	close(release)
	awaitClient(t, done)
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := peer.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("late dial connection read = %d, %v, want 0, EOF", n, err)
	}
}

func TestClient_StopActiveSessionAndRestart(t *testing.T) {
	c := lifecycleClient(t)
	c.Stop()
	for i := 0; i < 2; i++ {
		if i == 1 {
			c.config.ServeBackoff = &notifiedBackoff{waiting: make(chan struct{}, 1)}
		}
		conn, peer := net.Pipe()
		dials := 0
		c.config.DialTLS = func(string, string, *tls.Config) (net.Conn, error) {
			dials++
			return conn, nil
		}
		done := startClient(c)
		peer.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := peer.Read(make([]byte, 1)); err != nil {
			t.Fatal("client did not serve connection:", err)
		}
		duplicate := startClient(c)
		select {
		case err := <-duplicate:
			if err == nil {
				t.Fatal("duplicate Start succeeded")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("duplicate Start blocked")
		}
		stopClient(t, c)
		awaitClient(t, done)
		if dials != 1 {
			t.Errorf("dial count after Stop = %d, want 1", dials)
		}
		peer.Close()
		c.Stop()
	}
}

func TestClient_StopTLSHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	c := lifecycleClient(t)
	c.config.ServerAddr = listener.Addr().String()
	done := startClient(c)
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := peer.Read(make([]byte, 4096)); err != nil {
		t.Fatal("client did not send TLS handshake:", err)
	}
	stopClient(t, c)
	awaitClient(t, done)
}
