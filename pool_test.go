package tunnel

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/mmatczuk/go-http-tunnel/id"
	"golang.org/x/net/http2"
)

type poolWriteGate struct {
	net.Conn
	match   func([]byte) bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *poolWriteGate) Write(b []byte) (int, error) {
	if c.match(b) {
		c.once.Do(func() { close(c.entered); <-c.release })
	}
	return c.Conn.Write(b)
}

func gatePoolWrites(t *testing.T, conn net.Conn, match func([]byte) bool) *poolWriteGate {
	t.Helper()
	gate := &poolWriteGate{Conn: conn, match: match, entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-gate.release:
		default:
			close(gate.release)
		}
	})
	return gate
}

func poolPingFrame(ack bool) func([]byte) bool {
	return func(b []byte) bool {
		for len(b) >= 9 {
			n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
			if b[3] == byte(http2.FramePing) && (b[4]&byte(http2.FlagPingAck) != 0) == ack {
				return true
			}
			if len(b) < 9+n {
				break
			}
			b = b[9+n:]
		}
		return false
	}
}

func poolTestConn(t *testing.T, wrapClient, wrapServer func(net.Conn) net.Conn) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	if wrapClient != nil {
		client = wrapClient(client)
	}
	if wrapServer != nil {
		server = wrapServer(server)
	}
	go new(http2.Server).ServeConn(server, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})})
	return client
}

func awaitPoolSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}

func TestConnPoolProbeAllowsOtherClients(t *testing.T) {
	for _, operation := range []string{"Ping", "AddConn"} {
		t.Run(operation, func(t *testing.T) {
			p := newConnPool(new(http2.Transport), nil)
			slowID, fastID := id.New([]byte("slow")), id.New([]byte("fast"))
			var gate *poolWriteGate
			slow := poolTestConn(t, nil, func(conn net.Conn) net.Conn {
				gate = gatePoolWrites(t, conn, poolPingFrame(true))
				return gate
			})
			if err := p.AddConn(slow, slowID); err != nil {
				t.Fatal(err)
			}
			if err := p.AddConn(poolTestConn(t, nil, nil), fastID); err != nil {
				t.Fatal(err)
			}
			candidate := poolTestConn(t, nil, nil)
			probe := make(chan error, 1)
			go func() {
				if operation == "Ping" {
					_, err := p.Ping(slowID)
					probe <- err
				} else {
					probe <- p.AddConn(candidate, slowID)
				}
			}()
			awaitPoolSignal(t, gate.entered, "peer did not attempt PING ACK")
			request := make(chan error, 1)
			go func() {
				req, _ := http.NewRequest(http.MethodGet, p.URL(fastID), nil)
				cc, err := p.GetClientConn(req, p.addr(fastID))
				if err == nil {
					var resp *http.Response
					resp, err = cc.RoundTrip(req)
					if err == nil {
						body, readErr := io.ReadAll(resp.Body)
						resp.Body.Close()
						err = readErr
						if err == nil && string(body) != "ok" {
							err = fmt.Errorf("response = %q, want ok", body)
						}
					}
				}
				request <- err
			}()
			select {
			case err := <-request:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(100 * time.Millisecond):
				t.Error("unrelated client's request blocked while PING ACK was gated")
			}
			close(gate.release)
			err := <-probe
			if operation == "Ping" && err != nil || operation == "AddConn" && err != errClientAlreadyConnected {
				t.Fatalf("%s = %v", operation, err)
			}
		})
	}
}

func TestConnPoolAddConnPrefaceAllowsOtherClients(t *testing.T) {
	p := newConnPool(new(http2.Transport), nil)
	fastID := id.New([]byte("fast"))
	if err := p.AddConn(poolTestConn(t, nil, nil), fastID); err != nil {
		t.Fatal(err)
	}
	var gate *poolWriteGate
	candidate := poolTestConn(t, func(conn net.Conn) net.Conn {
		gate = gatePoolWrites(t, conn, func(b []byte) bool { return bytes.HasPrefix(b, []byte(http2.ClientPreface)) })
		return gate
	}, nil)
	added := make(chan error, 1)
	go func() { added <- p.AddConn(candidate, id.New([]byte("slow"))) }()
	awaitPoolSignal(t, gate.entered, "client did not write HTTP/2 preface")
	lookup := make(chan error, 1)
	go func() { _, err := p.GetClientConn(nil, p.addr(fastID)); lookup <- err }()
	select {
	case err := <-lookup:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("unrelated client's lookup blocked while HTTP/2 preface was gated")
	}
	close(gate.release)
	if err := <-added; err != nil {
		t.Fatal(err)
	}
}

func TestConnPoolStaleProbePreservesReplacement(t *testing.T) {
	var frees int
	p := newConnPool(new(http2.Transport), func(id.ID) { frees++ })
	identifier := id.New([]byte("same"))
	var gate *poolWriteGate
	old := poolTestConn(t, func(conn net.Conn) net.Conn {
		gate = gatePoolWrites(t, conn, poolPingFrame(false))
		return gate
	}, nil)
	if err := p.AddConn(old, identifier); err != nil {
		t.Fatal(err)
	}
	candidate := poolTestConn(t, nil, nil)
	stale := make(chan error, 1)
	go func() { stale <- p.AddConn(candidate, identifier) }()
	awaitPoolSignal(t, gate.entered, "duplicate probe did not send PING")
	replaced := make(chan error, 1)
	newer := poolTestConn(t, nil, nil)
	go func() {
		p.DeleteConn(identifier)
		replaced <- p.AddConn(newer, identifier)
	}()
	select {
	case err := <-replaced:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		close(gate.release)
		<-stale
		<-replaced
		t.Fatal("same-ID replacement blocked behind stale probe")
	}
	close(gate.release)
	if err := <-stale; err != errClientAlreadyConnected {
		t.Fatalf("stale AddConn = %v, want already connected", err)
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.conns[p.addr(identifier)].conn != newer {
		t.Error("stale probe replaced the newer connection")
	}
	if frees != 1 {
		t.Errorf("cleanup callbacks = %d, want only the deleted connection's callback", frees)
	}
}
