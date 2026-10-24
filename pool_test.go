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
			if _, err := p.AddConn(slow, slowID, "test"); err != nil {
				t.Fatal(err)
			}
			if _, err := p.AddConn(poolTestConn(t, nil, nil), fastID, "test"); err != nil {
				t.Fatal(err)
			}
			candidate := poolTestConn(t, nil, nil)
			probe := make(chan error, 1)
			go func() {
				if operation == "Ping" {
					_, err := p.Ping(slowID)
					probe <- err
				} else {
					_, err := p.AddConn(candidate, slowID, "test")
					probe <- err
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
	if _, err := p.AddConn(poolTestConn(t, nil, nil), fastID, "test"); err != nil {
		t.Fatal(err)
	}
	var gate *poolWriteGate
	candidate := poolTestConn(t, func(conn net.Conn) net.Conn {
		gate = gatePoolWrites(t, conn, func(b []byte) bool { return bytes.HasPrefix(b, []byte(http2.ClientPreface)) })
		return gate
	}, nil)
	added := make(chan error, 1)
	go func() { _, err := p.AddConn(candidate, id.New([]byte("slow")), "test"); added <- err }()
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
	p := newConnPool(new(http2.Transport), func(id.ID, string) { frees++ })
	identifier := id.New([]byte("same"))
	var gate *poolWriteGate
	old := poolTestConn(t, func(conn net.Conn) net.Conn {
		gate = gatePoolWrites(t, conn, poolPingFrame(false))
		return gate
	}, nil)
	if _, err := p.AddConn(old, identifier, "test"); err != nil {
		t.Fatal(err)
	}
	candidate := poolTestConn(t, nil, nil)
	stale := make(chan error, 1)
	go func() { _, err := p.AddConn(candidate, identifier, "test"); stale <- err }()
	awaitPoolSignal(t, gate.entered, "duplicate probe did not send PING")
	replaced := make(chan error, 1)
	newer := poolTestConn(t, nil, nil)
	go func() {
		p.DeleteConn(identifier)
		_, err := p.AddConn(newer, identifier, "test")
		replaced <- err
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

func TestConnPoolConcurrentAddConnKeepsWinner(t *testing.T) {
	p := newConnPool(new(http2.Transport), nil)
	identifier := id.New([]byte("same"))
	var gate *poolWriteGate
	candidate := poolTestConn(t, func(conn net.Conn) net.Conn {
		gate = gatePoolWrites(t, conn, func(b []byte) bool { return bytes.HasPrefix(b, []byte(http2.ClientPreface)) })
		return gate
	}, nil)
	pending := make(chan error, 1)
	go func() { _, err := p.AddConn(candidate, identifier, "test"); pending <- err }()
	awaitPoolSignal(t, gate.entered, "client did not write HTTP/2 preface")
	winner := poolTestConn(t, nil, nil)
	installed := make(chan error, 1)
	go func() { _, err := p.AddConn(winner, identifier, "test"); installed <- err }()
	select {
	case err := <-installed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		close(gate.release)
		<-pending
		<-installed
		t.Fatal("concurrent AddConn blocked behind pending preface")
	}
	close(gate.release)
	if err := <-pending; err != errClientAlreadyConnected {
		t.Fatalf("pending AddConn = %v, want already connected", err)
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.conns[p.addr(identifier)].conn != winner {
		t.Error("pending AddConn overwrote the installed connection")
	}
}

type poolDeathNotice struct {
	*connPool
	dead chan struct{}
}

func (p *poolDeathNotice) MarkDead(cc *http2.ClientConn) {
	close(p.dead)
	p.connPool.MarkDead(cc)
}

func TestConnPoolAddConnRejectsClosedConnection(t *testing.T) {
	transport := new(http2.Transport)
	p := newConnPool(transport, nil)
	dead := make(chan struct{})
	transport.ConnPool = &poolDeathNotice{connPool: p, dead: dead}
	client, peer := net.Pipe()
	t.Cleanup(func() { client.Close(); peer.Close() })
	gate := gatePoolWrites(t, client, func(b []byte) bool { return bytes.HasPrefix(b, []byte(http2.ClientPreface)) })
	go func() {
		peer.Read(make([]byte, 4096))
		peer.Close()
	}()
	added := make(chan error, 1)
	go func() { _, err := p.AddConn(gate, id.New([]byte("closed")), "test"); added <- err }()
	awaitPoolSignal(t, gate.entered, "client did not write HTTP/2 preface")
	if !p.mu.TryLock() {
		t.Fatal("pool lock held during HTTP/2 preface")
	}
	close(gate.release)
	select {
	case <-dead:
		p.mu.Unlock()
	case <-time.After(time.Second):
		p.mu.Unlock()
		t.Fatal("HTTP/2 read loop did not report closed connection")
	}
	if err := <-added; err != errClientNotConnected {
		t.Fatalf("AddConn after peer closed = %v, want client not connected", err)
	}
}

func TestConnPoolStaleRemovalPreservesReplacement(t *testing.T) {
	var freed []string
	p := newConnPool(new(http2.Transport), func(_ id.ID, tag string) { freed = append(freed, tag) })
	defer p.Close()
	identifier := id.New([]byte("same"))
	old, err := p.AddConn(poolTestConn(t, nil, nil), identifier, "old")
	if err != nil {
		t.Fatal(err)
	}
	p.DeleteConn(identifier)
	awaitPoolSignal(t, old.ctx.Done(), "deleted session was not canceled")
	current, err := p.AddConn(poolTestConn(t, nil, nil), identifier, "current")
	if err != nil {
		t.Fatal(err)
	}
	p.remove(old)
	p.MarkDead(old.clientConn)
	if _, err := p.Ping(identifier); err != nil {
		t.Fatalf("replacement stopped responding after stale removal: %v", err)
	}
	if current.ctx.Err() != nil {
		t.Fatal("stale removal canceled replacement")
	}
	if len(freed) != 1 || freed[0] != "old" {
		t.Fatalf("cleanup callbacks = %v, want [old]", freed)
	}
}

func TestConnPoolCloseRejectsPendingAdmission(t *testing.T) {
	p := newConnPool(new(http2.Transport), nil)
	current, err := p.AddConn(poolTestConn(t, nil, nil), id.New([]byte("current")), "current")
	if err != nil {
		t.Fatal(err)
	}
	var gate *poolWriteGate
	candidate := poolTestConn(t, func(conn net.Conn) net.Conn {
		gate = gatePoolWrites(t, conn, func(b []byte) bool { return bytes.HasPrefix(b, []byte(http2.ClientPreface)) })
		return gate
	}, nil)
	added := make(chan error, 1)
	go func() {
		_, err := p.AddConn(candidate, id.New([]byte("pending")), "pending")
		added <- err
	}()
	awaitPoolSignal(t, gate.entered, "pending connection did not write HTTP/2 preface")
	p.Close()
	awaitPoolSignal(t, current.ctx.Done(), "pool Close did not cancel admitted session")
	close(gate.release)
	if err := <-added; err != errClientNotConnected {
		t.Fatalf("pending admission after Close = %v, want client not connected", err)
	}
	if _, err := p.AddConn(poolTestConn(t, nil, nil), current.identifier, "late"); err != errClientNotConnected {
		t.Fatalf("new admission after Close = %v, want client not connected", err)
	}
	p.Close()
}

type poolCloseGate struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *poolCloseGate) Close() error {
	c.once.Do(func() { close(c.entered); <-c.release })
	return c.Conn.Close()
}

func TestConnPoolCloseConnectionAllowsOtherClients(t *testing.T) {
	p := newConnPool(new(http2.Transport), nil)
	var gate *poolCloseGate
	conn := poolTestConn(t, func(conn net.Conn) net.Conn {
		gate = &poolCloseGate{Conn: conn, entered: make(chan struct{}), release: make(chan struct{})}
		return gate
	}, nil)
	t.Cleanup(func() {
		select {
		case <-gate.release:
		default:
			close(gate.release)
		}
	})
	oldID, otherID := id.New([]byte("old")), id.New([]byte("other"))
	if _, err := p.AddConn(conn, oldID, "old"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.AddConn(poolTestConn(t, nil, nil), otherID, "other"); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); p.DeleteConn(oldID) }()
	t.Cleanup(func() { close(gate.release); <-done })
	awaitPoolSignal(t, gate.entered, "removed connection was not closed")
	lookup := make(chan error, 1)
	go func() { _, err := p.GetClientConn(nil, p.addr(otherID)); lookup <- err }()
	select {
	case err := <-lookup:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("unrelated client blocked while removed connection Close was gated")
	}
}
