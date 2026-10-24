package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/mmatczuk/go-http-tunnel/id"
	"github.com/mmatczuk/go-http-tunnel/log"
	"github.com/mmatczuk/go-http-tunnel/proto"
)

func TestTCPProxyUploadEOF(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	backend := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			backend <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		b, err := io.ReadAll(c)
		if err == nil {
			_, err = c.Write(append([]byte("reply:"), b...))
		}
		backend <- err
	}()
	var out bytes.Buffer
	NewTCPProxy(l.Addr().String(), nil).Proxy(&out, io.NopCloser(bytes.NewBufferString("request")), &proto.ControlMessage{ForwardedProto: proto.TCP})
	if err := <-backend; err != nil {
		t.Error(err)
	}
	if got := out.String(); got != "reply:request" {
		t.Fatalf("response = %q, want reply:request", got)
	}
}

func TestTCPProxyBackendEOFAndCancellation(t *testing.T) {
	for _, mode := range []string{"backend EOF", "cancel during upload", "cancel after upload EOF", "cancel before dial"} {
		t.Run(mode, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			pr, pw := io.Pipe()
			defer pr.Close()
			defer pw.Close()
			done := make(chan struct{})
			if mode == "cancel before dial" {
				cancel()
			}
			go func() {
				NewTCPProxy(l.Addr().String(), nil).Proxy(io.Discard, &proxyReader{ReadCloser: pr, ctx: ctx}, &proto.ControlMessage{ForwardedProto: proto.TCP})
				close(done)
			}()
			if mode != "cancel before dial" {
				l.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
				c, err := l.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				switch mode {
				case "backend EOF":
					c.(*net.TCPConn).CloseWrite()
				case "cancel during upload":
					cancel()
				case "cancel after upload EOF":
					pw.Close()
					if _, err := io.ReadAll(c); err != nil {
						t.Error(err)
					}
					cancel()
				}
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				pr.Close()
				cancel()
				t.Fatal("Proxy did not finish")
			}
		})
	}
}

type halfCloseReader struct {
	io.ReadCloser
	closed bool
}

func (r *halfCloseReader) Close() error { r.closed = true; return r.ReadCloser.Close() }

func TestTCPProxyFailedDialClosesUpload(t *testing.T) {
	r := &halfCloseReader{ReadCloser: io.NopCloser(bytes.NewReader(nil))}
	NewTCPProxy("invalid address", nil).Proxy(io.Discard, r, &proto.ControlMessage{ForwardedProto: proto.TCP})
	if !r.closed {
		t.Fatal("failed dial left upload open")
	}
}

type halfCloseTransport func(*http.Request) (*http.Response, error)

func (f halfCloseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type halfCloseConn struct {
	net.Conn
	readDone chan struct{}
}

func (c *halfCloseConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		close(c.readDone)
	}
	return n, err
}

func TestServerTCPResponseCompletionJoinsUpload(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			local, remote := net.Pipe()
			defer remote.Close()
			defer local.Close()
			conn := &halfCloseConn{Conn: local, readDone: make(chan struct{})}
			response := &halfCloseReader{ReadCloser: io.NopCloser(bytes.NewReader(nil))}
			s := &Server{connPool: newConnPool(nil, nil), logger: log.NewNopLogger(), httpClient: &http.Client{Transport: halfCloseTransport(func(r *http.Request) (*http.Response, error) {
				if fail {
					return nil, errors.New("transport failed")
				}
				return &http.Response{StatusCode: 200, Body: response, Header: make(http.Header)}, nil
			})}}
			done := make(chan error, 1)
			go func() { done <- s.proxyConn(id.ID{}, conn, &proto.ControlMessage{ForwardedProto: proto.TCP}) }()
			select {
			case err := <-done:
				if (err != nil) != fail {
					t.Errorf("proxyConn error = %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("response completion did not stop upload")
			}
			select {
			case <-conn.readDone:
			default:
				t.Error("proxyConn returned before upload finished")
			}
			if !fail && !response.closed {
				t.Error("response body left open")
			}
		})
	}
}

type halfCloseWriter struct {
	entered  chan struct{}
	release  chan struct{}
	finished chan struct{}
}

func (w *halfCloseWriter) Write(p []byte) (int, error) {
	close(w.entered)
	<-w.release
	close(w.finished)
	return len(p), nil
}

func TestTCPProxyJoinsResponseWriter(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()
	w := &halfCloseWriter{entered: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
	defer close(w.release)
	done := make(chan struct{})
	go func() {
		NewTCPProxy(l.Addr().String(), nil).Proxy(w, pr, &proto.ControlMessage{ForwardedProto: proto.TCP})
		close(done)
	}()
	l.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-w.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("response write did not start")
	}
	pw.Close()
	if _, err := io.ReadAll(c); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		t.Fatal("Proxy returned with response write in progress")
	default:
	}
	c.Close()
	w.release <- struct{}{}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Proxy did not join response writer")
	}
	select {
	case <-w.finished:
	default:
		t.Fatal("Proxy returned before response write finished")
	}
}
