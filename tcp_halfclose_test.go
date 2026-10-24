package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

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
