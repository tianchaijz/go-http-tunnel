package tunnel

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mmatczuk/go-http-tunnel/proto"
)

type stopServeBackoff struct{}

func (stopServeBackoff) NextBackOff() time.Duration { return -1 }
func (stopServeBackoff) Reset()                     {}

func TestClientServeBackoffStops(t *testing.T) {
	c := lifecycleClient(t)
	dialErr := errors.New("dial failed")
	dials := 0
	c.config.DialBackoff = nil
	c.config.ServeBackoff = stopServeBackoff{}
	c.config.DialTLS = func(string, string, *tls.Config) (net.Conn, error) {
		dials++
		if dials == 3 {
			c.Stop()
		}
		return nil, dialErr
	}
	err := c.Start()
	if dials != 1 || err == nil || err.Error() != "failed to connect to server: dial failed" {
		t.Fatalf("Start made %d dials and returned %v; want one dial and the connection error", dials, err)
	}
}

func TestClientHandshakeErrorPreservesText(t *testing.T) {
	c := lifecycleClient(t)
	session := &clientSession{}
	r := httptest.NewRequest(http.MethodConnect, "/", nil)
	r.Header.Set(proto.HeaderError, "100% failure: %s")
	c.handleHandshakeError(session, httptest.NewRecorder(), r)
	if got, want := session.serverErr.Error(), "server error: 100% failure: %s"; got != want {
		t.Fatalf("handshake error = %q, want %q", got, want)
	}
}
