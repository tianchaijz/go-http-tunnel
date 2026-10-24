// Copyright (C) 2017 Michał Matczuk
// Use of this source code is governed by an AGPL-style
// license that can be found in the LICENSE file.

package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/mmatczuk/go-http-tunnel/proto"
	"github.com/mmatczuk/go-http-tunnel/tunnelmock"
)

func TestClient_ConcurrentHeartbeats(t *testing.T) {
	t.Parallel()

	c := &Client{}
	session := &clientSession{}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodConnect, "/", nil)
			r.Header.Set(proto.HeaderHeartbeat, "true")
			w := httptest.NewRecorder()

			<-start
			c.serveHTTP(session, w, r)

			if w.Code != http.StatusOK {
				t.Errorf("Heartbeat status = %d, want %d", w.Code, http.StatusOK)
			}
		}()
	}
	close(start)
	wg.Wait()
}

func TestClient_UnknownAction(t *testing.T) {
	c := lifecycleClient(t)
	r := httptest.NewRequest(http.MethodPut, "/", nil)
	msg := &proto.ControlMessage{
		Action:         "unsupported",
		ForwardedHost:  "backend",
		ForwardedProto: proto.TCP,
	}
	msg.WriteToHeader(r.Header)
	w := httptest.NewRecorder()
	c.serveHTTP(&clientSession{}, w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("unknown action status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestClient_Dial(t *testing.T) {
	t.Parallel()

	s := httptest.NewTLSServer(nil)
	defer s.Close()

	c, err := NewClient(&ClientConfig{
		ServerAddr: s.Listener.Addr().String(),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Tunnels: map[string]*proto.Tunnel{"test": {}},
		Proxy:   Proxy(ProxyFuncs{}),
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := c.dial(context.Background())
	if err != nil {
		t.Fatal("Dial error", err)
	}
	if conn == nil {
		t.Fatal("Expected connection", err)
	}
	conn.Close()
}

func TestClient_DialBackoff(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	b := tunnelmock.NewMockBackoff(ctrl)
	gomock.InOrder(
		b.EXPECT().NextBackOff().Return(50*time.Millisecond).Times(2),
		b.EXPECT().NextBackOff().Return(-time.Millisecond),
	)

	d := func(network, addr string, config *tls.Config) (net.Conn, error) {
		return nil, errors.New("foobar")
	}

	c, err := NewClient(&ClientConfig{
		ServerAddr:      "8.8.8.8",
		TLSClientConfig: &tls.Config{},
		DialTLS:         d,
		DialBackoff:     b,
		Tunnels:         map[string]*proto.Tunnel{"test": {}},
		Proxy:           Proxy(ProxyFuncs{}),
	})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = c.dial(context.Background())

	if time.Since(start) < 100*time.Millisecond {
		t.Fatal("Wait mismatch", err)
	}

	if err.Error() != "backoff limit exeded: foobar" {
		t.Fatal("Error mismatch", err)
	}
}

func TestClient_SessionHandlersDoNotMutateReplacement(t *testing.T) {
	c := lifecycleClient(t)
	old := &clientSession{}
	replacement := &clientSession{lastHeartbeat: time.Unix(123, 0)}
	c.run = &clientRun{session: replacement}
	for _, header := range []string{proto.HeaderHeartbeat, proto.HeaderError} {
		r := httptest.NewRequest(http.MethodConnect, "/", nil)
		r.Header.Set(header, "late message")
		c.serveHTTP(old, httptest.NewRecorder(), r)
	}
	if old.lastHeartbeat.IsZero() || old.serverErr == nil {
		t.Fatal("late messages were not handled on their original session")
	}
	if replacement.lastHeartbeat != time.Unix(123, 0) || replacement.serverErr != nil {
		t.Fatal("late messages changed the replacement session")
	}
}
