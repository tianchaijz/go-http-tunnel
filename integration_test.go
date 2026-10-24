// Copyright (C) 2017 Michał Matczuk
// Use of this source code is governed by an AGPL-style
// license that can be found in the LICENSE file.

package tunnel_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mmatczuk/go-http-tunnel"
	"github.com/mmatczuk/go-http-tunnel/log"
	"github.com/mmatczuk/go-http-tunnel/proto"
)

const (
	payloadInitialSize = 512
	payloadLen         = 10
)

// echoHTTP starts serving HTTP requests on listener l, it accepts connections,
// reads request body and writes is back in response.
func echoHTTP(t testing.TB, l net.Listener) {
	http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prior := strings.Join(r.Header["X-Forwarded-For"], ", ")
		if len(strings.Split(prior, ",")) != 2 {
			t.Fatal(r.Header)
		}
		if !strings.Contains(r.Header.Get("X-Forwarded-Host"), "localhost:") {
			t.Fatal(r.Header)
		}
		if r.Header.Get("X-Forwarded-Proto") != "http" {
			t.Fatal(r.Header)
		}

		w.WriteHeader(http.StatusOK)
		if r.Body != nil {
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			w.Write(body)
		}
	}))
}

// echoTCP accepts connections and copies back received bytes.
func echoTCP(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			io.Copy(conn, conn)
		}()
	}
}

func makeEcho(t testing.TB) (http net.Listener, tcp net.Listener) {
	var err error

	// TCP echo
	tcp, err = net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	go echoTCP(tcp)

	// HTTP echo
	http, err = net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	go echoHTTP(t, http)

	return
}

func makeTunnelServer(t testing.TB) *tunnel.Server {
	s, err := tunnel.NewServer(&tunnel.ServerConfig{
		Addr:          ":0",
		AutoSubscribe: true,
		TLSConfig:     tlsConfig(),
		Logger:        log.NewStdLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()

	return s
}

func makeTunnelClient(t testing.TB, serverAddr string, httpLocalAddr, httpAddr, tcpLocalAddr, tcpAddr net.Addr) *tunnel.Client {
	httpProxy := tunnel.NewMultiHTTPProxy(map[string]*url.URL{
		"localhost:" + port(httpLocalAddr): {
			Scheme: "http",
			Host:   "127.0.0.1:" + port(httpAddr),
		},
	}, log.NewStdLogger())

	tcpProxy := tunnel.NewMultiTCPProxy(map[string]string{
		proto.TCP: tcpAddr.String(),
	}, log.NewStdLogger())

	tunnels := map[string]*proto.Tunnel{
		proto.HTTP: {
			Protocol: proto.HTTP,
			Host:     "localhost",
			Auth:     "user:password",
		},
		proto.TCP: {
			Protocol:   proto.TCP,
			Addr:       tcpAddr.String(),
			RemoteAddr: tcpLocalAddr.String(),
		},
	}

	c, err := tunnel.NewClient(&tunnel.ClientConfig{
		ServerAddr:      serverAddr,
		TLSClientConfig: tlsConfig(),
		Tunnels:         tunnels,
		Proxy: tunnel.Proxy(tunnel.ProxyFuncs{
			HTTP: httpProxy.Proxy,
			TCP:  tcpProxy.Proxy,
		}),
		Logger: log.NewStdLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if err := c.Start(); err != nil {
			t.Log(err)
		}
	}()

	return c
}

func TestIntegration(t *testing.T) {
	// local services
	http, tcp := makeEcho(t)
	defer http.Close()
	defer tcp.Close()

	// server
	s := makeTunnelServer(t)
	defer s.Stop()
	h := httptest.NewServer(s)
	defer h.Close()

	httpLocalAddr := h.Listener.Addr()
	tcpLocalAddr := freeAddr()

	// client
	c := makeTunnelClient(t, s.Addr(),
		httpLocalAddr, http.Addr(),
		tcpLocalAddr, tcp.Addr(),
	)
	// FIXME: replace sleep with client state change watch when ready
	time.Sleep(500 * time.Millisecond)
	defer c.Stop()

	payload := randPayload(payloadInitialSize, payloadLen)
	table := []struct {
		S []uint
	}{
		{[]uint{200, 160, 120, 80, 40, 20}},
		{[]uint{40, 80, 120, 160, 200}},
		{[]uint{0, 0, 0, 0, 0, 0, 0, 0, 0, 200}},
	}

	var wg sync.WaitGroup
	for _, test := range table {
		for i, repeat := range test.S {
			p := payload[i]
			r := repeat

			wg.Add(1)
			go func() {
				defer wg.Done()
				testHTTP(t, h.Listener.Addr(), p, r)
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				testTCP(t, tcpLocalAddr, p, r)
			}()
		}
	}
	wg.Wait()
}

func testHTTP(t testing.TB, addr net.Addr, payload []byte, repeat uint) {
	url := fmt.Sprintf("http://localhost:%s/some/path", port(addr))

	for repeat > 0 {
		r, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			t.Fatal("Failed to create request")
		}
		r.SetBasicAuth("user", "password")

		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Error(err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			t.Error("Unexpected status code", resp)
		}
		b, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Error("Read error")
		}
		n, m := len(b), len(payload)
		if n != m {
			t.Error("Write read mismatch", n, m)
		}
		repeat--
	}
}

func testTCP(t testing.TB, addr net.Addr, payload []byte, repeat uint) {
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal("Dial failed", err)
	}
	defer conn.Close()

	var buf = make([]byte, 10*1024*1024)
	var read, write int
	for repeat > 0 {
		m, err := conn.Write(payload)
		if err != nil {
			t.Error("Write failed", err)
		}
		if m != len(payload) {
			t.Log("Write mismatch", m, len(payload))
		}
		write += m

		n, err := conn.Read(buf)
		if err != nil {
			t.Error("Read failed", err)
		}
		read += n
		repeat--
	}

	for read < write {
		t.Log("No yet read everything", "write", write, "read", read)
		time.Sleep(50 * time.Millisecond)
		n, err := conn.Read(buf)
		if err != nil {
			t.Error("Read failed", err)
		}
		read += n
	}

	if read != write {
		t.Fatal("Write read mismatch", read, write)
	}
}

//
// helpers
//

// randPayload returns slice of randomly initialised data buffers.
func randPayload(initialSize, n int) [][]byte {
	payload := make([][]byte, n)
	l := initialSize
	for i := 0; i < n; i++ {
		payload[i] = randBytes(l)
		l *= 2
	}
	return payload
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	read, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	if read != n {
		panic("read did not fill whole slice")
	}
	return b
}

func freeAddr() net.Addr {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr()
}

func port(addr net.Addr) string {
	return fmt.Sprint(addr.(*net.TCPAddr).Port)
}

func tlsConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair("./testdata/selfsigned.crt", "./testdata/selfsigned.key")
	if err != nil {
		panic(err)
	}

	c := &tls.Config{
		Certificates:             []tls.Certificate{cert},
		ClientAuth:               tls.RequireAnyClientCert,
		SessionTicketsDisabled:   true,
		InsecureSkipVerify:       true,
		MinVersion:               tls.VersionTLS12,
		CipherSuites:             []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		PreferServerCipherSuites: true,
		NextProtos:               []string{"h2"},
	}
	c.BuildNameToCertificate()
	return c
}

func TestHTTPPublicCancellation(t *testing.T) {
	for _, upload := range []bool{false, true} {
		name := "GET"
		if upload {
			name = "unfinished_POST"
		}
		t.Run(name, func(t *testing.T) { testHTTPPublicCancellation(t, upload) })
	}
}

func testHTTPPublicCancellation(t *testing.T, upload bool) {
	arrived := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	survivorArrived := make(chan struct{})
	survivorRelease := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/survivor" {
			close(survivorArrived)
			select {
			case <-survivorRelease:
				io.WriteString(w, "survived")
			case <-r.Context().Done():
			}
			return
		}
		close(arrived)
		if upload {
			io.Copy(io.Discard, r.Body)
		}
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-release:
		}
	}))
	defer backend.Close()
	defer close(survivorRelease)
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	s := makeTunnelServer(t)
	defer s.Stop()
	httpProxy := tunnel.NewHTTPProxy(target, nil)
	c, err := tunnel.NewClient(&tunnel.ClientConfig{
		ServerAddr:      s.Addr(),
		TLSClientConfig: tlsConfig(),
		Tunnels: map[string]*proto.Tunnel{
			"web": {Protocol: proto.HTTP, Host: "cancel.test"},
		},
		Proxy: tunnel.Proxy(tunnel.ProxyFuncs{HTTP: func(ctx context.Context, w http.ResponseWriter, r io.ReadCloser, msg *proto.ControlMessage) {
			httpProxy.Proxy(ctx, w, struct{ io.ReadCloser }{r}, msg)
		}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	clientDone := make(chan error, 1)
	go func() { clientDone <- c.Start() }()
	defer func() {
		c.Stop()
		select {
		case <-clientDone:
		case <-time.After(3 * time.Second):
			t.Error("tunnel client did not stop")
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, _, ok := s.Subscriber("cancel.test"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("HTTP tunnel was not registered")
		}
		time.Sleep(time.Millisecond)
	}
	front := httptest.NewServer(s)
	defer func() {
		close(release)
		front.CloseClientConnections()
		front.Close()
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	method := http.MethodGet
	var body io.Reader
	var writer *io.PipeWriter
	if upload {
		method = http.MethodPost
		var reader *io.PipeReader
		reader, writer = io.Pipe()
		body = reader
		defer writer.Close()
		go func() { writer.Write(make([]byte, 65536)) }()
	}
	req, err := http.NewRequestWithContext(ctx, method, front.URL, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "cancel.test"
	done := make(chan error, 1)
	go func() {
		resp, err := front.Client().Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		done <- err
	}()
	select {
	case <-arrived:
	case <-time.After(3 * time.Second):
		t.Fatal("backend request did not arrive")
	}
	survivorDone := make(chan error, 1)
	go func() {
		req, err := http.NewRequest(http.MethodGet, front.URL+"/survivor", nil)
		if err != nil {
			survivorDone <- err
			return
		}
		req.Host = "cancel.test"
		resp, err := front.Client().Do(req)
		if err == nil {
			var data []byte
			data, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil && string(data) != "survived" {
				err = fmt.Errorf("surviving request body = %q", data)
			}
		}
		survivorDone <- err
	}()
	select {
	case <-survivorArrived:
	case <-time.After(3 * time.Second):
		t.Fatal("second backend request did not arrive")
	}
	cancel()
	if writer != nil {
		writer.CloseWithError(context.Canceled)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled public request succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("public request did not stop")
	}
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Error("backend request remained active after public HTTP cancellation")
	}
	select {
	case survivorRelease <- struct{}{}:
	case <-time.After(3 * time.Second):
		t.Error("second backend request was canceled")
	}
	select {
	case err := <-survivorDone:
		if err != nil {
			t.Errorf("second request failed after cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("second request did not complete")
	}
}
