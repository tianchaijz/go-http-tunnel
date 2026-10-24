// Copyright (C) 2017 Michał Matczuk
// Use of this source code is governed by an AGPL-style
// license that can be found in the LICENSE file.

package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/mmatczuk/go-http-tunnel/log"
	"github.com/mmatczuk/go-http-tunnel/proto"
)

// ClientConfig is configuration of the Client.
type ClientConfig struct {
	// ServerAddr specifies TCP address of the tunnel server.
	ServerAddr string
	// TLSClientConfig specifies the tls configuration to use with
	// tls.Client.
	TLSClientConfig *tls.Config
	// DialTLS specifies an optional dial function that creates a tls
	// connection to the server. If nil, dialing and TLS negotiation use
	// the current Start context. A custom callback runs synchronously and
	// must manage its own cancellation and timeouts.
	DialTLS func(network, addr string, config *tls.Config) (net.Conn, error)
	// Backoff specifies backoff policy on server connection retry. If nil
	// when dial fails it will not be retried.
	DialBackoff  Backoff
	ServeBackoff Backoff
	// Tunnels specifies the tunnels client requests to be opened on server.
	Tunnels map[string]*proto.Tunnel
	// Proxy is ProxyFunc responsible for transferring data between server
	// and local services.
	Proxy ProxyFunc
	// Logger is optional logger. If nil logging is disabled.
	Logger log.Logger

	ServerHeartbeatInterval time.Duration
}

// Client is responsible for creating connection to the server, handling control
// messages. It uses ProxyFunc for transferring data between server and local
// services.
type Client struct {
	config *ClientConfig

	mu         sync.Mutex
	run        *clientRun
	httpServer *http2.Server
	logger     log.Logger
}

type clientRun struct {
	ctx     context.Context
	cancel  context.CancelFunc
	session *clientSession
}

type clientSession struct {
	conn          net.Conn
	lastHeartbeat time.Time
	serverErr     error
}

// NewClient creates a new unconnected Client based on configuration. Caller
// must invoke Start() on returned instance in order to connect server.
func NewClient(config *ClientConfig) (*Client, error) {
	if config.ServerAddr == "" {
		return nil, errors.New("missing ServerAddr")
	}
	if config.TLSClientConfig == nil {
		return nil, errors.New("missing TLSClientConfig")
	}
	if len(config.Tunnels) == 0 {
		return nil, errors.New("missing Tunnels")
	}
	if config.Proxy == nil {
		return nil, errors.New("missing Proxy")
	}

	logger := config.Logger
	if logger == nil {
		logger = log.NewNopLogger()
	}

	c := &Client{
		config:     config,
		httpServer: &http2.Server{},
		logger:     logger,
	}

	return c, nil
}

// Start connects client to the server, it returns error if there is a
// connection error, or server cannot open requested tunnels. On connection
// error a backoff policy is used to reestablish the connection. When connected
// HTTP/2 server is started to handle ControlMessages. Stop makes Start return
// nil. Concurrent calls to Start return an error. After Start returns, the
// client can be started again.
func (c *Client) Start() error {
	c.mu.Lock()
	if c.run != nil {
		c.mu.Unlock()
		return errors.New("client already started")
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &clientRun{ctx: ctx, cancel: cancel}
	c.run = run
	c.mu.Unlock()

	var checker sync.WaitGroup
	defer func() {
		cancel()
		checker.Wait()
		c.mu.Lock()
		session := run.session
		if c.run == run {
			c.run = nil
		}
		c.mu.Unlock()
		if session != nil {
			session.conn.Close()
		}
	}()

	c.logger.Log("level", 1, "action", "start")
	if c.config.DialBackoff != nil {
		c.config.DialBackoff.Reset()
	}
	if c.config.ServeBackoff != nil {
		c.config.ServeBackoff.Reset()
	}
	if c.config.ServerHeartbeatInterval > 0 {
		checker.Add(1)
		go func() {
			defer checker.Done()
			c.checkHeartbeat(run)
		}()
	}

	doServe := func() error {
		conn, err := c.dial(ctx)
		if err != nil {
			return fmt.Errorf("failed to connect to server: %s", err)
		}

		session := &clientSession{conn: conn, lastHeartbeat: time.Now()}
		c.mu.Lock()
		if c.run != run || ctx.Err() != nil {
			c.mu.Unlock()
			conn.Close()
			return ctx.Err()
		}
		run.session = session
		c.mu.Unlock()

		c.httpServer.ServeConn(conn, &http2.ServeConnOpts{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.serveHTTP(session, w, r)
			}),
		})
		conn.Close()
		c.logger.Log("level", 1, "action", "disconnected")

		c.mu.Lock()
		err = session.serverErr
		if run.session == session {
			run.session = nil
		}
		c.mu.Unlock()
		if err == nil {
			err = errors.New("connection is being cut")
		}
		return err
	}

	b := c.config.ServeBackoff
	for {
		if ctx.Err() != nil {
			return nil
		}
		t := time.Now()
		err := doServe()
		if ctx.Err() != nil {
			return nil
		}
		if b == nil {
			return err
		}
		d := b.NextBackOff()
		if ctx.Err() != nil {
			return nil
		}
		if d < 0 || time.Since(t) > 60*time.Second {
			b.Reset()
			continue
		}
		c.logger.Log("level", 1, "action", "serve backoff", "sleep", d, "err", err)
		if waitBackoff(ctx, d) != nil {
			return nil
		}
	}
}

func (c *Client) checkHeartbeat(run *clientRun) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-run.ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			session := run.session
			stale := session != nil && time.Since(session.lastHeartbeat) > 2*c.config.ServerHeartbeatInterval
			c.mu.Unlock()
			if stale {
				c.logger.Log("level", 1, "action", "closing stale connection")
				session.conn.Close()
			}
		}
	}
}

func waitBackoff(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	var (
		network   = "tcp"
		addr      = c.config.ServerAddr
		tlsConfig = c.config.TLSClientConfig
	)

	doDial := func() (conn net.Conn, err error) {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		c.logger.Log(
			"level", 1,
			"action", "dial",
			"network", network,
			"addr", addr,
		)

		if c.config.DialTLS != nil {
			conn, err = c.config.DialTLS(network, addr, tlsConfig)
		} else {
			d := &net.Dialer{
				Timeout: DefaultTimeout,
			}
			conn, err = d.DialContext(ctx, network, addr)

			if err == nil {
				err = keepAlive(conn)
			}
			if err == nil {
				conn = tls.Client(conn, tlsConfig)
			}
			if err == nil {
				handshakeCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
				err = conn.(*tls.Conn).HandshakeContext(handshakeCtx)
				cancel()
			}
		}

		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			if conn != nil {
				conn.Close()
				conn = nil
			}

			c.logger.Log(
				"level", 0,
				"msg", "dial failed",
				"network", network,
				"addr", addr,
				"err", err,
			)
		}

		return
	}

	b := c.config.DialBackoff
	if b == nil {
		return doDial()
	}

	for {
		conn, err := doDial()
		if ctx.Err() != nil {
			if conn != nil {
				conn.Close()
			}
			return nil, ctx.Err()
		}

		// success
		if err == nil {
			b.Reset()
			return conn, err
		}

		// failure
		d := b.NextBackOff()
		if d < 0 {
			return conn, fmt.Errorf("backoff limit exeded: %s", err)
		}

		// backoff
		c.logger.Log(
			"level", 1,
			"action", "dial backoff",
			"sleep", d,
		)
		if err := waitBackoff(ctx, d); err != nil {
			return nil, err
		}
	}
}

func (c *Client) serveHTTP(session *clientSession, w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		if r.Header.Get(proto.HeaderError) != "" {
			c.handleHandshakeError(session, w, r)
		} else if r.Header.Get(proto.HeaderHeartbeat) != "" {
			c.handleHeartbeat(session, w, r)
		} else {
			c.handleHandshake(w, r)
		}
		return
	}

	msg, err := proto.ReadControlMessage(r)
	if err != nil {
		c.logger.Log(
			"level", 1,
			"err", err,
		)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	c.logger.Log(
		"level", 2,
		"action", "handle",
		"ctrlMsg", msg,
	)
	switch msg.Action {
	case proto.ActionProxy:
		c.config.Proxy(w, r.Body, msg)
	default:
		c.logger.Log(
			"level", 0,
			"msg", "unknown action",
			"ctrlMsg", msg,
		)
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	c.logger.Log(
		"level", 2,
		"action", "done",
		"ctrlMsg", msg,
	)
}

func (c *Client) handleHandshakeError(session *clientSession, w http.ResponseWriter, r *http.Request) {
	err := fmt.Errorf(r.Header.Get(proto.HeaderError))

	c.logger.Log(
		"level", 1,
		"action", "handshake error",
		"addr", r.RemoteAddr,
		"err", err,
	)

	c.mu.Lock()
	session.serverErr = fmt.Errorf("server error: %s", err)
	c.mu.Unlock()
}

func (c *Client) handleHandshake(w http.ResponseWriter, r *http.Request) {
	c.logger.Log(
		"level", 1,
		"action", "handshake",
		"addr", r.RemoteAddr,
	)

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	w.Header().Set(proto.HeaderHostname, hostname)

	w.WriteHeader(http.StatusOK)

	b, err := json.Marshal(c.config.Tunnels)
	if err != nil {
		c.logger.Log(
			"level", 0,
			"msg", "handshake failed",
			"err", err,
		)
		return
	}
	w.Write(b)
}

func (c *Client) handleHeartbeat(session *clientSession, w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	session.lastHeartbeat = time.Now()
	c.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// Stop cancels the current Start and closes its connection. Wait for Start to
// return before restarting. A custom DialTLS callback must return on its own.
func (c *Client) Stop() {
	c.mu.Lock()
	var session *clientSession
	if c.run != nil {
		c.run.cancel()
		session = c.run.session
	}
	c.mu.Unlock()

	c.logger.Log("level", 1, "action", "stop")
	if session != nil {
		session.conn.Close()
	}
}
