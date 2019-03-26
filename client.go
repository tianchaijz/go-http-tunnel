// Copyright (C) 2017 Michał Matczuk
// Use of this source code is governed by an AGPL-style
// license that can be found in the LICENSE file.

package tunnel

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
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
	// connection to the server. If DialTLS is nil, tls.Dial is used.
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

	conn           net.Conn
	connMu         sync.Mutex
	httpServer     *http2.Server
	serverErr      error
	lastHeartbeat  time.Time
	lastDisconnect time.Time
	logger         log.Logger
	exited         chan bool
	started        int32
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
		exited:     make(chan bool, 1),
		started:    0,
	}

	return c, nil
}

func (c *Client) Start() error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	c.exited <- true

	for {
		select {
		case <-c.exited:
			go c.start()
		case <-ticker.C:
			c.connMu.Lock()
			if time.Now().Sub(c.lastHeartbeat) > 2*c.config.ServerHeartbeatInterval {
				if c.conn != nil {
					c.logger.Log(
						"level", 1,
						"action", "closing stale connection",
					)

					c.conn.Close()
				}
			}
			c.connMu.Unlock()
		}
	}
}

// Start connects client to the server, it returns error if there is a
// connection error, or server cannot open requested tunnels. On connection
// error a backoff policy is used to reestablish the connection. When connected
// HTTP/2 server is started to handle ControlMessages.
func (c *Client) start() error {
	if !atomic.CompareAndSwapInt32(&c.started, 0, 1) {
		return nil
	}

	defer func() {
		atomic.StoreInt32(&c.started, 0)
		c.exited <- true
	}()

	c.logger.Log(
		"level", 1,
		"action", "start",
	)

	doServe := func() error {
		conn, err := c.connect()
		if err != nil {
			return err
		}

		c.httpServer.ServeConn(conn, &http2.ServeConnOpts{
			Handler: http.HandlerFunc(c.serveHTTP),
		})

		c.logger.Log(
			"level", 1,
			"action", "disconnected",
		)

		c.connMu.Lock()
		now := time.Now()
		err = c.serverErr

		// detect disconnect hiccup
		if err == nil {
			err = fmt.Errorf("connection is being cut")
		}

		c.conn = nil
		c.serverErr = nil
		c.lastDisconnect = now
		c.connMu.Unlock()

		return err
	}

	b := c.config.ServeBackoff
	if b == nil {
		return doServe()
	}
	defer b.Reset()

	var err error

	for {
		err = doServe()

		// failure
		d := b.NextBackOff()
		if d < 0 {
			break
		}

		// backoff
		c.logger.Log(
			"level", 1,
			"action", "serve backoff",
			"sleep", d,
			"err", err,
		)
		time.Sleep(d)
	}

	return fmt.Errorf("backoff limit exeded: %s", err)
}

func (c *Client) connect() (net.Conn, error) {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if c.conn != nil {
		return nil, fmt.Errorf("already connected")
	}

	conn, err := c.dial()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %s", err)
	}

	c.conn = conn
	c.lastHeartbeat = time.Now()

	return conn, nil
}

func (c *Client) dial() (net.Conn, error) {
	var (
		network   = "tcp"
		addr      = c.config.ServerAddr
		tlsConfig = c.config.TLSClientConfig
	)

	doDial := func() (conn net.Conn, err error) {
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
			conn, err = d.Dial(network, addr)

			if err == nil {
				err = keepAlive(conn)
			}
			if err == nil {
				conn = tls.Client(conn, tlsConfig)
			}
			if err == nil {
				err = conn.(*tls.Conn).Handshake()
			}
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
		time.Sleep(d)
	}
}

func (c *Client) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		if r.Header.Get(proto.HeaderError) != "" {
			c.handleHandshakeError(w, r)
		} else if r.Header.Get(proto.HeaderHeartbeat) != "" {
			c.handleHeartbeat(w, r)
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

func (c *Client) handleHandshakeError(w http.ResponseWriter, r *http.Request) {
	err := fmt.Errorf(r.Header.Get(proto.HeaderError))

	c.logger.Log(
		"level", 1,
		"action", "handshake error",
		"addr", r.RemoteAddr,
		"err", err,
	)

	c.connMu.Lock()
	c.serverErr = fmt.Errorf("server error: %s", err)
	c.connMu.Unlock()
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

func (c *Client) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	c.lastHeartbeat = time.Now()

	w.WriteHeader(http.StatusOK)
}

// Stop disconnects client from server.
func (c *Client) Stop() {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	c.logger.Log(
		"level", 1,
		"action", "stop",
	)

	if c.conn != nil {
		c.conn.Close()
	}
	c.conn = nil
}
