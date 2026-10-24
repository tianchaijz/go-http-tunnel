// Copyright (C) 2017 Michał Matczuk
// Use of this source code is governed by an AGPL-style
// license that can be found in the LICENSE file.

package tunnel

import (
	"context"
	"io"
	"net"
	"net/http"

	"github.com/mmatczuk/go-http-tunnel/log"
	"github.com/mmatczuk/go-http-tunnel/proto"
)

// TCPProxy forwards TCP streams.
type TCPProxy struct {
	// localAddr specifies default TCP address of the local server.
	localAddr    string
	localAddrMap map[string]string
	// logger is the proxy logger.
	logger log.Logger
}

// NewTCPProxy creates new direct TCPProxy, everything will be proxied to
// localAddr.
func NewTCPProxy(localAddr string, logger log.Logger) *TCPProxy {
	if logger == nil {
		logger = log.NewNopLogger()
	}

	return &TCPProxy{
		localAddr: localAddr,
		logger:    logger,
	}
}

// NewMultiTCPProxy creates a new dispatching TCPProxy, connections may go to
// different backends based on localAddrMap.
func NewMultiTCPProxy(localAddrMap map[string]string, logger log.Logger) *TCPProxy {
	if logger == nil {
		logger = log.NewNopLogger()
	}

	return &TCPProxy{
		localAddrMap: localAddrMap,
		logger:       logger,
	}
}

// Proxy is a ProxyFunc.
func (p *TCPProxy) Proxy(ctx context.Context, w http.ResponseWriter, r io.ReadCloser, msg *proto.ControlMessage) {
	defer r.Close()
	switch msg.ForwardedProto {
	case proto.TCP, proto.TCP4, proto.TCP6, proto.UNIX:
		// ok
	default:
		p.logger.Log(
			"level", 0,
			"msg", "unsupported protocol",
			"ctrlMsg", msg,
		)
		http.Error(w, "unsupported proxy protocol", http.StatusBadRequest)
		return
	}

	target := p.localAddrFor(msg.ForwardedHost)
	if target == "" {
		p.logger.Log(
			"level", 1,
			"msg", "no target",
			"ctrlMsg", msg,
		)
		http.Error(w, "no proxy target", http.StatusBadGateway)
		return
	}
	dialer := net.Dialer{Timeout: DefaultTimeout}
	local, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		p.logger.Log(
			"level", 0,
			"msg", "dial failed",
			"target", target,
			"ctrlMsg", msg,
			"err", err,
		)
		http.Error(w, "proxy dial failed", http.StatusBadGateway)
		return
	}
	defer local.Close()

	if err := keepAlive(local); err != nil {
		p.logger.Log(
			"level", 1,
			"msg", "TCP keepalive for tunneled connection failed",
			"target", target,
			"ctrlMsg", msg,
			"err", err,
		)
	}

	type copyResult struct {
		upload bool
		err    error
	}
	results := make(chan copyResult, 2)
	go func() {
		err := transfer(flushWriter{w}, local, log.NewContext(p.logger).With(
			"dst", msg.ForwardedHost,
			"src", target,
		))
		results <- copyResult{err: err}
	}()
	go func() {
		err := transfer(local, r, log.NewContext(p.logger).With(
			"dst", target,
			"src", msg.ForwardedHost,
		))
		results <- copyResult{upload: true, err: err}
	}()

	remaining := 2
	for remaining > 0 {
		select {
		case result := <-results:
			remaining--
			if result.upload && result.err == nil {
				if err := local.(*net.TCPConn).CloseWrite(); err == nil {
					continue
				}
			}
		case <-ctx.Done():
		}
		local.Close()
		r.Close()
		for remaining > 0 {
			<-results
			remaining--
		}
	}
}

// Remote address or tunnel name
func (p *TCPProxy) localAddrFor(host string) string {
	if len(p.localAddrMap) == 0 {
		return p.localAddr
	}

	if addr := p.localAddrMap[host]; addr != "" {
		return addr
	}

	return p.localAddr
}
