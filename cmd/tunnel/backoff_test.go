package main

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	tunnel "github.com/mmatczuk/go-http-tunnel"
	"github.com/mmatczuk/go-http-tunnel/proto"
)

type backoffTestClock struct{ now time.Time }

func (c *backoffTestClock) Now() time.Time { return c.now }

func TestClientHonorsConfiguredBackoffMaxTime(t *testing.T) {
	clock := &backoffTestClock{now: time.Unix(0, 0)}
	backoff := expBackoff(BackoffConfig{
		Interval: time.Nanosecond, Multiplier: 1, MaxInterval: time.Nanosecond, MaxTime: time.Second,
	})
	backoff.Clock = clock
	backoff.RandomizationFactor = 0
	var client *tunnel.Client
	dials := 0
	client, err := tunnel.NewClient(&tunnel.ClientConfig{
		ServerAddr: "unused:1", TLSClientConfig: &tls.Config{},
		Tunnels: map[string]*proto.Tunnel{"web": {Protocol: proto.HTTP, Host: "test.example"}},
		Proxy:   tunnel.Proxy(tunnel.ProxyFuncs{}), ServeBackoff: backoff,
		DialTLS: func(string, string, *tls.Config) (net.Conn, error) {
			dials++
			clock.now = clock.now.Add(600 * time.Millisecond)
			if dials == 3 {
				client.Stop()
			}
			return nil, errors.New("backend unavailable")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Start(); dials != 2 || err == nil {
		t.Fatalf("Start made %d attempts and returned %v; want two attempts then error", dials, err)
	}
}
