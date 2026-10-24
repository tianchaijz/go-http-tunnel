package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadClientConfigRejectsNilTunnel(t *testing.T) {
	for _, value := range []string{"null", "~", ""} {
		t.Run(value, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tunnel.yml")
			data := "server_addr: localhost:5223\ntunnels:\n  missing: " + value + "\n"
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			config, err := loadClientConfigFromFile(path)
			if err == nil || !strings.Contains(err.Error(), "missing") {
				t.Fatalf("null tunnel error = %v, want error naming missing tunnel", err)
			}
			if config != nil {
				t.Fatal("invalid configuration returned to caller")
			}
		})
	}
}

func TestLoadClientConfigHeartbeat(t *testing.T) {
	for _, tt := range []struct {
		name, fields string
		want         time.Duration
		wantError    bool
	}{
		{"default", "", 5 * time.Second, false},
		{"canonical", "server_heartbeat_interval: 17s\n", 17 * time.Second, false},
		{"legacy", "server_heartbeart_interval: 19s\n", 19 * time.Second, false},
		{"disabled", "server_heartbeat_interval: 0s\n", 0, false},
		{"both", "server_heartbeat_interval: 17s\nserver_heartbeart_interval: 19s\n", 0, true},
		{"unknown", "server_heartbeat_interva: 17s\n", 0, true},
		{"duplicate", "server_heartbeat_interval: 17s\nserver_heartbeat_interval: 19s\n", 0, true},
		{"unknown nested", "backoff:\n  max_tim: 1m\n", 0, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tunnel.yml")
			if err := os.WriteFile(path, []byte("server_addr: localhost:5223\n"+tt.fields), 0600); err != nil {
				t.Fatal(err)
			}
			config, err := loadClientConfigFromFile(path)
			if tt.wantError {
				if err == nil || config != nil {
					t.Fatalf("invalid config = %v, %v; want error", config, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := config.ServerHeartbeatInterval; got != tt.want {
				t.Fatalf("heartbeat = %s, want %s", got, tt.want)
			}
		})
	}
}
