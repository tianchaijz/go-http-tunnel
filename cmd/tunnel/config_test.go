package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
