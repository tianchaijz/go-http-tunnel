package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTLSConfigRejectsInvalidRootCA(t *testing.T) {
	for _, contents := range []string{"", "not a certificate"} {
		root := filepath.Join(t.TempDir(), "root.pem")
		if err := os.WriteFile(root, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		config, err := tlsConfig(&ClientConfig{
			ServerAddr: "localhost:5223",
			TLSCrt:     "../../testdata/selfsigned.crt",
			TLSKey:     "../../testdata/selfsigned.key",
			RootCA:     root,
		})
		if config != nil || err == nil || !strings.Contains(err.Error(), "root CA") {
			t.Fatalf("invalid root CA = %v, %v; want explicit root CA error", config, err)
		}
	}
}
