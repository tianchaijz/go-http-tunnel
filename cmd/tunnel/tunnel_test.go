package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTunnelMainProcess(t *testing.T) {
	if os.Getenv("TUNNEL_TEST_MAIN") != "1" {
		return
	}
	os.Args = append(os.Args[:1], os.Args[3:]...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	main()
}

func TestTunnelStartDoesNotLogCredentials(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	cert, err := filepath.Abs("../../testdata/selfsigned.crt")
	if err != nil {
		t.Fatal(err)
	}
	key, err := filepath.Abs("../../testdata/selfsigned.key")
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "tunnel.yml")
	data := fmt.Sprintf(`server_addr: %s
tls_crt: %s
tls_key: %s
tunnels:
  web:
    proto: http
    addr: http://127.0.0.1:8080
    host: app.example
    auth: credential-user-marker:credential-password-marker
`, listener.Addr(), cert, key)
	if err := os.WriteFile(config, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	for level := 0; level <= 3; level++ {
		t.Run(strconv.Itoa(level), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTunnelMainProcess$", "--",
				"-config", config, "-log-level", strconv.Itoa(level), "start-all")
			cmd.Env = append(os.Environ(), "TUNNEL_TEST_MAIN=1")
			outputFile, err := os.CreateTemp(t.TempDir(), "output")
			if err != nil {
				t.Fatal(err)
			}
			defer outputFile.Close()
			cmd.Stdout, cmd.Stderr = outputFile, outputFile
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			var output []byte
			for ctx.Err() == nil {
				output, err = os.ReadFile(outputFile.Name())
				if err != nil || strings.Contains(string(output), "dial failed") {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			cmd.Process.Kill()
			cmd.Wait()
			if err != nil || !strings.Contains(string(output), "dial failed") {
				t.Fatalf("client did not attempt a connection: err=%v output=%s", err, output)
			}
			for _, secret := range []string{"credential-user-marker", "credential-password-marker"} {
				if strings.Contains(string(output), secret) {
					t.Errorf("client output contains credential %q", secret)
				}
			}
		})
	}
}
