package main

import (
	"bufio"
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
			outputReader, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stderr = cmd.Stdout
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			var output strings.Builder
			scanner := bufio.NewScanner(outputReader)
			for scanner.Scan() {
				line := scanner.Text()
				output.WriteString(line + "\n")
				if strings.Contains(line, "dial failed") {
					break
				}
			}
			cmd.Process.Kill()
			cmd.Wait()
			if scanner.Err() != nil || !strings.Contains(output.String(), "dial failed") {
				t.Fatalf("client did not attempt a connection: err=%v output=%s", scanner.Err(), output.String())
			}
			for _, secret := range []string{"credential-user-marker", "credential-password-marker"} {
				if strings.Contains(output.String(), secret) {
					t.Errorf("client output contains credential %q", secret)
				}
			}
		})
	}
}
