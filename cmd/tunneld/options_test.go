package main

import (
	"flag"
	"os"
	"testing"
)

func TestDashboardFlag(t *testing.T) {
	originalFlags, originalArgs := flag.CommandLine, os.Args
	defer func() { flag.CommandLine = originalFlags; os.Args = originalArgs }()
	for _, tt := range []struct {
		args []string
		want string
		user string
	}{{nil, "", ""}, {[]string{"-dashboardAddr", "127.0.0.1:8081", "-dashboardUser", "admin"}, "127.0.0.1:8081", "admin"}} {
		flag.CommandLine = flag.NewFlagSet("tunneld", flag.ContinueOnError)
		os.Args = append([]string{"tunneld"}, tt.args...)
		opts := parseArgs()
		if opts.dashboardAddr != tt.want || opts.dashboardUser != tt.user {
			t.Fatalf("dashboardAddr=%q dashboardUser=%q", opts.dashboardAddr, opts.dashboardUser)
		}
		if flag.CommandLine.Lookup("dashboardPassword") != nil {
			t.Fatal("password must not have a command-line flag")
		}
	}
}
