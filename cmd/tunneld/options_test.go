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
	}{{nil, ""}, {[]string{"-dashboardAddr", "127.0.0.1:8081"}, "127.0.0.1:8081"}} {
		flag.CommandLine = flag.NewFlagSet("tunneld", flag.ContinueOnError)
		os.Args = append([]string{"tunneld"}, tt.args...)
		if got := parseArgs().dashboardAddr; got != tt.want {
			t.Fatalf("dashboardAddr=%q want %q", got, tt.want)
		}
	}
}
