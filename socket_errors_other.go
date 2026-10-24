//go:build !windows

package tunnel

import "syscall"

const errAddrInUse = syscall.EADDRINUSE
