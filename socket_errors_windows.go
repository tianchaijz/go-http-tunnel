package tunnel

import "syscall"

// Winsock uses WSAEADDRINUSE, not syscall.EADDRINUSE.
const errAddrInUse = syscall.Errno(10048)
