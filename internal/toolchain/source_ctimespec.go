//go:build darwin || freebsd || netbsd

package toolchain

import "syscall"

// statChangeTime is the stat's change time in nanoseconds under this
// platform's spelling of the field.
func statChangeTime(st *syscall.Stat_t) int64 { return st.Ctimespec.Nano() }
