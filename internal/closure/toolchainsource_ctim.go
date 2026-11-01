//go:build unix && !(darwin || freebsd || netbsd)

package closure

import "syscall"

// statChangeTime is the stat's change time in nanoseconds under this
// platform's spelling of the field — every unix platform but the three
// spelling it Ctimespec, so the two files partition unix by
// construction.
func statChangeTime(st *syscall.Stat_t) int64 { return st.Ctim.Nano() }
