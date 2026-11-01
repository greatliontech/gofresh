//go:build unix

package closure

import (
	"io/fs"
	"syscall"
)

// changeTime is the entry's inode change time in nanoseconds — the
// kernel's stamp, moved by every write, rename, or mode change and
// settable by no tool — or 0 where the stat carries none. The field's
// spelling is the platform's (statChangeTime): Ctimespec on darwin,
// freebsd and netbsd, Ctim on every other unix platform.
func changeTime(info fs.FileInfo) int64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return statChangeTime(st)
	}
	return 0
}

// stampsTrusted: the stat carries a change time, so a listing memo
// may serve over matching stamps.
const stampsTrusted = true
