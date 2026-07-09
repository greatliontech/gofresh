package unixopencreate

import (
	"testing"

	"golang.org/x/sys/unix"
)

func BenchmarkUnixOpenCreate(b *testing.B) {
	for b.Loop() {
		fd, err := unix.Open("out", unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY, 0o600)
		if err == nil {
			_ = unix.Close(fd)
		}
	}
}
