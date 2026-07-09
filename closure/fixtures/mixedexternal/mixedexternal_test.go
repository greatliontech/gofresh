package mixedexternal

import (
	"net"
	"os"
	"testing"
)

func BenchmarkMixedExternal(b *testing.B) {
	for b.Loop() {
		_, _ = os.ReadFile("fixture.txt")
		conn, _ := net.Dial("tcp", "127.0.0.1:1")
		if conn != nil {
			_ = conn.Close()
		}
	}
}
