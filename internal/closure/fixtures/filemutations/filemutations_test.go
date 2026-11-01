package filemutations

import (
	"os"
	"testing"
)

func BenchmarkCreate(b *testing.B) {
	for b.Loop() {
		f, _ := os.Create("out-create")
		if f != nil {
			_ = f.Close()
		}
	}
}

func BenchmarkOpenFileCreate(b *testing.B) {
	for b.Loop() {
		f, _ := os.OpenFile("out-openfile", os.O_CREATE|os.O_WRONLY, 0o600)
		if f != nil {
			_ = f.Close()
		}
	}
}

func BenchmarkWriteFile(b *testing.B) {
	for b.Loop() {
		_ = os.WriteFile("out-writefile", []byte("x"), 0o600)
	}
}
