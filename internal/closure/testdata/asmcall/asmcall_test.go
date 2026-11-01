package asmcall

import "testing"

func BenchmarkASMCall(b *testing.B) {
	for b.Loop() {
		asmEntry()
	}
}
