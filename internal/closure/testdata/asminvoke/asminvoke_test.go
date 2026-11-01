package asminvoke

import "testing"

func BenchmarkASMInvoke(b *testing.B) {
	for b.Loop() {
		asmEntry()
	}
}
