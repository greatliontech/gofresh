package opaqueasm

import "testing"

func BenchmarkOpaqueASM(b *testing.B) {
	for b.Loop() {
		asmEntry()
	}
}
