package asmcall

import "testing"

func BenchmarkASMMacro(b *testing.B) {
	for b.Loop() {
		asmMacro()
	}
}

func BenchmarkASMComponentMacro(b *testing.B) {
	for b.Loop() {
		asmComponentMacro()
	}
}

func BenchmarkASMLocalJump(b *testing.B) {
	for b.Loop() {
		asmLocalJump()
	}
}

func BenchmarkASMCall(b *testing.B) {
	for b.Loop() {
		asmEntry()
	}
}

func BenchmarkASMJump(b *testing.B) {
	for b.Loop() {
		asmJump()
	}
}
