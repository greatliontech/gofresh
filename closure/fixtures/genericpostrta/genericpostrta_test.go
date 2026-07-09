package genericpostrta

import "testing"

func BenchmarkGenericPostRTA(b *testing.B) {
	for b.Loop() {
		_ = call(direct{})
		asmEntry()
	}
}
