package genericescape

import "testing"

func BenchmarkGenericEscape(b *testing.B) {
	for b.Loop() {
		leak(Box[int]{})
	}
}
