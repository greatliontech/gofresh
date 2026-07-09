package embedfixture

import (
	_ "embed"
	"testing"
)

//go:embed data.txt
var payload string

func BenchmarkEmbed(b *testing.B) {
	for b.Loop() {
		_ = len(payload)
	}
}
