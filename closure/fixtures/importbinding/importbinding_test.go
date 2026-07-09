package importbinding

import (
	codec "encoding/json"
	"testing"
)

func BenchmarkImportBinding(b *testing.B) {
	for b.Loop() {
		_, _ = codec.Marshal(1)
	}
}
