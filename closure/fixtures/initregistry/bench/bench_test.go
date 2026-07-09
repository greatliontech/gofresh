package bench

import (
	"testing"

	_ "github.com/greatliontech/gofresh/closure/fixtures/initregistry/codec"
	"github.com/greatliontech/gofresh/closure/fixtures/initregistry/registry"
)

var data = []byte("payload")

func BenchmarkDecode(b *testing.B) {
	c := registry.Get("gzip")
	for b.Loop() {
		_ = c.Decode(data)
	}
}
