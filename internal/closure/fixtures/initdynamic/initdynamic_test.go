package initdynamic

import (
	"os"
	"testing"
)

var initData []byte

type reader interface {
	read()
}

type source struct{}

func (source) read() {
	initData, _ = os.ReadFile("pre.txt")
}

func init() {
	var r reader = source{}
	r.read()
}

func BenchmarkInitDynamic(b *testing.B) {
	for b.Loop() {
		_ = len(initData)
	}
}
