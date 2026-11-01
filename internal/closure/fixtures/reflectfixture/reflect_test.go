package reflectfixture

import (
	"reflect"
	"testing"
)

func target() {}

func BenchmarkReflect(b *testing.B) {
	v := reflect.ValueOf(target)
	for b.Loop() {
		v.Call(nil)
	}
}
