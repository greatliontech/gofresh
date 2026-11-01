package reflectexternal

import (
	"os"
	"reflect"
	"testing"
)

func target() {
	_, _ = os.ReadFile("fixture.txt")
}

func BenchmarkReflectExternal(b *testing.B) {
	v := reflect.ValueOf(target)
	for b.Loop() {
		v.Call(nil)
	}
}
