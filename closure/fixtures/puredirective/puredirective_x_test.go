// External test package: a directive here must resolve to the package under
// test's import path, the path the engine roots subjects under.
package puredirective_test

import "testing"

//gofresh:pure
func BenchmarkXAsserted(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = i
	}
}

func BenchmarkXNotAsserted(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = i
	}
}
