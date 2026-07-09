package direct

import "testing"

const UsedConst = 7

const UnusedConst = 99

type UsedType struct {
	N int
}

type UnusedType struct {
	N int
}

func used(v UsedType) int {
	return v.N + UsedConst
}

func unused(v UnusedType) int {
	return v.N + UnusedConst
}

func BenchmarkDirect(b *testing.B) {
	v := UsedType{N: 1}
	for b.Loop() {
		_ = used(v)
	}
}
