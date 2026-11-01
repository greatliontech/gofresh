package stdcallback

import (
	"sort"
	"testing"
)

type byLen []string

func (b byLen) Len() int { return len(b) }

func (b byLen) Less(i, j int) bool { return len(b[i]) < len(b[j]) }

func (b byLen) Swap(i, j int) { b[i], b[j] = b[j], b[i] }

func BenchmarkSortCallback(b *testing.B) {
	values := byLen{"bbb", "a", "cc"}
	for b.Loop() {
		sort.Sort(values)
	}
}
