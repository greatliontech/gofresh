package harnessshared

import (
	"os"
	"testing"
)

// shared is the cross-subject channel: analysis is subject-scoped, the
// process heap is not. TestPlant's runtime flow populates it with an
// implementation TestConsume's attributed enumeration cannot see.
var shared testing.TB

type envTB struct{ *testing.T }

func (envTB) Fatal(...any) { _ = os.Getenv("HARNESSSHARED_SECRET") }

func TestPlant(t *testing.T) {
	shared = envTB{t}
}

func helper(tb testing.TB) []byte {
	data, err := os.ReadFile("baseline.txt")
	if err != nil {
		tb.Fatal(err)
	}
	return data
}

func TestConsume(t *testing.T) {
	_ = helper(t)
	if shared != nil {
		_ = helper(shared)
	}
}
