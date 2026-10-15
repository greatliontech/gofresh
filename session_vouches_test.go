package gofresh

import (
	"os"
	"slices"
	"testing"
)

func TestSessionAcceptsTheResolvedVouchSet(t *testing.T) {
	entries, err := ParseVouchEntries([]string{"example.com/a.b:State", "example.com/dep:Other", "example.com/a.b:State"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(t.Context(), BuildDescription{Directory: t.TempDir(), Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{Vouches: entries})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.engine.dynamicStateVouches) != 2 || !s.engine.dynamicStateVouches["example.com/a.b.State"] || !s.engine.dynamicStateVouches["example.com/dep.Other"] {
		t.Fatal("resolved vouch set changed at session admission")
	}
	for _, value := range []string{"", "example.com/dep:State", "example.com/dep", "example.com/dep.", "example.com/dep.not-a-name", "example.com/pkg/x"} {
		if _, err := canonicalSessionVouches([]string{value}); err == nil {
			t.Fatalf("noncanonical identity admitted: %q", value)
		}
	}
	got, err := canonicalSessionVouches([]string{"example.com/dep.Other", "example.com/a.b.State", "example.com/dep.Other"})
	if err != nil || !slices.Equal(got, []string{"example.com/a.b.State", "example.com/dep.Other"}) {
		t.Fatalf("canonical set: %q %v", got, err)
	}
}
