package gotool

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// SetEnv drops every entry of the key and inserts the new one where
// NormalizeEnv orders it: over a normalized environment the result is
// what NormalizeEnv would return over the appended form — the setter
// keeps the policy's order instead of appending out of it.
//
//gofresh:pure
func TestSetEnvKeepsNormalizeEnvsOrder(t *testing.T) {
	cases := [][]string{
		{},
		{"A=2", "B=1"},
		{"GOFLAGS=old", "PWD=/a", "Z=1"},
		{"GOFLAGS=", "Z=1", "m=2"},
	}
	for _, env := range cases {
		got := SetEnv(env, "GOFLAGS", "-race")
		appended := append([]string(nil), env...)
		var kept []string
		for _, e := range appended {
			if !strings.HasPrefix(e, "GOFLAGS=") {
				kept = append(kept, e)
			}
		}
		want, err := NormalizeEnv(append(kept, "GOFLAGS=-race"))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("SetEnv(%v) = %v, want NormalizeEnv's order %v", env, got, want)
		}
		if n := strings.Count(strings.Join(got, "\n")+"\n", "GOFLAGS="); n != 1 {
			t.Fatalf("SetEnv(%v) carries GOFLAGS %d times", env, n)
		}
	}
}

// Coordinate never fails: the canonical coordinate where the
// filesystem answers, the absolute spelling for a directory that does
// not exist, the spelling itself only where even that fails.
func TestCoordinateDegrades(t *testing.T) {
	dir := t.TempDir()
	// A symlink spelling: the coordinate is the target's, never the
	// absolute spelling of the link.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := Coordinate(link); got != canonical || got == link {
		t.Fatalf("Coordinate(symlink) = %q, want the canonical %q", got, canonical)
	}
	missing := dir + "/no/such/dir"
	if got := Coordinate(missing); got != missing {
		t.Fatalf("Coordinate(missing absolute) = %q, want the absolute spelling", got)
	}
	if got := Coordinate("relative/missing"); got == "relative/missing" || got == "" {
		t.Fatalf("Coordinate(missing relative) = %q, want an absolute spelling", got)
	}
}
