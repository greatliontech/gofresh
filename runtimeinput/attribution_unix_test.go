//go:build unix

package runtimeinput

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// An unhashable member inside the module is spelled module-relative in
// its clause — a FIFO the bracket's walk meets at capture, and a member
// that became a FIFO or unreadable after the record was made, met by
// the hashing pass at revalidation — so one tree in two checkouts
// yields one manifest, one digest and one reason
// (REQ-inputs-refusal-attribution's spelling rule over the hashing
// pass's every refusal).
func TestUnhashableInModuleMembersSpellModuleRelative(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file")
	}
	plant := func(t *testing.T) (moduleDir, packageDir, data string) {
		moduleDir, packageDir = testDirs(t)
		data = filepath.Join(moduleDir, "data")
		if err := os.MkdirAll(data, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"pipe", "secret"} {
			if err := os.WriteFile(filepath.Join(data, name), []byte(name), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return moduleDir, packageDir, data
	}
	same := func(t *testing.T, arm string, states [2]State) {
		t.Helper()
		if states[0].Manifest != states[1].Manifest || states[0].Digest != states[1].Digest || states[0].Reason != states[1].Reason {
			t.Fatalf("%s: two checkouts' identities differ:\n%+v\n%+v", arm, states[0], states[1])
		}
	}

	// The bracket's walk meets the FIFO at capture: the refusal, wrapped
	// as the bracket's, names the member under the root's spelling.
	var walked [2]State
	for i := range walked {
		moduleDir, packageDir, data := plant(t)
		if err := os.Remove(filepath.Join(data, "pipe")); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(filepath.Join(data, "pipe"), 0o644); err != nil {
			t.Fatal(err)
		}
		state, err := FromTestLog([]byte("open ../data\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
		if err != nil {
			t.Fatal(err)
		}
		if got := RefusalClause(state.Reason); got != "observation bracket unverifiable: unhashable runtime directory entry: data/pipe" {
			t.Fatalf("checkout %d: the walked clause = %q", i, got)
		}
		if strings.Contains(state.Manifest, moduleDir) {
			t.Fatalf("checkout %d: the manifest names the checkout", i)
		}
		walked[i] = state.State
	}
	same(t, "walked", walked)

	// A member that became unhashable after the record: the hashing
	// pass meets it at revalidation, unwrapped, and spells it relative.
	for _, arm := range []struct {
		name   string
		mutate func(t *testing.T, data string)
		clause string
	}{
		{"pipe", func(t *testing.T, data string) {
			if err := os.Remove(filepath.Join(data, "pipe")); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(filepath.Join(data, "pipe"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "unhashable runtime input: data/pipe"},
		{"secret", func(t *testing.T, data string) {
			if err := os.Chmod(filepath.Join(data, "secret"), 0o000); err != nil {
				t.Fatal(err)
			}
		}, "unhashable runtime input: data/secret"},
	} {
		var derived [2]State
		for i := range derived {
			moduleDir, packageDir, data := plant(t)
			recorded, err := FromTestLog([]byte("open ../data/"+arm.name+"\n"), moduleDir, packageDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir)))
			if err != nil {
				t.Fatal(err)
			}
			if recorded.Unverifiable {
				t.Fatalf("%s, checkout %d: the record refused before the mutation: %q", arm.name, i, recorded.Reason)
			}
			arm.mutate(t, data)
			current, err := Current(context.Background(), recorded.Manifest, moduleDir, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !current.Unverifiable || RefusalClause(current.Reason) != arm.clause {
				t.Fatalf("%s, checkout %d: the revalidated state = %+v, want the clause %q", arm.name, i, current, arm.clause)
			}
			if strings.Contains(current.Reason, moduleDir) {
				t.Fatalf("%s, checkout %d: the reason names the checkout", arm.name, i)
			}
			derived[i] = current
		}
		same(t, arm.name, derived)
	}
}
