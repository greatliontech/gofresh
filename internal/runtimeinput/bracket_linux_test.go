//go:build linux

package runtimeinput

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/greatliontech/gofresh/internal/guard"
)

func TestBracketRetypingRemainsKnownBesideUnhashableContent(t *testing.T) {
	for _, beforeFIFO := range []bool{false, true} {
		dir := t.TempDir()
		p := filepath.Join(dir, "input")
		makeObject := func(fifo bool) {
			t.Helper()
			var err error
			if fifo {
				err = syscall.Mkfifo(p, 0600)
			} else {
				err = os.WriteFile(p, []byte("value"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		makeObject(beforeFIFO)
		bracket := testBracket(t, dir, "input")
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		makeObject(!beforeFIFO)
		observation, err := FromTestLog([]byte("open input\n"), dir, dir, nil, WithCompletedProcess("reader"), WithBracket(bracket))
		if err != nil || !observation.BracketMoved {
			t.Fatalf("known type movement lost, beforeFIFO=%t: %+v %v", beforeFIFO, observation, err)
		}
	}
}

func machineMotionFacts() (guard.MachineFacts, guard.MachineFacts) {
	before := guard.MachineFacts{CPUModel: "test CPU", PhysicalCores: 2, LogicalCores: 4, TotalRAMBytes: 8 << 30, OS: "linux", KernelVersion: "6.10.0"}
	after := before
	after.TotalRAMBytes = 16 << 30
	return before, after
}

func machineMotionRoots(t *testing.T) []string {
	t.Helper()
	roots := slices.Clone(guard.MachineFactSources)
	slices.Sort(roots)
	if len(roots) < 2 {
		t.Fatal("machine gatherer needs two contributing sources for this regression")
	}
	return roots[:2]
}

func makeMachineMotionSampler(t *testing.T, samples ...*guard.MachineFacts) (func() (guard.MachineFacts, error), func()) {
	t.Helper()
	count := 0
	fn := func() (guard.MachineFacts, error) {
		if count >= len(samples) {
			t.Fatal("unexpected extra machine gather")
		}
		sample := samples[count]
		count++
		if sample == nil {
			return guard.MachineFacts{}, errors.New("injected gather unavailable")
		}
		return *sample, nil
	}
	done := func() {
		t.Helper()
		if count != len(samples) {
			t.Fatalf("gathers = %d, want %d", count, len(samples))
		}
	}
	return fn, done
}

func TestMachineProjectionMovementSurvivesSourceAvailabilityShift(t *testing.T) {
	old, hotAdded := machineMotionFacts()
	for _, tc := range []struct {
		name             string
		before, after    [2]*guard.MachineFacts
		moved, unchanged bool
	}{
		{"shifted different projection", [2]*guard.MachineFacts{&old, nil}, [2]*guard.MachineFacts{nil, &hotAdded}, true, false},
		{"shifted same projection", [2]*guard.MachineFacts{&old, nil}, [2]*guard.MachineFacts{nil, &old}, false, false},
		{"lost projection alone", [2]*guard.MachineFacts{&old, nil}, [2]*guard.MachineFacts{}, false, false},
		{"gained projection alone", [2]*guard.MachineFacts{}, [2]*guard.MachineFacts{nil, &hotAdded}, false, false},
		{"contradictory capture retained", [2]*guard.MachineFacts{&old, &hotAdded}, [2]*guard.MachineFacts{}, true, false},
		{"contradictory closing retained", [2]*guard.MachineFacts{}, [2]*guard.MachineFacts{&old, &hotAdded}, true, false},
		{"independent stable projection", [2]*guard.MachineFacts{&old, &old}, [2]*guard.MachineFacts{&old, &old}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, roots := t.TempDir(), machineMotionRoots(t)
			sampler, done := makeMachineMotionSampler(t, tc.before[0], tc.before[1], tc.after[0], tc.after[1])
			var unchanged, moved bool
			var reason string
			var err error
			withRuntimeTestHooks(runtimeTestHookSet{machineFacts: sampler}, func() {
				b := testBracket(t, dir, roots...)
				unchanged, moved, reason, err = b.revalidate(t.Context(), dir)
			})
			done()
			if err != nil || moved != tc.moved || unchanged != tc.unchanged || (reason == "") != tc.unchanged {
				t.Fatalf("projection comparison: unchanged=%t moved=%t reason=%q err=%v", unchanged, moved, reason, err)
			}
			if moved && refusalClause(reason) != movedBracketClauseForRoot(roots[0]) {
				t.Fatalf("lost contributing-root attribution: %q", reason)
			}
		})
	}
}

func TestMachineBracketMovementSurvivesPostChangeManifest(t *testing.T) {
	dir, roots := t.TempDir(), machineMotionRoots(t)
	old, hotAdded := machineMotionFacts()
	capSampler, captured := makeMachineMotionSampler(t, &old, nil)
	var b Bracket
	withRuntimeTestHooks(runtimeTestHookSet{machineFacts: capSampler}, func() {
		b = testBracket(t, dir, roots...)
	})
	captured()
	// Manifest hashing is single-pass (before revalidation). Only the explicit
	// bracket retains a successful pre-change projection, under the other source root.
	finSampler, finalized := makeMachineMotionSampler(t, &hotAdded, &hotAdded, nil, &hotAdded)
	log := []byte("open " + strings.Join(roots, "\nopen ") + "\n")
	var observation Observation
	var err error
	withRuntimeTestHooks(runtimeTestHookSet{machineFacts: finSampler}, func() {
		observation, err = FromTestLog(log, dir, dir, nil, WithCompletedProcess("reader"), WithBracket(b))
	})
	if err != nil {
		t.Fatal(err)
	}
	finalized()
	if !observation.BracketMoved || refusalClause(observation.Reason) != movedBracketClauseForRoot(roots[0]) {
		t.Fatalf("known projection movement lost: %+v", observation.State)
	}
	var current State
	withRuntimeTestHooks(runtimeTestHookSet{
		machineFacts: func() (guard.MachineFacts, error) { return hotAdded, nil },
	}, func() {
		current, err = Current(t.Context(), observation.Manifest, dir, nil)
	})
	if err != nil || current != observation.State {
		t.Fatalf("later agreement repaired producing movement: %+v %v", current, err)
	}
	m, err := decode(observation.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != len(roots) {
		t.Fatalf("source identities changed: %+v", m.Paths)
	}
	for i, entry := range m.Paths {
		sum := sha256.Sum256(fmt.Appendf(nil, "path abs %s machine %s\n", roots[i], hotAdded.Fingerprint()))
		if entry.Kind != pathAbs || entry.Path != roots[i] || entry.Digest != hex.EncodeToString(sum[:])[:32] {
			t.Fatalf("path-specific manifest framing changed: %+v", entry)
		}
	}
}

func TestMachineProjectionKeepsRootScopeAndSeal(t *testing.T) {
	dir, roots := t.TempDir(), machineMotionRoots(t)
	old, hotAdded := machineMotionFacts()
	sampler1, done := makeMachineMotionSampler(t, &old, nil)
	var b Bracket
	withRuntimeTestHooks(runtimeTestHookSet{machineFacts: sampler1}, func() {
		b = testBracket(t, dir, roots...)
	})
	done()
	if err := b.checkSealed(); err != nil {
		t.Fatal(err)
	}
	for _, relocate := range []bool{false, true} {
		copy := b
		copy.roots = append([]bracketRoot(nil), b.roots...)
		if relocate {
			// The semantic union stays identical, but its attribution was forged.
			copy.roots[1].facts = clonePathFacts(b.roots[0].facts)
			copy.roots[0].facts = newPathFacts()
		} else {
			copy.roots[0].facts = clonePathFacts(b.roots[0].facts)
			for key := range copy.roots[0].facts.values {
				copy.roots[0].facts.put(key.path, key.kind, hotAdded.Fingerprint())
			}
		}
		if err := copy.checkSealed(); err == nil {
			t.Fatalf("forged machine projection accepted: relocate=%t", relocate)
		}
	}
	// Excluding one root removes its sample, not fields from the whole
	// projection another contributing root observes. Only B gathers here.
	sampler2, done := makeMachineMotionSampler(t, &old, &hotAdded)
	var moved bool
	var reason string
	var err error
	withRuntimeTestHooks(runtimeTestHookSet{machineFacts: sampler2}, func() {
		excluded, capErr := CaptureBracket(t.Context(), dir, roots, WithBracketExcludedPaths(roots[0]))
		if capErr != nil {
			t.Fatal(capErr)
		}
		_, moved, reason, err = excluded.revalidate(t.Context(), dir)
	})
	done()
	if err != nil || !moved || refusalClause(reason) != movedBracketClauseForRoot(roots[1]) {
		t.Fatalf("excluded root acquired attribution: moved=%t reason=%q err=%v", moved, reason, err)
	}
}

func TestPartialRootKnownMovement(t *testing.T) {
	for _, scenario := range []string{"same-root FIFO", "external symlink", "unreadable file", "unreadable member"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "input")
			if err := os.WriteFile(p, []byte("before"), 0600); err != nil {
				t.Fatal(err)
			}
			roots := []string{"input"}
			if scenario == "same-root FIFO" {
				if err := syscall.Mkfifo(filepath.Join(dir, "unknown"), 0600); err != nil {
					t.Fatal(err)
				}
				roots = []string{"."}
			} else if scenario == "unreadable member" {
				roots = []string{"."}
			}
			b := testBracket(t, dir, roots...)
			before, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "external symlink" {
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, []byte("after!"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(target, before.ModTime(), before.ModTime()); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, p); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(p, []byte("after!"), 0600); err != nil {
					t.Fatal(err)
				}
				if scenario == "same-root FIFO" {
					if err := os.Chtimes(p, before.ModTime(), before.ModTime()); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "unreadable file" || scenario == "unreadable member" {
					if os.Geteuid() == 0 {
						t.Skip("requires non-root read denial")
					}
					if err := os.Chmod(p, 0000); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.Chmod(p, 0600) })
					if _, err := os.ReadFile(p); !os.IsPermission(err) {
						t.Fatalf("read denial not established: %v", err)
					}
				}
			}
			observation, err := FromTestLog([]byte("open input\n"), dir, dir, nil, WithCompletedProcess("reader"), WithBracket(b))
			if err != nil || !observation.BracketMoved {
				t.Fatalf("known facts lost: %+v %v", observation, err)
			}
		})
	}
}

func TestRootKnowledgeChangeAloneIsNotMovement(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires non-root traversal denial")
	}
	for _, regain := range []bool{false, true} {
		dir := t.TempDir()
		parent := filepath.Join(dir, "parent")
		if err := os.Mkdir(parent, 0700); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(parent, "input")
		if err := os.WriteFile(p, []byte("stable"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(parent, 0700) })
		if regain {
			if err := os.Chmod(parent, 0000); err != nil {
				t.Fatal(err)
			}
		}
		// Only the file is bracketed. Traversal denial outside that root makes
		// its own stat and contents unknown without changing an observed value.
		bracket := testBracket(t, dir, "parent/input")
		mode := os.FileMode(0000)
		if regain {
			mode = 0700
		}
		if err := os.Chmod(parent, mode); err != nil {
			t.Fatal(err)
		}
		observation, err := FromTestLog([]byte("open parent/input\n"), dir, dir, nil, WithCompletedProcess("reader"), WithBracket(bracket))
		if err != nil || !observation.Unverifiable || observation.BracketMoved {
			t.Fatalf("regain=%t availability became drift: %+v %v", regain, observation, err)
		}
	}
}

func TestBracketSealBindsFactAvailabilityAndValues(t *testing.T) {
	dir := bindingModule(t)
	b := testBracket(t, dir, "data")
	for _, remove := range []bool{false, true} {
		for key := range b.roots[0].facts.values {
			copy := b
			copy.roots = append([]bracketRoot(nil), b.roots...)
			copy.roots[0].facts = clonePathFacts(b.roots[0].facts)
			if remove {
				delete(copy.roots[0].facts.values, key)
			} else {
				copy.roots[0].facts.values[key][0] += "changed"
			}
			if err := copy.checkSealed(); err == nil {
				t.Fatalf("tampered fact accepted: %+v remove=%t", key, remove)
			}
		}
	}
	if err := b.checkSealed(); err != nil {
		t.Fatal("test copies mutated original facts", err)
	}
}

func TestRootNamespaceFactsKeepAbsenceAndDanglingLinksDistinct(t *testing.T) {
	dir := t.TempDir()
	// An unobserved intermediate directory appearing does not change the
	// declared root's known absence.
	absent := testBracket(t, dir, "parent/input")
	if err := os.Mkdir(filepath.Join(dir, "parent"), 0700); err != nil {
		t.Fatal(err)
	}
	if unchanged, moved, reason, err := absent.revalidate(t.Context(), dir); err != nil || !unchanged || moved {
		t.Fatalf("unchanged absent root moved: %t %t %q %v", unchanged, moved, reason, err)
	}
	// Removing a dangling link is known namespace movement even though the
	// followed object was and remains absent, including through a parent link.
	if err := os.Symlink("parent", filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{"parent/input", "alias/input"} {
		p := filepath.Join(dir, "parent", "input")
		if err := os.Symlink("missing", p); err != nil {
			t.Fatal(err)
		}
		b := testBracket(t, dir, root)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if _, moved, reason, err := b.revalidate(t.Context(), dir); err != nil || !moved {
			t.Fatalf("lost dangling-link removal: %t %q %v", moved, reason, err)
		}
	}
}

func TestDirectoryEntryTypeSurvivesUnavailableInfo(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires non-root search denial")
	}
	for _, retype := range []bool{false, true} {
		dir := t.TempDir()
		data := filepath.Join(dir, "data")
		input := filepath.Join(data, "input")
		if err := os.Mkdir(data, 0700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(data, 0700) })
		if err := os.WriteFile(input, []byte("before"), 0600); err != nil {
			t.Fatal(err)
		}
		checkEntry := func(wantDir bool) {
			t.Helper()
			entries, err := os.ReadDir(data)
			if err != nil || len(entries) != 1 {
				t.Fatalf("readable listing: %+v %v", entries, err)
			}
			if entries[0].IsDir() != wantDir || entries[0].Type().IsDir() != wantDir {
				t.Fatal("directory entry did not expose actual type")
			}
			if _, err := entries[0].Info(); !os.IsPermission(err) {
				t.Fatalf("Info must be unavailable: %v", err)
			}
		}
		if err := os.Chmod(data, 0400); err != nil {
			t.Fatal(err)
		}
		checkEntry(false)
		b := testBracket(t, dir, "data")
		if err := os.Chmod(data, 0700); err != nil {
			t.Fatal(err)
		}
		if consumed, err := os.ReadFile(input); err != nil || string(consumed) != "before" {
			t.Fatalf("producing read: %q %v", consumed, err)
		}
		if retype {
			if err := os.Remove(input); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(input, 0700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(data, 0400); err != nil {
			t.Fatal(err)
		}
		checkEntry(retype)
		observation, err := FromTestLog([]byte("open data/input\n"), dir, dir, nil, WithCompletedProcess("reader"), WithBracket(b))
		if err != nil || observation.BracketMoved != retype || !observation.Unverifiable {
			t.Fatalf("retype=%t lost dirent knowledge: %+v %v", retype, observation, err)
		}
	}
}

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
		if got := refusalClause(state.Reason); got != "observation bracket unverifiable: unhashable runtime directory entry: data/pipe" {
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
			if !current.Unverifiable || refusalClause(current.Reason) != arm.clause {
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

