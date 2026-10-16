package runtimeinput

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/guard"
)

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

func machineMotionSamples(t *testing.T, samples ...*guard.MachineFacts) func() {
	t.Helper()
	previous := currentMachineFacts
	t.Cleanup(func() { currentMachineFacts = previous })
	count := 0
	currentMachineFacts = func() (guard.MachineFacts, error) {
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
	return func() {
		t.Helper()
		if count != len(samples) {
			t.Fatalf("gathers = %d, want %d", count, len(samples))
		}
	}
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
			done := machineMotionSamples(t, tc.before[0], tc.before[1], tc.after[0], tc.after[1])
			b := testBracket(t, dir, roots...)
			unchanged, moved, reason, err := b.revalidate(t.Context(), dir)
			done()
			if err != nil || moved != tc.moved || unchanged != tc.unchanged || (reason == "") != tc.unchanged {
				t.Fatalf("projection comparison: unchanged=%t moved=%t reason=%q err=%v", unchanged, moved, reason, err)
			}
			if moved && RefusalClause(reason) != MovedBracketClause(roots[0]) {
				t.Fatalf("lost contributing-root attribution: %q", reason)
			}
		})
	}
}

func TestMachineBracketMovementSurvivesPostChangeManifest(t *testing.T) {
	dir, roots := t.TempDir(), machineMotionRoots(t)
	old, hotAdded := machineMotionFacts()
	captured := machineMotionSamples(t, &old, nil)
	b := testBracket(t, dir, roots...)
	captured()
	// Both manifest hashing passes are post-change. Only the explicit bracket
	// retains a successful pre-change projection, under the other source root.
	finalized := machineMotionSamples(t, &hotAdded, &hotAdded, nil, &hotAdded, &hotAdded, &hotAdded)
	log := []byte("open " + strings.Join(roots, "\nopen ") + "\n")
	observation, err := FromTestLog(log, dir, dir, nil, WithCompletedProcess("reader"), WithBracket(b))
	if err != nil {
		t.Fatal(err)
	}
	finalized()
	if !observation.BracketMoved || RefusalClause(observation.Reason) != MovedBracketClause(roots[0]) {
		t.Fatalf("known projection movement lost: %+v", observation.State)
	}
	currentMachineFacts = func() (guard.MachineFacts, error) { return hotAdded, nil }
	current, err := Current(t.Context(), observation.Manifest, dir, nil)
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
	done := machineMotionSamples(t, &old, nil)
	b := testBracket(t, dir, roots...)
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
	done = machineMotionSamples(t, &old, &hotAdded)
	excluded, err := CaptureBracket(t.Context(), dir, roots, WithBracketExcludedPaths(roots[0]))
	if err != nil {
		t.Fatal(err)
	}
	_, moved, reason, err := excluded.revalidate(t.Context(), dir)
	done()
	if err != nil || !moved || RefusalClause(reason) != MovedBracketClause(roots[1]) {
		t.Fatalf("excluded root acquired attribution: moved=%t reason=%q err=%v", moved, reason, err)
	}
}
