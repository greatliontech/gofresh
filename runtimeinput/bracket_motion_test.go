package runtimeinput

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBracketMovementSurvivesComposition(t *testing.T) {
	dir := bindingModule(t)
	b := testBracket(t, dir, "data")
	file := filepath.Join(dir, "data", "fixture.txt")
	if err := os.WriteFile(file, []byte("after consumption"), 0600); err != nil {
		t.Fatal(err)
	}
	moved, err := FromTestLog([]byte("open data/fixture.txt\n"), dir, dir, nil, WithCompletedProcess("reader"), WithBracket(b))
	if err != nil {
		t.Fatal(err)
	}
	assertMoved := func(t *testing.T, observation Observation, err error) Observation {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		state, err := CompletedState(observation)
		if err != nil || !state.BracketMoved || !strings.Contains(state.Reason, "observation bracket moved: data") {
			t.Fatalf("lost movement: %+v %v", state, err)
		}
		current, err := Current(t.Context(), state.Manifest, dir, nil)
		if err != nil || current != state {
			t.Fatalf("recheck: %+v %v", current, err)
		}
		return observation
	}
	assertMoved(t, moved, nil)
	abs, err := Absolute(moved, dir, nil)
	abs = assertMoved(t, abs, err)
	rel, err := Relative(abs, dir, nil)
	rel = assertMoved(t, rel, err)
	if rel.State != moved.State {
		t.Fatal("identity roundtrip changed evidence")
	}
	adopted, err := Adopt(moved.Manifest, dir, "adoption", nil)
	assertMoved(t, adopted, err)
	empty, err := Merge(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	incomplete, err := Incomplete(dir, "interrupted", "unknown sibling", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, inputs := range [][]Observation{{moved, empty}, {empty, moved}, {incomplete, moved}, {moved, incomplete}, {moved, moved}} {
		merged, err := Merge(dir, nil, inputs...)
		assertMoved(t, merged, err)
	}
	tampered := moved
	tampered.BracketMoved = false
	if _, err := CompletedState(tampered); err == nil {
		t.Fatal("unsealed movement override accepted")
	}
	// Restoration after the failure was observed cannot erase producing history.
	if err := os.WriteFile(file, []byte("recorded"), 0644); err != nil {
		t.Fatal(err)
	}
	current, err := Current(t.Context(), moved.Manifest, dir, nil)
	if err != nil || !current.BracketMoved {
		t.Fatalf("restored value erased movement: %+v %v", current, err)
	}
	if _, err := Adopt(moved.Manifest, dir, "restored", nil); err == nil {
		t.Fatal("adoption accepted changed values")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if state, err := Current(ctx, moved.Manifest, dir, nil); !errors.Is(err, context.Canceled) || state != (State{}) {
		t.Fatalf("cancelled check supplied evidence: %+v %v", state, err)
	}
}

func TestBracketUnknownDoesNotMaskComparableMovement(t *testing.T) {
	for _, lateUnknown := range []bool{false, true} {
		for _, move := range []bool{false, true} {
			dir := bindingModule(t)
			external := filepath.Join(t.TempDir(), "external")
			if err := os.WriteFile(external, []byte("external"), 0600); err != nil {
				t.Fatal(err)
			}
			unknown := filepath.Join(dir, "a-unknown")
			if lateUnknown {
				if err := os.WriteFile(unknown, []byte("before"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Symlink(external, unknown); err != nil {
				t.Fatal(err)
			}
			b := testBracket(t, dir, "a-unknown", "data")
			if lateUnknown {
				if err := os.Remove(unknown); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(external, unknown); err != nil {
					t.Fatal(err)
				}
			}
			if move {
				if err := os.WriteFile(filepath.Join(dir, "data", "fixture.txt"), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			observation, err := FromTestLog([]byte("open data/fixture.txt\n"), dir, dir, nil, WithCompletedProcess("reader"), WithBracket(b))
			// Replacing a regular root with an external symlink is known
			// namespace movement, even though its new content is unhashable.
			if err != nil || !observation.Unverifiable || observation.BracketMoved != (move || lateUnknown) {
				t.Fatalf("lateUnknown=%t move=%t: %+v %v", lateUnknown, move, observation, err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, _, _, err := b.revalidate(ctx, dir); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled unknown bracket: %v", err)
			}
		}
	}
}

func TestBracketMovementIncludesObjectTransitions(t *testing.T) {
	for _, transition := range []string{"appearance", "disappearance", "retype"} {
		t.Run(transition, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "input")
			if transition != "appearance" {
				if err := os.WriteFile(p, []byte("before"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			b := testBracket(t, dir, "input")
			if transition != "appearance" {
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
			}
			if transition == "appearance" {
				if err := os.WriteFile(p, []byte("after"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if transition == "retype" {
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
			}
			observation, err := FromTestLog([]byte("open input\n"), dir, dir, nil, WithCompletedProcess("reader"), WithBracket(b))
			if err != nil || !observation.BracketMoved {
				t.Fatalf("lost %s: %+v %v", transition, observation, err)
			}
		})
	}
}

func TestMovementManifestCanonicalWireAndDigest(t *testing.T) {
	const raw = `{"v":4,"bracketMoved":true,"unverifiable":["diagnostic"]}`
	encoded := base64.RawURLEncoding.EncodeToString([]byte(raw))
	state, err := Current(t.Context(), encoded, t.TempDir(), nil)
	sum := sha256.Sum256([]byte("version 4\nbracket-moved\nunverifiable diagnostic\n"))
	if err != nil || !state.BracketMoved || state.Manifest != encoded || state.Digest != hex.EncodeToString(sum[:])[:32] {
		t.Fatalf("wire/digest disagreement: %+v %v", state, err)
	}
	for _, invalid := range []string{
		`{"v":4,"bracketMoved":false}`, `{"v":4,"bracketMoved":null}`,
		`{"v":4,"bracketMoved":true,"bracketMoved":true}`,
		`{"v":4,"unverifiable":["diagnostic"],"bracketMoved":true}`,
	} {
		if _, err := decode(base64.RawURLEncoding.EncodeToString([]byte(invalid))); err == nil {
			t.Fatalf("accepted %s", invalid)
		}
	}
	// Text alone is never semantic movement evidence, even when it looks exact.
	text, err := Incomplete(t.TempDir(), "caller", MovedBracketClause("data"), nil)
	if err != nil || text.BracketMoved {
		t.Fatalf("diagnostic granted guard authority: %+v %v", text, err)
	}
}
