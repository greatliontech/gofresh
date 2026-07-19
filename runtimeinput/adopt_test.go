package runtimeinput

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// adoptTestState re-evaluates a manifest of identities against the current
// view, yielding the canonical completed state a producing run would have
// recorded.
func adoptTestState(t *testing.T, m manifest, moduleDir string, env []string) State {
	t.Helper()
	encoded, err := encode(m)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		t.Fatal(err)
	}
	state, err := currentWithNormalizedEnv(encoded, moduleDir, normalized)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// A persisted union re-admitted through adoption merges with fresh
// observations to exactly the state a fresh merge of every contributor
// yields (REQ-inputs-adoption).
func TestAdoptedUnionMergesLikeFreshObservations(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fixture.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := []string{"ADOPT_A=1", "ADOPT_B=2"}
	stateA := adoptTestState(t, manifest{Version: manifestVersion, Env: []envInput{{Name: "ADOPT_A", Digest: testEntryDigest}}}, dir, env)
	stateB := adoptTestState(t, manifest{Version: manifestVersion, Paths: []pathInput{{pathID: pathID{Kind: pathRel, Path: "fixture.txt"}, Digest: testEntryDigest}}}, dir, env)
	obsA := newObservation(stateA, "proc-a", "test")
	obsB := newObservation(stateB, "proc-b", "test")
	union, err := MergeEnv(dir, env, obsA, obsB)
	if err != nil {
		t.Fatal(err)
	}
	persisted := union.State.Manifest

	adopted, err := AdoptEnv(persisted, dir, "persisted-union", env)
	if err != nil {
		t.Fatalf("AdoptEnv: %v", err)
	}
	stateC := adoptTestState(t, manifest{Version: manifestVersion, Env: []envInput{{Name: "ADOPT_B", Digest: testEntryDigest}}}, dir, env)
	obsC := newObservation(stateC, "proc-c", "test")
	widened, err := MergeEnv(dir, env, adopted, obsC)
	if err != nil {
		t.Fatalf("merge with adopted union: %v", err)
	}
	fresh, err := MergeEnv(dir, env, obsA, obsB, obsC)
	if err != nil {
		t.Fatal(err)
	}
	if widened.State != fresh.State {
		t.Fatalf("adopted-path union state = %+v, fresh union state = %+v, want identical digest semantics", widened.State, fresh.State)
	}
}

// Adoption re-evaluates recorded evidence and refuses a contradicted manifest,
// naming the moved input — persisted evidence never re-enters silently.
func TestAdoptRefusesMovedManifestNamingTheMover(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.txt")
	if err := os.WriteFile(path, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := []string{"ADOPT_A=1"}
	state := adoptTestState(t, manifest{Version: manifestVersion, Paths: []pathInput{{pathID: pathID{Kind: pathRel, Path: "fixture.txt"}, Digest: testEntryDigest}}}, dir, env)
	if err := os.WriteFile(path, []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := AdoptEnv(state.Manifest, dir, "persisted-union", env)
	if err == nil || !strings.Contains(err.Error(), "moved") || !strings.Contains(err.Error(), "fixture.txt") {
		t.Fatalf("AdoptEnv after move = %v, want refusal naming fixture.txt", err)
	}
}

// Adoption accepts only the canonical encoding; padded, reordered, or
// otherwise re-serialized manifests are refused structurally.
func TestAdoptRefusesNonCanonicalEncoding(t *testing.T) {
	dir := t.TempDir()
	env := []string{"ADOPT_A=1"}
	state := adoptTestState(t, manifest{Version: manifestVersion, Env: []envInput{{Name: "ADOPT_A", Digest: testEntryDigest}}}, dir, env)
	if _, err := AdoptEnv(state.Manifest+"A", dir, "persisted-union", env); err == nil {
		t.Fatal("AdoptEnv accepted a tampered encoding")
	}
	if _, err := AdoptEnv("", dir, "persisted-union", env); err == nil {
		t.Fatal("AdoptEnv accepted an empty manifest string")
	}
	// A semantically equal but re-serialized manifest — valid base64, valid
	// JSON, non-canonical byte form — must refuse at the canonical-encoding
	// gate itself, not depend on transport-layer validation.
	raw, err := base64.RawURLEncoding.DecodeString(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	reserialized := base64.RawURLEncoding.EncodeToString(append(raw, ' '))
	_, err = AdoptEnv(reserialized, dir, "persisted-union", env)
	if err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("AdoptEnv(re-serialized) = %v, want canonical-encoding refusal", err)
	}
}

// Adoption validates its inputs at the boundary: a process identity and a
// well-formed environment are required, and an adopted observation never
// aliases a genuine completed observation of the same state under the same
// process — their provenance dispositions differ, so merge refuses the
// conflict instead of silently unifying unverified and verified evidence.
func TestAdoptBoundaryValidationAndProvenance(t *testing.T) {
	dir := t.TempDir()
	env := []string{"ADOPT_A=1"}
	state := adoptTestState(t, manifest{Version: manifestVersion, Env: []envInput{{Name: "ADOPT_A", Digest: testEntryDigest}}}, dir, env)
	if _, err := AdoptEnv(state.Manifest, dir, "", env); err == nil {
		t.Fatal("AdoptEnv accepted an empty process identity")
	}
	if _, err := AdoptEnv(state.Manifest, dir, "p", []string{"ADOPT_A=1", "ADOPT_A=2"}); err == nil {
		t.Fatal("AdoptEnv accepted a duplicate-key environment")
	}
	adopted, err := AdoptEnv(state.Manifest, dir, "p", env)
	if err != nil {
		t.Fatal(err)
	}
	genuine := newObservation(state, "p", "complete")
	if _, err := MergeEnv(dir, env, adopted, genuine); err == nil || !strings.Contains(err.Error(), "conflicting observations") {
		t.Fatalf("merge of adopted and genuine evidence under one process = %v, want provenance conflict refusal", err)
	}
}

// An adopted union carries recorded incompleteness into merge: the reasons
// survive and keep the merged evidence unverifiable, never silently dropped.
func TestAdoptCarriesUnverifiableReasons(t *testing.T) {
	dir := t.TempDir()
	env := []string{"ADOPT_A=1"}
	state := adoptTestState(t, manifest{Version: manifestVersion, Unverifiable: []string{"incomplete: proc-x"}}, dir, env)
	adopted, err := AdoptEnv(state.Manifest, dir, "persisted-union", env)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := MergeEnv(dir, env, adopted)
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(merged.State.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Unverifiable) != 1 || m.Unverifiable[0] != "incomplete: proc-x" {
		t.Fatalf("merged unverifiable = %v, want the adopted incompleteness reason", m.Unverifiable)
	}
}

// Adopting the observation-free manifest succeeds and stays the identity of
// merge, mirroring REQ-inputs-merge's zero-observation semantics.
func TestAdoptObservationFreeManifest(t *testing.T) {
	dir := t.TempDir()
	env := []string{"ADOPT_A=1"}
	empty, err := MergeEnv(dir, env)
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := AdoptEnv(empty.State.Manifest, dir, "persisted-union", env)
	if err != nil {
		t.Fatalf("AdoptEnv(observation-free): %v", err)
	}
	remerged, err := MergeEnv(dir, env, adopted)
	if err != nil {
		t.Fatal(err)
	}
	if remerged.State != empty.State {
		t.Fatalf("re-merged empty state = %+v, want the observation-free state %+v", remerged.State, empty.State)
	}
}
