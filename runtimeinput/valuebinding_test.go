package runtimeinput

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// bindingModule builds a module with a "data" root holding one recorded
// fixture, the smallest surface for value-binding construction tests.
func bindingModule(t *testing.T) string {
	t.Helper()
	moduleDir := filepath.Join(t.TempDir(), "mod")
	if err := os.MkdirAll(filepath.Join(moduleDir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "data", "fixture.txt"), []byte("recorded"), 0o644); err != nil {
		t.Fatal(err)
	}
	return moduleDir
}

// manifestReasons decodes a state's manifest and returns its unverifiable
// reasons.
func manifestReasons(t *testing.T, state State) []string {
	t.Helper()
	m, err := decode(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	return m.Unverifiable
}

// TestCompletedObservationRequiresBracket pins the
// REQ-inputs-completed-observation gate list: completed construction without
// an observation bracket, with a bracket capture did not produce, with one
// captured under a foreign module view, or with a duplicate bracket is a
// construction error, while incomplete construction stays bracketless.
func TestCompletedObservationRequiresBracket(t *testing.T) {
	moduleDir := bindingModule(t)
	log := []byte("open data/fixture.txt\n")
	if _, err := FromTestLogEnv(log, moduleDir, moduleDir, nil, WithCompletedProcess("worker")); err == nil || !strings.Contains(err.Error(), "observation bracket") {
		t.Fatalf("completed construction without a bracket = %v, want missing-bracket error", err)
	}
	if _, err := FromTestLogEnv(log, moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(Bracket{})); err == nil {
		t.Fatal("completed construction accepted a zero bracket")
	}
	foreign := testBracket(t, t.TempDir())
	if _, err := FromTestLogEnv(log, moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(foreign)); err == nil {
		t.Fatal("completed construction accepted a bracket captured under a foreign module view")
	}
	bracket := testBracket(t, moduleDir)
	if _, err := FromTestLogEnv(log, moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket), WithBracket(bracket)); err == nil {
		t.Fatal("completed construction accepted duplicate brackets")
	}
	if _, err := IncompleteEnv(moduleDir, "worker", "interrupted", nil); err != nil {
		t.Fatalf("bracketless incomplete construction = %v, want success", err)
	}
}

// TestRunToIngestWindowMutationSealsObservationUnverifiable pins the
// run-to-ingest window of REQ-inputs-value-binding: an input edited between
// the producing run and observation construction moves the bracket, so the
// observation seals unverifiable naming the moved root, still constructs,
// converts, merges, and checks as unverifiable evidence, and is never bound.
func TestRunToIngestWindowMutationSealsObservationUnverifiable(t *testing.T) {
	moduleDir := bindingModule(t)
	bracket := testBracket(t, moduleDir, "data")
	log := []byte("open data/fixture.txt\n")
	// The edit between run and ingest: the value the run read is gone before
	// the manifest digest ever reads the file.
	if err := os.WriteFile(filepath.Join(moduleDir, "data", "fixture.txt"), []byte("edited between run and ingest"), 0o644); err != nil {
		t.Fatal(err)
	}
	observation, err := FromTestLogEnv(log, moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatalf("moved-bracket observation did not construct: %v", err)
	}
	state, err := CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Unverifiable || !strings.Contains(state.Reason, "observation bracket moved: data") {
		t.Fatalf("window-mutated observation = %+v, want moved-root unverifiable", state)
	}
	current, err := CurrentEnv(state.Manifest, moduleDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !current.Unverifiable {
		t.Fatal("current check read a moved-bracket manifest as bound")
	}
	merged, err := MergeEnv(moduleDir, nil, observation)
	if err != nil {
		t.Fatal(err)
	}
	if !merged.Unverifiable {
		t.Fatal("merge read a moved-bracket observation as bound")
	}
	converted, err := AbsoluteEnv(observation, moduleDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !converted.Unverifiable {
		t.Fatal("absolute conversion read a moved-bracket observation as bound")
	}
}

// TestSymlinkTargetMutationOutsideRootSealsIdentityUncovered pins the
// symlink-escape disposition of REQ-inputs-value-binding: an identity
// lexically under a declared root whose object resolves outside every root is
// uncovered, never bound — the bracket's fingerprint pins only the symlink's
// target string, so a mutation of the out-of-root target leaves the bracket
// unchanged and resolution-based coverage is the only guard.
func TestSymlinkTargetMutationOutsideRootSealsIdentityUncovered(t *testing.T) {
	moduleDir := filepath.Join(t.TempDir(), "mod")
	for _, dir := range []string{"testdata", "fixtures"} {
		if err := os.MkdirAll(filepath.Join(moduleDir, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(moduleDir, "fixtures", "big.txt")
	if err := os.WriteFile(target, []byte("recorded"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "fixtures", "big.txt"), filepath.Join(moduleDir, "testdata", "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	bracket := testBracket(t, moduleDir, "testdata")
	// The out-of-root target mutates between run and ingest; the symlink's
	// target string — all the root fingerprint observes — is unchanged.
	if err := os.WriteFile(target, []byte("mutated after the run"), 0o644); err != nil {
		t.Fatal(err)
	}
	observation, err := FromTestLogEnv([]byte("open testdata/link\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	state, err := CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Unverifiable {
		t.Fatalf("escaping identity sealed bound: %+v", state)
	}
	reasons := manifestReasons(t, state)
	joined := strings.Join(reasons, "\n")
	if !strings.Contains(joined, "runtime input not covered by observation bracket: testdata/link") {
		t.Fatalf("reasons = %q, want uncovered testdata/link", reasons)
	}
	for _, reason := range reasons {
		if strings.Contains(reason, "observation bracket moved") {
			t.Fatalf("unchanged bracket reported as moved: %q", reason)
		}
	}
}

// TestOutOfRootSymlinkChainSealsIdentityUncovered pins the chain leg of
// REQ-inputs-value-binding: an identity whose walk traverses a symlink
// residing outside every declared root is uncovered, never bound — the
// fingerprint records no target string for an out-of-root link, so a mid-span
// retarget between two in-root objects leaves the bracket unchanged while
// silently rebinding the identity. Both the file-link and the
// directory-component variants seal uncovered, naming the offending link.
func TestOutOfRootSymlinkChainSealsIdentityUncovered(t *testing.T) {
	moduleDir := bindingModule(t)
	if err := os.WriteFile(filepath.Join(moduleDir, "data", "g.txt"), []byte("the other in-root object"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(moduleDir, "other"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(moduleDir, "other", "link")
	if err := os.Symlink(filepath.Join("..", "data", "fixture.txt"), link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := os.Symlink("data", filepath.Join(moduleDir, "otherdir")); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir, "data")
	// Mid-span retarget of the out-of-root link between two in-root objects:
	// the bracket cannot see it, so only the chain check refuses the bind.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "data", "g.txt"), link); err != nil {
		t.Fatal(err)
	}
	observation, err := FromTestLogEnv([]byte("open other/link\nopen otherdir/fixture.txt\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	state, err := CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Unverifiable {
		t.Fatalf("out-of-root chain sealed bound: %+v", state)
	}
	reasons := manifestReasons(t, state)
	joined := strings.Join(reasons, "\n")
	if !strings.Contains(joined, "runtime input not covered by observation bracket: other/link") ||
		!strings.Contains(joined, "symlink outside every bracket root: ") ||
		!strings.Contains(joined, filepath.Join("other", "link")+")") {
		t.Fatalf("reasons = %q, want uncovered other/link naming the out-of-root link", reasons)
	}
	if !strings.Contains(joined, "runtime input not covered by observation bracket: otherdir/fixture.txt") ||
		!strings.Contains(joined, "otherdir)") {
		t.Fatalf("reasons = %q, want uncovered otherdir/fixture.txt naming the out-of-root directory link", reasons)
	}
	for _, reason := range reasons {
		if strings.Contains(reason, "observation bracket moved") {
			t.Fatalf("unchanged bracket reported as moved: %q", reason)
		}
	}
}

// TestInRootSymlinkChainStaysCoveredAndRetargetMovesBracket pins the positive
// side of the chain rule: a within-root link to a within-root target stays
// covered — its target string is in the root fingerprint — and retargeting it
// moves the bracket, which is exactly why the coverage is sound.
func TestInRootSymlinkChainStaysCoveredAndRetargetMovesBracket(t *testing.T) {
	moduleDir := bindingModule(t)
	if err := os.WriteFile(filepath.Join(moduleDir, "data", "alt.txt"), []byte("alternate"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(moduleDir, "data", "link")
	if err := os.Symlink("fixture.txt", link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	bracket := testBracket(t, moduleDir, "data")
	observation, err := FromTestLogEnv([]byte("open data/link\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	if observation.Unverifiable || observation.Reason != "" {
		t.Fatalf("in-root link chain = %+v, want bound", observation.State)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("alt.txt", link); err != nil {
		t.Fatal(err)
	}
	unchanged, reason, err := bracket.revalidate(context.Background(), moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged || reason == "" {
		t.Fatalf("in-root link retarget revalidated as unchanged (reason %q)", reason)
	}
}

// TestCoveredObservationBindsAsBefore pins the bound happy path of
// REQ-inputs-value-binding: with an unchanged bracket over the recorded
// roots, a completed observation seals bound exactly as before — including an
// absent input under a root, whose absence the root fingerprint pins.
func TestCoveredObservationBindsAsBefore(t *testing.T) {
	moduleDir := bindingModule(t)
	bracket := testBracket(t, moduleDir, "data")
	observation, err := FromTestLogEnv([]byte("open data/fixture.txt\nopen data/ghost.txt\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	state, err := CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	if state.Unverifiable || state.Reason != "" || !state.OK {
		t.Fatalf("covered observation = %+v, want bound", state)
	}
}

// TestOutOfRootReadSealsPerIdentityUncovered pins the uncovered-identity
// disposition of REQ-inputs-value-binding: coverage is per declared root,
// never inferred, and the unverifiable reason is per identity — the covered
// sibling in the same observation carries no disposition.
func TestOutOfRootReadSealsPerIdentityUncovered(t *testing.T) {
	moduleDir := bindingModule(t)
	if err := os.WriteFile(filepath.Join(moduleDir, "other.txt"), []byte("out of root"), 0o644); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir, "data")
	observation, err := FromTestLogEnv([]byte("open data/fixture.txt\nopen other.txt\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	state, err := CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Unverifiable {
		t.Fatalf("out-of-root read sealed bound: %+v", state)
	}
	joined := strings.Join(manifestReasons(t, state), "\n")
	if !strings.Contains(joined, "runtime input not covered by observation bracket: other.txt") {
		t.Fatalf("reasons = %q, want uncovered other.txt", joined)
	}
	if strings.Contains(joined, "data/fixture.txt") {
		t.Fatalf("covered identity carries a disposition: %q", joined)
	}
}

// TestExcludedIdentityObservedIsUncovered pins the exclusion leg of
// REQ-inputs-bracket-coverage: an excluded identity a run then observes is
// uncovered, never bound, and so is an identity resolving into the excluded
// subtree — the fingerprint does not observe the object it materializes to.
func TestExcludedIdentityObservedIsUncovered(t *testing.T) {
	moduleDir := bindingModule(t)
	if err := os.MkdirAll(filepath.Join(moduleDir, "data", "vol"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "data", "vol", "scratch.txt"), []byte("volatile"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := "open data/fixture.txt\nopen data/vol/scratch.txt\n"
	spy := filepath.Join(moduleDir, "data", "spy")
	if err := os.Symlink(filepath.Join("vol", "scratch.txt"), spy); err == nil {
		log += "open data/spy\n"
	}
	bracket, err := CaptureBracket(moduleDir, []string{"data"}, WithBracketExcludedPaths("data/vol"))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := FromTestLogEnv([]byte(log), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	state, err := CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Unverifiable {
		t.Fatalf("excluded-identity observation sealed bound: %+v", state)
	}
	joined := strings.Join(manifestReasons(t, state), "\n")
	if !strings.Contains(joined, "runtime input not covered by observation bracket: data/vol/scratch.txt") {
		t.Fatalf("reasons = %q, want uncovered data/vol/scratch.txt", joined)
	}
	if strings.Contains(log, "data/spy") && !strings.Contains(joined, "runtime input not covered by observation bracket: data/spy") {
		t.Fatalf("reasons = %q, want uncovered data/spy resolving into the excluded subtree", joined)
	}
	if strings.Contains(joined, "data/fixture.txt") {
		t.Fatalf("covered identity carries a disposition: %q", joined)
	}
}

// TestBracketCaptureRefusalSealsObservationUnverifiable pins the
// capture-refusal propagation of REQ-inputs-value-binding: a bracket already
// unverifiable at capture seals the observation unverifiable naming the
// capture-refusal reason, while the observation still constructs.
func TestBracketCaptureRefusalSealsObservationUnverifiable(t *testing.T) {
	moduleDir := bindingModule(t)
	externalDir := t.TempDir()
	bracket := testBracket(t, moduleDir, "data", externalDir)
	observation, err := FromTestLogEnv([]byte("open data/fixture.txt\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	state, err := CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Unverifiable || !strings.Contains(state.Reason, "observation bracket unverifiable: external directory input") {
		t.Fatalf("capture-refused bracket observation = %+v, want attributable unverifiable", state)
	}
}

// TestAbsoluteIdentityCoverageRequiresAbsoluteRoot pins the absolute-identity
// rule of REQ-inputs-value-binding: an absolute identity is covered only when
// it resolves under a declared absolute root's resolved path, else uncovered.
func TestAbsoluteIdentityCoverageRequiresAbsoluteRoot(t *testing.T) {
	moduleDir := bindingModule(t)
	external := filepath.Join(t.TempDir(), "ext.txt")
	if err := os.WriteFile(external, []byte("external"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := []byte("open " + external + "\n")
	covered, err := FromTestLogEnv(log, moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir, "data", external)))
	if err != nil {
		t.Fatal(err)
	}
	if covered.Unverifiable {
		t.Fatalf("absolute identity under its declared absolute root = %+v, want bound", covered.State)
	}
	uncovered, err := FromTestLogEnv(log, moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir, "data")))
	if err != nil {
		t.Fatal(err)
	}
	if !uncovered.Unverifiable || !strings.Contains(strings.Join(manifestReasons(t, uncovered.State), "\n"), "runtime input not covered by observation bracket: "+external) {
		t.Fatalf("rootless absolute identity = %+v, want uncovered", uncovered.State)
	}
	// Coverage is lexical-then-resolved from the covering root: an identity
	// lexically under no declared root is uncovered even when its resolution
	// lands under one — its own prefix chain is pinned by nothing.
	alias := filepath.Join(t.TempDir(), "alias.txt")
	if err := os.Symlink(external, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	aliased, err := FromTestLogEnv([]byte("open "+alias+"\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir, "data", external)))
	if err != nil {
		t.Fatal(err)
	}
	if !aliased.Unverifiable {
		t.Fatalf("aliased identity resolving into a root = %+v, want uncovered", aliased.State)
	}
}

// TestAbsoluteRootThroughSymlinkedPrefixStaysCovered pins the walk frame of
// REQ-inputs-value-binding for absolute identities: the walk is read from the
// covering root's own resolved position, so a symlinked prefix above the root
// — a macOS /var or /tmp, a merged-usr Linux — never uncovers the identity.
// The root is follow-hashed through its full chain, so a prefix-link retarget
// already moves the root digest and needs no residence check.
func TestAbsoluteRootThroughSymlinkedPrefixStaysCovered(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "ext.txt"), []byte("external"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(base, "alias")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	aliased := filepath.Join(base, "alias", "ext.txt")
	moduleDir := bindingModule(t)
	bracket := testBracket(t, moduleDir, "data", aliased)
	observation, err := FromTestLogEnv([]byte("open "+aliased+"\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	if observation.Unverifiable || observation.Reason != "" {
		t.Fatalf("absolute identity behind a symlinked prefix = %+v, want bound", observation.State)
	}
}

// TestAbsoluteIdentitySubRootChainStaysEnforced pins the residence rule at or
// below an absolute covering root: an out-of-root link traversed below the
// covering root's position is invisible to every fingerprint, so the identity
// seals uncovered naming the link even when the endpoint resolves under a
// declared absolute root.
func TestAbsoluteIdentitySubRootChainStaysEnforced(t *testing.T) {
	rootDir := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(t.TempDir(), "target.txt")
	if err := os.WriteFile(target, []byte("bound object"), 0o644); err != nil {
		t.Fatal(err)
	}
	// hop1 (under the declared directory root) → hop2 (under no root) → target.
	hop2 := filepath.Join(outside, "hop2")
	if err := os.Symlink(target, hop2); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	hop1 := filepath.Join(rootDir, "hop1")
	if err := os.Symlink(hop2, hop1); err != nil {
		t.Fatal(err)
	}
	moduleDir := bindingModule(t)
	// The directory root makes the bracket capture-unverifiable (external
	// directory), which is irrelevant here: the per-identity chain rule must
	// refuse independently.
	bracket := testBracket(t, moduleDir, rootDir, target)
	observation, err := FromTestLogEnv([]byte("open "+hop1+"\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Unverifiable {
		t.Fatalf("sub-root out-of-root chain sealed bound: %+v", observation.State)
	}
	joined := strings.Join(manifestReasons(t, observation.State), "\n")
	if !strings.Contains(joined, "runtime input not covered by observation bracket: "+hop1) ||
		!strings.Contains(joined, "symlink outside every bracket root: "+hop2) {
		t.Fatalf("reasons = %q, want uncovered %s naming out-of-root link %s", joined, hop1, hop2)
	}
}

// bindingReasonObservations builds one observation per binding-reason class
// under one module view: a moved-bracket observation carrying the
// observation-level reason "observation bracket moved: data", an
// uncovered-identity observation carrying the per-identity reason
// "runtime input not covered by observation bracket: other.txt", and a bound
// sibling carrying no reason.
func bindingReasonObservations(t *testing.T, moduleDir string) (moved, uncovered, bound Observation) {
	t.Helper()
	movedBracket := testBracket(t, moduleDir, "data")
	if err := os.WriteFile(filepath.Join(moduleDir, "data", "fixture.txt"), []byte("edited between run and ingest"), 0o644); err != nil {
		t.Fatal(err)
	}
	moved, err := FromTestLogEnv([]byte("open data/fixture.txt\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker-moved"), WithBracket(movedBracket))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "other.txt"), []byte("out of root"), 0o644); err != nil {
		t.Fatal(err)
	}
	uncovered, err = FromTestLogEnv([]byte("open other.txt\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker-uncovered"), WithBracket(testBracket(t, moduleDir, "data")))
	if err != nil {
		t.Fatal(err)
	}
	bound, err = FromTestLogEnv([]byte("open data/fixture.txt\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker-bound"), WithBracket(testBracket(t, moduleDir, "data")))
	if err != nil {
		t.Fatal(err)
	}
	if !moved.Unverifiable || !strings.Contains(strings.Join(manifestReasons(t, moved.State), "\n"), "observation bracket moved: data") {
		t.Fatalf("precondition: moved observation = %+v, want moved-bracket reason", moved.State)
	}
	if !uncovered.Unverifiable || !strings.Contains(strings.Join(manifestReasons(t, uncovered.State), "\n"), "runtime input not covered by observation bracket: other.txt") {
		t.Fatalf("precondition: uncovered observation = %+v, want uncovered-identity reason", uncovered.State)
	}
	if bound.Unverifiable || bound.Reason != "" {
		t.Fatalf("precondition: bound sibling = %+v, want bound", bound.State)
	}
	return moved, uncovered, bound
}

// TestBindingReasonsSurviveMergeUnion pins the merge leg of
// REQ-inputs-value-binding under the union clause of REQ-inputs-merge: the
// moved-bracket observation-level reason and the uncovered per-identity
// reason each appear verbatim in the merged manifest's unverifiable set, in
// either merge order, alongside a bound sibling — the merged union's
// unverifiable set contains every input's binding reasons, so merge never
// weakens a binding disposition (REQ-inputs-bracket-coverage).
func TestBindingReasonsSurviveMergeUnion(t *testing.T) {
	moduleDir := bindingModule(t)
	moved, uncovered, bound := bindingReasonObservations(t, moduleDir)
	merged, err := MergeEnv(moduleDir, nil, moved, uncovered, bound)
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := MergeEnv(moduleDir, nil, bound, uncovered, moved)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(merged, reversed) {
		t.Fatalf("binding-reason merge is not commutative:\n%+v\n%+v", merged, reversed)
	}
	got := map[string]bool{}
	for _, reason := range manifestReasons(t, merged.State) {
		got[reason] = true
	}
	for _, input := range []Observation{moved, uncovered, bound} {
		for _, reason := range manifestReasons(t, input.State) {
			if !got[reason] {
				t.Errorf("merge dropped binding reason %q", reason)
			}
		}
	}
	if !got["observation bracket moved: data"] || !got["runtime input not covered by observation bracket: other.txt"] {
		t.Fatalf("merged reasons = %v, want both binding classes verbatim", got)
	}
	if !merged.Unverifiable {
		t.Fatal("binding-unverifiable union merged as bound")
	}
}

// TestBindingReasonsSurviveAbsoluteConversion pins the conversion leg of
// REQ-inputs-value-binding under REQ-inputs-absolute-identities: absolute
// conversion carries both binding-reason classes into the converted manifest
// verbatim — path identities convert, recorded reasons never do — and the
// converted evidence stays unverifiable, never weakened.
func TestBindingReasonsSurviveAbsoluteConversion(t *testing.T) {
	moduleDir := bindingModule(t)
	moved, uncovered, _ := bindingReasonObservations(t, moduleDir)
	for name, observation := range map[string]Observation{
		"moved":     moved,
		"uncovered": uncovered,
	} {
		converted, err := AbsoluteEnv(observation, moduleDir, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := map[string]bool{}
		for _, reason := range manifestReasons(t, converted.State) {
			got[reason] = true
		}
		for _, reason := range manifestReasons(t, observation.State) {
			if !got[reason] {
				t.Errorf("%s: absolute conversion dropped binding reason %q", name, reason)
			}
		}
		if !converted.Unverifiable {
			t.Fatalf("%s: absolute conversion weakened the binding disposition", name)
		}
	}
}

// TestDirtyInspectsBindingUnverifiableState pins the dirty leg of
// REQ-inputs-value-binding under REQ-inputs-dirty: a state carrying binding
// reasons — including through a prior merge — still revalidates and yields
// dirty evidence from every module-relative identity's reproducibility alone;
// the binding disposition neither fakes nor suppresses dirt.
func TestDirtyInspectsBindingUnverifiableState(t *testing.T) {
	moduleDir := bindingModule(t)
	moved, uncovered, bound := bindingReasonObservations(t, moduleDir)
	merged, err := MergeEnv(moduleDir, nil, moved, uncovered, bound)
	if err != nil {
		t.Fatal(err)
	}
	reproducible := fakeInspector{reproducible: map[string]bool{"data/fixture.txt": true, "other.txt": true}}
	if dirty, err := DirtyEnv(merged, moduleDir, "commit", reproducible, nil); err != nil || dirty {
		t.Fatalf("reproducible binding-unverifiable state: dirty=%v err=%v, want false, nil", dirty, err)
	}
	partial := fakeInspector{reproducible: map[string]bool{"data/fixture.txt": true}}
	if dirty, err := DirtyEnv(merged, moduleDir, "commit", partial, nil); err != nil || !dirty {
		t.Fatalf("non-reproducible binding-unverifiable state: dirty=%v err=%v, want true, nil", dirty, err)
	}
}

// TestBracketNeverWeakensDisposition pins the never-weakens clause of
// REQ-inputs-bracket-coverage as an example: an observation the manifest
// treats as unverifiable stays unverifiable when bracketed by an unchanged
// covering bracket — the bracket only ever adds unverifiable reasons.
func TestBracketNeverWeakensDisposition(t *testing.T) {
	moduleDir := bindingModule(t)
	bracket := testBracket(t, moduleDir, "data")
	observation, err := FromTestLogEnv([]byte("stat data/fixture.txt\n"), moduleDir, moduleDir, nil, WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Unverifiable || !strings.Contains(strings.Join(manifestReasons(t, observation.State), "\n"), "stat metadata input: data/fixture.txt") {
		t.Fatalf("covered unchanged bracket weakened the stat disposition: %+v", observation.State)
	}
}
