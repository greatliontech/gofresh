package runtimeinput

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/quick"

	"github.com/greatliontech/gofresh/internal/outcome"
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
	state, err := currentWithNormalizedEnvContext(t.Context(), encoded, moduleDir, normalized)
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
	union, err := Merge(dir, env, obsA, obsB)
	if err != nil {
		t.Fatal(err)
	}
	persisted := union.State.Manifest

	adopted, err := Adopt(persisted, dir, "persisted-union", env)
	if err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	stateC := adoptTestState(t, manifest{Version: manifestVersion, Env: []envInput{{Name: "ADOPT_B", Digest: testEntryDigest}}}, dir, env)
	obsC := newObservation(stateC, "proc-c", "test")
	widened, err := Merge(dir, env, adopted, obsC)
	if err != nil {
		t.Fatalf("merge with adopted union: %v", err)
	}
	fresh, err := Merge(dir, env, obsA, obsB, obsC)
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
	_, err := Adopt(state.Manifest, dir, "persisted-union", env)
	if err == nil || !strings.Contains(err.Error(), "moved") || !strings.Contains(err.Error(), "fixture.txt") {
		t.Fatalf("Adopt after move = %v, want refusal naming fixture.txt", err)
	}
}

// Adoption accepts only the canonical encoding; padded, reordered, or
// otherwise re-serialized manifests are refused structurally.
func TestAdoptRefusesNonCanonicalEncoding(t *testing.T) {
	dir := t.TempDir()
	env := []string{"ADOPT_A=1"}
	state := adoptTestState(t, manifest{Version: manifestVersion, Env: []envInput{{Name: "ADOPT_A", Digest: testEntryDigest}}}, dir, env)
	if _, err := Adopt(state.Manifest+"A", dir, "persisted-union", env); err == nil {
		t.Fatal("Adopt accepted a tampered encoding")
	}
	if _, err := Adopt("", dir, "persisted-union", env); err == nil {
		t.Fatal("Adopt accepted an empty manifest string")
	}
	// A semantically equal but re-serialized manifest — valid base64, valid
	// JSON, non-canonical byte form — must refuse at the canonical-encoding
	// gate itself, not depend on transport-layer validation.
	raw, err := base64.RawURLEncoding.DecodeString(state.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	reserialized := base64.RawURLEncoding.EncodeToString(append(raw, ' '))
	_, err = Adopt(reserialized, dir, "persisted-union", env)
	if err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("Adopt(re-serialized) = %v, want canonical-encoding refusal", err)
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
	if _, err := Adopt(state.Manifest, dir, "", env); err == nil {
		t.Fatal("Adopt accepted an empty process identity")
	}
	if _, err := Adopt(state.Manifest, dir, "p", []string{"ADOPT_A=1", "ADOPT_A=2"}); err == nil {
		t.Fatal("Adopt accepted a duplicate-key environment")
	}
	adopted, err := Adopt(state.Manifest, dir, "p", env)
	if err != nil {
		t.Fatal(err)
	}
	genuine := newObservation(state, "p", "complete")
	if _, err := Merge(dir, env, adopted, genuine); err == nil || !strings.Contains(err.Error(), "conflicting observations") {
		t.Fatalf("merge of adopted and genuine evidence under one process = %v, want provenance conflict refusal", err)
	}
}

// An adopted union carries recorded incompleteness into merge: the reasons
// survive and keep the merged evidence unverifiable, never silently dropped.
func TestAdoptCarriesUnverifiableReasons(t *testing.T) {
	dir := t.TempDir()
	env := []string{"ADOPT_A=1"}
	state := adoptTestState(t, manifest{Version: manifestVersion, Unverifiable: []string{"incomplete: proc-x"}}, dir, env)
	adopted, err := Adopt(state.Manifest, dir, "persisted-union", env)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := Merge(dir, env, adopted)
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
	empty, err := Merge(dir, env)
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := Adopt(empty.State.Manifest, dir, "persisted-union", env)
	if err != nil {
		t.Fatalf("Adopt(observation-free): %v", err)
	}
	remerged, err := Merge(dir, env, adopted)
	if err != nil {
		t.Fatal(err)
	}
	if remerged.State != empty.State {
		t.Fatalf("re-merged empty state = %+v, want the observation-free state %+v", remerged.State, empty.State)
	}
}

func TestAliasRootListingAvailabilityDoesNotMixStatIdentities(t *testing.T) {
	dir := t.TempDir()
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(".", alias); err != nil {
		t.Fatal(err)
	}
	original := walkRuntimeDirectory
	t.Cleanup(func() { walkRuntimeDirectory = original })
	denied := false
	walkRuntimeDirectory = func(root string, visit fs.WalkDirFunc) error {
		if root != dir || !denied {
			return original(root, visit)
		}
		// filepath.WalkDir visits the root before attempting its listing, then
		// visits it again with the read error. Only that read is unavailable;
		// all actual namespace and followed-object stat observations stay live.
		info, err := os.Lstat(root)
		if err != nil {
			return err
		}
		entry := fs.FileInfoToDirEntry(info)
		if err := visit(root, entry, nil); err != nil {
			return err
		}
		return visit(root, entry, &os.PathError{Op: "readdir", Path: root, Err: fs.ErrPermission})
	}
	for _, before := range []bool{false, true} {
		for _, after := range []bool{false, true} {
			denied = before
			b := testBracket(t, dir, "alias")
			denied = after
			unchanged, moved, reason, err := b.revalidate(t.Context(), dir)
			if err != nil || moved || unchanged != (!before && !after) || (reason != "") != (before || after) {
				t.Fatalf("listing unavailable %t -> %t changed stat meaning: unchanged=%t moved=%t reason=%q err=%v", before, after, unchanged, moved, reason, err)
			}
		}
	}
}

// TestMovedInputsNamesTheMover pins the attribution behind a digest mismatch
// (REQ-inputs-guard): each input carries its own recorded digest, so a moved
// environment value or path names itself — values never disclosed — and an
// unmoved manifest names nothing.
func TestMovedInputsNamesTheMover(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(dir, "data", "fixture.txt")
	if err := os.WriteFile(fixture, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := []string{"MOVED_INPUT_PROBE=alpha", "PATH=/bin"}
	bracket, err := ambientCaptureBracket(dir, []string{"data"})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := FromTestLog([]byte("getenv MOVED_INPUT_PROBE\nopen data/fixture.txt\n"), dir, dir, env,
		WithCompletedProcess("package-test-binary:moved"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}

	if moved, err := ambientMovedInputs(st.Manifest, dir, env); err != nil || len(moved) != 0 {
		t.Fatalf("unmoved manifest attributed %v (%v)", moved, err)
	}

	// The environment value moves: exactly that input is named, value unseen.
	envMoved := []string{"MOVED_INPUT_PROBE=beta", "PATH=/bin"}
	moved, err := ambientMovedInputs(st.Manifest, dir, envMoved)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(moved, []string{"env MOVED_INPUT_PROBE"}) {
		t.Fatalf("moved = %v, want the env input alone", moved)
	}

	// The file moves: exactly that input is named.
	if err := os.WriteFile(fixture, []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	moved, err = ambientMovedInputs(st.Manifest, dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(moved, []string{"path data/fixture.txt"}) {
		t.Fatalf("moved = %v, want the path input alone", moved)
	}

	// The combined digest agrees with the attribution: moved inputs exist
	// exactly when the state digest moved.
	cur, err := ambientCurrentEnv(st.Manifest, dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Digest == st.Digest {
		t.Fatal("combined digest still matches after the input moved")
	}
}

// TestStateManifestRoundTripsUnmoved pins the shared seal: a recorded
// manifest whose inputs are unmoved recomputes to a byte-identical manifest
// and digest — the equality Merge and Absolute rely on.
func TestStateManifestRoundTripsUnmoved(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data", "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := []string{"ROUNDTRIP_PROBE=v", "PATH=/bin"}
	bracket, err := ambientCaptureBracket(dir, []string{"data"})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := FromTestLog([]byte("getenv ROUNDTRIP_PROBE\nopen data/f.txt\n"), dir, dir, env,
		WithCompletedProcess("package-test-binary:roundtrip"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	cur, err := ambientCurrentEnv(st.Manifest, dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if cur != st {
		t.Fatalf("unmoved state did not round-trip:\nrecorded %+v\ncurrent  %+v", st, cur)
	}
}

// TestManifestRejectsMalformedEntryDigests pins the digest-shape half of the
// canonical encoding: an entry digest that is not 32 lowercase hex characters
// refuses encode and decode alike.
func TestManifestRejectsMalformedEntryDigests(t *testing.T) {
	for _, bad := range []string{"", "short", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
		"0000000000000000000000000000000000000000000000000000000000000000"} {
		if _, err := encode(manifest{Version: manifestVersion, Env: []envInput{{Name: "A", Digest: bad}}}); err == nil {
			t.Fatalf("env digest %q encoded", bad)
		}
		if _, err := encode(manifest{Version: manifestVersion, Paths: []pathInput{{pathID: pathID{Kind: pathRel, Path: "x"}, Digest: bad}}}); err == nil {
			t.Fatalf("path digest %q encoded", bad)
		}
	}
	raw := `{"v":4,"env":[{"n":"A","d":"nothex"}]}`
	if _, err := ambientCurrent(base64.RawURLEncoding.EncodeToString([]byte(raw)), t.TempDir()); err == nil {
		t.Fatal("malformed entry digest decoded")
	}
}

// TestManifestRejectsDuplicateIdentities pins the set-per-identity reader rule:
// duplicate identities — including ones distinguished only by digest, which
// byte-level compaction cannot collapse — refuse decode and encode alike.
func TestManifestRejectsDuplicateIdentities(t *testing.T) {
	dupEnv := `{"v":4,"env":[{"n":"A","d":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"n":"A","d":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}`
	if _, err := ambientCurrent(base64.RawURLEncoding.EncodeToString([]byte(dupEnv)), t.TempDir()); err == nil {
		t.Fatal("duplicate env identity decoded")
	}
	dupPath := `{"v":4,"paths":[{"k":"rel","p":"x","d":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"k":"rel","p":"x","d":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}`
	if _, err := ambientCurrent(base64.RawURLEncoding.EncodeToString([]byte(dupPath)), t.TempDir()); err == nil {
		t.Fatal("duplicate path identity decoded")
	}
	if _, err := encode(manifest{Version: manifestVersion, Env: []envInput{
		{Name: "A", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{Name: "A", Digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	}}); err == nil {
		t.Fatal("duplicate env identity encoded")
	}
}

// TestManifestRejectsOlderToolEncodings pins the one-format sentence: the
// schemas older tools produced — env as bare strings, digest-less path
// objects — fail validation rather than reading as anything.
func TestManifestRejectsOlderToolEncodings(t *testing.T) {
	for _, raw := range []string{
		`{"v":1,"env":["A","B"]}`,
		`{"v":1,"paths":[{"k":"rel","p":"tracked"}]}`,
	} {
		if _, err := ambientCurrent(base64.RawURLEncoding.EncodeToString([]byte(raw)), t.TempDir()); err == nil {
			t.Fatalf("older-tool encoding decoded: %s", raw)
		}
	}
}

// Two malformed declarations refuse at ingest naming the first: the
// options apply in order and the earliest fault is the refusal.
func TestIngestRefusesTheFirstMalformedDeclaration(t *testing.T) {
	_, err := FromTestLog(nil, "/tmp/m", "/tmp/m", nil, withToolchainRoot("relative/go"), WithScratchNamespace("/abs/corpus", "tmp-*"))
	if err == nil || !strings.Contains(err.Error(), "clean absolute path") || strings.Contains(err.Error(), "module-relative") {
		t.Fatalf("ingest refused %v; want the first declaration's fault alone", err)
	}
}

// The native conjunction is independent of transcript multiplicity and portable
// encoded environment values. Every draw has a supported control and breaks each
// producing premise separately; identity-only finalization never repairs a
// missing outcome method.
func TestProducerPremisesAcrossGeneratedBindings(t *testing.T) {
	root, dir := producerModule(t)
	ctx := t.Context()
	frame := CaptureProducerFrame(ctx, root, dir, FrameOptions{})
	foreign := CaptureProducerFrame(ctx, root, dir, FrameOptions{})
	roots := &Roots{}
	path := filepath.Join(t.TempDir(), "capture")
	var failure string
	check := func(seed uint64, value []byte, repeated uint8) bool {
		env := producerEnv(dir, "PROPERTY="+base64.RawURLEncoding.EncodeToString(value))
		if repeated&1 == 1 {
			env = slices.DeleteFunc(env, func(s string) bool { return strings.HasPrefix(s, "PROPERTY=") })
		}
		r := rand.New(rand.NewSource(int64(seed)))
		identity := fmt.Sprintf("worker-%x", seed)
		changedEnv := append(slices.DeleteFunc(slices.Clone(env), func(s string) bool { return strings.HasPrefix(s, "PROPERTY=") }), "PROPERTY=changed~"+base64.RawURLEncoding.EncodeToString(value))
		for _, mode := range []string{"supported", "missing-receipt", "abnormal", "missing-support", "receipt-span", "receipt-env", "receipt-process", "support-span", "support-env", "support-process", "missing-env", "missing-pwd", "unsupported-open", "unsupported-stat", "unsupported-chdir", "unsupported-unknown", "identity-only"} {
			in := supportedIngest(t, frame, identity, env)
			in.Roots = roots
			log := strings.Repeat("getenv PROPERTY\n", int(repeated%16))
			wantReason := ""
			switch mode {
			case "missing-receipt":
				in.Completion = CompletionReceipt{}
				wantReason = "process completion receipt unavailable"
			case "abnormal":
				in.Completion, _ = frame.Completion(identity, env, "process did not complete")
				wantReason = "process did not complete"
			case "missing-support":
				in.Outcome = OutcomeSupport{}
				wantReason = "operation-outcome support unavailable"
			case "receipt-span":
				in.Completion, _ = foreign.Completion(identity, env, "")
				wantReason = "process completion receipt belongs to a different execution or environment"
			case "receipt-env":
				in.Completion, _ = frame.Completion(identity, changedEnv, "")
				wantReason = "process completion receipt belongs to a different execution or environment"
			case "receipt-process":
				in.Completion, _ = frame.Completion(identity+"-other", env, "")
				wantReason = "process completion receipt belongs to a different execution or environment"
			case "support-span", "support-env", "support-process":
				supportFrame, supportProcess, supportEnv := frame, identity, env
				switch mode {
				case "support-span":
					supportFrame = foreign
				case "support-env":
					supportEnv = changedEnv
				case "support-process":
					supportProcess += "-other"
				}
				binding, err := supportFrame.OutcomeBinding(supportProcess, supportEnv)
				if err != nil {
					t.Fatal(err)
				}
				in.Outcome = outcome.Prepare(binding, []string{supportedSubject}, "")
				wantReason = "operation-outcome support belongs to a different execution or environment"
			case "missing-env", "missing-pwd":
				withoutPWD := slices.DeleteFunc(slices.Clone(env), func(s string) bool { return strings.HasPrefix(s, "PWD=") })
				if mode == "missing-env" {
					withoutPWD = []string{}
				}
				in = supportedIngest(t, frame, identity, withoutPWD)
				in.Roots = roots
				wantReason = "process environment carries no PWD; cwd-anchored reads cannot classify under the frame"
			case "unsupported-open", "unsupported-stat", "unsupported-chdir", "unsupported-unknown":
				log += strings.TrimPrefix(mode, "unsupported-") + " unobserved-file\n"
				in.ExcludedPaths = []string{"pkg/unobserved-file"}
				wantReason = "operation-outcome support does not cover the captured operations"
			}
			// Capabilities keep their original ordering; the independently
			// permuted ingest describes the same environment.
			in.Env = slices.Clone(in.Env)
			r.Shuffle(len(in.Env), func(i, j int) { in.Env[i], in.Env[j] = in.Env[j], in.Env[i] })
			if err := os.WriteFile(path, []byte("# test log\n"+log), 0600); err != nil {
				t.Fatal(err)
			}
			var obs Observation
			var reason string
			var err error
			if mode == "identity-only" {
				obs, reason, err = frame.ObserveInputs(ctx, path, in)
			} else {
				obs, reason, err = frame.Observe(ctx, path, in)
			}
			fail := func(format string, args ...any) bool {
				failure = fmt.Sprintf("seed=%d mode=%s: ", seed, mode) + fmt.Sprintf(format, args...)
				return false
			}
			if err != nil {
				return fail("observation error: %v", err)
			}
			wantSupport := mode == "supported"
			wantIncomplete := !wantSupport && mode != "identity-only"
			if HasOutcomeSupport(obs.Manifest, supportedSubject) != wantSupport || obs.Unverifiable != wantIncomplete || reason != wantReason {
				return fail("premise disposition: %+v, %q", obs, reason)
			}
			conserved := func(stage string, got Observation) bool {
				if HasOutcomeSupport(got.Manifest, supportedSubject) != wantSupport || got.Unverifiable != wantIncomplete || (wantIncomplete && !strings.Contains(got.Reason, wantReason)) {
					return fail("%s changed support class or cause: %+v", stage, got)
				}
				if _, err := CompletedState(got); err != nil {
					return fail("%s unsealed result: %v", stage, err)
				}
				return true
			}
			if !conserved("original", obs) {
				return false
			}
			// Identity conversions and serialized re-admission preserve the
			// already-established class, not the current method's availability.
			absolute, err := Absolute(obs, root, in.Env)
			if err != nil {
				return fail("absolute: %v", err)
			}
			if !conserved("absolute", absolute) {
				return false
			}
			relative, err := Relative(absolute, root, in.Env)
			if err != nil {
				return fail("conversion changed authority: %+v, %v", relative, err)
			}
			if !conserved("relative", relative) {
				return false
			}
			adopted, err := Adopt(relative.Manifest, root, "reader", in.Env)
			if err != nil {
				return fail("readmission changed authority: %+v, %v", adopted, err)
			}
			if !conserved("adopted", adopted) {
				return false
			}
			if HasOutcomeSupport(adopted.Manifest, strings.Repeat("c", 64)) {
				return fail("another subject borrowed persisted support")
			}
		}
		return true
	}
	if !check(0, nil, 0) || !check(1, nil, 1) {
		t.Fatal(failure)
	}
	if err := quick.Check(check, &quick.Config{MaxCount: 20, Rand: rand.New(rand.NewSource(731))}); err != nil {
		t.Fatalf("%s\n%v", failure, err)
	}
}

// TestDescribeDisclosesIdentitySet pins the explanation surface of
// REQ-inputs-path-identities: a manifest's env names, materialized paths, and
// unverifiable dispositions are enumerable — identities only, never values.
func TestDescribeDisclosesIdentitySet(t *testing.T) {
	dir := t.TempDir()
	obs, err := ambientIncomplete(dir, "package-test-binary:describe", "testlog lacks operation outcome evidence")
	if err != nil {
		t.Fatal(err)
	}
	st, err := CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Describe(st.Manifest, dir)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if len(d.Unverifiable) == 0 {
		t.Fatal("incomplete observation's disposition not disclosed")
	}
	if len(d.EnvNames) != 0 || len(d.Paths) != 0 {
		t.Fatalf("incomplete observation disclosed identities: %+v", d)
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A manifest with concrete identities: build one from a testlog observation
	// under the completed-observation contract (process assertion + bracket).
	if err := os.MkdirAll(filepath.Join(dir, "testdata"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testdata", "fixture.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	bracket, err := ambientCaptureBracket(dir, []string{"testdata"})
	if err != nil {
		t.Fatal(err)
	}
	log := []byte("getenv HOME\nstat testdata/fixture.json\n")
	fromLog, err := ambientFromTestLog(log, dir, dir, WithCompletedProcess("package-test-binary:describe"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	logState, err := CompletedState(fromLog)
	if err != nil {
		t.Fatal(err)
	}
	ld, err := Describe(logState.Manifest, dir)
	if err != nil {
		t.Fatalf("Describe(testlog): %v", err)
	}
	if !reflect.DeepEqual(ld.EnvNames, []string{"HOME"}) {
		t.Fatalf("env names = %v, want [HOME]", ld.EnvNames)
	}
	wantPath := filepath.Join(abs, "testdata", "fixture.json")
	if !reflect.DeepEqual(ld.Paths, []string{wantPath}) {
		t.Fatalf("paths = %v, want [%s]", ld.Paths, wantPath)
	}
	if _, err := Describe("not-a-manifest", dir); err == nil {
		t.Fatal("malformed manifest described")
	}
}

// Absolute identities use the host's volume and separators; slash-rooted
// spellings alone are not absolute identities on Windows.
func scratchMatcherHostRoot(t testing.TB) string {
	t.Helper()
	abs, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	return filepath.VolumeName(abs) + string(filepath.Separator)
}

func TestScratchNamespaceMatchesPath(t *testing.T) {
	root := scratchMatcherHostRoot(t)
	for _, tc := range []struct {
		dir, pattern, identity string
		want                   bool
	}{
		{".", "*", filepath.Join(root, "outside"), false},
		{".", "*", root, false},
		{".", "*", ".", true}, // Native conservative match; never absence evidence.
		{".", "*", "inside/deep", true},
		{".", "bench-*", "bench-9/deep", true},
		{".", "bench-*", "pkg/bench-9", false},
		{"pkg", "bench-*", "pkg", false},
		{"pkg", "bench-*", "pkg/bench-", true},
		{"pkg", "bench-*", "pkg/bench-9/deep/file", true},
		{"pkg", "bench-*", "pkg/other/bench-9", false},
		{"pkg", "bench-*", "pkg2/bench-9", false},
		{"pkg", "scratch", "pkg/scratch", true},
		{"pkg", "scratch", "pkg/scratch123", true},
		{"pkg", "scratch", "pkg/scratc", false},
		{"pkg", "pre*post", "pkg/prepost", true},
		{"pkg", "pre*post", "pkg/pre9post/deep", true},
		{"pkg", "pre*post", "pkg/pre9", false},
		{"pkg", "aba*aba", "pkg/aba", false},
		{"pkg", "aba*aba", "pkg/ababa", false},
		{"pkg", "aba*aba", "pkg/abaaba", true},
		{"pkg", "a*b*c", "pkg/a*b9c", true},
		{"pkg", "a*b*c", "pkg/a9b*c", false},
		{"./other/../pkg//", "pre*post", "pkg/pre9post", true},
	} {
		t.Run(tc.dir+":"+tc.pattern+":"+tc.identity, func(t *testing.T) {
			got, err := (ScratchNamespace{Dir: tc.dir, Pattern: tc.pattern}).MatchesPath(tc.identity)
			if err != nil || got != tc.want {
				t.Fatalf("MatchesPath(%q) = %t, %v; want %t", tc.identity, got, err, tc.want)
			}
		})
	}
}

// Constructed witnesses give the public/native agreement property independent
// positive and negative controls, so a shared always-false matcher cannot pass.
func TestScratchNamespaceMatchesPathAgreement(t *testing.T) {
	root := scratchMatcherHostRoot(t)
	property := func(dirChoice uint8, literalStar, noStar bool, prefixID, suffixID uint32, token uint64) bool {
		dirs := []string{".", "pkg", "pkg/sub", "./pkg//", "other/../pkg"}
		dir := dirs[int(dirChoice)%len(dirs)]
		prefix := fmt.Sprintf("p%x", prefixID)
		if literalStar {
			prefix += "*"
		}
		suffix := ""
		if suffixID%2 != 0 {
			suffix = fmt.Sprintf("s%x", suffixID)
		}
		pattern := prefix + "*" + suffix
		if noStar {
			prefix, suffix = "scratch", ""
			pattern = prefix
		}
		minted := prefix + fmt.Sprint(token) + suffix
		n := ScratchNamespace{Dir: dir, Pattern: pattern}
		var cfg testLogConfig
		WithScratchNamespace(dir, pattern)(&cfg)
		if cfg.err != nil {
			t.Error(cfg.err)
			return false
		}
		positive := path.Join(dir, minted)
		for _, tc := range []struct {
			id   pathID
			want bool
		}{
			{pathID{Kind: pathRel, Path: positive}, true},
			{pathID{Kind: pathRel, Path: positive + "/deep/file"}, true},
			{pathID{Kind: pathRel, Path: path.Join(dir, "!"+minted)}, false},
			{pathID{Kind: pathAbs, Path: filepath.Join(root, filepath.FromSlash(positive))}, false},
		} {
			got, err := n.MatchesPath(tc.id.Path)
			native := cfg.scratchNamespaces[0].matches(tc.id)
			if err != nil || got != native || got != tc.want {
				t.Errorf("%+v MatchesPath(%+v) = %t, %v; native %t, want %t", n, tc.id, got, err, native, tc.want)
				return false
			}
		}
		return true
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatal(err)
	}
}

func TestScratchNamespaceMatchesPathMkdirTemp(t *testing.T) {
	root := t.TempDir()
	patterns := []string{"scratch", "pre*post", "aba*aba", "*"}
	// Windows filenames cannot contain the earlier, literal star. Pure
	// matching of this pattern remains covered on every host above.
	if runtime.GOOS != "windows" {
		patterns = append(patterns, "a*b*c")
	}
	for _, pattern := range patterns {
		minted, err := os.MkdirTemp(root, pattern)
		if err != nil {
			t.Fatal(err)
		}
		n := ScratchNamespace{Dir: "pkg", Pattern: pattern}
		for _, identity := range []string{"pkg/" + filepath.Base(minted), "pkg/" + filepath.Base(minted) + "/deep/file"} {
			if got, err := n.MatchesPath(identity); err != nil || !got {
				t.Fatalf("MkdirTemp(%q) identity %q: match %t, %v", pattern, identity, got, err)
			}
		}
	}
}

func TestScratchNamespaceMatchesPathRejectsMalformed(t *testing.T) {
	root := scratchMatcherHostRoot(t)
	for _, n := range []ScratchNamespace{
		{}, {Dir: "", Pattern: "*"}, {Dir: filepath.Join(root, "abs"), Pattern: "*"},
		{Dir: "../up", Pattern: "*"}, {Dir: "pkg/../../up", Pattern: "*"},
		{Dir: "pkg\x00", Pattern: "*"}, {Dir: "pkg\r", Pattern: "*"},
		{Dir: "pkg\n", Pattern: "*"}, {Dir: "pkg\xff", Pattern: "*"},
		{Dir: ".", Pattern: ""}, {Dir: ".", Pattern: "a/b"}, {Dir: ".", Pattern: `a\b`},
		{Dir: ".", Pattern: "a\x00"}, {Dir: ".", Pattern: "a\r"},
		{Dir: ".", Pattern: "a\n"}, {Dir: ".", Pattern: "a\xff"},
	} {
		var cfg testLogConfig
		WithScratchNamespace(n.Dir, n.Pattern)(&cfg)
		validated := ValidateScratchNamespace(n.Dir, n.Pattern)
		got, err := n.MatchesPath("child")
		if got || err == nil || cfg.err == nil || validated == nil || err.Error() != cfg.err.Error() || err.Error() != validated.Error() {
			t.Fatalf("%+v: match %t, %v; option %v, validator %v", n, got, err, cfg.err, validated)
		}
	}
	sep := string(filepath.Separator)
	// Concatenation deliberately preserves the malformed absolute spelling;
	// filepath.Join would clean the very components this assertion rejects.
	abs := filepath.Join(root, "outside")
	for _, identity := range []string{"", "..", "../outside", "pkg/../../outside", "./pkg", "pkg/.", "pkg/../child", "pkg//child", "pkg/", abs + sep + ".." + sep + "child", abs + sep + sep + "child", abs + sep, "bad\x00", "bad\r", "bad\n", "bad\xff"} {
		got, err := (ScratchNamespace{Dir: ".", Pattern: "*"}).MatchesPath(identity)
		if got || err == nil {
			t.Fatalf("malformed identity %q: match %t, %v", identity, got, err)
		}
	}
}

// The classification-root hook must remain untouched, and matching must work
// identically with existing, absent and symlinked physical names. Only ingest
// may consult those objects to establish admission.
func TestScratchNamespaceMatchesPathDoesNotResolve(t *testing.T) {
	prior := producerTestHooks.beforeRoots
	producerTestHooks.beforeRoots = func() { t.Fatal("pure matching reached classification-root resolution") }
	t.Cleanup(func() { producerTestHooks.beforeRoots = prior })
	root := t.TempDir()
	t.Chdir(root)
	n := ScratchNamespace{Dir: ".", Pattern: "scratch-*"}
	check := func(t *testing.T) {
		t.Helper()
		if got, err := n.MatchesPath("scratch-child/deep"); err != nil || !got {
			t.Fatalf("syntactic match depends on physical state: %t, %v", got, err)
		}
		if got, err := n.MatchesPath(filepath.Join(root, "scratch-child", "deep")); err != nil || got {
			t.Fatalf("absolute path acquired a relative identity: %t, %v", got, err)
		}
	}
	check(t)
	if err := os.Mkdir("scratch-child", 0o700); err != nil {
		t.Fatal(err)
	}
	check(t)
	if err := os.Remove("scratch-child"); err != nil {
		t.Fatal(err)
	}
	t.Run("symlink", func(t *testing.T) {
		if err := os.Symlink(filepath.Join(root, "absent"), "scratch-child"); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		check(t)
	})
}

// Arbitrary declarations and identity bytes exercise the same rejection
// grammar as ingest and the manifest; valid inputs agree with native matching.
func FuzzScratchNamespaceMatchesPath(f *testing.F) {
	root := scratchMatcherHostRoot(f)
	for _, seed := range [][3]string{
		{".", "*", filepath.Join(root, "outside")}, {".", "*", "."}, {"pkg", "a*b*c", "pkg/a*b9c/deep"},
		{"pkg", "aba*aba", "pkg/ababa"}, {"./pkg//", "scratch", "pkg/scratch9"},
		{"..", "*", "child"}, {".", "*", "../outside"}, {".", "*", "bad\xff"},
	} {
		f.Add(seed[0], seed[1], seed[2])
	}
	f.Fuzz(func(t *testing.T, dir, pattern, identity string) {
		n := ScratchNamespace{Dir: dir, Pattern: pattern}
		got, err := n.MatchesPath(identity)
		var cfg testLogConfig
		WithScratchNamespace(dir, pattern)(&cfg)
		wantErr := cfg.err
		id := pathID{Kind: pathRel, Path: identity}
		if filepath.IsAbs(identity) {
			id.Kind = pathAbs
		}
		if wantErr == nil {
			wantErr = validateManifest(manifest{Version: manifestVersion, Paths: []pathInput{{pathID: id, Digest: "00000000000000000000000000000000"}}})
		}
		if wantErr != nil {
			if got || err == nil || err.Error() != wantErr.Error() {
				t.Fatalf("match %t, %v; want false, %v", got, err, wantErr)
			}
			return
		}
		want := cfg.scratchNamespaces[0].matches(id)
		if err != nil || got != want {
			t.Fatalf("match %t, %v; native %t", got, err, want)
		}
	})
}

// A read inside a declared scratch namespace, absent at bracket capture
// and absent again at ingest, records neither an identity nor a
// disposition, while a sibling read of real state records normally
// (REQ-inputs-scratch-namespace).
func TestScratchNamespaceAdmitsEndpointAbsentReads(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(packageDir, "input.txt"), []byte("real"), 0o644); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir)
	log := []byte("open input.txt\nopen bench-a1b2c3/data.txt\nstat bench-a1b2c3\n")
	st, err := ambientFromTestLog(log, moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Unverifiable {
		t.Fatalf("state unverifiable: %s", st.Reason)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/input.txt" {
		t.Fatalf("paths = %+v, want only the real input", m.Paths)
	}
}

// An absence-probe outside the declared namespace keeps its per-identity
// missing-arm record: the appearance-pin is forfeited only inside the
// declared namespace, never package-wide
// (REQ-inputs-scratch-namespace, REQ-inputs-guard).
func TestScratchNamespacePreservesAbsenceProbesOutsideIt(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	bracket := testBracket(t, moduleDir)
	st, err := ambientFromTestLog([]byte("open tuning.yaml\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/tuning.yaml" {
		t.Fatalf("paths = %+v, want the absence-probe recorded", m.Paths)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "tuning.yaml"), []byte("tuned"), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := ambientCurrent(st.Manifest, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if current.Digest == st.Digest {
		t.Fatal("appearance of the probed path did not move the digest")
	}
}

// A pre-existing object the pattern happens to match stays observed: the
// capture membership vetoes the admission, so declared scratch can never
// swallow real pre-run state (REQ-inputs-scratch-namespace).
func TestScratchNamespacePreExistingMatchStaysObserved(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	old := filepath.Join(packageDir, "bench-old")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir)
	st, err := ambientFromTestLog([]byte("open bench-old/keep.txt\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/bench-old/keep.txt" {
		t.Fatalf("paths = %+v, want the pre-existing read recorded", m.Paths)
	}
}

// Scratch that outlives the run stays observed — state present at ingest
// is never per-run scratch — and its persistence has already moved the
// bracket, sealing the observation toward recomputation
// (REQ-inputs-scratch-namespace).
func TestScratchNamespaceSurvivingScratchStaysObserved(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	bracket := testBracket(t, moduleDir)
	leaked := filepath.Join(packageDir, "bench-leak")
	if err := os.MkdirAll(leaked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(leaked, "out.txt"), []byte("leaked"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := ambientFromTestLog([]byte("open bench-leak/out.txt\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/bench-leak/out.txt" {
		t.Fatalf("paths = %+v, want the surviving scratch recorded", m.Paths)
	}
	if !st.Unverifiable || !strings.Contains(st.Reason, "observation bracket moved") {
		t.Fatalf("state = %+v, want the persisted scratch to move the bracket", st)
	}
}

// The masquerade direction: pre-existing state the run consumed and
// removed is vetoed by membership AND moves the bracket at revalidation,
// so it can never pass as scratch and the observation seals toward
// recomputation (REQ-inputs-scratch-namespace).
func TestScratchNamespaceConsumedAndRemovedSealsBracket(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	victim := filepath.Join(packageDir, "bench-victim")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victim, "data.txt"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir)
	if err := os.RemoveAll(victim); err != nil {
		t.Fatal(err)
	}
	st, err := ambientFromTestLog([]byte("open bench-victim/data.txt\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/bench-victim/data.txt" {
		t.Fatalf("paths = %+v, want the consumed input recorded", m.Paths)
	}
	if !st.Unverifiable || !strings.Contains(st.Reason, "observation bracket moved") {
		t.Fatalf("state = %+v, want the consumption to move the bracket", st)
	}
}

// A namespace whose directory no declared bracket root covers is inert:
// without capture membership nothing can be proven absent-before, so its
// reads keep ordinary classification (REQ-inputs-scratch-namespace).
func TestScratchNamespaceInertWithoutBracketCoverage(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	other := filepath.Join(moduleDir, "other")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir, "pkg")
	st, err := ambientFromTestLog([]byte("open "+filepath.Join(moduleDir, "other", "bench-x", "gone.txt")+"\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("other", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "other/bench-x/gone.txt" {
		t.Fatalf("paths = %+v, want the uncovered read recorded", m.Paths)
	}
}

// A pre-existing namespace-matching symlink into a bracket-EXCLUDED
// subtree must not let consumed-and-removed state bind recordless: the
// exclusion removes the target from the fingerprint, so only the
// matching-child freshness veto stands between the alias and a false
// valid (REQ-inputs-scratch-namespace's matching-child anchor).
func TestScratchNamespaceExcludedSubtreeAliasStaysSealed(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	excl := filepath.Join(packageDir, "excl")
	if err := os.MkdirAll(excl, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(excl, "data.txt"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("excl", filepath.Join(packageDir, "bench-link")); err != nil {
		t.Fatal(err)
	}
	bracket, err := ambientCaptureBracket(moduleDir, []string{"."}, WithBracketExcludedPaths("pkg/excl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(excl, "data.txt")); err != nil {
		t.Fatal(err)
	}
	st, err := ambientFromTestLog([]byte("open bench-link/data.txt\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/bench-link/data.txt" {
		t.Fatalf("paths = %+v, want the aliased consumed input recorded", m.Paths)
	}
	if !st.Unverifiable {
		t.Fatalf("state = %+v, want the excluded-target alias sealed unverifiable", st)
	}
}

// The matching-child anchor vetoes reads BENEATH a pre-existing
// matching object, not merely the object's own identity: an absent
// deeper path under a pre-existing pattern-matching directory stays
// observed (REQ-inputs-scratch-namespace).
func TestScratchNamespacePreExistingMatchVetoesDepth(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.MkdirAll(filepath.Join(packageDir, "bench-old"), 0o755); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir)
	st, err := ambientFromTestLog([]byte("open bench-old/gone.txt\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/bench-old/gone.txt" {
		t.Fatalf("paths = %+v, want the absence-probe under pre-existing state recorded", m.Paths)
	}
}

// A namespace whose directory sits under a bracket exclusion admits
// nothing: the excluded subtree is outside the fingerprint, so pre-run
// absence is unknowable (REQ-inputs-scratch-namespace).
func TestScratchNamespaceUnderBracketExclusionAdmitsNothing(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	sub := filepath.Join(packageDir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	bracket, err := ambientCaptureBracket(moduleDir, []string{"."}, WithBracketExcludedPaths("pkg/sub"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := ambientFromTestLog([]byte("open sub/bench-x/gone.txt\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg/sub", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/sub/bench-x/gone.txt" {
		t.Fatalf("paths = %+v, want the exclusion-shadowed read recorded", m.Paths)
	}
}

// A run-created dangling link ancestor refuses the admission: an
// existing-but-unresolvable component is detectable evidence the
// runtime read escaped (REQ-inputs-scratch-namespace fail-closed
// resolution, dangling arm).
func TestScratchNamespaceDanglingLinkAncestorStaysObserved(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	bracket := testBracket(t, moduleDir)
	if err := os.Symlink("nowhere-at-all", filepath.Join(packageDir, "bench-dang")); err != nil {
		t.Fatal(err)
	}
	st, err := ambientFromTestLog([]byte("open bench-dang/x.txt\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/bench-dang/x.txt" {
		t.Fatalf("paths = %+v, want the dangling-ancestor read recorded", m.Paths)
	}
}

// The seal covers the retained capture listing: a forged member set
// fails the seal exactly as forged comparable facts would, and member framing
// distinguishes sets that plain newline framing would collide
// (REQ-inputs-value-binding's capture-produced-only rule).
func TestBracketSealCoversCaptureListing(t *testing.T) {
	moduleDir, _ := testDirs(t)
	bracket := testBracket(t, moduleDir)
	if err := bracket.checkSealed(); err != nil {
		t.Fatal(err)
	}
	forged := bracket
	forged.roots = append([]bracketRoot(nil), bracket.roots...)
	forged.roots[0].members = map[string]bool{"forged": true}
	if err := forged.checkSealed(); err == nil {
		t.Fatal("forged capture listing passed the seal")
	}

	a := bracket
	a.roots = []bracketRoot{{id: bracket.roots[0].id, members: map[string]bool{"a\nmember b": true}}}
	b := bracket
	b.roots = []bracketRoot{{id: bracket.roots[0].id, members: map[string]bool{"a": true, "b": true}}}
	if sealBracket(a) == sealBracket(b) {
		t.Fatal("member framing collides distinct capture listings")
	}
}

// A recorded module-relative DIRECTORY entry's digest shares the
// directory carve-out: membership-restored churn inside it leaves the
// digest, a mode change moves it (runtime-input manifest encoding
// term).
func TestRecordedDirectoryDigestSharesCarveOut(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	data := filepath.Join(packageDir, "data")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir)
	st, err := ambientFromTestLog([]byte("open data\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}

	scratch := filepath.Join(data, "churn.txt")
	if err := os.WriteFile(scratch, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(scratch); err != nil {
		t.Fatal(err)
	}
	current, err := ambientCurrent(st.Manifest, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if current.Digest != st.Digest {
		t.Fatal("membership-restored churn moved a recorded directory digest")
	}

	if err := os.Chmod(data, 0o700); err != nil {
		t.Fatal(err)
	}
	current, err = ambientCurrent(st.Manifest, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if current.Digest == st.Digest {
		t.Fatal("directory mode change did not move the recorded digest")
	}
}

// A read whose traversal crosses an existing link escaping the bracket
// root stays observed even when the target is absent and the lexical
// path matches the namespace: the nearest existing ancestor must
// resolve under the covering root's resolved position
// (REQ-inputs-scratch-namespace fail-closed resolution).
func TestScratchNamespaceEscapingLinkStaysObserved(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(packageDir, "bench-link")); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir)
	st, err := ambientFromTestLog([]byte("open bench-link/gone.txt\n"), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(bracket),
		WithScratchNamespace("pkg", "bench-*"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(st.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Paths) != 1 || m.Paths[0].Path != "pkg/bench-link/gone.txt" {
		t.Fatalf("paths = %+v, want the escaping-link read recorded", m.Paths)
	}
}

// Membership-restored churn — entries created and deleted within the
// span, moving only ancestor directories' own size and mtime — keeps the
// bracket: a directory object contributes membership and mode, never the
// metadata that only counts churn. A directory mode change still moves
// it (REQ-inputs-value-binding).
func TestBracketToleratesRestoredChurnButNotModeChange(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.WriteFile(filepath.Join(packageDir, "input.txt"), []byte("real"), 0o644); err != nil {
		t.Fatal(err)
	}
	bracket := testBracket(t, moduleDir)

	scratch := filepath.Join(packageDir, "bench-churn")
	if err := os.MkdirAll(scratch, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scratch, "tmp.txt"), []byte("scratch"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(scratch); err != nil {
		t.Fatal(err)
	}
	unchanged, _, reason, err := bracket.revalidate(context.Background(), moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if !unchanged {
		t.Fatalf("membership-restored churn moved the bracket: %s", reason)
	}

	if err := os.Chmod(packageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	unchanged, _, _, err = bracket.revalidate(context.Background(), moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged {
		t.Fatal("directory mode change did not move the bracket")
	}
}

// Namespace matching follows os.MkdirTemp semantics: the random string
// replaces the last "*" or is appended, matching is per direct child of
// the declared dir, and depth beneath a matching child is inside the
// namespace (REQ-inputs-scratch-namespace).
func TestScratchNamespaceMatching(t *testing.T) {
	cases := []struct {
		dir, pattern, path string
		want               bool
	}{
		{"pkg", "bench-*", "pkg/bench-123", true},
		{"pkg", "bench-*", "pkg/bench-123/deep/file.txt", true},
		{"pkg", "bench-*", "pkg/bench-", true},
		{"pkg", "bench-*", "pkg/other-123", false},
		{"pkg", "bench-*", "pkg", false},
		{"pkg", "bench-*", "other/bench-123", false},
		{"pkg", "scratch", "pkg/scratch12345", true},
		{"pkg", "scratch", "pkg/scratc", false},
		{"pkg", "pre*post", "pkg/preXpost", true},
		{"pkg", "pre*post", "pkg/prepost", true},
		{"pkg", "pre*post", "pkg/preX", false},
		{".", "bench-*", "bench-9", true},
		{".", "bench-*", "pkg/bench-9", false},
	}
	for _, tc := range cases {
		var cfg testLogConfig
		WithScratchNamespace(tc.dir, tc.pattern)(&cfg)
		if cfg.err != nil {
			t.Fatalf("%s %s: %v", tc.dir, tc.pattern, cfg.err)
		}
		got := cfg.scratchNamespaces[0].matches(pathID{Kind: pathRel, Path: tc.path})
		if got != tc.want {
			t.Errorf("dir=%s pattern=%s path=%s: matches=%v, want %v", tc.dir, tc.pattern, tc.path, got, tc.want)
		}
	}
}

// Malformed namespace declarations are refused loudly rather than read
// as anything (REQ-inputs-scratch-namespace).
func TestScratchNamespaceRejectsMalformedDeclarations(t *testing.T) {
	cases := []struct{ dir, pattern string }{
		{"", "bench-*"},
		{"/abs", "bench-*"},
		{"../up", "bench-*"},
		{"pkg", ""},
		{"pkg", "a/b"},
		{"pkg", "a\nb"},
	}
	for _, tc := range cases {
		var cfg testLogConfig
		WithScratchNamespace(tc.dir, tc.pattern)(&cfg)
		if cfg.err == nil {
			t.Errorf("dir=%q pattern=%q accepted", tc.dir, tc.pattern)
		}
	}
}

// The exported grammar check and the ingest option agree arm for arm: a
// declaration the validator accepts assembles, one it refuses fails the
// ingest with the same error — a producer preflighting at its boundary
// refuses exactly what ingest would degrade on.
func TestValidateScratchNamespaceMatchesOptionValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		dir, pattern string
		wantErr      string
	}{
		"valid":              {dir: "pkg", pattern: "scratch-*"},
		"multi-component":    {dir: "x", pattern: "a/b", wantErr: "single path component"},
		"empty pattern":      {dir: "x", pattern: "", wantErr: "single path component"},
		"absolute dir":       {dir: "/abs", pattern: "p", wantErr: "module-relative"},
		"empty dir":          {dir: "", pattern: "p", wantErr: "module-relative"},
		"escaping dir":       {dir: "../out", pattern: "p", wantErr: "escapes module"},
		"newline in pattern": {dir: "x", pattern: "a\nb", wantErr: "single path component"},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateScratchNamespace(tc.dir, tc.pattern)
			var cfg testLogConfig
			WithScratchNamespace(tc.dir, tc.pattern)(&cfg)
			if tc.wantErr == "" {
				if err != nil || cfg.err != nil {
					t.Fatalf("valid declaration refused: validator %v, option %v", err, cfg.err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validator error = %v, want %q", err, tc.wantErr)
			}
			if cfg.err == nil || cfg.err.Error() != err.Error() {
				t.Fatalf("option and validator disagree: option %v, validator %v", cfg.err, err)
			}
		})
	}
}
