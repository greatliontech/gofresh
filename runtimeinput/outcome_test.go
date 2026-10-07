package runtimeinput

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/outcome"
)

const supportedSubject = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// This package-level fixture supplies an already-proved empty/environment-only
// inventory. Engine integration tests separately exercise the real analysis
// issuer. No filesystem outcome is vouched for by this fixture.
func supportedIngest(t *testing.T, frame ProducerFrame, identity string, env []string) ProducerIngest {
	t.Helper()
	completion, err := frame.Completion(identity, env, "")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := frame.OutcomeBinding(identity, env)
	if err != nil {
		t.Fatal(err)
	}
	return ProducerIngest{Identity: identity, Env: env, Completion: completion, Outcome: outcome.Prepare(binding, []string{supportedSubject}, "")}
}

func TestProducerRequiresIndependentExecutionPremises(t *testing.T) {
	root, dir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	env := producerEnv(dir, "OUTCOME=value")
	good := supportedIngest(t, frame, "worker", env)
	cases := []struct {
		name        string
		change      func(*ProducerIngest)
		log, reason string
	}{
		{"supported", func(*ProducerIngest) {}, "getenv OUTCOME\n", ""},
		{"receipt missing", func(in *ProducerIngest) { in.Completion = CompletionReceipt{} }, "", "completion receipt unavailable"},
		{"support missing", func(in *ProducerIngest) { in.Outcome = OutcomeSupport{} }, "", "outcome support unavailable"},
		{"unsupported inventory", func(in *ProducerIngest) {
			binding, err := frame.OutcomeBinding(in.Identity, in.Env)
			if err != nil {
				t.Fatal(err)
			}
			in.Outcome = outcome.Prepare(binding, []string{supportedSubject}, "file outcomes not supported")
		}, "", "file outcomes not supported"},
		{"wrong process", func(in *ProducerIngest) { in.Identity = "other" }, "", "completion receipt belongs"},
		{"wrong environment", func(in *ProducerIngest) { in.Env = producerEnv(dir, "OUTCOME=changed") }, "", "completion receipt belongs"},
		{"wrong support process", func(in *ProducerIngest) { in.Outcome = supportedIngest(t, frame, "other", env).Outcome }, "", "outcome support belongs"},
		{"wrong support environment", func(in *ProducerIngest) {
			in.Outcome = supportedIngest(t, frame, "worker", producerEnv(dir, "OUTCOME=changed")).Outcome
		}, "", "outcome support belongs"},
		{"abnormal completion", func(in *ProducerIngest) {
			var err error
			in.Completion, err = frame.Completion("worker", env, "process killed")
			if err != nil {
				t.Fatal(err)
			}
		}, "", "process killed"},
		{"file contradicts inventory", func(*ProducerIngest) {}, "open fixture\n", "does not cover"},
		{"exclusion cannot hide contradiction", func(in *ProducerIngest) { in.ExcludedPaths = []string{frame.PkgRel + "/fixture"} }, "open fixture\n", "does not cover"},
		{"unknown operation", func(*ProducerIngest) {}, "unknown ignored\n", "does not cover"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := good
			tc.change(&in)
			obs, reason, err := frame.Observe(context.Background(), writeTestlog(t, tc.log), in)
			if err != nil {
				t.Fatal(err)
			}
			if tc.reason == "" {
				if reason != "" || obs.Unverifiable || !HasOutcomeSupport(obs.Manifest, supportedSubject) {
					t.Fatalf("supported=%+v, reason=%q", obs, reason)
				}
			} else if !strings.Contains(reason, tc.reason) || !obs.Unverifiable || HasOutcomeSupport(obs.Manifest, supportedSubject) {
				t.Fatalf("refusal=%+v reason=%q want %q", obs, reason, tc.reason)
			}
		})
	}
	copyFrame := frame
	if _, reason, err := copyFrame.Observe(context.Background(), writeTestlog(t, ""), good); err != nil || reason != "" {
		t.Fatalf("copied frame=%q %v", reason, err)
	}
	other := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	if _, reason, err := other.Observe(context.Background(), writeTestlog(t, ""), good); err != nil || !strings.Contains(reason, "completion receipt belongs") {
		t.Fatalf("independent frame=%q %v", reason, err)
	}
	for _, path := range []string{"", t.TempDir() + "/missing"} {
		if obs, reason, err := frame.Observe(context.Background(), path, good); err != nil || reason == "" || HasOutcomeSupport(obs.Manifest, supportedSubject) {
			t.Fatalf("missing capture=%+v %q %v", obs, reason, err)
		}
	}
}

func TestOutcomeBindingPreservesEnvironmentBytes(t *testing.T) {
	root, dir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	a := producerEnv(dir, "OUTCOME=\xff")
	b := producerEnv(dir, "OUTCOME=\xfe")
	first := supportedIngest(t, frame, "worker", a)
	second := supportedIngest(t, frame, "worker", b)
	ba, err := frame.OutcomeBinding("worker", a)
	if err != nil {
		t.Fatal(err)
	}
	bb, err := frame.OutcomeBinding("worker", b)
	if err != nil {
		t.Fatal(err)
	}
	if ba == bb {
		t.Error("distinct environment bytes share an execution binding")
	}
	for _, receipt := range []bool{true, false} {
		in := second
		want := "outcome support belongs"
		if receipt {
			in.Completion = first.Completion
			want = "completion receipt belongs"
		} else {
			in.Outcome = first.Outcome
		}
		obs, reason, err := frame.Observe(context.Background(), writeTestlog(t, "getenv OUTCOME\n"), in)
		if err != nil || !strings.Contains(reason, want) || !obs.Unverifiable || HasOutcomeSupport(obs.Manifest, supportedSubject) {
			t.Fatalf("raw environment mismatch: %+v %q %v", obs, reason, err)
		}
	}
}

func TestOutcomePremiseInputsAndExportedSubjects(t *testing.T) {
	root, dir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	env := producerEnv(dir)
	for _, process := range []string{"", "bad\nprocess", "bad\x00process", "\xff"} {
		if _, err := frame.OutcomeBinding(process, env); err == nil {
			t.Fatalf("accepted process %q", process)
		}
		if _, err := frame.Completion(process, env, ""); err == nil {
			t.Fatalf("accepted receipt process %q", process)
		}
	}
	for _, malformed := range [][]string{{"A=one", "A=two"}, {"missing-equals"}, {"=empty-name"}, {"A=bad\x00value"}} {
		if _, err := frame.OutcomeBinding("worker", malformed); err == nil {
			t.Fatalf("accepted environment %q", malformed)
		}
		if _, err := frame.Completion("worker", malformed, ""); err == nil {
			t.Fatalf("accepted receipt environment %q", malformed)
		}
	}
	in := supportedIngest(t, frame, "worker", env)
	invalidIngest := in
	invalidIngest.Env = []string{"missing-equals"}
	if reason := frame.outcomePremise(invalidIngest); !strings.Contains(reason, "binding invalid") {
		t.Fatalf("malformed binding reported as another premise: %q", reason)
	}
	exported := in.Outcome.Subjects()
	exported[0] = strings.Repeat("b", 64)
	obs, reason, err := frame.Observe(context.Background(), writeTestlog(t, ""), in)
	if err != nil || reason != "" || !HasOutcomeSupport(obs.Manifest, supportedSubject) || HasOutcomeSupport(obs.Manifest, exported[0]) {
		t.Fatalf("exported subjects altered opaque support: %+v %q %v", obs, reason, err)
	}
}

func TestProducerKeepsOneEnvironmentSnapshot(t *testing.T) {
	root, dir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	env := producerEnv(dir, "OUTCOME=original")
	original := slices.Clone(env)
	in := supportedIngest(t, frame, "worker", env)
	called := false
	in.Runner.Prepare = func(*exec.Cmd) {
		called = true
		for i, entry := range env {
			if strings.HasPrefix(entry, "OUTCOME=") {
				env[i] = "OUTCOME=changed"
			}
		}
	}
	obs, reason, err := frame.Observe(context.Background(), writeTestlog(t, "getenv OUTCOME\n"), in)
	if err != nil || reason != "" || !called {
		t.Fatalf("observe=%q %v, hook=%t", reason, err, called)
	}
	current, err := Current(context.Background(), obs.Manifest, root, original)
	if err != nil || current != obs.State {
		t.Fatalf("finalization did not retain its bound environment: %+v %v", current, err)
	}
}

type outcomeReadFunc func([]byte) (int, error)

func (f outcomeReadFunc) Read(p []byte) (int, error) { return f(p) }

func TestCaptureCancellationCannotBecomeIncompleteEvidence(t *testing.T) {
	for _, terminal := range []error{nil, io.EOF, io.ErrUnexpectedEOF} {
		ctx, cancel := context.WithCancel(context.Background())
		reader := outcomeReadFunc(func(p []byte) (int, error) {
			n := copy(p, "headerless capture")
			cancel()
			return n, terminal
		})
		data, err := io.ReadAll(captureReader{ctx: ctx, Reader: reader})
		if !errors.Is(err, context.Canceled) || len(data) != 0 {
			t.Fatalf("capture read under cancellation: %q %v", data, err)
		}
	}
	root, dir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	in := supportedIngest(t, frame, "worker", producerEnv(dir))
	path := filepath.Join(t.TempDir(), "headerless")
	if err := os.WriteFile(path, []byte("not a log"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := &cancelAfterChecks{Context: context.Background(), after: 1}
	obs, reason, err := frame.Observe(ctx, path, in)
	if !errors.Is(err, context.Canceled) || obs.OK || reason != "" {
		t.Fatalf("early refusal recorded cancellation: %+v %q %v", obs, reason, err)
	}
	screen := &cancelAfterChecks{Context: context.Background(), after: 8}
	if _, err := environmentLog(screen, []byte(strings.Repeat("getenv VALUE\n", 64))); !errors.Is(err, context.Canceled) {
		t.Fatalf("operation screen ignored cancellation: %v", err)
	}
	// OS errors may contain arbitrary path bytes. Their attribution must not
	// make the incomplete manifest itself unrepresentable.
	obs, reason, err = frame.Observe(context.Background(), filepath.Join(t.TempDir(), "bad\x00path"), in)
	if err != nil || !obs.Unverifiable || !strings.Contains(reason, "capture unreadable") {
		t.Fatalf("unreadable capture lost its disposition: %+v %q %v", obs, reason, err)
	}
}

func FuzzOutcomeBindingRetainsEnvironmentBytes(f *testing.F) {
	f.Add("\xff", "\xfe")
	f.Add("\xff", "\ufffd")
	f.Add("value\nOTHER=entry", "value")
	f.Fuzz(func(t *testing.T, a, b string) {
		// NUL is outside the environment grammar; every other byte, including
		// invalid UTF-8, remains in the generated value domain.
		a, b = strings.ReplaceAll(a, "\x00", "\x01"), strings.ReplaceAll(b, "\x00", "\x01")
		frame := ProducerFrame{span: new(outcome.Span)}
		first, err := frame.OutcomeBinding("worker", []string{"VALUE=" + a, "OTHER=fixed"})
		if err != nil {
			t.Fatal(err)
		}
		second, err := frame.OutcomeBinding("worker", []string{"OTHER=fixed", "VALUE=" + b})
		if err != nil {
			t.Fatal(err)
		}
		if (first == second) != (a == b) {
			t.Fatal("binding changed equality of normalized environment bytes")
		}
		separate, err := frame.OutcomeBinding("worker", []string{"A=" + a, "B=" + b})
		if err != nil {
			t.Fatal(err)
		}
		for _, separator := range []string{"", "\n"} {
			joined, err := frame.OutcomeBinding("worker", []string{"A=" + a + separator + "B=" + b})
			if err != nil {
				t.Fatal(err)
			}
			if separate == joined {
				t.Fatal("binding lost an environment-entry boundary")
			}
		}
	})
}

func TestOutcomeSupportSurvivesWithoutPromotion(t *testing.T) {
	root, dir := producerModule(t)
	frame := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	env := producerEnv(dir, "OUTCOME=value")
	obs, reason, err := frame.Observe(context.Background(), writeTestlog(t, "getenv OUTCOME\n"), supportedIngest(t, frame, "worker", env))
	if err != nil || reason != "" {
		t.Fatalf("observe=%q %v", reason, err)
	}
	current, err := Current(context.Background(), obs.Manifest, root, env)
	if err != nil || current != obs.State {
		t.Fatalf("current=%+v %v; want %+v", current, err, obs.State)
	}
	abs, err := Absolute(obs, root, env)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := Relative(abs, root, env)
	if err != nil || rel.State != obs.State {
		t.Fatalf("conversion=%+v %v", rel, err)
	}
	adopted, err := Adopt(obs.Manifest, root, "adopted", env)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := Merge(root, env)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := Merge(root, env, empty, obs, adopted)
	if err != nil || merged.State != obs.State {
		t.Fatalf("supported union=%+v %v", merged, err)
	}
	plain, err := FromTestLog([]byte("getenv OUTCOME\n"), root, dir, env, WithCompletedProcess("identity-only"), WithBracket(*frame.bracket))
	if err != nil {
		t.Fatal(err)
	}
	incomplete, err := Incomplete(root, "incomplete", "unsupported outcomes", env)
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range []Observation{plain, incomplete} {
		for _, pair := range [][]Observation{{obs, other}, {other, obs}} {
			union, err := Merge(root, env, pair...)
			if err != nil {
				t.Fatal(err)
			}
			if HasOutcomeSupport(union.Manifest, supportedSubject) {
				t.Fatal("merge upgraded unsupported child")
			}
			reentered, err := Adopt(union.Manifest, root, "again", env)
			if err != nil {
				t.Fatal(err)
			}
			if HasOutcomeSupport(reentered.Manifest, supportedSubject) {
				t.Fatal("adoption upgraded unsupported union")
			}
		}
	}
	if HasOutcomeSupport(obs.Manifest, strings.Repeat("b", 64)) {
		t.Fatal("another subject borrowed support")
	}
	old := base64.RawURLEncoding.EncodeToString([]byte(`{"v":1}`))
	if _, err := Adopt(old, root, "old", env); err == nil {
		t.Fatal("adopted old manifest")
	}
	if HasOutcomeSupport(old, supportedSubject) {
		t.Fatal("old manifest gained support")
	}
}

func TestProducerCancellationReachesClosingBracket(t *testing.T) {
	root, dir := producerModule(t)
	for i := 0; i < 128; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("input-%d", i)), []byte("value"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	frame := CaptureProducerFrame(context.Background(), root, dir, FrameOptions{})
	env := producerEnv(dir)
	in := supportedIngest(t, frame, "worker", env)
	in.Roots = &Roots{}
	path := writeTestlog(t, "")
	// Warm the roots independently: the later cancellation budgets reach the
	// finalizer's bracket walk, rather than an incidental go-env subprocess.
	if _, reason, err := frame.Observe(context.Background(), path, in); err != nil || reason != "" {
		t.Fatalf("warm observe: %q %v", reason, err)
	}
	for _, after := range []int{0, 8, 32, 64} {
		ctx := &cancelAfterChecks{Context: context.Background(), after: after}
		obs, reason, err := frame.Observe(ctx, path, in)
		if !errors.Is(err, context.Canceled) || reason != "" || obs.OK || obs.Manifest != "" {
			t.Fatalf("cancel after %d checks: %+v %q %v", after, obs, reason, err)
		}
	}
}

func TestOutcomeManifestRefusesInconsistentSupport(t *testing.T) {
	for _, m := range []manifest{
		{Version: 1},
		{Version: manifestVersion, Outcome: outcome.Method},
		{Version: manifestVersion, Subjects: []string{supportedSubject}},
		{Version: manifestVersion, Outcome: "unknown", Subjects: []string{supportedSubject}},
		{Version: manifestVersion, Outcome: outcome.Method, Subjects: []string{"not a digest"}},
		{Version: manifestVersion, Outcome: outcome.Method, Subjects: []string{supportedSubject}, Paths: []pathInput{{pathID: pathID{Kind: pathRel, Path: "file"}, Digest: testEntryDigest}}},
	} {
		if _, err := encode(m); err == nil {
			t.Fatalf("encoded inconsistent support: %+v", m)
		}
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decode(base64.RawURLEncoding.EncodeToString(data)); err == nil {
			t.Fatalf("decoded inconsistent support: %+v", m)
		}
	}
}

func TestManifestDigestPinsTheWireFold(t *testing.T) {
	plain := manifest{Version: manifestVersion, Env: []envInput{{Name: "A", Digest: testEntryDigest}}, Paths: []pathInput{{pathID: pathID{Kind: pathRel, Path: "file"}, Digest: strings.Repeat("1", 32)}}, Unverifiable: []string{"reason"}}
	if got := manifestDigest(plain); got != "e9b0bf7e90400968193363dbe4723a65" {
		t.Fatalf("identity-only wire digest = %q", got)
	}
	supported := manifest{Version: manifestVersion, Outcome: outcome.Method, Subjects: []string{supportedSubject}, Env: []envInput{{Name: "A", Digest: testEntryDigest}}}
	if got := manifestDigest(supported); got != "64b54fca91577ab18bd60fe5b9b3690c" {
		t.Fatalf("supported wire digest = %q", got)
	}
}

func FuzzOutcomeEvidenceMergePreservesSupport(f *testing.F) {
	f.Add(byte(0), byte(0), byte(0), []byte("supported processes"))
	f.Add(byte(0), byte(1), byte(0), []byte("identity-only child"))
	f.Add(byte(2), byte(0), byte(3), []byte("incomplete child"))
	f.Add(byte(3), byte(3), byte(0), []byte("zero-process identities"))
	f.Fuzz(func(t *testing.T, left, right, third byte, data []byte) {
		makeObservation := func(mode byte, index int) (Observation, string) {
			if mode%4 == 3 {
				obs, err := Merge(".", []string{})
				if err != nil {
					t.Fatal(err)
				}
				return obs, ""
			}
			key := sha256.Sum256(append([]byte{byte(index)}, data...))
			subject := hex.EncodeToString(key[:])
			m := manifest{Version: manifestVersion}
			switch mode % 4 {
			case 0:
				m.Outcome, m.Subjects = outcome.Method, []string{subject}
			case 2:
				m.Unverifiable = []string{"operation-outcome support unavailable"}
			}
			state, err := stateFromManifest(context.Background(), m, ".", []string{})
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decode(state.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			again, err := encode(decoded)
			if err != nil || again != state.Manifest {
				t.Fatalf("noncanonical roundtrip: %v", err)
			}
			return newObservation(state, fmt.Sprintf("process-%d", index), "fixture"), subject
		}
		a, keyA := makeObservation(left, 0)
		b, keyB := makeObservation(right, 1)
		c, keyC := makeObservation(third, 2)
		ab, err := Merge(".", []string{}, a, b)
		if err != nil {
			t.Fatal(err)
		}
		ba, err := Merge(".", []string{}, b, a)
		if err != nil || ba.State != ab.State {
			t.Fatalf("commutativity: %v", err)
		}
		idempotent, err := Merge(".", []string{}, ab, ab)
		if err != nil || idempotent.State != ab.State {
			t.Fatalf("idempotence: %v", err)
		}
		lhs, err := Merge(".", []string{}, ab, c)
		if err != nil {
			t.Fatal(err)
		}
		bc, err := Merge(".", []string{}, b, c)
		if err != nil {
			t.Fatal(err)
		}
		rhs, err := Merge(".", []string{}, a, bc)
		if err != nil || lhs.State != rhs.State {
			t.Fatalf("associativity: %v", err)
		}
		eligible := func(mode byte) bool { return mode%4 == 0 || mode%4 == 3 }
		want := eligible(left) && eligible(right) && eligible(third)
		for _, key := range []string{keyA, keyB, keyC} {
			if HasOutcomeSupport(lhs.Manifest, key) != (want && key != "") {
				t.Fatal("merge promoted or lost outcome support")
			}
		}
	})
}
