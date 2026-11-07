package gofresh

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/guard"
	"github.com/greatliontech/gofresh/internal/outcome"
	"github.com/greatliontech/gofresh/internal/testvariant"
	"github.com/greatliontech/gofresh/internal/runtimeinput"
	"github.com/greatliontech/stipulator/stipulate/structural"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Every nonempty subset keeps exactly its subjects' cut provenance, including
// nested projections and repeated selection. Comparison still distinguishes a
// genuine hash change from discharge availability (REQ-fresh-unit-close).
func FuzzSiblingCutProjection(f *testing.F) {
	f.Add([]byte{1, 0, 3, 2, 7, 4})
	f.Add([]byte{0})
	f.Add([]byte{1, 1, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		if len(data) > 32 {
			data = data[:32]
		}
		parent := &Snapshot{facts: &observationFacts{
			maximal: map[Subject]subjectFacts{},
			cut:     map[Subject]bool{},
		}}
		var selected []Subject
		for i, b := range data {
			s := Subject{Package: "example.com/property", Symbol: fmt.Sprintf("F%d", i)}
			parent.subjects = append(parent.subjects, s)
			parent.facts.maximal[s] = testSubjectFacts(closure.Closure{Hash: fmt.Sprintf("hash%d", i), Unverifiable: true, Refusal: closure.SharedDynamicStateRefusal, Reason: "refusal"})
			if b&1 != 0 {
				parent.facts.cut[s] = true
			}
			if i == 0 || b&2 != 0 {
				selected = append(selected, s)
			}
		}
		child, err := parent.Sibling(selected)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range parent.subjects {
			included := false
			for _, chosen := range selected {
				included = included || chosen == s
			}
			if got, want := child.facts.cut[s], included && parent.facts.cut[s]; got != want {
				t.Fatalf("cut provenance for %v: got %t want %t", s, got, want)
			}
		}
		nested, err := child.Sibling([]Subject{selected[0], selected[0]})
		if err != nil {
			t.Fatal(err)
		}
		s := selected[0]
		current := *nested.facts
		cl := current.maximal[s]
		cl.sharedState = nil
		current.maximal = map[Subject]subjectFacts{s: cl}
		current.cut = nil
		err = nested.compareObservationContext(context.Background(), current)
		if parent.facts.cut[s] {
			if !errors.Is(err, ErrAnalysisUnavailable) || errors.Is(err, ErrViewChanged) {
				t.Fatalf("cut-only difference: %v", err)
			}
		} else if err == nil {
			// The synthetic uncut row retains its reason; changing it without
			// a cut is a real difference, not a licensed neutralization.
			t.Fatal("uncut difference was neutralized")
		}
		cl.source.Identity.Hash = "moved"
		current.maximal[s] = cl
		if err := nested.compareObservationContext(context.Background(), current); !errors.Is(err, ErrViewChanged) {
			t.Fatalf("hash movement: %v", err)
		}
	})
}

// TestExternalDirectiveImmuneToObservationEvidence pins the observation half of
// REQ-external-precedence at the verdict function: completed observation
// evidence upgrades inferred closure unverifiability, never a declared
// external subject.
func TestExternalDirectiveImmuneToObservationEvidence(t *testing.T) {
	rec := Fingerprint{
		MaximalClosure:   "h",
		ToolchainContent: "stdlib",
		Guards:           guard.Guards{Toolchain: "tc", BuildConfig: "bc"},
		RuntimeInputs:    "manifest",
		RuntimeDigest:    "d",
	}
	rt := runtimeinput.State{Manifest: "manifest", Digest: "d", OK: true}
	inferred := closure.Closure{Hash: "h", ToolchainContent: "stdlib", Unverifiable: true, Reason: "reaches os.Open"}
	observed := ObservationAuthority{Assertion: "caller assertion", ProofStrategy: ObservationRTA, OutcomeMethod: "gofresh/immutable-environment@1"}
	if v := decideAfterClosureObserved(rec, inferred, rec.Guards, rt, CodeResult, PurityAuthority{}, observed); v.Status != Valid {
		t.Fatalf("observed inferred unverifiability = {%s %q}, want valid (the upgrade this test contrasts)", v.Status, v.Reason)
	}
	declared := closure.Closure{Hash: "h", ToolchainContent: "stdlib", Unverifiable: true, External: true, Reason: "external directive"}
	if v := decideAfterClosureObserved(rec, declared, rec.Guards, rt, CodeResult, PurityAuthority{}, observed); v.Status != Unverifiable || v.Reason != "external directive" {
		t.Fatalf("observed external subject = {%s %q}, want {unverifiable external directive}", v.Status, v.Reason)
	}
	if v := decideAfterClosureObserved(rec, declared, rec.Guards, rt, CodeResult, testPurityAuthority(true), observed); v.Status != Unverifiable || v.Reason != "external directive" {
		t.Fatalf("pure external subject = {%s %q}, want {unverifiable external directive}", v.Status, v.Reason)
	}
}

func TestBatchMarksRuntimeInputDriftStale(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("before"), 0o644); err != nil {
		t.Fatal(err)
	}
	state, err := riFromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	recorded := map[Subject]Fingerprint{subject: {
		RuntimeInputs: state.Manifest,
		RuntimeDigest: state.Digest,
	}}
	view := &Snapshot{moduleDir: dir}
	before, err := view.observeRuntimeInputs(context.Background(), recorded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture, []byte("after"), 0o644); err != nil {
		t.Fatal(err)
	}
	verdicts, err := view.finishRuntimeObservation(context.Background(), recorded, before, map[Subject]Verdict{subject: {Status: Valid}})
	if err != nil {
		t.Fatal(err)
	}
	if got := verdicts[subject]; got.Status != Stale || got.Reason != "runtimeinputs" {
		t.Fatalf("runtime-input drift verdict = %+v, want stale runtimeinputs", got)
	}
}

func TestRuntimeInputDriftIsSubjectLocal(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\nfunc G() {}\n")
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("before"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stateA, err := riFromTestLog([]byte("open a\n"), dir, dir, runtimeinput.WithCompletedProcess("worker-a"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	stateB, err := riFromTestLog([]byte("open b\n"), dir, dir, runtimeinput.WithCompletedProcess("worker-b"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	f := Subject{Package: "example.com/view", Symbol: "F"}
	g := Subject{Package: "example.com/view", Symbol: "G"}
	recorded := map[Subject]Fingerprint{
		f: {RuntimeInputs: stateA.Manifest, RuntimeDigest: stateA.Digest},
		g: {RuntimeInputs: stateB.Manifest, RuntimeDigest: stateB.Digest},
	}
	view := &Snapshot{moduleDir: dir}
	before, err := view.observeRuntimeInputs(context.Background(), recorded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("after"), 0o644); err != nil {
		t.Fatal(err)
	}
	verdicts, err := view.finishRuntimeObservation(context.Background(), recorded, before, map[Subject]Verdict{
		f: {Status: Valid},
		g: {Status: Valid},
	})
	if err != nil {
		t.Fatal(err)
	}
	if verdicts[f].Status != Stale || verdicts[g].Status != Valid {
		t.Fatalf("subject-local runtime drift = F:%+v G:%+v, want stale/valid", verdicts[f], verdicts[g])
	}
}

func TestRuntimeInputDriftDoesNotOverrideStale(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("before"), 0o644); err != nil {
		t.Fatal(err)
	}
	state, err := riFromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	recorded := map[Subject]Fingerprint{subject: {
		RuntimeInputs: state.Manifest,
		RuntimeDigest: "already-stale",
	}}
	view := &Snapshot{moduleDir: dir}
	before, err := view.observeRuntimeInputs(context.Background(), recorded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture, []byte("after"), 0o644); err != nil {
		t.Fatal(err)
	}
	verdicts, err := view.finishRuntimeObservation(context.Background(), recorded, before, map[Subject]Verdict{subject: {Status: Stale, Reason: "closure"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := verdicts[subject]; got.Status != Stale || got.Reason != "closure" {
		t.Fatalf("runtime drift overwrote stale verdict: %+v", got)
	}
}

func TestValidationComparesObservationProofsByAvailabilityClass(t *testing.T) {
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	analyzed := closure.Observability{Observable: true}
	rejected := closure.Observability{Reason: "startup effect: external dependence"}
	unavailableA := closure.Observability{Reason: "observation analysis unavailable: analysis budget exhausted"}
	unavailableB := closure.Observability{Reason: "observation analysis unavailable: load failed"}
	if err := compareObservationProof(subject, unavailableA, analyzed); !errors.Is(err, ErrAnalysisUnavailable) {
		t.Fatalf("unavailable re-establishment of an analyzed proof = %v, want ErrAnalysisUnavailable", err)
	}
	if err := compareObservationProof(subject, unavailableA, unavailableB); err != nil {
		t.Fatalf("two unavailable dispositions with different error text = %v, want consistent", err)
	}
	if err := compareObservationProof(subject, analyzed, unavailableA); err != nil {
		t.Fatalf("unavailable captured proof against current analyzed = %v, want consistent (the recording confers nothing)", err)
	}
	if err := compareObservationProof(subject, rejected, analyzed); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("analyzed dispositions differing = %v, want ErrViewChanged", err)
	}
	if err := compareObservationProof(subject, analyzed, analyzed); err != nil {
		t.Fatalf("identical analyzed dispositions = %v, want consistent", err)
	}
}

// sortedUniqueUnion's sorted, deduplicated output is the union recipe's
// own contract — the canonical form is what lets a derived union compare
// equal to a freshly observed one REGARDLESS of feeder order. Every
// production feeder today happens to arrive pre-sorted (the closure
// layer sorts per-package lists, and per-subject clones are sorted at
// store time), so this pin — not any integration path — is what holds
// the recipe to canonicalizing rather than trusting its callers.
func TestSortedUniqueUnionCanonicalizes(t *testing.T) {
	got := sortedUniqueUnion([][]string{{"b/b.go", "a/a.go"}, {"a/a.go", "c/c.go"}})
	want := []string{"a/a.go", "b/b.go", "c/c.go"}
	if !slices.Equal(got, want) {
		t.Fatalf("sortedUniqueUnion = %v, want %v", got, want)
	}
}

// The unaudited-toolchain notice fires exactly once per engine and
// serves the audit's OWNED axis-naming rendering with the source
// pointer appended; an audited selection (empty notice) emits nothing
// — without the notice, an unlisted toolchain surfaces only as a
// scatter of ordinary fail-closed refusals, the discovery shape the
// content keying was built to prevent.
func TestUnauditedToolchainNoticeFiresOnceAndNames(t *testing.T) {
	var got []string
	var once sync.Once
	emitUnauditedToolchainNotice(&once, "", func(d string) { got = append(got, d) })
	if len(got) != 0 {
		t.Fatalf("audited selection emitted a notice: %v", got)
	}
	owned := "toolchain-selection audit: the audited surface of go1.99.0 moved in 1 keys off go1.99.0: strings — standard-library observation admissions are disabled"

	emitUnauditedToolchainNotice(&once, owned, func(d string) { got = append(got, d) })
	emitUnauditedToolchainNotice(&once, owned, func(d string) { got = append(got, d) })
	if len(got) != 1 {
		t.Fatalf("notice fired %d times, want once per engine", len(got))
	}
	var second sync.Once
	emitUnauditedToolchainNotice(&second, owned, func(d string) { got = append(got, d) })
	if len(got) != 2 {
		t.Fatalf("a second engine's once did not fire independently: %d", len(got))
	}
	// The emitted text is the owned rendering itself (axis named), plus
	// the operator-facing source pointer.
	if !strings.Contains(got[0], owned) || !strings.Contains(got[0], "toolchainaudit.go") {
		t.Fatalf("notice does not serve the owned rendering with the pointer: %q", got[0])
	}
	if owned != "" && !strings.Contains(got[0], "moved in 1 keys off go1.99.0: strings") {
		t.Fatalf("owned rendering does not name the axis: %q", got[0])
	}
}

// fullFingerprint is a code-result fingerprint with every scalar optional
// key present. Historical omission is checked separately from fresh encoding.
func fullFingerprint() Fingerprint {
	return Fingerprint{
		MaximalClosure:       "0123456789abcdef0123456789abcdef",
		ToolchainContent:     "stdlib-content",
		AdmissionPolicy:      "audit-policy",
		TestVariantClosure:   "fedcba9876543210fedcba9876543210",
		ObservationAssertion: "caller assertion",
		ObservationProof: ObservationProof{
			Strategy:   ObservationRTA,
			Subject:    Subject{Package: "example.com/m/p", Symbol: "TestX"},
			Observable: false,
			Reason:     "reaches os.Getenv",
			Evidence:   "00112233445566778899aabbccddeeff",
		},
		Guards:                   guard.Guards{Toolchain: "go1.27.0 linux/amd64", BuildConfig: "b1"},
		PurityAssertion:          "source directive",
		DynamicStateVouches:      "example.com/m/p.state",
		SingleSubjectDischarges:  "example.com/m/p.single",
		PackageProcessDischarges: "example.com/m/p.proc",
		DynamicStateStrategy:     DynamicStateStrategy,
		ClosureStrategy:          ClosureStrategy,
		RuntimeInputs:            "manifest",
		RuntimeDigest:            "ffeeddccbbaa99887766554433221100",
		ResultKind:               CodeResult,
	}
}

// TestFingerprintRecordIsTheFleetForm pins the record form byte for
// byte in both directions: the keys in their order, the
// guards flattened, the proof nested with its package and symbol, every
// optional key omitted when empty. Historical dependency omission remains
// readable, including inside indented consumer envelopes, and re-encodes
// without filling missing evidence
// (REQ-fresh-fingerprint-record).
func TestFingerprintRecordIsTheFleetForm(t *testing.T) {
	full := fullFingerprint()
	want := `{"maximalClosure":"0123456789abcdef0123456789abcdef","testVariantClosure":"fedcba9876543210fedcba9876543210","toolchain":"go1.27.0 linux/amd64","buildConfig":"b1","toolchainContent":"stdlib-content","admissionPolicy":"audit-policy","observationAssertion":"caller assertion","observationProof":{"strategy":"` + ObservationRTA + `","package":"example.com/m/p","symbol":"TestX","observable":false,"reason":"reaches os.Getenv","evidence":"00112233445566778899aabbccddeeff"},"purityAssertion":"source directive","dynamicStateVouches":"example.com/m/p.state","singleSubjectDischarges":"example.com/m/p.single","packageProcessDischarges":"example.com/m/p.proc","dynamicStateStrategy":"` + DynamicStateStrategy + `","closureStrategy":"` + ClosureStrategy + `","runtimeInputs":"manifest","runtimeDigest":"ffeeddccbbaa99887766554433221100","resultKind":1}`
	got, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("record form:\n got %s\nwant %s", got, want)
	}
	var back Fingerprint
	if err := json.Unmarshal([]byte(want), &back); err != nil {
		t.Fatal(err)
	}
	if back != full {
		t.Fatalf("decoded %+v\nwant    %+v", back, full)
	}
	legacyBytes := strings.Replace(want, `"toolchainContent":"stdlib-content","admissionPolicy":"audit-policy",`, "", 1)
	legacyBytes = strings.Replace(legacyBytes, ObservationRTA, "gofresh/observation-rta@43", 1)
	var legacy Fingerprint
	if err := json.Unmarshal([]byte(legacyBytes), &legacy); err != nil || legacy.ToolchainContent != "" || legacy.AdmissionPolicy != "" || legacy.ObservationProof.Strategy != "gofresh/observation-rta@43" {
		t.Fatalf("historical dependencies were invented: %+v %v", legacy, err)
	}
	if data, err := json.Marshal(legacy); err != nil || string(data) != legacyBytes {
		t.Fatalf("historical bytes changed: %s %v", data, err)
	}
	// The minimal code-result record: the two hashes, the two code
	// guards, the kind — nothing else.
	minimal := Fingerprint{MaximalClosure: "a", TestVariantClosure: "b", Guards: guard.Guards{Toolchain: "t", BuildConfig: "c"}, ResultKind: CodeResult}
	got, err = json.Marshal(minimal)
	if err != nil || string(got) != `{"maximalClosure":"a","testVariantClosure":"b","toolchain":"t","buildConfig":"c","resultKind":1}` {
		t.Fatalf("minimal record = %s, %v", got, err)
	}
	// A measurement record carries its two measurement guards, and a
	// positive proof carries no reason key.
	measured := Fingerprint{MaximalClosure: "a", TestVariantClosure: "b", Guards: guard.Guards{Toolchain: "t", BuildConfig: "c", Machine: "m", RuntimeConfig: "r"}, ObservationAssertion: "caller assertion", ObservationProof: ObservationProof{Strategy: ObservationRTA, Subject: Subject{Package: "p", Symbol: "s"}, Observable: true, Evidence: "e"}, ResultKind: Measurement}
	got, err = json.Marshal(measured)
	if err != nil || string(got) != `{"maximalClosure":"a","testVariantClosure":"b","toolchain":"t","buildConfig":"c","machine":"m","runtimeConfig":"r","observationAssertion":"caller assertion","observationProof":{"strategy":"`+ObservationRTA+`","package":"p","symbol":"s","observable":true,"evidence":"e"},"resultKind":2}` {
		t.Fatalf("measurement record = %s, %v", got, err)
	}
	// The three strategy constants are interpolated, not spelled: each
	// carries its own golden (TestObservationRTAVersion,
	// TestDynamicStateStrategyVersion, TestClosureStrategyVersion), and
	// a derivation move is not a record-form move.
	//
	// The flattened types' shapes are the record's: a field added to any
	// of them would silently drop from the encoding, so each is pinned
	// beside the golden.
	shape := func(typ reflect.Type, want ...string) {
		t.Helper()
		var got []string
		for i := 0; i < typ.NumField(); i++ {
			got = append(got, typ.Field(i).Name+" "+typ.Field(i).Type.String())
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s fields = %v, want %v", typ, got, want)
		}
	}
	shape(reflect.TypeFor[guard.Guards](), "Toolchain string", "BuildConfig string", "Machine string", "RuntimeConfig string")
	shape(reflect.TypeFor[ObservationProof](), "Strategy string", "Subject gofresh.Subject", "Observable bool", "Reason string", "Evidence string")
	shape(reflect.TypeFor[Subject](), "Package string", "Symbol string")
	shape(reflect.TypeFor[InertTestVariantApplicability](), "Strategy string", "TestVariantClosure string")
	// The form owns its escaping: a parent encoder's escaping setting
	// leaves the bytes — and the value read back — unchanged.
	escaped := fullFingerprint()
	escaped.DynamicStateVouches = "a<b&c>d"
	var raw bytes.Buffer
	enc := json.NewEncoder(&raw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(escaped); err != nil {
		t.Fatal(err)
	}
	own, err := json.Marshal(escaped)
	if err != nil || strings.TrimSpace(raw.String()) != string(own) || !strings.Contains(string(own), `\u003cb\u0026c\u003ed`) {
		t.Fatalf("escaping under a parent encoder: %q vs %q, %v", raw.String(), own, err)
	}
	var fromRaw Fingerprint
	if err := json.Unmarshal(raw.Bytes(), &fromRaw); err != nil || fromRaw != escaped {
		t.Fatalf("the escaped record read back: %v, %+v", err, fromRaw)
	}
	// A negative proof without a reason is incoherent to the check but
	// readable: it decodes.
	var negative Fingerprint
	if err := json.Unmarshal([]byte(`{"maximalClosure":"a","testVariantClosure":"b","toolchain":"t","buildConfig":"c","observationProof":{"strategy":"s","package":"p","symbol":"s","observable":false,"evidence":"e"},"resultKind":1}`), &negative); err != nil || negative.ObservationProof.Observable || negative.ObservationProof.Reason != "" {
		t.Fatalf("a negative proof without a reason: %+v, %v", negative, err)
	}
}

// genFingerprint draws a valid fingerprint: either kind, the proof
// present or absent, every optional value empty or set.
func genFingerprint(r *rand.Rand) Fingerprint {
	pick := func(vals ...string) string { return vals[r.Intn(len(vals))] }
	f := Fingerprint{
		MaximalClosure:           pick("m1", "m2"),
		ToolchainContent:         pick("", "content-a", "content-b"),
		AdmissionPolicy:          pick("", "policy-a", "policy-b"),
		TestVariantClosure:       pick("", "v1", "v2"),
		ObservationAssertion:     pick("", "caller assertion"),
		PurityAssertion:          pick("", "caller assertion", "source directive"),
		DynamicStateVouches:      pick("", "a.b", "a.b,c.d"),
		SingleSubjectDischarges:  pick("", "a.s"),
		PackageProcessDischarges: pick("", "a.p"),
		DynamicStateStrategy:     pick("", DynamicStateStrategy, "old"),
		ClosureStrategy:          pick("", ClosureStrategy),
		RuntimeInputs:            pick("", "manifest"),
		RuntimeDigest:            pick("", "d1"),
		Guards:                   guard.Guards{Toolchain: pick("", "t"), BuildConfig: pick("", "b")},
	}
	if r.Intn(2) == 0 {
		f.ResultKind = CodeResult
	} else {
		f.ResultKind = Measurement
		f.Guards.Machine = pick("", "m")
		f.Guards.RuntimeConfig = pick("", "r")
	}
	if r.Intn(2) == 0 {
		observable := r.Intn(2) == 0
		reason := ""
		if !observable {
			reason = pick("", "reaches os.Getenv")
		}
		f.ObservationProof = ObservationProof{Strategy: pick(ObservationRTA, "s"), Subject: Subject{Package: pick("p", ""), Symbol: pick("s", "")}, Observable: observable, Reason: reason, Evidence: pick("", "e")}
	}
	if r.Intn(2) == 0 {
		f.InertTestVariantApplicability = InertTestVariantApplicability{pick(InertTestVariantExtension, "future", "a<&\u2028"), pick("v1", "v2", "b<&\u2029")}
	}
	return f
}

// TestFingerprintRecordRoundTrips is the round-trip property over a
// seeded draw of valid fingerprints of both kinds: decode(encode(f)) is
// f, encode(decode(b)) is b, and an empty optional value is an absent
// key — the identity a consumer's record names depend on
// (REQ-fresh-fingerprint-record).
func TestFingerprintRecordRoundTrips(t *testing.T) {
	r := rand.New(rand.NewSource(274))
	optional := map[string]func(Fingerprint) string{
		"toolchainContent":              func(f Fingerprint) string { return f.ToolchainContent },
		"admissionPolicy":               func(f Fingerprint) string { return f.AdmissionPolicy },
		"inertTestVariantApplicability": func(f Fingerprint) string { return f.InertTestVariantApplicability.Strategy },
		"machine":                       func(f Fingerprint) string { return f.Guards.Machine }, "runtimeConfig": func(f Fingerprint) string { return f.Guards.RuntimeConfig },
		"observationAssertion": func(f Fingerprint) string { return f.ObservationAssertion }, "purityAssertion": func(f Fingerprint) string { return f.PurityAssertion },
		"dynamicStateVouches": func(f Fingerprint) string { return f.DynamicStateVouches }, "singleSubjectDischarges": func(f Fingerprint) string { return f.SingleSubjectDischarges },
		"packageProcessDischarges": func(f Fingerprint) string { return f.PackageProcessDischarges }, "dynamicStateStrategy": func(f Fingerprint) string { return f.DynamicStateStrategy },
		"closureStrategy": func(f Fingerprint) string { return f.ClosureStrategy }, "runtimeInputs": func(f Fingerprint) string { return f.RuntimeInputs }, "runtimeDigest": func(f Fingerprint) string { return f.RuntimeDigest },
	}
	for i := 0; i < 500; i++ {
		f := genFingerprint(r)
		data, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("draw %d: %v", i, err)
		}
		var back Fingerprint
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatalf("draw %d: %v over %s", i, err, data)
		}
		if back != f {
			t.Fatalf("draw %d: decode(encode) moved:\n%+v\n%+v", i, f, back)
		}
		again, err := json.Marshal(back)
		if err != nil || string(again) != string(data) {
			t.Fatalf("draw %d: encode(decode) moved: %s vs %s (%v)", i, again, data, err)
		}
		for key, read := range optional {
			present := strings.Contains(string(data), `"`+key+`":`)
			if present != (read(f) != "") {
				t.Fatalf("draw %d: key %q present=%v for value %q in %s", i, key, present, read(f), data)
			}
		}
		if strings.Contains(string(data), `"observationProof":`) != (f.ObservationProof != (ObservationProof{})) {
			t.Fatalf("draw %d: proof key presence in %s", i, data)
		}
		if strings.Contains(string(data), `"reason":`) != (f.ObservationProof.Reason != "") {
			t.Fatalf("draw %d: reason key presence in %s", i, data)
		}
		// The whitespace rule over every draw: the record indented by a
		// parent decodes to the same value.
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, data, "", "  "); err != nil {
			t.Fatal(err)
		}
		var fromPretty Fingerprint
		if err := json.Unmarshal(pretty.Bytes(), &fromPretty); err != nil || fromPretty != f {
			t.Fatalf("draw %d: the indented record: %v, %+v", i, err, fromPretty)
		}
	}
}

// TestFingerprintRecordRefusals pins every decode refusal by its
// wording and the encoder's refusal of an invalid fingerprint: an
// unknown key, a duplicated key, an explicit null, a proof without its
// observable, a positive proof carrying a reason, a zero kind, and a
// code-result record carrying a measurement guard — while a measurement
// record carrying both guards decodes (REQ-fresh-fingerprint-record,
// REQ-guard-selective-capture).
func TestFingerprintRecordRefusals(t *testing.T) {
	base := `"maximalClosure":"a","testVariantClosure":"b","toolchain":"t","buildConfig":"c"`
	cases := []struct{ record, want string }{
		{`{` + base + `,"resultKind":1,"extra":"x"}`, `unknown field "extra"`},
		{`{` + base + `,"resultKind":1,"toolchain":"t2"}`, `field "toolchain" is duplicated`},
		{`{` + base + `,"resultKind":1,"purityAssertion":null}`, `field "purityAssertion" is null`},
		{`{` + base + `,"resultKind":1,"observationProof":null}`, `field "observationProof" is null`},
		{`{` + base + `,"resultKind":1,"observationProof":{"strategy":"s","package":"p","symbol":"s","evidence":"e"}}`, `carries no observable`},
		{`{` + base + `,"resultKind":1,"observationProof":{"strategy":"s","package":"p","symbol":"s","observable":true,"reason":"r","evidence":"e"}}`, `positive observation proof carries a reason`},
		{`{` + base + `,"resultKind":1,"observationProof":{"strategy":"s","package":"p","symbol":"s","observable":false,"reason":null,"evidence":"e"}}`, `observation proof field "reason" is null`},
		{`{` + base + `,"resultKind":1,"observationProof":{"strategy":"s","package":"p","symbol":"s","observable":false,"evidence":"e","evidence":"f"}}`, `gofresh: observation proof field "evidence" is duplicated`},
		{`{` + base + `,"resultKind":1,"observationProof":{"strategy":"s","package":"p","symbol":"s","observable":false,"evidence":"e","bogus":1}}`, `gofresh: observation proof: json: unknown field "bogus"`},
		{`{` + base + `,"resultKind":1,"observationProof":{"strategy":"s","package":"p","symbol":"s","observable":null,"evidence":"e"}}`, `gofresh: observation proof field "observable" is null`},
		{`{` + base + `,"resultKind":1,"observationProof":{"strategy":"s","package":"p","symbol":"s","observable":"yes","evidence":"e"}}`, `gofresh: observation proof field "observable" cannot hold a JSON string`},
		{`{` + base + `,"resultKind":true}`, `gofresh: fingerprint record field "resultKind" cannot hold a JSON bool`},
		{`{` + base + `,"resultKind":1,"extra":null}`, `gofresh: fingerprint record field "extra" is null`},
		// Bytes the encoder would not have written: a reordered record,
		// an empty-valued optional, a zero proof object (an indented one
		// decodes — see below).
		{`{"resultKind":1,"buildConfig":"c","toolchain":"t","testVariantClosure":"b","maximalClosure":"a"}`, `not the form's own encoding`},
		{`{` + base + `,"purityAssertion":"","resultKind":1}`, `not the form's own encoding`},
		{`{` + base + `,"observationProof":{"strategy":"","package":"","symbol":"","observable":false,"evidence":""},"resultKind":1}`, `not the form's own encoding`},
		{`{` + base + `}`, `invalid recorded result kind 0`},
		{`{` + base + `,"resultKind":3}`, `invalid recorded result kind 3`},
		{`{` + base + `,"resultKind":1,"machine":"m"}`, `code-result fingerprint carries measurement guards`},
		{`{` + base + `,"resultKind":1,"runtimeConfig":"r"}`, `code-result fingerprint carries measurement guards`},
		{`[]`, `not a JSON object`},
	}
	for _, c := range cases {
		var f Fingerprint
		err := json.Unmarshal([]byte(c.record), &f)
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Count(err.Error(), "gofresh: ") != 1 || strings.Contains(err.Error(), "fingerprintRecord") || strings.Contains(err.Error(), "observationProofRecord") {
			t.Errorf("%s: err = %v, want %q, prefixed exactly once, naming no internal type", c.record, err, c.want)
		}
		if f != (Fingerprint{}) {
			t.Errorf("%s: a refused record left %+v", c.record, f)
		}
	}
	// An indented record decodes — a parent document is free to indent
	// its nested values — and the form composes with such a document:
	// the envelope a consumer writes with MarshalIndent round-trips.
	var indented Fingerprint
	if err := json.Unmarshal([]byte("{\n  "+base+`,`+"\n  "+`"resultKind":1`+"\n}"), &indented); err != nil || indented.MaximalClosure != "a" {
		t.Fatalf("an indented record: %v, %+v", err, indented)
	}
	type envelope struct {
		Version     int         `json:"version"`
		Fingerprint Fingerprint `json:"fingerprint"`
	}
	pretty, err := json.MarshalIndent(envelope{8, fullFingerprint()}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var back envelope
	if err := json.Unmarshal(pretty, &back); err != nil || back.Fingerprint != fullFingerprint() {
		t.Fatalf("the pretty-printed envelope: %v, %+v", err, back.Fingerprint)
	}
	// Trailing data after the object is refused by the decoder itself —
	// encoding/json refuses it before a top-level UnmarshalJSON runs, so
	// the arm is reached directly.
	var direct Fingerprint
	if err := direct.UnmarshalJSON([]byte(`{` + base + `,"resultKind":1} 1`)); err == nil || err.Error() != "gofresh: fingerprint record carries trailing data" || direct != (Fingerprint{}) {
		t.Fatalf("trailing data: %v, %+v", err, direct)
	}
	var measured Fingerprint
	if err := json.Unmarshal([]byte(`{`+base+`,"machine":"m","runtimeConfig":"r","resultKind":2}`), &measured); err != nil || measured.Guards.Machine != "m" || measured.Guards.RuntimeConfig != "r" || measured.ResultKind != Measurement {
		t.Fatalf("a measurement record with both guards: %+v, %v", measured, err)
	}
	// The encoder refuses what the decoder refuses, so an invalid
	// record is never written.
	for _, c := range []struct {
		f    Fingerprint
		want string
	}{
		{Fingerprint{MaximalClosure: "a"}, "gofresh: invalid recorded result kind 0"},
		{Fingerprint{MaximalClosure: "a", ResultKind: 7}, "gofresh: invalid recorded result kind 7"},
		{Fingerprint{MaximalClosure: "a", ResultKind: CodeResult, Guards: guard.Guards{Machine: "m"}}, "gofresh: code-result fingerprint carries measurement guards"},
		{Fingerprint{MaximalClosure: "a", ResultKind: CodeResult, Guards: guard.Guards{RuntimeConfig: "r"}}, "gofresh: code-result fingerprint carries measurement guards"},
	} {
		if _, err := json.Marshal(c.f); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("encoding %+v: err = %v, want %q", c.f, err, c.want)
		}
		if err := c.f.Validate(); err == nil || err.Error() != c.want {
			t.Errorf("Validate(%+v) = %v, want %q", c.f, err, c.want)
		}
	}
	if err := fullFingerprint().Validate(); err != nil {
		t.Fatal(err)
	}
	// A refusal's wording names the record, so a consumer's store can
	// attribute the fault to the file it read.
	var f Fingerprint
	if err := json.Unmarshal([]byte(`{`+base+`,"resultKind":1,"extra":1}`), &f); err == nil || !strings.HasPrefix(err.Error(), "gofresh: fingerprint record: ") {
		t.Fatalf("unknown-key wording = %v", fmt.Sprint(err))
	}
}

// TestDecide exhaustively pins the pure verdict function (REQ-fresh-verdict,
// REQ-fresh-sound): the base state is valid, and each perturbation drives exactly
// one verdict. It isolates the guard-set policy (a measurement-guard drift is stale
// for a Measurement, valid for a CodeResult) and the purity override.
func TestDecide(t *testing.T) {
	base := func() (Fingerprint, closure.Closure, guard.Guards, runtimeinput.State) {
		return Fingerprint{
				MaximalClosure:       "C",
				ToolchainContent:     "stdlib",
				TestVariantClosure:   "T",
				Guards:               guard.Guards{Toolchain: "tc", BuildConfig: "bc", Machine: "m", RuntimeConfig: "rc"},
				DynamicStateStrategy: DynamicStateStrategy,
				RuntimeInputs:        "MANIFEST",
				RuntimeDigest:        "D",
			},
			closure.Closure{Hash: "C", TestVariants: "T", ToolchainContent: "stdlib"},
			guard.Guards{Toolchain: "tc", BuildConfig: "bc", Machine: "m", RuntimeConfig: "rc"},
			runtimeinput.State{Digest: "D", OK: true}
	}

	tests := []struct {
		name     string
		mutate   func(*Fingerprint, *closure.Closure, *guard.Guards, *runtimeinput.State)
		kind     Kind
		pure     bool
		want     Status
		wantReas string
	}{
		{"all clean", nil, Measurement, false, Valid, ""},
		{"policy movement preserves independent purity", func(f *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			f.AdmissionPolicy = "old"
			c.AdmissionPolicy = "new"
			c.Unverifiable = true
		}, CodeResult, true, Valid, ""},
		{"toolchain content drift", func(_ *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			c.ToolchainContent = "other"
		}, CodeResult, false, Stale, "toolchain content"},
		{"toolchain content drift under purity", func(_ *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			c.ToolchainContent = "other"
		}, CodeResult, true, Stale, "toolchain content"},
		{"historical content absent", func(f *Fingerprint, _ *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			f.ToolchainContent = ""
		}, CodeResult, true, Unverifiable, "toolchain content evidence unavailable"},
		{"current content unavailable", func(_ *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			c.ToolchainContent = ""
		}, CodeResult, false, Unverifiable, "toolchain content evidence unavailable"},
		{"runtime drift before missing content", func(f *Fingerprint, _ *closure.Closure, _ *guard.Guards, r *runtimeinput.State) {
			f.ToolchainContent = ""
			r.Digest = "moved"
		}, CodeResult, true, Stale, "runtimeinputs"},
		{"closure mismatch", func(f *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) { c.Hash = "C2" }, Measurement, false, Stale, "closure"},
		{"closure missing", func(f *Fingerprint, _ *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			f.MaximalClosure = ""
		}, Measurement, false, Stale, "closure"},
		{"closure both empty", func(f *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			f.MaximalClosure = ""
			c.Hash = "" // an unevaluable closure is not proof, so never valid (REQ-fresh-sound)
		}, Measurement, false, Stale, "closure"},
		{"test variant mismatch", func(f *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			c.TestVariants = "T2"
		}, Measurement, false, Stale, "test variants"},
		// A recorded compartment that predates the partition is absence of
		// proof, never valid — even when the current compartment is also
		// unevaluable (REQ-closure-test-variant-identity fail-closed arm).
		{"test variant missing on pre-partition record", func(f *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			f.TestVariantClosure = ""
			c.TestVariants = ""
		}, Measurement, false, Stale, "test variants"},
		// Core drift wins over compartment drift: the compartment discriminates
		// only inside an unchanged core (REQ-closure-test-variant-identity).
		{"core and compartment both drifted", func(f *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			c.Hash = "C2"
			c.TestVariants = "T2"
		}, Measurement, false, Stale, "closure"},
		{"runtime digest mismatch", func(_ *Fingerprint, _ *closure.Closure, _ *guard.Guards, r *runtimeinput.State) { r.Digest = "D2" }, Measurement, false, Stale, "runtimeinputs"},
		{"runtime not OK", func(_ *Fingerprint, _ *closure.Closure, _ *guard.Guards, r *runtimeinput.State) { r.OK = false }, Measurement, false, Stale, "runtimeinputs"},
		{"runtime digest missing", func(f *Fingerprint, _ *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) { f.RuntimeDigest = "" }, Measurement, false, Stale, "runtimeinputs"},
		{"toolchain drift", func(_ *Fingerprint, _ *closure.Closure, g *guard.Guards, _ *runtimeinput.State) { g.Toolchain = "tc2" }, Measurement, false, Stale, "toolchain"},
		{"machine drift under Measurement", func(_ *Fingerprint, _ *closure.Closure, g *guard.Guards, _ *runtimeinput.State) { g.Machine = "m2" }, Measurement, false, Stale, "machine"},
		{"machine drift under CodeResult ignored", func(_ *Fingerprint, _ *closure.Closure, g *guard.Guards, _ *runtimeinput.State) { g.Machine = "m2" }, CodeResult, false, Valid, ""},
		{"closure unverifiable, not pure", func(_ *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			c.Unverifiable = true
			c.Reason = "reaches os.Open"
		}, Measurement, false, Unverifiable, "reaches os.Open"},
		{"closure unverifiable, pure overrides", func(_ *Fingerprint, c *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			c.Unverifiable = true
		}, Measurement, true, Valid, ""},
		{"runtime unverifiable, not pure", func(_ *Fingerprint, _ *closure.Closure, _ *guard.Guards, r *runtimeinput.State) {
			r.Unverifiable = true
			r.Reason = "unbounded input"
		}, Measurement, false, Unverifiable, "unbounded input"},
		{"runtime unverifiable, pure overrides", func(_ *Fingerprint, _ *closure.Closure, _ *guard.Guards, r *runtimeinput.State) {
			r.Unverifiable = true
		}, Measurement, true, Valid, ""},
		// An absent manifest supplies no observation or caller assertion. Here
		// independent source evidence needs no runtime-input guard.
		{"no manifest, clean", func(f *Fingerprint, _ *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			f.RuntimeInputs = ""
			f.RuntimeDigest = ""
		}, Measurement, false, Valid, ""},
		// A digest without its manifest is corruption, not absence: the digest
		// proves the guard applied, so the recording is unevaluable — stale
		// (REQ-guard-completeness), never the vacuous hold above.
		{"digest without manifest", func(f *Fingerprint, _ *closure.Closure, _ *guard.Guards, _ *runtimeinput.State) {
			f.RuntimeInputs = ""
		}, Measurement, false, Stale, "runtimeinputs"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, cl, cur, rt := base()
			if tc.mutate != nil {
				tc.mutate(&rec, &cl, &cur, &rt)
			}
			got := decide(rec, cl, cur, rt, tc.kind, testPurityAuthority(tc.pure))
			if got.Status != tc.want || got.Reason != tc.wantReas {
				t.Errorf("decide = {%s %q}, want {%s %q}", got.Status, got.Reason, tc.want, tc.wantReas)
			}
		})
	}
}

// FuzzDecideSound is a property witness for REQ-fresh-sound and
// REQ-inputs-evidence-not-proof: with the code guards holding and the closure hash
// matching, decide never returns Valid when the closure or the runtime inputs reach
// an unverifiable dependence and no purity override applies. Guards are fixed equal
// and non-empty so the property exercises the unverifiability branch, not a guard
// mismatch.
func FuzzDecideSound(f *testing.F) {
	f.Add("C", "C", "T", "T", "stdlib", "stdlib", true, false, "", false)
	f.Add("C", "C", "T", "T2", "stdlib", "stdlib", false, false, "M", true)
	f.Add("C", "C", "", "T", "stdlib", "changed", false, false, "M", false)
	f.Add("C", "C", "T", "T", "", "stdlib", false, true, "M", false)
	f.Fuzz(func(t *testing.T, recCl, curCl, recTv, curTv, recStd, curStd string, clUnver, pure bool, manifest string, rtUnver bool) {
		g := guard.Guards{Toolchain: "t", BuildConfig: "b"}
		rec := Fingerprint{MaximalClosure: recCl, TestVariantClosure: recTv, ToolchainContent: recStd, DynamicStateStrategy: DynamicStateStrategy, Guards: g, RuntimeInputs: manifest, RuntimeDigest: "D"}
		cl := closure.Closure{Hash: curCl, TestVariants: curTv, ToolchainContent: curStd, Unverifiable: clUnver}
		rt := runtimeinput.State{Digest: "D", Unverifiable: rtUnver, OK: true}
		v := decide(rec, cl, g, rt, CodeResult, testPurityAuthority(pure))
		if v.Status == Valid && (recStd == "" || recStd != curStd) {
			t.Fatal("valid with missing or changed toolchain content")
		}
		if v.Status == Valid && !pure {
			if cl.Unverifiable || (rec.RuntimeInputs != "" && rt.Unverifiable) {
				t.Fatalf("sound violated: valid with an unverifiable dependence and no purity override (rec=%+v cl=%+v rt=%+v)", rec, cl, rt)
			}
		}
		// The compartment is evidence like the core: valid requires a
		// non-empty recorded compartment equal to the current one
		// (REQ-closure-test-variant-identity).
		if v.Status == Valid && (rec.TestVariantClosure == "" || rec.TestVariantClosure != cl.TestVariants) {
			t.Fatalf("sound violated: valid across test-variant compartment drift (rec=%+v cl=%+v)", rec, cl)
		}
	})
}

// TestEngineNeverInfersPurity pins REQ-purity-responsibility: a default engine treats
// no subject as pure — purity is only ever an explicit input, never inferred.
func TestEngineNeverInfersPurity(t *testing.T) {
	e, err := newEngine(withGoRunner(hermeticEnvRunner()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, s := range []Subject{{Package: "p", Symbol: "F"}, {Package: "p", Symbol: "T.M"}, {}} {
		if e.assumePure(s) {
			t.Errorf("default engine inferred purity for %+v", s)
		}
	}
}

// TestFingerprintDataShape pins the fingerprint as exported data — every
// constituent an exported field of the stated type, in order — whose
// behaviour is its record form and explicit effective-compartment accessor:
// the encoder and validity ladder on the value, the decoder on the pointer
// (REQ-fresh-fingerprint-data, REQ-fresh-fingerprint-record,
// REQ-fresh-observation-data).
func TestFingerprintDataShape(t *testing.T) {
	typeOf := reflect.TypeFor[Fingerprint]()
	want := []struct {
		name string
		typ  reflect.Type
	}{
		{"MaximalClosure", reflect.TypeFor[string]()}, {"ToolchainContent", reflect.TypeFor[string]()}, {"AdmissionPolicy", reflect.TypeFor[string]()}, {"TestVariantClosure", reflect.TypeFor[string]()},
		{"InertTestVariantApplicability", reflect.TypeFor[InertTestVariantApplicability]()},
		{"ObservationAssertion", reflect.TypeFor[string]()}, {"ObservationProof", reflect.TypeFor[ObservationProof]()},
		{"Guards", reflect.TypeFor[guard.Guards]()}, {"PurityAssertion", reflect.TypeFor[string]()},
		{"DynamicStateVouches", reflect.TypeFor[string]()}, {"SingleSubjectDischarges", reflect.TypeFor[string]()},
		{"PackageProcessDischarges", reflect.TypeFor[string]()}, {"DynamicStateStrategy", reflect.TypeFor[string]()},
		{"ClosureStrategy", reflect.TypeFor[string]()}, {"RuntimeInputs", reflect.TypeFor[string]()},
		{"RuntimeDigest", reflect.TypeFor[string]()}, {"ResultKind", reflect.TypeFor[Kind]()},
	}
	if typeOf.Kind() != reflect.Struct || typeOf.NumField() != len(want) {
		t.Fatalf("Fingerprint shape = %s with %d fields, want data struct with %d fields", typeOf.Kind(), typeOf.NumField(), len(want))
	}
	for i, w := range want {
		field := typeOf.Field(i)
		if field.Name != w.name || !field.IsExported() || field.Type != w.typ || field.Tag != "" {
			t.Fatalf("Fingerprint field %d = %s %s exported=%v tag=%q, want exported %s %s untagged", i, field.Name, field.Type, field.IsExported(), field.Tag, w.name, w.typ)
		}
	}
	methods := func(typ reflect.Type) []string {
		var names []string
		for i := 0; i < typ.NumMethod(); i++ {
			names = append(names, typ.Method(i).Name)
		}
		return names
	}
	if got := methods(typeOf); !reflect.DeepEqual(got, []string{"EffectiveTestVariantClosure", "MarshalJSON", "Validate"}) {
		t.Fatalf("Fingerprint value methods = %v, want record form and effective compartment", got)
	}
	if got := methods(reflect.PointerTo(typeOf)); !reflect.DeepEqual(got, []string{"EffectiveTestVariantClosure", "MarshalJSON", "UnmarshalJSON", "Validate"}) {
		t.Fatalf("Fingerprint pointer methods = %v, want record form and effective compartment", got)
	}
	structural.ExportedData[Subject](t,
		structural.FieldOf[string]("Package"),
		structural.FieldOf[string]("Symbol"),
	)
	structural.ExportedData[InertTestVariantApplicability](t,
		structural.FieldOf[string]("Strategy"),
		structural.FieldOf[string]("TestVariantClosure"),
	)
	structural.ExportedData[ObservationProof](t,
		structural.FieldOf[string]("Strategy"),
		structural.FieldOf[Subject]("Subject"),
		structural.FieldOf[bool]("Observable"),
		structural.FieldOf[string]("Reason"),
		structural.FieldOf[string]("Evidence"),
	)
	structural.ExportedData[guard.Guards](t,
		structural.FieldOf[string]("Toolchain"),
		structural.FieldOf[string]("BuildConfig"),
		structural.FieldOf[string]("Machine"),
		structural.FieldOf[string]("RuntimeConfig"),
	)
	structural.FunctionSignature[func(Fingerprint) string](t, Fingerprint.EffectiveTestVariantClosure)
	structural.FunctionSignature[func(Fingerprint) ([]byte, error)](t, Fingerprint.MarshalJSON)
	structural.FunctionSignature[func(Fingerprint) error](t, Fingerprint.Validate)
	structural.FunctionSignature[func(*Fingerprint, []byte) error](t, (*Fingerprint).UnmarshalJSON)
}

func TestObservationRTAVersion(t *testing.T) {
	if ObservationRTA != "gofresh/observation-rta@58" {
		t.Fatalf("ObservationRTA = %q, want content- and policy-bound proof evidence", ObservationRTA)
	}
}

func TestDynamicStateStrategyVersion(t *testing.T) {
	if DynamicStateStrategy != "gofresh/dynamic-state@49" {
		t.Fatalf("DynamicStateStrategy = %q, want the typed dynamic-state fact and summary derivation", DynamicStateStrategy)
	}
}

func TestClosureStrategyVersion(t *testing.T) {
	if ClosureStrategy != "gofresh/closure@1 gofresh/canonical-member@2 gofresh/variant-parse@2" {
		t.Fatalf("ClosureStrategy = %q, want the composition of the fold, canonical-member, and compartment derivations", ClosureStrategy)
	}
}

func TestPropCommitIdentityAbsent(t *testing.T) {
	typeOf := reflect.TypeFor[Fingerprint]()
	for i := 0; i < typeOf.NumField(); i++ {
		if strings.Contains(strings.ToLower(typeOf.Field(i).Name), "commit") {
			t.Fatalf("fingerprint validity surface contains commit identity field %s", typeOf.Field(i).Name)
		}
	}
}

func TestAssumePureInputShape(t *testing.T) {
	typeOf := reflect.TypeOf(withAssumePure)
	wantPredicate := reflect.TypeFor[func(Subject) bool]()
	if typeOf.NumIn() != 1 || typeOf.In(0) != wantPredicate || typeOf.NumOut() != 1 || typeOf.Out(0) != reflect.TypeFor[option]() {
		t.Fatalf("withAssumePure type = %s, want func(func(Subject) bool) option", typeOf)
	}
}

func TestBuildInputsRejectFlags(t *testing.T) {
	if _, err := newEngine(withBuildInputs("-race")); err == nil || !strings.Contains(err.Error(), "BuildFlags") {
		t.Fatalf("flag-shaped opaque input accepted: %v", err)
	}
}

func TestBuildFlagsRejectOverlay(t *testing.T) {
	flags := []string{"-overlay=overlay.json"}
	if _, err := newEngine(withBuildFlags(flags...)); err == nil || !strings.Contains(err.Error(), "-overlay") {
		t.Fatalf("engine accepted overlay: %v", err)
	}
	if _, err := scanPureDirectivesAt(t.TempDir(), os.Environ(), flags, "example.com/p"); err == nil || !strings.Contains(err.Error(), "-overlay") {
		t.Fatalf("purity scanner accepted overlay: %v", err)
	}
}

func TestDefaultDirIsFrozenAtEngineConstruction(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := newEngine(withGoRunner(hermeticEnvRunner()))
	if err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := os.Chdir(other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
	if engine.dir != original {
		t.Fatalf("default engine dir after chdir = %q, want frozen %q", engine.dir, original)
	}
}

// TestWithDirCoherence pins the one-tree rule: an engine rooted somewhere
// refuses guard capture in a different tree — an incoherent fingerprint
// (closure from one tree, environment from another) is never produced.
func TestWithDirCoherence(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/x\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := newEngine(withDir(dir), withGoRunner(hermeticEnvRunner()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := e.capture(context.Background(), Subject{Package: "example.com/x", Symbol: "F"}, t.TempDir()); err == nil || !strings.Contains(err.Error(), "one tree per fingerprint") {
		t.Fatalf("incoherent dirs accepted: %v", err)
	}
}

func TestDefaultDirCoherence(t *testing.T) {
	e, err := newEngine(withGoRunner(hermeticEnvRunner()))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.coherentDir(t.TempDir()); err == nil || !strings.Contains(err.Error(), "one tree per fingerprint") {
		t.Fatalf("default engine accepted guards from another tree: %v", err)
	}
}

func TestWithDirCoherenceResolvesSymlinks(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "base")
	other := filepath.Join(root, "other")
	child := filepath.Join(other, "child")
	for _, dir := range []string{base, child} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join("..", "other", "child"), filepath.Join(base, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	engineDir := filepath.Join(base, "link") + string(os.PathSeparator) + ".."
	e, err := newEngine(withDir(engineDir), withGoRunner(hermeticEnvRunner()))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.coherentDir(base); err == nil || !strings.Contains(err.Error(), "one tree per fingerprint") {
		t.Fatalf("symlink-divergent trees accepted: %v", err)
	}
}

// FuzzControlAndSessionAuthority is a property witness for REQ-vouch-input.
func FuzzControlAndSessionAuthority(f *testing.F) {
	f.Add("example.com/pkg", "Hook", "sub/dir", "-tags=fast", "out.test", "-v")
	f.Add("example.com/v2/sub", "State", "nested", "-race", "bin.test", "-count=1")
	f.Fuzz(func(t *testing.T, pkg, sym, relDir, flagVal, outPath, extraFlag string) {
		cleanIdent := func(s, def string) string {
			var b strings.Builder
			for _, r := range s {
				if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
					b.WriteRune(r)
				}
			}
			res := b.String()
			if res == "" || (res[0] >= '0' && res[0] <= '9') {
				return def
			}
			return res
		}
		vName := cleanIdent(sym, "Hook")
		pName := "example.com/" + strings.ToLower(cleanIdent(pkg, "pkg"))
		colonForm := pName + ":" + vName
		dotForm := pName + "." + vName
		gotCanon, err := ParseVouchEntry(colonForm)
		if err != nil || gotCanon != dotForm {
			t.Fatalf("ParseVouchEntry(%q) = (%q, %v), want %q", colonForm, gotCanon, err, dotForm)
		}
		gotSessionVouches, err := canonicalSessionVouches([]string{dotForm, dotForm})
		if err != nil || !slices.Equal(gotSessionVouches, []string{dotForm}) {
			t.Fatalf("canonicalSessionVouches = (%v, %v), want [%q]", gotSessionVouches, err, dotForm)
		}
		if _, err := canonicalSessionVouches([]string{colonForm}); err == nil {
			t.Fatalf("canonicalSessionVouches accepted non-canonical colon form %q", colonForm)
		}
		if _, err := canonicalSessionVouches([]string{pName}); err == nil {
			t.Fatalf("canonicalSessionVouches accepted bare package %q", pName)
		}
		_ = BuildDescription{
			Directory:   "/workspace/mod",
			Package:     pName,
			Environment: []string{"GOENV=off"},
			Flags:       []string{flagVal},
			Inputs:      []string{"input=1"},
		}
		_ = outPath
		_ = extraFlag
		// NewSession refuses invalid build/policy authority before any work.
		ctx := context.Background()
		validBuild := BuildDescription{Directory: "/tmp", Environment: []string{"GOENV=off"}, Inputs: []string{}}
		for _, invalidBuild := range []BuildDescription{
			{Directory: "", Environment: []string{}, Inputs: []string{}},
			{Directory: "/tmp", Package: pName, Environment: []string{}, Inputs: []string{}},
			{Directory: "/tmp", Environment: nil, Inputs: []string{}},
			{Directory: "/tmp", Environment: []string{}, Inputs: nil},
		} {
			if _, err := NewSession(ctx, invalidBuild, SessionPolicy{}); err == nil {
				t.Fatalf("NewSession accepted invalid BuildDescription: %+v", invalidBuild)
			}
		}
		if _, err := NewSession(ctx, validBuild, SessionPolicy{Execution: ExecutionModel(99)}); err == nil {
			t.Fatal("NewSession accepted unknown ExecutionModel")
		}
		if _, err := NewSession(ctx, validBuild, SessionPolicy{AnalysisBudget: -1}); err == nil {
			t.Fatal("NewSession accepted negative AnalysisBudget")
		}
		if _, err := NewSession(ctx, validBuild, SessionPolicy{PureSubjects: []Subject{{Package: pName, Symbol: ""}}}); err == nil {
			t.Fatal("NewSession accepted empty PureSubjects symbol")
		}
		if _, err := NewSession(ctx, validBuild, SessionPolicy{Vouches: []string{"invalid"}}); err == nil {
			t.Fatal("NewSession accepted invalid vouch identity")
		}
		// Process path rebasing and project isolation.
		sub := cleanIdent(relDir, "sub")
		rebased, err := rebaseProcessPath("/workspace/mod", sub)
		if err != nil || rebased != "/workspace/mod"+string(filepath.Separator)+sub {
			t.Fatalf("rebaseProcessPath = (%q, %v)", rebased, err)
		}
		eng := &engine{dir: "/workspace/mod", evidenceRoot: "/workspace"}
		if got := eng.evidenceRootFor("/workspace/mod"); got != "/workspace" {
			t.Fatalf("evidenceRootFor with explicit root = %q, want /workspace", got)
		}
		engNoRoot := &engine{dir: "/workspace/mod"}
		if got := engNoRoot.evidenceRootFor("/workspace/mod"); got != "/workspace/mod" {
			t.Fatalf("evidenceRootFor without explicit root = %q, want /workspace/mod", got)
		}
	})
}

// FuzzGuardRelevanceAndViewLifetime is a property witness for
// REQ-guard-runtime-relevance and REQ-guard-view-lifetime.
func FuzzGuardRelevanceAndViewLifetime(f *testing.F) {
	f.Add("tc1", "bc1", "m1", "rc1", "m2", "rc2", true, false)
	f.Add("tcA", "bcA", "", "", "mB", "rcB", false, true)
	f.Fuzz(func(t *testing.T, tc, bc, m1, rc1, m2, rc2 string, clUnver, rtUnver bool) {
		if tc == "" {
			tc = "tc"
		}
		if bc == "" {
			bc = "bc"
		}
		codeGuards := guard.Guards{Toolchain: tc, BuildConfig: bc}
		recCode := Fingerprint{
			MaximalClosure:       "C",
			ToolchainContent:     "stdlib",
			TestVariantClosure:   "T",
			DynamicStateStrategy: DynamicStateStrategy,
			ClosureStrategy:      ClosureStrategy,
			Guards:               codeGuards,
			RuntimeInputs:        "M",
			RuntimeDigest:        "D",
			ResultKind:           CodeResult,
		}
		if err := validateRecordedKind(recCode); err != nil {
			t.Fatalf("valid CodeResult rejected: %v", err)
		}
		if m1 != "" || rc1 != "" {
			badCode := recCode
			badCode.Guards.Machine = m1
			badCode.Guards.RuntimeConfig = rc1
			if err := validateRecordedKind(badCode); err == nil {
				t.Fatalf("CodeResult carrying measurement guards (%q, %q) was not refused", m1, rc1)
			}
		}
		// Omitting measurement guards from CodeResult means machine/runtimeConfig
		// changes do not stale CodeResult, but unverifiable runtime/closure
		// effects still withhold validity (REQ-guard-runtime-relevance).
		curGuards := guard.Guards{Toolchain: tc, BuildConfig: bc, Machine: m2, RuntimeConfig: rc2}
		cl := closure.Closure{Hash: "C", ToolchainContent: "stdlib", TestVariants: "T", Unverifiable: clUnver, Reason: "effect"}
		rt := runtimeinput.State{Manifest: "M", Digest: "D", OK: true, Unverifiable: rtUnver, Reason: "rt-effect"}
		v := decide(recCode, cl, curGuards, rt, CodeResult, PurityAuthority{})
		if (clUnver || rtUnver) && v.Status != Unverifiable {
			t.Fatalf("CodeResult ignored unverifiable runtime/closure effect: %+v", v)
		}
		if !clUnver && !rtUnver && v.Status != Valid {
			t.Fatalf("CodeResult staled on measurement-only guard movement: %+v", v)
		}
		// View lifetime: a Snapshot and its derived Sibling share the construction
		// code-guard capture, while independent RuntimeBindings supply their own
		// measurement guards without mutating the shared Snapshot facts.
		s1 := Subject{Package: "example.com/p", Symbol: "F"}
		s2 := Subject{Package: "example.com/p", Symbol: "G"}
		parent := &Snapshot{
			subjects: []Subject{s1, s2},
			packages: []string{"example.com/p"},
			kind:     Measurement,
			facts: &observationFacts{
				guards:  codeGuards,
				maximal: map[Subject]subjectFacts{s1: {}, s2: {}},
			},
		}
		sib, err := parent.Sibling([]Subject{s1})
		if err != nil {
			t.Fatalf("Sibling: %v", err)
		}
		if sib.guards() != codeGuards || parent.guards() != codeGuards {
			t.Fatalf("Sibling altered base snapshot guards: sib=%+v parent=%+v", sib.guards(), parent.guards())
		}
		b1 := &RuntimeBinding{snapshot: parent, runtime: boundRuntime{guards: guard.RuntimeGuards{Machine: m1, RuntimeConfig: rc1}}}
		b2 := &RuntimeBinding{snapshot: parent, runtime: boundRuntime{guards: guard.RuntimeGuards{Machine: m2, RuntimeConfig: rc2}}}
		v1, err := b1.newView([]Subject{s1})
		if err != nil {
			t.Fatalf("b1.newView: %v", err)
		}
		v2, err := b2.newView([]Subject{s1})
		if err != nil {
			t.Fatalf("b2.newView: %v", err)
		}
		if v1.guards().Toolchain != tc || v1.guards().Machine != m1 || v2.guards().Machine != m2 || parent.guards().Machine != "" {
			t.Fatalf("RuntimeBinding guard lifetime violated: v1=%+v v2=%+v parent=%+v", v1.guards(), v2.guards(), parent.guards())
		}
	})
}

// FuzzFreshnessVerdictAndObservationInvariants is a property witness for
// REQ-fresh-applicability-transform, REQ-fresh-commit-independent,
// REQ-fresh-dependency-identities, REQ-fresh-historical-implementation,
// REQ-fresh-observation-compatibility, REQ-fresh-observation-conjunction,
// REQ-fresh-observation-data, REQ-fresh-observation-lifecycle,
// REQ-fresh-producing-evidence, REQ-fresh-static-certificate,
// REQ-fresh-toolchain-dependencies, and REQ-purity-observation-separation.
func FuzzFreshnessVerdictAndObservationInvariants(f *testing.F) {
	f.Add("C1", "TV1", "TV2", "stdlib1", "policy1", "D1", true, false, false)
	f.Add("C2", "TVA", "TVB", "stdlib2", "policy2", "D2", false, true, true)
	f.Fuzz(func(t *testing.T, clHash, tv1, tv2, stdContent, admPolicy, rtDigest string, observable, rtUnver, sharedDyn bool) {
		if clHash == "" {
			clHash = "C"
		}
		if tv1 == "" {
			tv1 = "TV1"
		}
		if tv2 == "" || tv2 == tv1 {
			tv2 = tv1 + "_next"
		}
		if stdContent == "" {
			stdContent = "stdlib"
		}
		if admPolicy == "" {
			admPolicy = "policy"
		}
		if rtDigest == "" {
			rtDigest = "D"
		}
		subj := Subject{Package: "example.com/pkg", Symbol: "Bench"}
		guards := guard.Guards{Toolchain: "tc", BuildConfig: "bc"}
		reason := ""
		if !observable {
			reason = "reaches net.Dial"
		}
		rec := Fingerprint{
			MaximalClosure:       clHash,
			ToolchainContent:     stdContent,
			AdmissionPolicy:      admPolicy,
			TestVariantClosure:   tv1,
			ObservationAssertion: "caller assertion",
			ObservationProof: ObservationProof{
				Strategy:   ObservationRTA,
				Subject:    subj,
				Observable: observable,
				Reason:     reason,
			},
			Guards:               guards,
			DynamicStateStrategy: DynamicStateStrategy,
			ClosureStrategy:      ClosureStrategy,
			RuntimeInputs:        "manifest",
			RuntimeDigest:        rtDigest,
			ResultKind:           CodeResult,
		}
		rec.ObservationProof.Evidence = observationProofEvidence(rec)

		// 1. Observation proof compatibility & integrity (REQ-fresh-observation-compatibility, REQ-fresh-observation-data).
		if !compatibleObservationProof(rec, subj) {
			t.Fatalf("canonical proof rejected: %+v", rec)
		}
		if compatibleObservationProof(rec, Subject{Package: subj.Package, Symbol: subj.Symbol + "_other"}) {
			t.Fatal("proof accepted for wrong subject")
		}
		for _, mutate := range []func(*Fingerprint){
			func(fp *Fingerprint) { fp.MaximalClosure += "_drift" },
			func(fp *Fingerprint) { fp.ToolchainContent = "" },
			func(fp *Fingerprint) { fp.ToolchainContent += "_drift" },
			func(fp *Fingerprint) { fp.AdmissionPolicy = "" },
			func(fp *Fingerprint) { fp.AdmissionPolicy += "_drift" },
			func(fp *Fingerprint) { fp.ObservationAssertion = "" },
			func(fp *Fingerprint) { fp.ObservationProof.Strategy = "other" },
			func(fp *Fingerprint) { fp.ObservationProof.Observable = !fp.ObservationProof.Observable },
		} {
			copyRec := rec
			mutate(&copyRec)
			if compatibleObservationProof(copyRec, subj) {
				t.Fatalf("mutated proof remained compatible: %+v", copyRec)
			}
		}

		// 2. JSON representation round-trip & dependency identity preservation (REQ-fresh-dependency-identities).
		encoded, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var roundTripped Fingerprint
		if err := json.Unmarshal(encoded, &roundTripped); err != nil || roundTripped != rec {
			t.Fatalf("JSON round-trip mismatch: got %+v, err %v", roundTripped, err)
		}

		// 3. Guard precedence & toolchain dependency authority (REQ-fresh-dependency-identities, REQ-fresh-toolchain-dependencies).
		cl := closure.Closure{
			Hash:             clHash,
			ToolchainContent: stdContent,
			AdmissionPolicy:  admPolicy,
			TestVariants:     tv1,
			Unverifiable:     true,
			Reason:           "reaches os.Open",
		}
		if sharedDyn {
			cl.Refusal = closure.SharedDynamicStateRefusal
			cl.Culprit = closure.Subject{Package: "example.com/pkg", Symbol: "Global"}
		}
		rt := runtimeinput.State{Manifest: "manifest", Digest: rtDigest, OK: true, Unverifiable: rtUnver, Reason: "unbounded"}
		missingStd := rec
		missingStd.ToolchainContent = ""
		if v := decide(missingStd, cl, guards, rt, CodeResult, PurityAuthority{}); v.Status != Unverifiable || v.Ground.Cause != (Cause{Kind: ToolchainContentCause, Condition: Missing}) {
			t.Fatalf("missing historical ToolchainContent = %+v, want Unverifiable/Missing", v)
		}
		unavailStdCl := cl
		unavailStdCl.ToolchainContent = ""
		if v := decide(rec, unavailStdCl, guards, rt, CodeResult, PurityAuthority{}); v.Status != Unverifiable || v.Ground.Cause != (Cause{Kind: ToolchainContentCause, Condition: Unavailable}) {
			t.Fatalf("unavailable current ToolchainContent = %+v, want Unverifiable/Unavailable", v)
		}
		driftedStdCl := cl
		driftedStdCl.ToolchainContent = stdContent + "_drift"
		if v := decide(rec, driftedStdCl, guards, rt, CodeResult, PurityAuthority{}); v.Status != Stale || v.Ground.Cause != (Cause{Kind: ToolchainContentCause, Condition: Changed}) {
			t.Fatalf("drifted ToolchainContent = %+v, want Stale/Changed", v)
		}
		driftedRt := rt
		driftedRt.Digest = rtDigest + "_moved"
		if v := decide(missingStd, cl, guards, driftedRt, CodeResult, PurityAuthority{}); v.Status != Stale || v.Ground.Cause.Kind != RuntimeInputsCause {
			t.Fatalf("guard-precedence violated: runtime drift with missing ToolchainContent = %+v, want Stale/RuntimeInputsCause", v)
		}

		// Historical authority & AdmissionPolicy binding on observation support (REQ-fresh-toolchain-dependencies).
		manifestBytes, err := json.Marshal(struct {
			Version  int      `json:"v"`
			Outcome  string   `json:"outcome"`
			Subjects []string `json:"subjects"`
		}{4, outcome.Method, []string{outcomeSubject(rec, subj)}})
		if err != nil {
			t.Fatalf("Marshal manifest: %v", err)
		}
		recSupported := rec
		recSupported.RuntimeInputs = base64.RawURLEncoding.EncodeToString(manifestBytes)
		gotAuth := admittedObservation(recSupported, subj, cl)
		if observable != gotAuth.accepted() {
			t.Fatalf("admittedObservation(observable=%v) = %+v", observable, gotAuth)
		}
		missingPolicyRec := recSupported
		missingPolicyRec.AdmissionPolicy = ""
		if auth := admittedObservation(missingPolicyRec, subj, cl); auth.accepted() {
			t.Fatalf("missing historical AdmissionPolicy accepted observation authority: %+v", auth)
		}
		if v := decideAfterClosureObserved(missingPolicyRec, cl, guards, rt, CodeResult, PurityAuthority{}, admittedObservation(missingPolicyRec, subj, cl)); v.Status != Unverifiable {
			t.Fatalf("missing historical AdmissionPolicy lifted closure refusal: %+v", v)
		}
		driftedPolicyCl := cl
		driftedPolicyCl.AdmissionPolicy = admPolicy + "_drift"
		if auth := admittedObservation(recSupported, subj, driftedPolicyCl); auth.accepted() {
			t.Fatalf("drifted AdmissionPolicy accepted observation authority: %+v", auth)
		}
		if v := decideAfterClosureObserved(recSupported, driftedPolicyCl, guards, rt, CodeResult, PurityAuthority{}, admittedObservation(recSupported, subj, driftedPolicyCl)); v.Status != Unverifiable {
			t.Fatalf("drifted AdmissionPolicy lifted closure refusal: %+v", v)
		}
		for _, depMutate := range []func(*Fingerprint){
			func(fp *Fingerprint) { fp.ToolchainContent += "_drift" },
			func(fp *Fingerprint) { fp.AdmissionPolicy += "_drift" },
		} {
			mutFP := recSupported
			depMutate(&mutFP)
			if runtimeinput.HasOutcomeSupport(recSupported.RuntimeInputs, outcomeSubject(mutFP, subj)) {
				t.Fatalf("outcomeSubject failed to bind toolchain dependency in %+v", mutFP)
			}
		}

		// 4. Observation conjunction & separation from purity and shared dynamic state
		// (REQ-fresh-observation-conjunction, REQ-purity-observation-separation).
		obsAuth := ObservationAuthority{}
		if observable {
			obsAuth = ObservationAuthority{Assertion: rec.ObservationAssertion, ProofStrategy: ObservationRTA, OutcomeMethod: outcome.Method}
		}
		vObs := decideAfterClosureObserved(rec, cl, guards, rt, CodeResult, PurityAuthority{}, obsAuth)
		wantLift := observable && !rtUnver && !sharedDyn
		if wantLift {
			if vObs.Status != Valid || vObs.Ground.Accepted.Observation != obsAuth || vObs.Ground.Accepted.Purity != (PurityAuthority{}) {
				t.Fatalf("observation conjunction failed to lift or conflated purity: %+v", vObs)
			}
		} else if vObs.Status == Valid {
			t.Fatalf("unsound observation lift (observable=%v rtUnver=%v sharedDyn=%v): %+v", observable, rtUnver, sharedDyn, vObs)
		}

		// 5. Applicability transform, dependency propagation & historical implementation preservation
		// (REQ-fresh-applicability-transform, REQ-fresh-historical-implementation, REQ-fresh-static-certificate, REQ-fresh-producing-evidence, REQ-fresh-observation-lifecycle, REQ-fresh-toolchain-dependencies).
		if rec.EffectiveTestVariantClosure() != tv1 {
			t.Fatalf("EffectiveTestVariantClosure without transform = %q, want %q", rec.EffectiveTestVariantClosure(), tv1)
		}
		curCl := cl
		curCl.TestVariants = tv2
		curMaxFacts := closure.MaximalFacts{
			Identity: closure.MaximalIdentity{
				Hash:             curCl.Hash,
				ToolchainContent: curCl.ToolchainContent,
				AdmissionPolicy:  curCl.AdmissionPolicy,
				TestVariants:     curCl.TestVariants,
			},
		}
		ledger := testvariant.TestVariantLedger{BindingStrategy: testvariant.BindingStrategy}
		gitDir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(gitDir, ".git", "refs", "heads"), 0o755); err != nil {
			t.Fatalf("MkdirAll .git: %v", err)
		}
		if err := os.WriteFile(filepath.Join(gitDir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
			t.Fatalf("WriteFile HEAD: %v", err)
		}
		if err := os.WriteFile(filepath.Join(gitDir, ".git", "refs", "heads", "main"), []byte("1111111111111111111111111111111111111111\n"), 0o644); err != nil {
			t.Fatalf("WriteFile main ref: %v", err)
		}
		view := &Snapshot{
			subjects:  []Subject{subj},
			packages:  []string{subj.Package},
			moduleDir: gitDir,
			kind:      CodeResult,
			facts: &observationFacts{
				guards:             guards,
				maximal:            map[Subject]subjectFacts{subj: {source: curMaxFacts}},
				testVariantLedgers: map[string]testvariant.TestVariantLedger{subj.Package: ledger},
			},
			observable:           map[Subject]closure.Observability{subj: {Observable: observable, Reason: reason}},
			capturedObserved:     map[Subject]bool{},
			attachedObservations: map[Subject]runtimeinput.State{},
		}
		staticFP := view.fingerprintLocked(subj, curCl)
		if staticFP.ToolchainContent != curCl.ToolchainContent || staticFP.AdmissionPolicy != curCl.AdmissionPolicy {
			t.Fatalf("fingerprintLocked did not propagate toolchain dependencies: got (%q, %q), want (%q, %q)", staticFP.ToolchainContent, staticFP.AdmissionPolicy, curCl.ToolchainContent, curCl.AdmissionPolicy)
		}
		obsFP := view.observedFingerprintLocked(subj)
		if obsFP.ToolchainContent != curCl.ToolchainContent || obsFP.AdmissionPolicy != curCl.AdmissionPolicy || obsFP.ObservationProof.Evidence != observationProofEvidence(obsFP) {
			t.Fatalf("observedFingerprintLocked did not propagate and bind toolchain dependencies: %+v", obsFP)
		}
		if staticFP.RuntimeInputs != "" || staticFP.RuntimeDigest != "" || staticFP.ObservationAssertion != "" {
			t.Fatalf("static certificate carried producing runtime evidence: %+v", staticFP)
		}

		// 6. Commit-independence: no commit field on Fingerprint, and VCS commit / dirty-tree mutations
		// leave fingerprint projection and verdict decisions invariant (REQ-fresh-commit-independent).
		fpType := reflect.TypeFor[Fingerprint]()
		for i := 0; i < fpType.NumField(); i++ {
			if strings.Contains(strings.ToLower(fpType.Field(i).Name), "commit") {
				t.Fatalf("Fingerprint contains commit identity field %s", fpType.Field(i).Name)
			}
		}
		verdictBeforeVCS := decide(rec, cl, guards, rt, CodeResult, testPurityAuthority(true))
		if err := os.WriteFile(filepath.Join(gitDir, ".git", "HEAD"), []byte("2222222222222222222222222222222222222222\n"), 0o644); err != nil {
			t.Fatalf("WriteFile detached HEAD: %v", err)
		}
		if err := os.WriteFile(filepath.Join(gitDir, ".git", "refs", "heads", "main"), []byte("3333333333333333333333333333333333333333\n"), 0o644); err != nil {
			t.Fatalf("WriteFile mutated main ref: %v", err)
		}
		if err := os.WriteFile(filepath.Join(gitDir, "dirty.tmp"), []byte(clHash), 0o644); err != nil {
			t.Fatalf("WriteFile dirty.tmp: %v", err)
		}
		if gotFP := view.fingerprintLocked(subj, curCl); gotFP != staticFP {
			t.Fatalf("VCS commit/dirty mutation altered fingerprintLocked: before=%+v after=%+v", staticFP, gotFP)
		}
		if gotVerdict := decide(rec, cl, guards, rt, CodeResult, testPurityAuthority(true)); gotVerdict != verdictBeforeVCS {
			t.Fatalf("VCS commit/dirty mutation altered decide: before=%+v after=%+v", verdictBeforeVCS, gotVerdict)
		}

		if _, err := view.attachRuntimeState(subj, rec, &rt, true); err == nil {
			t.Fatal("attachRuntimeState accepted uncaptured observation proof")
		}
		extended, _, rejVerdict, err := view.prepareInertExtension(rec, ledger, subj)
		if err != nil || rejVerdict.Status != "" {
			t.Fatalf("prepareInertExtension failed on identical empty ledgers: verdict=%+v err=%v", rejVerdict, err)
		}
		if extended.TestVariantClosure != tv1 || extended.EffectiveTestVariantClosure() != tv2 || extended.MaximalClosure != rec.MaximalClosure || extended.ObservationProof != rec.ObservationProof || extended.RuntimeInputs != rec.RuntimeInputs || extended.RuntimeDigest != rec.RuntimeDigest {
			t.Fatalf("prepareInertExtension mutated producing fields: before=%+v after=%+v", rec, extended)
		}
		unknownApp := extended
		unknownApp.InertTestVariantApplicability.Strategy = "unknown/strategy@1"
		if v, failed := recordedEvidenceVerdict(unknownApp, curCl); !failed || v.Status != Stale || v.Ground.Cause.Condition != Unsupported {
			t.Fatalf("unknown applicability strategy not refused as Stale/Unsupported: %+v", v)
		}
	})
}

// FuzzPreparationAndUnitCoherence is a property witness for
// REQ-fresh-preparation, REQ-fresh-coherent-view, REQ-fresh-unit-bindings,
// and REQ-fresh-unit-exclusion.
func FuzzPreparationAndUnitCoherence(f *testing.F) {
	f.Add("example.com/p", "F", "Unknown1", "Unknown2", "D1", "D2", true)
	f.Add("example.com/q", "G", "MissingA", "MissingB", "DA", "DB", false)
	f.Fuzz(func(t *testing.T, pkg, knownSym, unk1, unk2, d1, d2 string, hasShapeErr bool) {
		if pkg == "" {
			pkg = "example.com/p"
		}
		if knownSym == "" {
			knownSym = "F"
		}
		if unk1 == "" || unk1 == knownSym {
			unk1 = knownSym + "_unk1"
		}
		if unk2 == "" || unk2 == knownSym || unk2 == unk1 {
			unk2 = knownSym + "_unk2"
		}
		sKnown := Subject{Package: pkg, Symbol: knownSym}
		sUnk1 := Subject{Package: pkg, Symbol: unk1}
		sUnk2 := Subject{Package: pkg, Symbol: unk2}

		view := &Snapshot{
			subjects: []Subject{sKnown},
			packages: []string{pkg},
			kind:     Measurement,
			facts: &observationFacts{
				guards:               guard.Guards{Toolchain: "tc", BuildConfig: "bc"},
				maximal:              map[Subject]subjectFacts{sKnown: {}},
				sourceFiles:          []string{"a.go"},
				sourceFilesBySubject: map[Subject][]string{sKnown: {"a.go"}},
				fileDigests:          map[string]string{"a.go": "h1"},
			},
		}
		goodFP := Fingerprint{
			MaximalClosure:       "C",
			ToolchainContent:     "stdlib",
			TestVariantClosure:   "T",
			DynamicStateStrategy: DynamicStateStrategy,
			ClosureStrategy:      ClosureStrategy,
			Guards:               guard.Guards{Toolchain: "tc", BuildConfig: "bc", Machine: "m", RuntimeConfig: "rc"},
			RuntimeInputs:        "M",
			RuntimeDigest:        d1,
			ResultKind:           Measurement,
		}
		wrongKindFP := goodFP
		wrongKindFP.ResultKind = CodeResult
		wrongKindFP.Guards.Machine = ""
		wrongKindFP.Guards.RuntimeConfig = ""

		badShapeFP := goodFP
		badShapeFP.ResultKind = Kind(99)

		// Tier 1 (Shape) precedes Tier 2 (Kind) and Tier 3 (Membership) (REQ-fresh-preparation).
		candidates := []Candidate{
			{Subject: sUnk1, Recorded: goodFP},
			{Subject: sKnown, Recorded: wrongKindFP},
		}
		if hasShapeErr {
			candidates = append(candidates, Candidate{Subject: sUnk2, Recorded: badShapeFP})
		}
		prepErr := view.prepareCandidates(candidates)
		var batchErr *RecordedBatchError
		if !errors.As(prepErr, &batchErr) {
			t.Fatalf("prepareCandidates err = %v, want *RecordedBatchError", prepErr)
		}
		if hasShapeErr && batchErr.Tier != RecordShapeRefusal {
			t.Fatalf("shape error did not win tier precedence: %+v", batchErr)
		}
		if !hasShapeErr && batchErr.Tier != RecordKindRefusal {
			t.Fatalf("kind error did not win over unknown subject: %+v", batchErr)
		}

		// Tier 3 deduplicates unknown subjects in request order.
		unkCandidates := []Candidate{
			{Subject: sUnk2, Recorded: goodFP},
			{Subject: sKnown, Recorded: goodFP},
			{Subject: sUnk1, Recorded: goodFP},
			{Subject: sUnk2, Recorded: goodFP},
		}
		unkErr := view.prepareCandidates(unkCandidates)
		var unknown *UnknownSubjectsError
		if !errors.As(unkErr, &unknown) || !slices.Equal(unknown.Subjects, []Subject{sUnk2, sUnk1}) {
			t.Fatalf("unknown subjects = %+v (%v), want [%+v %+v]", unknown, unkErr, sUnk2, sUnk1)
		}

		// Unit bindings & foreign handle refusal (REQ-fresh-unit-bindings).
		u1 := &Unit{snapshot: view, view: view}
		u2 := &Unit{snapshot: view, view: view}
		if _, err := u1.Register(context.Background(), BuildBinding{snapshot: &Snapshot{}, pkg: pkg, identity: "id"}, ProcessDescription{Identity: "p"}); err == nil {
			t.Fatal("Register accepted BuildBinding from foreign snapshot")
		}
		if _, err := u1.Register(context.Background(), BuildBinding{snapshot: view, pkg: pkg + "_other", identity: "id"}, ProcessDescription{Identity: "p"}); err == nil {
			t.Fatal("Register accepted BuildBinding from foreign package")
		}
		exec := &unitExecution{ready: true}
		u1.execution = exec
		foreignContrib := Contribution{unit: u2, execution: exec}
		if err := u1.Submit(foreignContrib, Terminal{Kind: NormalCompletion}); err == nil {
			t.Fatal("Submit accepted foreign unit's contribution")
		}
		ownContrib := Contribution{unit: u1, execution: exec}
		if err := u1.Submit(ownContrib, Terminal{Kind: NormalCompletion, Reason: "unexpected"}); err == nil {
			t.Fatal("Submit accepted NormalCompletion with non-empty reason")
		}
		if err := u1.Submit(ownContrib, Terminal{Kind: AbnormalCompletion, Reason: ""}); err == nil {
			t.Fatal("Submit accepted AbnormalCompletion with empty reason")
		}

		// Runtime motion & hold-still exclusion (REQ-fresh-coherent-view, REQ-fresh-unit-exclusion).
		sBefore := runtimeinput.State{Manifest: "M", Digest: d1, OK: true}
		sAfter := runtimeinput.State{Manifest: "M", Digest: d2, OK: true}
		cand := Candidate{Subject: sKnown, Recorded: goodFP}
		movedVerdict := view.runtimeMotion(context.Background(), cand, Verdict{Status: Valid}, sBefore, sAfter)
		if d1 != d2 && (movedVerdict.Status != Stale || movedVerdict.Ground.Cause.Kind != RuntimeInputsCause) {
			t.Fatalf("runtimeMotion did not stale on moved digest (%q != %q): %+v", d1, d2, movedVerdict)
		}
		if d1 == d2 && movedVerdict.Status != Valid {
			t.Fatalf("runtimeMotion staled on unchanged state: %+v", movedVerdict)
		}
		var held error
		unavailErr := unavailableReason("cut")
		if err := deferValidationUnavailability(errors.Join(ErrAnalysisUnavailable, errors.New(unavailErr)), &held); err != nil || held == nil {
			t.Fatalf("deferValidationUnavailability did not hold ErrAnalysisUnavailable: err=%v held=%v", err, held)
		}
		if err := deferValidationUnavailability(ErrViewChanged, &held); !errors.Is(err, ErrViewChanged) {
			t.Fatalf("concrete ErrViewChanged did not outrank held unavailability: %v", err)
		}
	})
}

// This property starts at the admitted-facts decision layer. It does not issue
// producing support or assert that arbitrary text is a canonical stored record.
// Diagnostic changes must preserve the decision and every accepted authority.
func FuzzJudgmentDiagnosticIndependence(f *testing.F) {
	for _, text := range []string{"", "a different cause", sharedDynamicStatePrefix + "not semantic authority", "runtimeinputs", "test variants"} {
		f.Add(text)
	}
	f.Fuzz(func(t *testing.T, text string) {
		guards := guard.Guards{Toolchain: "toolchain", BuildConfig: "build"}
		recorded := Fingerprint{MaximalClosure: "core", TestVariantClosure: "tests", ToolchainContent: "stdlib", AdmissionPolicy: "policy", Guards: guards, RuntimeInputs: "already-validated manifest", RuntimeDigest: "digest", ResultKind: CodeResult}
		for _, origin := range []closure.RefusalKind{closure.DependenceRefusal, closure.OpenWorldRefusal, closure.SharedDynamicStateRefusal, closure.AmbiguousSubjectRefusal} {
			for mask := 0; mask < 16; mask++ {
				cl := closure.Closure{Hash: "core", TestVariants: "tests", ToolchainContent: "stdlib", AdmissionPolicy: "policy", Unverifiable: true, Refusal: origin, Reason: "original diagnostic"}
				state := runtimeinput.State{OK: true, Digest: "digest", Unverifiable: mask&1 != 0, BracketMoved: mask&8 != 0, Reason: "original runtime diagnostic"}
				var observation ObservationAuthority
				if mask&2 != 0 {
					observation = ObservationAuthority{Assertion: "caller assertion", ProofStrategy: ObservationRTA, OutcomeMethod: outcome.Method}
				}
				purity := testPurityAuthority(mask&4 != 0)
				before := decideAfterClosureObserved(recorded, cl, guards, state, CodeResult, purity, observation)
				if state.BracketMoved && (before.Status != Stale || before.Ground.Cause != (Cause{Kind: RuntimeInputsCause, Condition: Changed}) || before.Ground.Accepted != (AcceptedAuthority{})) {
					t.Fatalf("movement waived by authority mask %d: %+v", mask, before)
				}
				cl.Reason, state.Reason = text, text
				after := decideAfterClosureObserved(recorded, cl, guards, state, CodeResult, purity, observation)
				before.Reason, after.Reason = "", ""
				if before != after {
					t.Fatalf("diagnostic changed semantic judgment: origin=%d inputs=%d text=%q before=%+v after=%+v", origin, mask, text, before, after)
				}
			}
		}
	})
}

func testPurityAuthority(enabled bool) PurityAuthority {
	if enabled {
		return PurityAuthority{Recorded: CallerPurity, Current: CallerPurity}
	}
	return PurityAuthority{}
}

// This fixture supplies stored evidence under the native wire grammar. It tests
// admission/checking, not the producer's independent execution-premise issuer.
func judgmentFixture(t *testing.T) (*Snapshot, Subject, Fingerprint, runtimeinput.State) {
	t.Helper()
	subject := Subject{Package: "example.com/judgment", Symbol: "F"}
	fp := Fingerprint{
		MaximalClosure: "core", TestVariantClosure: "tests", ToolchainContent: "stdlib", AdmissionPolicy: "policy",
		DynamicStateStrategy: DynamicStateStrategy, ClosureStrategy: ClosureStrategy, ResultKind: CodeResult,
		Guards:               guard.Guards{Toolchain: "toolchain", BuildConfig: "build"},
		ObservationAssertion: "caller assertion",
		ObservationProof:     ObservationProof{Strategy: ObservationRTA, Subject: subject, Observable: true},
	}
	fp.ObservationProof.Evidence = observationProofEvidence(fp)
	manifest, err := json.Marshal(struct {
		Version  int      `json:"v"`
		Outcome  string   `json:"outcome"`
		Subjects []string `json:"subjects"`
	}{4, outcome.Method, []string{outcomeSubject(fp, subject)}})
	if err != nil {
		t.Fatal(err)
	}
	fp.RuntimeInputs = base64.RawURLEncoding.EncodeToString(manifest)
	state, err := runtimeinput.Current(t.Context(), fp.RuntimeInputs, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	fp.RuntimeDigest = state.Digest
	cl := closure.Closure{Hash: fp.MaximalClosure, TestVariants: fp.TestVariantClosure, ToolchainContent: fp.ToolchainContent, AdmissionPolicy: fp.AdmissionPolicy, Unverifiable: true, Reason: "diagnostic only"}
	v := &Snapshot{
		session: &engine{deferredCheckClose: true, executionModel: SingleSubjectExecution},
		kind:    CodeResult, subjects: []Subject{subject},
		facts: &observationFacts{maximal: map[Subject]subjectFacts{subject: testSubjectFacts(cl)}, guards: fp.Guards,
			purity: map[Subject]string{}, vouchDischarges: map[Subject]string{subject: "dependency.Current"},
			discharges: map[Subject]attestationDischarges{subject: {singleSubject: "dependency.Single", packageProcess: "dependency.Package"}}},
		runtimeCurrent: func(context.Context, string, string) (runtimeinput.State, error) { return state, nil },
	}
	return v, subject, fp, state
}

func TestJudgmentAuthorityAndScope(t *testing.T) {
	for _, tc := range []struct {
		name     string
		change   func(*Snapshot, Subject, *Fingerprint)
		status   Status
		cause    CauseKind
		purity   PurityAuthority
		observed bool
	}{
		{name: "observation conjunction", status: Valid, observed: true},
		{name: "purity is independent of invalid proof", change: func(v *Snapshot, s Subject, f *Fingerprint) {
			f.PurityAssertion = "caller assertion"
			v.facts.purity[s] = "source directive"
			f.ObservationProof.Evidence = "invalid"
		}, status: Valid, purity: PurityAuthority{Recorded: CallerPurity, Current: SourcePurity}},
		{name: "invalid proof", change: func(_ *Snapshot, _ Subject, f *Fingerprint) { f.ObservationProof.Evidence = "invalid" }, status: Unverifiable, cause: ClosureDependenceCause},
		{name: "wrong proof subject", change: func(_ *Snapshot, _ Subject, f *Fingerprint) {
			f.ObservationProof.Subject.Symbol = "G"
			f.ObservationProof.Evidence = observationProofEvidence(*f)
		}, status: Unverifiable, cause: ClosureDependenceCause},
		{name: "missing completeness assertion", change: func(_ *Snapshot, _ Subject, f *Fingerprint) {
			f.ObservationAssertion = ""
			f.ObservationProof.Evidence = observationProofEvidence(*f)
		}, status: Unverifiable, cause: ClosureDependenceCause},
		{name: "policy movement", change: func(v *Snapshot, s Subject, _ *Fingerprint) {
			cl := v.facts.closure(s)
			cl.AdmissionPolicy = "new"
			v.facts.maximal[s] = testSubjectFacts(cl)
		}, status: Unverifiable, cause: ClosureDependenceCause},
		{name: "external dominates assertions", change: func(v *Snapshot, s Subject, f *Fingerprint) {
			cl := v.facts.closure(s)
			cl.External = true
			v.facts.maximal[s] = testSubjectFacts(cl)
			f.PurityAssertion = "caller assertion"
			v.facts.purity[s] = "caller assertion"
		}, status: Unverifiable, cause: ExternalDirectiveCause},
		{name: "guard drift dominates external", change: func(v *Snapshot, s Subject, f *Fingerprint) {
			cl := v.facts.closure(s)
			cl.External = true
			v.facts.maximal[s] = testSubjectFacts(cl)
			f.Guards.BuildConfig = "moved"
		}, status: Stale, cause: BuildConfigCause},
		{name: "source mismatch skips all authority", change: func(_ *Snapshot, _ Subject, f *Fingerprint) { f.MaximalClosure = "moved" }, status: Stale, cause: ClosureCause},
		{name: "ordinary proof needs no observation", change: func(v *Snapshot, s Subject, f *Fingerprint) {
			cl := v.facts.closure(s)
			cl.Unverifiable = false
			v.facts.maximal[s] = testSubjectFacts(cl)
			f.RuntimeInputs, f.RuntimeDigest = "", ""
		}, status: Valid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, subject, fp, _ := judgmentFixture(t)
			// Historical discharges are deliberately different from current
			// accepted ones: copying record fields must fail this test.
			fp.DynamicStateVouches, fp.SingleSubjectDischarges, fp.PackageProcessDischarges = "old.V", "old.S", "old.P"
			if tc.change != nil {
				tc.change(v, subject, &fp)
			}
			before, err := json.Marshal(fp)
			if err != nil {
				t.Fatal(err)
			}
			got, err := v.CheckObserved(t.Context(), fp, subject)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != tc.status || got.Ground.Cause.Kind != tc.cause {
				t.Fatalf("judgment = %+v", got)
			}
			wantScope := JudgmentScope{Subject: subject, ResultKind: CodeResult, ExecutionModel: SingleSubjectExecution}
			if got.Ground.Scope != wantScope {
				t.Fatalf("scope = %+v, want %+v", got.Ground.Scope, wantScope)
			}
			a := got.Ground.Accepted
			if a.Purity != tc.purity || a.Observation.accepted() != tc.observed {
				t.Fatalf("authority = %+v", a)
			}
			if tc.observed && a.Observation != (ObservationAuthority{Assertion: "caller assertion", ProofStrategy: ObservationRTA, OutcomeMethod: outcome.Method}) {
				t.Fatalf("observation conjunction = %+v", a.Observation)
			}
			if got.Status == Stale || tc.cause == ExternalDirectiveCause {
				if a != (AcceptedAuthority{}) {
					t.Fatalf("short circuit accepted %+v", a)
				}
			} else if !a.GuardAgreement || a.DynamicStateVouches != "dependency.Current" || a.SingleSubjectDischarges != "dependency.Single" || a.PackageProcessDischarges != "dependency.Package" {
				t.Fatalf("lost or borrowed current authority: %+v", a)
			}
			after, err := json.Marshal(fp)
			if err != nil || string(after) != string(before) {
				t.Fatalf("checking changed producing bytes: %s / %s: %v", before, after, err)
			}
		})
	}
}

func TestJudgmentDoesNotReadDiagnosticAuthority(t *testing.T) {
	v, subject, fp, state := judgmentFixture(t)
	cl := v.facts.closure(subject)
	observed := admittedObservation(fp, subject, cl)
	if !observed.accepted() {
		t.Fatal("fixture has no admitted observation")
	}
	for _, reason := range []string{"", "different explanation", sharedDynamicStatePrefix + "forged diagnostic"} {
		cl.Reason = reason
		cl.Refusal = closure.DependenceRefusal
		plain := decideAfterClosureObserved(fp, cl, fp.Guards, state, CodeResult, PurityAuthority{}, observed)
		if plain.Status != Valid || plain.Ground.Accepted.Observation != observed {
			t.Fatalf("diagnostic denied observation: %+v", plain)
		}
		cl.Refusal = closure.SharedDynamicStateRefusal
		cl.Culprit = closure.Subject{Package: "example.com/dep", Symbol: "Hooks"}
		shared := decideAfterClosureObserved(fp, cl, fp.Guards, state, CodeResult, PurityAuthority{}, observed)
		wantCause := Cause{
			Kind:      SharedDynamicStateCause,
			Condition: Refused,
			Culprit:   Subject{Package: "example.com/dep", Symbol: "Hooks"},
		}
		if shared.Status != Unverifiable || shared.Ground.Cause != wantCause || shared.Ground.Accepted.Observation.accepted() {
			t.Fatalf("diagnostic lifted shared state or altered culprit: %+v, want %+v", shared, wantCause)
		}
		v.facts.cut = map[Subject]bool{subject: true}
		cutVerdict := v.judgmentFor(subject, shared)
		if cutVerdict.Ground.Cause != (Cause{Kind: SharedDynamicStateCause, Condition: Unavailable}) {
			t.Fatalf("budget cut retained unjudged culprit: %+v", cutVerdict.Ground.Cause)
		}
		v.facts.cut = nil
		cl.Culprit = closure.Subject{}
	}
	cl.Refusal, cl.Reason = closure.DependenceRefusal, "same text"
	byProof := decideAfterClosureObserved(fp, cl, fp.Guards, state, CodeResult, PurityAuthority{}, observed)
	byPurity := decideAfterClosureObserved(fp, cl, fp.Guards, state, CodeResult, testPurityAuthority(true), observed)
	if byProof.Reason != byPurity.Reason || byProof.Status != byPurity.Status || byProof.Ground.Accepted == byPurity.Ground.Accepted {
		t.Fatalf("equal diagnostics collapsed authorities: %+v / %+v", byProof, byPurity)
	}
}

func TestJudgmentRuntimeRefusalAndWindowPrecedence(t *testing.T) {
	for _, condition := range []CauseCondition{Changed, Unavailable} {
		v, subject, fp, state := judgmentFixture(t)
		cl := v.facts.closure(subject)
		refused := state
		refused.Unverifiable, refused.Reason = true, "same text"
		proof := admittedObservation(fp, subject, cl)
		got := decideAfterClosureObserved(fp, cl, fp.Guards, refused, CodeResult, PurityAuthority{}, proof)
		if got.Status != Unverifiable || got.Ground.Cause.Kind != RuntimeInputsCause || got.Ground.Accepted.Observation.accepted() {
			t.Fatalf("proof lifted runtime refusal: %+v", got)
		}
		pure := decideAfterClosureObserved(fp, cl, fp.Guards, refused, CodeResult, testPurityAuthority(true), proof)
		if pure.Status != Valid || !pure.Ground.Accepted.Purity.accepted() || pure.Ground.Accepted.Observation.accepted() {
			t.Fatalf("purity relabeled runtime refusal: %+v", pure)
		}
		v.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
			if condition == Unavailable {
				return runtimeinput.State{}, nil
			}
			after := state
			after.Digest = "moved"
			return after, nil
		}
		for _, prior := range []Verdict{got, pure, decideAfterClosureObserved(fp, cl, fp.Guards, state, CodeResult, PurityAuthority{}, proof)} {
			finished, err := v.finishRuntimeObservation(t.Context(), map[Subject]Fingerprint{subject: fp}, map[Subject]runtimeinput.State{subject: state}, map[Subject]Verdict{subject: prior})
			if err != nil {
				t.Fatal(err)
			}
			actual := finished[subject]
			if actual.Status != Stale || actual.Ground.Cause != (Cause{Kind: RuntimeInputsCause, Condition: condition}) || actual.Ground.Accepted != (AcceptedAuthority{}) {
				t.Fatalf("late window retained authority: %+v", actual)
			}
		}
		stale := refusal(Stale, BuildConfigCause, Changed, "any diagnostic")
		finished, err := v.finishRuntimeObservation(t.Context(), map[Subject]Fingerprint{subject: fp}, map[Subject]runtimeinput.State{subject: state}, map[Subject]Verdict{subject: stale})
		if err != nil || finished[subject] != v.judgmentFor(subject, stale) {
			t.Fatalf("late window overrode prior staleness: %+v %v", finished, err)
		}
	}
}

func TestJudgmentGuardConditions(t *testing.T) {
	v, subject, base, state := judgmentFixture(t)
	cl := v.facts.closure(subject)
	for _, tc := range []struct {
		name   string
		change func(*Fingerprint, *runtimeinput.State)
		cause  Cause
	}{
		{"missing toolchain", func(f *Fingerprint, _ *runtimeinput.State) { f.Guards.Toolchain = "" }, Cause{Kind: ToolchainCause, Condition: Missing}},
		{"changed toolchain", func(f *Fingerprint, _ *runtimeinput.State) { f.Guards.Toolchain = "other" }, Cause{Kind: ToolchainCause, Condition: Changed}},
		{"missing digest", func(f *Fingerprint, _ *runtimeinput.State) { f.RuntimeDigest = "" }, Cause{Kind: RuntimeInputsCause, Condition: Missing}},
		{"changed digest", func(f *Fingerprint, _ *runtimeinput.State) { f.RuntimeDigest = "other" }, Cause{Kind: RuntimeInputsCause, Condition: Changed}},
		{"unavailable runtime", func(_ *Fingerprint, r *runtimeinput.State) { r.OK = false }, Cause{Kind: RuntimeInputsCause, Condition: Unavailable}},
		{"missing core", func(f *Fingerprint, _ *runtimeinput.State) { f.MaximalClosure = "" }, Cause{Kind: ClosureCause, Condition: Missing}},
		{"changed core", func(f *Fingerprint, _ *runtimeinput.State) { f.MaximalClosure = "other" }, Cause{Kind: ClosureCause, Condition: Changed}},
		{"unsupported endpoint", func(f *Fingerprint, _ *runtimeinput.State) {
			f.InertTestVariantApplicability = InertTestVariantApplicability{Strategy: "unknown", TestVariantClosure: "tests"}
		}, Cause{Kind: TestVariantsCause, Condition: Unsupported}},
		{"missing strategy", func(f *Fingerprint, _ *runtimeinput.State) { f.DynamicStateStrategy = "" }, Cause{Kind: DynamicStateStrategyCause, Condition: Missing}},
		{"unsupported strategy", func(f *Fingerprint, _ *runtimeinput.State) { f.DynamicStateStrategy = "unknown" }, Cause{Kind: DynamicStateStrategyCause, Condition: Unsupported}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fp, rt := base, state
			tc.change(&fp, &rt)
			got := decide(fp, cl, v.facts.guards, rt, CodeResult, testPurityAuthority(true))
			if got.Status != Stale || got.Ground.Cause != tc.cause || got.Ground.Accepted != (AcceptedAuthority{}) {
				t.Fatalf("guard judgment = %+v, want %+v", got, tc.cause)
			}
		})
	}
}

func TestJudgmentBatchEqualsSingleAndSibling(t *testing.T) {
	v, subject, fp, _ := judgmentFixture(t)
	other := Subject{Package: subject.Package, Symbol: "G"}
	v.subjects = append(v.subjects, other)
	v.facts.maximal[other] = v.facts.maximal[subject]
	recorded := map[Subject]Fingerprint{subject: fp, other: fp}
	batch, err := v.CheckObservedBatch(t.Context(), recorded)
	if err != nil {
		t.Fatal(err)
	}
	for s, rec := range recorded {
		single, err := v.CheckObserved(t.Context(), rec, s)
		if err != nil || single != batch[s] {
			t.Fatalf("single/batch disagree: %+v / %+v: %v", single, batch[s], err)
		}
		sibling, err := v.Sibling([]Subject{s, s})
		if err != nil {
			t.Fatal(err)
		}
		projected, err := sibling.CheckObserved(t.Context(), rec, s)
		if err != nil || projected != single {
			t.Fatalf("sibling lost ground: %+v / %+v: %v", projected, single, err)
		}
	}
	if batch[subject].Status != Valid || batch[other].Status != Unverifiable {
		t.Fatalf("fixture did not distinguish exact subject support: %+v", batch)
	}
}

func TestJudgmentApplicabilityNeedsCurrentProofAndOriginalSupport(t *testing.T) {
	for _, tc := range []struct {
		name     string
		current  closure.Observability
		original string
		valid    bool
	}{
		{"current derivation", closure.Observability{Observable: true, OutcomeMethod: outcome.Method}, "supported", true},
		{"no current outcome inventory", closure.Observability{Observable: true}, "supported", false},
		{"current proof refused", closure.Observability{Reason: "opaque refusal"}, "supported", false},
		{"current proof cannot supply original support", closure.Observability{Observable: true, OutcomeMethod: outcome.Method}, "identity-only", false},
		{"current proof cannot supply missing capture", closure.Observability{Observable: true, OutcomeMethod: outcome.Method}, "absent", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, subject, fp, _ := judgmentFixture(t)
			fp.InertTestVariantApplicability = InertTestVariantApplicability{Strategy: InertTestVariantExtension, TestVariantClosure: fp.TestVariantClosure}
			v.observable = map[Subject]closure.Observability{subject: tc.current}
			if tc.original == "absent" {
				fp.RuntimeInputs, fp.RuntimeDigest = "", ""
			} else if tc.original == "identity-only" {
				// Preserve a readable manifest and matching digest. Removing the
				// entire manifest would let the independent nonempty-manifest
				// guard hide a missing outcome-support admission check.
				fp.RuntimeInputs = base64.RawURLEncoding.EncodeToString([]byte(`{"v":4}`))
				state, err := runtimeinput.Current(t.Context(), fp.RuntimeInputs, t.TempDir(), nil)
				if err != nil || !state.OK || state.Unverifiable {
					t.Fatalf("identity-only control is not usable guard evidence: %+v %v", state, err)
				}
				fp.RuntimeDigest = state.Digest
				v.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) { return state, nil }
			}
			got, err := v.CheckObserved(t.Context(), fp, subject)
			if err != nil {
				t.Fatal(err)
			}
			a := got.Ground.Accepted
			if (got.Status == Valid) != tc.valid || a.Observation.CurrentApplicability != tc.valid {
				t.Fatalf("applicability authority = %+v", got)
			}
			if tc.valid {
				if len(v.applicabilityChecks) != 1 || a.Applicability != fp.InertTestVariantApplicability || a.Observation.ProofStrategy != fp.ObservationProof.Strategy {
					t.Fatalf("lost producing or current obligations: %+v %+v", got, v.applicabilityChecks)
				}
			} else if a.Observation != (ObservationAuthority{}) || a.Applicability != (InertTestVariantApplicability{}) || len(v.applicabilityChecks) != 0 {
				t.Fatalf("refused extension gained authority: %+v %+v", got, v.applicabilityChecks)
			}
		})
	}
}

func TestMembershipRefusalsCollectOrderedSubjectsAndScope(t *testing.T) {
	known := Subject{Package: "p", Symbol: "Known"}
	a, b := Subject{Package: "p", Symbol: "A"}, Subject{Package: "p", Symbol: "B"}
	v := &Snapshot{subjects: []Subject{known}, facts: &observationFacts{maximal: map[Subject]subjectFacts{known: {}}}}
	for _, tc := range []struct{ request, want []Subject }{
		{[]Subject{b, known, a, b, a}, []Subject{b, a}},
		{[]Subject{a, a, known, b, known}, []Subject{a, b}},
	} {
		child, err := v.Sibling(tc.request)
		var unknown *UnknownSubjectsError
		if child != nil || !errors.As(err, &unknown) || unknown.Scope != ParentView || !slices.Equal(unknown.Subjects, tc.want) {
			t.Fatalf("sibling refusal = %+v %v, want %+v", child, err, tc.want)
		}
		if strings.Contains(err.Error(), "selected source") {
			t.Fatalf("selection refusal asserts declaration absence: %v", err)
		}
		err = requireSubjects(tc.request, func(s Subject) bool { return s == known }, SelectedSource)
		if !errors.As(err, &unknown) || unknown.Scope != SelectedSource || !slices.Equal(unknown.Subjects, tc.want) {
			t.Fatalf("source refusal = %v", err)
		}
	}
	child, err := v.Sibling([]Subject{known, known})
	if err != nil || !slices.Equal(child.subjects, []Subject{known}) {
		t.Fatalf("known duplicate selection = %+v %v", child, err)
	}
	if child, err := v.Sibling(nil); err == nil || child != nil {
		t.Fatal("empty sibling accepted")
	}
}

func TestRecordedBatchPreparationHasDeterministicCompleteTiers(t *testing.T) {
	known := Subject{Package: "p", Symbol: "Known"}
	// Package and symbol are separate sorting axes: concatenated names can
	// collide for dotted import paths and method symbols.
	a := Subject{Package: "a", Symbol: "z.F"}
	b := Subject{Package: "a.z", Symbol: "F"}
	c := Subject{Package: "z", Symbol: "F"}
	d := Subject{Package: "z", Symbol: "G"}
	good := Fingerprint{ResultKind: CodeResult}
	wrongKind := Fingerprint{ResultKind: Measurement}
	malformed := Fingerprint{ResultKind: Kind(99)}
	v := &Snapshot{session: &engine{}, kind: CodeResult, facts: &observationFacts{maximal: map[Subject]subjectFacts{known: {}}}}
	work := 0
	oldWindow := viewTestHooks.runtimeWindow
	viewTestHooks.runtimeWindow = func() { work++ }
	t.Cleanup(func() { viewTestHooks.runtimeWindow = oldWindow })
	v.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
		work++
		return runtimeinput.State{}, nil
	}
	v.beforePreciseAnalysis = func() { work++ }
	for _, check := range []struct {
		name string
		call func(context.Context, map[Subject]Fingerprint) (map[Subject]Verdict, error)
	}{{"ordinary", v.CheckBatch}, {"observed", v.CheckObservedBatch}} {
		for _, order := range [][]Subject{{known, a, b, c, d}, {d, c, b, a, known}, {b, known, d, a, c}} {
			for tier := 0; tier < 3; tier++ {
				t.Run(check.name+"/"+string(rune('0'+tier)), func(t *testing.T) {
					recorded := map[Subject]Fingerprint{}
					for _, subject := range order {
						recorded[subject] = good
						if tier <= 1 && (subject == a || subject == b) {
							recorded[subject] = wrongKind
						}
						if tier == 0 && (subject == c || subject == d) {
							recorded[subject] = malformed
						}
					}
					verdicts, err := check.call(t.Context(), recorded)
					if verdicts != nil || err == nil || work != 0 {
						t.Fatalf("preparation paid work/returned partials: %+v %v work=%d", verdicts, err, work)
					}
					if tier == 2 {
						var unknown *UnknownSubjectsError
						if !errors.As(err, &unknown) || unknown.Scope != SelectedView || !slices.Equal(unknown.Subjects, []Subject{a, b, c, d}) {
							t.Fatalf("membership = %v", err)
						}
						return
					}
					var batch *RecordedBatchError
					if !errors.As(err, &batch) {
						t.Fatalf("untyped record refusal: %v", err)
					}
					wantTier, wantSubjects := RecordShapeRefusal, []Subject{c, d}
					if tier == 1 {
						wantTier, wantSubjects = RecordKindRefusal, []Subject{a, b}
					}
					var subjects []Subject
					for _, failure := range batch.Failures {
						subjects = append(subjects, failure.Subject)
					}
					if batch.Tier != wantTier || !slices.Equal(subjects, wantSubjects) {
						t.Fatalf("tier/set = %+v, want %v %+v", batch, wantTier, wantSubjects)
					}
					if tier == 0 && len(batch.Unwrap()) != 2 {
						t.Fatal("lost original shape refusals")
					}
				})
			}
		}
	}
	// Empty maps retain the successful empty-batch behavior.
	prepared, err := v.CheckBatch(t.Context(), nil)
	if err != nil || !reflect.DeepEqual(prepared, map[Subject]Verdict{}) {
		t.Fatalf("empty preparation = %+v %v", prepared, err)
	}
}

// TestDriftRefusalComponents pins the refusal vocabulary: guard drift names
// the guard, observability drift names both dispositions, and the mover
// summary stays bounded.
func TestDriftRefusalComponents(t *testing.T) {
	if got := differingGuard(guard.Guards{BuildConfig: "a"}, guard.Guards{BuildConfig: "b"}); got != "buildconfig" {
		t.Fatalf("differingGuard = %q, want buildconfig", got)
	}
	if got := differingGuard(guard.Guards{}, guard.Guards{}); got != "guards" {
		t.Fatalf("equal guards = %q, want the bare fallback", got)
	}
	err := compareObservationProof(Subject{Package: "p", Symbol: "S"},
		closure.Observability{Observable: false, Reason: "reaches os.Open"},
		closure.Observability{Observable: true})
	if err == nil || !strings.Contains(err.Error(), "captured observable, now not observable: reaches os.Open") {
		t.Fatalf("proof drift = %v, want both dispositions named", err)
	}
}

// Every phase the engine emits is one of the classified ones — a unit,
// a fact, or a diagnostic — and every unit and diagnostic phase is
// emitted somewhere: a phase added to an emitter and not to the set
// fails here, never in a consumer's silent stretch. The walk reads the
// five emitter shapes (emitProgress, emitUnit, emitDiagnostic, Unit,
// and a Progress literal's Phase) from the sources on disk — a
// hand-edit oracle, so its logic is pinned over synthetic sources
// below.
func TestEveryEmittedPhaseIsClassified(t *testing.T) {
	facts := []string{"served", "cancelled", "budget-exhausted"}
	diagnostics := []string{"toolchain-unaudited", "analysis-unavailable", "listing-unmodelled"}
	units := []string{"list", "typecheck", "load", "hash", "observe", "runtime", "prove"}
	emitted, err := emittedPhases(".")
	if err != nil {
		t.Fatal(err)
	}
	classified := slices.Concat(units, facts, diagnostics)
	for phase := range emitted {
		if !slices.Contains(classified, phase) {
			t.Errorf("phase %q is emitted and classified nowhere", phase)
		}
	}
	for _, phase := range slices.Concat(units, diagnostics) {
		if !emitted[phase] {
			t.Errorf("phase %q is emitted by no site the walk reads", phase)
		}
	}
}

// The walk's logic over synthetic sources: every emitter shape is read,
// a test file and a fixture directory are not.
//
//gofresh:pure
func TestEmittedPhaseWalkReadsEveryEmitterShape(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.go", `package a
func f(h H, e E) {
	h.emitProgress("p1", "")
	h.emitUnit("p2", "", 0, 1)
	h.emitDiagnostic("p3", "", "")
	h.Unit("p4", "", 0, 1)
	e.progress(Progress{Phase: "p5"})
	e.progress(gofresh.Progress{Phase: "p6", Package: "x"})
	h.other("p7")
}
`)
	write("a_test.go", "package a\nfunc g(h H) { h.emitProgress(\"t1\", \"\") }\n")
	write("fixtures/b.go", "package b\nfunc g(h H) { h.emitProgress(\"f1\", \"\") }\n")
	got, err := emittedPhases(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"p1", "p2", "p3", "p4", "p5", "p6"} {
		if !got[want] {
			t.Errorf("%s not read", want)
		}
	}
	for _, skip := range []string{"p7", "t1", "f1"} {
		if got[skip] {
			t.Errorf("%s read though it is no emitter (or a test/fixture)", skip)
		}
	}
}

// emittedPhases walks the non-test Go sources under root for every
// phase literal the five emitter shapes carry.
func emittedPhases(root string) (map[string]bool, error) {
	emitted := map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "fixtures") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				sel, ok := n.Fun.(*ast.SelectorExpr)
				if !ok || len(n.Args) == 0 {
					return true
				}
				if name := sel.Sel.Name; name == "emitProgress" || name == "emitUnit" || name == "emitDiagnostic" || name == "Unit" {
					if lit, ok := n.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						emitted[strings.Trim(lit.Value, "\"")] = true
					}
				}
			case *ast.CompositeLit:
				named := false
				switch typ := n.Type.(type) {
				case *ast.Ident:
					named = typ.Name == "Progress"
				case *ast.SelectorExpr:
					named = typ.Sel.Name == "Progress"
				}
				if !named {
					return true
				}
				for _, elt := range n.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Phase" {
						if lit, ok := kv.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
							emitted[strings.Trim(lit.Value, "\"")] = true
						}
					}
				}
			}
			return true
		})
		return nil
	})
	return emitted, err
}

// The vouch set rule: parse-many, deduplicated, sorted; one malformed
// entry refuses the whole set.
//
//gofresh:pure
func TestParseVouchEntriesIsASet(t *testing.T) {
	got, err := ParseVouchEntries([]string{"b/pkg:Y", "a/pkg:X", "b/pkg:Y"})
	if err != nil || !reflect.DeepEqual(got, []string{"a/pkg.X", "b/pkg.Y"}) {
		t.Fatalf("set = %v, %v", got, err)
	}
	if _, err := ParseVouchEntries([]string{"a/pkg:X", "not an entry"}); err == nil || !strings.Contains(err.Error(), "not an entry") {
		t.Fatalf("a malformed entry did not refuse the set: %v", err)
	}
	if got, err := ParseVouchEntries(nil); err != nil || len(got) != 0 {
		t.Fatalf("empty = %v, %v", got, err)
	}
}

// The skew check compares language series only, on both sides: patch
// and vendor flavors of one series agree; a different series refuses
// naming both versions; an unidentifiable version on either side
// refuses (unidentifiable is not agreement).
func TestToolchainSkewComparesLanguageSeries(t *testing.T) {
	if err := ToolchainSkew(runtime.Version()); err != nil {
		t.Fatalf("self-comparison skewed: %v", err)
	}
	for _, agree := range [][2]string{
		{"go1.27.0", "go1.27.0-dst.10"},
		{"go1.27.0-dst.10", "go1.27.5"},
		{"go1.26.5-X:nodwarf5", "go1.26.0"},
		{"go1.27.0 linux/amd64", "go1.27.0"},
		{"go3.1.0", "go3.1.9"}, // any digit major: future series must agree with themselves
	} {
		if err := toolchainSkew(agree[0], agree[1]); err != nil {
			t.Fatalf("same-series %v skewed: %v", agree, err)
		}
	}
	// The exec-sampled shapes: a trailing newline (and CRLF) on a
	// STOCK string must identify — the flavored variant passes even
	// without trimming (the suffix swallows it), so the stock shape
	// is the real anchor.
	for _, sampled := range []string{"go1.27.0\n", "go1.27.0\r\n", "go1.27.0-dst.10\n"} {
		if got := gotool.LanguageSeries(sampled); got != "go1.27" {
			t.Fatalf("gotool.LanguageSeries(%q) = %q, want go1.27 — exec-sampled trailing whitespace must trim", sampled, got)
		}
	}
	// The current devel shape (cmd/dist emits "go1.NN-devel_<hash> <date>",
	// deliberately Lang-compatible) identifies through the space cut.
	if got := gotool.LanguageSeries("go1.28-devel_abc123 Wed Aug 20 10:00:00 2026 +0000"); got != "go1.28" {
		t.Fatalf("devel shape = %q, want go1.28", got)
	}
	err := toolchainSkew("go1.26.5-X:nodwarf5", "go1.27.0-dst.10")
	if err == nil || !strings.Contains(err.Error(), "go1.26") || !strings.Contains(err.Error(), "go1.27") {
		t.Fatalf("older-frontend skew = %v, want both series named", err)
	}
	// The refusal is DIRECTIONAL within a major: a newer frontend
	// reads older language under the Go 1 compatibility promise — the
	// declared-toolchain workflow (--toolchain go1.26.x under a
	// go1.27 binary) must pass.
	if err := toolchainSkew("go1.27.0-dst.10", "go1.26.5"); err != nil {
		t.Fatalf("newer frontend over older ambient refused: %v", err)
	}
	// Across majors the promise has no basis: refuse BOTH directions.
	if err := toolchainSkew("go3.0.1", "go1.27.0"); err == nil || !strings.Contains(err.Error(), "cross-major") {
		t.Fatalf("go3 frontend over go1 ambient = %v, want the cross-major refusal", err)
	}
	if err := toolchainSkew("go1.27.0", "go3.0.1"); err == nil || !strings.Contains(err.Error(), "cross-major") {
		t.Fatalf("go1 frontend over go3 ambient = %v, want the cross-major refusal", err)
	}
	// TWO unidentifiable versions are not an agreement of anything.
	if err := toolchainSkew("devel +abc", "devel +abc"); err == nil {
		t.Fatal("two unidentifiable versions read as agreement")
	}
	// Unidentifiable on EITHER side refuses.
	for _, bad := range []string{"", "devel +abc123", "1.27.0", "gogarbage"} {
		// The refusal names its true cause: an unidentifiable version
		// reads "unidentifiable", never a series mismatch against an
		// empty language — the message is the operator's rebuild cue.
		if err := toolchainSkew(bad, "go1.27.0"); err == nil || !strings.Contains(err.Error(), "unidentifiable") {
			t.Fatalf("unidentifiable binary %q: %v, want the unidentifiable refusal", bad, err)
		}
		if err := toolchainSkew("go1.27.0", bad); err == nil || !strings.Contains(err.Error(), "unidentifiable") {
			t.Fatalf("unidentifiable ambient %q: %v, want the unidentifiable refusal", bad, err)
		}
	}
}

// The exported wrapper attributes runtime.Version() to the BINARY
// side of the message: a swapped labeling would point the operator's
// rebuild at the wrong toolchain.
func TestToolchainSkewLabelsTheBinarySide(t *testing.T) {
	self := runtime.Version()
	series := gotool.LanguageSeries(self)
	// A far-future ambient: the binary's frontend predates it, the
	// refusing direction.
	ambient := "go99.1.0"
	err := ToolchainSkew(ambient)
	if err == nil {
		t.Fatal("newer-series ambient did not skew")
	}
	// Each version's LANGUAGE annotation must be its own — a crossed
	// annotation points the operator's rebuild at the wrong series.
	if !strings.Contains(err.Error(), "binary built with "+self+" (language "+series+")") {
		t.Fatalf("skew message %q does not annotate the binary %q with its own series %q", err.Error(), self, series)
	}
	if !strings.Contains(err.Error(), "ambient toolchain "+ambient+" (language "+gotool.LanguageSeries(ambient)+")") {
		t.Fatalf("skew message %q does not annotate the ambient %q with its own series", err.Error(), ambient)
	}
}

// The engine supplies the strategy, guard and assertion axes; the constructed
// hasher supplies the source and admission dependencies before a memo is armed.
// A swapped constant must not key proofs by the fact derivation
// (REQ-closure-observability-memo, REQ-closure-dynamic-state-memo,
// REQ-closure-scan-memo).
func TestAnalysisScopeWiresTheStrategyConstants(t *testing.T) {
	guards := guard.Guards{Toolchain: "tc", BuildConfig: "bc"}
	plain := (&engine{}).analysisScope(guards)
	if plain.ProofStrategy != ObservationRTA || plain.FactStrategy != DynamicStateStrategy || plain.Toolchain != "tc" || plain.BuildConfig != "bc" {
		t.Fatalf("wrong caller-owned scope axes: %+v", plain)
	}
	if plain.Proofs() != "" || plain.Facts() != "" || plain.Scan() != "" || plain.TestingScan() != "" {
		t.Fatal("reported guards without source dependencies armed a memo")
	}
	attested := (&engine{executionModel: SingleSubjectExecution, dynamicStateVouches: map[string]bool{"example.com/dep:Hooks": true, "a.example/x:Y": true}}).analysisScope(guards)
	pkgAttested := (&engine{executionModel: PackageExecution}).analysisScope(guards)
	slices.Sort(attested.Vouches)
	if !attested.SingleSubject || attested.PackageProcess || pkgAttested.SingleSubject || !pkgAttested.PackageProcess || plain.SingleSubject || plain.PackageProcess || !slices.Equal(attested.Vouches, []string{"a.example/x:Y", "example.com/dep:Hooks"}) || len(plain.Vouches) != 0 {
		t.Fatalf("assertion axes not preserved: plain=%+v attested=%+v pkgAttested=%+v", plain, attested, pkgAttested)
	}
	if attested.ProofStrategy != plain.ProofStrategy || attested.FactStrategy != plain.FactStrategy || attested.Toolchain != plain.Toolchain || attested.BuildConfig != plain.BuildConfig {
		t.Fatal("assertions moved an unrelated scope axis")
	}
}
