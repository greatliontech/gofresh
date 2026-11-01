package gofresh

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestViewDiscoversSourcePurity(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"os\"\n\n//gofresh:pure\nfunc F() { _, _ = os.ReadFile(\"fixture\") }\n")
	verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
	if verdict.Status != Valid {
		t.Fatalf("directive-pure view = {%s %q}, want valid", verdict.Status, verdict.Reason)
	}
}

func TestViewAcceptsPromotedMethodSubject(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"os\"\n\ntype Inner struct{}\n\n//gofresh:pure\nfunc (Inner) M() { _, _ = os.ReadFile(\"fixture\") }\n\ntype Outer struct{ Inner }\n")
	subject := Subject{Package: "example.com/view", Symbol: "Outer.M"}
	fingerprint, verdict := captureCheckFP(t, dir, subject)
	if verdict.Status != Valid {
		t.Fatalf("promoted pure method = %+v, want valid", verdict)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nimport \"os\"\n\ntype Inner struct{}\n\n//gofresh:pure\nfunc (Inner) M() { _, _ = os.ReadFile(\"fixture\") }\n\ntype Outer struct{ *Inner }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	current, _, ok := inMemorySnapshotForSubject(dir, subject)
	if !ok {
		t.Fatal("inMemorySnapshotForSubject declined")
	}
	var err error
	verdict, err = current.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "closure" {
		t.Fatalf("promoting type edit = %+v, want stale closure", verdict)
	}
}

func TestImportedPromotedMethodInheritsPurityDirective(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"example.com/view/dep\"\n\ntype Outer struct { dep.Inner }\n")
	if err := os.Mkdir(filepath.Join(dir, "dep"), 0o755); err != nil {
		t.Fatal(err)
	}
	dependency := "package dep\n\nimport \"os\"\n\ntype Inner struct{}\n\n//gofresh:pure\nfunc (Inner) M() { _, _ = os.ReadFile(\"fixture\") }\n"
	if err := os.WriteFile(filepath.Join(dir, "dep", "dep.go"), []byte(dependency), 0o644); err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "Outer.M"}
	fingerprint, verdict := captureCheckFP(t, dir, subject)
	if fingerprint.PurityAssertion != "source directive" {
		t.Fatalf("imported promoted purity = %q, want source directive", fingerprint.PurityAssertion)
	}
	if verdict.Status != Valid {
		t.Fatalf("imported promoted purity verdict = %+v, want valid", verdict)
	}
}

func TestSourcePurityRemainsPortableWhenProducerAlsoAsserts(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"os\"\n\n//gofresh:pure\nfunc F() { _, _ = os.ReadFile(\"fixture\") }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	fingerprint, _ := captureCheckFP(t, dir, subject, withAssumePure(func(candidate Subject) bool { return candidate == subject }))
	if fingerprint.PurityAssertion != "caller assertion and source directive" {
		t.Fatalf("producer purity attribution = %q", fingerprint.PurityAssertion)
	}
	consumer, _, ok := inMemorySnapshotForSubject(dir, subject)
	if !ok {
		t.Fatal("inMemorySnapshotForSubject declined")
	}
	verdict, err := consumer.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("portable source purity verdict = %+v, want valid", verdict)
	}
}

func TestMalformedPurityAttributionCannotOverride(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"os\"\n\nfunc F() { _, _ = os.ReadFile(\"fixture\") }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	fingerprint, _ := captureCheckFP(t, dir, subject)
	fingerprint.PurityAssertion = "corrupt"
	consumer, _, ok := inMemorySnapshotForSubject(dir, subject, withAssumePure(func(candidate Subject) bool { return candidate == subject }))
	if !ok {
		t.Fatal("inMemorySnapshotForSubject declined")
	}
	verdict, err := consumer.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable {
		t.Fatalf("malformed purity attribution verdict = %+v, want unverifiable", verdict)
	}
}

func TestViewMarksCallerSuppliedCallbackUnverifiable(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F(fn func() int) int { return fn() }\n")
	verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "caller-supplied") {
		t.Fatalf("callback subject verdict = %+v, want caller-supplied unverifiable", verdict)
	}
	if verdict.Ground.Cause.Kind != OpenWorldCause {
		t.Fatalf("callback origin was not retained: %+v", verdict.Ground)
	}
}

func TestViewMarksGenericCallbackUnverifiable(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nfunc F[T func() int](fn T) int { return fn() }\n")
	verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
	if verdict.Status != Unverifiable {
		t.Fatalf("generic callback verdict = %+v, want unverifiable", verdict)
	}
}

func TestMutableCallbackGlobalIsCallerSuppliedUnverifiable(t *testing.T) {
	// Rebind mutates the callback global outside initialization, making
	// it process-shared dynamic state (REQ-closure-shared-dynamic-state).
	dir := writeViewModule(t, "package view\n\nvar Callback = func() {}\n\nfunc F() { Callback() }\n\nfunc Rebind(f func()) { Callback = f }\n")
	fingerprint, verdict := captureCheckFP(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "shares mutated dynamic state") {
		t.Fatalf("mutable callback global verdict = %+v fingerprint=%+v, want the shared-dynamic-state downgrade", verdict, fingerprint)
	}
	if verdict.Ground.Cause.Kind != SharedDynamicStateCause {
		t.Fatalf("shared-state origin was not retained: %+v", verdict.Ground)
	}
}

// A vouch naming a mutable-local variable confers nothing: code the
// caller can edit is fixed, not vouched — the downgrade stands and no
// discharge is recorded (REQ-vouch-dependency-boundary).
func TestVouchConfersNothingOnMutableLocalState(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nvar Callback = func() {}\n\nfunc F() { Callback() }\n\nfunc Rebind(f func()) { Callback = f }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	fingerprint, verdict := captureCheckFP(t, dir, subject, withDynamicStateVouches("", "example.com/view.Callback"))
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "shares mutated dynamic state") {
		t.Fatalf("mutable-local vouch lifted the downgrade: %+v", verdict)
	}
	if fingerprint.DynamicStateVouches != "" {
		t.Fatalf("mutable-local vouch recorded a discharge: %q", fingerprint.DynamicStateVouches)
	}
	// The vouch suppresses the verdict's downgrade, never the explain
	// derivation: a vouched variable's chain still derives on request
	// (REQ-vouch-recorded, REQ-explain-chain).
	chain, ok := inMemoryExplainViewForSubject(t, dir, subject, "example.com/view", "Callback")
	if !ok {
		t.Fatal("inMemoryExplainViewForSubject declined")
	}
	if chain.Arm == "" || len(chain.Links) == 0 {
		t.Fatalf("vouched variable's explain chain suppressed: %+v", chain)
	}
}

// A dynamic-capable global the program never mutates after
// initialization is ordinary source: the closure hashes its
// initializer, and the subject checks valid instead of downgrading
// (REQ-closure-shared-dynamic-state).
func TestImmutableCallbackGlobalChecksValid(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nvar Callback = func() {}\n\nvar ErrSentinel = error(nil)\n\nfunc F() { Callback() }\n")
	verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
	if verdict.Status != Valid {
		t.Fatalf("immutable callback global verdict = %+v, want valid", verdict)
	}
}

func TestMutableCallbackGlobalFromDependencyPropagates(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"example.com/view/dep\"\n\nfunc F() { dep.Run() }\n")
	if err := os.Mkdir(filepath.Join(dir, "dep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dep", "dep.go"), []byte("package dep\n\nvar Hook = func() {}\n\nfunc Run() { Hook() }\n\nfunc SetHook(f func()) { Hook = f }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "shares mutated dynamic state") {
		t.Fatalf("dependency callback global verdict = %+v, want propagated maximal disposition", verdict)
	}
}

func TestMaximalOrdinaryTestHarnessIsVerifiable(t *testing.T) {
	dir := writeViewModule(t, "package view\n")
	if err := os.WriteFile(filepath.Join(dir, "ordinary_test.go"), []byte("package view\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "TestF"})
	if verdict.Status != Valid {
		t.Fatalf("ordinary test harness verdict = %+v, want valid", verdict)
	}
}

func TestRuntimeAddressExposureIsUnverifiable(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"reflect\"\n\nfunc F() uintptr { value := 0; return reflect.ValueOf(&value).Pointer() }\n")
	verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reflect") {
		t.Fatalf("reflect.Pointer verdict = %+v, want unverifiable naming reflect", verdict)
	}
}

func TestUnsafePointerAddressInputIsUnverifiable(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"unsafe\"\n\nvar Address uintptr\nfunc F() byte { return *(*byte)(unsafe.Pointer(Address)) }\n")
	verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "unsafe") {
		t.Fatalf("unsafe pointer verdict = %+v, want unverifiable naming unsafe", verdict)
	}
}

func TestCPUDispatchedMathIsUnverifiableForCodeResult(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport \"math\"\n\nfunc F() uint64 { return math.Float64bits(math.Exp(1.25)) }\n")
	verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "math") {
		t.Fatalf("math.Exp verdict = %+v, want unverifiable naming math", verdict)
	}
}

func TestFormattedReaderInputIsUnverifiable(t *testing.T) {
	dir := writeViewModule(t, "package view\n\nimport (\"fmt\"; \"os\")\n\nfunc F() int { var value int; _, _ = fmt.Fscan(os.Stdin, &value); return value }\n")
	verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "fmt.Fscan") {
		t.Fatalf("fmt.Fscan verdict = %+v, want formatted-input unverifiable", verdict)
	}
}
