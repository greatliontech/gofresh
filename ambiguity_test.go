package gofresh

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSharedHelperFixture is the field shape: one directory whose
// in-package test file (package amb) and external test package (package
// amb_test) both declare mustHelper — legal Go, two distinct packages in
// one test binary sharing a top-level name.
func writeSharedHelperFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/amb\n\ngo 1.26\n",
		"lib.go": "package amb\n\nfunc Compute(x int) int { return x * 2 }\n",
		"internal_test.go": `package amb

import "testing"

func mustHelper(t *testing.T) int {
	t.Helper()
	return 21
}

func TestInternal(t *testing.T) {
	if Compute(mustHelper(t)) != 42 {
		t.Fatal("broken")
	}
}
`,
		"external_test.go": `package amb_test

import (
	"testing"

	"example.com/amb"
)

func mustHelper(t *testing.T) int {
	t.Helper()
	return 5
}

func TestExternal(t *testing.T) {
	if amb.Compute(mustHelper(t)) != 10 {
		t.Fatal("broken")
	}
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A name duplicated between a package and its external test package is a
// subject-local collapse, not a package-wide refusal: the view builds,
// every unambiguous subject captures sound evidence untouched by the
// collision, and only a request for the collapsed name itself answers
// with refused capture — unverifiable evidence naming both declarations
// (REQ-purity-directive's refusal, scoped to the subject it is about).
func TestSharedTestHelperNameKeepsPackageMeasurable(t *testing.T) {
	dir := writeSharedHelperFixture(t)
	const pkg = "example.com/amb"
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{
		{Package: pkg, Symbol: "Compute"},
		{Package: pkg, Symbol: "TestInternal"},
		{Package: pkg, Symbol: "TestExternal"},
	}
	view, err := engine.NewView(context.Background(), subjects, dir, WithUnboundedRefinement())
	if err != nil {
		t.Fatalf("shared helper name made the package unmeasurable: %v", err)
	}
	for _, subject := range subjects {
		fingerprint, err := view.CaptureObserved(context.Background(), subject)
		if err != nil {
			t.Fatalf("capture %s: %v", subject.Symbol, err)
		}
		if strings.Contains(fingerprint.Refinement.Reason, "ambiguous") {
			t.Fatalf("unambiguous subject %s degraded by a sibling collision: %+v", subject.Symbol, fingerprint.Refinement)
		}
	}
}

// Requesting the collapsed name itself is refused capture for exactly
// that subject: the view still builds, the evidence is unverifiable, and
// the reason names both declarations so the repair (rename one) is
// actionable without spelunking.
func TestAmbiguousSubjectItselfIsRefusedCaptureAlone(t *testing.T) {
	dir := writeSharedHelperFixture(t)
	const pkg = "example.com/amb"
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := Subject{Package: pkg, Symbol: "mustHelper"}
	view, err := engine.NewView(context.Background(), []Subject{ambiguous, {Package: pkg, Symbol: "Compute"}}, dir, WithUnboundedRefinement())
	if err != nil {
		t.Fatalf("ambiguous subject request failed view construction: %v", err)
	}
	fingerprint, err := view.CaptureObserved(context.Background(), ambiguous)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if !fingerprint.Refinement.Unverifiable {
		t.Fatalf("collapsed identity captured verifiable evidence: %+v", fingerprint.Refinement)
	}
	// The diagnostic names BOTH declarations: the repair (rename one) is
	// actionable only when the caller sees where each lives.
	reason := fingerprint.Refinement.Reason
	if !strings.Contains(reason, "ambiguous") {
		t.Fatalf("refused capture does not name the collision: %q", reason)
	}
	verdict, err := view.CheckObserved(context.Background(), fingerprint, ambiguous)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "declared at both") ||
		!strings.Contains(verdict.Reason, "internal_test.go") || !strings.Contains(verdict.Reason, "external_test.go") {
		t.Fatalf("verdict does not name both declarations: %+v", verdict)
	}
	if fingerprint.PurityAssertion != "" {
		t.Fatalf("collapsed identity carries a purity attribution: %q", fingerprint.PurityAssertion)
	}
	sibling, err := view.CaptureObserved(context.Background(), Subject{Package: pkg, Symbol: "Compute"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sibling.Refinement.Reason, "ambiguous") {
		t.Fatalf("sibling subject degraded by the collision: %+v", sibling.Refinement)
	}
}

// A caller assertion confers nothing on a collapsed identity either:
// the assertion names one declarer taking responsibility, and the
// identity has two (REQ-purity-directive, REQ-purity-responsibility).
func TestAmbiguousSubjectCallerAssertionConfersNothing(t *testing.T) {
	dir := writeSharedHelperFixture(t)
	const pkg = "example.com/amb"
	engine, err := New(WithDir(dir), WithAssumePure(func(Subject) bool { return true }))
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := Subject{Package: pkg, Symbol: "mustHelper"}
	view, err := engine.NewView(context.Background(), []Subject{ambiguous}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), ambiguous)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.PurityAssertion != "" {
		t.Fatalf("caller assertion attributed purity to a collapsed identity: %q", fingerprint.PurityAssertion)
	}
}

// A directive on either colliding declaration confers nothing: purity for
// a collapsed identity would let one declaration vouch for the other
// (REQ-purity-directive, REQ-purity-responsibility).
func TestAmbiguousSubjectDirectiveConfersNothing(t *testing.T) {
	dir := writeSharedHelperFixture(t)
	internal := filepath.Join(dir, "internal_test.go")
	content, err := os.ReadFile(internal)
	if err != nil {
		t.Fatal(err)
	}
	directive := strings.Replace(string(content), "func mustHelper(t *testing.T) int {", "//gofresh:pure\nfunc mustHelper(t *testing.T) int {", 1)
	if err := os.WriteFile(internal, []byte(directive), 0o644); err != nil {
		t.Fatal(err)
	}
	const pkg = "example.com/amb"
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := Subject{Package: pkg, Symbol: "mustHelper"}
	view, err := engine.NewView(context.Background(), []Subject{ambiguous}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), ambiguous)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.PurityAssertion != "" {
		t.Fatalf("directive on one colliding declaration attributed purity to the collapsed identity: %q", fingerprint.PurityAssertion)
	}

	// The public directive scan refuses the same attribution: the pure
	// predicate must never claim a collapsed identity.
	pred, err := ScanPureDirectivesIn(dir, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if pred(ambiguous) {
		t.Fatal("public directive scan claimed purity for a collapsed identity")
	}
}

// An external directive on a colliding declaration is refused the same
// way: the collapsed identity's evidence names the ambiguity, never one
// declaration's externality (REQ-purity-directive's refusal scope).
func TestAmbiguousSubjectExternalDirectiveConfersNothing(t *testing.T) {
	dir := writeSharedHelperFixture(t)
	external := filepath.Join(dir, "external_test.go")
	content, err := os.ReadFile(external)
	if err != nil {
		t.Fatal(err)
	}
	directive := strings.Replace(string(content), "func mustHelper(t *testing.T) int {", "//gofresh:external\nfunc mustHelper(t *testing.T) int {", 1)
	if err := os.WriteFile(external, []byte(directive), 0o644); err != nil {
		t.Fatal(err)
	}
	const pkg = "example.com/amb"
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := Subject{Package: pkg, Symbol: "mustHelper"}
	view, err := engine.NewView(context.Background(), []Subject{ambiguous}, dir)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), mustCapture(t, view, ambiguous), ambiguous)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "ambiguous") {
		t.Fatalf("collapsed identity with an external twin = %+v, want the ambiguity named, not the directive", verdict)
	}
}

func mustCapture(t *testing.T, view *View, subject Subject) Fingerprint {
	t.Helper()
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	return fingerprint
}
