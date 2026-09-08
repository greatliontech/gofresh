package gofresh

import (
	"context"
	"strings"
	"testing"
)

// The culprit walk both reachability scopings share records exactly the
// discharged prefix: every culprit before the first survivor, in the
// evidence's sorted form, and none after it — the survivor names the
// downgrade. Seven carriers in key order: five discharged, the sixth
// mutated in the subject's own rooted flow, the seventh dischargeable
// but past the survivor (REQ-closure-shared-dynamic-state,
// REQ-vouch-recorded).
func TestCulpritDischargeRecordsTheSortedPrefix(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine over a fixture (measured heavy under the fast tier)")
	}
	const decls = "var a = map[string]func(){}\nvar b = map[string]func(){}\nvar c = map[string]func(){}\nvar d = map[string]func(){}\nvar e = map[string]func(){}\nvar f = map[string]func(){}\nvar g = map[string]func(){}\n\nfunc mutA() { a[\"k\"] = nil }\nfunc mutB() { b[\"k\"] = nil }\nfunc mutC() { c[\"k\"] = nil }\nfunc mutD() { d[\"k\"] = nil }\nfunc mutE() { e[\"k\"] = nil }\nfunc mutF() { f[\"k\"] = nil }\nfunc mutG() { g[\"k\"] = nil }\n\n"
	const prefix = "example.com/view.a,example.com/view.b,example.com/view.c,example.com/view.d,example.com/view.e"
	t.Run("attested per-subject scoping", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\n"+decls+"func F() int {\n\tmutF()\n\treturn len(a) + len(b) + len(c) + len(d) + len(e) + len(f) + len(g)\n}\n")
		fingerprint, verdict := captureFingerprint(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, WithSingleSubjectExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.f is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade naming f — the rooted mutator", verdict)
		}
		if fingerprint.SingleSubjectDischarges != prefix {
			t.Fatalf("evidence = %q, want the sorted discharged prefix %q", fingerprint.SingleSubjectDischarges, prefix)
		}
	})
	t.Run("package-process scoping", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       "module example.com/view\n\ngo 1.26\n",
			"view.go":      "package view\n\n" + decls + "func F() int { return len(a) + len(b) + len(c) + len(d) + len(e) + len(f) + len(g) }\n",
			"view_test.go": "package view\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tmutF()\n\tif F() < 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		}
		dir := writeModuleTree(t, files)
		fingerprint, verdict := captureFingerprint(t, dir, Subject{Package: "example.com/view", Symbol: "TestF"}, WithPackageProcessExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.f is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade naming f — the harness-rooted mutator", verdict)
		}
		if fingerprint.PackageProcessDischarges != prefix {
			t.Fatalf("evidence = %q, want the sorted discharged prefix %q", fingerprint.PackageProcessDischarges, prefix)
		}
	})
}

// captureFingerprint captures and checks one subject, returning the
// fingerprint beside the verdict for evidence assertions.
func captureFingerprint(t *testing.T, dir string, subject Subject, opts ...Option) (Fingerprint, Verdict) {
	t.Helper()
	engine, err := New(append([]Option{WithDir(dir)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	return fingerprint, verdict
}
