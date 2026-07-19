package gofresh

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/gofresh/runtimeinput"
)

// TestStaleRuntimeInputsNamesTheMover pins the attribution surface end to end
// (REQ-inputs-path-identities): a recording staled by a moved runtime input
// reports which input moved, not one opaque word.
func TestStaleRuntimeInputsNamesTheMover(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	tmp := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(tmp, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/mover\n\ngo 1.26\n")
	write("m.go", "package mover\n\nfunc F() int { return 1 }\n")
	write("data/fixture.txt", "v1")

	subj := Subject{Package: "example.com/mover", Symbol: "F"}
	e, err := New(WithDir(tmp))
	if err != nil {
		t.Fatal(err)
	}
	fp, err := e.Capture(context.Background(), subj, tmp)
	if err != nil {
		t.Fatal(err)
	}
	bracket, err := runtimeinput.CaptureBracket(tmp, []string{"data"})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := runtimeinput.FromTestLog([]byte("open data/fixture.txt\n"), tmp, tmp,
		runtimeinput.WithCompletedProcess("package-test-binary:mover"), runtimeinput.WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	st, err := runtimeinput.CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	fp.RuntimeInputs = st.Manifest
	fp.RuntimeDigest = st.Digest

	if v, err := e.Check(context.Background(), fp, subj, tmp); err != nil {
		t.Fatal(err)
	} else if v.Status != Valid {
		t.Fatalf("unmoved input verdict = {%s %q}, want valid", v.Status, v.Reason)
	}

	write("data/fixture.txt", "v2")
	v, err := e.Check(context.Background(), fp, subj, tmp)
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != Stale || !strings.Contains(v.Reason, "moved: path data/fixture.txt") {
		t.Fatalf("moved-input verdict = {%s %q}, want stale naming the mover", v.Status, v.Reason)
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
	if got := movedSummary([]string{"a", "b", "c", "d", "e"}); got != "a, b, c, and 2 more" {
		t.Fatalf("movedSummary = %q", got)
	}
}
