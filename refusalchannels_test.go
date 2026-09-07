package gofresh

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/closure"
)

// The signature-dynamism refusal names the term conferring openness —
// the first type parameter, receiver, or parameter whose type carries
// dynamic reach — and its channel, so the operator bounds exactly that
// type; the term is the persisted open-world fact itself
// (REQ-closure-refusal-channels).
func TestOpenWorldRefusalNamesTheConferringTerm(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine over fixtures")
	}
	for name, tc := range map[string]struct{ source, subject, term string }{
		"function parameter": {"package view\n\nfunc F(f func()) { f() }\n", "F", "parameter f func()"},
		"unnamed parameter":  {"package view\n\nfunc F(int, func()) {}\n", "F", "parameter #2 func()"},
		"blank parameter":    {"package view\n\nfunc F(_ func()) {}\n", "F", "parameter #1 func()"},
		"interface receiver": {"package view\n\ntype R struct{ h func() }\n\nfunc (r R) F() { r.h() }\n", "R.F", "receiver view.R"},
		"type parameter":     {"package view\n\nfunc F[T any](t T) {}\n", "F", "type parameter T constrained by any"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeViewModule(t, tc.source)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: tc.subject})
			want := "subject accepts caller-supplied dynamic behavior through its " + tc.term + " (dischargeable by bounding that type away from dynamic carriers, or by " + closure.PurityResponsibility + ")"
			if verdict.Status != Unverifiable || verdict.Reason != want {
				t.Fatalf("verdict = %+v, want the open-world refusal naming %q", verdict, tc.term)
			}
		})
	}
	t.Run("closed signature carries no term", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\nfunc F(n int) int { return n + 1 }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid", verdict)
		}
	})
}

// Under an unaudited toolchain selection every tier refusal carries the
// selection's owned attribution — the degraded axis, appended at the
// tier's own composition: the closure tier, signature dynamism, and
// shared dynamic state here (the observability tier is pinned in the
// closure package) — while the declaration-borne refusals, the external
// directive and an ambiguous identity, carry none, and an audited
// selection attributes nothing (REQ-closure-refusal-channels).
func TestUnauditedSelectionAttributesTierRefusals(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine over fixtures")
	}
	axis := " (judged under an unaudited toolchain selection: selection \"dst\" under " + runtime.Version() + " is unwalked)"
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":           "module example.com/view\n\ngo 1.26\n",
		"view.go":          "package view\n\nimport \"net\"\n\nfunc Open(f func()) { f() }\n\nfunc Dial() error { _, err := net.Dial(\"tcp\", \"\"); return err }\n\n//gofresh:external\nfunc Declared() int { return 1 }\n\nfunc Twice() int { return 1 }\n",
		"view_test.go":     "package view_test\n\nfunc Twice() int { return 2 }\n",
		"shared/shared.go": "package shared\n\nvar Hook = func() {}\n\nfunc Rebind() { Hook = func() {} }\n\nfunc Shared() { Hook() }\n",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The shared-dynamic-state downgrade is package-wide, so its
	// fixture is its own package beside the others.
	shared := Subject{Package: "example.com/view/shared", Symbol: "Shared"}
	subjects := func(names ...string) []Subject {
		out := []Subject{shared}
		for _, name := range names {
			out = append(out, Subject{Package: "example.com/view", Symbol: name})
		}
		return out
	}
	engine, err := New(WithDir(dir), WithBuildFlags("-tags=dst"))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), subjects("Open", "Dial", "Declared", "Twice"), dir)
	if err != nil {
		t.Fatal(err)
	}
	reason := func(symbol string) string {
		subject := Subject{Package: "example.com/view", Symbol: symbol}
		if symbol == shared.Symbol {
			subject = shared
		}
		cl, ok := view.facts.maximal[subject]
		if !ok || !cl.Unverifiable {
			t.Fatalf("%s = %+v, want an unverifiable maximal closure", symbol, cl)
		}
		return cl.Reason
	}
	if got := reason("Open"); got != "subject accepts caller-supplied dynamic behavior through its parameter f func() (dischargeable by bounding that type away from dynamic carriers, or by "+closure.PurityResponsibility+")"+axis {
		t.Fatalf("signature-dynamism refusal = %q, want the term, the channel, and the axis", got)
	}
	if got := reason("Dial"); !strings.HasPrefix(got, "reaches net") || !strings.HasSuffix(got, axis) || strings.Count(got, "judged under") != 1 {
		t.Fatalf("closure-tier refusal = %q, want the reach with the axis appended once", got)
	}
	if got := reason("Shared"); !strings.Contains(got, "example.com/view/shared.Hook is mutated") || !strings.HasSuffix(got, axis) || strings.Count(got, "judged under") != 1 {
		t.Fatalf("shared-dynamic-state refusal = %q, want the culprit with the axis appended", got)
	}
	if got := reason("Declared"); got != "external directive" {
		t.Fatalf("external declaration = %q, want no attribution", got)
	}
	if got := reason("Twice"); !strings.HasPrefix(got, "ambiguous subject identity: ") || strings.Contains(got, "judged under") {
		t.Fatalf("ambiguous identity = %q, want no attribution", got)
	}
	for _, symbol := range []string{"Declared", "Twice", "Open"} {
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: symbol}, WithBuildFlags("-tags=dst"))
		if verdict.Status != Unverifiable || (symbol == "Declared" && verdict.Reason != "external directive") || (symbol == "Open" && !strings.HasSuffix(verdict.Reason, axis)) {
			t.Fatalf("%s verdict = %+v", symbol, verdict)
		}
	}
	audited, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := audited.NewView(context.Background(), subjects("Open", "Dial"), dir)
	if err != nil {
		t.Fatal(err)
	}
	for symbol, cl := range plain.facts.maximal {
		if strings.Contains(cl.Reason, "judged under") {
			t.Fatalf("audited selection attributed %s: %q", symbol.Symbol, cl.Reason)
		}
	}
}
