package gofresh

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeInitFixture(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// Init functions are unaddressable by name, so subjects carry the
// declaration ledger's positional identity: init#<file>#<ordinal>,
// 0-based within the file in declaration order. Each init declaration
// is its own subject - capture works, the fingerprint moves when
// anything in the subject's closure moves, and a change outside every
// init's reach and outside the subject's own reach leaves it valid.
func TestInitSubjectsCapturePositionally(t *testing.T) {
	dir := t.TempDir()
	writeInitFixture(t, dir, map[string]string{
		"go.mod": "module example.com/initfix\n\ngo 1.26\n",
		"a.go": `package initfix

var registry []string

func wireA() { registry = append(registry, "a") }

func init() { wireA() }

func init() { registry = append(registry, "second") }
`,
		"other/other.go": `package other

func Unwired(x int) int {
	if x > 10 {
		return x - 1
	}
	return x
}
`,
		"a_test.go": `package initfix

import "testing"

func TestRegistry(t *testing.T) {
	if len(registry) == 0 {
		t.Fatal("registry empty")
	}
}
`,
	})
	ctx := context.Background()
	first, second := Subject{Package: "example.com/initfix", Symbol: "init#a.go#0"}, Subject{Package: "example.com/initfix", Symbol: "init#a.go#1"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(ctx, []Subject{first, second}, dir)
	if err != nil {
		t.Fatal(err)
	}
	firstPrint, err := view.Capture(ctx, first)
	if err != nil {
		t.Fatalf("first init capture: %v", err)
	}
	secondPrint, err := view.Capture(ctx, second)
	if err != nil {
		t.Fatalf("second init capture: %v", err)
	}
	if firstPrint.MaximalClosure == "" || secondPrint.MaximalClosure == "" {
		t.Fatalf("init closures empty: %q %q", firstPrint.MaximalClosure, secondPrint.MaximalClosure)
	}

	// A change outside the subjects' closure entirely - an unimported
	// sibling package. (The home package's core is package-granular, so
	// the outside edit must live outside the package.) The init subject
	// stays put.
	writeInitFixture(t, dir, map[string]string{"other/other.go": `package other

func Unwired(x int) int {
	if x > 10 {
		return x - 2
	}
	return x
}
`})
	engine2, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view2, err := engine2.NewView(ctx, []Subject{first, second}, dir)
	if err != nil {
		t.Fatal(err)
	}
	firstAfterUnrelated, err := view2.Capture(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if firstAfterUnrelated.MaximalClosure != firstPrint.MaximalClosure {
		t.Fatalf("init closure moved on an unreachable edit: %q -> %q", firstPrint.MaximalClosure, firstAfterUnrelated.MaximalClosure)
	}

	// A change inside the first init's transitive reach moves it.
	writeInitFixture(t, dir, map[string]string{"a.go": `package initfix

var registry []string

func wireA() { registry = append(registry, "a", "wired") }

func init() { wireA() }

func init() { registry = append(registry, "second") }
`})
	engine3, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view3, err := engine3.NewView(ctx, []Subject{first, second}, dir)
	if err != nil {
		t.Fatal(err)
	}
	firstAfterWireEdit, err := view3.Capture(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if firstAfterWireEdit.MaximalClosure == firstPrint.MaximalClosure {
		t.Fatal("init closure did not move when its wiring changed")
	}
}

// A positional init subject that names no declaration - ordinal past
// the file's inits, or a file with none - refuses at view construction
// with the named subject, exactly like any unknown symbol.
func TestInitSubjectUnknownOrdinalRefuses(t *testing.T) {
	dir := t.TempDir()
	writeInitFixture(t, dir, map[string]string{
		"go.mod": "module example.com/initmiss\n\ngo 1.26\n",
		"a.go":   "package initmiss\n\nfunc init() {}\n",
		"a_test.go": `package initmiss

import "testing"

func TestNothing(t *testing.T) {}
`,
	})
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	missing := Subject{Package: "example.com/initmiss", Symbol: "init#a.go#1"}
	if _, err := engine.NewView(context.Background(), []Subject{missing}, dir); err == nil || !strings.Contains(err.Error(), "init#a.go#1") {
		t.Fatalf("unknown init ordinal view = %v, want a refusal naming the subject", err)
	}
}

// The positional identity is file-scoped: an init added in another
// file neither shifts an existing subject's identity nor makes it
// unresolvable. (Its closure moves - package initialization is in
// every subject's closure - but the key still names the same
// declaration and re-capture succeeds.)
func TestInitSubjectIdentityStableAcrossOtherFiles(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.com/initstable\n\ngo 1.26\n",
		"a.go":   "package initstable\n\nvar n int\n\nfunc init() { n++ }\n",
		"a_test.go": `package initstable

import "testing"

func TestN(t *testing.T) {
	if n == 0 {
		t.Fatal("n zero")
	}
}
`,
	}
	writeInitFixture(t, dir, files)
	ctx := context.Background()
	subject := Subject{Package: "example.com/initstable", Symbol: "init#a.go#0"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(ctx, []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.Capture(ctx, subject); err != nil {
		t.Fatal(err)
	}
	writeInitFixture(t, dir, map[string]string{"aa.go": "package initstable\n\nfunc init() { n += 2 }\n"})
	engine2, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	// The new file's own init starts at ordinal 0 - the counter is
	// per-file, never package-wide.
	added := Subject{Package: "example.com/initstable", Symbol: "init#aa.go#0"}
	view2, err := engine2.NewView(ctx, []Subject{subject, added}, dir)
	if err != nil {
		t.Fatalf("init subjects unresolvable after another file gained an init: %v", err)
	}
	if _, err := view2.Capture(ctx, subject); err != nil {
		t.Fatalf("existing init subject failed capture after another file gained an init: %v", err)
	}
	if _, err := view2.Capture(ctx, added); err != nil {
		t.Fatalf("added file's first init failed capture under its own 0-based ordinal: %v", err)
	}
}
