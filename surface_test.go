package gofresh

import (
	"context"
	"errors"
	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/shortgates"
	"github.com/greatliontech/stipulator/stipulate/structural"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Every exported analysis entry of the public packages names its
// environment in its signature (REQ-closure-analysis: the analyzed tree
// and build selection are explicit inputs, never implicit coupling): no
// production source of runtimeinput, gotool, the internal packages, or the
// root files outside session.go and view.go reads the ambient process
// environment (os.Environ, Getenv, LookupEnv, ExpandEnv, and syscall's).
// The ambient defaults are the root's own — newEngine without withEnv, and
// an engine-less view's runtime-input check — and live in session.go and
// view.go, outside this walk.
//
//gofresh:pure
func TestPublicPackagesReadNoAmbientEnvironment(t *testing.T) {
	roots := []string{"runtimeinput", "gotool", "internal"}
	files := []string{"checking.go", "explain.go", "fingerprint.go", "judgment.go", "provenance.go", "unit.go", "vouchfile.go"}
	for _, root := range roots {
		if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (d.Name() == "fixtures" || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				files = append(files, path)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, hit := range ambientReads(t, files) {
		t.Errorf("%s: reads the ambient environment; the entry must take env", hit)
	}
}

// ambientReads names every call of an ambient-environment reader in the
// given Go sources, as file:line:col.
func ambientReads(t *testing.T, files []string) []string {
	t.Helper()
	fset := token.NewFileSet()
	var hits []string
	for _, path := range files {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			ambient := (pkg.Name == "os" && (sel.Sel.Name == "Environ" || sel.Sel.Name == "Getenv" || sel.Sel.Name == "LookupEnv" || sel.Sel.Name == "ExpandEnv")) ||
				(pkg.Name == "syscall" && (sel.Sel.Name == "Environ" || sel.Sel.Name == "Getenv"))
			if ambient {
				hits = append(hits, fset.Position(call.Pos()).String())
			}
			return true
		})
	}
	return hits
}

// The walk's logic over synthetic sources: every ambient reader is named,
// a same-named method on another receiver is not, and a clean file yields
// nothing — the real-source walk above is this logic's hand-edit oracle
// (a source-reading pin cannot see an overlay, so the logic is pinned
// where a probe can reach it).
//
//gofresh:pure
func TestAmbientReadsNameEveryAmbientReader(t *testing.T) {
	dir := t.TempDir()
	dirty := filepath.Join(dir, "dirty.go")
	if err := os.WriteFile(dirty, []byte(`package p

import (
	"os"
	"syscall"
)

type env struct{}

func (env) Environ() []string { return nil }

func f() {
	_ = os.Environ()
	_ = os.Getenv("K")
	_, _ = os.LookupEnv("K")
	_ = os.ExpandEnv("$K")
	_ = syscall.Environ()
	_, _ = syscall.Getenv("K")
	_ = env{}.Environ()
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	clean := filepath.Join(dir, "clean.go")
	if err := os.WriteFile(clean, []byte("package p\n\nfunc g(env []string) []string { return env }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hits := ambientReads(t, []string{dirty, clean})
	if len(hits) != 6 {
		t.Fatalf("hits = %v; want the six ambient readers and not the method", hits)
	}
	for _, h := range hits {
		if !strings.HasPrefix(h, dirty+":") {
			t.Fatalf("a clean file was named: %s", h)
		}
	}
}

// A cancelled or missing preparation context admits no configuration work.
func TestConstructionContextRefusesBeforeOptions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []context.Context{nil, ctx} {
		called := false
		e, err := newEngineContext(input, func(*engine) { called = true })
		if e != nil || err == nil || called {
			t.Fatalf("context %v: engine returned=%t error=%v option called=%v", input, e != nil, err, called)
		}
		if input != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation returned %v", err)
		}
	}
}

// A cancellation during configuration cannot be reported as an unrelated flag
// refusal, even where the invalid flag prevents an environment query entirely.
func TestConstructionContextKeepsCancellationAttribution(t *testing.T) {
	for _, option := range []option{withBuildFlags("-overlay=unused"), withBuildInputs("-overlay=unused"), withEnv("malformed")} {
		ctx, cancel := context.WithCancel(context.Background())
		e, err := newEngineContext(ctx, withDir(t.TempDir()), option, func(*engine) { cancel() })
		cancel()
		if e != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled preparation: engine returned=%t error=%v", e != nil, err)
		}
	}
}

// The fast tier's gates are inert under a plain `go test`: every gate in
// the repository's test files is a skipping statement of a Test or Fuzz
// body, never in a helper, an uninvoked closure, or a fixture string
// (github.com/greatliontech/gofresh/shortgates states the rules and pins
// its own arms).
func TestShortGatesLiveInTestBodiesAndSkip(t *testing.T) {
	shortgates.Pin(t, ".")
}

func TestVariantLedgerTypesAreExportedData(t *testing.T) {
	// TestVariantLedger and TestVariantDelta carry deliberate methods (Clone;
	// Inert, the one Go-semantics judgment), so their field shapes are pinned
	// by reflection rather than the method-free ExportedData contract.
	for typeOf, want := range map[reflect.Type][]string{
		reflect.TypeFor[TestVariantLedger](): {"BindingStrategy", "BaseFiles", "Declarations", "FileHeaders"},
		reflect.TypeFor[TestVariantDelta]():  {"BindingsPreserved", "Added", "Changed", "Removed", "HeaderChanges"},
	} {
		if typeOf.NumField() != len(want) {
			t.Fatalf("%s has %d fields, want %d", typeOf, typeOf.NumField(), len(want))
		}
		for i, name := range want {
			if typeOf.Field(i).Name != name {
				t.Fatalf("%s field %d = %s, want %s", typeOf, i, typeOf.Field(i).Name, name)
			}
		}
	}
	structural.ExportedData[TestVariantDeclaration](t,
		structural.FieldOf[string]("File"),
		structural.FieldOf[string]("Kind"),
		structural.FieldOf[string]("Name"),
		structural.FieldOf[string]("Receiver"),
		structural.FieldOf[string]("Hash"),
		structural.FieldOf[string]("Package"),
		structural.FieldOf[[]string]("References"),
	)
	structural.ExportedData[TestVariantFileHeader](t,
		structural.FieldOf[string]("File"),
		structural.FieldOf[string]("Hash"),
		structural.FieldOf[bool]("Embedded"),
		structural.FieldOf[*TestVariantFileBindings]("Bindings"),
	)
	structural.ExportedData[TestVariantFileBindings](t,
		structural.FieldOf[string]("Package"),
		structural.FieldOf[[]string]("References"),
		structural.FieldOf[[]TestVariantImport]("Imports"),
	)
	structural.ExportedData[TestVariantImport](t,
		structural.FieldOf[string]("Name"),
		structural.FieldOf[string]("Path"),
	)
	structural.ExportedData[TestVariantDeclarationChange](t,
		structural.FieldOf[TestVariantDeclaration]("Before"),
		structural.FieldOf[TestVariantDeclaration]("After"),
	)
	structural.ExportedData[TestVariantHeaderChange](t,
		structural.FieldOf[string]("File"),
		structural.FieldOf[string]("Before"),
		structural.FieldOf[string]("After"),
		structural.FieldOf[bool]("Embedded"),
	)
}

func TestPurityInputIsSubjectPredicate(t *testing.T) {
	structural.ExportedData[SessionPolicy](t,
		structural.FieldOf[string]("EvidenceRoot"),
		structural.FieldOf[[]string]("Vouches"),
		structural.FieldOf[[]Subject]("PureSubjects"),
		structural.FieldOf[func(Subject) bool]("AssumePure"),
		structural.FieldOf[ExecutionModel]("Execution"),
		structural.FieldOf[time.Duration]("AnalysisBudget"),
		structural.FieldOf[gotool.Runner]("Runner"),
		structural.FieldOf[func(Progress)]("Progress"),
	)
}

func TestViewCheckUsesConstructionKind(t *testing.T) {
	structural.FunctionSignature[func(*Snapshot, context.Context, Fingerprint, Subject) (Verdict, error)](t, (*Snapshot).Check)
}

func TestVouchInputShapes(t *testing.T) {
	structural.FunctionSignature[func(string) (string, error)](t, ParseVouchEntry)
	structural.FunctionSignature[func([]string) ([]string, error)](t, ParseVouchEntries)
	structural.FunctionSignature[func(string) ([]string, error)](t, ReadVouchFile)
}
