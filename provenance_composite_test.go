package gofresh

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/gotool"
)

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
	units := UnitPhases()
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

// The composite is the one refusal every consumer's judged run answers a
// provenance fault with: an unidentifiable toolchain names the frontend
// and the cause in the one prose, a breaking skew rides ToolchainSkew's
// own words, both typed *ToolchainProvenanceError; an agreeing sample
// passes.
func TestToolchainProvenanceIsOneRefusal(t *testing.T) {
	ctx := context.Background()
	cause := errors.New("go: exec: not found")
	err := (&ToolchainProvenance{Sampler: SampleFunc(func(context.Context, string, []string) (string, error) { return "", cause })}).Check(ctx, ".", nil)
	var pe *ToolchainProvenanceError
	if !errors.As(err, &pe) || !errors.Is(err, cause) {
		t.Fatalf("unidentifiable: err = %v (typed %v)", err, errors.As(err, &pe))
	}
	want := "toolchain provenance: binary built with " + closure.AnalyzingFrontend() + ", ambient toolchain unidentifiable — refusing to judge: go: exec: not found"
	if err.Error() != want {
		t.Fatalf("prose = %q, want %q", err.Error(), want)
	}
	err = (&ToolchainProvenance{Sampler: SampleFunc(func(context.Context, string, []string) (string, error) { return "go0.1", nil })}).Check(ctx, ".", nil)
	if !errors.As(err, &pe) || err.Error() != ToolchainSkew("go0.1").Error() {
		t.Fatalf("skew: err = %v, want ToolchainSkew's own words, typed", err)
	}
	if err := (&ToolchainProvenance{Sampler: SampleFunc(func(context.Context, string, []string) (string, error) { return runtime.Version(), nil })}).Check(ctx, ".", nil); err != nil {
		t.Fatalf("an agreeing sample refused: %v", err)
	}
	// The zero value is one memo: two checks through one composite
	// share one sampler, created once.
	zero := &ToolchainProvenance{}
	_ = zero.Check(ctx, ".", []string{"PATH=/nonexistent"})
	first := zero.Sampler
	_ = zero.Check(ctx, ".", []string{"PATH=/nonexistent"})
	if first == nil || zero.Sampler != first {
		t.Fatalf("the zero composite did not hold one sampler across checks: %p then %p", first, zero.Sampler)
	}
	if _, ok := first.(*gotool.Sampler); !ok {
		t.Fatalf("the zero composite's sampler is %T, want the memoized gotool.Sampler", first)
	}
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

// The per-unit classification is the doc's: the seven phases opening a
// unit of work are units, the facts and the diagnostics are not.
//
//gofresh:pure
func TestUnitPhasesAreTheDocsList(t *testing.T) {
	got, want := UnitPhases(), []string{"hash", "list", "load", "observe", "prove", "runtime", "typecheck"}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UnitPhases = %v, want the set %v", got, want)
	}
	// A consumer's copy is its own: mutating it changes no verdict and
	// no later copy.
	got[0] = "x"
	if !(Progress{Phase: "hash"}).IsUnit() || (Progress{Phase: "x"}).IsUnit() {
		t.Fatal("a mutated copy changed the classification")
	}
	again := UnitPhases()
	sort.Strings(again)
	if !reflect.DeepEqual(again, want) {
		t.Fatalf("a later copy carries the mutation: %v", again)
	}
	for _, phase := range UnitPhases() {
		if !(Progress{Phase: phase}).IsUnit() {
			t.Errorf("%s is not a unit", phase)
		}
	}
	for _, phase := range []string{"served", "cancelled", "budget-exhausted", "toolchain-unaudited", "analysis-unavailable", "listing-unmodelled", ""} {
		if (Progress{Phase: phase}).IsUnit() {
			t.Errorf("%q reads as a unit", phase)
		}
	}
}
