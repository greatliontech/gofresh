package closure

import (
	"errors"
	"go/constant"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func TestSourceStartupSelectedCompilerBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("loads the actual selected compiler source graph")
	}
	source, main := loadCompilerStartupFixture(t)
	var use regionUse
	for _, block := range main.Blocks {
		for i, instruction := range block.Instrs {
			call, ok := instruction.(*ssa.Call)
			if !ok {
				continue
			}
			target := call.Call.StaticCallee()
			if target != nil && target.Pkg != nil && target.Pkg.Pkg.Path() == "cmd/compile/internal/gc" && target.Name() == "Main" && len(call.Call.Args) != 0 {
				use = regionUse{at: regionPoint{block, i}, operand: call.Call.Args[0]}
			}
		}
	}
	if use.operand == nil {
		t.Fatal("selected compiler main no longer exposes the candidate driver call")
	}
	// Compiler packages contain large generated instruction tables. Allow their
	// source inventory here so the test reaches an implementation boundary rather
	// than exercising the separately tested small-fixture budget refusal.
	limits := defaultRegistrationLimits()
	limits.source.work, limits.source.bytes = 16<<20, 512<<20
	result, err := prepareSourceEntry(t.Context(), sourceStartupInput{source: source, initialization: sourceLanguageInitialization}, main, use, limits)
	var failure *sourceStartupFailure
	if result != nil || !errors.As(err, &failure) || failure.phase != sourceStartupSelection || failure.operation != "initialization-binding" {
		t.Fatalf("want an atomic initialization-graph admission refusal, got %v, %v", result, err)
	}
	if len(failure.dependencyPath) == 0 || failure.dependencyPath[0] != "cmd/compile" || failure.dependencyPath[len(failure.dependencyPath)-1] != failure.packageID {
		t.Fatalf("unrooted compiler refusal: %+v", failure)
	}
	byID := map[string]int{}
	for i, p := range source.prog.Pkgs {
		byID[p.ID] = i
	}
	for i, id := range failure.dependencyPath {
		index, ok := byID[id]
		if !ok {
			t.Fatalf("refusal names an unselected package %q", id)
		}
		p := source.prog.Pkgs[index]
		if i+1 < len(failure.dependencyPath) {
			found := false
			for _, imported := range p.Imports {
				found = found || imported.ID == failure.dependencyPath[i+1]
			}
			if !found {
				t.Fatalf("refusal contains a nonexistent dependency edge from %s", id)
			}
			continue
		}
		// Check the actual refused graph independently of diagnostic wording.
		// Short-circuit variable initialization adds blocks beyond the admitted
		// guard/body/return shape; it cannot become a supplied entry-heap value.
		init := source.prog.Prog.Package(p.Types).Func("init")
		if init == nil || len(init.Blocks) <= 3 {
			t.Fatalf("refused package %s has no demonstrated initialization CFG boundary", id)
		}
		t.Logf("unsupported selected initialization graph: %s, %d blocks", id, len(init.Blocks))
	}
	t.Logf("selected compiler admission boundary: %s (%s); no initialization state published", strings.Join(failure.dependencyPath, " -> "), failure.operation)
}

func TestSourceStartupNativeOrderOracle(t *testing.T) {
	if testing.Short() {
		t.Skip("loads and executes a compiled multi-package initialization oracle")
	}
	const module = "example.com/startuporacle"
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod": "module " + module + "\n\ngo 1.27\n",
		"rec/rec.go": `package rec
var Trace string
var P = new(int)
func Step(before, after string) { if Trace!=before { panic("order or repeated initialization") }; Trace=after }
func init() { Step("", "rec"); *P=5 }
`,
		"z/z.go": `package z
import "example.com/startuporacle/rec"
func init() { rec.Step("rec,b", "rec,b,z"); *rec.P=7 }
`,
		"a/a.go": `package a
import ("example.com/startuporacle/rec"; _ "example.com/startuporacle/z")
func init() { rec.Step("rec,b,z", "rec,b,z,a"); *rec.P=9 }
`,
		"b/b.go": `package b
import "example.com/startuporacle/rec"
func init() { rec.Step("rec", "rec,b") }
`,
		"main.go": `package main
import (_ "example.com/startuporacle/a"; _ "example.com/startuporacle/b"; "example.com/startuporacle/rec")
var Answer string
func main() { if *rec.P!=9 { panic("lost alias mutation") }; Answer=rec.Trace; println(Answer) }
`,
	})
	source, main, h := loadSourceCommandFixture(t, dir, module)
	var use regionUse
	for _, block := range main.Blocks {
		for i, instruction := range block.Instrs {
			if call, ok := instruction.(*ssa.Call); ok {
				if builtin, ok := call.Call.Value.(*ssa.Builtin); ok && builtin.Name() == "println" {
					use = regionUse{at: regionPoint{block, i}, operand: call.Call.Args[0]}
				}
			}
		}
	}
	if use.operand == nil {
		t.Fatal("actual oracle output operand missing")
	}
	result, err := prepareSourceEntry(t.Context(), sourceStartupInput{source: source, initialization: sourceLanguageInitialization}, main, use, registrationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	got := constant.StringVal(startupScalar(t, result))
	if got != "rec,b,z,a" {
		t.Fatalf("lost ready-order, exactly-once initialization or alias mutation: %q", got)
	}
	command, err := h.runner.Command(t.Context(), h.dir, h.env, "run", ".")
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("native oracle: %v\n%s", err, output)
	}
	if strings.TrimSpace(string(output)) != got {
		t.Fatalf("checked source value %q disagrees with compiled oracle %q", got, output)
	}
}
