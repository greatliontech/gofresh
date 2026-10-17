package closure

import (
	"errors"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
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
	binder, err := newSelectedSourceBinder(t.Context(), source, main, limits.source)
	if err != nil {
		t.Fatal(err)
	}
	var buildcfgBound bool
	for _, p := range source.prog.Pkgs {
		if p.PkgPath != "internal/buildcfg" {
			continue
		}
		binding, err := binder.bindInitialization(p)
		if err != nil {
			t.Fatalf("selected buildcfg initializer still refuses: %v", err)
		}
		init := source.prog.Prog.Package(p.Types).Func("init")
		global, ok := init.Pkg.Members["FramePointerEnabled"].(*ssa.Global)
		if !ok || binding.function != init || len(init.Blocks) <= 3 {
			t.Fatal("missing exact selected branching buildcfg owner")
		}
		var branching, stored, typedShortCircuit bool
		for _, initializer := range p.TypesInfo.InitOrder {
			if len(initializer.Lhs) == 1 && initializer.Lhs[0] == global.Object() {
				expr, ok := initializer.Rhs.(*ast.BinaryExpr)
				typedShortCircuit = ok && expr.Op == token.LOR
			}
		}
		for _, block := range init.Blocks[1:] {
			for _, ins := range block.Instrs {
				if _, ok := ins.(*ssa.If); ok {
					branching = true
				}
				if store, ok := ins.(*ssa.Store); ok && store.Addr == global {
					phi, ok := store.Val.(*ssa.Phi)
					stored = ok && phi.Block() == block && len(phi.Edges) == 2 && len(block.Preds) == 2
				}
			}
		}
		if !typedShortCircuit || !branching || !stored || binding.end.at.block != init.Blocks[0].Succs[0] {
			t.Fatal("buildcfg positive lacks actual branch/store/return evidence")
		}
		buildcfgBound = true
		t.Logf("selected internal/buildcfg initialization bound: %d actual blocks, FramePointerEnabled stored", len(init.Blocks))
	}
	if !buildcfgBound {
		t.Fatal("selected compiler graph omitted internal/buildcfg")
	}
	result, err := prepareSourceEntry(t.Context(), sourceStartupInput{source: source, initialization: sourceLanguageInitialization}, main, use, limits)
	var failure *sourceStartupFailure
	if result != nil || !errors.As(err, &failure) || failure.phase != sourceStartupSelection || failure.operation != "external-storage" {
		t.Fatalf("want a selected external-input admission boundary, got %v, %v", result, err)
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
		// Read the selected inputs independently of the startup refusal. An
		// admitted buildcfg graph cannot grant external initialization authority.
		var boundary *computationFailure
		blocked := false
		if errors.As(err, &boundary) && boundary.at.IsValid() {
			if strings.Contains(boundary.premise, "budget") {
				t.Fatalf("source budget stopped before directive classification: %v", err)
			}
			for _, file := range p.Syntax {
				for _, group := range file.Comments {
					for _, comment := range group.List {
						if comment.Pos() != boundary.at {
							continue
						}
						text := comment.Text
						if !strings.HasPrefix(text, "//go:") || strings.HasPrefix(text, "//go:build ") {
							t.Fatal("refusal coordinate is not an implementation directive")
						}
						if !strings.HasPrefix(text, "//go:linkname ") {
							blocked = true // no other directive grammar is admitted
						} else {
							fields := strings.Fields(text)
							if len(fields) != 2 && len(fields) != 3 {
								t.Fatal("selected compiler source has malformed linkage")
							}
							object := p.Types.Scope().Lookup(fields[1])
							if _, storage := object.(*types.Var); storage {
								blocked = true
							}
							for _, declaringFile := range p.Syntax {
								for _, node := range declaringFile.Decls {
									if decl, ok := node.(*ast.FuncDecl); ok && p.TypesInfo.Defs[decl.Name] == object && decl.Body != nil {
										blocked = true
									}
								}
							}
						}
						t.Logf("selected unsupported directive at %s: %s", p.Fset.Position(comment.Pos()), text)
					}
				}
			}
		} else {
			for _, m := range source.metas {
				if m.ImportPath == id {
					blocked = len(m.CgoFiles)+len(m.CFiles)+len(m.CXXFiles)+len(m.MFiles)+len(m.HFiles)+len(m.FFiles)+len(m.SFiles)+len(m.SwigFiles)+len(m.SwigCXXFiles)+len(m.SysoFiles)+len(m.EmbedFiles)+len(m.CgoLDFLAGS)+len(m.CgoCFLAGS)+len(m.CgoCPPFLAGS)+len(m.CgoCXXFLAGS)+len(m.CgoFFLAGS)+len(m.CgoPkgConfig) != 0
				}
			}
		}
		if !blocked {
			t.Fatalf("refusal lacks independently demonstrated unsupported input: %v", err)
		}
	}
	t.Logf("selected compiler admission boundary: %s (%s); no initialization state published", strings.Join(failure.dependencyPath, " -> "), failure.operation)
}

func TestSourceStartupUnusedLinknameCompiledOracle(t *testing.T) {
	if testing.Short() {
		t.Skip("loads and executes compiled unused-linkname declarations")
	}
	const module = "example.com/unusedlinkage"
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod": "module " + module + "\n\ngo 1.27\n",
		"dep/decl.go": `package dep
import _ "unsafe"
//go:linkname renamedAbsent no.such.package/remote.Value
func renamedAbsent()int
//go:linkname anotherAbsent
func anotherAbsent(string)
var Value=7
func init(){Value=9}
`,
		"main.go": `package main
import "example.com/unusedlinkage/dep"
func main(){println(dep.Value)}
`,
	})
	source, main, h := loadSourceCommandFixture(t, dir, module)
	var use regionUse
	for _, block := range main.Blocks {
		for i, ins := range block.Instrs {
			if call, ok := ins.(*ssa.Call); ok {
				if builtin, ok := call.Call.Value.(*ssa.Builtin); ok && builtin.Name() == "println" {
					use = regionUse{at: regionPoint{block, i}, operand: call.Call.Args[0]}
				}
			}
		}
	}
	if use.operand == nil {
		t.Fatal("oracle output operand missing")
	}
	result, err := prepareSourceEntry(t.Context(), sourceStartupInput{source: source, initialization: sourceLanguageInitialization}, main, use, registrationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if got := startupScalar(t, result).ExactString(); got != "9" {
		t.Fatalf("source model lost imported initialization: %s", got)
	}
	// Successful real compilation/linking and execution is independent of the
	// source checker: the unresolved declarations must be dead, not stubbed or
	// resolved by an invented native implementation.
	command, err := h.runner.Command(t.Context(), h.dir, h.env, "run", ".")
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "9" {
		t.Fatalf("unused unresolved declarations failed the compiled oracle: %v\n%s", err, output)
	}
}

func TestSourceStartupNativeBranchOracle(t *testing.T) {
	if testing.Short() {
		t.Skip("loads and executes a compiled branching initialization oracle")
	}
	const module = "example.com/branchoracle"
	dir := t.TempDir()
	text := strings.Replace(startupBranchSource, "consume(Trace)", "println(Trace)", 1)
	writeTree(t, dir, map[string]string{"go.mod": "module " + module + "\n\ngo 1.27\n", "main.go": text})
	source, main, h := loadSourceCommandFixture(t, dir, module)
	var use regionUse
	for _, block := range main.Blocks {
		for i, ins := range block.Instrs {
			if call, ok := ins.(*ssa.Call); ok {
				if builtin, ok := call.Call.Value.(*ssa.Builtin); ok && builtin.Name() == "println" {
					use = regionUse{at: regionPoint{block, i}, operand: call.Call.Args[0]}
				}
			}
		}
	}
	if use.operand == nil {
		t.Fatal("oracle output operand missing")
	}
	result, err := prepareSourceEntry(t.Context(), sourceStartupInput{source: source, initialization: sourceLanguageInitialization}, main, use, registrationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	got := constant.StringVal(startupScalar(t, result))
	if got != "complete" {
		t.Fatalf("source branch effects: %q", got)
	}
	command, err := h.runner.Command(t.Context(), h.dir, h.env, "run", ".")
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != got {
		t.Fatalf("source %q disagrees with compiled oracle %q: %v", got, output, err)
	}
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
