package closure

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
)

type startupImporter func(string) (*types.Package, error)

func (f startupImporter) Import(path string) (*types.Package, error) { return f(path) }

func startupFixture(t *testing.T, files map[string][]string) (sourceStartupInput, *ssa.Function, regionUse) {
	t.Helper()
	fset := token.NewFileSet()
	prog := ssa.NewProgram(fset, ssa.SanityCheckFunctions|ssa.InstantiateGenerics)
	sizes := types.SizesFor("gc", "amd64")
	loaded := map[string]*packages.Package{}
	var pkgs []*packages.Package
	var metas []listPkg
	var load startupImporter
	load = func(path string) (*types.Package, error) {
		if path == "unsafe" {
			if prog.Package(types.Unsafe) == nil {
				prog.CreatePackage(types.Unsafe, nil, nil, true)
			}
			return types.Unsafe, nil
		}
		if p := loaded[path]; p != nil {
			return p.Types, nil
		}
		texts, ok := files[path]
		if !ok {
			return nil, fmt.Errorf("missing fixture %s", path)
		}
		p := &packages.Package{ID: path, PkgPath: path, Fset: fset, TypesSizes: sizes, Imports: map[string]*packages.Package{}}
		m := listPkg{ImportPath: path, Dir: "/startup/" + path}
		for i, text := range texts {
			name := fmt.Sprintf("%d.go", i)
			full := m.Dir + "/" + name
			file, err := parser.ParseFile(fset, full, text, parser.ParseComments)
			if err != nil {
				return nil, err
			}
			p.Syntax = append(p.Syntax, file)
			p.CompiledGoFiles = append(p.CompiledGoFiles, full)
			m.GoFiles = append(m.GoFiles, name)
		}
		p.TypesInfo = &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Implicits: map[ast.Node]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}, Scopes: map[ast.Node]*types.Scope{}, Instances: map[*ast.Ident]types.Instance{}}
		config := &types.Config{Importer: load, Sizes: sizes}
		var err error
		p.Types, err = config.Check(path, fset, p.Syntax, p.TypesInfo)
		if err != nil {
			return nil, err
		}
		p.Name, m.Name = p.Types.Name(), p.Types.Name()
		for _, imported := range p.Types.Imports() {
			if imported == types.Unsafe {
				p.Imports["unsafe"] = &packages.Package{ID: "unsafe", Types: types.Unsafe}
			} else {
				p.Imports[imported.Path()] = loaded[imported.Path()]
			}
			m.Imports = append(m.Imports, imported.Path())
		}
		loaded[path] = p
		pkgs = append(pkgs, p)
		metas = append(metas, m)
		prog.CreatePackage(p.Types, p.Syntax, p.TypesInfo, true)
		return p.Types, nil
	}
	if _, err := load("main"); err != nil {
		t.Fatal(err)
	}
	prog.Build()
	main := prog.Package(loaded["main"].Types).Func("main")
	var use regionUse
	for _, block := range main.Blocks {
		for i, ins := range block.Instrs {
			if call, ok := ins.(*ssa.Call); ok && call.Call.StaticCallee() != nil && call.Call.StaticCallee().Name() == "consume" {
				use = regionUse{at: regionPoint{block, i}, operand: call.Call.Args[0]}
			}
		}
	}
	return sourceStartupInput{source: computationSource{prog: &program{Prog: prog, Pkgs: pkgs}, metas: metas}, initialization: sourceLanguageInitialization}, main, use
}

func startupScalar(t *testing.T, result *sourceEntry) constant.Value {
	t.Helper()
	if result == nil || len(result.regions) != 1 || len(result.regions[0].packet.observations) != 1 {
		t.Fatal("missing complete main observation")
	}
	v := result.regions[0].packet.observations[0].value
	if v.kind != regionConstant {
		t.Fatalf("not an exact source value: %+v", v)
	}
	return v.scalar
}

func TestSourceStartupMainEntry(t *testing.T) {
	for _, tc := range []struct{ name, source, want string }{
		{"zero", `package main; var X int; func consume(int){}; func main(){consume(X)}`, "0"},
		{"dependency-order", `package main; var A=B; var B=7; func consume(int){}; func main(){consume(A)}`, "7"},
		{"explicit-suffix", `package main; var X int; func init(){X=3}; func init(){X=5}; func consume(int){}; func main(){consume(X)}`, "5"},
		{"main-prefix", `package main; var X int; func init(){X=3}; func change(){X=9}; func consume(int){}; func main(){change(); consume(X)}`, "9"},
		{"heap-alias", `package main; var P=new(int); func init(){*P=3}; func consume(int){}; func main(){q:=P; *q=9; consume(*P)}`, "9"},
		{"helper-alloc", `package main; func makeP()*int{return new(int)}; var P=makeP(); func init(){*P=3}; func consume(int){}; func main(){*P=9; consume(*P)}`, "9"},
		{"or-left", `package main; var A=true;var B=false;var X=A||B;func consume(bool){};func main(){consume(X)}`, "true"},
		{"or-right", `package main; var A=false;var B=true;var X=A||B;func consume(bool){};func main(){consume(X)}`, "true"},
		{"or-false", `package main; var A=false;var B=false;var X=A||B;func consume(bool){};func main(){consume(X)}`, "false"},
		{"and-left", `package main; var A=false;var B=true;var X=A&&B;func consume(bool){};func main(){consume(X)}`, "false"},
		{"and-right", `package main; var A=true;var B=false;var X=A&&B;func consume(bool){};func main(){consume(X)}`, "false"},
		{"and-true", `package main; var A=true;var B=true;var X=A&&B;func consume(bool){};func main(){consume(X)}`, "true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, main, use := startupFixture(t, map[string][]string{"main": {tc.source}})
			result, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{})
			if err != nil {
				t.Fatal(err)
			}
			if got := startupScalar(t, result).ExactString(); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
			if result.startup.owner.prog != in.source.prog || result.main.function != main || result.regions[0].packet.input.entry != (regionPoint{main.Blocks[0], 0}) {
				t.Fatal("lost owner/actual main entry")
			}
		})
	}
}

// The same source is also run by the compiled oracle. Comparisons and constant
// assignments expose skipped/taken RHS effects without adding arithmetic grammar.
const startupBranchSource = `package main
var Trace="before"
var A=true
var B=false
func step(before, after string) bool { if Trace!=before {panic("order")}; Trace=after; return true }
var C=A||step("never", "bad")
var D=B||step("before", "or")
var E=B&&step("never", "bad")
var F=A&&step("or", "and")
var After=Trace
func init(){if !C || !D || E || !F || After!="and" {panic("branch")}; Trace="first"}
func init(){if Trace!="first" {panic("suffix order")}; Trace="complete"}
func consume(string){}
func main(){consume(Trace)}
`

func TestSourceStartupBranchEffectsAndSuffix(t *testing.T) {
	in, main, use := startupFixture(t, map[string][]string{"main": {startupBranchSource}})
	result, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if got := constant.StringVal(startupScalar(t, result)); got != "complete" {
		t.Fatalf("skipped/taken RHS or explicit suffix effects lost: %q", got)
	}
}

func TestSourceStartupReadyOrderAndHeapContinuity(t *testing.T) {
	in, main, use := startupFixture(t, map[string][]string{
		"rec":  {`package rec; var S string; var P = new(int); func init(){if S!=""{panic("twice")}; S="ready"}; func Add(before, after string){if S!=before{panic("order")}; S=after}; func Make()*int{return new(int)}`},
		"z":    {`package z; import "rec"; var P=rec.Make(); func init(){rec.Add("b","bz"); *rec.P=7; *P=4}`},
		"a":    {`package a; import("rec"; "z"); var P=rec.Make(); func init(){rec.Add("bz","bza"); *rec.P=9; *P=6; *z.P=8}`},
		"b":    {`package b; import "rec"; var P=rec.Make(); func init(){rec.Add("ready","b"); *P=2}`},
		"main": {`package main; import("a"; "b"; "rec"; "z"); func consume(string){}; func main(){ if *rec.P != 9 || *a.P != 6 || *z.P != 8 || *b.P != 2 {panic("lost heap")}; consume(rec.S)}`},
	})
	result, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if got := constant.StringVal(startupScalar(t, result)); got != "bza" {
		t.Fatalf("used DFS instead of first-ready language schedule: %q", got)
	}
	var order []string
	for _, p := range result.startup.order {
		order = append(order, p.selected.ID)
	}
	if !slices.Equal(order, []string{"rec", "b", "z", "a", "main"}) {
		t.Fatal(order)
	}
	if len(result.startup.heaps[0].memory) < 9 {
		t.Fatal("discarded whole startup heap")
	}
}

func TestSourceStartupSelectedFileInitOrder(t *testing.T) {
	in, main, use := startupFixture(t, map[string][]string{"main": {
		`package main; var S string; func init(){if S!=""{panic("order")}; S="first"}; func consume(string){}`,
		`package main; func init(){if S!="first"{panic("order")}; S="firstsecond"}; func main(){consume(S)}`,
	}})
	result, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if got := constant.StringVal(startupScalar(t, result)); got != "firstsecond" {
		t.Fatal(got)
	}
}

func TestSourceStartupCompletedRepeatedAllocationRemainsSummary(t *testing.T) {
	in, main, use := startupFixture(t, map[string][]string{"main": {`package main
var P,Q *int
func makeP()*int{return new(int)}
func init(){
	for first:=true;;first=false {
		p:=makeP()
		if first {P=p} else {Q=p;break}
	}
}
func consume(int){}
func main(){
	r:=makeP()
	*r=7
	*P=9
	if *r!=7 {panic("cross-phase allocation collision")}
	consume(*Q)
}`}})
	result, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.regions) != 1 || len(result.regions[0].packet.observations) != 1 {
		t.Fatal("missing complete main observation")
	}
	// The two initialization allocations share a repeated abstract callsite.
	// Completing that phase preserves their summary cardinality: writing through
	// P cannot strongly overwrite every object represented by Q. The new main
	// call above is independently singleton and must not collide with that site.
	if got := result.regions[0].packet.observations[0].value; got.kind != regionUnknown {
		t.Fatalf("completed repeated allocation acquired singleton authority: %+v", got)
	}
}

func TestSourceStartupRefusalsAreScopedAndAtomic(t *testing.T) {
	for _, tc := range []struct{ name, extra, body string }{
		{"blank-effect", `var _ = effect(); func effect()int{panic("effect")}`, `consume(0)`},
		{"tuple", `var A,B=pair(); func pair()(int,int){return 1,2}`, `consume(A)`},
		{"directive", "//go:linkname X elsewhere.X\nvar X int", `consume(X)`},
		{"late-init", `var X=1; func init(){panic("late")}`, `consume(X)`},
		{"late-main", `var X=1`, `panic("late"); consume(X)`},
		{"go", `var X int; func init(){go func(){X=2}()}`, `consume(X)`},
		{"defer", `var X int; func init(){defer func(){X=2;panic("deferred")}()}`, `consume(X)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, main, use := startupFixture(t, map[string][]string{"main": {"package main\n" + tc.extra + "\nfunc consume(int){};func main(){" + tc.body + "}"}})
			got, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{})
			var refusal *sourceStartupFailure
			if got != nil || !errors.As(err, &refusal) || refusal.packageID != "main" || len(refusal.dependencyPath) == 0 || refusal.operation == "" {
				t.Fatalf("partial/unscoped refusal: %v %v", got, err)
			}
		})
	}
}

func TestSourceStartupOpaqueInitializedLeaves(t *testing.T) {
	for _, name := range []string{"float32", "float64", "complex64", "complex128"} {
		t.Run(name, func(t *testing.T) {
			text := fmt.Sprintf("package main;var F %s;var X struct{Opaque %s;Value int};func consume(int){};func main(){consume(X.Value)}", name, name)
			in, main, use := startupFixture(t, map[string][]string{"main": {text}})
			result, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{})
			if err != nil {
				t.Fatal(err)
			}
			if !constant.Compare(startupScalar(t, result), token.EQL, constant.MakeInt64(0)) || len(result.startup.heaps) != 1 {
				t.Fatal("opaque initialization lost the supported integer sibling")
			}
			memory := result.startup.heaps[0].memory
			for _, globalName := range []string{"F", "X"} {
				global := main.Pkg.Members[globalName].(*ssa.Global)
				value, present := memory[regionObject{kind: regionGlobal, site: global}]
				if !present {
					t.Fatal("initialized object disappeared from the startup heap", globalName)
				}
				if globalName == "X" {
					if value.kind != regionAggregate || len(value.elements) != 2 {
						t.Fatal("initialized aggregate lost its typed shape")
					}
					value = value.elements[0]
				}
				if name == "float32" || name == "float64" {
					if value.kind != regionFloat || value.floatBits != 0 || value.typ == nil || value.typ.String() != name {
						t.Fatalf("initialized float lost its exact language zero: %+v", value)
					}
					continue
				}
				if value.kind != regionUnknown || value.scalar != nil || value.typ == nil || value.typ.String() != name {
					t.Fatalf("opaque initialized leaf acquired scalar or bit authority: %+v", value)
				}
			}
		})
	}
}

func TestSourceStartupTransitiveBlankAndExternalInputs(t *testing.T) {
	for _, mode := range []string{"directive", "bodyless", "assembly", "embed", "absent-model", "external-model", "linker-X", "missing-dependency", "duplicate-metadata", "duplicate-package"} {
		t.Run(mode, func(t *testing.T) {
			extra := ""
			if mode == "directive" {
				extra = "\n//go:linkname X foreign.X\nvar X int"
			}
			if mode == "bodyless" {
				extra = "\nfunc foreign()\nfunc init(){foreign()}"
			}
			in, main, use := startupFixture(t, map[string][]string{"hidden": {"package hidden" + extra}, "mid": {`package mid; import _ "hidden"`}, "main": {`package main; import _ "mid"; func consume(int){};func main(){consume(0)}`}})
			switch mode {
			case "assembly":
				in.source.metas[0].SFiles = []string{"native.s"}
			case "embed":
				in.source.metas[0].EmbedFiles = []string{"data"}
			case "absent-model":
				in.initialization = sourceInitializationAbsent
			case "external-model":
				in.initialization = sourceExternalInitialization
			case "linker-X":
				in.linkerFlags = []string{"-X", "hidden.X=hello"}
			case "missing-dependency":
				in.source.prog.Pkgs = in.source.prog.Pkgs[1:]
			case "duplicate-metadata":
				in.source.metas = append(in.source.metas, in.source.metas[0])
			case "duplicate-package":
				in.source.prog.Pkgs = append(in.source.prog.Pkgs, in.source.prog.Pkgs[0])
			}
			got, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{})
			var refusal *sourceStartupFailure
			if got != nil || !errors.As(err, &refusal) {
				t.Fatal("external initialization accepted", err)
			}
			if mode == "directive" || mode == "assembly" || mode == "embed" || mode == "bodyless" {
				if refusal.packageID != "hidden" || !slices.Equal(refusal.dependencyPath, []string{"main", "mid", "hidden"}) {
					t.Fatal("lost transitive path", refusal)
				}
			}
		})
	}
}

func TestSourceStartupBudgetsCancellationAndEntry(t *testing.T) {
	in, main, use := startupFixture(t, map[string][]string{"main": {`package main;var X=2;func consume(int){};func main(){consume(X)}`}})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := prepareSourceEntry(ctx, in, main, use, registrationLimits{}); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled evidence", err)
	}
	for _, dimension := range []string{"source-work", "source-depth", "source-bytes", "work", "nodes", "locations", "states"} {
		limits := defaultRegistrationLimits()
		switch dimension {
		case "source-work":
			limits.source.work = 1
		case "source-depth":
			limits.source.depth = 1
		case "source-bytes":
			limits.source.bytes = 1
		case "work":
			limits.region.work = 1
		case "nodes":
			limits.region.nodes = 1
		case "locations":
			limits.region.locations = 1
		case "states":
			limits.region.states = 1
		}
		if got, err := prepareSourceEntry(t.Context(), in, main, use, limits); got != nil || err == nil || !strings.Contains(err.Error(), "budget") {
			t.Fatal(dimension, got, err)
		}
	}
	helper := main.Pkg.Func("consume")
	if got, err := prepareSourceEntry(t.Context(), in, helper, use, registrationLimits{}); got != nil || err == nil {
		t.Fatal("startup borrowed by helper")
	}
}

func TestSourceStartupRequiresLanguageMain(t *testing.T) {
	in, main, _ := startupFixture(t, map[string][]string{"main": {`package main
var X=2
func consume(int){}
func alternate(){consume(X)}
func main(){consume(X)}
`}})
	helper := main.Pkg.Func("alternate")
	var use regionUse
	for _, block := range helper.Blocks {
		for i, instruction := range block.Instrs {
			if call, ok := instruction.(*ssa.Call); ok && call.Call.StaticCallee() == main.Pkg.Func("consume") {
				use = regionUse{at: regionPoint{block, i}, operand: call.Call.Args[0]}
			}
		}
	}
	if use.operand == nil {
		t.Fatal("helper's actual use missing")
	}
	got, err := prepareSourceEntry(t.Context(), in, helper, use, registrationLimits{})
	var failure *sourceStartupFailure
	if got != nil || !errors.As(err, &failure) || failure.phase != sourceStartupEntry || failure.operation != "language-entry" {
		t.Fatalf("startup state borrowed as helper entry: %v, %v", got, err)
	}
}

func TestSourceStartupInitializerOwnership(t *testing.T) {
	for _, mode := range []string{"drop-explicit", "extra-explicit", "drop-import", "extra-import", "guard", "copy-init", "copy-main", "drop-initorder", "reorder-initorder"} {
		t.Run(mode, func(t *testing.T) {
			in, main, use := startupFixture(t, map[string][]string{
				"dep":  {`package dep; var X=1`},
				"main": {`package main; import "dep"; var X=dep.X; var Y=2; func init(){X=3}; func consume(int){}; func main(){consume(X)}`},
			})
			init := main.Pkg.Func("init")
			body := init.Blocks[1]
			p := in.source.prog.Pkgs[len(in.source.prog.Pkgs)-1]
			switch mode {
			case "drop-explicit":
				body.Instrs = append(body.Instrs[:len(body.Instrs)-2], body.Instrs[len(body.Instrs)-1])
			case "extra-explicit":
				last := len(body.Instrs) - 2
				body.Instrs = append(append(slices.Clone(body.Instrs[:last]), body.Instrs[last]), body.Instrs[last:]...)
			case "drop-import":
				body.Instrs = append(body.Instrs[:1], body.Instrs[2:]...)
			case "extra-import":
				body.Instrs = append(append(slices.Clone(body.Instrs[:1]), body.Instrs[1]), body.Instrs[1:]...)
			case "guard":
				body.Instrs[0].(*ssa.Store).Val = ssa.NewConst(constant.MakeBool(false), types.Typ[types.Bool])
			case "copy-init":
				copy := *init
				main.Pkg.Members["init"] = &copy
			case "copy-main":
				copy := *main
				main.Pkg.Members["main"] = &copy
				main = &copy
			case "drop-initorder":
				p.TypesInfo.InitOrder = p.TypesInfo.InitOrder[1:]
			case "reorder-initorder":
				slices.Reverse(p.TypesInfo.InitOrder)
			}
			if got, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{}); got != nil || err == nil {
				t.Fatal("unbound construction accepted", mode)
			}
		})
	}
}

func TestSourceStartupWholeHeapAlternatives(t *testing.T) {
	in, main, use := startupFixture(t, map[string][]string{"main": {`package main
var P=new(struct{});var Q=new(struct{});var X,Y int
func init(){if P==Q {X=1;Y=10}else{X=2;Y=20}}
func consume(int){}
func main(){if X==1 {if Y!=10{panic("correlation")}}else{if X!=2 || Y!=20{panic("correlation")}};consume(X)}`}})
	result, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.startup.heaps) != 2 || len(result.regions) != 2 {
		t.Fatal("lost language-permitted zero-size pointer alternatives")
	}
	seen := map[int64]bool{}
	for _, region := range result.regions {
		for _, observation := range region.packet.observations {
			n, ok := regionInt(observation.value)
			if !ok {
				t.Fatal("widened correlated value")
			}
			seen[n] = true
		}
	}
	if len(seen) != 2 || !seen[1] || !seen[2] {
		t.Fatal(seen)
	}
}

func TestSourceStartupBudgetIsAggregate(t *testing.T) {
	in, main, use := startupFixture(t, map[string][]string{
		"a": {`package a; var X=1`}, "b": {`package b;var X=2`}, "c": {`package c;var X=3`},
		"main": {`package main;import(_ "a";_ "b";_ "c");var X=4;func consume(int){};func main(){consume(X)}`},
	})
	result, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	limits := defaultRegistrationLimits()
	limits.region.work = 300
	var inputs []regionInput
	for _, p := range result.startup.order {
		for _, packet := range p.packets {
			inputs = append(inputs, packet.input)
		}
	}
	for _, region := range result.regions {
		inputs = append(inputs, region.packet.input)
	}
	// Every segment fits individually. Resetting the meter at a package or at
	// main would accept this program, so a mere tiny-budget refusal is insufficient.
	for _, input := range inputs {
		proposal, err := proposeRegion(t.Context(), input, limits.region)
		if err != nil {
			t.Fatal("individual proposal exceeds discriminator budget", err)
		}
		if _, err := checkRegion(t.Context(), input, proposal, limits.region); err != nil {
			t.Fatal("individual check exceeds discriminator budget", err)
		}
	}
	if got, err := prepareSourceEntry(t.Context(), in, main, use, limits); got != nil || err == nil || !strings.Contains(err.Error(), "work budget") {
		t.Fatal("reset aggregate budget", got, err)
	}
}

func TestSourceStartupLateCancellationAndCapturedSelection(t *testing.T) {
	in, main, use := startupFixture(t, map[string][]string{"main": {`package main;var P=new(int);func init(){*P=3};func consume(int){};func main(){*P=4;consume(*P)}`}})
	count := &regionCallCountingContext{Context: t.Context()}
	if _, err := prepareSourceEntry(count, in, main, use, registrationLimits{}); err != nil {
		t.Fatal(err)
	}
	for _, stop := range []int{count.checks / 2, count.checks - 1} {
		ctx := &regionCallCountingContext{Context: t.Context(), stop: stop}
		if got, err := prepareSourceEntry(ctx, in, main, use, registrationLimits{}); got != nil || !errors.Is(err, context.Canceled) {
			t.Fatal("late cancellation returned evidence", got, err)
		}
	}
	ctx := &regionMutatingContext{Context: t.Context(), mutate: func() {
		in.source.metas[0].GoFiles[0] = "different.go"
		in.source.metas[0].SFiles = []string{"external.s"}
	}}
	got, err := prepareSourceEntry(ctx, in, main, use, registrationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if startupScalar(t, got).ExactString() != "4" || got.startup.owner.metas[0].GoFiles[0] != "0.go" || len(got.startup.owner.metas[0].SFiles) != 0 {
		t.Fatal("context changed captured selection")
	}
}

func TestSourceStartupUnsafeIsOnlyALanguagePseudoPackage(t *testing.T) {
	in, main, use := startupFixture(t, map[string][]string{"main": {`package main;import "unsafe";var X=unsafe.Sizeof(byte(0));func consume(uintptr){};func main(){consume(X)}`}})
	got, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if startupScalar(t, got).ExactString() != "1" {
		t.Fatal("language constant lost")
	}
	main.Prog.Package(types.Unsafe).Members["borrowed"] = main.Pkg.Members["X"]
	if got, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{}); got != nil || err == nil {
		t.Fatal("pseudo-package exempted arbitrary storage")
	}
}

func TestSourceStartupRefusalRetainsActualCallBoundary(t *testing.T) {
	in, main, use := startupFixture(t, map[string][]string{
		"dep":  {`package dep;var X int;func Bad()int{return X+1}`},
		"main": {`package main;import "dep";func consume(int){};func main(){consume(dep.Bad())}`},
	})
	got, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{})
	var refusal *sourceStartupFailure
	if got != nil || !errors.As(err, &refusal) || refusal.phase != sourceStartupEntry || refusal.packageID != "dep" || !slices.Equal(refusal.dependencyPath, []string{"main", "dep"}) || len(refusal.operations) != 2 {
		t.Fatal("lost reached boundary", got, err, refusal)
	}
	if _, ok := refusal.operations[0].(*ssa.Call); !ok {
		t.Fatal("missing actual call")
	}
	if _, ok := refusal.operations[1].(*ssa.BinOp); !ok {
		t.Fatal("missing unsupported operation")
	}
}
