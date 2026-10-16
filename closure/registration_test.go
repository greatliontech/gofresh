package closure

import (
	"context"
	"errors"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
)

func TestRegistrationActualSelectedMain(t *testing.T) {
	if testing.Short() {
		t.Skip("loads the actual selected generated package-test main")
	}
	const pkg = "example.com/registrationreceipt"
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod":    "module " + pkg + "\n\ngo 1.27\n",
		"p.go":      "package p\n",
		"p_test.go": "package p\nimport \"testing\"\nfunc TestFirst(t *testing.T){}\nfunc TestSecond(t *testing.T){}\n",
	})
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	loader := newFixturePrograms(t, h)
	loader.supply(t, pkg)
	metas, err := h.list(pkg)
	if err != nil {
		t.Fatal(err)
	}
	source := computationSource{prog: loader.loaded, metas: metas}
	receipt, err := deriveRegistration(t.Context(), source, pkg+".test", registrationLimits{})
	if err != nil {
		for _, p := range source.prog.Pkgs {
			if p.ID == pkg+".test" {
				t.Logf("selected main compiled=%q syntax=%s", p.CompiledGoFiles, p.Fset.PositionFor(p.Syntax[0].Pos(), false).Filename)
			}
		}
		for _, m := range metas {
			if m.ImportPath == pkg+".test" {
				t.Logf("selected main listing dir=%q gofiles=%q", m.Dir, m.GoFiles)
			}
		}
		t.Fatal(err)
	}
	if receipt.selected != receipt.main.pkg || receipt.init != source.prog.Prog.Package(receipt.selected.Types).Func("init") || len(receipt.arguments) != 5 || len(receipt.imports) == 0 || len(receipt.intervening) != 1 {
		t.Fatal("lost actual generated ownership or omitted initialization inventory")
	}
	arg := receipt.arguments[1]
	if len(arg.rows) != 2 || constant.StringVal(arg.rows[0].elements[0].scalar) != "TestFirst" || constant.StringVal(arg.rows[1].elements[0].scalar) != "TestSecond" || arg.rows[0].elements[1].target != source.prog.Roots["TestFirst"] || arg.rows[1].elements[1].target != source.prog.Roots["TestSecond"] {
		t.Fatal("lost two-sibling row/function correlation")
	}
	if receipt.call.Call.Args[arg.index] != arg.packet.input.use.operand || regionInstruction(arg.packet.input.use.at) != receipt.call || arg.value.location.object.context != receipt.init {
		t.Fatal("receipt does not end at the actual consuming operand")
	}
	if len(receipt.open) != 7 || len(receipt.construction.input.premises) != 4 || len(arg.packet.input.premises) != 3 || len(receipt.frame.heap.memory)+len(receipt.frame.dead) != len(receipt.construction.observations[0].state.memory) || len(receipt.frame.heap.values) != 0 || len(receipt.frame.dead) != 2 {
		t.Fatal("receipt erased open obligations or changed the exact heap handoff")
	}
	for i := 2; i < 5; i++ {
		if receipt.arguments[i].value.kind != regionSlice || receipt.arguments[i].value.length != 0 || len(receipt.arguments[i].rows) != 0 {
			t.Fatal("empty selected table was not transported", i)
		}
	}
	if receipt.arguments[0].value.kind != regionInterface || len(receipt.arguments[0].value.elements) != 1 {
		t.Fatal("actual concrete interface construction was not transported")
	}

	// Mutations are confined to this test-owned loaded representation and restored
	// before each next case. The independently retained typed source is the oracle.
	for _, mode := range []string{"swapped-pairing", "changed-store", "different-operand", "owner-mismatch", "duplicate-selection", "missing-initorder", "guard", "imported-init", "explicit-init", "synthetic-label"} {
		t.Run(mode, func(t *testing.T) {
			var restore func()
			switch mode {
			case "swapped-pairing":
				var stores []*ssa.Store
				for _, ins := range receipt.init.Blocks[1].Instrs {
					if store, ok := ins.(*ssa.Store); ok {
						if fn, ok := store.Val.(*ssa.Function); ok && (fn == source.prog.Roots["TestFirst"] || fn == source.prog.Roots["TestSecond"]) {
							stores = append(stores, store)
						}
					}
				}
				if len(stores) != 2 {
					t.Fatal("actual callback stores missing")
				}
				stores[0].Val, stores[1].Val = stores[1].Val, stores[0].Val
				restore = func() { stores[0].Val, stores[1].Val = stores[1].Val, stores[0].Val }
			case "changed-store":
				for _, ins := range receipt.init.Blocks[1].Instrs {
					if store, ok := ins.(*ssa.Store); ok {
						if value, ok := store.Val.(*ssa.Const); ok && value.Value != nil && value.Value.Kind() == constant.String && constant.StringVal(value.Value) == "TestFirst" {
							store.Val = ssa.NewConst(constant.MakeString("wrong"), types.Typ[types.String])
							restore = func() { store.Val = value }
							break
						}
					}
				}
			case "different-operand":
				old := receipt.call.Call.Args[1]
				receipt.call.Call.Args[1] = receipt.call.Call.Args[2]
				restore = func() { receipt.call.Call.Args[1] = old }
			case "owner-mismatch":
				old := receipt.main.decl
				receipt.selected.TypesInfo.Defs[old.Name] = source.prog.Roots["TestFirst"].Object()
				restore = func() { receipt.selected.TypesInfo.Defs[old.Name] = receipt.main.pkg.Types.Scope().Lookup("main") }
			case "duplicate-selection":
				old := source.prog.Pkgs
				source.prog.Pkgs = append(append(old[:len(old):len(old)], receipt.selected), receipt.selected)
				restore = func() { source.prog.Pkgs = old }
			case "missing-initorder":
				old := receipt.selected.TypesInfo.InitOrder
				receipt.selected.TypesInfo.InitOrder = old[1:]
				restore = func() { receipt.selected.TypesInfo.InitOrder = old }
			case "guard":
				store := receipt.init.Blocks[1].Instrs[0].(*ssa.Store)
				old := store.Val
				store.Val = ssa.NewConst(constant.MakeBool(false), types.Typ[types.Bool])
				restore = func() { store.Val = old }
			case "imported-init":
				call := receipt.imports[0]
				old := call.Call.Value
				call.Call.Value = receipt.intervening[0].Call.Value
				restore = func() { call.Call.Value = old }
			case "explicit-init":
				call := receipt.intervening[0]
				old := call.Call.Value
				call.Call.Value = receipt.imports[0].Call.Value
				restore = func() { call.Call.Value = old }
			case "synthetic-label":
				old := receipt.init.Synthetic
				receipt.init.Synthetic = "arbitrary non-authorizing annotation"
				restore = func() { receipt.init.Synthetic = old }
			}
			if restore == nil {
				t.Fatal("mutation not applied")
			}
			defer restore()
			got, err := deriveRegistration(t.Context(), source, pkg+".test", registrationLimits{})
			if mode == "synthetic-label" {
				if err != nil || got == nil {
					t.Fatal("synthetic text supplied authority", err)
				}
			} else if err == nil || got != nil {
				t.Fatal("source/SSA disagreement accepted", mode)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := deriveRegistration(ctx, source, pkg+".test", registrationLimits{}); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled registration returned evidence", err)
	}
	for _, dimension := range []string{"source-work", "source-bytes", "source-depth", "region-work", "region-nodes", "region-locations"} {
		t.Run(dimension, func(t *testing.T) {
			limits := defaultRegistrationLimits()
			switch dimension {
			case "source-work":
				limits.source.work = 1
			case "source-bytes":
				limits.source.bytes = 1
			case "source-depth":
				limits.source.depth = 1
			case "region-work":
				limits.region.work = 1
			case "region-nodes":
				limits.region.nodes = 1
			case "region-locations":
				limits.region.locations = 1
			}
			if got, err := deriveRegistration(t.Context(), source, pkg+".test", limits); got != nil || err == nil {
				t.Fatal("budget exhaustion returned evidence")
			}
		})
	}
}

// These selected source fixtures exercise the same structural construction with
// unrelated type, field, callback and receiver names. They do not stand in for
// the actual-loader generated-main test above.
func registrationFixture(t *testing.T, extra, main string) computationSource {
	t.Helper()
	text := `package main
type Row struct { Label string; Invoke func() }
type Context struct{}
func Alpha(){}
func Beta(){}
var collection = []Row{{"one", Alpha}, {"two", Beta}}
func receive(c any, rows []Row){}
func unknown(){}
` + extra + `
func main(){` + main + `}
func F(){}`
	const path = "example.com/renamedregistration"
	const filename = "/registration/main.go"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, text, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	pkg := types.NewPackage(path, "main")
	sizes := types.SizesFor("gc", "amd64")
	sp, info, err := ssautil.BuildPackage(&types.Config{Sizes: sizes}, fset, pkg, []*ast.File{file}, ssa.SanityCheckFunctions)
	if err != nil {
		t.Fatal(err)
	}
	p := &packages.Package{ID: path, PkgPath: path, Name: "main", Types: pkg, TypesInfo: info, TypesSizes: sizes, Fset: fset, Syntax: []*ast.File{file}, CompiledGoFiles: []string{filename}}
	return computationSource{
		prog:  &program{PkgPath: path, Prog: sp.Prog, Pkgs: []*packages.Package{p}, Roots: map[string]*ssa.Function{"F": sp.Func("F")}},
		metas: []listPkg{{ImportPath: path, Name: "main", Dir: "/registration", GoFiles: []string{"main.go"}}},
	}
}

func TestRegistrationStructuralTransport(t *testing.T) {
	for _, tc := range []struct{ name, extra, body, refusal string }{
		{"renamed", "", `receive(Context{}, collection)`, ""},
		{"explicit-open-init", `func init(){unknown()}`, `receive(Context{}, collection)`, ""},
		{"zero-initialization-open", `var implicit int`, `receive(Context{}, collection)`, ""},
		{"unused-lookalike", `var unused = []Row{{"unused", Beta}}`, `_ = unused; receive(Context{}, collection)`, ""},
		{"actual-other-table", `var unused = []Row{{"unused", Beta}}`, `receive(Context{}, unused)`, ""},
		{"unknown-call", "", `unknown(); receive(Context{}, collection)`, "call effects"},
		{"alias-mutation", "", `alias := collection; alias[0].Invoke = Beta; receive(Context{}, collection)`, "correlation"},
		{"header-replacement", `var unused = []Row{{"one", Alpha}, {"two", Beta}}`, `collection = unused; receive(Context{}, collection)`, "different provenance"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := registrationFixture(t, tc.extra, tc.body)
			got, err := deriveRegistration(t.Context(), source, source.prog.Pkgs[0].ID, registrationLimits{})
			if tc.refusal != "" {
				if got != nil || err == nil || !strings.Contains(err.Error(), tc.refusal) {
					t.Fatal("wrong refusal", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			arg := got.arguments[1]
			if tc.name == "actual-other-table" {
				if arg.object.Name() != "unused" || len(arg.rows) != 1 || constant.StringVal(arg.rows[0].elements[0].scalar) != "unused" {
					t.Fatal("convenient unused table substituted for actual operand")
				}
			} else if arg.object.Name() != "collection" || len(arg.rows) != 2 || arg.rows[0].elements[1].target == arg.rows[1].elements[1].target {
				t.Fatal("renamed structural rows lost their identities")
			}
			if tc.name == "explicit-open-init" && (len(got.intervening) != 1 || got.frame.from != got.construction.input.use.at) {
				t.Fatal("explicit initialization disappeared")
			}
			if tc.name == "unused-lookalike" {
				var other ssa.Value
				for _, ins := range got.call.Block().Instrs {
					if load, ok := ins.(*ssa.UnOp); ok && load.Op == token.MUL {
						if global, ok := load.X.(*ssa.Global); ok && global.Name() == "unused" {
							other = load
						}
					}
				}
				if other == nil {
					t.Fatal("unused actual load absent")
				}
				got.call.Call.Args[1] = other
				if receipt, err := deriveRegistration(t.Context(), source, source.prog.Pkgs[0].ID, registrationLimits{}); receipt != nil || err == nil || !strings.Contains(err.Error(), "actual consuming operand") {
					t.Fatal("unused-table operand acquired provenance", err)
				}
			}
		})
	}
}

func TestRegistrationInitializerAllocationAndLiveFrame(t *testing.T) {
	source := registrationFixture(t, `var unused = []Row{{"one", Alpha}, {"two", Beta}}`, `receive(Context{}, collection)`)
	receipt, err := deriveRegistration(t.Context(), source, source.prog.Pkgs[0].ID, registrationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(receipt.frame.heap.memory) != 4 || len(receipt.frame.dead) != 4 || len(receipt.frame.heap.values) != 0 {
		t.Fatal("frame did not distinguish live headers/backings from dead row temporaries")
	}
	for object := range receipt.frame.heap.memory {
		if object.kind == regionAllocation && !object.site.(*ssa.Alloc).Heap {
			t.Fatal("stack temporary survived initializer frame")
		}
	}
	for _, object := range receipt.frame.dead {
		if object.kind != regionAllocation || object.site.(*ssa.Alloc).Heap {
			t.Fatal("live backing discarded as a row temporary")
		}
	}
	var stores []*ssa.Store
	for _, instruction := range receipt.init.Blocks[1].Instrs {
		if store, ok := instruction.(*ssa.Store); ok {
			if global, ok := store.Addr.(*ssa.Global); ok && global.Object() != nil {
				stores = append(stores, store)
			}
		}
	}
	if len(stores) != 2 {
		t.Fatal("table-header stores absent")
	}
	// Both tables have byte-for-byte identical row values. Substituting the first
	// table's backing at the second store must not establish the second literal's
	// allocation provenance merely because every row comparison succeeds.
	stores[1].Val = stores[0].Val
	if got, err := deriveRegistration(t.Context(), source, source.prog.Pkgs[0].ID, registrationLimits{}); got != nil || err == nil || !strings.Contains(err.Error(), "selected initializer allocation") {
		t.Fatal("identical unused backing replaced selected allocation", err)
	}
}
