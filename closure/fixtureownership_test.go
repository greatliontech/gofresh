package closure

import (
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	progpkg "github.com/greatliontech/gofresh/closure/internal/program"
)

func TestFixturePreparationKeepsSSAConsumerOwnership(t *testing.T) {
	if testing.Short() {
		t.Skip("checks consumers against two SSA owners of one typed load")
	}
	const path = "example.com/preparedowner"
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod": "module " + path + "\n\ngo 1.27\n",
		"p.go": `package p
type Row[T any]struct{Name string;F T}
func a(){}
func helper[T any](name string,f T)[]Row[T]{return []Row[T]{{name,f}}}
func F()[]Row[func()]{return helper("a",a)}
var Marker = "initial"
func init(){Marker="ready"}
`,
	})
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := progpkg.Prepare(t.Context(), h.dir, h.packageEnv, h.buildFlags, path)
	if err != nil {
		t.Fatal(err)
	}
	metas, err := h.list(path)
	if err != nil {
		t.Fatal(err)
	}
	var sources [2]computationSource
	var binders [2]*selectedSourceBinder
	var generic [2]*ssa.Function
	var initialization [2]*sourceInitialization
	var packets [2]*checkedRegion
	for i := range sources {
		p, err := prepared.Build(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		sources[i] = computationSource{prog: p, metas: metas}
		binders[i] = selectedSourceFixtureBinder(t, sources[i])
		for _, block := range p.Roots["F"].Blocks {
			for _, instruction := range block.Instrs {
				if call, ok := instruction.(*ssa.Call); ok {
					if target := call.Call.StaticCallee(); target != nil && target.Origin() == p.Roots["helper"] {
						generic[i] = target
					}
				}
			}
		}
		if generic[i] == nil || len(generic[i].TypeArgs()) != 1 || len(generic[i].Blocks) == 0 {
			t.Fatal("materialized generic control absent")
		}
		// Exercise actual literal/callback transport with no numeric-layout
		// selection. This is the same supported carrier as the loaded generic
		// region fixture, not a new numeric-specialization capability.
		if region := proveSourceRegion(t, sources[i]); len(region.calls) != 1 || region.calls[0].bound.function != generic[i] {
			t.Fatal("own generic region was not bound")
		}
		pkg := binders[i].pkgs[p.Roots["F"].Pkg.Pkg]
		initialization[i], err = binders[i].bindInitialization(pkg)
		if err != nil {
			t.Fatal("own compiler initializer binding", err)
		}
		init := initialization[i]
		input := regionInput{owner: p.Prog, root: init.function, entry: init.entry, use: init.end, premises: sourceStartupPremises()}
		proposal, err := proposeRegion(t.Context(), input, defaultRegionLimits())
		if err != nil {
			t.Fatal("own initializer proposal", err)
		}
		packets[i], err = checkRegion(t.Context(), input, proposal, defaultRegionLimits())
		if err != nil {
			t.Fatal("own initializer interpretation", err)
		}
		calls, err := binders[i].bindRegionCalls(packets[i])
		if err != nil || len(calls) != 1 {
			t.Fatalf("own initializer dependency binding: %v", err)
		}
	}
	a, b := sources[0].prog, sources[1].prog
	if a.Prog == b.Prog || a.Roots["F"] == b.Roots["F"] || generic[0] == generic[1] || initialization[0].function == initialization[1].function {
		t.Fatal("control did not create independent SSA owners")
	}
	if a.Roots["F"].Syntax() != b.Roots["F"].Syntax() || a.Roots["F"].Object() != b.Roots["F"].Object() || a.Roots["F"].Signature != b.Roots["F"].Signature || a.Roots["F"].Pkg.Pkg != b.Roots["F"].Pkg.Pkg || generic[0].Origin().Syntax() != generic[1].Origin().Syntax() || generic[0].Object() != generic[1].Object() || generic[0].Origin().Signature != generic[1].Origin().Signature {
		t.Fatal("control did not share actual syntax, declarations and typed identity")
	}
	for i, binder := range binders {
		for _, pair := range [][2]*ssa.Function{{sources[i].prog.Roots["F"], sources[1-i].prog.Roots["F"]}, {generic[i], generic[1-i]}} {
			if own, err := binder.bindCallable(pair[0]); err != nil || own.function != pair[0] {
				t.Fatalf("own callable rejected: %v", err)
			}
			if _, err := binder.bindCallable(pair[1]); err == nil {
				t.Fatal("shared typed declaration authorized another SSA owner's callable")
			}
		}
		// Synthetic init has no callable declaration. Its real consumers are
		// the initialization binder and region kernel/source dependency binder.
		if _, err := binder.bindRegionCalls(packets[1-i]); err == nil {
			t.Fatal("foreign initializer packet borrowed selected-source ownership")
		}
		foreign := packets[1-i].input
		foreign.owner = sources[i].prog.Prog
		if proposal, err := proposeRegion(t.Context(), foreign, defaultRegionLimits()); err == nil || proposal != nil {
			t.Fatal("foreign initializer accepted under another region owner")
		}
	}
}
