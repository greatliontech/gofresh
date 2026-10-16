package closure

import (
	"context"
	"errors"
	"fmt"
	"go/constant"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	progpkg "github.com/greatliontech/gofresh/closure/internal/program"
)

func TestRegionCallConcreteOracle(t *testing.T) {
	for _, tc := range []struct{ name, source string }{
		{"factories", `type Row struct{Name string;F func()};func a(){};func b(){};func factory(name string,f func())*Row{return &Row{name,f}};func F()[]*Row{x:=factory("a",a);y:=factory("b",b);return []*Row{x,y}}`},
		{"same-code-environments", `func factory(x int)func()int{return func()int{return x}};func F()[]func()int{a:=factory(1);b:=factory(2);return []func()int{a,b}}`},
		{"invoke-returned-environments", `func factory(x int)func()int{return func()int{return x}};func F()[]int{a:=factory(1);b:=factory(2);return []int{a(),b()}}`},
		{"mutate-returned-environment", `func factory(x int)(func(),func()int){return func(){x=9},func()int{return x}};func F()[]int{write,read:=factory(1);_,other:=factory(2);write();return []int{read(),other()}}`},
		{"arguments", `func a(){};func b(){};func pair(a,b func())[]func(){return []func(){a,b}};func F()[]func(){return pair(b,a)}`},
		{"receiver-alias", `type S struct{X int};func(s *S)Set(v int){s.X=v};func F()int{s:=S{1};p:=&s.X;s.Set(2);return *p}`},
		{"closure-cell", `func F()int{x:=1;f:=func(){x=2};f();return x}`},
		{"callback", `func apply(f func()){f()};func F()int{x:=1;apply(func(){x=2});return x}`},
		{"multiple-returns", `type Row struct{Name string;F func()};func a(){};func b(){};func pair(flag bool)(string,func()){if flag{return "a",a};return "b",b};func F(flag bool)Row{name,f:=pair(flag);return Row{name,f}}`},
		{"heap-and-return", `var g int;func helper(x int)int{g=x;return x};func F()[]int{x:=helper(2);return []int{x,g}}`},
		{"escaped-old-allocation", `type Box struct{X int};var old *Box;func factory(x int)*Box{return &Box{x}};func F()[]*Box{old=factory(1);next:=factory(2);return []*Box{old,next}}`},
		{"nested-contexts", `func leaf(x int)*int{return &x};func wrapper(x int)*int{return leaf(x)};func F()[]*int{return []*int{wrapper(1),wrapper(2)}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := regionFixture(t, tc.source)
			checked, _ := proveRegionFixture(t, in)
			if len(checked.calls) == 0 {
				t.Fatal("no checked subordinate retained")
			}
			for _, out := range checked.observations {
				if !regionTestPrecise(out.value, out.state, 0) {
					t.Fatal("positive call relation widened its result")
				}
			}
			if len(in.root.Params) == 0 {
				assertRegionCovers(t, checked, executeRegionConcrete(t, in))
			} else {
				for _, flag := range []bool{false, true} {
					assertRegionCovers(t, checked, executeRegionConcrete(t, in, flag))
				}
			}
		})
	}
}

func TestRegionCallRepeatedSiteIsSummary(t *testing.T) {
	in := regionFixture(t, `func factory(x int)*int{return &x};func F(again,next bool)*int{var old *int;x:=1;for again{p:=factory(x);if old==nil{old=p};x=2;again=next;next=false};return old}`)
	checked, _ := proveRegionFixture(t, in)
	for _, args := range [][2]bool{{false, false}, {true, false}, {true, true}} {
		assertRegionCovers(t, checked, executeRegionConcrete(t, in, args[0], args[1]))
	}
	found := false
	for _, out := range checked.observations {
		for object, value := range out.state.memory {
			if object.kind == regionAllocation && object.context != in.root {
				found = true
				if value.kind != regionUnknown {
					t.Fatal("repeated call allocation acquired singleton contents")
				}
			}
		}
	}
	if !found {
		t.Fatal("test did not observe repeated allocation")
	}
	in.initial.values = map[ssa.Value]regionValue{}
	for _, parameter := range in.root.Params {
		in.initial.values[parameter] = regionValue{typ: parameter.Type(), kind: regionConstant, scalar: constant.MakeBool(true)}
	}
	bound, _ := proveRegionFixture(t, in)
	assertRegionCovers(t, bound, executeRegionConcrete(t, in, true, true))
}

func TestRegionCallSameSiteDifferentInputs(t *testing.T) {
	in := regionFixture(t, `func helper(x int)int{return x};func F(again,next bool)int{x:=1;last:=0;for again{last=helper(x);x=2;again=next;next=false};return last}`)
	in.initial.values = map[ssa.Value]regionValue{}
	for _, parameter := range in.root.Params {
		in.initial.values[parameter] = regionValue{typ: parameter.Type(), kind: regionConstant, scalar: constant.MakeBool(true)}
	}
	checked, _ := proveRegionFixture(t, in)
	actual := executeRegionConcrete(t, in, true, true)
	if actual != int64(2) {
		t.Fatalf("reference execution=%v,want 2", actual)
	}
	for _, out := range checked.observations {
		if out.value.kind != regionConstant {
			t.Fatal("scalar loop lost precision")
		}
	}
	assertRegionCovers(t, checked, actual)
}

func TestRegionCallRefusals(t *testing.T) {
	for _, source := range []string{
		`func native()int;func F()int{return native()}`,
		`func native();func helper()int{native();return 1};func F()int{return helper()}`,
		`func F()int{return F()}`,
		`func helper()int{return F()};func F()int{return helper()}`,
		`func F(f func()int)int{return f()}`,
		`func helper(){go func(){}()};func F()int{helper();return 1}`,
		`func helper(){defer func(){}()};func F()int{helper();return 1}`,
		`type S struct{X int};func(s *S)M()int{return s.X};func F()int{s:=S{1};f:=s.M;return f()}`,
	} {
		t.Run(source, func(t *testing.T) {
			in := regionFixture(t, source)
			if p, err := proposeRegion(t.Context(), in, defaultRegionLimits()); err == nil || p != nil {
				t.Fatalf("unsupported call acquired proof: %v", err)
			}
		})
	}
}

func TestRegionCallForgedSubordinates(t *testing.T) {
	const source = `var g int;func helper(a,b int)(int,int){if a==1{g=b;return a,b};g=a;return b,a};func F()[]int{x,y:=helper(1,2);return []int{x,y,g}}`
	for _, corruption := range []string{"missing", "arguments", "context", "return", "heap", "edge"} {
		t.Run(corruption, func(t *testing.T) {
			in := regionFixture(t, source)
			_, p := proveRegionFixture(t, in)
			if len(p.calls) != 1 {
				t.Fatalf("unexpected subordinate count %d", len(p.calls))
			}
			proof := p.calls[0]
			switch corruption {
			case "missing":
				p.calls = nil
			case "arguments":
				a, b := proof.target.Params[0], proof.target.Params[1]
				proof.initial.values[a], proof.initial.values[b] = proof.initial.values[b], proof.initial.values[a]
			case "context":
				proof.invocation.path += "/caller-label"
			case "edge":
				for block := range proof.entries {
					if block != proof.target.Blocks[0] {
						delete(proof.entries, block)
						break
					}
				}
			case "return", "heap":
				changed := false
				for block, states := range proof.entries {
					if block == proof.target.Blocks[0] {
						continue
					}
					for i, state := range states {
						if corruption == "return" {
							state.values[proof.target.Params[0]] = regionValue{typ: types.Typ[types.Int], kind: regionConstant, scalar: constant.MakeInt64(9)}
						} else {
							global := proof.target.Pkg.Members["g"].(*ssa.Global)
							state.memory[regionObject{kind: regionGlobal, site: global}] = regionValue{typ: types.Typ[types.Int], kind: regionConstant, scalar: constant.MakeInt64(9)}
						}
						states[i] = state
						changed = true
					}
					proof.entries[block] = states
				}
				if !changed {
					t.Fatal("no callee successor changed")
				}
			}
			if packet, err := checkRegion(t.Context(), in, p, defaultRegionLimits()); err == nil || packet != nil {
				t.Fatal("forged callee acquired authority")
			}
		})
	}
}

func TestRegionCallForgedEntryCannotReplaceActualArgument(t *testing.T) {
	in := regionFixture(t, `func helper(x int)int{return x};func F()int{return helper(1)}`)
	_, proposal := proveRegionFixture(t, in)
	if len(proposal.calls) != 1 {
		t.Fatal("expected one subordinate")
	}
	proof := proposal.calls[0]
	parameter := proof.target.Params[0]
	// Replace only the invariant, not the independently matched actual input.
	// The otherwise complete one-block proof has no edge omission to hide a
	// failure to check the actual/formal entry inclusion.
	proof.entries[proof.target.Blocks[0]] = []regionState{{values: map[ssa.Value]regionValue{parameter: {typ: parameter.Type(), kind: regionConstant, scalar: constant.MakeInt64(9)}}, memory: proof.initial.memory}}
	if checked, err := checkRegion(t.Context(), in, proposal, defaultRegionLimits()); checked != nil || err == nil {
		t.Fatal("callee invariant replaced actual argument without proof")
	}
}

func TestRegionCallOwnedInputAndSharedBounds(t *testing.T) {
	in := regionFixture(t, `func helper(x int)*int{return &x};func F()[]*int{return []*int{helper(1),helper(2)}}`)
	_, p := proveRegionFixture(t, in)
	ctx := &regionMutatingContext{Context: t.Context(), mutate: func() {
		for _, proof := range p.calls {
			clear(proof.initial.values)
			clear(proof.initial.memory)
			for block, states := range proof.entries {
				for _, state := range states {
					clear(state.values)
					clear(state.memory)
				}
				delete(proof.entries, block)
			}
			proof.invocation.path = "changed"
		}
		p.calls = nil
	}}
	checked, err := checkRegion(ctx, in, p, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	assertRegionCovers(t, checked, executeRegionConcrete(t, in))
	// Each body individually fits; the common node counter must include all
	// actual caller/callee contexts rather than reset at each helper call.
	limits := defaultRegionLimits()
	own := 0
	for _, block := range in.root.Blocks {
		own += len(block.Instrs)
	}
	helper := in.root.Pkg.Func("helper")
	one := 0
	for _, block := range helper.Blocks {
		one += len(block.Instrs)
	}
	limits.nodes = own + one
	if p, err := proposeRegion(t.Context(), in, limits); err == nil || p != nil {
		t.Fatal("callee node budgets reset independently")
	}
	limits = defaultRegionLimits()
	limits.depth = 1
	nested := regionFixture(t, `func leaf()int{return 1};func helper()int{return leaf()};func F()int{return helper()}`)
	if p, err := proposeRegion(t.Context(), nested, limits); err == nil || p != nil {
		t.Fatal("call-depth budget ignored")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if p, err := proposeRegion(cancelled, in, defaultRegionLimits()); p != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled call proposal: %v", err)
	}
	_, p = proveRegionFixture(t, in)
	if result, err := checkRegion(cancelled, in, p, defaultRegionLimits()); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled call check: %v", err)
	}
	counted := &regionCallCountingContext{Context: t.Context()}
	if _, err := checkRegion(counted, in, p, defaultRegionLimits()); err != nil {
		t.Fatal(err)
	}
	if counted.checks < 2 {
		t.Fatal("checker did not observe its context")
	}
	interrupted := &regionCallCountingContext{Context: t.Context(), stop: counted.checks / 2}
	if result, err := checkRegion(interrupted, in, p, defaultRegionLimits()); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted call checking: %v", err)
	}
}

type regionCallCountingContext struct {
	context.Context
	checks, stop int
}

func (c *regionCallCountingContext) Err() error {
	c.checks++
	if c.stop > 0 && c.checks >= c.stop {
		return context.Canceled
	}
	return c.Context.Err()
}

func TestRegionCallLoadedGenericCarrier(t *testing.T) {
	if testing.Short() {
		t.Skip("actual selected package load")
	}
	dir := t.TempDir()
	const path = "example.com/regioncall"
	const source = `package carrier
type Row[T any]struct{Name string;F T}
func a(){}
func b(){}
func helper[T any](name string,f T)[]Row[T]{return []Row[T]{{name,f}}}
func F()[][]Row[func()]{return [][]Row[func()]{helper("a",a),helper("b",b)}}
`
	for name, text := range map[string]string{"go.mod": "module " + path + "\n\ngo 1.27.0\n", "carrier.go": source} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := progpkg.Load(t.Context(), dir, append(os.Environ(), "GOWORK=off", "GOPACKAGESDRIVER=off"), nil, path)
	if err != nil {
		t.Fatal(err)
	}
	fn := loaded.Roots["F"]
	if fn == nil {
		t.Fatal("loaded root missing")
	}
	in := regionInput{owner: loaded.Prog, root: fn, entry: regionPoint{fn.Blocks[0], 0}, premises: []string{"actual loader-owned typed SSA; source/native application binding remains open"}}
	for _, block := range fn.Blocks {
		for i, ins := range block.Instrs {
			if ret, ok := ins.(*ssa.Return); ok {
				in.use = regionUse{regionPoint{block, i}, ret.Results[0]}
			}
		}
	}
	checked, _ := proveRegionFixture(t, in)
	if len(checked.calls) != 2 {
		t.Fatalf("generic contexts = %d, want 2", len(checked.calls))
	}
	for _, proof := range checked.calls {
		if proof.target.Origin() == nil || len(proof.target.TypeArgs()) != 1 {
			t.Fatal("helper was not the actual loaded specialization")
		}
	}
	for _, out := range checked.observations {
		if !regionTestPrecise(out.value, out.state, 0) {
			t.Fatal("generic carrier widened")
		}
	}
	assertRegionCovers(t, checked, executeRegionConcrete(t, in))
}

func FuzzRegionCallFactoryOracle(f *testing.F) {
	f.Add(int8(1), int8(2), false)
	f.Add(int8(-3), int8(7), true)
	f.Fuzz(func(t *testing.T, a, b int8, swap bool) {
		text := fmt.Sprintf(`type Box struct{X int};func factory(x int)*Box{return &Box{x}};func F(flag bool)[]*Box{a:=factory(%d);b:=factory(%d);if flag{a,b=b,a};return []*Box{a,b}}`, a, b)
		in := regionFixture(t, text)
		checked, _ := proveRegionFixture(t, in)
		for _, out := range checked.observations {
			if !regionTestPrecise(out.value, out.state, 0) {
				t.Fatal("factory relation widened")
			}
		}
		assertRegionCovers(t, checked, executeRegionConcrete(t, in, swap))
	})
}

// Retain a source-level address of each distinct invocation's object. This
// assertion complements the concrete oracle: function identity alone cannot be
// a singleton allocation identity for multiple calls to that function.
func TestRegionCallAllocationContextsAreActualSites(t *testing.T) {
	in := regionFixture(t, `func factory(x int)*int{return &x};func F()[]*int{return []*int{factory(1),factory(2)}}`)
	checked, _ := proveRegionFixture(t, in)
	var contexts []regionInvocation
	for object := range checked.observations[0].state.memory {
		if object.kind == regionAllocation && object.context != in.root {
			contexts = append(contexts, object.invocation)
		}
	}
	if len(contexts) != 2 || contexts[0] == contexts[1] {
		t.Fatalf("factory allocations share contexts: %v", contexts)
	}
	if !slices.ContainsFunc(checked.calls, func(p *regionCallProof) bool { return p.invocation == contexts[0] }) {
		t.Fatal("allocation context lacks a checked actual call")
	}
}

func TestRegionCallInputObjectsHaveActualOwners(t *testing.T) {
	in := regionFixture(t, `func helper(p *int)int{return *p};func F(p *int)int{return helper(p)}`)
	parameter := in.root.Params[0]
	copy := *parameter
	object := regionObject{kind: regionFormal, site: &copy, context: in.root}
	in.initial = regionState{values: map[ssa.Value]regionValue{parameter: {typ: parameter.Type(), kind: regionPointer, location: regionLocation{object: object}}}, memory: map[regionObject]regionValue{object: {typ: types.Typ[types.Int], kind: regionConstant, scalar: constant.MakeInt64(1)}}}
	if proof, err := proposeRegion(t.Context(), in, defaultRegionLimits()); proof != nil || err == nil {
		t.Fatal("detached source identity acquired a region relation")
	}
}
