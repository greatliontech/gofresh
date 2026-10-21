package closure

import (
	"context"
	"errors"
	"go/ast"
	"go/constant"
	"go/types"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
)

func sourceRegionInput(t *testing.T, s computationSource) regionInput {
	t.Helper()
	fn := s.prog.Roots["F"]
	in := regionInput{owner: s.prog.Prog, root: fn, entry: regionPoint{fn.Blocks[0], 0}, premises: []string{"immutable typed SSA; source lowering, frame, concurrency and native application remain open"}}
	for _, block := range fn.Blocks {
		for i, instruction := range block.Instrs {
			if ret, ok := instruction.(*ssa.Return); ok {
				in.use = regionUse{at: regionPoint{block, i}}
				if len(ret.Results) == 1 {
					in.use.operand = ret.Results[0]
				}
			}
		}
	}
	return in
}

func sourceRegionFixture(t *testing.T, text string, instantiate bool) computationSource {
	t.Helper()
	s := relationFixture(t, text, 64)
	if instantiate {
		p := s.prog.Pkgs[0]
		pkg := types.NewPackage(p.PkgPath, p.Name)
		sp, info, err := ssautil.BuildPackage(&types.Config{Sizes: p.TypesSizes}, p.Fset, pkg, p.Syntax, ssa.SanityCheckFunctions|ssa.InstantiateGenerics)
		if err != nil {
			t.Fatal(err)
		}
		p.Types, p.TypesInfo = pkg, info
		s.prog.Prog, s.prog.Roots["F"] = sp.Prog, sp.Func("F")
	}
	return s
}

func proveSourceRegion(t *testing.T, s computationSource) *sourceRegion {
	t.Helper()
	in := sourceRegionInput(t, s)
	p, err := proposeRegion(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	r, err := checkSourceRegion(t.Context(), s, in, p, defaultRegistrationLimits().source, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSourceRegionSelectedCallsAndEnvironments(t *testing.T) {
	s := sourceRegionFixture(t, `func factory(x int)func()int{return func()int{return x}};func F()[]int{a:=factory(1);b:=factory(2);return []int{a(),b()}}`, false)
	r := proveSourceRegion(t, s)
	if r.root.function != s.prog.Roots["F"] || len(r.calls) != len(r.packet.calls) {
		t.Fatal("missing selected root or subordinate")
	}
	var closures []sourceRegionCall
	for i, call := range r.calls {
		if call.call != r.packet.calls[i] || call.bound.function != call.call.target || call.bound.identity.source == ([32]byte{}) || call.bound.identity.body == ([32]byte{}) {
			t.Fatal("bound targets detached from checked dependencies")
		}
		if call.bound.parent != nil {
			closures = append(closures, call)
		}
	}
	if len(closures) != 2 || closures[0].bound.function != closures[1].bound.function || closures[0].bound.parent != s.prog.Prog.Package(s.prog.Pkgs[0].Types).Func("factory") {
		t.Fatal("lost exact lexical target/parent")
	}
	free := closures[0].bound.function.FreeVars[0]
	if closures[0].call.invocation == closures[1].call.invocation || regionSameValue(closures[0].call.initial.values[free], closures[1].call.initial.values[free]) {
		t.Fatal("same code collapsed distinct captured environments")
	}
	if len(r.packet.openObligations()) == 0 {
		t.Fatal("source binding granted native/harness authority")
	}
}

func TestSourceRegionLexicalAndSpecializedRoots(t *testing.T) {
	for _, generic := range []bool{false, true} {
		text := `func F()func()int{return func()int{return 7}}`
		if generic {
			text = `func helper[T any]()int{return 7};func F()int{return helper[int]()}`
		}
		s := sourceRegionFixture(t, text, true)
		root := s.prog.Roots["F"]
		if generic {
			for _, block := range root.Blocks {
				for _, ins := range block.Instrs {
					if call, ok := ins.(*ssa.Call); ok {
						s.prog.Roots["F"] = call.Call.StaticCallee()
					}
				}
			}
		} else {
			s.prog.Roots["F"] = root.AnonFuncs[0]
		}
		r := proveSourceRegion(t, s)
		if r.root.function != s.prog.Roots["F"] || generic && len(r.root.typeArguments) != 1 || !generic && r.root.parent != root {
			t.Fatal("root lost its selected lexical/specialization identity")
		}
	}
}

func TestSourceRegionOnlyCheckedDependencies(t *testing.T) {
	s := sourceRegionFixture(t, `func helper()int{return 7};func native()int;func F()int{return helper()}`, false)
	in := sourceRegionInput(t, s)
	p, err := proposeRegion(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	foreign := sourceRegionFixture(t, `func F()int{return 8}`, false)
	p.calls = append(p.calls, &regionCallProof{target: foreign.prog.Roots["F"]}, &regionCallProof{target: s.prog.Prog.Package(s.prog.Pkgs[0].Types).Func("native")})
	r, err := checkSourceRegion(t.Context(), s, in, p, defaultRegistrationLimits().source, defaultRegionLimits())
	if err != nil || len(r.calls) != 1 || r.calls[0].bound.function.Name() != "helper" {
		t.Fatal("proposal-only target supplied/blocked selected authority", err)
	}
	// The kernel does not consume TypesInfo. An actual checked target still has
	// to bind to the selected declaration even when its SSA grammar checks.
	fn := r.calls[0].bound.function
	decl := fn.Syntax().(*ast.FuncDecl)
	s.prog.Pkgs[0].TypesInfo.Defs[decl.Name] = foreign.prog.Roots["F"].Object()
	if got, err := checkSourceRegion(t.Context(), s, in, p, defaultRegistrationLimits().source, defaultRegionLimits()); got != nil || err == nil {
		t.Fatal("actual checked dependency escaped selected binding")
	}
}

func TestSourceRegionCacheCannotSupplySemantics(t *testing.T) {
	s := sourceRegionFixture(t, `func helper(){println(7)};func F(){helper()}`, false)
	b := selectedSourceFixtureBinder(t, s)
	for _, fn := range []*ssa.Function{s.prog.Roots["F"], s.prog.Prog.Package(s.prog.Pkgs[0].Types).Func("helper")} {
		if _, err := b.bindCallable(fn); err != nil {
			t.Fatal(err)
		}
	}
	in := sourceRegionInput(t, s)
	checker := &registrationChecker{selectedSourceBinder: b, root: in.root, limits: defaultRegionLimits()}
	if packet, err := checker.check(in); packet != nil || err == nil || len(checker.callBindings) != 0 {
		t.Fatal("selected identity approved an unsupported effect")
	}
	for _, text := range []string{`func native()int;func F()int{return native()}`, `type S struct{};func(S)M()int{return 1};func F()int{s:=S{};f:=s.M;return f()}`} {
		s := sourceRegionFixture(t, text, false)
		in := sourceRegionInput(t, s)
		if p, err := proposeRegion(t.Context(), in, defaultRegionLimits()); p != nil || err == nil {
			t.Fatal("opaque/wrapper target acquired semantic authority")
		}
	}
}

func TestSelectedCallableLexicalRefusals(t *testing.T) {
	for _, mode := range []string{"membership", "copied-literal", "literal-type", "copied-function", "foreign", "wrapper", "bodyless", "generic-closure", "receiver-specialization"} {
		t.Run(mode, func(t *testing.T) {
			text := `func F()int{x:=1;f:=func()int{return x};return f()}`
			if mode == "wrapper" {
				text = `type S struct{};func(S)M()int{return 1};func F()int{s:=S{};f:=s.M;return f()}`
			}
			if mode == "bodyless" {
				text = `func native()int;func F()int{return native()}`
			}
			if mode == "generic-closure" {
				text = `func factory[T any](x T)func()T{return func()T{return x}};func F()int{return factory(1)()}`
			}
			if mode == "receiver-specialization" {
				text = `type S[T any]struct{X T};func(s S[T])M()T{return s.X};func F()int{return S[int]{1}.M()}`
			}
			s := sourceRegionFixture(t, text, true)
			root := s.prog.Roots["F"]
			var target *ssa.Function
			if len(root.AnonFuncs) != 0 {
				target = root.AnonFuncs[0]
			}
			for _, block := range root.Blocks {
				for _, instruction := range block.Instrs {
					if call, ok := instruction.(*ssa.Call); ok && call.Call.StaticCallee() != nil && target == nil {
						target = call.Call.StaticCallee()
					}
					if closure, ok := instruction.(*ssa.MakeClosure); ok && mode == "wrapper" {
						target = closure.Fn.(*ssa.Function)
					}
				}
			}
			if mode == "generic-closure" {
				target = target.AnonFuncs[0]
			}
			if target == nil {
				t.Fatal("fixture has no target")
			}
			switch mode {
			case "membership":
				root.AnonFuncs = nil
			case "copied-literal":
				decl := root.Syntax().(*ast.FuncDecl)
				assignment := decl.Body.List[1].(*ast.AssignStmt)
				copy := *assignment.Rhs[0].(*ast.FuncLit)
				assignment.Rhs[0] = &copy
			case "literal-type":
				lit := target.Syntax().(*ast.FuncLit)
				tv := s.prog.Pkgs[0].TypesInfo.Types[lit]
				tv.Type = types.NewSignatureType(nil, nil, nil, nil, nil, false)
				s.prog.Pkgs[0].TypesInfo.Types[lit] = tv
			case "copied-function":
				copy := *target
				target = &copy
			case "foreign":
				target = sourceRegionFixture(t, `func F()int{return 1}`, false).prog.Roots["F"]
			}
			b := selectedSourceFixtureBinder(t, s)
			if _, err := b.bindCallable(target); err == nil {
				t.Fatal("unbound lexical/opaque/specialized target accepted")
			}
		})
	}
}

func TestSelectedCallableGenericBinding(t *testing.T) {
	const text = `type Row[T any]struct{Name string;F T};func a(){};func helper[T any](name string,f T)[]Row[T]{return []Row[T]{{name,f}}};func other[T any](x T)T{return x};func F()[]Row[func()]{return helper("a",a)}`
	for _, mode := range []string{"valid", "label", "signature", "type-arguments", "origin", "origin-signature", "copy", "removed-body", "wrapper", "wrapper-label", "budget"} {
		t.Run(mode, func(t *testing.T) {
			s := sourceRegionFixture(t, text, mode != "wrapper" && mode != "wrapper-label")
			var target *ssa.Function
			for _, block := range s.prog.Roots["F"].Blocks {
				for _, ins := range block.Instrs {
					if call, ok := ins.(*ssa.Call); ok {
						target = call.Call.StaticCallee()
					}
				}
			}
			if target == nil || target.Origin() == nil {
				t.Fatal("fixture has no specialization")
			}
			switch mode {
			case "label":
				target.Synthetic = "not an approval label"
			case "wrapper-label":
				target.Synthetic = ""
			case "signature":
				target.Signature = s.prog.Roots["F"].Signature
			case "type-arguments":
				wrong, err := types.Instantiate(nil, target.Origin().Signature, []types.Type{types.Typ[types.Int]}, true)
				if err != nil {
					t.Fatal(err)
				}
				target.Signature = wrong.(*types.Signature)
			case "origin":
				decl := target.Origin().Syntax().(*ast.FuncDecl)
				s.prog.Pkgs[0].TypesInfo.Defs[decl.Name] = s.prog.Prog.Package(s.prog.Pkgs[0].Types).Func("other").Object()
			case "origin-signature":
				other := s.prog.Prog.Package(s.prog.Pkgs[0].Types).Func("other")
				target.Origin().Signature = other.Signature
				wrong, err := types.Instantiate(nil, other.Signature, target.TypeArgs(), true)
				if err != nil {
					t.Fatal(err)
				}
				target.Signature = wrong.(*types.Signature)
			case "copy":
				copy := *target
				target = &copy
			case "removed-body":
				target.Syntax().(*ast.FuncDecl).Body = nil
			}
			b := selectedSourceFixtureBinder(t, s)
			if mode == "budget" {
				b.limits.work = b.work + 1
			}
			bound, err := b.bindCallable(target)
			if mode == "valid" || mode == "label" {
				if err != nil {
					t.Fatal(err)
				}
				if bound.origin != target.Origin() || bound.function != target || len(bound.typeArguments) != 1 || !types.Identical(bound.typeArguments[0], types.NewSignatureType(nil, nil, nil, nil, nil, false)) {
					t.Fatal("lost specialization")
				}
				if _, err := b.bindDeclaration(target); err == nil {
					t.Fatal("ordinary declaration binder accepted a specialization")
				}
			} else if err == nil {
				t.Fatal("invalid specialization acquired selected binding")
			}
		})
	}
}

func TestSourceRegionBindingBudgetsAndCancellation(t *testing.T) {
	s := sourceRegionFixture(t, `func helper()int{return 7};func F()int{return helper()}`, false)
	b := selectedSourceFixtureBinder(t, s)
	root := s.prog.Roots["F"]
	if _, err := b.bindCallable(root); err != nil {
		t.Fatal(err)
	}
	b.limits.work = b.work
	if _, err := b.bindCallable(root); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatal("warm callable cache bypassed cumulative work bound", err)
	}
	b = selectedSourceFixtureBinder(t, s)
	if _, err := b.bindCallable(root); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	b.ctx = ctx
	if _, err := b.bindCallable(root); !errors.Is(err, context.Canceled) {
		t.Fatal("warm callable cache bypassed cancellation", err)
	}
	in := sourceRegionInput(t, s)
	p, err := proposeRegion(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	if r, err := checkSourceRegion(ctx, s, in, p, defaultRegistrationLimits().source, defaultRegionLimits()); r != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled source region", err)
	}
	if r, err := checkSourceRegion(nil, s, in, p, defaultRegistrationLimits().source, defaultRegionLimits()); r != nil || err == nil {
		t.Fatal("missing source-region context accepted")
	}
	limits := defaultRegistrationLimits().source
	limits.work = 1
	if r, err := checkSourceRegion(t.Context(), s, in, p, limits, defaultRegionLimits()); r != nil || err == nil {
		t.Fatal("source binding budget supplied a partial envelope")
	}
}

func TestSelectedCallableInstantiationSharesBudget(t *testing.T) {
	s := sourceRegionFixture(t, `func helper[T any](x T)T{return x};func F()int{return helper(7)}`, true)
	var target *ssa.Function
	for _, block := range s.prog.Roots["F"].Blocks {
		for _, ins := range block.Instrs {
			if call, ok := ins.(*ssa.Call); ok {
				target = call.Call.StaticCallee()
			}
		}
	}
	b := selectedSourceFixtureBinder(t, s)
	if _, err := b.bindCallable(target); err != nil {
		t.Fatal(err)
	}
	for _, dimension := range []string{"work", "bytes"} {
		limits := defaultRegistrationLimits().source
		if dimension == "work" {
			limits.work = b.work - 1
		} else {
			limits.bytes = b.bytes - 1
		}
		limited, err := newSelectedSourceBinder(t.Context(), s, s.prog.Roots["F"], limits)
		if err == nil {
			_, err = limited.bindCallable(target)
		}
		if err == nil || !strings.Contains(err.Error(), "budget") {
			t.Fatal("instantiation reset its cumulative "+dimension+" budget", err)
		}
	}
	b = selectedSourceFixtureBinder(t, s)
	if _, err := b.bindDeclaration(target.Origin()); err != nil {
		t.Fatal(err)
	}
	work := b.work
	observed := &relationCallbackContext{Context: t.Context()}
	b.ctx = observed
	if _, err := b.bindCallable(target); err != nil {
		t.Fatal(err)
	}
	if observed.checks == 0 || b.work-work != observed.checks {
		t.Fatal("instantiation reset the shared counter instead of retaining every charged step")
	}
	b = selectedSourceFixtureBinder(t, s)
	if _, err := b.bindDeclaration(target.Origin()); err != nil {
		t.Fatal(err)
	}
	counted := &regionCallCountingContext{Context: t.Context(), stop: 6}
	b.ctx = counted
	if _, err := b.bindCallable(target); !errors.Is(err, context.Canceled) || counted.checks != 6 || len(b.callables) != 0 {
		t.Fatal("interrupted instantiation preflight published a callable", err)
	}
}

func TestSourceRegionLoadedGenericCarrier(t *testing.T) {
	if testing.Short() {
		t.Skip("actual selected generic package load")
	}
	const pkg = "example.com/sourceregion"
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module " + pkg + "\n\ngo 1.27\n", "p.go": `package p
type Row[T any]struct{Name string;F T}
func a(){}
func helper[T any](name string,f T)[]Row[T]{return []Row[T]{{name,f}}}
func F()[]Row[func()]{return helper("a",a)}
`})
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
	s := computationSource{prog: loader.loaded, metas: metas}
	r := proveSourceRegion(t, s)
	if len(r.calls) != 1 || r.calls[0].bound.origin == nil || len(r.calls[0].bound.typeArguments) != 1 {
		t.Fatal("actual loaded specialization was not bound")
	}
}

func TestSourceRegionLoadedInterfaceBindings(t *testing.T) {
	if testing.Short() {
		t.Skip("actual selected interface-target source binding")
	}
	const pkg = "example.com/sourceinterface"
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module " + pkg + "\n\ngo 1.27\n", "p.go": `package p
type I interface{Get()int}
type A struct{X int}
type B struct{Y int}
func(a A)Get()int{return a.X}
func(b *B)Get()int{return b.Y}
func invoke(x I)int{return x.Get()}
func F()[]int{return []int{invoke(A{11}),invoke(A{13}),invoke(&B{22}),invoke(&B{24})}}
`})
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
	in := sourceRegionInput(t, source)
	in.premises = append(in.premises, "initialization and native/frame/harness applicability remain open")
	proposal, err := proposeRegion(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	r, err := checkSourceRegion(t.Context(), source, in, proposal, defaultRegistrationLimits().source, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	var info *types.Info
	for _, p := range source.prog.Pkgs {
		if p.Types == in.root.Pkg.Pkg {
			info = p.TypesInfo
		}
	}
	if info == nil {
		t.Fatal("selected root TypesInfo absent")
	}
	want := map[int64]*ssa.Function{}
	methods := map[*ssa.Function]*ast.FuncDecl{}
	for _, tc := range []struct {
		name   string
		values []int64
	}{{"A", []int64{11, 13}}, {"B", []int64{22, 24}}} {
		named := in.root.Pkg.Pkg.Scope().Lookup(tc.name).Type().(*types.Named)
		if named.NumMethods() != 1 {
			t.Fatal("fixture method inventory changed")
		}
		object := named.Method(0)
		fn := source.prog.Prog.FuncValue(object)
		if fn == nil {
			t.Fatal("selected canonical method absent")
		}
		decl, ok := fn.Syntax().(*ast.FuncDecl)
		if !ok || info.Defs[decl.Name] != object {
			t.Fatal("method lacks actual selected declaration")
		}
		methods[fn] = decl
		for _, value := range tc.values {
			want[value] = fn
		}
	}
	seen := map[int64]bool{}
	contexts := map[*ssa.Function][]*regionCallProof{}
	var invoke *ssa.Call
	for i, binding := range r.calls {
		if binding.call != r.packet.calls[i] {
			t.Fatal("binding detached from checked dependency")
		}
		call := binding.call
		if !call.at.Common().IsInvoke() {
			continue
		}
		if invoke == nil {
			invoke = call.at.(*ssa.Call)
		}
		if call.at != invoke {
			t.Fatal("fixture did not reuse one interface invoke site")
		}
		decl := methods[call.target]
		if decl == nil || binding.bound.function != call.target || binding.bound.syntax != decl || binding.bound.signature != call.target.Signature || binding.bound.pkg.Types != in.root.Pkg.Pkg || binding.bound.identity.source == ([32]byte{}) || binding.bound.identity.body == ([32]byte{}) {
			t.Fatal("interface-selected target did not bind its exact source declaration")
		}
		receiver, exists := call.initial.values[call.target.Params[0]]
		if !exists || !types.Identical(receiver.typ, call.target.Signature.Recv().Type()) {
			t.Fatal("lost typed actual receiver")
		}
		value := receiver
		if _, pointer := receiver.typ.(*types.Pointer); pointer {
			if receiver.kind != regionPointer || len(receiver.location.path) != 0 {
				t.Fatal("lost pointer receiver location")
			}
			var present bool
			value, present = call.initial.memory[receiver.location.object]
			if !present {
				t.Fatal("lost pointer receiver heap")
			}
		}
		if value.kind != regionAggregate || len(value.elements) != 1 || value.elements[0].kind != regionConstant {
			t.Fatal("lost receiver field relation")
		}
		n, exact := constant.Int64Val(value.elements[0].scalar)
		if !exact || want[n] != call.target || seen[n] {
			t.Fatal("receiver/type contexts collapsed or crossed", n)
		}
		seen[n] = true
		contexts[call.target] = append(contexts[call.target], call)
	}
	if len(seen) != 4 || len(contexts) != 2 {
		t.Fatal("missing value/pointer receiver contexts")
	}
	for target, calls := range contexts {
		if len(calls) != 2 || calls[0].invocation == calls[1].invocation || regionSameValue(calls[0].initial.values[target.Params[0]], calls[1].initial.values[target.Params[0]]) {
			t.Fatal("method identity replaced actual receiver contexts")
		}
	}
	open := strings.Join(append(r.packet.openObligations(), r.packet.input.premises...), " ")
	for _, obligation := range []string{"initialization", "native", "frame", "harness"} {
		if !strings.Contains(open, obligation) {
			t.Fatal("conditional scope lost", obligation)
		}
	}
	foreign := relationFixture(t, `func F()int{return 99}`, 64)
	for target, decl := range methods {
		t.Run("tampered-"+target.Signature.Recv().Type().String(), func(t *testing.T) {
			original := info.Defs[decl.Name]
			info.Defs[decl.Name] = foreign.prog.Roots["F"].Object()
			defer func() { info.Defs[decl.Name] = original }()
			// The semantic kernel consumes the unchanged typed SSA. Its success
			// must not hide disagreement in the selected method declaration.
			if packet, err := checkRegion(t.Context(), in, proposal, defaultRegionLimits()); err != nil || packet == nil {
				t.Fatal("semantic control failed", err)
			}
			b := selectedSourceFixtureBinder(t, source)
			if _, err := b.bindCallable(in.root); err != nil {
				t.Fatal("root binding control failed", err)
			}
			got, err := checkSourceRegion(t.Context(), source, in, proposal, defaultRegistrationLimits().source, defaultRegionLimits())
			var refusal *computationFailure
			if got != nil || !errors.As(err, &refusal) || refusal.function != target || !strings.Contains(refusal.premise, "selected function body binding disagrees") {
				t.Fatal("interface target escaped selected-source binding", err)
			}
		})
	}
}
