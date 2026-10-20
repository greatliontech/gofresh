package closure

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
)

// computationFixture builds actual typed source SSA without loading a toolchain
// or spawning a process, so the grammar and checker adversaries stay short-tier.
func computationFixture(t testing.TB, text string) computationSource {
	t.Helper()
	const path = "example.com/computation"
	dir, err := filepath.Abs("/computation")
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(dir, "p.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, "package p\n"+text, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	pkg := types.NewPackage(path, "p")
	ssaPkg, info, err := ssautil.BuildPackage(&types.Config{Importer: assemblyReferenceUnsafeImporter{}}, fset, pkg, []*ast.File{file}, ssa.SanityCheckFunctions)
	if err != nil {
		t.Fatal(err)
	}
	p := &packages.Package{ID: path, PkgPath: path, Name: "p", Types: pkg, TypesInfo: info, Fset: fset, Syntax: []*ast.File{file}, CompiledGoFiles: []string{filename}}
	return computationSource{
		prog:  &program{PkgPath: path, Prog: ssaPkg.Prog, Pkgs: []*packages.Package{p}, Roots: map[string]*ssa.Function{"F": ssaPkg.Func("F")}},
		metas: []listPkg{{ImportPath: path, Name: "p", Dir: dir, GoFiles: []string{"p.go"}}},
	}
}

func proveComputationFixture(ctx context.Context, source computationSource) (*checkedComputation, error) {
	root := source.prog.Roots["F"]
	certificate, err := proposeComputation(ctx, source, root)
	if err != nil {
		return nil, err
	}
	return checkComputation(ctx, source, root, certificate)
}

func TestComputationGrammar(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		accept       bool
	}{
		{"scalar", `func F(x int) int { if x < 0 { return -x }; return (x * 3 + 7) ^ 4 }`, true},
		{"string", `func F(s string, n int) string { if len(s)>n { return s[:n]+string(s[n]) }; return s }`, true},
		{"loop", `func F(s string) int { n:=0; for i:=0;i<len(s);i++ { n += int(s[i]) };return n }`, true},
		{"tuple", `func pair(x int)(int,bool){return x+1,x>0};func F(x int)int{y,ok:=pair(x);if ok{return y};return 0}`, true},
		{"direct", `func twice(x int)int{return x*2};func F(x int)int{return twice(x)}`, true},
		{"callback", `func twice(x int)int{return x*2};func apply(f func(int)int,x int)int{return f(x)};func F(x int)int{return apply(twice,x)}`, true},
		{"callback-contexts", `func twice(x int)int{return x*2};func inc(x int)int{return x+1};func apply(f func(int)int,x int)int{return f(x)};func F(x int)int{return apply(twice,x)+apply(inc,x)}`, true},
		{"initializer", `func helper(x int)int{return x+1};func init(){helper(2)};func F(x int)int{return helper(x)}`, true},
		{"global-read", `var x int;func F()int{return x}`, false},
		{"global-write", `var x int;func F()int{x++;return x}`, false},
		{"root-callback", `func F(f func(int)int,x int)int{return f(x)}`, false},
		{"native", `func native(x int)int;func F(x int)int{return native(x)}`, false},
		{"discarded-native", `func native(x int)int;func F(x int)int{native(x);return x}`, false},
		{"native-init", `func native();func init(){native()};func F(x int)int{return x}`, false},
		{"native-callback-context", `func inc(x int)int{return x+1};func native(x int)int;func apply(f func(int)int,x int)int{return f(x)};func F(x int)int{return apply(inc,x)+apply(native,x)}`, false},
		{"recursion", `func F(x int)int{if x==0{return 0};return F(x-1)}`, false},
		{"mutual-recursion", `func g(x int)int{return F(x)};func F(x int)int{return g(x)}`, false},
		{"float", `func F(x float64)float64{return x+1}`, false},
		{"uintptr", `func F(x uintptr)uintptr{return x+1}`, false},
		{"pointer", `func F(x *int)int{return *x}`, false},
		{"closure", `func F(x int)int{f:=func()int{return x};return f()}`, false},
		{"defer", `func f(){};func F()int{defer f();return 1}`, false},
		{"goroutine", `func f(){};func F()int{go f();return 1}`, false},
		{"panic", `func F(x int)int{panic(x)}`, false},
		{"print", `func F(x int)int{println(x);return x}`, false},
		{"generic-origin", `func F[T ~int](x T)T{return x}`, false},
		{"directive", "//go:noinline\nfunc F(x int)int{return x}", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := computationFixture(t, tc.source)
			checked, err := proveComputationFixture(t.Context(), source)
			if (err == nil) != tc.accept || (checked != nil) != tc.accept {
				t.Fatalf("checked=%v error=%v, want accepted=%t", checked != nil, err, tc.accept)
			}
		})
	}
}

func TestComputationCertificateCannotOmitObligations(t *testing.T) {
	const text = `func inc(x int)int{return x+1};func other(x int)int{return x-1};func apply(f func(int)int,x int)int{return f(x)};func init(){inc(1)};func F(x int)int{return apply(inc,x)}`
	for _, corruption := range []string{"root", "initializer", "callee", "binding", "duplicate", "extra"} {
		t.Run(corruption, func(t *testing.T) {
			source := computationFixture(t, text)
			root := source.prog.Roots["F"]
			cert, err := proposeComputation(t.Context(), source, root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := checkComputation(t.Context(), source, root, cert); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			pkg := source.prog.Prog.Package(source.prog.Pkgs[0].Types)
			switch corruption {
			case "root":
				cert.root = &computationContext{fn: pkg.Func("inc"), bindings: make([]*ssa.Function, 1)}
			case "initializer":
				cert.startup = nil
			case "callee":
				cert.contexts = slices.DeleteFunc(cert.contexts, func(c *computationContext) bool { return c.fn == pkg.Func("inc") })
			case "binding":
				for _, c := range cert.contexts {
					if c.fn == pkg.Func("apply") {
						c.bindings[0] = pkg.Func("other")
					}
				}
			case "duplicate":
				cert.contexts = append(cert.contexts, cert.root)
			case "extra":
				cert.contexts = append(cert.contexts, &computationContext{fn: pkg.Func("other"), bindings: make([]*ssa.Function, 1)})
			}
			if checked, err := checkComputation(t.Context(), source, root, cert); checked != nil || err == nil {
				t.Fatal("corrupted certificate acquired authority")
			}
		})
	}
	// Remove the initializer AND its contexts. Leaving an extra context in
	// the candidate would let the unused-context check hide a missing startup
	// coverage check. Each forged inventory below is otherwise closed.
	for _, body := range []string{`println("startup")`, `go harmless()`} {
		for _, replace := range []bool{false, true} {
			t.Run(fmt.Sprintf("hidden-startup/%s/replacement=%t", body, replace), func(t *testing.T) {
				source := computationFixture(t, `func harmless(){};func init(){`+body+`};func F(x int)int{return x}`)
				root := source.prog.Roots["F"]
				cert, err := proposeComputation(t.Context(), source, root)
				if err != nil {
					t.Fatal(err)
				}
				if checked, err := checkComputation(t.Context(), source, root, cert); checked != nil || err == nil {
					t.Fatal("effectful initializer control was admitted")
				}
				cert.startup = nil
				cert.contexts = []*computationContext{cert.root}
				want := "initializer inventory is incomplete"
				if replace {
					harmless := source.prog.Prog.Package(source.prog.Pkgs[0].Types).Func("harmless")
					entry := &computationContext{fn: harmless}
					cert.startup = []*computationContext{entry}
					cert.contexts = append(cert.contexts, entry)
					want = "initializer inventory disagrees with selected source"
				}
				checked, err := checkComputation(t.Context(), source, root, cert)
				var failure *computationFailure
				if checked != nil || !errors.As(err, &failure) || failure.premise != want {
					t.Fatalf("hidden initializer was not rejected by source coverage: %v", err)
				}
			})
		}
	}
}

func TestComputationChecksEveryBlockAndDiscardedCall(t *testing.T) {
	source := computationFixture(t, `func native()int;func F(x int)int{if x>0{native()};return x}`)
	root := source.prog.Roots["F"]
	cert, err := proposeComputation(t.Context(), source, root)
	if err != nil {
		t.Fatal(err)
	}
	// The proposer omits the dependency rather than reporting the bad block.
	cert.contexts = []*computationContext{cert.root}
	if checked, err := checkComputation(t.Context(), source, root, cert); checked != nil || err == nil || !strings.Contains(err.Error(), "callee context") {
		t.Fatalf("discarded call in a non-entry block was omitted: %v", err)
	}
}

func TestComputationSelectionAndCancellation(t *testing.T) {
	for _, flag := range []string{"-race", "--race", "-race=false", "'-cover=true'", "-gcflags=all=-N", "--ldflags=-X=p.x=1", "-toolexec=hook", "-pkgdir=/other", "-compiler=gccgo"} {
		if computationOptionSupported(flag) {
			t.Fatalf("unrepresented compilation mechanism admitted: %s", flag)
		}
	}
	for _, flag := range []string{"-tags=selected", "-mod=readonly", "-trimpath", "-pgo=off"} {
		if !computationOptionSupported(flag) {
			t.Fatalf("source-selecting or semantics-preserving option refused: %s", flag)
		}
	}
	source := computationFixture(t, `func F(x int)int{return x}`)
	root := source.prog.Roots["F"]
	cert, err := proposeComputation(t.Context(), source, root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if checked, err := checkComputation(ctx, source, root, cert); checked != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled checker: %v", err)
	}
	if cert, err := proposeComputation(ctx, source, root); cert != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled proposer: %v", err)
	}
	for _, corruption := range []string{"missing-package", "missing-file", "other-file", "native", "instrumented-variant"} {
		t.Run(corruption, func(t *testing.T) {
			changed := source
			changed.metas = slices.Clone(source.metas)
			switch corruption {
			case "missing-package":
				changed.metas = nil
			case "missing-file":
				changed.metas[0].GoFiles = nil
			case "other-file":
				changed.metas[0].GoFiles = []string{"other.go"}
			case "native":
				changed.metas[0].SFiles = []string{"native.s"}
			case "instrumented-variant":
				changed.metas[0].ForTest = changed.metas[0].ImportPath
			}
			if checked, err := checkComputation(t.Context(), changed, root, cert); checked != nil || err == nil {
				t.Fatal("incomplete selected-source binding accepted")
			}
		})
	}
}

func TestComputationEffectDischargeIsClaimLocal(t *testing.T) {
	source := computationFixture(t, `func helper(x int)int{return x+1};func unused(x int)int{return x-1};func F(x int)int{return helper(x)}`)
	checked, err := proveComputationFixture(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	covered := unauditedStandardEffect("example.com/computation", "helper")
	if !coversComputationEffects(source, checked, []externalEffect{covered}) {
		t.Fatal("checked function blocker was not discharged")
	}
	for _, effect := range []externalEffect{
		unauditedStandardEffect("example.com/computation", "unused"),
		unauditedStandardEffect("other", "helper"),
		{kind: externalEffectEnvironment, packagePath: covered.packagePath, symbol: covered.symbol, reason: covered.reason},
		{kind: externalEffectUnauditedStandard, reason: covered.reason},
		{kind: externalEffectUnauditedStandard, packagePath: covered.packagePath, symbol: covered.symbol, reason: covered.reason, unrefinable: true},
	} {
		effects := []externalEffect{covered, effect}
		before := slices.Clone(effects)
		if coversComputationEffects(source, checked, effects) || !slices.Equal(before, effects) {
			t.Fatalf("unrelated typed blocker was discharged or mutated: %+v", effect)
		}
	}
	if coversComputationEffects(source, nil, []externalEffect{covered}) {
		t.Fatal("absent checked proof discharged an effect")
	}
}

func TestComputationCallbackContextIsNotFunctionIdentity(t *testing.T) {
	source := computationFixture(t, `func good(x int)int{return x};func native(x int)int;func apply(f func(int)int,x int)int{return f(x)};func F(x int)int{return apply(good,x)+apply(native,x)}`)
	checked, err := proveComputationFixture(t.Context(), source)
	var failure *computationFailure
	if checked != nil || !errors.As(err, &failure) || failure.function == nil || failure.function.Name() != "native" || failure.premise != "selected source body is absent or unsupported" {
		t.Fatalf("second callback context did not reach its own opaque body: %v", err)
	}
}

func TestComputationFailureRetainsCallContexts(t *testing.T) {
	for _, callback := range []bool{false, true} {
		t.Run(fmt.Sprintf("callback=%t", callback), func(t *testing.T) {
			text := `func native(x int)int;func helper(x int)int{return native(x)};func F(x int)int{return helper(x)}`
			if callback {
				text = `func native(x int)int;func other(x int)int;func good(x int)int{return x};func helper(f func(int)int,x int)int{return f(x)};func F(x int)int{helper(good,x);return helper(native,x)};func G(x int)int{return helper(other,x)}`
			}
			source := computationFixture(t, text)
			pkg := source.prog.Prog.Package(source.prog.Pkgs[0].Types)
			root, helper, native := pkg.Func("F"), pkg.Func("helper"), pkg.Func("native")
			cert, err := proposeComputation(t.Context(), source, root)
			if err != nil {
				t.Fatal(err)
			}
			checked, err := checkComputation(t.Context(), source, root, cert)
			var failure *computationFailure
			if checked != nil || !errors.As(err, &failure) {
				t.Fatalf("opaque leaf acquired authority: %v", err)
			}
			account := failure.account()
			if account.function != native || account.phase != computationSubjectPhase || account.entry.fn != root || len(account.calls) != 2 {
				t.Fatalf("wrong structured refusal: %+v", account)
			}
			for i, want := range [][2]*ssa.Function{{root, helper}, {helper, native}} {
				edge := account.calls[i]
				if edge.caller.fn != want[0] || edge.callee.fn != want[1] {
					t.Fatalf("edge %d: %v -> %v, want %v -> %v", i, edge.caller.fn, edge.callee.fn, want[0], want[1])
				}
				var expected token.Pos
				for _, block := range want[0].Blocks {
					for _, instruction := range block.Instrs {
						if call, ok := instruction.(*ssa.Call); ok {
							// The last root call selects the refusing callback;
							// its earlier successful context must not leak in.
							expected = call.Pos()
						}
					}
				}
				if edge.at == token.NoPos || edge.at != expected {
					t.Fatalf("edge %d lost its call site: got %v want %v", i, edge.at, expected)
				}
			}
			if !callback {
				return
			}
			if account.calls[0].callee.bindings[0] != native || account.calls[1].caller.bindings[0] != native {
				t.Fatal("refusal borrowed the earlier successful callback context")
			}
			// Neither a caller mutating its projection nor the certificate's
			// owner editing its inventory can mutate a retained refusal.
			account.calls[0].callee.bindings[0] = pkg.Func("good")
			if account.calls[1].caller.bindings[0] != native {
				t.Fatal("two projected edges share mutable binding storage")
			}
			account.calls[1].caller.bindings[0] = pkg.Func("good")
			account.entry.bindings[0] = native
			for _, candidate := range cert.contexts {
				if candidate.fn == helper {
					candidate.bindings[0] = pkg.Func("good")
				}
			}
			again := failure.account()
			if again.calls[0].callee.bindings[0] != native || again.calls[1].caller.bindings[0] != native || again.entry.bindings[0] != nil {
				t.Fatal("refusal account aliases its caller or certificate")
			}
			otherRoot := pkg.Func("G")
			otherCert, err := proposeComputation(t.Context(), source, otherRoot)
			if err != nil {
				t.Fatal(err)
			}
			checked, err = checkComputation(t.Context(), source, otherRoot, otherCert)
			var otherFailure *computationFailure
			if checked != nil || !errors.As(err, &otherFailure) || otherFailure.account().calls[0].callee.bindings[0] != pkg.Func("other") || failure.account().calls[0].callee.bindings[0] != native {
				t.Fatalf("independent checks mixed callback contexts: %v", err)
			}
		})
	}
}

func TestComputationFailureAttributesStartup(t *testing.T) {
	source := computationFixture(t, `func native();func helper(){native()};func init(){helper()};func F(){}`)
	checked, err := proveComputationFixture(t.Context(), source)
	var failure *computationFailure
	if checked != nil || !errors.As(err, &failure) {
		t.Fatalf("startup leaf acquired authority: %v", err)
	}
	account := failure.account()
	if account.phase != computationStartupPhase || len(account.calls) != 2 || account.entry.fn != account.calls[0].caller.fn || account.function.Name() != "native" {
		t.Fatalf("startup refusal lost entry or path: %+v", account)
	}
}

func computationManyCalls(t testing.TB, count int) computationSource {
	t.Helper()
	return computationFixture(t, computationCallDeclarations(count, "F"))
}

func computationCallDeclarations(count int, caller string) string {
	var source strings.Builder
	fmt.Fprintf(&source, "func %s(){", caller)
	for i := 0; i < count; i++ {
		fmt.Fprintf(&source, "f%d();", i)
	}
	source.WriteString("}\n")
	for i := 0; i < count; i++ {
		fmt.Fprintf(&source, "func f%d(){}\n", i)
	}
	return source.String()
}

func TestComputationContextLimitAppliesDuringExpansion(t *testing.T) {
	source := computationManyCalls(t, 4200)
	root := source.prog.Roots["F"]
	cert, err := proposeComputation(t.Context(), source, root)
	var failure *computationFailure
	if cert != nil || !errors.As(err, &failure) || failure.function.Name() != "f4095" || failure.premise != "computation context bound exhausted" {
		t.Fatalf("one long body expanded past its first excess context: %v", err)
	}
	// Check the insertion boundary itself, using these actual selected
	// functions. Refusal must leave the inventory at capacity, not append
	// an excess context and reject it on a later expansion iteration.
	bounded := &computationCertificate{}
	pkg := source.prog.Prog.Package(source.prog.Pkgs[0].Types)
	for i := 0; i < 4096; i++ {
		if _, err := bounded.addContext(t.Context(), &computationContext{fn: pkg.Func(fmt.Sprintf("f%d", i))}); err != nil {
			t.Fatalf("refused a context below capacity: %v", err)
		}
	}
	if _, err := bounded.addContext(t.Context(), &computationContext{fn: pkg.Func("f4096")}); err == nil || len(bounded.contexts) != 4096 {
		t.Fatalf("excess insertion changed inventory: count=%d err=%v", len(bounded.contexts), err)
	}
	if got, err := bounded.addContext(t.Context(), &computationContext{fn: pkg.Func("f4095")}); err != nil || got != bounded.contexts[4095] || len(bounded.contexts) != 4096 {
		t.Fatalf("a duplicate consumed capacity: count=%d err=%v", len(bounded.contexts), err)
	}
}

func TestComputationExhaustionRetainsEntryAndPath(t *testing.T) {
	for _, tc := range []struct {
		name, source, entry, leaf string
		phase                     computationPhase
		route                     []string
	}{
		{
			name: "subject", source: `func F(){helper()}`,
			entry: "F", leaf: "f4094", phase: computationSubjectPhase,
			route: []string{"F", "helper", "f4094"},
		},
		{
			name: "duplicate-route", source: `func F(){helper();helper()}`,
			entry: "F", leaf: "f4094", phase: computationSubjectPhase,
			route: []string{"F", "helper", "f4094"},
		},
		{
			name: "startup", source: `func F(){};func init(){helper()}`,
			entry: "init#1", leaf: "f4093", phase: computationStartupPhase,
			route: []string{"init#1", "helper", "f4093"},
		},
		{
			name: "callback", source: `func relay(f func()){f()};func F(){relay(helper)}`,
			entry: "F", leaf: "f4093", phase: computationSubjectPhase,
			route: []string{"F", "relay", "helper", "f4093"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := computationFixture(t, computationCallDeclarations(4095, "helper")+tc.source)
			pkg := source.prog.Prog.Package(source.prog.Pkgs[0].Types)
			cert, err := proposeComputation(t.Context(), source, source.prog.Roots["F"])
			var failure *computationFailure
			if cert != nil || !errors.As(err, &failure) {
				t.Fatalf("exhaustion returned a candidate or no structured refusal: %v", err)
			}
			account := failure.account()
			if account.premise != "computation context bound exhausted" || account.function != pkg.Func(tc.leaf) || account.entry.fn != pkg.Func(tc.entry) || account.phase != tc.phase || len(account.calls) != len(tc.route)-1 {
				t.Fatalf("exhaustion lost its leaf, entry, phase or route: %+v", account)
			}
			for i, edge := range account.calls {
				caller, callee := pkg.Func(tc.route[i]), pkg.Func(tc.route[i+1])
				if edge.caller.fn != caller || edge.callee.fn != callee {
					t.Fatalf("edge %d: got %v -> %v, want %v -> %v", i, edge.caller.fn, edge.callee.fn, caller, callee)
				}
				// Direct calls identify their exact source site. When duplicate
				// references exist, search provenance keeps the first route.
				var expected token.Pos
				for _, block := range caller.Blocks {
					for _, instruction := range block.Instrs {
						if call, ok := instruction.(*ssa.Call); ok && call.Common().StaticCallee() == callee && expected == token.NoPos {
							expected = call.Pos()
						}
					}
				}
				if caller.Name() == "relay" {
					if edge.caller.bindings[0] != pkg.Func("helper") {
						t.Fatal("search path lost its callback specialization")
					}
					for _, instruction := range caller.Blocks[0].Instrs {
						if call, ok := instruction.(*ssa.Call); ok {
							expected = call.Pos()
						}
					}
				}
				if edge.at == token.NoPos || edge.at != expected {
					t.Fatalf("edge %d lost its exact source site: got %v want %v", i, edge.at, expected)
				}
			}
			if tc.name == "callback" {
				if account.calls[0].callee.bindings[0] != pkg.Func("helper") {
					t.Fatal("callee specialization differs from the next edge's caller")
				}
				account.calls[0].callee.bindings[0] = pkg.Func("F")
				if account.calls[1].caller.bindings[0] != pkg.Func("helper") || failure.account().calls[0].callee.bindings[0] != pkg.Func("helper") {
					t.Fatal("search refusal projections share mutable binding storage")
				}
			}
		})
	}
}

func TestComputationStartupInventoryExhaustionRetainsEntry(t *testing.T) {
	// The subject occupies one slot. The first 4095 explicit initializers
	// fill the inventory; the next initializer fails before any body expands.
	source := computationFixture(t, "func F(){}\n"+strings.Repeat("func init(){}\n", 4096))
	cert, err := proposeComputation(t.Context(), source, source.prog.Roots["F"])
	var failure *computationFailure
	if cert != nil || !errors.As(err, &failure) {
		t.Fatalf("startup inventory exhaustion returned a candidate: %v", err)
	}
	want := source.prog.Prog.Package(source.prog.Pkgs[0].Types).Func("init#4096")
	account := failure.account()
	if want == nil || account.function != want || account.entry.fn != want || account.phase != computationStartupPhase || len(account.calls) != 0 || account.premise != "computation context bound exhausted" {
		t.Fatalf("startup inventory refusal lost its entry or fabricated a call edge: %+v", account)
	}
}

// Err cancels a real context at a deterministic observation count. This makes
// cancellation inside a long single block reproducible without wall-clock races.
type computationCountingContext struct {
	context.Context
	cancel       context.CancelFunc
	checks, stop int
}

func (c *computationCountingContext) Err() error {
	c.checks++
	if c.checks == c.stop {
		c.cancel()
	}
	return c.Context.Err()
}

func TestComputationCancellationInsideLongBodyAndLookup(t *testing.T) {
	source := computationFixture(t, "func F(x int)int{"+strings.Repeat("x++;", 1024)+"println(x);return x}")
	root := source.prog.Roots["F"]
	cert, err := proposeComputation(t.Context(), source, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, checker := range []bool{false, true} {
		t.Run(fmt.Sprintf("checker=%t", checker), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			counted := &computationCountingContext{Context: ctx, cancel: cancel, stop: 64}
			if checker {
				checked, err := checkComputation(counted, source, root, cert)
				if checked != nil || !errors.Is(err, context.Canceled) {
					t.Fatalf("checker continued to the terminal print instead of cancelling: %v", err)
				}
			} else if candidate, err := proposeComputation(counted, source, root); candidate != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("proposer finished a long block instead of cancelling: %v", err)
			}
			if counted.checks != 64 {
				t.Fatalf("did not stop at the cancelling observation: %d", counted.checks)
			}
		})
	}
	lookupSource := computationManyCalls(t, 128)
	lookupCert, err := proposeComputation(t.Context(), lookupSource, lookupSource.prog.Roots["F"])
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	counted := &computationCountingContext{Context: ctx, cancel: cancel, stop: 64}
	before := len(lookupCert.contexts)
	if found, err := lookupCert.addContext(counted, lookupCert.contexts[before-1]); found != nil || !errors.Is(err, context.Canceled) || len(lookupCert.contexts) != before || counted.checks != 64 {
		t.Fatalf("duplicate lookup ignored cancellation: found=%v checks=%d size=%d err=%v", found != nil, counted.checks, len(lookupCert.contexts), err)
	}
}

// Every generated grammar instance has a source-computation positive and an
// otherwise identical ignored native call negative; neither assertion reads a
// classification table from the implementation.
func FuzzComputationGrammar(f *testing.F) {
	f.Add(uint8(0), int16(7), false)
	f.Add(uint8(3), int16(-4), true)
	f.Fuzz(func(t *testing.T, shape uint8, n int16, callback bool) {
		operations := []string{"x + %d", "x ^ %d", "x * %d", "x - %d"}
		expression := fmt.Sprintf(operations[int(shape)%len(operations)], n)
		call := "step(x)"
		if callback {
			call = "apply(step,x)"
		}
		for _, native := range []bool{false, true} {
			insert := ""
			if native {
				insert = "native();"
			}
			text := fmt.Sprintf("func native();func step(x int)int{%sreturn %s};func apply(f func(int)int,x int)int{return f(x)};func F(x int)int{return %s}", insert, expression, call)
			checked, err := proveComputationFixture(t.Context(), computationFixture(t, text))
			if (err == nil) == native || (checked != nil) == native {
				t.Fatalf("native=%t callback=%t source=%s: %v", native, callback, text, err)
			}
		}
	})
}
