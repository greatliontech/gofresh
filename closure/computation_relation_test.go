package closure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"math"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
	"github.com/greatliontech/gofresh/internal/bitrelation"
)

type relationCallbackContext struct {
	context.Context
	checks, at int
	callback   func()
}

func (c *relationCallbackContext) Err() error {
	c.checks++
	if c.checks == c.at && c.callback != nil {
		c.callback()
	}
	return c.Context.Err()
}

func TestComputationRelationOwnsInputsBeforeCallbacks(t *testing.T) {
	s := relationFixture(t, `func F(x,y int32)int32{return x-y}`, 64)
	scope, originals := relationInputs(t, s)
	baseline := &relationCallbackContext{Context: t.Context()}
	if _, err := deriveComputationRelation(baseline, s, s.prog.Roots["F"], scope, slices.Clone(originals), computationRelationLimits{}); err != nil {
		t.Fatal(err)
	}
	b := bitrelation.NewBuilder(0)
	constant, err := b.Const(bitrelation.Bits(32), 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, replacement := range []bitrelation.Term{originals[0], constant} {
		for at := 1; at <= baseline.checks; at++ {
			inputs := slices.Clone(originals)
			ctx := &relationCallbackContext{Context: t.Context(), at: at, callback: func() { inputs[1] = replacement }}
			r, err := deriveComputationRelation(ctx, s, s.prog.Roots["F"], scope, inputs, computationRelationLimits{})
			if err != nil || r == nil {
				t.Fatalf("callback %d/%d refused the owned original inputs: %v", at, baseline.checks, err)
			}
			if !slices.Equal(r.inputs, originals) || !slices.Equal(r.root.arguments, originals) {
				t.Fatalf("callback %d replaced published formals", at)
			}
			if got := relationEvaluate(t, r, 9, 4)[0]; got != 5 {
				t.Fatalf("callback %d changed x-y to %d", at, got)
			}
		}
	}
	// A refused count does not first invoke a callback or allocate its snapshot.
	limits := defaultComputationRelationLimits()
	limits.nodes = 1
	ctx := &relationCallbackContext{Context: t.Context()}
	if r, err := deriveComputationRelation(ctx, s, s.prog.Roots["F"], scope, originals, limits); r != nil || err == nil || ctx.checks != 0 {
		t.Fatal("input count was not bounded before the first callback")
	}
}

func relationSyntaxChecker(ctx context.Context, limits computationRelationLimits) *selectedSourceBinder {
	return &selectedSourceBinder{ctx: ctx, limits: selectedSourceLimits{work: limits.work, depth: limits.depth, bytes: limits.bytes}}
}

// A left-associated expression's Pos recursively reaches this sentinel even
// when a guarded AST walk must stop thousands of ancestors before visiting it.
type relationPositionSentinel struct{ ast.Expr }

func (*relationPositionSentinel) Pos() token.Pos {
	panic("position traversed beyond syntax budget")
}

func TestComputationRelationSyntaxPositionIsBounded(t *testing.T) {
	for _, selector := range []bool{false, true} {
		t.Run(fmt.Sprintf("selector=%t", selector), func(t *testing.T) {
			var expr ast.Expr = &relationPositionSentinel{}
			for range 8192 {
				if selector {
					expr = &ast.SelectorExpr{X: expr, Sel: ast.NewIdent("x")}
				} else {
					expr = &ast.BinaryExpr{X: expr, Op: token.ADD, Y: ast.NewIdent("x")}
				}
			}
			file := relationParseSyntax(t, "func F(x int32)int32{return x}")
			file.Decls[0].(*ast.FuncDecl).Body.List[0].(*ast.ReturnStmt).Results[0] = expr
			for _, workBound := range []bool{false, true} {
				limits := defaultComputationRelationLimits()
				want := "syntax depth"
				if workBound {
					limits.work = 64
					want = "work budget"
				}
				if _, err := relationSyntaxChecker(t.Context(), limits).preflightSyntax(nil, file); err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("deep left chain: %v", err)
				}
			}
		})
	}
	file := relationParseSyntax(t, "func F(x int32)int32{return x+x+x+x+x+x+x+x}")
	if _, err := relationSyntaxChecker(t.Context(), defaultComputationRelationLimits()).preflightSyntax(nil, file); err != nil {
		t.Fatal("bounded left-associated control", err)
	}
}

func TestComputationRelationEntryArityBeforeBindings(t *testing.T) {
	s := relationFixture(t, "func F(x int32)int32{return x}", 64)
	scope, inputs := relationInputs(t, s)
	root := s.prog.Roots["F"]
	for _, count := range []int{2, 1 << 20} {
		root.Params = make([]*ssa.Parameter, count)
		r, err := deriveComputationRelation(t.Context(), s, root, scope, inputs, computationRelationLimits{})
		var failure *computationFailure
		if r != nil || !errors.As(err, &failure) {
			t.Fatalf("parameter count %d: %v", count, err)
		}
		account := failure.account()
		if account.phase != computationSubjectPhase || account.function != root || account.entry.fn != root || len(account.entry.bindings) != 0 {
			t.Fatalf("refused arity allocated bindings or lost entry attribution: count=%d bindings=%d", count, len(account.entry.bindings))
		}
		want := "arity"
		if count > defaultComputationRelationLimits().nodes {
			want = "parameter budget"
		}
		if !strings.Contains(account.premise, want) {
			t.Fatalf("count %d: %s", count, account.premise)
		}
	}
}

func TestComputationRelationBuildConstraintBounds(t *testing.T) {
	for _, text := range []string{
		strings.Repeat("// +build linux\n", 4096),
		strings.Repeat("//+build custom.product\n", 4096),
		"//go:build " + strings.Repeat("custom || ", 4096) + "other\n",
	} {
		file := relationParseSyntax(t, text+"\nfunc F(x int32)int32{return x}")
		c := relationSyntaxChecker(t.Context(), defaultComputationRelationLimits())
		if _, err := c.preflightSyntax(nil, file); err == nil || !strings.Contains(err.Error(), "build-constraint") {
			t.Fatalf("printer normalization was not bounded: %v", err)
		}
		if c.work > 8192 || c.bytes > c.limits.bytes {
			t.Fatalf("constraint refusal did not stop boundedly: work=%d bytes=%d", c.work, c.bytes)
		}
		s := relationFixture(t, text+"\nfunc F(x int32)int32{return x}", 64)
		scope, inputs := relationInputs(t, s)
		if r, err := deriveComputationRelation(t.Context(), s, s.prog.Roots["F"], scope, inputs, computationRelationLimits{}); r != nil || err == nil || !strings.Contains(err.Error(), "build-constraint") {
			t.Fatalf("source derivation bypassed constraint guard: %v", err)
		}
	}
	// A single long tag is shallow, but recursive joins repeatedly copy its
	// bytes. Isolate that byte bound from syntax depth and ordinary payload.
	text := "// +build " + strings.Repeat("a", 1024) + "\n// +build b\n"
	file := relationParseSyntax(t, text+"\nfunc F(x int32)int32{return x}")
	limits := defaultComputationRelationLimits()
	limits.bytes = 8192
	if _, err := relationSyntaxChecker(t.Context(), limits).preflightSyntax(nil, file); err == nil || !strings.Contains(err.Error(), "build-constraint byte") {
		t.Fatal("constraint copies bypassed byte budget", err)
	}
	for _, text := range []string{
		"// +build linux,amd64 darwin\n// +build !cgo\n",
		"//go:build (custom.product && !other) || third\n// +build custom.product,!other third\n",
		"//+build arbitrary\n",
		"// +build " + strings.Repeat("a", 1024) + "\n",
	} {
		s := relationFixture(t, text+"\nfunc F(x int32)int32{return x}", 64)
		if got := relationEvaluate(t, relationProve(t, s), 7)[0]; got != 7 {
			t.Fatal("ordinary constraint changed relation", got)
		}
	}
}

func relationParseSyntax(t testing.TB, text string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "/budget/p.go", "package p\n"+text, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func TestComputationRelationSyntaxByteAndDepthBounds(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"literal", `var unused = "` + strings.Repeat("a", 32768) + `";func F(x int32)int32{return x}`},
		{"comment", "//" + strings.Repeat("a", 32768) + "\nfunc F(x int32)int32{return x}"},
		{"unattached-comment", "func F(x int32)int32{/*" + strings.Repeat("a", 32768) + "*/return x}"},
		{"identifier", "var " + strings.Repeat("a", 32768) + " = 1;func F(x int32)int32{return x}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := relationParseSyntax(t, tc.text)
			limits := defaultComputationRelationLimits()
			limits.bytes = 8192
			ctx := &relationCallbackContext{Context: t.Context()}
			c := relationSyntaxChecker(ctx, limits)
			if _, err := c.preflightSyntax(nil, file); err == nil || !strings.Contains(err.Error(), "byte budget") {
				t.Fatalf("unbounded payload: %v", err)
			}
			if c.bytes > limits.bytes || c.work > limits.work || ctx.checks > 512 {
				t.Fatalf("payload was scanned without bounded accounting: bytes=%d work=%d callbacks=%d", c.bytes, c.work, ctx.checks)
			}
			control := relationSyntaxChecker(t.Context(), defaultComputationRelationLimits())
			if _, err := control.preflightSyntax(nil, file); err != nil {
				t.Fatalf("adequate budget control: %v", err)
			}
			s := relationFixture(t, tc.text, 64)
			scope, inputs := relationInputs(t, s)
			if r, err := deriveComputationRelation(t.Context(), s, s.prog.Roots["F"], scope, inputs, limits); r != nil || err == nil || !strings.Contains(err.Error(), "byte budget") {
				t.Fatalf("source derivation bypassed payload preflight: %v", err)
			}
			if got := relationEvaluate(t, relationProve(t, s), 7)[0]; got != 7 {
				t.Fatal("bounded large-payload positive control", got)
			}
		})
	}
	version := relationParseSyntax(t, "func F()int32{return 0}")
	version.GoVersion = strings.Repeat("g", 32768)
	versionLimits := defaultComputationRelationLimits()
	versionLimits.bytes = 8192
	if _, err := relationSyntaxChecker(t.Context(), versionLimits).preflightSyntax(nil, version); err == nil || !strings.Contains(err.Error(), "byte budget") {
		t.Fatal("file string payload was not charged", err)
	}
	file := relationParseSyntax(t, "func F(x int32)int32{return "+strings.Repeat("(", 32)+"x"+strings.Repeat(")", 32)+"}")
	limits := defaultComputationRelationLimits()
	limits.depth = 16
	if _, err := relationSyntaxChecker(t.Context(), limits).preflightSyntax(nil, file); err == nil || !strings.Contains(err.Error(), "syntax depth") {
		t.Fatalf("syntax depth: %v", err)
	}
	if _, err := relationSyntaxChecker(t.Context(), defaultComputationRelationLimits()).preflightSyntax(nil, file); err != nil {
		t.Fatal(err)
	}
}

func TestComputationRelationSyntaxStopsWideWalk(t *testing.T) {
	// The test grammar supplies many independent siblings. Refusal must unwind
	// the walk, not merely return false and visit the remaining sibling roots.
	file := relationParseSyntax(t, "func F(x int32)int32{"+strings.Repeat("x++;", 4096)+"return x}")
	limits := defaultComputationRelationLimits()
	limits.work = 64
	ctx := &relationCallbackContext{Context: t.Context()}
	c := relationSyntaxChecker(ctx, limits)
	if _, err := c.preflightSyntax(nil, file); err == nil || !strings.Contains(err.Error(), "work budget") || c.work != limits.work+1 || ctx.checks != limits.work+1 {
		t.Fatalf("wide refusal: %v work=%d callbacks=%d", err, c.work, ctx.checks)
	}
	base, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx = &relationCallbackContext{Context: base, at: 64, callback: cancel}
	c = relationSyntaxChecker(ctx, defaultComputationRelationLimits())
	if _, err := c.preflightSyntax(nil, file); !errors.Is(err, context.Canceled) || ctx.checks != 64 {
		t.Fatalf("wide cancellation: %v callbacks=%d", err, ctx.checks)
	}
	if _, err := relationSyntaxChecker(t.Context(), defaultComputationRelationLimits()).preflightSyntax(nil, file); err != nil {
		t.Fatalf("wide positive control: %v", err)
	}
}

func TestComputationRelationBoundedHashAndCanonicalPackage(t *testing.T) {
	limits := defaultComputationRelationLimits()
	limits.bytes = 8192
	c := relationSyntaxChecker(t.Context(), limits)
	w := c.hasher(nil, token.NoPos)
	data := bytes.Repeat([]byte("x"), limits.bytes+1)
	if n, err := w.Write(data); n != 0 || err == nil || c.bytes != 0 {
		t.Fatal("oversize encoding was partially hashed")
	}
	base, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &relationCallbackContext{Context: base, at: 3, callback: cancel}
	c = relationSyntaxChecker(ctx, defaultComputationRelationLimits())
	w = c.hasher(nil, token.NoPos)
	if n, err := w.Write(data); n != 4096 || !errors.Is(err, context.Canceled) {
		t.Fatalf("hash cancellation boundary: n=%d err=%v", n, err)
	}

	s := relationFixture(t, "// retained comment\nconst k=3\nfunc helper(x int32)int32{return x+k};func F(x int32)int32{return helper(x)}", 64)
	r := relationProve(t, s)
	var canonical bytes.Buffer
	printConfig := printer.Config{Mode: printer.TabIndent | printer.UseSpaces, Tabwidth: 8}
	p := s.prog.Pkgs[0]
	for _, file := range p.Syntax {
		fmt.Fprintf(&canonical, "%q\n", filepath.Clean(p.Fset.PositionFor(file.Pos(), false).Filename))
		if err := printConfig.Fprint(&canonical, p.Fset, file); err != nil {
			t.Fatal(err)
		}
	}
	if r.root.source != sha256.Sum256(canonical.Bytes()) {
		t.Fatal("bounded source hash changed selected canonical bytes")
	}
	canonical.Reset()
	if err := printConfig.Fprint(&canonical, p.Fset, s.prog.Roots["F"].Syntax()); err != nil {
		t.Fatal(err)
	}
	if r.root.body != sha256.Sum256(canonical.Bytes()) {
		t.Fatal("body identity is not the selected canonical declaration")
	}
	// Both actual bound functions share one fully validated package digest.
	if len(r.dependencies) != 2 || r.dependencies[0].source != r.dependencies[1].source {
		t.Fatal("callee selected package binding disagrees")
	}
	c = relationSyntaxChecker(t.Context(), defaultComputationRelationLimits())
	c.source, c.metas, c.packages = s, map[string]listPkg{s.metas[0].ImportPath: s.metas[0]}, map[*packages.Package]selectedSourcePackage{}
	c.pkgs = map[*types.Package]*packages.Package{p.Types: p}
	selected, err := c.selectedPackage(s.prog.Roots["F"], p)
	if err != nil {
		t.Fatal(err)
	}
	c.limits.work, c.limits.bytes = c.work, c.bytes
	helper := s.prog.Prog.Package(p.Types).Func("helper")
	shared, err := c.selectedPackage(helper, p)
	if err != nil || shared.digest != selected.digest {
		t.Fatal("callee redundantly revalidated/encoded its selected package", err)
	}
}

func TestComputationRelationPrinterOutputBudget(t *testing.T) {
	// A long field aligns many short siblings. The output can be much larger
	// than its tokens; padding must reach the bounded writer incrementally.
	var text strings.Builder
	text.WriteString("package p\ntype S struct {\n" + strings.Repeat("A", 512) + " int\n")
	for i := 0; i < 256; i++ {
		fmt.Fprintf(&text, "F%d int\n", i)
	}
	text.WriteString("}\n")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "/budget/p.go", text.String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	c := relationSyntaxChecker(t.Context(), defaultComputationRelationLimits())
	if _, err := c.preflightSyntax(nil, file); err != nil {
		t.Fatal(err)
	}
	c.limits.bytes = c.bytes + 512
	w := c.hasher(nil, token.NoPos)
	if err := selectedSourcePrint(w, fset, file); err == nil || w.err == nil || !strings.Contains(err.Error(), "byte budget") || c.bytes > c.limits.bytes {
		t.Fatalf("unbounded encoded padding: %v bytes=%d limit=%d", err, c.bytes, c.limits.bytes)
	}
	c = relationSyntaxChecker(t.Context(), defaultComputationRelationLimits())
	if _, err := c.preflightSyntax(nil, file); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c.ctx = &relationCallbackContext{Context: ctx, at: 2, callback: cancel}
	w = c.hasher(nil, token.NoPos)
	if err := selectedSourcePrint(w, fset, file); !errors.Is(err, context.Canceled) {
		t.Fatalf("printer ignored cancellation: %v", err)
	}
}

func relationFixture(t testing.TB, text string, word int) computationSource {
	t.Helper()
	s := computationFixture(t, text)
	p := s.prog.Pkgs[0]
	arch := "amd64"
	if word == 32 {
		arch = "386"
	}
	p.TypesSizes = types.SizesFor("gc", arch)
	// Re-type-check with the explicitly selected width. The common helper's
	// implicit default sizes must not stand in for a cross-architecture load.
	pkg := types.NewPackage(p.PkgPath, p.Name)
	ssaPkg, info, err := ssautil.BuildPackage(&types.Config{Importer: assemblyReferenceUnsafeImporter{}, Sizes: p.TypesSizes}, p.Fset, pkg, p.Syntax, ssa.SanityCheckFunctions)
	if err != nil {
		t.Fatal(err)
	}
	p.Types, p.TypesInfo = pkg, info
	s.prog.Prog = ssaPkg.Prog
	s.prog.Roots["F"] = ssaPkg.Func("F")
	return s
}

func relationInputs(t testing.TB, s computationSource) (bitrelation.Scope, []bitrelation.Term) {
	t.Helper()
	scope := bitrelation.NewScope()
	b := bitrelation.NewBuilder(0)
	root := s.prog.Roots["F"]
	var inputs []bitrelation.Term
	for i, param := range root.Params {
		sort := computationRelationTypeOf(param.Type(), s.prog.Pkgs[0].TypesSizes).inputSort()
		input, err := b.Input(sort, scope, uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, input)
	}
	return scope, inputs
}

func relationProve(t testing.TB, s computationSource) *computationRelation {
	t.Helper()
	scope, inputs := relationInputs(t, s)
	r, err := deriveComputationRelation(t.Context(), s, s.prog.Roots["F"], scope, inputs, computationRelationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func relationEvaluate(t testing.TB, r *computationRelation, args ...uint64) []uint64 {
	t.Helper()
	if len(args) != len(r.inputs) {
		t.Fatal("test argument arity")
	}
	assign := make([]bitrelation.Assignment, len(args))
	for i, arg := range args {
		assign[i] = bitrelation.Assignment{Variable: r.inputs[i], Value: arg}
	}
	var results []uint64
	for _, output := range r.outputs {
		value, err := bitrelation.Eval(t.Context(), output, assign, bitrelation.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		results = append(results, value)
	}
	return results
}

func TestComputationRelationExactGoScalars(t *testing.T) {
	// The reference executes ordinary Go, independently of source translation or
	// the bitrelation primitive evaluator. Exhaust all int8 inputs and include
	// both branches, conversions, signed extrema, modular multiplication, and
	// oversize fixed shifts. These are tests, never all-input proof by sampling.
	text := `func pair(x int8)(int16,uint8){return int16(x),uint8(x)}
func F(x int8)(int16,uint8,bool,int8,int8,uint8){
 a,b:=pair(x); y:=x+3
 if x<0 { y = -x } else { y = x*7 }
 return a,b,(x>=-17 && x<29)||x==127,y,x>>12,uint8(x)<<9
}`
	r := relationProve(t, relationFixture(t, text, 64))
	for n := -128; n < 128; n++ {
		x := int8(n)
		y := x + 3
		if x < 0 {
			y = -x
		} else {
			y = x * 7
		}
		predicate := uint64(0)
		if (x >= -17 && x < 29) || x == 127 {
			predicate = 1
		}
		// Widen the reference operands before shifting and narrow the results;
		// the selected fixture still exercises shifts beyond its operand width.
		want := []uint64{uint64(uint16(int16(x))), uint64(uint8(x)), predicate, uint64(uint8(y)), uint64(uint8(int64(x) >> 12)), uint64(uint8(uint64(uint8(x)) << 9))}
		if got := relationEvaluate(t, r, uint64(uint8(x))); !slices.Equal(got, want) {
			t.Fatalf("x=%d: got %v want %v", x, got, want)
		}
	}
}

func TestComputationRelationBitwiseAndReturns(t *testing.T) {
	r := relationProve(t, relationFixture(t, `func F(x,y uint64,b bool)(uint64,bool){
 if b { return ((x&^y)|(x^y))+((^x)&y),x!=y }
 if x>y { return x-y,x>=y };return x<<7,x<=y
}`, 64))
	for _, x := range []uint64{0, 1, 127, 1 << 63, math.MaxUint64} {
		for _, y := range []uint64{0, 3, 1 << 63, math.MaxUint64} {
			for b := uint64(0); b < 2; b++ {
				var v uint64
				var ok bool
				if b != 0 {
					v, ok = ((x&^y)|(x^y))+((^x)&y), x != y
				} else if x > y {
					v, ok = x-y, x >= y
				} else {
					v, ok = x<<7, x <= y
				}
				truth := uint64(0)
				if ok {
					truth = 1
				}
				if got := relationEvaluate(t, r, x, y, b); !slices.Equal(got, []uint64{v, truth}) {
					t.Fatalf("(%d,%d,%d): %v", x, y, b, got)
				}
			}
		}
	}
}

func TestComputationRelationSelectedWidthsAndConstants(t *testing.T) {
	for _, width := range []int{32, 64} {
		r := relationProve(t, relationFixture(t, `func F(x int)(int64,uint64,int,int8,uint32){return int64(x),uint64(x),x+1,-128,4294967295}`, width))
		mask := uint64(math.MaxUint64)
		if width == 32 {
			mask = math.MaxUint32
		}
		for _, x := range []uint64{0, 1, mask >> 1, (mask >> 1) + 1, mask} {
			signed := int64(x)
			if width == 32 {
				signed = int64(int32(x))
			}
			want := []uint64{uint64(signed), uint64(signed), (x + 1) & mask, 128, math.MaxUint32}
			if got := relationEvaluate(t, r, x); !slices.Equal(got, want) {
				t.Fatalf("word=%d x=%d got=%v want=%v", width, x, got, want)
			}
		}
		if r.root.wordBits != width {
			t.Fatal("word width was not retained")
		}
		if r.root.parameters[0].sort != bitrelation.Bits(width) || !r.root.parameters[0].signed || r.root.results[0].name != "int64" || !r.root.results[0].signed || r.root.results[1].signed {
			t.Fatal("source scalar interpretations were not retained")
		}
	}
	r := relationProve(t, relationFixture(t, `func F()(int64,uint64){return -9223372036854775808,18446744073709551615}`, 64))
	if got := relationEvaluate(t, r); !slices.Equal(got, []uint64{1 << 63, math.MaxUint64}) {
		t.Fatal(got)
	}
}

func TestComputationRelationExactCalleeContexts(t *testing.T) {
	s := relationFixture(t, `func inc(x int32)int32{return x+1}
func dec(x int32)int32{return x-1}
func apply(f func(int32)int32,x int32)int32{return f(x)}
func F(x int32)(int32,int32){return apply(inc,x+5),apply(dec,x-3)}`, 64)
	r := relationProve(t, s)
	for _, x := range []int32{math.MinInt32, -1, 0, 1, math.MaxInt32} {
		if got := relationEvaluate(t, r, uint64(uint32(x))); !slices.Equal(got, []uint64{uint64(uint32(x + 6)), uint64(uint32(x - 4))}) {
			t.Fatal(x, got)
		}
	}
	var callbacks []string
	for _, dep := range r.dependencies {
		callbacks = append(callbacks, dep.callbacks...)
	}
	if len(callbacks) != 2 || callbacks[0] == callbacks[1] {
		t.Fatal("callback contexts collapsed", callbacks)
	}
	// A body with the same name in an independent load is not this root.
	other := relationFixture(t, `func F(x int32)(int32,int32){return x,x}`, 64)
	scope, inputs := relationInputs(t, s)
	if cert, err := deriveComputationRelation(t.Context(), s, other.prog.Roots["F"], scope, inputs, computationRelationLimits{}); cert != nil || err == nil {
		t.Fatal("foreign source root admitted")
	}
}

func TestComputationRelationRefusals(t *testing.T) {
	for _, tc := range []struct{ name, source string }{
		{"discarded-native", `func native();func F(x int32)int32{native();return x}`},
		{"discarded-branch", `func native();func F(x int32)int32{if x>0{native()};return x}`},
		{"discarded-hook", `var hook func();func F(x int32)int32{hook();return x}`},
		{"global-read", `var global int32;func F(x int32)int32{return x+global}`},
		{"global-write", `var global int32;func F(x int32)int32{global=x;return x}`},
		{"division", `func F(x int32)int32{return x/2}`},
		{"modulus", `func F(x int32)int32{return x%3}`},
		{"variable-negative-shift", `func F(x int32)int32{return x<<x}`},
		{"panic", `func F(x int32)int32{if x>0{panic(x)};return x}`},
		{"recursive", `func F(x int32)int32{if x>0{return F(x-1)};return x}`},
		{"loop", `func F(x int32)int32{for x>0{x--};return x}`},
		{"captured", `func F(x int32)int32{f:=func()int32{return x};return f()}`},
		{"generic", `func g[T ~int32](x T)T{return x+1};func F(x int32)int32{return g(x)}`},
		{"print", `func F(x int32)int32{println(x);return x}`},
		{"callback-native", `func native(x int32)int32;func apply(f func(int32)int32,x int32)int32{return f(x)};func F(x int32)int32{return apply(native,x)}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := relationFixture(t, tc.source, 64)
			scope, inputs := relationInputs(t, s)
			r, err := deriveComputationRelation(t.Context(), s, s.prog.Roots["F"], scope, inputs, computationRelationLimits{})
			var failure *computationFailure
			if r != nil || !errors.As(err, &failure) || failure.function == nil || failure.phase != computationSubjectPhase {
				t.Fatalf("relation=%v error=%v", r, err)
			}
		})
	}
}

func TestComputationRelationFormalInputs(t *testing.T) {
	s := relationFixture(t, `func F(x,y int32)int32{return x-y}`, 64)
	for _, mode := range []string{"alias", "constant", "expression", "scratch", "scope", "width", "bool", "missing", "extra"} {
		t.Run(mode, func(t *testing.T) {
			scope, inputs := relationInputs(t, s)
			b := bitrelation.NewBuilder(0)
			switch mode {
			case "alias":
				inputs[1] = inputs[0]
			case "constant":
				inputs[0], _ = b.Const(bitrelation.Bits(32), 0)
			case "expression":
				inputs[0], _ = b.Make(bitrelation.Add, bitrelation.Bits(32), 0, inputs[0], inputs[1])
			case "scratch":
				inputs[0], _ = b.Scratch(bitrelation.Bits(32), scope, 0)
			case "scope":
				inputs[0], _ = b.Input(bitrelation.Bits(32), bitrelation.NewScope(), 0)
			case "width":
				inputs[0], _ = b.Input(bitrelation.Bits(64), scope, 0)
			case "bool":
				inputs[0], _ = b.Input(bitrelation.Bool(), scope, 0)
			case "missing":
				inputs = inputs[:1]
			case "extra":
				inputs = append(inputs, inputs[0])
			}
			if r, err := deriveComputationRelation(t.Context(), s, s.prog.Roots["F"], scope, inputs, computationRelationLimits{}); r != nil || err == nil {
				t.Fatal("bad formal mapping acquired relation")
			}
		})
	}
}

func TestComputationRelationPhiEdgesAndGraphCoverage(t *testing.T) {
	const text = `func F(x int32)int32{var y int32;if x<0{y=x-7}else{y=x+11};return y}`
	s := relationFixture(t, text, 64)
	r := relationProve(t, s)
	for _, x := range []int32{-5, 0, 8} {
		want := x + 11
		if x < 0 {
			want = x - 7
		}
		if got := relationEvaluate(t, r, uint64(uint32(x)))[0]; got != uint64(uint32(want)) {
			t.Fatal(x, got, want)
		}
	}
	for _, mode := range []string{"swap-phi", "omit-edge", "omit-block", "foreign-operand", "cycle"} {
		t.Run(mode, func(t *testing.T) {
			s := relationFixture(t, text, 64)
			fn := s.prog.Roots["F"]
			var phi *ssa.Phi
			for _, b := range fn.Blocks {
				for _, ins := range b.Instrs {
					if p, ok := ins.(*ssa.Phi); ok {
						phi = p
					}
				}
			}
			if phi == nil {
				t.Fatal("fixture lacks phi")
			}
			switch mode {
			case "swap-phi":
				phi.Edges[0], phi.Edges[1] = phi.Edges[1], phi.Edges[0]
			case "omit-edge":
				phi.Block().Preds = phi.Block().Preds[:1]
			case "omit-block":
				fn.Blocks = fn.Blocks[:len(fn.Blocks)-1]
			case "foreign-operand":
				other := relationFixture(t, `func F(x int32)int32{return x}`, 64)
				phi.Edges[0] = other.prog.Roots["F"].Params[0]
			case "cycle":
				phi.Block().Succs = []*ssa.BasicBlock{fn.Blocks[0]}
				fn.Blocks[0].Preds = []*ssa.BasicBlock{phi.Block()}
			}
			scope, inputs := relationInputs(t, s)
			if r, err := deriveComputationRelation(t.Context(), s, fn, scope, inputs, computationRelationLimits{}); r != nil || err == nil {
				t.Fatal("malformed predecessor graph admitted")
			}
		})
	}
	// Swapping constant edges remains legal SSA but changes its interpretation.
	// This catches translating phi by block inventory order instead of Preds.
	s = relationFixture(t, `func F(x int32)int32{y:=int32(3);if x<0{y=9};return y}`, 64)
	before := relationProve(t, s)
	for _, b := range s.prog.Roots["F"].Blocks {
		for _, ins := range b.Instrs {
			if p, ok := ins.(*ssa.Phi); ok {
				p.Edges[0], p.Edges[1] = p.Edges[1], p.Edges[0]
			}
		}
	}
	after := relationProve(t, s)
	if relationEvaluate(t, before, 0)[0] == relationEvaluate(t, after, 0)[0] {
		t.Fatal("phi predecessor semantics ignored")
	}
}

func TestComputationRelationLocalBoundaryAndFrozenDependencies(t *testing.T) {
	s := relationFixture(t, `var global int32;func init(){println("startup")};func F(x int32)int32{return x+1}`, 64)
	r := relationProve(t, s)
	if r.open != (computationRelationObligations{true, true, true, true, true}) || r.owner != s.prog || r.rules != computationRelationRules {
		t.Fatal("local scope lost unresolved obligations")
	}
	if _, err := proveComputationFixture(t.Context(), s); err == nil {
		t.Fatal("local relation weakened whole startup checking")
	}
	oldSource, oldBody := r.root.source, r.root.body
	changed := relationFixture(t, `var global int32;func init(){println("startup")};func F(x int32)int32{return x+2}`, 64)
	r2 := relationProve(t, changed)
	if r2.root.source == oldSource || r2.root.body == oldBody || r2.owner == r.owner {
		t.Fatal("changed selected source lost identity")
	}
	// Mutating caller storage after construction cannot alter the certificate.
	scope, inputs := relationInputs(t, s)
	r3, err := deriveComputationRelation(t.Context(), s, s.prog.Roots["F"], scope, inputs, computationRelationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	inputs[0] = bitrelation.Term{}
	s.prog.Roots["F"].Blocks = nil
	if got := relationEvaluate(t, r3, 7)[0]; got != 8 || r3.root.source != oldSource || r3.root.body != oldBody {
		t.Fatal("certificate retained mutable term/source semantics")
	}
}

func TestComputationRelationSelectionBinding(t *testing.T) {
	for _, mode := range []string{"metadata", "filename", "syntax", "types-info", "body", "sizes", "opaque"} {
		t.Run(mode, func(t *testing.T) {
			s := relationFixture(t, `func F(x int32)int32{return x+1}`, 64)
			scope, inputs := relationInputs(t, s)
			p := s.prog.Pkgs[0]
			switch mode {
			case "metadata":
				s.metas = nil
			case "filename":
				p.CompiledGoFiles[0] = "/different.go"
			case "syntax":
				p.Syntax = nil
			case "types-info":
				p.TypesInfo = &types.Info{}
			case "body":
				for _, d := range p.Syntax[0].Decls {
					if f, ok := d.(*ast.FuncDecl); ok {
						f.Body = nil
					}
				}
			case "sizes":
				p.TypesSizes = nil
			case "opaque":
				s.metas[0].SFiles = []string{"native.s"}
			}
			if r, err := deriveComputationRelation(t.Context(), s, s.prog.Roots["F"], scope, inputs, computationRelationLimits{}); r != nil || err == nil {
				t.Fatal("incomplete selected body admitted")
			}
		})
	}
}

func TestComputationRelationCancellationAndBudgets(t *testing.T) {
	s := relationFixture(t, `func add(x int32)int32{return x+1};func F(x int32)int32{return add(x)}`, 64)
	scope, inputs := relationInputs(t, s)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if r, err := deriveComputationRelation(ctx, s, s.prog.Roots["F"], scope, inputs, computationRelationLimits{}); r != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(r, err)
	}
	for _, field := range []string{"nodes", "contexts", "work", "depth"} {
		limits := defaultComputationRelationLimits()
		switch field {
		case "nodes":
			limits.nodes = 1
		case "contexts":
			limits.contexts = 1
		case "work":
			limits.work = 1
		case "depth":
			limits.depth = 1
		}
		if r, err := deriveComputationRelation(t.Context(), s, s.prog.Roots["F"], scope, inputs, limits); r != nil || err == nil || !strings.Contains(err.Error(), "budget") {
			t.Fatalf("%s: %v %v", field, r, err)
		}
	}
	long := relationFixture(t, "func F(x int32)int32{"+strings.Repeat("x++;", 1024)+"return x}", 64)
	longScope, longInputs := relationInputs(t, long)
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	counted := &computationCountingContext{Context: ctx, cancel: cancel, stop: 64}
	if r, err := deriveComputationRelation(counted, long, long.prog.Roots["F"], longScope, longInputs, computationRelationLimits{}); r != nil || !errors.Is(err, context.Canceled) || counted.checks != 64 {
		t.Fatalf("in-progress cancellation: %v, checks=%d", err, counted.checks)
	}
}

func FuzzComputationRelationScalars(f *testing.F) {
	f.Add(uint8(0), int16(-32768), int16(32767), false)
	f.Add(uint8(2), int16(-19), int16(-123), true)
	f.Add(uint8(255), int16(27), int16(-1), true)
	f.Fuzz(func(t *testing.T, shape uint8, n, x int16, callback bool) {
		ops := []string{"+", "-", "*", "&", "^", "|", "&^", ">>"}
		operand := n
		if shape%8 == 7 {
			operand = int16(shape / 8)
		}
		expr := fmt.Sprintf("x %s (%d)", ops[shape%8], operand)
		invoke := "step(x)"
		if callback {
			invoke = "apply(step,x)"
		}
		text := fmt.Sprintf(`func step(x int16)int16{return %s}
func apply(f func(int16)int16,x int16)int16{return f(x)}
func F(x int16)int64{var y int16;if x<(%d){y=%s}else{y=-(%s)};return int64(y)}`, expr, n, invoke, invoke)
		r := relationProve(t, relationFixture(t, text, 64))
		var y int16
		switch shape % 8 {
		case 0:
			y = x + n
		case 1:
			y = x - n
		case 2:
			y = x * n
		case 3:
			y = x & n
		case 4:
			y = x ^ n
		case 5:
			y = x | n
		case 6:
			y = x &^ n
		case 7:
			y = x >> uint(shape/8)
		}
		if x >= n {
			y = -y
		}
		if got := relationEvaluate(t, r, uint64(uint16(x)))[0]; got != uint64(int64(y)) {
			t.Fatalf("shape=%d n=%d x=%d callback=%t: got %x want %x", shape, n, x, callback, got, uint64(int64(y)))
		}
	})
}
