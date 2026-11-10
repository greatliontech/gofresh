package dynstate

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/seams"
	"github.com/greatliontech/gofresh/internal/dynstate/protoaudit"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func bracketedSeamNodes(audited bool, p *packages.Package) map[ast.Node]bool {
	return seams.AnalyzeBracketedSeams(audited, p, nil, nil).Exempt
}

func syntheticPackageImports(tp *types.Package, nonStd map[string]*types.Package) map[string]*packages.Package {
	memo := map[*types.Package]*packages.Package{}
	var build func(*types.Package) *packages.Package
	build = func(cur *types.Package) *packages.Package {
		if cur == nil {
			return nil
		}
		if p, ok := memo[cur]; ok {
			return p
		}
		var mod *packages.Module
		if _, isLocal := nonStd[cur.Path()]; isLocal {
			mod = &packages.Module{Path: "example.com/mod"}
		}
		pkg := &packages.Package{
			ID:      cur.Path(),
			PkgPath: cur.Path(),
			Name:    cur.Name(),
			Types:   cur,
			Module:  mod,
		}
		memo[cur] = pkg
		if imps := cur.Imports(); len(imps) > 0 {
			pkg.Imports = make(map[string]*packages.Package, len(imps))
			for _, dep := range imps {
				if dep != nil {
					pkg.Imports[dep.Path()] = build(dep)
				}
			}
		}
		return pkg
	}
	if tp == nil || len(tp.Imports()) == 0 {
		return nil
	}
	out := make(map[string]*packages.Package, len(tp.Imports()))
	for _, dep := range tp.Imports() {
		if dep != nil {
			out[dep.Path()] = build(dep)
		}
	}
	return out
}

func mustTypecheckPackage(t *testing.T, pkgPath string, files map[string]string) *packages.Package {
	t.Helper()
	fset := token.NewFileSet()
	var syntax []*ast.File
	for name, src := range files {
		f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", name, err)
		}
		syntax = append(syntax, f)
	}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Instances:  make(map[*ast.Ident]types.Instance),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Implicits:  make(map[ast.Node]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Scopes:     make(map[ast.Node]*types.Scope),
	}
	conf := types.Config{Importer: importer.Default()}
	typesPkg, err := conf.Check(pkgPath, fset, syntax, info)
	if err != nil {
		t.Fatalf("types.Check(%s): %v", pkgPath, err)
	}
	return &packages.Package{
		ID:        pkgPath,
		PkgPath:   pkgPath,
		Name:      typesPkg.Name(),
		Fset:      fset,
		Syntax:    syntax,
		Types:     typesPkg,
		TypesInfo: info,
		Imports:   syntheticPackageImports(typesPkg, nil),
		Module:    &packages.Module{Path: "example.com/mod"},
	}
}

//gofresh:pure
func TestFixedPointMonotonicityIdempotenceAndPermutationInvariance(t *testing.T) {
	// 1. SolveLeastFixedPoint & SolveReachFixedPoint on cyclic graphs with self-loops and diamonds.
	lfpDeps := map[string]map[string]bool{
		"a": {"b": true, "c": true},
		"b": {"d": true},
		"c": {"d": true},
		"d": {},
		"e": {"f": true},
		"f": {"e": true}, // cycle without base -> stays false in least fixed point
		"g": {"g": true}, // self-loop -> stays false
	}
	lfpSet := map[string]bool{}
	syntaxutil.SolveLeastFixedPoint(lfpSet, lfpDeps, func(dep string) bool { return lfpSet[dep] })
	for _, wantTrue := range []string{"a", "b", "c", "d"} {
		if !lfpSet[wantTrue] {
			t.Fatalf("SolveLeastFixedPoint missing %q: %v", wantTrue, lfpSet)
		}
	}
	for _, wantFalse := range []string{"e", "f", "g"} {
		if lfpSet[wantFalse] {
			t.Fatalf("SolveLeastFixedPoint unexpectedly included cycle node %q: %v", wantFalse, lfpSet)
		}
	}
	// Idempotence: re-running SolveLeastFixedPoint on the converged set leaves it identical.
	beforeLFP := make(map[string]bool, len(lfpSet))
	for k, v := range lfpSet {
		beforeLFP[k] = v
	}
	syntaxutil.SolveLeastFixedPoint(lfpSet, lfpDeps, func(dep string) bool { return lfpSet[dep] })
	if !reflect.DeepEqual(lfpSet, beforeLFP) {
		t.Fatalf("SolveLeastFixedPoint not idempotent: got %v, want %v", lfpSet, beforeLFP)
	}

	reachDeps := map[string]map[string]bool{
		"x": {"y": true},
		"y": {"z": true},
		"z": {"x": true, "seed": true},
		"u": {"v": true},
		"v": {"u": true},
	}
	reachSet := map[string]bool{"seed": true}
	syntaxutil.SolveReachFixedPoint(reachSet, reachDeps, func(dep string) bool { return reachSet[dep] })
	for _, wantTrue := range []string{"seed", "x", "y", "z"} {
		if !reachSet[wantTrue] {
			t.Fatalf("SolveReachFixedPoint missing %q: %v", wantTrue, reachSet)
		}
	}
	for _, wantFalse := range []string{"u", "v"} {
		if reachSet[wantFalse] {
			t.Fatalf("SolveReachFixedPoint unexpectedly included disconnected cycle %q: %v", wantFalse, reachSet)
		}
	}

	// 2. Permutational invariance of ResolveEnvAudit, NewDeferralResolution, and Compose.
	fA := syntaxutil.FuncKey{Pkg: "example.com/a", Name: "NewA"}
	fB := syntaxutil.FuncKey{Pkg: "example.com/b", Name: "NewB"}
	fCycle := syntaxutil.FuncKey{Pkg: "example.com/c", Name: "Cycle"}
	pA0 := syntaxutil.ParamKey{Func: fA, Index: 0}
	pB0 := syntaxutil.ParamKey{Func: fB, Index: 0}

	baseMeta := []GraphPackage{
		{
			ImportPath: "example.com/a",
			PkgPath:    "example.com/a",
			Imports:    []string{"example.com/b", "example.com/c"},
			Class:      MutableLocalPackage,
		},
		{
			ImportPath: "example.com/b",
			PkgPath:    "example.com/b",
			Imports:    []string{"example.com/c"},
			Class:      MutableLocalPackage,
		},
		{
			ImportPath: "example.com/c",
			PkgPath:    "example.com/c",
			Class:      PinnedPackage,
			Pin:        "example.com/c@v1.0.0",
		},
	}
	baseFacts := map[string][]Fact{
		"example.com/a": {
			{
				Declares:               []string{"example.com/a.reg", "example.com/a.hook"},
				ReturnEnvFree:          []syntaxutil.FuncKey{fA},
				ReturnEnvDeps:          []syntaxutil.FuncDepEdge{{Func: fA, Callee: fB}},
				ReturnEnvInsertionDeps: []syntaxutil.FuncInsertionDepEdge{{Func: fA, Dep: syntaxutil.ParamAuditTarget(pA0)}},
				ParamInsertionFree:     []syntaxutil.ParamKey{pA0},
				ParamInsertionDeps:     []syntaxutil.ParamInsertionDepEdge{{Param: pA0, Dep: syntaxutil.ParamAuditTarget(pB0)}},
				ParamLeakFree:          []syntaxutil.ParamKey{pA0},
				ParamLeakFreeDeps:      []syntaxutil.ParamDepEdge{{Own: pA0, Dep: pB0}},
				EnvCallUses:            []syntaxutil.EnvCallUse{{Key: "example.com/a.reg", Callee: fA}},
				AttributedUses: []syntaxutil.AttributedUse{
					{Func: syntaxutil.FuncKey{Pkg: "example.com/a", Name: "Mut"}, Key: "example.com/a.hook"},
				},
				FuncRefs: []syntaxutil.FuncRef{
					{Callee: syntaxutil.FuncKey{Pkg: "example.com/a", Name: "Mut"}, Region: syntaxutil.RefRegion{Kind: syntaxutil.RegionProg}},
				},
			},
		},
		"example.com/b": {
			{
				Declares:           []string{"example.com/b.shared"},
				ReturnEnvFree:      []syntaxutil.FuncKey{fB},
				ParamInsertionFree: []syntaxutil.ParamKey{pB0},
				ParamLeakFree:      []syntaxutil.ParamKey{pB0},
				CarrierLinks:       []syntaxutil.CarrierLink{{From: "example.com/b.shared", To: "example.com/a.hook"}},
			},
		},
		"example.com/c": {
			{
				Declares:      []string{"example.com/c.pinned"},
				Mutates:       []string{"example.com/c.pinned"},
				ReturnEnvFree: []syntaxutil.FuncKey{fCycle},
				ReturnEnvDeps: []syntaxutil.FuncDepEdge{{Func: fCycle, Callee: fCycle}},
			},
		},
	}

	wantEA := ResolveEnvAudit(baseFacts, nil)
	if !wantEA.Resolved[fA] || !wantEA.Resolved[fB] || wantEA.Resolved[fCycle] {
		t.Fatalf("unexpected ResolveEnvAudit.Resolved: %+v", wantEA.Resolved)
	}
	wantRes := NewDeferralResolution(baseFacts, nil)
	wantCompose := Compose(baseMeta, baseFacts, "example.com/a", map[string]bool{"example.com/c.pinned": true}, true, false)
	if wantCompose.Downgraded == "" || wantCompose.VouchDischarges != "example.com/c.pinned" {
		t.Fatalf("unexpected Compose state: %+v", wantCompose)
	}

	rng := rand.New(rand.NewSource(42))
	for iter := 0; iter < 25; iter++ {
		permMeta := append([]GraphPackage(nil), baseMeta...)
		rng.Shuffle(len(permMeta), func(i, j int) { permMeta[i], permMeta[j] = permMeta[j], permMeta[i] })
		permFacts := make(map[string][]Fact, len(baseFacts))
		keys := []string{"example.com/a", "example.com/b", "example.com/c"}
		rng.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })
		for _, k := range keys {
			permFacts[k] = append([]Fact(nil), baseFacts[k]...)
		}
		gotEA := ResolveEnvAudit(permFacts, nil)
		if !reflect.DeepEqual(gotEA.Resolved, wantEA.Resolved) || !reflect.DeepEqual(gotEA.InsResolved, wantEA.InsResolved) {
			t.Fatalf("iter %d: ResolveEnvAudit permutation drift: got %+v, want %+v", iter, gotEA, wantEA)
		}
		gotRes := NewDeferralResolution(permFacts, nil)
		if !reflect.DeepEqual(gotRes.ParamLeakFree, wantRes.ParamLeakFree) ||
			!reflect.DeepEqual(gotRes.EnvFreeResolved, wantRes.EnvFreeResolved) {
			t.Fatalf("iter %d: NewDeferralResolution permutation drift", iter)
		}
		gotCompose := Compose(permMeta, permFacts, "example.com/a", map[string]bool{"example.com/c.pinned": true}, true, false)
		if gotCompose.Downgraded != wantCompose.Downgraded ||
			gotCompose.CulpritPkg != wantCompose.CulpritPkg ||
			gotCompose.CulpritSym != wantCompose.CulpritSym ||
			gotCompose.VouchDischarges != wantCompose.VouchDischarges {
			t.Fatalf("iter %d: Compose permutation drift: got %+v, want %+v", iter, gotCompose, wantCompose)
		}
	}
}

//gofresh:pure
func TestFieldPopulationProvesPoisonsDeferralsAndCyclicCtors(t *testing.T) {
	ctorA := syntaxutil.FuncKey{Pkg: "example.com/p", Name: "NewA"}
	ctorB := syntaxutil.FuncKey{Pkg: "example.com/p", Name: "NewB"}
	regFn := syntaxutil.FuncKey{Pkg: "example.com/p", Name: "Register"}
	cleanParam := syntaxutil.ParamKey{Func: regFn, Index: 0}
	dirtyParamA := syntaxutil.ParamKey{Func: ctorA, Index: 1}
	dirtyParamB := syntaxutil.ParamKey{Func: ctorB, Index: 2}

	// 1a. Mutual cycle in ReturnEnvDeps fails least fixed point (EnvFreeResolved == false), so FieldPopulationProves fails closed.
	factsUnresolvedCycle := map[string][]Fact{
		"example.com/p": {
			{
				ReturnEnvFree: []syntaxutil.FuncKey{ctorA, ctorB},
				ReturnEnvDeps: []syntaxutil.FuncDepEdge{
					{Func: ctorA, Callee: ctorB},
					{Func: ctorB, Callee: ctorA},
				},
				ParamLeakFree: []syntaxutil.ParamKey{cleanParam},
				EnvCallUses: []syntaxutil.EnvCallUse{
					{Key: "example.com/p.reg", Callee: ctorA},
				},
			},
		},
	}
	resUnresolved := NewDeferralResolution(factsUnresolvedCycle, nil)
	if ok, culprit := resUnresolved.FieldPopulationProves("example.com/p.reg", "fn", 0); ok || culprit != (syntaxutil.ParamKey{}) {
		t.Fatalf("FieldPopulationProves on unresolved constructor cycle = (%v, %+v), want (false, zero)", ok, culprit)
	}

	// 1b. Direct cycle guard in FieldPopulationProves when EnvFreeResolved holds across a cyclic EnvFreeDeps graph.
	resCleanCycle := NewDeferralResolution(factsUnresolvedCycle, nil)
	resCleanCycle.EnvFreeResolved[ctorA] = true
	resCleanCycle.EnvFreeResolved[ctorB] = true
	resCleanCycle.FieldDeferAt[syntaxutil.FieldPosKey{Owner: "example.com/p.reg", Field: "fn", Index: 0}] = []syntaxutil.ParamKey{cleanParam}
	resCleanCycle.RetDeferAt[syntaxutil.ReturnFieldPosKey{Func: ctorA, Field: "fn", Index: 0}] = []syntaxutil.ParamKey{cleanParam}
	resCleanCycle.RetDeferAt[syntaxutil.ReturnFieldPosKey{Func: ctorB, Field: "fn", Index: 0}] = []syntaxutil.ParamKey{cleanParam}
	if ok, culprit := resCleanCycle.FieldPopulationProves("example.com/p.reg", "fn", 0); !ok || culprit != (syntaxutil.ParamKey{}) {
		t.Fatalf("FieldPopulationProves on resolved cyclic EnvFreeDeps = (%v, %+v), want (true, zero)", ok, culprit)
	}

	// 2. Direct poisons: whole-owner (!HasPos), wildcard index (Index == -1), and specific index (Index == idx).
	for _, poison := range []syntaxutil.FieldParamPoison{
		{Owner: "example.com/p.reg"},
		{Owner: "example.com/p.reg", HasPos: true, Field: "fn", Index: -1},
		{Owner: "example.com/p.reg", HasPos: true, Field: "fn", Index: 0},
	} {
		poisonedFacts := map[string][]Fact{
			"example.com/p": {
				{
					FieldParamPoison: []syntaxutil.FieldParamPoison{poison},
				},
			},
		}
		pres := NewDeferralResolution(poisonedFacts, nil)
		if ok, culprit := pres.FieldPopulationProves("example.com/p.reg", "fn", 0); ok || culprit != (syntaxutil.ParamKey{}) {
			t.Fatalf("FieldPopulationProves with poison %+v = (%v, %+v), want (false, zero)", poison, ok, culprit)
		}
	}

	// 3. Direct FieldParamDefer with unproven parameter returns (false, dirtyParamA).
	deferFailFacts := map[string][]Fact{
		"example.com/p": {
			{
				FieldParamDefer: []syntaxutil.FieldParamDefer{
					{Pos: syntaxutil.FieldPosKey{Owner: "example.com/p.reg", Field: "fn", Index: 0}, Param: dirtyParamB},
					{Pos: syntaxutil.FieldPosKey{Owner: "example.com/p.reg", Field: "fn", Index: 0}, Param: dirtyParamA},
				},
			},
		},
	}
	dres := NewDeferralResolution(deferFailFacts, nil)
	if ok, culprit := dres.FieldPopulationProves("example.com/p.reg", "fn", 0); ok || culprit != dirtyParamA {
		t.Fatalf("FieldPopulationProves with unproven FieldParamDefer = (%v, %+v), want (false, %+v)", ok, culprit, dirtyParamA)
	}

	// 4. Constructor ReturnFieldParamDefer with multiple callees in EnvFreeDeps chooses deterministically in sorted FuncKey order.
	ctorBranchFacts := map[string][]Fact{
		"example.com/p": {
			{
				ReturnEnvFree: []syntaxutil.FuncKey{regFn, ctorA, ctorB},
				ReturnEnvDeps: []syntaxutil.FuncDepEdge{
					{Func: regFn, Callee: ctorB},
					{Func: regFn, Callee: ctorA},
				},
				ReturnFieldParamDefer: []syntaxutil.ReturnFieldParamDefer{
					{Pos: syntaxutil.ReturnFieldPosKey{Func: ctorA, Field: "fn", Index: 0}, Param: dirtyParamA},
					{Pos: syntaxutil.ReturnFieldPosKey{Func: ctorB, Field: "fn", Index: 0}, Param: dirtyParamB},
				},
				EnvCallUses: []syntaxutil.EnvCallUse{
					{Key: "example.com/p.reg", Callee: regFn},
				},
			},
		},
	}
	for i := 0; i < 20; i++ {
		bres := NewDeferralResolution(ctorBranchFacts, nil)
		ok, culprit := bres.FieldPopulationProves("example.com/p.reg", "fn", 0)
		if ok || culprit != dirtyParamA {
			t.Fatalf("iter %d: FieldPopulationProves constructor branch = (%v, %+v), want (false, %+v)", i, ok, culprit, dirtyParamA)
		}
	}

	// 5. Constructor ReturnFieldParamPoison (whole-func, wildcard index -1, specific index).
	for _, rpoison := range []syntaxutil.ReturnFieldParamPoison{
		{Func: ctorA},
		{Func: ctorA, HasPos: true, Field: "fn", Index: -1},
		{Func: ctorA, HasPos: true, Field: "fn", Index: 0},
	} {
		rfacts := map[string][]Fact{
			"example.com/p": {
				{
					ReturnEnvFree:          []syntaxutil.FuncKey{ctorA},
					ReturnFieldParamPoison: []syntaxutil.ReturnFieldParamPoison{rpoison},
					EnvCallUses:            []syntaxutil.EnvCallUse{{Key: "example.com/p.reg", Callee: ctorA}},
				},
			},
		}
		rres := NewDeferralResolution(rfacts, nil)
		if ok, culprit := rres.FieldPopulationProves("example.com/p.reg", "fn", 0); ok || culprit != (syntaxutil.ParamKey{}) {
			t.Fatalf("FieldPopulationProves with ReturnFieldParamPoison %+v = (%v, %+v), want (false, zero)", rpoison, ok, culprit)
		}
	}
}

//gofresh:pure
func TestMalformedFactEntriesFailClosedInCompose(t *testing.T) {
	meta := []GraphPackage{
		{
			ImportPath: "example.com/p",
			PkgPath:    "example.com/p",
			Class:      MutableLocalPackage,
		},
	}
	validFn := syntaxutil.FuncKey{Pkg: "example.com/p", Name: "F"}
	unusedFn := syntaxutil.FuncKey{Pkg: "example.com/p", Name: "UnusedHelper"}
	validParam := syntaxutil.ParamKey{Func: validFn, Index: 0}

	cases := []struct {
		name   string
		mutate func(*Fact)
	}{
		{"invalid ReturnEnvFree NUL", func(f *Fact) { f.ReturnEnvFree = []syntaxutil.FuncKey{{Pkg: "a\x00b", Name: "F"}} }},
		{"invalid ReturnEnvDeps empty", func(f *Fact) { f.ReturnEnvDeps = []syntaxutil.FuncDepEdge{{Func: validFn}} }},
		{"invalid ReturnEnvInsertionDeps", func(f *Fact) {
			f.ReturnEnvInsertionDeps = []syntaxutil.FuncInsertionDepEdge{{Func: validFn, Dep: syntaxutil.EnvAuditTarget{Func: validFn, ParamIndex: -2}}}
		}},
		{"invalid ParamInsertionFree", func(f *Fact) { f.ParamInsertionFree = []syntaxutil.ParamKey{{Func: validFn, Index: -1}} }},
		{"invalid ParamInsertionDeps", func(f *Fact) {
			f.ParamInsertionDeps = []syntaxutil.ParamInsertionDepEdge{{Param: validParam, Dep: syntaxutil.EnvAuditTarget{ParamIndex: 0}}}
		}},
		{"invalid ParamLeakFree", func(f *Fact) { f.ParamLeakFree = []syntaxutil.ParamKey{{Func: validFn, Index: -1}} }},
		{"invalid ParamLeakFreeDeps", func(f *Fact) { f.ParamLeakFreeDeps = []syntaxutil.ParamDepEdge{{Own: validParam}} }},
		{"invalid ParamRetentionFree", func(f *Fact) { f.ParamRetentionFree = []syntaxutil.ParamKey{{Func: validFn, Index: -1}} }},
		{"invalid ParamRetentionFreeDeps", func(f *Fact) { f.ParamRetentionFreeDeps = []syntaxutil.ParamDepEdge{{Own: validParam}} }},
		{"invalid ReceiverReadOnly", func(f *Fact) { f.ReceiverReadOnly = []syntaxutil.FuncKey{{Pkg: "example.com/p"}} }},
		{"invalid ReceiverRetentionFree", func(f *Fact) { f.ReceiverRetentionFree = []syntaxutil.FuncKey{{Name: "M"}} }},
		{"invalid OpaqueDeps", func(f *Fact) { f.OpaqueDeps = []syntaxutil.OpaqueDep{{Own: "a\x00b", Dep: "c"}} }},
		{"invalid FieldParamDefer", func(f *Fact) {
			f.FieldParamDefer = []syntaxutil.FieldParamDefer{{Pos: syntaxutil.FieldPosKey{Owner: "v", Field: "f", Index: -1}, Param: validParam}}
		}},
		{"invalid FieldParamPoison", func(f *Fact) {
			f.FieldParamPoison = []syntaxutil.FieldParamPoison{{Owner: "v", HasPos: false, Field: "nonempty"}}
		}},
		{"invalid ReturnFieldParamDefer", func(f *Fact) {
			f.ReturnFieldParamDefer = []syntaxutil.ReturnFieldParamDefer{{Pos: syntaxutil.ReturnFieldPosKey{Func: validFn, Field: "", Index: 0}, Param: validParam}}
		}},
		{"invalid ReturnFieldParamPoison", func(f *Fact) {
			f.ReturnFieldParamPoison = []syntaxutil.ReturnFieldParamPoison{{Func: validFn, HasPos: true, Field: "f", Index: -2}}
		}},
		{"invalid EnvCallUses", func(f *Fact) { f.EnvCallUses = []syntaxutil.EnvCallUse{{Key: "", Callee: validFn}} }},
		{"invalid MethodUses", func(f *Fact) { f.MethodUses = []syntaxutil.VarMethodUse{{Key: "a\x00b", Method: validFn}} }},
		{"invalid InitMethodUses", func(f *Fact) { f.InitMethodUses = []syntaxutil.VarMethodUse{{Key: "v"}} }},
		{"invalid ParamUses", func(f *Fact) {
			f.ParamUses = []syntaxutil.VarParamUse{{Key: "v", Param: syntaxutil.ParamKey{Func: validFn, Index: -1}}}
		}},
		{"invalid InitParamUses", func(f *Fact) { f.InitParamUses = []syntaxutil.VarParamUse{{Key: "", Param: validParam}} }},
		{"invalid FieldParamUses", func(f *Fact) { f.FieldParamUses = []syntaxutil.FieldPosKey{{Owner: "v", Field: "f", Index: -1}} }},
		{"invalid ElemParamUses", func(f *Fact) { f.ElemParamUses = []syntaxutil.ElemParamUse{{Key: "v", Owner: "o", Index: -1}} }},
		{"invalid FuncRefs kind", func(f *Fact) {
			f.FuncRefs = append(f.FuncRefs, syntaxutil.FuncRef{Callee: validFn, Region: syntaxutil.RefRegion{Kind: 99}})
		}},
		{"invalid FuncRefs RegionInit with caller", func(f *Fact) {
			f.FuncRefs = append(f.FuncRefs, syntaxutil.FuncRef{Callee: validFn, Region: syntaxutil.RefRegion{Kind: syntaxutil.RegionInit, Caller: validFn}})
		}},
		{"invalid AttributedUses", func(f *Fact) {
			f.AttributedUses = append(f.AttributedUses, syntaxutil.AttributedUse{Func: validFn, Key: "example.com/p.v", Escape: true, HasMethod: true, Method: validFn})
		}},
		{"invalid CarrierLinks", func(f *Fact) {
			f.CarrierLinks = []syntaxutil.CarrierLink{{From: "example.com/p.v", To: "bad\x00key"}}
		}},
		{"invalid ExportedSeams", func(f *Fact) {
			f.ExportedSeams = []syntaxutil.ExportedSeam{{Func: syntaxutil.FuncKey{}, Key: "example.com/p.v"}}
		}},
		{"invalid NonSeqFuncUses", func(f *Fact) {
			f.NonSeqFuncUses = []syntaxutil.FuncKey{{Pkg: "example.com/p", Name: ""}}
		}},
		{"invalid SeqFuncEdges", func(f *Fact) {
			f.SeqFuncEdges = []syntaxutil.FuncDepEdge{{Func: validFn}}
		}},
		{"invalid ParallelFuncs", func(f *Fact) {
			f.ParallelFuncs = []syntaxutil.FuncKey{{Name: "EnterParallel"}}
		}},
		{"invalid ParallelEdges", func(f *Fact) {
			f.ParallelEdges = []syntaxutil.FuncDepEdge{{Func: validFn}}
		}},
		{"invalid MappingDischarges", func(f *Fact) {
			f.MappingDischarges = []string{"bad\x00key"}
		}},
		{"invalid MemoDischarges", func(f *Fact) {
			f.MemoDischarges = []string{""}
		}},
		{"invalid ProtoClusters empty vars", func(f *Fact) {
			f.ProtoClusters = []protoaudit.ProtoClusterFact{{
				InitFn:      validFn,
				BuilderType: syntaxutil.TypeRef{Pkg: "example.com/rt", Name: "TypeBuilder"},
			}}
		}},
		{"invalid ProtoExtAliases self-target", func(f *Fact) {
			f.ProtoExtAliases = []protoaudit.ProtoExtAlias{{Key: "example.com/p.E", Target: "example.com/p.E"}}
		}},
		{"invalid ProtoRuntimeTypes unknown role", func(f *Fact) {
			f.ProtoRuntimeTypes = []protoaudit.ProtoRuntimeTypeFact{{
				Type: syntaxutil.TypeRef{Pkg: "example.com/p", Name: "MessageInfo"},
				Role: "unknown",
			}}
		}},
		{"invalid ProtoRuntimeTypes builder InitHelper", func(f *Fact) {
			f.ProtoRuntimeTypes = []protoaudit.ProtoRuntimeTypeFact{{
				Type:       syntaxutil.TypeRef{Pkg: "example.com/p", Name: "TypeBuilder"},
				Role:       protoaudit.ProtoRoleBuilder,
				InitHelper: validFn,
			}}
		}},
		{"invalid ProtoRuntimeTypes extension AllowedHelpers", func(f *Fact) {
			f.ProtoRuntimeTypes = []protoaudit.ProtoRuntimeTypeFact{{
				Type:           syntaxutil.TypeRef{Pkg: "example.com/p", Name: "ExtensionInfo"},
				Role:           protoaudit.ProtoRoleExtension,
				AllowedHelpers: []syntaxutil.FuncKey{validFn},
			}}
		}},
		{"invalid ProtoRuntimeTypes builder malformed SubBuilder", func(f *Fact) {
			f.ProtoRuntimeTypes = []protoaudit.ProtoRuntimeTypeFact{{
				Type:       syntaxutil.TypeRef{Pkg: "example.com/p", Name: "TypeBuilder"},
				Role:       protoaudit.ProtoRoleBuilder,
				SubBuilder: syntaxutil.TypeRef{Pkg: "example.com/p", Name: "a.Builder"},
			}}
		}},
		{"invalid ProtoRuntimeTypes builder malformed GuardTypes", func(f *Fact) {
			f.ProtoRuntimeTypes = []protoaudit.ProtoRuntimeTypeFact{{
				Type:       syntaxutil.TypeRef{Pkg: "example.com/p", Name: "TypeBuilder"},
				Role:       protoaudit.ProtoRoleBuilder,
				GuardTypes: []syntaxutil.TypeRef{{Pkg: "example.com/p", Name: ""}},
			}}
		}},
		{"invalid ProtoRuntimeTypes desc_builder empty GuardTypes", func(f *Fact) {
			f.ProtoRuntimeTypes = []protoaudit.ProtoRuntimeTypeFact{{
				Type: syntaxutil.TypeRef{Pkg: "example.com/p", Name: "Builder"},
				Role: protoaudit.ProtoRoleDescBuilder,
			}}
		}},
		{"invalid ProtoRuntimeTypes desc_builder non-zero SubBuilder", func(f *Fact) {
			f.ProtoRuntimeTypes = []protoaudit.ProtoRuntimeTypeFact{{
				Type:       syntaxutil.TypeRef{Pkg: "example.com/p", Name: "Builder"},
				Role:       protoaudit.ProtoRoleDescBuilder,
				SubBuilder: syntaxutil.TypeRef{Pkg: "example.com/p", Name: "Sub"},
				GuardTypes: []syntaxutil.TypeRef{{Pkg: "example.com/p", Name: "File"}},
			}}
		}},
		{"invalid ProtoRuntimeTypes desc_builder AllowedHelpers", func(f *Fact) {
			f.ProtoRuntimeTypes = []protoaudit.ProtoRuntimeTypeFact{{
				Type:           syntaxutil.TypeRef{Pkg: "example.com/p", Name: "Builder"},
				Role:           protoaudit.ProtoRoleDescBuilder,
				AllowedHelpers: []syntaxutil.FuncKey{validFn},
				GuardTypes:     []syntaxutil.TypeRef{{Pkg: "example.com/p", Name: "File"}},
			}}
		}},
		{"invalid ProtoRuntimeTypes enum GuardTypes", func(f *Fact) {
			f.ProtoRuntimeTypes = []protoaudit.ProtoRuntimeTypeFact{{
				Type:       syntaxutil.TypeRef{Pkg: "example.com/p", Name: "EnumInfo"},
				Role:       protoaudit.ProtoRoleEnum,
				GuardTypes: []syntaxutil.TypeRef{{Pkg: "example.com/p", Name: "Methods"}},
			}}
		}},
		{"invalid ProtoRuntimeTypes message malformed GuardTypes", func(f *Fact) {
			f.ProtoRuntimeTypes = []protoaudit.ProtoRuntimeTypeFact{{
				Type:       syntaxutil.TypeRef{Pkg: "example.com/p", Name: "MessageInfo"},
				Role:       protoaudit.ProtoRoleMessage,
				GuardTypes: []syntaxutil.TypeRef{{Pkg: "example.com/p", Name: ""}},
			}}
		}},
		{"invalid GrpcServiceVars qualified type name", func(f *Fact) {
			f.GrpcServiceVars = []protoaudit.GrpcServiceVarFact{{
				Key:     "example.com/p.Desc",
				SvcDesc: syntaxutil.TypeRef{Pkg: "example.com/grpc", Name: "a.ServiceDesc"},
			}}
		}},
		{"invalid MutatedStructTypes empty name", func(f *Fact) {
			f.MutatedStructTypes = []syntaxutil.TypeRef{{Pkg: "example.com/p", Name: ""}}
		}},
		{"invalid DirectVarWrites bare symbol", func(f *Fact) {
			f.DirectVarWrites = []string{"bare"}
		}},
		{"invalid DirectVarWrites nul byte", func(f *Fact) {
			f.DirectVarWrites = []string{"example.com/p.x\x00y"}
		}},
		{"invalid ConditionalStructMutations missing guards", func(f *Fact) {
			f.ConditionalStructMutations = []syntaxutil.ConditionalStructMutation{{
				Struct: syntaxutil.TypeRef{Pkg: "example.com/p", Name: "S"},
			}}
		}},
		{"invalid ConditionalStructMutations bad Struct", func(f *Fact) {
			f.ConditionalStructMutations = []syntaxutil.ConditionalStructMutation{{
				Struct:   syntaxutil.TypeRef{Pkg: "example.com/p", Name: ""},
				GuardPkg: "example.com/dep",
			}}
		}},
		{"invalid ConditionalStructMutations nul GuardPkg", func(f *Fact) {
			f.ConditionalStructMutations = []syntaxutil.ConditionalStructMutation{{
				Struct:   syntaxutil.TypeRef{Pkg: "example.com/p", Name: "S"},
				GuardPkg: "example.com/d\x00p",
			}}
		}},
		{"invalid ConditionalStructMutations bad GuardStruct", func(f *Fact) {
			f.ConditionalStructMutations = []syntaxutil.ConditionalStructMutation{{
				Struct:      syntaxutil.TypeRef{Pkg: "example.com/p", Name: "S"},
				GuardStruct: syntaxutil.TypeRef{Pkg: "example.com/dep", Name: "a.b"},
			}}
		}},
		{"invalid ConditionalStructMutations RequireDescBuilderGuard without GuardStruct", func(f *Fact) {
			f.ConditionalStructMutations = []syntaxutil.ConditionalStructMutation{{
				Struct:                  syntaxutil.TypeRef{Pkg: "example.com/p", Name: "S"},
				GuardPkg:                "example.com/dep",
				RequireDescBuilderGuard: true,
			}}
		}},
		{"invalid ConditionalStructMutations multiple modes", func(f *Fact) {
			f.ConditionalStructMutations = []syntaxutil.ConditionalStructMutation{{
				Struct:      syntaxutil.TypeRef{Pkg: "example.com/p", Name: "S"},
				GuardPkg:    "example.com/dep",
				GuardStruct: syntaxutil.TypeRef{Pkg: "example.com/dep", Name: "G"},
			}}
		}},
		{"invalid CarrierImportCalls without NoPostInitCarrierWrites", func(f *Fact) {
			f.NoPostInitCarrierWrites = false
			f.CarrierImportCalls = []string{"example.com/dep"}
		}},
		{"invalid CarrierImportCalls empty entry", func(f *Fact) {
			f.NoPostInitCarrierWrites = true
			f.CarrierImportCalls = []string{""}
		}},
		{"invalid CarrierImportCalls nul entry", func(f *Fact) {
			f.NoPostInitCarrierWrites = true
			f.CarrierImportCalls = []string{"example.com/d\x00p"}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Include an attributed use in unusedFn so that if unattributedMark["example.com/p.v"]
			// were not set on malformed-fact fallback, CulpritSites["example.com/p.v"].Unattributed
			// would falsely become false (only blaming unusedFn) or initOnlyFn would discharge validFn.
			fact := Fact{
				Declares:    []string{"example.com/p.v"},
				EnvCallable: []string{"example.com/p.v"},
				AttributedUses: []syntaxutil.AttributedUse{
					{Func: unusedFn, Key: "example.com/p.v"},
				},
				FuncRefs: []syntaxutil.FuncRef{
					{Callee: validFn, Region: syntaxutil.RefRegion{Kind: syntaxutil.RegionInit}},
				},
			}
			tc.mutate(&fact)
			state := Compose(meta, map[string][]Fact{"example.com/p": {fact}}, "example.com/p", nil, true, false)
			if state.Downgraded == "" {
				t.Fatalf("Compose with %s did not downgrade package", tc.name)
			}
			site, ok := state.CulpritSites["example.com/p.v"]
			if !ok || !site.Unattributed {
				t.Fatalf("Compose with %s produced CulpritSites[v] = %+v (ok=%v), want Unattributed=true", tc.name, site, ok)
			}
		})
	}

	// Cross-fact / empty-Declares fail-closed verification: when a helper/constructor
	// fact has Declares == nil and carries a partially malformed dependency, deferral,
	// opacity, or call-region edge, ResolveEnvAudit, NewDeferralResolution, and Compose
	// must poison the affected symbol/carrier rather than dropping the broken precondition.
	helperFn := syntaxutil.FuncKey{Pkg: "example.com/p", Name: "Helper"}
	helperParam := syntaxutil.ParamKey{Func: helperFn, Index: 0}
	crossFactCases := []struct {
		name       string
		ownerFact  Fact
		helperFact Fact
		check      func(*testing.T, *EnvAuditResolution, *DeferralResolution, ConeState)
	}{
		{
			name: "cross-fact malformed ReturnEnvDeps poisons constructor",
			ownerFact: Fact{
				Declares:    []string{"example.com/p.v"},
				EnvCallable: []string{"example.com/p.v"},
				EnvCallUses: []syntaxutil.EnvCallUse{{Key: "example.com/p.v", Callee: helperFn}},
			},
			helperFact: Fact{
				ReturnEnvFree: []syntaxutil.FuncKey{helperFn},
				ReturnEnvDeps: []syntaxutil.FuncDepEdge{{Func: helperFn, Callee: syntaxutil.FuncKey{}}},
			},
			check: func(t *testing.T, ea *EnvAuditResolution, dr *DeferralResolution, cs ConeState) {
				if ea.Resolved[helperFn] || dr.EnvFreeResolved[helperFn] || cs.Downgraded == "" {
					t.Fatalf("expected helperFn poisoned and package downgraded: ea=%v dr=%v cs=%+v", ea.Resolved[helperFn], dr.EnvFreeResolved[helperFn], cs)
				}
			},
		},
		{
			name: "cross-fact malformed ReturnEnvInsertionDeps poisons constructor",
			ownerFact: Fact{
				Declares:    []string{"example.com/p.v"},
				EnvCallable: []string{"example.com/p.v"},
				EnvCallUses: []syntaxutil.EnvCallUse{{Key: "example.com/p.v", Callee: helperFn}},
			},
			helperFact: Fact{
				ReturnEnvFree:          []syntaxutil.FuncKey{helperFn},
				ReturnEnvInsertionDeps: []syntaxutil.FuncInsertionDepEdge{{Func: helperFn, Dep: syntaxutil.EnvAuditTarget{Func: helperFn, ParamIndex: -2}}},
			},
			check: func(t *testing.T, ea *EnvAuditResolution, _ *DeferralResolution, cs ConeState) {
				if ea.Resolved[helperFn] || cs.Downgraded == "" {
					t.Fatalf("expected helperFn poisoned and package downgraded: ea=%v cs=%+v", ea.Resolved[helperFn], cs)
				}
			},
		},
		{
			name: "cross-fact malformed ParamInsertionDeps poisons param",
			ownerFact: Fact{
				Declares: []string{"example.com/p.v"},
			},
			helperFact: Fact{
				ParamInsertionFree: []syntaxutil.ParamKey{helperParam},
				ParamInsertionDeps: []syntaxutil.ParamInsertionDepEdge{{Param: helperParam, Dep: syntaxutil.EnvAuditTarget{ParamIndex: 0}}},
			},
			check: func(t *testing.T, ea *EnvAuditResolution, _ *DeferralResolution, _ ConeState) {
				if ea.InsResolved[helperParam] {
					t.Fatalf("expected helperParam poisoned in InsResolved")
				}
			},
		},
		{
			name: "cross-fact malformed ParamLeakFreeDeps poisons param",
			ownerFact: Fact{
				Declares:      []string{"example.com/p.v"},
				ParamLeakFree: []syntaxutil.ParamKey{{Func: syntaxutil.FuncKey{Pkg: "example.com/p", Name: "clean"}, Index: 0}},
				ParamUses:     []syntaxutil.VarParamUse{{Key: "example.com/p.v", Param: helperParam}},
			},
			helperFact: Fact{
				ParamLeakFree: []syntaxutil.ParamKey{helperParam},
				ParamLeakFreeDeps: []syntaxutil.ParamDepEdge{
					{Own: helperParam, Dep: syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/p", Name: "clean"}, Index: 0}},
					{Own: helperParam},
				},
			},
			check: func(t *testing.T, _ *EnvAuditResolution, dr *DeferralResolution, cs ConeState) {
				if dr.ParamLeakFree[helperParam] || cs.Downgraded == "" {
					t.Fatalf("expected helperParam leak-poisoned and package downgraded: dr=%v cs=%+v", dr.ParamLeakFree[helperParam], cs)
				}
			},
		},
		{
			name: "cross-fact malformed ParamRetentionFreeDeps poisons param",
			ownerFact: Fact{
				Declares:           []string{"example.com/p.v"},
				ParamRetentionFree: []syntaxutil.ParamKey{{Func: syntaxutil.FuncKey{Pkg: "example.com/p", Name: "clean"}, Index: 0}},
				InitParamUses:      []syntaxutil.VarParamUse{{Key: "example.com/p.v", Param: helperParam}},
			},
			helperFact: Fact{
				ParamRetentionFree: []syntaxutil.ParamKey{helperParam},
				ParamRetentionFreeDeps: []syntaxutil.ParamDepEdge{
					{Own: helperParam, Dep: syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/p", Name: "clean"}, Index: 0}},
					{Own: helperParam},
				},
			},
			check: func(t *testing.T, _ *EnvAuditResolution, dr *DeferralResolution, cs ConeState) {
				if dr.ParamRetentionFree[helperParam] || cs.Downgraded == "" {
					t.Fatalf("expected helperParam retention-poisoned and package downgraded: dr=%v cs=%+v", dr.ParamRetentionFree[helperParam], cs)
				}
			},
		},
		{
			name: "cross-fact malformed OpaqueDeps breaks opacity",
			ownerFact: Fact{
				Declares: []string{"example.com/p.v"},
				Opaque:   []string{"example.com/p.v"},
			},
			helperFact: Fact{
				OpaqueDeps: []syntaxutil.OpaqueDep{{Own: "example.com/p.v", Dep: "bad\x00dep"}},
			},
			check: func(t *testing.T, _ *EnvAuditResolution, dr *DeferralResolution, _ ConeState) {
				if !dr.NotOpaque["example.com/p.v"] {
					t.Fatalf("expected malformed OpaqueDeps to mark owner NotOpaque")
				}
			},
		},
		{
			name: "cross-fact malformed FieldParamDefer poisons owner",
			ownerFact: Fact{
				Declares:       []string{"example.com/p.v"},
				FieldParamUses: []syntaxutil.FieldPosKey{{Owner: "example.com/p.v", Field: "fn", Index: 0}},
			},
			helperFact: Fact{
				FieldParamDefer: []syntaxutil.FieldParamDefer{{Pos: syntaxutil.FieldPosKey{Owner: "example.com/p.v", Field: "fn", Index: -1}, Param: helperParam}},
			},
			check: func(t *testing.T, _ *EnvAuditResolution, dr *DeferralResolution, cs ConeState) {
				if ok, _ := dr.FieldPopulationProves("example.com/p.v", "fn", 0); ok || cs.Downgraded == "" {
					t.Fatalf("expected FieldPopulationProves=false and package downgraded: ok=%v cs=%+v", ok, cs)
				}
			},
		},
		{
			name: "cross-fact malformed ReturnFieldParamDefer poisons constructor",
			ownerFact: Fact{
				Declares:       []string{"example.com/p.v"},
				EnvCallUses:    []syntaxutil.EnvCallUse{{Key: "example.com/p.v", Callee: helperFn}},
				FieldParamUses: []syntaxutil.FieldPosKey{{Owner: "example.com/p.v", Field: "fn", Index: 0}},
			},
			helperFact: Fact{
				ReturnEnvFree:         []syntaxutil.FuncKey{helperFn},
				ReturnFieldParamDefer: []syntaxutil.ReturnFieldParamDefer{{Pos: syntaxutil.ReturnFieldPosKey{Func: helperFn, Field: "", Index: 0}, Param: helperParam}},
			},
			check: func(t *testing.T, _ *EnvAuditResolution, dr *DeferralResolution, cs ConeState) {
				if ok, _ := dr.FieldPopulationProves("example.com/p.v", "fn", 0); ok || cs.Downgraded == "" {
					t.Fatalf("expected FieldPopulationProves=false and package downgraded: ok=%v cs=%+v", ok, cs)
				}
			},
		},
		{
			name: "cross-fact malformed FuncRefs forces non-init reachability",
			ownerFact: Fact{
				Declares:       []string{"example.com/p.v"},
				AttributedUses: []syntaxutil.AttributedUse{{Func: validFn, Key: "example.com/p.v"}},
				FuncRefs:       []syntaxutil.FuncRef{{Callee: validFn, Region: syntaxutil.RefRegion{Kind: syntaxutil.RegionInit}}},
			},
			helperFact: Fact{
				FuncRefs: []syntaxutil.FuncRef{{Callee: validFn, Region: syntaxutil.RefRegion{Kind: 99}}},
			},
			check: func(t *testing.T, _ *EnvAuditResolution, _ *DeferralResolution, cs ConeState) {
				if cs.Downgraded == "" {
					t.Fatalf("expected malformed FuncRefs in helper fact to prevent initOnlyFn discharge")
				}
			},
		},
		{
			name: "cross-fact malformed ExportedSeams blocks valid exported seam",
			ownerFact: Fact{
				Declares:      []string{"example.com/p.v"},
				ExportedSeams: []syntaxutil.ExportedSeam{{Func: validFn, Key: "example.com/p.v"}},
			},
			helperFact: Fact{
				ExportedSeams: []syntaxutil.ExportedSeam{{Func: syntaxutil.FuncKey{}, Key: ""}},
			},
			check: func(t *testing.T, _ *EnvAuditResolution, _ *DeferralResolution, cs ConeState) {
				if cs.Downgraded == "" || !cs.CulpritSites["example.com/p.v"].Unattributed {
					t.Fatalf("expected cross-fact malformed ExportedSeams to block seam unattributed: %+v", cs)
				}
			},
		},
		{
			name: "cross-fact malformed NonSeqFuncUses blocks valid exported seam",
			ownerFact: Fact{
				Declares:      []string{"example.com/p.v"},
				ExportedSeams: []syntaxutil.ExportedSeam{{Func: validFn, Key: "example.com/p.v"}},
			},
			helperFact: Fact{
				NonSeqFuncUses: []syntaxutil.FuncKey{{Pkg: "example.com/p", Name: ""}},
			},
			check: func(t *testing.T, _ *EnvAuditResolution, _ *DeferralResolution, cs ConeState) {
				if cs.Downgraded == "" || !cs.CulpritSites["example.com/p.v"].Unattributed {
					t.Fatalf("expected cross-fact malformed NonSeqFuncUses to block seam unattributed: %+v", cs)
				}
			},
		},
		{
			name: "cross-fact malformed SeqFuncEdges blocks valid exported seam",
			ownerFact: Fact{
				Declares:      []string{"example.com/p.v"},
				ExportedSeams: []syntaxutil.ExportedSeam{{Func: validFn, Key: "example.com/p.v"}},
			},
			helperFact: Fact{
				SeqFuncEdges: []syntaxutil.FuncDepEdge{{}},
			},
			check: func(t *testing.T, _ *EnvAuditResolution, _ *DeferralResolution, cs ConeState) {
				if cs.Downgraded == "" || !cs.CulpritSites["example.com/p.v"].Unattributed {
					t.Fatalf("expected cross-fact malformed SeqFuncEdges to block seam unattributed: %+v", cs)
				}
			},
		},
		{
			name: "cross-fact malformed ParallelFuncs blocks valid exported seam",
			ownerFact: Fact{
				Declares:      []string{"example.com/p.v"},
				ExportedSeams: []syntaxutil.ExportedSeam{{Func: validFn, Key: "example.com/p.v"}},
			},
			helperFact: Fact{
				ParallelFuncs: []syntaxutil.FuncKey{{Name: "EnterParallel"}},
			},
			check: func(t *testing.T, _ *EnvAuditResolution, _ *DeferralResolution, cs ConeState) {
				if cs.Downgraded == "" || !cs.CulpritSites["example.com/p.v"].Unattributed {
					t.Fatalf("expected cross-fact malformed ParallelFuncs to block seam unattributed: %+v", cs)
				}
			},
		},
		{
			name: "cross-fact malformed ParallelEdges blocks valid exported seam",
			ownerFact: Fact{
				Declares:      []string{"example.com/p.v"},
				ExportedSeams: []syntaxutil.ExportedSeam{{Func: validFn, Key: "example.com/p.v"}},
			},
			helperFact: Fact{
				ParallelEdges: []syntaxutil.FuncDepEdge{{Func: validFn}},
			},
			check: func(t *testing.T, _ *EnvAuditResolution, _ *DeferralResolution, cs ConeState) {
				if cs.Downgraded == "" || !cs.CulpritSites["example.com/p.v"].Unattributed {
					t.Fatalf("expected cross-fact malformed ParallelEdges to block seam unattributed: %+v", cs)
				}
			},
		},
		{
			name: "cross-fact malformed DirectVarWrites blocks MappingDischarges",
			ownerFact: Fact{
				Declares:          []string{"example.com/p.v"},
				Mutates:           []string{"example.com/p.v"},
				MappingDischarges: []string{"example.com/p.v"},
			},
			helperFact: Fact{
				DirectVarWrites: []string{"bare"},
			},
			check: func(t *testing.T, _ *EnvAuditResolution, _ *DeferralResolution, cs ConeState) {
				if cs.Downgraded == "" || !cs.CulpritSites["example.com/p.v"].Unattributed {
					t.Fatalf("expected cross-fact malformed DirectVarWrites to block MappingDischarges: %+v", cs)
				}
			},
		},
		{
			name: "cross-fact malformed MutatedStructTypes blocks GrpcServiceVars",
			ownerFact: Fact{
				Declares: []string{"example.com/p.v"},
				Mutates:  []string{"example.com/p.v"},
				GrpcServiceVars: []protoaudit.GrpcServiceVarFact{{
					Key:     "example.com/p.v",
					SvcDesc: syntaxutil.TypeRef{Pkg: "example.com/grpc", Name: "ServiceDesc"},
				}},
			},
			helperFact: Fact{
				MutatedStructTypes: []syntaxutil.TypeRef{{Pkg: "example.com/grpc", Name: ""}},
			},
			check: func(t *testing.T, _ *EnvAuditResolution, _ *DeferralResolution, cs ConeState) {
				if cs.Downgraded == "" || !cs.CulpritSites["example.com/p.v"].Unattributed {
					t.Fatalf("expected cross-fact malformed MutatedStructTypes to block GrpcServiceVars: %+v", cs)
				}
			},
		},
		{
			name: "cross-fact malformed ConditionalStructMutations blocks GrpcServiceVars",
			ownerFact: Fact{
				Declares: []string{"example.com/p.v"},
				Mutates:  []string{"example.com/p.v"},
				GrpcServiceVars: []protoaudit.GrpcServiceVarFact{{
					Key:     "example.com/p.v",
					SvcDesc: syntaxutil.TypeRef{Pkg: "example.com/grpc", Name: "ServiceDesc"},
				}},
			},
			helperFact: Fact{
				ConditionalStructMutations: []syntaxutil.ConditionalStructMutation{{
					Struct: syntaxutil.TypeRef{Pkg: "example.com/p", Name: "S"},
				}},
			},
			check: func(t *testing.T, _ *EnvAuditResolution, _ *DeferralResolution, cs ConeState) {
				if cs.Downgraded == "" || !cs.CulpritSites["example.com/p.v"].Unattributed {
					t.Fatalf("expected cross-fact malformed ConditionalStructMutations to block GrpcServiceVars: %+v", cs)
				}
			},
		},
		{
			name: "cross-fact malformed CarrierImportCalls blocks GrpcServiceVars",
			ownerFact: Fact{
				Declares: []string{"example.com/p.v"},
				Mutates:  []string{"example.com/p.v"},
				GrpcServiceVars: []protoaudit.GrpcServiceVarFact{{
					Key:     "example.com/p.v",
					SvcDesc: syntaxutil.TypeRef{Pkg: "example.com/grpc", Name: "ServiceDesc"},
				}},
			},
			helperFact: Fact{
				NoPostInitCarrierWrites: false,
				CarrierImportCalls:      []string{"example.com/dep"},
			},
			check: func(t *testing.T, _ *EnvAuditResolution, _ *DeferralResolution, cs ConeState) {
				if cs.Downgraded == "" || !cs.CulpritSites["example.com/p.v"].Unattributed {
					t.Fatalf("expected cross-fact malformed CarrierImportCalls to block GrpcServiceVars: %+v", cs)
				}
			},
		},
	}
	for _, tc := range crossFactCases {
		t.Run(tc.name, func(t *testing.T) {
			facts := map[string][]Fact{
				"example.com/p": {tc.ownerFact, tc.helperFact},
			}
			ea := ResolveEnvAudit(facts, nil)
			dr := NewDeferralResolution(facts, nil)
			cs := Compose(meta, facts, "example.com/p", nil, true, false)
			tc.check(t, ea, dr, cs)
		})
	}

	// Cross-package malformed ConditionalStructMutations or CarrierImportCalls in a
	// sibling dependency package must also poison ProtoClusters and GrpcServiceVars
	// in an otherwise clean owner package.
	for _, xpkg := range []struct {
		name    string
		depFact Fact
	}{
		{
			name: "cross-pkg malformed ConditionalStructMutations",
			depFact: Fact{
				ConditionalStructMutations: []syntaxutil.ConditionalStructMutation{{
					Struct:                  syntaxutil.TypeRef{Pkg: "example.com/dep", Name: "S"},
					GuardPkg:                "example.com/other",
					RequireDescBuilderGuard: true,
				}},
			},
		},
		{
			name: "cross-pkg malformed CarrierImportCalls",
			depFact: Fact{
				NoPostInitCarrierWrites: true,
				CarrierImportCalls:      []string{"example.com/bad\x00dep"},
			},
		},
		{
			name: "cross-pkg malformed NonMutatingMethods invalid FuncKey",
			depFact: Fact{
				NonMutatingMethods: []syntaxutil.FuncKey{{Pkg: "example.com/dep", Name: ""}},
			},
		},
		{
			name: "cross-pkg malformed NonMutatingMethods mismatched Pkg",
			depFact: Fact{
				NonMutatingMethods: []syntaxutil.FuncKey{{Pkg: "example.com/other", Name: " T.M"}},
			},
		},
		{
			name: "cross-pkg malformed ConditionalStructMutations RequireNonMutatingMethod",
			depFact: Fact{
				ConditionalStructMutations: []syntaxutil.ConditionalStructMutation{{
					Struct:                   syntaxutil.TypeRef{Pkg: "example.com/dep", Name: "S"},
					GuardPkg:                 "example.com/other",
					RequireNonMutatingMethod: syntaxutil.FuncKey{Pkg: "example.com/other", Name: "T.M"},
				}},
			},
		},
	} {
		t.Run(xpkg.name, func(t *testing.T) {
			xMeta := []GraphPackage{
				{ImportPath: "example.com/p", PkgPath: "example.com/p", Imports: []string{"example.com/dep"}, Class: MutableLocalPackage},
				{ImportPath: "example.com/dep", PkgPath: "example.com/dep", Class: PinnedPackage, Pin: "example.com/dep@v1.0.0"},
			}
			xFacts := map[string][]Fact{
				"example.com/p": {{
					Declares: []string{"example.com/p.v"},
					Mutates:  []string{"example.com/p.v"},
					GrpcServiceVars: []protoaudit.GrpcServiceVarFact{{
						Key:     "example.com/p.v",
						SvcDesc: syntaxutil.TypeRef{Pkg: "example.com/grpc", Name: "ServiceDesc"},
					}},
				}},
				"example.com/dep": {xpkg.depFact},
			}
			cs := Compose(xMeta, xFacts, "example.com/p", nil, true, false)
			if cs.Downgraded == "" {
				t.Fatalf("%s failed to block GrpcServiceVars across packages: %+v", xpkg.name, cs)
			}
		})
	}
}

//gofresh:pure
func TestCarrierWalkPoliciesRecursiveTypesAndDirectives(t *testing.T) {
	pkg := mustTypecheckPackage(t, "example.com/carrier", map[string]string{
		"carrier.go": `package carrier

import (
	"sync/atomic"
	"testing"
	"unsafe"
)

type RecursiveClean struct {
	Val  int
	Next *RecursiveClean
}

type RecursiveDirty struct {
	Fn   func()
	Next *RecursiveDirty
}

type AtomicClean struct {
	Ptr atomic.Pointer[int]
}

type AtomicDirty struct {
	Ptr atomic.Pointer[func()]
}

type WrappedAtomic atomic.Pointer[int]

type UnsafeHolder struct {
	P unsafe.Pointer
}

func GenericClean[T ~int | ~string](x T) T { return x }
func GenericDirty[T any](x T) T            { return x }
func GenericMethodConstraint[T interface{ ~int; M() }](x T) T { return x }
func HarnessTest(t *testing.T) {}

func init() {}
func init() {}

//gofresh:pure
func PureFn(x int) int { return x }

//gofresh:pure
//gofresh:external
func ConflictFn(x int) int { return x }
`,
	})

	scope := pkg.Types.Scope()
	lookupType := func(name string) types.Type {
		obj := scope.Lookup(name)
		if obj == nil {
			t.Fatalf("missing type %s", name)
		}
		return obj.Type()
	}

	// 1. Recursive clean vs dirty types terminate and classify accurately.
	recClean := lookupType("RecursiveClean")
	recDirty := lookupType("RecursiveDirty")
	for _, policy := range []refconfine.CarrierWalkPolicy{refconfine.CarrierPolicyClosure, refconfine.CarrierPolicyConsumer, refconfine.CarrierPolicyAlias} {
		if refconfine.WalkDynamicCarrier(true, recClean, make(map[types.Type]bool), policy) {
			t.Fatalf("RecursiveClean classified as carrier under policy %v", policy)
		}
	}
	if !refconfine.TypeMayCarryUnknownDynamic(true, recDirty) || !refconfine.TypeHandsOutDynamicAlias(true, recDirty) {
		t.Fatal("RecursiveDirty (*RecursiveDirty reaching func()) must carry dynamic and hand out alias")
	}

	// 2. Plain func() carries dynamic under Closure/Consumer, but does NOT hand out alias by value.
	fnType := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	if !refconfine.TypeMayCarryUnknownDynamic(true, fnType) {
		t.Fatal("func() must carry dynamic under consumer policy")
	}
	if refconfine.TypeHandsOutDynamicAlias(true, fnType) {
		t.Fatal("func() by value must not hand out dynamic alias")
	}
	if !refconfine.TypeHandsOutDynamicAlias(true, types.NewSlice(fnType)) {
		t.Fatal("[]func() must hand out dynamic alias")
	}
	if !refconfine.TypeMayCarryUnknownDynamic(true, types.Typ[types.UnsafePointer]) {
		t.Fatal("unsafe.Pointer must carry dynamic")
	}

	// 3. Audited sync/atomic.Pointer[T] is transparent to T when audited=true, fail-closed when audited=false,
	// and defined wrapper types stay fail-closed.
	atomicClean := lookupType("AtomicClean")
	atomicDirty := lookupType("AtomicDirty")
	wrappedAtomic := lookupType("WrappedAtomic")
	if refconfine.TypeMayCarryUnknownDynamic(true, atomicClean) {
		t.Fatal("audited atomic.Pointer[int] must not carry dynamic")
	}
	if !refconfine.TypeMayCarryUnknownDynamic(false, atomicClean) {
		t.Fatal("unaudited atomic.Pointer[int] must fail closed")
	}
	if !refconfine.TypeMayCarryUnknownDynamic(true, atomicDirty) {
		t.Fatal("atomic.Pointer[func()] must carry dynamic")
	}
	if !refconfine.TypeMayCarryUnknownDynamic(true, wrappedAtomic) {
		t.Fatal("defined wrapper over atomic.Pointer[int] must fail closed")
	}

	// 4. SignatureOpenWorldTerm across generic constraints and testing harness signatures.
	lookupSig := func(name string) *types.Signature {
		fn, ok := scope.Lookup(name).(*types.Func)
		if !ok {
			t.Fatalf("missing func %s", name)
		}
		return fn.Type().(*types.Signature)
	}
	if term := refconfine.OpenWorldTerm(true, lookupSig("GenericClean")); term != "" {
		t.Fatalf("OpenWorldTerm(GenericClean) = %q, want empty", term)
	}
	if term := refconfine.OpenWorldTerm(true, lookupSig("GenericDirty")); !strings.Contains(term, "type parameter T") {
		t.Fatalf("OpenWorldTerm(GenericDirty) = %q, want type parameter T refusal", term)
	}
	if term := refconfine.OpenWorldTerm(true, lookupSig("GenericMethodConstraint")); !strings.Contains(term, "type parameter T") {
		t.Fatalf("OpenWorldTerm(GenericMethodConstraint) = %q, want type parameter T refusal", term)
	}
	if term := refconfine.OpenWorldTerm(true, lookupSig("HarnessTest")); term != "" {
		t.Fatalf("OpenWorldTerm(HarnessTest) = %q, want empty", term)
	}
	if term := refconfine.SignatureOpenWorldTerm(true, lookupSig("HarnessTest"), nil, false, refconfine.CarrierPolicyConsumer); !strings.Contains(term, "parameter t") {
		t.Fatalf("SignatureOpenWorldTerm(HarnessTest, allowHarness=false) = %q, want parameter t refusal", term)
	}

	// 5. WalkLoadedSubjects detects conflicting //gofresh:pure + //gofresh:external directives and numbers init ordinals.
	var scanned []ScannedSymbol
	err := WalkLoadedSubjects(true, true, []*packages.Package{pkg}, nil, []string{"example.com/carrier"}, func(s ScannedSymbol) {
		scanned = append(scanned, s)
	})
	if err == nil || !strings.Contains(err.Error(), "carries both //gofresh:pure and //gofresh:external") {
		t.Fatalf("WalkLoadedSubjects error = %v, want conflicting directive error", err)
	}
	initSeen := map[string]bool{}
	for _, s := range scanned {
		if strings.HasPrefix(s.Symbol, "init#") {
			initSeen[s.Symbol] = true
		}
	}
	if !initSeen["init#carrier.go#0"] || !initSeen["init#carrier.go#1"] {
		t.Fatalf("missing init ordinals in scanned symbols: %v", initSeen)
	}

	// 6. NodeDeclarationKey, ObjectDeclarationKey, and WalkLoadedSubjects handle nil inputs without panicking.
	if got := syntaxutil.NodeDeclarationKey(nil, nil); got != ":0" {
		t.Fatalf("NodeDeclarationKey(nil, nil) = %q, want :0", got)
	}
	if got := syntaxutil.ObjectDeclarationKey(nil, nil); !strings.HasPrefix(got, "universe:") {
		t.Fatalf("ObjectDeclarationKey(nil, nil) = %q, want universe:<nil>", got)
	}
	pkgNoTypesInfo := &packages.Package{
		PkgPath: "example.com/carrier",
		Syntax:  pkg.Syntax,
	}
	if err := WalkLoadedSubjects(true, true, []*packages.Package{nil, pkgNoTypesInfo}, nil, []string{"example.com/carrier"}, func(ScannedSymbol) {}); err == nil {
		t.Fatal("WalkLoadedSubjects with nil TypesInfo should still report directive conflict without panicking")
	}
}

//gofresh:pure
func FuzzComposeAndDeferralResolutionInvariants(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	f.Add([]byte{255, 128, 64, 32, 16, 8, 4, 2, 1})
	f.Add([]byte{10, 20, 30, 40, 50, 60})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 4 {
			return
		}
		pkgs := []string{"example.com/p0", "example.com/p1", "example.com/p2"}
		fns := []syntaxutil.FuncKey{
			{Pkg: pkgs[0], Name: "F0"},
			{Pkg: pkgs[1], Name: "F1"},
			{Pkg: pkgs[2], Name: "F2"},
		}
		vars := []string{
			"example.com/p0.v0",
			"example.com/p1.v1",
			"example.com/p2.v2",
		}

		meta := []GraphPackage{
			{ImportPath: pkgs[0], PkgPath: pkgs[0], Imports: []string{pkgs[1], pkgs[2]}, Class: MutableLocalPackage},
			{ImportPath: pkgs[1], PkgPath: pkgs[1], Imports: []string{pkgs[2]}, Class: MutableLocalPackage},
			{ImportPath: pkgs[2], PkgPath: pkgs[2], Class: PinnedPackage, Pin: "example.com/p2@v1.0.0"},
		}

		factsByPkg := map[string][]Fact{
			pkgs[0]: {{Declares: []string{vars[0]}}},
			pkgs[1]: {{Declares: []string{vars[1]}}},
			pkgs[2]: {{Declares: []string{vars[2]}}},
		}

		for i, b := range data {
			pIdx := int(b) % len(pkgs)
			f := &factsByPkg[pkgs[pIdx]][0]
			fnA := fns[int(b>>2)%len(fns)]
			fnB := fns[(int(b>>4)+i)%len(fns)]
			vA := vars[int(b>>1)%len(vars)]
			vB := vars[(int(b>>3)+i)%len(vars)]
			switch b % 13 {
			case 0:
				f.ReturnEnvFree = append(f.ReturnEnvFree, fnA)
			case 1:
				f.ReturnEnvDeps = append(f.ReturnEnvDeps, syntaxutil.FuncDepEdge{Func: fnA, Callee: fnB})
			case 2:
				f.ParamLeakFree = append(f.ParamLeakFree, syntaxutil.ParamKey{Func: fnA, Index: int(b & 1)})
			case 3:
				f.ParamLeakFreeDeps = append(f.ParamLeakFreeDeps, syntaxutil.ParamDepEdge{
					Own: syntaxutil.ParamKey{Func: fnA, Index: int(b & 1)},
					Dep: syntaxutil.ParamKey{Func: fnB, Index: int((b >> 1) & 1)},
				})
			case 4:
				f.CarrierLinks = append(f.CarrierLinks, syntaxutil.CarrierLink{From: vA, To: vB})
			case 5:
				f.Mutates = append(f.Mutates, vA)
			case 6:
				f.FieldParamDefer = append(f.FieldParamDefer, syntaxutil.FieldParamDefer{
					Pos:   syntaxutil.FieldPosKey{Owner: vA, Field: "fn", Index: 0},
					Param: syntaxutil.ParamKey{Func: fnA, Index: int(b & 1)},
				})
			case 7:
				f.EnvCallUses = append(f.EnvCallUses, syntaxutil.EnvCallUse{Key: vA, Callee: fnA})
			case 8:
				f.ExportedSeams = append(f.ExportedSeams, syntaxutil.ExportedSeam{Func: fnA, Key: vA})
			case 9:
				f.NonSeqFuncUses = append(f.NonSeqFuncUses, fnA)
			case 10:
				f.SeqFuncEdges = append(f.SeqFuncEdges, syntaxutil.FuncDepEdge{Func: fnA, Callee: fnB})
			case 11:
				f.ParallelFuncs = append(f.ParallelFuncs, fnB)
			case 12:
				f.ParallelEdges = append(f.ParallelEdges, syntaxutil.FuncDepEdge{Func: fnA, Callee: fnB})
			}
		}

		res1 := NewDeferralResolution(factsByPkg, nil)
		state1 := Compose(meta, factsByPkg, pkgs[0], nil, true, false)
		ok1, param1 := res1.FieldPopulationProves(vars[0], "fn", 0)

		// Reverse package insertion order and verify identical results.
		revMeta := []GraphPackage{meta[2], meta[1], meta[0]}
		revFacts := map[string][]Fact{
			pkgs[2]: factsByPkg[pkgs[2]],
			pkgs[1]: factsByPkg[pkgs[1]],
			pkgs[0]: factsByPkg[pkgs[0]],
		}
		res2 := NewDeferralResolution(revFacts, nil)
		state2 := Compose(revMeta, revFacts, pkgs[0], nil, true, false)
		ok2, param2 := res2.FieldPopulationProves(vars[0], "fn", 0)

		if !reflect.DeepEqual(res1.ParamLeakFree, res2.ParamLeakFree) ||
			!reflect.DeepEqual(res1.EnvFreeResolved, res2.EnvFreeResolved) {
			t.Fatalf("NewDeferralResolution order-dependent: %+v vs %+v", res1, res2)
		}
		if ok1 != ok2 || param1 != param2 {
			t.Fatalf("FieldPopulationProves order-dependent: (%v, %+v) vs (%v, %+v)", ok1, param1, ok2, param2)
		}
		if state1.Downgraded != state2.Downgraded ||
			state1.CulpritPkg != state2.CulpritPkg ||
			state1.CulpritSym != state2.CulpritSym ||
			!reflect.DeepEqual(state1.CulpritSites, state2.CulpritSites) {
			t.Fatalf("Compose order-dependent: %+v vs %+v", state1, state2)
		}
		_ = fmt.Sprintf("%s", state1.Downgraded)
	})
}

func TestBracketedSeamAtomicPureLoadAuditedAndConcurrentCallers(t *testing.T) {
	// 1. Pure-Load unexported uninitialized sync/atomic.Pointer[T] is exempted
	// under an audited toolchain and rejected when unaudited.
	pureLoadPkg := mustTypecheckPackage(t, "example.com/pureload", map[string]string{
		"seam.go": `package pureload

import "sync/atomic"

type hookSet struct {
	fn func() int
}

var hooks atomic.Pointer[hookSet]

func CallHook() int {
	if h := hooks.Load(); h != nil && h.fn != nil {
		return h.fn()
	}
	return 0
}
`,
	})
	if got := len(bracketedSeamNodes(true, pureLoadPkg)); got != 1 {
		t.Fatalf("audited pure-Load bracketedSeamNodes len = %d, want 1", got)
	}
	if got := len(bracketedSeamNodes(false, pureLoadPkg)); got != 0 {
		t.Fatalf("unaudited pure-Load bracketedSeamNodes len = %d, want 0", got)
	}

	// 2. Mutex-bracketed Store on sync/atomic.Pointer[T] requires an audited
	// toolchain, admits synchronous callback goroutines that do not invoke the
	// seam helper, and rejects concurrent or escaped callers.
	const baseHookSrc = `package hookseam

import (
	"sync"
	"sync/atomic"
)

type hookSet struct {
	observe func()
}

var (
	hooksMu sync.Mutex
	hooks   atomic.Pointer[hookSet]
	saved   int
)

func ReadHook() {
	if h := hooks.Load(); h != nil && h.observe != nil {
		h.observe()
	}
}

func withHooks(h hookSet, fn func()) {
	hooksMu.Lock()
	defer hooksMu.Unlock()
	defer hooks.Store(nil)
	hooks.Store(&h)
	fn()
}

func withSaved(v int, fn func()) {
	prev := saved
	defer func() { saved = prev }()
	saved = v
	fn()
}
`
	cleanPkg := mustTypecheckPackage(t, "example.com/hookseam", map[string]string{
		"seam.go": baseHookSrc,
		"caller_test.go": `package hookseam

import "testing"

func TestCleanCallbackGoroutine(t *testing.T) {
	t.Run("sub", func(t *testing.T) {
		run := func() {
			done := make(chan struct{})
			withHooks(hookSet{}, func() {
				go func() {
					ReadHook()
					close(done)
				}()
				<-done
			})
			withSaved(7, func() {})
		}
		run()
		defer func() { withSaved(9, func() {}) }()
	})
	t.Cleanup(func() { withHooks(hookSet{}, func() {}) })
}
`,
	})
	if got := len(bracketedSeamNodes(false, cleanPkg)); got != 2 {
		// Unaudited rejects the 3 atomic.Pointer selectors while retaining the
		// 2 scalar save-and-restore assignments on `saved`.
		t.Fatalf("unaudited cleanPkg bracketedSeamNodes len = %d, want 2", got)
	}
	if got := len(bracketedSeamNodes(true, cleanPkg)); got != 5 {
		t.Fatalf("audited cleanPkg bracketedSeamNodes len = %d, want 5 (Load + 2 Stores + 2 saved writes)", got)
	}

	cases := []struct {
		name string
		src  string
	}{
		{
			name: "direct_go_stmt",
			src: `package hookseam
import "testing"
func TestBad(t *testing.T) {
	go withHooks(hookSet{}, func() {})
	go withSaved(1, func() {})
}
`,
		},
		{
			name: "local_lit_go_stmt",
			src: `package hookseam
import "testing"
func TestBad(t *testing.T) {
	f := func() {
		withHooks(hookSet{}, func() {})
		withSaved(1, func() {})
	}
	go f()
}
`,
		},
		{
			name: "forwarded_async_param",
			src: `package hookseam
import "testing"
func innerSpawn(fn func()) { go fn() }
func outerSpawn(fn func()) { innerSpawn(fn) }
func TestBad(t *testing.T) {
	outerSpawn(func() {
		withHooks(hookSet{}, func() {})
		withSaved(1, func() {})
	})
}
`,
		},
		{
			name: "wrapped_go_closure_param",
			src: `package hookseam
import "testing"
func spawnClosure(fn func()) { go func() { fn() }() }
func TestBad(t *testing.T) {
	spawnClosure(func() {
		withHooks(hookSet{}, func() {})
		withSaved(1, func() {})
	})
}
`,
		},
		{
			name: "external_spawner_funclit",
			src: `package hookseam
import (
	"sync"
	"testing"
)
func TestBad(t *testing.T) {
	var wg sync.WaitGroup
	wg.Go(func() {
		withHooks(hookSet{}, func() {})
		withSaved(1, func() {})
	})
}
`,
		},
		{
			name: "variadic_spawn_param",
			src: `package hookseam
import "testing"
func spawnAll(fns ...func()) {
	for _, fn := range fns {
		go fn()
	}
}
func TestBad(t *testing.T) {
	spawnAll(func() {}, func() {
		withHooks(hookSet{}, func() {})
		withSaved(1, func() {})
	})
}
`,
		},
		{
			name: "helper_parallel_subtest",
			src: `package hookseam
import "testing"
func markParallel(t *testing.T) { t.Parallel() }
func TestBad(t *testing.T) {
	t.Run("sub", func(t *testing.T) {
		markParallel(t)
		withHooks(hookSet{}, func() {})
		withSaved(1, func() {})
	})
}
`,
		},
		{
			name: "transitive_parallel_caller",
			src: `package hookseam
import "testing"
func mid() {
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
func TestBad(t *testing.T) {
	t.Parallel()
	mid()
}
`,
		},
		{
			name: "escaped_func_value",
			src: `package hookseam
var _ = withHooks
var _ = withSaved
`,
		},
		{
			name: "var_init_direct_call",
			src: `package hookseam
var _ = func() int {
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
	return 0
}()
`,
		},
		{
			name: "init_func_caller",
			src: `package hookseam
func init() {
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "method_caller_via_interface",
			src: `package hookseam
import "testing"
type runner struct{}
func (runner) run() {
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
func TestBad(t *testing.T) {
	var r interface{ run() } = runner{}
	go r.run()
}
`,
		},
		{
			name: "immediate_closure_parallel",
			src: `package hookseam
import "testing"
func TestBad(t *testing.T) {
	func() { t.Parallel() }()
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "cleanup_closure_parallel",
			src: `package hookseam
import "testing"
func TestBad(t *testing.T) {
	t.Cleanup(func() { t.Parallel() })
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "outer_t_parallel_in_subtest",
			src: `package hookseam
import "testing"
func TestBad(t *testing.T) {
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
	t.Run("sub", func(_ *testing.T) {
		t.Parallel()
	})
}
`,
		},
		{
			name: "method_expr_parallel",
			src: `package hookseam
import "testing"
func TestBad(t *testing.T) {
	(*testing.T).Parallel(t)
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "method_value_parallel",
			src: `package hookseam
import "testing"
func TestBad(t *testing.T) {
	p := t.Parallel
	p()
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "receiver_method_parallel_helper",
			src: `package hookseam
import "testing"
type parHelper struct{ t *testing.T }
func (h parHelper) enter() { h.t.Parallel() }
func TestViaMethodParallel(t *testing.T) {
	parHelper{t: t}.enter()
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "func_value_parallel_helper",
			src: `package hookseam
import "testing"
func enterPar(t *testing.T) { t.Parallel() }
func TestViaFuncValParallel(t *testing.T) {
	fn := enterPar
	fn(t)
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "named_result_bare_return_closure",
			src: `package hookseam
func makeCaller() (fn func()) {
	fn = func() {
		withHooks(hookSet{}, func() {})
		withSaved(1, func() {})
	}
	return
}
func ExerciseBareReturn() {
	f := makeCaller()
	go f()
}
`,
		},
		{
			name: "nested_lit_named_result_bare_return_closure",
			src: `package hookseam
func ExerciseNestedBareReturn() {
	mk := func() (fn func()) {
		fn = func() {
			withHooks(hookSet{}, func() {})
			withSaved(1, func() {})
		}
		return
	}
	f := mk()
	go f()
}
`,
		},
		{
			name: "run_parallel_locally_bracketed_closure",
			src: `package hookseam
import "testing"
func BenchmarkRunParallelSeam(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			orig := saved
			defer func() { saved = orig }()
			saved = 42
			withHooks(hookSet{}, func() {})
			withSaved(1, func() {})
		}
	})
}
`,
		},
		{
			name: "channel_sent_locally_bracketed_closure",
			src: `package hookseam
func SendClosure() {
	ch := make(chan func(), 1)
	ch <- func() {
		orig := saved
		saved = 99
		saved = orig
		withHooks(hookSet{}, func() {})
		withSaved(1, func() {})
	}
}
`,
		},
		{
			name: "pkg_var_parallel_helper",
			src: `package hookseam
import "testing"
func rawEnter(t *testing.T) { t.Parallel() }
var enterVar = rawEnter
func TestViaPkgVarParallel(t *testing.T) {
	enterVar(t)
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "pkg_var_init_local_parallel_helper",
			src: `package hookseam
import "testing"
var enterInit func(*testing.T)
func init() {
	fn := func(t *testing.T) { t.Parallel() }
	enterInit = fn
}
func TestViaInitVarParallel(t *testing.T) {
	enterInit(t)
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "iface_dispatch_parallel_method",
			src: `package hookseam
import "testing"
type parRunner interface{ enter() }
type parImpl struct{ t *testing.T }
func (p parImpl) enter() { p.t.Parallel() }
func TestViaIfaceParallel(t *testing.T) {
	var r parRunner = parImpl{t: t}
	r.enter()
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "subtest_closure_via_pkg_var_parallel",
			src: `package hookseam
import "testing"
var subEnter = func(t *testing.T) { t.Parallel() }
func TestSubViaPkgVar(t *testing.T) {
	t.Run("sub", func(t *testing.T) {
		subEnter(t)
		withHooks(hookSet{}, func() {})
		withSaved(1, func() {})
	})
}
`,
		},
		{
			name: "subtest_closure_via_iface_parallel",
			src: `package hookseam
import "testing"
type parRunner interface{ enter() }
type parImpl struct{ t *testing.T }
func (p parImpl) enter() { p.t.Parallel() }
func TestSubViaIface(t *testing.T) {
	t.Run("sub", func(t *testing.T) {
		var r parRunner = parImpl{t: t}
		r.enter()
		withHooks(hookSet{}, func() {})
		withSaved(1, func() {})
	})
}
`,
		},
		{
			name: "composite_struct_field_holding_parallel_method",
			src: `package hookseam
import "testing"
type parRunner interface{ enter() }
type innerPar struct{ t *testing.T }
func (p innerPar) enter() { p.t.Parallel() }
type outerBox struct{ r innerPar }
func makeBox(t *testing.T) outerBox { return outerBox{r: innerPar{t: t}} }
func TestCompositeStructParallel(t *testing.T) {
	var r parRunner = makeBox(t).r
	r.enter()
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "defined_array_of_parallel_type",
			src: `package hookseam
import "testing"
type parRunner interface{ enter() }
type innerPar struct{ t *testing.T }
func (p innerPar) enter() { p.t.Parallel() }
type ParArr [1]innerPar
func makeArr(t *testing.T) ParArr { return ParArr{{t: t}} }
func TestArrayParallel(t *testing.T) {
	var r parRunner = makeArr(t)[0]
	r.enter()
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "instantiated_generic_alias_holding_parallel_type",
			src: `package hookseam
import "testing"
type parRunner interface{ enter() }
type innerPar struct{ t *testing.T }
func (p innerPar) enter() { p.t.Parallel() }
type GenericBox[V any] struct{ v V }
type BoxAlias = GenericBox[innerPar]
func makeAlias(t *testing.T) BoxAlias { return BoxAlias{v: innerPar{t: t}} }
func TestAliasParallel(t *testing.T) {
	var r parRunner = makeAlias(t).v
	r.enter()
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "param_composite_holding_parallel_type",
			src: `package hookseam
import "testing"
type parRunner interface{ enter() }
type innerPar struct{ t *testing.T }
func (p innerPar) enter() { p.t.Parallel() }
type outerBox struct{ r innerPar }
func runBox(box outerBox) {
	var r parRunner = box.r
	r.enter()
}
func TestParamComposite(t *testing.T) {
	runBox(outerBox{r: innerPar{t: t}})
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "mutually_recursive_composite_types_holding_parallel_method",
			src: `package hookseam
import "testing"
type parRunner interface{ enter() }
type nodeA struct{ b *nodeB }
type nodeB struct{ a *nodeA; p innerPar }
type innerPar struct{ t *testing.T }
func (p innerPar) enter() { p.t.Parallel() }
func makeNodeA(t *testing.T) nodeA {
	return nodeA{b: &nodeB{p: innerPar{t: t}}}
}
func TestMutualRecComposite(t *testing.T) {
	var r parRunner = makeNodeA(t).b.p
	r.enter()
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "exported_setter_populating_pkg_var_with_parallel_helper",
			src: `package hookseam
import "testing"
var enterHook func(*testing.T)
func InstallParallel() {
	enterHook = func(t *testing.T) { t.Parallel() }
}
func TestViaExportedSetter(t *testing.T) {
	InstallParallel()
	enterHook(t)
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "method_setter_populating_pkg_var_with_parallel_helper",
			src: `package hookseam
import "testing"
var enterHook func(*testing.T)
type installer struct{}
func (installer) Install() {
	enterHook = func(t *testing.T) { t.Parallel() }
}
func TestViaMethodSetter(t *testing.T) {
	installer{}.Install()
	enterHook(t)
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "parameterized_two_hop_setter_with_local_intermediate",
			src: `package hookseam
import "testing"
var enterHook func(*testing.T)
func rawPar(t *testing.T) { t.Parallel() }
func setInner(fn func(*testing.T)) {
	tmp := fn
	enterHook = tmp
}
func setOuter(fn func(*testing.T)) {
	setInner(fn)
}
func InstallViaParams() {
	setOuter(rawPar)
}
func TestViaParamSetter(t *testing.T) {
	if enterHook != nil {
		enterHook(t)
	}
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "interface_dispatched_setter_populating_pkg_var",
			src: `package hookseam
import "testing"
var enterHook func(*testing.T)
func rawPar(t *testing.T) { t.Parallel() }
type setterIface interface{ SetEnter(func(*testing.T)) }
type setterImpl struct{}
func (setterImpl) SetEnter(fn func(*testing.T)) { enterHook = fn }
func InstallViaIface() {
	var s setterIface = setterImpl{}
	s.SetEnter(rawPar)
}
func TestViaIfaceSetter(t *testing.T) {
	if enterHook != nil {
		enterHook(t)
	}
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "dynamic_func_value_setter_populating_pkg_var",
			src: `package hookseam
import "testing"
var enterHook func(*testing.T)
func rawPar(t *testing.T) { t.Parallel() }
func setEnter(fn func(*testing.T)) { enterHook = fn }
func InstallViaFuncVal() {
	f := setEnter
	f(rawPar)
}
func TestViaFuncValSetter(t *testing.T) {
	if enterHook != nil {
		enterHook(t)
	}
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "recv_method_factory_populating_pkg_var",
			src: `package hookseam
import "testing"
type box struct{ fn func(*testing.T) }
func (b box) GetFn() func(*testing.T) { return b.fn }
func rawPar(t *testing.T) { t.Parallel() }
var enterHook func(*testing.T)
func InstallViaRecvFactory() {
	b := box{fn: rawPar}
	enterHook = b.GetFn()
}
func TestViaRecvFactory(t *testing.T) {
	if enterHook != nil {
		enterHook(t)
	}
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
		{
			name: "unexported_underlying_composite_field_holding_parallel_method",
			src: `package hookseam
import "testing"
type innerPar struct{}
func (innerPar) Enter(t *testing.T) { t.Parallel() }
type outerOpaque struct{ f [1]innerPar }
var opaqueHolder any
func InstallOpaque() {
	var zero outerOpaque
	opaqueHolder = zero
}
func TestOpaqueUnderlying(t *testing.T) {
	if r, ok := opaqueHolder.(interface{ Enter(*testing.T) }); ok {
		r.Enter(t)
	}
	withHooks(hookSet{}, func() {})
	withSaved(1, func() {})
}
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			badPkg := mustTypecheckPackage(t, "example.com/hookseam", map[string]string{
				"seam.go":        baseHookSrc,
				"caller_test.go": tc.src,
			})
			if got := len(bracketedSeamNodes(true, badPkg)); got != 0 {
				t.Fatalf("%s: bracketedSeamNodes exempted %d nodes, want 0", tc.name, got)
			}
			fact := FactOf(true, badPkg, false)
			if len(fact.Mutates) == 0 && len(fact.AttributedUses) == 0 {
				t.Fatalf("%s: FactOf produced neither Mutates nor AttributedUses: %+v", tc.name, fact)
			}
		})
	}

	// Sequential test wrapper defining a literal Parallel() method (never called) and
	// scalar options struct with a non-callable Parallel field must NOT falsely taint seams.
	seqWrapperPkg := mustTypecheckPackage(t, "example.com/hookseam", map[string]string{
		"seam.go": baseHookSrc,
		"wrapper_test.go": `package hookseam
import "testing"
type testWrapper struct{ t *testing.T }
func (w *testWrapper) Parallel() { w.t.Parallel() }
func (w *testWrapper) Helper()   { w.t.Helper() }
type runOpts struct{ Parallel int }
func TestSequentialWrapper(t *testing.T) {
	w := &testWrapper{t: t}
	w.Helper()
	cfg := runOpts{Parallel: 2}
	if cfg.Parallel > 0 {
		withHooks(hookSet{}, func() {})
		withSaved(cfg.Parallel, func() {})
	}
}
`,
	})
	if got := len(bracketedSeamNodes(true, seqWrapperPkg)); got != 5 {
		t.Fatalf("sequential wrapper + scalar Parallel field bracketedSeamNodes len = %d, want 5", got)
	}

	// Shared sequential callback helper (e.g. runSubtest(t, body)) must NOT falsely
	// taint sequential tests using seams when a separate test passes a parallel closure.
	sharedCallbackPkg := mustTypecheckPackage(t, "example.com/hookseam", map[string]string{
		"seam.go": baseHookSrc,
		"subtest_test.go": `package hookseam
import "testing"
func runSubtest(t *testing.T, body func(*testing.T)) {
	t.Run("case", body)
}
func TestParallelSub(t *testing.T) {
	runSubtest(t, func(sub *testing.T) {
		sub.Parallel()
	})
}
func TestSequentialSubWithSeam(t *testing.T) {
	runSubtest(t, func(_ *testing.T) {
		withHooks(hookSet{}, func() {})
		withSaved(3, func() {})
	})
}
`,
	})
	if got := len(bracketedSeamNodes(true, sharedCallbackPkg)); got != 5 {
		t.Fatalf("shared sequential callback helper bracketedSeamNodes len = %d, want 5", got)
	}

	// Non-returned escaping closures (e.g., testing.B.RunParallel or time.AfterFunc)
	// that locally save-and-restore a scalar seam must not exempt their writes.
	nonRetEscClosurePkg := mustTypecheckPackage(t, "example.com/nonret", map[string]string{
		"seam.go": `package nonret
import (
	"testing"
	"time"
)
var probe func() int
func BenchmarkRace(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			orig := probe
			defer func() { probe = orig }()
			probe = func() int { return 1 }
		}
	})
}
func ScheduleRace() {
	time.AfterFunc(time.Millisecond, func() {
		orig := probe
		probe = func() int { return 2 }
		probe = orig
	})
}
`,
	})
	if got := len(bracketedSeamNodes(true, nonRetEscClosurePkg)); got != 0 {
		t.Fatalf("non-returned escaping closure bracketedSeamNodes len = %d, want 0", got)
	}
	if fact := FactOf(true, nonRetEscClosurePkg, false); len(fact.AttributedUses) == 0 {
		t.Fatalf("non-returned escaping closure FactOf.AttributedUses = %v, want non-empty", fact.AttributedUses)
	}

	// Receiver methods themselves must never be admitted as mutating seams,
	// because structural interface satisfaction can dispatch them from goroutines.
	methodSeamPkg := mustTypecheckPackage(t, "example.com/methodseam", map[string]string{
		"seam.go": `package methodseam
import (
	"sync"
	"sync/atomic"
)
type hookSet struct{ f func() }
var (
	hooksMu sync.Mutex
	hooks   atomic.Pointer[hookSet]
	saved   func()
)
type carrier struct{}
func (carrier) withAtomic(h hookSet, fn func()) {
	hooksMu.Lock()
	defer hooksMu.Unlock()
	defer hooks.Store(nil)
	hooks.Store(&h)
	fn()
}
func (carrier) withScalar(fn func()) {
	orig := saved
	defer func() { saved = orig }()
	saved = fn
}
`,
	})
	if got := len(bracketedSeamNodes(true, methodSeamPkg)); got != 0 {
		t.Fatalf("receiver-method seam exempted %d nodes, want 0", got)
	}
}

func TestComposeExportedSeamCrossPackageSequentialVsConcurrent(t *testing.T) {
	t.Parallel()
	seamSrc := `package seam

import (
	"sync"
	"sync/atomic"
)

type HookSet struct{ Observe func() }

type seamGroup struct {
	probe func() int
}

var (
	hooksMu sync.Mutex
	hooks   atomic.Pointer[HookSet]
	seams   seamGroup
)

func WithHooks(h HookSet, fn func()) {
	hooksMu.Lock()
	defer hooksMu.Unlock()
	defer hooks.Store(nil)
	hooks.Store(&h)
	fn()
}

func WithProbe(p func() int, fn func()) {
	orig := seams.probe
	defer func() { seams.probe = orig }()
	seams.probe = p
	fn()
}

func ReadProbe() int {
	if h := hooks.Load(); h != nil && h.Observe != nil {
		h.Observe()
	}
	if seams.probe != nil {
		return seams.probe()
	}
	return 0
}
`
	fset := token.NewFileSet()
	stdImp := importer.Default()
	parseCheckNamed := func(pkgPath, fileName, src string, deps map[string]*types.Package) *packages.Package {
		f, err := parser.ParseFile(fset, fileName, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", pkgPath, err)
		}
		info := &types.Info{
			Types:      make(map[ast.Expr]types.TypeAndValue),
			Instances:  make(map[*ast.Ident]types.Instance),
			Defs:       make(map[*ast.Ident]types.Object),
			Uses:       make(map[*ast.Ident]types.Object),
			Implicits:  make(map[ast.Node]types.Object),
			Selections: make(map[*ast.SelectorExpr]*types.Selection),
			Scopes:     make(map[ast.Node]*types.Scope),
		}
		conf := types.Config{
			Importer: importerFunc(func(path string) (*types.Package, error) {
				if tp, ok := deps[path]; ok {
					return tp, nil
				}
				return stdImp.Import(path)
			}),
		}
		tp, err := conf.Check(pkgPath, fset, []*ast.File{f}, info)
		if err != nil {
			t.Fatalf("Check(%s): %v", pkgPath, err)
		}
		return &packages.Package{
			ID:        pkgPath,
			PkgPath:   pkgPath,
			Name:      tp.Name(),
			Fset:      fset,
			Syntax:    []*ast.File{f},
			Types:     tp,
			TypesInfo: info,
			Imports:   syntheticPackageImports(tp, deps),
			Module:    &packages.Module{Path: "example.com"},
		}
	}
	parseCheck := func(pkgPath string, src string, deps map[string]*types.Package) *packages.Package {
		return parseCheckNamed(pkgPath, pkgPath+".go", src, deps)
	}

	seamPkg := parseCheck("example.com/seam", seamSrc, nil)
	seamFact := FactOf(true, seamPkg, false)
	if len(seamFact.ExportedSeams) != 2 {
		t.Fatalf("seamFact.ExportedSeams = %+v, want 2 entries (WithHooks, WithProbe)", seamFact.ExportedSeams)
	}

	deps := map[string]*types.Package{"example.com/seam": seamPkg.Types}

	// 1. Sequential cross-package caller keeps both seams clean.
	seqCaller := parseCheck("example.com/caller", `package caller
import (
	"testing"
	"example.com/seam"
)
func TestSequential(t *testing.T) {
	seam.WithHooks(seam.HookSet{}, func() {})
	seam.WithProbe(func() int { return 7 }, func() {})
}
`, deps)
	seqMeta := []GraphPackage{
		{ImportPath: "example.com/caller", PkgPath: "example.com/caller", Imports: []string{"example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}
	seqState := Compose(seqMeta, map[string][]Fact{
		"example.com/caller": {FactOf(true, seqCaller, false)},
		"example.com/seam":   {seamFact},
	}, "example.com/caller", nil, false, true)
	if seqState.Downgraded != "" {
		t.Fatalf("sequential cross-package caller downgraded: %+v", seqState)
	}

	// 2. Transitive 3-package chain from a parallel test through an unexported intermediate helper downgrades both seams.
	midPkg := parseCheck("example.com/mid", `package mid
import "example.com/seam"
func inner() {
	seam.WithHooks(seam.HookSet{}, func() {})
	seam.WithProbe(func() int { return 3 }, func() {})
}
func Exercise() { inner() }
`, deps)
	depsWithMid := map[string]*types.Package{
		"example.com/seam": seamPkg.Types,
		"example.com/mid":  midPkg.Types,
	}
	parCaller := parseCheck("example.com/top", `package top
import (
	"testing"
	"example.com/mid"
)
func TestParallel(t *testing.T) {
	t.Parallel()
	mid.Exercise()
}
`, depsWithMid)
	chainMeta := []GraphPackage{
		{ImportPath: "example.com/top", PkgPath: "example.com/top", Imports: []string{"example.com/mid"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/mid", PkgPath: "example.com/mid", Imports: []string{"example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}
	parState := Compose(chainMeta, map[string][]Fact{
		"example.com/top":  {FactOf(true, parCaller, false)},
		"example.com/mid":  {FactOf(true, midPkg, false)},
		"example.com/seam": {seamFact},
	}, "example.com/top", nil, false, true)
	if len(parState.RootCulprits) != 2 {
		t.Fatalf("parallel transitive cross-package caller RootCulprits = %+v, want 2 culprits (hooks and seams)", parState.RootCulprits)
	}
	if site := parState.CulpritSites["example.com/seam.hooks"]; site.Unattributed || !site.Fns["example.com/seam\x00WithHooks"] {
		t.Fatalf("parallel CulpritSites[hooks] = %+v, want attributed to WithHooks", site)
	}

	// 3. Package-level function-value escape in caller marks Unattributed (initReachFn).
	initEscCaller := parseCheck("example.com/esc", `package esc
import "example.com/seam"
var _ = seam.WithHooks
`, deps)
	escMeta := []GraphPackage{
		{ImportPath: "example.com/esc", PkgPath: "example.com/esc", Imports: []string{"example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}
	escState := Compose(escMeta, map[string][]Fact{
		"example.com/esc":  {FactOf(true, initEscCaller, false)},
		"example.com/seam": {seamFact},
	}, "example.com/esc", nil, true, false)
	if site := escState.CulpritSites["example.com/seam.hooks"]; !site.Unattributed {
		t.Fatalf("init-escaped ExportedSeam CulpritSites[hooks] = %+v, want Unattributed=true", site)
	}

	// 4. Cross-package .Parallel() helper (including through an intermediate package whose helper
	// also escapes as a value, package-scope var/init carriers, and interface/method/generic dispatch)
	// taints callers upward and blocks exported seams, while literal Parallel() wrapper methods and
	// scalar Parallel fields do not cause false positives.
	testutilPkg := parseCheck("example.com/testutil", `package testutil
import "testing"
func EnterParallel(t *testing.T) { t.Parallel() }
var EnterVar = EnterParallel
var EnterOps = struct{ Enter func(*testing.T) }{Enter: EnterParallel}
var EnterInit func(*testing.T)
func init() {
	EnterInit = func(t *testing.T) { t.Parallel() }
}
type Runner interface{ Enter(*testing.T) }
type impl struct{}
func (impl) Enter(t *testing.T) { t.Parallel() }
func NewRunner() Runner { return impl{} }
type NamedPar struct{}
func (NamedPar) Enter(t *testing.T) { t.Parallel() }
func NewNamedPar() (out NamedPar) { return }
var DefaultNamedPar NamedPar
type Harness struct{ T *testing.T }
func (h Harness) Enter() { h.T.Parallel() }
type GenericHarness[V any] struct{ T *testing.T; Val V }
func (g GenericHarness[V]) Enter() { g.T.Parallel() }
type Wrapper struct{ T *testing.T }
func (w Wrapper) Parallel() { w.T.Parallel() }
func (w Wrapper) Helper()   { w.T.Helper() }
type Config struct{ Parallel int }
`, nil)
	parMidPkg := parseCheck("example.com/parmid", `package parmid
import (
	"testing"
	"example.com/testutil"
)
var _ = EnterViaMid
func EnterViaMid(t *testing.T) { testutil.EnterParallel(t) }
func EnterViaPkgVar(t *testing.T) { testutil.EnterVar(t) }
`, map[string]*types.Package{"example.com/testutil": testutilPkg.Types})
	for _, callerCase := range []struct {
		name string
		src  string
	}{
		{
			name: "via_blocked_intermediate_helper",
			src: `package parcaller
import (
	"testing"
	"example.com/parmid"
	"example.com/seam"
)
func TestRace(t *testing.T) {
	parmid.EnterViaMid(t)
	seam.WithHooks(seam.HookSet{}, func() {})
	seam.WithProbe(func() int { return 5 }, func() {})
}
`,
		},
		{
			name: "via_cross_pkg_struct_method",
			src: `package parcaller
import (
	"testing"
	"example.com/seam"
	"example.com/testutil"
)
func TestRaceMethod(t *testing.T) {
	testutil.Harness{T: t}.Enter()
	seam.WithHooks(seam.HookSet{}, func() {})
	seam.WithProbe(func() int { return 5 }, func() {})
}
`,
		},
		{
			name: "via_cross_pkg_func_var_and_intermediate_pkg",
			src: `package parcaller
import (
	"testing"
	"example.com/parmid"
	"example.com/seam"
)
func TestRaceVar(t *testing.T) {
	parmid.EnterViaPkgVar(t)
	seam.WithHooks(seam.HookSet{}, func() {})
	seam.WithProbe(func() int { return 5 }, func() {})
}
`,
		},
		{
			name: "via_cross_pkg_struct_var_and_init_var",
			src: `package parcaller
import (
	"testing"
	"example.com/seam"
	"example.com/testutil"
)
func TestRaceStructAndInitVar(t *testing.T) {
	testutil.EnterOps.Enter(t)
	testutil.EnterInit(t)
	seam.WithHooks(seam.HookSet{}, func() {})
	seam.WithProbe(func() int { return 5 }, func() {})
}
`,
		},
		{
			name: "via_cross_pkg_iface_constructor",
			src: `package parcaller
import (
	"testing"
	"example.com/seam"
	"example.com/testutil"
)
func TestRaceIfaceCtor(t *testing.T) {
	testutil.NewRunner().Enter(t)
	seam.WithHooks(seam.HookSet{}, func() {})
	seam.WithProbe(func() int { return 5 }, func() {})
}
`,
		},
		{
			name: "via_cross_pkg_named_result_ctor_and_zero_var",
			src: `package parcaller
import (
	"testing"
	"example.com/seam"
	"example.com/testutil"
)
type localEnter interface{ Enter(*testing.T) }
func TestRaceNamedResultCtor(t *testing.T) {
	var r1 localEnter = testutil.NewNamedPar()
	var r2 localEnter = testutil.DefaultNamedPar
	r1.Enter(t)
	r2.Enter(t)
	seam.WithHooks(seam.HookSet{}, func() {})
	seam.WithProbe(func() int { return 5 }, func() {})
}
`,
		},
		{
			name: "via_cross_pkg_structural_iface_and_generic_harness",
			src: `package parcaller
import (
	"testing"
	"example.com/seam"
	"example.com/testutil"
)
type localRunner interface{ Enter() }
func TestRaceStructuralIface(t *testing.T) {
	var r1 localRunner = testutil.Harness{T: t}
	var r2 localRunner = testutil.GenericHarness[int]{T: t, Val: 1}
	r1.Enter()
	r2.Enter()
	seam.WithHooks(seam.HookSet{}, func() {})
	seam.WithProbe(func() int { return 5 }, func() {})
}
`,
		},
		{
			name: "via_bare_return_named_result_closure",
			src: `package parcaller
import "example.com/seam"
func MakeCaller() (fn func()) {
	fn = func() {
		seam.WithHooks(seam.HookSet{}, func() {})
		seam.WithProbe(func() int { return 5 }, func() {})
	}
	return
}
func RunConcurrent() {
	f := MakeCaller()
	go f()
}
`,
		},
	} {
		t.Run(callerCase.name, func(t *testing.T) {
			cPkg := parseCheck("example.com/parcaller", callerCase.src, map[string]*types.Package{
				"example.com/seam":     seamPkg.Types,
				"example.com/parmid":   parMidPkg.Types,
				"example.com/testutil": testutilPkg.Types,
			})
			meta := []GraphPackage{
				{ImportPath: "example.com/parcaller", PkgPath: "example.com/parcaller", Imports: []string{"example.com/parmid", "example.com/testutil", "example.com/seam"}, Class: MutableLocalPackage},
				{ImportPath: "example.com/parmid", PkgPath: "example.com/parmid", Imports: []string{"example.com/testutil"}, Class: MutableLocalPackage},
				{ImportPath: "example.com/testutil", PkgPath: "example.com/testutil", Class: MutableLocalPackage},
				{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
			}
			st := Compose(meta, map[string][]Fact{
				"example.com/parcaller": {FactOf(true, cPkg, false)},
				"example.com/parmid":    {FactOf(true, parMidPkg, false)},
				"example.com/testutil":  {FactOf(true, testutilPkg, false)},
				"example.com/seam":      {seamFact},
			}, "example.com/parcaller", nil, false, true)
			if len(st.RootCulprits) != 2 {
				t.Fatalf("%s: RootCulprits = %+v, want 2 culprits (hooks and seams)", callerCase.name, st.RootCulprits)
			}
		})
	}

	seqWrapperCaller := parseCheck("example.com/seqwrap", `package seqwrap
import (
	"testing"
	"example.com/seam"
	"example.com/testutil"
)
func TestSeqWrapper(t *testing.T) {
	w := testutil.Wrapper{T: t}
	w.Helper()
	cfg := testutil.Config{Parallel: 4}
	if cfg.Parallel > 0 {
		seam.WithHooks(seam.HookSet{}, func() {})
		seam.WithProbe(func() int { return cfg.Parallel }, func() {})
	}
}
`, map[string]*types.Package{
		"example.com/seam":     seamPkg.Types,
		"example.com/testutil": testutilPkg.Types,
	})
	seqWrapMeta := []GraphPackage{
		{ImportPath: "example.com/seqwrap", PkgPath: "example.com/seqwrap", Imports: []string{"example.com/testutil", "example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/testutil", PkgPath: "example.com/testutil", Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}
	seqWrapState := Compose(seqWrapMeta, map[string][]Fact{
		"example.com/seqwrap":  {FactOf(true, seqWrapperCaller, false)},
		"example.com/testutil": {FactOf(true, testutilPkg, false)},
		"example.com/seam":     {seamFact},
	}, "example.com/seqwrap", nil, false, true)
	if seqWrapState.Downgraded != "" {
		t.Fatalf("sequential cross-package Wrapper + scalar Config.Parallel downgraded: %+v", seqWrapState)
	}

	// 5. Cross-package .Parallel() helper called from TestRace in the same package as an unexported
	// atomic/scalar seam taints TestRace upward and blocks both unexported intra-package seams.
	intraPkg := parseCheck("example.com/intraseam", `package intraseam
import (
	"sync"
	"sync/atomic"
	"testing"
	"example.com/testutil"
)
type hookSet struct{ f func() }
var (
	hooksMu sync.Mutex
	hooks   atomic.Pointer[hookSet]
	saved   func() int
)
func withHooks(h hookSet, fn func()) {
	hooksMu.Lock()
	defer hooksMu.Unlock()
	defer hooks.Store(nil)
	hooks.Store(&h)
	fn()
}
func withSaved(s func() int, fn func()) {
	orig := saved
	defer func() { saved = orig }()
	saved = s
	fn()
}
func Read() int {
	if h := hooks.Load(); h != nil && h.f != nil {
		h.f()
	}
	if saved != nil {
		return saved()
	}
	return 0
}
func TestRaceUnexported(t *testing.T) {
	testutil.EnterParallel(t)
	withHooks(hookSet{}, func() {})
	withSaved(func() int { return 9 }, func() {})
}
`, map[string]*types.Package{"example.com/testutil": testutilPkg.Types})
	intraMeta := []GraphPackage{
		{ImportPath: "example.com/intraseam", PkgPath: "example.com/intraseam", Imports: []string{"example.com/testutil"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/testutil", PkgPath: "example.com/testutil", Class: MutableLocalPackage},
	}
	intraState := Compose(intraMeta, map[string][]Fact{
		"example.com/intraseam": {FactOf(true, intraPkg, false)},
		"example.com/testutil":  {FactOf(true, testutilPkg, false)},
	}, "example.com/intraseam", nil, false, true)
	if len(intraState.RootCulprits) != 2 {
		t.Fatalf("cross-pkg .Parallel helper + unexported intra-pkg seam RootCulprits = %+v, want 2 culprits (hooks and saved)", intraState.RootCulprits)
	}

	// 6. Cross-package direct variable assignment and parameterized setter (including 3-package forwarding)
	// populating a callable variable with a .Parallel() helper taints callers of that variable.
	hookHolderPkg := parseCheck("example.com/hookholder", `package hookholder
import "testing"
var EnterDirect func(*testing.T)
var enterParam func(*testing.T)
func SetEnter(fn func(*testing.T)) { enterParam = fn }
func RunDirect(t *testing.T) {
	if EnterDirect != nil {
		EnterDirect(t)
	}
}
func RunParam(t *testing.T) {
	if enterParam != nil {
		enterParam(t)
	}
}
`, nil)
	for _, xCase := range []struct {
		name string
		src  string
	}{
		{
			name: "cross_pkg_direct_var_assign",
			src: `package xcaller
import (
	"testing"
	"example.com/hookholder"
	"example.com/seam"
)
func rawPar(t *testing.T) { t.Parallel() }
func Install() { hookholder.EnterDirect = rawPar }
func TestCrossDirectVar(t *testing.T) {
	hookholder.RunDirect(t)
	seam.WithHooks(seam.HookSet{}, func() {})
	seam.WithProbe(func() int { return 5 }, func() {})
}
`,
		},
		{
			name: "cross_pkg_param_setter_unexported_arg",
			src: `package xcaller
import (
	"testing"
	"example.com/hookholder"
	"example.com/seam"
)
func rawPar(t *testing.T) { t.Parallel() }
func Install() { hookholder.SetEnter(rawPar) }
func TestCrossParamSetter(t *testing.T) {
	hookholder.RunParam(t)
	seam.WithHooks(seam.HookSet{}, func() {})
	seam.WithProbe(func() int { return 5 }, func() {})
}
`,
		},
		{
			name: "three_pkg_param_setter_forwarding_exported_par",
			src: `package xcaller
import (
	"testing"
	"example.com/hookholder"
	"example.com/seam"
	"example.com/testutil"
)
func Install() { hookholder.SetEnter(testutil.EnterParallel) }
func TestThreePkgParamSetter(t *testing.T) {
	hookholder.RunParam(t)
	seam.WithHooks(seam.HookSet{}, func() {})
	seam.WithProbe(func() int { return 5 }, func() {})
}
`,
		},
	} {
		t.Run(xCase.name, func(t *testing.T) {
			xPkg := parseCheck("example.com/xcaller", xCase.src, map[string]*types.Package{
				"example.com/hookholder": hookHolderPkg.Types,
				"example.com/seam":       seamPkg.Types,
				"example.com/testutil":   testutilPkg.Types,
			})
			xMeta := []GraphPackage{
				{ImportPath: "example.com/xcaller", PkgPath: "example.com/xcaller", Imports: []string{"example.com/hookholder", "example.com/seam", "example.com/testutil"}, Class: MutableLocalPackage},
				{ImportPath: "example.com/hookholder", PkgPath: "example.com/hookholder", Class: MutableLocalPackage},
				{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
				{ImportPath: "example.com/testutil", PkgPath: "example.com/testutil", Class: MutableLocalPackage},
			}
			xState := Compose(xMeta, map[string][]Fact{
				"example.com/xcaller":    {FactOf(true, xPkg, false)},
				"example.com/hookholder": {FactOf(true, hookHolderPkg, false)},
				"example.com/seam":       {seamFact},
				"example.com/testutil":   {FactOf(true, testutilPkg, false)},
			}, "example.com/xcaller", nil, false, true)
			if _, ok := xState.CulpritSites["example.com/seam.hooks"]; !ok {
				t.Fatalf("%s: expected example.com/seam.hooks to be blocked: %+v", xCase.name, xState.CulpritSites)
			}
			if _, ok := xState.CulpritSites["example.com/seam.seams"]; !ok {
				t.Fatalf("%s: expected example.com/seam.seams to be blocked: %+v", xCase.name, xState.CulpritSites)
			}
		})
	}
	// Control for section 6: SetEnter with a non-parallel callback must NOT block seam.hooks or seam.seams.
	seqSetterCaller := parseCheck("example.com/xseqcaller", `package xseqcaller
import (
	"testing"
	"example.com/hookholder"
	"example.com/seam"
)
func noop(_ *testing.T) {}
func InstallSeq() { hookholder.SetEnter(noop) }
func TestCrossSeqParamSetter(t *testing.T) {
	hookholder.RunParam(t)
	seam.WithHooks(seam.HookSet{}, func() {})
	seam.WithProbe(func() int { return 5 }, func() {})
}
`, map[string]*types.Package{
		"example.com/hookholder": hookHolderPkg.Types,
		"example.com/seam":       seamPkg.Types,
	})
	seqSetterState := Compose([]GraphPackage{
		{ImportPath: "example.com/xseqcaller", PkgPath: "example.com/xseqcaller", Imports: []string{"example.com/hookholder", "example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/hookholder", PkgPath: "example.com/hookholder", Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}, map[string][]Fact{
		"example.com/xseqcaller": {FactOf(true, seqSetterCaller, false)},
		"example.com/hookholder": {FactOf(true, hookHolderPkg, false)},
		"example.com/seam":       {seamFact},
	}, "example.com/xseqcaller", nil, false, true)
	if _, bad := seqSetterState.CulpritSites["example.com/seam.hooks"]; bad {
		t.Fatalf("sequential SetEnter(noop) unexpectedly blocked seam.hooks: %+v", seqSetterState.CulpritSites)
	}
	if _, bad := seqSetterState.CulpritSites["example.com/seam.seams"]; bad {
		t.Fatalf("sequential SetEnter(noop) unexpectedly blocked seam.seams: %+v", seqSetterState.CulpritSites)
	}

	// 7. RunnerOnly exported Cleanup seam stays clean when uncalled across the cone,
	// and is blocked if any foreign package calls TestSeam(&testing.T{}) directly.
	runnerSeamPkg := parseCheckNamed("example.com/cleanupseam", "cleanupseam_test.go", `package cleanupseam
import "testing"
var probe func() int
func Read() int {
	if probe != nil {
		return probe()
	}
	return 0
}
func TestSeam(t *testing.T) {
	orig := probe
	probe = func() int { return 42 }
	t.Cleanup(func() { probe = orig })
}
`, nil)
	runnerSeamFact := FactOf(true, runnerSeamPkg, false)
	if len(runnerSeamFact.ExportedSeams) != 1 || !runnerSeamFact.ExportedSeams[0].RunnerOnly {
		t.Fatalf("runnerSeamFact.ExportedSeams = %+v, want 1 RunnerOnly entry", runnerSeamFact.ExportedSeams)
	}
	aloneState := Compose([]GraphPackage{
		{ImportPath: "example.com/cleanupseam", PkgPath: "example.com/cleanupseam", Class: MutableLocalPackage},
	}, map[string][]Fact{
		"example.com/cleanupseam": {runnerSeamFact},
	}, "example.com/cleanupseam", nil, false, true)
	if aloneState.Downgraded != "" {
		t.Fatalf("uncalled RunnerOnly TestSeam downgraded: %+v", aloneState)
	}

	foreignTestCaller := parseCheckNamed("example.com/extcaller", "extcaller_test.go", `package extcaller
import (
	"testing"
	"example.com/cleanupseam"
)
func TestForeignCall(t *testing.T) {
	_ = t
	cleanupseam.TestSeam(&testing.T{})
}
`, map[string]*types.Package{"example.com/cleanupseam": runnerSeamPkg.Types})
	foreignState := Compose([]GraphPackage{
		{ImportPath: "example.com/extcaller", PkgPath: "example.com/extcaller", Imports: []string{"example.com/cleanupseam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/cleanupseam", PkgPath: "example.com/cleanupseam", Class: MutableLocalPackage},
	}, map[string][]Fact{
		"example.com/extcaller":   {FactOf(true, foreignTestCaller, false)},
		"example.com/cleanupseam": {runnerSeamFact},
	}, "example.com/extcaller", nil, false, true)
	if len(foreignState.RootCulprits) != 1 || foreignState.RootCulprits[0].Key != "example.com/cleanupseam.probe" {
		t.Fatalf("foreign caller of RunnerOnly TestSeam RootCulprits = %+v, want [example.com/cleanupseam.probe]", foreignState.RootCulprits)
	}

	// 8. Parameter parallel-taint slot (ParallelEdges) must NOT flow downward into
	// clean cross-package exported functions evaluated sequentially as call arguments.
	sinkPkg := parseCheck("example.com/sink", `package sink
import "testing"
func Consume(fn func(*testing.T)) { _ = fn }
`, nil)
	midCleanPkg := parseCheck("example.com/midclean", `package midclean
import (
	"testing"
	"example.com/seam"
)
func BuildCleanCb() func(*testing.T) {
	seam.WithHooks(seam.HookSet{}, func() {})
	seam.WithProbe(func() int { return 1 }, func() {})
	return nil
}
`, map[string]*types.Package{"example.com/seam": seamPkg.Types})
	parSinkCaller := parseCheckNamed("example.com/parsink", "parsink_test.go", `package parsink
import (
	"testing"
	"example.com/sink"
)
func parCb(t *testing.T) { t.Parallel() }
func TestParSink(t *testing.T) {
	_ = t
	sink.Consume(parCb)
}
`, map[string]*types.Package{"example.com/sink": sinkPkg.Types})
	seqSinkCaller := parseCheckNamed("example.com/seqsink", "seqsink_test.go", `package seqsink
import (
	"testing"
	"example.com/midclean"
	"example.com/sink"
)
func TestSeqSinkArg(t *testing.T) {
	_ = t
	sink.Consume(midclean.BuildCleanCb())
}
`, map[string]*types.Package{
		"example.com/midclean": midCleanPkg.Types,
		"example.com/sink":     sinkPkg.Types,
	})
	mixedState := Compose([]GraphPackage{
		{ImportPath: "example.com/mixedroot", PkgPath: "example.com/mixedroot", Imports: []string{"example.com/parsink", "example.com/seqsink"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/parsink", PkgPath: "example.com/parsink", Imports: []string{"example.com/sink"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/seqsink", PkgPath: "example.com/seqsink", Imports: []string{"example.com/midclean", "example.com/sink"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/midclean", PkgPath: "example.com/midclean", Imports: []string{"example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/sink", PkgPath: "example.com/sink", Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}, map[string][]Fact{
		"example.com/mixedroot": {{}},
		"example.com/parsink":   {FactOf(true, parSinkCaller, false)},
		"example.com/seqsink":   {FactOf(true, seqSinkCaller, false)},
		"example.com/midclean":  {FactOf(true, midCleanPkg, false)},
		"example.com/sink":      {FactOf(true, sinkPkg, false)},
		"example.com/seam":      {seamFact},
	}, "example.com/mixedroot", nil, false, true)
	if mixedState.Downgraded != "" || len(mixedState.RootCulprits) != 0 {
		t.Fatalf("ParallelEdges parameter slot falsely tainted sequential seam argument: %+v", mixedState)
	}

	// 9. Concrete receiver-method factory (returnID + recvID) returning a
	// .Parallel() callable into a variable invoked before an exported seam blocks
	// the seam.
	recvFactoryCaller := parseCheckNamed("example.com/recvfactory", "recvfactory_test.go", `package recvfactory
import (
	"testing"
	"example.com/seam"
)
type box struct {
	fn func(*testing.T)
}
func (b box) GetFn() func(*testing.T) { return b.fn }
func parCb(t *testing.T) { t.Parallel() }
var globalFn func(*testing.T)
func init() {
	b := box{fn: parCb}
	globalFn = b.GetFn()
}
func TestRecvFactory(t *testing.T) {
	globalFn(t)
	seam.WithHooks(seam.HookSet{}, func() {})
}
`, map[string]*types.Package{"example.com/seam": seamPkg.Types})
	recvFactoryState := Compose([]GraphPackage{
		{ImportPath: "example.com/recvfactory", PkgPath: "example.com/recvfactory", Imports: []string{"example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}, map[string][]Fact{
		"example.com/recvfactory": {FactOf(true, recvFactoryCaller, false)},
		"example.com/seam":        {seamFact},
	}, "example.com/recvfactory", nil, false, true)
	if _, ok := recvFactoryState.CulpritSites["example.com/seam.hooks"]; !ok {
		t.Fatalf("recvFactory CulpritSites missing example.com/seam.hooks: %+v", recvFactoryState.CulpritSites)
	}

	// 10. Cross-package indirect map/pointer parameter write-back (#w# slot)
	// taints a mutated map argument without cross-polluting unrelated clean maps.
	mapStorePkg := parseCheck("example.com/mapstore", `package mapstore
import "testing"
func Put(m map[string]func(*testing.T), f func(*testing.T)) {
	m["k"] = f
}
`, nil)
	mapStoreFact := FactOf(true, mapStorePkg, false)
	mapWriteDirtyCaller := parseCheckNamed("example.com/mapdirty", "mapdirty_test.go", `package mapdirty
import (
	"testing"
	"example.com/mapstore"
	"example.com/seam"
)
func parCb(t *testing.T) { t.Parallel() }
var globalMap = map[string]func(*testing.T){}
func init() {
	mapstore.Put(globalMap, parCb)
}
func TestMapDirty(t *testing.T) {
	globalMap["k"](t)
	seam.WithHooks(seam.HookSet{}, func() {})
}
`, map[string]*types.Package{
		"example.com/mapstore": mapStorePkg.Types,
		"example.com/seam":     seamPkg.Types,
	})
	mapDirtyState := Compose([]GraphPackage{
		{ImportPath: "example.com/mapdirty", PkgPath: "example.com/mapdirty", Imports: []string{"example.com/mapstore", "example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/mapstore", PkgPath: "example.com/mapstore", Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}, map[string][]Fact{
		"example.com/mapdirty": {FactOf(true, mapWriteDirtyCaller, false)},
		"example.com/mapstore": {mapStoreFact},
		"example.com/seam":     {seamFact},
	}, "example.com/mapdirty", nil, false, true)
	if _, ok := mapDirtyState.CulpritSites["example.com/seam.hooks"]; !ok {
		t.Fatalf("mapDirtyState CulpritSites missing example.com/seam.hooks: %+v", mapDirtyState.CulpritSites)
	}

	// 11. Shared non-carrier (*testing.T, string) helper called by both a
	// parallel test and a sequential seam test does not cross-pollute the seam.
	nonCarrierCaller := parseCheckNamed("example.com/noncarrier", "noncarrier_test.go", `package noncarrier
import (
	"testing"
	"example.com/seam"
)
var seenPrefix string
func makeDirLabel(t *testing.T, suffix string) string {
	seenPrefix = suffix
	return t.TempDir() + "/" + suffix
}
func TestParHelper(t *testing.T) {
	t.Parallel()
	_ = makeDirLabel(t, "par")
}
func TestSeqSeamWithHelper(t *testing.T) {
	dir := makeDirLabel(t, "seq")
	seam.WithHooks(seam.HookSet{}, func() { _ = dir })
}
`, map[string]*types.Package{"example.com/seam": seamPkg.Types})
	nonCarrierState := Compose([]GraphPackage{
		{ImportPath: "example.com/noncarrier", PkgPath: "example.com/noncarrier", Imports: []string{"example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}, map[string][]Fact{
		"example.com/noncarrier": {FactOf(true, nonCarrierCaller, false)},
		"example.com/seam":       {seamFact},
	}, "example.com/noncarrier", nil, false, true)
	if nonCarrierState.Downgraded != "" || len(nonCarrierState.RootCulprits) != 0 {
		t.Fatalf("non-carrier string/*testing.T helper falsely tainted sequential seam: %+v", nonCarrierState)
	}

	// 12. Cross-package mutable-reference return slot (#rw) taints exported
	// global/reader when a caller writes *slotpkg.HookSlot() = parCb.
	slotPkg := parseCheck("example.com/slotpkg", `package slotpkg
import "testing"
var enterHook func(*testing.T)
func HookSlot() *func(*testing.T) { return &enterHook }
func Enter(t *testing.T) {
	if enterHook != nil {
		enterHook(t)
	}
}
`, nil)
	slotFact := FactOf(true, slotPkg, false)
	slotSetupPkg := parseCheck("example.com/slotsetup", `package slotsetup
import (
	"testing"
	"example.com/slotpkg"
)
func parCb(t *testing.T) { t.Parallel() }
func Install() { *slotpkg.HookSlot() = parCb }
`, map[string]*types.Package{"example.com/slotpkg": slotPkg.Types})
	slotCallerPkg := parseCheckNamed("example.com/slotcaller", "slotcaller_test.go", `package slotcaller
import (
	"testing"
	"example.com/seam"
	"example.com/slotpkg"
	"example.com/slotsetup"
)
func init() { slotsetup.Install() }
func TestViaHookSlot(t *testing.T) {
	slotpkg.Enter(t)
	seam.WithHooks(seam.HookSet{}, func() {})
}
`, map[string]*types.Package{
		"example.com/seam":      seamPkg.Types,
		"example.com/slotpkg":   slotPkg.Types,
		"example.com/slotsetup": slotSetupPkg.Types,
	})
	slotState := Compose([]GraphPackage{
		{ImportPath: "example.com/slotcaller", PkgPath: "example.com/slotcaller", Imports: []string{"example.com/seam", "example.com/slotpkg", "example.com/slotsetup"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/slotsetup", PkgPath: "example.com/slotsetup", Imports: []string{"example.com/slotpkg"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/slotpkg", PkgPath: "example.com/slotpkg", Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}, map[string][]Fact{
		"example.com/slotcaller": {FactOf(true, slotCallerPkg, false)},
		"example.com/slotsetup":  {FactOf(true, slotSetupPkg, false)},
		"example.com/slotpkg":    {slotFact},
		"example.com/seam":       {seamFact},
	}, "example.com/slotcaller", nil, false, true)
	if _, ok := slotState.CulpritSites["example.com/seam.hooks"]; !ok {
		t.Fatalf("slotState CulpritSites missing example.com/seam.hooks: %+v", slotState.CulpritSites)
	}

	// 13. Cross-package generic function (#tp#) and generic receiver (#rtp#)
	// zero-value type-parameter instantiations taint exported readers.
	genPkg := parseCheck("example.com/genpkg", `package genpkg
import "testing"
var fnHolder any
var recvHolder any
func StoreZero[T any]() {
	var z T
	fnHolder = z
}
type Box[T any] struct{}
func (Box[T]) StoreZero() {
	var z T
	recvHolder = z
}
func EnterFn(t *testing.T) {
	if r, ok := fnHolder.(interface{ Enter(*testing.T) }); ok {
		r.Enter(t)
	}
}
func EnterRecv(t *testing.T) {
	if r, ok := recvHolder.(interface{ Enter(*testing.T) }); ok {
		r.Enter(t)
	}
}
`, nil)
	genFact := FactOf(true, genPkg, false)
	genSetupPkg := parseCheck("example.com/gensetup", `package gensetup
import (
	"testing"
	"example.com/genpkg"
)
type innerPar struct{}
func (innerPar) Enter(t *testing.T) { t.Parallel() }
func InstallFn() { genpkg.StoreZero[innerPar]() }
func InstallRecv() {
	var s interface{ StoreZero() } = genpkg.Box[innerPar]{}
	s.StoreZero()
}
`, map[string]*types.Package{"example.com/genpkg": genPkg.Types})
	genFnCaller := parseCheckNamed("example.com/genfncaller", "genfn_test.go", `package genfncaller
import (
	"testing"
	"example.com/genpkg"
	"example.com/gensetup"
	"example.com/seam"
)
func init() { gensetup.InstallFn() }
func TestViaGenFn(t *testing.T) {
	genpkg.EnterFn(t)
	seam.WithHooks(seam.HookSet{}, func() {})
}
`, map[string]*types.Package{
		"example.com/genpkg":   genPkg.Types,
		"example.com/gensetup": genSetupPkg.Types,
		"example.com/seam":     seamPkg.Types,
	})
	genFnState := Compose([]GraphPackage{
		{ImportPath: "example.com/genfncaller", PkgPath: "example.com/genfncaller", Imports: []string{"example.com/genpkg", "example.com/gensetup", "example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/gensetup", PkgPath: "example.com/gensetup", Imports: []string{"example.com/genpkg"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/genpkg", PkgPath: "example.com/genpkg", Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}, map[string][]Fact{
		"example.com/genfncaller": {FactOf(true, genFnCaller, false)},
		"example.com/gensetup":    {FactOf(true, genSetupPkg, false)},
		"example.com/genpkg":      {genFact},
		"example.com/seam":        {seamFact},
	}, "example.com/genfncaller", nil, false, true)
	if _, ok := genFnState.CulpritSites["example.com/seam.hooks"]; !ok {
		t.Fatalf("genFnState CulpritSites missing example.com/seam.hooks: %+v", genFnState.CulpritSites)
	}

	genRecvCaller := parseCheckNamed("example.com/genrecvcaller", "genrecv_test.go", `package genrecvcaller
import (
	"testing"
	"example.com/genpkg"
	"example.com/gensetup"
	"example.com/seam"
)
func init() { gensetup.InstallRecv() }
func TestViaGenRecv(t *testing.T) {
	genpkg.EnterRecv(t)
	seam.WithHooks(seam.HookSet{}, func() {})
}
`, map[string]*types.Package{
		"example.com/genpkg":   genPkg.Types,
		"example.com/gensetup": genSetupPkg.Types,
		"example.com/seam":     seamPkg.Types,
	})
	genRecvState := Compose([]GraphPackage{
		{ImportPath: "example.com/genrecvcaller", PkgPath: "example.com/genrecvcaller", Imports: []string{"example.com/genpkg", "example.com/gensetup", "example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/gensetup", PkgPath: "example.com/gensetup", Imports: []string{"example.com/genpkg"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/genpkg", PkgPath: "example.com/genpkg", Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}, map[string][]Fact{
		"example.com/genrecvcaller": {FactOf(true, genRecvCaller, false)},
		"example.com/gensetup":      {FactOf(true, genSetupPkg, false)},
		"example.com/genpkg":        {genFact},
		"example.com/seam":          {seamFact},
	}, "example.com/genrecvcaller", nil, false, true)
	if _, ok := genRecvState.CulpritSites["example.com/seam.hooks"]; !ok {
		t.Fatalf("genRecvState CulpritSites missing example.com/seam.hooks: %+v", genRecvState.CulpritSites)
	}

	// 14. Cross-package exported mutable-alias write-through (#w) taints aliased
	// unexported state across qualified local rebinding, dot-imports, and stdlib
	// maps.Copy, while bare cross-package variable rebinding does not falsely
	// backward-taint unmutated initializers.
	aliasPkg := parseCheck("example.com/aliaspkg", `package aliaspkg
import "testing"
var enterHook = func(*testing.T) {}
var HookPtr = &enterHook
var enterMap = map[string]func(*testing.T){}
var HookMap = enterMap
var cleanMap = map[string]func(*testing.T){"k": func(*testing.T) {}}
var ReboundMap = cleanMap
func EnterPtr(t *testing.T)   { enterHook(t) }
func EnterMap(t *testing.T)   { enterMap["k"](t) }
func EnterClean(t *testing.T) { cleanMap["k"](t) }
`, nil)
	aliasFact := FactOf(true, aliasPkg, false)

	aliasPtrCaller := parseCheckNamed("example.com/aliasptrcaller", "aliasptr_test.go", `package aliasptrcaller
import (
	"testing"
	"example.com/aliaspkg"
	"example.com/seam"
)
func parCb(t *testing.T) { t.Parallel() }
func init() {
	p := aliaspkg.HookPtr
	*p = parCb
}
func TestAliasPtr(t *testing.T) {
	aliaspkg.EnterPtr(t)
	seam.WithHooks(seam.HookSet{}, func() {})
}
`, map[string]*types.Package{
		"example.com/aliaspkg": aliasPkg.Types,
		"example.com/seam":     seamPkg.Types,
	})
	aliasPtrState := Compose([]GraphPackage{
		{ImportPath: "example.com/aliasptrcaller", PkgPath: "example.com/aliasptrcaller", Imports: []string{"example.com/aliaspkg", "example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/aliaspkg", PkgPath: "example.com/aliaspkg", Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}, map[string][]Fact{
		"example.com/aliasptrcaller": {FactOf(true, aliasPtrCaller, false)},
		"example.com/aliaspkg":       {aliasFact},
		"example.com/seam":           {seamFact},
	}, "example.com/aliasptrcaller", nil, false, true)
	if _, ok := aliasPtrState.CulpritSites["example.com/seam.hooks"]; !ok {
		t.Fatalf("aliasPtrState CulpritSites missing example.com/seam.hooks: %+v", aliasPtrState.CulpritSites)
	}

	aliasDotCaller := parseCheckNamed("example.com/aliasdotcaller", "aliasdot_test.go", `package aliasdotcaller
import (
	"testing"
	. "example.com/aliaspkg"
	"example.com/seam"
)
func parCb(t *testing.T) { t.Parallel() }
func init() {
	p := HookPtr
	*p = parCb
}
func TestAliasDot(t *testing.T) {
	EnterPtr(t)
	seam.WithHooks(seam.HookSet{}, func() {})
}
`, map[string]*types.Package{
		"example.com/aliaspkg": aliasPkg.Types,
		"example.com/seam":     seamPkg.Types,
	})
	aliasDotState := Compose([]GraphPackage{
		{ImportPath: "example.com/aliasdotcaller", PkgPath: "example.com/aliasdotcaller", Imports: []string{"example.com/aliaspkg", "example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/aliaspkg", PkgPath: "example.com/aliaspkg", Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}, map[string][]Fact{
		"example.com/aliasdotcaller": {FactOf(true, aliasDotCaller, false)},
		"example.com/aliaspkg":       {aliasFact},
		"example.com/seam":           {seamFact},
	}, "example.com/aliasdotcaller", nil, false, true)
	if _, ok := aliasDotState.CulpritSites["example.com/seam.hooks"]; !ok {
		t.Fatalf("aliasDotState CulpritSites missing example.com/seam.hooks: %+v", aliasDotState.CulpritSites)
	}

	aliasRebindCleanCaller := parseCheckNamed("example.com/aliasrebindclean", "aliasrebind_test.go", `package aliasrebindclean
import (
	"testing"
	"example.com/aliaspkg"
	"example.com/seam"
)
func parCb(t *testing.T) { t.Parallel() }
func init() {
	aliaspkg.ReboundMap = map[string]func(*testing.T){"k": parCb}
}
func TestAliasRebindClean(t *testing.T) {
	aliaspkg.EnterClean(t)
	seam.WithHooks(seam.HookSet{}, func() {})
}
`, map[string]*types.Package{
		"example.com/aliaspkg": aliasPkg.Types,
		"example.com/seam":     seamPkg.Types,
	})
	aliasRebindCleanState := Compose([]GraphPackage{
		{ImportPath: "example.com/aliasrebindclean", PkgPath: "example.com/aliasrebindclean", Imports: []string{"example.com/aliaspkg", "example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/aliaspkg", PkgPath: "example.com/aliaspkg", Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}, map[string][]Fact{
		"example.com/aliasrebindclean": {FactOf(true, aliasRebindCleanCaller, false)},
		"example.com/aliaspkg":         {aliasFact},
		"example.com/seam":             {seamFact},
	}, "example.com/aliasrebindclean", nil, false, true)
	if _, hasSeam := aliasRebindCleanState.CulpritSites["example.com/seam.hooks"]; hasSeam {
		t.Fatalf("bare cross-package rebinding falsely backward-tainted cleanMap and blocked seam: %+v", aliasRebindCleanState.CulpritSites)
	}

	aliasMapCaller := parseCheckNamed("example.com/aliasmapcaller", "aliasmap_test.go", `package aliasmapcaller
import (
	"maps"
	"testing"
	"example.com/aliaspkg"
	"example.com/seam"
)
func parCb(t *testing.T) { t.Parallel() }
func init() {
	maps.Copy(aliaspkg.HookMap, map[string]func(*testing.T){"k": parCb})
}
func TestAliasMap(t *testing.T) {
	aliaspkg.EnterMap(t)
	seam.WithHooks(seam.HookSet{}, func() {})
}
`, map[string]*types.Package{
		"example.com/aliaspkg": aliasPkg.Types,
		"example.com/seam":     seamPkg.Types,
	})
	aliasMapState := Compose([]GraphPackage{
		{ImportPath: "example.com/aliasmapcaller", PkgPath: "example.com/aliasmapcaller", Imports: []string{"example.com/aliaspkg", "example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/aliaspkg", PkgPath: "example.com/aliaspkg", Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}, map[string][]Fact{
		"example.com/aliasmapcaller": {FactOf(true, aliasMapCaller, false)},
		"example.com/aliaspkg":       {aliasFact},
		"example.com/seam":           {seamFact},
	}, "example.com/aliasmapcaller", nil, false, true)
	if _, ok := aliasMapState.CulpritSites["example.com/seam.hooks"]; !ok {
		t.Fatalf("aliasMapState CulpritSites missing example.com/seam.hooks: %+v", aliasMapState.CulpritSites)
	}

	// 15. Cross-package 0-arg receiver read (#recv) and 0-arg receiver
	// write-through (#wrecv) propagate .Parallel() taint across packages.
	recvHubPkg := parseCheck("example.com/recvhubpkg", `package recvhubpkg
import "testing"
var installed = func(*testing.T) {}
type Installer struct {
	Fn func(*testing.T)
}
func (in Installer) Install() {
	installed = in.Fn
}
func RunInstalled(t *testing.T) {
	installed(t)
}
func parFromRecv(t *testing.T) { t.Parallel() }
type Target struct {
	Fn func(*testing.T)
}
type Enabler struct {
	Dst *Target
}
func (e *Enabler) Enable() {
	e.Dst.Fn = parFromRecv
}
`, nil)
	recvHubFact := FactOf(true, recvHubPkg, false)

	recvReadCaller := parseCheckNamed("example.com/recvreadcaller", "recvread_test.go", `package recvreadcaller
import (
	"testing"
	"example.com/recvhubpkg"
	"example.com/seam"
)
func parCb(t *testing.T) { t.Parallel() }
func init() {
	in := recvhubpkg.Installer{Fn: parCb}
	in.Install()
}
func TestRecvRead(t *testing.T) {
	recvhubpkg.RunInstalled(t)
	seam.WithHooks(seam.HookSet{}, func() {})
}
`, map[string]*types.Package{
		"example.com/recvhubpkg": recvHubPkg.Types,
		"example.com/seam":       seamPkg.Types,
	})
	recvReadState := Compose([]GraphPackage{
		{ImportPath: "example.com/recvreadcaller", PkgPath: "example.com/recvreadcaller", Imports: []string{"example.com/recvhubpkg", "example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/recvhubpkg", PkgPath: "example.com/recvhubpkg", Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}, map[string][]Fact{
		"example.com/recvreadcaller": {FactOf(true, recvReadCaller, false)},
		"example.com/recvhubpkg":     {recvHubFact},
		"example.com/seam":           {seamFact},
	}, "example.com/recvreadcaller", nil, false, true)
	if _, ok := recvReadState.CulpritSites["example.com/seam.hooks"]; !ok {
		t.Fatalf("recvReadState CulpritSites missing example.com/seam.hooks: %+v", recvReadState.CulpritSites)
	}

	recvWriteCaller := parseCheckNamed("example.com/recvwritecaller", "recvwrite_test.go", `package recvwritecaller
import (
	"testing"
	"example.com/recvhubpkg"
	"example.com/seam"
)
var globalTarget = recvhubpkg.Target{Fn: func(*testing.T) {}}
func init() {
	dst := &globalTarget
	e := recvhubpkg.Enabler{Dst: dst}
	ep := &e
	enable := (*recvhubpkg.Enabler).Enable
	enable(ep)
}
func TestRecvWrite(t *testing.T) {
	globalTarget.Fn(t)
	seam.WithHooks(seam.HookSet{}, func() {})
}
`, map[string]*types.Package{
		"example.com/recvhubpkg": recvHubPkg.Types,
		"example.com/seam":       seamPkg.Types,
	})
	recvWriteState := Compose([]GraphPackage{
		{ImportPath: "example.com/recvwritecaller", PkgPath: "example.com/recvwritecaller", Imports: []string{"example.com/recvhubpkg", "example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/recvhubpkg", PkgPath: "example.com/recvhubpkg", Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}, map[string][]Fact{
		"example.com/recvwritecaller": {FactOf(true, recvWriteCaller, false)},
		"example.com/recvhubpkg":      {recvHubFact},
		"example.com/seam":            {seamFact},
	}, "example.com/recvwritecaller", nil, false, true)
	if _, ok := recvWriteState.CulpritSites["example.com/seam.hooks"]; !ok {
		t.Fatalf("recvWriteState CulpritSites missing example.com/seam.hooks: %+v", recvWriteState.CulpritSites)
	}

	// 16. Cross-package non-call function return write-through (sync.Pool{New: pkg.NewSlot})
	// and cross-package iterator yield write-through (slices.Collect(seqpkg.PtrSeq(p0))).
	poolSlotPkg := parseCheck("example.com/poolslotpkg", `package poolslotpkg
import (
	"iter"
	"testing"
)
var enterHook = func(*testing.T) {}
func NewSlot() any {
	p0 := &enterHook
	return p0
}
func EnterSlot(t *testing.T) {
	enterHook(t)
}
func PtrSeq(p *func(*testing.T)) iter.Seq[*func(*testing.T)] {
	return func(yield func(*func(*testing.T)) bool) {
		_ = yield(p)
	}
}
`, nil)
	poolSlotFact := FactOf(true, poolSlotPkg, false)

	slotPoolCaller := parseCheckNamed("example.com/slotpoolcaller", "slotpool_test.go", `package slotpoolcaller
import (
	"sync"
	"testing"
	"example.com/poolslotpkg"
	"example.com/seam"
)
func parCb(t *testing.T) { t.Parallel() }
func init() {
	pool := sync.Pool{New: poolslotpkg.NewSlot}
	ptr := pool.Get().(*func(*testing.T))
	*ptr = parCb
}
func TestSlotPool(t *testing.T) {
	poolslotpkg.EnterSlot(t)
	seam.WithHooks(seam.HookSet{}, func() {})
}
`, map[string]*types.Package{
		"example.com/poolslotpkg": poolSlotPkg.Types,
		"example.com/seam":        seamPkg.Types,
	})
	slotPoolState := Compose([]GraphPackage{
		{ImportPath: "example.com/slotpoolcaller", PkgPath: "example.com/slotpoolcaller", Imports: []string{"example.com/poolslotpkg", "example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/poolslotpkg", PkgPath: "example.com/poolslotpkg", Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}, map[string][]Fact{
		"example.com/slotpoolcaller": {FactOf(true, slotPoolCaller, false)},
		"example.com/poolslotpkg":    {poolSlotFact},
		"example.com/seam":           {seamFact},
	}, "example.com/slotpoolcaller", nil, false, true)
	if _, ok := slotPoolState.CulpritSites["example.com/seam.hooks"]; !ok {
		t.Fatalf("slotPoolState CulpritSites missing example.com/seam.hooks: %+v", slotPoolState.CulpritSites)
	}

	seqCollectCaller := parseCheckNamed("example.com/seqcollectcaller", "seqcollect_test.go", `package seqcollectcaller
import (
	"slices"
	"testing"
	"example.com/poolslotpkg"
	"example.com/seam"
)
func parCb(t *testing.T) { t.Parallel() }
var localHook = func(*testing.T) {}
func init() {
	p0 := &localHook
	ptrs := slices.Collect(poolslotpkg.PtrSeq(p0))
	*ptrs[0] = parCb
}
func TestSeqCollect(t *testing.T) {
	localHook(t)
	seam.WithHooks(seam.HookSet{}, func() {})
}
`, map[string]*types.Package{
		"example.com/poolslotpkg": poolSlotPkg.Types,
		"example.com/seam":        seamPkg.Types,
	})
	seqCollectState := Compose([]GraphPackage{
		{ImportPath: "example.com/seqcollectcaller", PkgPath: "example.com/seqcollectcaller", Imports: []string{"example.com/poolslotpkg", "example.com/seam"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/poolslotpkg", PkgPath: "example.com/poolslotpkg", Class: MutableLocalPackage},
		{ImportPath: "example.com/seam", PkgPath: "example.com/seam", Class: MutableLocalPackage},
	}, map[string][]Fact{
		"example.com/seqcollectcaller": {FactOf(true, seqCollectCaller, false)},
		"example.com/poolslotpkg":      {poolSlotFact},
		"example.com/seam":             {seamFact},
	}, "example.com/seqcollectcaller", nil, false, true)
	if _, ok := seqCollectState.CulpritSites["example.com/seam.hooks"]; !ok {
		t.Fatalf("seqCollectState CulpritSites missing example.com/seam.hooks: %+v", seqCollectState.CulpritSites)
	}
}

//gofresh:pure
func TestParallelDataflowIndirectAliasesTypeSwitchAndGenerics(t *testing.T) {
	const seamFile = `package p
var seamHook func() int
func withSeam(fn func() int, body func()) {
	orig := seamHook
	defer func() { seamHook = orig }()
	seamHook = fn
	body()
}
`
	cases := []struct {
		name     string
		testSrc  string
		wantSeam bool // true = seamHook is reported in Fact.Mutates; false = seamHook exempted
	}{
		{
			name: "non_iife_funclit_setter",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
func init() {
	set := func(fn func(*testing.T)) { enterHook = fn }
	set(rawPar)
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "iface_method_val_setter",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
type setterIface interface { SetEnter(func(*testing.T)) }
type setterImpl struct{}
func (setterImpl) SetEnter(fn func(*testing.T)) { enterHook = fn }
func init() {
	var s setterIface = setterImpl{}
	f := s.SetEnter
	f(rawPar)
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "embedded_iface_method_call_setter",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
type setterIface interface { SetEnter(func(*testing.T)) }
type setterImpl struct{}
func (setterImpl) SetEnter(fn func(*testing.T)) { enterHook = fn }
type setterWrap struct { setterIface }
func init() {
	w := setterWrap{setterIface: setterImpl{}}
	w.SetEnter(rawPar)
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "concrete_method_expr_setter",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
type setterImpl struct{}
func (setterImpl) SetEnter(fn func(*testing.T)) { enterHook = fn }
func init() {
	f := setterImpl.SetEnter
	f(setterImpl{}, rawPar)
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "iface_method_expr_setter",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
type setterIface interface { SetEnter(func(*testing.T)) }
type setterImpl struct{}
func (setterImpl) SetEnter(fn func(*testing.T)) { enterHook = fn }
func init() {
	f := setterIface.SetEnter
	f(setterImpl{}, rawPar)
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "bound_method_val_recv_mutation",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
type box struct { fn func(*testing.T) }
func (b *box) SetFn(fn func(*testing.T)) { b.fn = fn }
var globalBox = box{fn: func(*testing.T) {}}
func init() {
	f := globalBox.SetFn
	f(rawPar)
}
func TestSeam(t *testing.T) {
	globalBox.fn(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "local_map_alias_mutation",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var enterMap = map[string]func(*testing.T){}
func init() {
	m := enterMap
	m["k"] = rawPar
}
func TestSeam(t *testing.T) {
	enterMap["k"](t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "pointer_param_local_rebinding",
			testSrc: `package p
import "testing"
func cleanFn(*testing.T) {}
func rawPar(t *testing.T) { t.Parallel() }
var slot = cleanFn
var enterPtr = &slot
var globalPar = rawPar
func setPtr(p *func(*testing.T)) {
	q := p
	*q = globalPar
}
func init() {
	setPtr(enterPtr)
}
func TestSeam(t *testing.T) {
	slot(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "clean_local_rebinding_no_backward_taint",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var cleanMap = map[string]func(*testing.T){"k": func(*testing.T) {}}
func init() {
	m := cleanMap
	m = map[string]func(*testing.T){"k": rawPar}
	_ = m
}
func TestSeam(t *testing.T) {
	cleanMap["k"](t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: false,
		},
		{
			name: "type_assert_lhs_mutation",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var box any = map[string]func(*testing.T){}
func init() {
	box.(map[string]func(*testing.T))["k"] = rawPar
}
func TestSeam(t *testing.T) {
	box.(map[string]func(*testing.T))["k"](t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "mutable_return_slot_mutation",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
func hookSlot() *func(*testing.T) { return &enterHook }
func init() {
	*hookSlot() = rawPar
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "range_over_func_pointer_yield",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
func slotSeq(yield func(*func(*testing.T)) bool) {
	yield(&enterHook)
}
func init() {
	for p := range slotSeq {
		*p = rawPar
	}
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "builtin_copy_slice_param",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var enterSlice = make([]func(*testing.T), 1)
func fillSlice(dst, src []func(*testing.T)) {
	copy(dst, src)
}
func init() {
	fillSlice(enterSlice, []func(*testing.T){rawPar})
}
func TestSeam(t *testing.T) {
	enterSlice[0](t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "stdlib_maps_copy_mutator",
			testSrc: `package p
import (
	"maps"
	"testing"
)
func rawPar(t *testing.T) { t.Parallel() }
var enterMap = map[string]func(*testing.T){}
func init() {
	maps.Copy(enterMap, map[string]func(*testing.T){"k": rawPar})
}
func TestSeam(t *testing.T) {
	enterMap["k"](t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "reflect_addr_in_call_fun",
			testSrc: `package p
import (
	"reflect"
	"testing"
)
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
func init() {
	reflect.ValueOf(&enterHook).Elem().Set(reflect.ValueOf(rawPar))
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "stdlib_errors_is_no_false_taint",
			testSrc: `package p
import (
	"errors"
	"testing"
)
type parErr struct{}
func (parErr) Error() string { return "par" }
func (parErr) Enter(t *testing.T) { t.Parallel() }
var cleanErr = errors.New("ok")
func init() {
	var pe error = parErr{}
	_ = errors.Is(cleanErr, pe)
	_ = errors.Join(cleanErr, pe)
}
func TestSeam(t *testing.T) {
	_ = cleanErr.Error()
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: false,
		},
		{
			name: "type_switch_implicit_var_value",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
func setFromAny(step any) {
	switch fn := step.(type) {
	case func(*testing.T):
		enterHook = fn
	}
}
func init() {
	setFromAny(rawPar)
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "type_switch_implicit_var_alias_write",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var enterMap = map[string]func(*testing.T){}
func putInAny(box any, fn func(*testing.T)) {
	switch m := box.(type) {
	case map[string]func(*testing.T):
		m["k"] = fn
	}
}
func init() {
	putInAny(enterMap, rawPar)
}
func TestSeam(t *testing.T) {
	enterMap["k"](t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "generic_func_zero_val_type_param",
			testSrc: `package p
import "testing"
type innerPar struct{}
func (innerPar) Enter(t *testing.T) { t.Parallel() }
var opaqueHolder any
func storeZero[T any]() {
	var z T
	opaqueHolder = z
}
func init() {
	storeZero[innerPar]()
}
func TestSeam(t *testing.T) {
	opaqueHolder.(interface{ Enter(*testing.T) }).Enter(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "generic_recv_method_type_param_via_iface",
			testSrc: `package p
import "testing"
type innerPar struct{}
func (innerPar) Enter(t *testing.T) { t.Parallel() }
var opaqueHolder any
type zeroBox[T any] struct{}
func (zeroBox[T]) StoreZero() {
	var z T
	opaqueHolder = z
}
func init() {
	var s interface{ StoreZero() } = zeroBox[innerPar]{}
	s.StoreZero()
}
func TestSeam(t *testing.T) {
	opaqueHolder.(interface{ Enter(*testing.T) }).Enter(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "generic_container_clean_instantiation_no_cross_taint",
			testSrc: `package p
import "testing"
type innerPar struct{}
func (innerPar) Enter(t *testing.T) { t.Parallel() }
type memo[V any] struct { v V }
func (m *memo[V]) Get() V {
	var out V = m.v
	return out
}
func TestPar(t *testing.T) {
	m := &memo[innerPar]{}
	m.Get().Enter(t)
}
func TestCleanSeam(t *testing.T) {
	m := &memo[bool]{v: true}
	if m.Get() {
		withSeam(func() int { return 1 }, func() {})
	}
}
`,
			wantSeam: false,
		},
		{
			name: "zero_arg_iface_recv_read_direct_call",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
type installer interface { Install() }
type installerBox struct { fn func(*testing.T) }
func (b installerBox) Install() { enterHook = b.fn }
func init() {
	var in installer = installerBox{fn: rawPar}
	in.Install()
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "zero_arg_iface_method_val_and_expr_recv_read",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
type installer interface { Install() }
type installerBox struct { fn func(*testing.T) }
func (b installerBox) Install() { enterHook = b.fn }
func runPlain(fn func()) { fn() }
func init() {
	var in installer = installerBox{fn: rawPar}
	runPlain(in.Install)
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "method_interior_alias_return_direct",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
type slotBox struct { fn func(*testing.T) }
func (b *slotBox) Slot() *func(*testing.T) { return &b.fn }
var globalBox = slotBox{fn: func(*testing.T) {}}
func init() {
	*globalBox.Slot() = rawPar
}
func TestSeam(t *testing.T) {
	globalBox.fn(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "method_interior_alias_return_method_val",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
type slotBox struct { fn func(*testing.T) }
func (b *slotBox) Slot() *func(*testing.T) { return &b.fn }
var globalBox = slotBox{fn: func(*testing.T) {}}
func init() {
	slotFn := globalBox.Slot
	*slotFn() = rawPar
}
func TestSeam(t *testing.T) {
	globalBox.fn(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "zero_arg_iface_method_val_recv_write_through",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var enterMap = map[string]func(*testing.T){}
type enabler interface { Enable() }
type enablerBox struct { m map[string]func(*testing.T) }
func (e enablerBox) Enable() { e.m["k"] = rawPar }
func init() {
	var en enabler = enablerBox{m: enterMap}
	enable := en.Enable
	enable()
}
func TestSeam(t *testing.T) {
	enterMap["k"](t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "value_taken_stdlib_maps_copy",
			testSrc: `package p
import (
	"maps"
	"testing"
)
func rawPar(t *testing.T) { t.Parallel() }
var enterMap = map[string]func(*testing.T){}
func init() {
	cp := maps.Copy[map[string]func(*testing.T), map[string]func(*testing.T)]
	cp(enterMap, map[string]func(*testing.T){"k": rawPar})
}
func TestSeam(t *testing.T) {
	enterMap["k"](t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "value_taken_stdlib_reflect_valueof_and_elem",
			testSrc: `package p
import (
	"reflect"
	"testing"
)
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
func init() {
	vo := reflect.ValueOf
	rv := vo(&enterHook)
	elem := rv.Elem
	elem().Set(vo(rawPar))
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "value_taken_stdlib_reflect_method_expr_elem",
			testSrc: `package p
import (
	"reflect"
	"testing"
)
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
func init() {
	elemFn := reflect.Value.Elem
	elemFn(reflect.ValueOf(&enterHook)).Set(reflect.ValueOf(rawPar))
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "value_taken_stdlib_observer_no_false_taint",
			testSrc: `package p
import (
	"errors"
	"fmt"
	"testing"
)
type parErr struct{}
func (parErr) Error() string { return "par" }
func (parErr) Enter(t *testing.T) { t.Parallel() }
var cleanErr = errors.New("ok")
func init() {
	var pe error = parErr{}
	errf := fmt.Errorf
	join := errors.Join
	is := errors.Is
	_ = errf("%w %w", cleanErr, pe)
	_ = join(cleanErr, pe)
	_ = is(cleanErr, pe)
}
func TestSeam(t *testing.T) {
	_ = cleanErr.Error()
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: false,
		},
		{
			name: "tuple_unpack_call_arg_write_through",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
func pair() (*func(*testing.T), func(*testing.T)) {
	return &enterHook, rawPar
}
func assign(dst *func(*testing.T), src func(*testing.T)) {
	*dst = src
}
func init() {
	assign(pair())
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "stdlib_sync_map_range_callback",
			testSrc: `package p
import (
	"sync"
	"testing"
)
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
var sm sync.Map
func init() {
	sm.Store("k", rawPar)
	sm.Range(func(_, v any) bool {
		enterHook = v.(func(*testing.T))
		return true
	})
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "stdlib_sync_map_range_clean_isolated",
			testSrc: `package p
import (
	"sync"
	"testing"
)
func rawPar(t *testing.T) { t.Parallel() }
func cleanFn(t *testing.T) {}
var enterHook = cleanFn
var smPar sync.Map
var smClean sync.Map
func init() {
	smPar.Store("k", rawPar)
	smPar.Range(func(_, v any) bool {
		_ = v
		return true
	})
	smClean.Store("k", cleanFn)
	smClean.Range(func(_, v any) bool {
		enterHook = v.(func(*testing.T))
		return true
	})
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: false,
		},
		{
			name: "stdlib_user_iface_sync_map_range",
			testSrc: `package p
import (
	"sync"
	"testing"
)
type ranger interface {
	Range(func(any, any) bool)
}
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
var sm sync.Map
func init() {
	sm.Store("k", rawPar)
	var r ranger = &sm
	r.Range(func(_, v any) bool {
		enterHook = v.(func(*testing.T))
		return true
	})
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "stdlib_slices_contains_func_callback",
			testSrc: `package p
import (
	"slices"
	"testing"
)
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
func init() {
	_ = slices.ContainsFunc([]func(*testing.T){rawPar}, func(fn func(*testing.T)) bool {
		enterHook = fn
		return true
	})
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "stdlib_value_taken_contains_func_callback",
			testSrc: `package p
import (
	"slices"
	"testing"
)
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
func acceptCb(fn func(*testing.T)) bool {
	enterHook = fn
	return true
}
func invokeDynamic(cf func([]func(*testing.T), func(func(*testing.T)) bool) bool, cb func(func(*testing.T)) bool) {
	_ = cf([]func(*testing.T){rawPar}, cb)
}
func init() {
	invokeDynamic(slices.ContainsFunc[[]func(*testing.T), func(*testing.T)], acceptCb)
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "direct_iterator_call_callback",
			testSrc: `package p
import (
	"iter"
	"slices"
	"testing"
)
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
func consume(seq iter.Seq[func(*testing.T)]) {
	seq(func(fn func(*testing.T)) bool {
		enterHook = fn
		return true
	})
}
func init() {
	consume(slices.Values([]func(*testing.T){rawPar}))
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "stdlib_callback_param_write_through",
			testSrc: `package p
import (
	"iter"
	"slices"
	"testing"
)
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
func setAll(seq iter.Seq[*func(*testing.T)], fn func(*testing.T)) {
	seq(func(p *func(*testing.T)) bool {
		*p = fn
		return true
	})
}
func init() {
	p0 := &enterHook
	setAll(slices.Values([]*func(*testing.T){p0}), rawPar)
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "builtin_new_expr_write_through",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
func init() {
	p0 := &enterHook
	p := new(p0)
	**p = rawPar
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "builtin_new_value_copy_no_backward_taint",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
func cleanFn(t *testing.T) {}
var enterHook = cleanFn
func init() {
	p := new(enterHook)
	*p = rawPar
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: false,
		},
		{
			name: "builtin_unsafe_slice_write_through",
			testSrc: `package p
import (
	"testing"
	"unsafe"
)
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
func init() {
	p0 := &enterHook
	s := unsafe.Slice(p0, 1)
	s[0] = rawPar
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "sync_pool_func_ref_write_through",
			testSrc: `package p
import (
	"sync"
	"testing"
)
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
func newSlot() any {
	p0 := &enterHook
	return p0
}
func init() {
	pool := sync.Pool{New: newSlot}
	ptr := pool.Get().(*func(*testing.T))
	*ptr = rawPar
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "sync_pool_sibling_clean_isolated",
			testSrc: `package p
import (
	"sync"
	"testing"
)
func rawPar(t *testing.T) { t.Parallel() }
func cleanFn(t *testing.T) {}
var parTarget = cleanFn
var enterHook = cleanFn
func newParSlot() any {
	p0 := &parTarget
	return p0
}
func newCleanSlot() any {
	p0 := &enterHook
	return p0
}
func init() {
	parPool := sync.Pool{New: newParSlot}
	*(parPool.Get().(*func(*testing.T))) = rawPar
	cleanPool := sync.Pool{New: newCleanSlot}
	_ = cleanPool.Get()
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: false,
		},
		{
			name: "sync_pool_method_val_return_write_through",
			testSrc: `package p
import (
	"sync"
	"testing"
)
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
type maker struct{}
func (maker) NewSlot() any {
	p0 := &enterHook
	return p0
}
func init() {
	var m maker
	pool := sync.Pool{New: m.NewSlot}
	ptr := pool.Get().(*func(*testing.T))
	*ptr = rawPar
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "stdlib_slices_collect_user_seq_write_through",
			testSrc: `package p
import (
	"iter"
	"slices"
	"testing"
)
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
func ptrSeq(p *func(*testing.T)) iter.Seq[*func(*testing.T)] {
	return func(yield func(*func(*testing.T)) bool) {
		_ = yield(p)
	}
}
func collectGeneric[Seq ~func(func(*func(*testing.T)) bool)](s Seq) []*func(*testing.T) {
	return slices.Collect(iter.Seq[*func(*testing.T)](s))
}
func init() {
	p0 := &enterHook
	ptrs := collectGeneric(ptrSeq(p0))
	*ptrs[0] = rawPar
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "stdlib_maps_insert_user_seq2_write_through",
			testSrc: `package p
import (
	"iter"
	"maps"
	"testing"
)
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
func ptrSeq2(p *func(*testing.T)) iter.Seq2[string, *func(*testing.T)] {
	return func(yield func(string, *func(*testing.T)) bool) {
		_ = yield("k", p)
	}
}
func init() {
	p0 := &enterHook
	m := map[string]*func(*testing.T){}
	maps.Insert(m, ptrSeq2(p0))
	*m["k"] = rawPar
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "generic_seq_range_type_param_write_through",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
type yieldFn func(*func(*testing.T)) bool
func makeSeq(p *func(*testing.T)) func(yieldFn) {
	return func(yield yieldFn) {
		_ = yield(p)
	}
}
func fillRange[Yield ~func(*func(*testing.T)) bool, Seq ~func(Yield)](s Seq, fn func(*testing.T)) {
	for p := range s {
		*p = fn
	}
}
func init() {
	p0 := &enterHook
	s := makeSeq(p0)
	fillRange(s, rawPar)
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
		{
			name: "generic_func_call_type_param_write_through",
			testSrc: `package p
import "testing"
func rawPar(t *testing.T) { t.Parallel() }
var enterHook = func(*testing.T) {}
func callGetter[Fn ~func() *func(*testing.T)](f Fn, fn func(*testing.T)) {
	*f() = fn
}
func init() {
	p0 := &enterHook
	callGetter(func() *func(*testing.T) { return p0 }, rawPar)
}
func TestSeam(t *testing.T) {
	enterHook(t)
	withSeam(func() int { return 1 }, func() {})
}
`,
			wantSeam: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkg := mustTypecheckPackage(t, "example.com/p", map[string]string{
				"seam.go":      seamFile,
				"seam_test.go": tc.testSrc,
			})
			if tc.name == "stdlib_maps_copy_mutator" {
				if pkg.Imports["maps"] == nil || pkg.Imports["maps"].Module != nil {
					t.Fatalf("mustTypecheckPackage stdlib Imports[maps] = %+v, want non-nil with Module == nil", pkg.Imports["maps"])
				}
			}
			seamNodes := bracketedSeamNodes(true, pkg)
			if tc.wantSeam && len(seamNodes) != 0 {
				t.Fatalf("%s: bracketedSeamNodes len = %d, want 0", tc.name, len(seamNodes))
			}
			if !tc.wantSeam && len(seamNodes) != 2 {
				t.Fatalf("%s: bracketedSeamNodes len = %d, want 2", tc.name, len(seamNodes))
			}
			fact := FactOf(true, pkg, false)
			state := Compose([]GraphPackage{
				{ImportPath: "example.com/p", PkgPath: "example.com/p", Class: MutableLocalPackage},
			}, map[string][]Fact{
				"example.com/p": {fact},
			}, "example.com/p", nil, false, true)
			_, hasSeam := state.CulpritSites["example.com/p.seamHook"]
			if hasSeam != tc.wantSeam {
				t.Fatalf("Compose(%s).CulpritSites = %+v (hasSeam=%v, want %v)", tc.name, state.CulpritSites, hasSeam, tc.wantSeam)
			}
		})
	}
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }

func mustTypecheckWithStdImp(t *testing.T, stdImp types.Importer, pkgPath string, files map[string]string, deps map[string]*types.Package) *packages.Package {
	t.Helper()
	fset := token.NewFileSet()
	var names []string
	for name := range files {
		names = append(names, name)
	}
	var syntax []*ast.File
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, files[name], parser.ParseComments)
		if err != nil {
			t.Fatalf("ParseFile(%s/%s): %v", pkgPath, name, err)
		}
		syntax = append(syntax, f)
	}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Instances:  make(map[*ast.Ident]types.Instance),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Implicits:  make(map[ast.Node]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Scopes:     make(map[ast.Node]*types.Scope),
	}
	conf := types.Config{
		Importer: importerFunc(func(path string) (*types.Package, error) {
			if tp, ok := deps[path]; ok {
				return tp, nil
			}
			return stdImp.Import(path)
		}),
	}
	typesPkg, err := conf.Check(pkgPath, fset, syntax, info)
	if err != nil {
		t.Fatalf("types.Check(%s): %v", pkgPath, err)
	}
	return &packages.Package{
		ID:        pkgPath,
		PkgPath:   pkgPath,
		Name:      typesPkg.Name(),
		Fset:      fset,
		Syntax:    syntax,
		Types:     typesPkg,
		TypesInfo: info,
		Imports:   syntheticPackageImports(typesPkg, deps),
		Module:    &packages.Module{Path: "example.com/mod"},
	}
}

func inMemoryStdImporter(t *testing.T) types.Importer {
	t.Helper()
	stdSrcs := map[string]string{
		"sync": `package sync
type Mutex struct{}
func (*Mutex) Lock()   {}
func (*Mutex) Unlock() {}
type RWMutex struct{}
func (*RWMutex) Lock()    {}
func (*RWMutex) Unlock()  {}
func (*RWMutex) RLock()   {}
func (*RWMutex) RUnlock() {}
type Once struct{}
func (*Once) Do(f func()) { f() }
`,
		"sync/atomic": `package atomic
import "unsafe"
func LoadUint32(addr *uint32) uint32                                            { return *addr }
func StoreUint32(addr *uint32, v uint32)                                        { *addr = v }
func LoadPointer(addr *unsafe.Pointer) unsafe.Pointer                           { return *addr }
func CompareAndSwapPointer(addr *unsafe.Pointer, old, new unsafe.Pointer) bool { return true }
`,
		"syscall": `package syscall
type Errno uintptr
func (Errno) Error() string { return "" }
const EINVAL Errno = 22
func Syscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno)                  { return 0, 0, 0 }
func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno) { return 0, 0, 0 }
func Getpid() int { return 1 }
`,
		"reflect": `package reflect
type StructTag string
func (StructTag) Get(key string) string { return "" }
type StructField struct {
	Name      string
	PkgPath   string
	Type      Type
	Tag       StructTag
	Index     []int
	Anonymous bool
}
type Type interface {
	NumField() int
	Field(i int) StructField
	Implements(u Type) bool
	Elem() Type
	Name() string
}
type Value struct{}
func (Value) FieldByIndex(index []int) Value { return Value{} }
func TypeOf(i any) Type                      { return nil }
func ValueOf(i any) Value                    { return Value{} }
`,
		"strings": `package strings
func ToLower(s string) string { return s }
`,
		"fmt": `package fmt
func Sprint(a ...any) string                 { return "" }
func Sprintf(format string, a ...any) string { return format }
`,
		"slices": `package slices
func Reverse[S ~[]E, E any](s S) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
`,
		"encoding/json": `package json
func Unmarshal(data []byte, v any) error { return nil }
`,
		"bytes": `package bytes
func Equal(a, b []byte) bool { return string(a) == string(b) }
`,
	}
	built := make(map[string]*types.Package, len(stdSrcs))
	for path, src := range stdSrcs {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "std.go", src, 0)
		if err != nil {
			t.Fatalf("ParseFile(std %s): %v", path, err)
		}
		tp, err := (&types.Config{
			Importer: importerFunc(func(imp string) (*types.Package, error) {
				if imp == "unsafe" {
					return types.Unsafe, nil
				}
				return nil, fmt.Errorf("unexpected std import %q", imp)
			}),
		}).Check(path, fset, []*ast.File{f}, nil)
		if err != nil {
			t.Fatalf("types.Check(std %s): %v", path, err)
		}
		built[path] = tp
	}
	return importerFunc(func(path string) (*types.Package, error) {
		if path == "unsafe" {
			return types.Unsafe, nil
		}
		tp, ok := built[path]
		if !ok {
			return nil, fmt.Errorf("missing in-memory stdlib stub for %q", path)
		}
		return tp, nil
	})
}

func TestStructuralDischargesAndCrossVariantIntersection(t *testing.T) {
	stdImp := inMemoryStdImporter(t)
	mustTypecheckWithDeps := func(t *testing.T, pkgPath string, files map[string]string, deps map[string]*types.Package) *packages.Package {
		return mustTypecheckWithStdImp(t, stdImp, pkgPath, files, deps)
	}
	// 1. Domain 1 (mapping): mechanical syscall + sync.Mutex + unsafe.Slice bookkeeping verification,
	// audited gate, pure-Go / lockless / FuncLit / exported rejections, and cross-variant Declares intersection.
	cleanMapperSrc := `package unix
import (
	"sync"
	"syscall"
	"unsafe"
)
type mmapper struct {
	sync.Mutex
	active map[*byte][]byte
	mmap   func(addr, length uintptr, prot, flags, fd int, offset int64) (uintptr, error)
	munmap func(addr uintptr, length uintptr) error
}
type mremapMmapper struct {
	mmapper
}
var mapper = &mremapMmapper{
	mmapper: mmapper{
		active: make(map[*byte][]byte),
		mmap:   mmapSyscall,
		munmap: munmapSyscall,
	},
}
func mmapSyscall(addr, length uintptr, prot, flags, fd int, offset int64) (uintptr, error) {
	r0, _, e1 := syscall.Syscall6(9, addr, length, uintptr(prot), uintptr(flags), uintptr(fd), uintptr(offset))
	if e1 != 0 {
		return 0, e1
	}
	return r0, nil
}
func munmapSyscall(addr uintptr, length uintptr) error {
	_, _, e1 := syscall.Syscall(11, addr, length, 0)
	if e1 != 0 {
		return e1
	}
	return nil
}
func (m *mmapper) Mmap(fd int, offset int64, length int, prot int, flags int) ([]byte, error) {
	if length <= 0 {
		return nil, syscall.EINVAL
	}
	addr, err := m.mmap(0, uintptr(length), prot, flags, fd, offset)
	if err != nil {
		return nil, err
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(addr)), length)
	p := &b[cap(b)-1]
	m.Lock()
	defer m.Unlock()
	m.active[p] = b
	return b, nil
}
func (m *mmapper) Munmap(data []byte) error {
	if len(data) == 0 || len(data) != cap(data) {
		return syscall.EINVAL
	}
	p := &data[cap(data)-1]
	m.Lock()
	defer m.Unlock()
	b := m.active[p]
	if b == nil || &b[0] != &data[0] {
		return syscall.EINVAL
	}
	if err := m.munmap(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b))); err != nil {
		return err
	}
	delete(m.active, p)
	return nil
}
func Mmap(fd int, offset int64, length int, prot int, flags int) ([]byte, error) {
	return mapper.Mmap(fd, offset, length, prot, flags)
}
func Munmap(b []byte) error { return mapper.Munmap(b) }
`
	unixClean := mustTypecheckWithDeps(t, "example.com/unix", map[string]string{"mmap.go": cleanMapperSrc}, nil)
	factUnixAudited := FactOf(true, unixClean, false)
	if !reflect.DeepEqual(factUnixAudited.MappingDischarges, []string{"example.com/unix.mapper"}) {
		t.Fatalf("FactOf(audited=true) MappingDischarges = %v, want [example.com/unix.mapper]", factUnixAudited.MappingDischarges)
	}
	if factUnaudited := FactOf(false, unixClean, false); len(factUnaudited.MappingDischarges) != 0 {
		t.Fatalf("FactOf(audited=false) MappingDischarges = %v, want empty", factUnaudited.MappingDischarges)
	}
	unixMeta := []GraphPackage{{ImportPath: "example.com/unix", PkgPath: "example.com/unix", Class: MutableLocalPackage}}
	if st := Compose(unixMeta, map[string][]Fact{"example.com/unix": {factUnixAudited}}, "example.com/unix", nil, false, false); st.Downgraded != "" {
		t.Fatalf("clean mapping Compose downgraded: %q", st.Downgraded)
	}
	// Cross-variant intersection: if unix [unix.test] mutates mapper.mmap, MappingDischarges is absent in the test variant and Compose must refuse!
	unixTestVariant := mustTypecheckWithDeps(t, "example.com/unix", map[string]string{
		"mmap.go":      cleanMapperSrc,
		"mmap_test.go": "package unix\nfunc SwapForTest() { mapper.mmap = mmapSyscall }\n",
	}, nil)
	factUnixTest := FactOf(true, unixTestVariant, false)
	if len(factUnixTest.MappingDischarges) != 0 {
		t.Fatalf("expected callable-field mutation in test variant to block MappingDischarges, got %v", factUnixTest.MappingDischarges)
	}
	if st := Compose(unixMeta, map[string][]Fact{"example.com/unix": {factUnixAudited, factUnixTest}}, "example.com/unix", nil, true, false); !strings.Contains(st.Downgraded, "example.com/unix.mapper is mutated") {
		t.Fatalf("cross-variant mapping mutation failed to block discharge: %q", st.Downgraded)
	}
	for _, badMap := range []struct {
		name string
		src  string
	}{
		{
			name: "pure_go_make_slice",
			src: strings.Replace(cleanMapperSrc,
				"r0, _, e1 := syscall.Syscall6(9, addr, length, uintptr(prot), uintptr(flags), uintptr(fd), uintptr(offset))\n\tif e1 != 0 {\n\t\treturn 0, e1\n\t}\n\treturn r0, nil",
				"b := make([]byte, length)\n\treturn uintptr(unsafe.Pointer(&b[0])), nil", 1),
		},
		{
			name: "impure_syscall_getpid_in_mmap_helper",
			src: strings.Replace(cleanMapperSrc,
				"r0, _, e1 := syscall.Syscall6(",
				"_ = syscall.Getpid()\n\tr0, _, e1 := syscall.Syscall6(", 1),
		},
		{
			name: "funclit_active_mutation_outside_lock",
			src: strings.Replace(cleanMapperSrc,
				"m.active[p] = b",
				"m.active[p] = b\n\tf := func() { delete(m.active, p) }\n\t_ = f", 1),
		},
		{
			name: "conditional_non_deferred_unlock",
			src: strings.Replace(cleanMapperSrc,
				"m.Lock()\n\tdefer m.Unlock()\n\tm.active[p] = b",
				"m.Lock()\n\tif length == 1 { m.Unlock() }\n\tm.active[p] = b\n\tm.Unlock()", 1),
		},
		{
			name: "exported_mapper_var",
			src:  strings.Replace(strings.ReplaceAll(cleanMapperSrc, "mapper.", "Mapper."), "var mapper =", "var Mapper =", 1),
		},
	} {
		t.Run("mapping_"+badMap.name, func(t *testing.T) {
			pkg := mustTypecheckWithDeps(t, "example.com/unix", map[string]string{"mmap.go": badMap.src}, nil)
			if f := FactOf(true, pkg, false); len(f.MappingDischarges) != 0 {
				t.Fatalf("%s unexpectedly discharged: %v", badMap.name, f.MappingDischarges)
			}
		})
	}

	// 2. Domain 2 (memo): mechanical reflect.Type cache + RWMutex + init-only reflect.Type sentinel + post-store immutability.
	cleanMemoSrc := `package yaml
import (
	"reflect"
	"strings"
	"sync"
)
type Unmarshaler interface { UnmarshalYAML() error }
var unmarshalerType reflect.Type
func init() {
	var v Unmarshaler
	unmarshalerType = reflect.TypeOf(&v).Elem()
}
type fieldInfo struct {
	key    string
	num    int
	inline []int
}
type structInfo struct {
	fieldsList []fieldInfo
	fieldsMap  map[string]fieldInfo
}
var structMap = make(map[reflect.Type]*structInfo)
var fieldMapMutex sync.RWMutex
func getStructInfo(st reflect.Type) (*structInfo, error) {
	fieldMapMutex.RLock()
	sinfo, found := structMap[st]
	fieldMapMutex.RUnlock()
	if found {
		return sinfo, nil
	}
	n := st.NumField()
	fieldsMap := make(map[string]fieldInfo)
	var fieldsList []fieldInfo
	for i := 0; i != n; i++ {
		field := st.Field(i)
		if field.PkgPath != "" || field.Type.Implements(unmarshalerType) {
			continue
		}
		key := strings.ToLower(field.Name)
		info := fieldInfo{key: key, num: i, inline: append([]int{i}, field.Index...)}
		fieldsMap[key] = info
		fieldsList = append(fieldsList, info)
	}
	sinfo = &structInfo{fieldsList: fieldsList, fieldsMap: fieldsMap}
	fieldMapMutex.Lock()
	structMap[st] = sinfo
	fieldMapMutex.Unlock()
	return sinfo, nil
}
func readFieldByIdx(v reflect.Value, idx []int) reflect.Value {
	return v.FieldByIndex(idx)
}
func FieldCount(st reflect.Type) int {
	si, _ := getStructInfo(st)
	if len(si.fieldsList) > 0 {
		_ = readFieldByIdx(reflect.Value{}, si.fieldsList[0].inline)
	}
	return len(si.fieldsList)
}
`
	yamlClean := mustTypecheckWithDeps(t, "example.com/yaml", map[string]string{"yaml.go": cleanMemoSrc}, nil)
	factYamlAudited := FactOf(true, yamlClean, false)
	if !reflect.DeepEqual(factYamlAudited.MemoDischarges, []string{"example.com/yaml.structMap"}) {
		t.Fatalf("FactOf(audited=true) MemoDischarges = %v, want [example.com/yaml.structMap]", factYamlAudited.MemoDischarges)
	}
	if factYamlUn := FactOf(false, yamlClean, false); len(factYamlUn.MemoDischarges) != 0 {
		t.Fatalf("FactOf(audited=false) MemoDischarges = %v, want empty", factYamlUn.MemoDischarges)
	}
	for _, badMemo := range []struct {
		name  string
		files map[string]string
	}{
		{
			name: "map_iteration_in_memoFn",
			files: map[string]string{
				"yaml.go": strings.Replace(cleanMemoSrc,
					"sinfo = &structInfo{fieldsList: fieldsList, fieldsMap: fieldsMap}",
					"for _, v := range fieldsMap { fieldsList = append(fieldsList, v) }\n\tsinfo = &structInfo{fieldsList: fieldsList, fieldsMap: fieldsMap}", 1),
			},
		},
		{
			name: "funclit_inside_memoFn_storing_without_lock",
			files: map[string]string{
				"yaml.go": strings.Replace(cleanMemoSrc,
					"return sinfo, nil",
					"f := func() { structMap[st] = sinfo }; _ = f\n\treturn sinfo, nil", 1),
			},
		},
		{
			name: "pointer_format_verb_hash_v_in_memoFn",
			files: map[string]string{
				"yaml.go": strings.Replace(
					strings.Replace(cleanMemoSrc, "\"strings\"", "\"fmt\"\n\t\"strings\"", 1),
					"key := strings.ToLower(field.Name)",
					"key := fmt.Sprintf(\"%#v\", st) + strings.ToLower(field.Name)", 1),
			},
		},
		{
			name: "post_store_field_write",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc Mutate(t reflect.Type) { si, _ := getStructInfo(t); si.fieldsList[0].num = 99 }\n",
			},
		},
		{
			name: "post_store_map_field_write",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc MutateMap(t reflect.Type) { si, _ := getStructInfo(t); si.fieldsMap[\"x\"] = fieldInfo{} }\n",
			},
		},
		{
			name: "aliasing_append_on_protected_slice_field",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc AliasAppend(t reflect.Type) []int { si, _ := getStructInfo(t); return append(si.fieldsList[0].inline, 42) }\n",
			},
		},
		{
			name: "direct_return_protected_slice_without_local",
			files: map[string]string{
				"yaml.go":      strings.Replace(cleanMemoSrc, "_ = readFieldByIdx(reflect.Value{}, si.fieldsList[0].inline)", "", 1),
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc LeakInline(t reflect.Type) []int { si, _ := getStructInfo(t); return si.fieldsList[0].inline }\n",
			},
		},
		{
			name: "direct_struct_lit_escape_protected_slice",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport \"reflect\"\ntype Box struct{ S []int }\nfunc BoxInline(t reflect.Type) Box { si, _ := getStructInfo(t); return Box{S: si.fieldsList[0].inline} }\n",
			},
		},
		{
			name: "direct_slices_reverse_protected_slice",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport (\n\t\"reflect\"\n\t\"slices\"\n)\nfunc Rev(t reflect.Type) { si, _ := getStructInfo(t); slices.Reverse(si.fieldsList) }\n",
			},
		},
		{
			name: "intra_pkg_any_helper_on_tainted_slice",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc takeAny(x any) { _ = x }\nfunc PassTainted(t reflect.Type) { si, _ := getStructInfo(t); inl := si.fieldsList[0].inline; takeAny(inl) }\n",
			},
		},
		{
			name: "varspec_interface_boxing_protected",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc BoxVar(t reflect.Type) any { si, _ := getStructInfo(t); var a any = si; return a }\n",
			},
		},
		{
			name: "tuple_assign_interface_boxing_protected",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc BoxTuple(t reflect.Type) any { var a any; var err error; a, err = getStructInfo(t); _ = err; return a }\n",
			},
		},
		{
			name: "complit_slice_any_boxing_protected",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc BoxSlice(t reflect.Type) []any { si, _ := getStructInfo(t); return []any{si} }\n",
			},
		},
		{
			name: "append_slice_any_boxing_protected",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc BoxAppend(t reflect.Type) []any { si, _ := getStructInfo(t); var out []any; return append(out, si) }\n",
			},
		},
		{
			name: "send_chan_any_boxing_protected",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc BoxChan(t reflect.Type, ch chan<- any) { si, _ := getStructInfo(t); ch <- si }\n",
			},
		},
		{
			name: "generic_ptr_clobber_protected",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc clobber[T any](p *T) { var z T; *p = z }\nfunc MutGen(t reflect.Type) { si, _ := getStructInfo(t); clobber(si) }\n",
			},
		},
		{
			name: "unsafe_pointer_conv_protected",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport (\n\t\"reflect\"\n\t\"unsafe\"\n)\nfunc UnsafeLeak(t reflect.Type) unsafe.Pointer { si, _ := getStructInfo(t); return unsafe.Pointer(si) }\n",
			},
		},
		{
			name: "pointer_identity_comparison_top_level",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc Same(a, b reflect.Type) bool { sa, _ := getStructInfo(a); sb, _ := getStructInfo(b); return sa == sb }\n",
			},
		},
		{
			name: "pointer_identity_comparison_nested_fieldInfo",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc SameElem(a, b reflect.Type) bool { sa, _ := getStructInfo(a); sb, _ := getStructInfo(b); return &sa.fieldsList[0] == &sb.fieldsList[0] }\n",
			},
		},
		{
			name: "exported_structMap_var",
			files: map[string]string{
				"yaml.go": strings.ReplaceAll(cleanMemoSrc, "structMap", "StructMap"),
			},
		},
		{
			name: "ptr_to_basic_field_type_forbidden",
			files: map[string]string{
				"yaml.go": strings.Replace(cleanMemoSrc,
					"fieldsMap  map[string]fieldInfo",
					"fieldsMap  map[string]fieldInfo\n\tcount      *int", 1),
			},
		},
		{
			name: "ptr_to_basic_field_mutated",
			files: map[string]string{
				"yaml.go": strings.Replace(
					strings.Replace(cleanMemoSrc,
						"fieldsMap  map[string]fieldInfo",
						"fieldsMap  map[string]fieldInfo\n\tcount      *int", 1),
					"sinfo = &structInfo{fieldsList: fieldsList, fieldsMap: fieldsMap}",
					"sinfo = &structInfo{fieldsList: fieldsList, fieldsMap: fieldsMap, count: new(int)}", 1),
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc BumpCount(t reflect.Type) { si, _ := getStructInfo(t); *si.count = 99 }\n",
			},
		},
		{
			name: "ptr_to_unnamed_struct_field",
			files: map[string]string{
				"yaml.go": strings.Replace(cleanMemoSrc,
					"fieldsMap  map[string]fieldInfo",
					"fieldsMap  map[string]fieldInfo\n\tmeta       *struct{ n int }", 1),
			},
		},
		{
			name: "array_of_slice_field_mutated",
			files: map[string]string{
				"yaml.go": strings.Replace(cleanMemoSrc,
					"fieldsMap  map[string]fieldInfo",
					"fieldsMap  map[string]fieldInfo\n\tbuckets    [2][]int", 1),
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc MutBucket(t reflect.Type) { si, _ := getStructInfo(t); b := si.buckets[0]; b[0] = 99 }\n",
			},
		},
		{
			name: "unnamed_struct_slice_field",
			files: map[string]string{
				"yaml.go": strings.Replace(cleanMemoSrc,
					"fieldsMap  map[string]fieldInfo",
					"fieldsMap  map[string]fieldInfo\n\tsub        struct{ s []int }", 1),
			},
		},
		{
			name: "backward_aliased_local_slice_append",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc Sneak(t reflect.Type) { si, _ := getStructInfo(t); orig := make([][]int, 1); out := orig[:0]; out = append(out, si.fieldsList[0].inline); _ = out; orig[0][0] = 99 }\n",
			},
		},
		{
			name: "uncalled_bound_method_val_mutating_slice",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc (si *structInfo) clobberInline() { si.fieldsList[0].inline[0] = 77 }\nfunc BindMut(t reflect.Type) func() { si, _ := getStructInfo(t); return si.clobberInline }\n",
			},
		},
		{
			name: "uncalled_bound_method_val_returning_tainted_slice",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc (si *structInfo) getInline() []int { return si.fieldsList[0].inline }\nfunc BindRet(t reflect.Type) func() []int { si, _ := getStructInfo(t); return si.getInline }\n",
			},
		},
		{
			name: "implicit_ptr_method_val_on_by_value_capsule",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc (f *fieldInfo) mutNum() { f.num = 5 }\nfunc BindByValPtrRecv(t reflect.Type) func() { si, _ := getStructInfo(t); fi := si.fieldsList[0]; return fi.mutNum }\n",
			},
		},
		{
			name: "unexported_iface_dispatch_returning_tainted_slice",
			files: map[string]string{
				"yaml.go":      cleanMemoSrc,
				"yaml_test.go": "package yaml\nimport \"reflect\"\ntype inlineGetter interface { rawInline() []int }\nfunc (si *structInfo) rawInline() []int { return si.fieldsList[0].inline }\nfunc MutViaUnexportedIface(t reflect.Type) { si, _ := getStructInfo(t); var g inlineGetter = si; s := g.rawInline(); s[0] = 88 }\n",
			},
		},
	} {
		t.Run("memo_"+badMemo.name, func(t *testing.T) {
			pkg := mustTypecheckWithDeps(t, "example.com/yaml", badMemo.files, nil)
			if f := FactOf(true, pkg, false); len(f.MemoDischarges) != 0 {
				t.Fatalf("%s unexpectedly discharged: %v", badMemo.name, f.MemoDischarges)
			}
		})
	}
	mutMemoPkg := mustTypecheckWithDeps(t, "example.com/yaml", map[string]string{
		"yaml.go":      cleanMemoSrc,
		"yaml_test.go": "package yaml\nimport \"reflect\"\nfunc Mutate(t reflect.Type) { si, _ := getStructInfo(t); si.fieldsList[0].num = 99 }\n",
	}, nil)
	yamlMeta := []GraphPackage{{ImportPath: "example.com/yaml", PkgPath: "example.com/yaml", Class: MutableLocalPackage}}
	if st := Compose(yamlMeta, map[string][]Fact{"example.com/yaml": {factYamlAudited, FactOf(true, mutMemoPkg, false)}}, "example.com/yaml", nil, true, false); !strings.Contains(st.Downgraded, "example.com/yaml.structMap is mutated") {
		t.Fatalf("cross-variant memo mutation failed to block discharge: %q", st.Downgraded)
	}

	// Direct unit checks on VerifyReadOnlyRefConfinement: promoted capsule structs must be write-free,
	// read-only bound MethodVal on a pointer capsule returning a scalar is accepted, and implicit &val.PtrMethod
	// or uncalled mutating/slice-returning bound MethodVal is rejected.
	t.Run("refconfine_capsule_field_write_rejected", func(t *testing.T) {
		pkg := mustTypecheckWithDeps(t, "example.com/captest", map[string]string{
			"cap.go": `package captest
var protected []int
type capsule struct {
	buf []int
	tag int
}
func wrap() *capsule {
	return &capsule{buf: protected, tag: 1}
}
func mutateTag(c *capsule) {
	c.tag = 2
}
`,
		}, nil)
		ok := refconfine.VerifyReadOnlyRefConfinement(pkg, refconfine.Config{
			AllowCompositeLitIntoSeedStruct: true,
			AllowReturnFromUnexportedFunc:   true,
			CanBeSeedStructCapsule:          func(*types.Named) bool { return true },
			SeedExpr: func(expr ast.Expr) (bool, bool) {
				if id, isID := expr.(*ast.Ident); isID && id.Name == "protected" {
					if v, isV := pkg.TypesInfo.Uses[id].(*types.Var); isV && v.Parent() == pkg.Types.Scope() {
						return true, true
					}
				}
				return false, false
			},
		})
		if ok {
			t.Fatal("VerifyReadOnlyRefConfinement unexpectedly accepted mutated capsule struct")
		}
	})
	t.Run("refconfine_bound_method_val_read_only_vs_mutating_or_implicit_addr", func(t *testing.T) {
		baseCap := `package captest
var protected []int
type capsule struct {
	buf []int
}
func wrap() *capsule {
	return &capsule{buf: protected}
}
func (c *capsule) firstOrZero() int {
	if len(c.buf) == 0 {
		return 0
	}
	return c.buf[0]
}
`
		runConfine := func(src string) bool {
			pkg := mustTypecheckWithDeps(t, "example.com/captest", map[string]string{"cap.go": src}, nil)
			return refconfine.VerifyReadOnlyRefConfinement(pkg, refconfine.Config{
				AllowCompositeLitIntoSeedStruct: true,
				AllowReturnFromUnexportedFunc:   true,
				CanBeSeedStructCapsule:          func(*types.Named) bool { return true },
				SeedExpr: func(expr ast.Expr) (bool, bool) {
					if id, isID := expr.(*ast.Ident); isID && id.Name == "protected" {
						if v, isV := pkg.TypesInfo.Uses[id].(*types.Var); isV && v.Parent() == pkg.Types.Scope() {
							return true, true
						}
					}
					return false, false
				},
			})
		}
		if !runConfine(baseCap + "func Reader() func() int { c := wrap(); return c.firstOrZero }\n") {
			t.Fatal("VerifyReadOnlyRefConfinement rejected read-only scalar bound MethodVal on pointer capsule")
		}
		if runConfine(baseCap + "func (c *capsule) leakBuf() []int { return c.buf }\nfunc BadLeak() func() []int { c := wrap(); return c.leakBuf }\n") {
			t.Fatal("VerifyReadOnlyRefConfinement accepted slice-returning bound MethodVal")
		}
		if runConfine(baseCap + "func (c *capsule) mutBuf() { c.buf[0] = 9 }\nfunc BadMut() func() { c := wrap(); return c.mutBuf }\n") {
			t.Fatal("VerifyReadOnlyRefConfinement accepted mutating bound MethodVal")
		}
		if runConfine(baseCap + "func ImplicitAddr() func() int { byVal := capsule{buf: protected}; return byVal.firstOrZero }\n") {
			t.Fatal("VerifyReadOnlyRefConfinement accepted implicit &byVal pointer-receiver MethodVal")
		}
	})

	// 3. Domain 3 (proto & grpc): multi-package type aliases (impl + filetype + protoimpl),
	// AllowedHelpers / InitHelper cross-package enforcement, ProtoExtAlias fixed-point,
	// MutatedStructTypes & DirectVarWrites cross-package revocation, and cross-variant Declares intersection.
	implSrc := `package impl
import (
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"
)
type NoUnkeyedLiterals struct{}
type Methods = struct {
	NoUnkeyedLiterals
	Marshal func() []byte
}
type EnumInfo struct {
	GoReflectType reflect.Type
	Desc          any
}
type MessageInfo struct {
	reflectMessageInfo
	GoReflectType reflect.Type
	Desc          any
	initMu        sync.Mutex
	initDone      uint32
	sizecache     int
	coderFields   map[int]int
	methods       Methods
}
type reflectMessageInfo struct {
	nilMessage atomicNilMessage
}
type atomicNilMessage struct {
	p unsafe.Pointer
}
type nilMsgWrapper struct {
	mi   *MessageInfo
	flag int
}
func (m *atomicNilMessage) Init(mi *MessageInfo) *nilMsgWrapper {
	if p := atomic.LoadPointer(&m.p); p != nil {
		return (*nilMsgWrapper)(p)
	}
	w := &nilMsgWrapper{mi: mi}
	atomic.CompareAndSwapPointer(&m.p, nil, unsafe.Pointer(w))
	return (*nilMsgWrapper)(atomic.LoadPointer(&m.p))
}
func (mi *MessageInfo) NilWrapper() *nilMsgWrapper {
	return mi.nilMessage.Init(mi)
}
func (mi *MessageInfo) init() {
	if atomic.LoadUint32(&mi.initDone) == 1 {
		return
	}
	mi.initOnce()
}
func (mi *MessageInfo) initOnce() {
	mi.initMu.Lock()
	defer mi.initMu.Unlock()
	if mi.initDone == 1 {
		return
	}
	mi.sizecache = 1
	mi.methods.Marshal = func() []byte { return nil }
	atomic.StoreUint32(&mi.initDone, 1)
}
func (mi *MessageInfo) Size() int {
	mi.init()
	return mi.sizecache
}
func (mi *MessageInfo) ProtoMethods() *Methods {
	mi.init()
	return &mi.methods
}
type msgWrapper struct {
	mi *MessageInfo
}
func (m *msgWrapper) messageInfo() *MessageInfo {
	return m.mi
}
func (m *msgWrapper) ProtoMethods() *Methods {
	m.messageInfo().init()
	return &m.messageInfo().methods
}
type ExtTypeDesc struct {
	Number int32
}
type ExtensionInfo struct {
	ExtendedType  any
	ExtensionType any
	Field         int32
	Name          string
	Tag           string
	mu            sync.Mutex
	init          uint32
	desc          any
	td            ExtTypeDesc
}
func InitExtensionInfo(xi *ExtensionInfo, desc any, goType reflect.Type) {
	_ = goType
	xi.desc = desc
}
func (xi *ExtensionInfo) lazyInit() {
	xi.mu.Lock()
	defer xi.mu.Unlock()
	if xi.init == 1 {
		return
	}
	xi.td.Number = xi.Field
	atomic.StoreUint32(&xi.init, 1)
}
func (xi *ExtensionInfo) NameOf() string {
	if atomic.LoadUint32(&xi.init) == 0 {
		xi.lazyInit()
	}
	return xi.Name
}
func (xi *ExtensionInfo) TypeDescriptor() *ExtTypeDesc {
	if atomic.LoadUint32(&xi.init) == 0 {
		xi.lazyInit()
	}
	return &xi.td
}
`
	implPkg := mustTypecheckWithDeps(t, "example.com/proto/internal/impl", map[string]string{"impl.go": implSrc}, nil)
	// Intra-package unexported-field write outside onceCone, uninitialized &mi.methods, &mi.methods.Marshal, or FuncLit inside onceCone must reject ProtoRoleMessage!
	for _, badImpl := range []struct {
		name string
		src  string
	}{
		{"outside_once_cone", implSrc + "\nfunc (mi *MessageInfo) TamperUnexported() { mi.sizecache = 99 }\n"},
		{"funclit_inside_once_cone", strings.Replace(implSrc, "mi.sizecache = 1", "f := func() { mi.sizecache = 1 }\n\tf()", 1)},
		{"addr_methods_without_init", implSrc + "\nfunc (mi *MessageInfo) BadMethods() *Methods { return &mi.methods }\n"},
		{"addr_methods_subfield", implSrc + "\nfunc (mi *MessageInfo) BadSub() *func() []byte { mi.init(); return &mi.methods.Marshal }\n"},
		{"addr_methods_reassigned_var", implSrc + "\nfunc BadReassign(a, b *MessageInfo) *Methods { m := a; m.init(); m = b; return &m.methods }\n"},
		{"wrapper_getter_without_init", implSrc + "\nfunc (m *msgWrapper) BadWrapMethods() *Methods { return &m.messageInfo().methods }\n"},
		{"wrapper_getter_mutated_field", implSrc + "\nfunc (m *msgWrapper) SwapMI(other *MessageInfo) { m.mi = other }\n"},
		{"exported_by_value_substruct_on_message_info", strings.Replace(implSrc, "sizecache     int", "sizecache     int\n\tExtra         struct{ X int }", 1)},
		{"exported_int_slice_on_message_info", strings.Replace(implSrc, "sizecache     int", "sizecache     int\n\tNums          []int", 1)},
		{"aliased_unexported_map_mutated_outside_once_cone", implSrc + "\nfunc (mi *MessageInfo) BadMutMap() { m := mi.coderFields; delete(m, 1) }\n"},
		{"cas_helper_ret_struct_mutated", implSrc + "\nfunc (mi *MessageInfo) MutCAS() { w := mi.nilMessage.Init(mi); w.flag = 1 }\n"},
		{"cas_stateful_closure_field", strings.Replace(
			strings.Replace(implSrc, "flag int", "flag int\n\tcb   func() int", 1),
			"w := &nilMsgWrapper{mi: mi}",
			"n := 0\n\tw := &nilMsgWrapper{mi: mi, cb: func() int { n++; return n }}", 1)},
		{"cas_exported_field_on_wrapper", strings.Replace(implSrc, "flag int", "Flag int", 1)},
		{"cas_non_param_message_info", strings.Replace(implSrc,
			"w := &nilMsgWrapper{mi: mi}",
			"w := &nilMsgWrapper{mi: globalMI}", 1) + "\nvar globalMI *MessageInfo\n"},
		{"cas_substruct_pointer_receiver_method", strings.Replace(implSrc,
			"flag int",
			"flag int\n\tsub  casSub", 1) + "\ntype casSub struct{ x int }\nfunc (s *casSub) Touch() {}\n"},
		{"stateful_message_info_desc_interface", strings.Replace(
			strings.Replace(implSrc,
				"sizecache     int",
				"sizecache     int\n\tlazyDesc      MsgDesc", 1),
			"mi.sizecache = 1",
			"mi.sizecache = 1\n\tmi.lazyDesc = &mutMsgDesc{name: \"a\"}", 1) +
			"\ntype MsgDesc interface{ MsgName() string }\ntype mutMsgDesc struct{ name string }\nfunc (d *mutMsgDesc) MsgName() string { return d.name }\nfunc (d *mutMsgDesc) SetName(s string) { d.name = s }\n"},
		{"once_cone_closure_mutates_captured_local", strings.Replace(implSrc,
			"mi.methods.Marshal = func() []byte { return nil }",
			"n := 0\n\tmi.methods.Marshal = func() []byte { n++; return nil }", 1)},
		{"once_cone_closure_mutates_captured_slice_via_helper", strings.Replace(implSrc,
			"mi.methods.Marshal = func() []byte { return nil }",
			"buf := make([]byte, 1)\n\tmi.methods.Marshal = func() []byte { clobberBuf(buf); return buf }", 1) +
			"\nfunc clobberBuf(b []byte) { b[0]++ }\n"},
		{"recursive_once_cone_funclit", strings.Replace(implSrc,
			"mi.sizecache = 1",
			"mi.fillRec(2)", 1) + "\nfunc (mi *MessageInfo) fillRec(n int) {\n\tif n <= 0 { f := func() { mi.sizecache = 1 }; f(); return }\n\tmi.fillRec(n - 1)\n}\n"},
	} {
		t.Run("impl_"+badImpl.name, func(t *testing.T) {
			pkg := mustTypecheckWithDeps(t, "example.com/proto/internal/impl", map[string]string{"impl.go": badImpl.src}, nil)
			for _, rt := range FactOf(true, pkg, false).ProtoRuntimeTypes {
				if rt.Type.Name == "MessageInfo" && rt.Role == protoaudit.ProtoRoleMessage {
					t.Fatalf("%s unexpectedly verified ProtoRoleMessage: %+v", badImpl.name, rt)
				}
			}
		})
	}
	for _, badRole := range []struct {
		name string
		role string
		typ  string
		src  string
	}{
		{
			name: "enum_exported_int_slice",
			role: protoaudit.ProtoRoleEnum,
			typ:  "EnumInfo",
			src:  strings.Replace(implSrc, "type EnumInfo struct {\n\tGoReflectType reflect.Type", "type EnumInfo struct {\n\tGoReflectType reflect.Type\n\tTags []int32", 1),
		},
		{
			name: "enum_aliased_unexported_slice_mutated",
			role: protoaudit.ProtoRoleEnum,
			typ:  "EnumInfo",
			src:  strings.Replace(implSrc, "type EnumInfo struct {\n\tGoReflectType reflect.Type", "type EnumInfo struct {\n\tGoReflectType reflect.Type\n\traw []byte", 1) + "\nfunc (ei *EnumInfo) Corrupt() { b := ei.raw; b[0] = 99 }\n",
		},
		{
			name: "ext_exported_by_value_substruct",
			role: protoaudit.ProtoRoleExtension,
			typ:  "ExtensionInfo",
			src:  strings.Replace(implSrc, "td            ExtTypeDesc", "td            ExtTypeDesc\n\tSub           ExtTypeDesc", 1),
		},
		{
			name: "ext_aliased_unexported_slice_mutated_outside_once",
			role: protoaudit.ProtoRoleExtension,
			typ:  "ExtensionInfo",
			src:  strings.Replace(implSrc, "td            ExtTypeDesc", "td            ExtTypeDesc\n\traw           []byte", 1) + "\nfunc (xi *ExtensionInfo) Corrupt() { s := xi.raw; s[0] = 99 }\n",
		},
	} {
		t.Run("impl_"+badRole.name, func(t *testing.T) {
			pkg := mustTypecheckWithDeps(t, "example.com/proto/internal/impl", map[string]string{"impl.go": badRole.src}, nil)
			for _, rt := range FactOf(true, pkg, false).ProtoRuntimeTypes {
				if rt.Type.Name == badRole.typ && rt.Role == badRole.role {
					t.Fatalf("%s unexpectedly verified %s (%v): %+v", badRole.name, badRole.typ, badRole.role, rt)
				}
			}
		})
	}
	// MessageInfo onceCone mutating an unrelated EnumInfo struct must record EnumInfo in MutatedStructTypes!
	implCrossFamily := mustTypecheckWithDeps(t, "example.com/proto/internal/impl", map[string]string{
		"impl.go": strings.Replace(implSrc, "mi.sizecache = 1", "mi.sizecache = 1\n\tclobberEnum(nil)", 1) +
			"\nfunc clobberEnum(ei *EnumInfo) { if ei != nil { ei.Desc = \"bad\" } }\n",
	}, nil)
	factCrossFamily := FactOf(true, implCrossFamily, false)
	if !slices.Contains(factCrossFamily.MutatedStructTypes, syntaxutil.TypeRef{Pkg: "example.com/proto/internal/impl", Name: "EnumInfo"}) {
		t.Fatalf("onceCone mutating unrelated EnumInfo failed to record EnumInfo in MutatedStructTypes: %+v", factCrossFamily.MutatedStructTypes)
	}

	filetypePkg := mustTypecheckWithDeps(t, "example.com/proto/internal/filetype", map[string]string{"build.go": `package filetype
import (
	"reflect"
	"example.com/proto/internal/impl"
)
type FileDescriptor interface{ ProtoFile() }
type fileDesc struct{ raw []byte }
func (*fileDesc) ProtoFile() {}
type DescBuilder struct {
	RawDescriptor []byte
	NumEnums      int32
	NumMessages   int32
	NumExtensions int32
}
type Out struct {
	File FileDescriptor
}
type Builder struct {
	File              DescBuilder
	GoTypes           []any
	DependencyIndexes []int32
	EnumInfos         []impl.EnumInfo
	MessageInfos      []impl.MessageInfo
	ExtensionInfos    []impl.ExtensionInfo
}
func (tb Builder) Build() Out {
	for i := range tb.EnumInfos {
		tb.EnumInfos[i] = impl.EnumInfo{
			GoReflectType: reflect.TypeOf(tb.GoTypes[i]),
			Desc:          i,
		}
	}
	for i := range tb.MessageInfos {
		tb.MessageInfos[i].GoReflectType = reflect.TypeOf(tb.GoTypes[i])
		tb.MessageInfos[i].Desc = i
	}
	for i := range tb.ExtensionInfos {
		impl.InitExtensionInfo(&tb.ExtensionInfos[i], i, reflect.TypeOf(tb.GoTypes[0]))
	}
	return Out{File: &fileDesc{raw: tb.File.RawDescriptor}}
}
`}, map[string]*types.Package{"example.com/proto/internal/impl": implPkg.Types})

	badBuilderPkg := mustTypecheckWithDeps(t, "example.com/proto/internal/filetype", map[string]string{"build.go": `package filetype
import (
	"reflect"
	"example.com/proto/internal/impl"
)
type FileDescriptor interface{ ProtoFile() }
type fileDesc struct{ raw []byte }
func (*fileDesc) ProtoFile() {}
type mutMsgDesc struct{ name string }
func (d *mutMsgDesc) SetName(s string) { d.name = s }
type DescBuilder struct {
	RawDescriptor []byte
	NumEnums      int32
	NumMessages   int32
	NumExtensions int32
}
type Out struct {
	File FileDescriptor
}
type Builder struct {
	File              DescBuilder
	GoTypes           []any
	DependencyIndexes []int32
	EnumInfos         []impl.EnumInfo
	MessageInfos      []impl.MessageInfo
	ExtensionInfos    []impl.ExtensionInfo
}
func (tb Builder) Build() Out {
	for i := range tb.MessageInfos {
		tb.MessageInfos[i].GoReflectType = reflect.TypeOf(tb.GoTypes[i])
		tb.MessageInfos[i].Desc = &mutMsgDesc{name: "init"}
	}
	return Out{File: &fileDesc{raw: tb.File.RawDescriptor}}
}
`}, map[string]*types.Package{"example.com/proto/internal/impl": implPkg.Types})
	for _, rt := range FactOf(true, badBuilderPkg, false).ProtoRuntimeTypes {
		if rt.Type.Name == "Builder" && rt.Role == protoaudit.ProtoRoleBuilder {
			t.Fatalf("builder assigning mutable direct Desc struct unexpectedly verified ProtoRoleBuilder: %+v", rt)
		}
	}

	protoimplPkg := mustTypecheckWithDeps(t, "example.com/proto/runtime/protoimpl", map[string]string{"impl.go": `package protoimpl
import (
	"example.com/proto/internal/filetype"
	"example.com/proto/internal/impl"
)
type TypeBuilder = filetype.Builder
type DescBuilder = filetype.DescBuilder
type FileDescriptor = filetype.FileDescriptor
type EnumInfo = impl.EnumInfo
type MessageInfo = impl.MessageInfo
type ExtensionInfo = impl.ExtensionInfo
type Methods = impl.Methods
type ExtTypeDesc = impl.ExtTypeDesc
`}, map[string]*types.Package{
		"example.com/proto/internal/impl":     implPkg.Types,
		"example.com/proto/internal/filetype": filetypePkg.Types,
	})

	grpcPkg := mustTypecheckWithDeps(t, "example.com/grpc", map[string]string{"service.go": `package grpc
type MethodDesc struct {
	MethodName string
	Handler    func(srv any) error
}
type StreamDesc struct {
	StreamName string
	Handler    func(srv any) error
}
type ServiceDesc struct {
	ServiceName string
	HandlerType any
	Methods     []MethodDesc
	Streams     []StreamDesc
	Metadata    any
}
`}, nil)

	pbSrc := `package pb
import (
	"example.com/grpc"
	"example.com/proto/runtime/protoimpl"
)
type Mode int32
type Msg struct{ X int }
var File_x_proto protoimpl.FileDescriptor
var file_x_proto_rawDesc = []byte{0x0a, 0x01}
var file_x_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_x_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_x_proto_extTypes = []protoimpl.ExtensionInfo{{
	ExtendedType:  (*Msg)(nil),
	ExtensionType: (*int32)(nil),
	Field:         100,
	Name:          "pb.opt",
	Tag:           "varint,100,opt",
}}
var E_Opt = &file_x_proto_extTypes[0]
var file_x_proto_goTypes = []any{
	(Mode)(0),
	(*Msg)(nil),
}
var file_x_proto_depIdxs = []int32{0}
func init() { file_x_proto_init() }
func file_x_proto_init() {
	if File_x_proto != nil {
		return
	}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			RawDescriptor: file_x_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 1,
		},
		GoTypes:           file_x_proto_goTypes,
		DependencyIndexes: file_x_proto_depIdxs,
		EnumInfos:         file_x_proto_enumTypes,
		MessageInfos:      file_x_proto_msgTypes,
		ExtensionInfos:    file_x_proto_extTypes,
	}.Build()
	File_x_proto = out.File
	file_x_proto_goTypes = nil
	file_x_proto_depIdxs = nil
}
func ReadMsg() int { return file_x_proto_msgTypes[0].Size() }
type SvcServer interface{ Ping() }
func _Svc_Ping_Handler(srv any) error { return nil }
var Svc_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "pb.Svc",
	HandlerType: (*SvcServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Ping", Handler: _Svc_Ping_Handler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "x.proto",
}
func RegisterSvc(reg func(*grpc.ServiceDesc)) {
	reg(&Svc_ServiceDesc)
}
`
	pbDeps := map[string]*types.Package{
		"example.com/proto/internal/impl":     implPkg.Types,
		"example.com/proto/internal/filetype": filetypePkg.Types,
		"example.com/proto/runtime/protoimpl": protoimplPkg.Types,
		"example.com/grpc":                    grpcPkg.Types,
	}
	pbPkg := mustTypecheckWithDeps(t, "example.com/pb", map[string]string{"x.pb.go": pbSrc}, pbDeps)
	// Package-scope FuncLit writing File_x_proto must reject ProtoClusters!
	pbBlankLit := mustTypecheckWithDeps(t, "example.com/pb", map[string]string{
		"x.pb.go": pbSrc + "\nvar _ = func() { File_x_proto = nil }\n",
	}, pbDeps)
	if len(FactOf(true, pbBlankLit, false).ProtoClusters) != 0 {
		t.Fatal("package-scope FuncLit writing File_x_proto unexpectedly retained ProtoClusters")
	}

	pbAliasDeps := map[string]*types.Package{
		"example.com/proto/internal/impl":     implPkg.Types,
		"example.com/proto/internal/filetype": filetypePkg.Types,
		"example.com/proto/runtime/protoimpl": protoimplPkg.Types,
		"example.com/grpc":                    grpcPkg.Types,
		"example.com/pb":                      pbPkg.Types,
	}
	pbAliasPkg := mustTypecheckWithDeps(t, "example.com/pbalias", map[string]string{"alias.go": `package pbalias
import (
	"fmt"
	"example.com/grpc"
	"example.com/pb"
	"example.com/proto/runtime/protoimpl"
)
var E_Alias = pb.E_Opt
func Use() (int, string) {
	var localMethods protoimpl.Methods
	localMethods.Marshal = nil
	_ = localMethods
	_ = fmt.Sprint(&pb.Svc_ServiceDesc)
	return pb.ReadMsg(), E_Alias.NameOf()
}
func RegisterRemote(reg func(*grpc.ServiceDesc)) { reg(&pb.Svc_ServiceDesc) }
`}, pbAliasDeps)

	protoMeta := []GraphPackage{
		{ImportPath: "example.com/pbalias", PkgPath: "example.com/pbalias", Imports: []string{"example.com/pb", "example.com/grpc", "example.com/proto/runtime/protoimpl"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/pb", PkgPath: "example.com/pb", Imports: []string{"example.com/proto/runtime/protoimpl", "example.com/grpc"}, Class: MutableLocalPackage},
		{ImportPath: "example.com/proto/runtime/protoimpl", PkgPath: "example.com/proto/runtime/protoimpl", Imports: []string{"example.com/proto/internal/filetype", "example.com/proto/internal/impl"}, Class: PinnedPackage, Pin: "example.com/proto@v9.9.9"},
		{ImportPath: "example.com/proto/internal/filetype", PkgPath: "example.com/proto/internal/filetype", Imports: []string{"example.com/proto/internal/impl"}, Class: PinnedPackage, Pin: "example.com/proto@v9.9.9"},
		{ImportPath: "example.com/proto/internal/impl", PkgPath: "example.com/proto/internal/impl", Class: PinnedPackage, Pin: "example.com/proto@v9.9.9"},
		{ImportPath: "example.com/grpc", PkgPath: "example.com/grpc", Class: PinnedPackage, Pin: "example.com/grpc@v9.9.9"},
	}
	baseProtoFacts := func() map[string][]Fact {
		return map[string][]Fact{
			"example.com/pbalias":                 {FactOf(true, pbAliasPkg, false)},
			"example.com/pb":                      {FactOf(true, pbPkg, false)},
			"example.com/proto/runtime/protoimpl": {FactOf(true, protoimplPkg, false)},
			"example.com/proto/internal/filetype": {FactOf(true, filetypePkg, false)},
			"example.com/proto/internal/impl":     {FactOf(true, implPkg, false)},
			"example.com/grpc":                    {FactOf(true, grpcPkg, false)},
		}
	}
	// Unattested singleSubject=false must refuse.
	if st := Compose(protoMeta, baseProtoFacts(), "example.com/pbalias", nil, false, false); st.Downgraded == "" {
		t.Fatal("expected singleSubject=false to refuse protobuf cluster and grpc ServiceDesc")
	}
	// Attested singleSubject=true must discharge all cluster vars, E_Opt, E_Alias, and Svc_ServiceDesc (even with reg(&pb.Svc_ServiceDesc))!
	stClean := Compose(protoMeta, baseProtoFacts(), "example.com/pbalias", nil, true, false)
	if stClean.Downgraded != "" {
		bf := baseProtoFacts()
		t.Fatalf("clean proto+grpc+alias Compose(singleSubject=true) downgraded: %q\npbalias=%+v\npb.ProtoClusters=%+v\nfiletype.RT=%+v filetype.Mut=%+v\nimpl.RT=%+v impl.Mut=%+v",
			stClean.Downgraded,
			bf["example.com/pbalias"][0].ProtoExtAliases,
			bf["example.com/pb"][0].ProtoClusters,
			bf["example.com/proto/internal/filetype"][0].ProtoRuntimeTypes,
			bf["example.com/proto/internal/filetype"][0].MutatedStructTypes,
			bf["example.com/proto/internal/impl"][0].ProtoRuntimeTypes,
			bf["example.com/proto/internal/impl"][0].MutatedStructTypes,
		)
	}
	dischargedList := strings.Split(stClean.AttestationDischarges, ",")
	for _, wantVar := range []string{"example.com/pb.file_x_proto_msgTypes", "example.com/pb.E_Opt", "example.com/pbalias.E_Alias", "example.com/pb.Svc_ServiceDesc"} {
		if !slices.Contains(dischargedList, wantVar) {
			t.Fatalf("AttestationDischarges = %q, missing %s", stClean.AttestationDischarges, wantVar)
		}
	}

	// Cross-package direct variable writes, dot-imported writes, field address-takes,
	// pointer escapes (unsafe.Pointer, reflect.ValueOf, json.Unmarshal), clear(slice),
	// and range-LHS element mutations must revoke ProtoClusters / GrpcServiceVars!
	for _, xpkgCase := range []struct {
		name string
		src  string
		want string
	}{
		{
			name: "cross_pkg_file_var_reassignment",
			src:  "package pbalias\nimport \"example.com/pb\"\nfunc Clobber() { pb.File_x_proto = nil; _ = pb.ReadMsg() }\n",
			want: "example.com/pb.",
		},
		{
			name: "cross_pkg_ext_var_reassignment",
			src:  "package pbalias\nimport \"example.com/pb\"\nfunc Clobber() { pb.E_Opt = nil }\n",
			want: "example.com/pb.E_Opt",
		},
		{
			name: "cross_pkg_dot_imported_file_var_write",
			src:  "package pbalias\nimport . \"example.com/pb\"\nfunc Clobber() { File_x_proto = nil; _ = ReadMsg() }\n",
			want: "example.com/pb.",
		},
		{
			name: "cross_pkg_service_desc_field_addr_take",
			src:  "package pbalias\nimport \"example.com/pb\"\nfunc AddrField() *string { return &pb.Svc_ServiceDesc.ServiceName }\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "cross_pkg_service_desc_method_elem_addr_take",
			src:  "package pbalias\nimport (\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc AddrMethodElem() *grpc.MethodDesc { return &pb.Svc_ServiceDesc.Methods[0] }\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "non_builder_init_extension_info",
			src:  "package pbalias\nimport (\n\t\"reflect\"\n\t\"example.com/pb\"\n\t\"example.com/proto/internal/impl\"\n)\nvar E_Alias = pb.E_Opt\nfunc BadReinit() { impl.InitExtensionInfo(pb.E_Opt, \"evil\", reflect.TypeOf(0)) }\n",
			want: "example.com/",
		},
		{
			name: "cross_pkg_message_info_field_write",
			src:  "package pbalias\nimport (\n\t\"example.com/pb\"\n\t\"example.com/proto/runtime/protoimpl\"\n)\nfunc MutateMsg(mi *protoimpl.MessageInfo) { mi.Desc = \"tampered\"; _ = pb.ReadMsg() }\n",
			want: "example.com/pb.",
		},
		{
			name: "cross_pkg_proto_methods_guard_type_mutation",
			src:  "package pbalias\nimport (\n\t\"example.com/pb\"\n\t\"example.com/proto/runtime/protoimpl\"\n)\nfunc MutateMethods(mi *protoimpl.MessageInfo) { mi.ProtoMethods().Marshal = nil; _ = pb.ReadMsg() }\n",
			want: "example.com/pb.",
		},
		{
			name: "cross_pkg_proto_methods_raw_unnamed_struct_mutation",
			src:  "package pbalias\nimport (\n\t\"example.com/pb\"\n\t\"example.com/proto/internal/impl\"\n\t\"example.com/proto/runtime/protoimpl\"\n)\nfunc MutateRaw(mi *protoimpl.MessageInfo) {\n\traw := (*struct { impl.NoUnkeyedLiterals; Marshal func() []byte \"tag\" })(mi.ProtoMethods())\n\traw.Marshal = nil\n\t_ = pb.ReadMsg()\n}\n",
			want: "example.com/pb.",
		},
		{
			name: "cross_pkg_proto_methods_zero_embed_addr_take",
			src:  "package pbalias\nimport (\n\t\"example.com/pb\"\n\t\"example.com/proto/internal/impl\"\n\t\"example.com/proto/runtime/protoimpl\"\n)\nfunc AddrZeroEmbed(mi *protoimpl.MessageInfo) *impl.NoUnkeyedLiterals { _ = pb.ReadMsg(); return &mi.ProtoMethods().NoUnkeyedLiterals }\n",
			want: "example.com/pb.",
		},
		{
			name: "cross_pkg_ext_desc_guard_type_mutation",
			src:  "package pbalias\nimport \"example.com/pb\"\nfunc MutateExtDesc() { pb.E_Opt.TypeDescriptor().Number = 999 }\n",
			want: "example.com/pb.E_Opt",
		},
		{
			name: "cross_pkg_service_desc_field_write",
			src:  "package pbalias\nimport (\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc TamperSvc(sd *grpc.ServiceDesc) { sd.Metadata = \"evil\"; _ = pb.Svc_ServiceDesc }\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "cross_pkg_service_desc_unnamed_struct_ptr_conv",
			src:  "package pbalias\nimport (\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc ConvSvc() {\n\traw := (*struct {\n\t\tServiceName string \"alt\"\n\t\tHandlerType any\n\t\tMethods []grpc.MethodDesc\n\t\tStreams []grpc.StreamDesc\n\t\tMetadata any\n\t})(&pb.Svc_ServiceDesc)\n\traw.ServiceName = \"evil\"\n}\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "service_desc_unsafe_pointer_escape",
			src:  "package pbalias\nimport (\n\t\"unsafe\"\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc EscapeUnsafe(sd grpc.ServiceDesc) unsafe.Pointer { _ = pb.Svc_ServiceDesc; return unsafe.Pointer(&sd) }\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "service_desc_reflect_valueof_ptr_escape",
			src:  "package pbalias\nimport (\n\t\"reflect\"\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc EscapeReflect(sd grpc.ServiceDesc) reflect.Value { _ = pb.Svc_ServiceDesc; return reflect.ValueOf(&sd) }\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "ext_desc_reflect_byval_then_byptr_escape",
			src:  "package pbalias\nimport (\n\t\"reflect\"\n\t\"example.com/pb\"\n\t\"example.com/proto/runtime/protoimpl\"\n)\ntype extPair struct {\n\tByVal protoimpl.ExtTypeDesc\n\tByPtr *protoimpl.ExtTypeDesc\n}\nfunc EscapeByValThenPtr() reflect.Value {\n\td := pb.E_Opt.TypeDescriptor()\n\treturn reflect.ValueOf(extPair{ByVal: *d, ByPtr: d})\n}\n",
			want: "example.com/pb.E_Opt",
		},
		{
			name: "service_desc_json_unmarshal_ptr_escape",
			src:  "package pbalias\nimport (\n\t\"encoding/json\"\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc EscapeJSON(b []byte) { var sd grpc.ServiceDesc; _ = json.Unmarshal(b, &sd); _ = pb.Svc_ServiceDesc }\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "method_desc_slice_clear_mutation",
			src:  "package pbalias\nimport (\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc ClearMethods(ms []grpc.MethodDesc) { clear(ms); _ = pb.Svc_ServiceDesc }\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "method_desc_range_lhs_mutation",
			src:  "package pbalias\nimport (\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc RangeClobber(ms []grpc.MethodDesc) { for _, ms[0] = range ms {}; _ = pb.Svc_ServiceDesc }\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "fresh_local_rebound_in_range_stmt",
			src:  "package pbalias\nimport (\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc RangeRebind() {\n\tlocal := &grpc.ServiceDesc{ServiceName: \"x\"}\n\tfor _, local = range []*grpc.ServiceDesc{&pb.Svc_ServiceDesc} {\n\t\tlocal.ServiceName = \"evil\"\n\t}\n}\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "fresh_local_aliased_via_addr_take",
			src:  "package pbalias\nimport (\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc AddrRebind() {\n\tlocal := &grpc.ServiceDesc{ServiceName: \"x\"}\n\tp := &local\n\t*p = &pb.Svc_ServiceDesc\n\tlocal.ServiceName = \"evil\"\n}\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "fresh_local_aliased_slice_field_clear",
			src:  "package pbalias\nimport (\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc AliasedSliceClear() {\n\tlocal := grpc.ServiceDesc{Methods: pb.Svc_ServiceDesc.Methods}\n\tclear(local.Methods)\n}\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "fresh_local_embedded_ptr_field_write",
			src:  "package pbalias\nimport (\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\ntype svcWrap struct{ *grpc.ServiceDesc }\nfunc EmbeddedPtrWrite() *grpc.ServiceDesc {\n\t_ = pb.Svc_ServiceDesc\n\tw := svcWrap{ServiceDesc: &grpc.ServiceDesc{ServiceName: \"x\"}}\n\tout := w.ServiceDesc\n\tw.ServiceName = \"evil\"\n\treturn out\n}\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "fresh_local_published_in_loop_then_mutated",
			src:  "package pbalias\nimport (\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc LoopPublish(out chan<- *grpc.ServiceDesc) {\n\t_ = pb.Svc_ServiceDesc\n\tlocal := &grpc.ServiceDesc{ServiceName: \"x\"}\n\tfor i := 0; i < 2; i++ {\n\t\tlocal.ServiceName = \"evil\"\n\t\tout <- local\n\t}\n}\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "fresh_local_field_addr_before_publish",
			src:  "package pbalias\nimport (\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc FieldAddrBeforePublish() *grpc.ServiceDesc {\n\t_ = pb.Svc_ServiceDesc\n\tlocal := &grpc.ServiceDesc{ServiceName: \"x\"}\n\tp := &local.ServiceName\n\tout := local\n\t*p = \"evil\"\n\treturn out\n}\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "generic_ptr_clobber_service_desc",
			src:  "package pbalias\nimport (\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc setPtr[T any](p *T, v T) { *p = v }\nfunc ClobberGen() { setPtr(&pb.Svc_ServiceDesc, grpc.ServiceDesc{}) }\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "generic_slice_elem_clobber_methods",
			src:  "package pbalias\nimport \"example.com/pb\"\nfunc zeroFirst[T any](s []T) { var z T; s[0] = z }\nfunc ClobberSliceGen() { zeroFirst(pb.Svc_ServiceDesc.Methods) }\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "stdlib_slices_reverse_methods",
			src:  "package pbalias\nimport (\n\t\"slices\"\n\t\"example.com/pb\"\n)\nfunc ReverseMethods() { slices.Reverse(pb.Svc_ServiceDesc.Methods) }\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "generic_ptr_clobber_proto_methods_guard",
			src:  "package pbalias\nimport (\n\t\"example.com/pb\"\n\t\"example.com/proto/runtime/protoimpl\"\n)\nfunc setPtr[T any](p *T, v T) { *p = v }\nfunc ClobberProtoMethods(mi *protoimpl.MessageInfo) { setPtr(mi.ProtoMethods(), protoimpl.Methods{}); _ = pb.ReadMsg() }\n",
			want: "example.com/pb.",
		},
		{
			name: "value_taken_generic_func_instantiation",
			src:  "package pbalias\nimport (\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc setPtr[T any](p *T, v T) { *p = v }\nfunc ValGen() { fn := setPtr[grpc.ServiceDesc]; _ = fn; _ = pb.Svc_ServiceDesc }\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "third_party_any_callee_ptr_escape",
			src:  "package pbalias\nimport (\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc SinkAny(x any) { _ = x }\nfunc EscapeThirdPartyAny(sd grpc.ServiceDesc) { SinkAny(&sd); _ = pb.Svc_ServiceDesc }\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "method_desc_slice_append_overwrite",
			src:  "package pbalias\nimport (\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc AppendClobber() { ms := pb.Svc_ServiceDesc.Methods[:0]; _ = append(ms, grpc.MethodDesc{MethodName: \"hijacked\"}) }\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "fresh_local_backward_goto_after_publish",
			src:  "package pbalias\nimport (\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc GotoPublish(out chan<- *grpc.ServiceDesc, cond bool) {\n\t_ = pb.Svc_ServiceDesc\n\tlocal := &grpc.ServiceDesc{ServiceName: \"x\"}\n\tif cond { goto pub }\nmut:\n\tlocal.ServiceName = \"evil\"\n\treturn\npub:\n\tout <- local\n\tgoto mut\n}\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "fresh_local_substruct_field_alias_mutated_after_call_escape",
			src:  "package pbalias\nimport (\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\ntype outer struct{ Inner grpc.ServiceDesc }\nfunc publishOuter(o *outer) { _ = o }\nfunc SubStructAliasEscape() {\n\t_ = pb.Svc_ServiceDesc\n\tvar o outer\n\tp := &o.Inner\n\tpublishOuter(&o)\n\tp.ServiceName = \"evil\"\n}\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
		{
			name: "direct_return_complit_wrapping_non_fresh_slice_mutated",
			src:  "package pbalias\nimport (\n\t\"example.com/grpc\"\n\t\"example.com/pb\"\n)\nfunc makeWrap() grpc.ServiceDesc { return grpc.ServiceDesc{Methods: pb.Svc_ServiceDesc.Methods} }\nfunc MutReturned() {\n\tw := makeWrap()\n\tw.Methods[0].MethodName = \"evil\"\n}\n",
			want: "example.com/pb.Svc_ServiceDesc",
		},
	} {
		t.Run("proto_grpc_"+xpkgCase.name, func(t *testing.T) {
			badCaller := mustTypecheckWithDeps(t, "example.com/pbalias", map[string]string{"alias.go": xpkgCase.src}, pbAliasDeps)
			factsBad := baseProtoFacts()
			factsBad["example.com/pbalias"] = []Fact{FactOf(true, badCaller, false)}
			st := Compose(protoMeta, factsBad, "example.com/pbalias", nil, true, false)
			if !strings.Contains(st.Downgraded, xpkgCase.want) {
				t.Fatalf("%s failed to downgrade with %q: got %q", xpkgCase.name, xpkgCase.want, st.Downgraded)
			}
		})
	}

	// Cross-variant intersection on ProtoClusters: if pb [pb.test] mutates file_x_proto_msgTypes post-init, Compose refuses!
	pbTestVariant := mustTypecheckWithDeps(t, "example.com/pb", map[string]string{
		"x.pb.go":   pbSrc,
		"x_test.go": "package pb\nimport \"example.com/proto/runtime/protoimpl\"\nfunc ResetInTest() { file_x_proto_msgTypes = make([]protoimpl.MessageInfo, 1) }\n",
	}, pbDeps)
	factsCrossVariant := baseProtoFacts()
	factsCrossVariant["example.com/pb"] = []Fact{FactOf(true, pbPkg, false), FactOf(true, pbTestVariant, false)}
	if st := Compose(protoMeta, factsCrossVariant, "example.com/pbalias", nil, true, false); st.Downgraded == "" {
		t.Fatal("cross-variant post-init mutation in pb [pb.test] failed to block ProtoClusters discharge")
	}
}

func TestProtoDescBuilderDefaultValueAndCarrierConfinement(t *testing.T) {
	stdImp := inMemoryStdImporter(t)
	mustCheck := func(t *testing.T, pkgPath string, files map[string]string, deps map[string]*types.Package) *packages.Package {
		return mustTypecheckWithStdImp(t, stdImp, pkgPath, files, deps)
	}

	prSrc := `package protoreflect
type SourcePath []int32
func (p SourcePath) Copy() SourcePath {
	out := make(SourcePath, len(p))
	copy(out, p)
	return out
}
type FileDescriptor interface{ Path() string }
type FieldDescriptor interface{ Name() string }
type Value struct {
	b []byte
	v int
}
func ValueOfBytes(b []byte) Value { return Value{b: b, v: 1} }
func (v Value) IsValid() bool     { return v.v != 0 || len(v.b) > 0 }
func (v Value) Interface() any {
	if v.b != nil {
		return v.b
	}
	return v.v
}
func (v Value) Bytes() []byte { return v.b }
`
	defvalSrc := `package defval
import "example.com/proto/reflect/protoreflect"
func Unmarshal(s string, evs protoreflect.FieldDescriptor) (protoreflect.Value, error) {
	_ = evs
	return protoreflect.ValueOfBytes([]byte(s)), nil
}
`
	strsSrc := `package strs
func JSONCamelCase(s string) string {
	return s
}
`
	foreignSrc := `package foreign
type Registry struct {
	n int
}
func (r *Registry) Register() {}
`
	filedescSrc := `package filedesc
import (
	"bytes"
	"sync"
	"sync/atomic"
	"example.com/proto/internal/encoding/defval"
	"example.com/proto/internal/strs"
	"example.com/proto/reflect/protoreflect"
)
type stringName struct {
	hasJSON bool
	once    sync.Once
	json    string
}
func (s *stringName) InitJSON(name string) {
	s.hasJSON = true
	s.json = name
}
func (s *stringName) getJSON() string {
	s.once.Do(func() {
		if !s.hasJSON {
			s.json = strs.JSONCamelCase("f")
		}
	})
	return s.json
}
type defaultValue struct {
	val   protoreflect.Value
	bytes []byte
}
func DefaultValue(v protoreflect.Value) defaultValue {
	dv := defaultValue{val: v}
	if b, ok := v.Interface().([]byte); ok {
		dv.bytes = append([]byte(nil), b...)
	}
	return dv
}
func unmarshalDefault(b []byte, fd *Field) defaultValue {
	v, _ := defval.Unmarshal(string(b), fd)
	return DefaultValue(v)
}
func (dv *defaultValue) get() protoreflect.Value {
	if len(dv.bytes) > 0 && !bytes.Equal(dv.bytes, dv.val.Bytes()) {
		panic("mutated default bytes")
	}
	return dv.val
}
type OneofFields struct {
	List   []protoreflect.FieldDescriptor
	once   sync.Once
	byName map[string]protoreflect.FieldDescriptor
}
func (fs *OneofFields) ByName(s string) protoreflect.FieldDescriptor {
	fs.once.Do(func() {
		fs.byName = make(map[string]protoreflect.FieldDescriptor, len(fs.List))
		for _, f := range fs.List {
			fs.byName[f.Name()] = f
		}
	})
	return fs.byName[s]
}
type FieldL1 struct {
	Name    stringName
	Default defaultValue
	Path    protoreflect.SourcePath
}
type Field struct {
	L1 FieldL1
}
func (f *Field) Name() string                { return f.L1.Name.getJSON() }
func (f *Field) Default() protoreflect.Value { return f.L1.Default.get() }
type FileL1 struct {
	Path   string
	Fields []Field
	Oneofs OneofFields
}
type File struct {
	mu   sync.Mutex
	once uint32
	L1   FileL1
}
func (f *File) lazyInitOnce() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.once == 1 {
		return
	}
	f.L1.Fields = make([]Field, 1)
	f.L1.Fields[0].L1.Name.InitJSON("x")
	f.L1.Fields[0].L1.Default.val = protoreflect.ValueOfBytes([]byte(f.L1.Path))
	for i := range f.L1.Fields {
		if v := f.L1.Fields[i].L1.Default.val; v.IsValid() {
			f.L1.Fields[i].L1.Default = unmarshalDefault(v.Bytes(), nil)
		}
		f.L1.Oneofs.List = append(f.L1.Oneofs.List, &f.L1.Fields[i])
	}
	atomic.StoreUint32(&f.once, 1)
}
func (f *File) Path() string {
	if atomic.LoadUint32(&f.once) == 0 {
		f.lazyInitOnce()
	}
	return f.L1.Path
}
type Out struct {
	File   protoreflect.FileDescriptor
	Fields []Field
}
type Builder struct {
	RawDescriptor []byte
	NumFields     int32
	FileRegistry  any
}
func (db Builder) Build() Out {
	f := &File{L1: FileL1{Path: string(db.RawDescriptor)}}
	f.L1.Fields = make([]Field, int(db.NumFields))
	return Out{File: f, Fields: f.L1.Fields}
}
`
	implDescSrc := `package impl
import (
	"reflect"
	"sync"
	"sync/atomic"
	"example.com/foreign"
	"example.com/proto/internal/filedesc"
	"example.com/proto/reflect/protoreflect"
)
type regAdapter struct {
	reg *foreign.Registry
}
func (a regAdapter) Register() {
	a.reg.Register()
}
type EnumInfo struct {
	GoReflectType reflect.Type
	Desc          any
}
type MessageInfo struct {
	GoReflectType reflect.Type
	Desc          any
	initMu        sync.Mutex
	initDone      uint32
	sizecache     int
	getter        func() int
}
func (mi *MessageInfo) initOnce() {
	mi.initMu.Lock()
	defer mi.initMu.Unlock()
	if mi.initDone == 1 {
		return
	}
	var once sync.Once
	var cached int
	lazy := func() { once.Do(func() { cached = 1 }) }
	mi.getter = func() int { lazy(); return cached }
	mi.sizecache = 1
	atomic.StoreUint32(&mi.initDone, 1)
}
func (mi *MessageInfo) Size() int {
	if atomic.LoadUint32(&mi.initDone) == 0 {
		mi.initOnce()
	}
	return mi.sizecache
}
type extLazy struct {
	tagsize int
}
type ExtensionInfo struct {
	ExtendedType  any
	ExtensionType any
	Field         int32
	Name          string
	Tag           string
	mu            sync.Mutex
	init          uint32
	desc          protoreflect.FieldDescriptor
	lazy          *extLazy
}
func InitExtensionInfo(xi *ExtensionInfo, fd protoreflect.FieldDescriptor, goType reflect.Type) {
	_ = goType
	xi.desc = fd
}
func (xi *ExtensionInfo) lazyInit() {
	xi.mu.Lock()
	defer xi.mu.Unlock()
	if xi.init == 1 {
		return
	}
	if fd, ok := xi.desc.(*filedesc.Field); ok {
		xd := &filedesc.Field{}
		xd.L1.Default = fd.L1.Default
		xi.desc = xd
	}
	_ = filedesc.Builder{RawDescriptor: []byte{1}, FileRegistry: regAdapter{}}.Build()
	xi.lazy = &extLazy{tagsize: 1}
	atomic.StoreUint32(&xi.init, 1)
}
func (xi *ExtensionInfo) NameOf() string {
	if atomic.LoadUint32(&xi.init) == 0 {
		xi.lazyInit()
	}
	return xi.Name
}
`
	filetypeDescSrc := `package filetype
import (
	"reflect"
	"example.com/proto/internal/encoding/defval"
	"example.com/proto/internal/filedesc"
	"example.com/proto/internal/impl"
	"example.com/proto/reflect/protoreflect"
)
func unmarshalDefault(s string, fd protoreflect.FieldDescriptor) (protoreflect.Value, error) {
	v, err := defval.Unmarshal(s, fd)
	return v, err
}
func BuildDefaultField() *filedesc.Field {
	xd := &filedesc.Field{}
	v, _ := unmarshalDefault("x", xd)
	xd.L1.Default = filedesc.DefaultValue(v)
	return xd
}
type Out struct {
	File protoreflect.FileDescriptor
}
type Builder struct {
	File              filedesc.Builder
	GoTypes           []any
	DependencyIndexes []int32
	EnumInfos         []impl.EnumInfo
	MessageInfos      []impl.MessageInfo
	ExtensionInfos    []impl.ExtensionInfo
}
func (tb Builder) Build() Out {
	fbOut := tb.File.Build()
	for i := range tb.EnumInfos {
		tb.EnumInfos[i] = impl.EnumInfo{GoReflectType: reflect.TypeOf(tb.GoTypes[i]), Desc: &fbOut.Fields[i]}
	}
	for i := range tb.MessageInfos {
		tb.MessageInfos[i].GoReflectType = reflect.TypeOf(tb.GoTypes[i])
		tb.MessageInfos[i].Desc = &fbOut.Fields[i]
	}
	for i := range tb.ExtensionInfos {
		impl.InitExtensionInfo(&tb.ExtensionInfos[i], &fbOut.Fields[i], reflect.TypeOf(tb.GoTypes[0]))
	}
	return Out{File: fbOut.File}
}
`
	protoimplDescSrc := `package protoimpl
import (
	"example.com/proto/internal/filedesc"
	"example.com/proto/internal/filetype"
	"example.com/proto/internal/impl"
	"example.com/proto/reflect/protoreflect"
)
type TypeBuilder = filetype.Builder
type DescBuilder = filedesc.Builder
type FileDescriptor = protoreflect.FileDescriptor
type EnumInfo = impl.EnumInfo
type MessageInfo = impl.MessageInfo
type ExtensionInfo = impl.ExtensionInfo
`
	pbDescSrc := `package pb
import "example.com/proto/runtime/protoimpl"
type Mode int32
type Msg struct{ X int }
var File_d_proto protoimpl.FileDescriptor
var file_d_proto_rawDesc = []byte{0x0a}
var file_d_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_d_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_d_proto_extTypes = []protoimpl.ExtensionInfo{{
	ExtendedType:  (*Msg)(nil),
	ExtensionType: (*int32)(nil),
	Field:         10,
	Name:          "pb.ext",
	Tag:           "varint,10,opt",
}}
var E_Ext = &file_d_proto_extTypes[0]
var file_d_proto_goTypes = []any{(Mode)(0), (*Msg)(nil)}
var file_d_proto_depIdxs = []int32{0}
func init() { file_d_proto_init() }
func file_d_proto_init() {
	if File_d_proto != nil {
		return
	}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			RawDescriptor: file_d_proto_rawDesc,
			NumFields:     1,
		},
		GoTypes:           file_d_proto_goTypes,
		DependencyIndexes: file_d_proto_depIdxs,
		EnumInfos:         file_d_proto_enumTypes,
		MessageInfos:      file_d_proto_msgTypes,
		ExtensionInfos:    file_d_proto_extTypes,
	}.Build()
	File_d_proto = out.File
	file_d_proto_goTypes = nil
	file_d_proto_depIdxs = nil
}
func ReadSize() (int, string) { return file_d_proto_msgTypes[0].Size(), E_Ext.NameOf() }
`

	buildCone := func(t *testing.T, overrides map[string]string, extraCallerSrc string) ([]GraphPackage, map[string][]Fact) {
		t.Helper()
		srcOf := func(key, def string) string {
			if s, ok := overrides[key]; ok {
				return s
			}
			return def
		}
		prPkg := mustCheck(t, "example.com/proto/reflect/protoreflect", map[string]string{"pr.go": srcOf("protoreflect", prSrc)}, nil)
		strsPkg := mustCheck(t, "example.com/proto/internal/strs", map[string]string{"strs.go": srcOf("strs", strsSrc)}, nil)
		var sinkPkg *packages.Package
		defvalDeps := map[string]*types.Package{"example.com/proto/reflect/protoreflect": prPkg.Types}
		if sinkSrc, ok := overrides["sink"]; ok {
			sinkPkg = mustCheck(t, "example.com/proto/internal/sink", map[string]string{"sink.go": sinkSrc}, nil)
			defvalDeps["example.com/proto/internal/sink"] = sinkPkg.Types
		}
		defvalPkg := mustCheck(t, "example.com/proto/internal/encoding/defval", map[string]string{"defval.go": srcOf("defval", defvalSrc)}, defvalDeps)
		fdPkg := mustCheck(t, "example.com/proto/internal/filedesc", map[string]string{"fd.go": srcOf("filedesc", filedescSrc)}, map[string]*types.Package{
			"example.com/proto/reflect/protoreflect":     prPkg.Types,
			"example.com/proto/internal/strs":            strsPkg.Types,
			"example.com/proto/internal/encoding/defval": defvalPkg.Types,
		})
		foreignPkg := mustCheck(t, "example.com/foreign", map[string]string{"foreign.go": srcOf("foreign", foreignSrc)}, nil)
		implDeps := map[string]*types.Package{
			"example.com/foreign":                    foreignPkg.Types,
			"example.com/proto/internal/filedesc":    fdPkg.Types,
			"example.com/proto/reflect/protoreflect": prPkg.Types,
		}
		implP := mustCheck(t, "example.com/proto/internal/impl", map[string]string{"impl.go": srcOf("impl", implDescSrc)}, implDeps)
		ftP := mustCheck(t, "example.com/proto/internal/filetype", map[string]string{"ft.go": srcOf("filetype", filetypeDescSrc)}, map[string]*types.Package{
			"example.com/proto/internal/encoding/defval": defvalPkg.Types,
			"example.com/proto/internal/filedesc":        fdPkg.Types,
			"example.com/proto/internal/impl":            implP.Types,
			"example.com/proto/reflect/protoreflect":     prPkg.Types,
		})
		piP := mustCheck(t, "example.com/proto/runtime/protoimpl", map[string]string{"pi.go": protoimplDescSrc}, map[string]*types.Package{
			"example.com/proto/internal/filedesc":    fdPkg.Types,
			"example.com/proto/internal/filetype":    ftP.Types,
			"example.com/proto/internal/impl":        implP.Types,
			"example.com/proto/reflect/protoreflect": prPkg.Types,
		})
		pbP := mustCheck(t, "example.com/pb", map[string]string{"d.pb.go": pbDescSrc}, map[string]*types.Package{
			"example.com/proto/runtime/protoimpl": piP.Types,
		})

		pkgs := []*packages.Package{prPkg, strsPkg, defvalPkg, fdPkg, implP, ftP, piP, pbP}
		if sinkPkg != nil {
			pkgs = append(pkgs, sinkPkg)
		}
		if foreignPkg != nil {
			pkgs = append(pkgs, foreignPkg)
		}
		if extraCallerSrc != "" {
			callerDeps := map[string]*types.Package{
				"example.com/pb":                         pbP.Types,
				"example.com/proto/internal/filedesc":    fdPkg.Types,
				"example.com/proto/internal/strs":        strsPkg.Types,
				"example.com/proto/internal/impl":        implP.Types,
				"example.com/proto/runtime/protoimpl":    piP.Types,
				"example.com/proto/reflect/protoreflect": prPkg.Types,
			}
			callerP := mustCheck(t, "example.com/caller", map[string]string{"caller.go": extraCallerSrc}, callerDeps)
			pkgs = append(pkgs, callerP)
		}
		meta := make([]GraphPackage, 0, len(pkgs))
		facts := make(map[string][]Fact, len(pkgs))
		pkgSet := map[string]bool{}
		for _, p := range pkgs {
			pkgSet[p.PkgPath] = true
		}
		for _, p := range pkgs {
			facts[p.PkgPath] = []Fact{FactOf(true, p, false)}
			var imps []string
			for impPath := range p.Imports {
				if pkgSet[impPath] {
					imps = append(imps, impPath)
				}
			}
			slices.Sort(imps)
			cls := PinnedPackage
			pin := "example.com/proto@v1.0.0"
			if p.PkgPath == "example.com/pb" || p.PkgPath == "example.com/caller" {
				cls = MutableLocalPackage
				pin = ""
			}
			meta = append(meta, GraphPackage{
				ImportPath: p.PkgPath,
				PkgPath:    p.PkgPath,
				Imports:    imps,
				Class:      cls,
				Pin:        pin,
			})
		}
		return meta, facts
	}

	// Clean full cone discharges pb cluster and extension descriptor cleanly!
	cleanMeta, cleanFacts := buildCone(t, nil, "")
	stClean := Compose(cleanMeta, cleanFacts, "example.com/pb", nil, true, false)
	if stClean.Downgraded != "" {
		t.Fatalf("clean DescBuilder + defaultValue + defval cone downgraded: %q", stClean.Downgraded)
	}

	for _, tc := range []struct {
		name      string
		overrides map[string]string
		callerSrc string
	}{
		{
			name: "desc_builder_out_file_mutated_via_exported_method",
			overrides: map[string]string{
				"filedesc": filedescSrc + "\nfunc (f *File) SetPath(p string) { f.L1.Path = p }\n",
			},
		},
		{
			name: "filetype_builder_reads_mutable_global_in_build",
			overrides: map[string]string{
				"filetype": strings.Replace(filetypeDescSrc,
					"fbOut := tb.File.Build()",
					"_ = globalSalt\n\tfbOut := tb.File.Build()", 1) + "\nvar globalSalt = []byte{1}\nfunc SetSalt(b []byte) { globalSalt = b }\n",
			},
		},
		{
			name: "filetype_builder_recursive_helper_mutates_enum_info",
			overrides: map[string]string{
				"filetype": strings.Replace(filetypeDescSrc,
					"fbOut := tb.File.Build()",
					"recTamper(2, nil)\n\tfbOut := tb.File.Build()", 1) + "\nfunc recTamper(n int, ei *impl.EnumInfo) { if n <= 0 { if ei != nil { ei.Desc = \"bad\" }; return }; recTamper(n-1, ei) }\n",
			},
		},
		{
			name:      "cross_pkg_string_name_init_json_on_non_fresh_field",
			callerSrc: "package caller\nimport (\n\t\"example.com/pb\"\n\t\"example.com/proto/internal/filedesc\"\n)\nfunc TamperJSON(f *filedesc.Field) { _ = pb.File_d_proto; f.L1.Name.InitJSON(\"evil\") }\n",
		},
		{
			name:      "cross_pkg_file_l1_mutation",
			callerSrc: "package caller\nimport (\n\t\"example.com/pb\"\n\t\"example.com/proto/internal/filedesc\"\n)\nfunc TamperFile(f *filedesc.File) { _ = pb.File_d_proto; f.L1.Path = \"evil\" }\n",
		},
		{
			name: "default_value_missing_bytes_equal_guard",
			overrides: map[string]string{
				"filedesc": strings.Replace(filedescSrc,
					"!bytes.Equal(dv.bytes, dv.val.Bytes())",
					"!fakeEqual(dv.bytes, dv.val.Bytes())", 1) + "\nvar _ = bytes.Equal\nfunc fakeEqual(a, b []byte) bool { return len(a) == len(b) }\n",
			},
		},
		{
			name: "default_value_unmarshal_missing_cone_resolution",
			overrides: map[string]string{
				"filedesc": strings.Replace(filedescSrc,
					"if v := f.L1.Fields[i].L1.Default.val; v.IsValid() {\n\t\t\tf.L1.Fields[i].L1.Default = unmarshalDefault(v.Bytes(), nil)\n\t\t}",
					"", 1),
			},
		},
		{
			name: "copied_default_escaped_to_reflect_valueof_in_impl",
			overrides: map[string]string{
				"impl": strings.Replace(implDescSrc,
					"xd.L1.Default = fd.L1.Default",
					"xd.L1.Default = fd.L1.Default\n\t\t_ = reflect.ValueOf(&xd.L1.Default)", 1),
			},
		},
		{
			name: "foreign_opaque_struct_without_desc_builder_role",
			overrides: map[string]string{
				"foreign": foreignSrc + "\ntype opaque struct { raw []byte }\ntype Holder struct { Op opaque }\n",
				"impl": strings.Replace(implDescSrc,
					"xi.lazy = &extLazy{tagsize: 1}",
					"xi.lazy = &extLazy{tagsize: 1}\n\tvar src *foreign.Holder\n\tif src != nil { dst := &foreign.Holder{}; dst.Op = src.Op }", 1),
			},
		},
		{
			name: "non_desc_builder_cross_pkg_struct_in_once_cone",
			overrides: map[string]string{
				"foreign": foreignSrc + "\ntype EvilDesc struct { X int }\n",
				"impl": strings.Replace(implDescSrc,
					"mi.sizecache = 1",
					"_ = &foreign.EvilDesc{X: 1}\n\tmi.sizecache = 1", 1),
			},
		},
		{
			name: "builder_only_adapter_calls_mutating_registry_method",
			overrides: map[string]string{
				"foreign": "package foreign\ntype Registry struct { n int }\nfunc (r *Registry) Register() { r.n++ }\n",
			},
		},
		{
			name: "local_sync_once_memoizer_missing_lazy_init_before_read",
			overrides: map[string]string{
				"impl": strings.Replace(implDescSrc,
					"lazy(); return cached",
					"if false { lazy() }; return cached", 1),
			},
		},
		{
			name: "non_iife_closure_in_once_cone_mutates_captured_local",
			overrides: map[string]string{
				"impl": strings.Replace(
					strings.Replace(implDescSrc,
						"type MessageInfo struct {",
						"type MessageInfo struct {\n\tcounter func() int", 1),
					"mi.sizecache = 1",
					"calls := 0\n\tmi.counter = func() int { calls++; return calls }\n\tmi.sizecache = 1", 1),
			},
		},
		{
			name: "child_protected_struct_mutated_cross_package",
			overrides: map[string]string{
				"impl": strings.Replace(
					strings.Replace(implDescSrc,
						"type extLazy struct {\n\ttagsize int\n}",
						"type extLazy struct {\n\tTagsize int\n}\nfunc (xi *ExtensionInfo) Lazy() *extLazy { if atomic.LoadUint32(&xi.init) == 0 { xi.lazyInit() }; return xi.lazy }", 1),
					"tagsize: 1", "Tagsize: 1", 1),
			},
			callerSrc: "package caller\nimport \"example.com/pb\"\nfunc Corrupt() { pb.E_Ext.Lazy().Tagsize = 99 }\n",
		},
		{
			name: "oneof_fields_byname_stores_mutable_impl",
			overrides: map[string]string{
				"filedesc": strings.Replace(filedescSrc,
					"&f.L1.Fields[i]",
					"&mutFieldDesc{n: \"x\"}", 1) + "\ntype mutFieldDesc struct{ n string }\nfunc (m *mutFieldDesc) Name() string { return m.n }\nfunc (m *mutFieldDesc) SetName(s string) { m.n = s }\n",
			},
		},
		{
			name: "source_path_method_mutates_elem",
			overrides: map[string]string{
				"protoreflect": prSrc + "\nfunc (p SourcePath) Corrupt() { p[0] = 99 }\n",
			},
		},
		{
			name: "source_path_method_stashes_in_global",
			overrides: map[string]string{
				"protoreflect": prSrc + "\nvar leaked SourcePath\nfunc (p SourcePath) Stash() { leaked = p }\n",
			},
		},
		{
			name: "defval_stashes_arg_in_unexported_global",
			overrides: map[string]string{
				"defval": strings.Replace(defvalSrc, "_ = evs", "stashed = evs", 1) + "\nvar stashed protoreflect.FieldDescriptor\n",
			},
		},
		{
			name: "defval_non_iife_package_scope_closure_writes_global",
			overrides: map[string]string{
				"defval": defvalSrc + "\nvar stashed error\nvar sneaky = func(x error) { stashed = x }\n",
			},
		},
		{
			name: "defval_value_taken_impure_cross_pkg_func",
			overrides: map[string]string{
				"sink": "package sink\nvar saved error\nfunc Save(x any) { saved, _ = x.(error) }\n",
				"defval": strings.Replace(
					strings.Replace(defvalSrc,
						"import \"example.com/proto/reflect/protoreflect\"",
						"import (\n\t\"example.com/proto/internal/sink\"\n\t\"example.com/proto/reflect/protoreflect\"\n)", 1),
					"_ = evs",
					"fn := sink.Save\n\tfn(evs)", 1),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			meta, facts := buildCone(t, tc.overrides, tc.callerSrc)
			root := "example.com/pb"
			if tc.callerSrc != "" {
				root = "example.com/caller"
			}
			st := Compose(meta, facts, root, nil, true, false)
			if slices.Contains(strings.Split(st.AttestationDischarges, ","), "example.com/pb.file_d_proto_msgTypes") ||
				slices.Contains(strings.Split(st.AttestationDischarges, ","), "example.com/pb.E_Ext") ||
				st.Downgraded == "" {
				t.Fatalf("%s unexpectedly discharged cluster or failed to downgrade: %+v", tc.name, st)
			}
		})
	}
}

//gofresh:pure
func TestVerifyReadOnlyRefConfinementUnsafeConstantBuiltins(t *testing.T) {
	pkg := mustTypecheckPackage(t, "example.com/unsafeconfine", map[string]string{
		"p.go": `package unsafeconfine

import "unsafe"

type holder struct {
	items []int
	tag   int
}

var seed = holder{items: []int{1, 2, 3}, tag: 7}

const (
	seedSize   = unsafe.Sizeof(seed)
	seedAlign  = unsafe.Alignof(seed)
	itemsOff   = unsafe.Offsetof(seed.items)
)

func Inspect() uintptr {
	h := &seed
	return unsafe.Sizeof(*h) + unsafe.Alignof(*h) + unsafe.Offsetof(h.items) + uintptr(len(h.items))
}
`,
	})
	seedObj, ok := pkg.Types.Scope().Lookup("seed").(*types.Var)
	if !ok || seedObj == nil {
		t.Fatal("missing seed var")
	}
	holderType, ok := pkg.Types.Scope().Lookup("holder").(*types.TypeName)
	if !ok || holderType == nil {
		t.Fatal("missing holder type")
	}
	holderNamed, ok := holderType.Type().(*types.Named)
	if !ok || holderNamed == nil {
		t.Fatal("holder is not a *types.Named")
	}
	if !refconfine.VerifyReadOnlyRefConfinement(pkg, refconfine.Config{
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			id, ok := ast.Unparen(expr).(*ast.Ident)
			if ok && pkg.TypesInfo.Uses[id] == seedObj {
				return false, true
			}
			return false, false
		},
		SeedStructOrigin: func(named *types.Named) bool {
			return named != nil && named.Origin() == holderNamed.Origin()
		},
	}) {
		t.Fatal("VerifyReadOnlyRefConfinement rejected compile-time constant unsafe.{Sizeof,Alignof,Offsetof} on seed struct")
	}

	badPkg := mustTypecheckPackage(t, "example.com/unsafeconfinebad", map[string]string{
		"p.go": `package unsafeconfinebad

import "unsafe"

type holder struct {
	items []int
}

var seed = holder{items: []int{1, 2, 3}}

func Leak() *int {
	return unsafe.SliceData(seed.items)
}
`,
	})
	badSeedObj := badPkg.Types.Scope().Lookup("seed").(*types.Var)
	badHolderNamed := badPkg.Types.Scope().Lookup("holder").(*types.TypeName).Type().(*types.Named)
	if refconfine.VerifyReadOnlyRefConfinement(badPkg, refconfine.Config{
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			id, ok := ast.Unparen(expr).(*ast.Ident)
			if ok && badPkg.TypesInfo.Uses[id] == badSeedObj {
				return false, true
			}
			return false, false
		},
		SeedStructOrigin: func(named *types.Named) bool {
			return named != nil && named.Origin() == badHolderNamed.Origin()
		},
	}) {
		t.Fatal("VerifyReadOnlyRefConfinement unexpectedly accepted unsafe.SliceData on seed slice")
	}
}

//gofresh:pure
func TestDefects1To4BoundValueRangeCopyRootedSelectorValueSpecAndCrossPkgCarrierLinks(t *testing.T) {
	// Defect 1: boundValueRetentionFreeJudged rejects init-time carrier smuggling via range or copy.
	smugglePkg := mustTypecheckPackage(t, "example.com/smuggle", map[string]string{
		"p.go": `package smuggle

var globalHooks = []func(){func() {}}

type Box struct {
	slot  func()
	slots []func()
}

func (b *Box) SmuggleViaRange() {
	for _, fn := range globalHooks {
		b.slot = fn
	}
}

func (b *Box) SmuggleViaCopy() {
	tmp := make([]func(), len(globalHooks))
	copy(tmp, globalHooks)
	b.slots = tmp
}

func (b *Box) CleanInitStore() {
	b.slots = nil
}
`,
	})
	smuggleFact := FactOf(true, smugglePkg, false)
	for _, badMethod := range []string{"Box.SmuggleViaRange", "Box.SmuggleViaCopy"} {
		if slices.Contains(smuggleFact.ReceiverRetentionFree, syntaxutil.FuncKey{Pkg: "example.com/smuggle", Name: badMethod}) {
			t.Fatalf("ReceiverRetentionFree unexpectedly admitted %s: %+v", badMethod, smuggleFact.ReceiverRetentionFree)
		}
	}
	if !slices.Contains(smuggleFact.ReceiverRetentionFree, syntaxutil.FuncKey{Pkg: "example.com/smuggle", Name: "Box.CleanInitStore"}) {
		t.Fatalf("ReceiverRetentionFree omitted Box.CleanInitStore: %+v", smuggleFact.ReceiverRetentionFree)
	}

	// Defect 2 & Defect 3: boundValueJudged rooted(n.X) on chained SelectorExpr/IndexExpr scalar reads,
	// and receiverReadOnlyMethods ValueSpec local var bindings.
	precPkg := mustTypecheckPackage(t, "example.com/prec", map[string]string{
		"p.go": `package prec

type Sub struct {
	Count int
}

type Holder struct {
	sub   *Sub
	items []Sub
	nums  []int
}

func ReadChainedScalar(h *Holder) int {
	return h.sub.Count + h.items[0].Count
}

func (h *Holder) ReadViaVarSpec() int {
	var local []int = h.nums
	return len(local)
}

func (h *Holder) RangeScalarElems() int {
	sum := 0
	for i, v := range h.nums {
		sum += i + v
	}
	return sum
}

var extSubSink []*Sub

type PtrSliceHolder struct {
	items []*Sub
}

func (h *PtrSliceHolder) RangeLeakIntoIndexLvalue() {
	for _, extSubSink[0] = range h.items {
	}
}
`,
	})
	precFact := FactOf(true, precPkg, false)
	wantParam := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: "example.com/prec", Name: "ReadChainedScalar"}, Index: 0}
	if !slices.Contains(precFact.ParamLeakFree, wantParam) {
		t.Fatalf("ParamLeakFree omitted ReadChainedScalar(h *Holder) on chained scalar field read: %+v", precFact.ParamLeakFree)
	}
	wantRecvRO := syntaxutil.FuncKey{Pkg: "example.com/prec", Name: "Holder.ReadViaVarSpec"}
	if !slices.Contains(precFact.ReceiverReadOnly, wantRecvRO) {
		t.Fatalf("ReceiverReadOnly omitted Holder.ReadViaVarSpec with local var ValueSpec: %+v", precFact.ReceiverReadOnly)
	}
	wantRangeScalarRO := syntaxutil.FuncKey{Pkg: "example.com/prec", Name: "Holder.RangeScalarElems"}
	if !slices.Contains(precFact.ReceiverReadOnly, wantRangeScalarRO) {
		t.Fatalf("ReceiverReadOnly omitted Holder.RangeScalarElems with scalar range loop vars: %+v", precFact.ReceiverReadOnly)
	}
	unwantedRangeLeakRO := syntaxutil.FuncKey{Pkg: "example.com/prec", Name: "PtrSliceHolder.RangeLeakIntoIndexLvalue"}
	if slices.Contains(precFact.ReceiverReadOnly, unwantedRangeLeakRO) {
		t.Fatalf("ReceiverReadOnly admitted PtrSliceHolder.RangeLeakIntoIndexLvalue with non-ident range lvalue: %+v", precFact.ReceiverReadOnly)
	}

	// Defect 4: initAliasedLocals records CarrierLinks for cross-package pkgB.ExportedCarrier = ownCarrier
	// and SliceExpr LHS ownSlice[:1][0] = otherCarrier.
	stdImp := inMemoryStdImporter(t)
	pkgB := mustTypecheckWithStdImp(t, stdImp, "example.com/pkgb", map[string]string{
		"b.go": `package pkgb
var ExportedHook func()
`,
	}, nil)
	pkgA := mustTypecheckWithStdImp(t, stdImp, "example.com/pkga", map[string]string{
		"a.go": `package pkga
import "example.com/pkgb"
var (
	ownHook   func()
	sliceHook []func()
	otherHook func()
)
func init() {
	pkgb.ExportedHook = ownHook
	sliceHook[:1][0] = otherHook
}
`,
	}, map[string]*types.Package{"example.com/pkgb": pkgB.Types})
	factA := FactOf(true, pkgA, false)
	wantCrossLink := syntaxutil.CarrierLink{From: "example.com/pkgb.ExportedHook", To: "example.com/pkga.ownHook"}
	wantSliceLink := syntaxutil.CarrierLink{From: "example.com/pkga.sliceHook", To: "example.com/pkga.otherHook"}
	if !slices.Contains(factA.CarrierLinks, wantCrossLink) {
		t.Fatalf("CarrierLinks missing cross-package init assignment %+v: got %+v", wantCrossLink, factA.CarrierLinks)
	}
	if !slices.Contains(factA.CarrierLinks, wantSliceLink) {
		t.Fatalf("CarrierLinks missing SliceExpr LHS init assignment %+v: got %+v", wantSliceLink, factA.CarrierLinks)
	}
}
