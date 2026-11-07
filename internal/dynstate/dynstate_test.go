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
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
)

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
	// 1. solveLeastFixedPoint & solveReachFixedPoint on cyclic graphs with self-loops and diamonds.
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
	solveLeastFixedPoint(lfpSet, lfpDeps, func(dep string) bool { return lfpSet[dep] })
	for _, wantTrue := range []string{"a", "b", "c", "d"} {
		if !lfpSet[wantTrue] {
			t.Fatalf("solveLeastFixedPoint missing %q: %v", wantTrue, lfpSet)
		}
	}
	for _, wantFalse := range []string{"e", "f", "g"} {
		if lfpSet[wantFalse] {
			t.Fatalf("solveLeastFixedPoint unexpectedly included cycle node %q: %v", wantFalse, lfpSet)
		}
	}
	// Idempotence: re-running solveLeastFixedPoint on the converged set leaves it identical.
	beforeLFP := make(map[string]bool, len(lfpSet))
	for k, v := range lfpSet {
		beforeLFP[k] = v
	}
	solveLeastFixedPoint(lfpSet, lfpDeps, func(dep string) bool { return lfpSet[dep] })
	if !reflect.DeepEqual(lfpSet, beforeLFP) {
		t.Fatalf("solveLeastFixedPoint not idempotent: got %v, want %v", lfpSet, beforeLFP)
	}

	reachDeps := map[string]map[string]bool{
		"x": {"y": true},
		"y": {"z": true},
		"z": {"x": true, "seed": true},
		"u": {"v": true},
		"v": {"u": true},
	}
	reachSet := map[string]bool{"seed": true}
	solveReachFixedPoint(reachSet, reachDeps, func(dep string) bool { return reachSet[dep] })
	for _, wantTrue := range []string{"seed", "x", "y", "z"} {
		if !reachSet[wantTrue] {
			t.Fatalf("solveReachFixedPoint missing %q: %v", wantTrue, reachSet)
		}
	}
	for _, wantFalse := range []string{"u", "v"} {
		if reachSet[wantFalse] {
			t.Fatalf("solveReachFixedPoint unexpectedly included disconnected cycle %q: %v", wantFalse, reachSet)
		}
	}

	// 2. Permutational invariance of ResolveEnvAudit, NewDeferralResolution, and Compose.
	fA := FuncKey{Pkg: "example.com/a", Name: "NewA"}
	fB := FuncKey{Pkg: "example.com/b", Name: "NewB"}
	fCycle := FuncKey{Pkg: "example.com/c", Name: "Cycle"}
	pA0 := ParamKey{Func: fA, Index: 0}
	pB0 := ParamKey{Func: fB, Index: 0}

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
				ReturnEnvFree:          []FuncKey{fA},
				ReturnEnvDeps:          []FuncDepEdge{{Func: fA, Callee: fB}},
				ReturnEnvInsertionDeps: []FuncInsertionDepEdge{{Func: fA, Dep: ParamAuditTarget(pA0)}},
				ParamInsertionFree:     []ParamKey{pA0},
				ParamInsertionDeps:     []ParamInsertionDepEdge{{Param: pA0, Dep: ParamAuditTarget(pB0)}},
				ParamLeakFree:          []ParamKey{pA0},
				ParamLeakFreeDeps:      []ParamDepEdge{{Own: pA0, Dep: pB0}},
				EnvCallUses:            []EnvCallUse{{Key: "example.com/a.reg", Callee: fA}},
				AttributedUses: []AttributedUse{
					{Func: FuncKey{Pkg: "example.com/a", Name: "Mut"}, Key: "example.com/a.hook"},
				},
				FuncRefs: []FuncRef{
					{Callee: FuncKey{Pkg: "example.com/a", Name: "Mut"}, Region: RefRegion{Kind: RegionProg}},
				},
			},
		},
		"example.com/b": {
			{
				Declares:           []string{"example.com/b.shared"},
				ReturnEnvFree:      []FuncKey{fB},
				ParamInsertionFree: []ParamKey{pB0},
				ParamLeakFree:      []ParamKey{pB0},
				CarrierLinks:       []CarrierLink{{From: "example.com/b.shared", To: "example.com/a.hook"}},
			},
		},
		"example.com/c": {
			{
				Declares:      []string{"example.com/c.pinned"},
				Mutates:       []string{"example.com/c.pinned"},
				ReturnEnvFree: []FuncKey{fCycle},
				ReturnEnvDeps: []FuncDepEdge{{Func: fCycle, Callee: fCycle}},
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
	ctorA := FuncKey{Pkg: "example.com/p", Name: "NewA"}
	ctorB := FuncKey{Pkg: "example.com/p", Name: "NewB"}
	regFn := FuncKey{Pkg: "example.com/p", Name: "Register"}
	cleanParam := ParamKey{Func: regFn, Index: 0}
	dirtyParamA := ParamKey{Func: ctorA, Index: 1}
	dirtyParamB := ParamKey{Func: ctorB, Index: 2}

	// 1a. Mutual cycle in ReturnEnvDeps fails least fixed point (EnvFreeResolved == false), so FieldPopulationProves fails closed.
	factsUnresolvedCycle := map[string][]Fact{
		"example.com/p": {
			{
				ReturnEnvFree: []FuncKey{ctorA, ctorB},
				ReturnEnvDeps: []FuncDepEdge{
					{Func: ctorA, Callee: ctorB},
					{Func: ctorB, Callee: ctorA},
				},
				ParamLeakFree: []ParamKey{cleanParam},
				EnvCallUses: []EnvCallUse{
					{Key: "example.com/p.reg", Callee: ctorA},
				},
			},
		},
	}
	resUnresolved := NewDeferralResolution(factsUnresolvedCycle, nil)
	if ok, culprit := resUnresolved.FieldPopulationProves("example.com/p.reg", "fn", 0); ok || culprit != (ParamKey{}) {
		t.Fatalf("FieldPopulationProves on unresolved constructor cycle = (%v, %+v), want (false, zero)", ok, culprit)
	}

	// 1b. Direct cycle guard in FieldPopulationProves when EnvFreeResolved holds across a cyclic EnvFreeDeps graph.
	resCleanCycle := NewDeferralResolution(factsUnresolvedCycle, nil)
	resCleanCycle.EnvFreeResolved[ctorA] = true
	resCleanCycle.EnvFreeResolved[ctorB] = true
	resCleanCycle.FieldDeferAt[FieldPosKey{Owner: "example.com/p.reg", Field: "fn", Index: 0}] = []ParamKey{cleanParam}
	resCleanCycle.RetDeferAt[ReturnFieldPosKey{Func: ctorA, Field: "fn", Index: 0}] = []ParamKey{cleanParam}
	resCleanCycle.RetDeferAt[ReturnFieldPosKey{Func: ctorB, Field: "fn", Index: 0}] = []ParamKey{cleanParam}
	if ok, culprit := resCleanCycle.FieldPopulationProves("example.com/p.reg", "fn", 0); !ok || culprit != (ParamKey{}) {
		t.Fatalf("FieldPopulationProves on resolved cyclic EnvFreeDeps = (%v, %+v), want (true, zero)", ok, culprit)
	}

	// 2. Direct poisons: whole-owner (!HasPos), wildcard index (Index == -1), and specific index (Index == idx).
	for _, poison := range []FieldParamPoison{
		{Owner: "example.com/p.reg"},
		{Owner: "example.com/p.reg", HasPos: true, Field: "fn", Index: -1},
		{Owner: "example.com/p.reg", HasPos: true, Field: "fn", Index: 0},
	} {
		poisonedFacts := map[string][]Fact{
			"example.com/p": {
				{
					FieldParamPoison: []FieldParamPoison{poison},
				},
			},
		}
		pres := NewDeferralResolution(poisonedFacts, nil)
		if ok, culprit := pres.FieldPopulationProves("example.com/p.reg", "fn", 0); ok || culprit != (ParamKey{}) {
			t.Fatalf("FieldPopulationProves with poison %+v = (%v, %+v), want (false, zero)", poison, ok, culprit)
		}
	}

	// 3. Direct FieldParamDefer with unproven parameter returns (false, dirtyParamA).
	deferFailFacts := map[string][]Fact{
		"example.com/p": {
			{
				FieldParamDefer: []FieldParamDefer{
					{Pos: FieldPosKey{Owner: "example.com/p.reg", Field: "fn", Index: 0}, Param: dirtyParamB},
					{Pos: FieldPosKey{Owner: "example.com/p.reg", Field: "fn", Index: 0}, Param: dirtyParamA},
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
				ReturnEnvFree: []FuncKey{regFn, ctorA, ctorB},
				ReturnEnvDeps: []FuncDepEdge{
					{Func: regFn, Callee: ctorB},
					{Func: regFn, Callee: ctorA},
				},
				ReturnFieldParamDefer: []ReturnFieldParamDefer{
					{Pos: ReturnFieldPosKey{Func: ctorA, Field: "fn", Index: 0}, Param: dirtyParamA},
					{Pos: ReturnFieldPosKey{Func: ctorB, Field: "fn", Index: 0}, Param: dirtyParamB},
				},
				EnvCallUses: []EnvCallUse{
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
	for _, rpoison := range []ReturnFieldParamPoison{
		{Func: ctorA},
		{Func: ctorA, HasPos: true, Field: "fn", Index: -1},
		{Func: ctorA, HasPos: true, Field: "fn", Index: 0},
	} {
		rfacts := map[string][]Fact{
			"example.com/p": {
				{
					ReturnEnvFree:          []FuncKey{ctorA},
					ReturnFieldParamPoison: []ReturnFieldParamPoison{rpoison},
					EnvCallUses:            []EnvCallUse{{Key: "example.com/p.reg", Callee: ctorA}},
				},
			},
		}
		rres := NewDeferralResolution(rfacts, nil)
		if ok, culprit := rres.FieldPopulationProves("example.com/p.reg", "fn", 0); ok || culprit != (ParamKey{}) {
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
	validFn := FuncKey{Pkg: "example.com/p", Name: "F"}
	unusedFn := FuncKey{Pkg: "example.com/p", Name: "UnusedHelper"}
	validParam := ParamKey{Func: validFn, Index: 0}

	cases := []struct {
		name   string
		mutate func(*Fact)
	}{
		{"invalid ReturnEnvFree NUL", func(f *Fact) { f.ReturnEnvFree = []FuncKey{{Pkg: "a\x00b", Name: "F"}} }},
		{"invalid ReturnEnvDeps empty", func(f *Fact) { f.ReturnEnvDeps = []FuncDepEdge{{Func: validFn}} }},
		{"invalid ReturnEnvInsertionDeps", func(f *Fact) {
			f.ReturnEnvInsertionDeps = []FuncInsertionDepEdge{{Func: validFn, Dep: EnvAuditTarget{Func: validFn, ParamIndex: -2}}}
		}},
		{"invalid ParamInsertionFree", func(f *Fact) { f.ParamInsertionFree = []ParamKey{{Func: validFn, Index: -1}} }},
		{"invalid ParamInsertionDeps", func(f *Fact) {
			f.ParamInsertionDeps = []ParamInsertionDepEdge{{Param: validParam, Dep: EnvAuditTarget{ParamIndex: 0}}}
		}},
		{"invalid ParamLeakFree", func(f *Fact) { f.ParamLeakFree = []ParamKey{{Func: validFn, Index: -1}} }},
		{"invalid ParamLeakFreeDeps", func(f *Fact) { f.ParamLeakFreeDeps = []ParamDepEdge{{Own: validParam}} }},
		{"invalid ParamRetentionFree", func(f *Fact) { f.ParamRetentionFree = []ParamKey{{Func: validFn, Index: -1}} }},
		{"invalid ParamRetentionFreeDeps", func(f *Fact) { f.ParamRetentionFreeDeps = []ParamDepEdge{{Own: validParam}} }},
		{"invalid ReceiverReadOnly", func(f *Fact) { f.ReceiverReadOnly = []FuncKey{{Pkg: "example.com/p"}} }},
		{"invalid ReceiverRetentionFree", func(f *Fact) { f.ReceiverRetentionFree = []FuncKey{{Name: "M"}} }},
		{"invalid OpaqueDeps", func(f *Fact) { f.OpaqueDeps = []OpaqueDep{{Own: "a\x00b", Dep: "c"}} }},
		{"invalid FieldParamDefer", func(f *Fact) {
			f.FieldParamDefer = []FieldParamDefer{{Pos: FieldPosKey{Owner: "v", Field: "f", Index: -1}, Param: validParam}}
		}},
		{"invalid FieldParamPoison", func(f *Fact) {
			f.FieldParamPoison = []FieldParamPoison{{Owner: "v", HasPos: false, Field: "nonempty"}}
		}},
		{"invalid ReturnFieldParamDefer", func(f *Fact) {
			f.ReturnFieldParamDefer = []ReturnFieldParamDefer{{Pos: ReturnFieldPosKey{Func: validFn, Field: "", Index: 0}, Param: validParam}}
		}},
		{"invalid ReturnFieldParamPoison", func(f *Fact) {
			f.ReturnFieldParamPoison = []ReturnFieldParamPoison{{Func: validFn, HasPos: true, Field: "f", Index: -2}}
		}},
		{"invalid EnvCallUses", func(f *Fact) { f.EnvCallUses = []EnvCallUse{{Key: "", Callee: validFn}} }},
		{"invalid MethodUses", func(f *Fact) { f.MethodUses = []VarMethodUse{{Key: "a\x00b", Method: validFn}} }},
		{"invalid InitMethodUses", func(f *Fact) { f.InitMethodUses = []VarMethodUse{{Key: "v"}} }},
		{"invalid ParamUses", func(f *Fact) { f.ParamUses = []VarParamUse{{Key: "v", Param: ParamKey{Func: validFn, Index: -1}}} }},
		{"invalid InitParamUses", func(f *Fact) { f.InitParamUses = []VarParamUse{{Key: "", Param: validParam}} }},
		{"invalid FieldParamUses", func(f *Fact) { f.FieldParamUses = []FieldPosKey{{Owner: "v", Field: "f", Index: -1}} }},
		{"invalid ElemParamUses", func(f *Fact) { f.ElemParamUses = []ElemParamUse{{Key: "v", Owner: "o", Index: -1}} }},
		{"invalid FuncRefs kind", func(f *Fact) {
			f.FuncRefs = append(f.FuncRefs, FuncRef{Callee: validFn, Region: RefRegion{Kind: 99}})
		}},
		{"invalid FuncRefs RegionInit with caller", func(f *Fact) {
			f.FuncRefs = append(f.FuncRefs, FuncRef{Callee: validFn, Region: RefRegion{Kind: RegionInit, Caller: validFn}})
		}},
		{"invalid AttributedUses", func(f *Fact) {
			f.AttributedUses = append(f.AttributedUses, AttributedUse{Func: validFn, Key: "example.com/p.v", Escape: true, HasMethod: true, Method: validFn})
		}},
		{"invalid CarrierLinks", func(f *Fact) {
			f.CarrierLinks = []CarrierLink{{From: "example.com/p.v", To: "bad\x00key"}}
		}},
		{"invalid ExportedSeams", func(f *Fact) {
			f.ExportedSeams = []ExportedSeam{{Func: FuncKey{}, Key: "example.com/p.v"}}
		}},
		{"invalid NonSeqFuncUses", func(f *Fact) {
			f.NonSeqFuncUses = []FuncKey{{Pkg: "example.com/p", Name: ""}}
		}},
		{"invalid SeqFuncEdges", func(f *Fact) {
			f.SeqFuncEdges = []FuncDepEdge{{Func: validFn}}
		}},
		{"invalid ParallelFuncs", func(f *Fact) {
			f.ParallelFuncs = []FuncKey{{Name: "EnterParallel"}}
		}},
		{"invalid ParallelEdges", func(f *Fact) {
			f.ParallelEdges = []FuncDepEdge{{Func: validFn}}
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
				AttributedUses: []AttributedUse{
					{Func: unusedFn, Key: "example.com/p.v"},
				},
				FuncRefs: []FuncRef{
					{Callee: validFn, Region: RefRegion{Kind: RegionInit}},
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
	helperFn := FuncKey{Pkg: "example.com/p", Name: "Helper"}
	helperParam := ParamKey{Func: helperFn, Index: 0}
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
				EnvCallUses: []EnvCallUse{{Key: "example.com/p.v", Callee: helperFn}},
			},
			helperFact: Fact{
				ReturnEnvFree: []FuncKey{helperFn},
				ReturnEnvDeps: []FuncDepEdge{{Func: helperFn, Callee: FuncKey{}}},
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
				EnvCallUses: []EnvCallUse{{Key: "example.com/p.v", Callee: helperFn}},
			},
			helperFact: Fact{
				ReturnEnvFree:          []FuncKey{helperFn},
				ReturnEnvInsertionDeps: []FuncInsertionDepEdge{{Func: helperFn, Dep: EnvAuditTarget{Func: helperFn, ParamIndex: -2}}},
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
				ParamInsertionFree: []ParamKey{helperParam},
				ParamInsertionDeps: []ParamInsertionDepEdge{{Param: helperParam, Dep: EnvAuditTarget{ParamIndex: 0}}},
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
				ParamLeakFree: []ParamKey{{Func: FuncKey{Pkg: "example.com/p", Name: "clean"}, Index: 0}},
				ParamUses:     []VarParamUse{{Key: "example.com/p.v", Param: helperParam}},
			},
			helperFact: Fact{
				ParamLeakFree: []ParamKey{helperParam},
				ParamLeakFreeDeps: []ParamDepEdge{
					{Own: helperParam, Dep: ParamKey{Func: FuncKey{Pkg: "example.com/p", Name: "clean"}, Index: 0}},
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
				ParamRetentionFree: []ParamKey{{Func: FuncKey{Pkg: "example.com/p", Name: "clean"}, Index: 0}},
				InitParamUses:      []VarParamUse{{Key: "example.com/p.v", Param: helperParam}},
			},
			helperFact: Fact{
				ParamRetentionFree: []ParamKey{helperParam},
				ParamRetentionFreeDeps: []ParamDepEdge{
					{Own: helperParam, Dep: ParamKey{Func: FuncKey{Pkg: "example.com/p", Name: "clean"}, Index: 0}},
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
				OpaqueDeps: []OpaqueDep{{Own: "example.com/p.v", Dep: "bad\x00dep"}},
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
				FieldParamUses: []FieldPosKey{{Owner: "example.com/p.v", Field: "fn", Index: 0}},
			},
			helperFact: Fact{
				FieldParamDefer: []FieldParamDefer{{Pos: FieldPosKey{Owner: "example.com/p.v", Field: "fn", Index: -1}, Param: helperParam}},
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
				EnvCallUses:    []EnvCallUse{{Key: "example.com/p.v", Callee: helperFn}},
				FieldParamUses: []FieldPosKey{{Owner: "example.com/p.v", Field: "fn", Index: 0}},
			},
			helperFact: Fact{
				ReturnEnvFree:         []FuncKey{helperFn},
				ReturnFieldParamDefer: []ReturnFieldParamDefer{{Pos: ReturnFieldPosKey{Func: helperFn, Field: "", Index: 0}, Param: helperParam}},
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
				AttributedUses: []AttributedUse{{Func: validFn, Key: "example.com/p.v"}},
				FuncRefs:       []FuncRef{{Callee: validFn, Region: RefRegion{Kind: RegionInit}}},
			},
			helperFact: Fact{
				FuncRefs: []FuncRef{{Callee: validFn, Region: RefRegion{Kind: 99}}},
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
				ExportedSeams: []ExportedSeam{{Func: validFn, Key: "example.com/p.v"}},
			},
			helperFact: Fact{
				ExportedSeams: []ExportedSeam{{Func: FuncKey{}, Key: ""}},
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
				ExportedSeams: []ExportedSeam{{Func: validFn, Key: "example.com/p.v"}},
			},
			helperFact: Fact{
				NonSeqFuncUses: []FuncKey{{Pkg: "example.com/p", Name: ""}},
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
				ExportedSeams: []ExportedSeam{{Func: validFn, Key: "example.com/p.v"}},
			},
			helperFact: Fact{
				SeqFuncEdges: []FuncDepEdge{{}},
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
				ExportedSeams: []ExportedSeam{{Func: validFn, Key: "example.com/p.v"}},
			},
			helperFact: Fact{
				ParallelFuncs: []FuncKey{{Name: "EnterParallel"}},
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
				ExportedSeams: []ExportedSeam{{Func: validFn, Key: "example.com/p.v"}},
			},
			helperFact: Fact{
				ParallelEdges: []FuncDepEdge{{Func: validFn}},
			},
			check: func(t *testing.T, _ *EnvAuditResolution, _ *DeferralResolution, cs ConeState) {
				if cs.Downgraded == "" || !cs.CulpritSites["example.com/p.v"].Unattributed {
					t.Fatalf("expected cross-fact malformed ParallelEdges to block seam unattributed: %+v", cs)
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
	for _, policy := range []CarrierWalkPolicy{CarrierPolicyClosure, CarrierPolicyConsumer, CarrierPolicyAlias} {
		if WalkDynamicCarrier(true, recClean, make(map[types.Type]bool), policy) {
			t.Fatalf("RecursiveClean classified as carrier under policy %v", policy)
		}
	}
	if !TypeMayCarryUnknownDynamic(true, recDirty) || !TypeHandsOutDynamicAlias(true, recDirty) {
		t.Fatal("RecursiveDirty (*RecursiveDirty reaching func()) must carry dynamic and hand out alias")
	}

	// 2. Plain func() carries dynamic under Closure/Consumer, but does NOT hand out alias by value.
	fnType := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	if !TypeMayCarryUnknownDynamic(true, fnType) {
		t.Fatal("func() must carry dynamic under consumer policy")
	}
	if TypeHandsOutDynamicAlias(true, fnType) {
		t.Fatal("func() by value must not hand out dynamic alias")
	}
	if !TypeHandsOutDynamicAlias(true, types.NewSlice(fnType)) {
		t.Fatal("[]func() must hand out dynamic alias")
	}
	if !TypeMayCarryUnknownDynamic(true, types.Typ[types.UnsafePointer]) {
		t.Fatal("unsafe.Pointer must carry dynamic")
	}

	// 3. Audited sync/atomic.Pointer[T] is transparent to T when audited=true, fail-closed when audited=false,
	// and defined wrapper types stay fail-closed.
	atomicClean := lookupType("AtomicClean")
	atomicDirty := lookupType("AtomicDirty")
	wrappedAtomic := lookupType("WrappedAtomic")
	if TypeMayCarryUnknownDynamic(true, atomicClean) {
		t.Fatal("audited atomic.Pointer[int] must not carry dynamic")
	}
	if !TypeMayCarryUnknownDynamic(false, atomicClean) {
		t.Fatal("unaudited atomic.Pointer[int] must fail closed")
	}
	if !TypeMayCarryUnknownDynamic(true, atomicDirty) {
		t.Fatal("atomic.Pointer[func()] must carry dynamic")
	}
	if !TypeMayCarryUnknownDynamic(true, wrappedAtomic) {
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
	if term := OpenWorldTerm(true, lookupSig("GenericClean")); term != "" {
		t.Fatalf("OpenWorldTerm(GenericClean) = %q, want empty", term)
	}
	if term := OpenWorldTerm(true, lookupSig("GenericDirty")); !strings.Contains(term, "type parameter T") {
		t.Fatalf("OpenWorldTerm(GenericDirty) = %q, want type parameter T refusal", term)
	}
	if term := OpenWorldTerm(true, lookupSig("GenericMethodConstraint")); !strings.Contains(term, "type parameter T") {
		t.Fatalf("OpenWorldTerm(GenericMethodConstraint) = %q, want type parameter T refusal", term)
	}
	if term := OpenWorldTerm(true, lookupSig("HarnessTest")); term != "" {
		t.Fatalf("OpenWorldTerm(HarnessTest) = %q, want empty", term)
	}
	if term := SignatureOpenWorldTerm(true, lookupSig("HarnessTest"), nil, false, CarrierPolicyConsumer); !strings.Contains(term, "parameter t") {
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
	if got := NodeDeclarationKey(nil, nil); got != ":0" {
		t.Fatalf("NodeDeclarationKey(nil, nil) = %q, want :0", got)
	}
	if got := ObjectDeclarationKey(nil, nil); !strings.HasPrefix(got, "universe:") {
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
		fns := []FuncKey{
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
				f.ReturnEnvDeps = append(f.ReturnEnvDeps, FuncDepEdge{Func: fnA, Callee: fnB})
			case 2:
				f.ParamLeakFree = append(f.ParamLeakFree, ParamKey{Func: fnA, Index: int(b & 1)})
			case 3:
				f.ParamLeakFreeDeps = append(f.ParamLeakFreeDeps, ParamDepEdge{
					Own: ParamKey{Func: fnA, Index: int(b & 1)},
					Dep: ParamKey{Func: fnB, Index: int((b >> 1) & 1)},
				})
			case 4:
				f.CarrierLinks = append(f.CarrierLinks, CarrierLink{From: vA, To: vB})
			case 5:
				f.Mutates = append(f.Mutates, vA)
			case 6:
				f.FieldParamDefer = append(f.FieldParamDefer, FieldParamDefer{
					Pos:   FieldPosKey{Owner: vA, Field: "fn", Index: 0},
					Param: ParamKey{Func: fnA, Index: int(b & 1)},
				})
			case 7:
				f.EnvCallUses = append(f.EnvCallUses, EnvCallUse{Key: vA, Callee: fnA})
			case 8:
				f.ExportedSeams = append(f.ExportedSeams, ExportedSeam{Func: fnA, Key: vA})
			case 9:
				f.NonSeqFuncUses = append(f.NonSeqFuncUses, fnA)
			case 10:
				f.SeqFuncEdges = append(f.SeqFuncEdges, FuncDepEdge{Func: fnA, Callee: fnB})
			case 11:
				f.ParallelFuncs = append(f.ParallelFuncs, fnB)
			case 12:
				f.ParallelEdges = append(f.ParallelEdges, FuncDepEdge{Func: fnA, Callee: fnB})
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
