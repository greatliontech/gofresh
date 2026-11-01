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
				Declares:          []string{"example.com/a.reg", "example.com/a.hook"},
				ReturnEnvFree:     []FuncKey{fA},
				ReturnEnvDeps:     []FuncDepEdge{{Func: fA, Callee: fB}},
				ReturnEnvInsertionDeps: []FuncInsertionDepEdge{{Func: fA, Dep: ParamAuditTarget(pA0)}},
				ParamInsertionFree: []ParamKey{pA0},
				ParamInsertionDeps: []ParamInsertionDepEdge{{Param: pA0, Dep: ParamAuditTarget(pB0)}},
				ParamLeakFree:     []ParamKey{pA0},
				ParamLeakFreeDeps: []ParamDepEdge{{Own: pA0, Dep: pB0}},
				EnvCallUses:       []EnvCallUse{{Key: "example.com/a.reg", Callee: fA}},
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Include an attributed use in unusedFn so that if unattributedMark["example.com/p.v"]
			// were not set on malformed-fact fallback, CulpritSites["example.com/p.v"].Unattributed
			// would falsely become false (only blaming unusedFn) or initOnlyFn would discharge validFn.
			fact := Fact{
				Declares:      []string{"example.com/p.v"},
				EnvCallable:   []string{"example.com/p.v"},
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
			switch b % 8 {
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
			state1.CulpritSym != state2.CulpritSym {
			t.Fatalf("Compose order-dependent: %+v vs %+v", state1, state2)
		}
		_ = fmt.Sprintf("%s", state1.Downgraded)
	})
}
