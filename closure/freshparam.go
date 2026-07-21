package closure

import (
	"go/types"
	"sort"

	"golang.org/x/tools/go/ssa"
)

// freshParamAnalysis carries fresh-path capabilities across static
// function boundaries inside one subject's attributed reachability
// (REQ-inputs-fresh-mutation's boundary extension): a parameter holds a
// fresh capability when every attributed call site of its function
// passes a fresh value at that position, and its uses inside the
// function stay within the recognized operation graph under the same
// consumer discipline. Dynamic dispatch, variadic and closure callees,
// goroutine call sites, cyclic blocks, and recursion all refuse —
// fail-closed, exactly like the intraprocedural grammar. The analysis
// is derived from the per-subject reachability alone, so batch
// equivalence holds by construction
// (REQ-closure-observability-batch-equivalence), and the fixpoint
// evaluates eagerly in a deterministic order so cycle refusals never
// depend on map iteration.
type freshParamAnalysis struct {
	functions map[*ssa.Function]bool
	// callers lists the attributed static call sites per callee; only
	// sites inside reachable functions participate.
	callers map[*ssa.Function][]ssa.CallInstruction
	// dynamic marks functions any attributed dynamic site targets: a
	// capability cannot be proven through dispatch the analysis cannot
	// enumerate call sites for.
	dynamic map[*ssa.Function]bool

	argFresh map[freshParamKey]bool
	usesOK   map[freshParamKey]bool
}

type freshParamKey struct {
	fn  *ssa.Function
	idx int
}

func newFreshParamAnalysis(reach attributedReachability) *freshParamAnalysis {
	fp := &freshParamAnalysis{
		functions: reach.functions,
		callers:   map[*ssa.Function][]ssa.CallInstruction{},
		dynamic:   map[*ssa.Function]bool{},
		argFresh:  map[freshParamKey]bool{},
		usesOK:    map[freshParamKey]bool{},
	}
	for fn := range reach.functions {
		for _, block := range fn.Blocks {
			for _, instruction := range block.Instrs {
				site, ok := instruction.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				if callee := site.Common().StaticCallee(); callee != nil && reach.functions[callee] {
					fp.callers[callee] = append(fp.callers[callee], site)
				}
			}
		}
	}
	for _, targets := range reach.dynamicTargets {
		for target := range targets {
			fp.dynamic[target] = true
		}
	}
	fp.resolve()
	return fp
}

// resolve evaluates both fixpoint directions for every candidate
// parameter in a deterministic order, so recursion's fail-closed
// refusal is identical run to run regardless of map iteration.
func (fp *freshParamAnalysis) resolve() {
	keys := make([]freshParamKey, 0, len(fp.callers))
	for fn := range fp.callers {
		for i := range fn.Params {
			keys = append(keys, freshParamKey{fn: fn, idx: i})
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].fn != keys[j].fn {
			return keys[i].fn.String() < keys[j].fn.String()
		}
		return keys[i].idx < keys[j].idx
	})
	inArg := map[freshParamKey]bool{}
	for _, key := range keys {
		fp.paramArgFreshMemo(key, inArg)
	}
	inUses := map[freshParamKey]bool{}
	for _, key := range keys {
		fp.paramUsesObservableMemo(key, inUses)
	}
}

// paramEligible refuses every shape the boundary extension cannot
// carry: unreachable or dynamically-targeted functions, closures,
// variadic signatures, and non-string parameters.
func (fp *freshParamAnalysis) paramEligible(fn *ssa.Function, idx int) bool {
	if fp == nil || fn == nil || !fp.functions[fn] || fp.dynamic[fn] {
		return false
	}
	if len(fn.FreeVars) > 0 || fn.Signature.Variadic() {
		return false
	}
	if idx < 0 || idx >= len(fn.Params) {
		return false
	}
	basic, ok := fn.Params[idx].Type().Underlying().(*types.Basic)
	return ok && basic.Kind() == types.String
}

func (fp *freshParamAnalysis) paramArgFreshMemo(key freshParamKey, inProgress map[freshParamKey]bool) bool {
	if v, done := fp.argFresh[key]; done {
		return v
	}
	if inProgress == nil {
		inProgress = map[freshParamKey]bool{}
	}
	if inProgress[key] {
		// Recursion refuses fail-closed; the eager sorted resolve makes
		// the refusal deterministic.
		fp.argFresh[key] = false
		return false
	}
	if !fp.paramEligible(key.fn, key.idx) {
		fp.argFresh[key] = false
		return false
	}
	sites := fp.callers[key.fn]
	if len(sites) == 0 {
		fp.argFresh[key] = false
		return false
	}
	inProgress[key] = true
	fresh := true
	for _, site := range sites {
		// Subject-level this guard is redundant defense-in-depth: every
		// caller site is also a referrer in some origin's or parameter's
		// uses walk, whose consumer refuses go-sites and cyclic blocks
		// on its own. It stays because argFresh must hold independently
		// of which walk reached it.
		if _, concurrent := site.(*ssa.Go); concurrent || blockInCycle(site.Block()) {
			fresh = false
			break
		}
		args := site.Common().Args
		if key.idx >= len(args) || !freshPathValue(args[key.idx], make(map[ssa.Value]bool), fp, inProgress) {
			fresh = false
			break
		}
	}
	delete(inProgress, key)
	fp.argFresh[key] = fresh
	return fresh
}

func (fp *freshParamAnalysis) paramUsesObservableMemo(key freshParamKey, inProgress map[freshParamKey]bool) bool {
	if v, done := fp.usesOK[key]; done {
		return v
	}
	if inProgress == nil {
		inProgress = map[freshParamKey]bool{}
	}
	if inProgress[key] {
		fp.usesOK[key] = false
		return false
	}
	if !fp.paramEligible(key.fn, key.idx) {
		fp.usesOK[key] = false
		return false
	}
	inProgress[key] = true
	ok := observableFreshPathUses(key.fn.Params[key.idx], make(map[ssa.Value]bool), fp, inProgress)
	delete(inProgress, key)
	fp.usesOK[key] = ok
	return ok
}

// boundaryCrossingObservable admits passing a fresh capability into a
// static non-standard callee: every attributed call site of the callee
// must pass fresh at each position the value occupies, and the
// parameter's uses inside the callee must stay within the graph.
func (fp *freshParamAnalysis) boundaryCrossingObservable(site ssa.CallInstruction, pathValue ssa.Value, inProgress map[freshParamKey]bool) bool {
	if fp == nil || site == nil || site.Common() == nil {
		return false
	}
	callee := site.Common().StaticCallee()
	if callee == nil || isStdImportPath(funcPkgPath(callee)) {
		return false
	}
	found := false
	for i, arg := range site.Common().Args {
		if arg != pathValue {
			continue
		}
		found = true
		key := freshParamKey{fn: callee, idx: i}
		// The two fixpoint directions keep separate in-progress
		// namespaces: inProgress here is the uses direction's, and the
		// arg direction starts its own chain - a key mid-evaluation for
		// uses is not an arg-direction cycle.
		if !fp.paramArgFreshMemo(key, map[freshParamKey]bool{}) || !fp.paramUsesObservableMemo(key, inProgress) {
			return false
		}
	}
	return found
}
