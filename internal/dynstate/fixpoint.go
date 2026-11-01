package dynstate

import (
	"slices"
	"sort"
	"strings"
)

func (k FuncKey) SiteKey() string {
	return k.Pkg + "\x00" + k.Name
}

func validFactKey(k string) bool {
	return k != "" && !strings.Contains(k, "\x00")
}

// solveLeastFixedPoint computes the least fixed point of set over deps: any
// key in deps whose every edge target satisfies satisfied is added to set
// until convergence.
func solveLeastFixedPoint[K comparable, D comparable](set map[K]bool, deps map[K]map[D]bool, satisfied func(D) bool) {
	for changed := true; changed; {
		changed = false
		for k, edges := range deps {
			if set[k] {
				continue
			}
			ok := true
			for dep := range edges {
				if !satisfied(dep) {
					ok = false
					break
				}
			}
			if ok {
				set[k] = true
				changed = true
			}
		}
	}
}

// solveReachFixedPoint computes the reachability least fixed point of set over
// deps: any key in deps with at least one edge target satisfying triggered is
// added to set until convergence.
func solveReachFixedPoint[K comparable, D comparable](set map[K]bool, deps map[K]map[D]bool, triggered func(D) bool) {
	for changed := true; changed; {
		changed = false
		for k, edges := range deps {
			if set[k] {
				continue
			}
			for dep := range edges {
				if triggered(dep) {
					set[k] = true
					changed = true
					break
				}
			}
		}
	}
}

// DeferralResolution is the composed proof state every deferred mark resolves
// against — the leak-free parameter union, the receiver read-only union, the
// return-environment-free fixed point, and the registered field populations
// (REQ-explain-chain).
type DeferralResolution struct {
	ParamLeakFree      map[ParamKey]bool
	ParamRetentionFree map[ParamKey]bool
	ReadOnly           map[FuncKey]bool
	ReceiverRetention  map[FuncKey]bool
	NotOpaque          map[string]bool
	EnvFreeResolved    map[FuncKey]bool
	EnvFreeDeps        map[FuncKey]map[FuncKey]bool

	FieldDeferAt  map[FieldPosKey][]ParamKey
	FieldPoisonAt map[FieldParamPoison]bool
	RetDeferAt    map[ReturnFieldPosKey][]ParamKey
	RetPoisonAt   map[ReturnFieldParamPoison]bool
	CtorsOf       map[string][]FuncKey
}

// EnvAuditResolution is the environment-audit resolution shared by the verdict
// composition and explain: return-environment-free and argument-insertion
// claims resolve in one least fixed point over their conditional edges
// (REQ-closure-shared-dynamic-state).
type EnvAuditResolution struct {
	Declared    map[FuncKey]bool
	InsDeclared map[ParamKey]bool
	Resolved    map[FuncKey]bool
	InsResolved map[ParamKey]bool
	RetDeps     map[FuncKey]map[FuncKey]bool
	RetInsDeps  map[FuncKey]map[EnvAuditTarget]bool
	InsDeps     map[ParamKey]map[EnvAuditTarget]bool
}

func (e *EnvAuditResolution) DepResolved(dep EnvAuditTarget) bool {
	if !dep.Valid() {
		return false
	}
	if dep.IsParam() {
		return e.InsResolved[dep.Param()]
	}
	return e.Resolved[dep.Func]
}

// ResolveEnvAudit computes the joint least fixed point over ReturnEnvFree and
// ParamInsertionFree claims across allFacts.
func ResolveEnvAudit(allFacts map[string][]Fact, malformed func(fact Fact)) *EnvAuditResolution {
	e := &EnvAuditResolution{
		Declared:    map[FuncKey]bool{},
		InsDeclared: map[ParamKey]bool{},
		Resolved:    map[FuncKey]bool{},
		InsResolved: map[ParamKey]bool{},
		RetDeps:     map[FuncKey]map[FuncKey]bool{},
		RetInsDeps:  map[FuncKey]map[EnvAuditTarget]bool{},
		InsDeps:     map[ParamKey]map[EnvAuditTarget]bool{},
	}
	if malformed == nil {
		malformed = func(Fact) {}
	}
	poisonedFunc := map[FuncKey]bool{}
	poisonedParam := map[ParamKey]bool{}
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, key := range fact.ReturnEnvFree {
				if !key.Valid() {
					malformed(fact)
					continue
				}
				e.Declared[key] = true
			}
			for _, edge := range fact.ReturnEnvDeps {
				if !edge.Valid() {
					malformed(fact)
					if edge.Func.Valid() {
						poisonedFunc[edge.Func] = true
					}
					continue
				}
				if e.RetDeps[edge.Func] == nil {
					e.RetDeps[edge.Func] = map[FuncKey]bool{}
				}
				e.RetDeps[edge.Func][edge.Callee] = true
			}
			for _, edge := range fact.ReturnEnvInsertionDeps {
				if !edge.Valid() {
					malformed(fact)
					if edge.Func.Valid() {
						poisonedFunc[edge.Func] = true
					}
					continue
				}
				if e.RetInsDeps[edge.Func] == nil {
					e.RetInsDeps[edge.Func] = map[EnvAuditTarget]bool{}
				}
				e.RetInsDeps[edge.Func][edge.Dep] = true
			}
			for _, key := range fact.ParamInsertionFree {
				if !key.Valid() {
					malformed(fact)
					continue
				}
				e.InsDeclared[key] = true
			}
			for _, edge := range fact.ParamInsertionDeps {
				if !edge.Valid() {
					malformed(fact)
					if edge.Param.Valid() {
						poisonedParam[edge.Param] = true
					}
					continue
				}
				if e.InsDeps[edge.Param] == nil {
					e.InsDeps[edge.Param] = map[EnvAuditTarget]bool{}
				}
				e.InsDeps[edge.Param][edge.Dep] = true
			}
		}
	}
	for fnKey := range poisonedFunc {
		delete(e.Declared, fnKey)
	}
	for paramKey := range poisonedParam {
		delete(e.InsDeclared, paramKey)
	}
	for changed := true; changed; {
		changed = false
		for fnKey := range e.Declared {
			if e.Resolved[fnKey] {
				continue
			}
			ok := true
			for dep := range e.RetDeps[fnKey] {
				if !e.Resolved[dep] {
					ok = false
					break
				}
			}
			if ok {
				for dep := range e.RetInsDeps[fnKey] {
					if !e.DepResolved(dep) {
						ok = false
						break
					}
				}
			}
			if ok {
				e.Resolved[fnKey] = true
				changed = true
			}
		}
		for paramKey := range e.InsDeclared {
			if e.InsResolved[paramKey] {
				continue
			}
			ok := true
			for dep := range e.InsDeps[paramKey] {
				if !e.DepResolved(dep) {
					ok = false
					break
				}
			}
			if ok {
				e.InsResolved[paramKey] = true
				changed = true
			}
		}
	}
	return e
}

// NewDeferralResolution composes the cross-package proof state across allFacts.
func NewDeferralResolution(allFacts map[string][]Fact, malformed func(fact Fact)) *DeferralResolution {
	r := &DeferralResolution{
		ParamLeakFree:      map[ParamKey]bool{},
		ParamRetentionFree: map[ParamKey]bool{},
		ReadOnly:           map[FuncKey]bool{},
		ReceiverRetention:  map[FuncKey]bool{},
		NotOpaque:          map[string]bool{},
		EnvFreeResolved:    map[FuncKey]bool{},
		EnvFreeDeps:        map[FuncKey]map[FuncKey]bool{},

		FieldDeferAt:  map[FieldPosKey][]ParamKey{},
		FieldPoisonAt: map[FieldParamPoison]bool{},
		RetDeferAt:    map[ReturnFieldPosKey][]ParamKey{},
		RetPoisonAt:   map[ReturnFieldParamPoison]bool{},
		CtorsOf:       map[string][]FuncKey{},
	}
	if malformed == nil {
		malformed = func(Fact) {}
	}

	declaredKeys := map[string]bool{}
	opaqueDeps := map[string]map[string]bool{}
	paramDeps := map[ParamKey]map[ParamKey]bool{}
	retentionDeps := map[ParamKey]map[ParamKey]bool{}
	poisonedLeakParam := map[ParamKey]bool{}
	poisonedRetParam := map[ParamKey]bool{}
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, key := range fact.ParamLeakFree {
				if !key.Valid() {
					malformed(fact)
					continue
				}
				r.ParamLeakFree[key] = true
			}
			for _, edge := range fact.ParamLeakFreeDeps {
				if !edge.Valid() {
					malformed(fact)
					if edge.Own.Valid() {
						poisonedLeakParam[edge.Own] = true
					}
					continue
				}
				if paramDeps[edge.Own] == nil {
					paramDeps[edge.Own] = map[ParamKey]bool{}
				}
				paramDeps[edge.Own][edge.Dep] = true
			}
			for _, key := range fact.ParamRetentionFree {
				if !key.Valid() {
					malformed(fact)
					continue
				}
				r.ParamRetentionFree[key] = true
			}
			for _, edge := range fact.ParamRetentionFreeDeps {
				if !edge.Valid() {
					malformed(fact)
					if edge.Own.Valid() {
						poisonedRetParam[edge.Own] = true
					}
					continue
				}
				if retentionDeps[edge.Own] == nil {
					retentionDeps[edge.Own] = map[ParamKey]bool{}
				}
				retentionDeps[edge.Own][edge.Dep] = true
			}
			for _, key := range fact.ReceiverReadOnly {
				if !key.Valid() {
					malformed(fact)
					continue
				}
				r.ReadOnly[key] = true
			}
			for _, key := range fact.ReceiverRetentionFree {
				if !key.Valid() {
					malformed(fact)
					continue
				}
				r.ReceiverRetention[key] = true
			}
			opaque := make(map[string]bool, len(fact.Opaque))
			for _, key := range fact.Opaque {
				opaque[key] = true
			}
			for _, key := range fact.Declares {
				declaredKeys[key] = true
				if !opaque[key] {
					r.NotOpaque[key] = true
				}
			}
			for _, key := range fact.OpacityBreaks {
				r.NotOpaque[key] = true
			}
			for _, edge := range fact.OpaqueDeps {
				if !edge.Valid() {
					malformed(fact)
					if validFactKey(edge.Own) {
						r.NotOpaque[edge.Own] = true
					}
					continue
				}
				if opaqueDeps[edge.Own] == nil {
					opaqueDeps[edge.Own] = map[string]bool{}
				}
				opaqueDeps[edge.Own][edge.Dep] = true
			}
		}
	}
	for paramKey := range poisonedLeakParam {
		delete(r.ParamLeakFree, paramKey)
		delete(paramDeps, paramKey)
	}
	for paramKey := range poisonedRetParam {
		delete(r.ParamRetentionFree, paramKey)
		delete(retentionDeps, paramKey)
	}

	solveLeastFixedPoint(r.ParamLeakFree, paramDeps, func(dep ParamKey) bool {
		return r.ParamLeakFree[dep]
	})
	solveLeastFixedPoint(r.ParamRetentionFree, retentionDeps, func(dep ParamKey) bool {
		return r.ParamRetentionFree[dep] || r.ParamLeakFree[dep]
	})
	solveReachFixedPoint(r.NotOpaque, opaqueDeps, func(dep string) bool {
		return r.NotOpaque[dep] || !declaredKeys[dep]
	})

	ea := ResolveEnvAudit(allFacts, malformed)
	r.EnvFreeResolved = ea.Resolved
	r.EnvFreeDeps = ea.RetDeps

	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, entry := range fact.FieldParamDefer {
				if !entry.Valid() {
					malformed(fact)
					if validFactKey(entry.Pos.Owner) {
						r.FieldPoisonAt[FieldParamPoison{Owner: entry.Pos.Owner}] = true
					}
					continue
				}
				r.FieldDeferAt[entry.Pos] = append(r.FieldDeferAt[entry.Pos], entry.Param)
			}
			for _, entry := range fact.FieldParamPoison {
				if !entry.Valid() {
					malformed(fact)
					if validFactKey(entry.Owner) {
						r.FieldPoisonAt[FieldParamPoison{Owner: entry.Owner}] = true
					}
					continue
				}
				r.FieldPoisonAt[entry] = true
			}
			for _, entry := range fact.ReturnFieldParamDefer {
				if !entry.Valid() {
					malformed(fact)
					if entry.Pos.Func.Valid() {
						r.RetPoisonAt[ReturnFieldParamPoison{Func: entry.Pos.Func}] = true
					}
					continue
				}
				r.RetDeferAt[entry.Pos] = append(r.RetDeferAt[entry.Pos], entry.Param)
			}
			for _, entry := range fact.ReturnFieldParamPoison {
				if !entry.Valid() {
					malformed(fact)
					if entry.Func.Valid() {
						r.RetPoisonAt[ReturnFieldParamPoison{Func: entry.Func}] = true
					}
					continue
				}
				r.RetPoisonAt[entry] = true
			}
			for _, use := range fact.EnvCallUses {
				if !use.Valid() {
					malformed(fact)
					if validFactKey(use.Key) {
						r.FieldPoisonAt[FieldParamPoison{Owner: use.Key}] = true
					}
					continue
				}
				r.CtorsOf[use.Key] = append(r.CtorsOf[use.Key], use.Callee)
			}
		}
	}
	for pos, params := range r.FieldDeferAt {
		slices.SortFunc(params, ParamKey.Compare)
		r.FieldDeferAt[pos] = slices.Compact(params)
	}
	for pos, params := range r.RetDeferAt {
		slices.SortFunc(params, ParamKey.Compare)
		r.RetDeferAt[pos] = slices.Compact(params)
	}
	for key, ctors := range r.CtorsOf {
		slices.SortFunc(ctors, FuncKey.Compare)
		r.CtorsOf[key] = slices.Compact(ctors)
	}
	return r
}

// FieldPopulationProves resolves one field-position use against the carrier's
// registered population. On failure the second result names the unproven
// deferred parameter key when one decided it — zero value when a poison or an
// unresolved constructor decided (REQ-closure-shared-dynamic-state,
// REQ-explain-chain).
func (r *DeferralResolution) FieldPopulationProves(varKey, field string, idx int) (bool, ParamKey) {
	if r.FieldPoisonAt[FieldParamPoison{Owner: varKey}] ||
		r.FieldPoisonAt[FieldParamPoison{Owner: varKey, HasPos: true, Field: field, Index: -1}] ||
		r.FieldPoisonAt[FieldParamPoison{Owner: varKey, HasPos: true, Field: field, Index: idx}] {
		return false, ParamKey{}
	}
	for _, paramKey := range r.FieldDeferAt[FieldPosKey{Owner: varKey, Field: field, Index: idx}] {
		if !r.ParamLeakFree[paramKey] {
			return false, paramKey
		}
	}
	seen := map[FuncKey]bool{}
	ctors := r.CtorsOf[varKey]
	stack := make([]FuncKey, len(ctors))
	for i := range ctors {
		stack[len(ctors)-1-i] = ctors[i]
	}
	for len(stack) > 0 {
		fnKey := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[fnKey] {
			continue
		}
		seen[fnKey] = true
		if !r.EnvFreeResolved[fnKey] {
			return false, ParamKey{}
		}
		if r.RetPoisonAt[ReturnFieldParamPoison{Func: fnKey}] ||
			r.RetPoisonAt[ReturnFieldParamPoison{Func: fnKey, HasPos: true, Field: field, Index: -1}] ||
			r.RetPoisonAt[ReturnFieldParamPoison{Func: fnKey, HasPos: true, Field: field, Index: idx}] {
			return false, ParamKey{}
		}
		for _, paramKey := range r.RetDeferAt[ReturnFieldPosKey{Func: fnKey, Field: field, Index: idx}] {
			if !r.ParamLeakFree[paramKey] {
				return false, paramKey
			}
		}
		if deps := r.EnvFreeDeps[fnKey]; len(deps) > 0 {
			sortedDeps := make([]FuncKey, 0, len(deps))
			for dep := range deps {
				sortedDeps = append(sortedDeps, dep)
			}
			slices.SortFunc(sortedDeps, FuncKey.Compare)
			for i := len(sortedDeps) - 1; i >= 0; i-- {
				stack = append(stack, sortedDeps[i])
			}
		}
	}
	return true, ParamKey{}
}

// CarrierLinkGraph builds the symmetric adjacency map of init-flow carrier
// storage links across allFacts.
func CarrierLinkGraph(allFacts map[string][]Fact, malformed func(Fact)) map[string]map[string]bool {
	linkAdj := map[string]map[string]bool{}
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, link := range fact.CarrierLinks {
				if !link.Valid() {
					if malformed != nil {
						malformed(fact)
					}
					continue
				}
				if linkAdj[link.From] == nil {
					linkAdj[link.From] = map[string]bool{}
				}
				if linkAdj[link.To] == nil {
					linkAdj[link.To] = map[string]bool{}
				}
				linkAdj[link.From][link.To] = true
				linkAdj[link.To][link.From] = true
			}
		}
	}
	return linkAdj
}

// Compose runs the shared-dynamic-state judgment for one view package over the
// facts of that package's own test-binary graph (REQ-closure-shared-dynamic-state,
// REQ-closure-scan-memo).
func Compose(meta []GraphPackage, allFacts map[string][]Fact, viewPackage string, vouches map[string]bool, singleSubject, packageProcess bool) ConeState {
	var state ConeState
	mutated := map[string]bool{}
	escaped := map[string]bool{}
	envCarrying := map[string]bool{}
	unattributedMark := map[string]bool{}
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, key := range fact.Mutates {
				mutated[key] = true
			}
			for _, key := range fact.Escapes {
				escaped[key] = true
			}
			for _, key := range fact.EnvCarrying {
				envCarrying[key] = true
			}
		}
	}
	markDeclaresMutated := func(fact Fact) {
		for _, key := range fact.Declares {
			mutated[key] = true
			unattributedMark[key] = true
		}
	}
	resolution := NewDeferralResolution(allFacts, markDeclaresMutated)
	envFreeResolved := resolution.EnvFreeResolved
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, use := range fact.EnvCallUses {
				if !use.Valid() {
					markDeclaresMutated(fact)
					for _, key := range fact.Declares {
						envCarrying[key] = true
					}
					if validFactKey(use.Key) {
						envCarrying[use.Key] = true
						mutated[use.Key] = true
						unattributedMark[use.Key] = true
					}
					continue
				}
				if !envFreeResolved[use.Callee] {
					envCarrying[use.Key] = true
				}
			}
		}
	}
	readOnly := resolution.ReadOnly
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, use := range fact.MethodUses {
				if !use.Valid() {
					markDeclaresMutated(fact)
					if validFactKey(use.Key) {
						mutated[use.Key] = true
						unattributedMark[use.Key] = true
					}
					continue
				}
				if !readOnly[use.Method] {
					mutated[use.Key] = true
				}
			}
			for _, use := range fact.InitMethodUses {
				if !use.Valid() {
					markDeclaresMutated(fact)
					if validFactKey(use.Key) {
						escaped[use.Key] = true
						unattributedMark[use.Key] = true
					}
					continue
				}
				if !resolution.ReceiverRetention[use.Method] {
					escaped[use.Key] = true
				}
			}
		}
	}
	paramLeakFree := resolution.ParamLeakFree
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, use := range fact.ParamUses {
				if !use.Valid() {
					markDeclaresMutated(fact)
					if validFactKey(use.Key) {
						escaped[use.Key] = true
						unattributedMark[use.Key] = true
					}
					continue
				}
				if !paramLeakFree[use.Param] {
					escaped[use.Key] = true
				}
			}
			for _, use := range fact.InitParamUses {
				if !use.Valid() {
					markDeclaresMutated(fact)
					if validFactKey(use.Key) {
						escaped[use.Key] = true
						unattributedMark[use.Key] = true
					}
					continue
				}
				if !paramLeakFree[use.Param] && !resolution.ParamRetentionFree[use.Param] {
					escaped[use.Key] = true
				}
			}
		}
	}
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, use := range fact.FieldParamUses {
				if !use.Valid(0) {
					markDeclaresMutated(fact)
					if validFactKey(use.Owner) {
						escaped[use.Owner] = true
						unattributedMark[use.Owner] = true
					}
					continue
				}
				if ok, _ := resolution.FieldPopulationProves(use.Owner, use.Field, use.Index); !ok {
					escaped[use.Owner] = true
				}
			}
			for _, use := range fact.ElemParamUses {
				if !use.Valid() {
					markDeclaresMutated(fact)
					if validFactKey(use.Key) {
						escaped[use.Key] = true
						unattributedMark[use.Key] = true
					}
					continue
				}
				if ok, _ := resolution.FieldPopulationProves(use.Owner, ElemPositionField, use.Index); !ok {
					escaped[use.Key] = true
				}
			}
		}
	}
	refRegions := map[FuncKey]map[RefRegion]bool{}
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, edge := range fact.FuncRefs {
				if !edge.Valid() {
					markDeclaresMutated(fact)
					if edge.Callee.Valid() {
						if refRegions[edge.Callee] == nil {
							refRegions[edge.Callee] = map[RefRegion]bool{}
						}
						refRegions[edge.Callee][RefRegion{Kind: RegionProg}] = true
					}
					continue
				}
				if refRegions[edge.Callee] == nil {
					refRegions[edge.Callee] = map[RefRegion]bool{}
				}
				refRegions[edge.Callee][edge.Region] = true
			}
		}
	}
	initOnlyFn := map[FuncKey]bool{}
	solveLeastFixedPoint(initOnlyFn, refRegions, func(region RefRegion) bool {
		if region.Kind == RegionInit {
			return true
		}
		return region.Kind == RegionFunc && initOnlyFn[region.Caller]
	})
	initReachFn := map[FuncKey]bool{}
	solveReachFixedPoint(initReachFn, refRegions, func(region RefRegion) bool {
		if region.Kind == RegionInit || region.Kind == RegionProg {
			return true
		}
		return (region.Kind == RegionFunc || region.Kind == RegionLitFunc) && initReachFn[region.Caller]
	})

	for key := range mutated {
		unattributedMark[key] = true
	}
	for key := range escaped {
		unattributedMark[key] = true
	}
	envCallable := map[string]bool{}
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, key := range fact.EnvCallable {
				envCallable[key] = true
			}
		}
	}
	for key := range envCarrying {
		if envCallable[key] {
			unattributedMark[key] = true
		}
	}
	siteFns := map[string]map[string]bool{}
	attributeSite := func(key string, fn FuncKey) {
		if siteFns[key] == nil {
			siteFns[key] = map[string]bool{}
		}
		siteFns[key][fn.SiteKey()] = true
	}
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, use := range fact.AttributedUses {
				if !use.Valid() {
					markDeclaresMutated(fact)
					if validFactKey(use.Key) {
						mutated[use.Key] = true
						unattributedMark[use.Key] = true
					}
					continue
				}
				fn, key := use.Func, use.Key
				if !use.Literal && use.Escape {
					escaped[key] = true
					attributeSite(key, fn)
					continue
				}
				if use.Literal {
					if use.HasMethod {
						if readOnly[use.Method] {
							continue
						}
						mutated[key] = true
					} else if use.Escape {
						escaped[key] = true
					} else {
						mutated[key] = true
					}
					if initReachFn[fn] || strings.Contains(fn.Name, ".") {
						unattributedMark[key] = true
					} else {
						attributeSite(key, fn)
					}
					continue
				}
				if refRegions[fn] != nil && initOnlyFn[fn] {
					continue
				}
				if use.HasMethod {
					if !readOnly[use.Method] {
						mutated[key] = true
						attributeSite(key, fn)
					}
				} else {
					mutated[key] = true
					attributeSite(key, fn)
				}
			}
		}
	}
	linkAdj := CarrierLinkGraph(allFacts, func(fact Fact) {
		markDeclaresMutated(fact)
		for _, link := range fact.CarrierLinks {
			if !link.Valid() {
				if validFactKey(link.From) {
					mutated[link.From] = true
					unattributedMark[link.From] = true
				}
				if validFactKey(link.To) {
					mutated[link.To] = true
					unattributedMark[link.To] = true
				}
			}
		}
	})
	for changed := len(linkAdj) > 0; changed; {
		changed = false
		for a, others := range linkAdj {
			for b := range others {
				if mutated[a] && !mutated[b] {
					mutated[b] = true
					unattributedMark[b] = true
					changed = true
				}
				if escaped[a] && !escaped[b] {
					escaped[b] = true
					unattributedMark[b] = true
					changed = true
				}
				if envCarrying[a] && !envCarrying[b] {
					envCarrying[b] = true
					unattributedMark[b] = true
					changed = true
				}
			}
		}
	}
	notOpaque := resolution.NotOpaque
	pinnedPkg := map[string]bool{}
	pinOf := map[string]string{}
	for _, node := range meta {
		if node.Class == PinnedPackage {
			pinnedPkg[node.PkgPath] = true
			pinOf[node.PkgPath] = node.Pin
		}
	}
	vouchDischarged := map[string][]string{}
	dischargedSeen := map[string]bool{}
	vouchedOut := func(pkgPath, key string) bool {
		if !vouches[key] || !pinnedPkg[pkgPath] {
			return false
		}
		if seen := pkgPath + "\x00" + key; !dischargedSeen[seen] {
			dischargedSeen[seen] = true
			vouchDischarged[pkgPath] = append(vouchDischarged[pkgPath], key)
		}
		return true
	}
	attestedDischarged := map[string][]string{}
	auditedSourceOut := func(pkgPath, key string) bool {
		return pinnedPkg[pkgPath] && AuditedSourceListing.Listed(pkgPath+"\x00"+key, pinOf[pkgPath])
	}
	directiveCovered := map[string]bool{}
	for _, pkgFacts := range allFacts {
		perKey := map[string]bool{}
		for _, fact := range pkgFacts {
			directed := make(map[string]bool, len(fact.SingleSubjectVars))
			for _, key := range fact.SingleSubjectVars {
				directed[key] = true
			}
			for _, key := range fact.Declares {
				if covered, seen := perKey[key]; seen {
					perKey[key] = covered && directed[key]
				} else {
					perKey[key] = directed[key]
				}
			}
		}
		for key, covered := range perKey {
			if covered {
				directiveCovered[key] = true
			}
		}
	}
	mutableLocalPkg := map[string]bool{}
	for _, node := range meta {
		if node.Class == MutableLocalPackage {
			mutableLocalPkg[node.PkgPath] = true
		}
	}
	directiveDischargedOut := func(pkgPath, key string) bool {
		if !singleSubject || !mutableLocalPkg[pkgPath] || !directiveCovered[key] {
			return false
		}
		if seen := "directive\x00" + pkgPath + "\x00" + key; !dischargedSeen[seen] {
			dischargedSeen[seen] = true
			attestedDischarged[pkgPath] = append(attestedDischarged[pkgPath], key)
		}
		return true
	}
	generatedProtoVars := map[string]bool{}
	for _, pkgFacts := range allFacts {
		for _, fact := range pkgFacts {
			for _, key := range fact.GeneratedProtoVars {
				generatedProtoVars[key] = true
			}
		}
	}
	protoRuntimeAudited := false
	grpcRuntimeAudited := false
	for _, pin := range pinOf {
		if strings.HasPrefix(pin, "google.golang.org/protobuf@") {
			switch strings.TrimPrefix(pin, "google.golang.org/protobuf@") {
			case "v1.36.11":
				protoRuntimeAudited = true
			}
		}
		if strings.HasPrefix(pin, "google.golang.org/grpc@") {
			switch strings.TrimPrefix(pin, "google.golang.org/grpc@") {
			case "v1.82.1":
				grpcRuntimeAudited = true
			}
		}
	}
	generatedGrpcVars := map[string]bool{}
	for _, pkgFacts := range allFacts {
		for _, fact := range pkgFacts {
			for _, key := range fact.GeneratedGrpcVars {
				generatedGrpcVars[key] = true
			}
		}
	}
	generatedProtoOut := func(pkgPath, key string) bool {
		if !singleSubject {
			return false
		}
		if !(protoRuntimeAudited && generatedProtoVars[key]) && !(grpcRuntimeAudited && generatedGrpcVars[key]) {
			return false
		}
		if seen := "proto\x00" + pkgPath + "\x00" + key; !dischargedSeen[seen] {
			dischargedSeen[seen] = true
			attestedDischarged[pkgPath] = append(attestedDischarged[pkgPath], key)
		}
		return true
	}
	pkgCulprits := map[string][]Culprit{}
	culpritSeen := map[string]bool{}
	channelFor := func(pkgPath, key string) CulpritChannel {
		if mutableLocalPkg[pkgPath] {
			switch {
			case packageProcess && directiveCovered[key]:
				return ChannelRestructureUnbackedDirective
			case packageProcess:
				return ChannelRestructureDirectiveSingleSubjectOnly
			default:
				return ChannelRestructureOrDirective
			}
		}
		if envCarrying[key] {
			return ChannelCallerVouchEnvFree
		}
		return ChannelCallerVouch
	}
	recordCulprit := func(pkgPath, key string, verb CulpritVerb) {
		if seen := pkgPath + "\x00" + key; !culpritSeen[seen] {
			culpritSeen[seen] = true
			pkgCulprits[pkgPath] = append(pkgCulprits[pkgPath], Culprit{
				PkgPath: pkgPath,
				Key:     key,
				Verb:    verb,
				Channel: channelFor(pkgPath, key),
			})
		}
	}
	pkgPaths := make([]string, 0, len(allFacts))
	for pkgPath := range allFacts {
		pkgPaths = append(pkgPaths, pkgPath)
	}
	sort.Strings(pkgPaths)
	for _, pkgPath := range pkgPaths {
		for _, fact := range allFacts[pkgPath] {
			for _, key := range fact.Declares {
				if mutated[key] && !vouchedOut(pkgPath, key) && !auditedSourceOut(pkgPath, key) && !directiveDischargedOut(pkgPath, key) && !generatedProtoOut(pkgPath, key) {
					recordCulprit(pkgPath, key, CulpritMutated)
				}
			}
		}
		for _, fact := range allFacts[pkgPath] {
			for _, key := range fact.Declares {
				if escaped[key] && notOpaque[key] && !vouchedOut(pkgPath, key) && !auditedSourceOut(pkgPath, key) && !directiveDischargedOut(pkgPath, key) && !generatedProtoOut(pkgPath, key) {
					recordCulprit(pkgPath, key, CulpritEscapes)
				}
			}
		}
		for _, fact := range allFacts[pkgPath] {
			for _, key := range fact.Declares {
				if envCarrying[key] && !vouchedOut(pkgPath, key) && !auditedSourceOut(pkgPath, key) && !directiveDischargedOut(pkgPath, key) && !generatedProtoOut(pkgPath, key) {
					recordCulprit(pkgPath, key, CulpritEnvCarrying)
				}
			}
		}
	}
	imports := make(map[string][]string, len(meta))
	classes := make(map[string]PackageClass, len(meta))
	pkgPathOf := make(map[string]string, len(meta))
	for _, node := range meta {
		imports[node.ImportPath] = node.Imports
		classes[node.ImportPath] = node.Class
		pkgPathOf[node.ImportPath] = node.PkgPath
	}
	var walk func(listing string, seen map[string]bool) (string, string, string)
	walk = func(listing string, seen map[string]bool) (string, string, string) {
		if seen[listing] {
			return "", "", ""
		}
		seen[listing] = true
		if classes[listing] == StandardPackage {
			return "", "", ""
		}
		if culprits := pkgCulprits[pkgPathOf[listing]]; len(culprits) > 0 {
			pkg, sym := culprits[0].SubjectParts()
			return culprits[0].ReasonBody(), pkg, sym
		}
		for _, imported := range imports[listing] {
			if _, ok := pkgPathOf[imported]; !ok {
				continue
			}
			if culprit, pkg, sym := walk(imported, seen); culprit != "" {
				return culprit, pkg, sym
			}
		}
		return "", "", ""
	}
	for _, node := range meta {
		root := node.PkgPath
		if node.ForTest != "" {
			root = node.ForTest
		} else if node.TestMain {
			continue
		}
		if root != viewPackage || state.Downgraded != "" {
			continue
		}
		if culprit, pkg, sym := walk(node.ImportPath, map[string]bool{}); culprit != "" {
			state.Downgraded = culprit
			state.CulpritPkg = pkg
			state.CulpritSym = sym
		}
	}
	if len(pkgCulprits) > 0 && state.Downgraded != "" {
		state.CulpritSites = map[string]CulpritSiteSet{}
		var collectOrdered func(listing string, seen map[string]bool, acc *[]Culprit)
		collectOrdered = func(listing string, seen map[string]bool, acc *[]Culprit) {
			if seen[listing] {
				return
			}
			seen[listing] = true
			if classes[listing] == StandardPackage {
				return
			}
			*acc = append(*acc, pkgCulprits[pkgPathOf[listing]]...)
			for _, imported := range imports[listing] {
				if _, ok := pkgPathOf[imported]; !ok {
					continue
				}
				collectOrdered(imported, seen, acc)
			}
		}
		seen := map[string]bool{}
		for _, node := range meta {
			root := node.PkgPath
			if node.ForTest != "" {
				root = node.ForTest
			} else if node.TestMain {
				continue
			}
			if root != viewPackage {
				continue
			}
			var acc []Culprit
			collectOrdered(node.ImportPath, seen, &acc)
			state.RootCulprits = append(state.RootCulprits, acc...)
		}
		for _, culprit := range state.RootCulprits {
			if _, done := state.CulpritSites[culprit.Key]; done {
				continue
			}
			fns := siteFns[culprit.Key]
			state.CulpritSites[culprit.Key] = CulpritSiteSet{
				Fns:          fns,
				Unattributed: unattributedMark[culprit.Key] || len(fns) == 0,
			}
		}
	}
	collectReachable := func(source map[string][]string) string {
		acc := map[string]bool{}
		var collect func(listing string, seen map[string]bool)
		collect = func(listing string, seen map[string]bool) {
			if seen[listing] {
				return
			}
			seen[listing] = true
			if classes[listing] == StandardPackage {
				return
			}
			for _, key := range source[pkgPathOf[listing]] {
				acc[key] = true
			}
			for _, imported := range imports[listing] {
				if _, ok := pkgPathOf[imported]; !ok {
					continue
				}
				collect(imported, seen)
			}
		}
		for _, node := range meta {
			root := node.PkgPath
			if node.ForTest != "" {
				root = node.ForTest
			} else if node.TestMain {
				continue
			}
			if root != viewPackage {
				continue
			}
			collect(node.ImportPath, map[string]bool{})
		}
		if len(acc) == 0 {
			return ""
		}
		keys := make([]string, 0, len(acc))
		for key := range acc {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return strings.Join(keys, ",")
	}
	if len(vouchDischarged) > 0 {
		state.VouchDischarges = collectReachable(vouchDischarged)
	}
	evidenceDischarged := map[string][]string{}
	evidenceSeen := map[string]bool{}
	for _, pkgPath := range pkgPaths {
		for _, fact := range allFacts[pkgPath] {
			for _, key := range fact.PoolDischarges {
				if seen := pkgPath + "\x00" + key; !evidenceSeen[seen] {
					evidenceSeen[seen] = true
					evidenceDischarged[pkgPath] = append(evidenceDischarged[pkgPath], key)
				}
			}
		}
	}
	for pkgPath, keys := range attestedDischarged {
		for _, key := range keys {
			if seen := pkgPath + "\x00" + key; !evidenceSeen[seen] {
				evidenceSeen[seen] = true
				evidenceDischarged[pkgPath] = append(evidenceDischarged[pkgPath], key)
			}
		}
	}
	if len(evidenceDischarged) > 0 {
		state.AttestationDischarges = collectReachable(evidenceDischarged)
	}
	return state
}
