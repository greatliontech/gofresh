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

func validQualifiedVarKey(k string) bool {
	if strings.Contains(k, "\x00") {
		return false
	}
	dot := strings.LastIndexByte(k, '.')
	return dot > 0 && dot < len(k)-1
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

// BlockedExportedSeams resolves which exported mutating seam functions across
// allFacts are reachable from non-sequential function uses (go statements,
// .Parallel-bearing scopes including cross-package .Parallel helpers,
// init/method/var-initializer calls, or escaped function values) across
// call edges, returning varKey -> blocked exported seam functions.
func BlockedExportedSeams(allFacts map[string][]Fact, malformed func(Fact)) map[string]map[FuncKey]bool {
	blocked := map[string]map[FuncKey]bool{}
	recordBlocked := func(key string, fn FuncKey) {
		if blocked[key] == nil {
			blocked[key] = map[FuncKey]bool{}
		}
		blocked[key][fn] = true
	}
	hasMalformed := false
	validExportedSeams := 0
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, es := range fact.ExportedSeams {
				if !es.Valid() {
					hasMalformed = true
					if malformed != nil {
						malformed(fact)
					}
					continue
				}
				validExportedSeams++
			}
			for _, fn := range fact.NonSeqFuncUses {
				if !fn.Valid() {
					hasMalformed = true
					if malformed != nil {
						malformed(fact)
					}
				}
			}
			for _, edge := range fact.SeqFuncEdges {
				if !edge.Valid() {
					hasMalformed = true
					if malformed != nil {
						malformed(fact)
					}
				}
			}
			for _, fn := range fact.ParallelFuncs {
				if !fn.Valid() {
					hasMalformed = true
					if malformed != nil {
						malformed(fact)
					}
				}
			}
			for _, edge := range fact.ParallelEdges {
				if !edge.Valid() {
					hasMalformed = true
					if malformed != nil {
						malformed(fact)
					}
				}
			}
		}
	}
	if hasMalformed {
		for _, facts := range allFacts {
			for _, fact := range facts {
				for _, es := range fact.ExportedSeams {
					if validFactKey(es.Key) {
						recordBlocked(es.Key, FuncKey{})
					}
				}
			}
		}
		return blocked
	}
	if validExportedSeams == 0 {
		return blocked
	}

	parallelReached := map[FuncKey]bool{}
	nonSeqReached := map[FuncKey]bool{}
	seqAdj := map[FuncKey]map[FuncKey]bool{}
	revSeqAdj := map[FuncKey]map[FuncKey]bool{}
	revParAdj := map[FuncKey]map[FuncKey]bool{}
	addRevPar := func(caller, callee FuncKey) {
		if revParAdj[callee] == nil {
			revParAdj[callee] = map[FuncKey]bool{}
		}
		revParAdj[callee][caller] = true
	}
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, fn := range fact.ParallelFuncs {
				if fn.Valid() {
					parallelReached[fn] = true
				}
			}
			for _, fn := range fact.NonSeqFuncUses {
				if fn.Valid() {
					nonSeqReached[fn] = true
				}
			}
			for _, edge := range fact.SeqFuncEdges {
				if !edge.Valid() {
					continue
				}
				if seqAdj[edge.Func] == nil {
					seqAdj[edge.Func] = map[FuncKey]bool{}
				}
				seqAdj[edge.Func][edge.Callee] = true
				if revSeqAdj[edge.Callee] == nil {
					revSeqAdj[edge.Callee] = map[FuncKey]bool{}
				}
				revSeqAdj[edge.Callee][edge.Func] = true
				addRevPar(edge.Func, edge.Callee)
			}
			for _, edge := range fact.ParallelEdges {
				if !edge.Valid() {
					continue
				}
				addRevPar(edge.Func, edge.Callee)
			}
		}
	}
	if len(parallelReached) > 0 && len(revParAdj) > 0 {
		queue := make([]FuncKey, 0, len(parallelReached))
		for fn := range parallelReached {
			queue = append(queue, fn)
		}
		for len(queue) > 0 {
			cur := queue[len(queue)-1]
			queue = queue[:len(queue)-1]
			for caller := range revParAdj[cur] {
				if !parallelReached[caller] {
					parallelReached[caller] = true
					queue = append(queue, caller)
				}
			}
		}
	}
	for fn := range parallelReached {
		if fn.Pkg != "*" && !strings.Contains(fn.Name, "#") {
			nonSeqReached[fn] = true
		}
	}
	if len(nonSeqReached) > 0 && len(seqAdj) > 0 {
		queue := make([]FuncKey, 0, len(nonSeqReached))
		for fn := range nonSeqReached {
			queue = append(queue, fn)
		}
		for len(queue) > 0 {
			cur := queue[len(queue)-1]
			queue = queue[:len(queue)-1]
			for callee := range seqAdj[cur] {
				if !nonSeqReached[callee] {
					nonSeqReached[callee] = true
					queue = append(queue, callee)
				}
			}
		}
	}
	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, es := range fact.ExportedSeams {
				if es.Valid() && (nonSeqReached[es.Func] || (es.RunnerOnly && len(revSeqAdj[es.Func]) > 0)) {
					recordBlocked(es.Key, es.Func)
				}
			}
		}
	}
	return blocked
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
	malformedFactVars := map[string]bool{}
	markDeclaresMutated := func(fact Fact) {
		for _, key := range fact.Declares {
			mutated[key] = true
			unattributedMark[key] = true
			malformedFactVars[key] = true
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
	for key, fns := range BlockedExportedSeams(allFacts, markDeclaresMutated) {
		mutated[key] = true
		for fn := range fns {
			if !fn.Valid() || initReachFn[fn] || strings.Contains(fn.Name, ".") {
				unattributedMark[key] = true
			} else {
				attributeSite(key, fn)
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
	mutableLocalPkg := map[string]bool{}
	for _, node := range meta {
		switch node.Class {
		case PinnedPackage:
			pinnedPkg[node.PkgPath] = true
		case MutableLocalPackage:
			mutableLocalPkg[node.PkgPath] = true
		}
	}

	// Validate all structural discharge and struct-mutation slices, marking any
	// malformed fact fail-closed so neither its declared variables nor its
	// positive role/discharge claims can discharge culprits.
	isFactDischargeMalformed := func(fact Fact) bool {
		bad := false
		for _, key := range fact.MappingDischarges {
			if !validQualifiedVarKey(key) {
				bad = true
			}
		}
		for _, key := range fact.MemoDischarges {
			if !validQualifiedVarKey(key) {
				bad = true
			}
		}
		for _, c := range fact.ProtoClusters {
			if !c.Valid() {
				bad = true
			}
		}
		for _, a := range fact.ProtoExtAliases {
			if !a.Valid() {
				bad = true
			}
		}
		for _, rt := range fact.ProtoRuntimeTypes {
			if !rt.Valid() {
				bad = true
			}
		}
		for _, gv := range fact.GrpcServiceVars {
			if !gv.Valid() {
				bad = true
			}
		}
		for _, tr := range fact.MutatedStructTypes {
			if !tr.Valid() {
				bad = true
			}
		}
		for _, cm := range fact.ConditionalStructMutations {
			if !cm.Valid() {
				bad = true
			}
		}
		if !fact.NoPostInitCarrierWrites && len(fact.CarrierImportCalls) > 0 {
			bad = true
		}
		for _, dep := range fact.CarrierImportCalls {
			if !validNonEmptyPkgKey(dep) {
				bad = true
			}
		}
		for _, m := range fact.NonMutatingMethods {
			if !m.Valid() {
				bad = true
			}
		}
		for _, key := range fact.DirectVarWrites {
			if !validQualifiedVarKey(key) {
				bad = true
			}
		}
		return bad
	}
	pkgHasMalformedFact := map[string]bool{}
	mutatedStructs := map[TypeRef]bool{}
	directVarWritten := map[string]bool{}
	anyMalformedMutatedStruct := false
	anyMalformedDirectVarWrite := false
	for pkgPath, pkgFacts := range allFacts {
		for _, fact := range pkgFacts {
			if isFactDischargeMalformed(fact) {
				pkgHasMalformedFact[pkgPath] = true
				for _, sibling := range pkgFacts {
					markDeclaresMutated(sibling)
				}
			}
			for _, tr := range fact.MutatedStructTypes {
				if tr.Valid() {
					mutatedStructs[tr] = true
				} else {
					anyMalformedMutatedStruct = true
				}
			}
			for _, cm := range fact.ConditionalStructMutations {
				if !cm.Valid() {
					anyMalformedMutatedStruct = true
				}
			}
			if !fact.NoPostInitCarrierWrites && len(fact.CarrierImportCalls) > 0 {
				anyMalformedMutatedStruct = true
			}
			for _, dep := range fact.CarrierImportCalls {
				if !validNonEmptyPkgKey(dep) {
					anyMalformedMutatedStruct = true
				}
			}
			for _, m := range fact.NonMutatingMethods {
				if !m.Valid() || m.Pkg != pkgPath {
					anyMalformedMutatedStruct = true
				}
			}
			for _, key := range fact.DirectVarWrites {
				if validQualifiedVarKey(key) {
					directVarWritten[key] = true
				} else {
					anyMalformedDirectVarWrite = true
				}
			}
		}
	}

	pkgCannotRetainCarrier := map[string]bool{}
	for pkgPath, pkgFacts := range allFacts {
		if len(pkgFacts) == 0 || pkgHasMalformedFact[pkgPath] {
			continue
		}
		allOK := true
		for _, fact := range pkgFacts {
			if !fact.NoPostInitCarrierWrites {
				allOK = false
				break
			}
		}
		if allOK {
			pkgCannotRetainCarrier[pkgPath] = true
		}
	}
	for {
		changed := false
		for pkgPath := range pkgCannotRetainCarrier {
			drop := false
			for _, fact := range allFacts[pkgPath] {
				for _, dep := range fact.CarrierImportCalls {
					if !pkgCannotRetainCarrier[dep] {
						drop = true
						break
					}
				}
				if drop {
					break
				}
			}
			if drop {
				delete(pkgCannotRetainCarrier, pkgPath)
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	nonMutatingMethods := map[FuncKey]bool{}
	if !anyMalformedMutatedStruct {
		for pkgPath, pkgFacts := range allFacts {
			if len(pkgFacts) == 0 || pkgHasMalformedFact[pkgPath] {
				continue
			}
			var common map[FuncKey]bool
			for fi, fact := range pkgFacts {
				cur := make(map[FuncKey]bool, len(fact.NonMutatingMethods))
				for _, m := range fact.NonMutatingMethods {
					if m.Pkg == pkgPath {
						cur[m] = true
					}
				}
				if fi == 0 {
					common = cur
					continue
				}
				for m := range common {
					if !cur[m] {
						delete(common, m)
					}
				}
			}
			for m := range common {
				nonMutatingMethods[m] = true
			}
		}
	}
	// Precompute candidate ProtoRoleDescBuilder GuardTypes per package (intersected
	// across package variants) so RequireDescBuilderGuard conditional struct
	// mutations evaluate monotonically during the mutatedStructs least fixed point.
	type descBuilderCandidate struct {
		builderType TypeRef
		guardTypes  map[TypeRef]bool
	}
	descBuilderCandidates := map[string][]descBuilderCandidate{}
	if !anyMalformedMutatedStruct {
		for pkgPath, pkgFacts := range allFacts {
			if len(pkgFacts) == 0 || pkgHasMalformedFact[pkgPath] {
				continue
			}
			var common map[TypeRef]map[TypeRef]bool
			for fi, fact := range pkgFacts {
				cur := map[TypeRef]map[TypeRef]bool{}
				for _, rt := range fact.ProtoRuntimeTypes {
					if rt.Type.Pkg != pkgPath || rt.Role != ProtoRoleDescBuilder {
						continue
					}
					gt := make(map[TypeRef]bool, len(rt.GuardTypes))
					for _, g := range rt.GuardTypes {
						gt[g] = true
					}
					cur[rt.Type] = gt
				}
				if fi == 0 {
					common = cur
					continue
				}
				for bType, prevGT := range common {
					nextGT, ok := cur[bType]
					if !ok {
						delete(common, bType)
						continue
					}
					for g := range nextGT {
						prevGT[g] = true
					}
				}
			}
			for bType, gt := range common {
				descBuilderCandidates[pkgPath] = append(descBuilderCandidates[pkgPath], descBuilderCandidate{
					builderType: bType,
					guardTypes:  gt,
				})
			}
		}
	}
	hasValidDescBuilderCovering := func(guardStruct TypeRef) bool {
		for _, cand := range descBuilderCandidates[guardStruct.Pkg] {
			if guardStruct != cand.builderType && !cand.guardTypes[guardStruct] {
				continue
			}
			clean := true
			for g := range cand.guardTypes {
				if mutatedStructs[g] {
					clean = false
					break
				}
			}
			if clean {
				return true
			}
		}
		return false
	}
	for {
		changed := false
		for _, pkgFacts := range allFacts {
			for _, fact := range pkgFacts {
				for _, cm := range fact.ConditionalStructMutations {
					if !cm.Valid() || mutatedStructs[cm.Struct] {
						continue
					}
					triggered := false
					if cm.GuardPkg != "" && !pkgCannotRetainCarrier[cm.GuardPkg] {
						triggered = true
					}
					if !triggered && !cm.GuardStruct.IsZero() && !cm.RequireDescBuilderGuard && mutatedStructs[cm.GuardStruct] {
						triggered = true
					}
					if !triggered && cm.RequireDescBuilderGuard && !hasValidDescBuilderCovering(cm.GuardStruct) {
						triggered = true
					}
					if !triggered && !cm.RequireNonMutatingMethod.IsZero() && !nonMutatingMethods[cm.RequireNonMutatingMethod] {
						triggered = true
					}
					if triggered {
						mutatedStructs[cm.Struct] = true
						changed = true
					}
				}
			}
		}
		if !changed {
			break
		}
	}

	intersectDeclaredVarSet := func(extract func(pkgPath string, fact Fact) map[string]bool) map[string]bool {
		out := map[string]bool{}
		for pkgPath, pkgFacts := range allFacts {
			if pkgHasMalformedFact[pkgPath] {
				continue
			}
			perKey := map[string]bool{}
			for _, fact := range pkgFacts {
				present := extract(pkgPath, fact)
				for _, key := range fact.Declares {
					if covered, seen := perKey[key]; seen {
						perKey[key] = covered && present[key]
					} else {
						perKey[key] = present[key]
					}
				}
			}
			for key, covered := range perKey {
				if covered && !malformedFactVars[key] {
					out[key] = true
				}
			}
		}
		return out
	}

	mappingDischargedVars := intersectDeclaredVarSet(func(_ string, fact Fact) map[string]bool {
		if anyMalformedDirectVarWrite {
			return nil
		}
		m := make(map[string]bool, len(fact.MappingDischarges))
		for _, key := range fact.MappingDischarges {
			if !directVarWritten[key] {
				m[key] = true
			}
		}
		return m
	})
	memoDischargedVars := intersectDeclaredVarSet(func(_ string, fact Fact) map[string]bool {
		if anyMalformedDirectVarWrite {
			return nil
		}
		m := make(map[string]bool, len(fact.MemoDischarges))
		for _, key := range fact.MemoDischarges {
			if !directVarWritten[key] {
				m[key] = true
			}
		}
		return m
	})

	type rtRoleKey struct {
		Type TypeRef
		Role string
	}
	type rtRoleInfo struct {
		SubBuilder     TypeRef
		InitHelper     FuncKey
		AllowedHelpers map[FuncKey]bool
		GuardTypes     map[TypeRef]bool
	}
	verifiedRoles := map[rtRoleKey]rtRoleInfo{}
	for pkgPath, pkgFacts := range allFacts {
		if len(pkgFacts) == 0 || pkgHasMalformedFact[pkgPath] {
			continue
		}
		var common map[rtRoleKey]rtRoleInfo
		for fi, fact := range pkgFacts {
			cur := map[rtRoleKey]rtRoleInfo{}
			for _, rt := range fact.ProtoRuntimeTypes {
				if rt.Type.Pkg != pkgPath {
					continue
				}
				ah := make(map[FuncKey]bool, len(rt.AllowedHelpers))
				for _, h := range rt.AllowedHelpers {
					ah[h] = true
				}
				gt := make(map[TypeRef]bool, len(rt.GuardTypes))
				for _, g := range rt.GuardTypes {
					gt[g] = true
				}
				cur[rtRoleKey{Type: rt.Type, Role: rt.Role}] = rtRoleInfo{
					SubBuilder:     rt.SubBuilder,
					InitHelper:     rt.InitHelper,
					AllowedHelpers: ah,
					GuardTypes:     gt,
				}
			}
			if fi == 0 {
				common = cur
				continue
			}
			for k, prev := range common {
				next, ok := cur[k]
				if !ok || prev.InitHelper != next.InitHelper || prev.SubBuilder != next.SubBuilder {
					delete(common, k)
					continue
				}
				for h := range prev.AllowedHelpers {
					if !next.AllowedHelpers[h] {
						delete(prev.AllowedHelpers, h)
					}
				}
				for g := range next.GuardTypes {
					prev.GuardTypes[g] = true
				}
			}
		}
		for k, info := range common {
			if anyMalformedMutatedStruct {
				continue
			}
			if k.Role != ProtoRoleBuilder && k.Role != ProtoRoleDescBuilder && mutatedStructs[k.Type] {
				continue
			}
			guardMutated := false
			for g := range info.GuardTypes {
				if mutatedStructs[g] {
					guardMutated = true
					break
				}
			}
			if guardMutated {
				continue
			}
			verifiedRoles[k] = info
		}
	}
	for k, info := range verifiedRoles {
		if k.Role == ProtoRoleBuilder && !info.SubBuilder.IsZero() {
			if _, ok := verifiedRoles[rtRoleKey{Type: info.SubBuilder, Role: ProtoRoleDescBuilder}]; !ok {
				delete(verifiedRoles, k)
			}
		}
	}

	builderAllowedHelperByPkg := map[string]map[FuncKey]bool{}
	for k, info := range verifiedRoles {
		if k.Role == ProtoRoleBuilder && len(info.AllowedHelpers) > 0 {
			if builderAllowedHelperByPkg[k.Type.Pkg] == nil {
				builderAllowedHelperByPkg[k.Type.Pkg] = map[FuncKey]bool{}
			}
			for h := range info.AllowedHelpers {
				builderAllowedHelperByPkg[k.Type.Pkg][h] = true
			}
		}
	}
	nonBuilderReferencedFn := map[FuncKey]bool{}
	for pkgPath, pkgFacts := range allFacts {
		for _, fact := range pkgFacts {
			for _, edge := range fact.FuncRefs {
				if edge.Callee.Valid() && !builderAllowedHelperByPkg[pkgPath][edge.Callee] {
					nonBuilderReferencedFn[edge.Callee] = true
				}
			}
		}
	}
	for k, info := range verifiedRoles {
		if k.Role == ProtoRoleExtension && !info.InitHelper.IsZero() && nonBuilderReferencedFn[info.InitHelper] {
			delete(verifiedRoles, k)
		}
	}
	hasVerifiedRole := func(t TypeRef, role string) bool {
		_, ok := verifiedRoles[rtRoleKey{Type: t, Role: role}]
		return ok
	}

	protoVerifiedVars := intersectDeclaredVarSet(func(pkgPath string, fact Fact) map[string]bool {
		if anyMalformedDirectVarWrite {
			return nil
		}
		m := map[string]bool{}
		for _, c := range fact.ProtoClusters {
			if c.InitFn.Pkg != pkgPath || refRegions[c.InitFn] == nil || !initOnlyFn[c.InitFn] {
				continue
			}
			if !hasVerifiedRole(c.BuilderType, ProtoRoleBuilder) {
				continue
			}
			if !c.EnumType.IsZero() && !hasVerifiedRole(c.EnumType, ProtoRoleEnum) {
				continue
			}
			if !c.MsgType.IsZero() && !hasVerifiedRole(c.MsgType, ProtoRoleMessage) {
				continue
			}
			if !c.ExtType.IsZero() && !hasVerifiedRole(c.ExtType, ProtoRoleExtension) {
				continue
			}
			for _, key := range c.Vars {
				if !directVarWritten[key] {
					m[key] = true
				}
			}
		}
		return m
	})

	extAliasTargets := map[string]string{}
	if !anyMalformedDirectVarWrite {
		for pkgPath, pkgFacts := range allFacts {
			if pkgHasMalformedFact[pkgPath] {
				continue
			}
			perKeyTarget := map[string]string{}
			perKeyValid := map[string]bool{}
			for _, fact := range pkgFacts {
				byKey := make(map[string]string, len(fact.ProtoExtAliases))
				for _, a := range fact.ProtoExtAliases {
					byKey[a.Key] = a.Target
				}
				for _, key := range fact.Declares {
					target, ok := byKey[key]
					if prevValid, seen := perKeyValid[key]; seen {
						if !prevValid || !ok || perKeyTarget[key] != target {
							perKeyValid[key] = false
						}
					} else if ok {
						perKeyValid[key] = true
						perKeyTarget[key] = target
					} else {
						perKeyValid[key] = false
					}
				}
			}
			for key, ok := range perKeyValid {
				if ok && !malformedFactVars[key] && !directVarWritten[key] {
					extAliasTargets[key] = perKeyTarget[key]
				}
			}
		}
	}
	for changed := len(extAliasTargets) > 0; changed; {
		changed = false
		for key, target := range extAliasTargets {
			if !protoVerifiedVars[key] && protoVerifiedVars[target] {
				protoVerifiedVars[key] = true
				changed = true
			}
		}
	}

	grpcVerifiedVars := intersectDeclaredVarSet(func(_ string, fact Fact) map[string]bool {
		if anyMalformedMutatedStruct || anyMalformedDirectVarWrite {
			return nil
		}
		m := make(map[string]bool, len(fact.GrpcServiceVars))
		for _, gv := range fact.GrpcServiceVars {
			if mutatedStructs[gv.SvcDesc] {
				continue
			}
			if !gv.MethodDesc.IsZero() && mutatedStructs[gv.MethodDesc] {
				continue
			}
			if !gv.StreamDesc.IsZero() && mutatedStructs[gv.StreamDesc] {
				continue
			}
			if directVarWritten[gv.Key] {
				continue
			}
			m[gv.Key] = true
		}
		return m
	})

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
		return (pinnedPkg[pkgPath] || mutableLocalPkg[pkgPath]) && !malformedFactVars[key] &&
			(mappingDischargedVars[key] || memoDischargedVars[key])
	}
	directiveCovered := intersectDeclaredVarSet(func(_ string, fact Fact) map[string]bool {
		directed := make(map[string]bool, len(fact.SingleSubjectVars))
		for _, key := range fact.SingleSubjectVars {
			directed[key] = true
		}
		return directed
	})
	directiveDischargedOut := func(pkgPath, key string) bool {
		if !singleSubject || !mutableLocalPkg[pkgPath] || !directiveCovered[key] || malformedFactVars[key] {
			return false
		}
		if seen := "directive\x00" + pkgPath + "\x00" + key; !dischargedSeen[seen] {
			dischargedSeen[seen] = true
			attestedDischarged[pkgPath] = append(attestedDischarged[pkgPath], key)
		}
		return true
	}
	protoGrpcDischargedOut := func(pkgPath, key string) bool {
		if !singleSubject || (!pinnedPkg[pkgPath] && !mutableLocalPkg[pkgPath]) || malformedFactVars[key] {
			return false
		}
		if !protoVerifiedVars[key] && !grpcVerifiedVars[key] {
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
				if mutated[key] && !vouchedOut(pkgPath, key) && !auditedSourceOut(pkgPath, key) && !directiveDischargedOut(pkgPath, key) && !protoGrpcDischargedOut(pkgPath, key) {
					recordCulprit(pkgPath, key, CulpritMutated)
				}
			}
		}
		for _, fact := range allFacts[pkgPath] {
			for _, key := range fact.Declares {
				if escaped[key] && notOpaque[key] && !vouchedOut(pkgPath, key) && !auditedSourceOut(pkgPath, key) && !directiveDischargedOut(pkgPath, key) && !protoGrpcDischargedOut(pkgPath, key) {
					recordCulprit(pkgPath, key, CulpritEscapes)
				}
			}
		}
		for _, fact := range allFacts[pkgPath] {
			for _, key := range fact.Declares {
				if envCarrying[key] && !vouchedOut(pkgPath, key) && !auditedSourceOut(pkgPath, key) && !directiveDischargedOut(pkgPath, key) && !protoGrpcDischargedOut(pkgPath, key) {
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
