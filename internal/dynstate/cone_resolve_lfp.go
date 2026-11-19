package dynstate

import (
	"slices"
	"strings"
	"time"

	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"github.com/greatliontech/gofresh/internal/trace"
)

// IsObjectClosed reports whether key is a declared package variable whose
// closed sentinel opacity remains unbroken across allFacts.
func (r *DeferralResolution) IsObjectClosed(key string) bool {
	return r != nil && r.Declared[key] && !r.NotOpaque[key]
}

// FieldPopulationProves resolves one field-position use against the carrier's
// registered population. On failure the second result names the unproven
// deferred parameter key when one decided it — zero value when a poison, an
// unresolved constructor, or an unproven carrier owner decided
// (REQ-closure-shared-dynamic-state, REQ-explain-chain).
func (r *DeferralResolution) FieldPopulationProves(varKey, field string, idx int) (bool, syntaxutil.ParamKey) {
	if r == nil {
		return false, syntaxutil.ParamKey{}
	}
	if r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: varKey}] ||
		r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: varKey, HasPos: true, Field: field, Index: -1}] ||
		r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: varKey, HasPos: true, Field: field, Index: idx}] {
		return false, syntaxutil.ParamKey{}
	}
	for _, paramKey := range r.FieldDeferAt[syntaxutil.FieldPosKey{Owner: varKey, Field: field, Index: idx}] {
		if !r.ParamLeakFree[paramKey] {
			return false, paramKey
		}
	}
	seen := map[syntaxutil.FuncKey]bool{}
	ctors := r.CtorsOf[varKey]
	stack := make([]syntaxutil.FuncKey, len(ctors))
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
			return false, syntaxutil.ParamKey{}
		}
		if r.RetPoisonAt[syntaxutil.ReturnFieldParamPoison{Func: fnKey}] ||
			r.RetPoisonAt[syntaxutil.ReturnFieldParamPoison{Func: fnKey, HasPos: true, Field: field, Index: -1}] ||
			r.RetPoisonAt[syntaxutil.ReturnFieldParamPoison{Func: fnKey, HasPos: true, Field: field, Index: idx}] {
			return false, syntaxutil.ParamKey{}
		}
		for _, paramKey := range r.RetDeferAt[syntaxutil.ReturnFieldPosKey{Func: fnKey, Field: field, Index: idx}] {
			if !r.ParamLeakFree[paramKey] {
				return false, paramKey
			}
		}
		if deps := r.EnvFreeDeps[fnKey]; len(deps) > 0 {
			sortedDeps := make([]syntaxutil.FuncKey, 0, len(deps))
			for dep := range deps {
				sortedDeps = append(sortedDeps, dep)
			}
			slices.SortFunc(sortedDeps, syntaxutil.FuncKey.Compare)
			for i := len(sortedDeps) - 1; i >= 0; i-- {
				stack = append(stack, sortedDeps[i])
			}
		}
	}
	if r.OwnerUnproven[varKey] {
		return false, syntaxutil.ParamKey{}
	}
	return true, syntaxutil.ParamKey{}
}

func (e *EnvAuditResolution) DepResolved(dep syntaxutil.EnvAuditTarget) bool {
	if !dep.Valid() {
		return false
	}
	if dep.IsParam() {
		return e.InsResolved[dep.Param()]
	}
	return e.Resolved[dep.Func]
}

// CarrierLinkGraph builds the symmetric adjacency map of init-flow carrier
// storage links across allFacts.
func CarrierLinkGraph(allFacts map[string][]Fact, malformed func(Fact)) map[string]map[string]bool {
	var validLinks []syntaxutil.CarrierLink
	for _, facts := range allFacts {
		for _, fact := range facts {
			bad := false
			for _, link := range fact.CarrierLinks {
				if !link.Valid() {
					bad = true
					continue
				}
				validLinks = append(validLinks, link)
			}
			if bad && malformed != nil {
				malformed(fact)
			}
		}
	}
	return buildCarrierLinkGraph(validLinks, nil)
}

func addMapSet[K, V comparable](m map[K]map[V]bool, k K, v V) {
	if m[k] == nil {
		m[k] = map[V]bool{}
	}
	m[k][v] = true
}

func buildCarrierLinkGraph(validLinks []syntaxutil.CarrierLink, resolution *DeferralResolution) map[string]map[string]bool {
	linkAdj := map[string]map[string]bool{}
	for _, link := range validLinks {
		if resolution != nil && (resolution.IsObjectClosed(link.From) || resolution.IsObjectClosed(link.To)) {
			continue
		}
		addMapSet(linkAdj, link.From, link.To)
		addMapSet(linkAdj, link.To, link.From)
	}
	return linkAdj
}

type coneResolveTables struct {
	q                           ConeQuery
	tracing                     bool
	traceStart                  time.Time
	allFacts                    map[string][]Fact
	pkgPaths                    []string
	r                           *DeferralResolution
	ea                          *EnvAuditResolution
	mutated                     map[string]bool
	escaped                     map[string]bool
	envCarrying                 map[string]bool
	envCallable                 map[string]bool
	unattributedMark            map[string]bool
	malformedFactVars           map[string]bool
	pkgHasMalformedFact         map[string]bool
	paramCandidates             map[syntaxutil.ParamKey]bool
	methodCandidates            map[syntaxutil.FuncKey]bool
	poisonedLeakParam           map[syntaxutil.ParamKey]bool
	poisonedMethod              map[syntaxutil.FuncKey]bool
	retentionDeps               map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool
	poisonedRetParam            map[syntaxutil.ParamKey]bool
	opaqueDeps                  map[string]map[string]bool
	poisonedEnvFunc             map[syntaxutil.FuncKey]bool
	poisonedEnvParam            map[syntaxutil.ParamKey]bool
	hasMalformedSeam            bool
	exportedSeams               []syntaxutil.ExportedSeam
	allSeamKeys                 []string
	parallelReached             map[syntaxutil.FuncKey]bool
	nonSeqReached               map[syntaxutil.FuncKey]bool
	seqAdj                      map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool
	revSeqAdj                   map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool
	revParAdj                   map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool
	validLinks                  []syntaxutil.CarrierLink
	validFieldUses              []syntaxutil.FieldPosKey
	validElemUses               []syntaxutil.ElemParamUse
	mutatedStructs              map[syntaxutil.TypeRef]bool
	directVarWritten            map[string]bool
	nonMethodVarUsed            map[string]bool
	anyMalformedMutatedStruct   bool
	anyMalformedDirectVarWrite  bool
	anyMalformedNonMethodVarUse bool
	allCondStructMutations      []syntaxutil.ConditionalStructMutation
}

func (crt *coneResolveTables) solveFixedPointsAndAssemble() *ConeAnalysis {
	// Stage 2a: Joint confinement least fixed point (ParamLeakFree & ReadOnly).
	for pk := range crt.paramCandidates {
		delete(crt.r.ParamLeakFree, pk)
	}
	for pk := range crt.poisonedLeakParam {
		delete(crt.r.ParamLeakFree, pk)
		delete(crt.paramCandidates, pk)
		delete(crt.ea.ParamDeps, pk)
		delete(crt.ea.ParamMethodDeps, pk)
	}
	for mk := range crt.methodCandidates {
		delete(crt.r.ReadOnly, mk)
	}
	for mk := range crt.poisonedMethod {
		delete(crt.r.ReadOnly, mk)
		delete(crt.methodCandidates, mk)
		delete(crt.ea.MethodDeps, mk)
		delete(crt.ea.MethodParamDeps, mk)
	}
	for changed := true; changed; {
		changed = false
		for pk := range crt.paramCandidates {
			if crt.r.ParamLeakFree[pk] {
				continue
			}
			ok := true
			for dep := range crt.ea.ParamDeps[pk] {
				if !crt.r.ParamLeakFree[dep] {
					ok = false
					break
				}
			}
			if ok {
				for mk := range crt.ea.ParamMethodDeps[pk] {
					if !crt.r.ReadOnly[mk] {
						ok = false
						break
					}
				}
			}
			if ok {
				crt.r.ParamLeakFree[pk] = true
				changed = true
			}
		}
		for mk := range crt.methodCandidates {
			if crt.r.ReadOnly[mk] {
				continue
			}
			ok := true
			for dep := range crt.ea.MethodDeps[mk] {
				if !crt.r.ReadOnly[dep] {
					ok = false
					break
				}
			}
			if ok {
				for pk := range crt.ea.MethodParamDeps[mk] {
					if !crt.r.ParamLeakFree[pk] {
						ok = false
						break
					}
				}
			}
			if ok {
				crt.r.ReadOnly[mk] = true
				changed = true
			}
		}
	}

	// Stage 2b: Parameter retention LFP & closed-object opacity reachability.
	for pk := range crt.poisonedRetParam {
		delete(crt.r.ParamRetentionFree, pk)
		delete(crt.retentionDeps, pk)
	}
	syntaxutil.SolveLeastFixedPoint(crt.r.ParamRetentionFree, crt.retentionDeps, func(dep syntaxutil.ParamKey) bool {
		return crt.r.ParamRetentionFree[dep] || crt.r.ParamLeakFree[dep]
	})
	syntaxutil.SolveReachFixedPoint(crt.r.NotOpaque, crt.opaqueDeps, func(dep string) bool {
		return crt.r.NotOpaque[dep] || !crt.r.Declared[dep]
	})
	for key := range crt.escaped {
		if !crt.r.IsObjectClosed(key) {
			crt.r.OwnerUnproven[key] = true
		}
	}

	// Stage 2c: Environment-audit joint LFP (ReturnEnvFree & ParamInsertionFree).
	for fnKey := range crt.poisonedEnvFunc {
		delete(crt.ea.Declared, fnKey)
	}
	for paramKey := range crt.poisonedEnvParam {
		delete(crt.ea.InsDeclared, paramKey)
	}
	for changed := true; changed; {
		changed = false
		for fnKey := range crt.ea.Declared {
			if crt.ea.Resolved[fnKey] {
				continue
			}
			ok := true
			for dep := range crt.ea.RetDeps[fnKey] {
				if !crt.ea.Resolved[dep] {
					ok = false
					break
				}
			}
			if ok {
				for pk := range crt.ea.RetParamDeps[fnKey] {
					if !crt.ea.ParamLeakFree[pk] {
						ok = false
						break
					}
				}
			}
			if ok {
				for mk := range crt.ea.RetMethodDeps[fnKey] {
					if !crt.ea.ReadOnly[mk] {
						ok = false
						break
					}
				}
			}
			if ok {
				for dep := range crt.ea.RetInsDeps[fnKey] {
					if !crt.ea.DepResolved(dep) {
						ok = false
						break
					}
				}
			}
			if ok {
				crt.ea.Resolved[fnKey] = true
				changed = true
			}
		}
		for paramKey := range crt.ea.InsDeclared {
			if crt.ea.InsResolved[paramKey] {
				continue
			}
			ok := true
			for dep := range crt.ea.InsDeps[paramKey] {
				if !crt.ea.DepResolved(dep) {
					ok = false
					break
				}
			}
			if ok {
				for pk := range crt.ea.InsParamDeps[paramKey] {
					if !crt.ea.ParamLeakFree[pk] {
						ok = false
						break
					}
				}
			}
			if ok {
				for mk := range crt.ea.InsMethodDeps[paramKey] {
					if !crt.ea.ReadOnly[mk] {
						ok = false
						break
					}
				}
			}
			if ok {
				crt.ea.InsResolved[paramKey] = true
				changed = true
			}
		}
	}
	crt.r.EnvFreeResolved = crt.ea.Resolved

	// Stage 2d: Call-region fixed points (InitOnlyFn & InitReachFn).
	syntaxutil.SolveLeastFixedPoint(crt.r.InitOnlyFn, crt.r.RefRegions, func(region syntaxutil.RefRegion) bool {
		if region.Kind == syntaxutil.RegionInit {
			return true
		}
		return region.Kind == syntaxutil.RegionFunc && crt.r.InitOnlyFn[region.Caller]
	})
	syntaxutil.SolveReachFixedPoint(crt.r.InitReachFn, crt.r.RefRegions, func(region syntaxutil.RefRegion) bool {
		if region.Kind == syntaxutil.RegionInit || region.Kind == syntaxutil.RegionProg {
			return true
		}
		return (region.Kind == syntaxutil.RegionFunc || region.Kind == syntaxutil.RegionLitFunc) && crt.r.InitReachFn[region.Caller]
	})

	// Stage 2e: Blocked exported seams.
	blockedSeams := map[string]map[syntaxutil.FuncKey]bool{}
	if crt.hasMalformedSeam {
		for _, key := range crt.allSeamKeys {
			addMapSet(blockedSeams, key, syntaxutil.FuncKey{})
		}
	} else if len(crt.exportedSeams) > 0 {
		if len(crt.parallelReached) > 0 && len(crt.revParAdj) > 0 {
			syntaxutil.PropagateBFS(crt.parallelReached, crt.revParAdj)
		}
		for fn := range crt.parallelReached {
			if fn.Pkg != "*" && !strings.Contains(fn.Name, "#") {
				crt.nonSeqReached[fn] = true
			}
		}
		if len(crt.nonSeqReached) > 0 && len(crt.seqAdj) > 0 {
			syntaxutil.PropagateBFS(crt.nonSeqReached, crt.seqAdj)
		}
		for _, es := range crt.exportedSeams {
			if crt.nonSeqReached[es.Func] || (es.RunnerOnly && len(crt.revSeqAdj[es.Func]) > 0) {
				addMapSet(blockedSeams, es.Key, es.Func)
			}
		}
	}

	// Stage 2f: Active carrier link graph and component population pooling.
	linkAdj := buildCarrierLinkGraph(crt.validLinks, crt.r)
	if len(linkAdj) > 0 {
		visited := map[string]bool{}
		var components [][]string
		for _, link := range crt.validLinks {
			for _, start := range [2]string{link.From, link.To} {
				if linkAdj[start] == nil || visited[start] {
					continue
				}
				visited[start] = true
				comp := []string{start}
				for i := 0; i < len(comp); i++ {
					for next := range linkAdj[comp[i]] {
						if !visited[next] {
							visited[next] = true
							comp = append(comp, next)
						}
					}
				}
				if len(comp) > 1 {
					components = append(components, comp)
				}
			}
		}
		if len(components) > 0 {
			compOf := map[string]int{}
			for idx, comp := range components {
				for _, k := range comp {
					compOf[k] = idx + 1
				}
			}
			for _, comp := range components {
				var pooledCtors []syntaxutil.FuncKey
				for _, k := range comp {
					pooledCtors = append(pooledCtors, crt.r.CtorsOf[k]...)
				}
				if len(pooledCtors) > 0 {
					slices.SortFunc(pooledCtors, syntaxutil.FuncKey.Compare)
					pooledCtors = slices.Compact(pooledCtors)
					for _, k := range comp {
						crt.r.CtorsOf[k] = pooledCtors
					}
				}
			}
			type poisonEntry struct {
				compIdx int
				hasPos  bool
				field   string
				index   int
			}
			var addPoisons []poisonEntry
			for p := range crt.r.FieldPoisonAt {
				if cid := compOf[p.Owner]; cid > 0 {
					addPoisons = append(addPoisons, poisonEntry{compIdx: cid - 1, hasPos: p.HasPos, field: p.Field, index: p.Index})
				}
			}
			for _, pe := range addPoisons {
				for _, k := range components[pe.compIdx] {
					crt.r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: k, HasPos: pe.hasPos, Field: pe.field, Index: pe.index}] = true
				}
			}
			type deferEntry struct {
				compIdx int
				field   string
				index   int
				params  []syntaxutil.ParamKey
			}
			var addDefers []deferEntry
			for pos, params := range crt.r.FieldDeferAt {
				if cid := compOf[pos.Owner]; cid > 0 {
					addDefers = append(addDefers, deferEntry{compIdx: cid - 1, field: pos.Field, index: pos.Index, params: params})
				}
			}
			for _, de := range addDefers {
				for _, k := range components[de.compIdx] {
					targetPos := syntaxutil.FieldPosKey{Owner: k, Field: de.field, Index: de.index}
					crt.r.FieldDeferAt[targetPos] = append(crt.r.FieldDeferAt[targetPos], de.params...)
				}
			}
		}
	}
	for pos, params := range crt.r.FieldDeferAt {
		slices.SortFunc(params, syntaxutil.ParamKey.Compare)
		crt.r.FieldDeferAt[pos] = slices.Compact(params)
	}
	for pos, params := range crt.r.RetDeferAt {
		slices.SortFunc(params, syntaxutil.ParamKey.Compare)
		crt.r.RetDeferAt[pos] = slices.Compact(params)
	}
	for key, ctors := range crt.r.CtorsOf {
		slices.SortFunc(ctors, syntaxutil.FuncKey.Compare)
		crt.r.CtorsOf[key] = slices.Compact(ctors)
	}

	// Stage 2g: Unified deferred mark resolution, site attribution, and OwnerUnproven seeding.
	siteFns := map[string]map[string]bool{}
	attributeSite := func(key string, fn syntaxutil.FuncKey) {
		addMapSet(siteFns, key, fn.SiteKey())
	}
	mayRunAtInit := func(fn syntaxutil.FuncKey) bool {
		return crt.r.InitReachFn[fn] || strings.Contains(fn.Name, ".")
	}
	isInitOnlyPlain := func(fn syntaxutil.FuncKey) bool {
		return crt.r.RefRegions[fn] != nil && crt.r.InitOnlyFn[fn]
	}
	markEscaped := func(key string) {
		crt.escaped[key] = true
		if !crt.r.IsObjectClosed(key) {
			crt.r.OwnerUnproven[key] = true
		}
	}
	markMutated := func(key string) {
		crt.mutated[key] = true
		crt.r.OwnerUnproven[key] = true
	}
	applyAttributedUse := func(use syntaxutil.AttributedUse) {
		if !use.Valid() {
			return
		}
		fn, key := use.Func, use.Key
		if use.Literal {
			if use.HasMethod {
				if crt.r.ReadOnly[use.Method] {
					return
				}
				markMutated(key)
			} else if use.Escape {
				markEscaped(key)
			} else {
				markMutated(key)
			}
			if mayRunAtInit(fn) {
				crt.unattributedMark[key] = true
			} else {
				attributeSite(key, fn)
			}
			return
		}
		if use.Escape {
			markEscaped(key)
			if mayRunAtInit(fn) {
				crt.unattributedMark[key] = true
			} else {
				attributeSite(key, fn)
			}
			return
		}
		if use.HasMethod {
			if crt.r.ReadOnly[use.Method] {
				return
			}
			if isInitOnlyPlain(fn) {
				if !crt.r.ReceiverRetention[use.Method] {
					markMutated(key)
					crt.unattributedMark[key] = true
				}
				return
			}
			markMutated(key)
			if !crt.r.ReceiverRetention[use.Method] && mayRunAtInit(fn) {
				crt.unattributedMark[key] = true
			} else {
				attributeSite(key, fn)
			}
			return
		}
		if isInitOnlyPlain(fn) {
			return
		}
		markMutated(key)
		attributeSite(key, fn)
	}

	for _, pkgPath := range crt.pkgPaths {
		for _, fact := range crt.allFacts[pkgPath] {
			var factAttrEnv map[string][]syntaxutil.FuncKey
			if len(fact.EnvCarryingFns) > 0 {
				factAttrEnv = make(map[string][]syntaxutil.FuncKey, len(fact.EnvCarryingFns))
				for _, use := range fact.EnvCarryingFns {
					if use.Valid() {
						factAttrEnv[use.Key] = append(factAttrEnv[use.Key], use.Func)
					}
				}
			}
			for _, key := range fact.EnvCarrying {
				if !syntaxutil.ValidFactKey(key) {
					continue
				}
				fns := factAttrEnv[key]
				if crt.envCallable[key] || len(fns) == 0 {
					crt.unattributedMark[key] = true
					continue
				}
				for _, fn := range fns {
					if mayRunAtInit(fn) {
						crt.unattributedMark[key] = true
					} else {
						attributeSite(key, fn)
					}
				}
			}
			for _, use := range fact.EnvCallUses {
				if !use.Valid() || crt.r.EnvFreeResolved[use.Callee] {
					continue
				}
				// Keep r.OwnerUnproven[use.Key] unset: FieldPopulationProves
				// inspects r.CtorsOf[use.Key] directly.
				crt.envCarrying[use.Key] = true
				if use.Func.IsZero() || crt.envCallable[use.Key] || mayRunAtInit(use.Func) {
					crt.unattributedMark[use.Key] = true
				} else {
					attributeSite(use.Key, use.Func)
				}
			}
			for _, use := range fact.EnvCallParamUses {
				if !use.Valid() || crt.r.ParamLeakFree[use.Param] {
					continue
				}
				crt.envCarrying[use.Key] = true
				crt.r.OwnerUnproven[use.Key] = true
				if use.Func.IsZero() || crt.envCallable[use.Key] || mayRunAtInit(use.Func) {
					crt.unattributedMark[use.Key] = true
				} else {
					attributeSite(use.Key, use.Func)
				}
			}
			for _, use := range fact.EnvCallMethodUses {
				if !use.Valid() || crt.r.ReadOnly[use.Method] {
					continue
				}
				crt.envCarrying[use.Key] = true
				crt.r.OwnerUnproven[use.Key] = true
				if use.Func.IsZero() || crt.envCallable[use.Key] || mayRunAtInit(use.Func) {
					crt.unattributedMark[use.Key] = true
				} else {
					attributeSite(use.Key, use.Func)
				}
			}
			for _, use := range fact.MethodUses {
				if use.Valid() && !crt.r.ReadOnly[use.Method] {
					markMutated(use.Key)
					crt.unattributedMark[use.Key] = true
				}
			}
			for _, use := range fact.InitMethodUses {
				if use.Valid() && !crt.r.ReceiverRetention[use.Method] {
					markEscaped(use.Key)
					crt.unattributedMark[use.Key] = true
				}
			}
			for _, use := range fact.ParamUses {
				if !use.Valid() || crt.r.ParamLeakFree[use.Param] {
					continue
				}
				if use.Func.IsZero() {
					markEscaped(use.Key)
					crt.unattributedMark[use.Key] = true
					continue
				}
				fn, key := use.Func, use.Key
				if use.Literal {
					markEscaped(key)
					if mayRunAtInit(fn) {
						crt.unattributedMark[key] = true
					} else {
						attributeSite(key, fn)
					}
					continue
				}
				if isInitOnlyPlain(fn) {
					if !crt.r.ParamRetentionFree[use.Param] {
						markEscaped(key)
						crt.unattributedMark[key] = true
					}
					continue
				}
				markEscaped(key)
				if !crt.r.ParamRetentionFree[use.Param] && mayRunAtInit(fn) {
					crt.unattributedMark[key] = true
				} else {
					attributeSite(key, fn)
				}
			}
			for _, use := range fact.InitParamUses {
				if use.Valid() && use.Func.IsZero() && !crt.r.ParamLeakFree[use.Param] && !crt.r.ParamRetentionFree[use.Param] {
					markEscaped(use.Key)
					crt.unattributedMark[use.Key] = true
				}
			}
			for _, use := range fact.AttributedUses {
				applyAttributedUse(use)
			}
			if !crt.q.SingleSubject {
				for _, use := range fact.PoolAttributedUses {
					applyAttributedUse(use)
				}
			}
		}
	}
	for key, fns := range blockedSeams {
		markMutated(key)
		for fn := range fns {
			if !fn.Valid() || mayRunAtInit(fn) {
				crt.unattributedMark[key] = true
			} else {
				attributeSite(key, fn)
			}
		}
	}
	for key := range crt.envCarrying {
		if crt.envCallable[key] {
			crt.unattributedMark[key] = true
		}
	}

	// Stage 2h: Converge OwnerUnproven across LinkAdj, FieldParamUses, and
	// ElemParamUses (note LinkAdj already excludes IsObjectClosed endpoints),
	// then evaluate FieldParamUses/ElemParamUses escapes and propagate marks
	// across LinkAdj.
	for changed := true; changed; {
		changed = false
		for key := range crt.r.OwnerUnproven {
			for next := range linkAdj[key] {
				if !crt.r.OwnerUnproven[next] {
					crt.r.OwnerUnproven[next] = true
					changed = true
				}
			}
		}
		for _, use := range crt.validFieldUses {
			if len(linkAdj[use.Owner]) == 0 {
				continue
			}
			// Neighbor-only propagation: never set r.OwnerUnproven[use.Owner]
			// from use.Owner's own failed FieldParamUses.
			if ok, _ := crt.r.FieldPopulationProves(use.Owner, use.Field, use.Index); !ok {
				for next := range linkAdj[use.Owner] {
					if !crt.r.OwnerUnproven[next] {
						crt.r.OwnerUnproven[next] = true
						changed = true
					}
				}
			}
		}
		for _, use := range crt.validElemUses {
			if crt.r.IsObjectClosed(use.Key) || crt.r.OwnerUnproven[use.Key] {
				continue
			}
			if ok, _ := crt.r.FieldPopulationProves(use.Owner, syntaxutil.ElemPositionField, use.Index); !ok {
				crt.r.OwnerUnproven[use.Key] = true
				changed = true
			}
		}
	}
	for _, use := range crt.validFieldUses {
		if ok, _ := crt.r.FieldPopulationProves(use.Owner, use.Field, use.Index); !ok {
			crt.escaped[use.Owner] = true
			crt.unattributedMark[use.Owner] = true
		}
	}
	for _, use := range crt.validElemUses {
		if ok, _ := crt.r.FieldPopulationProves(use.Owner, syntaxutil.ElemPositionField, use.Index); !ok {
			crt.escaped[use.Key] = true
			crt.unattributedMark[use.Key] = true
		}
	}
	if len(linkAdj) > 0 {
		propagateWithUnattributed := func(set map[string]bool) {
			if len(set) == 0 {
				return
			}
			queue := make([]string, 0, len(set))
			for k := range set {
				if linkAdj[k] != nil {
					queue = append(queue, k)
				}
			}
			for len(queue) > 0 {
				cur := queue[len(queue)-1]
				queue = queue[:len(queue)-1]
				for next := range linkAdj[cur] {
					crt.unattributedMark[next] = true
					if !set[next] {
						set[next] = true
						queue = append(queue, next)
					}
				}
			}
		}
		propagateWithUnattributed(crt.mutated)
		propagateWithUnattributed(crt.escaped)
		propagateWithUnattributed(crt.envCarrying)
	}

	out := &ConeAnalysis{
		Deferral:           crt.r,
		EnvAudit:           crt.ea,
		BlockedSeams:       blockedSeams,
		LinkAdj:            linkAdj,
		NonVouchDischarged: map[string]bool{},
	}
	if len(crt.q.Meta) == 0 && crt.q.ViewPackage == "" {
		return out
	}

	// Stage 3: Discharges and view-package ConeState assembly.
	discharges := deriveConeDischarges(
		crt.q.Ctx,
		crt.q.ViewPackage,
		crt.q.Meta,
		crt.pkgPaths,
		crt.allFacts,
		crt.r.RefRegions,
		crt.r.InitOnlyFn,
		crt.r.ParamLeakFree,
		crt.pkgHasMalformedFact,
		crt.malformedFactVars,
		crt.mutatedStructs,
		crt.allCondStructMutations,
		crt.directVarWritten,
		crt.nonMethodVarUsed,
		crt.anyMalformedMutatedStruct,
		crt.anyMalformedDirectVarWrite,
		crt.anyMalformedNonMethodVarUse,
	)

	for _, pkgPath := range crt.pkgPaths {
		inGraph := discharges.pinnedPkg[pkgPath] || discharges.mutableLocalPkg[pkgPath]
		if !inGraph || crt.pkgHasMalformedFact[pkgPath] {
			continue
		}
		for _, fact := range crt.allFacts[pkgPath] {
			for _, key := range fact.Declares {
				if crt.malformedFactVars[key] {
					continue
				}
				if discharges.isAttestationFreeDischarged(pkgPath, key, crt.malformedFactVars) {
					out.NonVouchDischarged[key] = true
					continue
				}
				if crt.q.SingleSubject && discharges.mutableLocalPkg[pkgPath] && discharges.directiveCovered[key] {
					out.NonVouchDischarged[key] = true
					continue
				}
				if discharges.isClusterAttestedDischarged(pkgPath, key, crt.q.SingleSubject, crt.malformedFactVars) {
					out.NonVouchDischarged[key] = true
				}
			}
		}
	}

	if crt.q.ViewPackage == "" {
		return out
	}

	out.State = buildViewConeState(
		crt.q,
		crt.pkgPaths,
		crt.allFacts,
		crt.r.NotOpaque,
		crt.mutated,
		crt.escaped,
		crt.envCarrying,
		crt.unattributedMark,
		siteFns,
		crt.pkgHasMalformedFact,
		crt.malformedFactVars,
		discharges,
	)
	if crt.tracing {
		trace.Emit(crt.q.Ctx, trace.DomainDynstate, "dynstate.compose.done", crt.q.ViewPackage,
			trace.Int("cone_pkgs", len(crt.allFacts)),
			trace.Bool("downgraded", out.State.Downgraded != ""),
			trace.Int("culprits", len(out.State.RootCulprits)),
			trace.Int64("dur_ns", time.Since(crt.traceStart).Nanoseconds()),
		)
	}
	return out
}
