package dynstate

import (
	"slices"

	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// DeferralResolution is the composed proof state every deferred mark resolves
// against — the leak-free parameter union, the receiver read-only union, the
// return-environment-free fixed point, and the registered field populations
// (REQ-explain-chain).
type DeferralResolution struct {
	ParamLeakFree      map[syntaxutil.ParamKey]bool
	ParamRetentionFree map[syntaxutil.ParamKey]bool
	ReadOnly           map[syntaxutil.FuncKey]bool
	ReceiverRetention  map[syntaxutil.FuncKey]bool
	NotOpaque          map[string]bool
	EnvFreeResolved    map[syntaxutil.FuncKey]bool
	EnvFreeDeps        map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool

	FieldDeferAt  map[syntaxutil.FieldPosKey][]syntaxutil.ParamKey
	FieldPoisonAt map[syntaxutil.FieldParamPoison]bool
	RetDeferAt    map[syntaxutil.ReturnFieldPosKey][]syntaxutil.ParamKey
	RetPoisonAt   map[syntaxutil.ReturnFieldParamPoison]bool
	CtorsOf       map[string][]syntaxutil.FuncKey
}

// EnvAuditResolution is the environment-audit resolution shared by the verdict
// composition and explain: return-environment-free and argument-insertion
// claims resolve in one least fixed point over their conditional edges
// (REQ-closure-shared-dynamic-state).
type EnvAuditResolution struct {
	Declared    map[syntaxutil.FuncKey]bool
	InsDeclared map[syntaxutil.ParamKey]bool
	Resolved    map[syntaxutil.FuncKey]bool
	InsResolved map[syntaxutil.ParamKey]bool
	RetDeps     map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool
	RetInsDeps  map[syntaxutil.FuncKey]map[syntaxutil.EnvAuditTarget]bool
	InsDeps     map[syntaxutil.ParamKey]map[syntaxutil.EnvAuditTarget]bool
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

// ResolveEnvAudit computes the joint least fixed point over ReturnEnvFree and
// ParamInsertionFree claims across allFacts.
func ResolveEnvAudit(allFacts map[string][]Fact, malformed func(fact Fact)) *EnvAuditResolution {
	e := &EnvAuditResolution{
		Declared:    map[syntaxutil.FuncKey]bool{},
		InsDeclared: map[syntaxutil.ParamKey]bool{},
		Resolved:    map[syntaxutil.FuncKey]bool{},
		InsResolved: map[syntaxutil.ParamKey]bool{},
		RetDeps:     map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool{},
		RetInsDeps:  map[syntaxutil.FuncKey]map[syntaxutil.EnvAuditTarget]bool{},
		InsDeps:     map[syntaxutil.ParamKey]map[syntaxutil.EnvAuditTarget]bool{},
	}
	if malformed == nil {
		malformed = func(Fact) {}
	}
	poisonedFunc := map[syntaxutil.FuncKey]bool{}
	poisonedParam := map[syntaxutil.ParamKey]bool{}
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
					e.RetDeps[edge.Func] = map[syntaxutil.FuncKey]bool{}
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
					e.RetInsDeps[edge.Func] = map[syntaxutil.EnvAuditTarget]bool{}
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
					e.InsDeps[edge.Param] = map[syntaxutil.EnvAuditTarget]bool{}
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
		ParamLeakFree:      map[syntaxutil.ParamKey]bool{},
		ParamRetentionFree: map[syntaxutil.ParamKey]bool{},
		ReadOnly:           map[syntaxutil.FuncKey]bool{},
		ReceiverRetention:  map[syntaxutil.FuncKey]bool{},
		NotOpaque:          map[string]bool{},
		EnvFreeResolved:    map[syntaxutil.FuncKey]bool{},
		EnvFreeDeps:        map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool{},

		FieldDeferAt:  map[syntaxutil.FieldPosKey][]syntaxutil.ParamKey{},
		FieldPoisonAt: map[syntaxutil.FieldParamPoison]bool{},
		RetDeferAt:    map[syntaxutil.ReturnFieldPosKey][]syntaxutil.ParamKey{},
		RetPoisonAt:   map[syntaxutil.ReturnFieldParamPoison]bool{},
		CtorsOf:       map[string][]syntaxutil.FuncKey{},
	}
	if malformed == nil {
		malformed = func(Fact) {}
	}

	declaredKeys := map[string]bool{}
	opaqueDeps := map[string]map[string]bool{}
	paramDeps := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	retentionDeps := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	poisonedLeakParam := map[syntaxutil.ParamKey]bool{}
	poisonedRetParam := map[syntaxutil.ParamKey]bool{}
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
					paramDeps[edge.Own] = map[syntaxutil.ParamKey]bool{}
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
					retentionDeps[edge.Own] = map[syntaxutil.ParamKey]bool{}
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
					if syntaxutil.ValidFactKey(edge.Own) {
						r.NotOpaque[edge.Own] = true
					}
					continue
				}
				if opaqueDeps[edge.Own] == nil {
					opaqueDeps[edge.Own] = map[string]bool{}
				}
				opaqueDeps[edge.Own][edge.Dep] = true
			}
			for _, entry := range fact.FieldParamDefer {
				if !entry.Valid() {
					malformed(fact)
					if syntaxutil.ValidFactKey(entry.Pos.Owner) {
						r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: entry.Pos.Owner}] = true
					}
					continue
				}
				r.FieldDeferAt[entry.Pos] = append(r.FieldDeferAt[entry.Pos], entry.Param)
			}
			for _, entry := range fact.FieldParamPoison {
				if !entry.Valid() {
					malformed(fact)
					if syntaxutil.ValidFactKey(entry.Owner) {
						r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: entry.Owner}] = true
					}
					continue
				}
				r.FieldPoisonAt[entry] = true
			}
			for _, entry := range fact.ReturnFieldParamDefer {
				if !entry.Valid() {
					malformed(fact)
					if entry.Pos.Func.Valid() {
						r.RetPoisonAt[syntaxutil.ReturnFieldParamPoison{Func: entry.Pos.Func}] = true
					}
					continue
				}
				r.RetDeferAt[entry.Pos] = append(r.RetDeferAt[entry.Pos], entry.Param)
			}
			for _, entry := range fact.ReturnFieldParamPoison {
				if !entry.Valid() {
					malformed(fact)
					if entry.Func.Valid() {
						r.RetPoisonAt[syntaxutil.ReturnFieldParamPoison{Func: entry.Func}] = true
					}
					continue
				}
				r.RetPoisonAt[entry] = true
			}
			for _, use := range fact.EnvCallUses {
				if !use.Valid() {
					malformed(fact)
					if syntaxutil.ValidFactKey(use.Key) {
						r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: use.Key}] = true
					}
					continue
				}
				r.CtorsOf[use.Key] = append(r.CtorsOf[use.Key], use.Callee)
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

	syntaxutil.SolveLeastFixedPoint(r.ParamLeakFree, paramDeps, func(dep syntaxutil.ParamKey) bool {
		return r.ParamLeakFree[dep]
	})
	syntaxutil.SolveLeastFixedPoint(r.ParamRetentionFree, retentionDeps, func(dep syntaxutil.ParamKey) bool {
		return r.ParamRetentionFree[dep] || r.ParamLeakFree[dep]
	})
	syntaxutil.SolveReachFixedPoint(r.NotOpaque, opaqueDeps, func(dep string) bool {
		return r.NotOpaque[dep] || !declaredKeys[dep]
	})

	ea := ResolveEnvAudit(allFacts, malformed)
	r.EnvFreeResolved = ea.Resolved
	r.EnvFreeDeps = ea.RetDeps

	for pos, params := range r.FieldDeferAt {
		slices.SortFunc(params, syntaxutil.ParamKey.Compare)
		r.FieldDeferAt[pos] = slices.Compact(params)
	}
	for pos, params := range r.RetDeferAt {
		slices.SortFunc(params, syntaxutil.ParamKey.Compare)
		r.RetDeferAt[pos] = slices.Compact(params)
	}
	for key, ctors := range r.CtorsOf {
		slices.SortFunc(ctors, syntaxutil.FuncKey.Compare)
		r.CtorsOf[key] = slices.Compact(ctors)
	}
	return r
}

// FieldPopulationProves resolves one field-position use against the carrier's
// registered population. On failure the second result names the unproven
// deferred parameter key when one decided it — zero value when a poison or an
// unresolved constructor decided (REQ-closure-shared-dynamic-state,
// REQ-explain-chain).
func (r *DeferralResolution) FieldPopulationProves(varKey, field string, idx int) (bool, syntaxutil.ParamKey) {
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
	return true, syntaxutil.ParamKey{}
}
