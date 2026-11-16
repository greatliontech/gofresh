package dynstate

import (
	"go/token"
	"slices"
	"strings"

	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// DeferralResolution is the composed proof state every deferred mark resolves
// against — the leak-free parameter union, the receiver read-only union, the
// return-environment-free fixed point, and the registered field populations
// (REQ-explain-chain).
type DeferralResolution struct {
	Declared           map[string]bool
	ParamLeakFree      map[syntaxutil.ParamKey]bool
	ParamRetentionFree map[syntaxutil.ParamKey]bool
	ReadOnly           map[syntaxutil.FuncKey]bool
	ReceiverRetention  map[syntaxutil.FuncKey]bool
	NotOpaque          map[string]bool
	OwnerUnproven      map[string]bool
	EnvFreeResolved    map[syntaxutil.FuncKey]bool
	EnvFreeDeps        map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool
	RefRegions         map[syntaxutil.FuncKey]map[syntaxutil.RefRegion]bool
	InitOnlyFn         map[syntaxutil.FuncKey]bool
	InitReachFn        map[syntaxutil.FuncKey]bool

	StringUnsafePackages       map[string]bool
	ReturnStringUnsafePackages map[string]bool
	BoundedRoots               bool

	FieldDeferAt  map[syntaxutil.FieldPosKey][]syntaxutil.ParamKey
	FieldPoisonAt map[syntaxutil.FieldParamPoison]bool
	RetDeferAt    map[syntaxutil.ReturnFieldPosKey][]syntaxutil.ParamKey
	RetPoisonAt   map[syntaxutil.ReturnFieldParamPoison]bool
	CtorsOf       map[string][]syntaxutil.FuncKey
}

// AppliesStringAttributedUse reports whether a return-string escape use in
// pkgPath is reachable by a string-header unsafe consumer in this cone.
func (r *DeferralResolution) AppliesStringAttributedUse(pkgPath string, fn syntaxutil.FuncKey) bool {
	if r == nil {
		return false
	}
	if r.ReturnStringUnsafePackages[pkgPath] {
		return true
	}
	if !r.StringUnsafePackages[pkgPath] {
		return false
	}
	if fn.IsZero() || strings.Contains(fn.Name, ".") {
		return true
	}
	if !r.BoundedRoots && token.IsExported(fn.Name) {
		return true
	}
	return r.RefRegions[fn] != nil
}

// IsObjectClosed reports whether key is a declared package variable whose
// closed sentinel opacity remains unbroken across allFacts.
func (r *DeferralResolution) IsObjectClosed(key string) bool {
	return r != nil && r.Declared[key] && !r.NotOpaque[key]
}

// EnvAuditResolution is the environment-audit resolution shared by the verdict
// composition and explain: return-environment-free and argument-insertion
// claims resolve in one least fixed point over their conditional edges
// (REQ-closure-shared-dynamic-state).
type EnvAuditResolution struct {
	Declared        map[syntaxutil.FuncKey]bool
	InsDeclared     map[syntaxutil.ParamKey]bool
	Resolved        map[syntaxutil.FuncKey]bool
	InsResolved     map[syntaxutil.ParamKey]bool
	RetDeps         map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool
	RetParamDeps    map[syntaxutil.FuncKey]map[syntaxutil.ParamKey]bool
	RetMethodDeps   map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool
	RetInsDeps      map[syntaxutil.FuncKey]map[syntaxutil.EnvAuditTarget]bool
	InsDeps         map[syntaxutil.ParamKey]map[syntaxutil.EnvAuditTarget]bool
	InsParamDeps    map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool
	InsMethodDeps   map[syntaxutil.ParamKey]map[syntaxutil.FuncKey]bool
	ParamLeakFree   map[syntaxutil.ParamKey]bool
	ReadOnly        map[syntaxutil.FuncKey]bool
	ParamDeps       map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool
	ParamMethodDeps map[syntaxutil.ParamKey]map[syntaxutil.FuncKey]bool
	MethodDeps           map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool
	MethodParamDeps      map[syntaxutil.FuncKey]map[syntaxutil.ParamKey]bool
	StringUnsafePackages map[string]bool
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

type confinementResolution struct {
	paramLeakFree   map[syntaxutil.ParamKey]bool
	readOnly        map[syntaxutil.FuncKey]bool
	paramDeps       map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool
	paramMethodDeps map[syntaxutil.ParamKey]map[syntaxutil.FuncKey]bool
	methodDeps      map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool
	methodParamDeps map[syntaxutil.FuncKey]map[syntaxutil.ParamKey]bool
}

func resolveConfinementJointLFP(allFacts map[string][]Fact, malformed func(fact Fact)) confinementResolution {
	if malformed == nil {
		malformed = func(Fact) {}
	}
	res := confinementResolution{
		paramLeakFree:   map[syntaxutil.ParamKey]bool{},
		readOnly:        map[syntaxutil.FuncKey]bool{},
		paramDeps:       map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{},
		paramMethodDeps: map[syntaxutil.ParamKey]map[syntaxutil.FuncKey]bool{},
		methodDeps:      map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool{},
		methodParamDeps: map[syntaxutil.FuncKey]map[syntaxutil.ParamKey]bool{},
	}
	paramCandidates := map[syntaxutil.ParamKey]bool{}
	methodCandidates := map[syntaxutil.FuncKey]bool{}
	poisonedParam := map[syntaxutil.ParamKey]bool{}
	poisonedMethod := map[syntaxutil.FuncKey]bool{}

	for _, facts := range allFacts {
		for _, fact := range facts {
			for _, key := range fact.ParamLeakFree {
				if !key.Valid() {
					malformed(fact)
					continue
				}
				res.paramLeakFree[key] = true
			}
			for _, edge := range fact.ParamLeakFreeDeps {
				if !edge.Valid() {
					malformed(fact)
					if edge.Own.Valid() {
						poisonedParam[edge.Own] = true
					}
					continue
				}
				paramCandidates[edge.Own] = true
				if res.paramDeps[edge.Own] == nil {
					res.paramDeps[edge.Own] = map[syntaxutil.ParamKey]bool{}
				}
				res.paramDeps[edge.Own][edge.Dep] = true
			}
			for _, edge := range fact.ParamLeakFreeMethodDeps {
				if !edge.Valid() {
					malformed(fact)
					if edge.Param.Valid() {
						poisonedParam[edge.Param] = true
					}
					continue
				}
				paramCandidates[edge.Param] = true
				if res.paramMethodDeps[edge.Param] == nil {
					res.paramMethodDeps[edge.Param] = map[syntaxutil.FuncKey]bool{}
				}
				res.paramMethodDeps[edge.Param][edge.Method] = true
			}
			for _, key := range fact.ReceiverReadOnly {
				if !key.Valid() {
					malformed(fact)
					continue
				}
				res.readOnly[key] = true
			}
			for _, edge := range fact.ReceiverReadOnlyDeps {
				if !edge.Valid() {
					malformed(fact)
					if edge.Func.Valid() {
						poisonedMethod[edge.Func] = true
					}
					continue
				}
				methodCandidates[edge.Func] = true
				if res.methodDeps[edge.Func] == nil {
					res.methodDeps[edge.Func] = map[syntaxutil.FuncKey]bool{}
				}
				res.methodDeps[edge.Func][edge.Callee] = true
			}
			for _, edge := range fact.ReceiverReadOnlyParamDeps {
				if !edge.Valid() {
					malformed(fact)
					if edge.Func.Valid() {
						poisonedMethod[edge.Func] = true
					}
					continue
				}
				methodCandidates[edge.Func] = true
				if res.methodParamDeps[edge.Func] == nil {
					res.methodParamDeps[edge.Func] = map[syntaxutil.ParamKey]bool{}
				}
				res.methodParamDeps[edge.Func][edge.Param] = true
			}
		}
	}

	for pk := range paramCandidates {
		delete(res.paramLeakFree, pk)
	}
	for pk := range poisonedParam {
		delete(res.paramLeakFree, pk)
		delete(paramCandidates, pk)
		delete(res.paramDeps, pk)
		delete(res.paramMethodDeps, pk)
	}
	for mk := range methodCandidates {
		delete(res.readOnly, mk)
	}
	for mk := range poisonedMethod {
		delete(res.readOnly, mk)
		delete(methodCandidates, mk)
		delete(res.methodDeps, mk)
		delete(res.methodParamDeps, mk)
	}

	for changed := true; changed; {
		changed = false
		for pk := range paramCandidates {
			if res.paramLeakFree[pk] {
				continue
			}
			ok := true
			for dep := range res.paramDeps[pk] {
				if !res.paramLeakFree[dep] {
					ok = false
					break
				}
			}
			if ok {
				for mk := range res.paramMethodDeps[pk] {
					if !res.readOnly[mk] {
						ok = false
						break
					}
				}
			}
			if ok {
				res.paramLeakFree[pk] = true
				changed = true
			}
		}
		for mk := range methodCandidates {
			if res.readOnly[mk] {
				continue
			}
			ok := true
			for dep := range res.methodDeps[mk] {
				if !res.readOnly[dep] {
					ok = false
					break
				}
			}
			if ok {
				for pk := range res.methodParamDeps[mk] {
					if !res.paramLeakFree[pk] {
						ok = false
						break
					}
				}
			}
			if ok {
				res.readOnly[mk] = true
				changed = true
			}
		}
	}
	return res
}

// ResolveEnvAudit computes the joint least fixed point over ReturnEnvFree and
// ParamInsertionFree claims across allFacts.
func ResolveEnvAudit(allFacts map[string][]Fact, malformed func(fact Fact)) *EnvAuditResolution {
	return ResolveEnvAuditWithMeta(nil, allFacts, malformed)
}

func ResolveEnvAuditWithMeta(meta []GraphPackage, allFacts map[string][]Fact, malformed func(fact Fact)) *EnvAuditResolution {
	conf := resolveConfinementJointLFP(allFacts, malformed)
	strUnsafe, _ := upstreamStringUnsafePackagesWithConfinement(meta, allFacts, conf.paramLeakFree, conf.readOnly, malformed)
	return resolveEnvAuditWithConfinement(strUnsafe, allFacts, conf, malformed)
}

func resolveEnvAuditWithConfinement(strUnsafePkg map[string]bool, allFacts map[string][]Fact, conf confinementResolution, malformed func(fact Fact)) *EnvAuditResolution {
	e := &EnvAuditResolution{
		Declared:             map[syntaxutil.FuncKey]bool{},
		InsDeclared:          map[syntaxutil.ParamKey]bool{},
		Resolved:             map[syntaxutil.FuncKey]bool{},
		InsResolved:          map[syntaxutil.ParamKey]bool{},
		RetDeps:              map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool{},
		RetParamDeps:         map[syntaxutil.FuncKey]map[syntaxutil.ParamKey]bool{},
		RetMethodDeps:        map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool{},
		RetInsDeps:           map[syntaxutil.FuncKey]map[syntaxutil.EnvAuditTarget]bool{},
		InsDeps:              map[syntaxutil.ParamKey]map[syntaxutil.EnvAuditTarget]bool{},
		InsParamDeps:         map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{},
		InsMethodDeps:        map[syntaxutil.ParamKey]map[syntaxutil.FuncKey]bool{},
		ParamLeakFree:        conf.paramLeakFree,
		ReadOnly:             conf.readOnly,
		ParamDeps:            conf.paramDeps,
		ParamMethodDeps:      conf.paramMethodDeps,
		MethodDeps:           conf.methodDeps,
		MethodParamDeps:      conf.methodParamDeps,
		StringUnsafePackages: strUnsafePkg,
	}
	if malformed == nil {
		malformed = func(Fact) {}
	}
	poisonedFunc := map[syntaxutil.FuncKey]bool{}
	poisonedParam := map[syntaxutil.ParamKey]bool{}
	for pkgPath, facts := range allFacts {
		applyStrBlock := strUnsafePkg[pkgPath]
		for _, fact := range facts {
			for _, key := range fact.StringReturnEnvBlocked {
				if !key.Valid() || key.Pkg != pkgPath {
					malformed(fact)
					continue
				}
				if applyStrBlock || strUnsafePkg[key.Pkg] {
					poisonedFunc[key] = true
				}
			}
			for _, key := range fact.StringParamInsertionBlocked {
				if !key.Valid() || key.Func.Pkg != pkgPath {
					malformed(fact)
					continue
				}
				if applyStrBlock || strUnsafePkg[key.Func.Pkg] {
					poisonedParam[key] = true
				}
			}
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
			for _, edge := range fact.ReturnEnvParamDeps {
				if !edge.Valid() {
					malformed(fact)
					if edge.Func.Valid() {
						poisonedFunc[edge.Func] = true
					}
					continue
				}
				if e.RetParamDeps[edge.Func] == nil {
					e.RetParamDeps[edge.Func] = map[syntaxutil.ParamKey]bool{}
				}
				e.RetParamDeps[edge.Func][edge.Param] = true
			}
			for _, edge := range fact.ReturnEnvMethodDeps {
				if !edge.Valid() {
					malformed(fact)
					if edge.Func.Valid() {
						poisonedFunc[edge.Func] = true
					}
					continue
				}
				if e.RetMethodDeps[edge.Func] == nil {
					e.RetMethodDeps[edge.Func] = map[syntaxutil.FuncKey]bool{}
				}
				e.RetMethodDeps[edge.Func][edge.Callee] = true
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
			for _, edge := range fact.ParamInsertionParamDeps {
				if !edge.Valid() {
					malformed(fact)
					if edge.Own.Valid() {
						poisonedParam[edge.Own] = true
					}
					continue
				}
				if e.InsParamDeps[edge.Own] == nil {
					e.InsParamDeps[edge.Own] = map[syntaxutil.ParamKey]bool{}
				}
				e.InsParamDeps[edge.Own][edge.Dep] = true
			}
			for _, edge := range fact.ParamInsertionMethodDeps {
				if !edge.Valid() {
					malformed(fact)
					if edge.Param.Valid() {
						poisonedParam[edge.Param] = true
					}
					continue
				}
				if e.InsMethodDeps[edge.Param] == nil {
					e.InsMethodDeps[edge.Param] = map[syntaxutil.FuncKey]bool{}
				}
				e.InsMethodDeps[edge.Param][edge.Method] = true
			}
			for _, edge := range fact.StringReturnEnvDeps {
				if !edge.Valid() || edge.Func.Pkg != pkgPath {
					malformed(fact)
					if edge.Func.Valid() {
						poisonedFunc[edge.Func] = true
					}
					continue
				}
				if applyStrBlock {
					if e.RetDeps[edge.Func] == nil {
						e.RetDeps[edge.Func] = map[syntaxutil.FuncKey]bool{}
					}
					e.RetDeps[edge.Func][edge.Callee] = true
				}
			}
			for _, edge := range fact.StringReturnEnvParamDeps {
				if !edge.Valid() || edge.Func.Pkg != pkgPath {
					malformed(fact)
					if edge.Func.Valid() {
						poisonedFunc[edge.Func] = true
					}
					continue
				}
				if applyStrBlock {
					if e.RetParamDeps[edge.Func] == nil {
						e.RetParamDeps[edge.Func] = map[syntaxutil.ParamKey]bool{}
					}
					e.RetParamDeps[edge.Func][edge.Param] = true
				}
			}
			for _, edge := range fact.StringReturnEnvMethodDeps {
				if !edge.Valid() || edge.Func.Pkg != pkgPath {
					malformed(fact)
					if edge.Func.Valid() {
						poisonedFunc[edge.Func] = true
					}
					continue
				}
				if applyStrBlock {
					if e.RetMethodDeps[edge.Func] == nil {
						e.RetMethodDeps[edge.Func] = map[syntaxutil.FuncKey]bool{}
					}
					e.RetMethodDeps[edge.Func][edge.Callee] = true
				}
			}
			for _, edge := range fact.StringReturnEnvInsertionDeps {
				if !edge.Valid() || edge.Func.Pkg != pkgPath {
					malformed(fact)
					if edge.Func.Valid() {
						poisonedFunc[edge.Func] = true
					}
					continue
				}
				if applyStrBlock {
					if e.RetInsDeps[edge.Func] == nil {
						e.RetInsDeps[edge.Func] = map[syntaxutil.EnvAuditTarget]bool{}
					}
					e.RetInsDeps[edge.Func][edge.Dep] = true
				}
			}
			for _, edge := range fact.StringParamInsertionDeps {
				if !edge.Valid() || edge.Param.Func.Pkg != pkgPath {
					malformed(fact)
					if edge.Param.Valid() {
						poisonedParam[edge.Param] = true
					}
					continue
				}
				if applyStrBlock {
					if e.InsDeps[edge.Param] == nil {
						e.InsDeps[edge.Param] = map[syntaxutil.EnvAuditTarget]bool{}
					}
					e.InsDeps[edge.Param][edge.Dep] = true
				}
			}
			for _, edge := range fact.StringParamInsertionParamDeps {
				if !edge.Valid() || edge.Own.Func.Pkg != pkgPath {
					malformed(fact)
					if edge.Own.Valid() {
						poisonedParam[edge.Own] = true
					}
					continue
				}
				if applyStrBlock {
					if e.InsParamDeps[edge.Own] == nil {
						e.InsParamDeps[edge.Own] = map[syntaxutil.ParamKey]bool{}
					}
					e.InsParamDeps[edge.Own][edge.Dep] = true
				}
			}
			for _, edge := range fact.StringParamInsertionMethodDeps {
				if !edge.Valid() || edge.Param.Func.Pkg != pkgPath {
					malformed(fact)
					if edge.Param.Valid() {
						poisonedParam[edge.Param] = true
					}
					continue
				}
				if applyStrBlock {
					if e.InsMethodDeps[edge.Param] == nil {
						e.InsMethodDeps[edge.Param] = map[syntaxutil.FuncKey]bool{}
					}
					e.InsMethodDeps[edge.Param][edge.Method] = true
				}
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
				for pk := range e.RetParamDeps[fnKey] {
					if !e.ParamLeakFree[pk] {
						ok = false
						break
					}
				}
			}
			if ok {
				for mk := range e.RetMethodDeps[fnKey] {
					if !e.ReadOnly[mk] {
						ok = false
						break
					}
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
				for pk := range e.InsParamDeps[paramKey] {
					if !e.ParamLeakFree[pk] {
						ok = false
						break
					}
				}
			}
			if ok {
				for mk := range e.InsMethodDeps[paramKey] {
					if !e.ReadOnly[mk] {
						ok = false
						break
					}
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
	return NewDeferralResolutionWithMeta(nil, allFacts, malformed)
}

// NewDeferralResolutionWithMeta composes the cross-package proof state across
// allFacts using meta's package import graph to scope string-header unsafe
// invalidations to packages reachable from a string-header unsafe importer.
func NewDeferralResolutionWithMeta(meta []GraphPackage, allFacts map[string][]Fact, malformed func(fact Fact)) *DeferralResolution {
	return NewDeferralResolutionWithRoots(meta, allFacts, false, malformed)
}

// NewDeferralResolutionWithRoots composes the cross-package proof state across
// allFacts, setting BoundedRoots when the execution model bounds invoked roots
// to test subjects compiled inside allFacts (SingleSubjectExecution or
// PackageExecution).
func NewDeferralResolutionWithRoots(meta []GraphPackage, allFacts map[string][]Fact, boundedRoots bool, malformed func(fact Fact)) *DeferralResolution {
	r := &DeferralResolution{
		Declared:           map[string]bool{},
		ParamLeakFree:      map[syntaxutil.ParamKey]bool{},
		ParamRetentionFree: map[syntaxutil.ParamKey]bool{},
		ReadOnly:           map[syntaxutil.FuncKey]bool{},
		ReceiverRetention:  map[syntaxutil.FuncKey]bool{},
		NotOpaque:          map[string]bool{},
		OwnerUnproven:      map[string]bool{},
		EnvFreeResolved:    map[syntaxutil.FuncKey]bool{},
		EnvFreeDeps:        map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool{},
		BoundedRoots:       boundedRoots,

		FieldDeferAt:  map[syntaxutil.FieldPosKey][]syntaxutil.ParamKey{},
		FieldPoisonAt: map[syntaxutil.FieldParamPoison]bool{},
		RetDeferAt:    map[syntaxutil.ReturnFieldPosKey][]syntaxutil.ParamKey{},
		RetPoisonAt:   map[syntaxutil.ReturnFieldParamPoison]bool{},
		CtorsOf:       map[string][]syntaxutil.FuncKey{},
	}
	markMalformed := func(fact Fact) {
		for _, key := range fact.Declares {
			r.OwnerUnproven[key] = true
		}
		if malformed != nil {
			malformed(fact)
		}
	}

	conf := resolveConfinementJointLFP(allFacts, markMalformed)
	r.ParamLeakFree = conf.paramLeakFree
	r.ReadOnly = conf.readOnly
	r.StringUnsafePackages, r.ReturnStringUnsafePackages = upstreamStringUnsafePackagesWithConfinement(meta, allFacts, r.ParamLeakFree, r.ReadOnly, markMalformed)

	declaredKeys := r.Declared
	opaqueDeps := map[string]map[string]bool{}
	retentionDeps := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	poisonedRetParam := map[syntaxutil.ParamKey]bool{}
	for pkgPath, facts := range allFacts {
		applyStr := r.StringUnsafePackages[pkgPath]
		for _, fact := range facts {
			for _, key := range fact.ParamRetentionFree {
				if !key.Valid() {
					markMalformed(fact)
					continue
				}
				r.ParamRetentionFree[key] = true
			}
			for _, edge := range fact.ParamRetentionFreeDeps {
				if !edge.Valid() {
					markMalformed(fact)
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
			for _, key := range fact.ReceiverRetentionFree {
				if !key.Valid() {
					markMalformed(fact)
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
					markMalformed(fact)
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
					markMalformed(fact)
					if syntaxutil.ValidFactKey(entry.Pos.Owner) {
						r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: entry.Pos.Owner}] = true
					}
					continue
				}
				r.FieldDeferAt[entry.Pos] = append(r.FieldDeferAt[entry.Pos], entry.Param)
			}
			for _, entry := range fact.FieldParamPoison {
				if !entry.Valid() {
					markMalformed(fact)
					if syntaxutil.ValidFactKey(entry.Owner) {
						r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: entry.Owner}] = true
					}
					continue
				}
				r.FieldPoisonAt[entry] = true
			}
			for _, entry := range fact.ReturnFieldParamDefer {
				if !entry.Valid() {
					markMalformed(fact)
					if entry.Pos.Func.Valid() {
						r.RetPoisonAt[syntaxutil.ReturnFieldParamPoison{Func: entry.Pos.Func}] = true
					}
					continue
				}
				r.RetDeferAt[entry.Pos] = append(r.RetDeferAt[entry.Pos], entry.Param)
			}
			for _, entry := range fact.ReturnFieldParamPoison {
				if !entry.Valid() {
					markMalformed(fact)
					if entry.Func.Valid() {
						r.RetPoisonAt[syntaxutil.ReturnFieldParamPoison{Func: entry.Func}] = true
					}
					continue
				}
				r.RetPoisonAt[entry] = true
			}
			for _, use := range fact.EnvCallUses {
				if !use.Valid() {
					markMalformed(fact)
					if syntaxutil.ValidFactKey(use.Key) {
						r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: use.Key}] = true
						r.OwnerUnproven[use.Key] = true
					}
					continue
				}
				r.CtorsOf[use.Key] = append(r.CtorsOf[use.Key], use.Callee)
			}
			for _, use := range fact.EnvCallParamUses {
				if !use.Valid() {
					markMalformed(fact)
					if syntaxutil.ValidFactKey(use.Key) {
						r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: use.Key}] = true
						r.OwnerUnproven[use.Key] = true
					}
					continue
				}
				if !r.ParamLeakFree[use.Param] {
					r.OwnerUnproven[use.Key] = true
				}
			}
			for _, use := range fact.EnvCallMethodUses {
				if !use.Valid() {
					markMalformed(fact)
					if syntaxutil.ValidFactKey(use.Key) {
						r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: use.Key}] = true
						r.OwnerUnproven[use.Key] = true
					}
					continue
				}
				if !r.ReadOnly[use.Method] {
					r.OwnerUnproven[use.Key] = true
				}
			}
			for _, use := range fact.StringEnvCallUses {
				if !use.Valid() {
					markMalformed(fact)
					if syntaxutil.ValidFactKey(use.Key) {
						r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: use.Key}] = true
						r.OwnerUnproven[use.Key] = true
					}
					continue
				}
				if applyStr {
					r.CtorsOf[use.Key] = append(r.CtorsOf[use.Key], use.Callee)
				}
			}
			for _, use := range fact.StringEnvCallParamUses {
				if !use.Valid() {
					markMalformed(fact)
					if syntaxutil.ValidFactKey(use.Key) {
						r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: use.Key}] = true
						r.OwnerUnproven[use.Key] = true
					}
					continue
				}
				if applyStr && !r.ParamLeakFree[use.Param] {
					r.OwnerUnproven[use.Key] = true
				}
			}
			for _, use := range fact.StringEnvCallMethodUses {
				if !use.Valid() {
					markMalformed(fact)
					if syntaxutil.ValidFactKey(use.Key) {
						r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: use.Key}] = true
						r.OwnerUnproven[use.Key] = true
					}
					continue
				}
				if applyStr && !r.ReadOnly[use.Method] {
					r.OwnerUnproven[use.Key] = true
				}
			}
		}
	}
	for paramKey := range poisonedRetParam {
		delete(r.ParamRetentionFree, paramKey)
		delete(retentionDeps, paramKey)
	}

	syntaxutil.SolveLeastFixedPoint(r.ParamRetentionFree, retentionDeps, func(dep syntaxutil.ParamKey) bool {
		return r.ParamRetentionFree[dep] || r.ParamLeakFree[dep]
	})
	syntaxutil.SolveReachFixedPoint(r.NotOpaque, opaqueDeps, func(dep string) bool {
		return r.NotOpaque[dep] || !declaredKeys[dep]
	})

	ea := resolveEnvAuditWithConfinement(r.StringUnsafePackages, allFacts, conf, markMalformed)
	r.EnvFreeResolved = ea.Resolved
	r.EnvFreeDeps = ea.RetDeps

	refRegions, initOnlyFn, initReachFn := ResolveFuncRefRegions(allFacts, markMalformed)
	r.RefRegions = refRegions
	r.InitOnlyFn = initOnlyFn
	r.InitReachFn = initReachFn
	blockedSeams := BlockedExportedSeams(allFacts, markMalformed)
	for key := range blockedSeams {
		r.OwnerUnproven[key] = true
	}

	linkAdj := ActiveCarrierLinkGraph(allFacts, r, func(fact Fact) {
		markMalformed(fact)
		for _, link := range fact.CarrierLinks {
			if !link.Valid() {
				if syntaxutil.ValidFactKey(link.From) {
					r.OwnerUnproven[link.From] = true
				}
				if syntaxutil.ValidFactKey(link.To) {
					r.OwnerUnproven[link.To] = true
				}
			}
		}
		for _, link := range fact.StringCarrierLinks {
			if !link.Valid() {
				if syntaxutil.ValidFactKey(link.From) {
					r.OwnerUnproven[link.From] = true
				}
				if syntaxutil.ValidFactKey(link.To) {
					r.OwnerUnproven[link.To] = true
				}
			}
		}
	})

	if len(linkAdj) > 0 {
		visited := map[string]bool{}
		var components [][]string
		for start := range linkAdj {
			if visited[start] {
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
					pooledCtors = append(pooledCtors, r.CtorsOf[k]...)
				}
				if len(pooledCtors) > 0 {
					slices.SortFunc(pooledCtors, syntaxutil.FuncKey.Compare)
					pooledCtors = slices.Compact(pooledCtors)
					for _, k := range comp {
						r.CtorsOf[k] = pooledCtors
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
			for p := range r.FieldPoisonAt {
				if cid := compOf[p.Owner]; cid > 0 {
					addPoisons = append(addPoisons, poisonEntry{compIdx: cid - 1, hasPos: p.HasPos, field: p.Field, index: p.Index})
				}
			}
			for _, pe := range addPoisons {
				for _, k := range components[pe.compIdx] {
					r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: k, HasPos: pe.hasPos, Field: pe.field, Index: pe.index}] = true
				}
			}
			type deferEntry struct {
				compIdx int
				field   string
				index   int
				params  []syntaxutil.ParamKey
			}
			var addDefers []deferEntry
			for pos, params := range r.FieldDeferAt {
				if cid := compOf[pos.Owner]; cid > 0 {
					addDefers = append(addDefers, deferEntry{compIdx: cid - 1, field: pos.Field, index: pos.Index, params: params})
				}
			}
			for _, de := range addDefers {
				for _, k := range components[de.compIdx] {
					targetPos := syntaxutil.FieldPosKey{Owner: k, Field: de.field, Index: de.index}
					r.FieldDeferAt[targetPos] = append(r.FieldDeferAt[targetPos], de.params...)
				}
			}
		}
	}

	applyOwnerAttributedUse := func(fact Fact, use syntaxutil.AttributedUse, apply bool) {
		if !use.Valid() {
			markMalformed(fact)
			if syntaxutil.ValidFactKey(use.Key) {
				r.OwnerUnproven[use.Key] = true
			}
			return
		}
		if !apply {
			return
		}
		fn, key := use.Func, use.Key
		if !use.Literal && use.Escape {
			if !r.IsObjectClosed(key) {
				r.OwnerUnproven[key] = true
			}
			return
		}
		if use.Literal {
			if use.HasMethod {
				if !r.ReadOnly[use.Method] {
					r.OwnerUnproven[key] = true
				}
			} else if use.Escape {
				if !r.IsObjectClosed(key) {
					r.OwnerUnproven[key] = true
				}
			} else {
				r.OwnerUnproven[key] = true
			}
			return
		}
		if refRegions[fn] != nil && initOnlyFn[fn] {
			if use.HasMethod && !r.ReadOnly[use.Method] && !r.ReceiverRetention[use.Method] {
				r.OwnerUnproven[key] = true
			}
			return
		}
		if !use.HasMethod || !r.ReadOnly[use.Method] {
			r.OwnerUnproven[key] = true
		}
	}

	var validFieldUses []syntaxutil.FieldPosKey
	var validElemUses []syntaxutil.ElemParamUse
	for pkgPath, facts := range allFacts {
		applyStr := r.StringUnsafePackages[pkgPath]
		for _, fact := range facts {
			for _, key := range fact.Mutates {
				r.OwnerUnproven[key] = true
			}
			for _, key := range fact.Escapes {
				if !r.IsObjectClosed(key) {
					r.OwnerUnproven[key] = true
				}
			}
			for _, key := range fact.StringEscapes {
				if !syntaxutil.ValidQualifiedVarKey(key) {
					markMalformed(fact)
					continue
				}
				if applyStr && !r.IsObjectClosed(key) {
					r.OwnerUnproven[key] = true
				}
			}
			for _, key := range fact.EnvCarrying {
				r.OwnerUnproven[key] = true
			}
			factStrEnvSet := make(map[string]bool, len(fact.StringEnvCarrying))
			for _, key := range fact.StringEnvCarrying {
				if !syntaxutil.ValidQualifiedVarKey(key) {
					markMalformed(fact)
					continue
				}
				factStrEnvSet[key] = true
				if applyStr {
					r.OwnerUnproven[key] = true
				}
			}
			for _, key := range fact.StringEnvCallable {
				if !syntaxutil.ValidQualifiedVarKey(key) {
					markMalformed(fact)
				}
			}
			for _, use := range fact.StringEnvCarryingFns {
				if !use.Valid() || !factStrEnvSet[use.Key] {
					markMalformed(fact)
					if syntaxutil.ValidFactKey(use.Key) {
						r.OwnerUnproven[use.Key] = true
					}
				}
			}
			for _, use := range fact.MethodUses {
				if !use.Valid() {
					markMalformed(fact)
					if syntaxutil.ValidFactKey(use.Key) {
						r.OwnerUnproven[use.Key] = true
					}
					continue
				}
				if !r.ReadOnly[use.Method] {
					r.OwnerUnproven[use.Key] = true
				}
			}
			for _, use := range fact.InitMethodUses {
				if !use.Valid() {
					markMalformed(fact)
					if syntaxutil.ValidFactKey(use.Key) {
						r.OwnerUnproven[use.Key] = true
					}
					continue
				}
				if !r.ReceiverRetention[use.Method] && !r.IsObjectClosed(use.Key) {
					r.OwnerUnproven[use.Key] = true
				}
			}
			for _, use := range fact.ParamUses {
				if !use.Valid() {
					markMalformed(fact)
					if syntaxutil.ValidFactKey(use.Key) {
						r.OwnerUnproven[use.Key] = true
					}
					continue
				}
				if r.ParamLeakFree[use.Param] {
					continue
				}
				if !use.Func.IsZero() && !use.Literal && refRegions[use.Func] != nil && initOnlyFn[use.Func] && r.ParamRetentionFree[use.Param] {
					continue
				}
				if !r.IsObjectClosed(use.Key) {
					r.OwnerUnproven[use.Key] = true
				}
			}
			for _, use := range fact.InitParamUses {
				if !use.Valid() || !use.Func.IsZero() {
					markMalformed(fact)
					if syntaxutil.ValidFactKey(use.Key) {
						r.OwnerUnproven[use.Key] = true
					}
					continue
				}
				if !r.ParamLeakFree[use.Param] && !r.ParamRetentionFree[use.Param] && !r.IsObjectClosed(use.Key) {
					r.OwnerUnproven[use.Key] = true
				}
			}
			for _, use := range fact.FieldParamUses {
				if !use.Valid(0) {
					markMalformed(fact)
					if syntaxutil.ValidFactKey(use.Owner) {
						r.OwnerUnproven[use.Owner] = true
					}
					continue
				}
				validFieldUses = append(validFieldUses, use)
			}
			for _, use := range fact.ElemParamUses {
				if !use.Valid() {
					markMalformed(fact)
					if syntaxutil.ValidFactKey(use.Key) {
						r.OwnerUnproven[use.Key] = true
					}
					continue
				}
				validElemUses = append(validElemUses, use)
			}
			for _, use := range fact.AttributedUses {
				applyOwnerAttributedUse(fact, use, true)
			}
			for _, use := range fact.StringAttributedUses {
				applyOwnerAttributedUse(fact, use, r.AppliesStringAttributedUse(pkgPath, use.Func))
			}
		}
	}

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

	for changed := true; changed; {
		changed = false
		for key := range r.OwnerUnproven {
			for next := range linkAdj[key] {
				if !r.IsObjectClosed(next) && !r.OwnerUnproven[next] {
					r.OwnerUnproven[next] = true
					changed = true
				}
			}
		}
		for _, use := range validFieldUses {
			if r.IsObjectClosed(use.Owner) || len(linkAdj[use.Owner]) == 0 {
				continue
			}
			if ok, _ := r.FieldPopulationProves(use.Owner, use.Field, use.Index); !ok {
				for next := range linkAdj[use.Owner] {
					if !r.IsObjectClosed(next) && !r.OwnerUnproven[next] {
						r.OwnerUnproven[next] = true
						changed = true
					}
				}
			}
		}
		for _, use := range validElemUses {
			if r.IsObjectClosed(use.Key) || r.OwnerUnproven[use.Key] {
				continue
			}
			if ok, _ := r.FieldPopulationProves(use.Owner, syntaxutil.ElemPositionField, use.Index); !ok {
				r.OwnerUnproven[use.Key] = true
				changed = true
			}
		}
	}
	return r
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
