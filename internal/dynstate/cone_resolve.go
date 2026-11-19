package dynstate

import (
	"context"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"github.com/greatliontech/gofresh/internal/propharness"
	"github.com/greatliontech/gofresh/internal/trace"
)

// ConeQuery specifies one shared-dynamic-state composition, discharge, or
// explanation query over a package graph's derived facts.
type ConeQuery struct {
	Ctx            context.Context
	Meta           []GraphPackage
	Facts          map[string][]Fact
	ViewPackage    string
	Vouches        map[string]bool
	SingleSubject  bool
	PackageProcess bool
	OnMalformed    func(Fact)
}

// ConeAnalysis holds the unified resolution, link/seam graphs, non-vouch
// discharges, and optional view-package ConeState computed in a single pass by
// AnalyzeCone.
type ConeAnalysis struct {
	State              ConeState
	Deferral           *DeferralResolution
	EnvAudit           *EnvAuditResolution
	BlockedSeams       map[string]map[syntaxutil.FuncKey]bool
	LinkAdj            map[string]map[string]bool
	NonVouchDischarged map[string]bool
}

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

	FieldDeferAt  map[syntaxutil.FieldPosKey][]syntaxutil.ParamKey
	FieldPoisonAt map[syntaxutil.FieldParamPoison]bool
	RetDeferAt    map[syntaxutil.ReturnFieldPosKey][]syntaxutil.ParamKey
	RetPoisonAt   map[syntaxutil.ReturnFieldParamPoison]bool
	CtorsOf       map[string][]syntaxutil.FuncKey
}

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

// EnvAuditResolution is the environment-audit resolution shared by verdict
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
	MethodDeps      map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool
	MethodParamDeps map[syntaxutil.FuncKey]map[syntaxutil.ParamKey]bool
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

// Compose runs the shared-dynamic-state judgment for one view package over the
// facts of that package's own test-binary graph (REQ-closure-shared-dynamic-state,
// REQ-closure-scan-memo).
func Compose(meta []GraphPackage, allFacts map[string][]Fact, viewPackage string, vouches map[string]bool, singleSubject, packageProcess bool) ConeState {
	return AnalyzeCone(ConeQuery{
		Meta:           meta,
		Facts:          allFacts,
		ViewPackage:    viewPackage,
		Vouches:        vouches,
		SingleSubject:  singleSubject,
		PackageProcess: packageProcess,
	}).State
}

// NonVouchDischargedVars returns the set of declared dynamic-state variable keys
// discharged by mechanical source audits or active execution-model attestations
// (excluding caller vouches, whose derivation chains remain observable on
// request under REQ-explain-chain).
func NonVouchDischargedVars(meta []GraphPackage, allFacts map[string][]Fact, singleSubject bool) map[string]bool {
	return AnalyzeCone(ConeQuery{
		Meta:          meta,
		Facts:         allFacts,
		SingleSubject: singleSubject,
	}).NonVouchDischarged
}

// NewDeferralResolution composes the cross-package proof state across allFacts.
func NewDeferralResolution(allFacts map[string][]Fact, malformed func(Fact)) *DeferralResolution {
	return AnalyzeCone(ConeQuery{
		Facts:       allFacts,
		OnMalformed: malformed,
	}).Deferral
}

// ResolveEnvAudit computes the joint least fixed point over ReturnEnvFree and
// ParamInsertionFree claims across allFacts.
func ResolveEnvAudit(allFacts map[string][]Fact, malformed func(Fact)) *EnvAuditResolution {
	return AnalyzeCone(ConeQuery{
		Facts:       allFacts,
		OnMalformed: malformed,
	}).EnvAudit
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

// AnalyzeCone validates all Fact fields, solves the joint confinement,
// retention, opacity, environment-audit, call-region, seam, and carrier-link
// fixed points once, derives source and execution-attested discharges, and
// (when q.ViewPackage != "") composes the view package's ConeState.
func AnalyzeCone(q ConeQuery) *ConeAnalysis {
	var traceStart time.Time
	tracing := q.ViewPackage != "" && trace.Enabled(q.Ctx, trace.DomainDynstate, q.ViewPackage)
	if tracing {
		traceStart = time.Now()
	}

	allFacts := q.Facts
	pkgPaths := make([]string, 0, len(allFacts))
	for pkgPath := range allFacts {
		pkgPaths = append(pkgPaths, pkgPath)
	}
	sort.Strings(pkgPaths)

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
		RefRegions:         map[syntaxutil.FuncKey]map[syntaxutil.RefRegion]bool{},
		InitOnlyFn:         map[syntaxutil.FuncKey]bool{},
		InitReachFn:        map[syntaxutil.FuncKey]bool{},
		FieldDeferAt:       map[syntaxutil.FieldPosKey][]syntaxutil.ParamKey{},
		FieldPoisonAt:      map[syntaxutil.FieldParamPoison]bool{},
		RetDeferAt:         map[syntaxutil.ReturnFieldPosKey][]syntaxutil.ParamKey{},
		RetPoisonAt:        map[syntaxutil.ReturnFieldParamPoison]bool{},
		CtorsOf:            map[string][]syntaxutil.FuncKey{},
	}
	ea := &EnvAuditResolution{
		Declared:        map[syntaxutil.FuncKey]bool{},
		InsDeclared:     map[syntaxutil.ParamKey]bool{},
		Resolved:        map[syntaxutil.FuncKey]bool{},
		InsResolved:     map[syntaxutil.ParamKey]bool{},
		RetDeps:         r.EnvFreeDeps,
		RetParamDeps:    map[syntaxutil.FuncKey]map[syntaxutil.ParamKey]bool{},
		RetMethodDeps:   map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool{},
		RetInsDeps:      map[syntaxutil.FuncKey]map[syntaxutil.EnvAuditTarget]bool{},
		InsDeps:         map[syntaxutil.ParamKey]map[syntaxutil.EnvAuditTarget]bool{},
		InsParamDeps:    map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{},
		InsMethodDeps:   map[syntaxutil.ParamKey]map[syntaxutil.FuncKey]bool{},
		ParamLeakFree:   r.ParamLeakFree,
		ReadOnly:        r.ReadOnly,
		ParamDeps:       map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{},
		ParamMethodDeps: map[syntaxutil.ParamKey]map[syntaxutil.FuncKey]bool{},
		MethodDeps:      map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool{},
		MethodParamDeps: map[syntaxutil.FuncKey]map[syntaxutil.ParamKey]bool{},
	}

	mutated := map[string]bool{}
	escaped := map[string]bool{}
	envCarrying := map[string]bool{}
	envCallable := map[string]bool{}
	unattributedMark := map[string]bool{}
	malformedFactVars := map[string]bool{}
	pkgHasMalformedFact := map[string]bool{}

	poisonVar := func(key string) {
		if !syntaxutil.ValidFactKey(key) {
			return
		}
		mutated[key] = true
		unattributedMark[key] = true
		malformedFactVars[key] = true
		r.OwnerUnproven[key] = true
	}

	paramCandidates := map[syntaxutil.ParamKey]bool{}
	methodCandidates := map[syntaxutil.FuncKey]bool{}
	poisonedLeakParam := map[syntaxutil.ParamKey]bool{}
	poisonedMethod := map[syntaxutil.FuncKey]bool{}
	retentionDeps := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	poisonedRetParam := map[syntaxutil.ParamKey]bool{}
	opaqueDeps := map[string]map[string]bool{}
	poisonedEnvFunc := map[syntaxutil.FuncKey]bool{}
	poisonedEnvParam := map[syntaxutil.ParamKey]bool{}

	hasMalformedSeam := false
	var exportedSeams []syntaxutil.ExportedSeam
	var allSeamKeys []string
	parallelReached := map[syntaxutil.FuncKey]bool{}
	nonSeqReached := map[syntaxutil.FuncKey]bool{}
	seqAdj := map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool{}
	revSeqAdj := map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool{}
	revParAdj := map[syntaxutil.FuncKey]map[syntaxutil.FuncKey]bool{}

	var validLinks []syntaxutil.CarrierLink
	var validFieldUses []syntaxutil.FieldPosKey
	var validElemUses []syntaxutil.ElemParamUse

	mutatedStructs := map[syntaxutil.TypeRef]bool{}
	directVarWritten := map[string]bool{}
	nonMethodVarUsed := map[string]bool{}
	anyMalformedMutatedStruct := false
	anyMalformedDirectVarWrite := false
	anyMalformedNonMethodVarUse := false
	var allCondStructMutations []syntaxutil.ConditionalStructMutation

	// Stage 1: Single-pass validation and table collection across all Fact fields.
	for _, pkgPath := range pkgPaths {
		prefix := pkgPath + "."
		for _, fact := range allFacts[pkgPath] {
			factBad := false

			opaque := make(map[string]bool, len(fact.Opaque))
			for _, key := range fact.Opaque {
				if !syntaxutil.ValidFactKey(key) {
					factBad = true
					continue
				}
				opaque[key] = true
			}
			for _, key := range fact.Declares {
				if !syntaxutil.ValidFactKey(key) {
					factBad = true
					continue
				}
				r.Declared[key] = true
				if !opaque[key] {
					r.NotOpaque[key] = true
				}
			}
			for _, key := range fact.OpacityBreaks {
				if !syntaxutil.ValidFactKey(key) {
					factBad = true
					continue
				}
				r.NotOpaque[key] = true
			}
			for _, edge := range fact.OpaqueDeps {
				if !edge.Valid() {
					factBad = true
					if syntaxutil.ValidFactKey(edge.Own) {
						r.NotOpaque[edge.Own] = true
					}
					continue
				}
				addMapSet(opaqueDeps, edge.Own, edge.Dep)
			}

			for _, key := range fact.Mutates {
				if !syntaxutil.ValidFactKey(key) {
					factBad = true
					continue
				}
				mutated[key] = true
				unattributedMark[key] = true
				r.OwnerUnproven[key] = true
			}
			for _, key := range fact.Escapes {
				if !syntaxutil.ValidFactKey(key) {
					factBad = true
					continue
				}
				escaped[key] = true
				unattributedMark[key] = true
			}
			for _, key := range fact.EnvCallable {
				if !syntaxutil.ValidFactKey(key) {
					factBad = true
					continue
				}
				envCallable[key] = true
			}

			factEnvSet := make(map[string]bool, len(fact.EnvCarrying))
			for _, key := range fact.EnvCarrying {
				if !syntaxutil.ValidFactKey(key) {
					factBad = true
					continue
				}
				factEnvSet[key] = true
				envCarrying[key] = true
				r.OwnerUnproven[key] = true
			}
			for _, use := range fact.EnvCarryingFns {
				if !use.Valid() || !factEnvSet[use.Key] {
					factBad = true
					for _, key := range fact.Declares {
						if syntaxutil.ValidFactKey(key) {
							envCarrying[key] = true
						}
					}
					if syntaxutil.ValidFactKey(use.Key) {
						poisonVar(use.Key)
						envCarrying[use.Key] = true
					}
				}
			}

			for _, es := range fact.ExportedSeams {
				if syntaxutil.ValidFactKey(es.Key) {
					allSeamKeys = append(allSeamKeys, es.Key)
				}
				if !es.Valid() {
					factBad = true
					hasMalformedSeam = true
					poisonVar(es.Key)
					continue
				}
				exportedSeams = append(exportedSeams, es)
			}
			for _, fn := range fact.NonSeqFuncUses {
				if !fn.Valid() {
					factBad = true
					hasMalformedSeam = true
					continue
				}
				nonSeqReached[fn] = true
			}
			for _, edge := range fact.SeqFuncEdges {
				if !edge.Valid() {
					factBad = true
					hasMalformedSeam = true
					continue
				}
				addMapSet(seqAdj, edge.Func, edge.Callee)
				addMapSet(revSeqAdj, edge.Callee, edge.Func)
				addMapSet(revParAdj, edge.Callee, edge.Func)
			}
			for _, fn := range fact.ParallelFuncs {
				if !fn.Valid() {
					factBad = true
					hasMalformedSeam = true
					continue
				}
				parallelReached[fn] = true
			}
			for _, edge := range fact.ParallelEdges {
				if !edge.Valid() {
					factBad = true
					hasMalformedSeam = true
					continue
				}
				addMapSet(revParAdj, edge.Callee, edge.Func)
			}

			for _, key := range fact.ParamLeakFree {
				if !key.Valid() {
					factBad = true
					continue
				}
				r.ParamLeakFree[key] = true
			}
			for _, edge := range fact.ParamLeakFreeDeps {
				if !edge.Valid() {
					factBad = true
					if edge.Own.Valid() {
						poisonedLeakParam[edge.Own] = true
					}
					continue
				}
				paramCandidates[edge.Own] = true
				addMapSet(ea.ParamDeps, edge.Own, edge.Dep)
			}
			for _, edge := range fact.ParamLeakFreeMethodDeps {
				if !edge.Valid() {
					factBad = true
					if edge.Param.Valid() {
						poisonedLeakParam[edge.Param] = true
					}
					continue
				}
				paramCandidates[edge.Param] = true
				addMapSet(ea.ParamMethodDeps, edge.Param, edge.Method)
			}
			for _, key := range fact.ReceiverReadOnly {
				if !key.Valid() {
					factBad = true
					continue
				}
				r.ReadOnly[key] = true
			}
			for _, edge := range fact.ReceiverReadOnlyDeps {
				if !edge.Valid() {
					factBad = true
					if edge.Func.Valid() {
						poisonedMethod[edge.Func] = true
					}
					continue
				}
				methodCandidates[edge.Func] = true
				addMapSet(ea.MethodDeps, edge.Func, edge.Callee)
			}
			for _, edge := range fact.ReceiverReadOnlyParamDeps {
				if !edge.Valid() {
					factBad = true
					if edge.Func.Valid() {
						poisonedMethod[edge.Func] = true
					}
					continue
				}
				methodCandidates[edge.Func] = true
				addMapSet(ea.MethodParamDeps, edge.Func, edge.Param)
			}

			for _, key := range fact.ParamRetentionFree {
				if !key.Valid() {
					factBad = true
					continue
				}
				r.ParamRetentionFree[key] = true
			}
			for _, edge := range fact.ParamRetentionFreeDeps {
				if !edge.Valid() {
					factBad = true
					if edge.Own.Valid() {
						poisonedRetParam[edge.Own] = true
					}
					continue
				}
				addMapSet(retentionDeps, edge.Own, edge.Dep)
			}
			for _, key := range fact.ReceiverRetentionFree {
				if !key.Valid() {
					factBad = true
					continue
				}
				r.ReceiverRetention[key] = true
			}

			for _, entry := range fact.FieldParamDefer {
				if !entry.Valid() {
					factBad = true
					if syntaxutil.ValidFactKey(entry.Pos.Owner) {
						r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: entry.Pos.Owner}] = true
					}
					continue
				}
				r.FieldDeferAt[entry.Pos] = append(r.FieldDeferAt[entry.Pos], entry.Param)
			}
			for _, entry := range fact.FieldParamPoison {
				if !entry.Valid() {
					factBad = true
					if syntaxutil.ValidFactKey(entry.Owner) {
						r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: entry.Owner}] = true
					}
					continue
				}
				r.FieldPoisonAt[entry] = true
			}
			for _, entry := range fact.ReturnFieldParamDefer {
				if !entry.Valid() {
					factBad = true
					if entry.Pos.Func.Valid() {
						r.RetPoisonAt[syntaxutil.ReturnFieldParamPoison{Func: entry.Pos.Func}] = true
					}
					continue
				}
				r.RetDeferAt[entry.Pos] = append(r.RetDeferAt[entry.Pos], entry.Param)
			}
			for _, entry := range fact.ReturnFieldParamPoison {
				if !entry.Valid() {
					factBad = true
					if entry.Func.Valid() {
						r.RetPoisonAt[syntaxutil.ReturnFieldParamPoison{Func: entry.Func}] = true
					}
					continue
				}
				r.RetPoisonAt[entry] = true
			}

			poisonMalformedEnvCallUse := func(useKey string) {
				factBad = true
				for _, key := range fact.Declares {
					if syntaxutil.ValidFactKey(key) {
						envCarrying[key] = true
					}
				}
				if syntaxutil.ValidFactKey(useKey) {
					r.FieldPoisonAt[syntaxutil.FieldParamPoison{Owner: useKey}] = true
					poisonVar(useKey)
					envCarrying[useKey] = true
				}
			}
			for _, use := range fact.EnvCallUses {
				if !use.Valid() {
					poisonMalformedEnvCallUse(use.Key)
					continue
				}
				r.CtorsOf[use.Key] = append(r.CtorsOf[use.Key], use.Callee)
			}
			for _, use := range fact.EnvCallParamUses {
				if !use.Valid() {
					poisonMalformedEnvCallUse(use.Key)
				}
			}
			for _, use := range fact.EnvCallMethodUses {
				if !use.Valid() {
					poisonMalformedEnvCallUse(use.Key)
				}
			}

			for _, key := range fact.ReturnEnvFree {
				if !key.Valid() {
					factBad = true
					continue
				}
				ea.Declared[key] = true
			}
			for _, edge := range fact.ReturnEnvDeps {
				if !edge.Valid() {
					factBad = true
					if edge.Func.Valid() {
						poisonedEnvFunc[edge.Func] = true
					}
					continue
				}
				addMapSet(ea.RetDeps, edge.Func, edge.Callee)
			}
			for _, edge := range fact.ReturnEnvParamDeps {
				if !edge.Valid() {
					factBad = true
					if edge.Func.Valid() {
						poisonedEnvFunc[edge.Func] = true
					}
					continue
				}
				addMapSet(ea.RetParamDeps, edge.Func, edge.Param)
			}
			for _, edge := range fact.ReturnEnvMethodDeps {
				if !edge.Valid() {
					factBad = true
					if edge.Func.Valid() {
						poisonedEnvFunc[edge.Func] = true
					}
					continue
				}
				addMapSet(ea.RetMethodDeps, edge.Func, edge.Callee)
			}
			for _, edge := range fact.ReturnEnvInsertionDeps {
				if !edge.Valid() {
					factBad = true
					if edge.Func.Valid() {
						poisonedEnvFunc[edge.Func] = true
					}
					continue
				}
				addMapSet(ea.RetInsDeps, edge.Func, edge.Dep)
			}
			for _, key := range fact.ParamInsertionFree {
				if !key.Valid() {
					factBad = true
					continue
				}
				ea.InsDeclared[key] = true
			}
			for _, edge := range fact.ParamInsertionDeps {
				if !edge.Valid() {
					factBad = true
					if edge.Param.Valid() {
						poisonedEnvParam[edge.Param] = true
					}
					continue
				}
				addMapSet(ea.InsDeps, edge.Param, edge.Dep)
			}
			for _, edge := range fact.ParamInsertionParamDeps {
				if !edge.Valid() {
					factBad = true
					if edge.Own.Valid() {
						poisonedEnvParam[edge.Own] = true
					}
					continue
				}
				addMapSet(ea.InsParamDeps, edge.Own, edge.Dep)
			}
			for _, edge := range fact.ParamInsertionMethodDeps {
				if !edge.Valid() {
					factBad = true
					if edge.Param.Valid() {
						poisonedEnvParam[edge.Param] = true
					}
					continue
				}
				addMapSet(ea.InsMethodDeps, edge.Param, edge.Method)
			}

			for _, edge := range fact.FuncRefs {
				if !edge.Valid() {
					factBad = true
					if edge.Callee.Valid() {
						addMapSet(r.RefRegions, edge.Callee, syntaxutil.RefRegion{Kind: syntaxutil.RegionProg})
					}
					continue
				}
				addMapSet(r.RefRegions, edge.Callee, edge.Region)
			}

			for _, link := range fact.CarrierLinks {
				if !link.Valid() {
					factBad = true
					poisonVar(link.From)
					poisonVar(link.To)
					continue
				}
				validLinks = append(validLinks, link)
			}

			for _, use := range fact.MethodUses {
				if !use.Valid() {
					factBad = true
					poisonVar(use.Key)
				}
			}
			for _, use := range fact.InitMethodUses {
				if !use.Valid() {
					factBad = true
					poisonVar(use.Key)
				}
			}
			for _, use := range fact.ParamUses {
				if !use.Valid() {
					factBad = true
					poisonVar(use.Key)
				}
			}
			for _, use := range fact.InitParamUses {
				if !use.Valid() || !use.Func.IsZero() {
					factBad = true
					poisonVar(use.Key)
				}
			}
			for _, use := range fact.FieldParamUses {
				if !use.Valid(0) {
					factBad = true
					poisonVar(use.Owner)
					continue
				}
				validFieldUses = append(validFieldUses, use)
			}
			for _, use := range fact.ElemParamUses {
				if !use.Valid() {
					factBad = true
					poisonVar(use.Key)
					poisonVar(use.Owner)
					continue
				}
				validElemUses = append(validElemUses, use)
			}
			for _, use := range fact.AttributedUses {
				if !use.Valid() {
					factBad = true
					poisonVar(use.Key)
				}
			}
			for _, use := range fact.PoolAttributedUses {
				if !use.Valid() {
					factBad = true
					poisonVar(use.Key)
				}
			}

			for k, v := range fact.PureMethods {
				if !syntaxutil.ValidFactKey(k) || !syntaxutil.ValidFactKey(v) {
					factBad = true
				}
			}
			for k, v := range fact.ExternalMethods {
				if !syntaxutil.ValidFactKey(k) || !syntaxutil.ValidFactKey(v) {
					factBad = true
				}
			}

			for _, key := range fact.PoolDischarges {
				if !syntaxutil.ValidQualifiedVarKey(key) {
					factBad = true
				}
			}
			for _, key := range fact.PoolMutates {
				if !syntaxutil.ValidQualifiedVarKey(key) {
					factBad = true
					continue
				}
				if !q.SingleSubject {
					mutated[key] = true
					unattributedMark[key] = true
					r.OwnerUnproven[key] = true
				}
			}
			for _, key := range fact.PoolEscapes {
				if !syntaxutil.ValidQualifiedVarKey(key) {
					factBad = true
					continue
				}
				if !q.SingleSubject {
					escaped[key] = true
					unattributedMark[key] = true
				}
			}
			for _, key := range fact.SingleSubjectVars {
				if !syntaxutil.ValidQualifiedVarKey(key) {
					factBad = true
				}
			}
			for _, key := range fact.MappingDischarges {
				if !syntaxutil.ValidQualifiedVarKey(key) {
					factBad = true
				}
			}
			for _, key := range fact.MemoDischarges {
				if !syntaxutil.ValidQualifiedVarKey(key) {
					factBad = true
				}
			}
			for _, mt := range fact.OnceMemoTypes {
				if !mt.Valid() || mt.Type.Pkg != pkgPath {
					factBad = true
					anyMalformedMutatedStruct = true
				}
			}
			for _, cand := range fact.OnceMemoCandidates {
				if !cand.Valid() || !strings.HasPrefix(cand.Key, prefix) || strings.Contains(cand.Key[len(prefix):], ".") {
					factBad = true
				}
			}
			if len(fact.HarnessDischarges) > 0 {
				if !propharness.IsHarnessPath(pkgPath) {
					factBad = true
				} else {
					for _, key := range fact.HarnessDischarges {
						if !syntaxutil.ValidQualifiedVarKey(key) || !strings.HasPrefix(key, prefix) || strings.Contains(key[len(prefix):], ".") {
							factBad = true
						}
					}
				}
			}
			for _, c := range fact.ProtoClusters {
				if !c.Valid() {
					factBad = true
				}
			}
			for _, a := range fact.ReadOnlyVarAliases {
				if !a.Valid() || !strings.HasPrefix(a.Key, prefix) || strings.Contains(a.Key[len(prefix):], ".") {
					factBad = true
					anyMalformedNonMethodVarUse = true
				}
			}
			for _, rt := range fact.ProtoRuntimeTypes {
				if !rt.Valid() {
					factBad = true
				}
			}
			for _, sg := range fact.StaticCompositeGlobals {
				if !sg.Valid() || !strings.HasPrefix(sg.Key, prefix) || strings.Contains(sg.Key[len(prefix):], ".") {
					factBad = true
				}
			}
			for _, tr := range fact.MutatedStructTypes {
				if tr.Valid() {
					mutatedStructs[tr] = true
				} else {
					factBad = true
					anyMalformedMutatedStruct = true
				}
			}
			for _, cm := range fact.ConditionalStructMutations {
				if cm.Valid() {
					allCondStructMutations = append(allCondStructMutations, cm)
				} else {
					factBad = true
					anyMalformedMutatedStruct = true
				}
			}
			for _, rf := range fact.ReflectedIfaceMethodSets {
				if !rf.Valid() {
					factBad = true
					anyMalformedMutatedStruct = true
				}
			}
			if !fact.NoPostInitCarrierWrites && len(fact.CarrierImportCalls) > 0 {
				factBad = true
				anyMalformedMutatedStruct = true
			}
			for _, dep := range fact.CarrierImportCalls {
				if !syntaxutil.ValidNonEmptyPkgKey(dep) {
					factBad = true
					anyMalformedMutatedStruct = true
				}
			}
			for _, m := range fact.NonMutatingMethods {
				if !m.Valid() || m.Pkg != pkgPath {
					factBad = true
					anyMalformedMutatedStruct = true
				}
			}
			for _, key := range fact.DirectVarWrites {
				if syntaxutil.ValidQualifiedVarKey(key) {
					directVarWritten[key] = true
				} else {
					factBad = true
					anyMalformedDirectVarWrite = true
				}
			}
			for _, key := range fact.NonMethodVarUses {
				if syntaxutil.ValidQualifiedVarKey(key) {
					nonMethodVarUsed[key] = true
				} else {
					factBad = true
					anyMalformedNonMethodVarUse = true
				}
			}

			if factBad {
				pkgHasMalformedFact[pkgPath] = true
				for _, key := range fact.Declares {
					poisonVar(key)
				}
				if q.OnMalformed != nil {
					q.OnMalformed(fact)
				}
			}
		}
		if pkgHasMalformedFact[pkgPath] {
			for _, sib := range allFacts[pkgPath] {
				for _, key := range sib.Declares {
					poisonVar(key)
				}
			}
		}
	}

	return (&coneResolveTables{
		q:                           q,
		tracing:                     tracing,
		traceStart:                  traceStart,
		allFacts:                    allFacts,
		pkgPaths:                    pkgPaths,
		r:                           r,
		ea:                          ea,
		mutated:                     mutated,
		escaped:                     escaped,
		envCarrying:                 envCarrying,
		envCallable:                 envCallable,
		unattributedMark:            unattributedMark,
		malformedFactVars:           malformedFactVars,
		pkgHasMalformedFact:         pkgHasMalformedFact,
		paramCandidates:             paramCandidates,
		methodCandidates:            methodCandidates,
		poisonedLeakParam:           poisonedLeakParam,
		poisonedMethod:              poisonedMethod,
		retentionDeps:               retentionDeps,
		poisonedRetParam:            poisonedRetParam,
		opaqueDeps:                  opaqueDeps,
		poisonedEnvFunc:             poisonedEnvFunc,
		poisonedEnvParam:            poisonedEnvParam,
		hasMalformedSeam:            hasMalformedSeam,
		exportedSeams:               exportedSeams,
		allSeamKeys:                 allSeamKeys,
		parallelReached:             parallelReached,
		nonSeqReached:               nonSeqReached,
		seqAdj:                      seqAdj,
		revSeqAdj:                   revSeqAdj,
		revParAdj:                   revParAdj,
		validLinks:                  validLinks,
		validFieldUses:              validFieldUses,
		validElemUses:               validElemUses,
		mutatedStructs:              mutatedStructs,
		directVarWritten:            directVarWritten,
		nonMethodVarUsed:            nonMethodVarUsed,
		anyMalformedMutatedStruct:   anyMalformedMutatedStruct,
		anyMalformedDirectVarWrite:  anyMalformedDirectVarWrite,
		anyMalformedNonMethodVarUse: anyMalformedNonMethodVarUse,
		allCondStructMutations:      allCondStructMutations,
	}).solveFixedPointsAndAssemble()
}
