package dynstate

import (
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
	var start time.Time
	tracing := q.ViewPackage != "" && trace.Enabled(nil, trace.DomainDynstate, q.ViewPackage)
	if tracing {
		start = time.Now()
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
			for _, a := range fact.ProtoExtAliases {
				if !a.Valid() {
					factBad = true
				}
			}
			for _, rt := range fact.ProtoRuntimeTypes {
				if !rt.Valid() {
					factBad = true
				}
			}
			for _, gv := range fact.GrpcServiceVars {
				if !gv.Valid() {
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

	// Stage 2a: Joint confinement least fixed point (ParamLeakFree & ReadOnly).
	for pk := range paramCandidates {
		delete(r.ParamLeakFree, pk)
	}
	for pk := range poisonedLeakParam {
		delete(r.ParamLeakFree, pk)
		delete(paramCandidates, pk)
		delete(ea.ParamDeps, pk)
		delete(ea.ParamMethodDeps, pk)
	}
	for mk := range methodCandidates {
		delete(r.ReadOnly, mk)
	}
	for mk := range poisonedMethod {
		delete(r.ReadOnly, mk)
		delete(methodCandidates, mk)
		delete(ea.MethodDeps, mk)
		delete(ea.MethodParamDeps, mk)
	}
	for changed := true; changed; {
		changed = false
		for pk := range paramCandidates {
			if r.ParamLeakFree[pk] {
				continue
			}
			ok := true
			for dep := range ea.ParamDeps[pk] {
				if !r.ParamLeakFree[dep] {
					ok = false
					break
				}
			}
			if ok {
				for mk := range ea.ParamMethodDeps[pk] {
					if !r.ReadOnly[mk] {
						ok = false
						break
					}
				}
			}
			if ok {
				r.ParamLeakFree[pk] = true
				changed = true
			}
		}
		for mk := range methodCandidates {
			if r.ReadOnly[mk] {
				continue
			}
			ok := true
			for dep := range ea.MethodDeps[mk] {
				if !r.ReadOnly[dep] {
					ok = false
					break
				}
			}
			if ok {
				for pk := range ea.MethodParamDeps[mk] {
					if !r.ParamLeakFree[pk] {
						ok = false
						break
					}
				}
			}
			if ok {
				r.ReadOnly[mk] = true
				changed = true
			}
		}
	}

	// Stage 2b: Parameter retention LFP & closed-object opacity reachability.
	for pk := range poisonedRetParam {
		delete(r.ParamRetentionFree, pk)
		delete(retentionDeps, pk)
	}
	syntaxutil.SolveLeastFixedPoint(r.ParamRetentionFree, retentionDeps, func(dep syntaxutil.ParamKey) bool {
		return r.ParamRetentionFree[dep] || r.ParamLeakFree[dep]
	})
	syntaxutil.SolveReachFixedPoint(r.NotOpaque, opaqueDeps, func(dep string) bool {
		return r.NotOpaque[dep] || !r.Declared[dep]
	})
	for key := range escaped {
		if !r.IsObjectClosed(key) {
			r.OwnerUnproven[key] = true
		}
	}

	// Stage 2c: Environment-audit joint LFP (ReturnEnvFree & ParamInsertionFree).
	for fnKey := range poisonedEnvFunc {
		delete(ea.Declared, fnKey)
	}
	for paramKey := range poisonedEnvParam {
		delete(ea.InsDeclared, paramKey)
	}
	for changed := true; changed; {
		changed = false
		for fnKey := range ea.Declared {
			if ea.Resolved[fnKey] {
				continue
			}
			ok := true
			for dep := range ea.RetDeps[fnKey] {
				if !ea.Resolved[dep] {
					ok = false
					break
				}
			}
			if ok {
				for pk := range ea.RetParamDeps[fnKey] {
					if !ea.ParamLeakFree[pk] {
						ok = false
						break
					}
				}
			}
			if ok {
				for mk := range ea.RetMethodDeps[fnKey] {
					if !ea.ReadOnly[mk] {
						ok = false
						break
					}
				}
			}
			if ok {
				for dep := range ea.RetInsDeps[fnKey] {
					if !ea.DepResolved(dep) {
						ok = false
						break
					}
				}
			}
			if ok {
				ea.Resolved[fnKey] = true
				changed = true
			}
		}
		for paramKey := range ea.InsDeclared {
			if ea.InsResolved[paramKey] {
				continue
			}
			ok := true
			for dep := range ea.InsDeps[paramKey] {
				if !ea.DepResolved(dep) {
					ok = false
					break
				}
			}
			if ok {
				for pk := range ea.InsParamDeps[paramKey] {
					if !ea.ParamLeakFree[pk] {
						ok = false
						break
					}
				}
			}
			if ok {
				for mk := range ea.InsMethodDeps[paramKey] {
					if !ea.ReadOnly[mk] {
						ok = false
						break
					}
				}
			}
			if ok {
				ea.InsResolved[paramKey] = true
				changed = true
			}
		}
	}
	r.EnvFreeResolved = ea.Resolved

	// Stage 2d: Call-region fixed points (InitOnlyFn & InitReachFn).
	syntaxutil.SolveLeastFixedPoint(r.InitOnlyFn, r.RefRegions, func(region syntaxutil.RefRegion) bool {
		if region.Kind == syntaxutil.RegionInit {
			return true
		}
		return region.Kind == syntaxutil.RegionFunc && r.InitOnlyFn[region.Caller]
	})
	syntaxutil.SolveReachFixedPoint(r.InitReachFn, r.RefRegions, func(region syntaxutil.RefRegion) bool {
		if region.Kind == syntaxutil.RegionInit || region.Kind == syntaxutil.RegionProg {
			return true
		}
		return (region.Kind == syntaxutil.RegionFunc || region.Kind == syntaxutil.RegionLitFunc) && r.InitReachFn[region.Caller]
	})

	// Stage 2e: Blocked exported seams.
	blockedSeams := map[string]map[syntaxutil.FuncKey]bool{}
	if hasMalformedSeam {
		for _, key := range allSeamKeys {
			addMapSet(blockedSeams, key, syntaxutil.FuncKey{})
		}
	} else if len(exportedSeams) > 0 {
		if len(parallelReached) > 0 && len(revParAdj) > 0 {
			syntaxutil.PropagateBFS(parallelReached, revParAdj)
		}
		for fn := range parallelReached {
			if fn.Pkg != "*" && !strings.Contains(fn.Name, "#") {
				nonSeqReached[fn] = true
			}
		}
		if len(nonSeqReached) > 0 && len(seqAdj) > 0 {
			syntaxutil.PropagateBFS(nonSeqReached, seqAdj)
		}
		for _, es := range exportedSeams {
			if nonSeqReached[es.Func] || (es.RunnerOnly && len(revSeqAdj[es.Func]) > 0) {
				addMapSet(blockedSeams, es.Key, es.Func)
			}
		}
	}

	// Stage 2f: Active carrier link graph and component population pooling.
	linkAdj := buildCarrierLinkGraph(validLinks, r)
	if len(linkAdj) > 0 {
		visited := map[string]bool{}
		var components [][]string
		for _, link := range validLinks {
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

	// Stage 2g: Unified deferred mark resolution, site attribution, and OwnerUnproven seeding.
	siteFns := map[string]map[string]bool{}
	attributeSite := func(key string, fn syntaxutil.FuncKey) {
		addMapSet(siteFns, key, fn.SiteKey())
	}
	mayRunAtInit := func(fn syntaxutil.FuncKey) bool {
		return r.InitReachFn[fn] || strings.Contains(fn.Name, ".")
	}
	isInitOnlyPlain := func(fn syntaxutil.FuncKey) bool {
		return r.RefRegions[fn] != nil && r.InitOnlyFn[fn]
	}
	markEscaped := func(key string) {
		escaped[key] = true
		if !r.IsObjectClosed(key) {
			r.OwnerUnproven[key] = true
		}
	}
	markMutated := func(key string) {
		mutated[key] = true
		r.OwnerUnproven[key] = true
	}
	applyAttributedUse := func(use syntaxutil.AttributedUse) {
		if !use.Valid() {
			return
		}
		fn, key := use.Func, use.Key
		if use.Literal {
			if use.HasMethod {
				if r.ReadOnly[use.Method] {
					return
				}
				markMutated(key)
			} else if use.Escape {
				markEscaped(key)
			} else {
				markMutated(key)
			}
			if mayRunAtInit(fn) {
				unattributedMark[key] = true
			} else {
				attributeSite(key, fn)
			}
			return
		}
		if use.Escape {
			markEscaped(key)
			if mayRunAtInit(fn) {
				unattributedMark[key] = true
			} else {
				attributeSite(key, fn)
			}
			return
		}
		if use.HasMethod {
			if r.ReadOnly[use.Method] {
				return
			}
			if isInitOnlyPlain(fn) {
				if !r.ReceiverRetention[use.Method] {
					markMutated(key)
					unattributedMark[key] = true
				}
				return
			}
			markMutated(key)
			if !r.ReceiverRetention[use.Method] && mayRunAtInit(fn) {
				unattributedMark[key] = true
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

	for _, pkgPath := range pkgPaths {
		for _, fact := range allFacts[pkgPath] {
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
				if envCallable[key] || len(fns) == 0 {
					unattributedMark[key] = true
					continue
				}
				for _, fn := range fns {
					if mayRunAtInit(fn) {
						unattributedMark[key] = true
					} else {
						attributeSite(key, fn)
					}
				}
			}
			for _, use := range fact.EnvCallUses {
				if !use.Valid() || r.EnvFreeResolved[use.Callee] {
					continue
				}
				// Keep r.OwnerUnproven[use.Key] unset: FieldPopulationProves
				// inspects r.CtorsOf[use.Key] directly.
				envCarrying[use.Key] = true
				if use.Func.IsZero() || envCallable[use.Key] || mayRunAtInit(use.Func) {
					unattributedMark[use.Key] = true
				} else {
					attributeSite(use.Key, use.Func)
				}
			}
			for _, use := range fact.EnvCallParamUses {
				if !use.Valid() || r.ParamLeakFree[use.Param] {
					continue
				}
				envCarrying[use.Key] = true
				r.OwnerUnproven[use.Key] = true
				if use.Func.IsZero() || envCallable[use.Key] || mayRunAtInit(use.Func) {
					unattributedMark[use.Key] = true
				} else {
					attributeSite(use.Key, use.Func)
				}
			}
			for _, use := range fact.EnvCallMethodUses {
				if !use.Valid() || r.ReadOnly[use.Method] {
					continue
				}
				envCarrying[use.Key] = true
				r.OwnerUnproven[use.Key] = true
				if use.Func.IsZero() || envCallable[use.Key] || mayRunAtInit(use.Func) {
					unattributedMark[use.Key] = true
				} else {
					attributeSite(use.Key, use.Func)
				}
			}
			for _, use := range fact.MethodUses {
				if use.Valid() && !r.ReadOnly[use.Method] {
					markMutated(use.Key)
					unattributedMark[use.Key] = true
				}
			}
			for _, use := range fact.InitMethodUses {
				if use.Valid() && !r.ReceiverRetention[use.Method] {
					markEscaped(use.Key)
					unattributedMark[use.Key] = true
				}
			}
			for _, use := range fact.ParamUses {
				if !use.Valid() || r.ParamLeakFree[use.Param] {
					continue
				}
				if use.Func.IsZero() {
					markEscaped(use.Key)
					unattributedMark[use.Key] = true
					continue
				}
				fn, key := use.Func, use.Key
				if use.Literal {
					markEscaped(key)
					if mayRunAtInit(fn) {
						unattributedMark[key] = true
					} else {
						attributeSite(key, fn)
					}
					continue
				}
				if isInitOnlyPlain(fn) {
					if !r.ParamRetentionFree[use.Param] {
						markEscaped(key)
						unattributedMark[key] = true
					}
					continue
				}
				markEscaped(key)
				if !r.ParamRetentionFree[use.Param] && mayRunAtInit(fn) {
					unattributedMark[key] = true
				} else {
					attributeSite(key, fn)
				}
			}
			for _, use := range fact.InitParamUses {
				if use.Valid() && use.Func.IsZero() && !r.ParamLeakFree[use.Param] && !r.ParamRetentionFree[use.Param] {
					markEscaped(use.Key)
					unattributedMark[use.Key] = true
				}
			}
			for _, use := range fact.AttributedUses {
				applyAttributedUse(use)
			}
			if !q.SingleSubject {
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
				unattributedMark[key] = true
			} else {
				attributeSite(key, fn)
			}
		}
	}
	for key := range envCarrying {
		if envCallable[key] {
			unattributedMark[key] = true
		}
	}

	// Stage 2h: Converge OwnerUnproven across LinkAdj, FieldParamUses, and
	// ElemParamUses (note LinkAdj already excludes IsObjectClosed endpoints),
	// then evaluate FieldParamUses/ElemParamUses escapes and propagate marks
	// across LinkAdj.
	for changed := true; changed; {
		changed = false
		for key := range r.OwnerUnproven {
			for next := range linkAdj[key] {
				if !r.OwnerUnproven[next] {
					r.OwnerUnproven[next] = true
					changed = true
				}
			}
		}
		for _, use := range validFieldUses {
			if len(linkAdj[use.Owner]) == 0 {
				continue
			}
			// Neighbor-only propagation: never set r.OwnerUnproven[use.Owner]
			// from use.Owner's own failed FieldParamUses.
			if ok, _ := r.FieldPopulationProves(use.Owner, use.Field, use.Index); !ok {
				for next := range linkAdj[use.Owner] {
					if !r.OwnerUnproven[next] {
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
	for _, use := range validFieldUses {
		if ok, _ := r.FieldPopulationProves(use.Owner, use.Field, use.Index); !ok {
			escaped[use.Owner] = true
			unattributedMark[use.Owner] = true
		}
	}
	for _, use := range validElemUses {
		if ok, _ := r.FieldPopulationProves(use.Owner, syntaxutil.ElemPositionField, use.Index); !ok {
			escaped[use.Key] = true
			unattributedMark[use.Key] = true
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
					unattributedMark[next] = true
					if !set[next] {
						set[next] = true
						queue = append(queue, next)
					}
				}
			}
		}
		propagateWithUnattributed(mutated)
		propagateWithUnattributed(escaped)
		propagateWithUnattributed(envCarrying)
	}

	out := &ConeAnalysis{
		Deferral:           r,
		EnvAudit:           ea,
		BlockedSeams:       blockedSeams,
		LinkAdj:            linkAdj,
		NonVouchDischarged: map[string]bool{},
	}
	if len(q.Meta) == 0 && q.ViewPackage == "" {
		return out
	}

	// Stage 3: Discharges and view-package ConeState assembly.
	discharges := deriveConeDischarges(
		q.Meta,
		pkgPaths,
		allFacts,
		r.RefRegions,
		r.InitOnlyFn,
		r.ParamLeakFree,
		pkgHasMalformedFact,
		malformedFactVars,
		mutatedStructs,
		allCondStructMutations,
		directVarWritten,
		nonMethodVarUsed,
		anyMalformedMutatedStruct,
		anyMalformedDirectVarWrite,
		anyMalformedNonMethodVarUse,
	)

	for _, pkgPath := range pkgPaths {
		inGraph := discharges.pinnedPkg[pkgPath] || discharges.mutableLocalPkg[pkgPath]
		if !inGraph || pkgHasMalformedFact[pkgPath] {
			continue
		}
		for _, fact := range allFacts[pkgPath] {
			for _, key := range fact.Declares {
				if malformedFactVars[key] {
					continue
				}
				if discharges.mappingDischargedVars[key] || discharges.memoDischargedVars[key] || discharges.harnessDischargedVars[key] {
					out.NonVouchDischarged[key] = true
					continue
				}
				if q.SingleSubject && discharges.mutableLocalPkg[pkgPath] && discharges.directiveCovered[key] {
					out.NonVouchDischarged[key] = true
					continue
				}
				if q.SingleSubject && (discharges.protoVerifiedVars[key] || discharges.grpcVerifiedVars[key]) {
					out.NonVouchDischarged[key] = true
				}
			}
		}
	}

	if q.ViewPackage == "" {
		return out
	}

	out.State = buildViewConeState(
		q,
		pkgPaths,
		allFacts,
		r.NotOpaque,
		mutated,
		escaped,
		envCarrying,
		unattributedMark,
		siteFns,
		pkgHasMalformedFact,
		malformedFactVars,
		discharges,
	)
	if tracing {
		trace.Emit(nil, trace.DomainDynstate, "dynstate.compose.done", q.ViewPackage,
			trace.Int("cone_pkgs", len(allFacts)),
			trace.Bool("downgraded", out.State.Downgraded != ""),
			trace.Int("culprits", len(out.State.RootCulprits)),
			trace.Int64("dur_ns", time.Since(start).Nanoseconds()),
		)
	}
	return out
}
