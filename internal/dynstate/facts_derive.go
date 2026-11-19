package dynstate

import (
	"context"
	"go/ast"
	"go/types"
	"slices"
	"sort"
	"time"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/capsule"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/seams"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"github.com/greatliontech/gofresh/internal/propharness"
	"github.com/greatliontech/gofresh/internal/trace"
)

// FactOf derives one package's execution-agnostic dynamic-state fact from its
// syntax and type information.
func FactOf(audited bool, p *packages.Package) Fact {
	return FactOfWithHooksCtx(nil, audited, p, false, nil)
}

// FactOfCtx derives one package's execution-agnostic dynamic-state fact,
// emitting trace.DomainDynstate provenance events to any active sink on ctx.
func FactOfCtx(ctx context.Context, audited bool, p *packages.Package) Fact {
	return FactOfWithHooksCtx(ctx, audited, p, false, nil)
}

// FactOfWithHooks derives one package's dynamic-state fact with optional
// explain observation hooks armed. Returned Fact fields are independent of
// singleSubject; singleSubject only suppresses hooks observations at sync.Pool
// call sites that single-subject attestation discharges.
func FactOfWithHooks(audited bool, p *packages.Package, singleSubject bool, hooks *syntaxutil.ExplainHookSet) Fact {
	return FactOfWithHooksCtx(nil, audited, p, singleSubject, hooks)
}

// FactOfWithHooksCtx derives one package's dynamic-state fact with optional
// explain observation hooks armed and ctx-scoped trace.DomainDynstate emission.
func FactOfWithHooksCtx(ctx context.Context, audited bool, p *packages.Package, singleSubject bool, hooks *syntaxutil.ExplainHookSet) Fact {
	if p == nil {
		return Fact{}
	}
	return factOfWithCacheCtx(ctx, audited, p, nil, singleSubject, hooks)
}

func factOfWithCache(audited bool, p *packages.Package, fc *pkgFlowCache, singleSubject bool, hooks *syntaxutil.ExplainHookSet) Fact {
	return factOfWithCacheCtx(nil, audited, p, fc, singleSubject, hooks)
}

func factOfWithCacheCtx(ctx context.Context, audited bool, p *packages.Package, fc *pkgFlowCache, singleSubject bool, hooks *syntaxutil.ExplainHookSet) Fact {
	var fact Fact
	if p == nil {
		return fact
	}
	var start time.Time
	target := dynstateTarget(p)
	tracing := trace.Enabled(ctx, trace.DomainDynstate, target)
	if tracing {
		start = time.Now()
	}
	var idx *refconfine.PkgIndex
	var callIdx *refconfine.CallSiteIndex
	var initOnly map[string]bool
	if p.Types != nil && p.TypesInfo != nil && len(p.Syntax) > 0 {
		idx = refconfine.BuildPkgIndex(p)
		callIdx = idx.CallSites
		initOnly = idx.InitOnly
	} else {
		callIdx = refconfine.BuildCallSiteIndex(p)
		initOnly = callIdx.InitOnlyHelpers()
	}
	if fc == nil {
		fc = newPkgFlowCacheWithIndex(audited, p, idx)
	} else {
		fc.attachToIndex(idx)
	}
	mutated := map[string]bool{}
	escaped := map[string]bool{}
	methodUses := map[string]map[syntaxutil.FuncKey]bool{}
	paramUses := map[string]map[syntaxutil.ParamKey]bool{}
	initParamUses := map[string]map[syntaxutil.ParamKey]bool{}
	initMethodUses := map[string]map[syntaxutil.FuncKey]bool{}
	fieldUses := map[string]map[syntaxutil.FieldPosKey]bool{}
	elemUses := map[string]map[syntaxutil.ElemParamUse]bool{}
	carrierLinks := map[string]map[string]bool{}
	var attributedUses []syntaxutil.AttributedUse
	var attributedParamUses []syntaxutil.VarParamUse
	poolDischarged := map[string]bool{}
	poolMutated := map[string]bool{}
	poolEscaped := map[string]bool{}
	var poolAttributedUses []syntaxutil.AttributedUse
	var seamHook seams.ExportedSeamMarkHook
	if hooks != nil && hooks.ExportedSeamSite != nil {
		seamHook = hooks.ExportedSeamSite
	}
	seamAnalysis := seams.AnalyzeBracketedSeams(audited, p, idx, seamHook)
	fact.ExportedSeams = seamAnalysis.ExportedSeams
	fact.NonSeqFuncUses = seamAnalysis.NonSeqFuncUses
	fact.SeqFuncEdges = seamAnalysis.SeqFuncEdges
	fact.ParallelFuncs = seamAnalysis.ParallelFuncs
	fact.ParallelEdges = seamAnalysis.ParallelEdges
	recordDynamicGlobalUses(audited, p, fc, idx, callIdx, seamAnalysis.Exempt, mutated, escaped, initOnly, methodUses, paramUses, initParamUses, initMethodUses, fieldUses, elemUses, carrierLinks, &attributedUses, &attributedParamUses, singleSubject, poolDischarged, poolMutated, poolEscaped, &poolAttributedUses, hooks)
	for key := range poolDischarged {
		fact.PoolDischarges = append(fact.PoolDischarges, key)
	}
	sort.Strings(fact.PoolDischarges)
	for key := range poolMutated {
		fact.PoolMutates = append(fact.PoolMutates, key)
	}
	sort.Strings(fact.PoolMutates)
	for key := range poolEscaped {
		fact.PoolEscapes = append(fact.PoolEscapes, key)
	}
	sort.Strings(fact.PoolEscapes)
	fact.PoolAttributedUses = append(fact.PoolAttributedUses, poolAttributedUses...)
	slices.SortFunc(fact.PoolAttributedUses, syntaxutil.AttributedUse.Compare)
	fact.PoolAttributedUses = slices.Compact(fact.PoolAttributedUses)
	funcRefs := map[syntaxutil.FuncKey]map[syntaxutil.RefRegion]bool{}
	recordFunctionReferenceRegions(p, fc, initOnly, funcRefs)
	opaque := map[string]bool{}
	breaks := map[string]bool{}
	opaqueDeps := map[string]map[string]bool{}
	recordOpaqueDynamicVars(p, fc, opaque, breaks, opaqueDeps)
	for own, deps := range opaqueDeps {
		for dep := range deps {
			fact.OpaqueDeps = append(fact.OpaqueDeps, syntaxutil.OpaqueDep{Own: own, Dep: dep})
		}
	}
	slices.SortFunc(fact.OpaqueDeps, syntaxutil.OpaqueDep.Compare)
	var pkgConf packageConfinementSummary
	var settledGlobals settledGlobalMap
	var unattestedBroken map[string]bool
	singleSubjectSet := map[string]bool{}
	if p.Types != nil && p.Module != nil && idx != nil {
		for variable, vs := range idx.VarSpecs {
			if variable == nil || vs == nil || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
				continue
			}
			if !refconfine.TypeMayCarryUnknownDynamic(audited, variable.Type()) {
				continue
			}
			doc := vs.Doc
			if doc == nil {
				if gd := idx.VarGenDecls[variable]; gd != nil && len(gd.Specs) == 1 {
					doc = gd.Doc
				}
			}
			if syntaxutil.HasDirective(doc, "//gofresh:single-subject") {
				key := syntaxutil.DynamicVarKey(variable)
				singleSubjectSet[key] = true
				fact.SingleSubjectVars = append(fact.SingleSubjectVars, key)
			}
		}
		sort.Strings(fact.SingleSubjectVars)
	}
	if p.Types != nil {
		pkgPath := p.Types.Path()
		pkgConf = solvePackageConfinement(audited, p, fc, callIdx)
		for method := range pkgConf.readOnly {
			fact.ReceiverReadOnly = append(fact.ReceiverReadOnly, syntaxutil.FuncKey{Pkg: pkgPath, Name: method})
		}
		slices.SortFunc(fact.ReceiverReadOnly, syntaxutil.FuncKey.Compare)
		for method, deps := range pkgConf.readOnlyDeps {
			fnKey := syntaxutil.FuncKey{Pkg: pkgPath, Name: method}
			for callee := range deps {
				fact.ReceiverReadOnlyDeps = append(fact.ReceiverReadOnlyDeps, syntaxutil.FuncDepEdge{Func: fnKey, Callee: callee})
			}
		}
		slices.SortFunc(fact.ReceiverReadOnlyDeps, syntaxutil.FuncDepEdge.Compare)
		for method, pdeps := range pkgConf.readOnlyParamDeps {
			fnKey := syntaxutil.FuncKey{Pkg: pkgPath, Name: method}
			for pk := range pdeps {
				fact.ReceiverReadOnlyParamDeps = append(fact.ReceiverReadOnlyParamDeps, syntaxutil.FuncParamDepEdge{Func: fnKey, Param: pk})
			}
		}
		slices.SortFunc(fact.ReceiverReadOnlyParamDeps, syntaxutil.FuncParamDepEdge.Compare)
		for method := range pkgConf.retentionMethods {
			fact.ReceiverRetentionFree = append(fact.ReceiverRetentionFree, syntaxutil.FuncKey{Pkg: pkgPath, Name: method})
		}
		slices.SortFunc(fact.ReceiverRetentionFree, syntaxutil.FuncKey.Compare)
		readOnly := pkgConf.readOnly
		paramLeakFree := pkgConf.paramLeakFree
		unattestedBroken = make(map[string]bool, len(mutated)+len(escaped)+len(poolMutated)+len(poolEscaped))
		for k := range mutated {
			unattestedBroken[k] = true
		}
		for k := range escaped {
			unattestedBroken[k] = true
		}
		for k := range poolMutated {
			unattestedBroken[k] = true
		}
		for k := range poolEscaped {
			unattestedBroken[k] = true
		}
		for _, seam := range seamAnalysis.ExportedSeams {
			unattestedBroken[seam.Key] = true
		}
		for _, au := range attributedUses {
			if !au.HasMethod || au.Method.Pkg != pkgPath || !readOnly[au.Method.Name] {
				unattestedBroken[au.Key] = true
			}
		}
		for _, au := range poolAttributedUses {
			unattestedBroken[au.Key] = true
		}
		for _, mm := range []map[string]map[syntaxutil.FuncKey]bool{methodUses, initMethodUses} {
			for varKey, mks := range mm {
				for mk := range mks {
					if mk.Pkg != pkgPath || !readOnly[mk.Name] {
						unattestedBroken[varKey] = true
					}
				}
			}
		}
		for _, pm := range []map[string]map[syntaxutil.ParamKey]bool{paramUses, initParamUses} {
			for varKey, pks := range pm {
				for pk := range pks {
					if pk.Func.Pkg != pkgPath || !paramLeakFree[pk] {
						unattestedBroken[varKey] = true
					}
				}
			}
		}
		for _, pu := range attributedParamUses {
			if pu.Param.Func.Pkg != pkgPath || !paramLeakFree[pu.Param] {
				unattestedBroken[pu.Key] = true
			}
		}
		for varKey, wants := range fieldUses {
			if len(wants) > 0 {
				unattestedBroken[varKey] = true
			}
		}
		for varKey, wants := range elemUses {
			if len(wants) > 0 {
				unattestedBroken[varKey] = true
			}
		}
		settledGlobals = settledPackageDataGlobals(audited, p, fc, paramLeakFree, readOnly, unattestedBroken, singleSubjectSet)
	}
	envCarrying := map[string]bool{}
	envCarryingFns := map[string]map[syntaxutil.FuncKey]bool{}
	envCarryingUnattr := map[string]bool{}
	envCallableVars := map[string]bool{}
	envCalls := map[syntaxutil.EnvCallUse]bool{}
	envParamCalls := map[syntaxutil.EnvCallParamUse]bool{}
	envMethodCalls := map[syntaxutil.EnvCallMethodUse]bool{}
	regCarrierLinks := map[syntaxutil.CarrierLink]bool{}
	fieldDefer := map[syntaxutil.FieldPosKey]map[syntaxutil.ParamKey]bool{}
	fieldPoison := map[string]map[syntaxutil.FieldParamPoison]bool{}
	recordEnvCarryingRegistrations(audited, p, fc, idx, callIdx, initOnly, unattestedBroken, singleSubjectSet, settledGlobals, &pkgConf, seamAnalysis.Exempt, envCarrying, envCarryingFns, envCarryingUnattr, envCallableVars, envCalls, envParamCalls, envMethodCalls, regCarrierLinks, fieldDefer, fieldPoison, hooks)
	for pos, params := range fieldDefer {
		for param := range params {
			fact.FieldParamDefer = append(fact.FieldParamDefer, syntaxutil.FieldParamDefer{Pos: pos, Param: param})
		}
	}
	slices.SortFunc(fact.FieldParamDefer, syntaxutil.FieldParamDefer.Compare)
	for _, entries := range fieldPoison {
		for entry := range entries {
			fact.FieldParamPoison = append(fact.FieldParamPoison, entry)
		}
	}
	slices.SortFunc(fact.FieldParamPoison, syntaxutil.FieldParamPoison.Compare)
	for _, wants := range fieldUses {
		for want := range wants {
			fact.FieldParamUses = append(fact.FieldParamUses, want)
		}
	}
	slices.SortFunc(fact.FieldParamUses, syntaxutil.FieldPosKey.Compare)
	for _, wants := range elemUses {
		for want := range wants {
			fact.ElemParamUses = append(fact.ElemParamUses, want)
		}
	}
	slices.SortFunc(fact.ElemParamUses, syntaxutil.ElemParamUse.Compare)
	for key := range envCarrying {
		fact.EnvCarrying = append(fact.EnvCarrying, key)
	}
	sort.Strings(fact.EnvCarrying)
	for key, fns := range envCarryingFns {
		if envCarryingUnattr[key] {
			continue
		}
		for fn := range fns {
			fact.EnvCarryingFns = append(fact.EnvCarryingFns, syntaxutil.VarFuncUse{Key: key, Func: fn})
		}
	}
	slices.SortFunc(fact.EnvCarryingFns, syntaxutil.VarFuncUse.Compare)
	for key := range envCallableVars {
		fact.EnvCallable = append(fact.EnvCallable, key)
	}
	sort.Strings(fact.EnvCallable)
	for use := range envCalls {
		if !use.Func.IsZero() && envCalls[syntaxutil.EnvCallUse{Key: use.Key, Callee: use.Callee}] {
			continue
		}
		fact.EnvCallUses = append(fact.EnvCallUses, use)
	}
	slices.SortFunc(fact.EnvCallUses, syntaxutil.EnvCallUse.Compare)
	for use := range envParamCalls {
		if !use.Func.IsZero() && envParamCalls[syntaxutil.EnvCallParamUse{Key: use.Key, Param: use.Param}] {
			continue
		}
		fact.EnvCallParamUses = append(fact.EnvCallParamUses, use)
	}
	slices.SortFunc(fact.EnvCallParamUses, syntaxutil.EnvCallParamUse.Compare)
	for use := range envMethodCalls {
		if !use.Func.IsZero() && envMethodCalls[syntaxutil.EnvCallMethodUse{Key: use.Key, Method: use.Method}] {
			continue
		}
		fact.EnvCallMethodUses = append(fact.EnvCallMethodUses, use)
	}
	slices.SortFunc(fact.EnvCallMethodUses, syntaxutil.EnvCallMethodUse.Compare)
	fact.AttributedUses = append(fact.AttributedUses, attributedUses...)
	slices.SortFunc(fact.AttributedUses, syntaxutil.AttributedUse.Compare)
	fact.AttributedUses = slices.Compact(fact.AttributedUses)
	for callee, regions := range funcRefs {
		for region := range regions {
			fact.FuncRefs = append(fact.FuncRefs, syntaxutil.FuncRef{Callee: callee, Region: region})
		}
	}
	slices.SortFunc(fact.FuncRefs, syntaxutil.FuncRef.Compare)
	for varKey, methodKeys := range methodUses {
		for methodKey := range methodKeys {
			fact.MethodUses = append(fact.MethodUses, syntaxutil.VarMethodUse{Key: varKey, Method: methodKey})
		}
	}
	slices.SortFunc(fact.MethodUses, syntaxutil.VarMethodUse.Compare)
	if p.Types != nil {
		for paramKey := range pkgConf.paramLeakFree {
			fact.ParamLeakFree = append(fact.ParamLeakFree, paramKey)
		}
		slices.SortFunc(fact.ParamLeakFree, syntaxutil.ParamKey.Compare)
		for ownKey, edges := range pkgConf.paramDeps {
			for dep := range edges {
				fact.ParamLeakFreeDeps = append(fact.ParamLeakFreeDeps, syntaxutil.ParamDepEdge{Own: ownKey, Dep: dep})
			}
		}
		slices.SortFunc(fact.ParamLeakFreeDeps, syntaxutil.ParamDepEdge.Compare)
		for ownKey, edges := range pkgConf.paramMethodDeps {
			for mk := range edges {
				fact.ParamLeakFreeMethodDeps = append(fact.ParamLeakFreeMethodDeps, syntaxutil.ParamMethodDepEdge{Param: ownKey, Method: mk})
			}
		}
		slices.SortFunc(fact.ParamLeakFreeMethodDeps, syntaxutil.ParamMethodDepEdge.Compare)
		for paramKey := range pkgConf.paramRetention {
			fact.ParamRetentionFree = append(fact.ParamRetentionFree, paramKey)
		}
		slices.SortFunc(fact.ParamRetentionFree, syntaxutil.ParamKey.Compare)
		for ownKey, edges := range pkgConf.paramRetDeps {
			for dep := range edges {
				fact.ParamRetentionFreeDeps = append(fact.ParamRetentionFreeDeps, syntaxutil.ParamDepEdge{Own: ownKey, Dep: dep})
			}
		}
		slices.SortFunc(fact.ParamRetentionFreeDeps, syntaxutil.ParamDepEdge.Compare)
		outflow := analyzeClosureOutflowSummaries(audited, p, fc, settledGlobals, &pkgConf, hooks)
		pkgPath := p.Types.Path()
		for fnName := range outflow.returnEnvFree {
			fnKey := syntaxutil.FuncKey{Pkg: pkgPath, Name: fnName}
			fact.ReturnEnvFree = append(fact.ReturnEnvFree, fnKey)
			for callee := range outflow.returnEnvDeps[fnName] {
				fact.ReturnEnvDeps = append(fact.ReturnEnvDeps, syntaxutil.FuncDepEdge{Func: fnKey, Callee: callee})
			}
			for pk := range outflow.returnEnvParamDeps[fnName] {
				fact.ReturnEnvParamDeps = append(fact.ReturnEnvParamDeps, syntaxutil.FuncParamDepEdge{Func: fnKey, Param: pk})
			}
			for mk := range outflow.returnEnvMethodDeps[fnName] {
				fact.ReturnEnvMethodDeps = append(fact.ReturnEnvMethodDeps, syntaxutil.FuncDepEdge{Func: fnKey, Callee: mk})
			}
			for dep := range outflow.returnInsertionCallDep[fnName] {
				fact.ReturnEnvInsertionDeps = append(fact.ReturnEnvInsertionDeps, syntaxutil.FuncInsertionDepEdge{Func: fnKey, Dep: dep})
			}
			for entry := range outflow.returnFieldDefer[fnName] {
				fact.ReturnFieldParamDefer = append(fact.ReturnFieldParamDefer, entry)
			}
			for entry := range outflow.returnFieldPoison[fnName] {
				fact.ReturnFieldParamPoison = append(fact.ReturnFieldParamPoison, entry)
			}
		}
		slices.SortFunc(fact.ReturnEnvFree, syntaxutil.FuncKey.Compare)
		slices.SortFunc(fact.ReturnEnvDeps, syntaxutil.FuncDepEdge.Compare)
		slices.SortFunc(fact.ReturnEnvParamDeps, syntaxutil.FuncParamDepEdge.Compare)
		slices.SortFunc(fact.ReturnEnvMethodDeps, syntaxutil.FuncDepEdge.Compare)
		slices.SortFunc(fact.ReturnEnvInsertionDeps, syntaxutil.FuncInsertionDepEdge.Compare)
		slices.SortFunc(fact.ReturnFieldParamDefer, syntaxutil.ReturnFieldParamDefer.Compare)
		slices.SortFunc(fact.ReturnFieldParamPoison, syntaxutil.ReturnFieldParamPoison.Compare)
		for ownKey := range outflow.paramInsertionFree {
			fact.ParamInsertionFree = append(fact.ParamInsertionFree, ownKey)
			for dep := range outflow.paramInsertionDeps[ownKey] {
				fact.ParamInsertionDeps = append(fact.ParamInsertionDeps, syntaxutil.ParamInsertionDepEdge{Param: ownKey, Dep: dep})
			}
			for pk := range outflow.paramInsertionParams[ownKey] {
				fact.ParamInsertionParamDeps = append(fact.ParamInsertionParamDeps, syntaxutil.ParamDepEdge{Own: ownKey, Dep: pk})
			}
			for mk := range outflow.paramInsertionMethods[ownKey] {
				fact.ParamInsertionMethodDeps = append(fact.ParamInsertionMethodDeps, syntaxutil.ParamMethodDepEdge{Param: ownKey, Method: mk})
			}
		}
		slices.SortFunc(fact.ParamInsertionFree, syntaxutil.ParamKey.Compare)
		slices.SortFunc(fact.ParamInsertionDeps, syntaxutil.ParamInsertionDepEdge.Compare)
		slices.SortFunc(fact.ParamInsertionParamDeps, syntaxutil.ParamDepEdge.Compare)
		slices.SortFunc(fact.ParamInsertionMethodDeps, syntaxutil.ParamMethodDepEdge.Compare)
	}
	for varKey, paramKeys := range paramUses {
		for paramKey := range paramKeys {
			fact.ParamUses = append(fact.ParamUses, syntaxutil.VarParamUse{Key: varKey, Param: paramKey})
		}
	}
	fact.ParamUses = append(fact.ParamUses, attributedParamUses...)
	slices.SortFunc(fact.ParamUses, syntaxutil.VarParamUse.Compare)
	fact.ParamUses = slices.Compact(fact.ParamUses)
	for varKey, paramKeys := range initParamUses {
		for paramKey := range paramKeys {
			fact.InitParamUses = append(fact.InitParamUses, syntaxutil.VarParamUse{Key: varKey, Param: paramKey})
		}
	}
	slices.SortFunc(fact.InitParamUses, syntaxutil.VarParamUse.Compare)
	for varKey, methodKeys := range initMethodUses {
		for methodKey := range methodKeys {
			fact.InitMethodUses = append(fact.InitMethodUses, syntaxutil.VarMethodUse{Key: varKey, Method: methodKey})
		}
	}
	slices.SortFunc(fact.InitMethodUses, syntaxutil.VarMethodUse.Compare)
	for keyA, others := range carrierLinks {
		for keyB := range others {
			fact.CarrierLinks = append(fact.CarrierLinks, syntaxutil.CarrierLink{From: keyA, To: keyB})
		}
	}
	for link := range regCarrierLinks {
		fact.CarrierLinks = append(fact.CarrierLinks, link)
	}
	slices.SortFunc(fact.CarrierLinks, syntaxutil.CarrierLink.Compare)
	fact.CarrierLinks = slices.Compact(fact.CarrierLinks)
	for key := range mutated {
		fact.Mutates = append(fact.Mutates, key)
	}
	sort.Strings(fact.Mutates)
	for key := range escaped {
		fact.Escapes = append(fact.Escapes, key)
	}
	sort.Strings(fact.Escapes)
	for key := range opaque {
		fact.Opaque = append(fact.Opaque, key)
	}
	sort.Strings(fact.Opaque)
	for key := range breaks {
		fact.OpacityBreaks = append(fact.OpacityBreaks, key)
	}
	sort.Strings(fact.OpacityBreaks)
	if p.Types != nil && p.Module != nil {
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			if variable, ok := scope.Lookup(name).(*types.Var); ok && refconfine.TypeMayCarryUnknownDynamic(audited, variable.Type()) {
				fact.Declares = append(fact.Declares, syntaxutil.DynamicVarKey(variable))
			}
		}
		sort.Strings(fact.Declares)
	}
	recordPackageMethodDirectives(p, &fact)
	if idx != nil {
		fact.DirectVarWrites = capsule.CollectDirectCrossPkgVarWrites(audited, p, idx)
	}
	if p.Types != nil && p.Module != nil {
		if idx != nil {
			freshCache := freshstruct.NewFreshLocalsCache(p, idx)
			confinedCacheMaps := freshstruct.FindMutexConfinedConstructorCaches(p, idx)
			fact.MappingDischarges = deriveMappingDischarges(ctx, audited, p, fc, idx)
			fact.MemoDischarges = deriveMemoDischarges(ctx, audited, p, fc, idx)
			var onceMemoExempt map[ast.Node]bool
			fact.OnceMemoTypes, onceMemoExempt = deriveOnceMemoTypes(ctx, audited, p, fc, idx, freshCache, &pkgConf)
			if len(fact.Declares) > 0 && propharness.MayBeHarnessPackage(p) {
				if vp, _ := propharness.VerifyPackageWithIndex(ctx, trace.DomainDynstate, audited, p, idx); vp != nil {
					fact.HarnessDischarges = slices.Clone(fact.Declares)
				}
			}
			unattestedMutated := make(map[string]bool, len(mutated)+len(poolMutated))
			for key := range mutated {
				unattestedMutated[key] = true
			}
			for key := range poolMutated {
				unattestedMutated[key] = true
			}
			var claimedVars map[*types.Var]bool
			fact.InitSettledClusters, fact.InitBuilders, fact.LazyOnceCapsuleTypes, fact.MutatedStructTypes, fact.ConditionalStructMutations, fact.ReflectedIfaceMethodSets, claimedVars =
				capsule.DeriveCapsuleAndStructFactsCtx(ctx, audited, p, idx, freshCache, confinedCacheMaps, initOnly, unattestedMutated, onceMemoExempt)
			var exemptAliasIdents map[*ast.Ident]bool
			fact.ReadOnlyVarAliases, exemptAliasIdents = deriveReadOnlyVarAliases(ctx, audited, p, fc, idx, singleSubjectSet, claimedVars)
			fact.StaticCompositeGlobals = deriveStaticCompositeGlobals(ctx, audited, p, fc, idx, singleSubjectSet, claimedVars)
			fact.OnceMemoCandidates = deriveOnceMemoCandidates(ctx, audited, p, fc, idx, singleSubjectSet, exemptAliasIdents)
			fact.NonMethodVarUses = capsule.CollectNonMethodCrossPkgVarUses(audited, p, idx, exemptAliasIdents)
			fact.NonMutatingMethods = capsule.DeriveNonMutatingMethods(audited, p, idx)
			fact.NoPostInitCarrierWrites, fact.CarrierImportCalls =
				capsule.DeriveNoPostInitCarrierWrites(audited, p, idx, initOnly, fact.DirectVarWrites)
		}
	} else if idx != nil {
		freshCache := freshstruct.NewFreshLocalsCache(p, idx)
		confinedCacheMaps := freshstruct.FindMutexConfinedConstructorCaches(p, idx)
		fact.NonMethodVarUses = capsule.CollectNonMethodCrossPkgVarUses(audited, p, idx, nil)
		fact.MutatedStructTypes, fact.ConditionalStructMutations, fact.ReflectedIfaceMethodSets = freshstruct.CollectMutatedStructTypesWithCapsuleFieldsCtx(ctx, p, idx, freshCache, confinedCacheMaps, nil, nil, nil, nil, nil)
		fact.NonMutatingMethods = capsule.DeriveNonMutatingMethods(audited, p, idx)
		fact.NoPostInitCarrierWrites, fact.CarrierImportCalls =
			capsule.DeriveNoPostInitCarrierWrites(audited, p, idx, initOnly, fact.DirectVarWrites)
	}
	if tracing {
		for _, v := range fact.Mutates {
			trace.Emit(ctx, trace.DomainDynstate, "dynstate.var.reject", target,
				trace.String("var", v),
				trace.String("kind", "mutates"),
			)
		}
		for _, v := range fact.Escapes {
			trace.Emit(ctx, trace.DomainDynstate, "dynstate.var.reject", target,
				trace.String("var", v),
				trace.String("kind", "escapes"),
			)
		}
		trace.Emit(ctx, trace.DomainDynstate, "dynstate.factof.done", target,
			trace.Bool("audited", audited),
			trace.Int("declares", len(fact.Declares)),
			trace.Int("mutates", len(fact.Mutates)),
			trace.Int("escapes", len(fact.Escapes)),
			trace.Int64("dur_ns", time.Since(start).Nanoseconds()),
		)
	}
	return fact
}
