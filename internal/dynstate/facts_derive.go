package dynstate

import (
	"go/ast"
	"go/types"
	"slices"
	"sort"
	"time"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/seams"
	"github.com/greatliontech/gofresh/internal/dynstate/protoaudit"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"github.com/greatliontech/gofresh/internal/propharness"
	"github.com/greatliontech/gofresh/internal/trace"
)

// FactOf derives one package's execution-agnostic dynamic-state fact from its
// syntax and type information.
func FactOf(audited bool, p *packages.Package) Fact {
	return FactOfWithHooks(audited, p, false, nil)
}

// FactOfWithHooks derives one package's dynamic-state fact with optional
// explain observation hooks armed. Returned Fact fields are independent of
// singleSubject; singleSubject only suppresses hooks observations at sync.Pool
// call sites that single-subject attestation discharges.
func FactOfWithHooks(audited bool, p *packages.Package, singleSubject bool, hooks *syntaxutil.ExplainHookSet) Fact {
	if p == nil {
		return Fact{}
	}
	return factOfWithCache(audited, p, newPkgFlowCache(audited, p), singleSubject, hooks)
}

func factOfWithCache(audited bool, p *packages.Package, fc *pkgFlowCache, singleSubject bool, hooks *syntaxutil.ExplainHookSet) Fact {
	var fact Fact
	if p == nil {
		return fact
	}
	var start time.Time
	tracing := trace.Enabled(nil, trace.DomainDynstate, p.PkgPath)
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
		fc = newPkgFlowCache(audited, p)
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
	stringEscaped := map[string]bool{}
	var stringAttributedUses []syntaxutil.AttributedUse
	pkgStrUnsafe := fc != nil && fc.pkgHasStringHeaderUnsafe
	fact.HasStringHeaderUnsafe = pkgStrUnsafe
	if p.Types != nil {
		sinkPkgs := map[string]bool{}
		sinkParams := map[syntaxutil.ParamKey]bool{}
		sinkMethods := map[syntaxutil.FuncKey]bool{}
		callbackTargets := map[string]bool{}
		collectForeignStringAndCallbackEdges(audited, p, fc, sinkPkgs, sinkParams, sinkMethods, callbackTargets)
		for q := range sinkPkgs {
			fact.StringSinkPkgs = append(fact.StringSinkPkgs, q)
		}
		sort.Strings(fact.StringSinkPkgs)
		for pk := range sinkParams {
			fact.StringSinkParams = append(fact.StringSinkParams, pk)
		}
		slices.SortFunc(fact.StringSinkParams, syntaxutil.ParamKey.Compare)
		for mk := range sinkMethods {
			fact.StringSinkMethods = append(fact.StringSinkMethods, mk)
		}
		slices.SortFunc(fact.StringSinkMethods, syntaxutil.FuncKey.Compare)
		for q := range callbackTargets {
			fact.StringCallbackTargets = append(fact.StringCallbackTargets, q)
		}
		sort.Strings(fact.StringCallbackTargets)
	}
	baseHooks := hooks
	if hooks != nil && hooks.StringUnsafeOnly {
		baseHooks = nil
	}
	var seamHook seams.ExportedSeamMarkHook
	if baseHooks != nil && baseHooks.ExportedSeamSite != nil {
		seamHook = baseHooks.ExportedSeamSite
	}
	seamAnalysis := seams.AnalyzeBracketedSeams(audited, p, idx, seamHook)
	fact.ExportedSeams = seamAnalysis.ExportedSeams
	fact.NonSeqFuncUses = seamAnalysis.NonSeqFuncUses
	fact.SeqFuncEdges = seamAnalysis.SeqFuncEdges
	fact.ParallelFuncs = seamAnalysis.ParallelFuncs
	fact.ParallelEdges = seamAnalysis.ParallelEdges
	recordDynamicGlobalUses(audited, p, fc, idx, callIdx, seamAnalysis.Exempt, mutated, escaped, initOnly, methodUses, paramUses, initParamUses, initMethodUses, fieldUses, elemUses, carrierLinks, &attributedUses, &attributedParamUses, singleSubject, poolDischarged, poolMutated, poolEscaped, &poolAttributedUses, stringEscaped, &stringAttributedUses, baseHooks)
	for key := range stringEscaped {
		fact.StringEscapes = append(fact.StringEscapes, key)
	}
	sort.Strings(fact.StringEscapes)
	fact.StringAttributedUses = append(fact.StringAttributedUses, stringAttributedUses...)
	slices.SortFunc(fact.StringAttributedUses, syntaxutil.AttributedUse.Compare)
	fact.StringAttributedUses = slices.Compact(fact.StringAttributedUses)
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
		settledGlobals = settledPackageDataGlobals(audited, pkgStrUnsafe, p, fc, paramLeakFree, readOnly, unattestedBroken, singleSubjectSet)
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
	recordEnvCarryingRegistrations(audited, pkgStrUnsafe, p, fc, idx, callIdx, initOnly, unattestedBroken, singleSubjectSet, settledGlobals, &pkgConf, seamAnalysis.Exempt, envCarrying, envCarryingFns, envCarryingUnattr, envCallableVars, envCalls, envParamCalls, envMethodCalls, regCarrierLinks, fieldDefer, fieldPoison, baseHooks)
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
		envFree, envDeps, retParamDeps, retMethodDeps, retFieldDefer, retFieldPoison, insFree, insDeps, insParamDeps, insMethodDeps, callerInsDeps := returnEnvFreeFunctions(audited, pkgStrUnsafe, p, fc, settledGlobals, &pkgConf, baseHooks)
		pkgPath := p.Types.Path()
		for fnName := range envFree {
			fnKey := syntaxutil.FuncKey{Pkg: pkgPath, Name: fnName}
			fact.ReturnEnvFree = append(fact.ReturnEnvFree, fnKey)
			for callee := range envDeps[fnName] {
				fact.ReturnEnvDeps = append(fact.ReturnEnvDeps, syntaxutil.FuncDepEdge{Func: fnKey, Callee: callee})
			}
			for pk := range retParamDeps[fnName] {
				fact.ReturnEnvParamDeps = append(fact.ReturnEnvParamDeps, syntaxutil.FuncParamDepEdge{Func: fnKey, Param: pk})
			}
			for mk := range retMethodDeps[fnName] {
				fact.ReturnEnvMethodDeps = append(fact.ReturnEnvMethodDeps, syntaxutil.FuncDepEdge{Func: fnKey, Callee: mk})
			}
			for dep := range callerInsDeps[fnName] {
				fact.ReturnEnvInsertionDeps = append(fact.ReturnEnvInsertionDeps, syntaxutil.FuncInsertionDepEdge{Func: fnKey, Dep: dep})
			}
			for entry := range retFieldDefer[fnName] {
				fact.ReturnFieldParamDefer = append(fact.ReturnFieldParamDefer, entry)
			}
			for entry := range retFieldPoison[fnName] {
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
		for ownKey := range insFree {
			fact.ParamInsertionFree = append(fact.ParamInsertionFree, ownKey)
			for dep := range insDeps[ownKey] {
				fact.ParamInsertionDeps = append(fact.ParamInsertionDeps, syntaxutil.ParamInsertionDepEdge{Param: ownKey, Dep: dep})
			}
			for pk := range insParamDeps[ownKey] {
				fact.ParamInsertionParamDeps = append(fact.ParamInsertionParamDeps, syntaxutil.ParamDepEdge{Own: ownKey, Dep: pk})
			}
			for mk := range insMethodDeps[ownKey] {
				fact.ParamInsertionMethodDeps = append(fact.ParamInsertionMethodDeps, syntaxutil.ParamMethodDepEdge{Param: ownKey, Method: mk})
			}
		}
		slices.SortFunc(fact.ParamInsertionFree, syntaxutil.ParamKey.Compare)
		slices.SortFunc(fact.ParamInsertionDeps, syntaxutil.ParamInsertionDepEdge.Compare)
		slices.SortFunc(fact.ParamInsertionParamDeps, syntaxutil.ParamDepEdge.Compare)
		slices.SortFunc(fact.ParamInsertionMethodDeps, syntaxutil.ParamMethodDepEdge.Compare)

		if !pkgStrUnsafe {
			var strHooks *syntaxutil.ExplainHookSet
			if hooks != nil && hooks.IncludeStringUnsafeSites {
				strHooks = hooks
			}
			strSettled := settledPackageDataGlobals(audited, true, p, fc, pkgConf.paramLeakFree, pkgConf.readOnly, unattestedBroken, singleSubjectSet)
			strEnvCarrying := map[string]bool{}
			strEnvCarryingFns := map[string]map[syntaxutil.FuncKey]bool{}
			strEnvCarryingUnattr := map[string]bool{}
			strEnvCallable := map[string]bool{}
			strEnvCalls := map[syntaxutil.EnvCallUse]bool{}
			strEnvParamCalls := map[syntaxutil.EnvCallParamUse]bool{}
			strEnvMethodCalls := map[syntaxutil.EnvCallMethodUse]bool{}
			strRegLinks := map[syntaxutil.CarrierLink]bool{}
			strFieldDefer := map[syntaxutil.FieldPosKey]map[syntaxutil.ParamKey]bool{}
			strFieldPoison := map[string]map[syntaxutil.FieldParamPoison]bool{}
			recordEnvCarryingRegistrations(audited, true, p, fc, idx, callIdx, initOnly, unattestedBroken, singleSubjectSet, strSettled, &pkgConf, seamAnalysis.Exempt, strEnvCarrying, strEnvCarryingFns, strEnvCarryingUnattr, strEnvCallable, strEnvCalls, strEnvParamCalls, strEnvMethodCalls, strRegLinks, strFieldDefer, strFieldPoison, strHooks)
			for key := range strEnvCarrying {
				fact.StringEnvCarrying = append(fact.StringEnvCarrying, key)
			}
			sort.Strings(fact.StringEnvCarrying)
			for key := range strEnvCallable {
				if !envCallableVars[key] {
					fact.StringEnvCallable = append(fact.StringEnvCallable, key)
				}
			}
			sort.Strings(fact.StringEnvCallable)
			for key, fns := range strEnvCarryingFns {
				if strEnvCarryingUnattr[key] || strEnvCallable[key] || envCallableVars[key] {
					continue
				}
				for fn := range fns {
					fact.StringEnvCarryingFns = append(fact.StringEnvCarryingFns, syntaxutil.VarFuncUse{Key: key, Func: fn})
				}
			}
			slices.SortFunc(fact.StringEnvCarryingFns, syntaxutil.VarFuncUse.Compare)
			for use := range strEnvCalls {
				if envCalls[use] {
					continue
				}
				unattr := syntaxutil.EnvCallUse{Key: use.Key, Callee: use.Callee}
				if !use.Func.IsZero() && (envCalls[unattr] || strEnvCalls[unattr]) {
					continue
				}
				fact.StringEnvCallUses = append(fact.StringEnvCallUses, use)
			}
			slices.SortFunc(fact.StringEnvCallUses, syntaxutil.EnvCallUse.Compare)
			for use := range strEnvParamCalls {
				if envParamCalls[use] {
					continue
				}
				unattr := syntaxutil.EnvCallParamUse{Key: use.Key, Param: use.Param}
				if !use.Func.IsZero() && (envParamCalls[unattr] || strEnvParamCalls[unattr]) {
					continue
				}
				fact.StringEnvCallParamUses = append(fact.StringEnvCallParamUses, use)
			}
			slices.SortFunc(fact.StringEnvCallParamUses, syntaxutil.EnvCallParamUse.Compare)
			for use := range strEnvMethodCalls {
				if envMethodCalls[use] {
					continue
				}
				unattr := syntaxutil.EnvCallMethodUse{Key: use.Key, Method: use.Method}
				if !use.Func.IsZero() && (envMethodCalls[unattr] || strEnvMethodCalls[unattr]) {
					continue
				}
				fact.StringEnvCallMethodUses = append(fact.StringEnvCallMethodUses, use)
			}
			slices.SortFunc(fact.StringEnvCallMethodUses, syntaxutil.EnvCallMethodUse.Compare)
			for link := range strRegLinks {
				if !regCarrierLinks[link] && !carrierLinks[link.From][link.To] {
					fact.StringCarrierLinks = append(fact.StringCarrierLinks, link)
				}
			}
			slices.SortFunc(fact.StringCarrierLinks, syntaxutil.CarrierLink.Compare)

			strEnvFree, strEnvDeps, strRetParamDeps, strRetMethodDeps, strRetFieldDefer, strRetFieldPoison, strInsFree, strInsDeps, strInsParamDeps, strInsMethodDeps, strCallerInsDeps := returnEnvFreeFunctions(audited, true, p, fc, strSettled, &pkgConf, strHooks)
			for fnName := range envFree {
				fnKey := syntaxutil.FuncKey{Pkg: pkgPath, Name: fnName}
				if !strEnvFree[fnName] ||
					!boolMapSubset(strRetFieldDefer[fnName], retFieldDefer[fnName]) ||
					!boolMapSubset(strRetFieldPoison[fnName], retFieldPoison[fnName]) {
					fact.StringReturnEnvBlocked = append(fact.StringReturnEnvBlocked, fnKey)
					continue
				}
				for callee := range strEnvDeps[fnName] {
					if !envDeps[fnName][callee] {
						fact.StringReturnEnvDeps = append(fact.StringReturnEnvDeps, syntaxutil.FuncDepEdge{Func: fnKey, Callee: callee})
					}
				}
				for pk := range strRetParamDeps[fnName] {
					if !retParamDeps[fnName][pk] {
						fact.StringReturnEnvParamDeps = append(fact.StringReturnEnvParamDeps, syntaxutil.FuncParamDepEdge{Func: fnKey, Param: pk})
					}
				}
				for mk := range strRetMethodDeps[fnName] {
					if !retMethodDeps[fnName][mk] {
						fact.StringReturnEnvMethodDeps = append(fact.StringReturnEnvMethodDeps, syntaxutil.FuncDepEdge{Func: fnKey, Callee: mk})
					}
				}
				for dep := range strCallerInsDeps[fnName] {
					if !callerInsDeps[fnName][dep] {
						fact.StringReturnEnvInsertionDeps = append(fact.StringReturnEnvInsertionDeps, syntaxutil.FuncInsertionDepEdge{Func: fnKey, Dep: dep})
					}
				}
			}
			slices.SortFunc(fact.StringReturnEnvBlocked, syntaxutil.FuncKey.Compare)
			slices.SortFunc(fact.StringReturnEnvDeps, syntaxutil.FuncDepEdge.Compare)
			slices.SortFunc(fact.StringReturnEnvParamDeps, syntaxutil.FuncParamDepEdge.Compare)
			slices.SortFunc(fact.StringReturnEnvMethodDeps, syntaxutil.FuncDepEdge.Compare)
			slices.SortFunc(fact.StringReturnEnvInsertionDeps, syntaxutil.FuncInsertionDepEdge.Compare)
			for ownKey := range insFree {
				if !strInsFree[ownKey] {
					fact.StringParamInsertionBlocked = append(fact.StringParamInsertionBlocked, ownKey)
					continue
				}
				for dep := range strInsDeps[ownKey] {
					if !insDeps[ownKey][dep] {
						fact.StringParamInsertionDeps = append(fact.StringParamInsertionDeps, syntaxutil.ParamInsertionDepEdge{Param: ownKey, Dep: dep})
					}
				}
				for pk := range strInsParamDeps[ownKey] {
					if !insParamDeps[ownKey][pk] {
						fact.StringParamInsertionParamDeps = append(fact.StringParamInsertionParamDeps, syntaxutil.ParamDepEdge{Own: ownKey, Dep: pk})
					}
				}
				for mk := range strInsMethodDeps[ownKey] {
					if !insMethodDeps[ownKey][mk] {
						fact.StringParamInsertionMethodDeps = append(fact.StringParamInsertionMethodDeps, syntaxutil.ParamMethodDepEdge{Param: ownKey, Method: mk})
					}
				}
			}
			slices.SortFunc(fact.StringParamInsertionBlocked, syntaxutil.ParamKey.Compare)
			slices.SortFunc(fact.StringParamInsertionDeps, syntaxutil.ParamInsertionDepEdge.Compare)
			slices.SortFunc(fact.StringParamInsertionParamDeps, syntaxutil.ParamDepEdge.Compare)
			slices.SortFunc(fact.StringParamInsertionMethodDeps, syntaxutil.ParamMethodDepEdge.Compare)
		}
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
		fact.DirectVarWrites = protoaudit.CollectDirectCrossPkgVarWrites(audited, p, idx)
		fact.NonMethodVarUses = protoaudit.CollectNonMethodCrossPkgVarUses(audited, p, idx)
	}
	if p.Types != nil && p.Module != nil {
		if idx != nil {
			fact.MappingDischarges = deriveMappingDischarges(audited, p, idx)
			fact.MemoDischarges = deriveMemoDischarges(audited, p, idx)
			var onceMemoExempt map[ast.Node]bool
			fact.OnceMemoTypes, onceMemoExempt = deriveOnceMemoTypes(audited, p, fc, idx, &pkgConf)
			fact.OnceMemoCandidates = deriveOnceMemoCandidates(audited, p, fc, idx, singleSubjectSet)
			if len(fact.Declares) > 0 && propharness.IsHarnessPath(p.PkgPath) && propharness.VerifyPackage(audited, p) {
				fact.HarnessDischarges = slices.Clone(fact.Declares)
			}
			unattestedMutated := make(map[string]bool, len(mutated)+len(poolMutated))
			for key := range mutated {
				unattestedMutated[key] = true
			}
			for key := range poolMutated {
				unattestedMutated[key] = true
			}
			fact.ProtoClusters, fact.ProtoExtAliases, fact.ProtoRuntimeTypes, fact.GrpcServiceVars, fact.MutatedStructTypes, fact.ConditionalStructMutations =
				protoaudit.DeriveProtoAndStructFacts(audited, p, idx, initOnly, unattestedMutated, onceMemoExempt)
			fact.NonMutatingMethods = protoaudit.DeriveNonMutatingMethods(audited, p, idx)
			fact.NoPostInitCarrierWrites, fact.CarrierImportCalls =
				protoaudit.DeriveNoPostInitCarrierWrites(audited, p, idx, initOnly, fact.DirectVarWrites)
		}
	} else if idx != nil {
		fact.MutatedStructTypes, fact.ConditionalStructMutations = freshstruct.CollectMutatedStructTypes(p, idx, nil, nil, nil, nil, nil)
		fact.NonMutatingMethods = protoaudit.DeriveNonMutatingMethods(audited, p, idx)
		fact.NoPostInitCarrierWrites, fact.CarrierImportCalls =
			protoaudit.DeriveNoPostInitCarrierWrites(audited, p, idx, initOnly, fact.DirectVarWrites)
	}
	if tracing {
		for _, v := range fact.Mutates {
			trace.Emit(nil, trace.DomainDynstate, "dynstate.var.reject", p.PkgPath,
				trace.String("var", v),
				trace.String("kind", "mutates"),
			)
		}
		for _, v := range fact.Escapes {
			trace.Emit(nil, trace.DomainDynstate, "dynstate.var.reject", p.PkgPath,
				trace.String("var", v),
				trace.String("kind", "escapes"),
			)
		}
		trace.Emit(nil, trace.DomainDynstate, "dynstate.factof.done", p.PkgPath,
			trace.Bool("audited", audited),
			trace.Int("declares", len(fact.Declares)),
			trace.Int("mutates", len(fact.Mutates)),
			trace.Int("escapes", len(fact.Escapes)),
			trace.Int64("dur_ns", time.Since(start).Nanoseconds()),
		)
	}
	return fact
}

func boolMapSubset[K comparable](sub, super map[K]bool) bool {
	for k := range sub {
		if !super[k] {
			return false
		}
	}
	return true
}
