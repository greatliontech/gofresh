package dynstate

import (
	"go/types"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/seams"
	"github.com/greatliontech/gofresh/internal/dynstate/protoaudit"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"github.com/greatliontech/gofresh/internal/trace"
)

// FactOf derives one package's dynamic-state fact from its syntax and type
// information.
func FactOf(audited bool, p *packages.Package, singleSubject bool) Fact {
	return FactOfWithHooks(audited, p, singleSubject, nil)
}

// FactOfWithHooks derives one package's dynamic-state fact with optional
// explain observation hooks armed.
func FactOfWithHooks(audited bool, p *packages.Package, singleSubject bool, hooks *syntaxutil.ExplainHookSet) Fact {
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
	var poolDischarged map[string]bool
	if singleSubject {
		poolDischarged = map[string]bool{}
	}
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
	recordDynamicGlobalUses(audited, p, idx, callIdx, seamAnalysis.Exempt, mutated, escaped, initOnly, methodUses, paramUses, initParamUses, initMethodUses, fieldUses, elemUses, carrierLinks, &attributedUses, singleSubject, poolDischarged, hooks)
	for key := range poolDischarged {
		fact.PoolDischarges = append(fact.PoolDischarges, key)
	}
	sort.Strings(fact.PoolDischarges)
	funcRefs := map[syntaxutil.FuncKey]map[syntaxutil.RefRegion]bool{}
	recordFunctionReferenceRegions(p, initOnly, funcRefs)
	opaque := map[string]bool{}
	breaks := map[string]bool{}
	opaqueDeps := map[string]map[string]bool{}
	recordOpaqueDynamicVars(p, opaque, breaks, opaqueDeps)
	for own, deps := range opaqueDeps {
		for dep := range deps {
			fact.OpaqueDeps = append(fact.OpaqueDeps, syntaxutil.OpaqueDep{Own: own, Dep: dep})
		}
	}
	slices.SortFunc(fact.OpaqueDeps, syntaxutil.OpaqueDep.Compare)
	envCarrying := map[string]bool{}
	envCalls := map[string]map[syntaxutil.FuncKey]bool{}
	fieldDefer := map[syntaxutil.FieldPosKey]map[syntaxutil.ParamKey]bool{}
	fieldPoison := map[string]map[syntaxutil.FieldParamPoison]bool{}
	recordEnvCarryingRegistrations(audited, p, seamAnalysis.Exempt, envCarrying, envCalls, fieldDefer, fieldPoison, hooks)
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
	ownPrefix := ""
	if p.Types != nil {
		ownPrefix = p.Types.Path() + "."
	}
	for key := range envCarrying {
		callable := true
		if ownPrefix != "" && strings.HasPrefix(key, ownPrefix) {
			if variable, ok := p.Types.Scope().Lookup(strings.TrimPrefix(key, ownPrefix)).(*types.Var); ok {
				if _, isFunc := types.Unalias(variable.Type()).Underlying().(*types.Signature); !isFunc {
					callable = false
				}
			}
		}
		if callable {
			fact.EnvCallable = append(fact.EnvCallable, key)
		}
	}
	sort.Strings(fact.EnvCallable)
	for varKey, callees := range envCalls {
		for callee := range callees {
			fact.EnvCallUses = append(fact.EnvCallUses, syntaxutil.EnvCallUse{Key: varKey, Callee: callee})
		}
	}
	slices.SortFunc(fact.EnvCallUses, syntaxutil.EnvCallUse.Compare)
	fact.AttributedUses = append(fact.AttributedUses, attributedUses...)
	slices.SortFunc(fact.AttributedUses, syntaxutil.AttributedUse.Compare)
	for callee, regions := range funcRefs {
		for region := range regions {
			fact.FuncRefs = append(fact.FuncRefs, syntaxutil.FuncRef{Callee: callee, Region: region})
		}
	}
	slices.SortFunc(fact.FuncRefs, syntaxutil.FuncRef.Compare)
	readOnly := receiverReadOnlyMethods(audited, p, callIdx)
	retentionMethods := receiverRetentionFreeMethods(audited, p, readOnly)
	if p.Types != nil {
		pkgPath := p.Types.Path()
		for method := range readOnly {
			fact.ReceiverReadOnly = append(fact.ReceiverReadOnly, syntaxutil.FuncKey{Pkg: pkgPath, Name: method})
		}
		slices.SortFunc(fact.ReceiverReadOnly, syntaxutil.FuncKey.Compare)
		for method := range retentionMethods {
			fact.ReceiverRetentionFree = append(fact.ReceiverRetentionFree, syntaxutil.FuncKey{Pkg: pkgPath, Name: method})
		}
		slices.SortFunc(fact.ReceiverRetentionFree, syntaxutil.FuncKey.Compare)
	}
	for varKey, methodKeys := range methodUses {
		for methodKey := range methodKeys {
			fact.MethodUses = append(fact.MethodUses, syntaxutil.VarMethodUse{Key: varKey, Method: methodKey})
		}
	}
	slices.SortFunc(fact.MethodUses, syntaxutil.VarMethodUse.Compare)
	if p.Types != nil {
		paramLeakFree, paramDeps, paramRetention, paramRetentionDeps := paramLeakFreeFunctions(audited, p, readOnly, retentionMethods)
		for paramKey := range paramLeakFree {
			fact.ParamLeakFree = append(fact.ParamLeakFree, paramKey)
		}
		slices.SortFunc(fact.ParamLeakFree, syntaxutil.ParamKey.Compare)
		for ownKey, edges := range paramDeps {
			for dep := range edges {
				fact.ParamLeakFreeDeps = append(fact.ParamLeakFreeDeps, syntaxutil.ParamDepEdge{Own: ownKey, Dep: dep})
			}
		}
		slices.SortFunc(fact.ParamLeakFreeDeps, syntaxutil.ParamDepEdge.Compare)
		for paramKey := range paramRetention {
			fact.ParamRetentionFree = append(fact.ParamRetentionFree, paramKey)
		}
		slices.SortFunc(fact.ParamRetentionFree, syntaxutil.ParamKey.Compare)
		for ownKey, edges := range paramRetentionDeps {
			for dep := range edges {
				fact.ParamRetentionFreeDeps = append(fact.ParamRetentionFreeDeps, syntaxutil.ParamDepEdge{Own: ownKey, Dep: dep})
			}
		}
		slices.SortFunc(fact.ParamRetentionFreeDeps, syntaxutil.ParamDepEdge.Compare)
		envFree, envDeps, retFieldDefer, retFieldPoison, insFree, insDeps, callerInsDeps := returnEnvFreeFunctions(audited, p, paramLeakFree, readOnly, hooks)
		pkgPath := p.Types.Path()
		for fnName := range envFree {
			fnKey := syntaxutil.FuncKey{Pkg: pkgPath, Name: fnName}
			fact.ReturnEnvFree = append(fact.ReturnEnvFree, fnKey)
			for callee := range envDeps[fnName] {
				fact.ReturnEnvDeps = append(fact.ReturnEnvDeps, syntaxutil.FuncDepEdge{Func: fnKey, Callee: callee})
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
		slices.SortFunc(fact.ReturnEnvInsertionDeps, syntaxutil.FuncInsertionDepEdge.Compare)
		slices.SortFunc(fact.ReturnFieldParamDefer, syntaxutil.ReturnFieldParamDefer.Compare)
		slices.SortFunc(fact.ReturnFieldParamPoison, syntaxutil.ReturnFieldParamPoison.Compare)
		for ownKey := range insFree {
			fact.ParamInsertionFree = append(fact.ParamInsertionFree, ownKey)
			for dep := range insDeps[ownKey] {
				fact.ParamInsertionDeps = append(fact.ParamInsertionDeps, syntaxutil.ParamInsertionDepEdge{Param: ownKey, Dep: dep})
			}
		}
		slices.SortFunc(fact.ParamInsertionFree, syntaxutil.ParamKey.Compare)
		slices.SortFunc(fact.ParamInsertionDeps, syntaxutil.ParamInsertionDepEdge.Compare)
	}
	for varKey, paramKeys := range paramUses {
		for paramKey := range paramKeys {
			fact.ParamUses = append(fact.ParamUses, syntaxutil.VarParamUse{Key: varKey, Param: paramKey})
		}
	}
	slices.SortFunc(fact.ParamUses, syntaxutil.VarParamUse.Compare)
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
	slices.SortFunc(fact.CarrierLinks, syntaxutil.CarrierLink.Compare)
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
	}
	if p.Types != nil && p.Module != nil {
		if idx != nil {
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
					fact.SingleSubjectVars = append(fact.SingleSubjectVars, syntaxutil.DynamicVarKey(variable))
				}
			}
			sort.Strings(fact.SingleSubjectVars)
			fact.MappingDischarges = deriveMappingDischarges(audited, p, idx)
			fact.MemoDischarges = deriveMemoDischarges(audited, p, idx)
			fact.ProtoClusters, fact.ProtoExtAliases, fact.ProtoRuntimeTypes, fact.GrpcServiceVars, fact.MutatedStructTypes, fact.ConditionalStructMutations =
				protoaudit.DeriveProtoAndStructFacts(audited, p, idx, initOnly, mutated)
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
		trace.Emit(nil, trace.DomainDynstate, "dynstate.factof.done", p.PkgPath,
			trace.Bool("audited", audited),
			trace.Bool("single_subject", singleSubject),
			trace.Int("declares", len(fact.Declares)),
			trace.Int("mutates", len(fact.Mutates)),
			trace.Int("escapes", len(fact.Escapes)),
			trace.Int64("dur_ns", time.Since(start).Nanoseconds()),
		)
	}
	return fact
}
