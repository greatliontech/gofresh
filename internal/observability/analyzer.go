package observability

import (
	"go/types"
	"strings"
	"time"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/trace"
)

type tier2Result struct {
	effects      []externalEffect
	widen        bool
	widenReason  string
	unverifiable bool
	reason       string
}

func tier2Reachable(h *Hasher, base *tier2Base, reachable attributedReachability) (tier2Result, error) {
	res, _, err := tier2ReachableWithObjects(h, base, reachable)
	return res, err
}

func tier2ReachableWithObjects(h *Hasher, base *tier2Base, reachable attributedReachability) (tier2Result, map[types.Object]bool, error) {
	subj := ""
	if reachable.subjectRoot != nil {
		subj = reachable.subjectRoot.String()
	}
	var start time.Time
	ctx := h.Context()
	tracing := trace.Enabled(ctx, trace.DomainClosure, subj)
	if tracing {
		start = time.Now()
	}
	a := base.analyzer()
	a.rtaResolved = reachable.resolved
	a.skipOriginScan = reachable.instantiatedOrigins
	a.openWorld = reachable.openWorld
	a.fresh = newFreshParamAnalysis(h.SelectionAudited(), h.PureDelegates(), reachable, a.isStdFunction)
	a.fresh.traceCtx = ctx
	a.enumeratedTypes = reachable.enumeratedTypes
	a.initBoxedTypes = reachable.initBoxedTypes
	if reachable.subjectRoot != nil {
		a.subjectRoots = map[*ssa.Function]bool{reachable.subjectRoot: true}
	}
	a.startupOnly = syncStartupOnlyFunctionsForBase(base, reachable)
	a.zeroGlobals = startupZeroGlobalsForReach(base, reachable)
	a.zeroGlobalDecls = zeroGlobalDeclKeys(a.zeroGlobals)
	targetPkgPath := ""
	if a.prog != nil {
		targetPkgPath = a.prog.PkgPath
	}
	for _, extra := range [][]types.Type{reachable.enumeratedTypes, reachable.initBoxedTypes} {
		for _, ct := range extra {
			a.checkMakeInterfaceStdHooks(nil, nil, ct)
		}
	}
	extraSubjectTargets := map[*ssa.Function]bool{}
	for site, targets := range reachable.dynamicTargets {
		if !reachable.functions[site.Parent()] {
			continue
		}
		callerIdx := a.idxForFunction(site.Parent())
		if (callerIdx == nil && !isAnalyzableUnnamedWrapper(site.Parent())) || (callerIdx != nil && callerIdx.testMain) {
			continue
		}
		targets = narrowedTargets(site, targets, a.fresh)
		if len(targets) == 0 {
			continue
		}
		if a.rtaResolved[site] && !a.openWorld && len(targets) != 0 {
			admitted := true
			for target := range targets {
				if harnessInvokeAdmitted(h.SelectionAudited(), target) {
					continue
				}
				idx := a.idxForFunction(target)
				if (idx == nil && !isAnalyzableUnnamedWrapper(target)) || (idx != nil && idx.testMain) {
					admitted = false
					break
				}
			}
			if admitted {
				a.subjectDeterminedInvokes[site] = true
				for target := range targets {
					if !reachable.functions[target] && !harnessInvokeAdmitted(h.SelectionAudited(), target) {
						extraSubjectTargets[target] = true
					}
				}
			}
		}
		callerStd := callerIdx != nil && callerIdx.std
		for target := range targets {
			if observableDirEntryCall(site) {
				continue
			}
			idx := a.idxForFunction(target)
			if idx == nil {
				continue
			}
			if vp := a.verifiedHarness(idx.path); vp != nil {
				var ok bool
				if target.Parent() == nil {
					ok = a.admitPropertyHarnessInvokeTarget(reachable, site, target)
				} else {
					ok = a.admitPropertyHarnessAnonTarget(site, target, vp)
				}
				if !ok {
					a.requestWiden("property harness reached as a dynamic target in " + site.Parent().String())
				}
				continue
			}
			if !idx.std {
				if len(target.Blocks) == 0 && idx.meta != nil && len(idx.meta.SFiles) > 0 {
					if effect, asmClassified := a.classifyVerifiedAsmCallee(target, idx, site.Common(), site); asmClassified {
						a.recordExternalEffect(effect)
					}
				}
				continue
			}
			effect, ok := classBEffectForFunction(target)
			if !ok {
				if harnessEffect, harnessOK := harnessCalleeEffect(h.SelectionAudited(), target, true); harnessOK {
					a.recordExternalEffect(harnessEffect)
					continue
				}
			}
			forceCheckStdTarget := idx.path == "net/url"
			if !ok && (!callerStd || forceCheckStdTarget) && !admittedPureStandardOrDelegateCallee(h.SelectionAudited(), h.PureDelegates(), false, h, targetPkgPath, idx.path, target, site, callerStd && !forceCheckStdTarget, a.fresh) {
				if tracing {
					callerName := ""
					if site != nil && site.Parent() != nil {
						callerName = site.Parent().String()
					}
					trace.Emit(ctx, trace.DomainClosure, "closure.rta_std.reject", subj,
						trace.String("caller", callerName),
						trace.String("callee", target.String()),
						trace.String("reason", "unaudited_rta_target"),
					)
				}
				effect = unauditedStandardEffect(idx.path, functionSymbolName(target))
				ok = true
			}
			if ok {
				a.recordExternalEffect(effect)
			}
		}
	}
	for fn := range reachable.functions {
		if err := a.contextErr(); err != nil {
			return tier2Result{}, nil, err
		}
		a.rtaReach[fn] = true
	}
	for fn := range reachable.functions {
		if err := a.contextErr(); err != nil {
			return tier2Result{}, nil, err
		}
		a.addFunction(fn)
		if idx := a.idxForFunction(fn); idx != nil && idx.std {
			continue
		}
		a.scanFunction(fn)
		if err := a.contextErr(); err != nil {
			return tier2Result{}, nil, err
		}
	}
	for fn := range extraSubjectTargets {
		a.rtaReach[fn] = true
		if err := a.contextErr(); err != nil {
			return tier2Result{}, nil, err
		}
		a.addFunction(fn)
		if idx := a.idxForFunction(fn); idx != nil && idx.std {
			continue
		}
		a.scanFunction(fn)
		if err := a.contextErr(); err != nil {
			return tier2Result{}, nil, err
		}
	}
	if err := a.drainObjects(); err != nil {
		return tier2Result{}, nil, err
	}
	for {
		if err := a.contextErr(); err != nil {
			return tier2Result{}, nil, err
		}
		pkgCount := len(a.filePkgs)
		if err := a.addReachedPackageFiles(); err != nil {
			return tier2Result{}, nil, err
		}
		if err := a.drainObjects(); err != nil {
			return tier2Result{}, nil, err
		}
		if len(a.filePkgs) == pkgCount {
			break
		}
	}
	res := a.result()
	if tracing {
		trace.Emit(ctx, trace.DomainClosure, "tier2.subject.done", subj,
			trace.Int("functions", len(reachable.functions)),
			trace.Int("objects", len(a.seenObjects)),
			trace.Int("effects", len(res.effects)),
			trace.Bool("widen", res.widen),
			trace.String("widen_reason", res.widenReason),
			trace.String("reason", res.reason),
			trace.Int64("elapsed_ns", time.Since(start).Nanoseconds()),
		)
	}
	return res, a.seenObjects, nil
}

func (a *tier2Analyzer) addFunction(fn *ssa.Function) {
	if fn == nil {
		return
	}
	if origin := fn.Origin(); origin != nil {
		fn = origin
	}
	idx := a.idxForFunction(fn)
	if idx == nil || idx.std || idx.testMain {
		return
	}
	if fn.Synthetic == "package initializer" || (fn.Name() == "init" && fn.Object() == nil) {
		a.addStartupPackage(idx)
		return
	}
	if obj := fn.Object(); obj != nil {
		if obj.Pkg() != nil {
			a.enqueueObject(obj)
			return
		}
		if fn.Signature != nil {
			if recv := fn.Signature.Recv(); recv != nil {
				a.addType(recv.Type())
			} else if strings.HasPrefix(fn.Synthetic, "thunk for ") && fn.Signature.Params().Len() > 0 {
				a.addType(fn.Signature.Params().At(0).Type())
			}
		}
		return
	}
	if parent := fn.Parent(); parent != nil {
		if a.rtaReach[parent] || initFlowFrame(parent) {
			a.addFunction(parent)
		} else if idx.cache {
			if fn.Syntax() != nil {
				a.markPackage(idx)
				a.scanNodeRefs(idx, fn.Syntax(), a.startupOnly[fn])
			} else {
				a.addFunction(parent)
			}
		}
		a.scanFunction(fn)
	}
}

func (a *tier2Analyzer) addStartupPackage(idx *pkgIndex) {
	if idx == nil || !idx.mutable {
		return
	}
	a.markPackage(idx)
	for _, n := range idx.vars {
		a.scanNodeRefs(idx, n, true)
	}
	for _, n := range idx.inits {
		a.scanNodeRefs(idx, n, true)
	}
}

func (a *tier2Analyzer) scanFunction(fn *ssa.Function) {
	if fn == nil || a.skipOriginScan[fn] {
		return
	}
	idx := a.idxForFunction(fn)
	if (idx == nil && !isAnalyzableUnnamedWrapper(fn)) || (idx != nil && idx.testMain) {
		return
	}
	if idx != nil && a.propertyHarnessAudited(idx.path) {
		return
	}
	isStd := idx != nil && idx.std
	if len(fn.Blocks) == 0 {
		a.scanBodylessNonStdFunction(fn, idx, a.subjectRoots[fn])
		return
	}
	if idx != nil && !idx.std {
		a.markFilePackage(idx)
		if obj := fn.Object(); obj != nil {
			if target := a.linknameTarget(idx, obj); target != "" {
				if !(a.base != nil && a.base.isVerifiedReadOnlyLinknameVar(idx, obj, target)) {
					a.addLinknameTarget(target)
				}
			}
		}
	}
	if a.scanned[fn] {
		return
	}
	a.scanned[fn] = true
	classified, classifiedOK := classBEffectForFunction(fn)
	suppressNestedFileIO := isStd && classifiedOK && classified.Kind == externalEffectFileIO
	if idx != nil && !idx.std && idx.wasmImport {
		effect := opaqueExternalEffect(externalEffectLinkage, "reaches go:wasmimport")
		effect.Unrefinable = true
		a.recordExternalEffect(effect)
	}
	if idx != nil && idx.cache && hasExternalCgoMeta(idx.meta) {
		effect := opaqueExternalEffect(externalEffectNative, "reaches cgo external library")
		effect.Unrefinable = true
		a.recordExternalEffect(effect)
	}
	if idx != nil && idx.cache {
		a.scanCacheFunctionRefs(idx, fn)
	}
	if isStd && stdBodyCut(a.h.SelectionAudited(), fn, classified, classifiedOK) {
		return
	}
	var fnZeroGlobals map[*ssa.Global]bool
	if a.startupOnly[fn] {
		fnZeroGlobals = a.zeroGlobals
	}
	var ops [16]*ssa.Value
	for _, block := range liveBlocks(fn, fnZeroGlobals) {
		if a.contextErr() != nil {
			return
		}
		for _, instr := range block.Instrs {
			if v, ok := instr.(ssa.Value); ok {
				a.addValueType(idx, v)
			}
			for _, op := range instr.Operands(ops[:0]) {
				if op == nil || *op == nil {
					continue
				}
				a.scanValue(idx, *op)
			}
			fromRTA := a.rtaReach[fn]
			if isStd {
				fromRTA = false
			}
			a.scanInstruction(idx, fn, instr, fromRTA, suppressNestedFileIO)
		}
	}
}

func atomicObservabilityOperation(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	pkgPath, name := funcPkgPath(fn), functionSymbolName(fn)
	if pkgPath == "testing" && name == "TempDir" || pkgPath == "path/filepath" && name == "Join" {
		return true
	}
	if pkgPath == "os" {
		switch name {
		case "WriteFile", "Remove", "RemoveAll":
			return true
		}
	}
	return false
}

func (a *tier2Analyzer) scanCacheFunctionRefs(idx *pkgIndex, fn *ssa.Function) {
	if idx == nil || fn == nil {
		return
	}
	startupOnly := a.startupOnly[fn]
	if origin := fn.Origin(); origin != nil {
		fn = origin
	}
	obj := fn.Object()
	if obj == nil {
		if fn.Synthetic == "package initializer" || fn.Name() == "init" {
			for _, n := range idx.vars {
				a.scanNodeRefs(idx, n, startupOnly)
			}
			for _, n := range idx.inits {
				a.scanNodeRefs(idx, n, startupOnly)
			}
		}
		return
	}
	if obj.Pkg() == nil && fn.Synthetic != "" {
		if fn.Signature != nil {
			if recv := fn.Signature.Recv(); recv != nil {
				a.addType(recv.Type())
			} else if strings.HasPrefix(fn.Synthetic, "thunk for ") && fn.Signature.Params().Len() > 0 {
				a.addType(fn.Signature.Params().At(0).Type())
			}
		}
		return
	}
	obj = originObject(obj)
	node := idx.decls[obj]
	if node == nil {
		a.requestWiden("missing cache function declaration for " + obj.String())
		return
	}
	a.scanNodeRefs(idx, node, startupOnly)
}

func (a *tier2Analyzer) scanValue(callerIdx *pkgIndex, v ssa.Value) {
	if v == nil {
		return
	}
	a.addValueType(nil, v)
	switch x := v.(type) {
	case *ssa.Global:
		if obj := x.Object(); obj != nil {
			objStd := false
			if obj.Pkg() != nil {
				if objIdx := a.idxByTypes[obj.Pkg()]; objIdx != nil {
					objStd = objIdx.std
				} else {
					objStd = isStdImportPath(obj.Pkg().Path())
				}
			}
			if !(callerIdx != nil && callerIdx.std) && objStd {
				if !(a.h.SelectionAudited() && isUnmutatedStandardSentinelGlobalAny(a.prog, x)) {
					a.recordExternalEffect(symbolExternalEffect(externalEffectUnauditedStandard, obj.Pkg().Path(), obj.Name(), "reaches standard global "+obj.Pkg().Path()+"."+obj.Name()))
				}
			}
			a.enqueueObject(obj)
		}
	case *ssa.Function:
		if !(callerIdx != nil && callerIdx.std) && funcPkgPath(x) == "go/ast" && baseFunctionSymbolName(x) == "String" && !auditedStandardMethod(a.h.SelectionAudited(), x) {
			a.recordExternalEffect(unauditedStandardEffect("go/ast", "String"))
		}
		a.addFunction(x)
	}
}

func isOSFileType(t types.Type) bool {
	if pointer, ok := types.Unalias(t).(*types.Pointer); ok {
		t = pointer.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "os" && named.Obj().Name() == "File"
}

func (a *tier2Analyzer) scanInstruction(idx *pkgIndex, caller *ssa.Function, instr ssa.Instruction, fromRTA, suppressNestedFileIO bool) {
	var fnZeroGlobals map[*ssa.Global]bool
	if a.startupOnly[caller] {
		fnZeroGlobals = a.zeroGlobals
	}
	callerStd := idx != nil && idx.std
	recordFlagBackedReferences(a.flagBacked, fnZeroGlobals, a.recordExternalEffect, instr)
	a.checkInstructionStdHooks(caller, callerStd, instr)
	switch x := instr.(type) {
	case ssa.CallInstruction:
		a.scanCall(idx, caller, x, fromRTA, suppressNestedFileIO)
	case *ssa.MakeInterface:
		a.addInterfaceMethodSet(x.X.Type())
	case *ssa.Field:
		if effect, ok := testingRuntimeFieldEffect(x.X.Type(), x.Field); ok {
			a.recordExternalEffect(effect)
		}
	case *ssa.FieldAddr:
		if effect, ok := testingRuntimeFieldEffect(x.X.Type(), x.Field); ok {
			a.recordExternalEffect(effect)
		}
	}
}

func testingRuntimeFieldEffect(t types.Type, index int) (externalEffect, bool) {
	if pointer, ok := types.Unalias(t).(*types.Pointer); ok {
		t = pointer.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "testing" || named.Obj().Name() != "B" {
		return externalEffect{}, false
	}
	structure, ok := named.Underlying().(*types.Struct)
	if !ok || index < 0 || index >= structure.NumFields() {
		return externalEffect{}, false
	}
	if name := structure.Field(index).Name(); name == "N" {
		return harnessPacingEffect("B.N"), true
	}
	return externalEffect{}, false
}

func (a *tier2Analyzer) scanCall(callerIdx *pkgIndex, caller *ssa.Function, site ssa.CallInstruction, fromRTA, suppressNestedFileIO bool) {
	c := site.Common()
	if c == nil {
		return
	}
	callerStd := callerIdx != nil && callerIdx.std
	if c.IsInvoke() && observableDirEntryCall(site) {
		return
	}
	if !callerStd {
		if c.IsInvoke() {
			if !a.dispatchAdmitted(site, fromRTA) {
				a.requestWiden("interface invoke outside RTA: " + invokeEdgeName(c, caller))
			}
		} else if c.StaticCallee() == nil {
			if _, ok := c.Value.(*ssa.Builtin); !ok && !a.dispatchAdmitted(site, fromRTA) {
				a.requestWiden("computed function call in " + caller.String() + computedEdgeSuffix(c))
			}
		}
	}
	callee := c.StaticCallee()
	if callee == nil {
		return
	}
	pkgPath, name := funcPkgPath(callee), functionSymbolName(callee)
	if !callerStd && syntheticInterfaceMethodWrapper(callee) && !dispatchProvenanceClosed(site, a.fresh) {
		a.requestWiden("interface dispatch on unattributable state in " + caller.String())
		return
	}
	if harnessEffect, ok := harnessCalleeEffect(a.h.SelectionAudited(), callee, false); ok {
		a.recordExternalEffect(harnessEffect)
		return
	}
	if !callerStd {
		if vp := a.verifiedHarness(pkgPath); vp != nil {
			if mk, isSample := propertyHarnessSeededSampleCallee(vp, callee); isSample && !harnessSeededSampleHasExplicitSeed(c) {
				a.recordExternalEffect(propertyHarnessUnseededSampleEffect(vp, mk))
			}
			if !propertyHarnessClosedArgs(c, a.fresh) {
				a.requestWiden("property-harness argument is not locally closed in " + caller.String())
			}
			if mc, ok := c.Value.(*ssa.MakeClosure); ok {
				for _, b := range mc.Bindings {
					if b != nil {
						a.addHarnessArgMethodSets(b.Type())
					}
				}
			}
			for _, arg := range c.Args {
				if arg != nil {
					a.addHarnessArgMethodSets(arg.Type())
				}
			}
			for _, ta := range callee.TypeArgs() {
				a.addHarnessArgMethodSets(ta)
			}
			return
		}
	}
	if observableFileMethod(callee) {
		if len(c.Args) != 0 && fileValueFromAdmittedOpen(c.Args[0], make(map[ssa.Value]bool), a.fresh) {
			return
		}
		a.recordExternalEffect(symbolExternalEffect(externalEffectFileIO, "os", "File."+name, "reaches os.File."+name+" on an unattributed file handle (file I/O)"))
		return
	}
	effect, classified := a.classifyCalleeEffect(callee, pkgPath, name, c, site, callerStd)
	if classified {
		effect.Observable = observableCallEffect(a.h.SelectionAudited(), effect, c, site, a.fresh)
		if callerStd && (effect.Kind == externalEffectFilesystemMutation || effect.Kind == externalEffectPathMutation) {
			return
		}
		if callerIdx != nil && (callerIdx.path == "flag" || callerIdx.path == "go/ast" || callerIdx.path == "go/scanner") && effect.Kind == externalEffectFormattedOutput {
			return
		}
		if !(suppressNestedFileIO && effect.Kind == externalEffectFileIO) {
			a.recordExternalEffect(effect)
		}
	}
	calleeStd := a.isStdFunction(callee)
	if !fromRTA || (!callerStd && calleeStd && !isBenchmarkHarnessPath(pkgPath)) {
		a.scanFunction(callee)
	}
	if !callerStd && pkgPath == "reflect" && (name == "Call" || name == "CallSlice" || name == "MakeFunc" || name == "MethodByName") {
		a.requestWiden("reflect dispatch")
	}
}

func (a *tier2Analyzer) classifyCalleeEffect(callee *ssa.Function, pkgPath, name string, c *ssa.CallCommon, site ssa.CallInstruction, callerStd bool) (externalEffect, bool) {
	audited := a.h.SelectionAudited()
	if timeUnixCallChainedToUTCOrFixedZone(audited, callee, pkgPath, name, c, site) {
		return externalEffect{}, false
	}
	targetPkgPath := ""
	if a.prog != nil {
		targetPkgPath = a.prog.PkgPath
	}
	if admittedGatedStandardSymbol(audited, !callerStd, a.h, targetPkgPath, callee, pkgPath, name, c, site, a.fresh) {
		return externalEffect{}, false
	}
	effect, classified := classBEffect(pkgPath, name)
	calleeIdx := a.idxForFunction(callee)
	if !classified && calleeIdx != nil && !calleeIdx.std && len(callee.Blocks) == 0 && calleeIdx.meta != nil && len(calleeIdx.meta.SFiles) > 0 {
		effect, classified = a.classifyVerifiedAsmCallee(callee, calleeIdx, c, site)
	}
	if !classified && c.StaticCallee() == callee && flagProvenSetUse(a.flagProven, pkgPath, name, c) {
		return externalEffect{}, false
	}
	if !classified && name != "init" && !callerStd && calleeIdx != nil && calleeIdx.std && !isStandardFallbackExempt(audited, pkgPath) &&
		!admittedPureStandardOrDelegateCallee(audited, a.h.PureDelegates(), false, a.h, targetPkgPath, pkgPath, callee, site, callerStd, a.fresh) {
		effect = unauditedStandardEffect(pkgPath, name)
		classified = true
	}
	if osOpenFileMayMutate(callee, pkgPath, name, c) {
		effect = symbolExternalEffect(externalEffectFilesystemMutation, pkgPath, name, "reaches os.OpenFile (filesystem mutation)")
		classified = true
	}
	if !classified && syscallOpenMayCreate(pkgPath, name, c) {
		effect = symbolExternalEffect(externalEffectFilesystemMutation, pkgPath, name, "reaches "+pkgPath+"."+name+" (filesystem mutation)")
		classified = true
	}
	return effect, classified
}

func timeUnixCallChainedToUTCOrFixedZone(audited bool, callee *ssa.Function, pkgPath, name string, c *ssa.CallCommon, site ssa.CallInstruction) bool {
	if !audited || pkgPath != "time" || (name != "Unix" && name != "UnixMilli" && name != "UnixMicro") {
		return false
	}
	if c == nil || c.StaticCallee() != callee {
		return false
	}
	callVal, ok := site.(*ssa.Call)
	if !ok || callVal.Referrers() == nil {
		return false
	}
	sawConsumer := false
	for _, ref := range *callVal.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
			continue
		case *ssa.Call:
			rc := r.Common()
			if rc == nil || rc.IsInvoke() || rc.Value == callVal || len(rc.Args) == 0 || rc.Args[0] != callVal {
				return false
			}
			for _, arg := range rc.Args[1:] {
				if arg == callVal {
					return false
				}
			}
			rCallee := rc.StaticCallee()
			if rCallee == nil || funcPkgPath(rCallee) != "time" {
				return false
			}
			switch rCallee.Name() {
			case "UTC":
				if len(rc.Args) != 1 {
					return false
				}
				sawConsumer = true
			case "In":
				if len(rc.Args) != 2 || !locFromFixedZone(audited, rc.Args[1], make(map[ssa.Value]bool)) {
					return false
				}
				sawConsumer = true
			default:
				return false
			}
		default:
			return false
		}
	}
	return sawConsumer
}

func locFromFixedZone(audited bool, v ssa.Value, seen map[ssa.Value]bool) bool {
	if !audited || v == nil || seen[v] {
		return false
	}
	seen[v] = true
	switch val := v.(type) {
	case *ssa.Call:
		callee := val.Call.StaticCallee()
		return callee != nil && funcPkgPath(callee) == "time" && functionSymbolName(callee) == "FixedZone"
	case *ssa.Phi:
		if len(val.Edges) == 0 {
			return false
		}
		for _, edge := range val.Edges {
			if !locFromFixedZone(audited, edge, seen) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func (a *tier2Analyzer) dispatchAdmitted(site ssa.CallInstruction, fromRTA bool) bool {
	if a.openWorld {
		return false
	}
	c := site.Common()
	if c == nil {
		return false
	}
	siteFP := contextCancelMethodFP(site, a.fresh)
	if !subjectClosedDynamicValue(c.Value, make(map[ssa.Value]bool), siteFP) {
		return c.IsInvoke() && a.closedGoASTNodeTargets(site, fromRTA)
	}
	if fromRTA && a.subjectDeterminedInvokes[site] {
		return true
	}
	var held map[*ssa.Function]bool
	var ok bool
	if c.IsInvoke() {
		held, ok = closedInvokeTargets(site, siteFP)
	} else if c.StaticCallee() == nil {
		held, ok = closedDynamicTargets(c.Value, siteFP)
	}
	if ok {
		targetPkgPath := ""
		if a.prog != nil {
			targetPkgPath = a.prog.PkgPath
		}
		for fn := range held {
			idx := a.idxForFunction(fn)
			if idx == nil {
				if !isAnalyzableUnnamedWrapper(fn) {
					return false
				}
				continue
			}
			if idx.testMain || a.propertyHarnessAudited(idx.path) {
				return false
			}
			if idx.std {
				if (!fromRTA && ((!c.IsInvoke() && fn.Parent() == nil) || !a.h.SelectionAudited())) || observableFileMethod(fn) {
					return false
				}
				callerStd := site != nil && site.Parent() != nil && a.isStdFunction(site.Parent())
				forceCheckStdTarget := idx.path == "go/ast" || idx.path == "net/url"
				if (!callerStd || forceCheckStdTarget) && !admittedResolvedStandardOrDelegateCallee(a.h.SelectionAudited(), a.h.PureDelegates(), a.h, targetPkgPath, idx.path, fn, c.IsInvoke(), siteFP) {
					return false
				}
				if _, classB := classBEffectForFunction(fn); classB {
					return false
				}
				if _, harnessOK := harnessCalleeEffect(a.h.SelectionAudited(), fn, true); harnessOK {
					return false
				}
			} else if len(fn.Blocks) == 0 {
				if idx.meta == nil || len(idx.meta.SFiles) == 0 {
					return false
				}
				if _, _, asmOK := a.verifiedPackageAssemblyFunc(idx.meta, fn); !asmOK {
					return false
				}
			}
		}
		for fn := range held {
			if fromRTA {
				a.rtaReach[fn] = true
			}
			a.addFunction(fn)
			if idx := a.idxForFunction(fn); idx == nil || !idx.std {
				if idx != nil && len(fn.Blocks) == 0 && idx.meta != nil && len(idx.meta.SFiles) > 0 {
					if effect, asmClassified := a.classifyVerifiedAsmCallee(fn, idx, c, site); asmClassified {
						a.recordExternalEffect(effect)
					}
				}
				a.scanFunction(fn)
			}
		}
		return true
	}
	return c.IsInvoke() && a.closedGoASTNodeTargets(site, fromRTA)
}

func stdBodyCut(audited bool, fn *ssa.Function, classified externalEffect, classifiedOK bool) bool {
	if audited && fn != nil && funcPkgPath(fn) == "go/parser" {
		if sym := functionSymbolName(fn); sym == "ParseExpr" || auditset.GoParserSourceFunc(sym) {
			return true
		}
	}
	return classifiedOK && classified.Kind == externalEffectFileIO ||
		atomicObservabilityOperation(fn) || harnessBodyCut(audited, fn)
}

func (a *tier2Analyzer) addInterfaceMethodSet(t types.Type) {
	if t == nil || a.seenIfaceBoxTypes[t] {
		return
	}
	if a.seenIfaceBoxTypes != nil {
		a.seenIfaceBoxTypes[t] = true
	}
	if a.base != nil && a.base.ifaceMethodDone != nil && a.base.ifaceMethodDone[t] {
		for _, fn := range a.base.ifaceMethodObjs[t] {
			a.enqueueObject(fn)
		}
		return
	}
	var funcs []*types.Func
	if a.hasNonStdNamedType(t) {
		for _, mt := range []types.Type{t, types.NewPointer(t)} {
			set := types.NewMethodSet(mt)
			for i := 0; i < set.Len(); i++ {
				if fn, ok := set.At(i).Obj().(*types.Func); ok {
					funcs = append(funcs, fn)
					a.enqueueObject(fn)
				}
			}
		}
	}
	if a.base != nil && a.base.ifaceMethodDone != nil {
		a.base.ifaceMethodDone[t] = true
		if len(funcs) > 0 {
			a.base.ifaceMethodObjs[t] = funcs
		}
	}
}

func (a *tier2Analyzer) hasNonStdNamedType(t types.Type) bool {
	found := false
	walkTypeGraph(t, false, map[types.Type]bool{}, func(t types.Type) bool {
		named, ok := t.(*types.Named)
		if !ok {
			return true
		}
		obj := named.Obj()
		if obj == nil || obj.Pkg() == nil {
			return true
		}
		if idx := a.idxByTypes[obj.Pkg()]; idx != nil {
			if !idx.std && !a.propertyHarnessAudited(idx.path) {
				found = true
				return false
			}
		} else if !isStdImportPath(obj.Pkg().Path()) && !a.propertyHarnessAudited(obj.Pkg().Path()) {
			found = true
			return false
		}
		return true
	})
	return found
}

func (a *tier2Analyzer) drainObjects() error {
	for len(a.objectQueue) > 0 {
		if err := a.contextErr(); err != nil {
			return err
		}
		obj := a.objectQueue[0]
		a.objectQueue = a.objectQueue[1:]
		a.addObject(obj)
	}
	return nil
}

func (a *tier2Analyzer) contextErr() error {
	if a == nil || a.h == nil {
		return nil
	}
	return a.h.ContextErr()
}

func (a *tier2Analyzer) enqueueObject(obj types.Object) {
	if obj == nil || obj.Pkg() == nil || a.seenObjects[obj] {
		return
	}
	a.seenObjects[obj] = true
	a.objectQueue = append(a.objectQueue, obj)
}

func (a *tier2Analyzer) addObject(obj types.Object) {
	if obj == nil || obj.Pkg() == nil {
		return
	}
	idx := a.idxByTypes[obj.Pkg()]
	if idx == nil {
		if !isStdImportPath(obj.Pkg().Path()) {
			a.requestWiden("missing source metadata for " + obj.Pkg().Path())
		}
		return
	}
	a.addReverseLinknameTargets(obj)
	if fn, ok := obj.(*types.Func); ok {
		if ssaFn := a.prog.Prog.FuncValue(fn); ssaFn != nil {
			a.scanFunction(ssaFn)
		}
	}
	if !idx.std {
		if target := a.linknameTarget(idx, obj); target != "" {
			if !(a.base != nil && a.base.isVerifiedReadOnlyLinknameVar(idx, obj, target)) {
				a.addLinknameTarget(target)
			}
		}
	}
	if idx.std || idx.testMain || a.propertyHarnessAudited(idx.path) {
		return
	}
	if !isPackageLevelObject(obj) {
		return
	}
	node := idx.decls[originObject(obj)]
	var ssaFn *ssa.Function
	if fn, ok := obj.(*types.Func); ok && a.prog != nil && a.prog.Prog != nil {
		ssaFn = a.prog.Prog.FuncValue(fn)
	}
	startupOnly := ssaFn != nil && a.startupOnly[ssaFn]
	if idx.cache {
		a.addType(obj.Type())
		if node != nil {
			a.scanNodeRefs(idx, node, startupOnly)
		} else if _, ok := obj.(*types.Func); !ok {
			a.requestWiden("missing declaration for " + obj.String())
		}
		if ssaFn != nil {
			a.scanFunction(ssaFn)
		}
		return
	}
	if node == nil {
		if _, ok := obj.(*types.Func); ok {
			a.addType(obj.Type())
			return
		}
		a.requestWiden("missing declaration for " + obj.String())
		return
	}
	a.markPackage(idx)
	a.addType(obj.Type())
	a.scanNodeRefs(idx, node, startupOnly)
	if ssaFn != nil {
		a.scanFunction(ssaFn)
	}
}
