package closure

import (
	"context"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/closure/internal/propharness"
	"github.com/greatliontech/gofresh/internal/closure/internal/rta"
	"github.com/greatliontech/gofresh/internal/trace"
)

// enumerationClosure is one signature-open subject's whole-view caller
// closure (REQ-closure-analysis): the direct static call sites that are
// its only references, plus the dispatch candidates those sites pass —
// closed function values seeded address-taken, materialized concrete
// types seeded into the runtime-type walk — so everything an enumerable
// caller can hand the subject is analyzed view content.
type enumerationClosure struct {
	sites       []ssa.CallInstruction
	addrTaken   map[*ssa.Function]bool
	types       []types.Type
	fieldStores map[int][]ssa.Value
}

type structFieldKey struct {
	named *types.Named
	field int
}

type dynamicSeedEntry struct {
	types []types.Type
	funcs []*ssa.Function
}

type callerReferenceSummary struct {
	sites                   map[*ssa.Function][]ssa.CallInstruction
	allStaticSites          map[*ssa.Function][]ssa.CallInstruction
	harnessCallbackSites    map[*ssa.Function][]ssa.CallInstruction
	valueRef                map[*ssa.Function]bool
	directValueRef          map[*ssa.Function]bool
	valueRefOutsideInit     map[*ssa.Function]bool
	closureRefs             map[*ssa.Function][]*ssa.MakeClosure
	nonClosureRef           map[*ssa.Function]bool
	structRefFirstFn        map[*types.Named]*ssa.Function
	structRefMultiFn        map[*types.Named]bool
	structReferencedByType  map[*types.Named]bool
	structPoisoned          map[structFieldKey]bool
	structFieldStores       map[structFieldKey][]ssa.Value
	structWholeStores       map[*types.Named][]ssa.Value
	structBoxedValues       map[*types.Named][]ssa.Value
	structFieldReads        map[structFieldKey][]ssa.Value
	namedSigSources         map[*types.Named][]ssa.Value
	namedSigPoisoned        map[*types.Named]bool
	mutatedGlobals          map[*ssa.Global]bool
	errorNewSentinelGlobals map[*ssa.Global]bool
	zeroCandidateGlobals    map[*ssa.Global]bool
	allFunctions            map[*ssa.Function]bool
	userPaths               map[string]bool
	pureDelegates           map[string]bool

	progClosedDone    map[ssa.Value]bool
	enumClosedDone    map[ssa.Value]bool
	progTypesMemo     map[ssa.Value][]types.Type
	progTypesFailed   map[ssa.Value]bool
	enumTypesMemo     map[ssa.Value][]types.Type
	enumTypesFailed   map[ssa.Value]bool
	progFuncsMemo     map[ssa.Value][]*ssa.Function
	progFuncsFailed   map[ssa.Value]bool
	progInvokeTargets map[ssa.CallInstruction]map[*ssa.Function]bool
	progInvokeFailed          map[ssa.CallInstruction]bool
	enumInvokeTargets         map[ssa.CallInstruction]map[*ssa.Function]bool
	enumInvokeFailed          map[ssa.CallInstruction]bool
	enumSeedsMemo             map[ssa.Value]dynamicSeedEntry
	enumStructClosed          map[*types.Named]bool
	userMutatesOSWrapperError bool
	prog                      *program
}

func isOSWrapperErrorStruct(t types.Type) bool {
	if t == nil {
		return false
	}
	base := types.Unalias(t)
	if ptr, ok := base.(*types.Pointer); ok {
		base = types.Unalias(ptr.Elem())
	}
	named, ok := base.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	pkgPath := named.Obj().Pkg().Path()
	name := named.Obj().Name()
	return (pkgPath == "os" && name == "SyscallError") || ((pkgPath == "io/fs" || pkgPath == "os") && name == "PathError")
}

func typeContainsOSWrapperErrorStruct(t types.Type) bool {
	if t == nil {
		return false
	}
	found := false
	walkTypeGraph(t, true, map[types.Type]bool{}, func(sub types.Type) bool {
		if isOSWrapperErrorStruct(sub) {
			found = true
			return false
		}
		return true
	})
	return found
}

func (s *callerReferenceSummary) isStructReferencedOutside(named *types.Named, root *ssa.Function) bool {
	if s == nil || named == nil {
		return false
	}
	first, ok := s.structRefFirstFn[named]
	return ok && (first != root || s.structRefMultiFn[named])
}

func summaryCacheKeyFor(audited bool, pureDelegates map[string]bool) string {
	prefix := "0"
	if audited {
		prefix = "1"
	}
	if len(pureDelegates) == 0 {
		return prefix
	}
	keys := make([]string, 0, len(pureDelegates))
	for k, ok := range pureDelegates {
		if ok {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return prefix
	}
	slices.Sort(keys)
	return prefix + ":" + strings.Join(keys, ",")
}

func lookupSummaryForProg(prog *program, audited bool) *callerReferenceSummary {
	if prog == nil || prog.Summaries == nil {
		return nil
	}
	prefix := "0"
	if audited {
		prefix = "1"
	}
	if s, ok := prog.Summaries[prefix].(*callerReferenceSummary); ok && s != nil {
		return s
	}
	for k, v := range prog.Summaries {
		if strings.HasPrefix(k, prefix+":") {
			if s, ok := v.(*callerReferenceSummary); ok && s != nil {
				return s
			}
		}
	}
	return nil
}

func isPromotedWrapper(fn *ssa.Function) bool {
	return fn != nil && strings.HasPrefix(fn.Synthetic, "wrapper for ")
}

func isUnnamedStructPromotedWrapper(fn *ssa.Function) bool {
	if !isPromotedWrapper(fn) || fn.Pkg != nil || fn.Signature == nil || fn.Signature.Recv() == nil {
		return false
	}
	t := types.Unalias(fn.Signature.Recv().Type())
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	_, ok := t.(*types.Struct)
	return ok
}

func unnamedWrapperDeclaringPkg(fn *ssa.Function) *types.Package {
	if !isUnnamedStructPromotedWrapper(fn) {
		return nil
	}
	t := types.Unalias(fn.Signature.Recv().Type())
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	st, ok := t.(*types.Struct)
	if !ok {
		return nil
	}
	for i := 0; i < st.NumFields(); i++ {
		if pkg := st.Field(i).Pkg(); pkg != nil {
			return pkg
		}
	}
	return nil
}

func isAnalyzableUnnamedWrapper(fn *ssa.Function) bool {
	return isUnnamedStructPromotedWrapper(fn) && len(fn.Blocks) > 0
}

func isStdPkgPath(userPaths map[string]bool, pkgPath string) bool {
	return pkgPath != "" && !userPaths[pkgPath] && isStdImportPath(pkgPath)
}

func isBoundMethodWrapper(fn *ssa.Function) bool {
	return fn != nil && strings.HasPrefix(fn.Synthetic, "bound method wrapper for ")
}

// enumerateCallerReferences makes one deterministic pass over the whole
// analyzed program, collecting for each candidate root its direct static
// call sites and whether any other reference exists — an address
// capture, a stored value, a dynamic use, or a call held by a body the
// enumeration cannot judge as a caller. The same pass records, for EVERY
// function value in the program, whether any address-taking reference to
// it lies outside initializer flow: a value with none is init-planted —
// whatever its shape (an init-parented anonymous closure, a synthetic
// method-value wrapper materialized by an initializer, a named function
// registered there) — and feeds the enumeration-target narrowing.
// Function order is sorted so site order, and every judgment derived
// from it, is run-to-run stable.
func enumerateCallerReferencesForProgram(prog *program, audited bool, pureDelegates map[string]bool, userPaths map[string]bool, all map[*ssa.Function]bool) *callerReferenceSummary {
	key := summaryCacheKeyFor(audited, pureDelegates)
	var ordered []*ssa.Function
	wholeProgram := false
	if prog != nil {
		if cached, ok := prog.Summaries[key].(*callerReferenceSummary); ok && cached != nil {
			return cached
		}
		if all == nil {
			all = progAllFunctions(prog)
		}
		if len(all) == len(progAllFunctions(prog)) {
			ordered = progOrderedFunctions(prog)
			wholeProgram = true
		}
	}
	harnessAudited := propertyHarnessAuditedProg(audited, prog)
	var rootPkgPath string
	if prog != nil {
		rootPkgPath = prog.PkgPath
	}
	res := enumerateCallerReferencesWithOrdered(audited, harnessAudited, rootPkgPath, userPaths, all, ordered)
	res.prog = prog
	res.pureDelegates = pureDelegates
	if prog != nil {
		if wholeProgram && prog.MutatedGlobals == nil && res.mutatedGlobals != nil {
			prog.MutatedGlobals = res.mutatedGlobals
		}
		if prog.Summaries == nil {
			prog.Summaries = make(map[string]any, 2)
		}
		prog.Summaries[key] = res
	}
	return res
}

func enumerateCallerReferences(audited bool, userPaths map[string]bool, all map[*ssa.Function]bool) *callerReferenceSummary {
	return enumerateCallerReferencesWithOrdered(audited, false, "", userPaths, all, nil)
}

func enumerateCallerReferencesWithOrdered(audited, harnessAudited bool, rootPkgPath string, userPaths map[string]bool, all map[*ssa.Function]bool, ordered []*ssa.Function) *callerReferenceSummary {
	if ordered == nil {
		ordered = orderedFunctionsForProgram(all)
	}
	largeCap := max(len(ordered)/4, 16)
	smallCap := max(len(ordered)/16, 16)
	summary := callerReferenceSummary{
		sites:                  make(map[*ssa.Function][]ssa.CallInstruction, largeCap),
		allStaticSites:         make(map[*ssa.Function][]ssa.CallInstruction, largeCap),
		harnessCallbackSites:   make(map[*ssa.Function][]ssa.CallInstruction),
		valueRef:               make(map[*ssa.Function]bool, smallCap),
		directValueRef:         make(map[*ssa.Function]bool, smallCap),
		valueRefOutsideInit:    make(map[*ssa.Function]bool, smallCap),
		closureRefs:            make(map[*ssa.Function][]*ssa.MakeClosure),
		nonClosureRef:          make(map[*ssa.Function]bool, largeCap),
		structRefFirstFn:       make(map[*types.Named]*ssa.Function),
		structRefMultiFn:       make(map[*types.Named]bool),
		structReferencedByType: make(map[*types.Named]bool),
		structPoisoned:         make(map[structFieldKey]bool),
		structFieldStores:      make(map[structFieldKey][]ssa.Value),
		structWholeStores:      make(map[*types.Named][]ssa.Value),
		structBoxedValues:      make(map[*types.Named][]ssa.Value),
		structFieldReads:       make(map[structFieldKey][]ssa.Value),
		namedSigSources:        make(map[*types.Named][]ssa.Value),
		namedSigPoisoned:       make(map[*types.Named]bool),
		mutatedGlobals:         make(map[*ssa.Global]bool),
		allFunctions:           all,
		userPaths:              userPaths,
		progClosedDone:         make(map[ssa.Value]bool),
		enumClosedDone:         make(map[ssa.Value]bool),
		progTypesMemo:          make(map[ssa.Value][]types.Type),
		progTypesFailed:        make(map[ssa.Value]bool),
		enumTypesMemo:          make(map[ssa.Value][]types.Type),
		enumTypesFailed:        make(map[ssa.Value]bool),
		progFuncsMemo:          make(map[ssa.Value][]*ssa.Function),
		progFuncsFailed:        make(map[ssa.Value]bool),
		progInvokeTargets:      make(map[ssa.CallInstruction]map[*ssa.Function]bool),
		progInvokeFailed:       make(map[ssa.CallInstruction]bool),
		enumInvokeTargets:      make(map[ssa.CallInstruction]map[*ssa.Function]bool),
		enumInvokeFailed:       make(map[ssa.CallInstruction]bool),
		enumSeedsMemo:          make(map[ssa.Value]dynamicSeedEntry),
		enumStructClosed:       make(map[*types.Named]bool),
	}
	errType := types.Universe.Lookup("error").Type()
	errSentinelPoisoned := make(map[*ssa.Global]bool)
	errSentinelInitStores := make(map[*ssa.Global]int)
	zeroSeenGlobals := make(map[*ssa.Global]bool)
	nonZeroGlobals := make(map[*ssa.Global]bool)
	recordGlobalOp := func(fn *ssa.Function, initFrame bool, instr ssa.Instruction, g *ssa.Global) {
		if g == nil {
			return
		}
		if !summary.mutatedGlobals[g] {
			switch r := instr.(type) {
			case *ssa.DebugRef:
			case *ssa.UnOp:
				if r.Op != token.MUL || r.X != g {
					summary.mutatedGlobals[g] = true
				}
			case *ssa.Store:
				if r.Addr != g || fn.Pkg != g.Pkg || !initFrame {
					summary.mutatedGlobals[g] = true
				}
			default:
				summary.mutatedGlobals[g] = true
			}
		}
		if !isStdNonUserFunction(fn, userPaths) && g.Pkg != nil && g.Pkg.Pkg != nil {
			if _, isDbg := instr.(*ssa.DebugRef); !isDbg {
				pkgPath := g.Pkg.Pkg.Path()
				if !isStdImportPath(pkgPath) || userPaths[pkgPath] {
					zeroSeenGlobals[g] = true
					if !nonZeroGlobals[g] {
						switch x := instr.(type) {
						case *ssa.UnOp:
							if x.Op != token.MUL || x.X != g {
								nonZeroGlobals[g] = true
							}
						case *ssa.Store:
							if x.Addr != g || x.Val == g || !isZeroSSAConst(x.Val) {
								nonZeroGlobals[g] = true
							}
						default:
							nonZeroGlobals[g] = true
						}
					}
				}
			}
		}
		if !errSentinelPoisoned[g] && g.Pkg != nil && g.Pkg.Pkg != nil {
			if ptr, ok := types.Unalias(g.Type()).(*types.Pointer); ok && types.Identical(ptr.Elem(), errType) {
				switch r := instr.(type) {
				case *ssa.DebugRef:
				case *ssa.UnOp:
					if r.Op != token.MUL || r.X != g {
						errSentinelPoisoned[g] = true
					}
				case *ssa.Store:
					if r.Addr != g || r.Val == g || fn != g.Pkg.Func("init") {
						errSentinelPoisoned[g] = true
					} else if call, ok := r.Val.(*ssa.Call); !ok || call.Common() == nil {
						errSentinelPoisoned[g] = true
					} else if callee := call.Common().StaticCallee(); callee == nil || funcPkgPath(callee) != "errors" || callee.Name() != "New" {
						errSentinelPoisoned[g] = true
					} else {
						errSentinelInitStores[g]++
						if errSentinelInitStores[g] > 1 {
							errSentinelPoisoned[g] = true
						}
					}
				default:
					errSentinelPoisoned[g] = true
				}
			}
		}
	}
	recordStructRef := func(named *types.Named, fn *ssa.Function) {
		summary.structReferencedByType[named] = true
		if first, ok := summary.structRefFirstFn[named]; !ok {
			summary.structRefFirstFn[named] = fn
		} else if first != fn {
			summary.structRefMultiFn[named] = true
		}
	}
	namedSigReferenced := make(map[*types.Named]bool)
	recordNamedSigRef := func(ns *types.Named) {
		if ns != nil {
			namedSigReferenced[ns] = true
		}
	}
	structFieldReads := summary.structFieldReads
	closureRefs := make(map[*ssa.Function][]*ssa.MakeClosure)
	storeRefs := make(map[*ssa.Function][]*ssa.Store)
	callArgRefs := make(map[*ssa.Function][]ssa.CallInstruction)
	methodsByName := make(map[string][]*ssa.Function)
	instantiatedOrigins := make(map[*ssa.Function]bool)
	if audited {
		for _, fn := range ordered {
			if orig := fn.Origin(); orig != nil && !parameterizedBody(fn) {
				instantiatedOrigins[orig] = true
			}
			fnPkg := funcPkgPath(fn)
			if isStdPkgPath(userPaths, fnPkg) {
				continue
			}
			if fn.Signature == nil || fn.Signature.Recv() == nil || (fn.Synthetic != "" && !isPromotedWrapper(fn) && !(audited && fn.Origin() != nil)) || parameterizedBody(fn) || len(fn.Params) == 0 {
				continue
			}
			hasDynamicParam := false
			if recv := fn.Params[0]; recv != nil && derefNamedStruct(userPaths, recv.Type()) == nil && derefNamedSignature(userPaths, recv.Type()) == nil && typeMayCarryDynamicTop(audited, recv.Type()) {
				hasDynamicParam = true
			}
			if !hasDynamicParam {
				for _, param := range fn.Params[1:] {
					if param != nil && typeMayCarryDynamicTop(audited, param.Type()) {
						hasDynamicParam = true
						break
					}
				}
			}
			if hasDynamicParam {
				methodsByName[fn.Name()] = append(methodsByName[fn.Name()], fn)
			}
		}
	}
	poisonStruct := func(named *types.Named, field int) {
		if named == nil {
			return
		}
		if field < 0 {
			key := structFieldKey{named: named, field: -1}
			if !summary.structPoisoned[key] {
				summary.structPoisoned[key] = true
				if trace.AnyEnabled() {
					trace.Emit(nil, trace.DomainClosure, "closure.struct.poison", named.String(),
						trace.Int("field", -1),
					)
				}
			}
			if st, ok := named.Underlying().(*types.Struct); ok {
				for i := 0; i < st.NumFields(); i++ {
					summary.structPoisoned[structFieldKey{named: named, field: i}] = true
				}
			}
			return
		}
		key := structFieldKey{named: named, field: field}
		if !summary.structPoisoned[key] {
			summary.structPoisoned[key] = true
			if trace.AnyEnabled() {
				trace.Emit(nil, trace.DomainClosure, "closure.struct.poison", named.String(),
					trace.Int("field", field),
				)
			}
		}
	}
	poisonContainedTypes := func(t types.Type, refFn *ssa.Function) {
		walkTypeGraph(t, true, map[types.Type]bool{}, func(sub types.Type) bool {
			if isOSWrapperErrorStruct(sub) {
				summary.userMutatesOSWrapperError = true
			}
			if named := derefNamedStruct(userPaths, sub); named != nil {
				if refFn != nil {
					recordStructRef(named, refFn)
				}
				poisonStruct(named, -1)
			} else if ns := derefNamedSignature(userPaths, sub); ns != nil {
				recordNamedSigRef(ns)
				summary.namedSigPoisoned[ns] = true
			}
			return true
		})
	}
	poisonEmbeddedCarriers := func(recvOrBoxed types.Type, topNamed *types.Named, refFn *ssa.Function) {
		if recvOrBoxed == nil {
			return
		}
		baseT := types.Unalias(recvOrBoxed)
		if ptr, ok := baseT.(*types.Pointer); ok {
			baseT = types.Unalias(ptr.Elem())
		}
		st, ok := baseT.Underlying().(*types.Struct)
		if !ok {
			return
		}
		seenEmbed := make(map[*types.Struct]bool)
		var walkEmbed func(*types.Struct)
		walkEmbed = func(cur *types.Struct) {
			if cur == nil || seenEmbed[cur] {
				return
			}
			seenEmbed[cur] = true
			for i := 0; i < cur.NumFields(); i++ {
				fld := cur.Field(i)
				if !fld.Embedded() {
					continue
				}
				ft := fld.Type()
				if inner := derefNamedStruct(userPaths, ft); inner != nil {
					if refFn != nil {
						recordStructRef(inner, refFn)
					}
					poisonStruct(inner, -1)
				}
				if ns := derefNamedSignature(userPaths, ft); ns != nil {
					recordNamedSigRef(ns)
					summary.namedSigPoisoned[ns] = true
				}
				ftElem := types.Unalias(ft)
				if ptr, ok := ftElem.(*types.Pointer); ok {
					ftElem = types.Unalias(ptr.Elem())
				}
				switch sub := ftElem.Underlying().(type) {
				case *types.Struct:
					walkEmbed(sub)
				case *types.Interface:
				default:
					if topNamed != nil && typeMayCarryDynamicTop(audited, ftElem) {
						poisonStruct(topNamed, -1)
					}
				}
			}
		}
		walkEmbed(st)
	}
	type candIfaceKey struct {
		cand  *ssa.Function
		iface *types.Interface
	}
	type reflectTypeRef struct {
		typ types.Type
		fn  *ssa.Function
	}
	var implMemo map[candIfaceKey]bool
	var reflectValueTypes []reflectTypeRef
	var reflectMutationFns []*ssa.Function
	var reflectOpenValueFns []*ssa.Function
	var space [16]*ssa.Value
	for _, fn := range ordered {
		initFrame := initFlowFrame(fn)
		if audited && parameterizedBody(fn) {
			orig := fn
			if fn.Origin() != nil {
				orig = fn.Origin()
			}
			if instantiatedOrigins[orig] {
				for _, b := range fn.Blocks {
					for _, instr := range b.Instrs {
						if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
							if callee := site.Common().StaticCallee(); callee != nil {
								summary.allStaticSites[callee] = append(summary.allStaticSites[callee], site)
							}
							if isPotentialHarnessCallbackSite(site) {
								summary.harnessCallbackSites[fn] = append(summary.harnessCallbackSites[fn], site)
							}
						}
						for _, op := range instr.Operands(space[:0]) {
							if op != nil && *op != nil {
								if g, ok := (*op).(*ssa.Global); ok {
									recordGlobalOp(fn, initFrame, instr, g)
								}
							}
						}
					}
				}
				continue
			}
		}
		// A body the enumeration cannot judge as a caller — a synthetic
		// function (other than a promoted-method forwarding wrapper) or a
		// parameterized origin (open over type parameters) — makes any
		// call it holds a refusing reference, exactly like a value
		// capture: its arguments are never judged, so they must never
		// count as an enumerated site.
		fnIsPromotedWrapper := isPromotedWrapper(fn)
		fnIsBoundWrapper := isBoundMethodWrapper(fn)
		fnRecordCallSite := !fnIsPromotedWrapper && !(audited && fnIsBoundWrapper)
		fnRecordInvokeSite := !fnIsPromotedWrapper && !fnIsBoundWrapper
		judgeable := (fn.Synthetic == "" || fnIsPromotedWrapper || (audited && fn.Origin() != nil)) && !parameterizedBody(fn)
		structJudgeable := fn.Synthetic == "" || fnIsPromotedWrapper || (audited && fn.Origin() != nil)
		fnPkg := funcPkgPath(fn)
		nonStdFrame := !isStdPkgPath(userPaths, fnPkg)
		nonHarnessUserFrame := nonStdFrame && !(harnessAudited && propharness.IsHarnessPath(fnPkg))
		hasUserTypes := nonStdFrame || (fnPkg == "strconv" && fn.Synthetic == "")
		if !hasUserTypes {
			for cur := fn; cur != nil; cur = cur.Parent() {
				if len(cur.TypeArgs()) > 0 {
					hasUserTypes = true
					break
				}
			}
		}
		if audited && hasUserTypes {
			hasRecv := fn.Signature != nil && fn.Signature.Recv() != nil
			for pIdx, param := range fn.Params {
				if param == nil || param.Type() == nil {
					continue
				}
				if named := derefNamedStruct(userPaths, param.Type()); named != nil {
					recordStructRef(named, fn)
					if !structJudgeable {
						poisonStruct(named, -1)
					}
				} else if namedSig := derefNamedSignature(userPaths, param.Type()); namedSig != nil {
					recordNamedSigRef(namedSig)
					if hasRecv && pIdx == 0 {
						continue
					}
					if !structJudgeable {
						summary.namedSigPoisoned[namedSig] = true
					} else if _, isPtr := types.Unalias(param.Type()).(*types.Pointer); !isPtr {
						summary.namedSigSources[namedSig] = append(summary.namedSigSources[namedSig], param)
					} else {
						summary.namedSigPoisoned[namedSig] = true
					}
				}
			}
		}
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				if audited && hasUserTypes {
					if v, ok := instr.(ssa.Value); ok && v.Type() != nil {
						if _, isAlloc := instr.(*ssa.Alloc); isAlloc && nonHarnessUserFrame && isOSWrapperErrorStruct(v.Type()) {
							summary.userMutatesOSWrapperError = true
						}
						if named := derefNamedStruct(userPaths, v.Type()); named != nil {
							recordStructRef(named, fn)
							poison := !structJudgeable
							switch instr.(type) {
							case *ssa.Convert, *ssa.ChangeType:
								poison = true
							case ssa.CallInstruction:
								if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
									if callee := site.Common().StaticCallee(); callee != nil && len(callee.Blocks) == 0 {
										poison = true
									}
								}
							}
							if poison {
								poisonStruct(named, -1)
							}
						} else if namedSig := derefNamedSignature(userPaths, v.Type()); namedSig != nil {
							recordNamedSigRef(namedSig)
							if isPromotedWrapper(fn) && fn.Signature != nil && fn.Signature.Recv() != nil && derefNamedSignature(userPaths, fn.Signature.Recv().Type()) == namedSig {
								// Synthetic pointer-method-table wrapper (*NamedSig).M:
								// boxing *NamedSig via MakeInterface or referencing w
								// directly poisons namedSig below; value MakeInterface
								// already records the boxed NamedSig operand.
							} else if !structJudgeable {
								summary.namedSigPoisoned[namedSig] = true
							} else if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr {
								switch x := instr.(type) {
								case *ssa.Phi:
								case *ssa.ChangeType:
									if x.X == nil {
										summary.namedSigPoisoned[namedSig] = true
									} else {
										summary.namedSigSources[namedSig] = append(summary.namedSigSources[namedSig], x.X)
									}
								case *ssa.MakeClosure:
									summary.namedSigSources[namedSig] = append(summary.namedSigSources[namedSig], v)
								case *ssa.TypeAssert, *ssa.Extract, *ssa.Lookup, *ssa.Index, *ssa.Field, *ssa.UnOp:
									summary.namedSigSources[namedSig] = append(summary.namedSigSources[namedSig], v)
								case ssa.CallInstruction:
									if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
										if callee := site.Common().StaticCallee(); callee != nil && len(callee.Blocks) == 0 {
											summary.namedSigPoisoned[namedSig] = true
										} else {
											summary.namedSigSources[namedSig] = append(summary.namedSigSources[namedSig], v)
										}
									}
								default:
									summary.namedSigPoisoned[namedSig] = true
								}
							} else if v.Referrers() == nil {
								summary.namedSigPoisoned[namedSig] = true
							} else {
								for _, ref := range *v.Referrers() {
									switch r := ref.(type) {
									case *ssa.DebugRef:
									case *ssa.UnOp:
										if r.Op != token.MUL || r.X != v {
											summary.namedSigPoisoned[namedSig] = true
										}
									case *ssa.Store:
										if r.Addr != v || r.Val == nil {
											summary.namedSigPoisoned[namedSig] = true
										} else if _, isInstr := r.Val.(ssa.Instruction); !isInstr {
											summary.namedSigSources[namedSig] = append(summary.namedSigSources[namedSig], r.Val)
										}
									default:
										summary.namedSigPoisoned[namedSig] = true
									}
								}
							}
						}
					}
					switch x := instr.(type) {
					case *ssa.Convert:
						if x.X != nil {
							poisonContainedTypes(x.X.Type(), fn)
							if typeContainsOSWrapperErrorStruct(x.X.Type()) {
								summary.userMutatesOSWrapperError = true
							}
						}
						if x.Type() != nil {
							poisonContainedTypes(x.Type(), fn)
							if typeContainsOSWrapperErrorStruct(x.Type()) {
								summary.userMutatesOSWrapperError = true
							}
						}
					case *ssa.ChangeType:
						if x.X != nil {
							if named := derefNamedStruct(userPaths, x.X.Type()); named != nil {
								poisonStruct(named, -1)
							}
							if typeContainsOSWrapperErrorStruct(x.X.Type()) {
								summary.userMutatesOSWrapperError = true
							}
						}
						if x.Type() != nil && typeContainsOSWrapperErrorStruct(x.Type()) {
							summary.userMutatesOSWrapperError = true
						}
					case *ssa.MakeInterface:
						if x.X != nil && x.X.Type() != nil {
							elemT := x.X.Type()
							_, isPtr := types.Unalias(elemT).(*types.Pointer)
							if ptr, ok := types.Unalias(elemT).(*types.Pointer); ok {
								elemT = ptr.Elem()
							}
							if ns := derefNamedSignature(userPaths, x.X.Type()); ns != nil {
								recordNamedSigRef(ns)
								if !structJudgeable || isPtr {
									summary.namedSigPoisoned[ns] = true
								} else {
									summary.namedSigSources[ns] = append(summary.namedSigSources[ns], x.X)
								}
							}
							topNamed := derefNamedStruct(userPaths, x.X.Type())
							for _, inner := range collectValueContainedUserStructs(userPaths, elemT) {
								recordStructRef(inner, fn)
								if structJudgeable && topNamed != nil {
									if inner == topNamed {
										summary.structBoxedValues[inner] = append(summary.structBoxedValues[inner], x.X)
									}
								} else {
									poisonStruct(inner, -1)
								}
							}
							poisonEmbeddedCarriers(x.X.Type(), topNamed, fn)
						}
					}
					if f, ok := instr.(*ssa.Field); ok && f.X != nil {
						if named := derefNamedStruct(userPaths, f.X.Type()); named != nil {
							if !structJudgeable {
								poisonStruct(named, f.Field)
							} else {
								key := structFieldKey{named: named, field: f.Field}
								structFieldReads[key] = append(structFieldReads[key], f)
							}
						}
					}
					if fa, ok := instr.(*ssa.FieldAddr); ok && fa.X != nil {
						if nonHarnessUserFrame && isOSWrapperErrorStruct(fa.X.Type()) {
							if !structJudgeable || fa.Referrers() == nil {
								summary.userMutatesOSWrapperError = true
							} else {
								for _, ref := range *fa.Referrers() {
									switch r := ref.(type) {
									case *ssa.DebugRef:
									case *ssa.UnOp:
										if r.Op != token.MUL || r.X != fa {
											summary.userMutatesOSWrapperError = true
										}
									default:
										summary.userMutatesOSWrapperError = true
									}
								}
							}
						}
						if named := derefNamedStruct(userPaths, fa.X.Type()); named != nil {
							recordStructRef(named, fn)
							innerNamed := derefNamedStruct(userPaths, fa.Type())
							if innerNamed != nil {
								recordStructRef(innerNamed, fn)
							}
							if !structJudgeable || fa.Referrers() == nil {
								poisonStruct(named, fa.Field)
							} else {
								for _, ref := range *fa.Referrers() {
									switch r := ref.(type) {
									case *ssa.DebugRef:
									case *ssa.UnOp:
										if r.Op != token.MUL || r.X != fa {
											poisonStruct(named, fa.Field)
										} else {
											key := structFieldKey{named: named, field: fa.Field}
											structFieldReads[key] = append(structFieldReads[key], r)
										}
									case *ssa.Store:
										if r.Addr != fa || r.Val == nil {
											poisonStruct(named, fa.Field)
										} else {
											key := structFieldKey{named: named, field: fa.Field}
											summary.structFieldStores[key] = append(summary.structFieldStores[key], r.Val)
										}
									case *ssa.FieldAddr:
										if innerNamed == nil || r.X != fa {
											poisonStruct(named, fa.Field)
										}
									case ssa.CallInstruction:
										_, isGo := r.(*ssa.Go)
										okCall := false
										if !isGo && innerNamed != nil && r.Common() != nil && !r.Common().IsInvoke() {
											if callee := r.Common().StaticCallee(); callee != nil && len(callee.Blocks) > 0 && (callee.Synthetic == "" || isPromotedWrapper(callee) || (audited && callee.Origin() != nil)) && !parameterizedBody(callee) && len(r.Common().Args) == len(callee.Params) {
												okCall = true
												for i, arg := range r.Common().Args {
													if arg == fa && derefNamedStruct(userPaths, callee.Params[i].Type()) != innerNamed {
														okCall = false
														break
													}
												}
											}
										}
										if !okCall {
											poisonStruct(named, fa.Field)
										}
									default:
										poisonStruct(named, fa.Field)
									}
								}
							}
						}
					}
					if st, ok := instr.(*ssa.Store); ok && st.Val != nil && st.Val.Type() != nil {
						c, isConst := st.Val.(*ssa.Const)
						isZero := isConst && c.Value == nil
						if !isZero {
							if nonHarnessUserFrame && typeContainsOSWrapperErrorStruct(st.Val.Type()) {
								summary.userMutatesOSWrapperError = true
							}
							var topNamed *types.Named
							if _, isPtr := types.Unalias(st.Val.Type()).(*types.Pointer); !isPtr {
								topNamed = derefNamedStruct(userPaths, st.Val.Type())
							}
							for _, inner := range collectValueContainedUserStructs(userPaths, st.Val.Type()) {
								recordStructRef(inner, fn)
								if structJudgeable && topNamed != nil {
									if inner == topNamed {
										summary.structWholeStores[inner] = append(summary.structWholeStores[inner], st.Val)
									}
								} else {
									poisonStruct(inner, -1)
								}
							}
						}
					}
					if nonHarnessUserFrame {
						if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
							c := site.Common()
							if c.IsInvoke() {
								if c.Method != nil && c.Method.Pkg() != nil && c.Method.Pkg().Path() == "reflect" {
									mName := c.Method.Name()
									if isReflectMutationSymbol(mName) && (mName != "Addr" || !isAddrOnlyForUnsafePointerConvert(site)) {
										reflectMutationFns = append(reflectMutationFns, fn)
									}
									if mName == "ValueOf" || isReflectOpenProducerSymbol(mName) {
										reflectOpenValueFns = append(reflectOpenValueFns, fn)
									}
								}
							} else if callee := c.StaticCallee(); callee != nil {
								calleePkg := funcPkgPath(callee)
								calleeSym := strings.TrimSuffix(strings.TrimSuffix(functionSymbolName(callee), "$bound"), "$thunk")
								if calleePkg == "os" && calleeSym == "NewSyscallError" {
									summary.userMutatesOSWrapperError = true
								}
								if calleePkg == "reflect" {
									if isReflectMutationSymbol(calleeSym) && (calleeSym != "Addr" || !isAddrOnlyForUnsafePointerConvert(site)) {
										reflectMutationFns = append(reflectMutationFns, fn)
									}
									if calleeSym == "ValueOf" {
										if !isNonMutatingReflectValueRoot(site.Value()) {
											if len(c.Args) == 1 {
												if mi, ok := c.Args[0].(*ssa.MakeInterface); ok && mi.X != nil && mi.X.Type() != nil {
													reflectValueTypes = append(reflectValueTypes, reflectTypeRef{typ: mi.X.Type(), fn: fn})
												} else {
													reflectOpenValueFns = append(reflectOpenValueFns, fn)
												}
											} else {
												reflectOpenValueFns = append(reflectOpenValueFns, fn)
											}
										}
									} else if isReflectOpenProducerSymbol(calleeSym) {
										reflectOpenValueFns = append(reflectOpenValueFns, fn)
									}
								}
								calleeNonStd := !isStdPkgPath(userPaths, calleePkg)
								if (calleeNonStd && len(callee.Blocks) == 0 && callee.Synthetic == "" && !parameterizedBody(callee)) || isStdDeserializerCall(calleePkg, calleeSym) || (harnessAudited && propharness.IsHarnessPath(calleePkg) && (calleeSym == "Make" || calleeSym == "MakeCustom")) {
									for _, arg := range c.Args {
										if arg != nil {
											poisonContainedTypes(arg.Type(), fn)
										}
									}
									if val := site.Value(); val != nil {
										poisonContainedTypes(val.Type(), fn)
									}
									for _, ta := range callee.TypeArgs() {
										poisonContainedTypes(ta, fn)
									}
								}
							}
						}
					}
				}
				rands := instr.Operands(space[:0])
				for _, op := range rands {
					if op != nil && *op != nil {
						if g, ok := (*op).(*ssa.Global); ok {
							recordGlobalOp(fn, initFrame, instr, g)
						}
					}
				}
				if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
					if isPotentialHarnessCallbackSite(site) {
						summary.harnessCallbackSites[fn] = append(summary.harnessCallbackSites[fn], site)
					}
					if callee := site.Common().StaticCallee(); callee != nil {
						summary.allStaticSites[callee] = append(summary.allStaticSites[callee], site)
						summary.nonClosureRef[callee] = true
						if fnRecordCallSite {
							if judgeable {
								summary.sites[callee] = append(summary.sites[callee], site)
							} else {
								summary.valueRef[callee] = true
								summary.directValueRef[callee] = true
							}
						}
					} else if audited && len(methodsByName) > 0 && site.Common().IsInvoke() && site.Common().Method != nil {
						if cands := methodsByName[site.Common().Method.Name()]; len(cands) > 0 {
							iface, _ := types.Unalias(site.Common().Value.Type()).Underlying().(*types.Interface)
							if iface != nil {
								for _, cand := range cands {
									if cand == fn {
										continue
									}
									key := candIfaceKey{cand: cand, iface: iface}
									impl, cached := implMemo[key]
									if !cached {
										recvType := cand.Signature.Recv().Type()
										impl = types.Implements(recvType, iface) || types.Implements(types.NewPointer(recvType), iface)
										if implMemo == nil {
											implMemo = make(map[candIfaceKey]bool, 16)
										}
										implMemo[key] = impl
									}
									if impl && fnRecordInvokeSite {
										if judgeable {
											summary.sites[cand] = append(summary.sites[cand], site)
										} else {
											summary.valueRef[cand] = true
											summary.directValueRef[cand] = true
										}
									}
								}
							}
						}
					}
					if !site.Common().IsInvoke() {
						// The callee operand is the call itself, not a
						// value reference.
						rands = rands[1:]
					}
				}
				for _, op := range rands {
					if audited && hasUserTypes && op != nil && *op != nil && (*op).Type() != nil {
						if named := derefNamedStruct(userPaths, (*op).Type()); named != nil {
							recordStructRef(named, fn)
						} else if g, isGlob := (*op).(*ssa.Global); isGlob {
							if ns := derefNamedSignature(userPaths, g.Type()); ns != nil {
								recordNamedSigRef(ns)
								unopLoad := false
								if u, ok := instr.(*ssa.UnOp); ok && u.Op == token.MUL && u.X == g {
									unopLoad = true
								}
								storeAddr := false
								if st, ok := instr.(*ssa.Store); ok && st.Addr == g && st.Val != g {
									storeAddr = true
								}
								if !structJudgeable || (!unopLoad && !storeAddr) {
									summary.namedSigPoisoned[ns] = true
								}
							}
						}
					}
					if g, ok := (*op).(*ssa.Function); ok {
						if audited && nonHarnessUserFrame {
							gPkg := funcPkgPath(g)
							gSym := strings.TrimSuffix(strings.TrimSuffix(functionSymbolName(g), "$bound"), "$thunk")
							if gPkg == "os" && gSym == "NewSyscallError" {
								summary.userMutatesOSWrapperError = true
							}
							if gPkg == "reflect" {
								if isReflectMutationSymbol(gSym) {
									reflectMutationFns = append(reflectMutationFns, fn)
								}
								if gSym == "ValueOf" || isReflectOpenProducerSymbol(gSym) {
									reflectOpenValueFns = append(reflectOpenValueFns, fn)
								}
							}
						}
						summary.directValueRef[g] = true
						if !initFrame {
							summary.valueRefOutsideInit[g] = true
						}
						if audited && judgeable && !fnIsPromotedWrapper {
							if mc, ok := instr.(*ssa.MakeClosure); ok && mc.Fn == g && !slices.Contains(mc.Bindings, ssa.Value(g)) {
								closureRefs[g] = append(closureRefs[g], mc)
								summary.closureRefs[g] = closureRefs[g]
								continue
							}
							summary.nonClosureRef[g] = true
							if st, ok := instr.(*ssa.Store); ok && st.Val == g && st.Addr != g {
								storeRefs[g] = append(storeRefs[g], st)
								continue
							}
							if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil && !site.Common().IsInvoke() && site.Common().StaticCallee() != nil {
								callArgRefs[g] = append(callArgRefs[g], site)
								continue
							}
						}
						summary.nonClosureRef[g] = true
						summary.valueRef[g] = true
					}
				}
			}
		}
	}
	if len(errSentinelInitStores) > 0 {
		summary.errorNewSentinelGlobals = make(map[*ssa.Global]bool, len(errSentinelInitStores))
		for g, count := range errSentinelInitStores {
			if count == 1 && !errSentinelPoisoned[g] {
				summary.errorNewSentinelGlobals[g] = true
			}
		}
	}
	if len(zeroSeenGlobals) > 0 {
		for g := range zeroSeenGlobals {
			if !nonZeroGlobals[g] {
				if summary.zeroCandidateGlobals == nil {
					summary.zeroCandidateGlobals = make(map[*ssa.Global]bool)
				}
				summary.zeroCandidateGlobals[g] = true
			}
		}
	}
	if audited {
		for _, w := range ordered {
			if !isPromotedWrapper(w) || w.Signature == nil || w.Signature.Recv() == nil {
				continue
			}
			hasDirectCall := false
			for _, s := range summary.sites[w] {
				if s != nil && s.Common() != nil && !s.Common().IsInvoke() {
					hasDirectCall = true
					break
				}
			}
			if !hasDirectCall && !summary.valueRef[w] && !summary.directValueRef[w] {
				continue
			}
			if ns := derefNamedSignature(userPaths, w.Signature.Recv().Type()); ns != nil {
				summary.namedSigPoisoned[ns] = true
			}
			wTopNamed := derefNamedStruct(userPaths, w.Signature.Recv().Type())
			poisonEmbeddedCarriers(w.Signature.Recv().Type(), wTopNamed, w)
		}
		if len(reflectMutationFns) > 0 {
			var reflectLiveMemo map[*ssa.Function]bool
			var reflectVisiting map[*ssa.Function]bool
			var reflectFnLive func(*ssa.Function) (bool, bool)
			reflectFnLive = func(fn *ssa.Function) (bool, bool) {
				if fn == nil {
					return false, false
				}
				if rootPkgPath == "" {
					return true, false
				}
				top := fn
				for top.Parent() != nil {
					top = top.Parent()
				}
				if v, ok := reflectLiveMemo[top]; ok {
					return v, false
				}
				if reflectVisiting[top] {
					return false, true
				}
				if reflectLiveMemo == nil {
					reflectLiveMemo = make(map[*ssa.Function]bool, 16)
					reflectVisiting = make(map[*ssa.Function]bool, 16)
				}
				reflectVisiting[top] = true
				defer delete(reflectVisiting, top)
				pkgPath := funcPkgPath(top)
				if pkgPath == rootPkgPath || pkgPath == rootPkgPath+"_test" || pkgPath == "main" || initFlowFrame(top) || summary.directValueRef[top] || summary.valueRef[top] {
					reflectLiveMemo[top] = true
					return true, false
				}
				if top.Signature != nil && top.Signature.Recv() != nil {
					if recvNamed := derefNamedStruct(userPaths, top.Signature.Recv().Type()); recvNamed == nil || len(summary.structBoxedValues[recvNamed]) > 0 || summary.structPoisoned[structFieldKey{named: recvNamed, field: -1}] {
						reflectLiveMemo[top] = true
						return true, false
					}
				}
				tainted := false
				for _, site := range summary.allStaticSites[top] {
					if site != nil && site.Parent() != nil {
						cLive, cTainted := reflectFnLive(site.Parent())
						if cLive {
							reflectLiveMemo[top] = true
							return true, false
						}
						if cTainted {
							tainted = true
						}
					}
				}
				if !tainted {
					reflectLiveMemo[top] = false
				}
				return false, tainted
			}
			sawReflectMutation := false
			for _, fn := range reflectMutationFns {
				if live, _ := reflectFnLive(fn); live {
					sawReflectMutation = true
					break
				}
			}
			if sawReflectMutation {
				summary.userMutatesOSWrapperError = true
				sawOpenReflectValue := false
				for _, fn := range reflectOpenValueFns {
					if live, _ := reflectFnLive(fn); live {
						sawOpenReflectValue = true
						break
					}
				}
				var liveReflectTypes []reflectTypeRef
				if !sawOpenReflectValue {
					for _, rv := range reflectValueTypes {
						if live, _ := reflectFnLive(rv.fn); live {
							liveReflectTypes = append(liveReflectTypes, rv)
						}
					}
					if len(liveReflectTypes) == 0 {
						sawOpenReflectValue = true
					} else {
						for _, rv := range liveReflectTypes {
							if typeReachesOpenReflectCarrier(rv.typ) {
								sawOpenReflectValue = true
								break
							}
						}
					}
				}
				if sawOpenReflectValue {
					for named := range summary.structReferencedByType {
						poisonStruct(named, -1)
					}
					for ns := range namedSigReferenced {
						summary.namedSigPoisoned[ns] = true
					}
				} else {
					for _, rv := range liveReflectTypes {
						poisonContainedTypes(rv.typ, rv.fn)
					}
				}
			}
		}
		var collectFuncValueCallSites func(val ssa.Value, seen map[ssa.Value]bool) ([]ssa.CallInstruction, bool)
		var collectStoreTargetCallSites func(addr ssa.Value, seen map[ssa.Value]bool) ([]ssa.CallInstruction, bool)
		collectStoreTargetCallSites = func(addr ssa.Value, seen map[ssa.Value]bool) ([]ssa.CallInstruction, bool) {
			if fa, ok := addr.(*ssa.FieldAddr); ok && fa.X != nil {
				if named := derefNamedStruct(userPaths, fa.X.Type()); named != nil {
					key := structFieldKey{named: named, field: fa.Field}
					if summary.structPoisoned[key] {
						return nil, false
					}
					reads := structFieldReads[key]
					if len(reads) == 0 {
						return nil, false
					}
					var sites []ssa.CallInstruction
					for _, rd := range reads {
						sub, ok := collectFuncValueCallSites(rd, seen)
						if !ok {
							return nil, false
						}
						sites = append(sites, sub...)
					}
					return sites, true
				}
			}
			if alloc, ok := addr.(*ssa.Alloc); ok {
				if seen[alloc] {
					return nil, true
				}
				seen[alloc] = true
				if alloc.Referrers() == nil {
					return nil, false
				}
				var sites []ssa.CallInstruction
				for _, ref := range *alloc.Referrers() {
					switch r := ref.(type) {
					case *ssa.DebugRef:
					case *ssa.Store:
						if r.Addr != alloc {
							return nil, false
						}
					case *ssa.UnOp:
						if r.Op != token.MUL || r.X != alloc {
							return nil, false
						}
						sub, ok := collectFuncValueCallSites(r, seen)
						if !ok {
							return nil, false
						}
						sites = append(sites, sub...)
					case *ssa.MakeClosure:
						cFn, ok := r.Fn.(*ssa.Function)
						if !ok || len(cFn.Blocks) == 0 || len(r.Bindings) != len(cFn.FreeVars) {
							return nil, false
						}
						for i, b := range r.Bindings {
							if b == alloc {
								sub, ok := collectFuncValueCallSites(cFn.FreeVars[i], seen)
								if !ok {
									return nil, false
								}
								sites = append(sites, sub...)
							}
						}
					default:
						return nil, false
					}
				}
				return sites, true
			}
			return nil, false
		}
		collectFuncValueCallSites = func(val ssa.Value, seen map[ssa.Value]bool) ([]ssa.CallInstruction, bool) {
			if val == nil {
				return nil, false
			}
			if seen[val] {
				return nil, true
			}
			seen[val] = true
			refs := val.Referrers()
			if refs == nil {
				return nil, false
			}
			var sites []ssa.CallInstruction
			for _, ref := range *refs {
				switch r := ref.(type) {
				case *ssa.DebugRef:
				case *ssa.BinOp:
					if r.Op != token.EQL && r.Op != token.NEQ {
						return nil, false
					}
				case *ssa.Phi:
					sub, ok := collectFuncValueCallSites(r, seen)
					if !ok {
						return nil, false
					}
					sites = append(sites, sub...)
				case *ssa.ChangeType:
					if r.X != val {
						return nil, false
					}
					sub, ok := collectFuncValueCallSites(r, seen)
					if !ok {
						return nil, false
					}
					sites = append(sites, sub...)
				case *ssa.UnOp:
					if r.Op != token.MUL || r.X != val {
						return nil, false
					}
					sub, ok := collectFuncValueCallSites(r, seen)
					if !ok {
						return nil, false
					}
					sites = append(sites, sub...)
				case *ssa.MakeClosure:
					cFn, ok := r.Fn.(*ssa.Function)
					if !ok || len(cFn.Blocks) == 0 || len(r.Bindings) != len(cFn.FreeVars) {
						return nil, false
					}
					for i, b := range r.Bindings {
						if b == val {
							sub, ok := collectFuncValueCallSites(cFn.FreeVars[i], seen)
							if !ok {
								return nil, false
							}
							sites = append(sites, sub...)
						}
					}
				case *ssa.Store:
					if r.Val != val || r.Addr == val {
						return nil, false
					}
					sub, ok := collectStoreTargetCallSites(r.Addr, seen)
					if !ok {
						return nil, false
					}
					sites = append(sites, sub...)
				case ssa.CallInstruction:
					if _, isGo := r.(*ssa.Go); isGo || r.Common() == nil {
						return nil, false
					}
					caller := r.Parent()
					if caller == nil || (caller.Synthetic != "" && !isPromotedWrapper(caller) && caller.Origin() == nil) || parameterizedBody(caller) {
						return nil, false
					}
					passedAsArg := false
					for i, arg := range r.Common().Args {
						if arg == val {
							passedAsArg = true
							callee := r.Common().StaticCallee()
							if r.Common().IsInvoke() || callee == nil || len(callee.Blocks) == 0 || (callee.Synthetic != "" && !isPromotedWrapper(callee) && callee.Origin() == nil) || parameterizedBody(callee) || len(r.Common().Args) != len(callee.Params) {
								return nil, false
							}
							sub, ok := collectFuncValueCallSites(callee.Params[i], seen)
							if !ok {
								return nil, false
							}
							sites = append(sites, sub...)
						}
					}
					if !r.Common().IsInvoke() && r.Common().Value == val {
						sites = append(sites, r)
					} else if !passedAsArg {
						return nil, false
					}
				default:
					return nil, false
				}
			}
			return sites, true
		}
		for _, g := range ordered {
			if summary.valueRef[g] {
				continue
			}
			mcs := closureRefs[g]
			sts := storeRefs[g]
			cas := callArgRefs[g]
			if len(mcs) == 0 && len(sts) == 0 && len(cas) == 0 {
				continue
			}
			var extraSites []ssa.CallInstruction
			okAll := true
			for _, mc := range mcs {
				sub, ok := collectFuncValueCallSites(mc, make(map[ssa.Value]bool))
				if !ok || len(sub) == 0 {
					okAll = false
					break
				}
				extraSites = append(extraSites, sub...)
			}
			for _, st := range sts {
				if !okAll {
					break
				}
				sub, ok := collectStoreTargetCallSites(st.Addr, make(map[ssa.Value]bool))
				if !ok || len(sub) == 0 {
					okAll = false
					break
				}
				extraSites = append(extraSites, sub...)
			}
			for _, site := range cas {
				if !okAll {
					break
				}
				callee := site.Common().StaticCallee()
				if callee == nil || len(callee.Blocks) == 0 || (callee.Synthetic != "" && !isPromotedWrapper(callee) && callee.Origin() == nil) || parameterizedBody(callee) || len(site.Common().Args) != len(callee.Params) {
					okAll = false
					break
				}
				for i, arg := range site.Common().Args {
					if arg == g {
						sub, ok := collectFuncValueCallSites(callee.Params[i], make(map[ssa.Value]bool))
						if !ok || len(sub) == 0 {
							okAll = false
							break
						}
						extraSites = append(extraSites, sub...)
					}
				}
			}
			if !okAll {
				summary.valueRef[g] = true
			} else {
				summary.sites[g] = append(summary.sites[g], extraSites...)
			}
		}
	}
	dedupCallSites := func(sites []ssa.CallInstruction) []ssa.CallInstruction {
		if len(sites) <= 1 {
			return sites
		}
		seenSite := make(map[ssa.CallInstruction]bool, len(sites))
		dedup := sites[:0]
		for _, s := range sites {
			if !seenSite[s] {
				seenSite[s] = true
				dedup = append(dedup, s)
			}
		}
		return dedup
	}
	for _, w := range ordered {
		if audited && isBoundMethodWrapper(w) {
			wsites := dedupCallSites(summary.sites[w])
			summary.sites[w] = wsites
			wval := summary.valueRef[w]
			wdval := summary.directValueRef[w]
			if len(wsites) == 0 && !wval && !wdval {
				continue
			}
			for _, b := range w.Blocks {
				for _, instr := range b.Instrs {
					if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
						if callee := site.Common().StaticCallee(); callee != nil {
							summary.directValueRef[callee] = true
							if wval || len(wsites) == 0 {
								summary.valueRef[callee] = true
							} else {
								summary.sites[callee] = append(summary.sites[callee], site)
							}
						} else if site.Common().IsInvoke() && site.Common().Method != nil {
							mname := site.Common().Method.Name()
							iface, _ := types.Unalias(site.Common().Value.Type()).Underlying().(*types.Interface)
							if iface != nil {
								for _, cand := range methodsByName[mname] {
									if cand == w {
										continue
									}
									recvType := cand.Signature.Recv().Type()
									if types.Implements(recvType, iface) || types.Implements(types.NewPointer(recvType), iface) {
										summary.directValueRef[cand] = true
										if wval || len(wsites) == 0 {
											summary.valueRef[cand] = true
										} else {
											summary.sites[cand] = append(summary.sites[cand], site)
										}
									}
								}
							}
						}
					}
				}
			}
			continue
		}
		if !isPromotedWrapper(w) {
			continue
		}
		wsites := dedupCallSites(summary.sites[w])
		summary.sites[w] = wsites
		wval := summary.valueRef[w]
		wdval := summary.directValueRef[w]
		if len(wsites) == 0 && !wval && !wdval {
			continue
		}
		for _, b := range w.Blocks {
			for _, instr := range b.Instrs {
				if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
					if callee := site.Common().StaticCallee(); callee != nil {
						if wval {
							summary.valueRef[callee] = true
						}
						if wdval {
							summary.directValueRef[callee] = true
						}
						if len(wsites) > 0 {
							summary.sites[callee] = append(summary.sites[callee], wsites...)
						}
					} else if audited && site.Common().IsInvoke() && site.Common().Method != nil {
						mname := site.Common().Method.Name()
						iface, _ := types.Unalias(site.Common().Value.Type()).Underlying().(*types.Interface)
						if iface != nil {
							for _, cand := range methodsByName[mname] {
								if cand == w {
									continue
								}
								recvType := cand.Signature.Recv().Type()
								if types.Implements(recvType, iface) || types.Implements(types.NewPointer(recvType), iface) {
									if wval {
										summary.valueRef[cand] = true
									}
									if wdval {
										summary.directValueRef[cand] = true
									}
									if len(wsites) > 0 {
										summary.sites[cand] = append(summary.sites[cand], wsites...)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	for key := range summary.structPoisoned {
		delete(summary.structFieldStores, key)
		if key.field < 0 {
			delete(summary.structWholeStores, key.named)
			delete(summary.structBoxedValues, key.named)
		}
	}
	for fn, sites := range summary.sites {
		summary.sites[fn] = dedupCallSites(sites)
	}
	return &summary
}

func provenanceReachableStartup(ctx context.Context, audited bool, prog *program, roots []*ssa.Function, mask uint64, result *rta.Result, harnessAudited bool, userPaths map[string]bool) (map[*ssa.Function]bool, error) {
	return provenanceBFS(ctx, audited, prog, roots, mask, result, harnessAudited, userPaths, true, nil)
}

func provenanceReachable(ctx context.Context, roots []*ssa.Function, mask uint64, result *rta.Result, harnessAudited bool, userPaths map[string]bool, dropTarget func(ssa.CallInstruction, *ssa.Function) bool) (map[*ssa.Function]bool, error) {
	reach, _, err := provenanceBFSWithCandidates(ctx, false, nil, roots, mask, result, harnessAudited, userPaths, false, dropTarget, nil, nil)
	return reach, err
}

func provenanceReachableWithCandidates(ctx context.Context, audited bool, prog *program, roots []*ssa.Function, mask uint64, result *rta.Result, harnessAudited bool, userPaths map[string]bool, dropTarget func(ssa.CallInstruction, *ssa.Function) bool, candidateTypes, initBoxedTypes []types.Type) (map[*ssa.Function]bool, bool, error) {
	return provenanceBFSWithCandidates(ctx, audited, prog, roots, mask, result, harnessAudited, userPaths, false, dropTarget, candidateTypes, initBoxedTypes)
}

func provenanceBFS(ctx context.Context, audited bool, prog *program, roots []*ssa.Function, mask uint64, result *rta.Result, harnessAudited bool, userPaths map[string]bool, deferUnscannedClosures bool, dropTarget func(ssa.CallInstruction, *ssa.Function) bool) (map[*ssa.Function]bool, error) {
	reach, _, err := provenanceBFSWithCandidates(ctx, audited, prog, roots, mask, result, harnessAudited, userPaths, deferUnscannedClosures, dropTarget, nil, nil)
	return reach, err
}

func lookupCachedBaseStartup(prog *program) *baseStartupReachSummary {
	if prog == nil || prog.Summaries == nil {
		return nil
	}
	if s, ok := prog.Summaries["baseStartupReach:1:1"].(*baseStartupReachSummary); ok && s != nil {
		return s
	}
	if s, ok := prog.Summaries["baseStartupReach:0:1"].(*baseStartupReachSummary); ok && s != nil {
		return s
	}
	return nil
}

func hasStartupAncestor(fn *ssa.Function, startupFns map[*ssa.Function]bool) bool {
	if fn == nil || fn.Parent() == nil {
		return false
	}
	if initFlowFrame(fn) {
		return true
	}
	if len(startupFns) == 0 {
		return false
	}
	for p := fn.Parent(); p != nil; p = p.Parent() {
		if startupFns[p] {
			return true
		}
	}
	return false
}

func typeCanCarryAnyInitBoxed(t types.Type, initBoxed []types.Type) bool {
	if t == nil || len(initBoxed) == 0 {
		return false
	}
	found := false
	walkTypeGraph(t, true, map[types.Type]bool{}, func(cur types.Type) bool {
		iface, ok := cur.(*types.Interface)
		if !ok {
			return true
		}
		if rta.ContainsTypeParam(iface, nil) {
			found = true
			return false
		}
		for _, bt := range initBoxed {
			if bt == nil {
				continue
			}
			if rta.ContainsTypeParam(bt, nil) || types.Implements(bt, iface) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func isMethodlessCarrierFreeType(audited bool, t types.Type) bool {
	if t == nil || typeMayCarryDynamicTop(audited, t) {
		return false
	}
	cur := types.Unalias(t)
	for {
		switch u := cur.(type) {
		case *types.Basic:
			return true
		case *types.Slice:
			cur = types.Unalias(u.Elem())
		case *types.Array:
			cur = types.Unalias(u.Elem())
		default:
			return false
		}
	}
}

func isCarrierFreeCallArg(audited bool, site ssa.CallInstruction, arg ssa.Value) bool {
	if arg == nil || !typeMayCarryDynamicTop(audited, arg.Type()) {
		return true
	}
	if c, ok := arg.(*ssa.Const); ok && c.Value == nil {
		return true
	}
	if mi, ok := arg.(*ssa.MakeInterface); ok && mi.X != nil {
		return isMethodlessCarrierFreeType(audited, mi.X.Type())
	}
	if sl, ok := arg.(*ssa.Slice); ok && sl.Low == nil && sl.High == nil && sl.Max == nil {
		alloc, ok := sl.X.(*ssa.Alloc)
		if !ok || alloc.Referrers() == nil || sl.Referrers() == nil {
			return false
		}
		for _, sref := range *sl.Referrers() {
			switch sref.(type) {
			case *ssa.DebugRef:
			default:
				if sref != site {
					return false
				}
			}
		}
		for _, aref := range *alloc.Referrers() {
			switch ar := aref.(type) {
			case *ssa.DebugRef:
			case *ssa.Slice:
				if ar != sl {
					return false
				}
			case *ssa.IndexAddr:
				if ar.X != alloc || ar.Referrers() == nil {
					return false
				}
				for _, iref := range *ar.Referrers() {
					switch ir := iref.(type) {
					case *ssa.DebugRef:
					case *ssa.Store:
						if ir.Addr != ar || !isCarrierFreeCallArg(audited, site, ir.Val) {
							return false
						}
					default:
						return false
					}
				}
			default:
				return false
			}
		}
		return true
	}
	return false
}

func isCarrierFreeStaticCall(audited bool, site ssa.CallInstruction, callee *ssa.Function) bool {
	if site == nil || site.Common() == nil || callee == nil {
		return false
	}
	c := site.Common()
	if mc, ok := c.Value.(*ssa.MakeClosure); ok {
		for _, b := range mc.Bindings {
			if b != nil && typeMayCarryDynamicTop(audited, b.Type()) {
				return false
			}
		}
	}
	for _, arg := range c.Args {
		if !isCarrierFreeCallArg(audited, site, arg) {
			return false
		}
	}
	for _, ta := range callee.TypeArgs() {
		if typeMayCarryDynamicTop(audited, ta) {
			return false
		}
	}
	return true
}

func provenanceBFSWithCandidates(ctx context.Context, audited bool, prog *program, roots []*ssa.Function, mask uint64, result *rta.Result, harnessAudited bool, userPaths map[string]bool, deferUnscannedClosures bool, dropTarget func(ssa.CallInstruction, *ssa.Function) bool, candidateTypes, initBoxedTypes []types.Type) (map[*ssa.Function]bool, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	reachable := make(map[*ssa.Function]bool)
	scanned := make(map[*ssa.Function]bool)
	canDispatchNonStd := make(map[*ssa.Function]bool, len(roots))
	scannedWithNonStd := make(map[*ssa.Function]bool)
	var pendingByParent map[*ssa.Function][]*ssa.Function
	if deferUnscannedClosures {
		pendingByParent = make(map[*ssa.Function][]*ssa.Function)
	}
	queue := append([]*ssa.Function(nil), roots...)
	var rootSSAProg *ssa.Program
	if prog != nil {
		rootSSAProg = prog.Prog
	}
	for _, r := range roots {
		if r != nil {
			if rootSSAProg == nil {
				rootSSAProg = r.Prog
			}
			if !isStdPkgPath(userPaths, funcPkgPath(r)) {
				canDispatchNonStd[r] = true
			}
		}
	}
	var syncZeroGlobals, wholeZeroGlobals map[*ssa.Global]bool
	var asyncStartup map[*ssa.Function]bool
	var wholeComputed bool
	if deferUnscannedClosures && len(roots) > 0 && initFlowFrame(roots[0]) {
		syncZeroGlobals = rtaUnmutatedZeroGlobals(audited, prog, result, mask, userPaths)
		if len(syncZeroGlobals) > 0 {
			asyncStartup = computeRTAAsyncStartupFunctions(result, mask, userPaths)
		}
	}
	var sawHarnessCall bool
	var dispatchedTargets map[*ssa.Function]bool
	var harnessCandidateTargets map[*ssa.Function]bool
	var seenCandidateTypes map[types.Type]bool
	var pendingCandidateTypes []types.Type
	enqueueDispatchedMethodsOfType := func(ssaProg *ssa.Program, rootType types.Type) {
		if ssaProg == nil || rootType == nil || len(dispatchedTargets) == 0 {
			return
		}
		walkTypeGraph(rootType, true, seenCandidateTypes, func(cur types.Type) bool {
			named, ok := cur.(*types.Named)
			if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
				return true
			}
			pkgPath := named.Obj().Pkg().Path()
			if isStdPkgPath(userPaths, pkgPath) || pkgPath == "testing" || (harnessAudited && propharness.IsHarnessPath(pkgPath)) {
				return true
			}
			for _, mt := range []types.Type{named, types.NewPointer(named)} {
				mset := ssaProg.MethodSets.MethodSet(mt)
				for i, n := 0, mset.Len(); i < n; i++ {
					sel := mset.At(i)
					if sel.Obj() == nil {
						continue
					}
					if cm := ssaProg.MethodValue(sel); cm != nil && dispatchedTargets[cm] {
						if harnessCandidateTargets == nil {
							harnessCandidateTargets = make(map[*ssa.Function]bool)
						}
						harnessCandidateTargets[cm] = true
						canDispatchNonStd[cm] = true
						queue = append(queue, cm)
					}
				}
			}
			return true
		})
	}
	noteHarnessCandidateType := func(ssaProg *ssa.Program, t types.Type) {
		if result == nil || t == nil {
			return
		}
		if !sawHarnessCall {
			pendingCandidateTypes = append(pendingCandidateTypes, t)
			return
		}
		enqueueDispatchedMethodsOfType(ssaProg, t)
	}
	activateHarnessDispatchedMethods := func(ssaProg *ssa.Program) {
		if sawHarnessCall || result == nil {
			return
		}
		sawHarnessCall = true
		dispatchedTargets = make(map[*ssa.Function]bool)
		for _, targets := range result.Targets {
			for target, targetMask := range targets {
				if targetMask&mask != 0 && !isTestingMRun(target) && !isTestingBLaunch(target) {
					dispatchedTargets[target] = true
				}
			}
		}
		for _, targets := range result.HarnessStdTargets {
			for target, targetMask := range targets {
				if targetMask&mask != 0 && !isTestingMRun(target) && !isTestingBLaunch(target) {
					dispatchedTargets[target] = true
				}
			}
		}
		seenCandidateTypes = make(map[types.Type]bool)
		for _, pt := range pendingCandidateTypes {
			enqueueDispatchedMethodsOfType(ssaProg, pt)
		}
		pendingCandidateTypes = nil
	}
	for _, ct := range candidateTypes {
		noteHarnessCandidateType(rootSSAProg, ct)
	}
	var usedInitBoxed bool
	var baseStartup *baseStartupReachSummary
	var checkedGlobalCarrier map[*ssa.Global]bool
	if len(initBoxedTypes) > 0 {
		baseStartup = lookupCachedBaseStartup(prog)
	}
	seedInitBoxedTypes := func(ssaProg *ssa.Program) {
		if usedInitBoxed {
			return
		}
		usedInitBoxed = true
		for _, bt := range initBoxedTypes {
			noteHarnessCandidateType(ssaProg, bt)
		}
	}
	var provFP *freshParamAnalysis
	var provFPInit bool
	getProvFP := func() *freshParamAnalysis {
		if provFPInit {
			return provFP
		}
		provFPInit = true
		sum := lookupSummaryForProg(prog, audited)
		var pureDelegates map[string]bool
		if sum != nil {
			pureDelegates = sum.pureDelegates
		}
		fp := newBitOnlyFreshParamAnalysis(harnessAudited, audited, pureDelegates, userPaths, sum, func(f *ssa.Function) bool {
			return isStdPkgPath(userPaths, funcPkgPath(f))
		})
		fp.resetDynamicMemos()
		if sum != nil {
			fp.inProgramSites = true
			fp.programSites = sum.sites
			fp.programValueRef = sum.valueRef
			fp.programFunctions = sum.allFunctions
		} else if prog != nil {
			fp.prog = prog
			fp.programFunctions = progAllFunctions(prog)
		}
		provFP = fp
		return provFP
	}
	var opsBuf [8]*ssa.Value
	for len(queue) != 0 {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		fn := queue[0]
		queue = queue[1:]
		if fn == nil || result.Reachable[fn]&mask == 0 {
			continue
		}
		fnNonStdDispatch := canDispatchNonStd[fn]
		if scanned[fn] && (!fnNonStdDispatch || scannedWithNonStd[fn]) {
			continue
		}
		scanned[fn] = true
		if fnNonStdDispatch {
			scannedWithNonStd[fn] = true
		}
		if deferUnscannedClosures {
			if pending := pendingByParent[fn]; len(pending) > 0 {
				delete(pendingByParent, fn)
				queue = append(queue, pending...)
			}
		}
		fnPath := funcPkgPath(fn)
		fnIsStd := isStdPkgPath(userPaths, fnPath)
		// A harness frame - the standard testing package or an audited
		// property harness - is never subject content; its dispatch
		// targets still traverse, so the caller-supplied callbacks it
		// runs stay subject flow (REQ-closure-observability-analysis).
		harnessFrame := fnPath == "testing" || harnessAudited && propharness.IsHarnessPath(fnPath)
		if !harnessFrame {
			reachable[fn] = true
			if !usedInitBoxed && len(initBoxedTypes) > 0 && len(fn.FreeVars) > 0 &&
				(baseStartup == nil || hasStartupAncestor(fn, baseStartup.startupFunctions)) {
				for _, fv := range fn.FreeVars {
					if fv != nil && typeCanCarryAnyInitBoxed(fv.Type(), initBoxedTypes) {
						seedInitBoxedTypes(fn.Prog)
						break
					}
				}
			}
		}
		fnZeroGlobals := syncZeroGlobals
		if len(syncZeroGlobals) > 0 && asyncStartup[fn] {
			if !wholeComputed {
				wholeComputed = true
				if prog != nil {
					wholeZeroGlobals = unmutatedZeroGlobalsForFunctions(audited, prog, userPaths, progAllFunctions(prog))
				}
			}
			fnZeroGlobals = wholeZeroGlobals
		}
		for _, block := range liveBlocks(fn, fnZeroGlobals) {
			for _, instruction := range block.Instrs {
				if !harnessFrame {
					if !usedInitBoxed && len(initBoxedTypes) > 0 {
						for _, op := range instruction.Operands(opsBuf[:0]) {
							if op == nil {
								continue
							}
							g, ok := (*op).(*ssa.Global)
							if !ok || g == nil || checkedGlobalCarrier[g] {
								continue
							}
							if checkedGlobalCarrier == nil {
								checkedGlobalCarrier = make(map[*ssa.Global]bool)
							}
							checkedGlobalCarrier[g] = true
							var gPkg string
							if g.Pkg != nil && g.Pkg.Pkg != nil {
								gPkg = g.Pkg.Pkg.Path()
							}
							if gPkg == "testing" || (harnessAudited && propharness.IsHarnessPath(gPkg)) {
								continue
							}
							if isStdPkgPath(userPaths, gPkg) && baseStartup != nil && !baseStartup.userTouchedStdGlobals[g] {
								continue
							}
							if typeCanCarryAnyInitBoxed(g.Type(), initBoxedTypes) {
								seedInitBoxedTypes(fn.Prog)
								break
							}
						}
					}
					if mi, isMI := instruction.(*ssa.MakeInterface); isMI && mi.X != nil {
						noteHarnessCandidateType(fn.Prog, mi.X.Type())
						continue
					}
				}
				site, ok := instruction.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				callee := site.Common().StaticCallee()
				if isTestingMRun(callee) {
					continue
				}
				if callee != nil {
					calleePath := funcPkgPath(callee)
					calleeHarness := calleePath == "testing" || harnessAudited && propharness.IsHarnessPath(calleePath)
					calleeIsStd := isStdPkgPath(userPaths, calleePath)
					calleeNonStdDispatch := false
					switch {
					case !calleeIsStd:
						calleeNonStdDispatch = true
					case !fnNonStdDispatch:
						calleeNonStdDispatch = false
					case fnIsStd:
						calleeNonStdDispatch = true
					case audited && !calleeHarness && (auditset.PurePackage(calleePath) || auditedStandardCallee(true, calleePath, functionSymbolName(callee), callee)) && isCarrierFreeStaticCall(audited, site, callee):
						calleeNonStdDispatch = false
					default:
						calleeNonStdDispatch = true
					}
					if calleeNonStdDispatch {
						canDispatchNonStd[callee] = true
					}
					if !harnessFrame || calleeHarness {
						queue = append(queue, callee)
					}
					if calleeHarness && !harnessFrame && !initFlowFrame(callee) {
						activateHarnessDispatchedMethods(fn.Prog)
						if mc, ok := site.Common().Value.(*ssa.MakeClosure); ok {
							for _, b := range mc.Bindings {
								if b != nil {
									noteHarnessCandidateType(fn.Prog, b.Type())
								}
							}
						}
						for _, arg := range site.Common().Args {
							if arg != nil {
								noteHarnessCandidateType(fn.Prog, arg.Type())
							}
						}
						for _, ta := range callee.TypeArgs() {
							noteHarnessCandidateType(fn.Prog, ta)
						}
						continue
					}
				}
				var closedSet map[*ssa.Function]bool
				if audited && !deferUnscannedClosures && !harnessFrame && !fnIsStd && callee == nil && len(result.Targets[site]) > 1 {
					fp := getProvFP()
					if site.Common().IsInvoke() {
						if set, ok := closedInvokeTargets(site, fp); ok && len(set) > 0 {
							closedSet = set
						}
					} else if set, ok := closedDynamicTargets(site.Common().Value, fp); ok && len(set) > 0 {
						closedSet = set
					}
				}
				enqueueSiteTargets := func(targets map[*ssa.Function]uint64) {
					for target, targetMask := range targets {
						if targetMask&mask == 0 || isTestingMRun(target) || isTestingBLaunch(target) {
							continue
						}
						if closedSet != nil && !closedSet[target] {
							continue
						}
						if dropTarget != nil && !harnessCandidateTargets[target] && dropTarget(site, target) {
							continue
						}
						targetPath := funcPkgPath(target)
						targetIsStd := isStdPkgPath(userPaths, targetPath)
						if !fnNonStdDispatch && !targetIsStd && !harnessCandidateTargets[target] {
							continue
						}
						targetHarness := targetPath == "testing" || harnessAudited && propharness.IsHarnessPath(targetPath)
						// User callbacks dispatched from harness frames stay
						// in the walk by the load's module facts, never by
						// path shape: a dotless user module's callback
						// classified standard here silently vanished from
						// the startup and test-main walks - the
						// dotless-module soundness family.
						if !harnessFrame || targetHarness || !targetIsStd {
							if !targetIsStd || fnNonStdDispatch {
								canDispatchNonStd[target] = true
							}
							if deferUnscannedClosures && target.Parent() != nil && target.Synthetic == "" && !scanned[target.Parent()] && !isTestingCleanupCallback(target) {
								pendingByParent[target.Parent()] = append(pendingByParent[target.Parent()], target)
								continue
							}
							queue = append(queue, target)
						}
					}
				}
				enqueueSiteTargets(result.Targets[site])
				if harnessFrame && !initFlowFrame(fn) && len(result.HarnessStdTargets) > 0 {
					enqueueSiteTargets(result.HarnessStdTargets[site])
				}
			}
		}
	}
	return reachable, usedInitBoxed, nil
}

// userModulePaths collects every loaded package path the module graph
// proves user code: both load configs request NeedModule, so in module
// mode a nil Module is exactly the standard library, and these paths
// are the code no path-shape heuristic may classify standard - a user
// module is legally named without a dot (the dotless-module soundness
// family).
func userModulePaths(pkgs []*packages.Package) map[string]bool {
	user := map[string]bool{}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.Module != nil {
			user[p.PkgPath] = true
		}
	})
	return user
}

// initFlowFrame reports whether a frame is initializer flow: the
// synthetic package initializer, a compiler-numbered user init body, or
// a function transitively parented under one. A function value whose
// every address-taking reference lies in such frames is init-planted -
// address-taken under every mask by the init roots, the one provenance
// an enumeration-closed subject's pinned operand set can never
// legitimately carry. Init-flow qualified helpers keep their masks -
// the boundary is the initializer itself.
func initFlowFrame(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	top := fn
	for top.Parent() != nil {
		top = top.Parent()
	}
	// A method named init is an ordinary function: only the synthetic
	// package initializer and the compiler-numbered user init bodies
	// qualify - classifying any other frame as initializer flow would
	// let the narrowing drop legitimate subject content, the unsound
	// direction.
	if top.Signature != nil && top.Signature.Recv() != nil {
		return false
	}
	name := top.Name()
	if name == "init" {
		return top.Synthetic == "package initializer"
	}
	if rest, ok := strings.CutPrefix(name, "init#"); ok {
		for _, r := range rest {
			if r < '0' || r > '9' {
				return false
			}
		}
		return rest != ""
	}
	return false
}
