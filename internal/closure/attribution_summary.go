package closure

import (
	"context"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/propharness"
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

type carrierMemoKey struct {
	value ssa.Value
	named *types.Named
	scope uint8
}

type carrierRootMemoEntry struct {
	closed      bool
	hasLeaf     bool
	usedSubject bool
	lowlink     int
}

type dynamicSeedEntry struct {
	types []types.Type
	funcs []*ssa.Function
}

type callerReferenceSummary struct {
	ctx                     context.Context
	wholeProgram            bool
	sites                   map[*ssa.Function][]ssa.CallInstruction
	allStaticSites          map[*ssa.Function][]ssa.CallInstruction
	harnessCallbackSites    map[*ssa.Function][]ssa.CallInstruction
	valueRef                map[*ssa.Function]bool
	directValueRef          map[*ssa.Function]bool
	valueRefOutsideInit     map[*ssa.Function]bool
	closures                map[*ssa.Function][]*ssa.MakeClosure
	nonClosureRef           map[*ssa.Function]bool
	strictLocalFunc         map[*ssa.Function]bool
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
	nonReadOnlyGlobals      map[*ssa.Global]bool
	mutatedGlobals          map[*ssa.Global]bool
	errorNewSentinelGlobals map[*ssa.Global]bool
	zeroCandidateGlobals    map[*ssa.Global]bool
	allFunctions            map[*ssa.Function]bool
	userPaths               map[string]bool
	pureDelegates           map[string]bool
	verifiedHarnesses       map[string]*propharness.VerifiedPackage

	progMemos                 [4]dynamicMemoTables
	enumMemos                 [4]dynamicMemoTables
	enumSeedsMemo             [2]map[ssa.Value]dynamicSeedEntry
	enumStructClosed          [2]map[*types.Named]bool
	userMutatesOSWrapperError bool
	prog                      *program
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

// enumerateCallerReferencesForProgram makes one deterministic pass over the
// analyzed program, collecting for each candidate root its direct static call
// sites and whether any other reference exists, while recording whole-program
// global read-only, mutation, sentinel, and startup-zero summaries.
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
	verified := verifiedHarnessesProg(audited, prog)
	var rootPkgPath string
	if prog != nil {
		rootPkgPath = prog.PkgPath
	}
	res := enumerateCallerReferencesWithOrdered(audited, verified, rootPkgPath, userPaths, all, ordered)
	res.wholeProgram = wholeProgram
	res.prog = prog
	res.pureDelegates = pureDelegates
	res.verifiedHarnesses = verified
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
	return enumerateCallerReferencesWithOrdered(audited, nil, "", userPaths, all, nil)
}

func enumerateCallerReferencesWithOrdered(audited bool, verifiedHarnesses map[string]*propharness.VerifiedPackage, rootPkgPath string, userPaths map[string]bool, all map[*ssa.Function]bool, ordered []*ssa.Function) *callerReferenceSummary {
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
		closures:               make(map[*ssa.Function][]*ssa.MakeClosure),
		nonClosureRef:          make(map[*ssa.Function]bool, largeCap),
		strictLocalFunc:        make(map[*ssa.Function]bool, smallCap),
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
		allFunctions:           all,
		userPaths:              userPaths,
		verifiedHarnesses:      verifiedHarnesses,
		progMemos:              *newDynamicMemoQuad(),
		enumMemos:              *newDynamicMemoQuad(),
		enumSeedsMemo: [2]map[ssa.Value]dynamicSeedEntry{
			make(map[ssa.Value]dynamicSeedEntry),
			make(map[ssa.Value]dynamicSeedEntry),
		},
		enumStructClosed: [2]map[*types.Named]bool{
			make(map[*types.Named]bool),
			make(map[*types.Named]bool),
		},
	}
	globalAcc := newProgramGlobalAccumulator(true, true, userPaths)
	var reflectState summaryReflectState
	reflectState.namedSigReferenced = make(map[*types.Named]bool)
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
	type candIfaceKey struct {
		cand  *ssa.Function
		iface *types.Interface
	}
	var implMemo map[candIfaceKey]bool
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
									globalAcc.record(fn, initFrame, instr, g)
								}
							}
						}
					}
				}
				continue
			}
		}
		fnIsPromotedWrapper := isPromotedWrapper(fn)
		fnIsBoundWrapper := isBoundMethodWrapper(fn)
		fnRecordCallSite := !fnIsPromotedWrapper && !(audited && fnIsBoundWrapper)
		fnRecordInvokeSite := !fnIsPromotedWrapper && !fnIsBoundWrapper
		judgeable := (fn.Synthetic == "" || fnIsPromotedWrapper || (audited && fn.Origin() != nil)) && !parameterizedBody(fn)
		structJudgeable := fn.Synthetic == "" || fnIsPromotedWrapper || (audited && fn.Origin() != nil)
		fnPkg := funcPkgPath(fn)
		nonStdFrame := !isStdPkgPath(userPaths, fnPkg)
		nonHarnessUserFrame := nonStdFrame && verifiedHarnesses[fnPkg] == nil
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
			summary.scanUserTypeParams(fn, structJudgeable, &reflectState)
		}
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				if audited && hasUserTypes {
					summary.scanUserTypeAndReflectInstr(audited, fn, instr, structJudgeable, nonHarnessUserFrame, &reflectState)
				}
				rands := instr.Operands(space[:0])
				for _, op := range rands {
					if op != nil && *op != nil {
						if g, ok := (*op).(*ssa.Global); ok {
							globalAcc.record(fn, initFrame, instr, g)
						}
					}
				}
				if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
					if isPotentialHarnessCallbackSite(site) {
						summary.harnessCallbackSites[fn] = append(summary.harnessCallbackSites[fn], site)
					}
					if callee := site.Common().StaticCallee(); callee != nil {
						summary.allStaticSites[callee] = append(summary.allStaticSites[callee], site)
						if site.Common().Value == callee || !judgeable {
							summary.nonClosureRef[callee] = true
						}
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
											summary.nonClosureRef[cand] = true
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
							summary.recordStructRef(named, fn)
						} else if g, isGlob := (*op).(*ssa.Global); isGlob {
							if ns := derefNamedSignature(userPaths, g.Type()); ns != nil {
								reflectState.recordNamedSigRef(ns)
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
							gSym := baseFunctionSymbolName(g)
							if gPkg == "os" && gSym == "NewSyscallError" {
								summary.userMutatesOSWrapperError = true
							}
							if gPkg == "reflect" {
								if isReflectMutationSymbol(gSym) {
									reflectState.reflectMutationFns = append(reflectState.reflectMutationFns, fn)
								}
								if gSym == "ValueOf" || isReflectOpenProducerSymbol(gSym) {
									reflectState.reflectOpenValueFns = append(reflectState.reflectOpenValueFns, fn)
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
	summary.nonReadOnlyGlobals = globalAcc.nonReadOnly
	summary.mutatedGlobals = globalAcc.mutated
	summary.errorNewSentinelGlobals = globalAcc.errorSentinels()
	summary.zeroCandidateGlobals = globalAcc.zeroCandidates()
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
			summary.poisonEmbeddedCarriers(audited, w.Signature.Recv().Type(), wTopNamed, w, &reflectState)
		}
		summary.poisonLiveReflectMutations(rootPkgPath, &reflectState)
		summary.resolveIndirectFuncSites(ordered, closureRefs, storeRefs, callArgRefs)
	}
	summary.propagateWrapperReferences(audited, ordered, methodsByName)
	return &summary
}

func (summary *callerReferenceSummary) resolveIndirectFuncSites(
	ordered []*ssa.Function,
	closureRefs map[*ssa.Function][]*ssa.MakeClosure,
	storeRefs map[*ssa.Function][]*ssa.Store,
	callArgRefs map[*ssa.Function][]ssa.CallInstruction,
) {
	userPaths := summary.userPaths
	structFieldReads := summary.structFieldReads
	var collectFuncValueCallSites func(val ssa.Value, seen map[ssa.Value]bool, strict *bool) ([]ssa.CallInstruction, bool)
	var collectStoreTargetCallSites func(addr ssa.Value, seen map[ssa.Value]bool, strict *bool) ([]ssa.CallInstruction, bool)
	collectStoreTargetCallSites = func(addr ssa.Value, seen map[ssa.Value]bool, strict *bool) ([]ssa.CallInstruction, bool) {
		if fa, ok := addr.(*ssa.FieldAddr); ok && fa.X != nil {
			if strict != nil {
				*strict = false
			}
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
					sub, ok := collectFuncValueCallSites(rd, seen, strict)
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
					sub, ok := collectFuncValueCallSites(r, seen, strict)
					if !ok {
						return nil, false
					}
					sites = append(sites, sub...)
				case *ssa.MakeClosure:
					cFn, ok := r.Fn.(*ssa.Function)
					if !ok || len(cFn.Blocks) == 0 || len(r.Bindings) != len(cFn.FreeVars) {
						return nil, false
					}
					if strict != nil && *strict {
						if initFlowFrame(cFn) || initFlowFrame(r.Parent()) {
							*strict = false
						} else if _, okOuter := collectFuncValueCallSites(r, seen, strict); !okOuter {
							*strict = false
						}
					}
					for i, b := range r.Bindings {
						if b == alloc {
							sub, ok := collectFuncValueCallSites(cFn.FreeVars[i], seen, strict)
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
	collectFuncValueCallSites = func(val ssa.Value, seen map[ssa.Value]bool, strict *bool) ([]ssa.CallInstruction, bool) {
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
				sub, ok := collectFuncValueCallSites(r, seen, strict)
				if !ok {
					return nil, false
				}
				sites = append(sites, sub...)
			case *ssa.ChangeType:
				if r.X != val {
					return nil, false
				}
				sub, ok := collectFuncValueCallSites(r, seen, strict)
				if !ok {
					return nil, false
				}
				sites = append(sites, sub...)
			case *ssa.UnOp:
				if r.Op != token.MUL || r.X != val {
					return nil, false
				}
				sub, ok := collectFuncValueCallSites(r, seen, strict)
				if !ok {
					return nil, false
				}
				sites = append(sites, sub...)
			case *ssa.MakeClosure:
				cFn, ok := r.Fn.(*ssa.Function)
				if !ok || len(cFn.Blocks) == 0 || len(r.Bindings) != len(cFn.FreeVars) {
					return nil, false
				}
				if strict != nil && *strict {
					if initFlowFrame(cFn) || initFlowFrame(r.Parent()) {
						*strict = false
					} else if _, okOuter := collectFuncValueCallSites(r, seen, strict); !okOuter {
						*strict = false
					}
				}
				for i, b := range r.Bindings {
					if b == val {
						sub, ok := collectFuncValueCallSites(cFn.FreeVars[i], seen, strict)
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
				sub, ok := collectStoreTargetCallSites(r.Addr, seen, strict)
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
						sub, ok := collectFuncValueCallSites(callee.Params[i], seen, strict)
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
		mcs := closureRefs[g]
		if !summary.nonClosureRef[g] && len(mcs) > 0 {
			summary.closures[g] = mcs
		}
		if summary.valueRef[g] {
			continue
		}
		sts := storeRefs[g]
		cas := callArgRefs[g]
		if len(mcs) == 0 && len(sts) == 0 && len(cas) == 0 {
			if g != nil && g.Synthetic == "" && !parameterizedBody(g) && !initFlowFrame(g) {
				summary.strictLocalFunc[g] = true
			}
			continue
		}
		var extraSites []ssa.CallInstruction
		okAll := true
		strictLocal := g != nil && g.Synthetic == "" && !parameterizedBody(g) && !initFlowFrame(g)
		for _, mc := range mcs {
			if mc.Parent() == nil || initFlowFrame(mc.Parent()) {
				strictLocal = false
			}
			sub, ok := collectFuncValueCallSites(mc, make(map[ssa.Value]bool), &strictLocal)
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
			if st.Parent() == nil || initFlowFrame(st.Parent()) {
				strictLocal = false
			}
			sub, ok := collectStoreTargetCallSites(st.Addr, make(map[ssa.Value]bool), &strictLocal)
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
			if site.Parent() == nil || initFlowFrame(site.Parent()) {
				strictLocal = false
			}
			callee := site.Common().StaticCallee()
			if callee == nil || len(callee.Blocks) == 0 || (callee.Synthetic != "" && !isPromotedWrapper(callee) && callee.Origin() == nil) || parameterizedBody(callee) || len(site.Common().Args) != len(callee.Params) {
				okAll = false
				break
			}
			for i, arg := range site.Common().Args {
				if arg == g {
					sub, ok := collectFuncValueCallSites(callee.Params[i], make(map[ssa.Value]bool), &strictLocal)
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
			if strictLocal {
				summary.strictLocalFunc[g] = true
			}
		}
	}
}

func dedupCallSites(sites []ssa.CallInstruction) []ssa.CallInstruction {
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

func (summary *callerReferenceSummary) propagateWrapperReferences(audited bool, ordered []*ssa.Function, methodsByName map[string][]*ssa.Function) {
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
}
