package dynstate

import (
	"go/ast"
	"go/types"
	"math"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type closureOutflowSummaries struct {
	returnEnvFree          map[string]bool
	returnEnvDeps          map[string]map[syntaxutil.FuncKey]bool
	returnEnvParamDeps     map[string]map[syntaxutil.ParamKey]bool
	returnEnvMethodDeps    map[string]map[syntaxutil.FuncKey]bool
	returnFieldDefer       map[string]map[syntaxutil.ReturnFieldParamDefer]bool
	returnFieldPoison      map[string]map[syntaxutil.ReturnFieldParamPoison]bool
	paramInsertionFree     map[syntaxutil.ParamKey]bool
	paramInsertionDeps     map[syntaxutil.ParamKey]map[syntaxutil.EnvAuditTarget]bool
	paramInsertionParams   map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool
	paramInsertionMethods  map[syntaxutil.ParamKey]map[syntaxutil.FuncKey]bool
	returnInsertionCallDep map[string]map[syntaxutil.EnvAuditTarget]bool
}

type resolvedInsertionState struct {
	poison     map[types.Object]bool
	uses       map[types.Object]map[syntaxutil.EnvAuditTarget]bool
	paramDeps  map[types.Object]map[syntaxutil.ParamKey]bool
	methodDeps map[types.Object]map[syntaxutil.FuncKey]bool
}

type outflowEvalCtx struct {
	insMode      bool
	resolved     resolvedInsertionState
	localFree    map[types.Object]int // 0 unknown, 2 free, 3 refused
	provingDepth map[types.Object]int
	curDepth     int
	fnDeps       map[syntaxutil.FuncKey]bool
	useDeps      map[syntaxutil.EnvAuditTarget]bool
	paramDeps    map[syntaxutil.ParamKey]bool
	methodDeps   map[syntaxutil.FuncKey]bool
	onRefusal    func(*flowir.Value)
}

func newOutflowEvalCtx(insMode bool, resolved resolvedInsertionState) *outflowEvalCtx {
	return &outflowEvalCtx{
		insMode:      insMode,
		resolved:     resolved,
		localFree:    map[types.Object]int{},
		provingDepth: map[types.Object]int{},
		fnDeps:       map[syntaxutil.FuncKey]bool{},
		useDeps:      map[syntaxutil.EnvAuditTarget]bool{},
		paramDeps:    map[syntaxutil.ParamKey]bool{},
		methodDeps:   map[syntaxutil.FuncKey]bool{},
	}
}

func (c *outflowEvalCtx) resetMemo() {
	clear(c.localFree)
	clear(c.provingDepth)
	c.curDepth = 0
}

func newObjectUnionFind(pairSets ...[][2]types.Object) func(types.Object) types.Object {
	roots := map[types.Object]types.Object{}
	var find func(types.Object) types.Object
	find = func(x types.Object) types.Object {
		r, ok := roots[x]
		if !ok || r == x {
			return x
		}
		root := find(r)
		roots[x] = root
		return root
	}
	for _, pairs := range pairSets {
		for _, pair := range pairs {
			a, b := find(pair[0]), find(pair[1])
			if a != b {
				roots[a] = b
			}
		}
	}
	return find
}

// analyzeClosureOutflowSummaries proves, per plain named function of the
// package, constructor-result environment freedom (ReturnEnvFree*) and
// parameter-insertion environment freedom (ParamInsertionFree*) in a single
// pass over each lowered function body.
func analyzeClosureOutflowSummaries(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	settledGlobals settledGlobalMap,
	pkgConf *packageConfinementSummary,
	hooks *syntaxutil.ExplainHookSet,
) closureOutflowSummaries {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return closureOutflowSummaries{}
	}
	ownPath := p.Types.Path()
	carries := refconfine.TypeCarriesSignature
	classifyWants := func(
		wants map[syntaxutil.ParamKey]bool,
		methodWants map[syntaxutil.FuncKey]bool,
		paramOut map[syntaxutil.ParamKey]bool,
		methodOut map[syntaxutil.FuncKey]bool,
	) bool {
		for want := range wants {
			provenLocal, conditional := pkgConf.classifyParam(ownPath, want)
			if !provenLocal && (!conditional || paramOut == nil) {
				return false
			}
		}
		for want := range methodWants {
			provenLocal, conditional := pkgConf.classifyMethod(ownPath, want)
			if !provenLocal && (!conditional || methodOut == nil) {
				return false
			}
		}
		for want := range wants {
			provenLocal, _ := pkgConf.classifyParam(ownPath, want)
			if !provenLocal {
				paramOut[want] = true
			}
		}
		for want := range methodWants {
			provenLocal, _ := pkgConf.classifyMethod(ownPath, want)
			if !provenLocal {
				methodOut[want] = true
			}
		}
		return true
	}
	sharesHeader := func(t types.Type) bool {
		if t == nil {
			return true
		}
		if tup, ok := types.Unalias(t).(*types.Tuple); ok && tup.Len() > 0 {
			t = tup.At(0).Type()
		}
		switch types.Unalias(t).Underlying().(type) {
		case *types.Struct, *types.Array, *types.Basic:
			return false
		}
		return true
	}
	reachOrAddrOrStr := func(t types.Type) bool {
		return refconfine.TypeHandsOutMutableReach(t) || syntaxutil.ContainsUintptr(t)
	}
	elemReach := func(t types.Type) bool {
		if t == nil {
			return true
		}
		switch u := types.Unalias(t).Underlying().(type) {
		case *types.Slice:
			return reachOrAddrOrStr(u.Elem())
		case *types.Array:
			return reachOrAddrOrStr(u.Elem())
		case *types.Map:
			return reachOrAddrOrStr(u.Key()) || reachOrAddrOrStr(u.Elem())
		}
		return true
	}

	proven := map[string]bool{}
	deps := map[string]map[syntaxutil.FuncKey]bool{}
	retParamDeps := map[string]map[syntaxutil.ParamKey]bool{}
	retMethodDeps := map[string]map[syntaxutil.FuncKey]bool{}
	retDefer := map[string]map[syntaxutil.ReturnFieldParamDefer]bool{}
	retPoison := map[string]map[syntaxutil.ReturnFieldParamPoison]bool{}
	insFree := map[syntaxutil.ParamKey]bool{}
	insDeps := map[syntaxutil.ParamKey]map[syntaxutil.EnvAuditTarget]bool{}
	insParamDeps := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	insMethodDeps := map[syntaxutil.ParamKey]map[syntaxutil.FuncKey]bool{}
	callerInsDeps := map[string]map[syntaxutil.EnvAuditTarget]bool{}

	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil || fd.Body == nil || fd.Name.Name == "init" {
				continue
			}
			body := fc.funcBody(p, fd)
			if body == nil {
				continue
			}
			fnKey := fd.Name.Name
			ownFuncKey := syntaxutil.FuncKey{Pkg: ownPath, Name: fnKey}

			params := map[types.Object]bool{}
			paramIndex := map[types.Object]int{}
			paramCount := 0
			if fd.Type.Params != nil {
				for _, field := range fd.Type.Params.List {
					if len(field.Names) == 0 {
						insFree[syntaxutil.ParamKey{Func: ownFuncKey, Index: paramCount}] = true
						paramCount++
						continue
					}
					for _, name := range field.Names {
						if obj := p.TypesInfo.Defs[name]; obj != nil && name.Name != "_" {
							params[obj] = true
							paramIndex[obj] = paramCount
						} else {
							insFree[syntaxutil.ParamKey{Func: ownFuncKey, Index: paramCount}] = true
						}
						paramCount++
					}
				}
			}

			localSources := map[types.Object][]*flowir.Value{}
			directBinds := map[types.Object][]*flowir.Value{}
			hasZeroDecl := map[types.Object]bool{}
			rangeBound := map[types.Object]bool{}
			hasSpreadAppend := map[types.Object]bool{}
			writeSources := map[types.Object][]*flowir.Value{}
			insertionWrites := map[types.Object][]*flowir.Value{}
			localBroken := map[types.Object]bool{}
			paramRebound := map[types.Object]bool{}
			captureBroken := map[types.Object]bool{}
			var aliasPairs [][2]types.Object
			var heldPairs [][2]types.Object
			stmtCallDeps := map[syntaxutil.FuncKey]bool{}
			rawObjParamDeps := map[types.Object]map[syntaxutil.ParamKey]bool{}
			rawObjMethodDeps := map[types.Object]map[syntaxutil.FuncKey]bool{}

			trackedVar := func(obj types.Object) (*types.Var, bool) {
				if !syntaxutil.IsLocalVar(obj) {
					return nil, false
				}
				v := obj.(*types.Var)
				if !carries(v.Type()) &&
					!refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) &&
					!reachOrAddrOrStr(v.Type()) {
					return nil, false
				}
				return v, true
			}

			var breakValueVars func(v *flowir.Value, capture bool, gate func(types.Object) bool)
			breakObj := func(obj types.Object, capture bool, gate func(types.Object) bool) {
				if obj == nil {
					return
				}
				if _, ok := trackedVar(obj); (ok || params[obj]) && (gate == nil || gate(obj)) {
					localBroken[obj] = true
					if capture {
						captureBroken[obj] = true
					}
				}
			}
			breakValueVars = func(v *flowir.Value, capture bool, gate func(types.Object) bool) {
				if v == nil {
					return
				}
				v.WalkValues(func(cur *flowir.Value) bool {
					switch cur.Kind {
					case flowir.ValPlace:
						breakObj(cur.Place.Obj, capture, gate)
					case flowir.ValAddrOf:
						breakObj(cur.AddrPlace.Obj, capture, gate)
					case flowir.ValMethodVal:
						if cur.HasRecvPlace {
							breakObj(cur.RecvPlace.Obj, capture, gate)
						}
					case flowir.ValMakeClosure:
						if cur.Closure != nil {
							for fv := range cur.Closure.FreeVars {
								breakObj(fv, capture, gate)
							}
						}
					case flowir.ValCall:
						if cur.AutoAddrRecv && cur.HasRecvPlace {
							breakObj(cur.RecvPlace.Obj, capture, gate)
						}
						if cur.CallKind == flowir.CallIIFE && cur.IIFE != nil {
							for fv := range cur.IIFE.FreeVars {
								breakObj(fv, capture, gate)
							}
						}
					}
					return true
				})
			}
			breakPlaceBase := func(pl flowir.Place, capture bool) {
				if pl.Obj != nil {
					breakObj(pl.Obj, capture, nil)
					return
				}
				if pl.Root == flowir.RootTransient && pl.Base != nil {
					breakValueVars(pl.Base, capture, nil)
				}
			}
			breakTargets := func(v *flowir.Value) {
				breakValueVars(v, true, nil)
			}

			pairLink := func(obj, sobj types.Object, shares bool) {
				if obj == nil || sobj == nil {
					return
				}
				if v, ok := sobj.(*types.Var); ok && v.IsField() {
					return
				}
				_, tracked := trackedVar(sobj)
				if !tracked || !reachOrAddrOrStr(sobj.Type()) {
					return
				}
				if shares {
					aliasPairs = append(aliasPairs, [2]types.Object{obj, sobj})
				} else {
					heldPairs = append(heldPairs, [2]types.Object{obj, sobj})
				}
			}

			var linkBacking func(obj types.Object, src *flowir.Value)
			linkPlaceValue := func(obj types.Object, pl flowir.Place, valType types.Type, shares bool) {
				if pl.Obj != nil {
					pairLink(obj, pl.Obj, shares && sharesHeader(valType))
					return
				}
				if pl.Root == flowir.RootTransient && pl.Base != nil {
					pl.Base.WalkValues(func(cur *flowir.Value) bool {
						if cur.Kind == flowir.ValPlace && cur.Place.Obj != nil {
							pairLink(obj, cur.Place.Obj, true)
						} else if cur.Kind == flowir.ValAddrOf && cur.AddrPlace.Obj != nil {
							pairLink(obj, cur.AddrPlace.Obj, true)
						}
						return true
					})
				}
			}
			linkBacking = func(obj types.Object, src *flowir.Value) {
				if src == nil {
					return
				}
				switch src.Kind {
				case flowir.ValPlace:
					linkPlaceValue(obj, src.Place, src.Type, true)
				case flowir.ValAddrOf:
					if src.AddrPlace.Obj != nil {
						pairLink(obj, src.AddrPlace.Obj, true)
					} else if src.AddrPlace.Root == flowir.RootTransient {
						linkBacking(obj, src.AddrPlace.Base)
					}
				case flowir.ValMethodVal:
					if src.AutoAddr && src.HasRecvPlace && src.RecvPlace.Obj != nil {
						pairLink(obj, src.RecvPlace.Obj, true)
					}
					linkBacking(obj, src.Recv)
				case flowir.ValAllocFresh:
					switch src.AllocKind {
					case flowir.AllocMake, flowir.AllocBuiltinNewType:
						return
					case flowir.AllocBuiltinNewExpr:
						for _, a := range src.Args {
							linkBacking(obj, a)
						}
					case flowir.AllocCompositeLit:
						for i := range src.CompositeElts {
							linkBacking(obj, src.CompositeElts[i].MapKey)
							linkBacking(obj, src.CompositeElts[i].Value)
						}
					}
				case flowir.ValConvert:
					linkBacking(obj, src.Arg)
				case flowir.ValCall:
					if src.CallKind == flowir.CallBuiltin {
						switch src.BuiltinName {
						case "len", "cap", "Sizeof", "Alignof", "Offsetof":
							return
						case "Slice", "SliceData", "String", "StringData":
							if len(src.Args) > 0 {
								linkBacking(obj, src.Args[0])
							}
							return
						case "append":
							if len(src.Args) > 0 {
								if src.Args[0].Kind == flowir.ValPlace {
									linkPlaceValue(obj, src.Args[0].Place, src.Args[0].Type, true)
								} else {
									linkBacking(obj, src.Args[0])
								}
								for _, a := range src.Args[1:] {
									linkBacking(obj, a)
								}
							}
							return
						}
					}
					if src.AutoAddrRecv && src.HasRecvPlace && src.RecvPlace.Obj != nil {
						pairLink(obj, src.RecvPlace.Obj, true)
					}
					linkBacking(obj, src.Recv)
					linkBacking(obj, src.Callee)
					for _, a := range src.Args {
						linkBacking(obj, a)
					}
				case flowir.ValChanRecv:
					linkBacking(obj, src.Chan)
				case flowir.ValScalarLitOrConst, flowir.ValMakeClosure:
					return
				case flowir.ValCompositeExpr:
					for _, a := range src.Args {
						linkBacking(obj, a)
					}
				}
			}

			var pendingStores []outflowPendingStore
			var pendingAppendSlices []outflowPendingStore
			type insertionUse struct {
				call        *flowir.Value
				root        types.Object
				calleeParam syntaxutil.ParamKey
				args        []*flowir.Value
			}
			var pendingInsertionUses []insertionUse

			bindPlace := func(dst flowir.Place, src *flowir.Value, broken bool, isZeroDecl bool) {
				if dst.IsBlank() {
					return
				}
				if !dst.IsBareVar() {
					if !broken && src != nil && dst.Obj != nil {
						if _, tracked := trackedVar(dst.Obj); tracked {
							if _, keyVal, isMapW := dst.AsMapWrite(); isMapW && keyVal != nil {
								pendingStores = append(pendingStores, outflowPendingStore{robj: dst.Obj, place: dst, source: keyVal, isMapKey: true})
							}
							pendingStores = append(pendingStores, outflowPendingStore{robj: dst.Obj, place: dst, source: src})
							return
						}
					}
					breakPlaceBase(dst, true)
					if src != nil {
						breakValueVars(src, true, func(o types.Object) bool {
							return reachOrAddrOrStr(o.Type())
						})
					}
					return
				}
				obj := dst.Obj
				if obj != nil && params[obj] {
					paramRebound[obj] = true
					localBroken[obj] = true
					linkBacking(obj, src)
					return
				}
				if _, ok := trackedVar(obj); !ok {
					if src != nil && (dst.Root == flowir.RootPkgGlobal || dst.Root == flowir.RootOuterVar || dst.Root == flowir.RootTransient) {
						breakValueVars(src, true, func(o types.Object) bool {
							return reachOrAddrOrStr(o.Type())
						})
					}
					return
				}
				if isZeroDecl {
					hasZeroDecl[obj] = true
					return
				}
				if broken || src == nil {
					localBroken[obj] = true
					return
				}
				if src.Kind == flowir.ValCall && src.CallKind == flowir.CallBuiltin &&
					src.BuiltinName == "append" && len(src.Args) > 0 &&
					src.Args[0] != nil && src.Args[0].Kind == flowir.ValPlace &&
					src.Args[0].Place.IsBareVar() && src.Args[0].Place.Obj == obj {
					linkBacking(obj, src)
					directBinds[obj] = append(directBinds[obj], src)
					localSources[obj] = append(localSources[obj], src.Args[1:]...)
					return
				}
				linkBacking(obj, src)
				directBinds[obj] = append(directBinds[obj], src)
				localSources[obj] = append(localSources[obj], src)
			}

			collectMutableArgRoots := func(arg *flowir.Value) map[types.Object]bool {
				roots := map[types.Object]bool{}
				if arg == nil || (arg.Type != nil && !reachOrAddrOrStr(arg.Type)) {
					return roots
				}
				var walk func(v *flowir.Value)
				walk = func(v *flowir.Value) {
					if v == nil {
						return
					}
					isStrBuiltin := v.Kind == flowir.ValCall && v.CallKind == flowir.CallBuiltin &&
						(v.BuiltinName == "String" || v.BuiltinName == "StringData")
					if !isStrBuiltin && v.Kind != flowir.ValAddrOf && v.Type != nil && !reachOrAddrOrStr(v.Type) {
						return
					}
					switch v.Kind {
					case flowir.ValPlace:
						if v.Place.Obj != nil {
							if _, tr := trackedVar(v.Place.Obj); (tr || params[v.Place.Obj]) && reachOrAddrOrStr(v.Place.Obj.Type()) {
								roots[v.Place.Obj] = true
							}
						} else if v.Place.Root == flowir.RootTransient {
							walk(v.Place.Base)
						}
					case flowir.ValAddrOf:
						if v.AddrPlace.Obj != nil {
							if _, tr := trackedVar(v.AddrPlace.Obj); tr || params[v.AddrPlace.Obj] {
								roots[v.AddrPlace.Obj] = true
							}
						} else if v.AddrPlace.Root == flowir.RootTransient {
							walk(v.AddrPlace.Base)
						}
					case flowir.ValAllocFresh:
						switch v.AllocKind {
						case flowir.AllocBuiltinNewExpr:
							for _, a := range v.Args {
								walk(a)
							}
						case flowir.AllocCompositeLit:
							for i := range v.CompositeElts {
								walk(v.CompositeElts[i].MapKey)
								walk(v.CompositeElts[i].Value)
							}
						}
					case flowir.ValConvert:
						walk(v.Arg)
					case flowir.ValCall:
						if v.CallKind == flowir.CallBuiltin {
							switch v.BuiltinName {
							case "len", "cap", "Sizeof", "Alignof", "Offsetof":
								return
							case "Slice", "SliceData", "String", "StringData":
								if len(v.Args) > 0 {
									walk(v.Args[0])
								}
								return
							case "append":
								for _, a := range v.Args {
									walk(a)
								}
								return
							}
						}
						walk(v.Recv)
						for _, a := range v.Args {
							walk(a)
						}
					}
				}
				walk(arg)
				return roots
			}

			var scanValueEffects func(v *flowir.Value)
			scanValueEffects = func(v *flowir.Value) {
				if v == nil {
					return
				}
				switch v.Kind {
				case flowir.ValConvert:
					if v.Arg != nil && (syntaxutil.IsUnsafePointerType(v.Arg.Type) ||
						(syntaxutil.IsUnsafePointerType(v.Type) && syntaxutil.ContainsUintptr(v.Arg.Type))) {
						breakTargets(v.Arg)
					}
				case flowir.ValAddrOf:
					breakPlaceBase(v.AddrPlace, true)
				case flowir.ValChanRecv:
					breakTargets(v.Chan)
				case flowir.ValMethodVal:
					if v.Method != nil {
						if sig, ok := v.Method.Type().(*types.Signature); ok && sig.Recv() != nil {
							_, ptr := types.Unalias(sig.Recv().Type()).(*types.Pointer)
							if ptr || v.AutoAddr || sharesHeader(sig.Recv().Type()) || reachOrAddrOrStr(sig.Recv().Type()) {
								if v.AutoAddr && v.HasRecvPlace {
									breakPlaceBase(v.RecvPlace, true)
								}
								breakTargets(v.Recv)
							}
						} else {
							if v.AutoAddr && v.HasRecvPlace {
								breakPlaceBase(v.RecvPlace, true)
							}
							breakTargets(v.Recv)
						}
					} else {
						if v.AutoAddr && v.HasRecvPlace {
							breakPlaceBase(v.RecvPlace, true)
						}
						breakTargets(v.Recv)
					}
				case flowir.ValMakeClosure:
					if v.Closure != nil && v.Lit != nil && v.Lit.Body != nil {
						for fv := range v.Closure.FreeVars {
							if _, tr := trackedVar(fv); !tr && !params[fv] {
								continue
							}
							wants := map[syntaxutil.ParamKey]bool{}
							mw := map[syntaxutil.FuncKey]bool{}
							fvParams := map[syntaxutil.ParamKey]bool{}
							fvMethods := map[syntaxutil.FuncKey]bool{}
							if !boundValueClosureEnvLeakFreeJudged(audited, p, fc, map[types.Object]bool{fv: true}, v.Lit.Body, wants, mw) ||
								!classifyWants(wants, mw, fvParams, fvMethods) {
								localBroken[fv] = true
								captureBroken[fv] = true
								continue
							}
							if len(fvParams) > 0 {
								if rawObjParamDeps[fv] == nil {
									rawObjParamDeps[fv] = map[syntaxutil.ParamKey]bool{}
								}
								for pk := range fvParams {
									rawObjParamDeps[fv][pk] = true
								}
							}
							if len(fvMethods) > 0 {
								if rawObjMethodDeps[fv] == nil {
									rawObjMethodDeps[fv] = map[syntaxutil.FuncKey]bool{}
								}
								for mk := range fvMethods {
									rawObjMethodDeps[fv][mk] = true
								}
							}
						}
					}
					return
				case flowir.ValCall:
					switch v.CallKind {
					case flowir.CallBuiltin:
						switch {
						case v.BuiltinName == "Sizeof" || v.BuiltinName == "Alignof" || v.BuiltinName == "Offsetof":
							return
						case v.BuiltinName == "StringData" || v.BuiltinName == "String" || v.BuiltinName == "Slice" || v.BuiltinName == "SliceData" || v.BuiltinName == "Add":
							for _, a := range v.Args {
								breakTargets(a)
							}
						case v.BuiltinName == "copy" && len(v.Args) == 2:
							if v.Args[0] != nil && v.Args[0].Kind == flowir.ValPlace {
								breakPlaceBase(v.Args[0].Place, true)
								bindPlace(v.Args[0].Place, nil, true, false)
							}
							breakTargets(v.Args[0])
							if v.Args[0] == nil || v.Args[0].Type == nil || elemReach(v.Args[0].Type) {
								breakValueVars(v.Args[1], true, func(o types.Object) bool {
									return reachOrAddrOrStr(o.Type())
								})
							}
						case v.BuiltinName == "append" && len(v.Args) >= 2:
							base := v.Args[0]
							freshBase := base != nil && (base.Kind == flowir.ValScalarLitOrConst ||
								base.Kind == flowir.ValPlace && base.Place.Root == flowir.RootConstOrNil ||
								base.Kind == flowir.ValAllocFresh && (base.AllocKind == flowir.AllocMake || base.AllocKind == flowir.AllocBuiltinNewType || base.AllocKind == flowir.AllocCompositeLit) ||
								isPureFreshDataValueWith(base, nil))
							if !freshBase {
								unwrapSlicePlace := func(cur *flowir.Value) (flowir.Place, bool) {
									for cur != nil {
										if cur.Kind == flowir.ValConvert && !cur.IsTypeAssert && cur.Arg != nil && cur.Arg.Type != nil {
											if _, isSlice := types.Unalias(cur.Arg.Type).Underlying().(*types.Slice); isSlice {
												cur = cur.Arg
												continue
											}
										}
										break
									}
									if cur == nil {
										return flowir.Place{}, false
									}
									if cur.Kind == flowir.ValAddrOf && cur.IsArraySlice && cur.AddrPlace.Obj != nil {
										return cur.AddrPlace, true
									}
									if cur.Kind != flowir.ValPlace || cur.Place.Obj == nil {
										return flowir.Place{}, false
									}
									pl := cur.Place
									for len(pl.Projs) > 0 {
										last := pl.Projs[len(pl.Projs)-1]
										if last.Kind != flowir.ProjSlice || last.BaseType == nil {
											break
										}
										okSlice := false
										switch u := types.Unalias(last.BaseType).Underlying().(type) {
										case *types.Slice, *types.Array:
											okSlice = true
										case *types.Pointer:
											if _, isArr := types.Unalias(u.Elem()).Underlying().(*types.Array); isArr {
												okSlice = true
											}
										}
										if !okSlice {
											break
										}
										pl.Projs = pl.Projs[:len(pl.Projs)-1]
									}
									return pl, true
								}
								if slicePlace, ok := unwrapSlicePlace(base); ok {
									baseObj := slicePlace.Obj
									if _, tr := trackedVar(baseObj); tr || params[baseObj] {
										if v.Ellipsis {
											hasSpreadAppend[baseObj] = true
										}
										if slicePlace.IsBareVar() {
											for _, elem := range v.Args[1:] {
												insertionWrites[baseObj] = append(insertionWrites[baseObj], elem)
												linkBacking(baseObj, elem)
											}
										} else {
											for _, elem := range v.Args[1:] {
												pendingAppendSlices = append(pendingAppendSlices, outflowPendingStore{
													robj:   baseObj,
													place:  slicePlace,
													source: elem,
												})
											}
										}
									} else {
										breakPlaceBase(slicePlace, true)
										for _, elem := range v.Args[1:] {
											breakValueVars(elem, true, func(o types.Object) bool {
												return reachOrAddrOrStr(o.Type())
											})
										}
									}
								} else {
									breakTargets(base)
									for _, elem := range v.Args[1:] {
										breakValueVars(elem, true, func(o types.Object) bool {
											return reachOrAddrOrStr(o.Type())
										})
									}
								}
							}
						}
					case flowir.CallPlain:
						if v.CalleeFunc == nil || v.IsMethodExprCall {
							breakTargets(v.Callee)
							for _, a := range v.Args {
								breakTargets(a)
							}
							break
						}
						calleeFK := syntaxutil.FuncKey{Pkg: v.CalleePkg, Name: v.CalleeFunc.Name()}
						if !auditset.ValuePlaneClone(calleeFK.Pkg, calleeFK.Name) {
							reaches := carries(v.Type)
							for _, arg := range v.Args {
								if reaches {
									break
								}
								arg.WalkValues(func(cur *flowir.Value) bool {
									if cur.Kind == flowir.ValPlace && cur.Place.Obj != nil {
										if _, tr := trackedVar(cur.Place.Obj); tr || params[cur.Place.Obj] {
											reaches = true
											return false
										}
									}
									return !reaches
								})
							}
							if reaches {
								stmtCallDeps[calleeFK] = true
							}

							// Link or reject co-arguments sharing mutable reach across non-audited calls.
							perArgRoots := make([]map[types.Object]bool, len(v.Args))
							for i, arg := range v.Args {
								perArgRoots[i] = collectMutableArgRoots(arg)
							}
							for i := 0; i < len(perArgRoots); i++ {
								for j := i + 1; j < len(perArgRoots); j++ {
									for r1 := range perArgRoots[i] {
										for r2 := range perArgRoots[j] {
											if r1 == r2 {
												localBroken[r1] = true
												captureBroken[r1] = true
											} else {
												pairLink(r1, r2, true)
											}
										}
									}
								}
							}

							breakReachIn := func(val *flowir.Value) {
								breakValueVars(val, true, func(obj types.Object) bool {
									return reachOrAddrOrStr(obj.Type())
								})
							}
							var classifyLit func(elts []flowir.CompositeElt)
							classifyLit = func(elts []flowir.CompositeElt) {
								for i := range elts {
									for _, part := range []*flowir.Value{elts[i].MapKey, elts[i].Value} {
										if part == nil || (part.Type != nil && !reachOrAddrOrStr(part.Type)) {
											continue
										}
										switch part.Kind {
										case flowir.ValAllocFresh:
											switch part.AllocKind {
											case flowir.AllocMake, flowir.AllocBuiltinNewType:
											case flowir.AllocBuiltinNewExpr:
												for _, a := range part.Args {
													breakReachIn(a)
												}
											case flowir.AllocCompositeLit:
												classifyLit(part.CompositeElts)
											}
										case flowir.ValScalarLitOrConst, flowir.ValMakeClosure:
										default:
											breakReachIn(part)
										}
									}
								}
							}
							var classifyArg func(arg *flowir.Value, calleeParam syntaxutil.ParamKey, callArgs []*flowir.Value)
							classifyArg = func(arg *flowir.Value, calleeParam syntaxutil.ParamKey, callArgs []*flowir.Value) {
								if arg == nil || (arg.Type != nil && !reachOrAddrOrStr(arg.Type)) {
									return
								}
								switch arg.Kind {
								case flowir.ValPlace:
									if arg.Place.Obj != nil {
										obj := arg.Place.Obj
										_, tracked := trackedVar(obj)
										if (tracked || params[obj]) && reachOrAddrOrStr(obj.Type()) {
											pendingInsertionUses = append(pendingInsertionUses, insertionUse{
												call:        v,
												root:        obj,
												calleeParam: calleeParam,
												args:        callArgs,
											})
										}
										return
									}
									breakReachIn(arg)
								case flowir.ValAllocFresh:
									switch arg.AllocKind {
									case flowir.AllocMake, flowir.AllocBuiltinNewType:
										return
									case flowir.AllocBuiltinNewExpr:
										for _, a := range arg.Args {
											classifyArg(a, calleeParam, callArgs)
										}
									case flowir.AllocCompositeLit:
										classifyLit(arg.CompositeElts)
									}
								case flowir.ValAddrOf:
									// &place on a variable was already broken by ValAddrOf; nothing additional needed.
									if arg.AddrPlace.Root == flowir.RootTransient {
										breakReachIn(arg.AddrPlace.Base)
									}
								case flowir.ValScalarLitOrConst, flowir.ValMakeClosure:
								case flowir.ValConvert:
									if arg.IsTypeAssert {
										breakReachIn(arg)
										return
									}
									classifyArg(arg.Arg, calleeParam, callArgs)
								case flowir.ValCall:
									switch arg.CallKind {
									case flowir.CallBuiltin:
										switch arg.BuiltinName {
										case "append":
											for ai, a := range arg.Args {
												if ai == len(arg.Args)-1 && arg.Ellipsis && a != nil && a.Type != nil {
													if sl, ok := types.Unalias(a.Type).Underlying().(*types.Slice); ok &&
														!reachOrAddrOrStr(sl.Elem()) {
														continue
													}
												}
												classifyArg(a, calleeParam, callArgs)
											}
											return
										default:
											breakReachIn(arg)
											return
										}
									case flowir.CallPlain:
										if arg.CalleeFunc != nil && !arg.IsMethodExprCall {
											if auditset.ValuePlaneClone(arg.CalleePkg, arg.CalleeFunc.Name()) && !elemReach(arg.Type) {
												return
											}
										}
										breakReachIn(arg)
									default:
										breakReachIn(arg)
									}
								default:
									breakReachIn(arg)
								}
							}
							v.ForEachArgParam(func(arg *flowir.Value, slotType types.Type, slotIdx int, pIdx int, pOK bool, _ bool) bool {
								if slotType != nil && !refconfine.CallResultHandsOut(slotType) {
									return true
								}
								idx := slotIdx
								if pOK {
									idx = pIdx
								}
								classifyArg(arg, syntaxutil.ParamKey{Func: calleeFK, Index: idx}, v.Args)
								return true
							})
						}
					case flowir.CallMethod:
						for _, a := range v.Args {
							breakTargets(a)
						}
						recvExempt := false
						var deferredRecvMethod syntaxutil.FuncKey
						if !v.IsMethodExprCall && v.CalleeFunc != nil && !syntaxutil.InterfaceReceiver(v.CalleeFunc) &&
							v.Selection != nil && refconfine.InstantiatedResultsHandOutNothing(audited, v.Selection.Type()) {
							if sig, ok := v.CalleeFunc.Type().(*types.Signature); ok && sig.Recv() != nil {
								_, ptr := types.Unalias(sig.Recv().Type()).(*types.Pointer)
								if !ptr && !v.AutoAddrRecv && !sharesHeader(sig.Recv().Type()) &&
									!refconfine.CallResultHandsOut(sig.Recv().Type()) {
									recvExempt = true
								}
							}
							if !recvExempt {
								mk := syntaxutil.MethodFactKey(v.CalleeFunc)
								provenLocal, conditional := pkgConf.classifyMethod(ownPath, mk)
								if provenLocal {
									recvExempt = true
								} else if conditional {
									deferredRecvMethod = mk
								}
							}
						}
						if !recvExempt && deferredRecvMethod.Valid() {
							var recvPl flowir.Place
							hasRecvPl := false
							if v.AutoAddrRecv && v.HasRecvPlace {
								recvPl = v.RecvPlace
								hasRecvPl = true
							} else {
								cur := v.Recv
								for cur != nil && cur.Kind == flowir.ValConvert && !cur.IsTypeAssert {
									cur = cur.Arg
								}
								if cur != nil && cur.Kind == flowir.ValPlace {
									recvPl = cur.Place
									hasRecvPl = true
								}
							}
							if hasRecvPl && recvPl.Obj != nil {
								if _, tr := trackedVar(recvPl.Obj); tr || params[recvPl.Obj] {
									recvPl.ForEachChildValue(func(cv *flowir.Value) bool {
										breakTargets(cv)
										return true
									})
									if rawObjMethodDeps[recvPl.Obj] == nil {
										rawObjMethodDeps[recvPl.Obj] = map[syntaxutil.FuncKey]bool{}
									}
									rawObjMethodDeps[recvPl.Obj][deferredRecvMethod] = true
									recvExempt = true
								}
							}
						}
						if !recvExempt {
							if v.AutoAddrRecv && v.HasRecvPlace {
								breakPlaceBase(v.RecvPlace, true)
							}
							breakTargets(v.Recv)
						}
					default:
						if v.AutoAddrRecv && v.HasRecvPlace {
							breakPlaceBase(v.RecvPlace, true)
						}
						breakTargets(v.Recv)
						breakTargets(v.Callee)
						for _, a := range v.Args {
							breakTargets(a)
						}
						if v.CallKind == flowir.CallIIFE && v.IIFE != nil {
							for fv := range v.IIFE.FreeVars {
								breakObj(fv, true, nil)
							}
						}
					}
				}
				v.ForEachChildValue(func(ch *flowir.Value) bool {
					scanValueEffects(ch)
					return true
				})
			}

			body.ForEachSyncOp(func(op *flowir.Op) bool {
				switch op.Kind {
				case flowir.OpAssign:
					for i := range op.Dsts {
						op.Dsts[i].ForEachChildValue(func(cv *flowir.Value) bool {
							scanValueEffects(cv)
							return true
						})
					}
					for _, src := range op.Srcs {
						scanValueEffects(src)
					}
					switch op.AssignKind {
					case flowir.AssignZeroDecl:
						for _, dst := range op.Dsts {
							bindPlace(dst, nil, false, true)
						}
					case flowir.AssignIncDec, flowir.AssignCompound:
						for _, dst := range op.Dsts {
							if _, keyVal, isMapW := dst.AsMapWrite(); isMapW && keyVal != nil && dst.Obj != nil {
								if _, tr := trackedVar(dst.Obj); tr {
									pendingStores = append(pendingStores, outflowPendingStore{robj: dst.Obj, place: dst, source: keyVal, isMapKey: true})
								}
							}
							bindPlace(dst, nil, true, false)
						}
					case flowir.AssignRange:
						var rangeSrc *flowir.Value
						if len(op.Srcs) == 1 {
							rangeSrc = op.Srcs[0]
						}
						container := false
						if rangeSrc != nil && rangeSrc.Type != nil {
							switch u := types.Unalias(rangeSrc.Type).Underlying().(type) {
							case *types.Slice, *types.Array, *types.Map, *types.Basic:
								container = true
							case *types.Pointer:
								_, isArr := types.Unalias(u.Elem()).Underlying().(*types.Array)
								container = isArr
							case *types.Chan:
								breakTargets(rangeSrc)
							}
						}
						for _, dst := range op.Dsts {
							if dst.IsBareVar() && dst.Obj != nil {
								rangeBound[dst.Obj] = true
							}
							if container {
								bindPlace(dst, rangeSrc, false, false)
							} else {
								bindPlace(dst, nil, true, false)
							}
						}
					default:
						op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
							bindPlace(dst, src, src == nil, false)
							return true
						})
					}
				case flowir.OpTypeSwitchBind:
					scanValueEffects(op.SwitchSrc)
					if op.SwitchDst != nil {
						srcVal := op.SwitchSrc
						if srcVal != nil && op.SwitchDst.Type() != nil &&
							(srcVal.Type == nil || !types.Identical(op.SwitchDst.Type(), srcVal.Type)) {
							srcVal = &flowir.Value{
								Kind:         flowir.ValConvert,
								Type:         op.SwitchDst.Type(),
								Raw:          srcVal.Raw,
								Arg:          srcVal,
								IsTypeAssert: true,
							}
						}
						bindPlace(flowir.Place{
							Root: flowir.RootLocal,
							Obj:  op.SwitchDst,
							Type: op.SwitchDst.Type(),
						}, srcVal, srcVal == nil, false)
					}
				case flowir.OpChanSend:
					breakPlaceBase(op.ChanPlace, true)
					breakTargets(op.ChanVal)
					breakTargets(op.SendVal)
					scanValueEffects(op.ChanVal)
					scanValueEffects(op.SendVal)
				case flowir.OpReturn:
					for _, r := range op.Results {
						scanValueEffects(r)
					}
				case flowir.OpDefer:
					scanValueEffects(op.Call)
				case flowir.OpGo:
					breakTargets(op.Call)
				case flowir.OpExpr:
					scanValueEffects(op.Expr)
				}
				return true
			})

			for _, ps := range pendingStores {
				linkBacking(ps.robj, ps.source)
			}
			for _, pa := range pendingAppendSlices {
				linkBacking(pa.robj, pa.source)
			}

			aliasFind := newObjectUnionFind(aliasPairs)
			reachFind := newObjectUnionFind(aliasPairs, heldPairs)

			propagateBroken := func() {
				for changed := true; changed; {
					changed = false
					for _, pairs := range [][][2]types.Object{aliasPairs, heldPairs} {
						for _, pair := range pairs {
							if localBroken[pair[0]] != localBroken[pair[1]] {
								localBroken[pair[0]], localBroken[pair[1]] = true, true
								changed = true
							}
							if captureBroken[pair[0]] != captureBroken[pair[1]] {
								captureBroken[pair[0]], captureBroken[pair[1]] = true, true
								changed = true
							}
						}
					}
				}
			}
			propagateBroken()

			var unwrapBareOrResliceVar func(v *flowir.Value, extras *[]*flowir.Value) (types.Object, bool)
			unwrapBareOrResliceVar = func(v *flowir.Value, extras *[]*flowir.Value) (types.Object, bool) {
				if v == nil {
					return nil, false
				}
				if v.Kind == flowir.ValConvert && !v.IsTypeAssert && isSliceOrMapType(v.Type) {
					return unwrapBareOrResliceVar(v.Arg, extras)
				}
				if v.Kind != flowir.ValPlace || v.Place.Obj == nil || params[v.Place.Obj] {
					return nil, false
				}
				if _, tr := trackedVar(v.Place.Obj); !tr || !isSliceOrMapType(v.Place.Obj.Type()) {
					return nil, false
				}
				if len(v.Place.Projs) == 0 {
					return v.Place.Obj, true
				}
				if !isSliceResliceOnlyPlace(v.Place) {
					return nil, false
				}
				if extras != nil {
					for _, pr := range v.Place.Projs {
						if pr.Low != nil {
							*extras = append(*extras, pr.Low)
						}
						if pr.High != nil {
							*extras = append(*extras, pr.High)
						}
						if pr.Max != nil {
							*extras = append(*extras, pr.Max)
						}
					}
				}
				return v.Place.Obj, true
			}
			var unwrapSameHeaderVar func(v *flowir.Value, extras *[]*flowir.Value) (types.Object, bool)
			unwrapSameHeaderVar = func(v *flowir.Value, extras *[]*flowir.Value) (types.Object, bool) {
				if v == nil {
					return nil, false
				}
				if v.Kind == flowir.ValConvert && !v.IsTypeAssert && isSliceOrMapType(v.Type) {
					return unwrapSameHeaderVar(v.Arg, extras)
				}
				if v.Kind == flowir.ValCall && v.CallKind == flowir.CallBuiltin && v.BuiltinName == "append" &&
					!v.Ellipsis && len(v.Args) > 0 {
					var subExtras []*flowir.Value
					obj, ok := unwrapSameHeaderVar(v.Args[0], &subExtras)
					if !ok {
						return nil, false
					}
					if extras != nil {
						*extras = append(*extras, subExtras...)
						*extras = append(*extras, v.Args[1:]...)
					}
					return obj, true
				}
				return unwrapBareOrResliceVar(v, extras)
			}

			var headerPairs [][2]types.Object
			for obj, binds := range directBinds {
				if params[obj] || !isSliceOrMapType(obj.Type()) {
					continue
				}
				for _, b := range binds {
					if srcObj, ok := unwrapSameHeaderVar(b, nil); ok && srcObj != obj {
						headerPairs = append(headerPairs, [2]types.Object{obj, srcObj})
					}
				}
			}
			headerFind := newObjectUnionFind(headerPairs)

			embeddedObj := map[types.Object]bool{}
			markObjEmbedded := func(o *types.Var) {
				if o != nil {
					embeddedObj[o] = true
				}
			}
			var markValueEmbedded func(v *flowir.Value)
			markValueEmbedded = func(v *flowir.Value) {
				if v == nil {
					return
				}
				switch v.Kind {
				case flowir.ValPlace:
					if isElementReadPlace(v.Place) {
						v.Place.ForEachChildValue(func(cv *flowir.Value) bool {
							markValueEmbedded(cv)
							return true
						})
						return
					}
					markObjEmbedded(v.Place.Obj)
					v.Place.ForEachChildValue(func(cv *flowir.Value) bool {
						markValueEmbedded(cv)
						return true
					})
					return
				case flowir.ValAddrOf:
					markObjEmbedded(v.AddrPlace.Obj)
					v.AddrPlace.ForEachChildValue(func(cv *flowir.Value) bool {
						markValueEmbedded(cv)
						return true
					})
					markValueEmbedded(v.Low)
					markValueEmbedded(v.High)
					markValueEmbedded(v.Max)
					return
				case flowir.ValMethodVal:
					if v.HasRecvPlace {
						markObjEmbedded(v.RecvPlace.Obj)
						v.RecvPlace.ForEachChildValue(func(cv *flowir.Value) bool {
							markValueEmbedded(cv)
							return true
						})
					}
					markValueEmbedded(v.Recv)
					return
				case flowir.ValMakeClosure:
					if v.Closure != nil {
						for fv := range v.Closure.FreeVars {
							markObjEmbedded(fv)
						}
					}
					return
				case flowir.ValCall:
					switch v.CallKind {
					case flowir.CallBuiltin:
						switch v.BuiltinName {
						case "Sizeof", "Alignof", "Offsetof":
							return
						case "len", "cap", "clear":
							if len(v.Args) == 1 {
								var extras []*flowir.Value
								if _, ok := unwrapBareOrResliceVar(v.Args[0], &extras); ok {
									for _, ex := range extras {
										markValueEmbedded(ex)
									}
									return
								}
							}
						case "delete":
							if len(v.Args) == 2 {
								var extras []*flowir.Value
								if _, ok := unwrapBareOrResliceVar(v.Args[0], &extras); ok {
									for _, ex := range extras {
										markValueEmbedded(ex)
									}
									markValueEmbedded(v.Args[1])
									return
								}
							}
						}
					case flowir.CallPlain:
						if v.CalleeFunc != nil && !v.IsMethodExprCall {
							calleeFK := syntaxutil.FuncKey{Pkg: v.CalleePkg, Name: v.CalleeFunc.Name()}
							if auditset.ValuePlaneClone(calleeFK.Pkg, calleeFK.Name) {
								for _, arg := range v.Args {
									var extras []*flowir.Value
									if _, ok := unwrapBareOrResliceVar(arg, &extras); ok {
										for _, ex := range extras {
											markValueEmbedded(ex)
										}
										continue
									}
									markValueEmbedded(arg)
								}
								return
							}
							for j, arg := range v.Args {
								idx := j
								if v.CalleeSig != nil && v.CalleeSig.Variadic() && v.CalleeSig.Params().Len() > 0 && idx >= v.CalleeSig.Params().Len()-1 {
									idx = v.CalleeSig.Params().Len() - 1
								}
								calleeParam := syntaxutil.ParamKey{Func: calleeFK, Index: idx}
								if pkgConf != nil && calleeParam.Func.Pkg == ownPath && pkgConf.paramLeakFree[calleeParam] {
									var extras []*flowir.Value
									if _, ok := unwrapBareOrResliceVar(arg, &extras); ok {
										for _, ex := range extras {
											markValueEmbedded(ex)
										}
										continue
									}
								}
								markValueEmbedded(arg)
							}
							return
						}
					}
					if v.AutoAddrRecv && v.HasRecvPlace {
						markObjEmbedded(v.RecvPlace.Obj)
					}
					if v.CallKind == flowir.CallIIFE && v.IIFE != nil {
						for fv := range v.IIFE.FreeVars {
							markObjEmbedded(fv)
						}
					}
				}
				v.ForEachChildValue(func(ch *flowir.Value) bool {
					markValueEmbedded(ch)
					return true
				})
			}

			markDstPlaceEmbedded := func(dst flowir.Place) {
				if dst.IsBareVar() {
					return
				}
				if !isDirectIndexPlace(dst) {
					markObjEmbedded(dst.Obj)
				}
				dst.ForEachChildValue(func(cv *flowir.Value) bool {
					markValueEmbedded(cv)
					return true
				})
			}
			body.ForEachSyncOp(func(op *flowir.Op) bool {
				switch op.Kind {
				case flowir.OpAssign:
					switch op.AssignKind {
					case flowir.AssignZeroDecl:
						for _, dst := range op.Dsts {
							markDstPlaceEmbedded(dst)
						}
					case flowir.AssignIncDec, flowir.AssignCompound:
						for _, dst := range op.Dsts {
							markDstPlaceEmbedded(dst)
						}
						for _, src := range op.Srcs {
							markValueEmbedded(src)
						}
					case flowir.AssignRange:
						for _, dst := range op.Dsts {
							markDstPlaceEmbedded(dst)
						}
						if len(op.Srcs) == 1 {
							if len(op.Dsts) <= 1 || op.Dsts[1].IsBlank() {
								var extras []*flowir.Value
								if _, ok := unwrapBareOrResliceVar(op.Srcs[0], &extras); ok {
									for _, ex := range extras {
										markValueEmbedded(ex)
									}
									break
								}
							}
							markValueEmbedded(op.Srcs[0])
						}
					default:
						op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
							if dst.IsBareVar() {
								if dst.Obj != nil && !params[dst.Obj] {
									if _, tr := trackedVar(dst.Obj); tr && isSliceOrMapType(dst.Obj.Type()) {
										var extras []*flowir.Value
										if _, ok := unwrapSameHeaderVar(src, &extras); ok {
											for _, ex := range extras {
												markValueEmbedded(ex)
											}
											return true
										}
									}
								}
								markValueEmbedded(src)
								return true
							}
							markDstPlaceEmbedded(dst)
							markValueEmbedded(src)
							return true
						})
					}
				case flowir.OpTypeSwitchBind:
					markValueEmbedded(op.SwitchSrc)
				case flowir.OpChanSend:
					markObjEmbedded(op.ChanPlace.Obj)
					op.ChanPlace.ForEachChildValue(func(cv *flowir.Value) bool {
						markValueEmbedded(cv)
						return true
					})
					markValueEmbedded(op.ChanVal)
					markValueEmbedded(op.SendVal)
				case flowir.OpReturn:
					for _, r := range op.Results {
						var extras []*flowir.Value
						if _, ok := unwrapBareOrResliceVar(r, &extras); ok {
							for _, ex := range extras {
								markValueEmbedded(ex)
							}
							continue
						}
						markValueEmbedded(r)
					}
				case flowir.OpDefer:
					markValueEmbedded(op.Call)
				case flowir.OpGo:
					markValueEmbedded(op.Call)
				case flowir.OpExpr:
					if op.Expr != nil && op.Expr.Kind == flowir.ValCall && op.Expr.CallKind == flowir.CallBuiltin &&
						op.Expr.BuiltinName == "append" && !op.Expr.Ellipsis && len(op.Expr.Args) >= 2 {
						var extras []*flowir.Value
						if _, ok := unwrapBareOrResliceVar(op.Expr.Args[0], &extras); ok {
							for _, ex := range extras {
								markValueEmbedded(ex)
							}
							for _, a := range op.Expr.Args[1:] {
								markValueEmbedded(a)
							}
							return true
						}
					}
					markValueEmbedded(op.Expr)
				}
				return true
			})

			headerMembers := map[types.Object][]types.Object{}
			headerSeen := map[types.Object]bool{}
			headerEmbedded := map[types.Object]bool{}
			addHeaderCandidate := func(o types.Object) {
				v, ok := o.(*types.Var)
				if !ok || v == nil || params[v] || v.Type() == nil || !isSliceOrMapType(v.Type()) {
					return
				}
				if _, tr := trackedVar(o); !tr {
					return
				}
				hRoot := headerFind(o)
				if !headerSeen[o] {
					headerSeen[o] = true
					headerMembers[hRoot] = append(headerMembers[hRoot], o)
				}
				if embeddedObj[o] {
					headerEmbedded[hRoot] = true
				}
			}
			for o := range directBinds {
				addHeaderCandidate(o)
			}
			for _, ps := range pendingStores {
				addHeaderCandidate(ps.robj)
			}
			for _, pa := range pendingAppendSlices {
				addHeaderCandidate(pa.robj)
			}
			for o := range insertionWrites {
				addHeaderCandidate(o)
			}
			for o := range embeddedObj {
				addHeaderCandidate(o)
			}

			freshObj, _ := computeOutflowFreshOwnedLocals(outflowFreshInput{
				directBinds:         directBinds,
				hasZeroDecl:         hasZeroDecl,
				params:              params,
				localBroken:         localBroken,
				rangeBound:          rangeBound,
				hasSpreadAppend:     hasSpreadAppend,
				headerMembers:       headerMembers,
				headerEmbedded:      headerEmbedded,
				headerFind:          headerFind,
				insertionWrites:     insertionWrites,
				pendingStores:       pendingStores,
				pendingAppendSlices: pendingAppendSlices,
			})

			deepWrite := func(dst flowir.Place, fresh bool) bool {
				selectorSeen := false
				for idx, pr := range dst.Projs {
					atRoot := idx == 0
					final := idx == len(dst.Projs)-1
					switch pr.Kind {
					case flowir.ProjDeref:
						if !atRoot || !fresh {
							return true
						}
						if pr.Type == nil {
							selectorSeen = true
						} else if _, isArr := types.Unalias(pr.Type).Underlying().(*types.Array); !isArr {
							selectorSeen = true
						}
					case flowir.ProjField:
						ptrBase := pr.Indirect
						if !ptrBase && pr.BaseType != nil {
							_, ptrBase = types.Unalias(pr.BaseType).Underlying().(*types.Pointer)
						}
						if ptrBase && (!atRoot || !fresh) {
							return true
						}
						selectorSeen = true
					case flowir.ProjIndex:
						if !final || !fresh || selectorSeen {
							return true
						}
					case flowir.ProjSlice:
						if !fresh || selectorSeen {
							return true
						}
					}
				}
				return false
			}

			for _, ps := range pendingStores {
				if deepWrite(ps.place, freshObj[ps.robj]) {
					breakObj(ps.robj, false, nil)
					insertionWrites[ps.robj] = append(insertionWrites[ps.robj], ps.source)
					continue
				}
				writeSources[ps.robj] = append(writeSources[ps.robj], ps.source)
			}
			for _, pa := range pendingAppendSlices {
				if !freshObj[pa.robj] || deepWrite(pa.place, true) {
					breakObj(pa.robj, false, nil)
					insertionWrites[pa.robj] = append(insertionWrites[pa.robj], pa.source)
					continue
				}
				writeSources[pa.robj] = append(writeSources[pa.robj], pa.source)
				insertionWrites[pa.robj] = append(insertionWrites[pa.robj], pa.source)
			}

			sharedWrites := map[types.Object][]*flowir.Value{}
			for obj, stores := range writeSources {
				root := aliasFind(obj)
				sharedWrites[root] = append(sharedWrites[root], stores...)
			}
			sharedInsertionWrites := map[types.Object][]*flowir.Value{}
			for obj, stores := range insertionWrites {
				rRoot := reachFind(obj)
				sharedInsertionWrites[rRoot] = append(sharedInsertionWrites[rRoot], stores...)
			}

			objParamDeps := map[types.Object]map[syntaxutil.ParamKey]bool{}
			for obj, pks := range rawObjParamDeps {
				rRoot := reachFind(obj)
				if objParamDeps[rRoot] == nil {
					objParamDeps[rRoot] = map[syntaxutil.ParamKey]bool{}
				}
				for pk := range pks {
					objParamDeps[rRoot][pk] = true
				}
			}
			objMethodDeps := map[types.Object]map[syntaxutil.FuncKey]bool{}
			for obj, mks := range rawObjMethodDeps {
				rRoot := reachFind(obj)
				if objMethodDeps[rRoot] == nil {
					objMethodDeps[rRoot] = map[syntaxutil.FuncKey]bool{}
				}
				for mk := range mks {
					objMethodDeps[rRoot][mk] = true
				}
			}

			componentMembers := map[types.Object][]types.Object{}
			memberSeen := map[types.Object]bool{}
			collectMember := func(o types.Object) {
				if o != nil && !memberSeen[o] {
					memberSeen[o] = true
					componentMembers[aliasFind(o)] = append(componentMembers[aliasFind(o)], o)
				}
			}
			for _, pair := range aliasPairs {
				collectMember(pair[0])
				collectMember(pair[1])
			}
			for obj := range writeSources {
				collectMember(obj)
			}
			for obj := range params {
				collectMember(obj)
			}
			for root, ms := range componentMembers {
				if len(sharedWrites[root]) == 0 {
					continue
				}
				hasParam := false
				for _, m := range ms {
					if params[m] {
						hasParam = true
						break
					}
				}
				if hasParam {
					for _, m := range ms {
						localBroken[m] = true
					}
				}
			}

			propagateBroken()

			placeProjsAdmitted := func(projs []flowir.Proj) bool {
				for _, pr := range projs {
					switch pr.Kind {
					case flowir.ProjField:
					case flowir.ProjIndex:
						if pr.BaseType == nil {
							return false
						}
						switch u := types.Unalias(pr.BaseType).Underlying().(type) {
						case *types.Map, *types.Slice, *types.Array, *types.Basic:
						case *types.Pointer:
							if _, isArr := types.Unalias(u.Elem()).Underlying().(*types.Array); !isArr {
								return false
							}
						default:
							return false
						}
					default:
						return false
					}
				}
				return true
			}

			visitingLits := map[*ast.FuncLit]bool{}
			foldRootConfinementDeps := func(ctx *outflowEvalCtx, rRoot types.Object) {
				for pk := range objParamDeps[rRoot] {
					ctx.paramDeps[pk] = true
				}
				for mk := range objMethodDeps[rRoot] {
					ctx.methodDeps[mk] = true
				}
				for pk := range ctx.resolved.paramDeps[rRoot] {
					ctx.paramDeps[pk] = true
				}
				for mk := range ctx.resolved.methodDeps[rRoot] {
					ctx.methodDeps[mk] = true
				}
			}

			var evalFree func(ctx *outflowEvalCtx, v *flowir.Value) (bool, int)
			var checkPlainCallReachArgSeen func(ctx *outflowEvalCtx, arg *flowir.Value, currentCall *flowir.Value, skipInsertionRoot types.Object, allowInsParam bool, visiting map[types.Object]bool) bool

			evalFree = func(ctx *outflowEvalCtx, v *flowir.Value) (resOK bool, resCyc int) {
				if ctx.onRefusal != nil {
					defer func() {
						if !resOK {
							ctx.onRefusal(v)
						}
					}()
				}
				if v == nil {
					return false, math.MaxInt
				}
				if v.Type != nil && !carries(v.Type) {
					return true, math.MaxInt
				}
				minCycle := math.MaxInt
				merge := func(childOK bool, cyc int) bool {
					if !childOK {
						return false
					}
					if cyc < minCycle {
						minCycle = cyc
					}
					return true
				}

				judgeObj := func(obj types.Object, isParam bool) (bool, int) {
					root := aliasFind(obj)
					rRoot := reachFind(obj)
					if isParam {
						if ctx.insMode {
							if paramRebound[obj] || captureBroken[obj] || ctx.resolved.poison[rRoot] {
								ctx.localFree[obj] = 3
								return false, math.MaxInt
							}
						} else if localBroken[obj] || ctx.resolved.poison[rRoot] {
							ctx.localFree[obj] = 3
							return false, math.MaxInt
						}
					} else if ctx.resolved.poison[rRoot] {
						ctx.localFree[obj] = 3
						return false, math.MaxInt
					}
					for use := range ctx.resolved.uses[rRoot] {
						ctx.useDeps[use] = true
					}
					foldRootConfinementDeps(ctx, rRoot)
					switch ctx.localFree[obj] {
					case 2:
						return true, math.MaxInt
					case 3:
						return false, math.MaxInt
					}
					if d, active := ctx.provingDepth[obj]; active && d > 0 {
						return true, d
					}
					if !isParam && localBroken[obj] {
						ctx.localFree[obj] = 3
						return false, math.MaxInt
					}
					myDepth := ctx.curDepth + 1
					ctx.curDepth = myDepth
					ctx.provingDepth[obj] = myDepth
					defer func() {
						delete(ctx.provingDepth, obj)
						ctx.curDepth = myDepth - 1
					}()

					objMinCycle := math.MaxInt
					if !isParam {
						for _, src := range localSources[obj] {
							okSrc, cyc := evalFree(ctx, src)
							if !okSrc {
								ctx.localFree[obj] = 3
								return false, math.MaxInt
							}
							if cyc < objMinCycle {
								objMinCycle = cyc
							}
						}
					}
					for _, stored := range sharedWrites[root] {
						okSt, cyc := evalFree(ctx, stored)
						if !okSt {
							ctx.localFree[obj] = 3
							return false, math.MaxInt
						}
						if cyc < objMinCycle {
							objMinCycle = cyc
						}
					}
					for _, stored := range sharedInsertionWrites[rRoot] {
						okSt, cyc := evalFree(ctx, stored)
						if !okSt {
							ctx.localFree[obj] = 3
							return false, math.MaxInt
						}
						if cyc < objMinCycle {
							objMinCycle = cyc
						}
					}
					if objMinCycle >= myDepth {
						ctx.localFree[obj] = 2
						return true, math.MaxInt
					}
					return true, objMinCycle
				}

				switch v.Kind {
				case flowir.ValScalarLitOrConst:
					return true, math.MaxInt

				case flowir.ValAllocFresh:
					switch v.AllocKind {
					case flowir.AllocMake, flowir.AllocBuiltinNewType:
						return true, math.MaxInt
					case flowir.AllocBuiltinNewExpr:
						if len(v.Args) != 1 {
							return false, math.MaxInt
						}
						return evalFree(ctx, v.Args[0])
					case flowir.AllocCompositeLit:
						for i := range v.CompositeElts {
							if v.CompositeElts[i].MapKey != nil {
								if !merge(evalFree(ctx, v.CompositeElts[i].MapKey)) {
									return false, math.MaxInt
								}
							}
							if v.CompositeElts[i].Value != nil {
								if !merge(evalFree(ctx, v.CompositeElts[i].Value)) {
									return false, math.MaxInt
								}
							}
						}
						return true, minCycle
					}

				case flowir.ValMakeClosure:
					if v.Lit == nil || v.Closure == nil || visitingLits[v.Lit] {
						return false, math.MaxInt
					}
					visitingLits[v.Lit] = true
					defer delete(visitingLits, v.Lit)
					litCtx := ctx
					if ctx.insMode {
						litCtx = &outflowEvalCtx{
							insMode:      false,
							resolved:     ctx.resolved,
							localFree:    map[types.Object]int{},
							provingDepth: map[types.Object]int{},
							fnDeps:       ctx.fnDeps,
							useDeps:      ctx.useDeps,
							paramDeps:    ctx.paramDeps,
							methodDeps:   ctx.methodDeps,
							onRefusal:    ctx.onRefusal,
						}
					}
					wants := map[syntaxutil.ParamKey]bool{}
					methodWants := map[syntaxutil.FuncKey]bool{}
					origin := &rootOriginPolicy{
						verifyLocalOrigins:   true,
						allowEnclosingParams: true,
						settledGlobals:       settledGlobals,
						checkCarryingValue: func(sub *flowir.Value) bool {
							okSub, _ := evalFree(litCtx, sub)
							return okSub
						},
					}
					if !environmentFreeFuncLitWithOrigin(audited, p, fc, v.Lit, fd, wants, methodWants, origin) {
						return false, math.MaxInt
					}
					if !classifyWants(wants, methodWants, litCtx.paramDeps, litCtx.methodDeps) {
						return false, math.MaxInt
					}
					for fv := range v.Closure.FreeVars {
						if reachOrAddrOrStr(fv.Type()) {
							fvVal := &flowir.Value{
								Kind: flowir.ValPlace,
								Type: fv.Type(),
								Place: flowir.Place{
									Root: flowir.RootLocal,
									Obj:  fv,
									Type: fv.Type(),
								},
							}
							if !checkPlainCallReachArgSeen(litCtx, fvVal, nil, nil, false, map[types.Object]bool{}) {
								return false, math.MaxInt
							}
						}
						if !carries(fv.Type()) {
							continue
						}
						if params[fv] {
							if !merge(judgeObj(fv, true)) {
								return false, math.MaxInt
							}
						} else if syntaxutil.IsLocalVar(fv) {
							if !merge(judgeObj(fv, false)) {
								return false, math.MaxInt
							}
						}
					}
					return true, minCycle

				case flowir.ValPlace:
					if !placeProjsAdmitted(v.Place.Projs) {
						return false, math.MaxInt
					}
					switch v.Place.Root {
					case flowir.RootFunc, flowir.RootConstOrNil:
						return true, math.MaxInt
					case flowir.RootParam, flowir.RootLocal, flowir.RootResult:
						obj := v.Place.Obj
						if obj == nil {
							return false, math.MaxInt
						}
						if params[obj] {
							return judgeObj(obj, true)
						}
						if syntaxutil.IsLocalVar(obj) {
							return judgeObj(obj, false)
						}
					case flowir.RootTransient:
						if v.Place.Base != nil {
							return evalFree(ctx, v.Place.Base)
						}
					}
					return false, math.MaxInt

				case flowir.ValConvert:
					if v.IsTypeAssert || v.Arg == nil || syntaxutil.IsUnsafePointerType(v.Arg.Type) {
						return false, math.MaxInt
					}
					return evalFree(ctx, v.Arg)

				case flowir.ValCall:
					switch v.CallKind {
					case flowir.CallBuiltin:
						if v.BuiltinName == "append" {
							for _, arg := range v.Args {
								if !merge(evalFree(ctx, arg)) {
									return false, math.MaxInt
								}
							}
							return true, minCycle
						}
						return false, math.MaxInt

					case flowir.CallPlain:
						if v.CalleeFunc == nil || v.IsMethodExprCall {
							return false, math.MaxInt
						}
						calleeFK := syntaxutil.FuncKey{Pkg: v.CalleePkg, Name: v.CalleeFunc.Name()}
						isVP := auditset.ValuePlaneClone(calleeFK.Pkg, calleeFK.Name)
						perArg := make([]map[types.Object]bool, len(v.Args))
						for i, arg := range v.Args {
							if !merge(evalFree(ctx, arg)) {
								return false, math.MaxInt
							}
							if !isVP {
								if !checkPlainCallReachArgSeen(ctx, arg, v, nil, false, map[types.Object]bool{}) {
									return false, math.MaxInt
								}
								perArg[i] = collectMutableArgRoots(arg)
							}
						}
						if !isVP {
							for i := 0; i < len(perArg); i++ {
								for j := i + 1; j < len(perArg); j++ {
									for r := range perArg[i] {
										if perArg[j][r] && !params[r] {
											return false, math.MaxInt
										}
									}
								}
							}
							ctx.fnDeps[calleeFK] = true
						}
						return true, minCycle
					}
					return false, math.MaxInt
				}
				return false, math.MaxInt
			}

			checkPlainCallReachArgSeen = func(ctx *outflowEvalCtx, arg *flowir.Value, currentCall *flowir.Value, skipInsertionRoot types.Object, allowInsParam bool, visiting map[types.Object]bool) bool {
				if isPureFreshDataValue(settledGlobals, arg) {
					return true
				}
				return checkPureOrFreshValue(arg, valuePurityPolicy{
					allowAppend:          true,
					allowValuePlane:      true,
					allowRuntimeOps:      true,
					allowNonMutableReach: true,
					allowSigLeaf: func(leaf *flowir.Value) bool {
						okArg, _ := evalFree(ctx, leaf)
						return okArg
					},
					allowPlace: func(pv *flowir.Value) bool {
						if pv.Place.Root == flowir.RootFunc && !pv.Place.IsMethodExpr {
							return true
						}
						if pv.Place.Root == flowir.RootPkgGlobal {
							return pv.Place.Obj != nil && settledGlobals.hasUnembedded(pv.Place.Obj)
						}
						if pv.Place.Root == flowir.RootTransient && pv.Place.Base != nil {
							return checkPlainCallReachArgSeen(ctx, pv.Place.Base, currentCall, skipInsertionRoot, allowInsParam, visiting)
						}
						if pv.Place.Obj != nil {
							obj := pv.Place.Obj
							if !params[obj] && !syntaxutil.IsLocalVar(obj) {
								return false
							}
							isInsParam := allowInsParam && params[obj]
							if visiting[obj] {
								return isInsParam
							}
							root := aliasFind(obj)
							rRoot := reachFind(obj)
							if isInsParam {
								if paramRebound[obj] || captureBroken[obj] || ctx.resolved.poison[rRoot] {
									return false
								}
							} else if localBroken[obj] || captureBroken[obj] || ctx.resolved.poison[rRoot] {
								return false
							}
							if !params[obj] && !freshObj[obj] && !hasZeroDecl[obj] && len(localSources[obj]) == 0 {
								return false
							}
							for use := range ctx.resolved.uses[rRoot] {
								ctx.useDeps[use] = true
							}
							foldRootConfinementDeps(ctx, rRoot)
							if !allowInsParam && rRoot != skipInsertionRoot {
								for _, use := range pendingInsertionUses {
									if reachFind(use.root) == rRoot && use.call != currentCall {
										provenLocal, conditional := pkgConf.classifyParam(ownPath, use.calleeParam)
										if !provenLocal {
											if !conditional {
												return false
											}
											ctx.paramDeps[use.calleeParam] = true
										}
									}
								}
							}
							visiting[obj] = true
							defer delete(visiting, obj)
							for _, src := range localSources[obj] {
								if !checkPlainCallReachArgSeen(ctx, src, currentCall, skipInsertionRoot, allowInsParam, visiting) {
									return false
								}
							}
							for _, st := range sharedWrites[root] {
								if !checkPlainCallReachArgSeen(ctx, st, currentCall, skipInsertionRoot, allowInsParam, visiting) {
									return false
								}
							}
							for _, st := range sharedInsertionWrites[rRoot] {
								if !checkPlainCallReachArgSeen(ctx, st, currentCall, skipInsertionRoot, allowInsParam, visiting) {
									return false
								}
							}
							return true
						}
						return false
					},
				})
			}

			computeResolvedUses := func(insMode bool) resolvedInsertionState {
				if len(pendingInsertionUses) == 0 {
					return resolvedInsertionState{}
				}
				state := resolvedInsertionState{
					poison:     map[types.Object]bool{},
					uses:       map[types.Object]map[syntaxutil.EnvAuditTarget]bool{},
					paramDeps:  map[types.Object]map[syntaxutil.ParamKey]bool{},
					methodDeps: map[types.Object]map[syntaxutil.FuncKey]bool{},
				}
				step := func(record bool) bool {
					changed := false
					for _, use := range pendingInsertionUses {
						rRoot := reachFind(use.root)
						if state.poison[rRoot] {
							continue
						}
						stepCtx := newOutflowEvalCtx(insMode, state)
						allFree := true
						for _, a := range use.args {
							if okA, _ := evalFree(stepCtx, a); !okA {
								allFree = false
								break
							}
							if a != nil && a.Type != nil && reachOrAddrOrStr(a.Type) &&
								!checkPlainCallReachArgSeen(stepCtx, a, use.call, rRoot, insMode, map[types.Object]bool{}) {
								allFree = false
								break
							}
						}
						if !allFree {
							state.poison[rRoot] = true
							changed = true
							continue
						}
						if record {
							if state.uses[rRoot] == nil {
								state.uses[rRoot] = map[syntaxutil.EnvAuditTarget]bool{}
							}
							addUse := func(t syntaxutil.EnvAuditTarget) {
								if !state.uses[rRoot][t] {
									state.uses[rRoot][t] = true
									changed = true
								}
							}
							addUse(syntaxutil.ParamAuditTarget(use.calleeParam))
							for fk := range stepCtx.fnDeps {
								addUse(syntaxutil.FuncAuditTarget(fk))
							}
							for u := range stepCtx.useDeps {
								addUse(u)
							}
							for pk := range stepCtx.paramDeps {
								if state.paramDeps[rRoot] == nil {
									state.paramDeps[rRoot] = map[syntaxutil.ParamKey]bool{}
								}
								if !state.paramDeps[rRoot][pk] {
									state.paramDeps[rRoot][pk] = true
									changed = true
								}
							}
							for mk := range stepCtx.methodDeps {
								if state.methodDeps[rRoot] == nil {
									state.methodDeps[rRoot] = map[syntaxutil.FuncKey]bool{}
								}
								if !state.methodDeps[rRoot][mk] {
									state.methodDeps[rRoot][mk] = true
									changed = true
								}
							}
						}
					}
					return changed
				}
				for step(false) {
				}
				for step(true) {
				}
				return state
			}

			retResolved := computeResolvedUses(false)
			insResolved := computeResolvedUses(true)

			for obj, idx := range paramIndex {
				key := syntaxutil.ParamKey{Func: ownFuncKey, Index: idx}
				root := aliasFind(obj)
				rRoot := reachFind(obj)
				if captureBroken[obj] || insResolved.poison[rRoot] {
					continue
				}
				insCtx := newOutflowEvalCtx(true, insResolved)
				foldRootConfinementDeps(insCtx, rRoot)
				okIns := true
				for _, stores := range [][]*flowir.Value{sharedWrites[root], sharedInsertionWrites[rRoot]} {
					for _, stored := range stores {
						if okSt, _ := evalFree(insCtx, stored); !okSt {
							okIns = false
							break
						}
						if stored != nil && stored.Type != nil && reachOrAddrOrStr(stored.Type) &&
							!checkPlainCallReachArgSeen(insCtx, stored, nil, nil, true, map[types.Object]bool{}) {
							okIns = false
							break
						}
					}
					if !okIns {
						break
					}
				}
				if !okIns {
					continue
				}
				for fk := range insCtx.fnDeps {
					insCtx.useDeps[syntaxutil.FuncAuditTarget(fk)] = true
				}
				for use := range insResolved.uses[rRoot] {
					insCtx.useDeps[use] = true
				}
				insFree[key] = true
				if len(insCtx.useDeps) > 0 {
					insDeps[key] = insCtx.useDeps
				}
				if len(insCtx.paramDeps) > 0 {
					insParamDeps[key] = insCtx.paramDeps
				}
				if len(insCtx.methodDeps) > 0 {
					insMethodDeps[key] = insCtx.methodDeps
				}
			}

			retCtx := newOutflowEvalCtx(false, retResolved)
			for callee := range stmtCallDeps {
				retCtx.fnDeps[callee] = true
			}
			if hooks != nil && hooks.Refusal != nil {
				retCtx.onRefusal = func(v *flowir.Value) {
					if v == nil || v.Raw == nil {
						return
					}
					e := syntaxutil.UnparenExpr(v.Raw)
					clause := "an unrecognized return shape"
					switch e := e.(type) {
					case *ast.Ident:
						obj := p.TypesInfo.Uses[e]
						if obj == nil {
							obj = p.TypesInfo.Defs[e]
						}
						switch {
						case obj != nil && localBroken[obj]:
							clause = "write or capture broke the binding"
						case obj != nil && retResolved.poison[reachFind(obj)]:
							clause = "an unjudgeable argument to a deferring call poisoned the storage"
						case obj != nil && len(sharedWrites[aliasFind(obj)]) > 0:
							clause = "a stored value refused"
						default:
							clause = "a binding source refused"
						}
					case *ast.CallExpr:
						clause = "callee outside the audited set and dependency channel"
					case *ast.CompositeLit:
						clause = "a literal element refused"
					case *ast.SelectorExpr, *ast.IndexExpr, *ast.SliceExpr:
						clause = "an unadmitted derivation shape"
					}
					syntaxutil.ExplainRefusalMark(hooks, p, fd.Name.Name, e, clause)
				}
			}

			namedResultIdent := func(rv *types.Var) ast.Expr {
				if rv == nil {
					return &ast.Ident{}
				}
				if fd.Type != nil && fd.Type.Results != nil {
					for _, field := range fd.Type.Results.List {
						for _, id := range field.Names {
							if id != nil && p.TypesInfo.Defs[id] == rv {
								return id
							}
						}
					}
				}
				return &ast.Ident{NamePos: rv.Pos(), Name: rv.Name()}
			}

			okRet := true
			var firstNamedResult *types.Var
			for _, rv := range body.Results {
				if rv != nil {
					if firstNamedResult == nil {
						firstNamedResult = rv
					}
					if localBroken[rv] {
						syntaxutil.ExplainRefusalMark(hooks, p, fd.Name.Name, namedResultIdent(rv), "write or capture broke the binding")
						okRet = false
						break
					}
				}
			}
			sawReturn := false
			if okRet {
				body.ForEachSyncOp(func(op *flowir.Op) bool {
					if op.Kind != flowir.OpReturn {
						return true
					}
					sawReturn = true
					if op.IsNaked {
						retExpr := namedResultIdent(firstNamedResult)
						if op.StmtAST != nil {
							retExpr = &ast.Ident{NamePos: op.StmtAST.Pos()}
						}
						syntaxutil.ExplainRefusalMark(hooks, p, fd.Name.Name, retExpr, "an unrecognized return shape")
						okRet = false
						return false
					}
					for _, res := range op.Results {
						if okRes, _ := evalFree(retCtx, res); !okRes {
							okRet = false
							return false
						}
					}
					return true
				})
			}
			if !okRet {
				continue
			}
			if firstNamedResult != nil && !sawReturn {
				syntaxutil.ExplainRefusalMark(hooks, p, fd.Name.Name, namedResultIdent(firstNamedResult), "an unrecognized return shape")
				continue
			}
			proven[fnKey] = true
			if len(retCtx.fnDeps) > 0 {
				deps[fnKey] = retCtx.fnDeps
			}
			if len(retCtx.paramDeps) > 0 {
				retParamDeps[fnKey] = retCtx.paramDeps
			}
			if len(retCtx.methodDeps) > 0 {
				retMethodDeps[fnKey] = retCtx.methodDeps
			}
			if len(retCtx.useDeps) > 0 {
				callerInsDeps[fnKey] = retCtx.useDeps
			}
			recordReturnFieldRegistrants(audited, p, fc, fnKey, body, retDefer, retPoison)
		}
	}
	return closureOutflowSummaries{
		returnEnvFree:          proven,
		returnEnvDeps:          deps,
		returnEnvParamDeps:     retParamDeps,
		returnEnvMethodDeps:    retMethodDeps,
		returnFieldDefer:       retDefer,
		returnFieldPoison:      retPoison,
		paramInsertionFree:     insFree,
		paramInsertionDeps:     insDeps,
		paramInsertionParams:   insParamDeps,
		paramInsertionMethods:  insMethodDeps,
		returnInsertionCallDep: callerInsDeps,
	}
}

func recordReturnFieldRegistrants(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	fnKey string,
	body *flowir.Body,
	retDefer map[string]map[syntaxutil.ReturnFieldParamDefer]bool,
	retPoison map[string]map[syntaxutil.ReturnFieldParamPoison]bool,
) {
	if body == nil {
		return
	}
	ownPath := ""
	if p.Types != nil {
		ownPath = p.Types.Path()
	}
	ownFuncKey := syntaxutil.FuncKey{Pkg: ownPath, Name: fnKey}
	emit := func(m fieldRegMark) {
		switch m.class {
		case 'd':
			if retDefer[fnKey] == nil {
				retDefer[fnKey] = map[syntaxutil.ReturnFieldParamDefer]bool{}
			}
			retDefer[fnKey][syntaxutil.ReturnFieldParamDefer{
				Pos:   syntaxutil.ReturnFieldPosKey{Func: ownFuncKey, Field: m.field, Index: m.idx},
				Param: m.param,
			}] = true
		case 'p':
			if retPoison[fnKey] == nil {
				retPoison[fnKey] = map[syntaxutil.ReturnFieldParamPoison]bool{}
			}
			if m.field == "" {
				retPoison[fnKey][syntaxutil.ReturnFieldParamPoison{Func: ownFuncKey}] = true
			} else {
				retPoison[fnKey][syntaxutil.ReturnFieldParamPoison{Func: ownFuncKey, HasPos: true, Field: m.field, Index: m.idx}] = true
			}
		}
	}

	var scanBody func(b *flowir.Body)
	var scanRVal func(v *flowir.Value)

	scanPlaceWrite := func(dst flowir.Place, src *flowir.Value) {
		if src != nil && len(dst.Projs) > 0 {
			last := dst.Projs[len(dst.Projs)-1]
			if last.Kind == flowir.ProjField && last.Field != nil && last.Selection != nil && last.Type != nil {
				if _, isSig := types.Unalias(last.Type).Underlying().(*types.Signature); isSig {
					classifyFieldRegistrantFlowValue(audited, p, fc, last.Field.Name(), src, emit)
				}
			}
		}
		if _, mapKey, isMapW := dst.AsMapWrite(); isMapW && mapKey != nil {
			classifyRegistrantFlowValue(audited, p, fc, mapKey, emit)
		}
		dst.ForEachChildValue(func(cv *flowir.Value) bool {
			scanRVal(cv)
			return true
		})
	}

	scanRVal = func(v *flowir.Value) {
		if v == nil || v.IsTypeExpr {
			return
		}
		switch v.Kind {
		case flowir.ValAllocFresh:
			if v.AllocKind == flowir.AllocCompositeLit {
				classifyRegistrantCompositeValue(audited, p, fc, v, emit)
				return
			}
		case flowir.ValMakeClosure:
			classifyLiteralRegistrant(audited, p, fc, syntaxutil.ElemPositionField, v.Lit, emit)
			return
		case flowir.ValMethodVal:
			emit(fieldRegMark{class: 'p', field: syntaxutil.ElemPositionField, idx: -1})
		case flowir.ValPlace:
			if v.Place.Root == flowir.RootFunc {
				classifyFieldRegistrantFlowValue(audited, p, fc, syntaxutil.ElemPositionField, v, emit)
				return
			}
			if v.Place.Root == flowir.RootPkgGlobal && v.Place.Obj != nil && refconfine.TypeCarriesSignature(v.Place.Obj.Type()) {
				emit(fieldRegMark{class: 'p', idx: -1})
			}
			for _, proj := range v.Place.Projs {
				if (proj.Kind == flowir.ProjField || proj.Kind == flowir.ProjIndex) && refconfine.TypeCarriesSignature(proj.Type) {
					emit(fieldRegMark{class: 'p', field: syntaxutil.ElemPositionField, idx: -1})
					break
				}
			}
			v.Place.ForEachChildValue(func(cv *flowir.Value) bool {
				scanRVal(cv)
				return true
			})
			return
		case flowir.ValCall:
			if v.CallKind != flowir.CallBuiltin && (v.CallKind != flowir.CallPlain || v.IsMethodExprCall) {
				if refconfine.TypeCarriesSignature(v.Type) {
					emit(fieldRegMark{class: 'p', field: syntaxutil.ElemPositionField, idx: -1})
				}
			}
			if v.CallKind == flowir.CallIIFE && v.IIFE != nil {
				scanBody(v.IIFE)
			}
		}
		v.ForEachChildValue(func(ch *flowir.Value) bool {
			scanRVal(ch)
			return true
		})
	}

	scanBody = func(b *flowir.Body) {
		if b == nil {
			return
		}
		b.ForEachSyncOp(func(op *flowir.Op) bool {
			switch op.Kind {
			case flowir.OpAssign:
				switch op.AssignKind {
				case flowir.AssignZeroDecl:
					// Zero declarations introduce no non-nil function registrants.
				case flowir.AssignIncDec:
					for _, dst := range op.Dsts {
						scanPlaceWrite(dst, nil)
					}
				case flowir.AssignRange:
					for _, dst := range op.Dsts {
						dst.ForEachChildValue(func(cv *flowir.Value) bool {
							scanRVal(cv)
							return true
						})
					}
					for _, src := range op.Srcs {
						scanRVal(src)
					}
				default:
					op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
						scanPlaceWrite(dst, src)
						return true
					})
					for _, src := range op.Srcs {
						scanRVal(src)
					}
				}
			case flowir.OpTypeSwitchBind:
				scanRVal(op.SwitchSrc)
			case flowir.OpChanSend:
				op.ChanPlace.ForEachChildValue(func(cv *flowir.Value) bool {
					scanRVal(cv)
					return true
				})
				scanRVal(op.ChanVal)
				scanRVal(op.SendVal)
			case flowir.OpReturn:
				for _, r := range op.Results {
					scanRVal(r)
				}
			case flowir.OpDefer, flowir.OpGo:
				scanRVal(op.Call)
			case flowir.OpExpr:
				scanRVal(op.Expr)
			}
			return true
		})
	}
	scanBody(body)
}
