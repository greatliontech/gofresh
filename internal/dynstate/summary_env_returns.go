package dynstate

import (
	"go/ast"
	"go/types"
	"math"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// returnEnvFreeFunctions proves, per plain named function of the package, that
// every value its return expressions can carry into a carrier is
// environment-free provided the call's arguments are — the constructor-result
// admission of the environment-free registration audit.
func returnEnvFreeFunctions(
	audited bool,
	p *packages.Package,
	settledGlobals settledGlobalMap,
	pkgConf *packageConfinementSummary,
	hooks *syntaxutil.ExplainHookSet,
) (
	map[string]bool,
	map[string]map[syntaxutil.FuncKey]bool,
	map[string]map[syntaxutil.ParamKey]bool,
	map[string]map[syntaxutil.FuncKey]bool,
	map[string]map[syntaxutil.ReturnFieldParamDefer]bool,
	map[string]map[syntaxutil.ReturnFieldParamPoison]bool,
	map[syntaxutil.ParamKey]bool,
	map[syntaxutil.ParamKey]map[syntaxutil.EnvAuditTarget]bool,
	map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool,
	map[syntaxutil.ParamKey]map[syntaxutil.FuncKey]bool,
	map[string]map[syntaxutil.EnvAuditTarget]bool,
) {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil
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
	elemReach := func(t types.Type) bool {
		if t == nil {
			return true
		}
		switch u := types.Unalias(t).Underlying().(type) {
		case *types.Slice:
			return refconfine.TypeHandsOutMutableReach(u.Elem())
		case *types.Array:
			return refconfine.TypeHandsOutMutableReach(u.Elem())
		case *types.Map:
			return refconfine.TypeHandsOutMutableReach(u.Key()) || refconfine.TypeHandsOutMutableReach(u.Elem())
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
			body := flowir.LowerFunc(p.TypesInfo, p.Types, fd)
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
					!refconfine.TypeHandsOutMutableReach(v.Type()) {
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
				if !tracked || !refconfine.TypeHandsOutMutableReach(sobj.Type()) {
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
					if src.CallKind == flowir.CallBuiltin && src.BuiltinName == "append" {
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

			type pendingStore struct {
				robj     types.Object
				place    flowir.Place
				source   *flowir.Value
				isMapKey bool
			}
			var pendingStores []pendingStore
			var pendingAppendSlices []pendingStore
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
								pendingStores = append(pendingStores, pendingStore{robj: dst.Obj, place: dst, source: keyVal, isMapKey: true})
							}
							pendingStores = append(pendingStores, pendingStore{robj: dst.Obj, place: dst, source: src})
							return
						}
					}
					breakPlaceBase(dst, true)
					if src != nil {
						breakValueVars(src, true, func(o types.Object) bool {
							return refconfine.TypeHandsOutMutableReach(o.Type())
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
							return refconfine.TypeHandsOutMutableReach(o.Type())
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
				if arg == nil || (arg.Type != nil && !refconfine.TypeHandsOutMutableReach(arg.Type)) {
					return roots
				}
				var walk func(v *flowir.Value)
				walk = func(v *flowir.Value) {
					if v == nil || (v.Kind != flowir.ValAddrOf && v.Type != nil && !refconfine.TypeHandsOutMutableReach(v.Type)) {
						return
					}
					switch v.Kind {
					case flowir.ValPlace:
						if v.Place.Obj != nil {
							if _, tr := trackedVar(v.Place.Obj); (tr || params[v.Place.Obj]) && refconfine.TypeHandsOutMutableReach(v.Place.Obj.Type()) {
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
						if v.CallKind == flowir.CallBuiltin && v.BuiltinName == "append" {
							for _, a := range v.Args {
								walk(a)
							}
						} else {
							walk(v.Recv)
							for _, a := range v.Args {
								walk(a)
							}
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
				case flowir.ValAddrOf:
					breakPlaceBase(v.AddrPlace, true)
				case flowir.ValChanRecv:
					breakTargets(v.Chan)
				case flowir.ValMethodVal:
					if v.Method != nil {
						if sig, ok := v.Method.Type().(*types.Signature); ok && sig.Recv() != nil {
							_, ptr := types.Unalias(sig.Recv().Type()).(*types.Pointer)
							if ptr || v.AutoAddr || sharesHeader(sig.Recv().Type()) || refconfine.TypeHandsOutMutableReach(sig.Recv().Type()) {
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
							if !boundValueClosureEnvLeakFreeJudged(audited, p, map[types.Object]bool{fv: true}, v.Lit.Body, wants, mw) ||
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
						case v.BuiltinName == "copy" && len(v.Args) == 2:
							if v.Args[0] != nil && v.Args[0].Kind == flowir.ValPlace {
								breakPlaceBase(v.Args[0].Place, true)
								bindPlace(v.Args[0].Place, nil, true, false)
							}
							breakTargets(v.Args[0])
							if v.Args[0] == nil || v.Args[0].Type == nil || elemReach(v.Args[0].Type) {
								breakValueVars(v.Args[1], true, func(o types.Object) bool {
									return refconfine.TypeHandsOutMutableReach(o.Type())
								})
							}
						case v.BuiltinName == "append" && len(v.Args) >= 2:
							base := v.Args[0]
							freshBase := base != nil && (base.Kind == flowir.ValScalarLitOrConst ||
								base.Kind == flowir.ValPlace && base.Place.Root == flowir.RootConstOrNil ||
								base.Kind == flowir.ValAllocFresh && (base.AllocKind == flowir.AllocMake || base.AllocKind == flowir.AllocBuiltinNewType || base.AllocKind == flowir.AllocCompositeLit) ||
								base.Kind == flowir.ValCall && base.CallKind == flowir.CallBuiltin && base.BuiltinName == "make" ||
								base.Raw != nil && isPureFreshDataExprWith(p, base.Raw, nil))
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
												pendingAppendSlices = append(pendingAppendSlices, pendingStore{
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
												return refconfine.TypeHandsOutMutableReach(o.Type())
											})
										}
									}
								} else {
									breakTargets(base)
									for _, elem := range v.Args[1:] {
										breakValueVars(elem, true, func(o types.Object) bool {
											return refconfine.TypeHandsOutMutableReach(o.Type())
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
						if !auditedValuePlane[calleeFK] {
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
									return refconfine.TypeHandsOutMutableReach(obj.Type())
								})
							}
							var classifyLit func(elts []flowir.CompositeElt)
							classifyLit = func(elts []flowir.CompositeElt) {
								for i := range elts {
									for _, part := range []*flowir.Value{elts[i].MapKey, elts[i].Value} {
										if part == nil || (part.Type != nil && !refconfine.TypeHandsOutMutableReach(part.Type)) {
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
								if arg == nil || (arg.Type != nil && !refconfine.TypeHandsOutMutableReach(arg.Type)) {
									return
								}
								switch arg.Kind {
								case flowir.ValPlace:
									if arg.Place.Obj != nil {
										obj := arg.Place.Obj
										_, tracked := trackedVar(obj)
										if (tracked || params[obj]) && refconfine.TypeHandsOutMutableReach(obj.Type()) {
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
										case "make":
											return
										case "new":
											if arg.CallAST != nil && syntaxutil.IsBuiltinNewType(p.TypesInfo, arg.CallAST) {
												return
											}
											for _, a := range arg.Args {
												classifyArg(a, calleeParam, callArgs)
											}
											return
										case "append":
											for ai, a := range arg.Args {
												if ai == len(arg.Args)-1 && arg.Ellipsis && a != nil && a.Type != nil {
													if sl, ok := types.Unalias(a.Type).Underlying().(*types.Slice); ok &&
														!refconfine.TypeHandsOutMutableReach(sl.Elem()) {
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
											innerFK := syntaxutil.FuncKey{Pkg: arg.CalleePkg, Name: arg.CalleeFunc.Name()}
											if auditedValuePlane[innerFK] && !elemReach(arg.Type) {
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
								if !ptr && !v.AutoAddrRecv && !sharesHeader(sig.Recv().Type()) && !refconfine.TypeHandsOutMutableReach(sig.Recv().Type()) {
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
									pendingStores = append(pendingStores, pendingStore{robj: dst.Obj, place: dst, source: keyVal, isMapKey: true})
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

			aliasRoot := map[types.Object]types.Object{}
			var aliasFind func(types.Object) types.Object
			aliasFind = func(x types.Object) types.Object {
				r, ok := aliasRoot[x]
				if !ok || r == x {
					return x
				}
				root := aliasFind(r)
				aliasRoot[x] = root
				return root
			}
			for _, pair := range aliasPairs {
				a, b := aliasFind(pair[0]), aliasFind(pair[1])
				if a != b {
					aliasRoot[a] = b
				}
			}

			reachRoot := map[types.Object]types.Object{}
			var reachFind func(types.Object) types.Object
			reachFind = func(x types.Object) types.Object {
				r, ok := reachRoot[x]
				if !ok || r == x {
					return x
				}
				root := reachFind(r)
				reachRoot[x] = root
				return root
			}
			for _, pairs := range [][][2]types.Object{aliasPairs, heldPairs} {
				for _, pair := range pairs {
					a, b := reachFind(pair[0]), reachFind(pair[1])
					if a != b {
						reachRoot[a] = b
					}
				}
			}

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

			isSliceOrMapType := func(t types.Type) bool {
				if t == nil {
					return false
				}
				switch types.Unalias(t).Underlying().(type) {
				case *types.Slice, *types.Map:
					return true
				}
				return false
			}
			isStructPtrType := func(t types.Type) bool {
				if t == nil {
					return false
				}
				ptr, ok := types.Unalias(t).Underlying().(*types.Pointer)
				if !ok {
					return false
				}
				_, isSt := types.Unalias(ptr.Elem()).Underlying().(*types.Struct)
				return isSt
			}
			isSliceResliceOnlyPlace := func(pl flowir.Place) bool {
				if pl.Obj == nil || pl.Obj.Type() == nil {
					return false
				}
				if _, isSl := types.Unalias(pl.Obj.Type()).Underlying().(*types.Slice); !isSl {
					return false
				}
				for _, pr := range pl.Projs {
					if pr.Kind != flowir.ProjSlice {
						return false
					}
				}
				return true
			}
			isElementReadPlace := func(pl flowir.Place) bool {
				if pl.Obj == nil || len(pl.Projs) == 0 {
					return false
				}
				idxPos := 0
				for idxPos < len(pl.Projs) && pl.Projs[idxPos].Kind == flowir.ProjSlice {
					idxPos++
				}
				if idxPos >= len(pl.Projs) || pl.Projs[idxPos].Kind != flowir.ProjIndex || pl.Projs[idxPos].BaseType == nil {
					return false
				}
				if idxPos > 0 {
					if pl.Obj.Type() == nil {
						return false
					}
					if _, isSl := types.Unalias(pl.Obj.Type()).Underlying().(*types.Slice); !isSl {
						return false
					}
				}
				return isSliceOrMapType(pl.Projs[idxPos].BaseType)
			}
			isDirectIndexPlace := func(pl flowir.Place) bool {
				if pl.Obj == nil || len(pl.Projs) == 0 {
					return false
				}
				last := len(pl.Projs) - 1
				if pl.Projs[last].Kind != flowir.ProjIndex || pl.Projs[last].BaseType == nil {
					return false
				}
				if !isSliceOrMapType(pl.Projs[last].BaseType) {
					return false
				}
				if last > 0 {
					if pl.Obj.Type() == nil {
						return false
					}
					if _, isSl := types.Unalias(pl.Obj.Type()).Underlying().(*types.Slice); !isSl {
						return false
					}
					for i := 0; i < last; i++ {
						if pl.Projs[i].Kind != flowir.ProjSlice {
							return false
						}
					}
				}
				return true
			}
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
			headerRoot := map[types.Object]types.Object{}
			var headerFind func(types.Object) types.Object
			headerFind = func(x types.Object) types.Object {
				r, ok := headerRoot[x]
				if !ok || r == x {
					return x
				}
				root := headerFind(r)
				headerRoot[x] = root
				return root
			}
			for _, pair := range headerPairs {
				a, b := headerFind(pair[0]), headerFind(pair[1])
				if a != b {
					headerRoot[a] = b
				}
			}

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
							if auditedValuePlane[calleeFK] {
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

			isSelfAppend := func(obj types.Object, src *flowir.Value) bool {
				return src != nil && src.Kind == flowir.ValCall && src.CallKind == flowir.CallBuiltin &&
					src.BuiltinName == "append" && len(src.Args) > 0 &&
					src.Args[0] != nil && src.Args[0].Kind == flowir.ValPlace &&
					src.Args[0].Place.IsBareVar() && src.Args[0].Place.Obj == obj
			}

			freshObj := map[types.Object]bool{}
			elemOwned := map[types.Object]bool{}
			var srcFresh func(v *flowir.Value) bool
			srcFresh = func(v *flowir.Value) bool {
				if v == nil {
					return false
				}
				switch v.Kind {
				case flowir.ValAllocFresh:
					switch v.AllocKind {
					case flowir.AllocMake, flowir.AllocBuiltinNewType, flowir.AllocCompositeLit:
						return true
					case flowir.AllocBuiltinNewExpr:
						return len(v.Args) == 1 && !v.Ellipsis && srcFresh(v.Args[0])
					}
					return false
				case flowir.ValConvert:
					return !v.IsTypeAssert && !syntaxutil.IsUnsafePointerType(v.Type) && srcFresh(v.Arg)
				case flowir.ValCall:
					if v.CallKind == flowir.CallBuiltin {
						switch v.BuiltinName {
						case "make":
							return true
						case "new":
							if v.CallAST != nil && syntaxutil.IsBuiltinNewType(p.TypesInfo, v.CallAST) {
								return true
							}
							return len(v.Args) == 1 && !v.Ellipsis && srcFresh(v.Args[0])
						case "append":
							return len(v.Args) > 0 && srcFresh(v.Args[0])
						}
					}
					return false
				case flowir.ValPlace:
					obj := v.Place.Obj
					if obj == nil || params[obj] || !freshObj[obj] || localBroken[obj] || rangeBound[obj] {
						return false
					}
					if len(v.Place.Projs) == 0 || isSliceResliceOnlyPlace(v.Place) {
						return true
					}
					if len(v.Place.Projs) == 1 && v.Place.Projs[0].Kind == flowir.ProjIndex && v.Place.Projs[0].BaseType != nil {
						var elemT types.Type
						switch u := types.Unalias(v.Place.Projs[0].BaseType).Underlying().(type) {
						case *types.Map:
							elemT = u.Elem()
						case *types.Slice:
							elemT = u.Elem()
						}
						if elemT != nil && (isSliceOrMapType(elemT) || isStructPtrType(elemT)) {
							return elemOwned[headerFind(obj)]
						}
					}
					return false
				}
				return false
			}
			var bindConstructsOwnedElems func(hRoot types.Object, v *flowir.Value) bool
			bindConstructsOwnedElems = func(hRoot types.Object, v *flowir.Value) bool {
				if v == nil {
					return false
				}
				switch v.Kind {
				case flowir.ValAllocFresh:
					switch v.AllocKind {
					case flowir.AllocMake:
						return true
					case flowir.AllocCompositeLit:
						for i := range v.CompositeElts {
							if v.CompositeElts[i].Value == nil || !srcFresh(v.CompositeElts[i].Value) {
								return false
							}
						}
						return true
					}
					return false
				case flowir.ValConvert:
					return !v.IsTypeAssert && isSliceOrMapType(v.Type) && bindConstructsOwnedElems(hRoot, v.Arg)
				case flowir.ValCall:
					if v.CallKind == flowir.CallBuiltin {
						switch v.BuiltinName {
						case "make":
							return true
						case "append":
							if v.Ellipsis || len(v.Args) == 0 || !bindConstructsOwnedElems(hRoot, v.Args[0]) {
								return false
							}
							for _, a := range v.Args[1:] {
								if !srcFresh(a) {
									return false
								}
							}
							return true
						}
					}
					return false
				case flowir.ValPlace:
					obj := v.Place.Obj
					if obj == nil || headerFind(obj) != hRoot || !freshObj[obj] || localBroken[obj] || rangeBound[obj] {
						return false
					}
					return len(v.Place.Projs) == 0 || isSliceResliceOnlyPlace(v.Place)
				}
				return false
			}
			for obj, binds := range directBinds {
				if params[obj] || localBroken[obj] || rangeBound[obj] || len(binds) == 0 {
					continue
				}
				nonSelf := 0
				for _, b := range binds {
					if !isSelfAppend(obj, b) {
						nonSelf++
					}
				}
				if nonSelf > 0 || hasZeroDecl[obj] {
					freshObj[obj] = true
				}
			}
			for hRoot, members := range headerMembers {
				if !headerEmbedded[hRoot] && len(members) > 0 {
					elemOwned[hRoot] = true
				}
			}
			for changed := true; changed; {
				changed = false
				for obj, binds := range directBinds {
					if !freshObj[obj] {
						continue
					}
					for _, b := range binds {
						if isSelfAppend(obj, b) {
							continue
						}
						if !srcFresh(b) {
							freshObj[obj] = false
							changed = true
							break
						}
					}
				}
				for hRoot, members := range headerMembers {
					if !elemOwned[hRoot] {
						continue
					}
					okOwned := !headerEmbedded[hRoot] && len(members) > 0
					for _, o := range members {
						if !okOwned {
							break
						}
						if !freshObj[o] || params[o] || localBroken[o] || rangeBound[o] || hasSpreadAppend[o] || len(directBinds[o]) == 0 {
							okOwned = false
							break
						}
						for _, b := range directBinds[o] {
							if !bindConstructsOwnedElems(hRoot, b) {
								okOwned = false
								break
							}
						}
						if !okOwned {
							break
						}
						for _, iw := range insertionWrites[o] {
							if !srcFresh(iw) {
								okOwned = false
								break
							}
						}
					}
					if okOwned {
						for _, ps := range pendingStores {
							if ps.robj == nil || headerFind(ps.robj) != hRoot || ps.isMapKey {
								continue
							}
							if !isDirectIndexPlace(ps.place) || !srcFresh(ps.source) {
								okOwned = false
								break
							}
						}
					}
					if okOwned {
						for _, pa := range pendingAppendSlices {
							if pa.robj == nil || headerFind(pa.robj) != hRoot {
								continue
							}
							if !isSliceResliceOnlyPlace(pa.place) || !srcFresh(pa.source) {
								okOwned = false
								break
							}
						}
					}
					if !okOwned {
						elemOwned[hRoot] = false
						changed = true
					}
				}
			}

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

			resolvedUses := map[types.Object]map[syntaxutil.EnvAuditTarget]bool{}
			resolvedParamDeps := map[types.Object]map[syntaxutil.ParamKey]bool{}
			resolvedMethodDeps := map[types.Object]map[syntaxutil.FuncKey]bool{}
			usePoison := map[types.Object]bool{}
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

			fnDeps := map[syntaxutil.FuncKey]bool{}
			for callee := range stmtCallDeps {
				fnDeps[callee] = true
			}
			insCallDeps := map[syntaxutil.EnvAuditTarget]bool{}
			retFnParamDeps := map[syntaxutil.ParamKey]bool{}
			retFnMethodDeps := map[syntaxutil.FuncKey]bool{}
			useFold := &insCallDeps
			paramDepFold := &retFnParamDeps
			methodDepFold := &retFnMethodDeps
			foldRootConfinementDeps := func(rRoot types.Object) {
				for pk := range objParamDeps[rRoot] {
					(*paramDepFold)[pk] = true
				}
				for mk := range objMethodDeps[rRoot] {
					(*methodDepFold)[mk] = true
				}
				for pk := range resolvedParamDeps[rRoot] {
					(*paramDepFold)[pk] = true
				}
				for mk := range resolvedMethodDeps[rRoot] {
					(*methodDepFold)[mk] = true
				}
			}
			recordFnDep := func(callee syntaxutil.FuncKey) {
				fnDeps[callee] = true
			}

			localFree := map[types.Object]int{} // 0 unknown, 2 free, 3 refused
			provingDepth := map[types.Object]int{}
			curDepth := 0
			inInsMode := false
			visitingLits := map[*ast.FuncLit]bool{}

			var evalFree func(v *flowir.Value) (bool, int)
			var judgeLocal func(obj types.Object) (bool, int)
			var judgeParam func(obj types.Object) (bool, int)

			// checkPlainCallReachArg ensures mutable-reach arguments passed to a
			// constructor or insertion call do not smuggle unverified mutable package
			// globals, unverified call results, or interface-boxed stateful closures.
			var checkPlainCallReachArgSeen func(arg *flowir.Value, currentCall *flowir.Value, skipInsertionRoot types.Object, allowInsParam bool, visiting map[types.Object]bool) bool
			checkPlainCallReachArgSeen = func(arg *flowir.Value, currentCall *flowir.Value, skipInsertionRoot types.Object, allowInsParam bool, visiting map[types.Object]bool) bool {
				if arg == nil || arg.Type == nil || refconfine.TypeReachesSyncNoCopyByValue(arg.Type) {
					return false
				}
				if !refconfine.TypeHandsOutMutableReach(arg.Type) {
					if carries(arg.Type) {
						okArg, _ := evalFree(arg)
						return okArg
					}
					return true
				}
				if arg.Raw != nil && isPureFreshDataExpr(p, settledGlobals, arg.Raw) {
					return true
				}
				switch arg.Kind {
				case flowir.ValScalarLitOrConst:
					return true
				case flowir.ValPlace:
					if arg.Place.Root == flowir.RootConstOrNil || arg.Place.Root == flowir.RootFunc {
						return true
					}
					if arg.Place.Root == flowir.RootPkgGlobal {
						return arg.Place.Obj != nil && settledGlobals.hasUnembedded(arg.Place.Obj)
					}
					if arg.Place.Root == flowir.RootTransient && arg.Place.Base != nil {
						return checkPlainCallReachArgSeen(arg.Place.Base, currentCall, skipInsertionRoot, allowInsParam, visiting)
					}
					if arg.Place.Obj != nil {
						obj := arg.Place.Obj
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
							if paramRebound[obj] || captureBroken[obj] || usePoison[rRoot] {
								return false
							}
						} else if localBroken[obj] || captureBroken[obj] || usePoison[rRoot] {
							return false
						}
						if !params[obj] && !freshObj[obj] && len(localSources[obj]) == 0 {
							return false
						}
						for use := range resolvedUses[rRoot] {
							(*useFold)[use] = true
						}
						foldRootConfinementDeps(rRoot)
						if !allowInsParam && rRoot != skipInsertionRoot {
							for _, use := range pendingInsertionUses {
								if reachFind(use.root) == rRoot && use.call != currentCall {
									provenLocal, conditional := pkgConf.classifyParam(ownPath, use.calleeParam)
									if !provenLocal {
										if !conditional {
											return false
										}
										(*paramDepFold)[use.calleeParam] = true
									}
								}
							}
						}
						visiting[obj] = true
						defer delete(visiting, obj)
						for _, src := range localSources[obj] {
							if !checkPlainCallReachArgSeen(src, currentCall, skipInsertionRoot, allowInsParam, visiting) {
								return false
							}
						}
						for _, st := range sharedWrites[root] {
							if !checkPlainCallReachArgSeen(st, currentCall, skipInsertionRoot, allowInsParam, visiting) {
								return false
							}
						}
						for _, st := range sharedInsertionWrites[rRoot] {
							if !checkPlainCallReachArgSeen(st, currentCall, skipInsertionRoot, allowInsParam, visiting) {
								return false
							}
						}
						return true
					}
					return false
				case flowir.ValAllocFresh:
					switch arg.AllocKind {
					case flowir.AllocMake, flowir.AllocBuiltinNewType:
						return true
					case flowir.AllocBuiltinNewExpr:
						return len(arg.Args) == 1 && checkPlainCallReachArgSeen(arg.Args[0], currentCall, skipInsertionRoot, allowInsParam, visiting)
					case flowir.AllocCompositeLit:
						for i := range arg.CompositeElts {
							if arg.CompositeElts[i].MapKey != nil && !checkPlainCallReachArgSeen(arg.CompositeElts[i].MapKey, currentCall, skipInsertionRoot, allowInsParam, visiting) {
								return false
							}
							if arg.CompositeElts[i].Value != nil && !checkPlainCallReachArgSeen(arg.CompositeElts[i].Value, currentCall, skipInsertionRoot, allowInsParam, visiting) {
								return false
							}
						}
						return true
					}
				case flowir.ValConvert:
					return !arg.IsTypeAssert && !syntaxutil.IsUnsafePointerType(arg.Type) && checkPlainCallReachArgSeen(arg.Arg, currentCall, skipInsertionRoot, allowInsParam, visiting)
				case flowir.ValCall:
					if arg.CallKind == flowir.CallBuiltin {
						switch arg.BuiltinName {
						case "make":
							return true
						case "new":
							if arg.CallAST != nil && syntaxutil.IsBuiltinNewType(p.TypesInfo, arg.CallAST) {
								return true
							}
							return len(arg.Args) == 1 && !arg.Ellipsis && checkPlainCallReachArgSeen(arg.Args[0], currentCall, skipInsertionRoot, allowInsParam, visiting)
						case "append":
							if len(arg.Args) == 0 {
								return false
							}
							if arg.Args[0] == nil || arg.Args[0].Raw == nil || !isPureFreshDataExprWith(p, arg.Args[0].Raw, nil) {
								return false
							}
							for _, a := range arg.Args {
								if !checkPlainCallReachArgSeen(a, currentCall, skipInsertionRoot, allowInsParam, visiting) {
									return false
								}
							}
							return true
						}
						return false
					}
					if arg.CallKind == flowir.CallPlain && arg.CalleeFunc != nil && !arg.IsMethodExprCall {
						fk := syntaxutil.FuncKey{Pkg: arg.CalleePkg, Name: arg.CalleeFunc.Name()}
						if !auditedValuePlane[fk] {
							return false
						}
						for _, a := range arg.Args {
							if !checkPlainCallReachArgSeen(a, currentCall, skipInsertionRoot, allowInsParam, visiting) {
								return false
							}
						}
						return true
					}
				}
				return false
			}
			checkPlainCallReachArg := func(arg *flowir.Value, currentCall *flowir.Value) bool {
				return checkPlainCallReachArgSeen(arg, currentCall, nil, false, map[types.Object]bool{})
			}
			checkInsStoredReachArg := func(arg *flowir.Value) bool {
				return checkPlainCallReachArgSeen(arg, nil, nil, true, map[types.Object]bool{})
			}

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

			judgeParam = func(obj types.Object) (bool, int) {
				root := aliasFind(obj)
				rRoot := reachFind(obj)
				if inInsMode {
					if paramRebound[obj] || captureBroken[obj] || usePoison[rRoot] {
						localFree[obj] = 3
						return false, math.MaxInt
					}
				} else if localBroken[obj] || usePoison[rRoot] {
					localFree[obj] = 3
					return false, math.MaxInt
				}
				for use := range resolvedUses[rRoot] {
					(*useFold)[use] = true
				}
				foldRootConfinementDeps(rRoot)
				switch localFree[obj] {
				case 2:
					return true, math.MaxInt
				case 3:
					return false, math.MaxInt
				}
				if d, active := provingDepth[obj]; active && d > 0 {
					return true, d
				}
				myDepth := curDepth + 1
				curDepth = myDepth
				provingDepth[obj] = myDepth
				defer func() {
					delete(provingDepth, obj)
					curDepth = myDepth - 1
				}()

				minCycle := math.MaxInt
				for _, stored := range sharedWrites[root] {
					okSt, cyc := evalFree(stored)
					if !okSt {
						localFree[obj] = 3
						return false, math.MaxInt
					}
					if cyc < minCycle {
						minCycle = cyc
					}
				}
				for _, stored := range sharedInsertionWrites[rRoot] {
					okSt, cyc := evalFree(stored)
					if !okSt {
						localFree[obj] = 3
						return false, math.MaxInt
					}
					if cyc < minCycle {
						minCycle = cyc
					}
				}
				if minCycle >= myDepth {
					localFree[obj] = 2
					return true, math.MaxInt
				}
				return true, minCycle
			}

			judgeLocal = func(obj types.Object) (bool, int) {
				root := aliasFind(obj)
				rRoot := reachFind(obj)
				if usePoison[rRoot] {
					localFree[obj] = 3
					return false, math.MaxInt
				}
				for use := range resolvedUses[rRoot] {
					(*useFold)[use] = true
				}
				foldRootConfinementDeps(rRoot)
				switch localFree[obj] {
				case 2:
					return true, math.MaxInt
				case 3:
					return false, math.MaxInt
				}
				if d, active := provingDepth[obj]; active && d > 0 {
					return true, d
				}
				if localBroken[obj] {
					localFree[obj] = 3
					return false, math.MaxInt
				}
				myDepth := curDepth + 1
				curDepth = myDepth
				provingDepth[obj] = myDepth
				defer func() {
					delete(provingDepth, obj)
					curDepth = myDepth - 1
				}()

				minCycle := math.MaxInt
				for _, src := range localSources[obj] {
					okSrc, cyc := evalFree(src)
					if !okSrc {
						localFree[obj] = 3
						return false, math.MaxInt
					}
					if cyc < minCycle {
						minCycle = cyc
					}
				}
				for _, stored := range sharedWrites[root] {
					okSt, cyc := evalFree(stored)
					if !okSt {
						localFree[obj] = 3
						return false, math.MaxInt
					}
					if cyc < minCycle {
						minCycle = cyc
					}
				}
				for _, stored := range sharedInsertionWrites[rRoot] {
					okSt, cyc := evalFree(stored)
					if !okSt {
						localFree[obj] = 3
						return false, math.MaxInt
					}
					if cyc < minCycle {
						minCycle = cyc
					}
				}
				if minCycle >= myDepth {
					localFree[obj] = 2
					return true, math.MaxInt
				}
				return true, minCycle
			}

			evalFree = func(v *flowir.Value) (bool, int) {
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
						return evalFree(v.Args[0])
					case flowir.AllocCompositeLit:
						for i := range v.CompositeElts {
							if v.CompositeElts[i].MapKey != nil {
								if !merge(evalFree(v.CompositeElts[i].MapKey)) {
									return false, math.MaxInt
								}
							}
							if v.CompositeElts[i].Value != nil {
								if !merge(evalFree(v.CompositeElts[i].Value)) {
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
					savedInsMode := inInsMode
					var savedLocalFree map[types.Object]int
					if savedInsMode {
						inInsMode = false
						savedLocalFree = localFree
						localFree = map[types.Object]int{}
						defer func() {
							inInsMode = savedInsMode
							localFree = savedLocalFree
						}()
					}
					wants := map[syntaxutil.ParamKey]bool{}
					methodWants := map[syntaxutil.FuncKey]bool{}
					origin := &rootOriginPolicy{
						verifyLocalOrigins:   true,
						allowEnclosingParams: true,
						settledGlobals:       settledGlobals,
						checkCarryingValue: func(sub *flowir.Value) bool {
							okSub, _ := evalFree(sub)
							return okSub
						},
					}
					if !environmentFreeFuncLitWithOrigin(audited, p, v.Lit, fd, wants, methodWants, origin) {
						return false, math.MaxInt
					}
					if !classifyWants(wants, methodWants, *paramDepFold, *methodDepFold) {
						return false, math.MaxInt
					}
					// Ensure any captured signature-carrying or mutable-reach outer local/param in fd is also sound.
					for fv := range v.Closure.FreeVars {
						if refconfine.TypeHandsOutMutableReach(fv.Type()) {
							fvVal := &flowir.Value{
								Kind: flowir.ValPlace,
								Type: fv.Type(),
								Place: flowir.Place{
									Root: flowir.RootLocal,
									Obj:  fv,
									Type: fv.Type(),
								},
							}
							if !checkPlainCallReachArg(fvVal, nil) {
								return false, math.MaxInt
							}
						}
						if !carries(fv.Type()) {
							continue
						}
						if params[fv] {
							if !merge(judgeParam(fv)) {
								return false, math.MaxInt
							}
						} else if syntaxutil.IsLocalVar(fv) {
							if !merge(judgeLocal(fv)) {
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
							return judgeParam(obj)
						}
						if syntaxutil.IsLocalVar(obj) {
							return judgeLocal(obj)
						}
					case flowir.RootTransient:
						if v.Place.Base != nil {
							return evalFree(v.Place.Base)
						}
					}
					return false, math.MaxInt

				case flowir.ValConvert:
					if v.IsTypeAssert || v.Arg == nil {
						return false, math.MaxInt
					}
					return evalFree(v.Arg)

				case flowir.ValCall:
					switch v.CallKind {
					case flowir.CallBuiltin:
						switch v.BuiltinName {
						case "make":
							return true, math.MaxInt
						case "new":
							if v.CallAST != nil && syntaxutil.IsBuiltinNewType(p.TypesInfo, v.CallAST) {
								return true, math.MaxInt
							}
							if len(v.Args) == 1 {
								return evalFree(v.Args[0])
							}
							return false, math.MaxInt
						case "append":
							for _, arg := range v.Args {
								if !merge(evalFree(arg)) {
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
						// Reject passing the same mutable-reach local/param twice to a constructor call.
						perArg := make([]map[types.Object]bool, len(v.Args))
						for i, arg := range v.Args {
							if !merge(evalFree(arg)) {
								return false, math.MaxInt
							}
							if !auditedValuePlane[calleeFK] {
								if !checkPlainCallReachArg(arg, v) {
									return false, math.MaxInt
								}
								perArg[i] = collectMutableArgRoots(arg)
							}
						}
						if !auditedValuePlane[calleeFK] {
							for i := 0; i < len(perArg); i++ {
								for j := i + 1; j < len(perArg); j++ {
									for r := range perArg[i] {
										if perArg[j][r] && !params[r] {
											return false, math.MaxInt
										}
									}
								}
							}
							recordFnDep(calleeFK)
						}
						return true, minCycle
					}
					return false, math.MaxInt
				}
				return false, math.MaxInt
			}

			free := func(v *flowir.Value) bool {
				okVal, _ := evalFree(v)
				return okVal
			}

			computeResolvedUses := func(insMode bool) (
				map[types.Object]bool,
				map[types.Object]map[syntaxutil.EnvAuditTarget]bool,
				map[types.Object]map[syntaxutil.ParamKey]bool,
				map[types.Object]map[syntaxutil.FuncKey]bool,
			) {
				poison := map[types.Object]bool{}
				resolved := map[types.Object]map[syntaxutil.EnvAuditTarget]bool{}
				resParams := map[types.Object]map[syntaxutil.ParamKey]bool{}
				resMethods := map[types.Object]map[syntaxutil.FuncKey]bool{}
				prevPoison, prevResolved, prevResP, prevResM, prevInsMode := usePoison, resolvedUses, resolvedParamDeps, resolvedMethodDeps, inInsMode
				usePoison = poison
				resolvedUses = resolved
				resolvedParamDeps = resParams
				resolvedMethodDeps = resMethods
				inInsMode = insMode

				step := func(record bool) bool {
					changed := false
					for _, use := range pendingInsertionUses {
						rRoot := reachFind(use.root)
						if poison[rRoot] {
							continue
						}
						argFnDeps := map[syntaxutil.FuncKey]bool{}
						argUseDeps := map[syntaxutil.EnvAuditTarget]bool{}
						argParamDeps := map[syntaxutil.ParamKey]bool{}
						argMethodDeps := map[syntaxutil.FuncKey]bool{}
						prevRec, prevFold, prevPFold, prevMFold := recordFnDep, useFold, paramDepFold, methodDepFold
						recordFnDep = func(callee syntaxutil.FuncKey) { argFnDeps[callee] = true }
						useFold = &argUseDeps
						paramDepFold = &argParamDeps
						methodDepFold = &argMethodDeps
						clear(localFree)

						allFree := true
						for _, a := range use.args {
							if !free(a) {
								allFree = false
								break
							}
							if a != nil && a.Type != nil && refconfine.TypeHandsOutMutableReach(a.Type) &&
								!checkPlainCallReachArgSeen(a, use.call, rRoot, insMode, map[types.Object]bool{}) {
								allFree = false
								break
							}
						}
						recordFnDep, useFold, paramDepFold, methodDepFold = prevRec, prevFold, prevPFold, prevMFold

						if !allFree {
							poison[rRoot] = true
							changed = true
							continue
						}
						if record {
							if resolved[rRoot] == nil {
								resolved[rRoot] = map[syntaxutil.EnvAuditTarget]bool{}
							}
							addUse := func(t syntaxutil.EnvAuditTarget) {
								if !resolved[rRoot][t] {
									resolved[rRoot][t] = true
									changed = true
								}
							}
							addUse(syntaxutil.ParamAuditTarget(use.calleeParam))
							for fk := range argFnDeps {
								addUse(syntaxutil.FuncAuditTarget(fk))
							}
							for u := range argUseDeps {
								addUse(u)
							}
							for pk := range argParamDeps {
								if resParams[rRoot] == nil {
									resParams[rRoot] = map[syntaxutil.ParamKey]bool{}
								}
								if !resParams[rRoot][pk] {
									resParams[rRoot][pk] = true
									changed = true
								}
							}
							for mk := range argMethodDeps {
								if resMethods[rRoot] == nil {
									resMethods[rRoot] = map[syntaxutil.FuncKey]bool{}
								}
								if !resMethods[rRoot][mk] {
									resMethods[rRoot][mk] = true
									changed = true
								}
							}
						}
					}
					return changed
				}

				scratchFnDeps := map[syntaxutil.FuncKey]bool{}
				scratchUseDeps := map[syntaxutil.EnvAuditTarget]bool{}
				scratchParamDeps := map[syntaxutil.ParamKey]bool{}
				scratchMethodDeps := map[syntaxutil.FuncKey]bool{}
				savedRecordFnDep, savedFold, savedPFold, savedMFold := recordFnDep, useFold, paramDepFold, methodDepFold
				recordFnDep = func(callee syntaxutil.FuncKey) { scratchFnDeps[callee] = true }
				useFold = &scratchUseDeps
				paramDepFold = &scratchParamDeps
				methodDepFold = &scratchMethodDeps
				for step(false) {
					clear(localFree)
				}
				recordFnDep, useFold, paramDepFold, methodDepFold = savedRecordFnDep, savedFold, savedPFold, savedMFold
				clear(localFree)
				for step(true) {
					clear(localFree)
				}
				clear(localFree)

				usePoison, resolvedUses, resolvedParamDeps, resolvedMethodDeps, inInsMode = prevPoison, prevResolved, prevResP, prevResM, prevInsMode
				return poison, resolved, resParams, resMethods
			}

			retUsePoison, retResolvedUses, retResParamDeps, retResMethodDeps := computeResolvedUses(false)
			insUsePoison, insResolvedUses, insResParamDeps, insResMethodDeps := computeResolvedUses(true)
			usePoison = insUsePoison
			resolvedUses = insResolvedUses
			resolvedParamDeps = insResParamDeps
			resolvedMethodDeps = insResMethodDeps

			for obj, idx := range paramIndex {
				key := syntaxutil.ParamKey{Func: ownFuncKey, Index: idx}
				root := aliasFind(obj)
				rRoot := reachFind(obj)
				if captureBroken[obj] || usePoison[rRoot] {
					continue
				}
				clear(localFree)
				collected := map[syntaxutil.EnvAuditTarget]bool{}
				collectedParams := map[syntaxutil.ParamKey]bool{}
				collectedMethods := map[syntaxutil.FuncKey]bool{}
				savedRec, savedF, savedPF, savedMF := recordFnDep, useFold, paramDepFold, methodDepFold
				recordFnDep = func(callee syntaxutil.FuncKey) { collected[syntaxutil.FuncAuditTarget(callee)] = true }
				useFold = &collected
				paramDepFold = &collectedParams
				methodDepFold = &collectedMethods
				inInsMode = true
				foldRootConfinementDeps(rRoot)
				okIns := true
				for _, stored := range append(append([]*flowir.Value{}, sharedWrites[root]...), sharedInsertionWrites[rRoot]...) {
					if !free(stored) {
						okIns = false
						break
					}
					if stored != nil && stored.Type != nil && refconfine.TypeHandsOutMutableReach(stored.Type) &&
						!checkInsStoredReachArg(stored) {
						okIns = false
						break
					}
				}
				inInsMode = false
				recordFnDep, useFold, paramDepFold, methodDepFold = savedRec, savedF, savedPF, savedMF
				if !okIns {
					continue
				}
				for use := range resolvedUses[rRoot] {
					collected[use] = true
				}
				insFree[key] = true
				if len(collected) > 0 {
					insDeps[key] = collected
				}
				if len(collectedParams) > 0 {
					insParamDeps[key] = collectedParams
				}
				if len(collectedMethods) > 0 {
					insMethodDeps[key] = collectedMethods
				}
			}
			usePoison = retUsePoison
			resolvedUses = retResolvedUses
			resolvedParamDeps = retResParamDeps
			resolvedMethodDeps = retResMethodDeps
			clear(localFree)

			emitRefusal := func(v *flowir.Value) {
				if hooks == nil || hooks.Refusal == nil || v == nil || v.Raw == nil {
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
					case obj != nil && usePoison[reachFind(obj)]:
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
			if hooks != nil && hooks.Refusal != nil {
				innerEval := evalFree
				evalFree = func(v *flowir.Value) (bool, int) {
					r, cyc := innerEval(v)
					if !r {
						emitRefusal(v)
					}
					return r, cyc
				}
			}

			okRet := true
			body.ForEachSyncOp(func(op *flowir.Op) bool {
				if op.Kind != flowir.OpReturn {
					return true
				}
				if op.IsNaked {
					okRet = false
					return false
				}
				for _, res := range op.Results {
					if !free(res) {
						okRet = false
						return false
					}
				}
				return true
			})
			if !okRet {
				continue
			}
			proven[fnKey] = true
			if len(fnDeps) > 0 {
				deps[fnKey] = fnDeps
			}
			if len(retFnParamDeps) > 0 {
				retParamDeps[fnKey] = retFnParamDeps
			}
			if len(retFnMethodDeps) > 0 {
				retMethodDeps[fnKey] = retFnMethodDeps
			}
			if len(insCallDeps) > 0 {
				callerInsDeps[fnKey] = insCallDeps
			}
			recordReturnFieldRegistrants(audited, p, fnKey, fd.Body, retDefer, retPoison)
		}
	}
	return proven, deps, retParamDeps, retMethodDeps, retDefer, retPoison, insFree, insDeps, insParamDeps, insMethodDeps, callerInsDeps
}

func recordReturnFieldRegistrants(
	audited bool,
	p *packages.Package,
	fnKey string,
	body ast.Node,
	retDefer map[string]map[syntaxutil.ReturnFieldParamDefer]bool,
	retPoison map[string]map[syntaxutil.ReturnFieldParamPoison]bool,
) {
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
	fieldWrite := func(lhs, rhs ast.Expr) {
		if sel, ok := syntaxutil.UnparenExpr(lhs).(*ast.SelectorExpr); ok {
			if selection, ok := p.TypesInfo.Selections[sel]; ok && selection.Kind() == types.FieldVal {
				if _, isSig := types.Unalias(selection.Type()).Underlying().(*types.Signature); isSig {
					classifyFieldRegistrantValue(audited, p, sel.Sel.Name, rhs, emit)
				}
			}
		}
		if _, mapKey, ok := syntaxutil.LHSMapWriteKey(p.TypesInfo, lhs); ok {
			classifyRegistrantFlow(audited, p, mapKey, emit)
		}
	}
	funPositions := map[ast.Node]bool{}
	writePositions := map[ast.Node]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
		funLoop:
			for cur := syntaxutil.UnparenExpr(n.Fun); ; {
				funPositions[cur] = true
				switch x := cur.(type) {
				case *ast.IndexExpr:
					cur = syntaxutil.UnparenExpr(x.X)
				case *ast.IndexListExpr:
					cur = syntaxutil.UnparenExpr(x.X)
				case *ast.SelectorExpr:
					funPositions[x.Sel] = true
					break funLoop
				default:
					break funLoop
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range n.Lhs {
				writePositions[syntaxutil.UnparenExpr(lhs)] = true
			}
		case *ast.IncDecStmt:
			writePositions[syntaxutil.UnparenExpr(n.X)] = true
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			classifyRegistrantComposite(audited, p, n, emit)
			return false
		case *ast.AssignStmt:
			if len(n.Lhs) == len(n.Rhs) {
				for i, lhs := range n.Lhs {
					fieldWrite(lhs, n.Rhs[i])
				}
			} else if len(n.Rhs) == 1 {
				for _, lhs := range n.Lhs {
					fieldWrite(lhs, n.Rhs[0])
				}
			}
		case *ast.IncDecStmt:
			if _, mapKey, ok := syntaxutil.LHSMapWriteKey(p.TypesInfo, n.X); ok {
				classifyRegistrantFlow(audited, p, mapKey, emit)
			}
		case *ast.FuncLit:
			if !funPositions[n] {
				classifyLiteralRegistrant(audited, p, syntaxutil.ElemPositionField, n, emit)
			}
		case *ast.CallExpr:
			if tv, ok := p.TypesInfo.Types[n.Fun]; ok && tv.IsType() {
				break
			}
			if ident, ok := syntaxutil.UnparenExpr(n.Fun).(*ast.Ident); ok {
				if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
					break
				}
			}
			if fn, _ := syntaxutil.PlainCalleeFunc(p, n.Fun); fn != nil {
				break
			}
			if refconfine.TypeCarriesSignature(p.TypesInfo.TypeOf(n)) {
				emit(fieldRegMark{class: 'p', field: syntaxutil.ElemPositionField, idx: -1})
			}
		case *ast.SelectorExpr:
			if funPositions[n] || writePositions[n] {
				break
			}
			if _, isSelection := p.TypesInfo.Selections[n]; !isSelection {
				if _, isFunc := p.TypesInfo.Uses[n.Sel].(*types.Func); isFunc {
					classifyFieldRegistrantValue(audited, p, syntaxutil.ElemPositionField, n, emit)
					break
				}
			}
			if refconfine.TypeCarriesSignature(p.TypesInfo.TypeOf(n)) {
				emit(fieldRegMark{class: 'p', field: syntaxutil.ElemPositionField, idx: -1})
			}
		case *ast.IndexExpr, *ast.IndexListExpr:
			expr := n.(ast.Expr)
			if funPositions[n] || writePositions[n] {
				break
			}
			if fn, _ := syntaxutil.PlainCalleeFunc(p, expr); fn != nil {
				classifyFieldRegistrantValue(audited, p, syntaxutil.ElemPositionField, expr, emit)
				break
			}
			if refconfine.TypeCarriesSignature(p.TypesInfo.TypeOf(expr)) {
				emit(fieldRegMark{class: 'p', field: syntaxutil.ElemPositionField, idx: -1})
			}
		case *ast.Ident:
			if funPositions[n] {
				break
			}
			if _, isFunc := p.TypesInfo.Uses[n].(*types.Func); isFunc {
				classifyFieldRegistrantValue(audited, p, syntaxutil.ElemPositionField, n, emit)
				break
			}
			if v, ok := p.TypesInfo.Uses[n].(*types.Var); ok && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() && refconfine.TypeCarriesSignature(v.Type()) {
				emit(fieldRegMark{class: 'p', idx: -1})
			}
		}
		return true
	})
}
