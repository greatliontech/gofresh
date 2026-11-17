package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/dynstate/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// settledGlobalMap maps each proven settled unexported package data global to
// the set of single-definition carrier variables whose top-level initializer
// embeds its mutable reach directly (empty when never embedded in a carrier).
type settledGlobalMap map[*types.Var]map[*types.Var]bool

func (m settledGlobalMap) hasUnembedded(v *types.Var) bool {
	if m == nil || v == nil {
		return false
	}
	carriers, ok := m[v]
	return ok && len(carriers) == 0
}

func (m settledGlobalMap) allowedForTargets(v *types.Var, targets []*types.Var) bool {
	if m == nil || v == nil {
		return false
	}
	carriers, ok := m[v]
	if !ok {
		return false
	}
	if len(carriers) == 0 {
		return true
	}
	return len(targets) == 1 && carriers[targets[0]]
}

// isSettledReachArgValue reports whether val, appearing as a mutable-reach
// argument to a plain constructor call at a registration site (whose signature
// plane was already verified by carryingValue(val)), introduces no unsettled
// mutable reach.
func isSettledReachArgValue(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	settledGlobals settledGlobalMap,
	currentTargets []*types.Var,
	enclosing ast.Node,
	exemptCall *ast.CallExpr,
	pkgConf *packageConfinementSummary,
	paramSink map[syntaxutil.ParamKey]bool,
	methodSink map[syntaxutil.FuncKey]bool,
	checkSigOrigin func(*flowir.Value) bool,
	val *flowir.Value,
) bool {
	return isSettledReachArgValueSeen(audited, p, fc, settledGlobals, currentTargets, enclosing, exemptCall, pkgConf, paramSink, methodSink, checkSigOrigin, val, map[*types.Var]bool{})
}

func isSettledReachArgValueSeen(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	settledGlobals settledGlobalMap,
	currentTargets []*types.Var,
	enclosing ast.Node,
	exemptCall *ast.CallExpr,
	pkgConf *packageConfinementSummary,
	paramSink map[syntaxutil.ParamKey]bool,
	methodSink map[syntaxutil.FuncKey]bool,
	checkSigOrigin func(*flowir.Value) bool,
	val *flowir.Value,
	visiting map[*types.Var]bool,
) bool {
	if p == nil || p.TypesInfo == nil || val == nil || val.IsTypeExpr || val.Type == nil {
		return false
	}
	if isPureFreshDataValue(settledGlobals, val) {
		return true
	}
	localParams := map[syntaxutil.ParamKey]bool{}
	localMethods := map[syntaxutil.FuncKey]bool{}
	commitSinks := func() bool {
		if len(localParams) > 0 {
			if paramSink == nil {
				return false
			}
			for pk := range localParams {
				paramSink[pk] = true
			}
		}
		if len(localMethods) > 0 {
			if methodSink == nil {
				return false
			}
			for mk := range localMethods {
				methodSink[mk] = true
			}
		}
		return true
	}
	ok := checkPureOrFreshValue(val, valuePurityPolicy{
		allowAppend:          true,
		allowValuePlane:      true,
		allowRuntimeOps:      true,
		allowNonMutableReach: true,
		allowSigLeaf: func(leaf *flowir.Value) bool {
			return checkSigOrigin != nil && checkSigOrigin(leaf)
		},
		allowPlace: func(pv *flowir.Value) bool {
			if !pv.Place.IsBareVar() {
				return false
			}
			v := pv.Place.Obj
			if v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
				return settledGlobals.allowedForTargets(v, currentTargets)
			}
			if !syntaxutil.IsLocalVar(v) || enclosing == nil || visiting[v] {
				return false
			}
			enclBody := fc.scopeBody(p, enclosing)
			if enclBody == nil || !enclBody.OwnsVar(v) {
				return false
			}
			if v == enclBody.Recv || enclBody.ResultSet[v] {
				return false
			}
			if _, isParam := enclBody.ParamIndex[v]; isParam {
				return false
			}
			visiting[v] = true
			defer delete(visiting, v)
			defs := 0
			var initVal *flowir.Value
			enclBody.ForEachSyncOp(func(op *flowir.Op) bool {
				if op.Kind == flowir.OpAssign {
					op.ForEachAssignPair(func(_ int, dst flowir.Place, isDef bool, src *flowir.Value) bool {
						if dst.Obj == v {
							if dst.IsBareVar() && isDef && src != nil {
								defs++
								initVal = src
							} else {
								defs = 2
							}
						}
						return true
					})
				}
				return true
			})
			if defs != 1 || initVal == nil || !isSettledReachArgValueSeen(audited, p, fc, settledGlobals, currentTargets, enclosing, nil, pkgConf, localParams, localMethods, checkSigOrigin, initVal, visiting) {
				return false
			}
			wants := map[syntaxutil.ParamKey]bool{}
			methodWants := map[syntaxutil.FuncKey]bool{}
			roots := map[types.Object]bool{v: true}
			origin := &rootOriginPolicy{
				verifyLocalOrigins: true,
				settledGlobals:     settledGlobals,
				currentTargets:     currentTargets,
				checkCarryingValue: checkSigOrigin,
			}
			if !enclosingConfinesRoots(audited, p, fc, enclosing, nil, exemptCall, roots, wants, methodWants, origin) {
				return false
			}
			ownPath := ""
			if p.Types != nil {
				ownPath = p.Types.Path()
			}
			for w := range wants {
				provenLocal, conditional := pkgConf.classifyParam(ownPath, w)
				if !provenLocal && !conditional {
					return false
				}
				if !provenLocal {
					localParams[w] = true
				}
			}
			for mw := range methodWants {
				provenLocal, conditional := pkgConf.classifyMethod(ownPath, mw)
				if !provenLocal && !conditional {
					return false
				}
				if !provenLocal {
					localMethods[mw] = true
				}
			}
			return true
		},
	})
	return ok && commitSinks()
}

func elemHandsOutReach(t types.Type) bool {
	if t == nil {
		return true
	}
	hasReach := func(et types.Type) bool {
		return refconfine.TypeHandsOutMutableReach(et) || syntaxutil.ContainsUintptr(et)
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Slice:
		return hasReach(u.Elem())
	case *types.Map:
		return hasReach(u.Key()) || hasReach(u.Elem())
	default:
		return true
	}
}

func varSetEqual(a, b map[*types.Var]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// settledPackageDataGlobals identifies unexported non-carrier package-scope
// variables initialized from pure fresh data expressions and never mutated or
// leaked anywhere in p, recording any single-definition unbroken carrier whose
// initializer directly embeds the global's mutable reach.
func settledPackageDataGlobals(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	paramLeakFree map[syntaxutil.ParamKey]bool,
	readOnly map[string]bool,
	unattestedBroken map[string]bool,
	singleSubjectVars map[string]bool,
) settledGlobalMap {
	if p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 {
		return nil
	}
	ownPath := p.Types.Path()
	funcDecls := map[*types.Func]*ast.FuncDecl{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name != nil && fd.Body != nil {
				if fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func); ok && fn != nil {
					funcDecls[fn] = fd
				}
			}
		}
	}

	candidates := map[*types.Var]*flowir.Value{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != len(vs.Values) {
					continue
				}
				for i, name := range vs.Names {
					if name == nil || name.IsExported() || name.Name == "_" {
						continue
					}
					v, ok := p.TypesInfo.Defs[name].(*types.Var)
					if !ok || v == nil || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() {
						continue
					}
					if refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) ||
						refconfine.TypeReachesSyncNoCopyByValue(v.Type()) {
						continue
					}
					candidates[v] = fc.exprValue(p, vs.Values[i])
				}
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	// Fixed-point seed: keep candidates whose own initializer is pure fresh data.
	settled := settledGlobalMap{}
	settledRawExported := map[*types.Var]bool{}
	inSettledVar := func(gv *types.Var) bool {
		_, ok := settled[gv]
		return ok
	}
	for changed := true; changed; {
		changed = false
		for v, initVal := range candidates {
			if _, ok := settled[v]; ok {
				continue
			}
			if isPureFreshDataValueWith(initVal, inSettledVar) {
				settled[v] = map[*types.Var]bool{}
				changed = true
			}
		}
	}
	if len(settled) == 0 {
		return nil
	}

	wantsResolve := func(wants map[syntaxutil.ParamKey]bool, methodWants map[syntaxutil.FuncKey]bool) bool {
		for w := range wants {
			if w.Func.Pkg != ownPath || !paramLeakFree[w] {
				return false
			}
		}
		for mw := range methodWants {
			if mw.Pkg != ownPath || !readOnly[mw.Name] {
				return false
			}
		}
		return true
	}

	carrierSafeForEmbedding := func(carrier *types.Var, ownSpec *ast.ValueSpec, embedsRawData bool) bool {
		if carrier == nil {
			return false
		}
		key := syntaxutil.DynamicVarKey(carrier)
		if unattestedBroken[key] || singleSubjectVars[key] {
			return false
		}
		if carrier.Exported() && embedsRawData && !refconfine.TypeHandsOutDynamicAlias(audited, carrier.Type()) {
			return false
		}
		for _, file := range p.Syntax {
			for _, decl := range file.Decls {
				switch d := decl.(type) {
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						vs, ok := spec.(*ast.ValueSpec)
						if !ok || vs == ownSpec {
							continue
						}
						if bodyMentionsVar(fc.body(p, vs), carrier) {
							return false
						}
					}
				case *ast.FuncDecl:
					if d.Body == nil || d.Name == nil {
						continue
					}
					if !bodyMentionsVar(fc.funcBody(p, d), carrier) {
						continue
					}
					wants := map[syntaxutil.ParamKey]bool{}
					mw := map[syntaxutil.FuncKey]bool{}
					if !enclosingConfinesRoots(audited, p, fc, d, nil, nil, map[types.Object]bool{carrier: true}, wants, mw, nil) ||
						!wantsResolve(wants, mw) {
						return false
					}
				}
			}
		}
		return true
	}

	reachOrStr := func(t types.Type) bool {
		return refconfine.TypeHandsOutMutableReach(t) || syntaxutil.ContainsUintptr(t)
	}

	checkTopValueSpecUse := func(g *types.Var, vs *ast.ValueSpec, embeddedOut map[*types.Var]bool, embeddedRawExported *bool) bool {
		if len(vs.Names) == 1 && len(vs.Values) == 1 {
			if lhsVar, ok := p.TypesInfo.Defs[vs.Names[0]].(*types.Var); ok && lhsVar != nil {
				carriersOfLHS, inSettled := settled[lhsVar]
				isCarrierLHS := refconfine.TypeMayCarryUnknownDynamic(audited, lhsVar.Type())
				if !inSettled && !isCarrierLHS && reachOrStr(lhsVar.Type()) {
					return false
				}
				rhsVal := fc.exprValue(p, vs.Values[0])
				if rhsVal == nil {
					return false
				}
				okSpec := true
				embedsReach := false
				embedsRawData := false
				var checkVal func(v *flowir.Value)
				checkVal = func(v *flowir.Value) {
					if !okSpec || v == nil {
						return
					}
					switch v.Kind {
					case flowir.ValPlace:
						if v.Place.Obj == g && reachOrStr(g.Type()) &&
							(len(v.Place.Projs) == 0 || v.Type == nil || reachOrStr(v.Type)) {
							embedsReach = true
							embedsRawData = true
						}
					case flowir.ValConvert:
						if syntaxutil.IsUnsafePointerType(v.Type) && valueMentionsVar(v.Arg, g) {
							okSpec = false
							return
						}
					case flowir.ValAddrOf:
						if v.AddrPlace.Obj == g {
							okSpec = false
							return
						}
					case flowir.ValMethodVal:
						if v.Recv != nil && valueMentionsVar(v.Recv, g) {
							okSpec = false
							return
						}
					case flowir.ValMakeClosure:
						if v.Lit != nil && bodyMentionsVar(v.Closure, g) {
							wants := map[syntaxutil.ParamKey]bool{}
							mw := map[syntaxutil.FuncKey]bool{}
							if !enclosingConfinesRoots(audited, p, fc, v.Lit, nil, nil, map[types.Object]bool{g: true}, wants, mw, nil) ||
								!wantsResolve(wants, mw) {
								okSpec = false
								return
							}
						}
						return
					case flowir.ValCall:
						if v.CallKind == flowir.CallIIFE {
							if valueMentionsVar(v, g) {
								okSpec = false
							}
							return
						}
						if v.CallKind == flowir.CallBuiltin {
							switch v.BuiltinName {
							case "StringData", "String":
								if valueMentionsVar(v, g) {
									okSpec = false
								}
								return
							case "Sizeof", "Alignof", "Offsetof":
								return
							case "len", "cap":
								for _, arg := range v.Args {
									if arg != nil && arg.Kind == flowir.ValPlace && arg.Place.Obj == g && len(arg.Place.Projs) == 0 {
										continue
									}
									checkVal(arg)
								}
								return
							}
						}
						if v.CallKind == flowir.CallPlain && !v.IsMethodExprCall && v.CalleeFunc != nil {
							fk := syntaxutil.FuncKey{Pkg: v.CalleePkg, Name: v.CalleeFunc.Origin().Name()}
							if auditset.ValuePlaneClone(fk.Pkg, fk.Name) {
								shallowSafe := !elemHandsOutReach(v.Type)
								for _, arg := range v.Args {
									if shallowSafe && arg != nil && arg.Kind == flowir.ValPlace && arg.Place.Obj == g && len(arg.Place.Projs) == 0 {
										continue
									}
									checkVal(arg)
								}
								return
							}
							v.ForEachArgParam(func(arg *flowir.Value, slotType types.Type, _ int, pIdx int, pOK bool, packedVariadic bool) bool {
								if !okSpec || !valueMentionsVar(arg, g) {
									return okSpec
								}
								paramType := v.FormalParamSlotType(pIdx, packedVariadic)
								handsOutSlot := refconfine.CallResultHandsOut(slotType) ||
									(paramType != nil && refconfine.CallResultHandsOut(paramType) && refconfine.CallResultHandsOut(slotType))
								if slotType != nil && !handsOutSlot &&
									!(v.AutoAddrRecv && v.HasRecvPlace && v.RecvPlace.Obj == g) {
									return true
								}
								if !reachOrStr(g.Type()) && !(v.AutoAddrRecv && v.HasRecvPlace && v.RecvPlace.Obj == g) {
									return true
								}
								if v.Type == nil || reachOrStr(v.Type) || refconfine.TypeReachesSyncNoCopyByValue(v.Type) {
									okSpec = false
									return false
								}
								if !pOK {
									okSpec = false
									return false
								}
								pk := syntaxutil.ParamKey{Func: fk, Index: pIdx}
								confinementOK := fk.Pkg == ownPath && paramLeakFree[pk] &&
									!refconfine.CallResultHandsOut(v.Type)
								if !confinementOK && arg != nil && arg.Kind == flowir.ValPlace && arg.Place.Obj == g && len(arg.Place.Projs) == 0 {
									if fd := funcDecls[v.CalleeFunc]; fd != nil {
										fnBody := fc.funcBody(p, fd)
										if fnBody != nil && pIdx < len(fnBody.Params) && fnBody.Params[pIdx] != nil {
											wants := map[syntaxutil.ParamKey]bool{}
											mw := map[syntaxutil.FuncKey]bool{}
											pRoot := map[types.Object]bool{fnBody.Params[pIdx]: true}
											if enclosingConfinesRoots(audited, p, fc, fd, nil, nil, pRoot, wants, mw, nil) &&
												wantsResolve(wants, mw) {
												confinementOK = true
											}
										}
									}
								}
								if !confinementOK {
									okSpec = false
									return false
								}
								return true
							})
							if !okSpec {
								return
							}
							for _, arg := range v.Args {
								if arg != nil && arg.Kind == flowir.ValPlace && arg.Place.Obj == g && len(arg.Place.Projs) == 0 {
									continue
								}
								checkVal(arg)
							}
							return
						}
						for _, arg := range v.Args {
							if valueMentionsVar(arg, g) && (reachOrStr(g.Type()) || (v.AutoAddrRecv && v.HasRecvPlace && v.RecvPlace.Obj == g)) {
								okSpec = false
								return
							}
						}
					}
					v.ForEachChildValue(func(ch *flowir.Value) bool {
						checkVal(ch)
						return okSpec
					})
				}
				checkVal(rhsVal)
				if !okSpec {
					return false
				}
				if embedsReach {
					switch {
					case inSettled:
						for c := range carriersOfLHS {
							embeddedOut[c] = true
						}
						if embedsRawData && settledRawExported[lhsVar] {
							*embeddedRawExported = true
						}
						return len(embeddedOut) <= 1
					case isCarrierLHS:
						if !carrierSafeForEmbedding(lhsVar, vs, embedsRawData) {
							return false
						}
						embeddedOut[lhsVar] = true
						if embedsRawData && lhsVar.Exported() {
							*embeddedRawExported = true
						}
						return len(embeddedOut) <= 1
					default:
						return false
					}
				}
				return true
			}
		}
		return false
	}

	for changed := true; changed; {
		changed = false
		for g := range settled {
			keep := true
			embedded := map[*types.Var]bool{}
			rawExported := false
			usedInFuncDecl := false
			specUses := 0
			for dep := range settled {
				if dep == g || !reachOrStr(dep.Type()) || !valueMentionsVar(candidates[g], dep) {
					continue
				}
				for c := range settled[dep] {
					embedded[c] = true
				}
				if settledRawExported[dep] {
					rawExported = true
				}
				if len(embedded) > 1 {
					keep = false
					break
				}
			}
			for _, file := range p.Syntax {
				if !keep {
					break
				}
				for _, decl := range file.Decls {
					if !keep {
						break
					}
					switch d := decl.(type) {
					case *ast.FuncDecl:
						if d.Body == nil || !bodyMentionsVar(fc.funcBody(p, d), g) {
							continue
						}
						usedInFuncDecl = true
						wants := map[syntaxutil.ParamKey]bool{}
						mw := map[syntaxutil.FuncKey]bool{}
						if !enclosingConfinesRoots(audited, p, fc, d, nil, nil, map[types.Object]bool{g: true}, wants, mw, nil) ||
							!wantsResolve(wants, mw) {
							keep = false
						}
					case *ast.GenDecl:
						for _, spec := range d.Specs {
							vs, ok := spec.(*ast.ValueSpec)
							if !ok {
								continue
							}
							isOwnSpec := false
							for _, nm := range vs.Names {
								if p.TypesInfo.Defs[nm] == g {
									isOwnSpec = true
									break
								}
							}
							if isOwnSpec {
								for i, nm := range vs.Names {
									if p.TypesInfo.Defs[nm] == g {
										continue
									}
									if i < len(vs.Values) && valueMentionsVar(fc.exprValue(p, vs.Values[i]), g) {
										keep = false
										break
									}
								}
								continue
							}
							if !bodyMentionsVar(fc.body(p, vs), g) {
								continue
							}
							specUses++
							if !checkTopValueSpecUse(g, vs, embedded, &rawExported) {
								keep = false
								break
							}
						}
					}
				}
			}
			if keep && rawExported && (usedInFuncDecl || specUses > 1) {
				keep = false
			}
			if keep && !isPureFreshDataValueWith(candidates[g], inSettledVar) {
				keep = false
			}
			if !keep {
				delete(settled, g)
				delete(settledRawExported, g)
				changed = true
			} else if !varSetEqual(embedded, settled[g]) || settledRawExported[g] != rawExported {
				settled[g] = embedded
				settledRawExported[g] = rawExported
				changed = true
			}
		}
	}
	return settled
}

func bodyMentionsVar(b *flowir.Body, target *types.Var) bool {
	if b == nil || target == nil {
		return false
	}
	hit := false
	checkLocalVal := func(v *flowir.Value) {
		if hit || v == nil {
			return
		}
		v.WalkValues(func(cur *flowir.Value) bool {
			if hit {
				return false
			}
			switch cur.Kind {
			case flowir.ValPlace:
				if cur.Place.Obj == target {
					hit = true
					return false
				}
			case flowir.ValAddrOf:
				if cur.AddrPlace.Obj == target {
					hit = true
					return false
				}
			case flowir.ValMethodVal:
				if cur.HasRecvPlace && cur.RecvPlace.Obj == target {
					hit = true
					return false
				}
			case flowir.ValCall:
				if cur.AutoAddrRecv && cur.HasRecvPlace && cur.RecvPlace.Obj == target {
					hit = true
					return false
				}
			}
			return true
		})
	}
	visitAllBodyOps(b, func(op *flowir.Op) {
		if hit {
			return
		}
		switch op.Kind {
		case flowir.OpAssign:
			for _, dst := range op.Dsts {
				if dst.Obj == target {
					hit = true
					return
				}
			}
		case flowir.OpTypeSwitchBind:
			if op.SwitchDst == target {
				hit = true
				return
			}
		case flowir.OpChanSend:
			if op.ChanPlace.Obj == target {
				hit = true
				return
			}
		}
		forEachOpTopValues(op, checkLocalVal)
	})
	return hit
}

func valueMentionsVar(v *flowir.Value, target *types.Var) bool {
	if v == nil || target == nil {
		return false
	}
	hit := false
	v.WalkValues(func(cur *flowir.Value) bool {
		if hit {
			return false
		}
		switch cur.Kind {
		case flowir.ValPlace:
			if cur.Place.Obj == target {
				hit = true
				return false
			}
		case flowir.ValAddrOf:
			if cur.AddrPlace.Obj == target {
				hit = true
				return false
			}
		case flowir.ValMethodVal:
			if cur.HasRecvPlace && cur.RecvPlace.Obj == target {
				hit = true
				return false
			}
		case flowir.ValMakeClosure:
			if bodyMentionsVar(cur.Closure, target) {
				hit = true
				return false
			}
		case flowir.ValCall:
			if (cur.AutoAddrRecv && cur.HasRecvPlace && cur.RecvPlace.Obj == target) ||
				(cur.CallKind == flowir.CallIIFE && bodyMentionsVar(cur.IIFE, target)) {
				hit = true
				return false
			}
		}
		return true
	})
	return hit
}

func closureExtractsNoCarrierFromRoots(audited bool, b *flowir.Body, carrierAliasRoots map[types.Object]bool) bool {
	if b == nil || len(carrierAliasRoots) == 0 {
		return true
	}
	isScalarType := func(t types.Type) bool {
		return t != nil &&
			!refconfine.CallResultHandsOut(t) &&
			!refconfine.TypeMayCarryUnknownDynamic(audited, t)
	}
	ok := true
	var checkVal func(v *flowir.Value)
	checkVal = func(v *flowir.Value) {
		if !ok || v == nil {
			return
		}
		switch v.Kind {
		case flowir.ValInvalid:
			ok = false
			return
		case flowir.ValPlace:
			if v.Place.Obj != nil && carrierAliasRoots[v.Place.Obj] {
				if len(v.Place.Projs) == 0 || !isScalarType(v.Type) {
					ok = false
					return
				}
				v.Place.ForEachChildValue(func(cv *flowir.Value) bool {
					checkVal(cv)
					return ok
				})
				return
			}
		case flowir.ValAddrOf:
			if v.AddrPlace.Obj != nil && carrierAliasRoots[v.AddrPlace.Obj] {
				ok = false
				return
			}
		case flowir.ValMethodVal:
			if v.HasRecvPlace && v.RecvPlace.Obj != nil && carrierAliasRoots[v.RecvPlace.Obj] {
				ok = false
				return
			}
		case flowir.ValMakeClosure:
			if v.Closure == nil || !closureExtractsNoCarrierFromRoots(audited, v.Closure, carrierAliasRoots) {
				ok = false
			}
			return
		case flowir.ValCompare:
			for _, a := range v.Args {
				if a != nil && a.Kind == flowir.ValPlace && a.Place.IsBareVar() && carrierAliasRoots[a.Place.Obj] {
					continue
				}
				checkVal(a)
				if !ok {
					return
				}
			}
			return
		case flowir.ValCall:
			if v.AutoAddrRecv && v.HasRecvPlace && v.RecvPlace.Obj != nil && carrierAliasRoots[v.RecvPlace.Obj] {
				ok = false
				return
			}
			if v.CallKind == flowir.CallIIFE {
				if v.IIFE == nil || !closureExtractsNoCarrierFromRoots(audited, v.IIFE, carrierAliasRoots) {
					ok = false
					return
				}
				for _, a := range v.Args {
					checkVal(a)
					if !ok {
						return
					}
				}
				return
			}
			if v.CallKind == flowir.CallBuiltin {
				switch v.BuiltinName {
				case "StringData", "String":
					ok = false
					return
				case "Sizeof", "Alignof", "Offsetof":
					return
				case "len", "cap":
					for _, a := range v.Args {
						if a != nil && a.Kind == flowir.ValPlace && a.Place.IsBareVar() && carrierAliasRoots[a.Place.Obj] {
							continue
						}
						checkVal(a)
						if !ok {
							return
						}
					}
					return
				}
			}
		}
		v.ForEachChildValue(func(ch *flowir.Value) bool {
			checkVal(ch)
			return ok
		})
	}

	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if !ok {
			return false
		}
		switch op.Kind {
		case flowir.OpAssign:
			if op.AssignKind == flowir.AssignRange && len(op.Srcs) == 1 && op.Srcs[0] != nil &&
				op.Srcs[0].Kind == flowir.ValPlace && op.Srcs[0].Place.IsBareVar() && carrierAliasRoots[op.Srcs[0].Place.Obj] {
				if op.Srcs[0].Type == nil {
					ok = false
					return false
				}
				switch types.Unalias(op.Srcs[0].Type).Underlying().(type) {
				case *types.Chan, *types.Signature:
					ok = false
					return false
				}
				for _, dst := range op.Dsts {
					if dst.IsBlank() {
						continue
					}
					if !dst.IsBareVar() || dst.Obj == nil || !isScalarType(dst.Obj.Type()) {
						ok = false
						return false
					}
				}
				return true
			}
			if op.AssignKind == flowir.AssignMulti && len(op.Dsts) == 2 && len(op.Srcs) == 1 && op.Srcs[0] != nil &&
				op.Srcs[0].Kind == flowir.ValPlace && op.Srcs[0].Place.Obj != nil && carrierAliasRoots[op.Srcs[0].Place.Obj] &&
				len(op.Srcs[0].Place.Projs) == 1 && op.Srcs[0].Place.Projs[0].Kind == flowir.ProjIndex {
				for _, dst := range op.Dsts {
					if dst.IsBlank() {
						continue
					}
					if !dst.IsBareVar() || dst.Obj == nil || !isScalarType(dst.Obj.Type()) {
						ok = false
						return false
					}
				}
				op.Srcs[0].Place.ForEachChildValue(func(cv *flowir.Value) bool {
					checkVal(cv)
					return ok
				})
				return ok
			}
			for _, dst := range op.Dsts {
				if dst.Obj != nil && carrierAliasRoots[dst.Obj] {
					ok = false
					return false
				}
				dst.ForEachChildValue(func(cv *flowir.Value) bool {
					checkVal(cv)
					return ok
				})
			}
			for _, src := range op.Srcs {
				checkVal(src)
			}
		case flowir.OpTypeSwitchBind:
			if op.SwitchDst != nil && carrierAliasRoots[op.SwitchDst] {
				ok = false
				return false
			}
			checkVal(op.SwitchSrc)
		case flowir.OpChanSend:
			if op.ChanPlace.Obj != nil && carrierAliasRoots[op.ChanPlace.Obj] {
				ok = false
				return false
			}
			op.ChanPlace.ForEachChildValue(func(cv *flowir.Value) bool {
				checkVal(cv)
				return ok
			})
			checkVal(op.ChanVal)
			checkVal(op.SendVal)
		case flowir.OpReturn:
			for _, r := range op.Results {
				checkVal(r)
			}
		case flowir.OpDefer, flowir.OpGo:
			checkVal(op.Call)
		case flowir.OpExpr:
			checkVal(op.Expr)
		}
		return ok
	})
	return ok
}

type rootOriginPolicy struct {
	verifyLocalOrigins   bool
	allowEnclosingParams bool
	inInitFlow           bool
	nestedClosure        bool
	unattestedBroken     map[string]bool
	singleSubjectVars    map[string]bool
	settledGlobals       settledGlobalMap
	currentTargets       []*types.Var
	checkCarryingValue   func(*flowir.Value) bool
	checkEnclosingParam  func(pIdx int, paramVar *types.Var) bool
	carrierAliasRoots    map[types.Object]bool
	linkedCarrierGlobals map[string]bool
}

// enclosingConfinesRoots verifies that enclosing never mutates, rebinds after
// initialization, addresses, spawns goroutines with, or leaks mutable backing
// storage of roots outside selfLit (and exemptCall when non-nil).
func enclosingConfinesRoots(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	enclosing ast.Node,
	selfLit *ast.FuncLit,
	exemptCall *ast.CallExpr,
	roots map[types.Object]bool,
	wants map[syntaxutil.ParamKey]bool,
	methodWants map[syntaxutil.FuncKey]bool,
	origin *rootOriginPolicy,
) bool {
	if p == nil || p.TypesInfo == nil || enclosing == nil {
		return false
	}
	if len(roots) == 0 {
		return true
	}
	enclBody := fc.scopeBody(p, enclosing)
	if enclBody == nil {
		return false
	}

	reachOrStr := func(t types.Type) bool {
		return refconfine.TypeHandsOutMutableReach(t) || syntaxutil.ContainsUintptr(t)
	}

	var exemptMap map[*ast.CallExpr]bool
	if exemptCall != nil {
		exemptMap = map[*ast.CallExpr]bool{exemptCall: true}
	}
	aliases := flowir.BuildEnclosingMemAliasesExcept(
		enclBody,
		func(o types.Object) bool { return syntaxutil.IsLocalVar(o) || roots[o] },
		reachOrStr,
		exemptMap,
	)
	for changed := true; changed; {
		changed = false
		for r := range roots {
			for nb := range aliases[r] {
				if !roots[nb] {
					roots[nb] = true
					changed = true
				}
			}
		}
	}

	var globalRoots []*types.Var
	for r := range roots {
		if r == nil || refconfine.TypeReachesSyncNoCopyByValue(r.Type()) {
			return false
		}
		v, ok := r.(*types.Var)
		if !ok {
			return false
		}
		if syntaxutil.IsLocalVar(v) {
			if enclBody.ResultSet[v] {
				return false
			}
			if origin != nil && !origin.nestedClosure {
				if !enclBody.OwnsVar(v) {
					return false
				}
				nonScalar := reachOrStr(v.Type()) ||
					refconfine.TypeCarriesSignature(v.Type()) ||
					refconfine.TypeMayCarryUnknownDynamic(audited, v.Type())
				if nonScalar && v == enclBody.Recv {
					return false
				}
				if nonScalar && !origin.allowEnclosingParams {
					if pIdx, isParam := enclBody.ParamIndex[v]; isParam {
						if origin.checkEnclosingParam == nil || !origin.checkEnclosingParam(pIdx, v) {
							return false
						}
					}
				}
			} else {
				if !enclBody.OwnsVar(v) && !enclBody.FreeVars[v] {
					return false
				}
				if origin != nil && origin.verifyLocalOrigins {
					if v == enclBody.Recv {
						return false
					}
					if _, isParam := enclBody.ParamIndex[v]; isParam {
						return false
					}
				}
			}
		} else {
			globalRoots = append(globalRoots, v)
		}
	}

	usedCarrierGlobal := false
	var isCleanRootInitValue func(v *flowir.Value) bool
	isCleanRootInitValue = func(v *flowir.Value) bool {
		var settled settledGlobalMap
		var targets []*types.Var
		if origin != nil {
			settled = origin.settledGlobals
			targets = origin.currentTargets
		}
		if isPureFreshDataValue(settled, v) {
			return true
		}
		return checkPureOrFreshValue(v, valuePurityPolicy{
			allowAppend:          true,
			allowValuePlane:      true,
			allowRuntimeOps:      true,
			allowTypeAssert:      true,
			allowNonMutableReach: true,
			allowSigLeaf: func(leaf *flowir.Value) bool {
				if leaf.Kind == flowir.ValScalarLitOrConst ||
					(leaf.Kind == flowir.ValPlace && (leaf.Place.Root == flowir.RootConstOrNil || (leaf.Place.Root == flowir.RootFunc && !leaf.Place.IsMethodExpr))) {
					return true
				}
				return origin != nil && origin.checkCarryingValue != nil && origin.checkCarryingValue(leaf)
			},
			allowPlace: func(pv *flowir.Value) bool {
				if pv.Place.Root == flowir.RootFunc && !pv.Place.IsMethodExpr {
					return true
				}
				if pv.Place.Root == flowir.RootPkgGlobal {
					gv := pv.Place.Obj
					if gv == nil {
						return false
					}
					if settled.allowedForTargets(gv, targets) {
						return true
					}
					if origin != nil && origin.inInitFlow && !origin.nestedClosure && len(pv.Place.Projs) == 0 &&
						!gv.IsField() && gv.Pkg() != nil && gv.Parent() == gv.Pkg().Scope() &&
						refconfine.TypeMayCarryUnknownDynamic(audited, gv.Type()) {
						gvKey := syntaxutil.DynamicVarKey(gv)
						if (p.Types == nil || gv.Pkg() != p.Types || !origin.unattestedBroken[gvKey]) && !origin.singleSubjectVars[gvKey] {
							if origin.linkedCarrierGlobals == nil {
								origin.linkedCarrierGlobals = map[string]bool{}
							}
							origin.linkedCarrierGlobals[gvKey] = true
							usedCarrierGlobal = true
							return true
						}
					}
					return false
				}
				if pv.Place.Obj != nil && roots[pv.Place.Obj] {
					if origin != nil && origin.carrierAliasRoots[pv.Place.Obj] {
						usedCarrierGlobal = true
					}
					return true
				}
				if pv.Place.Root == flowir.RootTransient && pv.Place.Base != nil {
					return isCleanRootInitValue(pv.Place.Base)
				}
				return false
			},
		})
	}

	isOuterOrSigVar := func(v *types.Var) bool {
		if v == nil || !syntaxutil.IsLocalVar(v) {
			return true
		}
		if v == enclBody.Recv || enclBody.ResultSet[v] {
			return true
		}
		if _, isParam := enclBody.ParamIndex[v]; isParam {
			return true
		}
		return v.Pos() < enclBody.BodyStart || v.Pos() > enclBody.BodyEnd
	}

	// valMutableRoots collects mutable-reach roots whose backing memory may be
	// handed out by evaluating v.
	reachOrSyncOrStr := func(t types.Type) bool {
		return reachOrStr(t) || refconfine.TypeReachesSyncNoCopyByValue(t)
	}
	var valMutableRoots func(v *flowir.Value, out map[*types.Var]bool)
	placeMutableRoots := func(pl flowir.Place, out map[*types.Var]bool) {
		if pl.Obj != nil && roots[pl.Obj] && reachOrSyncOrStr(pl.Obj.Type()) {
			out[pl.Obj] = true
		}
		if pl.Root == flowir.RootTransient && pl.Base != nil {
			valMutableRoots(pl.Base, out)
		}
	}
	valMutableRoots = func(v *flowir.Value, out map[*types.Var]bool) {
		if v == nil {
			return
		}
		if selfLit != nil && v.Kind == flowir.ValMakeClosure && v.Lit == selfLit {
			return
		}
		if exemptCall != nil && v.Kind == flowir.ValCall && v.CallAST == exemptCall {
			return
		}
		isStrBuiltin := v.Kind == flowir.ValCall && v.CallKind == flowir.CallBuiltin &&
			(v.BuiltinName == "String" || v.BuiltinName == "StringData")
		if !isStrBuiltin && v.Kind != flowir.ValAddrOf && v.Kind != flowir.ValMethodVal &&
			v.Type != nil && !reachOrSyncOrStr(v.Type) {
			return
		}
		switch v.Kind {
		case flowir.ValPlace:
			if len(v.Place.Projs) > 0 && v.Type != nil &&
				!reachOrSyncOrStr(v.Type) {
				return
			}
			placeMutableRoots(v.Place, out)
		case flowir.ValAddrOf:
			if v.AddrPlace.Obj != nil && roots[v.AddrPlace.Obj] {
				out[v.AddrPlace.Obj] = true
			} else if v.AddrPlace.Root == flowir.RootTransient && v.AddrPlace.Base != nil {
				valMutableRoots(v.AddrPlace.Base, out)
			}
		case flowir.ValMethodVal:
			if v.HasRecvPlace && v.RecvPlace.Obj != nil && roots[v.RecvPlace.Obj] {
				out[v.RecvPlace.Obj] = true
			}
			valMutableRoots(v.Recv, out)
		case flowir.ValAllocFresh:
			switch v.AllocKind {
			case flowir.AllocBuiltinNewExpr:
				for _, a := range v.Args {
					valMutableRoots(a, out)
				}
			case flowir.AllocCompositeLit:
				for i := range v.CompositeElts {
					valMutableRoots(v.CompositeElts[i].MapKey, out)
					valMutableRoots(v.CompositeElts[i].Value, out)
				}
			}
		case flowir.ValMakeClosure:
			if v.Closure != nil {
				for fv := range v.Closure.FreeVars {
					if roots[fv] && reachOrSyncOrStr(fv.Type()) {
						out[fv] = true
					}
				}
				for _, gv := range globalRoots {
					if reachOrSyncOrStr(gv.Type()) && bodyMentionsVar(v.Closure, gv) {
						out[gv] = true
					}
				}
			}
		case flowir.ValCall:
			if v.CallKind == flowir.CallBuiltin {
				switch v.BuiltinName {
				case "len", "cap", "Sizeof", "Alignof", "Offsetof":
					return
				case "Slice", "SliceData", "String", "StringData":
					if len(v.Args) > 0 {
						valMutableRoots(v.Args[0], out)
					}
					return
				}
			}
			if v.AutoAddrRecv && v.HasRecvPlace && v.RecvPlace.Obj != nil && roots[v.RecvPlace.Obj] {
				out[v.RecvPlace.Obj] = true
			}
			valMutableRoots(v.Recv, out)
			valMutableRoots(v.Callee, out)
			for _, a := range v.Args {
				valMutableRoots(a, out)
			}
		case flowir.ValConvert:
			valMutableRoots(v.Arg, out)
		case flowir.ValChanRecv:
			valMutableRoots(v.Chan, out)
		case flowir.ValCompositeExpr:
			for _, a := range v.Args {
				valMutableRoots(a, out)
			}
		}
	}
	suppliesMutableRoot := func(v *flowir.Value) bool {
		m := map[*types.Var]bool{}
		valMutableRoots(v, m)
		return len(m) > 0
	}

	valTouchesAnyRoot := func(v *flowir.Value) bool {
		return valueTouchesRootSet(v, func(o types.Object) bool { return roots[o] }, globalRoots)
	}

	definedOnce := map[types.Object]bool{}
	sound := true

	var checkValue func(v *flowir.Value)
	checkValue = func(v *flowir.Value) {
		if !sound || v == nil {
			return
		}
		if selfLit != nil && v.Kind == flowir.ValMakeClosure && v.Lit == selfLit {
			return
		}
		if exemptCall != nil && v.Kind == flowir.ValCall && v.CallAST == exemptCall {
			return
		}
		switch v.Kind {
		case flowir.ValInvalid:
			sound = false
			return
		case flowir.ValConvert:
			if syntaxutil.IsUnsafePointerType(v.Type) &&
				(suppliesMutableRoot(v.Arg) || (valTouchesAnyRoot(v.Arg) && (v.Arg == nil || syntaxutil.ContainsUintptr(v.Arg.Type)))) {
				sound = false
				return
			}
		case flowir.ValAddrOf:
			if v.AddrPlace.Obj != nil && roots[v.AddrPlace.Obj] {
				sound = false
				return
			}
			if v.AddrPlace.Root == flowir.RootTransient && suppliesMutableRoot(v.AddrPlace.Base) {
				sound = false
				return
			}
		case flowir.ValMethodVal:
			if v.AutoAddr && v.HasRecvPlace && v.RecvPlace.Obj != nil && roots[v.RecvPlace.Obj] {
				sound = false
				return
			}
			if suppliesMutableRoot(v.Recv) {
				sound = false
				return
			}
		case flowir.ValChanRecv:
			if suppliesMutableRoot(v.Chan) {
				sound = false
				return
			}
		case flowir.ValMakeClosure:
			if v.Lit == nil || v.Closure == nil {
				sound = false
				return
			}
			localRoots := map[types.Object]bool{}
			subRoots := map[types.Object]bool{}
			for fv := range v.Closure.FreeVars {
				if roots[fv] {
					subRoots[fv] = true
					if syntaxutil.IsLocalVar(fv) {
						localRoots[fv] = true
					}
				}
			}
			for _, gv := range globalRoots {
				if bodyMentionsVar(v.Closure, gv) {
					subRoots[gv] = true
				}
			}
			if len(localRoots) > 0 && !boundValueClosureEnvLeakFreeJudged(audited, p, fc, localRoots, v.Lit.Body, wants, methodWants) {
				sound = false
				return
			}
			if len(subRoots) > 0 {
				var subOrigin *rootOriginPolicy
				if origin != nil {
					cp := *origin
					cp.nestedClosure = true
					subOrigin = &cp
				}
				if !enclosingConfinesRoots(audited, p, fc, v.Lit, selfLit, exemptCall, subRoots, wants, methodWants, subOrigin) {
					sound = false
					return
				}
			}
			return
		case flowir.ValCall:
			switch v.CallKind {
			case flowir.CallBuiltin:
				switch v.BuiltinName {
				case "StringData", "String":
					if suppliesMutableRoot(v) || valTouchesAnyRoot(v) {
						sound = false
						return
					}
				case "Sizeof", "Alignof", "Offsetof":
					return
				case "delete", "clear", "close":
					if len(v.Args) > 0 && suppliesMutableRoot(v.Args[0]) {
						sound = false
						return
					}
				case "copy":
					if len(v.Args) > 0 && suppliesMutableRoot(v.Args[0]) {
						sound = false
						return
					}
					if len(v.Args) == 2 && suppliesMutableRoot(v.Args[1]) &&
						(v.Args[0] == nil || elemHandsOutReach(v.Args[0].Type)) {
						sound = false
						return
					}
				case "append":
					if len(v.Args) > 0 && suppliesMutableRoot(v.Args[0]) {
						sound = false
						return
					}
					if len(v.Args) >= 2 && !isPureFreshDataValueWith(v.Args[0], nil) {
						for _, a := range v.Args[1:] {
							if suppliesMutableRoot(a) {
								sound = false
								return
							}
						}
					}
				}
			case flowir.CallPlain:
				if v.CalleeFunc == nil || v.IsMethodExprCall {
					for _, a := range v.Args {
						if suppliesMutableRoot(a) {
							sound = false
							return
						}
					}
					break
				}
				fk := syntaxutil.FuncKey{Pkg: v.CalleePkg, Name: v.CalleeFunc.Origin().Name()}
				if !auditset.ValuePlaneClone(fk.Pkg, fk.Name) {
					v.ForEachArgParam(func(a *flowir.Value, slotType types.Type, _ int, pIdx int, pOK bool, _ bool) bool {
						if !suppliesMutableRoot(a) {
							return true
						}
						if slotType != nil && !refconfine.CallResultHandsOut(slotType) {
							return true
						}
						if wants == nil || !pOK {
							sound = false
							return false
						}
						wants[syntaxutil.ParamKey{Func: fk, Index: pIdx}] = true
						return true
					})
					if !sound {
						return
					}
				}
			case flowir.CallMethod:
				for _, a := range v.Args {
					if suppliesMutableRoot(a) {
						sound = false
						return
					}
				}
				recvMutable := suppliesMutableRoot(v.Recv) ||
					(v.AutoAddrRecv && v.HasRecvPlace && v.RecvPlace.Obj != nil && roots[v.RecvPlace.Obj])
				if recvMutable {
					if v.IsMethodExprCall || v.Selection == nil {
						sound = false
						return
					}
					fn, ok := v.Selection.Obj().(*types.Func)
					if !ok || fn == nil || syntaxutil.InterfaceReceiver(fn) || refconfine.AuditedSynchronization(audited, fn) {
						sound = false
						return
					}
					if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
						_, ptrRecv := types.Unalias(sig.Recv().Type()).(*types.Pointer)
						if ptrRecv || reachOrStr(sig.Recv().Type()) {
							if methodWants == nil {
								sound = false
								return
							}
							methodWants[syntaxutil.MethodFactKey(fn)] = true
						}
					}
				}
			case flowir.CallIIFE:
				if valTouchesAnyRoot(v) {
					sound = false
					return
				}
			default:
				if suppliesMutableRoot(v.Callee) {
					sound = false
					return
				}
				for _, a := range v.Args {
					if suppliesMutableRoot(a) {
						sound = false
						return
					}
				}
			}
		}
		v.ForEachChildValue(func(ch *flowir.Value) bool {
			checkValue(ch)
			return sound
		})
	}

	enclBody.ForEachSyncOp(func(op *flowir.Op) bool {
		if !sound {
			return false
		}
		switch op.Kind {
		case flowir.OpAssign:
			if op.AssignKind == flowir.AssignRange {
				if len(op.Srcs) != 1 || op.Srcs[0] == nil || op.Srcs[0].Type == nil {
					sound = false
					return false
				}
				bindsRoot := false
				for _, dst := range op.Dsts {
					if dst.Obj != nil && roots[dst.Obj] {
						bindsRoot = true
						break
					}
				}
				switch types.Unalias(op.Srcs[0].Type).Underlying().(type) {
				case *types.Chan:
					if bindsRoot || suppliesMutableRoot(op.Srcs[0]) {
						sound = false
						return false
					}
				case *types.Signature:
					if bindsRoot || suppliesMutableRoot(op.Srcs[0]) || valTouchesAnyRoot(op.Srcs[0]) {
						sound = false
						return false
					}
				}
			}
			op.ForEachAssignPair(func(_ int, dst flowir.Place, isDef bool, src *flowir.Value) bool {
				dst.ForEachChildValue(func(cv *flowir.Value) bool {
					checkValue(cv)
					return sound
				})
				if !sound {
					return false
				}
				if dst.Obj != nil && roots[dst.Obj] {
					if !dst.IsBareVar() || !isDef || isOuterOrSigVar(dst.Obj) ||
						op.AssignKind == flowir.AssignCompound || op.AssignKind == flowir.AssignIncDec ||
						definedOnce[dst.Obj] {
						sound = false
						return false
					}
					definedOnce[dst.Obj] = true
					if op.AssignKind != flowir.AssignZeroDecl {
						if src == nil {
							sound = false
							return false
						}
						usedCarrierGlobal = false
						if origin != nil && origin.verifyLocalOrigins && reachOrStr(dst.Obj.Type()) {
							if !isCleanRootInitValue(src) {
								sound = false
								return false
							}
							if usedCarrierGlobal {
								if origin.carrierAliasRoots == nil {
									origin.carrierAliasRoots = map[types.Object]bool{}
								}
								origin.carrierAliasRoots[dst.Obj] = true
							}
						}
						isBareCarrierAlias := usedCarrierGlobal && src.Kind == flowir.ValPlace && len(src.Place.Projs) == 0
						if !isBareCarrierAlias && origin != nil && refconfine.TypeCarriesSignature(dst.Obj.Type()) {
							if !origin.nestedClosure && origin.checkCarryingValue != nil && !origin.checkCarryingValue(src) {
								sound = false
								return false
							}
						}
					}
				} else if dst.Root == flowir.RootTransient && suppliesMutableRoot(dst.Base) {
					sound = false
					return false
				}
				if _, keyVal, isMapW := dst.AsMapWrite(); isMapW && keyVal != nil && suppliesMutableRoot(keyVal) {
					sound = false
					return false
				}
				if src != nil && suppliesMutableRoot(src) {
					allowedDst := dst.IsBlank() ||
						(dst.IsBareVar() && syntaxutil.IsLocalVar(dst.Obj) && roots[dst.Obj] && isDef && !isOuterOrSigVar(dst.Obj))
					if !allowedDst {
						sound = false
						return false
					}
				}
				return sound
			})
			for _, src := range op.Srcs {
				checkValue(src)
				if !sound {
					return false
				}
			}

		case flowir.OpTypeSwitchBind:
			checkValue(op.SwitchSrc)
			if !sound {
				return false
			}
			if op.SwitchDst != nil && roots[op.SwitchDst] {
				if definedOnce[op.SwitchDst] || op.SwitchSrc == nil {
					sound = false
					return false
				}
				definedOnce[op.SwitchDst] = true
				usedCarrierGlobal = false
				if origin != nil && origin.verifyLocalOrigins && reachOrStr(op.SwitchDst.Type()) {
					if !isCleanRootInitValue(op.SwitchSrc) {
						sound = false
						return false
					}
					if usedCarrierGlobal {
						if origin.carrierAliasRoots == nil {
							origin.carrierAliasRoots = map[types.Object]bool{}
						}
						origin.carrierAliasRoots[op.SwitchDst] = true
					}
				}
				if refconfine.TypeCarriesSignature(op.SwitchDst.Type()) {
					if op.SwitchSrc.Type == nil || !types.Identical(op.SwitchDst.Type(), op.SwitchSrc.Type) {
						sound = false
						return false
					}
					if !usedCarrierGlobal && origin != nil && !origin.nestedClosure &&
						origin.checkCarryingValue != nil && !origin.checkCarryingValue(op.SwitchSrc) {
						sound = false
						return false
					}
				}
			} else if op.SwitchDst != nil && op.SwitchSrc != nil && suppliesMutableRoot(op.SwitchSrc) &&
				(op.SwitchDst.Type() == nil ||
					reachOrStr(op.SwitchDst.Type()) ||
					refconfine.TypeCarriesSignature(op.SwitchDst.Type()) ||
					refconfine.TypeReachesSyncNoCopyByValue(op.SwitchDst.Type())) {
				sound = false
				return false
			}

		case flowir.OpChanSend:
			if (op.ChanPlace.Obj != nil && roots[op.ChanPlace.Obj]) ||
				suppliesMutableRoot(op.ChanVal) || suppliesMutableRoot(op.SendVal) {
				sound = false
				return false
			}
			checkValue(op.ChanVal)
			checkValue(op.SendVal)

		case flowir.OpReturn:
			for _, resVal := range op.Results {
				checkValue(resVal)
				if !sound {
					return false
				}
				m := map[*types.Var]bool{}
				valMutableRoots(resVal, m)
				for r := range m {
					if _, isParam := enclBody.ParamIndex[r]; !isParam {
						sound = false
						return false
					}
				}
			}

		case flowir.OpDefer:
			checkValue(op.Call)

		case flowir.OpGo:
			if valTouchesAnyRoot(op.Call) {
				sound = false
				return false
			}

		case flowir.OpExpr:
			checkValue(op.Expr)
		}
		return sound
	})
	if sound && origin != nil && len(origin.carrierAliasRoots) > 0 {
		for changed := true; changed; {
			changed = false
			for r := range origin.carrierAliasRoots {
				for nb := range aliases[r] {
					if !origin.carrierAliasRoots[nb] {
						origin.carrierAliasRoots[nb] = true
						changed = true
					}
				}
			}
		}
		visitAllBodyOps(enclBody, func(op *flowir.Op) {
			if !sound {
				return
			}
			checkLitVal := func(v *flowir.Value) {
				if !sound || v == nil {
					return
				}
				v.WalkValues(func(cur *flowir.Value) bool {
					if !sound {
						return false
					}
					if cur.Kind == flowir.ValMakeClosure && cur.Lit != selfLit {
						if cur.Closure == nil || !closureExtractsNoCarrierFromRoots(audited, cur.Closure, origin.carrierAliasRoots) {
							sound = false
							return false
						}
					}
					return true
				})
			}
			forEachOpTopValues(op, checkLitVal)
		})
	}
	return sound
}

func environmentFreeFuncLitWithOrigin(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	lit *ast.FuncLit,
	enclosing ast.Node,
	wants map[syntaxutil.ParamKey]bool,
	methodWants map[syntaxutil.FuncKey]bool,
	origin *rootOriginPolicy,
) bool {
	if p == nil || p.TypesInfo == nil || lit == nil || lit.Body == nil {
		return false
	}
	litBody := fc.litBody(p, lit)
	if litBody == nil {
		return false
	}
	roots := make(map[types.Object]bool, len(litBody.FreeVars))
	for fv := range litBody.FreeVars {
		roots[fv] = true
	}
	if len(roots) == 0 {
		return true
	}
	if enclosing == nil {
		return false
	}
	if !enclosingConfinesRoots(audited, p, fc, enclosing, lit, nil, roots, wants, methodWants, origin) {
		return false
	}
	if origin != nil && len(origin.carrierAliasRoots) > 0 && !closureExtractsNoCarrierFromRoots(audited, litBody, origin.carrierAliasRoots) {
		return false
	}
	localRoots := make(map[types.Object]bool, len(roots))
	for r := range roots {
		if syntaxutil.IsLocalVar(r) {
			localRoots[r] = true
		}
	}
	if len(localRoots) > 0 && !boundValueClosureEnvLeakFreeJudged(audited, p, fc, localRoots, lit.Body, wants, methodWants) {
		return false
	}
	return true
}

// fieldRegMark is one registered-population disposition for a func-signature
// struct field a carrier can hand out: class 'd' defers the field position to a
// parameter's leak-free fact, class 'p' poisons it. A poison with field ""
// covers the whole population, idx -1 every index.
type fieldRegMark struct {
	class byte
	field string
	idx   int
	param syntaxutil.ParamKey
}

// classifyFieldRegistrantsValue derives the registered-population marks of one
// admitted registration store over lowered flowir places and values.
func classifyFieldRegistrantsValue(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	dst flowir.Place,
	hasDst bool,
	rhs *flowir.Value,
	emit func(fieldRegMark),
) {
	if hasDst && len(dst.Projs) > 0 {
		last := dst.Projs[len(dst.Projs)-1]
		if last.Kind == flowir.ProjField && last.Field != nil && last.Selection != nil && last.Type != nil {
			if _, isSig := types.Unalias(last.Type).Underlying().(*types.Signature); isSig {
				classifyFieldRegistrantFlowValue(audited, p, fc, last.Field.Name(), rhs, emit)
				return
			}
		}
	}
	classifyRegistrantFlowValue(audited, p, fc, rhs, emit)
}

func classifyRegistrantFlowValue(audited bool, p *packages.Package, fc *pkgFlowCache, v *flowir.Value, emit func(fieldRegMark)) {
	if v == nil || v.IsTypeExpr {
		return
	}
	switch v.Kind {
	case flowir.ValScalarLitOrConst:
		return
	case flowir.ValAllocFresh:
		switch v.AllocKind {
		case flowir.AllocCompositeLit:
			classifyRegistrantCompositeValue(audited, p, fc, v, emit)
			return
		case flowir.AllocMake, flowir.AllocBuiltinNewType:
			return
		case flowir.AllocBuiltinNewExpr:
			for _, arg := range v.Args {
				classifyRegistrantFlowValue(audited, p, fc, arg, emit)
			}
			return
		}
	case flowir.ValMakeClosure:
		classifyLiteralRegistrant(audited, p, fc, syntaxutil.ElemPositionField, v.Lit, emit)
		return
	case flowir.ValConvert:
		if !v.IsTypeAssert && v.Arg != nil && !syntaxutil.IsUnsafePointerType(v.Arg.Type) {
			classifyRegistrantFlowValue(audited, p, fc, v.Arg, emit)
			return
		}
	case flowir.ValCall:
		if v.IsMethodExprCall && v.Recv != nil {
			classifyRegistrantFlowValue(audited, p, fc, v.Recv, emit)
		}
		for _, arg := range v.Args {
			classifyRegistrantFlowValue(audited, p, fc, arg, emit)
		}
		return
	case flowir.ValPlace:
		if v.IsNil || v.IsConst || v.Place.Root == flowir.RootConstOrNil {
			return
		}
		if v.Place.Root == flowir.RootFunc && !v.Place.IsMethodExpr && len(v.Place.Projs) == 0 && v.Place.Func != nil {
			classifyFieldRegistrantFlowValue(audited, p, fc, syntaxutil.ElemPositionField, v, emit)
			return
		}
	}
	if refconfine.TypeCarriesSignature(v.Type) {
		emit(fieldRegMark{class: 'p', idx: -1})
	}
}

func classifyRegistrantCompositeValue(audited bool, p *packages.Package, fc *pkgFlowCache, litVal *flowir.Value, emit func(fieldRegMark)) {
	if litVal == nil || litVal.ElemType == nil {
		emit(fieldRegMark{class: 'p', idx: -1})
		return
	}
	switch syntaxutil.UnderlyingType(litVal.ElemType).(type) {
	case *types.Struct:
		for i := range litVal.CompositeElts {
			elt := &litVal.CompositeElts[i]
			if elt.Field == nil {
				emit(fieldRegMark{class: 'p', idx: -1})
				continue
			}
			if _, isSig := types.Unalias(elt.Field.Type()).Underlying().(*types.Signature); isSig {
				classifyFieldRegistrantFlowValue(audited, p, fc, elt.Field.Name(), elt.Value, emit)
				continue
			}
			classifyRegistrantFlowValue(audited, p, fc, elt.Value, emit)
		}
	case *types.Map:
		for i := range litVal.CompositeElts {
			elt := &litVal.CompositeElts[i]
			if elt.MapKey != nil {
				classifyRegistrantFlowValue(audited, p, fc, elt.MapKey, emit)
			}
			if elt.Value != nil {
				classifyRegistrantFlowValue(audited, p, fc, elt.Value, emit)
			}
		}
	case *types.Slice, *types.Array:
		for i := range litVal.CompositeElts {
			elt := &litVal.CompositeElts[i]
			if elt.Value != nil {
				classifyRegistrantFlowValue(audited, p, fc, elt.Value, emit)
			}
		}
	default:
		emit(fieldRegMark{class: 'p', idx: -1})
	}
}

func classifyFieldRegistrantFlowValue(audited bool, p *packages.Package, fc *pkgFlowCache, field string, v *flowir.Value, emit func(fieldRegMark)) {
	deferNamed := func(fn *types.Func) bool {
		if fn == nil || fn.Pkg() == nil {
			return false
		}
		fn = fn.Origin()
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() != nil {
			return false
		}
		fk := syntaxutil.FuncKey{Pkg: fn.Pkg().Path(), Name: fn.Name()}
		for idx := 0; idx < sig.Params().Len(); idx++ {
			emit(fieldRegMark{class: 'd', field: field, idx: idx, param: syntaxutil.ParamKey{Func: fk, Index: idx}})
		}
		return true
	}
	if v != nil && !v.IsTypeExpr {
		switch v.Kind {
		case flowir.ValScalarLitOrConst:
			if v.IsNil {
				return
			}
		case flowir.ValMakeClosure:
			classifyLiteralRegistrant(audited, p, fc, field, v.Lit, emit)
			return
		case flowir.ValPlace:
			if v.IsNil {
				return
			}
			if v.Place.Root == flowir.RootFunc && !v.Place.IsMethodExpr && len(v.Place.Projs) == 0 && v.Place.Func != nil && deferNamed(v.Place.Func) {
				return
			}
		}
	}
	emit(fieldRegMark{class: 'p', field: field, idx: -1})
}

func classifyLiteralRegistrant(audited bool, p *packages.Package, fc *pkgFlowCache, field string, lit *ast.FuncLit, emit func(fieldRegMark)) {
	if lit == nil || lit.Type == nil || lit.Body == nil {
		emit(fieldRegMark{class: 'p', field: field, idx: -1})
		return
	}
	idx := 0
	if lit.Type.Params != nil {
		for _, group := range lit.Type.Params.List {
			names := group.Names
			if len(names) == 0 {
				idx++
				continue
			}
			for _, name := range names {
				if name.Name == "_" {
					idx++
					continue
				}
				obj := p.TypesInfo.Defs[name]
				if obj == nil {
					emit(fieldRegMark{class: 'p', field: field, idx: idx})
					idx++
					continue
				}
				wants := map[syntaxutil.ParamKey]bool{}
				if boundValueLeakFreeJudged(audited, p, fc, map[types.Object]bool{obj: true}, lit.Body, wants, nil, nil, nil, nil) {
					for want := range wants {
						emit(fieldRegMark{class: 'd', field: field, idx: idx, param: want})
					}
				} else {
					emit(fieldRegMark{class: 'p', field: field, idx: idx})
				}
				idx++
			}
		}
	}
}

// recordEnvCarryingRegistrations records, per dynamic-capable package variable
// (own or foreign), whether this package's direct code stores a
// function-carrying value into it that is not provably environment-free.
func recordEnvCarryingRegistrations(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	callIdx *refconfine.CallSiteIndex,
	initOnly map[string]bool,
	unattestedBroken map[string]bool,
	singleSubjectVars map[string]bool,
	settledGlobals settledGlobalMap,
	pkgConf *packageConfinementSummary,
	exemptSeamNodes map[ast.Node]bool,
	envCarrying map[string]bool,
	envCarryingFns map[string]map[syntaxutil.FuncKey]bool,
	envCarryingUnattr map[string]bool,
	envCallableVars map[string]bool,
	envCalls map[syntaxutil.EnvCallUse]bool,
	envParamCalls map[syntaxutil.EnvCallParamUse]bool,
	envMethodCalls map[syntaxutil.EnvCallMethodUse]bool,
	carrierLinks map[syntaxutil.CarrierLink]bool,
	fieldDefer map[syntaxutil.FieldPosKey]map[syntaxutil.ParamKey]bool,
	fieldPoison map[string]map[syntaxutil.FieldParamPoison]bool,
	hooks *syntaxutil.ExplainHookSet,
) {
	if p == nil || p.TypesInfo == nil {
		return
	}
	if fc == nil {
		fc = newPkgFlowCache(audited, p)
	}
	ownPath := ""
	if p.Types != nil {
		ownPath = p.Types.Path()
	}
	reachOrStr := func(t types.Type) bool {
		return refconfine.TypeHandsOutMutableReach(t) || syntaxutil.ContainsUintptr(t)
	}
	carrierVar := func(obj types.Object) (*types.Var, bool) {
		variable, ok := obj.(*types.Var)
		if !ok || variable == nil || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
			return nil, false
		}
		if !refconfine.TypeMayCarryUnknownDynamic(audited, variable.Type()) {
			return nil, false
		}
		return variable, true
	}
	var localAliases map[types.Object]localCarrierAliases
	targetVarsForPlace := func(dst flowir.Place, writeContainer bool) []*types.Var {
		if dst.Root == flowir.RootBlank {
			return nil
		}
		if dst.Obj != nil {
			if cv, isC := carrierVar(dst.Obj); isC {
				return []*types.Var{cv}
			}
			if placeEntersInterior(dst, writeContainer) {
				return localAliases[dst.Obj].all
			}
			return localAliases[dst.Obj].root
		}
		if dst.Root == flowir.RootTransient && dst.Base != nil {
			return collectValueCarrierVars(audited, dst.Base, carrierVar, localAliases, nil)
		}
		return nil
	}
	targetVarsForValue := func(val *flowir.Value, writeContainer bool) (flowir.Place, bool, []*types.Var) {
		if val == nil {
			return flowir.Place{}, false, nil
		}
		switch val.Kind {
		case flowir.ValPlace:
			return val.Place, true, targetVarsForPlace(val.Place, writeContainer)
		case flowir.ValAddrOf:
			if val.IsArraySlice && val.AddrPlace.Obj != nil {
				if cv, isC := carrierVar(val.AddrPlace.Obj); isC {
					return flowir.Place{}, false, []*types.Var{cv}
				}
				if placeEntersInterior(val.AddrPlace, false) {
					return flowir.Place{}, false, localAliases[val.AddrPlace.Obj].all
				}
				return flowir.Place{}, false, localAliases[val.AddrPlace.Obj].root
			}
		}
		return flowir.Place{}, false, collectValueCarrierVars(audited, val, carrierVar, localAliases, nil)
	}
	computeLocalAliases := func(scopeBody *flowir.Body, parent map[types.Object]localCarrierAliases) map[types.Object]localCarrierAliases {
		aliased, _ := computeBodyCarrierAliases(audited, fc, scopeBody, carrierAliasConfig{
			parentAliases: parent,
			carrierVar:    carrierVar,
			descendNested: true,
		})
		return aliased
	}

	var enclosingScope ast.Node
	var currentRegFn syntaxutil.FuncKey
	var currentTargets []*types.Var
	var pendingEnvCalls map[syntaxutil.FuncKey]bool
	var pendingEnvParams map[syntaxutil.ParamKey]bool
	var pendingEnvMethods map[syntaxutil.FuncKey]bool
	var pendingCarrierLinks map[string]bool
	var carryingValue func(val *flowir.Value) bool

	wantsResolve := func(wants map[syntaxutil.ParamKey]bool, methodWants map[syntaxutil.FuncKey]bool) bool {
		for w := range wants {
			provenLocal, conditional := pkgConf.classifyParam(ownPath, w)
			if !provenLocal && (!conditional || pendingEnvParams == nil) {
				return false
			}
		}
		for mw := range methodWants {
			provenLocal, conditional := pkgConf.classifyMethod(ownPath, mw)
			if !provenLocal && (!conditional || pendingEnvMethods == nil) {
				return false
			}
		}
		for w := range wants {
			provenLocal, _ := pkgConf.classifyParam(ownPath, w)
			if !provenLocal {
				pendingEnvParams[w] = true
			}
		}
		for mw := range methodWants {
			provenLocal, _ := pkgConf.classifyMethod(ownPath, mw)
			if !provenLocal {
				pendingEnvMethods[mw] = true
			}
		}
		return true
	}

	isSyncInitFlowScope := func(scope ast.Node) bool {
		if scope == nil {
			return true
		}
		fd, ok := scope.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Name == nil {
			return false
		}
		return fd.Name.Name == "init" || (!fd.Name.IsExported() && initOnly[fd.Name.Name])
	}

	singleWriteTopLevelInit := func(cv *types.Var) (*flowir.Value, bool) {
		if p.Types == nil || cv == nil || cv.Pkg() != p.Types || cv.Parent() != p.Types.Scope() {
			return nil, false
		}
		if reachOrStr(cv.Type()) || refconfine.TypeReachesSyncNoCopyByValue(cv.Type()) {
			return nil, false
		}
		cvKey := syntaxutil.DynamicVarKey(cv)
		if unattestedBroken[cvKey] || singleSubjectVars[cvKey] {
			return nil, false
		}
		return fc.singleWritePkgGlobalInit(p, cv)
	}

	visitingSingleWriteVars := map[*types.Var]bool{}
	visitingInitParams := map[syntaxutil.ParamKey]bool{}
	visitingFuncLits := map[*ast.FuncLit]bool{}

	cloneFuncMap := func(m map[syntaxutil.FuncKey]bool) map[syntaxutil.FuncKey]bool {
		if m == nil {
			return nil
		}
		out := make(map[syntaxutil.FuncKey]bool, len(m))
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	cloneParamMap := func(m map[syntaxutil.ParamKey]bool) map[syntaxutil.ParamKey]bool {
		if m == nil {
			return nil
		}
		out := make(map[syntaxutil.ParamKey]bool, len(m))
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	cloneStringMap := func(m map[string]bool) map[string]bool {
		if m == nil {
			return nil
		}
		out := make(map[string]bool, len(m))
		for k, v := range m {
			out[k] = v
		}
		return out
	}

	carryingAtScope := func(scope ast.Node, val *flowir.Value) bool {
		prev := enclosingScope
		snapCalls := cloneFuncMap(pendingEnvCalls)
		snapParams := cloneParamMap(pendingEnvParams)
		snapMethods := cloneFuncMap(pendingEnvMethods)
		snapLinks := cloneStringMap(pendingCarrierLinks)
		enclosingScope = scope
		bad := carryingValue(val)
		enclosingScope = prev
		if bad {
			pendingEnvCalls = snapCalls
			pendingEnvParams = snapParams
			pendingEnvMethods = snapMethods
			pendingCarrierLinks = snapLinks
		}
		return bad
	}

	var checkCapturedSigOriginAtScope func(scope ast.Node, val *flowir.Value) bool
	var checkInitOnlyParamAtCallSites func(fd *ast.FuncDecl, pIdx int, paramVar *types.Var) bool

	checkCapturedSigOriginAtScope = func(scope ast.Node, val *flowir.Value) bool {
		if val == nil || val.IsTypeExpr {
			return false
		}
		if !carryingAtScope(scope, val) {
			return true
		}
		if !isSyncInitFlowScope(scope) {
			return false
		}
		if val.Kind != flowir.ValPlace || !val.Place.IsBareVar() || val.Place.Obj == nil {
			return false
		}
		v := val.Place.Obj
		if p.Types != nil && v.Pkg() == p.Types && v.Parent() == p.Types.Scope() {
			if visitingSingleWriteVars[v] {
				return false
			}
			cvInit, ok := singleWriteTopLevelInit(v)
			if !ok {
				return false
			}
			visitingSingleWriteVars[v] = true
			defer delete(visitingSingleWriteVars, v)
			return checkCapturedSigOriginAtScope(nil, cvInit)
		}
		if callerFD, isFD := scope.(*ast.FuncDecl); isFD && syntaxutil.IsLocalVar(v) {
			if callIdx != nil {
				if cp, isParam := callIdx.Params[v]; isParam && !callIdx.Written[v] {
					return checkInitOnlyParamAtCallSites(callerFD, cp.Index, v)
				}
			}
			if !visitingSingleWriteVars[v] && !reachOrStr(v.Type()) {
				fnBody := fc.funcBody(p, callerFD)
				if initVal, ok := fc.singleWriteLocalInit(p, fnBody, v); ok {
					visitingSingleWriteVars[v] = true
					defer delete(visitingSingleWriteVars, v)
					return checkCapturedSigOriginAtScope(callerFD, initVal)
				}
			}
		}
		return false
	}

	checkInitOnlyParamAtCallSites = func(fd *ast.FuncDecl, pIdx int, paramVar *types.Var) bool {
		if fd == nil || fd.Recv != nil || fd.Name == nil || fd.Name.IsExported() || !initOnly[fd.Name.Name] ||
			idx == nil || callIdx == nil || paramVar == nil {
			return false
		}
		fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func)
		if !ok || fn == nil || callIdx.Escaped[fn] {
			return false
		}
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig == nil || pIdx < 0 || pIdx >= sig.Params().Len() {
			return false
		}
		pk := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: ownPath, Name: fn.Name()}, Index: pIdx}
		if visitingInitParams[pk] {
			return false
		}
		visitingInitParams[pk] = true
		defer delete(visitingInitParams, pk)

		isVariadicSlot := sig.Variadic() && pIdx == sig.Params().Len()-1
		for _, call := range callIdx.Calls[fn] {
			if call == nil || idx.InFuncLit[call] || idx.InGoStmt[call] {
				return false
			}
			var callerScope ast.Node
			if callerFD := idx.EnclFunc[call]; callerFD != nil {
				callerScope = callerFD
			}
			if !isSyncInitFlowScope(callerScope) {
				return false
			}
			if len(call.Args) == 1 && sig.Params().Len() > 1 {
				if _, isTup := p.TypesInfo.TypeOf(call.Args[0]).(*types.Tuple); isTup {
					return false
				}
			}
			if !isVariadicSlot || call.Ellipsis.IsValid() {
				if pIdx >= len(call.Args) {
					return false
				}
				argVal := fc.exprValue(p, call.Args[pIdx])
				if refconfine.TypeReachesSyncNoCopyByValue(paramVar.Type()) {
					return false
				}
				if refconfine.TypeCarriesSignature(paramVar.Type()) && !checkCapturedSigOriginAtScope(callerScope, argVal) {
					return false
				}
				if reachOrStr(paramVar.Type()) && !isPureFreshDataValue(settledGlobals, argVal) {
					return false
				}
				continue
			}
			sl, isSl := types.Unalias(paramVar.Type()).Underlying().(*types.Slice)
			if !isSl {
				return false
			}
			elemT := sl.Elem()
			if refconfine.TypeReachesSyncNoCopyByValue(elemT) {
				return false
			}
			for ai := pIdx; ai < len(call.Args); ai++ {
				argVal := fc.exprValue(p, call.Args[ai])
				if refconfine.TypeCarriesSignature(elemT) && !checkCapturedSigOriginAtScope(callerScope, argVal) {
					return false
				}
				if reachOrStr(elemT) && !isPureFreshDataValue(settledGlobals, argVal) {
					return false
				}
			}
		}
		return true
	}

	checkLocalCarryingInit := func(initVal *flowir.Value) bool {
		return checkCapturedSigOriginAtScope(enclosingScope, initVal)
	}

	carryingValue = func(val *flowir.Value) bool {
		if val == nil || val.IsTypeExpr {
			return false
		}
		switch val.Kind {
		case flowir.ValScalarLitOrConst:
			return false
		case flowir.ValAllocFresh:
			switch val.AllocKind {
			case flowir.AllocMake, flowir.AllocBuiltinNewType:
				return false
			case flowir.AllocBuiltinNewExpr:
				return len(val.Args) != 1 || val.Ellipsis || carryingValue(val.Args[0])
			case flowir.AllocCompositeLit:
				for i := range val.CompositeElts {
					elt := &val.CompositeElts[i]
					if elt.MapKey != nil && carryingValue(elt.MapKey) {
						return true
					}
					if elt.Index != nil && carryingValue(elt.Index) {
						return true
					}
					if carryingValue(elt.Value) {
						return true
					}
				}
				return false
			}
		case flowir.ValMakeClosure:
			if val.Lit == nil || visitingFuncLits[val.Lit] {
				return true
			}
			visitingFuncLits[val.Lit] = true
			defer delete(visitingFuncLits, val.Lit)
			wants := map[syntaxutil.ParamKey]bool{}
			methodWants := map[syntaxutil.FuncKey]bool{}
			var checkParamFn func(int, *types.Var) bool
			if fd, isFD := enclosingScope.(*ast.FuncDecl); isFD && isSyncInitFlowScope(fd) && fd.Name != nil && fd.Name.Name != "init" {
				checkParamFn = func(pIdx int, pv *types.Var) bool {
					return checkInitOnlyParamAtCallSites(fd, pIdx, pv)
				}
			}
			origin := &rootOriginPolicy{
				verifyLocalOrigins:   true,
				allowEnclosingParams: false,
				inInitFlow:           isSyncInitFlowScope(enclosingScope),
				unattestedBroken:     unattestedBroken,
				singleSubjectVars:    singleSubjectVars,
				settledGlobals:       settledGlobals,
				currentTargets:       currentTargets,
				checkCarryingValue:   checkLocalCarryingInit,
				checkEnclosingParam:  checkParamFn,
			}
			if !environmentFreeFuncLitWithOrigin(audited, p, fc, val.Lit, enclosingScope, wants, methodWants, origin) {
				return true
			}
			if !wantsResolve(wants, methodWants) {
				return true
			}
			if origin.inInitFlow && pendingCarrierLinks != nil {
				for gvKey := range origin.linkedCarrierGlobals {
					pendingCarrierLinks[gvKey] = true
				}
			}
			return false
		case flowir.ValMethodVal:
			return true
		case flowir.ValConvert:
			if !val.IsTypeAssert && val.Arg != nil {
				if val.Arg.IsNil {
					return false
				}
				if !syntaxutil.IsUnsafePointerType(val.Arg.Type) && val.Type != nil {
					if val.Arg.Type != nil && types.Identical(types.Unalias(val.Type).Underlying(), types.Unalias(val.Arg.Type).Underlying()) {
						return carryingValue(val.Arg)
					}
					if _, isIface := types.Unalias(val.Type).Underlying().(*types.Interface); isIface {
						return carryingValue(val.Arg)
					}
				}
			}
		case flowir.ValCall:
			switch val.CallKind {
			case flowir.CallBuiltin:
				if val.BuiltinName == "append" {
					for _, arg := range val.Args {
						if carryingValue(arg) {
							return true
						}
					}
					return false
				}
			case flowir.CallPlain:
				if !val.IsMethodExprCall && val.CalleeFunc != nil {
					fn := val.CalleeFunc.Origin()
					calleeFK := syntaxutil.FuncKey{Pkg: val.CalleePkg, Name: fn.Name()}
					if auditset.ValuePlaneClone(calleeFK.Pkg, calleeFK.Name) {
						for _, arg := range val.Args {
							if carryingValue(arg) {
								return true
							}
						}
						return false
					}
					if pendingEnvCalls != nil && refconfine.TypeCarriesSignature(val.Type) {
						for _, arg := range val.Args {
							if carryingValue(arg) {
								return true
							}
							if arg != nil && arg.Type != nil && reachOrStr(arg.Type) {
								if !isSettledReachArgValue(audited, p, fc, settledGlobals, currentTargets, enclosingScope, val.CallAST, pkgConf, pendingEnvParams, pendingEnvMethods, checkLocalCarryingInit, arg) {
									return true
								}
							}
						}
						pendingEnvCalls[calleeFK] = true
						return false
					}
				}
			}
		case flowir.ValPlace:
			if val.IsNil || val.IsConst || val.Place.Root == flowir.RootConstOrNil {
				return false
			}
			if val.Place.Root == flowir.RootFunc && len(val.Place.Projs) == 0 {
				return false
			}
		}
		return refconfine.TypeCarriesSignature(val.Type)
	}

	isExemptSeamPlace := func(dst flowir.Place) bool {
		if dst.Raw == nil || len(exemptSeamNodes) == 0 {
			return false
		}
		return exemptSeamNodes[dst.Raw] || exemptSeamNodes[syntaxutil.UnparenExpr(dst.Raw)]
	}

	poisonExemptPlace := func(dst flowir.Place) {
		if fieldPoison == nil {
			return
		}
		for _, variable := range targetVarsForPlace(dst, false) {
			key := syntaxutil.DynamicVarKey(variable)
			if fieldPoison[key] == nil {
				fieldPoison[key] = map[syntaxutil.FieldParamPoison]bool{}
			}
			fieldPoison[key][syntaxutil.FieldParamPoison{Owner: key}] = true
		}
	}

	flowPos := func(v *flowir.Value) token.Pos {
		if v != nil && v.Raw != nil {
			return v.Raw.Pos()
		}
		return token.NoPos
	}

	handleStoreCore := func(dst flowir.Place, hasDst bool, targets []*types.Var, rhs *flowir.Value) {
		if len(targets) == 0 {
			return
		}
		var flows []*flowir.Value
		if rhs != nil {
			flows = []*flowir.Value{rhs}
			if rhs.Kind == flowir.ValCall && rhs.CallKind == flowir.CallBuiltin && rhs.BuiltinName == "append" && len(rhs.Args) > 0 {
				base := rhs.Args[0]
				if base != nil && base.Kind == flowir.ValPlace && base.Place.IsBareVar() && base.Place.Obj != nil {
					if variable, ok := carrierVar(base.Place.Obj); ok && len(targets) == 1 && variable == targets[0] {
						flows = rhs.Args[1:]
					}
				}
			}
		}
		if hasDst {
			if _, mapKey, ok := dst.AsMapWrite(); ok && mapKey != nil {
				flows = append(flows, mapKey)
			}
		}
		if len(flows) == 0 {
			return
		}
		poison := false
		pendingEnvCalls = map[syntaxutil.FuncKey]bool{}
		pendingEnvParams = map[syntaxutil.ParamKey]bool{}
		pendingEnvMethods = map[syntaxutil.FuncKey]bool{}
		pendingCarrierLinks = map[string]bool{}
		prevTargets := currentTargets
		currentTargets = targets
		var poisonAt, deferredAt token.Pos
		for _, flow := range flows {
			beforeCalls, beforeParams, beforeMethods := len(pendingEnvCalls), len(pendingEnvParams), len(pendingEnvMethods)
			if carryingValue(flow) {
				poison = true
				poisonAt = flowPos(flow)
				break
			}
			if deferredAt == token.NoPos && (len(pendingEnvCalls) > beforeCalls || len(pendingEnvParams) > beforeParams || len(pendingEnvMethods) > beforeMethods) {
				deferredAt = flowPos(flow)
			}
		}
		currentTargets = prevTargets
		if poison {
			for _, variable := range targets {
				key := syntaxutil.DynamicVarKey(variable)
				syntaxutil.ExplainStoreMark(hooks, p, key, poisonAt)
				envCarrying[key] = true
				if envCallableVars != nil {
					if _, isFunc := types.Unalias(variable.Type()).Underlying().(*types.Signature); isFunc {
						envCallableVars[key] = true
					}
				}
				if currentRegFn.Valid() {
					if envCarryingFns != nil {
						if envCarryingFns[key] == nil {
							envCarryingFns[key] = map[syntaxutil.FuncKey]bool{}
						}
						envCarryingFns[key][currentRegFn] = true
					}
				} else if envCarryingUnattr != nil {
					envCarryingUnattr[key] = true
				}
			}
		} else {
			if len(pendingEnvCalls) > 0 || len(pendingEnvParams) > 0 || len(pendingEnvMethods) > 0 {
				for _, variable := range targets {
					key := syntaxutil.DynamicVarKey(variable)
					if deferredAt != token.NoPos {
						syntaxutil.ExplainStoreMark(hooks, p, key, deferredAt)
					}
					if envCallableVars != nil {
						if _, isFunc := types.Unalias(variable.Type()).Underlying().(*types.Signature); isFunc {
							envCallableVars[key] = true
						}
					}
					if envCalls != nil {
						for callee := range pendingEnvCalls {
							envCalls[syntaxutil.EnvCallUse{Key: key, Callee: callee, Func: currentRegFn}] = true
						}
					}
					if envParamCalls != nil {
						for pk := range pendingEnvParams {
							envParamCalls[syntaxutil.EnvCallParamUse{Key: key, Param: pk, Func: currentRegFn}] = true
						}
					}
					if envMethodCalls != nil {
						for mk := range pendingEnvMethods {
							envMethodCalls[syntaxutil.EnvCallMethodUse{Key: key, Method: mk, Func: currentRegFn}] = true
						}
					}
				}
			}
			if carrierLinks != nil && len(pendingCarrierLinks) > 0 {
				for gvKey := range pendingCarrierLinks {
					for _, variable := range targets {
						key := syntaxutil.DynamicVarKey(variable)
						if key != gvKey {
							carrierLinks[syntaxutil.CarrierLink{From: key, To: gvKey}] = true
						}
					}
				}
			}
			if fieldDefer != nil {
				var marks []fieldRegMark
				for _, flow := range flows {
					classifyFieldRegistrantsValue(audited, p, fc, dst, hasDst, flow, func(m fieldRegMark) {
						marks = append(marks, m)
					})
				}
				for _, variable := range targets {
					key := syntaxutil.DynamicVarKey(variable)
					for _, m := range marks {
						switch m.class {
						case 'd':
							pos := syntaxutil.FieldPosKey{Owner: key, Field: m.field, Index: m.idx}
							if fieldDefer[pos] == nil {
								fieldDefer[pos] = map[syntaxutil.ParamKey]bool{}
							}
							fieldDefer[pos][m.param] = true
						case 'p':
							if fieldPoison[key] == nil {
								fieldPoison[key] = map[syntaxutil.FieldParamPoison]bool{}
							}
							if m.field == "" {
								fieldPoison[key][syntaxutil.FieldParamPoison{Owner: key}] = true
							} else {
								fieldPoison[key][syntaxutil.FieldParamPoison{Owner: key, HasPos: true, Field: m.field, Index: m.idx}] = true
							}
						}
					}
				}
			}
		}
		pendingEnvCalls = nil
		pendingEnvParams = nil
		pendingEnvMethods = nil
		pendingCarrierLinks = nil
	}

	handleStorePlace := func(dst flowir.Place, rhs *flowir.Value, rebindable, writeContainer bool) {
		if rebindable && dst.IsBareVar() && dst.Obj != nil {
			if _, isCarrier := carrierVar(dst.Obj); !isCarrier {
				return
			}
		}
		targets := targetVarsForPlace(dst, writeContainer)
		handleStoreCore(dst, true, targets, rhs)
	}

	handleStoreValue := func(lhsVal, rhs *flowir.Value, writeContainer bool) {
		dst, hasDst, targets := targetVarsForValue(lhsVal, writeContainer)
		handleStoreCore(dst, hasDst, targets, rhs)
	}

	var walkStoresBody func(b *flowir.Body, scope ast.Node, aliases map[types.Object]localCarrierAliases)
	walkStoresBody = func(b *flowir.Body, scope ast.Node, aliases map[types.Object]localCarrierAliases) {
		if b == nil {
			return
		}
		prevScope := enclosingScope
		prevAliases := localAliases
		enclosingScope = scope
		localAliases = aliases
		defer func() {
			enclosingScope = prevScope
			localAliases = prevAliases
		}()

		var scanVal func(v *flowir.Value)
		scanVal = func(v *flowir.Value) {
			if v == nil {
				return
			}
			switch v.Kind {
			case flowir.ValMakeClosure:
				if v.Closure != nil {
					walkStoresBody(v.Closure, v.Lit, computeLocalAliases(v.Closure, aliases))
				}
				return
			case flowir.ValCall:
				if v.CallKind == flowir.CallIIFE {
					for _, a := range v.Args {
						scanVal(a)
					}
					if v.IIFE != nil {
						var iifeLit *ast.FuncLit
						if v.CallAST != nil {
							iifeLit, _ = syntaxutil.UnparenExpr(v.CallAST.Fun).(*ast.FuncLit)
						}
						walkStoresBody(v.IIFE, iifeLit, computeLocalAliases(v.IIFE, aliases))
					}
					return
				}
				if v.CallKind == flowir.CallBuiltin {
					switch {
					case v.BuiltinName == "copy" && len(v.Args) == 2:
						handleStoreValue(v.Args[0], v.Args[1], true)
					case v.BuiltinName == "append" && len(v.Args) > 1:
						for _, flow := range v.Args[1:] {
							handleStoreValue(v.Args[0], flow, true)
						}
					}
				}
			}
			v.ForEachChildValue(func(ch *flowir.Value) bool {
				scanVal(ch)
				return true
			})
		}

		b.ForEachSyncOp(func(op *flowir.Op) bool {
			switch op.Kind {
			case flowir.OpAssign:
				switch op.AssignKind {
				case flowir.AssignZeroDecl:
					// Uninitialized declarations store no function-carrying values.
				case flowir.AssignIncDec:
					for _, dst := range op.Dsts {
						if _, mapKey, ok := dst.AsMapWrite(); ok && mapKey != nil {
							handleStorePlace(dst, nil, false, false)
						}
						dst.ForEachChildValue(func(cv *flowir.Value) bool {
							scanVal(cv)
							return true
						})
					}
				case flowir.AssignCompound:
					for i, dst := range op.Dsts {
						var rhs *flowir.Value
						if i < len(op.Srcs) && op.Srcs[i] != nil {
							rhs = op.Srcs[i]
							if rhs.Kind == flowir.ValCompositeExpr && len(rhs.Args) == 2 {
								rhs = rhs.Args[1]
							}
						}
						if isExemptSeamPlace(dst) {
							poisonExemptPlace(dst)
						} else if rhs != nil {
							handleStorePlace(dst, rhs, true, false)
						}
						dst.ForEachChildValue(func(cv *flowir.Value) bool {
							scanVal(cv)
							return true
						})
						scanVal(rhs)
					}
				case flowir.AssignRange:
					var rngSrc *flowir.Value
					if len(op.Srcs) == 1 {
						rngSrc = op.Srcs[0]
					}
					rs, _ := op.StmtAST.(*ast.RangeStmt)
					isAssignTok := rs != nil && rs.Tok == token.ASSIGN
					for i, dst := range op.Dsts {
						isDef := i < len(op.DstDefs) && op.DstDefs[i]
						if (isAssignTok || !isDef) && rngSrc != nil {
							handleStorePlace(dst, rngSrc, true, false)
						}
						dst.ForEachChildValue(func(cv *flowir.Value) bool {
							scanVal(cv)
							return true
						})
					}
					for _, src := range op.Srcs {
						scanVal(src)
					}
				default:
					for i, dst := range op.Dsts {
						if isExemptSeamPlace(dst) {
							poisonExemptPlace(dst)
						} else {
							var rhs *flowir.Value
							if len(op.Dsts) == len(op.Srcs) {
								rhs = op.Srcs[i]
							} else if len(op.Srcs) == 1 {
								rhs = op.Srcs[0]
							}
							if rhs != nil {
								handleStorePlace(dst, rhs, true, false)
							}
						}
						dst.ForEachChildValue(func(cv *flowir.Value) bool {
							scanVal(cv)
							return true
						})
					}
					for _, src := range op.Srcs {
						scanVal(src)
					}
				}
			case flowir.OpTypeSwitchBind:
				if op.CaseAST == nil {
					scanVal(op.SwitchSrc)
				}
			case flowir.OpChanSend:
				handleStoreValue(op.ChanVal, op.SendVal, true)
				scanVal(op.ChanVal)
				scanVal(op.SendVal)
			case flowir.OpReturn:
				for _, r := range op.Results {
					scanVal(r)
				}
			case flowir.OpDefer:
				scanVal(op.Call)
			case flowir.OpGo:
				saved := enclosingScope
				enclosingScope = op.StmtAST
				scanVal(op.Call)
				enclosingScope = saved
			case flowir.OpExpr:
				scanVal(op.Expr)
			}
			return true
		})
	}

	for _, file := range p.Syntax {
		if file == nil {
			continue
		}
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if decl.Body != nil {
					if ownPath != "" && decl.Recv == nil && decl.Name != nil &&
						!initOnly[decl.Name.Name] && decl.Name.Name != "init" &&
						decl.Name.Name != "TestMain" && decl.Name.Name != "_" {
						currentRegFn = syntaxutil.FuncKey{Pkg: ownPath, Name: decl.Name.Name}
					}
					b := fc.funcBody(p, decl)
					walkStoresBody(b, decl, computeLocalAliases(b, nil))
					currentRegFn = syntaxutil.FuncKey{}
				}
			case *ast.GenDecl:
				if decl.Tok == token.VAR || decl.Tok == token.CONST {
					b := fc.body(p, decl)
					walkStoresBody(b, nil, computeLocalAliases(b, nil))
				}
			}
		}
	}
}
