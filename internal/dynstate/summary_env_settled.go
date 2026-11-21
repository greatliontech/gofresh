package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
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
			return pkgConf.resolveWants(ownPath, wants, methodWants, localParams, localMethods)
		},
	})
	return ok && commitSinks()
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
						if flowir.BodyMentionsVar(fc.body(p, vs), carrier) {
							return false
						}
					}
				case *ast.FuncDecl:
					if d.Body == nil || d.Name == nil {
						continue
					}
					if !flowir.BodyMentionsVar(fc.funcBody(p, d), carrier) {
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
						if syntaxutil.IsUnsafePointerType(v.Type) && flowir.ValueMentionsVar(v.Arg, g) {
							okSpec = false
							return
						}
					case flowir.ValAddrOf:
						if v.AddrPlace.Obj == g {
							okSpec = false
							return
						}
					case flowir.ValMethodVal:
						if v.Recv != nil && flowir.ValueMentionsVar(v.Recv, g) {
							okSpec = false
							return
						}
					case flowir.ValMakeClosure:
						if v.Lit != nil && flowir.BodyMentionsVar(v.Closure, g) {
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
							if flowir.ValueMentionsVar(v, g) {
								okSpec = false
							}
							return
						}
						if v.CallKind == flowir.CallBuiltin {
							switch v.BuiltinName {
							case "StringData", "String":
								if flowir.ValueMentionsVar(v, g) {
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
								shallowSafe := !containerElemHandsOutReach(v.Type)
								for _, arg := range v.Args {
									if shallowSafe && arg != nil && arg.Kind == flowir.ValPlace && arg.Place.Obj == g && len(arg.Place.Projs) == 0 {
										continue
									}
									checkVal(arg)
								}
								return
							}
							v.ForEachArgParam(func(arg *flowir.Value, slotType types.Type, _ int, pIdx int, pOK bool, packedVariadic bool) bool {
								if !okSpec || !flowir.ValueMentionsVar(arg, g) {
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
							if flowir.ValueMentionsVar(arg, g) && (reachOrStr(g.Type()) || (v.AutoAddrRecv && v.HasRecvPlace && v.RecvPlace.Obj == g)) {
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
				if dep == g || !reachOrStr(dep.Type()) || !flowir.ValueMentionsVar(candidates[g], dep) {
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
						if d.Body == nil || !flowir.BodyMentionsVar(fc.funcBody(p, d), g) {
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
									if i < len(vs.Values) && flowir.ValueMentionsVar(fc.exprValue(p, vs.Values[i]), g) {
										keep = false
										break
									}
								}
								continue
							}
							if !flowir.BodyMentionsVar(fc.body(p, vs), g) {
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
