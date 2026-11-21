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

// onceFieldOfDo resolves a call of the shape `x.field.Do(f)` — Do on a
// by-value sync.Once field selected from some value — to that field,
// or nil for every other shape.
func onceFieldOfDo(audited bool, info *types.Info, call *ast.CallExpr) *types.Var {
	if len(call.Args) != 1 {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	selection, ok := info.Selections[sel]
	if !ok || selection.Kind() != types.MethodVal {
		return nil
	}
	fn, ok := selection.Obj().(*types.Func)
	if !ok || !refconfine.AuditedOnceDo(audited, fn) {
		return nil
	}
	fieldSel, ok := sel.X.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	fieldSelection, ok := info.Selections[fieldSel]
	if !ok || fieldSelection.Kind() != types.FieldVal || len(fieldSelection.Index()) != 1 {
		return nil
	}
	field, ok := fieldSelection.Obj().(*types.Var)
	if !ok {
		return nil
	}
	named, ok := types.Unalias(field.Type()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "sync" || named.Obj().Name() != "Once" {
		return nil
	}
	return field
}

func markStructFieldsDisqualified(t types.Type, out map[*types.Var]bool) {
	seen := map[types.Type]bool{}
	var walk func(cur types.Type)
	walk = func(cur types.Type) {
		if cur == nil {
			return
		}
		u := types.Unalias(cur)
		if seen[u] {
			return
		}
		seen[u] = true
		st, ok := u.Underlying().(*types.Struct)
		if !ok {
			return
		}
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			out[f] = true
			walk(f.Type())
		}
	}
	walk(t)
}

func collectPackageOnceFieldUsage(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
) (
	onceSites map[*types.Var]int,
	fieldRefIdents map[*types.Var][]*ast.Ident,
	disqualifiedOnceFields map[*types.Var]bool,
	aliasedInitOnceFields map[*types.Var]bool,
) {
	onceSites = map[*types.Var]int{}
	fieldRefIdents = map[*types.Var][]*ast.Ident{}
	disqualifiedOnceFields = map[*types.Var]bool{}
	aliasedInitOnceFields = map[*types.Var]bool{}
	zeroKeyIdents := map[*ast.Ident]bool{}
	pureInitKeyIdents := map[*ast.Ident]bool{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				if field := onceFieldOfDo(audited, p.TypesInfo, x); field != nil {
					onceSites[field]++
				}
				if tv, ok := p.TypesInfo.Types[ast.Unparen(x.Fun)]; ok && tv.IsType() && len(x.Args) == 1 {
					to := p.TypesInfo.TypeOf(x)
					from := p.TypesInfo.TypeOf(x.Args[0])
					if to != nil && from != nil && !types.Identical(from, to) {
						for _, convT := range []types.Type{to, from} {
							if ptr, isPtr := types.Unalias(convT).(*types.Pointer); isPtr {
								convT = ptr.Elem()
							}
							markStructFieldsDisqualified(convT, disqualifiedOnceFields)
							markStructFieldsDisqualified(convT, aliasedInitOnceFields)
						}
					}
				}
			case *ast.CompositeLit:
				ct := p.TypesInfo.TypeOf(x)
				if ct != nil {
					if ptr, isPtr := types.Unalias(ct).Underlying().(*types.Pointer); isPtr {
						ct = ptr.Elem()
					}
					if st, isSt := types.Unalias(ct).Underlying().(*types.Struct); isSt && len(x.Elts) > 0 {
						if _, keyed := x.Elts[0].(*ast.KeyValueExpr); keyed {
							for _, elt := range x.Elts {
								if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
									if keyID, isID := ast.Unparen(kv.Key).(*ast.Ident); isID {
										if fld, isVar := p.TypesInfo.Uses[keyID].(*types.Var); isVar && fld != nil && fld.IsField() {
											val := fc.exprValue(p, kv.Value)
											if isZeroFieldInitValue(fld.Type(), val) {
												zeroKeyIdents[keyID] = true
											} else {
												disqualifiedOnceFields[fld] = true
												markStructFieldsDisqualified(fld.Type(), disqualifiedOnceFields)
												if isPureFreshDataValueWith(val, nil) {
													pureInitKeyIdents[keyID] = true
												} else {
													aliasedInitOnceFields[fld] = true
													markStructFieldsDisqualified(fld.Type(), aliasedInitOnceFields)
												}
											}
										}
									}
								}
							}
						} else {
							for i, elt := range x.Elts {
								if i < st.NumFields() {
									fld := st.Field(i)
									val := fc.exprValue(p, elt)
									if !isZeroFieldInitValue(fld.Type(), val) {
										disqualifiedOnceFields[fld] = true
										markStructFieldsDisqualified(fld.Type(), disqualifiedOnceFields)
										if !isPureFreshDataValueWith(val, nil) {
											aliasedInitOnceFields[fld] = true
											markStructFieldsDisqualified(fld.Type(), aliasedInitOnceFields)
										}
									}
								}
							}
						}
					}
				}
			}
			return true
		})
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && !zeroKeyIdents[id] && !pureInitKeyIdents[id] {
				if fld, isVar := p.TypesInfo.Uses[id].(*types.Var); isVar && fld != nil && fld.IsField() {
					fieldRefIdents[fld] = append(fieldRefIdents[fld], id)
				}
			}
			return true
		})
	}
	return onceSites, fieldRefIdents, disqualifiedOnceFields, aliasedInitOnceFields
}

func identInPostDoAsyncSubtree(methodBody *ast.BlockStmt, afterPos token.Pos, target *ast.Ident) bool {
	if methodBody == nil || target == nil {
		return true
	}
	hit := false
	ast.Inspect(methodBody, func(n ast.Node) bool {
		if hit || n == nil {
			return false
		}
		if n.End() <= afterPos {
			return false
		}
		switch sub := n.(type) {
		case *ast.FuncLit:
			if target.Pos() >= sub.Pos() && target.Pos() <= sub.End() {
				hit = true
				return false
			}
		case *ast.GoStmt:
			if target.Pos() >= sub.Pos() && target.Pos() <= sub.End() {
				hit = true
				return false
			}
		}
		return true
	})
	return hit
}

func collectByValuePrivateStructFields(recvPtrType types.Type, pkg *types.Package) []*types.Var {
	ptr, ok := types.Unalias(recvPtrType).(*types.Pointer)
	if !ok || pkg == nil {
		return nil
	}
	var fields []*types.Var
	seen := map[types.Type]bool{}
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil {
			return
		}
		u := types.Unalias(t)
		if seen[u] {
			return
		}
		seen[u] = true
		st, ok := u.Underlying().(*types.Struct)
		if !ok {
			return
		}
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if f == nil || f.Exported() || f.Pkg() != pkg {
				continue
			}
			fields = append(fields, f)
			walk(f.Type())
		}
	}
	walk(ptr.Elem())
	return fields
}

func receiverByValueOnceFillField(dst flowir.Place, recvObj types.Object) (fld *types.Var, whole bool) {
	if dst.Obj == nil || dst.Obj != recvObj || len(dst.Projs) == 0 {
		return nil, false
	}
	start := 0
	if dst.Projs[0].Kind == flowir.ProjDeref {
		start = 1
	}
	if start >= len(dst.Projs) || dst.Projs[start].Kind != flowir.ProjField {
		return nil, false
	}
	var lastField *types.Var
	k := start
	for k < len(dst.Projs) {
		pr := &dst.Projs[k]
		if pr.Kind != flowir.ProjField || pr.Field == nil || pr.Field.Exported() || syntaxutil.SelectionCrossesEmbeddedPointer(pr.Selection) {
			break
		}
		if k > start && pr.Indirect {
			break
		}
		lastField = pr.Field
		k++
	}
	if lastField == nil {
		return nil, false
	}
	if k < len(dst.Projs) {
		if _, isByValStruct := types.Unalias(lastField.Type()).Underlying().(*types.Struct); isByValStruct {
			return nil, false
		}
	}
	return lastField, k == len(dst.Projs)
}

func isPkgOrOuterToBody(body *flowir.Body, v *types.Var) bool {
	if v == nil || v.IsField() {
		return false
	}
	if v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
		return true
	}
	if body == nil {
		return true
	}
	return v.Pos() < body.BodyStart || v.Pos() > body.BodyEnd
}

func isOnceExternalCarrierOrReachVar(audited bool, doBody *flowir.Body, recvObj types.Object, v *types.Var) bool {
	if v == nil || v.IsField() || v == recvObj {
		return false
	}
	if !isPkgOrOuterToBody(doBody, v) {
		return false
	}
	return sharesMemOrSigOrDynamic(audited)(v.Type())
}

func onceFillValueSmuggles(
	audited bool,
	doBody *flowir.Body,
	smuggledLocals map[types.Object]bool,
	admCandidates map[*types.Var]bool,
	recvObj types.Object,
	v *flowir.Value,
) bool {
	if v == nil {
		return true
	}
	found := false
	var walk func(cur *flowir.Value)
	var walkBody func(b *flowir.Body)
	walkBody = func(b *flowir.Body) {
		if found || b == nil {
			return
		}
		b.ForEachSyncOp(func(op *flowir.Op) bool {
			switch op.Kind {
			case flowir.OpAssign:
				for i := range op.Dsts {
					op.Dsts[i].ForEachChildValue(func(cv *flowir.Value) bool {
						walk(cv)
						return !found
					})
					if found {
						return false
					}
				}
				for _, s := range op.Srcs {
					walk(s)
					if found {
						return false
					}
				}
			case flowir.OpTypeSwitchBind:
				walk(op.SwitchSrc)
			case flowir.OpChanSend:
				walk(op.ChanVal)
				walk(op.SendVal)
			case flowir.OpReturn:
				for _, r := range op.Results {
					walk(r)
					if found {
						return false
					}
				}
			case flowir.OpDefer, flowir.OpGo:
				walk(op.Call)
			case flowir.OpExpr:
				walk(op.Expr)
			}
			return !found
		})
	}
	walk = func(cur *flowir.Value) {
		if found || cur == nil {
			return
		}
		if cur.Kind == flowir.ValInvalid || cur.Kind == flowir.ValChanRecv {
			found = true
			return
		}
		if cur.Type != nil && !sharesMemOrSigOrDynamic(audited)(cur.Type) {
			return
		}
		switch cur.Kind {
		case flowir.ValPlace:
			if vObj := cur.Place.Obj; vObj != nil {
				if vObj == recvObj {
					fld, _ := receiverByValueOnceFillField(cur.Place, recvObj)
					if fld == nil || !admCandidates[fld] {
						found = true
						return
					}
				} else if smuggledLocals[vObj] || isOnceExternalCarrierOrReachVar(audited, doBody, recvObj, vObj) {
					found = true
					return
				}
			}
		case flowir.ValAddrOf:
			if vObj := cur.AddrPlace.Obj; vObj != nil {
				if vObj == recvObj {
					fld, _ := receiverByValueOnceFillField(cur.AddrPlace, recvObj)
					if fld == nil || !admCandidates[fld] {
						found = true
						return
					}
				} else if smuggledLocals[vObj] || isPkgOrOuterToBody(doBody, vObj) {
					found = true
					return
				}
			}
		case flowir.ValMethodVal:
			found = true
			return
		case flowir.ValMakeClosure:
			if cur.Closure == nil {
				found = true
				return
			}
			for fv := range cur.Closure.FreeVars {
				if fv == recvObj || smuggledLocals[fv] || isOnceExternalCarrierOrReachVar(audited, doBody, recvObj, fv) {
					found = true
					return
				}
			}
			walkBody(cur.Closure)
			return
		case flowir.ValCall:
			switch {
			case cur.CallKind == flowir.CallIIFE && cur.IIFE != nil:
				for _, a := range cur.Args {
					walk(a)
					if found {
						return
					}
				}
				walkBody(cur.IIFE)
				return
			case cur.CallKind == flowir.CallBuiltin && (cur.BuiltinName == "Sizeof" || cur.BuiltinName == "Alignof" || cur.BuiltinName == "Offsetof"):
				return
			case cur.CallKind == flowir.CallBuiltin && cur.BuiltinName == "append":
				for _, a := range cur.Args {
					walk(a)
					if found {
						return
					}
				}
				return
			case cur.CallKind == flowir.CallPlain && !cur.IsMethodExprCall && cur.CalleeFunc != nil && auditset.ValuePlaneClone(cur.CalleePkg, cur.CalleeFunc.Name()):
				for _, a := range cur.Args {
					walk(a)
					if found {
						return
					}
				}
				return
			default:
				found = true
				return
			}
		}
		cur.ForEachChildValue(func(child *flowir.Value) bool {
			walk(child)
			return !found
		})
	}
	walk(v)
	return found
}

func computeOnceFillSmuggledLocals(
	audited bool,
	fc *pkgFlowCache,
	doBody *flowir.Body,
	admCandidates map[*types.Var]bool,
	recvObj types.Object,
) map[types.Object]bool {
	smuggled := map[types.Object]bool{}
	var exclude map[types.Object]bool
	if recvObj != nil {
		exclude = map[types.Object]bool{recvObj: true}
	}
	propagateFlowVarTaint(audited, fc, doBody, smuggled, flowVarTaintConfig{
		exclude: exclude,
		valTaints: func(v *flowir.Value) bool {
			return onceFillValueSmuggles(audited, doBody, smuggled, admCandidates, recvObj, v)
		},
		reverseFlowAndCallTargets: true,
		checkAssignDstType:        true,
		checkCopyDstElem:          true,
	})
	return smuggled
}

func propagateReceiverFieldTaint(
	doBody *flowir.Body,
	recvObj types.Object,
	allowField map[*types.Var]bool,
) (map[types.Object]map[*types.Var]bool, func(*flowir.Value) map[*types.Var]bool) {
	tainted := map[types.Object]map[*types.Var]bool{}
	addTaint := func(obj types.Object, fld *types.Var) bool {
		if obj == nil || fld == nil {
			return false
		}
		if tainted[obj] == nil {
			tainted[obj] = map[*types.Var]bool{}
		}
		if !tainted[obj][fld] {
			tainted[obj][fld] = true
			return true
		}
		return false
	}
	valTaints := func(v *flowir.Value) map[*types.Var]bool {
		var out map[*types.Var]bool
		if v == nil {
			return nil
		}
		v.WalkValues(func(cur *flowir.Value) bool {
			switch cur.Kind {
			case flowir.ValPlace:
				if fld, _ := receiverByValueOnceFillField(cur.Place, recvObj); fld != nil {
					if allowField == nil || allowField[fld] {
						if out == nil {
							out = map[*types.Var]bool{}
						}
						out[fld] = true
					}
				} else if cur.Place.Obj != nil {
					for f := range tainted[cur.Place.Obj] {
						if out == nil {
							out = map[*types.Var]bool{}
						}
						out[f] = true
					}
				}
			case flowir.ValAddrOf:
				if fld, _ := receiverByValueOnceFillField(cur.AddrPlace, recvObj); fld != nil {
					if allowField == nil || allowField[fld] {
						if out == nil {
							out = map[*types.Var]bool{}
						}
						out[fld] = true
					}
				} else if cur.AddrPlace.Obj != nil {
					for f := range tainted[cur.AddrPlace.Obj] {
						if out == nil {
							out = map[*types.Var]bool{}
						}
						out[f] = true
					}
				}
			}
			return true
		})
		return out
	}
	if doBody != nil {
		for changed := true; changed; {
			changed = false
			doBody.ForEachSyncOp(func(op *flowir.Op) bool {
				if op.Kind == flowir.OpAssign {
					op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
						if dst.Obj != nil && dst.Obj != recvObj {
							for fld := range valTaints(src) {
								if addTaint(dst.Obj, fld) {
									changed = true
								}
							}
						}
						return true
					})
				} else if op.Kind == flowir.OpTypeSwitchBind && op.SwitchDst != nil {
					for fld := range valTaints(op.SwitchSrc) {
						if addTaint(op.SwitchDst, fld) {
							changed = true
						}
					}
				}
				return true
			})
		}
	}
	return tainted, valTaints
}

func computeOnceDoFieldAdmissions(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	methodDecl *ast.FuncDecl,
	doCall *ast.CallExpr,
	doLit *ast.FuncLit,
	doBody *flowir.Body,
	recvObj types.Object,
	fieldRefIdents map[*types.Var][]*ast.Ident,
	disqualifiedOnceFields map[*types.Var]bool,
	aliasedInitOnceFields map[*types.Var]bool,
) *onceDoAdmission {
	adm := &onceDoAdmission{
		doBody:             doBody,
		candidates:         map[*types.Var]bool{},
		confinedOnceFields: map[*types.Var]bool{},
		confinedTainted:    map[types.Object]bool{},
		fillFields:         map[*types.Var]bool{},
		freshFillFields:    map[*types.Var]bool{},
		freshTainted:       map[types.Object]bool{},
	}
	methodBody := fc.funcBody(p, methodDecl)
	if methodDecl == nil || methodDecl.Body == nil || doCall == nil || doLit == nil || doLit.Body == nil || methodBody == nil || methodBody.HasGoto {
		adm.smuggledLocals = computeOnceFillSmuggledLocals(audited, fc, doBody, adm.candidates, recvObj)
		return adm
	}

	isConfinedToDoAndPost := func(fld *types.Var, disallow map[*types.Var]bool) bool {
		if disallow[fld] {
			return false
		}
		confinedRefs := true
		var checkRefs func(t types.Type, seen map[types.Type]bool)
		checkRefs = func(t types.Type, seen map[types.Type]bool) {
			if !confinedRefs || t == nil {
				return
			}
			u := types.Unalias(t)
			if seen[u] {
				return
			}
			seen[u] = true
			st, ok := u.Underlying().(*types.Struct)
			if !ok {
				return
			}
			for i := 0; i < st.NumFields(); i++ {
				sf := st.Field(i)
				if sf.Exported() || sf.Pkg() != p.Types || disallow[sf] {
					confinedRefs = false
					return
				}
				for _, id := range fieldRefIdents[sf] {
					inDo := id.Pos() >= doLit.Body.Pos() && id.Pos() <= doLit.Body.End()
					postDo := id.Pos() > doCall.End() && id.Pos() <= methodDecl.Body.End() && !identInPostDoAsyncSubtree(methodDecl.Body, doCall.End(), id)
					if !inDo && !postDo {
						confinedRefs = false
						return
					}
				}
				checkRefs(sf.Type(), seen)
			}
		}
		for _, id := range fieldRefIdents[fld] {
			inDo := id.Pos() >= doLit.Body.Pos() && id.Pos() <= doLit.Body.End()
			postDo := id.Pos() > doCall.End() && id.Pos() <= methodDecl.Body.End() && !identInPostDoAsyncSubtree(methodDecl.Body, doCall.End(), id)
			if !inDo && !postDo {
				return false
			}
		}
		checkRefs(fld.Type(), map[types.Type]bool{})
		return confinedRefs
	}

	candidates := adm.candidates
	for _, fld := range collectByValuePrivateStructFields(recvObj.Type(), p.Types) {
		ft := fld.Type()
		if refconfine.TypeMayCarryUnknownDynamic(audited, ft) ||
			refconfine.TypeCarriesSignature(ft) ||
			refconfine.TypeReachesSyncNoCopyByValue(ft) ||
			refconfine.TypeReachesOnce(ft) {
			continue
		}
		if isConfinedToDoAndPost(fld, aliasedInitOnceFields) {
			adm.confinedOnceFields[fld] = true
		}
		if (refconfine.TypeHandsOutMutableReach(ft) || syntaxutil.ContainsUintptr(ft)) && isConfinedToDoAndPost(fld, disqualifiedOnceFields) {
			candidates[fld] = true
		}
	}
	adm.smuggledLocals = computeOnceFillSmuggledLocals(audited, fc, doBody, candidates, recvObj)

	if len(adm.confinedOnceFields) > 0 {
		confSmuggled := computeOnceFillSmuggledLocals(audited, fc, doBody, adm.confinedOnceFields, recvObj)
		confTainted, _ := propagateReceiverFieldTaint(doBody, recvObj, nil)
		for obj, flds := range confTainted {
			if len(flds) == 0 || confSmuggled[obj] {
				continue
			}
			allConf := true
			for fld := range flds {
				if !adm.confinedOnceFields[fld] {
					allConf = false
					break
				}
			}
			if allConf {
				adm.confinedTainted[obj] = true
			}
		}
	}

	if len(candidates) == 0 {
		return adm
	}

	var excludeRecv map[types.Object]bool
	if recvObj != nil {
		excludeRecv = map[types.Object]bool{recvObj: true}
	}
	freshLocals := computeBodyFreshSelfContainedLocals(audited, fc, doBody, excludeRecv, adm.smuggledLocals)

	// Track whole-field stores, fresh whole-field stores, local aliases of each
	// candidate field, and interior/element mutations in doBody.
	wholeCount := map[*types.Var]int{}
	nonFreshWhole := map[*types.Var]bool{}
	taintedFromField, valueFieldTaints := propagateReceiverFieldTaint(doBody, recvObj, candidates)

	interiorMutated := map[*types.Var]bool{}
	markCallInterior := func(v *flowir.Value) {
		if v == nil {
			return
		}
		v.WalkValues(func(cur *flowir.Value) bool {
			if cur.Kind == flowir.ValCall && cur.CallKind == flowir.CallBuiltin {
				switch cur.BuiltinName {
				case "clear", "delete", "copy":
					if len(cur.Args) >= 1 {
						for fld := range valueFieldTaints(cur.Args[0]) {
							interiorMutated[fld] = true
						}
					}
				}
			}
			return true
		})
	}
	doBody.ForEachSyncOp(func(op *flowir.Op) bool {
		switch op.Kind {
		case flowir.OpAssign:
			if op.AssignKind == flowir.AssignMulti && len(op.Srcs) == 1 {
				for _, dst := range op.Dsts {
					if fld, whole := receiverByValueOnceFillField(dst, recvObj); fld != nil && candidates[fld] {
						if whole {
							wholeCount[fld]++
							nonFreshWhole[fld] = true
						} else {
							interiorMutated[fld] = true
						}
					} else if !dst.IsBareVar() && dst.Obj != nil {
						for f := range taintedFromField[dst.Obj] {
							interiorMutated[f] = true
						}
					}
				}
			} else {
				op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
					if fld, whole := receiverByValueOnceFillField(dst, recvObj); fld != nil && candidates[fld] {
						if whole {
							wholeCount[fld]++
							if op.AssignKind != flowir.AssignPlain || !isFreshLocalOnceValue(audited, src, freshLocals) {
								nonFreshWhole[fld] = true
							}
						} else {
							interiorMutated[fld] = true
						}
					} else if !dst.IsBareVar() && dst.Obj != nil {
						for f := range taintedFromField[dst.Obj] {
							interiorMutated[f] = true
						}
					}
					return true
				})
			}
			for _, s := range op.Srcs {
				markCallInterior(s)
			}
		case flowir.OpExpr:
			markCallInterior(op.Expr)
		case flowir.OpDefer, flowir.OpGo:
			markCallInterior(op.Call)
		case flowir.OpReturn:
			for _, r := range op.Results {
				markCallInterior(r)
			}
		}
		return true
	})

	for fld := range candidates {
		freshInit := wholeCount[fld] > 0 && !nonFreshWhole[fld]
		if interiorMutated[fld] && !freshInit {
			continue
		}
		adm.fillFields[fld] = true
		if freshInit {
			if _, isByValStruct := types.Unalias(fld.Type()).Underlying().(*types.Struct); !isByValStruct {
				adm.freshFillFields[fld] = true
			}
		}
	}
	for obj, flds := range taintedFromField {
		if len(flds) == 0 || adm.smuggledLocals[obj] {
			continue
		}
		allFresh := true
		for fld := range flds {
			if !adm.freshFillFields[fld] {
				allFresh = false
				break
			}
		}
		if allFresh {
			adm.freshTainted[obj] = true
		}
	}
	return adm
}

func findAdmittedReceiverOnceDo(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	methodDecl *ast.FuncDecl,
	body *flowir.Body,
	recvObj types.Object,
	onceSites map[*types.Var]int,
	fieldRefIdents map[*types.Var][]*ast.Ident,
	disqualifiedOnceFields map[*types.Var]bool,
	aliasedInitOnceFields map[*types.Var]bool,
) map[*ast.CallExpr]*onceDoAdmission {
	if body == nil || recvObj == nil {
		return nil
	}
	if _, pointer := types.Unalias(recvObj.Type()).(*types.Pointer); !pointer {
		return nil
	}
	if refconfine.OnceFieldCount(recvObj.Type()) != 1 {
		return nil
	}
	for i := range body.Ops {
		op := &body.Ops[i]
		if !op.TopLevelInBody {
			return nil
		}
		if op.Kind == flowir.OpExpr && op.Expr != nil && op.Expr.Kind == flowir.ValCall && op.Expr.CallAST != nil {
			call := op.Expr.CallAST
			field := onceFieldOfDo(audited, p.TypesInfo, call)
			if field != nil && !field.Exported() && !disqualifiedOnceFields[field] && onceSites[field] == 1 && len(fieldRefIdents[field]) == 1 {
				if ident, ok := call.Fun.(*ast.SelectorExpr).X.(*ast.SelectorExpr).X.(*ast.Ident); ok && p.TypesInfo.Uses[ident] == recvObj {
					if rawLit, isLit := call.Args[0].(*ast.FuncLit); isLit && len(op.Expr.Args) == 1 &&
						op.Expr.Args[0] != nil && op.Expr.Args[0].Kind == flowir.ValMakeClosure && op.Expr.Args[0].Closure != nil {
						doBody := op.Expr.Args[0].Closure
						capturesOther := false
						for fv := range doBody.FreeVars {
							if fv != recvObj {
								capturesOther = true
								break
							}
						}
						if !capturesOther {
							adm := computeOnceDoFieldAdmissions(audited, p, fc, methodDecl, call, rawLit, doBody, recvObj, fieldRefIdents, disqualifiedOnceFields, aliasedInitOnceFields)
							return map[*ast.CallExpr]*onceDoAdmission{call: adm}
						}
					}
				}
			}
		}
		if !opCleanBeforeOnceDo(op, recvObj) {
			return nil
		}
	}
	return nil
}

func opCleanBeforeOnceDo(op *flowir.Op, recvObj types.Object) bool {
	if op == nil || !op.TopLevelInBody || op.Kind != flowir.OpAssign || op.AssignKind == flowir.AssignRange {
		return false
	}
	clean := true
	checkVal := func(v *flowir.Value) {
		if v == nil || !clean {
			return
		}
		v.WalkValues(func(cur *flowir.Value) bool {
			switch cur.Kind {
			case flowir.ValInvalid, flowir.ValCall, flowir.ValChanRecv:
				clean = false
				return false
			case flowir.ValPlace:
				if cur.Place.Obj == recvObj || cur.Place.Root == flowir.RootPkgGlobal {
					clean = false
					return false
				}
			case flowir.ValAddrOf:
				if cur.AddrPlace.Obj == recvObj || cur.AddrPlace.Root == flowir.RootPkgGlobal {
					clean = false
					return false
				}
			case flowir.ValMethodVal:
				if cur.HasRecvPlace && (cur.RecvPlace.Obj == recvObj || cur.RecvPlace.Root == flowir.RootPkgGlobal) {
					clean = false
					return false
				}
			case flowir.ValMakeClosure:
				if rVar, ok := recvObj.(*types.Var); ok && cur.Closure != nil && cur.Closure.FreeVars[rVar] {
					clean = false
					return false
				}
			}
			return true
		})
	}
	op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
		if !dst.IsBareVar() || dst.Root != flowir.RootLocal {
			clean = false
			return false
		}
		checkVal(src)
		return clean
	})
	return clean
}
