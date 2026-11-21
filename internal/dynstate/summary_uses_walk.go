package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type globalBodyWalk struct {
	s                  *globalUseScanner
	b                  *flowir.Body
	descendNested      bool
	allowLocalAddrBind bool
}

func (s *globalUseScanner) walkBody(b *flowir.Body, descendNested bool) {
	if b == nil {
		return
	}
	if len(s.aliasedLocals) > 0 && !s.precomputedDeclAliases {
		savedAliases := s.aliasedLocals
		extended, _ := computeBodyCarrierAliases(s.audited, s.fc, b, carrierAliasConfig{
			parentAliases:  savedAliases,
			carrierVar:     s.dynamicPackageVar,
			skipMethodRecv: s.isExemptMethodRecvCall,
			descendNested:  descendNested,
		})
		s.aliasedLocals = extended
		defer func() { s.aliasedLocals = savedAliases }()
	}
	prevJudgedRange := s.activeJudgedRangeVars
	s.activeJudgedRangeVars = nil
	defer func() { s.activeJudgedRangeVars = prevJudgedRange }()

	w := &globalBodyWalk{
		s:             s,
		b:             b,
		descendNested: descendNested,
	}
	b.ForEachSyncOp(w.walkOp)
}

func (w *globalBodyWalk) markRecvValueEscaped(recv *flowir.Value) {
	if recv == nil {
		return
	}
	walkTransientTargetValues(recv, func(cur *flowir.Value) {
		switch cur.Kind {
		case flowir.ValPlace:
			if cur.Place.Obj != nil && !w.s.activeJudgedRangeVars[cur.Place.Obj] {
				if variable, ok := w.s.dynamicPackageVar(cur.Place.Obj); ok {
					w.s.markEscapedVars([]*types.Var{variable}, cur.Place.RootPos)
				} else {
					w.s.markEscapedVars(w.s.aliasedLocals[cur.Place.Obj].all, cur.Place.RootPos)
				}
			}
		case flowir.ValAddrOf:
			if cur.AddrPlace.Obj != nil && !w.s.activeJudgedRangeVars[cur.AddrPlace.Obj] {
				if variable, ok := w.s.dynamicPackageVar(cur.AddrPlace.Obj); ok {
					w.s.markEscapedVars([]*types.Var{variable}, cur.AddrPlace.RootPos)
				} else {
					w.s.markEscapedVars(w.s.aliasedLocals[cur.AddrPlace.Obj].all, cur.AddrPlace.RootPos)
				}
			}
		}
	})
}

func (w *globalBodyWalk) walkPlaceRead(pl flowir.Place, vt types.Type) {
	pl.ForEachChildValue(func(cv *flowir.Value) bool {
		w.walkValue(cv)
		return true
	})
	if pl.Obj == nil || w.s.activeJudgedRangeVars[pl.Obj] {
		return
	}
	// A 1-hop index read whose element hands out no mutable reach and no
	// sync.noCopy value (such as `m[k]` returning int or func()) is writeless.
	if len(pl.Projs) == 1 && pl.Projs[0].Kind == flowir.ProjIndex && vt != nil &&
		!refconfine.TypeHandsOutMutableReach(vt) &&
		!refconfine.TypeReachesSyncNoCopyByValue(vt) &&
		!syntaxutil.ContainsUintptr(vt) {
		return
	}
	if variable, ok := w.s.dynamicPackageVar(pl.Obj); ok {
		if refconfine.TypeHandsOutDynamicAlias(w.s.audited, variable.Type()) ||
			syntaxutil.ContainsUintptr(vt) {
			w.s.markEscapedVars([]*types.Var{variable}, pl.RootPos)
		}
		return
	}
	entry := w.s.aliasedLocals[pl.Obj]
	vars := entry.root
	if flowir.PlaceEntersInterior(pl, false) || canAliasCarrierType(w.s.audited, vt) || isTypeParamType(vt) {
		vars = entry.all
	}
	w.s.markEscapedVars(vars, pl.RootPos)
}

func (w *globalBodyWalk) walkCallArg(a *flowir.Value) {
	if a != nil && a.Kind == flowir.ValPlace &&
		!refconfine.CallResultHandsOut(a.Type) && !isTypeParamType(a.Type) {
		w.walkPlaceRead(a.Place, a.Type)
		return
	}
	w.walkValue(a)
}

func (w *globalBodyWalk) walkMethodCall(v *flowir.Value) {
	s := w.s
	if !v.IsMethodExprCall && v.Selection != nil && v.Selection.Kind() == types.MethodVal && v.CalleeFunc != nil {
		fn := v.CalleeFunc
		sel := v.CalleeSelector()
		if refconfine.AuditedPooling(s.audited, fn) && v.HasRecvPlace {
			if poolPos, poolVar, isBarePool := poolCarrierPlace(v.RecvPlace); poolVar != nil {
				v.RecvPlace.ForEachChildValue(func(cv *flowir.Value) bool {
					w.walkValue(cv)
					return true
				})
				for _, a := range v.Args {
					w.walkCallArg(a)
				}
				s.dischargePool(poolVar)
				if sel == nil || !s.provenCalls[sel] {
					if _, vOK := s.dynamicPackageVar(poolVar); vOK {
						key := syntaxutil.DynamicVarKey(poolVar)
						if s.sink.methodUses != nil && isBarePool && !syntaxutil.InterfaceReceiver(fn) &&
							refconfine.InstantiatedResultsHandOutNothing(s.audited, v.Selection.Type()) && sel != nil {
							factKey := syntaxutil.MethodFactKey(fn)
							if s.sink.poolMethods != nil {
								if s.sink.poolMethods[key] == nil {
									s.sink.poolMethods[key] = map[syntaxutil.FuncKey]bool{}
								}
								s.sink.poolMethods[key][factKey] = true
							} else if s.sink.poolMutated != nil {
								s.sink.poolMutated[key] = true
							}
							if !s.singleSubject {
								syntaxutil.ExplainDeferralMark(s.hooks, s.p, 'm', key, syntaxutil.DeferralResolvent{
									Method:      factKey,
									EnclosingFn: s.currentDeferFn,
									Literal:     s.currentDeferLit,
								}, sel.Pos())
							}
						} else {
							if sig, sigOK := fn.Type().(*types.Signature); sigOK && sig.Recv() != nil {
								if _, ptr := types.Unalias(sig.Recv().Type()).(*types.Pointer); ptr {
									if !s.singleSubject {
										syntaxutil.ExplainAttributedMark(s.hooks, s.p, "mutation", key, s.currentDeferFn, s.currentDeferLit, poolPos)
									}
									if s.sink.poolMutated != nil {
										s.sink.poolMutated[key] = true
									}
								}
							}
							if refconfine.TypeHandsOutDynamicAlias(s.audited, poolVar.Type()) {
								if !s.singleSubject {
									syntaxutil.ExplainMark(s.hooks, s.p, "escape", key, poolPos)
								}
								if s.sink.poolEscaped != nil {
									s.sink.poolEscaped[key] = true
								}
							}
						}
					}
				}
				return
			}
		}
		if refconfine.DataMemoMethod(s.audited, fn) && v.HasRecvPlace && v.RecvPlace.IsBareVar() && s.dataMemos[v.RecvPlace.Obj] {
			for _, a := range v.Args {
				w.walkValue(a)
			}
			return
		}
		if sel != nil && s.exemptSeamNodes[sel] {
			if !(v.HasRecvPlace && v.RecvPlace.IsBareVar()) {
				w.walkValue(v.Recv)
			}
			for _, a := range v.Args {
				w.walkValue(a)
			}
			return
		}
		if s.sink.methodUses != nil && !syntaxutil.InterfaceReceiver(fn) &&
			refconfine.InstantiatedResultsHandOutNothing(s.audited, v.Selection.Type()) &&
			v.HasRecvPlace && v.RecvPlace.IsBareVar() && sel != nil {
			if variable, vOK := s.dynamicPackageVar(v.RecvPlace.Obj); vOK {
				key := syntaxutil.DynamicVarKey(variable)
				if s.sink.methodUses[key] == nil {
					s.sink.methodUses[key] = map[syntaxutil.FuncKey]bool{}
				}
				factKey := syntaxutil.MethodFactKey(fn)
				s.sink.methodUses[key][factKey] = true
				syntaxutil.ExplainDeferralMark(s.hooks, s.p, 'm', key, syntaxutil.DeferralResolvent{
					Method:      factKey,
					EnclosingFn: s.currentDeferFn,
					Literal:     s.currentDeferLit,
				}, sel.Pos())
				for _, a := range v.Args {
					w.walkCallArg(a)
				}
				return
			}
		}
		if sig, sigOK := fn.Type().(*types.Signature); sigOK && sig.Recv() != nil {
			if _, ptr := types.Unalias(sig.Recv().Type()).(*types.Pointer); ptr {
				s.markPtrRecvMutated(v.Recv, v.AutoAddrRecv)
				w.markRecvValueEscaped(v.Recv)
			}
		}
	}
	w.walkValue(v.Recv)
	for _, a := range v.Args {
		w.walkCallArg(a)
	}
}

func (w *globalBodyWalk) walkValue(v *flowir.Value) {
	if v == nil {
		return
	}
	s := w.s
	switch v.Kind {
	case flowir.ValMakeClosure:
		if w.descendNested && v.Closure != nil {
			s.walkBody(v.Closure, true)
		}
		return

	case flowir.ValPlace:
		w.walkPlaceRead(v.Place, v.Type)
		return

	case flowir.ValAddrOf:
		isDirectLocalBind := w.allowLocalAddrBind
		w.allowLocalAddrBind = false
		v.AddrPlace.ForEachChildValue(func(cv *flowir.Value) bool {
			w.walkValue(cv)
			return true
		})
		if v.Low != nil {
			w.walkValue(v.Low)
		}
		if v.High != nil {
			w.walkValue(v.High)
		}
		if v.Max != nil {
			w.walkValue(v.Max)
		}
		if v.AddrPlace.Obj != nil && !w.s.activeJudgedRangeVars[v.AddrPlace.Obj] {
			if variable, ok := s.dynamicPackageVar(v.AddrPlace.Obj); ok {
				s.markMutatedVars([]*types.Var{variable}, v.AddrPlace.RootPos)
				if !isDirectLocalBind {
					s.markEscapedVars([]*types.Var{variable}, v.AddrPlace.RootPos)
				}
			} else {
				entry := s.aliasedLocals[v.AddrPlace.Obj]
				vars := entry.root
				canAlias := flowir.PlaceEntersInterior(v.AddrPlace, false) || addrOfSubplaceCanAliasCarrier(s.audited, v)
				if canAlias {
					vars = entry.all
				}
				s.markMutatedVars(vars, v.AddrPlace.RootPos)
				if !isDirectLocalBind && canAlias {
					s.markEscapedVars(vars, v.AddrPlace.RootPos)
				}
			}
		} else if v.AddrPlace.Root == flowir.RootTransient && v.AddrPlace.Base != nil {
			vars := collectValueCarrierVars(s.audited, v.AddrPlace.Base, s.dynamicPackageVar, s.aliasedLocals, s.isExemptMethodRecvCall)
			s.markMutatedVars(vars, v.AddrPlace.RootPos)
			if !isDirectLocalBind {
				s.markEscapedVars(vars, v.AddrPlace.RootPos)
			}
		}
		return

	case flowir.ValChanRecv:
		s.markValueMutated(v.Chan, true)
		w.walkValue(v.Chan)
		return

	case flowir.ValCompare:
		for _, side := range []*flowir.Value{v.Left, v.Right} {
			if side == nil {
				continue
			}
			if side.Kind == flowir.ValPlace && len(side.Place.Projs) == 0 &&
				side.Type != nil && !refconfine.TypeReachesSyncNoCopyByValue(side.Type) {
				continue
			}
			w.walkValue(side)
		}
		return

	case flowir.ValMethodVal:
		if v.Method != nil {
			if sig, ok := v.Method.Type().(*types.Signature); ok && sig.Recv() != nil {
				if _, ptr := types.Unalias(sig.Recv().Type()).(*types.Pointer); ptr {
					s.markPtrRecvMutated(v.Recv, v.AutoAddr)
					w.markRecvValueEscaped(v.Recv)
				}
			}
		}
		w.walkValue(v.Recv)
		return

	case flowir.ValCall:
		switch v.CallKind {
		case flowir.CallIIFE:
			for _, a := range v.Args {
				w.walkValue(a)
			}
			if w.descendNested && v.IIFE != nil {
				s.walkBody(v.IIFE, true)
			}
			return

		case flowir.CallBuiltin:
			switch v.BuiltinName {
			case "Sizeof", "Alignof", "Offsetof":
				return
			case "len", "cap":
				for _, a := range v.Args {
					if a != nil && a.Kind == flowir.ValPlace && len(a.Place.Projs) == 0 {
						continue
					}
					w.walkValue(a)
				}
				return
			case "delete", "clear":
				if len(v.Args) > 0 && v.Args[0] != nil {
					s.markValueMutated(v.Args[0], true)
					if v.Args[0].Kind == flowir.ValPlace {
						v.Args[0].Place.ForEachChildValue(func(cv *flowir.Value) bool {
							w.walkValue(cv)
							return true
						})
					} else {
						w.walkValue(v.Args[0])
					}
					for _, a := range v.Args[1:] {
						w.walkValue(a)
					}
					return
				}
			}
			for _, a := range v.Args {
				w.walkValue(a)
			}
			return

		case flowir.CallPlain:
			var deferredArgs map[int]bool
			if s.sink.paramUses != nil && !s.inGoOp && !v.IsMethodExprCall {
				deferredArgs = s.deferCarrierArgs(v, s.sink.paramUses, 'p')
			}
			if v.IsMethodExprCall && v.Recv != nil {
				w.walkValue(v.Recv)
			}
			for i, a := range v.Args {
				if deferredArgs[i] {
					continue
				}
				w.walkCallArg(a)
			}
			return

		case flowir.CallMethod:
			w.walkMethodCall(v)
			return

		case flowir.CallIndirect:
			var deferredArgs map[int]bool
			if s.elemUses != nil && !s.inGoOp && v.Callee != nil && v.Callee.Kind == flowir.ValPlace &&
				len(v.Callee.Place.Projs) == 1 && v.Callee.Place.Projs[0].Kind == flowir.ProjIndex &&
				v.Callee.Place.Obj != nil && v.CalleeSig != nil {
				if owner, ok := s.dynamicPackageVar(v.Callee.Place.Obj); ok {
					ownerKey := syntaxutil.DynamicVarKey(owner)
					for i, arg := range v.Args {
						argPos, variable := s.carrierArgVar(arg)
						if variable == nil {
							continue
						}
						idx := i
						if v.CalleeSig.Variadic() && idx >= v.CalleeSig.Params().Len()-1 {
							idx = v.CalleeSig.Params().Len() - 1
						}
						argKey := syntaxutil.DynamicVarKey(variable)
						want := syntaxutil.ElemParamUse{Key: argKey, Owner: ownerKey, Index: idx}
						if s.elemUses[argKey] == nil {
							s.elemUses[argKey] = map[syntaxutil.ElemParamUse]bool{}
						}
						s.elemUses[argKey][want] = true
						if arg.Raw != nil {
							argPos = arg.Raw.Pos()
						}
						syntaxutil.ExplainDeferralMark(s.hooks, s.p, 'e', argKey, syntaxutil.DeferralResolvent{ElemUse: want}, argPos)
						if deferredArgs == nil {
							deferredArgs = map[int]bool{}
						}
						deferredArgs[i] = true
					}
				}
			}
			w.walkValue(v.Callee)
			for i, a := range v.Args {
				if deferredArgs[i] {
					continue
				}
				w.walkValue(a)
			}
			return
		}
	}

	v.ForEachChildValue(func(ch *flowir.Value) bool {
		w.walkValue(ch)
		return true
	})
}

func (w *globalBodyWalk) walkRangeOp(op *flowir.Op) {
	s := w.s
	for i, dst := range op.Dsts {
		dst.ForEachChildValue(func(cv *flowir.Value) bool {
			w.walkValue(cv)
			return true
		})
		if !(i < len(op.DstDefs) && op.DstDefs[i] && dst.IsBareVar()) {
			s.markPlaceMutated(dst, false)
		}
	}
	var rngSrc *flowir.Value
	if len(op.Srcs) > 0 {
		rngSrc = op.Srcs[0]
	}
	if rngSrc != nil && rngSrc.Type != nil {
		t := rngSrc.Type
		if _, isChan := types.Unalias(t).Underlying().(*types.Chan); isChan {
			s.markValueMutated(rngSrc, true)
			w.walkValue(rngSrc)
			return
		}
		if (!refconfine.RangeBindsAlias(t) && !refconfine.TypeReachesSyncNoCopyByValue(t)) || len(op.Dsts) == 0 {
			if rngSrc.Kind == flowir.ValPlace && len(rngSrc.Place.Projs) == 0 {
				return
			}
			w.walkValue(rngSrc)
			return
		}
		rngStmt, _ := op.StmtAST.(*ast.RangeStmt)
		if rngStmt != nil && rngStmt.Tok == token.DEFINE && op.RangeBody != nil {
			roots := map[types.Object]bool{}
			sound := true
			for i, dst := range op.Dsts {
				if dst.IsBlank() {
					continue
				}
				if !dst.IsBareVar() || dst.Obj == nil || i >= len(op.DstDefs) || !op.DstDefs[i] {
					sound = false
					break
				}
				if refconfine.TypeReachesSyncNoCopyByValue(dst.Obj.Type()) {
					sound = false
					break
				}
				if refconfine.TypeHandsOutMutableReach(dst.Obj.Type()) || syntaxutil.ContainsUintptr(dst.Obj.Type()) {
					roots[dst.Obj] = true
				}
			}
			var wants map[syntaxutil.ParamKey]bool
			var methodWants map[syntaxutil.FuncKey]bool
			var fieldWants map[syntaxutil.FieldPosKey]bool
			var elemWants map[syntaxutil.ElemParamUse]bool
			var returned bool
			var retPtr *bool
			if s.sink.paramUses != nil {
				wants = map[syntaxutil.ParamKey]bool{}
				if s.sink.methodUses != nil {
					methodWants = map[syntaxutil.FuncKey]bool{}
				}
				if s.fieldUses != nil {
					fieldWants = map[syntaxutil.FieldPosKey]bool{}
				}
				if s.elemUses != nil {
					elemWants = map[syntaxutil.ElemParamUse]bool{}
				}
				if s.currentFn != nil && s.currentFn.Recv == nil && s.currentFn.Name != nil &&
					!s.currentFn.Name.IsExported() && s.currentFn.Name.Name != "init" {
					retPtr = &returned
				}
			}
			if sound && (len(roots) == 0 || boundValueLeakFreeJudged(s.audited, s.p, s.fc, roots, rngStmt.Body, wants, retPtr, methodWants, fieldWants, elemWants)) {
				markRangeBoundObjs := func() {
					for _, dst := range op.Dsts {
						if dst.IsBareVar() && dst.Obj != nil && roots[dst.Obj] {
							if s.activeJudgedRangeVars == nil {
								s.activeJudgedRangeVars = map[types.Object]bool{}
							}
							s.activeJudgedRangeVars[dst.Obj] = true
						}
					}
				}
				if len(wants) == 0 && len(methodWants) == 0 && len(fieldWants) == 0 && len(elemWants) == 0 && !returned {
					markRangeBoundObjs()
					if rngSrc.Kind == flowir.ValPlace && len(rngSrc.Place.Projs) == 0 {
						return
					}
					w.walkValue(rngSrc)
					return
				}
				srcVars := collectValueCarrierVars(s.audited, rngSrc, s.dynamicPackageVar, s.aliasedLocals, s.isExemptMethodRecvCall)
				if rngSrc.Kind == flowir.ValPlace && rngSrc.Place.Obj != nil {
					if cv, ok := s.dynamicPackageVar(rngSrc.Place.Obj); ok {
						appendUniqueVars(&srcVars, []*types.Var{cv})
					}
				}
				if len(srcVars) > 0 {
					var rngPos token.Pos
					if rngSrc.Raw != nil {
						rngPos = rngSrc.Raw.Pos()
					}
					keys := make([]string, 0, len(srcVars))
					for _, sv := range srcVars {
						keys = append(keys, syntaxutil.DynamicVarKey(sv))
					}
					for _, key := range keys {
						s.recordConfinementSinkUses(key, wants, methodWants, fieldWants, elemWants, s.currentDeferFn, s.currentDeferLit, rngPos)
					}
					if returned {
						s.pendingReturns = append(s.pendingReturns, pendingReturnDisposition{
							fn:     s.currentFn.Name.Name,
							keys:   keys,
							attrFn: s.currentAttrFn,
							pos:    rngPos,
						})
					}
					markRangeBoundObjs()
					if rngSrc.Kind == flowir.ValPlace && len(rngSrc.Place.Projs) == 0 {
						return
					}
					rngSrc.ForEachChildValue(func(cv *flowir.Value) bool {
						w.walkValue(cv)
						return true
					})
					return
				}
			}
		}
	}
	w.walkValue(rngSrc)
}

func (w *globalBodyWalk) walkOp(op *flowir.Op) bool {
	s := w.s
	switch op.Kind {
	case flowir.OpAssign:
		if op.AssignKind == flowir.AssignRange {
			w.walkRangeOp(op)
			return true
		}
		if op.AssignKind == flowir.AssignZeroDecl {
			return true
		}
		for _, dst := range op.Dsts {
			dst.ForEachChildValue(func(cv *flowir.Value) bool {
				w.walkValue(cv)
				return true
			})
			if dst.Raw != nil && s.exemptSeamNodes[dst.Raw] {
				continue
			}
			if dst.IsBareVar() && syntaxutil.IsLocalVar(dst.Obj) {
				continue
			}
			s.markPlaceMutated(dst, false)
		}
		if op.AssignKind == flowir.AssignIncDec {
			return true
		}
		if op.AssignKind == flowir.AssignCompound {
			for _, src := range op.Srcs {
				if src != nil && src.Kind == flowir.ValCompositeExpr && len(src.Args) == 2 {
					w.walkValue(src.Args[1])
				} else {
					w.walkValue(src)
				}
			}
			return true
		}
		if op.AssignKind == flowir.AssignMulti && len(op.Dsts) == 2 && len(op.Srcs) == 1 && op.Dsts[0].IsBlank() {
			src := op.Srcs[0]
			if src != nil && src.Kind == flowir.ValPlace && len(src.Place.Projs) == 1 && src.Place.Projs[0].Kind == flowir.ProjIndex {
				src.Place.ForEachChildValue(func(cv *flowir.Value) bool {
					w.walkValue(cv)
					return true
				})
				return true
			}
		}
		for i, src := range op.Srcs {
			if op.AssignKind == flowir.AssignPlain && i < len(op.Dsts) &&
				op.Dsts[i].IsBareVar() && (op.Dsts[i].IsBlank() || op.Dsts[i].Root == flowir.RootLocal) &&
				src != nil && src.Kind == flowir.ValAddrOf {
				prevLocalAddr := w.allowLocalAddrBind
				w.allowLocalAddrBind = true
				w.walkValue(src)
				w.allowLocalAddrBind = prevLocalAddr
				continue
			}
			w.walkValue(src)
		}

	case flowir.OpTypeSwitchBind:
		if op.CaseAST == nil {
			w.walkValue(op.SwitchSrc)
		}

	case flowir.OpChanSend:
		op.ChanPlace.ForEachChildValue(func(cv *flowir.Value) bool {
			w.walkValue(cv)
			return true
		})
		s.markPlaceMutated(op.ChanPlace, true)
		if op.ChanPlace.Obj == nil && op.ChanPlace.Root != flowir.RootTransient {
			w.walkValue(op.ChanVal)
		}
		w.walkValue(op.SendVal)

	case flowir.OpReturn:
		for _, r := range op.Results {
			w.walkValue(r)
		}

	case flowir.OpDefer:
		w.walkValue(op.Call)

	case flowir.OpGo:
		if w.descendNested {
			prevGo := s.inGoOp
			s.inGoOp = true
			w.walkValue(op.Call)
			s.inGoOp = prevGo
		}

	case flowir.OpExpr:
		w.walkValue(op.Expr)
	}
	return true
}
