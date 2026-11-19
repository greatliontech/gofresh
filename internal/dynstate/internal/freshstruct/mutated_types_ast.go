package freshstruct

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func (msc *mutatedStructCollector) scanSyntaxFiles() {
	for _, file := range msc.p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil || isUnreachableConstIfBranch(msc.p, msc.idx, n) {
				return false
			}
			if call, ok := n.(*ast.CallExpr); ok {
				cur := ast.Unparen(call.Fun)
				msc.directCallFuns[cur] = true
				switch e := cur.(type) {
				case *ast.IndexExpr:
					cur = ast.Unparen(e.X)
					msc.directCallFuns[cur] = true
				case *ast.IndexListExpr:
					cur = ast.Unparen(e.X)
					msc.directCallFuns[cur] = true
				}
				if sel, isSel := cur.(*ast.SelectorExpr); isSel && sel.Sel != nil {
					msc.directCallFuns[sel.Sel] = true
				}
			}
			if msc.exempted[n] {
				return true
			}
			syncEncl := msc.idx.SyncEnclFuncDecl(n)
			fresh, freshEsc := msc.getFresh(syncEncl)

			switch x := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range x.Lhs {
					msc.recordMutatedSlotWrite(x, lhs, fresh, freshEsc)
					isBlank := false
					if id, isID := ast.Unparen(lhs).(*ast.Ident); isID && id.Name == "_" {
						isBlank = true
					}
					if !isBlank {
						dstT := msc.p.TypesInfo.TypeOf(lhs)
						if msc.typeCrossesAnyOrEfaceUnion(dstT) && !isCurrentPkgPrivateAnyDest(msc.p, lhs, msc.funcParamVars) {
							msc.markCrossesAnyBoundary("non_private_assign_dest", dstT, lhs)
						}
						lhsMentionsRV := typeMentionsReflectValue(dstT)
						if !lhsMentionsRV {
							if ix, isIdx := ast.Unparen(lhs).(*ast.IndexExpr); isIdx {
								lhsMentionsRV = typeMentionsReflectValue(msc.p.TypesInfo.TypeOf(ix.X))
							}
						}
						if lhsMentionsRV && !isCurrentPkgPrivateAnyDest(msc.p, lhs, msc.funcParamVars) {
							msc.sawReflectValueCrossPkgArg = true
						}
						if len(x.Lhs) == len(x.Rhs) && i < len(x.Rhs) {
							msc.recordInterfaceBox(x, syncEncl, dstT, x.Rhs[i], msc.p.TypesInfo.TypeOf(x.Rhs[i]), fresh, freshEsc)
						} else if len(x.Rhs) == 1 {
							if tup, isTup := msc.p.TypesInfo.TypeOf(x.Rhs[0]).(*types.Tuple); isTup && i < tup.Len() {
								msc.recordInterfaceBox(x, syncEncl, dstT, nil, tup.At(i).Type(), fresh, freshEsc)
							}
						}
					}
					if (syncEncl == nil || syncEncl.Name == nil || syncEncl.Name.Name != "init") && syntaxutil.RootPkgScopeVar(msc.p, lhs) != nil {
						if len(x.Lhs) == len(x.Rhs) && i < len(x.Rhs) {
							rhs := x.Rhs[i]
							if !msc.isFreshAddrTarget(syncEncl, rhs, fresh, freshEsc) && !syntaxutil.IsNilIdent(msc.p.TypesInfo, rhs) && !syntaxutil.IsTypedNilSliceConv(msc.p, rhs) {
								msc.recordNamedContainerAt(x, msc.p.TypesInfo.TypeOf(rhs))
							}
						}
					}
				}
			case *ast.ValueSpec:
				for i, nm := range x.Names {
					if nm == nil || nm.Name == "_" {
						continue
					}
					dstT := msc.p.TypesInfo.TypeOf(nm)
					if len(x.Names) == len(x.Values) && i < len(x.Values) {
						msc.recordInterfaceBox(x, syncEncl, dstT, x.Values[i], msc.p.TypesInfo.TypeOf(x.Values[i]), fresh, freshEsc)
					} else if len(x.Values) == 1 {
						if tup, isTup := msc.p.TypesInfo.TypeOf(x.Values[0]).(*types.Tuple); isTup && i < tup.Len() {
							msc.recordInterfaceBox(x, syncEncl, dstT, nil, tup.At(i).Type(), fresh, freshEsc)
						}
					}
				}
			case *ast.ReturnStmt:
				if resTuple := msc.enclosingFuncResultTypes(x); resTuple != nil {
					for i := 0; i < resTuple.Len(); i++ {
						if msc.typeCrossesAnyOrEfaceUnion(resTuple.At(i).Type()) {
							msc.markCrossesAnyBoundary("return_any_type", resTuple.At(i).Type(), x)
						}
					}
					if len(x.Results) == resTuple.Len() {
						for i, r := range x.Results {
							msc.recordInterfaceBox(x, syncEncl, resTuple.At(i).Type(), r, msc.p.TypesInfo.TypeOf(r), fresh, freshEsc)
						}
					} else if len(x.Results) == 1 && resTuple.Len() > 1 {
						if tup, isTup := msc.p.TypesInfo.TypeOf(x.Results[0]).(*types.Tuple); isTup && tup.Len() == resTuple.Len() {
							for i := 0; i < resTuple.Len(); i++ {
								msc.recordInterfaceBox(x, syncEncl, resTuple.At(i).Type(), nil, tup.At(i).Type(), fresh, freshEsc)
							}
						}
					}
				}
			case *ast.SendStmt:
				if ch, isCh := syntaxutil.UnderlyingType(msc.p.TypesInfo.TypeOf(x.Chan)).(*types.Chan); isCh {
					if msc.typeCrossesAnyOrEfaceUnion(ch.Elem()) {
						msc.markCrossesAnyBoundary("chan_send_any", ch.Elem(), x)
					}
					if typeMentionsReflectValue(ch.Elem()) {
						msc.sawReflectValueCrossPkgArg = true
					}
					msc.recordInterfaceBox(x, syncEncl, ch.Elem(), x.Value, msc.p.TypesInfo.TypeOf(x.Value), fresh, freshEsc)
				}
			case *ast.IndexExpr:
				if mp, isMap := syntaxutil.UnderlyingType(msc.p.TypesInfo.TypeOf(x.X)).(*types.Map); isMap {
					msc.recordInterfaceBox(x, syncEncl, mp.Key(), x.Index, msc.p.TypesInfo.TypeOf(x.Index), fresh, freshEsc)
				}
			case *ast.CompositeLit:
				compT := syntaxutil.UnderlyingType(msc.p.TypesInfo.TypeOf(x))
				switch u := compT.(type) {
				case *types.Slice:
					for _, elt := range x.Elts {
						val := elt
						if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
							val = kv.Value
						}
						msc.recordInterfaceBox(x, syncEncl, u.Elem(), val, msc.p.TypesInfo.TypeOf(val), fresh, freshEsc)
					}
				case *types.Array:
					for _, elt := range x.Elts {
						val := elt
						if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
							val = kv.Value
						}
						msc.recordInterfaceBox(x, syncEncl, u.Elem(), val, msc.p.TypesInfo.TypeOf(val), fresh, freshEsc)
					}
				case *types.Map:
					for _, elt := range x.Elts {
						if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
							msc.recordInterfaceBox(x, syncEncl, u.Key(), kv.Key, msc.p.TypesInfo.TypeOf(kv.Key), fresh, freshEsc)
							msc.recordInterfaceBox(x, syncEncl, u.Elem(), kv.Value, msc.p.TypesInfo.TypeOf(kv.Value), fresh, freshEsc)
						}
					}
				case *types.Struct:
					if len(x.Elts) > 0 {
						clT := msc.p.TypesInfo.TypeOf(x)
						if capNamed := msc.foreignReflectTypeCapsuleStruct(syntaxutil.DerefNamedStruct(clT)); capNamed != nil {
							msc.recordStructAt(x, capNamed)
						}
						if capPkg := msc.extractForeignCapsuleWrapperPkg(clT); capPkg != "" {
							msc.recordForeignCapsuleMsgIfaces(clT, capPkg)
						}
					}
					for i, elt := range x.Elts {
						if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
							if kid, isID := ast.Unparen(kv.Key).(*ast.Ident); isID {
								if fld, _ := msc.p.TypesInfo.Uses[kid].(*types.Var); fld != nil {
									msc.recordInterfaceBox(x, syncEncl, fld.Type(), kv.Value, msc.p.TypesInfo.TypeOf(kv.Value), fresh, freshEsc)
								}
							}
						} else if i < u.NumFields() {
							msc.recordInterfaceBox(x, syncEncl, u.Field(i).Type(), elt, msc.p.TypesInfo.TypeOf(elt), fresh, freshEsc)
						}
					}
				}
			case *ast.IncDecStmt:
				msc.recordMutatedSlotWrite(x, x.X, fresh, freshEsc)
			case *ast.TypeAssertExpr:
				if x.Type != nil {
					taT := msc.p.TypesInfo.TypeOf(x.Type)
					msc.recordInterfaceBox(x, syncEncl, taT, x.X, msc.p.TypesInfo.TypeOf(x.X), fresh, freshEsc)
					if !isEmptyInterfaceType(taT) {
						msc.recordBoundaryResultOrRecvChanType(taT)
					}
				}
			case *ast.TypeSwitchStmt:
				var swSrc ast.Expr
				switch asg := x.Assign.(type) {
				case *ast.AssignStmt:
					if len(asg.Rhs) == 1 {
						if ta, isTA := ast.Unparen(asg.Rhs[0]).(*ast.TypeAssertExpr); isTA && ta.Type == nil {
							swSrc = ta.X
						}
					}
				case *ast.ExprStmt:
					if ta, isTA := ast.Unparen(asg.X).(*ast.TypeAssertExpr); isTA && ta.Type == nil {
						swSrc = ta.X
					}
				}
				if swSrc != nil && x.Body != nil {
					swSrcT := msc.p.TypesInfo.TypeOf(swSrc)
					for _, st := range x.Body.List {
						if cc, isCC := st.(*ast.CaseClause); isCC {
							for _, ctExpr := range cc.List {
								ctT := msc.p.TypesInfo.TypeOf(ctExpr)
								msc.recordInterfaceBox(cc, syncEncl, ctT, swSrc, swSrcT, fresh, freshEsc)
								if !isEmptyInterfaceType(ctT) {
									msc.recordBoundaryResultOrRecvChanType(ctT)
								}
							}
						}
					}
				}
			case *ast.RangeStmt:
				rxT := msc.p.TypesInfo.TypeOf(x.X)
				if ch, isCh := syntaxutil.UnderlyingType(rxT).(*types.Chan); isCh {
					msc.recordBoundaryResultOrRecvChanType(ch.Elem())
				}
				if x.Tok == token.ASSIGN {
					rKeyT, rValT := rangeKeyValueTypes(rxT)
					rElemTypes := [2]types.Type{rKeyT, rValT}
					for ri, re := range [2]ast.Expr{x.Key, x.Value} {
						if re == nil {
							continue
						}
						msc.recordMutatedSlotWrite(x, re, fresh, freshEsc)
						if id, isID := ast.Unparen(re).(*ast.Ident); isID && id.Name == "_" {
							continue
						}
						reT := msc.p.TypesInfo.TypeOf(re)
						if !isCurrentPkgPrivateAnyDest(msc.p, re, msc.funcParamVars) {
							msc.recordBoundaryParamType(reT)
						}
						msc.recordInterfaceBox(x, syncEncl, reT, nil, rElemTypes[ri], fresh, freshEsc)
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.ARROW {
					msc.recordBoundaryResultOrRecvChanType(msc.p.TypesInfo.TypeOf(x))
				}
				if x.Op == token.AND && !msc.isFreshAddrTarget(syncEncl, x.X, fresh, freshEsc) {
					inner := ast.Unparen(x.X)
					switch in := inner.(type) {
					case *ast.SelectorExpr:
						if selInfo := msc.p.TypesInfo.Selections[in]; selInfo != nil && selInfo.Kind() == types.FieldVal {
							_, isFieldPtr := types.Unalias(selInfo.Type()).(*types.Pointer)
							_, _, subSt, isSubStruct := syntaxutil.TypeRefOfStructFull(selInfo.Type())
							if !(!isFieldPtr && isSubStruct && subSt.NumFields() > 0 && !selInfo.Obj().Exported()) && !refconfine.IsPureAtomicLoadArg(msc.p, msc.idx, x) {
								msc.recordMutatedExpr(x, in, fresh, freshEsc)
							}
						}
					case *ast.IndexExpr:
						elemT := msc.p.TypesInfo.TypeOf(in)
						_, isElemPtr := types.Unalias(elemT).(*types.Pointer)
						_, _, elemSt, isElemStruct := syntaxutil.TypeRefOfStructFull(elemT)
						if !(!isElemPtr && isElemStruct && elemSt.NumFields() > 0) {
							msc.recordMutatedExpr(x, in, fresh, freshEsc)
						}
					}
				}
			case *ast.CallExpr:
				if tv := msc.p.TypesInfo.Types[x.Fun]; tv.IsType() && len(x.Args) == 1 {
					dstT := types.Unalias(tv.Type)
					srcT := types.Unalias(msc.p.TypesInfo.TypeOf(x.Args[0]))
					msc.recordInterfaceBox(x, syncEncl, dstT, x.Args[0], srcT, fresh, freshEsc)
					if _, isSrcNamed := srcT.(*types.Named); isSrcNamed && !types.Identical(dstT, srcT) &&
						!msc.isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) && !syntaxutil.IsNilIdent(msc.p.TypesInfo, x.Args[0]) && !syntaxutil.IsTypedNilSliceConv(msc.p, x.Args[0]) {
						msc.recordNamedContainerAt(x, srcT)
					}
					if syntaxutil.IsUnsafePointerType(dstT) {
						if basic, isB := syntaxutil.UnderlyingType(srcT).(*types.Basic); isB && basic.Kind() == types.Uintptr {
							tvArg := msc.p.TypesInfo.Types[x.Args[0]]
							isConstZero := tvArg.Value != nil && tvArg.Value.Kind() == constant.Int && constant.Sign(tvArg.Value) == 0
							if !isConstZero && !msc.safeRawUintptrConvs[x] {
								msc.sawRawUintptrToUnsafePtr = true
								msc.sawUnsafeIfaceHeaderBypass = true
								msc.sawReflectValueOfAny = true
								msc.sawReflectMutOrEscape = true
								msc.reflectedIfaceSets[syntaxutil.ReflectFlagROBypassAnyKey] = true
								msc.reflectedIfaceSets[syntaxutil.ReflectFlagROLocalBypassKey] = true
								msc.reflectedIfaceSets[syntaxutil.ReflectRawUintptrToPtrKey] = true
							}
						} else if !msc.safeEfaceUnsafePtrConvs[x] && !refconfine.IsSafeAtomicPointerValueArg(msc.p, msc.idx, x) && !refconfine.IsPureAtomicLoadInnerConv(msc.p, msc.idx, x) && !msc.isFreshReflectOrBoxTarget(syncEncl, x.Args[0], fresh, freshEsc) {
							if ptr, isPtr := syntaxutil.UnderlyingType(msc.p.TypesInfo.TypeOf(x.Args[0])).(*types.Pointer); isPtr {
								if refconfine.IsAtomicPointerSlotTargetInnerConv(msc.p, msc.idx, x) {
									syntaxutil.ForEachValueContainedStructType(ptr.Elem(), func(vt types.Type) {
										msc.recordStructAt(x, vt)
									})
								} else {
									msc.recordUnsafeTargetElem(x, ptr.Elem())
								}
							}
						}
					} else if dstPtr, isDstPtr := dstT.Underlying().(*types.Pointer); isDstPtr {
						if srcPtr, isSrcPtr := syntaxutil.UnderlyingType(msc.p.TypesInfo.TypeOf(x.Args[0])).(*types.Pointer); isSrcPtr {
							dstElem := types.Unalias(dstPtr.Elem())
							srcElem := types.Unalias(srcPtr.Elem())
							if !types.Identical(dstElem, srcElem) && !msc.isFreshReflectOrBoxTarget(syncEncl, x.Args[0], fresh, freshEsc) {
								if _, isSt := srcElem.Underlying().(*types.Struct); isSt {
									syntaxutil.ForEachValueContainedStructType(srcElem, func(vt types.Type) {
										msc.recordStructAt(x, vt)
									})
								}
							}
						}
					}
					return true
				}
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID {
					if b, isB := msc.p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "delete", "clear", "copy", "append":
							if len(x.Args) > 0 {
								arg0Expr := x.Args[0]
								arg0T := msc.p.TypesInfo.TypeOf(x.Args[0])
								var argTup *types.Tuple
								if len(x.Args) == 1 {
									if tup, isTup := arg0T.(*types.Tuple); isTup && tup.Len() > 0 {
										argTup = tup
										arg0Expr = nil
										arg0T = tup.At(0).Type()
									}
								}
								if arg0Expr != nil {
									msc.recordMutatedExpr(x, arg0Expr, fresh, freshEsc)
								}
								if (b.Name() == "copy" || b.Name() == "append") && !isCurrentPkgPrivateSliceMutDest(msc.p, arg0Expr, msc.funcParamVars) {
									msc.recordBoundaryParamType(arg0T)
								}
								if arg0Expr == nil || (!msc.isFreshAddrTarget(syncEncl, arg0Expr, fresh, freshEsc) && !syntaxutil.IsNilIdent(msc.p.TypesInfo, arg0Expr) && !syntaxutil.IsTypedNilSliceConv(msc.p, arg0Expr)) {
									msc.recordNamedContainerAt(x, arg0T)
								}
								if (b.Name() == "clear" || b.Name() == "copy" || b.Name() == "append") && (arg0Expr == nil || !msc.isFreshAddrTarget(syncEncl, arg0Expr, fresh, freshEsc)) {
									if sl, isSl := syntaxutil.UnderlyingType(arg0T).(*types.Slice); isSl {
										syntaxutil.ForEachValueContainedStructType(sl.Elem(), func(vt types.Type) {
											msc.recordStructAt(x, vt)
										})
									}
								}
								if b.Name() == "append" && !x.Ellipsis.IsValid() {
									if sl, isSl := syntaxutil.UnderlyingType(arg0T).(*types.Slice); isSl {
										if argTup != nil {
											for ti := 1; ti < argTup.Len(); ti++ {
												msc.recordInterfaceBox(x, syncEncl, sl.Elem(), nil, argTup.At(ti).Type(), fresh, freshEsc)
											}
										} else {
											for _, elemArg := range x.Args[1:] {
												msc.recordInterfaceBox(x, syncEncl, sl.Elem(), elemArg, msc.p.TypesInfo.TypeOf(elemArg), fresh, freshEsc)
											}
										}
									}
								}
							}
						case "SliceData":
							if len(x.Args) > 0 && !msc.isFreshReflectOrBoxTarget(syncEncl, x.Args[0], fresh, freshEsc) && !syntaxutil.IsNilIdent(msc.p.TypesInfo, x.Args[0]) && !syntaxutil.IsTypedNilSliceConv(msc.p, x.Args[0]) {
								msc.recordNamedContainerAt(x, msc.p.TypesInfo.TypeOf(x.Args[0]))
								if sl, isSl := syntaxutil.UnderlyingType(msc.p.TypesInfo.TypeOf(x.Args[0])).(*types.Slice); isSl {
									msc.recordUnsafeTargetElem(x, sl.Elem())
								}
							}
						case "Slice":
							if len(x.Args) > 0 {
								msc.recordUnsafeSliceArg(x, x.Args[0])
							}
						case "panic":
							if len(x.Args) != 1 {
								msc.sawCarrierPanic = true
								msc.markCrossesAnyBoundary("panic_non_scalar", nil, x)
							} else {
								argT := msc.p.TypesInfo.TypeOf(x.Args[0])
								basic, isBasic := syntaxutil.UnderlyingType(argT).(*types.Basic)
								if !isBasic || basic.Kind() == types.UnsafePointer || basic.Kind() == types.Uintptr {
									msc.sawCarrierPanic = true
									msc.markCrossesAnyBoundary("panic_non_scalar", argT, x)
									if typeMentionsReflectValue(argT) {
										msc.sawReflectValueCrossPkgArg = true
									}
									msc.recordInterfaceBox(x, syncEncl, types.NewInterfaceType(nil, nil), x.Args[0], argT, fresh, freshEsc)
								}
							}
						}
						return true
					}
				} else if sel, isSel := ast.Unparen(x.Fun).(*ast.SelectorExpr); isSel {
					if b, isB := msc.p.TypesInfo.Uses[sel.Sel].(*types.Builtin); isB && len(x.Args) > 0 {
						switch b.Name() {
						case "Slice":
							msc.recordUnsafeSliceArg(x, x.Args[0])
							return true
						case "SliceData":
							if !msc.isFreshReflectOrBoxTarget(syncEncl, x.Args[0], fresh, freshEsc) && !syntaxutil.IsNilIdent(msc.p.TypesInfo, x.Args[0]) && !syntaxutil.IsTypedNilSliceConv(msc.p, x.Args[0]) {
								msc.recordNamedContainerAt(x, msc.p.TypesInfo.TypeOf(x.Args[0]))
								if sl, isSl := syntaxutil.UnderlyingType(msc.p.TypesInfo.TypeOf(x.Args[0])).(*types.Slice); isSl {
									msc.recordUnsafeTargetElem(x, sl.Elem())
								}
							}
							return true
						}
					}
				}
				if callee := syntaxutil.ResolveCalledFuncObj(msc.p, x.Fun); callee != nil {
					if recvSt := msc.unexportedForeignRecvStruct(callee); recvSt != nil {
						if sel, isSel := ast.Unparen(x.Fun).(*ast.SelectorExpr); isSel {
							if selInfo := msc.p.TypesInfo.Selections[sel]; selInfo != nil {
								switch selInfo.Kind() {
								case types.MethodVal:
									if !msc.isFreshAddrTarget(syncEncl, sel.X, fresh, freshEsc) {
										msc.recordStructAt(x, recvSt)
										msc.recordMutatedExpr(x, sel.X, fresh, freshEsc)
									}
								case types.MethodExpr:
									if len(x.Args) == 0 || !msc.isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) {
										msc.recordStructAt(x, recvSt)
										if len(x.Args) > 0 {
											msc.recordMutatedExpr(x, x.Args[0], fresh, freshEsc)
										}
									}
								}
							}
						}
					}
					isTrueStdCallee := msc.isTrueStdPkg(callee.Pkg())
					origSig, _ := callee.Type().(*types.Signature)
					isDynamicIfaceCall := origSig != nil && origSig.Recv() != nil && isRuntimeInterfaceType(origSig.Recv().Type())
					isForeignNonStdCallee := callee.Pkg() != nil && callee.Pkg() != msc.p.Types && !isTrueStdCallee
					if isDynamicIfaceCall || isForeignNonStdCallee {
						if origSig != nil && origSig.Recv() != nil {
							msc.recordBoundaryParamType(origSig.Recv().Type())
						}
						if sel, isSel := ast.Unparen(x.Fun).(*ast.SelectorExpr); isSel {
							if sInfo := msc.p.TypesInfo.Selections[sel]; sInfo != nil && sInfo.Kind() == types.MethodVal &&
								typeMentionsReflectValue(msc.p.TypesInfo.TypeOf(sel.X)) {
								msc.sawReflectValueCrossPkgArg = true
							}
						}
						for _, a := range x.Args {
							if typeMentionsReflectValue(msc.p.TypesInfo.TypeOf(a)) {
								msc.sawReflectValueCrossPkgArg = true
								break
							}
						}
						if callSig, okCS := syntaxutil.UnderlyingType(msc.p.TypesInfo.TypeOf(x.Fun)).(*types.Signature); okCS {
							for pi := 0; pi < callSig.Params().Len(); pi++ {
								pt := callSig.Params().At(pi).Type()
								if callSig.Variadic() && pi == callSig.Params().Len()-1 && !x.Ellipsis.IsValid() {
									if sl, isSl := types.Unalias(pt).Underlying().(*types.Slice); isSl {
										pt = sl.Elem()
									}
								}
								if !isEmptyInterfaceType(pt) {
									msc.recordBoundaryParamType(pt)
								}
							}
							for ri := 0; ri < callSig.Results().Len(); ri++ {
								msc.recordBoundaryResultOrRecvChanType(callSig.Results().At(ri).Type())
							}
						}
					}
					if isTrueStdCallee && callee.Pkg().Path() == "reflect" && callee.Name() == "ValueOf" && len(x.Args) == 1 {
						if !syntaxutil.IsNilIdent(msc.p.TypesInfo, x.Args[0]) {
							if argT := msc.p.TypesInfo.TypeOf(x.Args[0]); argT != nil && !types.IsInterface(argT) {
								msc.inspectBoxedConcreteMethodCapabilities(argT)
							}
						}
						if !msc.isFreshReflectOrBoxTarget(syncEncl, x.Args[0], fresh, freshEsc) {
							argT := msc.p.TypesInfo.TypeOf(x.Args[0])
							if typeMentionsEmptyInterfaceWith(argT, true) || syntaxutil.ContainsUnsafePointer(argT) {
								msc.sawReflectValueOfAny = true
							}
							msc.recordReflectedNonEmptyIface(syncEncl, argT)
							msc.recordDirectReflectiveArgTypes(x, argT)
						}
					} else {
						if origSig != nil && origSig.Recv() != nil {
							isIfaceRecv := types.IsInterface(origSig.Recv().Type())
							recvSt := msc.unexportedForeignRecvStruct(callee)
							if isIfaceRecv || recvSt != nil {
								for pi := 0; pi < origSig.Params().Len(); pi++ {
									capNamed := msc.foreignReflectTypeCapsulePtrElem(origSig.Params().At(pi).Type())
									if capNamed == nil {
										continue
									}
									if isIfaceRecv || (recvSt != nil && recvSt.Obj().Pkg() == capNamed.Obj().Pkg() &&
										!isVerifiedForeignCapsuleSetterCall(msc.p, msc.idx, msc.clusterMsgGoTypes, x, capNamed, recvSt)) {
										msc.recordStructAt(x, capNamed)
									}
								}
							}
						}
						if callee.Pkg() != nil && callee.Pkg() != msc.p.Types && !isTrueStdCallee && origSig != nil && origSig.Recv() != nil &&
							msc.typeCrossesAnyOrEfaceUnion(origSig.Recv().Type()) {
							msc.markCrossesAnyBoundary("foreign_recv_any", origSig.Recv().Type(), x)
						}
						isAtomicPointerMethod := isTrueStdCallee && callee.Pkg().Path() == "sync/atomic" && syntaxutil.MethodRecvNamedTypeName(callee) == "Pointer"
						isGeneric := !isAtomicPointerMethod && origSig != nil && (origSig.TypeParams().Len() > 0 || origSig.RecvTypeParams().Len() > 0)
						isCmp := isTrueStdCallee && callee.Pkg().Path() == "cmp"
						isMethodExpr := false
						var matchedCtxKey *types.Named
						var ctxIfaceKey string
						isConfinedSyncMapCall := false
						isConfinedSyncPoolCall := false
						isConfinedContextWithValue := false
						if isTrueStdCallee && callee.Pkg().Path() == "context" && callee.Name() == "WithValue" && len(x.Args) == 3 && !x.Ellipsis.IsValid() {
							if keyNamed, isKN := types.Unalias(msc.p.TypesInfo.TypeOf(x.Args[1])).(*types.Named); isKN && msc.confinedContextKeys[keyNamed] {
								isConfinedContextWithValue = true
								matchedCtxKey = keyNamed
								if ctxIf, isCIf := syntaxutil.UnderlyingType(msc.p.TypesInfo.TypeOf(x.Args[0])).(*types.Interface); isCIf {
									ctxIfaceKey = syntaxutil.IfaceMethodSetKey(ctxIf)
								}
							}
						}
						if sel, isSel := ast.Unparen(x.Fun).(*ast.SelectorExpr); isSel {
							if isTrueStdCallee && callee.Pkg().Path() == "sync" {
								if recvID, isID := ast.Unparen(sel.X).(*ast.Ident); isID {
									if rv, _ := msc.p.TypesInfo.Uses[recvID].(*types.Var); rv != nil {
										if msc.confinedSyncMaps[rv] {
											isConfinedSyncMapCall = true
										} else if msc.confinedSyncPools[rv] {
											isConfinedSyncPoolCall = true
										}
									}
								} else if recvSel, isRS := ast.Unparen(sel.X).(*ast.SelectorExpr); isRS {
									if fInfo := msc.p.TypesInfo.Selections[recvSel]; fInfo != nil && fInfo.Kind() == types.FieldVal {
										if fv, _ := fInfo.Obj().(*types.Var); fv != nil && msc.confinedSyncMapFields[fv] {
											isConfinedSyncMapCall = true
										}
									}
								}
							}
							if selInfo := msc.p.TypesInfo.Selections[sel]; selInfo != nil {
								switch selInfo.Kind() {
								case types.MethodVal:
									if isAtomicPointerMethod && callee.Name() != "Load" && !msc.isFreshAddrTarget(syncEncl, sel.X, fresh, freshEsc) {
										msc.recordMutatedExpr(x, sel.X, fresh, freshEsc)
									}
									if isGeneric && origSig != nil && origSig.RecvTypeParams().Len() > 0 && (!isTrueStdCallee || !msc.isFreshAddrTarget(syncEncl, sel.X, fresh, freshEsc)) {
										if isTrueStdCallee {
											msc.recordGenericArgTypes(x, msc.p.TypesInfo.TypeOf(sel.X))
										} else {
											msc.recordNonStdGenericTypeUse(x, syncEncl, msc.p.TypesInfo.TypeOf(sel.X), isForeignNonStdCallee)
										}
									}
								case types.MethodExpr:
									isMethodExpr = true
									if isAtomicPointerMethod && callee.Name() != "Load" && len(x.Args) > 0 && !msc.isFreshAddrTarget(syncEncl, x.Args[0], fresh, freshEsc) {
										msc.recordMutatedExpr(x, x.Args[0], fresh, freshEsc)
									}
								}
							}
						}
						if sig, okSig := syntaxutil.UnderlyingType(msc.p.TypesInfo.TypeOf(x.Fun)).(*types.Signature); okSig {
							if isGeneric && origSig != nil {
								for ri := 0; ri < sig.Results().Len() && ri < origSig.Results().Len(); ri++ {
									resT := sig.Results().At(ri).Type()
									if isCmp && !types.IsInterface(resT) {
										continue
									}
									if syntaxutil.TypeMentionsTypeParam(origSig.Results().At(ri).Type()) {
										if isTrueStdCallee {
											msc.recordGenericArgTypes(x, resT)
										} else {
											msc.recordNonStdGenericTypeUse(x, syncEncl, resT, isForeignNonStdCallee)
										}
									}
								}
							}
							type argEntry struct {
								expr ast.Expr
								typ  types.Type
							}
							var argEntries []argEntry
							if len(x.Args) == 1 {
								if tup, isTup := msc.p.TypesInfo.TypeOf(x.Args[0]).(*types.Tuple); isTup {
									for ti := 0; ti < tup.Len(); ti++ {
										argEntries = append(argEntries, argEntry{typ: tup.At(ti).Type()})
									}
								}
							}
							if argEntries == nil {
								for _, arg := range x.Args {
									argEntries = append(argEntries, argEntry{expr: arg, typ: msc.p.TypesInfo.TypeOf(arg)})
								}
							}
							for ai, ae := range argEntries {
								pi := ai
								if sig.Variadic() && ai >= sig.Params().Len()-1 {
									pi = sig.Params().Len() - 1
								}
								if pi < sig.Params().Len() {
									pt := types.Unalias(sig.Params().At(pi).Type())
									if sig.Variadic() && ai >= sig.Params().Len()-1 && !x.Ellipsis.IsValid() {
										if sl, isSl := pt.Underlying().(*types.Slice); isSl {
											pt = types.Unalias(sl.Elem())
										}
									}
									if isGeneric && origSig != nil && !(isCmp && !types.IsInterface(pt)) &&
										!(isMethodExpr && ai == 0) &&
										(!isTrueStdCallee || ae.expr == nil || !msc.isFreshAddrTarget(syncEncl, ae.expr, fresh, freshEsc)) {
										origAI := ai
										origPI := pi
										if isMethodExpr {
											origAI = ai - 1
											origPI = pi - 1
										}
										if origPI >= 0 && origPI < origSig.Params().Len() {
											origPT := types.Unalias(origSig.Params().At(origPI).Type())
											if origSig.Variadic() && origAI >= origSig.Params().Len()-1 && !x.Ellipsis.IsValid() {
												if sl, isSl := origPT.Underlying().(*types.Slice); isSl {
													origPT = types.Unalias(sl.Elem())
												}
											}
											if syntaxutil.TypeMentionsTypeParam(origPT) {
												if isTrueStdCallee {
													msc.recordGenericArgTypes(x, ae.typ)
												} else {
													if !(ae.expr != nil && syntaxutil.IsNilIdent(msc.p.TypesInfo, ae.expr)) &&
														ae.typ != nil && !types.IsInterface(ae.typ) {
														msc.inspectBoxedConcreteMethodCapabilities(ae.typ)
													}
													if ae.expr == nil || (!msc.isTypedNilOrNilExpr(ae.expr) && !msc.isFreshReflectOrBoxTarget(syncEncl, ae.expr, fresh, freshEsc)) {
														msc.recordNonStdGenericTypeUse(x, syncEncl, ae.typ, isForeignNonStdCallee)
													}
												}
												continue
											}
										}
									}
									if ae.expr != nil && (msc.isTypedNilOrNilExpr(ae.expr) || msc.isFreshReflectOrBoxTarget(syncEncl, ae.expr, fresh, freshEsc)) {
										if !syntaxutil.IsNilIdent(msc.p.TypesInfo, ae.expr) &&
											ae.typ != nil && !types.IsInterface(ae.typ) && types.IsInterface(pt) &&
											(!syntaxutil.IsReadOnlyEmptyInterfaceCallee(msc.p, callee) || callMayWrapErrorOperand(msc.p, x, callee, ai, ae.typ)) &&
											!(isTrueStdCallee && callee.Pkg().Path() == "sort" && ai == 0 && len(x.Args) == 2 && !x.Ellipsis.IsValid() &&
												(callee.Name() == "Slice" || callee.Name() == "SliceStable" || callee.Name() == "SliceIsSorted")) {
											msc.inspectBoxedConcreteMethodCapabilities(ae.typ)
										}
										continue
									}
									if iface, isIf := pt.Underlying().(*types.Interface); isIf {
										if iface.NumMethods() == 0 {
											if isConfinedSyncMapCall || isConfinedSyncPoolCall || isConfinedContextWithValue {
												isStoredValArg := (isConfinedSyncMapCall && ai == 1 && (callee.Name() == "Store" || callee.Name() == "LoadOrStore")) ||
													(isConfinedSyncPoolCall && ai == 0 && callee.Name() == "Put") ||
													(isConfinedContextWithValue && ai == 2)
												if isStoredValArg && ae.typ != nil {
													if !types.IsInterface(ae.typ) {
														msc.recordPendingNonEmptyIfaceBox(x, syncEncl, ae.typ)
														if isConfinedContextWithValue {
															hasValUnsafePtr := syntaxutil.ContainsUnsafePointer(ae.typ)
															if ctxIfaceKey != "" {
																ctxFlagRO := syntaxutil.ReflectFlagROBypassPrefix + ctxIfaceKey
																if hasValUnsafePtr || typeMentionsEmptyInterfaceWith(ae.typ, true) {
																	msc.unsafePtrCarrierBoxes[unsafeCarrierBoxKey{boxKey: ctxFlagRO}] = true
																}
																msc.recordEscapedArgTypesWithSink(x, ae.typ, true, false, func(node ast.Node, vt types.Type, crossedForeignPkg string) {
																	if ref, ok := msc.resolveStructAt(node, vt); ok {
																		msc.recordPendingBoxedEntry(ref, ctxFlagRO, crossedForeignPkg)
																	}
																})
																fam := msc.exemptFamilyByFunc[syncEncl]
																forEachNestedNonEmptyIface(ae.typ, false, msc.exemptReadFields, msc.foreignReflectFields, fam, func(nif *types.Interface) {
																	if k := syntaxutil.IfaceMethodSetKey(nif); k != "" {
																		msc.ctxBoxedExported[ctxBoxedIfaceKey{ctxKey: ctxIfaceKey, methodSet: k}] = true
																		msc.ctxBoxedAll[ctxBoxedIfaceKey{ctxKey: ctxIfaceKey, methodSet: k}] = true
																	}
																})
																forEachNestedNonEmptyIface(ae.typ, true, msc.exemptReadFields, msc.foreignReflectFields, fam, func(nif *types.Interface) {
																	if k := syntaxutil.IfaceMethodSetKey(nif); k != "" {
																		msc.ctxBoxedAll[ctxBoxedIfaceKey{ctxKey: ctxIfaceKey, methodSet: k}] = true
																	}
																})
															}
															if matchedCtxKey != nil && msc.confinedContextLookups[matchedCtxKey] {
																if hasValUnsafePtr || typeMentionsEmptyInterfaceWith(ae.typ, true) {
																	msc.unsafePtrCarrierBoxes[unsafeCarrierBoxKey{boxKey: syntaxutil.ContextKeyTheftFlagROKey}] = true
																}
																fam := msc.exemptFamilyByFunc[syncEncl]
																forEachNestedNonEmptyIface(ae.typ, false, msc.exemptReadFields, msc.foreignReflectFields, fam, func(nif *types.Interface) {
																	if k := syntaxutil.IfaceMethodSetKey(nif); k != "" {
																		msc.ctxBoxedExported[ctxBoxedIfaceKey{ctxKey: syntaxutil.ContextKeyTheftMethodSetKey, methodSet: k}] = true
																		msc.ctxBoxedAll[ctxBoxedIfaceKey{ctxKey: syntaxutil.ContextKeyTheftMethodSetKey, methodSet: k}] = true
																	}
																})
																forEachNestedNonEmptyIface(ae.typ, true, msc.exemptReadFields, msc.foreignReflectFields, fam, func(nif *types.Interface) {
																	if k := syntaxutil.IfaceMethodSetKey(nif); k != "" {
																		msc.ctxBoxedAll[ctxBoxedIfaceKey{ctxKey: syntaxutil.ContextKeyTheftMethodSetKey, methodSet: k}] = true
																	}
																})
																msc.recordEscapedArgTypesWithSink(x, ae.typ, false, false, func(node ast.Node, vt types.Type, crossedForeignPkg string) {
																	if ref, ok := msc.resolveStructAt(node, vt); ok {
																		msc.recordPendingBoxedEntry(ref, syntaxutil.ContextKeyTheftMethodSetKey, crossedForeignPkg)
																	}
																})
																msc.recordEscapedArgTypesWithSink(x, ae.typ, true, false, func(node ast.Node, vt types.Type, crossedForeignPkg string) {
																	if ref, ok := msc.resolveStructAt(node, vt); ok {
																		msc.recordPendingBoxedEntry(ref, syntaxutil.ContextKeyTheftFlagROKey, crossedForeignPkg)
																	}
																})
															}
														}
													} else if isConfinedContextWithValue {
														if srcIf, isSIf := syntaxutil.UnderlyingType(ae.typ).(*types.Interface); isSIf && !syntaxutil.IsNamedInPkg(ae.typ, "reflect", "Type") {
															if k := syntaxutil.IfaceMethodSetKey(srcIf); k != "" {
																if ctxIfaceKey != "" {
																	msc.ctxBoxedExported[ctxBoxedIfaceKey{ctxKey: ctxIfaceKey, methodSet: k}] = true
																	msc.ctxBoxedAll[ctxBoxedIfaceKey{ctxKey: ctxIfaceKey, methodSet: k}] = true
																}
																if matchedCtxKey != nil && msc.confinedContextLookups[matchedCtxKey] {
																	msc.ctxBoxedExported[ctxBoxedIfaceKey{ctxKey: syntaxutil.ContextKeyTheftMethodSetKey, methodSet: k}] = true
																	msc.ctxBoxedAll[ctxBoxedIfaceKey{ctxKey: syntaxutil.ContextKeyTheftMethodSetKey, methodSet: k}] = true
																}
															}
															if matchedCtxKey != nil && msc.mismatchedContextIfaceKeys[matchedCtxKey] {
																msc.recordInterfaceBox(x, syncEncl, pt, ae.expr, ae.typ, fresh, freshEsc)
															}
														}
													}
												}
											} else if isTrueStdCallee && callee.Pkg().Path() == "sort" && ai == 0 && len(x.Args) == 2 && !x.Ellipsis.IsValid() &&
												(callee.Name() == "Slice" || callee.Name() == "SliceStable" || callee.Name() == "SliceIsSorted") {
												if callee.Name() != "SliceIsSorted" && ae.expr != nil && !msc.isFreshAddrTarget(syncEncl, ae.expr, fresh, freshEsc) {
													msc.recordNamedContainerAt(x, ae.typ)
													if sl, isSl := syntaxutil.UnderlyingType(ae.typ).(*types.Slice); isSl {
														syntaxutil.ForEachValueContainedStructType(sl.Elem(), func(vt types.Type) {
															msc.recordStructAt(x, vt)
														})
													}
												}
											} else if syntaxutil.IsReadOnlyEmptyInterfaceCallee(msc.p, callee) {
												if ae.typ != nil && callMayWrapErrorOperand(msc.p, x, callee, ai, ae.typ) {
													if errObj := types.Universe.Lookup("error"); errObj != nil {
														msc.recordInterfaceBox(x, syncEncl, errObj.Type(), ae.expr, ae.typ, fresh, freshEsc)
													}
												}
												if ae.typ != nil && callMayFormatPointerIdentity(msc.p, x, callee, ai, ae.typ) {
													msc.markCrossesAnyBoundary("fmt_pointer_identity", ae.typ, x)
													if typeMentionsEmptyInterfaceWith(ae.typ, true) {
														msc.sawFmtPointerIdentityOnAny = true
													}
													if !isEmptyInterfaceType(ae.typ) {
														fam := msc.exemptFamilyByFunc[syncEncl]
														forEachNestedNonEmptyIface(ae.typ, true, msc.exemptReadFields, msc.foreignReflectFields, fam, func(nif *types.Interface) {
															if k := syntaxutil.IfaceMethodSetKey(nif); k != "" {
																msc.fmtPointerErasedIfaces[k] = true
															}
														})
														if !types.IsInterface(ae.typ) {
															msc.recordEscapedArgTypesWithSink(x, ae.typ, true, false, func(node ast.Node, vt types.Type, crossedForeignPkg string) {
																if ref, ok := msc.resolveStructAt(node, vt); ok && !msc.seen[ref] {
																	msc.recordPendingBoxedEntry(ref, syntaxutil.ReflectRawUintptrToPtrKey, crossedForeignPkg)
																}
															})
														}
													}
												}
											} else {
												paramIdx := pi
												if isMethodExpr {
													paramIdx = pi - 1
												}
												if callee.Pkg() == msc.p.Types && !x.Ellipsis.IsValid() && paramIdx >= 0 && origSig != nil && paramIdx < origSig.Params().Len() &&
													msc.typeDispatchOnlyAnyParams[origSig.Params().At(paramIdx)] {
													if ae.typ != nil && !types.IsInterface(ae.typ) {
														msc.recordPendingNonEmptyIfaceBox(x, syncEncl, ae.typ)
													}
													continue
												}
												if isTrueStdCallee && (ae.typ == nil || types.IsInterface(ae.typ)) {
													msc.sawStdMutatingEmptyIfaceCall = true
												}
												deferredToParam := false
												if origSig != nil && origSig.Recv() != nil && types.IsInterface(origSig.Recv().Type()) && !isTrueStdCallee && refconfine.TypeContainsRefOrPointer(ae.typ) {
													msc.markCrossesAnyBoundary("dynamic_iface_call_any_arg", ae.typ, x)
												} else if callee.Pkg() != nil && callee.Pkg() != msc.p.Types && !isTrueStdCallee && refconfine.TypeContainsRefOrPointer(ae.typ) {
													canDeferToCallee := !x.Ellipsis.IsValid() && paramIdx >= 0 && !isEmptyInterfaceType(ae.typ)
													if canDeferToCallee {
														for ri := 0; ri < sig.Results().Len(); ri++ {
															if typeMentionsEmptyInterfaceWith(sig.Results().At(ri).Type(), true) {
																canDeferToCallee = false
																break
															}
														}
													}
													if canDeferToCallee {
														for oj, otherAE := range argEntries {
															if otherAE.typ == nil {
																canDeferToCallee = false
																break
															}
															if _, isOtherIf := types.Unalias(otherAE.typ).Underlying().(*types.Interface); !isOtherIf && typeMentionsEmptyInterfaceWith(otherAE.typ, true) {
																canDeferToCallee = false
																break
															}
															if oj != ai && typeHasCallbackIfaceTakingAny(otherAE.typ) {
																canDeferToCallee = false
																break
															}
														}
													}
													if fk, okFK := syntaxutil.CallableFactKey(callee); okFK && canDeferToCallee {
														msc.recordDeferredParamAnyBox(x, syncEncl, ae.expr, ae.typ, syntaxutil.ParamKey{Func: fk, Index: paramIdx}, fresh, freshEsc)
														deferredToParam = true
													} else {
														msc.markCrossesAnyBoundary("foreign_call_any_arg", ae.typ, x)
													}
												}
												if !deferredToParam {
													msc.recordInterfaceBox(x, syncEncl, pt, ae.expr, ae.typ, fresh, freshEsc)
												}
											}
										} else {
											msc.recordInterfaceBox(x, syncEncl, pt, ae.expr, ae.typ, fresh, freshEsc)
										}
									} else if (isDynamicIfaceCall || (callee.Pkg() != nil && callee.Pkg() != msc.p.Types && !isTrueStdCallee)) && msc.typeCrossesAnyOrEfaceUnion(pt) {
										msc.markCrossesAnyBoundary("call_param_mentions_any", pt, x)
									}
								}
							}
						}
					}
				} else if sig, okSig := syntaxutil.UnderlyingType(msc.p.TypesInfo.TypeOf(x.Fun)).(*types.Signature); okSig {
					for pi := 0; pi < sig.Params().Len(); pi++ {
						pt := sig.Params().At(pi).Type()
						if capNamed := msc.foreignReflectTypeCapsulePtrElem(pt); capNamed != nil {
							msc.recordStructAt(x, capNamed)
						}
						msc.recordBoundaryParamType(pt)
					}
					for ri := 0; ri < sig.Results().Len(); ri++ {
						msc.recordBoundaryResultOrRecvChanType(sig.Results().At(ri).Type())
					}
					if len(x.Args) == 1 {
						if tup, isTup := msc.p.TypesInfo.TypeOf(x.Args[0]).(*types.Tuple); isTup {
							for ai := 0; ai < tup.Len(); ai++ {
								pi := ai
								if sig.Variadic() && ai >= sig.Params().Len()-1 {
									pi = sig.Params().Len() - 1
								}
								if pi < sig.Params().Len() {
									pt := types.Unalias(sig.Params().At(pi).Type())
									if sig.Variadic() && ai >= sig.Params().Len()-1 && !x.Ellipsis.IsValid() {
										if sl, isSl := pt.Underlying().(*types.Slice); isSl {
											pt = types.Unalias(sl.Elem())
										}
									}
									msc.recordInterfaceBox(x, syncEncl, pt, nil, tup.At(ai).Type(), fresh, freshEsc)
								}
							}
							return true
						}
					}
					for ai, arg := range x.Args {
						pi := ai
						if sig.Variadic() && ai >= sig.Params().Len()-1 {
							pi = sig.Params().Len() - 1
						}
						if pi < sig.Params().Len() {
							pt := types.Unalias(sig.Params().At(pi).Type())
							if sig.Variadic() && ai >= sig.Params().Len()-1 && !x.Ellipsis.IsValid() {
								if sl, isSl := pt.Underlying().(*types.Slice); isSl {
									pt = types.Unalias(sl.Elem())
								}
							}
							msc.recordInterfaceBox(x, syncEncl, pt, arg, msc.p.TypesInfo.TypeOf(arg), fresh, freshEsc)
						}
					}
				}
			}
			return true
		})
	}

}
