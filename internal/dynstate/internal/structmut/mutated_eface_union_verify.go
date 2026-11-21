package structmut

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func (efu *efaceUnionHelper) verifyEfaceUnionStructs() {
	scope := efu.p.Types.Scope()
	// Step 2: Verify sealed representation-preserving 2-word eface union structs
	// (such as unexported unsafe.Pointer + scalar value-union representations).
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok || tn == nil || tn.Exported() || tn.IsAlias() {
			continue
		}
		uNamed, ok := tn.Type().(*types.Named)
		if !ok || uNamed == nil || uNamed.TypeParams() != nil {
			continue
		}
		uSt, isSt := uNamed.Underlying().(*types.Struct)
		if !isSt {
			continue
		}
		var uPtrFields []*types.Var
		schemaOK := true
		for i := 0; i < uSt.NumFields(); i++ {
			f := uSt.Field(i)
			if isZeroSizedPaddingType(f.Type()) {
				if f.Embedded() && types.NewMethodSet(types.NewPointer(f.Type())).Len() != 0 {
					schemaOK = false
					break
				}
				continue
			}
			if syntaxutil.IsUnsafePointerType(f.Type()) {
				if f.Exported() || f.Embedded() || len(uPtrFields) >= 2 {
					schemaOK = false
					break
				}
				uPtrFields = append(uPtrFields, f)
				continue
			}
			if b, isB := syntaxutil.UnderlyingType(f.Type()).(*types.Basic); !isB || b.Kind() == types.UnsafePointer || b.Kind() == types.Uintptr {
				schemaOK = false
				break
			}
		}
		if !schemaOK || len(uPtrFields) != 2 {
			continue
		}
		uTyp, uData := uPtrFields[0], uPtrFields[1]

		isUnionValueType := func(t types.Type) bool {
			return t != nil && types.Unalias(t).Underlying() == uSt
		}

		// Reject union types that expose any direct or promoted pointer-receiver
		// methods in p.Types (preventing auto-addressed u.PtrMethod() mutations).
		hasPtrRecvMethod := false
		for _, sname := range scope.Names() {
			stn, okST := scope.Lookup(sname).(*types.TypeName)
			if !okST || stn == nil || stn.IsAlias() {
				continue
			}
			snamed, okSN := stn.Type().(*types.Named)
			if !okSN || snamed == nil || !isUnionValueType(snamed) {
				continue
			}
			mset := types.NewMethodSet(types.NewPointer(snamed))
			for mi := 0; mi < mset.Len(); mi++ {
				if refconfine.SelectionHasPointerReceiver(mset.At(mi)) {
					hasPtrRecvMethod = true
					break
				}
			}
			if hasPtrRecvMethod {
				break
			}
		}
		if hasPtrRecvMethod {
			continue
		}

		typeContainsUnionStruct := func(root types.Type) bool {
			seenT := map[types.Type]bool{}
			foundU := false
			var walkU func(t types.Type)
			walkU = func(t types.Type) {
				if t == nil || foundU {
					return
				}
				t = types.Unalias(t)
				if isUnionValueType(t) || types.IdenticalIgnoreTags(t.Underlying(), uSt) {
					foundU = true
					return
				}
				if seenT[t] {
					return
				}
				seenT[t] = true
				switch u := t.Underlying().(type) {
				case *types.Pointer:
					walkU(u.Elem())
				case *types.Slice:
					walkU(u.Elem())
				case *types.Array:
					walkU(u.Elem())
				case *types.Map:
					walkU(u.Elem())
				case *types.Struct:
					for i := 0; i < u.NumFields(); i++ {
						walkU(u.Field(i).Type())
					}
				}
			}
			walkU(root)
			return foundU
		}

		var exprTouchesUnionStruct func(expr ast.Expr) bool
		exprTouchesUnionStruct = func(expr ast.Expr) bool {
			for cur := ast.Unparen(expr); cur != nil; {
				if typeContainsUnionStruct(efu.p.TypesInfo.TypeOf(cur)) {
					return true
				}
				switch e := cur.(type) {
				case *ast.SelectorExpr:
					cur = ast.Unparen(e.X)
				case *ast.IndexExpr:
					cur = ast.Unparen(e.X)
				case *ast.SliceExpr:
					cur = ast.Unparen(e.X)
				case *ast.StarExpr:
					cur = ast.Unparen(e.X)
				default:
					return false
				}
			}
			return false
		}

		// Ensure no &uVal / &uVal.field, unsafe.Pointer(&uVal), unsafe.Slice(&uVal, n),
		// unsafe.SliceData([]uVal), or struct-rebinding conversion creates an untracked
		// field/memory alias on uSt.
		var packConvs []*ast.CallExpr
		usedNonIfaceSentinels := map[*types.Var]bool{}
		litAndAddrOK := true
		for _, file := range efu.p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				if !litAndAddrOK || n == nil {
					return false
				}
				switch x := n.(type) {
				case *ast.UnaryExpr:
					if x.Op == token.AND && exprTouchesUnionStruct(x.X) {
						litAndAddrOK = false
						return false
					}
				case *ast.CallExpr:
					tv := efu.p.TypesInfo.Types[ast.Unparen(x.Fun)]
					if tv.IsType() && len(x.Args) == 1 {
						srcT := efu.p.TypesInfo.TypeOf(x.Args[0])
						if conversionRebindsUnionStruct(tv.Type, srcT, uSt) {
							litAndAddrOK = false
							return false
						}
						if syntaxutil.IsUnsafePointerType(tv.Type) {
							if ptr, isP := syntaxutil.UnderlyingType(srcT).(*types.Pointer); isP && typeContainsUnionStruct(ptr.Elem()) {
								litAndAddrOK = false
								return false
							}
						}
					}
					if sdCall, okSD := efu.isUnsafeBuiltinCall(x, "SliceData"); okSD && len(sdCall.Args) == 1 {
						if sl, isSl := syntaxutil.UnderlyingType(efu.p.TypesInfo.TypeOf(sdCall.Args[0])).(*types.Slice); isSl && typeContainsUnionStruct(sl.Elem()) {
							litAndAddrOK = false
							return false
						}
					}
					if slCall, okSl := efu.isUnsafeBuiltinCall(x, "Slice"); okSl && len(slCall.Args) >= 1 {
						if ptr, isP := syntaxutil.UnderlyingType(efu.p.TypesInfo.TypeOf(slCall.Args[0])).(*types.Pointer); isP && typeContainsUnionStruct(ptr.Elem()) {
							litAndAddrOK = false
							return false
						}
					}
				case *ast.CompositeLit:
					if !isUnionValueType(efu.p.TypesInfo.TypeOf(x)) || len(x.Elts) == 0 {
						return true
					}
					var typExpr, dataExpr ast.Expr
					for _, elt := range x.Elts {
						kv, isKV := elt.(*ast.KeyValueExpr)
						if !isKV {
							litAndAddrOK = false
							return false
						}
						kid, isKID := ast.Unparen(kv.Key).(*ast.Ident)
						if !isKID {
							litAndAddrOK = false
							return false
						}
						fv, _ := efu.p.TypesInfo.Uses[kid].(*types.Var)
						if fv == uTyp {
							typExpr = kv.Value
						} else if fv == uData {
							dataExpr = kv.Value
						}
					}
					if dataExpr == nil || syntaxutil.IsNilIdent(efu.p.TypesInfo, dataExpr) {
						if typExpr != nil && !syntaxutil.IsNilIdent(efu.p.TypesInfo, typExpr) {
							tid, isTID := ast.Unparen(typExpr).(*ast.Ident)
							tvObj, _ := efu.p.TypesInfo.Uses[tid].(*types.Var)
							sk := efu.sentinelVars[tvObj]
							if !isTID || tvObj == nil || (sk != sentinelOtherScalar && sk != sentinelNil) {
								litAndAddrOK = false
								return false
							}
							if sk != sentinelNil {
								usedNonIfaceSentinels[tvObj] = true
							}
						}
						return true
					}
					// Check unsafe.Pointer(unsafe.StringData(...)) or unsafe.Pointer(unsafe.SliceData(...))
					if upCall, isUP := ast.Unparen(dataExpr).(*ast.CallExpr); isUP && len(upCall.Args) == 1 && !upCall.Ellipsis.IsValid() {
						upTV := efu.p.TypesInfo.Types[ast.Unparen(upCall.Fun)]
						if upTV.IsType() && syntaxutil.IsUnsafePointerType(upTV.Type) {
							if _, isSD := efu.isUnsafeBuiltinCall(upCall.Args[0], "StringData"); isSD {
								tid, isTID := ast.Unparen(typExpr).(*ast.Ident)
								tvObj, _ := efu.p.TypesInfo.Uses[tid].(*types.Var)
								if !isTID || tvObj == nil || efu.sentinelVars[tvObj] != sentinelString {
									litAndAddrOK = false
									return false
								}
								usedNonIfaceSentinels[tvObj] = true
								return true
							}
							if _, isSlD := efu.isUnsafeBuiltinCall(upCall.Args[0], "SliceData"); isSlD {
								tid, isTID := ast.Unparen(typExpr).(*ast.Ident)
								tvObj, _ := efu.p.TypesInfo.Uses[tid].(*types.Var)
								if !isTID || tvObj == nil || efu.sentinelVars[tvObj] != sentinelBytes {
									litAndAddrOK = false
									return false
								}
								usedNonIfaceSentinels[tvObj] = true
								return true
							}
						}
					}
					// Otherwise must be paired hdr.hTyp + hdr.hData from hdr := (*Hdr)(unsafe.Pointer(&inAny))
					tSel, isTS := ast.Unparen(typExpr).(*ast.SelectorExpr)
					dSel, isDS := ast.Unparen(dataExpr).(*ast.SelectorExpr)
					if !isTS || !isDS {
						litAndAddrOK = false
						return false
					}
					thID, isTH := ast.Unparen(tSel.X).(*ast.Ident)
					dhID, isDH := ast.Unparen(dSel.X).(*ast.Ident)
					if !isTH || !isDH {
						litAndAddrOK = false
						return false
					}
					hdrVar, _ := efu.p.TypesInfo.Uses[thID].(*types.Var)
					if hdrVar == nil || efu.p.TypesInfo.Uses[dhID] != hdrVar || !efu.isUnmodifiedSingleDefLocal(hdrVar) || len(efu.idx.UsesOf[hdrVar]) != 2 {
						litAndAddrOK = false
						return false
					}
					_, hTyp, hData, okHdr := efu.parseEfaceHeaderPtrType(hdrVar.Type())
					if !okHdr {
						litAndAddrOK = false
						return false
					}
					tsInfo := efu.p.TypesInfo.Selections[tSel]
					dsInfo := efu.p.TypesInfo.Selections[dSel]
					if tsInfo == nil || dsInfo == nil || tsInfo.Obj() != hTyp || dsInfo.Obj() != hData {
						litAndAddrOK = false
						return false
					}
					// Find hdrVar's defining assignment hdr := (*Hdr)(unsafe.Pointer(&inAny))
					encl := innermostFuncOrLitBody(efu.idx, x)
					if encl == nil {
						litAndAddrOK = false
						return false
					}
					var foundConv *ast.CallExpr
					ast.Inspect(encl, func(sn ast.Node) bool {
						if foundConv != nil || sn == nil {
							return false
						}
						as, isAS := sn.(*ast.AssignStmt)
						if !isAS || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
							return true
						}
						lid, isLID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
						if !isLID || efu.p.TypesInfo.Defs[lid] != hdrVar {
							return true
						}
						hdrCast, isCast := ast.Unparen(as.Rhs[0]).(*ast.CallExpr)
						if !isCast || len(hdrCast.Args) != 1 || hdrCast.Ellipsis.IsValid() {
							return false
						}
						innerConv, isInner := ast.Unparen(hdrCast.Args[0]).(*ast.CallExpr)
						if isInner {
							if _, _, okIn := efu.extractSingleAddrEmptyIfaceLocal(innerConv); okIn {
								foundConv = innerConv
							}
						}
						return false
					})
					if foundConv == nil {
						litAndAddrOK = false
						return false
					}
					packConvs = append(packConvs, foundConv)
				}
				return true
			})
		}
		if !litAndAddrOK {
			continue
		}

		// Verify every read of uTyp and uData across p.
		var unpackConvs []*ast.CallExpr
		unpackPairedTypSels := map[*ast.SelectorExpr]bool{}
		getIfaceFuncs := map[*types.Func]bool{}
		getStringFuncs := map[*types.Func]bool{}
		getBytesFuncs := map[*types.Func]bool{}

		enclosingPackageFunc := func(n ast.Node) *types.Func {
			for cur := n; cur != nil; cur = efu.idx.ParentMap[cur] {
				if _, isFL := cur.(*ast.FuncLit); isFL {
					return nil
				}
				if fd, isFD := cur.(*ast.FuncDecl); isFD && fd.Name != nil {
					fn, _ := efu.p.TypesInfo.Defs[fd.Name].(*types.Func)
					return fn
				}
			}
			return nil
		}

		dataUsesOK := true
		for _, uid := range efu.idx.UsesOf[uData] {
			if kv, isKV := efu.idx.ParentMap[uid].(*ast.KeyValueExpr); isKV && ast.Unparen(kv.Key) == uid {
				if cl, isCL := efu.idx.ParentMap[kv].(*ast.CompositeLit); isCL && isUnionValueType(efu.p.TypesInfo.TypeOf(cl)) {
					continue
				}
			}
			sel, isSel := efu.idx.ParentMap[uid].(*ast.SelectorExpr)
			if !isSel || sel.Sel != uid || refconfine.IdentOrExprIsWritten(efu.idx, sel) {
				dataUsesOK = false
				break
			}
			sInfo := efu.p.TypesInfo.Selections[sel]
			if sInfo == nil || sInfo.Kind() != types.FieldVal || len(sInfo.Index()) != 1 {
				dataUsesOK = false
				break
			}
			recvID, isRID := ast.Unparen(sel.X).(*ast.Ident)
			if !isRID {
				dataUsesOK = false
				break
			}
			recvVar, _ := efu.p.TypesInfo.Uses[recvID].(*types.Var)
			if !efu.isUnmodifiedSingleDefLocal(recvVar) || !isUnionValueType(recvVar.Type()) {
				dataUsesOK = false
				break
			}
			enclBody := innermostFuncOrLitBody(efu.idx, sel)
			if enclBody == nil || cachedScopeHasGotoOrLabel(efu.p, efu.idx, enclBody) {
				dataUsesOK = false
				break
			}
			par := efu.idx.ParentUnparen(sel)
			// Case D1: (*byte)(recv.ptr) inside unsafe.String or unsafe.Slice
			if byteCast, isBC := par.(*ast.CallExpr); isBC && len(byteCast.Args) == 1 && ast.Unparen(byteCast.Args[0]) == sel {
				bcTV := efu.p.TypesInfo.Types[ast.Unparen(byteCast.Fun)]
				if bcPtr, isP := types.Unalias(bcTV.Type).(*types.Pointer); bcTV.IsType() && isP {
					if eb, isB := syntaxutil.UnderlyingType(bcPtr.Elem()).(*types.Basic); isB && eb.Kind() == types.Byte {
						outerCall := efu.idx.ParentUnparen(byteCast)
						if strCall, okStr := efu.isUnsafeBuiltinCall(outerCall, "String"); okStr && len(strCall.Args) == 2 && ast.Unparen(strCall.Args[0]) == byteCast {
							enclFn := enclosingPackageFunc(sel)
							if enclFn == nil || enclFn.Exported() {
								dataUsesOK = false
								break
							}
							esig, okES := enclFn.Type().(*types.Signature)
							if !okES || esig.Recv() == nil || esig.Recv() != recvVar {
								dataUsesOK = false
								break
							}
							getStringFuncs[enclFn] = true
							continue
						}
						if slCall, okSl := efu.isUnsafeBuiltinCall(outerCall, "Slice"); okSl && len(slCall.Args) == 2 && ast.Unparen(slCall.Args[0]) == byteCast {
							enclFn := enclosingPackageFunc(sel)
							if enclFn == nil || enclFn.Exported() {
								dataUsesOK = false
								break
							}
							esig, okES := enclFn.Type().(*types.Signature)
							if !okES || esig.Recv() == nil || esig.Recv() != recvVar {
								dataUsesOK = false
								break
							}
							getBytesFuncs[enclFn] = true
							continue
						}
					}
				}
			}
			// Case D2: Hdr{hTyp: recv.typ, hData: recv.ptr} assigned to *(*Hdr)(unsafe.Pointer(&outAny))
			kv, isKV := par.(*ast.KeyValueExpr)
			if !isKV || ast.Unparen(kv.Value) != sel {
				dataUsesOK = false
				break
			}
			hdrLit, isCL := efu.idx.ParentUnparen(kv).(*ast.CompositeLit)
			if !isCL || len(hdrLit.Elts) != 2 {
				dataUsesOK = false
				break
			}
			hdrLitPtrT := types.NewPointer(efu.p.TypesInfo.TypeOf(hdrLit))
			hdrSt, hTyp, hData, okHdr := efu.parseEfaceHeaderPtrType(hdrLitPtrT)
			if !okHdr {
				dataUsesOK = false
				break
			}
			var pairedTypSel *ast.SelectorExpr
			bothMatched := true
			for _, elt := range hdrLit.Elts {
				ekv, isEKV := elt.(*ast.KeyValueExpr)
				if !isEKV {
					bothMatched = false
					break
				}
				ekid, isEKID := ast.Unparen(ekv.Key).(*ast.Ident)
				if !isEKID {
					bothMatched = false
					break
				}
				efv, _ := efu.p.TypesInfo.Uses[ekid].(*types.Var)
				if efv == hData {
					if ast.Unparen(ekv.Value) != sel {
						bothMatched = false
						break
					}
				} else if efv == hTyp {
					tsel, isTS := ast.Unparen(ekv.Value).(*ast.SelectorExpr)
					if !isTS {
						bothMatched = false
						break
					}
					trID, isTR := ast.Unparen(tsel.X).(*ast.Ident)
					tsInfo := efu.p.TypesInfo.Selections[tsel]
					if !isTR || efu.p.TypesInfo.Uses[trID] != recvVar || tsInfo == nil || tsInfo.Obj() != uTyp {
						bothMatched = false
						break
					}
					pairedTypSel = tsel
				} else {
					bothMatched = false
					break
				}
			}
			if !bothMatched || pairedTypSel == nil {
				dataUsesOK = false
				break
			}
			as, isAS := efu.idx.ParentUnparen(hdrLit).(*ast.AssignStmt)
			if !isAS || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Rhs[0]) != hdrLit {
				dataUsesOK = false
				break
			}
			star, isStar := ast.Unparen(as.Lhs[0]).(*ast.StarExpr)
			if !isStar {
				dataUsesOK = false
				break
			}
			lhsCast, isCast := ast.Unparen(star.X).(*ast.CallExpr)
			if !isCast || len(lhsCast.Args) != 1 || lhsCast.Ellipsis.IsValid() {
				dataUsesOK = false
				break
			}
			lhsTV := efu.p.TypesInfo.Types[ast.Unparen(lhsCast.Fun)]
			lhsHdrSt, _, _, okLHdr := efu.parseEfaceHeaderPtrType(lhsTV.Type)
			if !lhsTV.IsType() || !okLHdr || lhsHdrSt != hdrSt {
				dataUsesOK = false
				break
			}
			outConv, isOutConv := ast.Unparen(lhsCast.Args[0]).(*ast.CallExpr)
			if !isOutConv || len(outConv.Args) != 1 || outConv.Ellipsis.IsValid() {
				dataUsesOK = false
				break
			}
			outConvTV := efu.p.TypesInfo.Types[ast.Unparen(outConv.Fun)]
			outUn, isOutUn := ast.Unparen(outConv.Args[0]).(*ast.UnaryExpr)
			if !outConvTV.IsType() || !syntaxutil.IsUnsafePointerType(outConvTV.Type) || !isOutUn || outUn.Op != token.AND {
				dataUsesOK = false
				break
			}
			outID, isOutID := ast.Unparen(outUn.X).(*ast.Ident)
			if !isOutID {
				dataUsesOK = false
				break
			}
			outVar, _ := efu.p.TypesInfo.Uses[outID].(*types.Var)
			if !efu.isZeroInitEmptyIfaceVar(outVar, outID) {
				dataUsesOK = false
				break
			}
			enclFn := enclosingPackageFunc(sel)
			if enclFn == nil || enclFn.Exported() {
				dataUsesOK = false
				break
			}
			esig, okES := enclFn.Type().(*types.Signature)
			if !okES || esig.Recv() == nil || esig.Recv() != recvVar {
				dataUsesOK = false
				break
			}
			getIfaceFuncs[enclFn] = true
			unpackPairedTypSels[pairedTypSel] = true
			unpackConvs = append(unpackConvs, outConv)
		}
		if !dataUsesOK {
			continue
		}

		typUsesOK := true
		for _, uid := range efu.idx.UsesOf[uTyp] {
			if kv, isKV := efu.idx.ParentMap[uid].(*ast.KeyValueExpr); isKV && ast.Unparen(kv.Key) == uid {
				if cl, isCL := efu.idx.ParentMap[kv].(*ast.CompositeLit); isCL && isUnionValueType(efu.p.TypesInfo.TypeOf(cl)) {
					continue
				}
			}
			sel, isSel := efu.idx.ParentMap[uid].(*ast.SelectorExpr)
			if !isSel || sel.Sel != uid || refconfine.IdentOrExprIsWritten(efu.idx, sel) {
				typUsesOK = false
				break
			}
			if unpackPairedTypSels[sel] {
				continue
			}
			switch par := efu.idx.ParentUnparen(sel).(type) {
			case *ast.BinaryExpr:
				if par.Op != token.EQL && par.Op != token.NEQ {
					typUsesOK = false
				}
			case *ast.SwitchStmt:
				if par.Init != nil || ast.Unparen(par.Tag) != sel {
					typUsesOK = false
				}
			default:
				typUsesOK = false
			}
			if !typUsesOK {
				break
			}
		}
		if !typUsesOK {
			continue
		}

		// Verify every call site of getBytesFuncs is gated on switch callRecv.typ { case bytesType: ... }.
		findEnclosingTypSwitchCase := func(call *ast.CallExpr, callRecv *types.Var) (*ast.SwitchStmt, *ast.CaseClause) {
			var prev ast.Node = call
			var foundCC *ast.CaseClause
			for cur := efu.idx.ParentMap[call]; cur != nil; cur = efu.idx.ParentMap[cur] {
				switch node := cur.(type) {
				case *ast.FuncDecl, *ast.FuncLit:
					return nil, nil
				case *ast.CaseClause:
					if foundCC == nil {
						for _, st := range node.Body {
							if st == prev {
								foundCC = node
								break
							}
						}
					}
				case *ast.SwitchStmt:
					if foundCC != nil && node.Body != nil {
						for _, raw := range node.Body.List {
							if raw == foundCC {
								if node.Init != nil {
									return nil, nil
								}
								tagSel, isTS := ast.Unparen(node.Tag).(*ast.SelectorExpr)
								if !isTS {
									return nil, nil
								}
								tagRID, isTR := ast.Unparen(tagSel.X).(*ast.Ident)
								tsInfo := efu.p.TypesInfo.Selections[tagSel]
								if isTR && efu.p.TypesInfo.Uses[tagRID] == callRecv && tsInfo != nil && tsInfo.Obj() == uTyp {
									hasFallthrough := false
									ast.Inspect(node.Body, func(sn ast.Node) bool {
										if hasFallthrough || sn == nil {
											return false
										}
										if _, isInnerSw := sn.(*ast.SwitchStmt); isInnerSw {
											return false
										}
										if br, isBR := sn.(*ast.BranchStmt); isBR && br.Tok == token.FALLTHROUGH {
											hasFallthrough = true
											return false
										}
										return true
									})
									if !hasFallthrough {
										return node, foundCC
									}
								}
							}
						}
					}
					foundCC = nil
				}
				prev = cur
			}
			return nil, nil
		}

		verifyTagGatedHelpers := func(fns map[*types.Func]bool, wantKind sentinelKind) bool {
			for hFn := range fns {
				uses := efu.idx.UsesOf[hFn]
				if len(uses) == 0 {
					return false
				}
				for _, uid := range uses {
					sel, isSel := efu.idx.ParentMap[uid].(*ast.SelectorExpr)
					if !isSel || sel.Sel != uid {
						return false
					}
					call, isCall := efu.idx.ParentUnparen(sel).(*ast.CallExpr)
					if !isCall || ast.Unparen(call.Fun) != sel || len(call.Args) != 0 {
						return false
					}
					crID, isCR := ast.Unparen(sel.X).(*ast.Ident)
					if !isCR {
						return false
					}
					callRecv, _ := efu.p.TypesInfo.Uses[crID].(*types.Var)
					if !efu.isUnmodifiedSingleDefLocal(callRecv) {
						return false
					}
					enclBody := innermostFuncOrLitBody(efu.idx, call)
					if enclBody == nil || cachedScopeHasGotoOrLabel(efu.p, efu.idx, enclBody) {
						return false
					}
					_, cc := findEnclosingTypSwitchCase(call, callRecv)
					if cc == nil || len(cc.List) == 0 {
						return false
					}
					for _, ce := range cc.List {
						cid, isCID := ast.Unparen(ce).(*ast.Ident)
						cv, _ := efu.p.TypesInfo.Uses[cid].(*types.Var)
						if !isCID || cv == nil || efu.sentinelVars[cv] != wantKind {
							return false
						}
					}
				}
			}
			return true
		}

		helpersOK := verifyTagGatedHelpers(getBytesFuncs, sentinelBytes) &&
			verifyTagGatedHelpers(getStringFuncs, sentinelString)
		if !helpersOK {
			continue
		}

		// Verify every call site of getIfaceFuncs either sits in default: of a
		// switch callRecv.typ covering every usedNonIfaceSentinels tag, or sits
		// directly in a TypeSwitchStmt whose non-panicking cases match only
		// non-empty interfaces.
		for giFn := range getIfaceFuncs {
			uses := efu.idx.UsesOf[giFn]
			if len(uses) == 0 {
				helpersOK = false
				break
			}
			for _, uid := range uses {
				sel, isSel := efu.idx.ParentMap[uid].(*ast.SelectorExpr)
				if !isSel || sel.Sel != uid {
					helpersOK = false
					break
				}
				call, isCall := efu.idx.ParentUnparen(sel).(*ast.CallExpr)
				if !isCall || ast.Unparen(call.Fun) != sel || len(call.Args) != 0 {
					helpersOK = false
					break
				}
				crID, isCR := ast.Unparen(sel.X).(*ast.Ident)
				if !isCR {
					helpersOK = false
					break
				}
				callRecv, _ := efu.p.TypesInfo.Uses[crID].(*types.Var)
				if !efu.isUnmodifiedSingleDefLocal(callRecv) {
					helpersOK = false
					break
				}
				enclBody := innermostFuncOrLitBody(efu.idx, call)
				if enclBody == nil || cachedScopeHasGotoOrLabel(efu.p, efu.idx, enclBody) {
					helpersOK = false
					break
				}
				sw, cc := findEnclosingTypSwitchCase(call, callRecv)
				if sw != nil && cc != nil && cc.List == nil {
					covered := map[*types.Var]bool{}
					for _, raw := range sw.Body.List {
						occ, okOCC := raw.(*ast.CaseClause)
						if !okOCC || occ == cc {
							continue
						}
						for _, ce := range occ.List {
							if cid, isCID := ast.Unparen(ce).(*ast.Ident); isCID {
								if cv, _ := efu.p.TypesInfo.Uses[cid].(*types.Var); cv != nil {
									covered[cv] = true
								}
							}
						}
					}
					allCovered := true
					for req := range usedNonIfaceSentinels {
						if !covered[req] {
							allCovered = false
							break
						}
					}
					if allCovered {
						continue
					}
				}
				// Alternative: switch vi := callRecv.getIface().(type) { case NonEmptyIface: ... default: panic(...) }
				ta, isTA := efu.idx.ParentUnparen(call).(*ast.TypeAssertExpr)
				if !isTA || ast.Unparen(ta.X) != call || ta.Type != nil {
					helpersOK = false
					break
				}
				parStmt := efu.idx.ParentUnparen(ta)
				var ts *ast.TypeSwitchStmt
				switch ps := parStmt.(type) {
				case *ast.ExprStmt:
					ts, _ = efu.idx.ParentUnparen(ps).(*ast.TypeSwitchStmt)
				case *ast.AssignStmt:
					if ps.Tok == token.DEFINE && len(ps.Lhs) == 1 && len(ps.Rhs) == 1 && ast.Unparen(ps.Rhs[0]) == ta {
						ts, _ = efu.idx.ParentUnparen(ps).(*ast.TypeSwitchStmt)
					}
				}
				if ts == nil || ts.Assign != parStmt || ts.Body == nil {
					helpersOK = false
					break
				}
				sawDefaultPanic := false
				casesNonEmpty := true
				for _, raw := range ts.Body.List {
					tcc, okTCC := raw.(*ast.CaseClause)
					if !okTCC {
						continue
					}
					if tcc.List == nil {
						if len(tcc.Body) == 1 && stmtAlwaysTerminates(efu.p, tcc.Body[0]) {
							// Require panic specifically on default so invalid non-interface tags cannot return normally.
							if es, isES := tcc.Body[0].(*ast.ExprStmt); isES && stmtAlwaysTerminates(efu.p, es) {
								sawDefaultPanic = true
							}
						}
						continue
					}
					for _, ct := range tcc.List {
						ctIface, isIf := syntaxutil.UnderlyingType(efu.p.TypesInfo.TypeOf(ct)).(*types.Interface)
						if !isIf || ctIface.NumMethods() == 0 {
							casesNonEmpty = false
							break
						}
					}
				}
				if !sawDefaultPanic || !casesNonEmpty {
					helpersOK = false
					break
				}
			}
			if !helpersOK {
				break
			}
		}
		if !helpersOK {
			continue
		}

		for _, c := range packConvs {
			efu.safe[c] = true
		}
		for _, c := range unpackConvs {
			efu.safe[c] = true
		}
	}

}
