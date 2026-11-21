package capsule

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func isZeroSizedStructOrArray(root types.Type) bool {
	seen := map[types.Type]bool{}
	var check func(t types.Type) bool
	check = func(t types.Type) bool {
		if t == nil {
			return false
		}
		t = types.Unalias(t)
		if seen[t] {
			return false
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Array:
			return u.Len() == 0
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if !check(u.Field(i).Type()) {
					return false
				}
			}
			return true
		}
		return false
	}
	return check(root)
}

func isSafeConverterGoTypeField(p *packages.Package, idx *refconfine.PkgIndex, fld *types.Var, verifiedCapsuleRoots map[*types.Named]bool) bool {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || fld == nil || !fld.IsField() || fld.Exported() || fld.Pkg() != p.Types {
		return false
	}
	pkgPath := p.Types.Path()
	isInternalPkg := pkgPath == "internal" || strings.HasPrefix(pkgPath, "internal/") ||
		strings.HasSuffix(pkgPath, "/internal") || strings.Contains(pkgPath, "/internal/")
	ownerNamed := (*types.Named)(nil)
	for _, name := range p.Types.Scope().Names() {
		tn, okTN := p.Types.Scope().Lookup(name).(*types.TypeName)
		if !okTN || tn == nil || tn.IsAlias() {
			continue
		}
		n, okN := tn.Type().(*types.Named)
		if !okN || n == nil {
			continue
		}
		st, okSt := n.Underlying().(*types.Struct)
		if !okSt {
			continue
		}
		for i := 0; i < st.NumFields(); i++ {
			if st.Field(i) == fld {
				if n.Obj().Exported() || ownerNamed != nil {
					return false
				}
				ownerNamed = n
			}
		}
	}
	if ownerNamed == nil {
		return false
	}
	ownerSt := ownerNamed.Underlying().(*types.Struct)
	fldIdx := -1
	for i := 0; i < ownerSt.NumFields(); i++ {
		if ownerSt.Field(i) == fld {
			fldIdx = i
			break
		}
	}
	if fldIdx < 0 {
		return false
	}
	for _, uid := range idx.UsesOf[fld] {
		if kv, isKV := idx.ParentMap[uid].(*ast.KeyValueExpr); isKV && ast.Unparen(kv.Key) == uid {
			continue
		}
		if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
			return false
		}
	}
	hasStructRebindOrUnsafeAddr := func(target *types.Named) bool {
		if target == nil {
			return true
		}
		targetSt, okSt := target.Underlying().(*types.Struct)
		if !okSt {
			return true
		}
		matchesTarget := func(t types.Type) bool {
			if t == nil {
				return false
			}
			t = types.Unalias(t)
			if ptr, isP := t.(*types.Pointer); isP {
				t = types.Unalias(ptr.Elem())
			}
			return t == target || types.IdenticalIgnoreTags(t.Underlying(), targetSt)
		}
		hit := false
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				if hit || n == nil {
					return false
				}
				call, isC := n.(*ast.CallExpr)
				if !isC || len(call.Args) != 1 || call.Ellipsis.IsValid() {
					return true
				}
				tv := p.TypesInfo.Types[ast.Unparen(call.Fun)]
				if !tv.IsType() || tv.Type == nil || syntaxutil.IsNilIdent(p.TypesInfo, call.Args[0]) {
					return true
				}
				dstT := types.Unalias(tv.Type)
				srcT := p.TypesInfo.TypeOf(call.Args[0])
				if srcT == nil {
					return true
				}
				srcT = types.Unalias(srcT)
				if syntaxutil.IsUnsafePointerType(dstT) && matchesTarget(srcT) {
					hit = true
					return false
				}
				_, dstSt := syntaxutil.DerefAnyStructType(dstT)
				_, srcSt := syntaxutil.DerefAnyStructType(srcT)
				if dstSt != nil && srcSt != nil &&
					(matchesTarget(dstT) || matchesTarget(srcT)) && !types.Identical(dstT, srcT) {
					hit = true
					return false
				}
				return true
			})
		}
		return hit
	}
	if hasStructRebindOrUnsafeAddr(ownerNamed) {
		return false
	}
	visitedVars := map[*types.Var]bool{}
	var isSafeTypeOrigin func(expr ast.Expr) bool
	isSafeTypeOrigin = func(expr ast.Expr) bool {
		if expr == nil {
			return false
		}
		expr = ast.Unparen(expr)
		switch e := expr.(type) {
		case *ast.Ident:
			v, _ := p.TypesInfo.Uses[e].(*types.Var)
			if v == nil || v.Pkg() != p.Types {
				return false
			}
			if visitedVars[v] {
				return true
			}
			for _, uid := range idx.UsesOf[v] {
				if u, isU := idx.ParentUnparen(uid).(*ast.UnaryExpr); isU && u.Op == token.AND && ast.Unparen(u.X) == uid {
					return false
				}
			}
			for fn, fd := range idx.FuncDecls {
				if fn == nil || fd == nil {
					continue
				}
				sig, okS := fn.Type().(*types.Signature)
				if !okS {
					continue
				}
				for pi := 0; pi < sig.Params().Len(); pi++ {
					if sig.Params().At(pi) == v {
						if sig.Recv() != nil {
							return false
						}
						if fn.Exported() && (!isInternalPkg || len(idx.UsesOf[fn]) == 0) {
							return false
						}
						visitedVars[v] = true
						for _, cuid := range idx.UsesOf[fn] {
							cc := refconfine.EnclosingCallOfCalleeIdent(idx, cuid)
							if cc == nil || cc.Ellipsis.IsValid() || pi >= len(cc.Args) {
								return false
							}
							if !isSafeTypeOrigin(cc.Args[pi]) {
								return false
							}
						}
						return true
					}
				}
			}
			if v.Parent() == p.Types.Scope() {
				if idx.DefCounts[v] != 1 {
					return false
				}
				for _, uid := range idx.UsesOf[v] {
					if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
						return false
					}
				}
				vs := idx.VarSpecs[v]
				if vs == nil || len(vs.Names) != len(vs.Values) {
					return false
				}
				visitedVars[v] = true
				for i, nm := range vs.Names {
					if p.TypesInfo.Defs[nm] == v {
						return isSafeTypeOrigin(vs.Values[i])
					}
				}
				return false
			}
			enclFD := idx.EnclFunc[e]
			if enclFD == nil || enclFD.Body == nil {
				return false
			}
			visitedVars[v] = true
			sawWrite := false
			localOK := true
			ast.Inspect(enclFD.Body, func(bn ast.Node) bool {
				if !localOK || bn == nil {
					return false
				}
				switch x := bn.(type) {
				case *ast.ValueSpec:
					for i, nm := range x.Names {
						if p.TypesInfo.Defs[nm] == v {
							if i >= len(x.Values) || !isSafeTypeOrigin(x.Values[i]) {
								localOK = false
								return false
							}
							sawWrite = true
						}
					}
				case *ast.AssignStmt:
					for i, lhs := range x.Lhs {
						lid, isID := ast.Unparen(lhs).(*ast.Ident)
						if !isID {
							continue
						}
						if p.TypesInfo.Defs[lid] == v || p.TypesInfo.Uses[lid] == v {
							if len(x.Lhs) != len(x.Rhs) || i >= len(x.Rhs) || !isSafeTypeOrigin(x.Rhs[i]) {
								localOK = false
								return false
							}
							sawWrite = true
						}
					}
				case *ast.RangeStmt:
					for _, re := range []ast.Expr{x.Key, x.Value} {
						if rid, isID := ast.Unparen(re).(*ast.Ident); isID && (p.TypesInfo.Defs[rid] == v || p.TypesInfo.Uses[rid] == v) {
							localOK = false
							return false
						}
					}
				}
				return true
			})
			return sawWrite && localOK
		case *ast.SelectorExpr:
			selInfo := p.TypesInfo.Selections[e]
			if selInfo == nil || selInfo.Kind() != types.FieldVal {
				return false
			}
			if syntaxutil.IsNamedInPkg(selInfo.Recv(), "reflect", "StructField") && e.Sel != nil && e.Sel.Name == "Type" {
				return true
			}
			recvNamed := syntaxutil.DerefNamedStruct(selInfo.Recv())
			if recvNamed == nil {
				return false
			}
			if verifiedCapsuleRoots[recvNamed] {
				return true
			}
			sfld, _ := selInfo.Obj().(*types.Var)
			if sfld == nil || !sfld.IsField() || sfld.Exported() || sfld.Pkg() != p.Types ||
				recvNamed.Obj() == nil || recvNamed.Obj().Pkg() != p.Types || recvNamed.Obj().Exported() ||
				hasStructRebindOrUnsafeAddr(recvNamed) {
				return false
			}
			if visitedVars[sfld] {
				return true
			}
			for _, uid := range idx.UsesOf[sfld] {
				if u, isU := idx.ParentUnparen(uid).(*ast.UnaryExpr); isU && u.Op == token.AND {
					return false
				}
			}
			sSt, okSt := recvNamed.Underlying().(*types.Struct)
			if !okSt {
				return false
			}
			sIdx := -1
			for si := 0; si < sSt.NumFields(); si++ {
				if sSt.Field(si) == sfld {
					sIdx = si
					break
				}
			}
			if sIdx < 0 {
				return false
			}
			visitedVars[sfld] = true
			sawFldWrite := false
			fldOK := true
			for _, sfile := range p.Syntax {
				ast.Inspect(sfile, func(sn ast.Node) bool {
					if !fldOK || sn == nil {
						return false
					}
					switch sx := sn.(type) {
					case *ast.CompositeLit:
						if syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(sx)) != recvNamed || len(sx.Elts) == 0 {
							return true
						}
						if _, isKV0 := sx.Elts[0].(*ast.KeyValueExpr); isKV0 {
							for _, elt := range sx.Elts {
								kv, isKV := elt.(*ast.KeyValueExpr)
								if !isKV {
									fldOK = false
									return false
								}
								kid, isID := ast.Unparen(kv.Key).(*ast.Ident)
								if isID && p.TypesInfo.Uses[kid] == sfld {
									if !isSafeTypeOrigin(kv.Value) {
										fldOK = false
										return false
									}
									sawFldWrite = true
								}
							}
						} else if sIdx < len(sx.Elts) {
							if !isSafeTypeOrigin(sx.Elts[sIdx]) {
								fldOK = false
								return false
							}
							sawFldWrite = true
						}
					case *ast.AssignStmt:
						for i, lhs := range sx.Lhs {
							lsel, isS := ast.Unparen(lhs).(*ast.SelectorExpr)
							if !isS || lsel.Sel == nil || p.TypesInfo.Uses[lsel.Sel] != sfld {
								continue
							}
							if len(sx.Lhs) != len(sx.Rhs) || i >= len(sx.Rhs) || !isSafeTypeOrigin(sx.Rhs[i]) {
								fldOK = false
								return false
							}
							sawFldWrite = true
						}
					}
					return true
				})
			}
			return sawFldWrite && fldOK
		case *ast.CallExpr:
			callee := syntaxutil.ResolveCalledFuncObj(p, e.Fun)
			if callee == nil || callee.Pkg() == nil || callee.Pkg().Path() != "reflect" || !syntaxutil.IsTrueStdlibInPkg(p, "reflect") {
				return false
			}
			switch callee.Name() {
			case "Elem", "Key":
				if sel, isS := ast.Unparen(e.Fun).(*ast.SelectorExpr); isS && len(e.Args) == 0 {
					return isSafeTypeOrigin(sel.X)
				}
			case "PtrTo", "PointerTo", "SliceOf":
				return len(e.Args) == 1 && isSafeTypeOrigin(e.Args[0])
			case "TypeOf":
				if len(e.Args) != 1 || e.Ellipsis.IsValid() {
					return false
				}
				return isCarrierFreeSafeTypeOfArg(p, p.TypesInfo.TypeOf(e.Args[0]))
			}
		}
		return false
	}
	sawInit := false
	allInitsOK := true
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !allInitsOK || n == nil {
				return false
			}
			cl, isCL := n.(*ast.CompositeLit)
			if !isCL || syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(cl)) != ownerNamed || len(cl.Elts) == 0 {
				return true
			}
			sawInit = true
			if _, isKV0 := cl.Elts[0].(*ast.KeyValueExpr); isKV0 {
				for _, elt := range cl.Elts {
					kv, isKV := elt.(*ast.KeyValueExpr)
					if !isKV {
						allInitsOK = false
						return false
					}
					kid, isID := ast.Unparen(kv.Key).(*ast.Ident)
					if isID && p.TypesInfo.Uses[kid] == fld {
						if !isSafeTypeOrigin(kv.Value) {
							allInitsOK = false
							return false
						}
					}
				}
			} else if fldIdx < len(cl.Elts) {
				if !isSafeTypeOrigin(cl.Elts[fldIdx]) {
					allInitsOK = false
					return false
				}
			}
			return true
		})
	}
	return sawInit && allInitsOK
}

func isCarrierFreeSafeTypeOfArg(p *packages.Package, root types.Type) bool {
	if p == nil || p.Types == nil || root == nil {
		return false
	}
	seen := map[types.Type]bool{}
	ok := true
	var walk func(t types.Type, allowPtr bool)
	walk = func(t types.Type, allowPtr bool) {
		if t == nil || !ok {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.Invalid || u.Kind() == types.UnsafePointer || u.Kind() == types.Uintptr {
				ok = false
			}
		case *types.Pointer:
			if !allowPtr {
				ok = false
				return
			}
			walk(u.Elem(), true)
		case *types.Slice:
			walk(u.Elem(), false)
		case *types.Array:
			walk(u.Elem(), false)
		case *types.Struct:
			named, isN := t.(*types.Named)
			if !isN || named.Obj() == nil || named.Obj().Pkg() != p.Types {
				ok = false
				return
			}
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type(), false)
			}
		default:
			ok = false
		}
	}
	walk(root, true)
	return ok
}

func collectSafePtrWrapperParams(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	capNamed *types.Named,
	foreignReflectFields map[*types.Var]bool,
) []syntaxutil.ParamKey {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || capNamed == nil {
		return nil
	}
	wantCapPtr := types.NewPointer(capNamed)
	isMatchingCapsuleWrapper := func(t types.Type) bool {
		wNamed, isN := types.Unalias(t).(*types.Named)
		if !isN || wNamed.Obj() == nil || wNamed.Obj().Pkg() != p.Types || wNamed.Obj().Exported() || wNamed.TypeParams() != nil {
			return false
		}
		st, isSt := wNamed.Underlying().(*types.Struct)
		if !isSt || st.NumFields() == 0 {
			return false
		}
		sawTarget := false
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if isZeroSizedStructOrArray(f.Type()) {
				if sawTarget {
					return false
				}
				continue
			}
			if sawTarget || !foreignReflectFields[f] || !types.Identical(types.Unalias(f.Type()), wantCapPtr) {
				return false
			}
			sawTarget = true
		}
		return sawTarget
	}
	var out []syntaxutil.ParamKey
	for fn, fd := range idx.FuncDecls {
		if fn == nil || fd == nil || fd.Body == nil || !fn.Exported() || fn.Pkg() != p.Types {
			continue
		}
		sig, okS := fn.Type().(*types.Signature)
		if !okS || sig.TypeParams().Len() > 0 || sig.RecvTypeParams().Len() > 0 || sig.Params().Len() != 1 || sig.Results().Len() != 1 {
			continue
		}
		if sig.Recv() != nil && !isZeroSizedStructOrArray(sig.Recv().Type()) {
			continue
		}
		pv := sig.Params().At(0)
		if !syntaxutil.IsUnsafePointerType(pv.Type()) {
			continue
		}
		retPtr, isRP := types.Unalias(sig.Results().At(0).Type()).(*types.Pointer)
		if !isRP || !isMatchingCapsuleWrapper(retPtr.Elem()) {
			continue
		}
		if len(fd.Body.List) != 1 {
			continue
		}
		ret, isRet := fd.Body.List[0].(*ast.ReturnStmt)
		if !isRet || len(ret.Results) != 1 {
			continue
		}
		castCall, isCC := ast.Unparen(ret.Results[0]).(*ast.CallExpr)
		if !isCC || len(castCall.Args) != 1 || castCall.Ellipsis.IsValid() {
			continue
		}
		castTV := p.TypesInfo.Types[ast.Unparen(castCall.Fun)]
		if !castTV.IsType() || !types.Identical(types.Unalias(castTV.Type), types.Unalias(sig.Results().At(0).Type())) {
			continue
		}
		arg := ast.Unparen(castCall.Args[0])
		if innerConv, isIC := arg.(*ast.CallExpr); isIC && len(innerConv.Args) == 1 && !innerConv.Ellipsis.IsValid() {
			itv := p.TypesInfo.Types[ast.Unparen(innerConv.Fun)]
			if itv.IsType() && syntaxutil.IsUnsafePointerType(itv.Type) {
				arg = ast.Unparen(innerConv.Args[0])
			}
		}
		if !syntaxutil.IsIdentUsingObj(p.TypesInfo, arg, pv) {
			continue
		}
		if fk, okFK := syntaxutil.CallableFactKey(fn); okFK {
			out = append(out, syntaxutil.ParamKey{Func: fk, Index: 0})
		}
	}
	slices.SortFunc(out, syntaxutil.ParamKey.Compare)
	return out
}

func collectSafeAtomicPtrCopyFuncs(p *packages.Package, idx *refconfine.PkgIndex) []syntaxutil.FuncKey {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || !syntaxutil.IsTrueStdlibInPkg(p, "sync/atomic") {
		return nil
	}
	isUnsafePtrSlotCast := func(expr ast.Expr, wantParam *types.Var) bool {
		c, isC := ast.Unparen(expr).(*ast.CallExpr)
		if !isC || len(c.Args) != 1 || c.Ellipsis.IsValid() {
			return false
		}
		tv := p.TypesInfo.Types[ast.Unparen(c.Fun)]
		if !tv.IsType() || tv.Type == nil {
			return false
		}
		ptr, isP := types.Unalias(tv.Type).(*types.Pointer)
		if !isP || !syntaxutil.IsUnsafePointerType(ptr.Elem()) {
			return false
		}
		arg := ast.Unparen(c.Args[0])
		if ic, isIC := arg.(*ast.CallExpr); isIC && len(ic.Args) == 1 && !ic.Ellipsis.IsValid() {
			itv := p.TypesInfo.Types[ast.Unparen(ic.Fun)]
			if itv.IsType() && syntaxutil.IsUnsafePointerType(itv.Type) {
				arg = ast.Unparen(ic.Args[0])
			}
		}
		return syntaxutil.IsIdentUsingObj(p.TypesInfo, arg, wantParam)
	}
	isCopyAssignStmt := func(stmt ast.Stmt, srcP, dstP *types.Var) bool {
		as, isAS := stmt.(*ast.AssignStmt)
		if !isAS || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return false
		}
		st, isSt := ast.Unparen(as.Lhs[0]).(*ast.StarExpr)
		if !isSt || !isUnsafePtrSlotCast(st.X, dstP) {
			return false
		}
		rc, isRC := ast.Unparen(as.Rhs[0]).(*ast.CallExpr)
		if !isRC || len(rc.Args) != 1 || rc.Ellipsis.IsValid() {
			return false
		}
		fn := syntaxutil.ResolveCalledFuncObj(p, rc.Fun)
		return fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == "sync/atomic" && fn.Name() == "LoadPointer" &&
			isUnsafePtrSlotCast(rc.Args[0], srcP)
	}
	var out []syntaxutil.FuncKey
	for fn, fd := range idx.FuncDecls {
		if fn == nil || fd == nil || fd.Body == nil || !fn.Exported() || fn.Pkg() != p.Types {
			continue
		}
		sig, okS := fn.Type().(*types.Signature)
		if !okS || sig.TypeParams().Len() > 0 || sig.RecvTypeParams().Len() > 0 || sig.Params().Len() != 2 || sig.Results().Len() != 0 {
			continue
		}
		if sig.Recv() != nil && !isZeroSizedStructOrArray(sig.Recv().Type()) {
			continue
		}
		p0, p1 := sig.Params().At(0), sig.Params().At(1)
		if !syntaxutil.IsUnsafePointerType(p0.Type()) || !syntaxutil.IsUnsafePointerType(p1.Type()) {
			continue
		}
		okBody := false
		if len(fd.Body.List) == 1 {
			if isCopyAssignStmt(fd.Body.List[0], p0, p1) {
				okBody = true
			} else if ifs, isIf := fd.Body.List[0].(*ast.IfStmt); isIf && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 && isCopyAssignStmt(ifs.Body.List[0], p0, p1) {
				un, isUn := ast.Unparen(ifs.Cond).(*ast.UnaryExpr)
				if isUn && un.Op == token.NOT {
					cc, isCC := ast.Unparen(un.X).(*ast.CallExpr)
					if isCC && len(cc.Args) == 3 && !cc.Ellipsis.IsValid() {
						cfn := syntaxutil.ResolveCalledFuncObj(p, cc.Fun)
						isNilSecondArg := syntaxutil.IsNilIdent(p.TypesInfo, cc.Args[1])
						if !isNilSecondArg {
							if nc, isNC := ast.Unparen(cc.Args[1]).(*ast.CallExpr); isNC && len(nc.Args) == 1 && !nc.Ellipsis.IsValid() {
								ntv := p.TypesInfo.Types[ast.Unparen(nc.Fun)]
								isNilSecondArg = ntv.IsType() && syntaxutil.IsUnsafePointerType(ntv.Type) && syntaxutil.IsNilIdent(p.TypesInfo, nc.Args[0])
							}
						}
						if cfn != nil && cfn.Pkg() != nil && cfn.Pkg().Path() == "sync/atomic" && cfn.Name() == "CompareAndSwapPointer" &&
							isUnsafePtrSlotCast(cc.Args[0], p0) && isNilSecondArg {
							if derefDst, isDD := ast.Unparen(cc.Args[2]).(*ast.StarExpr); isDD && isUnsafePtrSlotCast(derefDst.X, p1) {
								okBody = true
							}
						}
					}
				}
			}
		}
		if okBody {
			if fk, okFK := syntaxutil.CallableFactKey(fn); okFK {
				out = append(out, fk)
			}
		}
	}
	slices.SortFunc(out, syntaxutil.FuncKey.Compare)
	return out
}
