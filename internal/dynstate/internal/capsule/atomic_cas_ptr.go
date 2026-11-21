package capsule

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func verifyAtomicCASPointerStruct(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	named *types.Named,
	rootNamed *types.Named,
) (*ast.FuncDecl, map[ast.Node]bool, []syntaxutil.TypeRef) {
	if named == nil || named.Obj() == nil || named.Obj().Pkg() != p.Types || named.Obj().Exported() || named.TypeParams().Len() > 0 || types.NewMethodSet(named).Len() != 0 {
		return nil, nil, nil
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok || st.NumFields() != 1 || st.Field(0).Exported() {
		return nil, nil, nil
	}
	b, ok := types.Unalias(st.Field(0).Type()).Underlying().(*types.Basic)
	if !ok || b.Kind() != types.UnsafePointer {
		return nil, nil, nil
	}
	pset := types.NewMethodSet(types.NewPointer(named))
	if pset.Len() != 1 {
		return nil, nil, nil
	}
	m, ok := pset.At(0).Obj().(*types.Func)
	if !ok || m.Pkg() != p.Types {
		return nil, nil, nil
	}
	sig, ok := m.Type().(*types.Signature)
	if !ok || sig.Results().Len() != 1 {
		return nil, nil, nil
	}
	retPtr, ok := types.Unalias(sig.Results().At(0).Type()).(*types.Pointer)
	if !ok {
		return nil, nil, nil
	}
	retNamed, ok := types.Unalias(retPtr.Elem()).(*types.Named)
	if !ok || retNamed.Obj() == nil || retNamed.Obj().Pkg() != p.Types || retNamed.Obj().Exported() || retNamed.TypeParams().Len() > 0 {
		return nil, nil, nil
	}
	if _, isSt := retNamed.Underlying().(*types.Struct); !isSt {
		return nil, nil, nil
	}
	fd := idx.FuncDecls[m]
	if fd == nil || fd.Body == nil || bodyMutatesAnyPackageGlobal(p, fd.Body, nil) {
		return nil, nil, nil
	}

	unmutatedRootParams := map[*types.Var]bool{}
	for i := 0; i < sig.Params().Len(); i++ {
		pv := sig.Params().At(i)
		if !syntaxutil.IsPtrToNamed(pv.Type(), rootNamed) {
			continue
		}
		clean := true
		for _, uid := range idx.UsesOf[pv] {
			if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
				clean = false
				break
			}
		}
		if clean {
			unmutatedRootParams[pv] = true
		}
	}

	isValidCASAllocLit := func(expr ast.Expr) bool {
		un, isUn := ast.Unparen(expr).(*ast.UnaryExpr)
		if !isUn || un.Op != token.AND {
			return false
		}
		cl, isCL := ast.Unparen(un.X).(*ast.CompositeLit)
		if !isCL || syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(cl)) != retNamed {
			return false
		}
		for _, elt := range cl.Elts {
			kv, isKV := elt.(*ast.KeyValueExpr)
			if !isKV {
				return false
			}
			val := ast.Unparen(kv.Value)
			vt := p.TypesInfo.TypeOf(val)
			if vt == nil {
				return false
			}
			if syntaxutil.IsPtrToNamed(vt, rootNamed) {
				pid, isID := val.(*ast.Ident)
				if !isID {
					return false
				}
				pv, _ := p.TypesInfo.Uses[pid].(*types.Var)
				if pv == nil || !unmutatedRootParams[pv] {
					return false
				}
				continue
			}
			if refconfine.TypeContainsRefOrPointer(vt) {
				return false
			}
		}
		return true
	}

	allocLocals := map[*types.Var]bool{}
	loadLocals := map[*types.Var]bool{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, isAs := n.(*ast.AssignStmt)
		if !isAs || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		lid, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
		if !isID {
			return true
		}
		lv, _ := p.TypesInfo.Defs[lid].(*types.Var)
		if lv == nil || idx.DefCounts[lv] != 1 {
			return true
		}
		if isValidCASAllocLit(as.Rhs[0]) {
			allocLocals[lv] = true
		} else if rc, isRC := ast.Unparen(as.Rhs[0]).(*ast.CallExpr); isRC && len(rc.Args) == 1 {
			if cs, isCS := ast.Unparen(rc.Fun).(*ast.SelectorExpr); isCS {
				if afn, isFn := p.TypesInfo.Uses[cs.Sel].(*types.Func); isFn && afn.Pkg() != nil && afn.Pkg().Path() == "sync/atomic" && afn.Name() == "LoadPointer" {
					loadLocals[lv] = true
				}
			}
		}
		return true
	})
	for lv := range allocLocals {
		for _, uid := range idx.UsesOf[lv] {
			if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
				delete(allocLocals, lv)
				break
			}
		}
	}
	for lv := range loadLocals {
		for _, uid := range idx.UsesOf[lv] {
			if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
				delete(loadLocals, lv)
				break
			}
		}
	}

	fld := st.Field(0)
	casAddrExempt := map[ast.Node]bool{}
	allowedUnsafeConvs := map[*ast.CallExpr]bool{}
	sawCAS := false
	for _, id := range idx.UsesOf[fld] {
		if !idx.IsSyncInFuncDecl(id, fd) {
			return nil, nil, nil
		}
		sel, isSel := idx.ParentUnparen(id).(*ast.SelectorExpr)
		if !isSel || sel.Sel != id {
			return nil, nil, nil
		}
		un, isUn := idx.ParentUnparen(sel).(*ast.UnaryExpr)
		if !isUn || un.Op != token.AND {
			return nil, nil, nil
		}
		call, isCall := idx.ParentUnparen(un).(*ast.CallExpr)
		if !isCall || len(call.Args) == 0 || ast.Unparen(call.Args[0]) != un {
			return nil, nil, nil
		}
		selFun, isSF := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !isSF {
			return nil, nil, nil
		}
		afn, isFn := p.TypesInfo.Uses[selFun.Sel].(*types.Func)
		if !isFn || afn.Pkg() == nil || afn.Pkg().Path() != "sync/atomic" {
			return nil, nil, nil
		}
		switch afn.Name() {
		case "LoadPointer":
			if len(call.Args) != 1 {
				return nil, nil, nil
			}
		case "CompareAndSwapPointer":
			if len(call.Args) != 3 || !syntaxutil.IsNilIdent(p.TypesInfo, call.Args[1]) {
				return nil, nil, nil
			}
			conv, isConv := ast.Unparen(call.Args[2]).(*ast.CallExpr)
			if !isConv || len(conv.Args) != 1 || !p.TypesInfo.Types[conv.Fun].IsType() {
				return nil, nil, nil
			}
			wExpr := ast.Unparen(conv.Args[0])
			if !isValidCASAllocLit(wExpr) {
				wid, isID := wExpr.(*ast.Ident)
				if !isID {
					return nil, nil, nil
				}
				wv, _ := p.TypesInfo.Uses[wid].(*types.Var)
				if wv == nil || !allocLocals[wv] {
					return nil, nil, nil
				}
			}
			allowedUnsafeConvs[conv] = true
			sawCAS = true
		default:
			return nil, nil, nil
		}
		casAddrExempt[un] = true
	}
	if !sawCAS {
		return nil, nil, nil
	}

	returnsValid := true
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if !returnsValid || n == nil {
			return false
		}
		switch n.(type) {
		case *ast.FuncLit, *ast.GoStmt:
			returnsValid = false
			return false
		}
		ret, isRet := n.(*ast.ReturnStmt)
		if !isRet {
			return true
		}
		if len(ret.Results) != 1 {
			returnsValid = false
			return false
		}
		conv, isConv := ast.Unparen(ret.Results[0]).(*ast.CallExpr)
		if !isConv || len(conv.Args) != 1 || !p.TypesInfo.Types[conv.Fun].IsType() || !syntaxutil.IsPtrToNamed(p.TypesInfo.Types[conv.Fun].Type, retNamed) {
			returnsValid = false
			return false
		}
		src := ast.Unparen(conv.Args[0])
		if rid, isID := src.(*ast.Ident); isID {
			rv, _ := p.TypesInfo.Uses[rid].(*types.Var)
			if rv == nil || !loadLocals[rv] {
				returnsValid = false
				return false
			}
			return true
		}
		rc, isRC := src.(*ast.CallExpr)
		if !isRC || len(rc.Args) != 1 {
			returnsValid = false
			return false
		}
		cs, isCS := ast.Unparen(rc.Fun).(*ast.SelectorExpr)
		if !isCS {
			returnsValid = false
			return false
		}
		afn, isFn := p.TypesInfo.Uses[cs.Sel].(*types.Func)
		if !isFn || afn.Pkg() == nil || afn.Pkg().Path() != "sync/atomic" || afn.Name() != "LoadPointer" {
			returnsValid = false
			return false
		}
		return true
	})
	if !returnsValid {
		return nil, nil, nil
	}

	casTargets := map[*types.Named]bool{named: true, retNamed: true}
	casPtrConvs := map[*ast.CallExpr]bool{}
	convValid := true
	expanded := true
	for expanded && convValid {
		expanded = false
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				if !convValid || n == nil {
					return false
				}
				conv, isConv := n.(*ast.CallExpr)
				if !isConv || len(conv.Args) != 1 || !p.TypesInfo.Types[conv.Fun].IsType() || allowedUnsafeConvs[conv] {
					return true
				}
				argT := types.Unalias(p.TypesInfo.TypeOf(conv.Args[0]))
				srcPtr, isSrcPtr := argT.(*types.Pointer)
				if !isSrcPtr {
					return true
				}
				srcNamed, isSN := types.Unalias(srcPtr.Elem()).(*types.Named)
				if !isSN || !casTargets[srcNamed] {
					return true
				}
				dstT := types.Unalias(p.TypesInfo.Types[conv.Fun].Type)
				dstPtr, isDstPtr := dstT.(*types.Pointer)
				if !isDstPtr {
					convValid = false
					return false
				}
				dstSt, isDN := types.Unalias(dstPtr.Elem()).(*types.Named)
				if !isDN || dstSt == nil || dstSt.Obj() == nil || dstSt.Obj().Pkg() != p.Types || dstSt.Obj().Exported() || dstSt.TypeParams().Len() > 0 {
					convValid = false
					return false
				}
				if _, isStruct := dstSt.Underlying().(*types.Struct); !isStruct {
					convValid = false
					return false
				}
				casPtrConvs[conv] = true
				if !casTargets[dstSt] {
					casTargets[dstSt] = true
					expanded = true
				}
				return true
			})
		}
	}
	if !convValid {
		return nil, nil, nil
	}

	allCASProtected := map[*types.Named]bool{named: true}
	checkedCASSub := map[*types.Named]bool{}
	var verifyCASStruct func(cn *types.Named, isSub bool) bool
	verifyCASStruct = func(cn *types.Named, isSub bool) bool {
		if cn == nil || cn.Obj() == nil || cn.Obj().Pkg() != p.Types || cn.Obj().Exported() || cn.TypeParams().Len() > 0 {
			return false
		}
		if isSub {
			if checkedCASSub[cn] {
				return true
			}
		} else if allCASProtected[cn] {
			return true
		}
		cst, okS := cn.Underlying().(*types.Struct)
		if !okS {
			return false
		}
		if isSub {
			if types.NewMethodSet(types.NewPointer(cn)).Len() != types.NewMethodSet(cn).Len() {
				return false
			}
			checkedCASSub[cn] = true
		} else {
			allCASProtected[cn] = true
		}
		for i := 0; i < cst.NumFields(); i++ {
			cf := cst.Field(i)
			if cf.Exported() {
				return false
			}
			ft := types.Unalias(cf.Type())
			if !isSub && syntaxutil.IsPtrToNamed(ft, rootNamed) {
				continue
			}
			elem := ft
			zeroLenArray := false
			for {
				ar, isAr := elem.Underlying().(*types.Array)
				if !isAr {
					break
				}
				if ar.Len() == 0 && types.NewMethodSet(types.NewPointer(elem)).Len() == 0 {
					zeroLenArray = true
					break
				}
				elem = types.Unalias(ar.Elem())
			}
			if zeroLenArray && types.NewMethodSet(types.NewPointer(ft)).Len() == 0 {
				continue
			}
			if subSt, isSt := elem.Underlying().(*types.Struct); isSt {
				if subN, isSubN := elem.(*types.Named); isSubN {
					if subSt.NumFields() == 0 && types.NewMethodSet(types.NewPointer(subN)).Len() == 0 {
						continue
					}
					if !verifyCASStruct(subN, true) {
						return false
					}
					continue
				}
				if subSt.NumFields() == 0 && types.NewMethodSet(types.NewPointer(elem)).Len() == 0 {
					continue
				}
				return false
			}
			if !refconfine.TypeContainsRefOrPointer(elem) {
				continue
			}
			if isSub && elem == ft {
				if ub, isB := elem.Underlying().(*types.Basic); isB && ub.Kind() == types.UnsafePointer {
					continue
				}
			}
			return false
		}
		return true
	}
	for ct := range casTargets {
		if ct == named {
			continue
		}
		if !verifyCASStruct(ct, false) {
			return nil, nil, nil
		}
	}
	if refconfine.PkgHasAnyMutationOnStructs(p, allCASProtected, casAddrExempt) {
		return nil, nil, nil
	}

	casExempt := make(map[ast.Node]bool, len(casAddrExempt)+len(allowedUnsafeConvs)+len(casPtrConvs))
	for n := range casAddrExempt {
		casExempt[n] = true
	}
	for c := range allowedUnsafeConvs {
		casExempt[c] = true
	}
	for c := range casPtrConvs {
		casExempt[c] = true
	}

	guards := make([]syntaxutil.TypeRef, 0, len(allCASProtected))
	for ct := range allCASProtected {
		ref := syntaxutil.TypeRef{Pkg: p.Types.Path(), Name: ct.Obj().Name()}
		if !ref.Valid() {
			return nil, nil, nil
		}
		guards = append(guards, ref)
	}
	sort.Slice(guards, func(i, j int) bool { return guards[i].Key() < guards[j].Key() })
	return fd, casExempt, guards
}
