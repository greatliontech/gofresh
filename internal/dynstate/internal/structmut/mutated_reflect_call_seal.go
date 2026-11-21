package structmut

import (
	"go/ast"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshalloc"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func pkgHasReflectCallFileHazard(p *packages.Package) bool {
	if p == nil || len(p.Syntax) == 0 {
		return true
	}
	if len(p.OtherFiles) > 0 || (len(p.GoFiles) > 0 && len(p.CompiledGoFiles) > len(p.GoFiles)) {
		return true
	}
	for _, file := range p.Syntax {
		for _, imp := range file.Imports {
			if imp != nil && imp.Path != nil {
				if uq, err := strconv.Unquote(imp.Path.Value); err == nil && (uq == "C" || uq == "unsafe") {
					return true
				}
			}
		}
		for _, cg := range file.Comments {
			for _, c := range cg.List {
				if strings.Contains(c.Text, "go:linkname") {
					return true
				}
			}
		}
		for _, decl := range file.Decls {
			if fd, isFD := decl.(*ast.FuncDecl); isFD && fd.Body == nil {
				return true
			}
		}
	}
	return false
}

func isSafeScalarReflectValueCallArg(p *packages.Package, rawArg ast.Expr, isTrueStdPkg func(*types.Package) bool) bool {
	if p == nil || p.TypesInfo == nil || rawArg == nil {
		return false
	}
	arg := ast.Unparen(rawArg)
	if syntaxutil.IsNilIdent(p.TypesInfo, arg) || syntaxutil.IsTypedNilSliceConv(p, arg) {
		return true
	}
	cl, isCL := arg.(*ast.CompositeLit)
	if !isCL {
		return false
	}
	for _, elt := range cl.Elts {
		val := elt
		if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
			val = kv.Value
		}
		vc, isVC := ast.Unparen(val).(*ast.CallExpr)
		if !isVC || len(vc.Args) != 1 || vc.Ellipsis.IsValid() {
			return false
		}
		vfn := syntaxutil.ResolveCalledFuncObj(p, vc.Fun)
		if vfn == nil || !isTrueStdPkg(vfn.Pkg()) || vfn.Pkg().Path() != "reflect" || vfn.Name() != "ValueOf" ||
			freshalloc.TypeCanCarryExtractedObject(p.TypesInfo.TypeOf(vc.Args[0])) {
			return false
		}
	}
	return true
}

func isScalarCallableVoidMethod(fn *types.Func, sig *types.Signature, isTrueStdPkg func(*types.Package) bool) bool {
	if fn == nil || !fn.Exported() || sig == nil || sig.Results().Len() > 0 {
		return false
	}
	nFixed := sig.Params().Len()
	if sig.Variadic() && nFixed > 0 {
		nFixed--
	}
	for i := 0; i < nFixed; i++ {
		pt := sig.Params().At(i).Type()
		if (!freshalloc.IsRuntimeInterfaceType(pt) && freshalloc.TypeCanCarryExtractedObject(pt)) || ifaceSealsOutStdlib(pt, isTrueStdPkg) {
			return false
		}
	}
	return true
}

func typeSealsOutStdlibForReflectCall(root types.Type, isTrueStdPkg func(*types.Package) bool) bool {
	visiting := map[types.Type]bool{}
	var check func(t types.Type) bool
	check = func(t types.Type) bool {
		if t == nil {
			return false
		}
		t = types.Unalias(t)
		if _, isTP := t.(*types.TypeParam); isTP {
			return false
		}
		if visiting[t] {
			return true
		}
		visiting[t] = true
		defer delete(visiting, t)

		if freshalloc.IsRuntimeInterfaceType(t) {
			if !ifaceSealsOutStdlib(t, isTrueStdPkg) {
				return false
			}
			ms := types.NewMethodSet(t)
			for i := 0; i < ms.Len(); i++ {
				fn, _ := ms.At(i).Obj().(*types.Func)
				sig, _ := ms.At(i).Type().(*types.Signature)
				if fn == nil || sig == nil || isScalarCallableVoidMethod(fn, sig, isTrueStdPkg) {
					return false
				}
			}
			return true
		}
		named, isNamed := t.(*types.Named)
		if !isNamed || named.Obj() == nil || named.Obj().Pkg() == nil || isTrueStdPkg(named.Obj().Pkg()) || named.TypeParams() != nil {
			return false
		}
		st, isSt := named.Underlying().(*types.Struct)
		if !isSt {
			return false
		}
		ms := types.NewMethodSet(named)
		ptrMS := types.NewMethodSet(types.NewPointer(named))
		if ms.Len() == 0 {
			return false
		}
		returnsOwnPkgNamed := false
		for i := 0; i < ptrMS.Len(); i++ {
			fn, _ := ptrMS.At(i).Obj().(*types.Func)
			sig, _ := ptrMS.At(i).Type().(*types.Signature)
			if fn == nil || sig == nil || fn.Pkg() == nil || isTrueStdPkg(fn.Pkg()) ||
				isScalarCallableVoidMethod(fn, sig, isTrueStdPkg) {
				return false
			}
			if sig.Results().Len() == 1 {
				if rn, okN := types.Unalias(sig.Results().At(0).Type()).(*types.Named); okN && rn.Obj() != nil && rn.Obj().Pkg() == named.Obj().Pkg() {
					returnsOwnPkgNamed = true
				}
			}
		}
		unsafePtrFields := 0
		hasUint64Field := false
		for i := 0; i < st.NumFields(); i++ {
			fld := st.Field(i)
			if fld == nil {
				return false
			}
			ft := fld.Type()
			if b, okB := types.Unalias(ft).Underlying().(*types.Basic); okB && b.Kind() == types.Uint64 && !fld.Exported() {
				hasUint64Field = true
			}
			if !freshalloc.TypeCanCarryExtractedObject(ft) {
				continue
			}
			if !fld.Exported() && syntaxutil.IsUnsafePointerType(ft) {
				unsafePtrFields++
				continue
			}
			if !check(ft) {
				return false
			}
		}
		if unsafePtrFields > 0 {
			return ms.Len() == ptrMS.Len() && unsafePtrFields == 2 && hasUint64Field && returnsOwnPkgNamed
		}
		return true
	}
	return check(root)
}

func classifyReflectCallRootSealLevel(root types.Type, isTrueStdPkg func(*types.Package) bool) uint8 {
	if !typeSealsOutStdlibForReflectCall(root, isTrueStdPkg) {
		return 0
	}
	visiting := map[types.Type]bool{}
	var isLevel2 func(t types.Type) bool
	isLevel2 = func(t types.Type) bool {
		if t == nil {
			return false
		}
		t = types.Unalias(t)
		if visiting[t] {
			return true
		}
		if !typeSealsOutStdlibForReflectCall(t, isTrueStdPkg) {
			return false
		}
		visiting[t] = true
		defer delete(visiting, t)

		if st, isSt := t.Underlying().(*types.Struct); isSt {
			for i := 0; i < st.NumFields(); i++ {
				fld := st.Field(i)
				if fld == nil {
					return false
				}
				ft := fld.Type()
				if !freshalloc.TypeCanCarryExtractedObject(ft) || syntaxutil.IsNamedInPkg(ft, "reflect", "Type") {
					continue
				}
				if syntaxutil.IsUnsafePointerType(ft) || !isLevel2(ft) {
					return false
				}
			}
		}
		ms := types.NewMethodSet(t)
		for i := 0; i < ms.Len(); i++ {
			sig, ok := ms.At(i).Type().(*types.Signature)
			if !ok {
				return false
			}
			for r := 0; r < sig.Results().Len(); r++ {
				resT := sig.Results().At(r).Type()
				if !freshalloc.TypeCanCarryExtractedObject(resT) || syntaxutil.IsNamedInPkg(resT, "reflect", "Type") {
					continue
				}
				if !typeSealsOutStdlibForReflectCall(resT, isTrueStdPkg) {
					return false
				}
			}
		}
		return true
	}
	if isLevel2(root) {
		return 2
	}
	return 1
}

func collectPkgInterfaceMethodNames(p *packages.Package) map[string]bool {
	names := map[string]bool{}
	if p == nil || p.Types == nil || p.TypesInfo == nil {
		return names
	}
	seen := map[types.Type]bool{}
	var scanType func(t types.Type)
	scanType = func(t types.Type) {
		if t == nil {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			scanType(u.Elem())
		case *types.Slice:
			scanType(u.Elem())
		case *types.Array:
			scanType(u.Elem())
		case *types.Chan:
			scanType(u.Elem())
		case *types.Map:
			scanType(u.Key())
			scanType(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				scanType(u.Field(i).Type())
			}
		case *types.Signature:
			for i := 0; i < u.Params().Len(); i++ {
				scanType(u.Params().At(i).Type())
			}
			for i := 0; i < u.Results().Len(); i++ {
				scanType(u.Results().At(i).Type())
			}
		case *types.Tuple:
			for i := 0; i < u.Len(); i++ {
				scanType(u.At(i).Type())
			}
		case *types.Interface:
			for i := 0; i < u.NumMethods(); i++ {
				if m := u.Method(i); m != nil {
					names[m.Name()] = true
					scanType(m.Type())
				}
			}
		}
	}
	for _, tv := range p.TypesInfo.Types {
		scanType(tv.Type)
	}
	for _, obj := range p.TypesInfo.Defs {
		if obj != nil {
			scanType(obj.Type())
		}
	}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		if obj := scope.Lookup(name); obj != nil {
			scanType(obj.Type())
		}
	}
	return names
}

func typeMentionsAnyInterface(root types.Type) bool {
	seen := map[types.Type]bool{}
	hit := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || hit {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		if freshalloc.IsRuntimeInterfaceType(t) {
			hit = true
			return
		}
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			walk(u.Elem())
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Chan:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		case *types.Signature:
			for i := 0; i < u.Params().Len(); i++ {
				walk(u.Params().At(i).Type())
			}
			for i := 0; i < u.Results().Len(); i++ {
				walk(u.Results().At(i).Type())
			}
		case *types.Tuple:
			for i := 0; i < u.Len(); i++ {
				walk(u.At(i).Type())
			}
		}
	}
	walk(root)
	return hit
}

func collectStrictConcreteUnexportedStructs(
	p *packages.Package,
	fc *flowir.PkgCache,
	convertedStructs map[*types.Named]bool,
) map[*types.Named]bool {
	out := map[*types.Named]bool{}
	if p == nil || p.Types == nil || p.TypesInfo == nil || fc == nil {
		return out
	}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok || tn == nil || tn.Exported() || tn.IsAlias() {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok || named == nil || named.TypeParams() != nil || convertedStructs[named.Origin()] {
			continue
		}
		if _, isSt := named.Underlying().(*types.Struct); isSt {
			out[named.Origin()] = true
		}
	}
	if len(out) == 0 {
		return out
	}

	evictInType := func(t types.Type) {
		if t == nil || len(out) == 0 {
			return
		}
		seen := map[types.Type]bool{}
		found := map[*types.Named]bool{}
		freshalloc.RecordNamedStructsInto(t, found, seen)
		for nm := range found {
			delete(out, nm)
		}
	}

	_ = pkgExportedAPIReaches(
		p,
		func(t types.Type) bool {
			evictInType(t)
			return false
		},
		nil,
		func(sig *types.Signature) bool {
			if sig != nil {
				for i := 0; i < sig.Params().Len(); i++ {
					evictInType(sig.Params().At(i).Type())
				}
				for i := 0; i < sig.Results().Len(); i++ {
					evictInType(sig.Results().At(i).Type())
				}
			}
			return false
		},
	)

	seenEmbed := map[types.Type]bool{}
	var scanEmbedded func(t types.Type)
	scanEmbedded = func(t types.Type) {
		if t == nil {
			return
		}
		t = types.Unalias(t)
		if seenEmbed[t] {
			return
		}
		seenEmbed[t] = true
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			scanEmbedded(u.Elem())
		case *types.Slice:
			scanEmbedded(u.Elem())
		case *types.Array:
			scanEmbedded(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				fld := u.Field(i)
				if fld != nil {
					if fld.Embedded() {
						evictInType(fld.Type())
					}
					scanEmbedded(fld.Type())
				}
			}
		}
	}
	for _, tv := range p.TypesInfo.Types {
		scanEmbedded(tv.Type)
	}
	for _, obj := range p.TypesInfo.Defs {
		if obj != nil {
			scanEmbedded(obj.Type())
		}
	}

	fc.ForEachOp(func(enclFn *types.Func, enclLit *ast.FuncLit, _ *flowir.Body, op *flowir.Op) bool {
		if len(out) == 0 {
			return false
		}
		switch op.Kind {
		case flowir.OpAssign:
			if op.AssignKind != flowir.AssignZeroDecl {
				for i, dst := range op.Dsts {
					for j := range dst.Projs {
						pr := &dst.Projs[j]
						if pr.Kind == flowir.ProjIndex && pr.Key != nil && typeMentionsAnyInterface(pr.BaseType) {
							evictInType(pr.Key.Type)
						}
					}
					if !dst.IsBlank() && typeMentionsAnyInterface(dst.Type) {
						if i < len(op.Srcs) && op.Srcs[i] != nil {
							evictInType(op.Srcs[i].Type)
						} else {
							for _, s := range op.Srcs {
								if s != nil {
									evictInType(s.Type)
								}
							}
						}
					}
				}
			}
		case flowir.OpReturn:
			var sig *types.Signature
			if enclLit != nil {
				sig, _ = p.TypesInfo.TypeOf(enclLit).(*types.Signature)
			} else if enclFn != nil {
				sig, _ = enclFn.Type().(*types.Signature)
			}
			if len(op.Results) == 1 && op.Results[0] != nil && sig != nil && sig.Results().Len() > 1 {
				for r := 0; r < sig.Results().Len(); r++ {
					if typeMentionsAnyInterface(sig.Results().At(r).Type()) {
						evictInType(op.Results[0].Type)
						break
					}
				}
			} else {
				for i, res := range op.Results {
					if res == nil {
						continue
					}
					if sig == nil || i >= sig.Results().Len() || typeMentionsAnyInterface(sig.Results().At(i).Type()) {
						evictInType(res.Type)
					}
				}
			}
		case flowir.OpChanSend:
			if op.SendVal != nil {
				chanT := op.ChanPlace.Type
				if chanT == nil && op.ChanVal != nil {
					chanT = op.ChanVal.Type
				}
				if chanT == nil || typeMentionsAnyInterface(chanT) {
					evictInType(op.SendVal.Type)
				}
			}
		}
		op.ForEachValue(func(root *flowir.Value) bool {
			root.WalkValues(func(v *flowir.Value) bool {
				if v == nil || len(out) == 0 {
					return false
				}
				switch v.Kind {
				case flowir.ValAllocFresh:
					if typeMentionsAnyInterface(v.Type) || typeMentionsAnyInterface(v.ElemType) {
						for _, a := range v.Args {
							if a != nil {
								evictInType(a.Type)
							}
						}
						for i := range v.CompositeElts {
							if v.CompositeElts[i].Value != nil {
								evictInType(v.CompositeElts[i].Value.Type)
							}
							if v.CompositeElts[i].MapKey != nil {
								evictInType(v.CompositeElts[i].MapKey.Type)
							}
						}
					}
				case flowir.ValCall:
					if v.CalleeFunc == nil || v.CalleeFunc.Pkg() != p.Types {
						if v.Recv != nil {
							evictInType(v.Recv.Type)
						}
						for _, a := range v.Args {
							if a != nil {
								evictInType(a.Type)
							}
						}
					} else {
						sig := v.CalleeSig
						if sig == nil {
							sig, _ = v.CalleeFunc.Type().(*types.Signature)
						}
						anyIfaceParam := sig == nil || v.IsMethodExprCall ||
							(sig.Recv() != nil && typeMentionsAnyInterface(sig.Recv().Type()))
						if !anyIfaceParam {
							for i := 0; i < sig.Params().Len(); i++ {
								if typeMentionsAnyInterface(sig.Params().At(i).Type()) {
									anyIfaceParam = true
									break
								}
							}
						}
						if anyIfaceParam {
							if v.Recv != nil {
								evictInType(v.Recv.Type)
							}
							for _, a := range v.Args {
								if a != nil {
									evictInType(a.Type)
								}
							}
						}
					}
				}
				return len(out) > 0
			})
			return len(out) > 0
		})
		return len(out) > 0
	})
	return out
}

func isTrivialIndexOperand(idxExpr ast.Expr, info *types.Info) bool {
	if idxExpr == nil || info == nil {
		return false
	}
	idxExpr = ast.Unparen(idxExpr)
	if tv, ok := info.Types[idxExpr]; ok && tv.Value != nil {
		return true
	}
	if id, isID := idxExpr.(*ast.Ident); isID {
		switch info.Uses[id].(type) {
		case *types.Var, *types.Const:
			return true
		}
	}
	return false
}

func exprUnconditionallyIndexesVar(e ast.Expr, target *types.Var, info *types.Info) bool {
	if e == nil || target == nil || info == nil {
		return false
	}
	switch x := ast.Unparen(e).(type) {
	case *ast.IndexExpr:
		if id, isID := ast.Unparen(x.X).(*ast.Ident); isID && info.Uses[id] == target && isTrivialIndexOperand(x.Index, info) {
			return true
		}
		return exprUnconditionallyIndexesVar(x.X, target, info)
	case *ast.SelectorExpr:
		return exprUnconditionallyIndexesVar(x.X, target, info)
	case *ast.TypeAssertExpr:
		return exprUnconditionallyIndexesVar(x.X, target, info)
	case *ast.UnaryExpr:
		if x.Op == token.ARROW {
			return false
		}
		return exprUnconditionallyIndexesVar(x.X, target, info)
	case *ast.CallExpr:
		if tv, ok := info.Types[x.Fun]; ok && tv.IsType() && len(x.Args) == 1 && !x.Ellipsis.IsValid() {
			return exprUnconditionallyIndexesVar(x.Args[0], target, info)
		}
		if sel, isS := ast.Unparen(x.Fun).(*ast.SelectorExpr); isS && info.Selections[sel] != nil {
			return exprUnconditionallyIndexesVar(sel.X, target, info)
		}
	}
	return false
}

func callReturnIsUnconditionallyIndexed(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	call *ast.CallExpr,
	addrOrOuterVars map[*types.Var]bool,
) bool {
	if p == nil || p.TypesInfo == nil || idx == nil || call == nil {
		return false
	}
	par := idx.ParentUnparen(call)
	if ie, isIdx := par.(*ast.IndexExpr); isIdx && ast.Unparen(ie.X) == call {
		return isTrivialIndexOperand(ie.Index, p.TypesInfo)
	}
	as, isAS := par.(*ast.AssignStmt)
	if !isAS || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Rhs[0]) != call {
		return false
	}
	lhsID, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
	if !isID || lhsID.Name == "_" {
		return false
	}
	var outVar *types.Var
	if as.Tok == token.DEFINE {
		outVar, _ = p.TypesInfo.Defs[lhsID].(*types.Var)
	} else if as.Tok == token.ASSIGN {
		outVar, _ = p.TypesInfo.Uses[lhsID].(*types.Var)
	}
	if outVar == nil || outVar.Parent() == p.Types.Scope() || addrOrOuterVars[outVar] {
		return false
	}
	blk, isBlk := idx.ParentMap[as].(*ast.BlockStmt)
	if !isBlk || blk == nil {
		return false
	}
	asIdx := -1
	for i, st := range blk.List {
		if st == as {
			asIdx = i
			break
		}
	}
	if asIdx < 0 {
		return false
	}
	for _, st := range blk.List[asIdx+1:] {
		switch s := st.(type) {
		case *ast.ExprStmt:
			if exprUnconditionallyIndexesVar(s.X, outVar, p.TypesInfo) {
				return true
			}
		case *ast.AssignStmt:
			if len(s.Rhs) > 0 && exprUnconditionallyIndexesVar(s.Rhs[0], outVar, p.TypesInfo) {
				return true
			}
			for _, lhs := range s.Lhs {
				if id, ok := ast.Unparen(lhs).(*ast.Ident); ok && p.TypesInfo.Uses[id] == outVar {
					return false
				}
			}
		case *ast.ReturnStmt:
			if len(s.Results) > 0 && exprUnconditionallyIndexesVar(s.Results[0], outVar, p.TypesInfo) {
				return true
			}
			return false
		case *ast.IfStmt:
			if s.Init == nil && exprUnconditionallyIndexesVar(s.Cond, outVar, p.TypesInfo) {
				return true
			}
			return false
		default:
			return false
		}
	}
	return false
}

func extractReflectInterfaceTypeAssertNarrowing(
	p *packages.Package,
	ifs *ast.IfStmt,
	eligibleLocalRV map[*types.Var]bool,
	sealedParamLevel map[*types.Var]uint8,
	addrOrOuterVars map[*types.Var]bool,
	isTrueStdPkg func(*types.Package) bool,
) (*types.Var, uint8) {
	if p == nil || p.TypesInfo == nil || ifs == nil || ifs.Init == nil || ifs.Cond == nil {
		return nil, 0
	}
	as, isAS := ifs.Init.(*ast.AssignStmt)
	if !isAS || as.Tok != token.DEFINE || len(as.Lhs) != 2 || len(as.Rhs) != 1 {
		return nil, 0
	}
	okID, isOKID := ast.Unparen(as.Lhs[1]).(*ast.Ident)
	condID, isCondID := ast.Unparen(ifs.Cond).(*ast.Ident)
	if !isOKID || !isCondID {
		return nil, 0
	}
	okVar, _ := p.TypesInfo.Defs[okID].(*types.Var)
	if okVar == nil || addrOrOuterVars[okVar] || p.TypesInfo.Uses[condID] != okVar {
		return nil, 0
	}
	ta, isTA := ast.Unparen(as.Rhs[0]).(*ast.TypeAssertExpr)
	if !isTA || ta.Type == nil {
		return nil, 0
	}
	assertedT := p.TypesInfo.TypeOf(ta.Type)
	if freshalloc.IsRuntimeInterfaceType(assertedT) {
		return nil, 0
	}
	lv := classifyReflectCallRootSealLevel(assertedT, isTrueStdPkg)
	if lv == 0 {
		return nil, 0
	}
	icall, isCall := ast.Unparen(ta.X).(*ast.CallExpr)
	if !isCall || len(icall.Args) != 0 || icall.Ellipsis.IsValid() {
		return nil, 0
	}
	callee := syntaxutil.ResolveCalledFuncObj(p, icall.Fun)
	if callee == nil || !isTrueStdPkg(callee.Pkg()) || callee.Pkg().Path() != "reflect" || callee.Name() != "Interface" {
		return nil, 0
	}
	sel, isSel := ast.Unparen(icall.Fun).(*ast.SelectorExpr)
	if !isSel {
		return nil, 0
	}
	if sInfo := p.TypesInfo.Selections[sel]; sInfo == nil || sInfo.Kind() != types.MethodVal {
		return nil, 0
	}
	rvID, isRVID := ast.Unparen(sel.X).(*ast.Ident)
	if !isRVID {
		return nil, 0
	}
	rvVar, _ := p.TypesInfo.Uses[rvID].(*types.Var)
	if rvVar == nil || addrOrOuterVars[rvVar] || (!eligibleLocalRV[rvVar] && sealedParamLevel[rvVar] == 0) {
		return nil, 0
	}
	if valID, isValID := ast.Unparen(as.Lhs[0]).(*ast.Ident); isValID && valID.Name != "_" {
		if p.TypesInfo.Defs[valID] == rvVar || p.TypesInfo.Uses[valID] == rvVar {
			return nil, 0
		}
	} else if !isValID {
		return nil, 0
	}
	return rvVar, lv
}
