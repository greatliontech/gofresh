package structmut

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func typeContainsAnyInterface(root types.Type) bool {
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
		switch u := t.Underlying().(type) {
		case *types.Interface:
			hit = true
		case *types.Pointer:
			walk(u.Elem())
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Chan:
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
		}
	}
	walk(root)
	return hit
}

func exprCarriesNonFreshInterface(p *packages.Package, expr ast.Expr) bool {
	if p == nil || p.TypesInfo == nil || expr == nil {
		return false
	}
	expr = ast.Unparen(expr)
	if syntaxutil.IsNilIdent(p.TypesInfo, expr) || syntaxutil.IsTypedNilSliceConv(p, expr) {
		return false
	}
	if !typeContainsAnyInterface(p.TypesInfo.TypeOf(expr)) {
		return false
	}
	switch e := expr.(type) {
	case *ast.CompositeLit:
		_, isStructComp := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(e)).(*types.Struct)
		for _, elt := range e.Elts {
			val := elt
			if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
				if !isStructComp && exprCarriesNonFreshInterface(p, kv.Key) {
					return true
				}
				val = kv.Value
			}
			if exprCarriesNonFreshInterface(p, val) {
				return true
			}
		}
		return false
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			if cl, ok := ast.Unparen(e.X).(*ast.CompositeLit); ok {
				return exprCarriesNonFreshInterface(p, cl)
			}
		}
	case *ast.CallExpr:
		if syntaxutil.IsBuiltinNewType(p.TypesInfo, e) {
			return false
		}
		if id, ok := ast.Unparen(e.Fun).(*ast.Ident); ok {
			if b, isB := p.TypesInfo.Uses[id].(*types.Builtin); isB && b.Name() == "make" {
				return false
			}
		}
		tv := p.TypesInfo.Types[ast.Unparen(e.Fun)]
		if tv.IsType() && len(e.Args) == 1 && syntaxutil.IsNilIdent(p.TypesInfo, e.Args[0]) {
			return false
		}
	}
	return true
}

func containsUnsafePointerWithOpaqueOwner(curPkg *types.Package, root types.Type) (bool, string) {
	return walkCarrierLeafWithOpaqueOwner(curPkg, root, func(t types.Type) bool {
		b, ok := t.Underlying().(*types.Basic)
		return ok && b.Kind() == types.UnsafePointer
	})
}

func typeMentionsEmptyIfaceWithOpaqueOwner(curPkg *types.Package, root types.Type) (bool, string) {
	return walkCarrierLeafWithOpaqueOwner(curPkg, root, func(t types.Type) bool {
		if syntaxutil.IsNamedInPkg(t, "reflect", "Type") {
			return false
		}
		iface, ok := t.Underlying().(*types.Interface)
		return ok && iface.NumMethods() == 0
	})
}

func walkCarrierLeafWithOpaqueOwner(curPkg *types.Package, root types.Type, isLeaf func(types.Type) bool) (bool, string) {
	type visitKey struct {
		t              types.Type
		opaqueOwnerPkg string
	}
	seen := map[visitKey]bool{}
	sawHit := false
	sawUnowned := false
	singleOwner := ""
	recordOwner := func(owner string) {
		sawHit = true
		if owner == "" {
			sawUnowned = true
			return
		}
		if singleOwner == "" {
			singleOwner = owner
		} else if singleOwner != owner {
			sawUnowned = true
		}
	}
	var walk func(t types.Type, owner string)
	walk = func(t types.Type, owner string) {
		if t == nil {
			return
		}
		t = types.Unalias(t)
		if syntaxutil.IsNamedInPkg(t, "reflect", "Type") {
			return
		}
		if isLeaf(t) {
			recordOwner(owner)
			return
		}
		vk := visitKey{t: t, opaqueOwnerPkg: owner}
		if seen[vk] {
			return
		}
		seen[vk] = true
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			walk(u.Elem(), owner)
		case *types.Slice:
			walk(u.Elem(), owner)
		case *types.Array:
			walk(u.Elem(), owner)
		case *types.Map:
			walk(u.Key(), owner)
			walk(u.Elem(), owner)
		case *types.Chan:
			walk(u.Elem(), owner)
		case *types.Signature:
			for i := 0; i < u.Params().Len(); i++ {
				walk(u.Params().At(i).Type(), owner)
			}
			for i := 0; i < u.Results().Len(); i++ {
				walk(u.Results().At(i).Type(), owner)
			}
		case *types.Struct:
			tNamed, isTN := t.(*types.Named)
			isOpaqueForeign := false
			if isTN && curPkg != nil && tNamed.Obj() != nil && tNamed.Obj().Pkg() != nil && tNamed.Obj().Pkg() != curPkg {
				isOpaqueForeign = true
				for si := 0; si < u.NumFields(); si++ {
					sf := u.Field(si)
					if sf.Exported() && !(sf.Embedded() && isZeroSizedPaddingType(sf.Type())) {
						isOpaqueForeign = false
						break
					}
				}
			}
			for i := 0; i < u.NumFields(); i++ {
				f := u.Field(i)
				nextOwner := owner
				if nextOwner == "" && isOpaqueForeign && !f.Exported() && !f.Embedded() && f.Pkg() == tNamed.Obj().Pkg() {
					nextOwner = f.Pkg().Path()
				}
				walk(f.Type(), nextOwner)
			}
		}
	}
	walk(root, "")
	if !sawHit {
		return false, ""
	}
	if sawUnowned {
		return true, ""
	}
	return true, singleOwner
}

func forEachNestedNonEmptyIface(root types.Type, includeUnexportedFields bool, exemptReadFields, foreignReflectFields map[*types.Var]bool, exemptFam map[*types.Named]bool, visit func(*types.Interface)) {
	forEachNestedNonEmptyIfaceWithGuard(nil, root, includeUnexportedFields, exemptReadFields, foreignReflectFields, exemptFam, func(iface *types.Interface, _ syntaxutil.TypeRef) {
		visit(iface)
	})
}

func forEachNestedNonEmptyIfaceWithGuard(curPkg *types.Package, root types.Type, includeUnexportedFields bool, exemptReadFields, foreignReflectFields map[*types.Var]bool, exemptFam map[*types.Named]bool, visit func(*types.Interface, syntaxutil.TypeRef)) {
	type visitKey struct {
		t                 types.Type
		opaqueGuardStruct syntaxutil.TypeRef
	}
	seen := map[visitKey]bool{}
	var walk func(t types.Type, opaqueGuardStruct syntaxutil.TypeRef)
	walk = func(t types.Type, opaqueGuardStruct syntaxutil.TypeRef) {
		if t == nil {
			return
		}
		t = types.Unalias(t)
		if syntaxutil.IsNamedInPkg(t, "reflect", "Type") {
			return
		}
		if named, isN := t.(*types.Named); isN && exemptFam[named] {
			return
		}
		vk := visitKey{t: t, opaqueGuardStruct: opaqueGuardStruct}
		if seen[vk] {
			return
		}
		seen[vk] = true
		switch u := t.Underlying().(type) {
		case *types.Interface:
			if u.NumMethods() > 0 {
				visit(u, opaqueGuardStruct)
			}
		case *types.Pointer:
			walk(u.Elem(), opaqueGuardStruct)
		case *types.Slice:
			walk(u.Elem(), opaqueGuardStruct)
		case *types.Array:
			walk(u.Elem(), opaqueGuardStruct)
		case *types.Map:
			walk(u.Key(), opaqueGuardStruct)
			walk(u.Elem(), opaqueGuardStruct)
		case *types.Chan:
			walk(u.Elem(), opaqueGuardStruct)
		case *types.Struct:
			tNamed, isTN := t.(*types.Named)
			isOpaqueForeign := false
			if isTN && curPkg != nil && tNamed.Obj() != nil && tNamed.Obj().Pkg() != nil && tNamed.Obj().Pkg() != curPkg {
				isOpaqueForeign = true
				for si := 0; si < u.NumFields(); si++ {
					sf := u.Field(si)
					if sf.Exported() && !(sf.Embedded() && isZeroSizedPaddingType(sf.Type())) {
						isOpaqueForeign = false
						break
					}
				}
			}
			for i := 0; i < u.NumFields(); i++ {
				f := u.Field(i)
				if exemptReadFields[f] || foreignReflectFields[f] {
					continue
				}
				if !includeUnexportedFields && !f.Exported() && !f.Embedded() {
					continue
				}
				nextGuard := opaqueGuardStruct
				if isTN && curPkg != nil && tNamed.Obj() != nil && tNamed.Obj().Pkg() != nil &&
					tNamed.Obj().Pkg() != curPkg && !f.Exported() && !f.Embedded() && f.Pkg() == tNamed.Obj().Pkg() {
					var ptrElemGuard syntaxutil.TypeRef
					if isOpaqueForeign {
						if fPtr, isFP := types.Unalias(f.Type()).(*types.Pointer); isFP {
							if elemN, isEN := types.Unalias(fPtr.Elem()).(*types.Named); isEN && elemN.Obj() != nil && elemN.Obj().Pkg() == f.Pkg() {
								if _, isSt := elemN.Underlying().(*types.Struct); isSt {
									cand := syntaxutil.TypeRef{Pkg: f.Pkg().Path(), Name: elemN.Obj().Name()}
									if cand.Valid() {
										ptrElemGuard = cand
									}
								}
							}
						}
					}
					if !ptrElemGuard.IsZero() {
						nextGuard = ptrElemGuard
					} else if nextGuard.IsZero() || nextGuard.Pkg != f.Pkg().Path() {
						cand := syntaxutil.TypeRef{Pkg: f.Pkg().Path(), Name: tNamed.Obj().Name()}
						if cand.Valid() {
							nextGuard = cand
						}
					}
				}
				walk(f.Type(), nextGuard)
			}
		}
	}
	walk(root, syntaxutil.TypeRef{})
}

func collectTypeDispatchOnlyAnyParams(p *packages.Package, idx *refconfine.PkgIndex) map[*types.Var]bool {
	out := map[*types.Var]bool{}
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil {
		return out
	}
	isSafeAnyReadOnlyCall := func(call *ast.CallExpr, uid *ast.Ident) bool {
		if ast.Unparen(call.Fun) == uid || call.Ellipsis.IsValid() {
			return false
		}
		callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
		if !syntaxutil.IsReadOnlyEmptyInterfaceCallee(p, callee) {
			return false
		}
		argIdx := -1
		for i, a := range call.Args {
			if ast.Unparen(a) == uid {
				argIdx = i
				break
			}
		}
		if argIdx < 0 {
			return false
		}
		argT := p.TypesInfo.TypeOf(uid)
		return !callMayWrapErrorOperand(p, call, callee, argIdx, argT) &&
			!callMayFormatPointerIdentity(p, call, callee, argIdx, argT)
	}
	isReadOnlyAnyVar := func(v *types.Var) bool {
		if v == nil || idx.DefCounts[v] > 1 {
			return false
		}
		for _, uid := range idx.UsesOf[v] {
			if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
				return false
			}
			switch par := idx.ParentUnparen(uid).(type) {
			case *ast.BinaryExpr:
				if par.Op != token.EQL && par.Op != token.NEQ {
					return false
				}
				other := par.Y
				if ast.Unparen(par.Y) == uid {
					other = par.X
				}
				if !syntaxutil.IsNilIdent(p.TypesInfo, other) {
					return false
				}
			case *ast.CallExpr:
				if !isSafeAnyReadOnlyCall(par, uid) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	isTypeDispatchOnlyParam := func(fd *ast.FuncDecl, pv *types.Var) bool {
		if fd == nil || fd.Body == nil || pv == nil || idx.DefCounts[pv] != 1 {
			return false
		}
		for _, uid := range idx.UsesOf[pv] {
			if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
				return false
			}
			switch par := idx.ParentUnparen(uid).(type) {
			case *ast.BinaryExpr:
				if par.Op != token.EQL && par.Op != token.NEQ {
					return false
				}
				other := par.Y
				if ast.Unparen(par.Y) == uid {
					other = par.X
				}
				if !syntaxutil.IsNilIdent(p.TypesInfo, other) {
					return false
				}
			case *ast.CallExpr:
				if !isSafeAnyReadOnlyCall(par, uid) {
					return false
				}
			case *ast.TypeAssertExpr:
				if ast.Unparen(par.X) != uid {
					return false
				}
				if par.Type != nil {
					taT := p.TypesInfo.TypeOf(par.Type)
					if taT == nil || isEmptyInterfaceType(taT) {
						return false
					}
					continue
				}
				parStmt := idx.ParentUnparen(par)
				var ts *ast.TypeSwitchStmt
				switch ps := parStmt.(type) {
				case *ast.ExprStmt:
					ts, _ = idx.ParentUnparen(ps).(*ast.TypeSwitchStmt)
				case *ast.AssignStmt:
					if ps.Tok != token.DEFINE || len(ps.Lhs) != 1 || len(ps.Rhs) != 1 || ast.Unparen(ps.Rhs[0]) != par {
						return false
					}
					ts, _ = idx.ParentUnparen(ps).(*ast.TypeSwitchStmt)
					if lid, isID := ast.Unparen(ps.Lhs[0]).(*ast.Ident); isID {
						if defV, _ := p.TypesInfo.Defs[lid].(*types.Var); defV != nil && !isReadOnlyAnyVar(defV) {
							return false
						}
					}
				}
				if ts == nil || ts.Assign != parStmt || ts.Body == nil {
					return false
				}
				for _, raw := range ts.Body.List {
					cc, okCC := raw.(*ast.CaseClause)
					if !okCC {
						continue
					}
					for _, ct := range cc.List {
						if syntaxutil.IsNilIdent(p.TypesInfo, ct) {
							continue
						}
						ctT := p.TypesInfo.TypeOf(ct)
						if ctT == nil || isEmptyInterfaceType(ctT) {
							return false
						}
					}
					if impV, _ := p.TypesInfo.Implicits[cc].(*types.Var); impV != nil && isEmptyInterfaceType(impV.Type()) {
						if !isReadOnlyAnyVar(impV) {
							return false
						}
					}
				}
			default:
				return false
			}
		}
		return true
	}
	for fn, fd := range idx.FuncDecls {
		if fn == nil || fd == nil || fd.Body == nil || fn.Pkg() != p.Types {
			continue
		}
		sig, okS := fn.Type().(*types.Signature)
		if !okS || sig.TypeParams().Len() > 0 || sig.RecvTypeParams().Len() > 0 {
			continue
		}
		if sig.Recv() != nil && types.IsInterface(sig.Recv().Type()) {
			continue
		}
		limit := sig.Params().Len()
		if sig.Variadic() {
			limit--
		}
		for i := 0; i < limit; i++ {
			pv := sig.Params().At(i)
			if pv != nil && isEmptyInterfaceType(pv.Type()) {
				if isTypeDispatchOnlyParam(fd, pv) {
					out[pv] = true
				}
			}
		}
	}
	return out
}

func sigMentionsReflectTypeParam(fn *types.Func) bool {
	if fn == nil {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() != nil {
		return false
	}
	for i := 0; i < sig.Params().Len(); i++ {
		pt := sig.Params().At(i).Type()
		if sig.Variadic() && i == sig.Params().Len()-1 {
			if sl, isSl := types.Unalias(pt).Underlying().(*types.Slice); isSl {
				pt = sl.Elem()
			}
		}
		if syntaxutil.IsNamedInPkg(pt, "reflect", "Type") {
			return true
		}
	}
	return false
}

func typeImplementsPureStringerOrError(p *packages.Package, t types.Type) bool {
	if t == nil || isEmptyInterfaceType(t) {
		return false
	}
	mset := types.NewMethodSet(t)
	hasStringOrError := false
	for i := 0; i < mset.Len(); i++ {
		fn, _ := mset.At(i).Obj().(*types.Func)
		if fn == nil || !fn.Exported() {
			continue
		}
		sig, okS := mset.At(i).Type().(*types.Signature)
		if !okS {
			continue
		}
		if fn.Name() == "Format" && sig.Params().Len() == 2 && sig.Results().Len() == 0 &&
			syntaxutil.IsNamedInPkg(sig.Params().At(0).Type(), "fmt", "State") {
			return false
		}
		if (fn.Name() == "String" || fn.Name() == "Error") && sig.Params().Len() == 0 && sig.Results().Len() == 1 {
			if b, isB := types.Unalias(sig.Results().At(0).Type()).(*types.Basic); isB && b.Kind() == types.String {
				hasStringOrError = true
			}
		}
	}
	return hasStringOrError && (p == nil || syntaxutil.IsTrueStdlibInPkg(p, "fmt"))
}

func isNamedInPkgPath(t types.Type, pkgPath string) bool {
	if t == nil || pkgPath == "" {
		return false
	}
	n, ok := types.Unalias(t).(*types.Named)
	return ok && n.Obj() != nil && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == pkgPath
}

func unwrapSealedPkgIface(t types.Type, pkg *types.Package) *types.Interface {
	if t == nil || pkg == nil {
		return nil
	}
	for {
		t = types.Unalias(t)
		arr, isArr := t.Underlying().(*types.Array)
		if !isArr {
			break
		}
		t = arr.Elem()
	}
	named, isN := t.(*types.Named)
	if !isN || named.Obj() == nil || named.Obj().Exported() || named.Obj().Pkg() != pkg {
		return nil
	}
	iface, isIf := named.Underlying().(*types.Interface)
	if !isIf || iface.NumMethods() == 0 {
		return nil
	}
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		if m != nil && !m.Exported() && m.Pkg() == pkg {
			return iface
		}
	}
	return nil
}

func ifaceOrArrayElemIsPkgSealed(t types.Type, p *packages.Package, capPkgPath string) bool {
	if p == nil || p.Types == nil || p.TypesInfo == nil {
		return false
	}
	iface := unwrapSealedPkgIface(t, p.Types)
	if iface == nil {
		return false
	}
	for _, obj := range p.TypesInfo.Defs {
		tn, isTN := obj.(*types.TypeName)
		if !isTN || tn == nil || tn.IsAlias() {
			continue
		}
		nt := tn.Type()
		if _, isIf := nt.Underlying().(*types.Interface); isIf {
			continue
		}
		if !types.Implements(nt, iface) && !types.Implements(types.NewPointer(nt), iface) {
			continue
		}
		if _, isSt := nt.Underlying().(*types.Struct); !isSt {
			return false
		}
		hasCapStruct := false
		syntaxutil.ForEachValueContainedStructType(nt, func(vt types.Type) {
			if isNamedInPkgPath(vt, capPkgPath) {
				hasCapStruct = true
			}
		})
		if hasCapStruct {
			return false
		}
	}
	return true
}

func sealedPkgIfaceImplementorStructs(t types.Type, p *packages.Package, capPkgPath string) []types.Type {
	if p == nil || p.Types == nil || p.TypesInfo == nil {
		return nil
	}
	iface := unwrapSealedPkgIface(t, p.Types)
	if iface == nil {
		return nil
	}
	var out []types.Type
	seen := map[types.Type]bool{}
	for _, obj := range p.TypesInfo.Defs {
		tn, isTN := obj.(*types.TypeName)
		if !isTN || tn == nil || tn.IsAlias() {
			continue
		}
		nt := types.Unalias(tn.Type())
		if seen[nt] {
			continue
		}
		if _, isSt := nt.Underlying().(*types.Struct); !isSt {
			continue
		}
		if !types.Implements(nt, iface) && !types.Implements(types.NewPointer(nt), iface) {
			continue
		}
		hasCapStruct := false
		syntaxutil.ForEachValueContainedStructType(nt, func(vt types.Type) {
			if isNamedInPkgPath(vt, capPkgPath) {
				hasCapStruct = true
			}
		})
		if !hasCapStruct {
			seen[nt] = true
			out = append(out, nt)
		}
	}
	return out
}

func callMayWrapErrorOperand(p *packages.Package, call *ast.CallExpr, callee *types.Func, argIdx int, argT types.Type) bool {
	if p == nil || p.TypesInfo == nil || call == nil || callee == nil || callee.Pkg() == nil || argT == nil {
		return false
	}
	if callee.Pkg().Path() != "fmt" || callee.Name() != "Errorf" || argIdx < 1 || len(call.Args) == 0 {
		return false
	}
	errObj := types.Universe.Lookup("error")
	if errObj == nil || (!types.IsInterface(argT) && !types.AssignableTo(argT, errObj.Type())) {
		return false
	}
	if len(call.Args) == 1 {
		return true
	}
	tvFmt := p.TypesInfo.Types[call.Args[0]]
	if tvFmt.Value == nil || tvFmt.Value.Kind() != constant.String {
		return true
	}
	fmtStr := constant.StringVal(tvFmt.Value)
	var directives []auditset.FmtDirective
	hasIdxOrDyn := false
	hasWrap := false
	scanOK := auditset.ScanFmtDirectives(fmtStr, func(d auditset.FmtDirective) bool {
		if d.HasArgIndex || d.DynamicWidth || d.DynamicPrec {
			hasIdxOrDyn = true
		}
		if d.Verb == 'w' {
			hasWrap = true
		}
		directives = append(directives, d)
		return true
	})
	if !scanOK {
		return true
	}
	if !hasWrap {
		return false
	}
	if !hasIdxOrDyn && !call.Ellipsis.IsValid() {
		ord := argIdx - 1
		return ord >= 0 && ord < len(directives) && directives[ord].Verb == 'w'
	}
	return true
}

func callMayFormatPointerIdentity(p *packages.Package, call *ast.CallExpr, callee *types.Func, argIdx int, argT types.Type) bool {
	if p == nil || p.TypesInfo == nil || call == nil || callee == nil || callee.Pkg() == nil || argT == nil {
		return false
	}
	if syntaxutil.IsNamedInPkg(argT, "reflect", "Type") || !refconfine.TypeContainsRefOrPointer(argT) {
		return false
	}
	switch callee.Pkg().Path() {
	case "runtime", "reflect":
		return false
	case "log", "testing":
		return true
	case "fmt":
		isStringer := typeImplementsPureStringerOrError(p, argT)
		fmtArgIdx := -1
		switch callee.Name() {
		case "Sprintf", "Printf", "Errorf":
			fmtArgIdx = 0
		case "Fprintf", "Appendf":
			fmtArgIdx = 1
		case "Sprint", "Sprintln", "Print", "Println", "Fprint", "Fprintln", "Append", "Appendln":
			return call.Ellipsis.IsValid() || !isStringer
		default:
			return true
		}
		if argIdx <= fmtArgIdx || fmtArgIdx >= len(call.Args) {
			return false
		}
		tvFmt := p.TypesInfo.Types[call.Args[fmtArgIdx]]
		if tvFmt.Value == nil || tvFmt.Value.Kind() != constant.String {
			return true
		}
		fmtStr := constant.StringVal(tvFmt.Value)
		var directives []auditset.FmtDirective
		hasIdxOrDyn := false
		scanOK := auditset.ScanFmtDirectives(fmtStr, func(d auditset.FmtDirective) bool {
			if d.HasArgIndex || d.DynamicWidth || d.DynamicPrec {
				hasIdxOrDyn = true
			}
			directives = append(directives, d)
			return true
		})
		if !scanOK {
			return true
		}
		directiveSafe := func(d auditset.FmtDirective) bool {
			if !d.Sharp && d.Verb == 'T' {
				return true
			}
			return isStringer && d.InvokesStringerOnly()
		}
		if !hasIdxOrDyn && !call.Ellipsis.IsValid() {
			ord := argIdx - (fmtArgIdx + 1)
			if ord >= 0 && ord < len(directives) {
				return !directiveSafe(directives[ord])
			}
			return !isStringer
		}
		if !isStringer {
			return true
		}
		for _, d := range directives {
			if !directiveSafe(d) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func isCurrentPkgPrivateAnyDest(p *packages.Package, lhs ast.Expr, funcParamVars map[*types.Var]bool) bool {
	return isCurrentPkgPrivateDestWithMode(p, lhs, funcParamVars, false)
}

func isCurrentPkgPrivateSliceMutDest(p *packages.Package, dst ast.Expr, funcParamVars map[*types.Var]bool) bool {
	return isCurrentPkgPrivateDestWithMode(p, dst, funcParamVars, true)
}

func isCurrentPkgPrivateDestWithMode(p *packages.Package, lhs ast.Expr, funcParamVars map[*types.Var]bool, initialContainerProj bool) bool {
	if p == nil || p.Types == nil || p.TypesInfo == nil || lhs == nil {
		return false
	}
	cur := ast.Unparen(lhs)
	hasContainerProj := initialContainerProj
	hasExportedFieldProj := false
	for {
		switch e := cur.(type) {
		case *ast.IndexExpr:
			hasContainerProj = true
			cur = ast.Unparen(e.X)
		case *ast.SliceExpr:
			hasContainerProj = true
			cur = ast.Unparen(e.X)
		case *ast.SelectorExpr:
			if selInfo := p.TypesInfo.Selections[e]; selInfo != nil && selInfo.Kind() == types.FieldVal {
				fld, _ := selInfo.Obj().(*types.Var)
				if fld == nil || fld.Pkg() != p.Types {
					return false
				}
				if !hasExportedFieldProj && !fld.Exported() && !fld.Embedded() {
					return true
				}
				if selInfo.Indirect() {
					return false
				}
				hasExportedFieldProj = true
				cur = ast.Unparen(e.X)
				continue
			}
			v, _ := p.TypesInfo.Uses[e.Sel].(*types.Var)
			return v != nil && !v.IsField() && v.Pkg() == p.Types && !v.Exported()
		case *ast.Ident:
			v, _ := p.TypesInfo.Uses[e].(*types.Var)
			if v == nil {
				v, _ = p.TypesInfo.Defs[e].(*types.Var)
			}
			if v == nil || v.Pkg() != p.Types {
				return false
			}
			if v.Parent() == p.Types.Scope() {
				return !v.Exported()
			}
			if hasContainerProj || hasExportedFieldProj {
				return !funcParamVars[v]
			}
			return true
		default:
			return false
		}
	}
}

func sigMentionsSpecificTypeParam(sig *types.Signature, target *types.TypeParam) bool {
	if sig == nil || target == nil {
		return false
	}
	seen := map[types.Type]bool{}
	found := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || found {
			return
		}
		t = types.Unalias(t)
		if t == target {
			found = true
			return
		}
		if seen[t] {
			return
		}
		seen[t] = true
		if named, isN := t.(*types.Named); isN && named.TypeArgs() != nil {
			for i := 0; i < named.TypeArgs().Len(); i++ {
				walk(named.TypeArgs().At(i))
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			walk(u.Elem())
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Chan:
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
		case *types.Interface:
			for i := 0; i < u.NumMethods(); i++ {
				walk(u.Method(i).Type())
			}
		}
	}
	for i := 0; i < sig.Params().Len(); i++ {
		walk(sig.Params().At(i).Type())
	}
	for i := 0; i < sig.Results().Len(); i++ {
		walk(sig.Results().At(i).Type())
	}
	return found
}
