package structmut

import (
	"go/ast"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshalloc"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func collectTypeAssertedSyncMaps(p *packages.Package, idx *refconfine.PkgIndex) (map[*types.Var]bool, map[*types.Var]bool) {
	out := map[*types.Var]bool{}
	outFields := map[*types.Var]bool{}
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || !syntaxutil.IsTrueStdlibInPkg(p, "sync") {
		return out, outFields
	}
	verifySyncMapRecvExpr := func(recvExpr ast.Expr, storedIfaces, assertedIfaces *[]*types.Interface) bool {
		sel, isSel := idx.ParentUnparen(recvExpr).(*ast.SelectorExpr)
		if !isSel || ast.Unparen(sel.X) != recvExpr || sel.Sel == nil {
			return false
		}
		call, isCall := idx.ParentUnparen(sel).(*ast.CallExpr)
		if !isCall || ast.Unparen(call.Fun) != sel || call.Ellipsis.IsValid() {
			return false
		}
		recordStoredIface := func(vt types.Type) {
			if vt == nil || syntaxutil.IsNamedInPkg(vt, "reflect", "Type") {
				return
			}
			if sif, isIf := syntaxutil.UnderlyingType(vt).(*types.Interface); isIf {
				*storedIfaces = append(*storedIfaces, sif)
			}
		}
		recordAssertedIface := func(taT types.Type) {
			if taT == nil || syntaxutil.IsNamedInPkg(taT, "reflect", "Type") {
				return
			}
			if aif, isIf := syntaxutil.UnderlyingType(taT).(*types.Interface); isIf {
				*assertedIfaces = append(*assertedIfaces, aif)
			}
		}
		switch sel.Sel.Name {
		case "Delete":
			return isExprStmtNode(idx.ParentUnparen(call))
		case "Store":
			if !isExprStmtNode(idx.ParentUnparen(call)) || len(call.Args) != 2 {
				return false
			}
			vt := p.TypesInfo.TypeOf(call.Args[1])
			if isEmptyInterfaceType(vt) {
				return false
			}
			recordStoredIface(vt)
			return true
		case "Load", "LoadOrStore":
			if sel.Sel.Name == "LoadOrStore" {
				if len(call.Args) != 2 {
					return false
				}
				vt := p.TypesInfo.TypeOf(call.Args[1])
				if isEmptyInterfaceType(vt) {
					return false
				}
				recordStoredIface(vt)
			}
			as, isAS := idx.ParentUnparen(call).(*ast.AssignStmt)
			if !isAS || len(as.Lhs) != 2 || len(as.Rhs) != 1 || ast.Unparen(as.Rhs[0]) != call {
				return false
			}
			lhs0, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
			if !isID {
				return false
			}
			if lhs0.Name == "_" {
				return true
			}
			if as.Tok != token.DEFINE {
				return false
			}
			resVar, okDef := p.TypesInfo.Defs[lhs0].(*types.Var)
			if !okDef || resVar == nil || idx.DefCounts[resVar] != 1 {
				return false
			}
			for _, ruid := range idx.UsesOf[resVar] {
				ta, isTA := idx.ParentUnparen(ruid).(*ast.TypeAssertExpr)
				if !isTA || ast.Unparen(ta.X) != ruid || ta.Type == nil {
					return false
				}
				taT := p.TypesInfo.TypeOf(ta.Type)
				if taT == nil || isEmptyInterfaceType(taT) {
					return false
				}
				recordAssertedIface(taT)
			}
			return true
		default:
			return false
		}
	}
	ifacesPreserveSubsets := func(storedIfaces, assertedIfaces []*types.Interface) bool {
		for _, sif := range storedIfaces {
			sk := syntaxutil.IfaceMethodSetKey(sif)
			if sk == "" {
				return false
			}
			for _, aif := range assertedIfaces {
				if !syntaxutil.MethodSetSubset(syntaxutil.IfaceMethodSetKey(aif), sk) {
					return false
				}
			}
		}
		return true
	}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		v, ok := scope.Lookup(name).(*types.Var)
		if !ok || v == nil || v.Exported() || idx.DefCounts[v] != 1 || !syntaxutil.IsNamedInPkg(v.Type(), "sync", "Map") {
			continue
		}
		vs := idx.VarSpecs[v]
		if vs == nil {
			continue
		}
		if len(vs.Values) > 0 {
			if len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			cl, isCL := ast.Unparen(vs.Values[0]).(*ast.CompositeLit)
			if !isCL || len(cl.Elts) != 0 {
				continue
			}
		}
		uses := idx.UsesOf[v]
		if len(uses) == 0 {
			continue
		}
		clean := true
		var storedIfaces, assertedIfaces []*types.Interface
		for _, uid := range uses {
			if !verifySyncMapRecvExpr(uid, &storedIfaces, &assertedIfaces) {
				clean = false
				break
			}
		}
		if clean && ifacesPreserveSubsets(storedIfaces, assertedIfaces) {
			out[v] = true
		}
	}
	unkeyedLitStructs := map[*types.Named]bool{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			cl, isCL := n.(*ast.CompositeLit)
			if !isCL || len(cl.Elts) == 0 {
				return true
			}
			if _, isKV := cl.Elts[0].(*ast.KeyValueExpr); isKV {
				return true
			}
			if named := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(cl)); named != nil {
				unkeyedLitStructs[named] = true
			}
			return true
		})
	}
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok || tn == nil || tn.Exported() || tn.IsAlias() {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok || named == nil || named.TypeParams() != nil || unkeyedLitStructs[named] {
			continue
		}
		st, isSt := named.Underlying().(*types.Struct)
		if !isSt {
			continue
		}
		for fi := 0; fi < st.NumFields(); fi++ {
			f := st.Field(fi)
			if f.Exported() || f.Embedded() || !syntaxutil.IsNamedInPkg(f.Type(), "sync", "Map") {
				continue
			}
			uses := idx.UsesOf[f]
			if len(uses) == 0 {
				continue
			}
			clean := true
			var storedIfaces, assertedIfaces []*types.Interface
			for _, uid := range uses {
				recvSel, isRS := idx.ParentMap[uid].(*ast.SelectorExpr)
				if !isRS || recvSel.Sel != uid {
					clean = false
					break
				}
				fInfo := p.TypesInfo.Selections[recvSel]
				if fInfo == nil || fInfo.Kind() != types.FieldVal || len(fInfo.Index()) != 1 {
					clean = false
					break
				}
				if !verifySyncMapRecvExpr(recvSel, &storedIfaces, &assertedIfaces) {
					clean = false
					break
				}
			}
			if clean && ifacesPreserveSubsets(storedIfaces, assertedIfaces) {
				outFields[f] = true
			}
		}
	}
	return out, outFields
}

func isExprStmtNode(n ast.Node) bool {
	_, ok := n.(*ast.ExprStmt)
	return ok
}

func collectConfinedContextKeyTypes(p *packages.Package, idx *refconfine.PkgIndex) (map[*types.Named]bool, map[*types.Named]bool, map[*types.Named]bool) {
	out := map[*types.Named]bool{}
	hasLookup := map[*types.Named]bool{}
	mismatchedIface := map[*types.Named]bool{}
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || !syntaxutil.IsTrueStdlibInPkg(p, "context") {
		return out, hasLookup, mismatchedIface
	}
	cands := map[*types.Named]*types.TypeName{}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok || tn == nil || tn.Exported() || tn.IsAlias() {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok || named == nil || named.TypeParams() != nil || !types.Comparable(named) ||
			refconfine.TypeContainsRefOrPointer(named) || syntaxutil.ContainsUintptr(named) {
			continue
		}
		cands[named] = tn
	}
	if len(cands) == 0 {
		return out, hasLookup, mismatchedIface
	}

	ctxStoredIfaces := map[*types.Named][]*types.Interface{}
	ctxAssertedIfaces := map[*types.Named][]*types.Interface{}
	recordCtxAsserted := func(key *types.Named, taT types.Type) {
		if taT == nil || syntaxutil.IsNamedInPkg(taT, "reflect", "Type") {
			return
		}
		if aif, isIf := syntaxutil.UnderlyingType(taT).(*types.Interface); isIf {
			ctxAssertedIfaces[key] = append(ctxAssertedIfaces[key], aif)
		}
	}
	isCleanContextLookup := func(key *types.Named, call *ast.CallExpr) bool {
		par := idx.ParentUnparen(call)
		if ta, isTA := par.(*ast.TypeAssertExpr); isTA {
			if ast.Unparen(ta.X) != call || ta.Type == nil {
				return false
			}
			taT := p.TypesInfo.TypeOf(ta.Type)
			if taT == nil || isEmptyInterfaceType(taT) {
				return false
			}
			recordCtxAsserted(key, taT)
			return true
		}
		as, isAS := par.(*ast.AssignStmt)
		if !isAS || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Rhs[0]) != call {
			return false
		}
		lhs0, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
		if !isID {
			return false
		}
		if lhs0.Name == "_" {
			return true
		}
		resVar, okDef := p.TypesInfo.Defs[lhs0].(*types.Var)
		if !okDef || resVar == nil || idx.DefCounts[resVar] != 1 {
			return false
		}
		for _, ruid := range idx.UsesOf[resVar] {
			ta, isTA := idx.ParentUnparen(ruid).(*ast.TypeAssertExpr)
			if !isTA || ast.Unparen(ta.X) != ruid || ta.Type == nil {
				return false
			}
			taT := p.TypesInfo.TypeOf(ta.Type)
			if taT == nil || isEmptyInterfaceType(taT) {
				return false
			}
			recordCtxAsserted(key, taT)
		}
		return true
	}

	sawUse := map[*types.Named]bool{}
	lookupSeen := map[*types.Named]bool{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if len(cands) == 0 || n == nil {
				return false
			}
			if id, isID := n.(*ast.Ident); isID {
				if tn, ok := p.TypesInfo.Uses[id].(*types.TypeName); ok && tn != nil {
					if named, isN := tn.Type().(*types.Named); isN && cands[named] != nil {
						par := idx.ParentUnparen(id)
						switch pn := par.(type) {
						case *ast.CompositeLit:
							if ast.Unparen(pn.Type) != id || len(pn.Elts) != 0 {
								delete(cands, named)
							}
						case *ast.CallExpr:
							if ast.Unparen(pn.Fun) != id || len(pn.Args) != 1 || pn.Ellipsis.IsValid() {
								delete(cands, named)
							}
						case *ast.ValueSpec:
							if pn.Type != id {
								delete(cands, named)
							} else {
								for _, nm := range pn.Names {
									if nm != nil && nm.IsExported() {
										delete(cands, named)
									}
								}
							}
						default:
							delete(cands, named)
						}
					}
				}
			}
			if expr, isExpr := n.(ast.Expr); isExpr {
				tv, okTV := p.TypesInfo.Types[expr]
				if okTV && tv.IsValue() {
					if _, isParen := expr.(*ast.ParenExpr); !isParen {
						if named, isN := types.Unalias(tv.Type).(*types.Named); isN && cands[named] != nil {
							sawUse[named] = true
							call, isCall := idx.ParentUnparen(expr).(*ast.CallExpr)
							if !isCall || call.Ellipsis.IsValid() {
								delete(cands, named)
								return true
							}
							callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
							if callee != nil && callee.Pkg() != nil && callee.Pkg().Path() == "context" &&
								syntaxutil.IsTrueStdlibInPkg(p, "context") {
								if callee.Name() == "WithValue" && len(call.Args) == 3 && ast.Unparen(call.Args[1]) == expr {
									valT := p.TypesInfo.TypeOf(call.Args[2])
									if !isEmptyInterfaceType(valT) {
										if sif, isIf := syntaxutil.UnderlyingType(valT).(*types.Interface); isIf && !syntaxutil.IsNamedInPkg(valT, "reflect", "Type") {
											ctxStoredIfaces[named] = append(ctxStoredIfaces[named], sif)
										}
										return true
									}
								}
								if callee.Name() == "Value" && len(call.Args) == 1 && ast.Unparen(call.Args[0]) == expr {
									if sig, okS := callee.Type().(*types.Signature); okS && sig.Recv() != nil && types.IsInterface(sig.Recv().Type()) {
										if isCleanContextLookup(named, call) {
											lookupSeen[named] = true
											return true
										}
									}
								}
							}
							delete(cands, named)
						}
					}
				}
			}
			return true
		})
	}
	for named := range cands {
		if sawUse[named] {
			preserves := true
			for _, sif := range ctxStoredIfaces[named] {
				sk := syntaxutil.IfaceMethodSetKey(sif)
				if sk == "" {
					preserves = false
					break
				}
				for _, aif := range ctxAssertedIfaces[named] {
					if !syntaxutil.MethodSetSubset(syntaxutil.IfaceMethodSetKey(aif), sk) {
						preserves = false
						break
					}
				}
				if !preserves {
					break
				}
			}
			if !preserves {
				mismatchedIface[named] = true
			}
			out[named] = true
			if lookupSeen[named] {
				hasLookup[named] = true
			}
		}
	}
	return out, hasLookup, mismatchedIface
}

func collectContextKeyThiefFacts(p *packages.Package, idx *refconfine.PkgIndex) []syntaxutil.ReflectedIfaceFact {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || syntaxutil.IsTrueStdlibInPkg(p, p.Types.Path()) {
		return nil
	}
	isConfinedKeyParam := func(fd *ast.FuncDecl, keyParam *types.Var) bool {
		if fd == nil || fd.Body == nil || keyParam == nil {
			return false
		}
		if idx.DefCounts[keyParam] != 1 {
			return false
		}
		for _, uid := range idx.UsesOf[keyParam] {
			if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
				return false
			}
			switch par := idx.ParentUnparen(uid).(type) {
			case *ast.BinaryExpr:
				if par.Op != token.EQL && par.Op != token.NEQ {
					return false
				}
			case *ast.IndexExpr:
				if ast.Unparen(par.Index) != uid || refconfine.IdentOrExprIsWritten(idx, par) {
					return false
				}
				if _, isMap := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(par.X)).(*types.Map); !isMap {
					return false
				}
			case *ast.CallExpr:
				if len(par.Args) != 1 || par.Ellipsis.IsValid() || ast.Unparen(par.Args[0]) != uid {
					return false
				}
				callee := syntaxutil.ResolveCalledFuncObj(p, par.Fun)
				if callee == nil || callee.Name() != "Value" {
					return false
				}
				csig, okS := callee.Type().(*types.Signature)
				if !okS || csig.Recv() == nil || csig.Params().Len() != 1 || csig.Results().Len() != 1 ||
					!isEmptyInterfaceType(csig.Params().At(0).Type()) || !isEmptyInterfaceType(csig.Results().At(0).Type()) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	for fn, fd := range idx.FuncDecls {
		if fn == nil || fn.Pkg() != p.Types || fn.Name() != "Value" {
			continue
		}
		sig, okS := fn.Type().(*types.Signature)
		if !okS || sig.Recv() == nil || sig.Params().Len() != 1 || sig.Results().Len() != 1 ||
			!isEmptyInterfaceType(sig.Params().At(0).Type()) || !isEmptyInterfaceType(sig.Results().At(0).Type()) {
			continue
		}
		if !isConfinedKeyParam(fd, sig.Params().At(0)) {
			return []syntaxutil.ReflectedIfaceFact{{MethodSet: syntaxutil.ContextKeyTheftMethodSetKey}}
		}
	}
	return nil
}

func typeHasCallbackIfaceTakingAny(root types.Type) bool {
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
		if syntaxutil.IsNamedInPkg(t, "context", "Context") ||
			syntaxutil.IsNamedInPkg(t, "reflect", "Type") {
			return
		}
		switch u := t.Underlying().(type) {
		case *types.Signature:
			for pi := 0; pi < u.Params().Len(); pi++ {
				if typeMentionsEmptyInterfaceWith(u.Params().At(pi).Type(), true) {
					hit = true
					return
				}
			}
		case *types.Interface:
			for i := 0; i < u.NumMethods(); i++ {
				msig, okS := u.Method(i).Type().(*types.Signature)
				if !okS {
					continue
				}
				for pi := 0; pi < msig.Params().Len(); pi++ {
					if typeMentionsEmptyInterfaceWith(msig.Params().At(pi).Type(), true) {
						hit = true
						return
					}
				}
			}
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
		}
	}
	walk(root)
	return hit
}

func typeMentionsEmptyInterface(root types.Type) bool {
	return typeMentionsEmptyInterfaceWith(root, false)
}

func typeMentionsEmptyInterfaceWith(root types.Type, includeUnexportedFields bool) bool {
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
		if _, isTP := t.(*types.TypeParam); isTP {
			return
		}
		switch u := t.Underlying().(type) {
		case *types.Interface:
			if u.NumMethods() == 0 {
				hit = true
				return
			}
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
				if f := u.Field(i); includeUnexportedFields || f.Exported() || f.Embedded() {
					walk(f.Type())
				}
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

func pkgExportedAPIReaches(
	p *packages.Package,
	checkVarType func(types.Type) bool,
	checkNamedType func(types.Type) bool,
	checkSig func(*types.Signature) bool,
) bool {
	if p == nil || p.Types == nil {
		return false
	}
	seenAPI := map[types.Type]bool{}
	seenSigs := map[*types.Signature]bool{}
	hit := false
	var walkAPIType func(t types.Type)
	var walkSig func(sig *types.Signature)
	walkSig = func(sig *types.Signature) {
		if sig == nil || hit || seenSigs[sig] {
			return
		}
		seenSigs[sig] = true
		if checkSig != nil && checkSig(sig) {
			hit = true
			return
		}
		for i := 0; i < sig.Params().Len(); i++ {
			walkAPIType(sig.Params().At(i).Type())
		}
		for i := 0; i < sig.Results().Len(); i++ {
			walkAPIType(sig.Results().At(i).Type())
		}
	}
	walkAPIType = func(t types.Type) {
		if t == nil || hit {
			return
		}
		t = types.Unalias(t)
		if seenAPI[t] {
			return
		}
		seenAPI[t] = true
		if named, isN := t.(*types.Named); isN {
			if named.TypeArgs() != nil {
				for ti := 0; ti < named.TypeArgs().Len(); ti++ {
					walkAPIType(named.TypeArgs().At(ti))
				}
			}
			orig := named.Origin()
			if orig.Obj() == nil || orig.Obj().Pkg() != p.Types {
				return
			}
			if _, isIf := orig.Underlying().(*types.Interface); !isIf && named.TypeParams() == nil && orig.TypeParams() == nil {
				mset := types.NewMethodSet(types.NewPointer(named))
				for mi := 0; mi < mset.Len(); mi++ {
					mObj := mset.At(mi).Obj()
					if mObj != nil && mObj.Exported() {
						if msig, okS := mObj.Type().(*types.Signature); okS {
							walkSig(msig)
						}
					}
				}
			} else {
				for mi := 0; mi < orig.NumMethods(); mi++ {
					mObj := orig.Method(mi)
					if mObj != nil && mObj.Exported() {
						if msig, okS := mObj.Type().(*types.Signature); okS {
							walkSig(msig)
						}
					}
				}
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			walkAPIType(u.Elem())
		case *types.Slice:
			walkAPIType(u.Elem())
		case *types.Array:
			walkAPIType(u.Elem())
		case *types.Map:
			walkAPIType(u.Key())
			walkAPIType(u.Elem())
		case *types.Chan:
			walkAPIType(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if f := u.Field(i); f.Exported() || f.Embedded() {
					walkAPIType(f.Type())
				}
			}
		case *types.Interface:
			for i := 0; i < u.NumMethods(); i++ {
				mObj := u.Method(i)
				if mObj != nil && mObj.Exported() {
					if msig, okS := mObj.Type().(*types.Signature); okS {
						walkSig(msig)
					}
				}
			}
		case *types.Signature:
			walkSig(u)
		}
	}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		if obj == nil || !obj.Exported() {
			continue
		}
		switch o := obj.(type) {
		case *types.Var:
			if checkVarType != nil && checkVarType(o.Type()) {
				return true
			}
			walkAPIType(o.Type())
		case *types.Func:
			if sig, ok := o.Type().(*types.Signature); ok {
				walkSig(sig)
			}
		case *types.TypeName:
			ut := types.Unalias(o.Type())
			if checkNamedType != nil && checkNamedType(ut) {
				return true
			}
			walkAPIType(ut)
		}
		if hit {
			return true
		}
	}
	return hit
}

func sigExposesEmptyIface(sig *types.Signature) bool {
	if sig == nil {
		return false
	}
	for i := 0; i < sig.Results().Len(); i++ {
		if typeMentionsEmptyInterface(sig.Results().At(i).Type()) {
			return true
		}
	}
	for i := 0; i < sig.Params().Len(); i++ {
		pt := sig.Params().At(i).Type()
		if sig.Variadic() && i == sig.Params().Len()-1 {
			if sl, isSl := types.Unalias(pt).Underlying().(*types.Slice); isSl {
				pt = sl.Elem()
			}
		}
		if _, isIf := types.Unalias(pt).Underlying().(*types.Interface); !isIf && typeMentionsEmptyInterface(pt) {
			return true
		}
	}
	return false
}

func pkgExposesEmptyIfaceBoundary(p *packages.Package) bool {
	if p == nil || p.Types == nil {
		return false
	}
	return pkgExportedAPIReaches(
		p,
		typeMentionsEmptyInterface,
		func(t types.Type) bool {
			return !types.IsInterface(t) && typeMentionsEmptyInterface(t)
		},
		sigExposesEmptyIface,
	)
}

func pkgCanLeakEmptyIfaceUpward(p *packages.Package, idx *refconfine.PkgIndex) bool {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || len(p.Syntax) == 0 {
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
	isScalarBasic := func(t types.Type) bool {
		if t == nil {
			return false
		}
		b, ok := syntaxutil.UnderlyingType(t).(*types.Basic)
		return ok && b.Kind() != types.UnsafePointer && b.Kind() != types.Uintptr
	}
	isUniverseErr := func(t types.Type) bool {
		if t == nil {
			return false
		}
		named, ok := types.Unalias(t).(*types.Named)
		return ok && named.Obj() != nil && named.Obj().Pkg() == nil && named.Obj().Name() == "error"
	}
	isSafeInternalAssertTarget := func(t types.Type) bool {
		if isScalarBasic(t) {
			return true
		}
		if t == nil {
			return false
		}
		cur := types.Unalias(t)
		if ptr, isP := cur.Underlying().(*types.Pointer); isP {
			cur = types.Unalias(ptr.Elem())
		}
		named, isN := cur.(*types.Named)
		if !isN || named.Obj() == nil || named.Obj().Pkg() != p.Types || named.Obj().Exported() {
			return false
		}
		st, isSt := named.Underlying().(*types.Struct)
		if !isSt {
			return false
		}
		for i := 0; i < st.NumFields(); i++ {
			ft := st.Field(i).Type()
			if !isScalarBasic(ft) && !isUniverseErr(ft) {
				return false
			}
		}
		return true
	}
	checkExportedSig := func(sig *types.Signature) bool {
		if sig == nil {
			return false
		}
		for i := 0; i < sig.Results().Len(); i++ {
			if typeMentionsEmptyInterfaceWith(sig.Results().At(i).Type(), true) {
				return true
			}
		}
		for i := 0; i < sig.Params().Len(); i++ {
			pt := sig.Params().At(i).Type()
			if sig.Variadic() && i == sig.Params().Len()-1 {
				if sl, isSl := types.Unalias(pt).Underlying().(*types.Slice); isSl {
					pt = sl.Elem()
				}
			}
			if _, isIf := types.Unalias(pt).Underlying().(*types.Interface); !isIf && typeMentionsEmptyInterfaceWith(pt, true) {
				return true
			}
		}
		return false
	}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		if obj == nil {
			continue
		}
		switch o := obj.(type) {
		case *types.Var:
			vt := o.Type()
			if typeMentionsEmptyInterfaceWith(vt, true) {
				return true
			}
			if refconfine.TypeContainsRefOrPointer(vt) || syntaxutil.ContainsUintptr(vt) {
				iface, isIf := types.Unalias(vt).Underlying().(*types.Interface)
				if !isIf || iface.NumMethods() == 0 || idx.DefCounts[o] != 1 {
					return true
				}
				for _, uid := range idx.UsesOf[o] {
					if refconfine.IdentOrExprIsWritten(idx, uid) || freshalloc.IdentReachesMutatedOrAddrPrefix(p, idx, uid) {
						return true
					}
				}
			}
		case *types.Func:
			if o.Exported() {
				if sig, ok := o.Type().(*types.Signature); ok && checkExportedSig(sig) {
					return true
				}
			}
		case *types.TypeName:
			if named, ok := types.Unalias(o.Type()).(*types.Named); ok {
				if !types.IsInterface(named) && typeMentionsEmptyInterfaceWith(named, true) {
					return true
				}
			}
		}
	}
	if pkgExportedAPIReaches(p, nil, nil, checkExportedSig) {
		return true
	}
	leaksViaSyntax := false
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if leaksViaSyntax || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.StructType, *ast.ArrayType, *ast.MapType, *ast.ChanType:
				if t := p.TypesInfo.TypeOf(x.(ast.Expr)); t != nil && typeMentionsEmptyInterfaceWith(t, true) {
					leaksViaSyntax = true
					return false
				}
			case *ast.TypeAssertExpr:
				if x.Type != nil && !isSafeInternalAssertTarget(p.TypesInfo.TypeOf(x.Type)) {
					leaksViaSyntax = true
					return false
				}
			case *ast.TypeSwitchStmt:
				if x.Body != nil {
					for _, raw := range x.Body.List {
						cc, okCC := raw.(*ast.CaseClause)
						if !okCC {
							continue
						}
						for _, ct := range cc.List {
							if syntaxutil.IsNilIdent(p.TypesInfo, ct) {
								continue
							}
							if !isSafeInternalAssertTarget(p.TypesInfo.TypeOf(ct)) {
								leaksViaSyntax = true
								return false
							}
						}
					}
				}
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB && b.Name() == "panic" {
						if len(x.Args) != 1 || !isScalarBasic(p.TypesInfo.TypeOf(x.Args[0])) {
							leaksViaSyntax = true
							return false
						}
					}
				}
			}
			return true
		})
		if leaksViaSyntax {
			return true
		}
	}
	return false
}
