package capsule

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func pkgReifiesStructReflectType(p *packages.Package, target *types.Named) bool {
	if p == nil || p.TypesInfo == nil || target == nil {
		return false
	}
	mentionsTarget := func(root types.Type) bool {
		seen := map[types.Type]bool{}
		hit := false
		var walk func(t types.Type)
		walk = func(t types.Type) {
			if t == nil || hit {
				return
			}
			t = types.Unalias(t)
			if t == target {
				hit = true
				return
			}
			if seen[t] {
				return
			}
			seen[t] = true
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
			}
		}
		walk(root)
		return hit
	}
	reified := false
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if reified || n == nil {
				return false
			}
			call, isCall := n.(*ast.CallExpr)
			if !isCall {
				return true
			}
			callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
			if callee == nil || callee.Pkg() == nil || callee.Pkg().Path() != "reflect" || !syntaxutil.IsTrueStdlibInPkg(p, "reflect") {
				return true
			}
			switch callee.Name() {
			case "TypeOf", "ValueOf":
				if len(call.Args) == 1 && mentionsTarget(p.TypesInfo.TypeOf(call.Args[0])) {
					reified = true
					return false
				}
			case "TypeFor":
				if sig, okS := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(call.Fun)).(*types.Signature); okS && sig.Results().Len() == 1 {
					for id, inst := range p.TypesInfo.Instances {
						if id.Pos() >= call.Fun.Pos() && id.End() <= call.Fun.End() && inst.TypeArgs != nil {
							for ti := 0; ti < inst.TypeArgs.Len(); ti++ {
								if mentionsTarget(inst.TypeArgs.At(ti)) {
									reified = true
									return false
								}
							}
						}
					}
				}
			}
			return true
		})
	}
	return reified
}

func isSealedStdlibIface(p *packages.Package, iface *types.Interface) bool {
	if p == nil || iface == nil {
		return false
	}
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		if !m.Exported() && m.Pkg() != nil && m.Pkg() != p.Types && syntaxutil.IsTrueStdlibInPkg(p, m.Pkg().Path()) {
			return true
		}
	}
	return false
}

func typeMentionsMatchingNonEmptyIface(p *packages.Package, root types.Type, stopRoots map[*types.Named]bool, target *types.Named) bool {
	var ptrTarget *types.Pointer
	if target != nil {
		ptrTarget = types.NewPointer(target)
	}
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
		if n, isN := t.(*types.Named); isN && stopRoots[n] {
			return
		}
		switch u := t.Underlying().(type) {
		case *types.Interface:
			if u.NumMethods() > 0 && !isSealedStdlibIface(p, u) &&
				(target == nil || types.Implements(target, u) || types.Implements(ptrTarget, u)) {
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
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		}
	}
	walk(root)
	return hit
}

func pkgTakesUnsafeAddrOfMatchingIface(p *packages.Package, idx *refconfine.PkgIndex, stopRoots map[*types.Named]bool, target *types.Named) bool {
	if p == nil || p.TypesInfo == nil || idx == nil {
		return false
	}
	hit := false
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if hit || n == nil {
				return false
			}
			call, isCall := n.(*ast.CallExpr)
			if !isCall || len(call.Args) == 0 {
				return true
			}
			if tv := p.TypesInfo.Types[call.Fun]; tv.IsType() && len(call.Args) == 1 && syntaxutil.IsUnsafePointerType(types.Unalias(tv.Type)) {
				if refconfine.IsPureAtomicLoadInnerConv(p, idx, call) ||
					refconfine.IsAtomicPointerSlotTargetInnerConv(p, idx, call) ||
					refconfine.IsSafeAtomicPointerValueArg(p, idx, call) {
					return true
				}
				if ptr, isP := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(call.Args[0])).(*types.Pointer); isP && typeMentionsMatchingNonEmptyIface(p, ptr.Elem(), stopRoots, target) {
					hit = true
					return false
				}
				return true
			}
			if b := syntaxutil.LookupBuiltin(p.TypesInfo, ast.Unparen(call.Fun)); b != nil {
				switch b.Name() {
				case "SliceData":
					if sl, isSl := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(call.Args[0])).(*types.Slice); isSl && typeMentionsMatchingNonEmptyIface(p, sl.Elem(), stopRoots, target) {
						hit = true
						return false
					}
				case "Slice":
					if ptr, isP := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(call.Args[0])).(*types.Pointer); isP && typeMentionsMatchingNonEmptyIface(p, ptr.Elem(), stopRoots, target) {
						hit = true
						return false
					}
				}
			}
			return true
		})
	}
	return hit
}

func pkgConfinesMatchingIfaceValueOf(p *packages.Package, idx *refconfine.PkgIndex, stopRoots map[*types.Named]bool, target *types.Named) bool {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil {
		return false
	}
	var ptrTarget *types.Pointer
	if target != nil {
		ptrTarget = types.NewPointer(target)
	}
	stmtAlwaysPanics := func(stmt ast.Stmt) bool {
		blk, isB := stmt.(*ast.BlockStmt)
		if !isB || len(blk.List) == 0 {
			return false
		}
		es, isE := blk.List[len(blk.List)-1].(*ast.ExprStmt)
		if !isE {
			return false
		}
		c, isC := ast.Unparen(es.X).(*ast.CallExpr)
		if !isC {
			return false
		}
		cid, isID := ast.Unparen(c.Fun).(*ast.Ident)
		if !isID {
			return false
		}
		b, isBuilt := p.TypesInfo.Uses[cid].(*types.Builtin)
		return isBuilt && b.Name() == "panic"
	}
	isRVTypeCall := func(expr ast.Expr, rv *types.Var) bool {
		c, isC := ast.Unparen(expr).(*ast.CallExpr)
		if !isC || len(c.Args) != 0 || c.Ellipsis.IsValid() {
			return false
		}
		sel, isS := ast.Unparen(c.Fun).(*ast.SelectorExpr)
		if !isS || sel.Sel == nil || sel.Sel.Name != "Type" {
			return false
		}
		id, isID := ast.Unparen(sel.X).(*ast.Ident)
		if !isID || p.TypesInfo.Uses[id] != rv {
			return false
		}
		fn := syntaxutil.ResolveCalledFuncObj(p, c.Fun)
		return fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == "reflect" && fn.Name() == "Type"
	}
	ok := true
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !ok || n == nil {
				return false
			}
			call, isCall := n.(*ast.CallExpr)
			if !isCall || len(call.Args) != 1 || call.Ellipsis.IsValid() || !syntaxutil.IsTrueStdlibInPkg(p, "reflect") {
				return true
			}
			callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
			if callee == nil || callee.Pkg() == nil || callee.Pkg().Path() != "reflect" || callee.Name() != "ValueOf" {
				return true
			}
			argT := p.TypesInfo.TypeOf(call.Args[0])
			if argT == nil {
				return true
			}
			iface, isIf := types.Unalias(argT).Underlying().(*types.Interface)
			if !isIf {
				if typeMentionsMatchingNonEmptyIface(p, argT, stopRoots, target) {
					ok = false
					return false
				}
				return true
			}
			if iface.NumMethods() == 0 || isSealedStdlibIface(p, iface) {
				return true
			}
			if target != nil && !types.Implements(target, iface) && !types.Implements(ptrTarget, iface) {
				return true
			}
			if sel, isSel := idx.ParentUnparen(call).(*ast.SelectorExpr); isSel && ast.Unparen(sel.X) == call && sel.Sel != nil {
				if oc, isOC := idx.ParentUnparen(sel).(*ast.CallExpr); isOC && ast.Unparen(oc.Fun) == sel {
					switch sel.Sel.Name {
					case "Type", "Kind", "IsNil", "IsValid", "IsZero", "Len", "Cap", "NumField", "NumMethod":
						return true
					}
				}
			}
			as, isAS := idx.ParentUnparen(call).(*ast.AssignStmt)
			if !isAS || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Rhs[0]) != call {
				ok = false
				return false
			}
			lid, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
			if !isID {
				ok = false
				return false
			}
			rv, _ := p.TypesInfo.Uses[lid].(*types.Var)
			if rv == nil {
				rv, _ = p.TypesInfo.Defs[lid].(*types.Var)
			}
			enclFD := idx.SyncEnclFuncDecl(call)
			if rv == nil || enclFD == nil || idx.EnclFunc[call] != enclFD || enclFD.Body == nil || rv.Parent() == p.Types.Scope() ||
				rv.Pos() <= enclFD.Body.Pos() || rv.Pos() >= enclFD.Body.End() {
				ok = false
				return false
			}
			sawReturn := false
			for _, uid := range idx.UsesOf[rv] {
				if idx.EnclFunc[uid] != enclFD {
					ok = false
					return false
				}
				if uid == lid {
					continue
				}
				par := idx.ParentUnparen(uid)
				switch pn := par.(type) {
				case *ast.AssignStmt:
					if len(pn.Lhs) != 1 || len(pn.Rhs) != 1 || ast.Unparen(pn.Lhs[0]) != uid {
						ok = false
						return false
					}
					rc, isRC := ast.Unparen(pn.Rhs[0]).(*ast.CallExpr)
					if !isRC {
						ok = false
						return false
					}
					rfn := syntaxutil.ResolveCalledFuncObj(p, rc.Fun)
					if rfn == nil || rfn.Pkg() == nil || rfn.Pkg().Path() != "reflect" {
						ok = false
						return false
					}
					switch rfn.Name() {
					case "ValueOf", "Zero", "Elem":
					default:
						ok = false
						return false
					}
				case *ast.SelectorExpr:
					if ast.Unparen(pn.X) != uid || pn.Sel == nil {
						ok = false
						return false
					}
					oc, isOC := idx.ParentUnparen(pn).(*ast.CallExpr)
					if !isOC || ast.Unparen(oc.Fun) != pn {
						ok = false
						return false
					}
					switch pn.Sel.Name {
					case "Type", "Kind", "IsNil", "IsValid", "IsZero", "Len", "Cap", "NumField", "NumMethod":
					case "Elem":
						ras, isRAS := idx.ParentUnparen(oc).(*ast.AssignStmt)
						if !isRAS || len(ras.Lhs) != 1 || len(ras.Rhs) != 1 || ast.Unparen(ras.Rhs[0]) != oc {
							ok = false
							return false
						}
						rlid, isRID := ast.Unparen(ras.Lhs[0]).(*ast.Ident)
						if !isRID || p.TypesInfo.Uses[rlid] != rv {
							ok = false
							return false
						}
					default:
						ok = false
						return false
					}
				case *ast.ReturnStmt:
					sawReturn = true
				default:
					ok = false
					return false
				}
			}
			if sawReturn {
				if idx.FlowCache(p).FuncBody(enclFD).HasGotoAnywhere() {
					ok = false
					return false
				}
				var earliestRetPos token.Pos
				ast.Inspect(enclFD.Body, func(bn ast.Node) bool {
					if bn == nil {
						return false
					}
					if retS, isRet := bn.(*ast.ReturnStmt); isRet && retS.Pos() >= call.Pos() {
						if !earliestRetPos.IsValid() || retS.Pos() < earliestRetPos {
							earliestRetPos = retS.Pos()
						}
					}
					return true
				})
				assignAfter := func(afterPos token.Pos) bool {
					reassigned := false
					ast.Inspect(enclFD.Body, func(bn ast.Node) bool {
						if reassigned || bn == nil {
							return false
						}
						if as, isAS := bn.(*ast.AssignStmt); isAS && as.Pos() >= afterPos {
							for _, lhs := range as.Lhs {
								if id, isID := ast.Unparen(lhs).(*ast.Ident); isID && p.TypesInfo.Uses[id] == rv {
									reassigned = true
									return false
								}
							}
						}
						return true
					})
					return reassigned
				}
				if !earliestRetPos.IsValid() {
					ok = false
					return false
				}
				var enclRecvVar *types.Var
				if enclFD.Recv != nil && len(enclFD.Recv.List) == 1 && len(enclFD.Recv.List[0].Names) == 1 {
					rvObj, _ := p.TypesInfo.Defs[enclFD.Recv.List[0].Names[0]].(*types.Var)
					if rvObj != nil && idx.DefCounts[rvObj] == 1 {
						recvClean := true
						for _, ruid := range idx.UsesOf[rvObj] {
							if refconfine.IdentIsWrittenOrAddrTaken(idx, ruid) {
								recvClean = false
								break
							}
						}
						if recvClean {
							enclRecvVar = rvObj
						}
					}
				}
				isRecvUnexportedField := func(expr ast.Expr) bool {
					if enclRecvVar == nil {
						return false
					}
					sel, isS := ast.Unparen(expr).(*ast.SelectorExpr)
					if !isS || !syntaxutil.IsIdentUsingObj(p.TypesInfo, sel.X, enclRecvVar) {
						return false
					}
					selInfo := p.TypesInfo.Selections[sel]
					if selInfo == nil || selInfo.Kind() != types.FieldVal || selInfo.Obj() == nil || selInfo.Obj().Exported() {
						return false
					}
					fld, _ := selInfo.Obj().(*types.Var)
					return isSafeConverterGoTypeField(p, idx, fld, stopRoots)
				}
				hasTypeGuard := false
				for _, stmt := range enclFD.Body.List {
					if stmt.Pos() >= earliestRetPos {
						break
					}
					ifs, isIfS := stmt.(*ast.IfStmt)
					if !isIfS || ifs.Init != nil || ifs.Pos() <= call.End() || ifs.End() > earliestRetPos || ifs.Else != nil || !stmtAlwaysPanics(ifs.Body) {
						continue
					}
					bin, isBin := ast.Unparen(ifs.Cond).(*ast.BinaryExpr)
					if !isBin || bin.Op != token.NEQ {
						continue
					}
					xIsRV := isRVTypeCall(bin.X, rv)
					yIsRV := isRVTypeCall(bin.Y, rv)
					otherSide := bin.Y
					if yIsRV {
						otherSide = bin.X
					}
					if xIsRV != yIsRV && isRecvUnexportedField(otherSide) && !assignAfter(ifs.Pos()) {
						hasTypeGuard = true
						break
					}
				}
				if !hasTypeGuard {
					ok = false
					return false
				}
			}
			return true
		})
	}
	return ok
}
