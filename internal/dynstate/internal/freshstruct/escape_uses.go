package freshstruct

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

type freshEscapeCoupling struct {
	srcRoot *types.Var
	dstRoot *types.Var
	atPos   token.Pos
}

func enclosingFuncLit(idx *refconfine.PkgIndex, n ast.Node) *ast.FuncLit {
	cur := idx.ParentMap[n]
	var outer *ast.FuncLit
	for cur != nil {
		if lit, isLit := cur.(*ast.FuncLit); isLit {
			outer = lit
		}
		if _, isFD := cur.(*ast.FuncDecl); isFD {
			break
		}
		cur = idx.ParentMap[cur]
	}
	return outer
}

func classifyFieldAssignedClosureUse(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	lit *ast.FuncLit,
	v *types.Var,
	resolveRoot func(ast.Expr) *types.Var,
) (ownerRoot *types.Var, ok bool, returnsAddrOnly bool) {
	if lit == nil || lit.Body == nil {
		return nil, false, false
	}
	as, isAs := idx.ParentUnparen(lit).(*ast.AssignStmt)
	if !isAs || len(as.Lhs) != len(as.Rhs) {
		return nil, false, false
	}
	lhsIdx := -1
	for i, r := range as.Rhs {
		if ast.Unparen(r) == lit {
			lhsIdx = i
			break
		}
	}
	if lhsIdx < 0 {
		return nil, false, false
	}
	lhsSel, isSel := ast.Unparen(as.Lhs[lhsIdx]).(*ast.SelectorExpr)
	if !isSel {
		return nil, false, false
	}
	selInfo := p.TypesInfo.Selections[lhsSel]
	if selInfo == nil || selInfo.Kind() != types.FieldVal {
		return nil, false, false
	}
	ownerRoot = resolveRoot(lhsSel.X)
	if ownerRoot == nil {
		return nil, false, false
	}
	for _, uid := range idx.UsesOf[v] {
		if !(lit.Body.Pos() <= uid.Pos() && uid.Pos() < lit.Body.End()) {
			continue
		}
		if IdentReachesMutatedOrAddrPrefix(p, idx, uid) {
			par := idx.ParentUnparen(uid)
			if un, isUn := par.(*ast.UnaryExpr); isUn && un.Op == token.AND {
				if _, isRet := idx.ParentUnparen(un).(*ast.ReturnStmt); isRet {
					returnsAddrOnly = true
					continue
				}
			}
			return nil, false, false
		}
		cur := ast.Expr(uid)
		for {
			sel, isS := idx.ParentUnparen(cur).(*ast.SelectorExpr)
			if !isS || ast.Unparen(sel.X) != cur {
				break
			}
			si := p.TypesInfo.Selections[sel]
			if si == nil || si.Kind() != types.FieldVal {
				return nil, false, false
			}
			cur = sel
		}
		if cur == uid || refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
			return nil, false, false
		}
	}
	return ownerRoot, true, returnsAddrOnly
}

func useIsNonEscapingOnFreshVar(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	fd *ast.FuncDecl,
	sum *freshFuncSummary,
	v *types.Var,
	id *ast.Ident,
	freshParamFuncs map[*types.Func]map[int]bool,
	nonEscParams map[*types.Func]map[int]bool,
	mapStoreParams map[*types.Func]map[int]int,
	retStructParams map[*types.Func]map[int]bool,
	paramGuardPkgs map[*types.Func]map[int]map[string]bool,
	nonEscAuxVars map[*types.Var]bool,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	resolveRoot func(ast.Expr) *types.Var,
	couplings *[]freshEscapeCoupling,
) bool {
	cur := ast.Expr(id)
	for {
		par := idx.ParentUnparen(cur)
		switch x := par.(type) {
		case *ast.StarExpr:
			if cur == id && ast.Unparen(x.X) == cur {
				cur = x
				continue
			}
		case *ast.SelectorExpr:
			if ast.Unparen(x.X) == cur {
				selInfo := p.TypesInfo.Selections[x]
				if selInfo != nil && selInfo.Kind() == types.FieldVal {
					cur = x
					continue
				}
				if selInfo != nil && selInfo.Kind() == types.MethodVal {
					call, isCall := idx.ParentUnparen(x).(*ast.CallExpr)
					if !isCall || ast.Unparen(call.Fun) != x {
						return false
					}
					return isNonEscapingMethodOrHelperCallOnFresh(
						p, idx, fd, sum, call, -1, v,
						freshParamFuncs, nonEscParams, mapStoreParams, retStructParams, paramGuardPkgs, nonEscAuxVars, resolveRoot, couplings,
					)
				}
			}
		case *ast.IndexExpr:
			if ast.Unparen(x.X) == cur {
				cur = x
				continue
			}
		case *ast.SliceExpr:
			if ast.Unparen(x.X) == cur {
				cur = x
				continue
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND && ast.Unparen(x.X) == cur {
				switch up := idx.ParentUnparen(x).(type) {
				case *ast.ValueSpec:
					for i, val := range up.Values {
						if ast.Unparen(val) == x && i < len(up.Names) {
							av, _ := p.TypesInfo.Defs[up.Names[i]].(*types.Var)
							if av != nil && sum.vars[av] != nil {
								return true
							}
						}
					}
					return false
				case *ast.AssignStmt:
					if len(up.Lhs) == len(up.Rhs) {
						for i, r := range up.Rhs {
							if ast.Unparen(r) == x {
								if av := syntaxutil.LookupIdentVar(p.TypesInfo, up.Lhs[i]); av != nil && sum.vars[av] != nil {
									return true
								}
							}
						}
					}
					return false
				case *ast.CallExpr:
					for ai, arg := range up.Args {
						if ast.Unparen(arg) == x {
							return isNonEscapingMethodOrHelperCallOnFresh(
								p, idx, fd, sum, up, ai, v,
								freshParamFuncs, nonEscParams, mapStoreParams, retStructParams, paramGuardPkgs, nonEscAuxVars, resolveRoot, couplings,
							)
						}
					}
					return false
				default:
					return false
				}
			}
		}
		break
	}

	par := idx.ParentUnparen(cur)
	switch x := par.(type) {
	case *ast.AssignStmt:
		for _, lhs := range x.Lhs {
			if ast.Unparen(lhs) == cur {
				return cur != id || sum.vars[v] != nil
			}
		}
		if len(x.Lhs) == len(x.Rhs) {
			for i, rhs := range x.Rhs {
				if ast.Unparen(rhs) == cur {
					lhs := ast.Unparen(x.Lhs[i])
					if !refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
						return true
					}
					if ix, isIx := lhs.(*ast.IndexExpr); isIx {
						if mv := syntaxutil.LookupPkgScopeVar(p, ix.X); mv != nil && confinedCacheMaps[mv][fd] {
							return true
						}
					}
					if sel, isSel := lhs.(*ast.SelectorExpr); isSel {
						if dstRoot := resolveRoot(sel.X); dstRoot != nil && sum.vars[dstRoot] != nil {
							*couplings = append(*couplings, freshEscapeCoupling{srcRoot: sum.vars[v].rootVar, dstRoot: dstRoot, atPos: x.Pos()})
							return true
						}
					}
				}
			}
		}
		return false
	case *ast.IncDecStmt:
		return ast.Unparen(x.X) == cur && cur != id
	case *ast.RangeStmt:
		if ast.Unparen(x.X) == cur {
			if x.Value == nil || syntaxutil.IsBlankIdent(x.Value) || !refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(x.Value)) {
				return true
			}
		}
		return false
	case *ast.BinaryExpr:
		if x.Op == token.EQL || x.Op == token.NEQ || !refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
			return true
		}
		return false
	case *ast.CallExpr:
		if cid, isCID := ast.Unparen(x.Fun).(*ast.Ident); isCID {
			if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
				switch b.Name() {
				case "len", "cap":
					return true
				case "clear":
					return len(x.Args) == 1 && ast.Unparen(x.Args[0]) == cur
				case "copy":
					if len(x.Args) == 2 && (ast.Unparen(x.Args[0]) == cur || ast.Unparen(x.Args[1]) == cur) {
						if sl, isSl := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(cur)).(*types.Slice); isSl && !refconfine.TypeContainsRefOrPointer(sl.Elem()) {
							return true
						}
					}
					return false
				case "append":
					if len(x.Args) >= 1 && ast.Unparen(x.Args[0]) == cur {
						if as, isAs := idx.ParentUnparen(x).(*ast.AssignStmt); isAs && len(as.Lhs) == 1 && syntaxutil.SameFieldTargetExpr(p, as.Lhs[0], cur) {
							return true
						}
					}
					for ai := 1; ai < len(x.Args); ai++ {
						if ast.Unparen(x.Args[ai]) == cur {
							if !refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
								return true
							}
							if dstRoot := resolveRoot(x.Args[0]); dstRoot != nil && sum.vars[dstRoot] != nil {
								*couplings = append(*couplings, freshEscapeCoupling{srcRoot: sum.vars[v].rootVar, dstRoot: dstRoot, atPos: x.Pos()})
								return true
							}
						}
					}
					return false
				}
			}
		}
		for ai, arg := range x.Args {
			if ast.Unparen(arg) == cur {
				if !refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
					return true
				}
				if isNonEscapingMethodOrHelperCallOnFresh(
					p, idx, fd, sum, x, ai, v,
					freshParamFuncs, nonEscParams, mapStoreParams, retStructParams, paramGuardPkgs, nonEscAuxVars, resolveRoot, couplings,
				) {
					return true
				}
				if cur != id && !x.Ellipsis.IsValid() {
					if iface, isIface := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(cur)).(*types.Interface); isIface && iface.NumMethods() > 0 {
						anyFreshImplements := false
						for fv := range sum.vars {
							if fv == nil || fv.Type() == nil {
								continue
							}
							ft := types.Unalias(fv.Type())
							if types.Implements(ft, iface) {
								anyFreshImplements = true
								break
							}
							if ptr, isP := ft.Underlying().(*types.Pointer); isP && types.Implements(ptr.Elem(), iface) {
								anyFreshImplements = true
								break
							}
							if !types.IsInterface(ft) && types.Implements(types.NewPointer(ft), iface) {
								anyFreshImplements = true
								break
							}
						}
						if !anyFreshImplements {
							callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun)
							if callee != nil && callee.Origin().Pkg() != nil && callee.Origin().Pkg() != p.Types {
								sig, okSig := p.TypesInfo.TypeOf(x.Fun).(*types.Signature)
								if okSig {
									argsOK := true
									for oai, oa := range x.Args {
										if oai == ai {
											continue
										}
										if refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(oa)) {
											argsOK = false
											break
										}
									}
									resOK := true
									for ri := 0; ri < sig.Results().Len(); ri++ {
										rt := sig.Results().At(ri).Type()
										if refconfine.TypeContainsRefOrPointer(rt) && !syntaxutil.IsErrorType(rt) {
											resOK = false
											break
										}
									}
									if argsOK && resOK {
										recordFreshVarGuardPkg(sum, v, callee.Origin().Pkg().Path())
										return true
									}
								}
							}
						}
					}
				}
				return false
			}
		}
		return false
	default:
		if cur != id && !refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
			return true
		}
		return false
	}
}

func isNonEscapingMethodOrHelperCallOnFresh(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	fd *ast.FuncDecl,
	sum *freshFuncSummary,
	call *ast.CallExpr,
	argIdx int,
	srcVar *types.Var,
	freshParamFuncs map[*types.Func]map[int]bool,
	nonEscParams map[*types.Func]map[int]bool,
	mapStoreParams map[*types.Func]map[int]int,
	retStructParams map[*types.Func]map[int]bool,
	paramGuardPkgs map[*types.Func]map[int]map[string]bool,
	nonEscAuxVars map[*types.Var]bool,
	resolveRoot func(ast.Expr) *types.Var,
	couplings *[]freshEscapeCoupling,
) bool {
	if call == nil || call.Ellipsis.IsValid() {
		return false
	}
	callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
	if callee == nil {
		return false
	}
	orig := callee.Origin()
	if orig.Pkg() == p.Types {
		if orig.Exported() {
			return false
		}
		slot := argIdx
		if sel, isS := ast.Unparen(call.Fun).(*ast.SelectorExpr); isS {
			if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.MethodExpr {
				slot = argIdx - 1
			}
		}
		if slot >= 0 && freshParamFuncs[orig][slot] {
			return true
		}
		if !nonEscParams[orig][slot] {
			return false
		}
		for gPkg := range paramGuardPkgs[orig][slot] {
			recordFreshVarGuardPkg(sum, srcVar, gPkg)
		}
		if mSlot, hasMap := mapStoreParams[orig][slot]; hasMap {
			var mapArg ast.Expr
			if mSlot == -1 {
				if sel, isS := ast.Unparen(call.Fun).(*ast.SelectorExpr); isS {
					if si := p.TypesInfo.Selections[sel]; si != nil && si.Kind() == types.MethodVal {
						mapArg = sel.X
					} else if si != nil && si.Kind() == types.MethodExpr && len(call.Args) > 0 {
						mapArg = call.Args[0]
					}
				}
			} else if mSlot >= 0 && mSlot < len(call.Args) {
				mapArg = call.Args[mSlot]
			}
			mv := syntaxutil.LookupIdentVar(p.TypesInfo, mapArg)
			if mv == nil || !nonEscAuxVars[mv] {
				return false
			}
		}
		if retStructParams[orig][slot] {
			as, isAs := idx.ParentUnparen(call).(*ast.AssignStmt)
			if !isAs || len(as.Rhs) != 1 || ast.Unparen(as.Rhs[0]) != call || len(as.Lhs) == 0 {
				return false
			}
			if sel, isSel := ast.Unparen(as.Lhs[0]).(*ast.SelectorExpr); isSel {
				dstRoot := resolveRoot(sel.X)
				if dstRoot == nil || sum.vars[dstRoot] == nil {
					return false
				}
				*couplings = append(*couplings, freshEscapeCoupling{srcRoot: sum.vars[srcVar].rootVar, dstRoot: dstRoot, atPos: call.Pos()})
				return true
			}
			var targetAssign *ast.AssignStmt
			var dstRoot *types.Var
			sawCarrierOut := false
			for _, lhs := range as.Lhs {
				if syntaxutil.IsBlankIdent(lhs) {
					continue
				}
				lt := p.TypesInfo.TypeOf(lhs)
				if (!refconfine.TypeContainsRefOrPointer(lt) && !syntaxutil.ContainsUintptr(lt)) || syntaxutil.IsErrorType(lt) {
					continue
				}
				lid, isID := ast.Unparen(lhs).(*ast.Ident)
				if !isID {
					return false
				}
				lv, isDef := p.TypesInfo.Defs[lid].(*types.Var)
				if !isDef || lv == nil || idx.DefCounts[lv] != 1 || len(idx.UsesOf[lv]) == 0 {
					return false
				}
				sawCarrierOut = true
				for _, uid := range idx.UsesOf[lv] {
					if idx.InFuncLit[uid] || idx.InGoStmt[uid] {
						return false
					}
					extCall, isEC := idx.ParentUnparen(uid).(*ast.CallExpr)
					if !isEC || extCall.Ellipsis.IsValid() {
						return false
					}
					isArg := false
					for _, ea := range extCall.Args {
						if ast.Unparen(ea) == uid {
							isArg = true
							break
						}
					}
					if !isArg {
						return false
					}
					extCtor := syntaxutil.ResolveCalledFuncObj(p, extCall.Fun)
					if extCtor == nil || extCtor.Origin().Pkg() == nil {
						return false
					}
					as2, isAs2 := idx.ParentUnparen(extCall).(*ast.AssignStmt)
					if !isAs2 || len(as2.Lhs) != 1 || len(as2.Rhs) != 1 || ast.Unparen(as2.Rhs[0]) != extCall {
						return false
					}
					sel2, isSel2 := ast.Unparen(as2.Lhs[0]).(*ast.SelectorExpr)
					if !isSel2 {
						return false
					}
					dr := resolveRoot(sel2.X)
					if dr == nil || sum.vars[dr] == nil {
						return false
					}
					if targetAssign != nil && targetAssign != as2 {
						return false
					}
					targetAssign = as2
					dstRoot = dr
					if extCtor.Origin().Pkg() != p.Types {
						recordFreshVarGuardPkg(sum, srcVar, extCtor.Origin().Pkg().Path())
						recordFreshVarGuardPkg(sum, dr, extCtor.Origin().Pkg().Path())
					}
				}
			}
			if !sawCarrierOut || dstRoot == nil {
				return false
			}
			*couplings = append(*couplings, freshEscapeCoupling{srcRoot: sum.vars[srcVar].rootVar, dstRoot: dstRoot, atPos: targetAssign.Pos()})
		}
		return true
	}

	sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !isSel {
		return false
	}
	selInfo := p.TypesInfo.Selections[sel]
	if selInfo == nil || (selInfo.Kind() != types.MethodVal && selInfo.Kind() != types.MethodExpr) {
		return false
	}
	dummyPF := &PkgFreshConstructors{p: p, idx: idx, funcs: map[*ast.FuncDecl]*freshFuncSummary{fd: sum}}
	if selInfo.Kind() == types.MethodVal && argIdx >= 0 {
		if !dummyPF.isFreshContainerAt(sum, sel.X, call.Pos()) {
			return false
		}
	}
	for _, a := range call.Args {
		if refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(a)) && !dummyPF.isFreshContainerAt(sum, a, call.Pos()) {
			return false
		}
	}
	sig, okSig := p.TypesInfo.TypeOf(call.Fun).(*types.Signature)
	if !okSig {
		return false
	}
	if sig.Results().Len() == 0 {
		return true
	}
	allScalarOrErr := true
	for ri := 0; ri < sig.Results().Len(); ri++ {
		rt := sig.Results().At(ri).Type()
		if refconfine.TypeContainsRefOrPointer(rt) && !syntaxutil.IsErrorType(rt) {
			allScalarOrErr = false
			break
		}
	}
	if allScalarOrErr {
		return true
	}
	return callResultStaysLocal(p, idx, call, nonEscAuxVars)
}

func callResultStaysLocal(p *packages.Package, idx *refconfine.PkgIndex, call *ast.CallExpr, nonEscAuxVars map[*types.Var]bool) bool {
	return exprResultStaysLocalWithDepth(p, idx, call, nonEscAuxVars, 0)
}

func exprResultStaysLocalWithDepth(p *packages.Package, idx *refconfine.PkgIndex, start ast.Expr, nonEscAuxVars map[*types.Var]bool, depth int) bool {
	if depth > 4 {
		return false
	}
	checkBoundLocalVar := func(v *types.Var) bool {
		if v == nil || idx.DefCounts[v] != 1 {
			return false
		}
		for _, uid := range idx.UsesOf[v] {
			if idx.InFuncLit[uid] || idx.InGoStmt[uid] {
				return false
			}
			up := idx.ParentUnparen(uid)
			if bs, isBin := up.(*ast.BinaryExpr); isBin && (bs.Op == token.EQL || bs.Op == token.NEQ) {
				continue
			}
			if usel, isUS := up.(*ast.SelectorExpr); isUS && ast.Unparen(usel.X) == uid {
				if mc, isMC := idx.ParentUnparen(usel).(*ast.CallExpr); isMC && ast.Unparen(mc.Fun) == usel {
					if !refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(mc)) || exprResultStaysLocalWithDepth(p, idx, mc, nonEscAuxVars, depth+1) {
						continue
					}
				}
			}
			if upTA, isTA := up.(*ast.TypeAssertExpr); isTA && ast.Unparen(upTA.X) == uid && upTA.Type != nil {
				if !refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(upTA)) || exprResultStaysLocalWithDepth(p, idx, upTA, nonEscAuxVars, depth+1) {
					continue
				}
			}
			if upAs, isUpAs := up.(*ast.AssignStmt); isUpAs && len(upAs.Lhs) == 1 && len(upAs.Rhs) == 1 && ast.Unparen(upAs.Rhs[0]) == uid {
				if ix, isIx := ast.Unparen(upAs.Lhs[0]).(*ast.IndexExpr); isIx {
					mv := syntaxutil.LookupIdentVar(p.TypesInfo, ix.X)
					enclFD := idx.SyncEnclFuncDecl(uid)
					if mv != nil && nonEscAuxVars[mv] && idx.DefCounts[mv] == 1 && mv.Parent() != p.Types.Scope() &&
						enclFD != nil && enclFD.Body != nil && enclFD.Body.Pos() <= mv.Pos() && mv.Pos() < enclFD.Body.End() {
						allMapReadsLocal := true
						for _, muid := range idx.UsesOf[mv] {
							if idx.InFuncLit[muid] || idx.InGoStmt[muid] {
								allMapReadsLocal = false
								break
							}
							mix, isMix := idx.ParentUnparen(muid).(*ast.IndexExpr)
							if !isMix || ast.Unparen(mix.X) != muid {
								allMapReadsLocal = false
								break
							}
							if mAs, isMAs := idx.ParentUnparen(mix).(*ast.AssignStmt); isMAs && len(mAs.Lhs) == 1 && ast.Unparen(mAs.Lhs[0]) == mix {
								continue
							}
							if !exprResultStaysLocalWithDepth(p, idx, mix, nonEscAuxVars, depth+1) {
								allMapReadsLocal = false
								break
							}
						}
						if allMapReadsLocal {
							continue
						}
					}
				}
			}
			return false
		}
		return true
	}

	cur := ast.Unparen(start)
	for {
		par := idx.ParentUnparen(cur)
		switch x := par.(type) {
		case *ast.TypeAssertExpr:
			if ast.Unparen(x.X) == cur && x.Type != nil {
				if !refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(x)) {
					return true
				}
				cur = x
				continue
			}
			return false
		case *ast.SelectorExpr:
			if ast.Unparen(x.X) == cur {
				si := p.TypesInfo.Selections[x]
				if si != nil && si.Kind() == types.MethodVal {
					mc, isMC := idx.ParentUnparen(x).(*ast.CallExpr)
					if !isMC || ast.Unparen(mc.Fun) != x {
						return false
					}
					for _, ma := range mc.Args {
						if refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(ma)) {
							return false
						}
					}
					if !refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(mc)) {
						return true
					}
					cur = mc
					continue
				}
			}
			return false
		case *ast.BinaryExpr:
			return x.Op == token.EQL || x.Op == token.NEQ
		case *ast.CallExpr:
			if sel, isS := ast.Unparen(x.Fun).(*ast.SelectorExpr); isS {
				if mv := syntaxutil.LookupIdentVar(p.TypesInfo, sel.X); mv != nil && nonEscAuxVars[mv] {
					callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun)
					if callee != nil && callee.Pkg() == p.Types && !callee.Exported() {
						return true
					}
				}
			}
			return false
		case *ast.AssignStmt:
			if len(x.Rhs) == 1 && ast.Unparen(x.Rhs[0]) == cur {
				if len(x.Lhs) == 2 && (syntaxutil.IsBlankIdent(x.Lhs[1]) || !refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(x.Lhs[1]))) {
					if syntaxutil.IsBlankIdent(x.Lhs[0]) {
						return true
					}
					if lid, isID := ast.Unparen(x.Lhs[0]).(*ast.Ident); isID {
						v, _ := p.TypesInfo.Defs[lid].(*types.Var)
						return checkBoundLocalVar(v)
					}
				}
				if len(x.Lhs) == 1 {
					if syntaxutil.IsBlankIdent(x.Lhs[0]) {
						return true
					}
					if lid, isID := ast.Unparen(x.Lhs[0]).(*ast.Ident); isID {
						v, _ := p.TypesInfo.Defs[lid].(*types.Var)
						return checkBoundLocalVar(v)
					}
				}
			}
			return false
		default:
			return false
		}
	}
}
