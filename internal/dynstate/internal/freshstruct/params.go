package freshstruct

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

type funcParamAliasIndex struct {
	paramSlotOfVar map[*types.Var]int
	typeSwitchSucc map[*types.Var][]*types.Var
	ifaceLocalDeps map[*types.Var][]*types.Var
}

func methodChainRootVar(p *packages.Package, expr ast.Expr) *types.Var {
	cur := ast.Unparen(expr)
	sawCall := false
	for {
		mc, isMC := cur.(*ast.CallExpr)
		if !isMC || mc.Ellipsis.IsValid() {
			break
		}
		for _, ma := range mc.Args {
			if refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(ma)) {
				return nil
			}
		}
		sel, isSel := ast.Unparen(mc.Fun).(*ast.SelectorExpr)
		if !isSel {
			return nil
		}
		si := p.TypesInfo.Selections[sel]
		if si == nil || si.Kind() != types.MethodVal {
			return nil
		}
		sawCall = true
		cur = ast.Unparen(sel.X)
	}
	if !sawCall {
		return nil
	}
	for {
		sel, isSel := cur.(*ast.SelectorExpr)
		if !isSel {
			break
		}
		si := p.TypesInfo.Selections[sel]
		if si == nil || si.Kind() != types.FieldVal {
			return nil
		}
		cur = ast.Unparen(sel.X)
	}
	return syntaxutil.LookupIdentVar(p.TypesInfo, cur)
}

func preindexIntraParamAliases(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	eligibleUnexported map[*types.Func]*ast.FuncDecl,
) map[*ast.FuncDecl]*funcParamAliasIndex {
	out := make(map[*ast.FuncDecl]*funcParamAliasIndex, len(eligibleUnexported))
	for fn, fd := range eligibleUnexported {
		if fn == nil || fd == nil || fd.Body == nil {
			continue
		}
		sig, okS := fn.Type().(*types.Signature)
		if !okS {
			continue
		}
		paramSlotOfVar := map[*types.Var]int{}
		if sig.Recv() != nil {
			paramSlotOfVar[sig.Recv()] = -1
		}
		for i := 0; i < sig.Params().Len(); i++ {
			paramSlotOfVar[sig.Params().At(i)] = i
		}
		entry := &funcParamAliasIndex{
			paramSlotOfVar: paramSlotOfVar,
			typeSwitchSucc: map[*types.Var][]*types.Var{},
			ifaceLocalDeps: map[*types.Var][]*types.Var{},
		}
		seenIfaceLocal := map[*types.Var]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.TypeSwitchStmt:
				var switchedExpr ast.Expr
				if as, isAs := s.Assign.(*ast.AssignStmt); isAs && len(as.Rhs) == 1 {
					if ta, isTA := ast.Unparen(as.Rhs[0]).(*ast.TypeAssertExpr); isTA {
						switchedExpr = ta.X
					}
				}
				if sv := syntaxutil.LookupIdentVar(p.TypesInfo, switchedExpr); sv != nil && s.Body != nil {
					for _, st := range s.Body.List {
						if cc, isCC := st.(*ast.CaseClause); isCC {
							if imp, okI := p.TypesInfo.Implicits[cc].(*types.Var); okI && imp != nil {
								entry.typeSwitchSucc[sv] = append(entry.typeSwitchSucc[sv], imp)
							}
						}
					}
				}
			case *ast.AssignStmt:
				if len(s.Lhs) == 1 && len(s.Rhs) == 1 {
					lid, isID := ast.Unparen(s.Lhs[0]).(*ast.Ident)
					if !isID {
						return true
					}
					var lv *types.Var
					if dv, okD := p.TypesInfo.Defs[lid].(*types.Var); okD && dv != nil && idx.DefCounts[dv] == 1 {
						lv = dv
					} else if uv, okU := p.TypesInfo.Uses[lid].(*types.Var); okU && uv != nil && uv.Parent() != p.Types.Scope() && !paramSlotHas(paramSlotOfVar, uv) && idx.DefCounts[uv] == 1 {
						lv = uv
					}
					if lv == nil || !types.IsInterface(lv.Type()) || seenIfaceLocal[lv] {
						return true
					}
					seenIfaceLocal[lv] = true
					var deps []*types.Var
					allValid := true
					for _, uid := range idx.UsesOf[lv] {
						if upAs, isUpAs := idx.ParentUnparen(uid).(*ast.AssignStmt); isUpAs {
							for _, lhs := range upAs.Lhs {
								if ast.Unparen(lhs) == uid {
									if len(upAs.Lhs) != 1 || len(upAs.Rhs) != 1 {
										allValid = false
										break
									}
									rv := methodChainRootVar(p, upAs.Rhs[0])
									if rv == nil {
										allValid = false
										break
									}
									deps = append(deps, rv)
								}
							}
						}
						if !allValid {
							break
						}
					}
					if allValid {
						if dv, okD := p.TypesInfo.Defs[lid].(*types.Var); okD && dv == lv {
							rv := methodChainRootVar(p, s.Rhs[0])
							if rv == nil {
								allValid = false
							} else {
								deps = append(deps, rv)
							}
						}
					}
					if allValid && len(deps) > 0 {
						entry.ifaceLocalDeps[lv] = deps
					}
				}
			}
			return true
		})
		out[fd] = entry
	}
	return out
}

func computeLocalNonEscapingAuxVars(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	allFDs []*ast.FuncDecl,
	eligibleUnexported map[*types.Func]*ast.FuncDecl,
) map[*types.Var]bool {
	cands := map[*types.Var]bool{}
	for _, fd := range allFDs {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if s, isAs := n.(*ast.AssignStmt); isAs && len(s.Lhs) == len(s.Rhs) && s.Tok == token.DEFINE {
				for i, l := range s.Lhs {
					if lid, isID := ast.Unparen(l).(*ast.Ident); isID {
						v, _ := p.TypesInfo.Defs[lid].(*types.Var)
						if v != nil && idx.DefCounts[v] == 1 && !idx.InFuncLit[lid] && !idx.InGoStmt[lid] && isAuxLocalInit(p, s.Rhs[i]) {
							cands[v] = true
						}
					}
				}
			}
			return true
		})
	}
	for fn := range eligibleUnexported {
		sig, okS := fn.Type().(*types.Signature)
		if !okS || len(idx.UsesOf[fn]) == 0 {
			continue
		}
		if sig.Recv() != nil {
			cands[sig.Recv()] = true
		}
		for i := 0; i < sig.Params().Len(); i++ {
			cands[sig.Params().At(i)] = true
		}
	}

	for {
		changed := false
		for v := range cands {
			bad := false
			for _, uid := range idx.UsesOf[v] {
				if idx.InFuncLit[uid] || idx.InGoStmt[uid] {
					bad = true
					break
				}
				par := idx.ParentUnparen(uid)
				switch x := par.(type) {
				case *ast.IndexExpr:
					if ast.Unparen(x.X) == uid {
						if IdentReachesMutatedOrAddrPrefix(p, idx, uid) {
							if as, isAs := idx.ParentUnparen(x).(*ast.AssignStmt); !isAs || len(as.Lhs) != 1 || ast.Unparen(as.Lhs[0]) != x {
								bad = true
							}
						}
						continue
					}
					bad = true
				case *ast.SelectorExpr:
					if ast.Unparen(x.X) == uid {
						si := p.TypesInfo.Selections[x]
						if si != nil && si.Kind() == types.FieldVal {
							continue
						}
						if si != nil && si.Kind() == types.MethodVal {
							mc, isMC := idx.ParentUnparen(x).(*ast.CallExpr)
							if isMC && ast.Unparen(mc.Fun) == x {
								callee := syntaxutil.ResolveCalledFuncObj(p, mc.Fun)
								if callee != nil && eligibleUnexported[callee.Origin()] != nil {
									if cSig, okCS := callee.Origin().Type().(*types.Signature); okCS && cSig.Recv() != nil && cands[cSig.Recv()] {
										continue
									}
								}
							}
						}
					}
					bad = true
				case *ast.KeyValueExpr:
					if ast.Unparen(x.Value) == uid {
						if cl, isCL := idx.ParentUnparen(x).(*ast.CompositeLit); isCL {
							var holderNode ast.Expr = cl
							if un, isUn := idx.ParentUnparen(cl).(*ast.UnaryExpr); isUn && un.Op == token.AND {
								holderNode = un
							}
							if as, isAs := idx.ParentUnparen(holderNode).(*ast.AssignStmt); isAs && len(as.Lhs) == 1 && as.Tok == token.DEFINE {
								if lid, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident); isID {
									if dv, _ := p.TypesInfo.Defs[lid].(*types.Var); dv != nil && cands[dv] {
										continue
									}
								}
							}
						}
					}
					bad = true
				case *ast.CallExpr:
					callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun)
					if callee != nil && eligibleUnexported[callee.Origin()] != nil && !x.Ellipsis.IsValid() {
						cSig, _ := callee.Origin().Type().(*types.Signature)
						matchedParam := false
						for ai, a := range x.Args {
							if ast.Unparen(a) == uid && cSig != nil && ai < cSig.Params().Len() && cands[cSig.Params().At(ai)] {
								matchedParam = true
							}
						}
						if matchedParam {
							continue
						}
					}
					bad = true
				default:
					bad = true
				}
				if bad {
					break
				}
			}
			if bad {
				delete(cands, v)
				changed = true
			}
		}
		for fn := range eligibleUnexported {
			sig, okS := fn.Type().(*types.Signature)
			if !okS {
				continue
			}
			if rv := sig.Recv(); rv != nil && cands[rv] {
				for _, uid := range idx.UsesOf[fn] {
					call := refconfine.EnclosingCallOfCalleeIdent(idx, uid)
					okSite := false
					if call != nil {
						if sel, isS := ast.Unparen(call.Fun).(*ast.SelectorExpr); isS {
							if si := p.TypesInfo.Selections[sel]; si != nil && si.Kind() == types.MethodVal {
								if mv := syntaxutil.LookupIdentVar(p.TypesInfo, sel.X); mv != nil && cands[mv] {
									okSite = true
								}
							}
						}
					}
					if !okSite {
						delete(cands, rv)
						changed = true
						break
					}
				}
			}
			for pi := 0; pi < sig.Params().Len(); pi++ {
				pv := sig.Params().At(pi)
				if !cands[pv] {
					continue
				}
				for _, uid := range idx.UsesOf[fn] {
					call := refconfine.EnclosingCallOfCalleeIdent(idx, uid)
					if call == nil || call.Ellipsis.IsValid() || pi >= len(call.Args) {
						delete(cands, pv)
						changed = true
						break
					}
					mv := syntaxutil.LookupIdentVar(p.TypesInfo, call.Args[pi])
					if mv == nil || !cands[mv] {
						delete(cands, pv)
						changed = true
						break
					}
				}
			}
		}
		if !changed {
			break
		}
	}
	return cands
}

func isAuxLocalInit(p *packages.Package, expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	switch e := expr.(type) {
	case *ast.CompositeLit:
		return true
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			_, ok := ast.Unparen(e.X).(*ast.CompositeLit)
			return ok
		}
	case *ast.CallExpr:
		if id, isID := ast.Unparen(e.Fun).(*ast.Ident); isID {
			if b, isB := p.TypesInfo.Uses[id].(*types.Builtin); isB && (b.Name() == "make" || b.Name() == "new") {
				return true
			}
		}
	}
	return false
}

func initNonEscapingIntraParams(
	eligibleUnexported map[*types.Func]*ast.FuncDecl,
) (
	nonEsc map[*types.Func]map[int]bool,
	mapStore map[*types.Func]map[int]int,
	retStruct map[*types.Func]map[int]bool,
	guardPkgs map[*types.Func]map[int]map[string]bool,
) {
	nonEsc = map[*types.Func]map[int]bool{}
	mapStore = map[*types.Func]map[int]int{}
	retStruct = map[*types.Func]map[int]bool{}
	guardPkgs = map[*types.Func]map[int]map[string]bool{}

	for fn := range eligibleUnexported {
		sig, okS := fn.Type().(*types.Signature)
		if !okS {
			continue
		}
		nonEsc[fn] = map[int]bool{}
		if sig.Recv() != nil {
			nonEsc[fn][-1] = true
		}
		for i := 0; i < sig.Params().Len(); i++ {
			nonEsc[fn][i] = true
		}
	}
	return nonEsc, mapStore, retStruct, guardPkgs
}

func resolveSummaryRootVar(p *packages.Package, sum *freshFuncSummary, expr ast.Expr) *types.Var {
	if sum == nil {
		return nil
	}
	cur := ast.Unparen(expr)
	for {
		switch e := cur.(type) {
		case *ast.Ident:
			v, _ := p.TypesInfo.Uses[e].(*types.Var)
			if st := sum.vars[v]; st != nil {
				return st.rootVar
			}
			return nil
		case *ast.SelectorExpr:
			selInfo := p.TypesInfo.Selections[e]
			if selInfo == nil || selInfo.Kind() != types.FieldVal || syntaxutil.SelectionCrossesEmbeddedPointer(selInfo) {
				return nil
			}
			cur = ast.Unparen(e.X)
		case *ast.IndexExpr:
			cur = ast.Unparen(e.X)
		case *ast.SliceExpr:
			cur = ast.Unparen(e.X)
		case *ast.StarExpr:
			cur = ast.Unparen(e.X)
		default:
			return nil
		}
	}
}

func stepNonEscapingIntraParams(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	pf *PkgFreshConstructors,
	eligibleUnexported map[*types.Func]*ast.FuncDecl,
	aliasIndex map[*ast.FuncDecl]*funcParamAliasIndex,
	freshReturnFuncs map[*types.Func]bool,
	nonEscAuxVars map[*types.Var]bool,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	nonEsc map[*types.Func]map[int]bool,
	mapStore map[*types.Func]map[int]int,
	retStruct map[*types.Func]map[int]bool,
	guardPkgs map[*types.Func]map[int]map[string]bool,
) bool {
	anyChanged := false
	for {
		changed := false
		for fn, fd := range eligibleUnexported {
			sig, _ := fn.Type().(*types.Signature)
			slots := nonEsc[fn]
			fIdx := aliasIndex[fd]
			if len(slots) == 0 || sig == nil || fIdx == nil {
				continue
			}
			paramSlotOfVar := fIdx.paramSlotOfVar

			checkSlot := func(slot int, pv *types.Var) (ok bool, needMapSlot int, hasMap bool, needRet bool, slotGuards map[string]bool) {
				hasMap = false
				slotGuards = map[string]bool{}
				trackedVars := map[*types.Var]bool{pv: true}
				returnOnlyVars := map[*types.Var]bool{}

				for {
					addedTracked := false
					for tv := range trackedVars {
						for _, imp := range fIdx.typeSwitchSucc[tv] {
							if !trackedVars[imp] {
								trackedVars[imp] = true
								addedTracked = true
							}
						}
					}
					for lv, deps := range fIdx.ifaceLocalDeps {
						if trackedVars[lv] {
							continue
						}
						allFromTracked := true
						for _, d := range deps {
							if !trackedVars[d] {
								allFromTracked = false
								break
							}
						}
						if allFromTracked {
							trackedVars[lv] = true
							addedTracked = true
						}
					}
					if !addedTracked {
						break
					}
				}

				mcResultAccounted := func(mc *ast.CallExpr) bool {
					if !refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(mc)) && !syntaxutil.ContainsUintptr(p.TypesInfo.TypeOf(mc)) {
						return true
					}
					if callResultStaysLocal(p, idx, mc, nil) {
						return true
					}
					curOut := ast.Expr(mc)
					for {
						upSel, isUS := idx.ParentUnparen(curOut).(*ast.SelectorExpr)
						if !isUS || ast.Unparen(upSel.X) != curOut {
							break
						}
						si := p.TypesInfo.Selections[upSel]
						if si == nil || si.Kind() != types.MethodVal {
							break
						}
						upMC, isUMC := idx.ParentUnparen(upSel).(*ast.CallExpr)
						if !isUMC || ast.Unparen(upMC.Fun) != upSel {
							return false
						}
						for _, ma := range upMC.Args {
							if refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(ma)) {
								return false
							}
						}
						if !refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(upMC)) && !syntaxutil.ContainsUintptr(p.TypesInfo.TypeOf(upMC)) {
							return true
						}
						curOut = upMC
					}
					if as, isAs := idx.ParentUnparen(curOut).(*ast.AssignStmt); isAs && len(as.Lhs) == 1 && len(as.Rhs) == 1 && ast.Unparen(as.Rhs[0]) == curOut {
						if lv := syntaxutil.LookupIdentVar(p.TypesInfo, as.Lhs[0]); lv != nil && trackedVars[lv] {
							return true
						}
					}
					kvParent := idx.ParentUnparen(curOut)
					if ta, isTA := kvParent.(*ast.TypeAssertExpr); isTA && ast.Unparen(ta.X) == curOut && ta.Type != nil {
						kvParent = idx.ParentUnparen(ta)
					}
					if kv, isKV := kvParent.(*ast.KeyValueExpr); isKV {
						if cl, isCL := idx.ParentUnparen(kv).(*ast.CompositeLit); isCL {
							if ret, isRet := idx.ParentUnparen(cl).(*ast.ReturnStmt); isRet && len(ret.Results) >= 1 && ast.Unparen(ret.Results[0]) == cl {
								needRet = true
								return true
							}
						}
					}
					return false
				}

				for tv := range trackedVars {
					for _, uid := range idx.UsesOf[tv] {
						if idx.InFuncLit[uid] || idx.InGoStmt[uid] {
							return false, 0, false, false, nil
						}
						if tv != pv {
							if upAs, isUpAs := idx.ParentUnparen(uid).(*ast.AssignStmt); isUpAs && len(upAs.Lhs) == 1 && ast.Unparen(upAs.Lhs[0]) == uid {
								continue
							}
						}
						cur := ast.Expr(uid)
						methodHandled := false
						for {
							par := idx.ParentUnparen(cur)
							if sel, isS := par.(*ast.SelectorExpr); isS && ast.Unparen(sel.X) == cur {
								si := p.TypesInfo.Selections[sel]
								if si != nil && si.Kind() == types.FieldVal {
									cur = sel
									continue
								}
								if si != nil && si.Kind() == types.MethodVal {
									mc, isMC := idx.ParentUnparen(sel).(*ast.CallExpr)
									if !isMC || ast.Unparen(mc.Fun) != sel || mc.Ellipsis.IsValid() {
										return false, 0, false, false, nil
									}
									for _, ma := range mc.Args {
										if refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(ma)) {
											return false, 0, false, false, nil
										}
									}
									if !mcResultAccounted(mc) {
										return false, 0, false, false, nil
									}
									methodHandled = true
								}
							}
							break
						}
						if methodHandled {
							continue
						}
						par := idx.ParentUnparen(cur)
						switch x := par.(type) {
						case *ast.TypeAssertExpr:
							if ast.Unparen(x.X) == cur {
								if x.Type == nil {
									continue
								}
								if as, isAs := idx.ParentUnparen(x).(*ast.AssignStmt); isAs && len(as.Lhs) == 2 && len(as.Rhs) == 1 && ast.Unparen(as.Rhs[0]) == x && syntaxutil.IsBlankIdent(as.Lhs[0]) {
									continue
								}
							}
							return false, 0, false, false, nil
						case *ast.AssignStmt:
							for _, l := range x.Lhs {
								if ast.Unparen(l) == cur {
									return false, 0, false, false, nil
								}
							}
							if len(x.Lhs) == 1 && len(x.Rhs) == 1 && ast.Unparen(x.Rhs[0]) == cur {
								if !refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
									continue
								}
								if ix, isIx := ast.Unparen(x.Lhs[0]).(*ast.IndexExpr); isIx && cur == uid {
									if mv := syntaxutil.LookupIdentVar(p.TypesInfo, ix.X); mv != nil {
										if ms, okMS := paramSlotOfVar[mv]; okMS {
											if hasMap && needMapSlot != ms {
												return false, 0, false, false, nil
											}
											hasMap = true
											needMapSlot = ms
											continue
										}
									}
								}
							}
							return false, 0, false, false, nil
						case *ast.KeyValueExpr:
							if ast.Unparen(x.Value) == cur && cur == uid {
								if cl, isCL := idx.ParentUnparen(x).(*ast.CompositeLit); isCL {
									if ret, isRet := idx.ParentUnparen(cl).(*ast.ReturnStmt); isRet && len(ret.Results) >= 1 && ast.Unparen(ret.Results[0]) == cl {
										needRet = true
										continue
									}
								}
							}
							return false, 0, false, false, nil
						case *ast.BinaryExpr:
							if x.Op == token.EQL || x.Op == token.NEQ || !refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
								continue
							}
							return false, 0, false, false, nil
						case *ast.CallExpr:
							if !refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
								continue
							}
							callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun)
							if callee == nil || x.Ellipsis.IsValid() {
								return false, 0, false, false, nil
							}
							orig := callee.Origin()
							if orig.Pkg() != nil && orig.Pkg() != p.Types {
								slotGuards[orig.Pkg().Path()] = true
								if !refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(x)) && !syntaxutil.ContainsUintptr(p.TypesInfo.TypeOf(x)) {
									continue
								}
								as, isAs := idx.ParentUnparen(x).(*ast.AssignStmt)
								if !isAs || len(as.Rhs) != 1 || ast.Unparen(as.Rhs[0]) != x {
									return false, 0, false, false, nil
								}
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
										return false, 0, false, false, nil
									}
									lv, isDef := p.TypesInfo.Defs[lid].(*types.Var)
									if !isDef || lv == nil || idx.DefCounts[lv] != 1 {
										return false, 0, false, false, nil
									}
									returnOnlyVars[lv] = true
									needRet = true
								}
								continue
							}
							if orig.Pkg() != p.Types || eligibleUnexported[orig] == nil {
								return false, 0, false, false, nil
							}
							matched := false
							calleeNeedsRet := false
							for ai, a := range x.Args {
								if ast.Unparen(a) == cur {
									cSlot := ai
									if sel, isS := ast.Unparen(x.Fun).(*ast.SelectorExpr); isS {
										if si := p.TypesInfo.Selections[sel]; si != nil && si.Kind() == types.MethodExpr {
											cSlot = ai - 1
										}
									}
									if !nonEsc[orig][cSlot] {
										matched = false
										break
									}
									matched = true
									for g := range guardPkgs[orig][cSlot] {
										slotGuards[g] = true
									}
									if origMSlot, hasOrigMap := mapStore[orig][cSlot]; hasOrigMap {
										var mapArg ast.Expr
										if origMSlot == -1 {
											if sel, isS := ast.Unparen(x.Fun).(*ast.SelectorExpr); isS {
												if si := p.TypesInfo.Selections[sel]; si != nil && si.Kind() == types.MethodVal {
													mapArg = sel.X
												} else if si != nil && si.Kind() == types.MethodExpr && len(x.Args) > 0 {
													mapArg = x.Args[0]
												}
											}
										} else if origMSlot >= 0 && origMSlot < len(x.Args) {
											mapArg = x.Args[origMSlot]
										}
										mv := syntaxutil.LookupIdentVar(p.TypesInfo, mapArg)
										if mv == nil {
											matched = false
											break
										}
										if !nonEscAuxVars[mv] {
											callerMSlot, okCMS := paramSlotOfVar[mv]
											if !okCMS || (hasMap && needMapSlot != callerMSlot) {
												matched = false
												break
											}
											hasMap = true
											needMapSlot = callerMSlot
										}
									}
									if retStruct[orig][cSlot] {
										calleeNeedsRet = true
									}
								}
							}
							if !matched {
								return false, 0, false, false, nil
							}
							if calleeNeedsRet {
								callParent := idx.ParentUnparen(x)
								if ret, isRet := callParent.(*ast.ReturnStmt); isRet {
									if len(ret.Results) == 0 || ast.Unparen(ret.Results[0]) != x {
										return false, 0, false, false, nil
									}
									needRet = true
									continue
								}
								as, isAs := callParent.(*ast.AssignStmt)
								if !isAs || len(as.Rhs) != 1 || ast.Unparen(as.Rhs[0]) != x || len(as.Lhs) == 0 {
									return false, 0, false, false, nil
								}
								fnSum := pf.funcs[fd]
								for _, lhs := range as.Lhs {
									if syntaxutil.IsBlankIdent(lhs) {
										continue
									}
									lt := p.TypesInfo.TypeOf(lhs)
									if (!refconfine.TypeContainsRefOrPointer(lt) && !syntaxutil.ContainsUintptr(lt)) || syntaxutil.IsErrorType(lt) {
										continue
									}
									if lid, isID := ast.Unparen(lhs).(*ast.Ident); isID {
										lv, isDef := p.TypesInfo.Defs[lid].(*types.Var)
										if !isDef || lv == nil || idx.DefCounts[lv] != 1 {
											return false, 0, false, false, nil
										}
										returnOnlyVars[lv] = true
										needRet = true
										continue
									}
									sel, isSel := ast.Unparen(lhs).(*ast.SelectorExpr)
									if !isSel || !freshReturnFuncs[fn] || fdInConfinedCache(fd, confinedCacheMaps) || fnSum == nil {
										return false, 0, false, false, nil
									}
									if !pf.isFreshContainerAt(fnSum, sel.X, as.Pos()) {
										return false, 0, false, false, nil
									}
									dstRoot := resolveSummaryRootVar(p, fnSum, sel.X)
									if dstRoot == nil || paramSlotHas(paramSlotOfVar, dstRoot) {
										return false, 0, false, false, nil
									}
									rootSt := fnSum.vars[dstRoot]
									if rootSt == nil || rootSt.rootVar != dstRoot || rootSt.escapePos != token.NoPos {
										return false, 0, false, false, nil
									}
									needRet = true
								}
							}
							continue
						default:
							if cur != uid && !refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(cur)) {
								continue
							}
							return false, 0, false, false, nil
						}
					}
				}

				for rv := range returnOnlyVars {
					for _, uid := range idx.UsesOf[rv] {
						if idx.InFuncLit[uid] || idx.InGoStmt[uid] {
							return false, 0, false, false, nil
						}
						par := idx.ParentUnparen(uid)
						if _, isRet := par.(*ast.ReturnStmt); isRet {
							continue
						}
						if as, isAs := par.(*ast.AssignStmt); isAs && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 && ast.Unparen(as.Lhs[0]) == uid {
							rhs := ast.Unparen(as.Rhs[0])
							if c, isC := rhs.(*ast.CallExpr); isC && !c.Ellipsis.IsValid() {
								extFn := syntaxutil.ResolveCalledFuncObj(p, c.Fun)
								if extFn != nil && extFn.Origin().Pkg() != nil {
									allScalarArgs := true
									for _, ca := range c.Args {
										if refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(ca)) || syntaxutil.ContainsUintptr(p.TypesInfo.TypeOf(ca)) {
											allScalarArgs = false
											break
										}
									}
									if allScalarArgs {
										if extFn.Origin().Pkg() != p.Types {
											slotGuards[extFn.Origin().Pkg().Path()] = true
										}
										continue
									}
								}
							}
						}
						return false, 0, false, false, nil
					}
				}

				return true, needMapSlot, hasMap, needRet, slotGuards
			}

			for slot := range slots {
				var pv *types.Var
				if slot == -1 {
					pv = sig.Recv()
				} else if slot >= 0 && slot < sig.Params().Len() {
					pv = sig.Params().At(slot)
				}
				if pv == nil {
					delete(slots, slot)
					changed = true
					continue
				}
				ok, mSlot, hasMap, needRet, sGuards := checkSlot(slot, pv)
				if !ok {
					delete(slots, slot)
					if mapStore[fn] != nil {
						delete(mapStore[fn], slot)
					}
					if retStruct[fn] != nil {
						delete(retStruct[fn], slot)
					}
					if guardPkgs[fn] != nil {
						delete(guardPkgs[fn], slot)
					}
					changed = true
					continue
				}
				if hasMap {
					if mapStore[fn] == nil {
						mapStore[fn] = map[int]int{}
					}
					if prev, had := mapStore[fn][slot]; !had || prev != mSlot {
						mapStore[fn][slot] = mSlot
						changed = true
					}
				}
				if needRet {
					if retStruct[fn] == nil {
						retStruct[fn] = map[int]bool{}
					}
					if !retStruct[fn][slot] {
						retStruct[fn][slot] = true
						changed = true
					}
				}
				if len(sGuards) > 0 {
					if guardPkgs[fn] == nil {
						guardPkgs[fn] = map[int]map[string]bool{}
					}
					if guardPkgs[fn][slot] == nil {
						guardPkgs[fn][slot] = map[string]bool{}
					}
					for g := range sGuards {
						if !guardPkgs[fn][slot][g] {
							guardPkgs[fn][slot][g] = true
							changed = true
						}
					}
				}
			}
		}
		if changed {
			anyChanged = true
		} else {
			break
		}
	}
	return anyChanged
}

func paramSlotHas(m map[*types.Var]int, v *types.Var) bool {
	_, ok := m[v]
	return ok
}
