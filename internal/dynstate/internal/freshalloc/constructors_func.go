package freshalloc

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type freshAliasDef struct {
	v       *types.Var
	pos     token.Pos
	addrArg ast.Expr
}

type freshConstructorFuncAnalyzer struct {
	p                 *packages.Package
	idx               *refconfine.PkgIndex
	fd                *ast.FuncDecl
	fn                *types.Func
	sum               *freshFuncSummary
	dummyPF           *PkgFreshConstructors
	freshReturnFuncs  map[*types.Func]bool
	freshParamFuncs   map[*types.Func]map[int]bool
	nonEscParams      map[*types.Func]map[int]bool
	mapStoreParams    map[*types.Func]map[int]int
	retStructParams   map[*types.Func]map[int]bool
	paramGuardPkgs    map[*types.Func]map[int]map[string]bool
	nonEscAuxVars     map[*types.Var]bool
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool

	params             map[*types.Var]bool
	namedResults       map[*types.Var]bool
	disqualified       map[*types.Var]bool
	topStmtIndex       map[ast.Stmt]int
	initialDefTopIdx   map[*types.Var]int
	rebindTopIdx       map[*types.Var]int
	rebindAssign       map[*types.Var]*ast.AssignStmt
	assignCount        map[*types.Var]int
	selfAppendSeen     map[*types.Var]bool
	loops              []ast.Node
	defers             []*ast.DeferStmt
	aliasDefs          []freshAliasDef
	deferredAppendVars []deferredAppendElemVar
	deferredFieldVars  []deferredFieldAssignVar
	nonReturnEscaped   map[*types.Var]bool
}

func analyzeSingleFreshConstructorFunc(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	fd *ast.FuncDecl,
	fn *types.Func,
	freshReturnFuncs map[*types.Func]bool,
	freshParamFuncs map[*types.Func]map[int]bool,
	nonEscParams map[*types.Func]map[int]bool,
	mapStoreParams map[*types.Func]map[int]int,
	retStructParams map[*types.Func]map[int]bool,
	paramGuardPkgs map[*types.Func]map[int]map[string]bool,
	nonEscAuxVars map[*types.Var]bool,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
) *freshFuncSummary {
	sum := &freshFuncSummary{
		fd:             fd,
		fn:             fn,
		vars:           map[*types.Var]*freshVarState{},
		nonFreshFields: map[*types.Var]bool{},
		coneCallees:    map[*types.Func]bool{},
	}
	a := &freshConstructorFuncAnalyzer{
		p:                 p,
		idx:               idx,
		fd:                fd,
		fn:                fn,
		sum:               sum,
		dummyPF:           &PkgFreshConstructors{p: p, idx: idx, funcs: map[*ast.FuncDecl]*freshFuncSummary{fd: sum}},
		freshReturnFuncs:  freshReturnFuncs,
		freshParamFuncs:   freshParamFuncs,
		nonEscParams:      nonEscParams,
		mapStoreParams:    mapStoreParams,
		retStructParams:   retStructParams,
		paramGuardPkgs:    paramGuardPkgs,
		nonEscAuxVars:     nonEscAuxVars,
		confinedCacheMaps: confinedCacheMaps,
		params:            map[*types.Var]bool{},
		namedResults:      map[*types.Var]bool{},
		disqualified:      map[*types.Var]bool{},
		topStmtIndex:      map[ast.Stmt]int{},
		initialDefTopIdx:  map[*types.Var]int{},
		rebindTopIdx:      map[*types.Var]int{},
		rebindAssign:      map[*types.Var]*ast.AssignStmt{},
		assignCount:       map[*types.Var]int{},
		selfAppendSeen:    map[*types.Var]bool{},
	}
	a.initSignatureCandidates()
	a.collectCandidatesAndFieldWrites()
	a.resolveRebindsAndAliases()
	a.solveEscapeFixpoint()
	a.resolveDeferredFieldFreshness()
	return sum
}

func (a *freshConstructorFuncAnalyzer) initSignatureCandidates() {
	if a.fn != nil {
		if sig, okS := a.fn.Type().(*types.Signature); okS {
			if sig.Recv() != nil {
				a.params[sig.Recv()] = true
			}
			for i := 0; i < sig.Params().Len(); i++ {
				pv := sig.Params().At(i)
				a.params[pv] = true
				if a.freshParamFuncs[a.fn][i] {
					_, isSl := syntaxutil.UnderlyingType(pv.Type()).(*types.Slice)
					a.sum.vars[pv] = &freshVarState{
						rootVar:    pv,
						declPos:    a.fd.Body.Pos(),
						escapePos:  token.NoPos,
						isValSlice: isSl,
					}
				}
			}
			for i := 0; i < sig.Results().Len(); i++ {
				rv := sig.Results().At(i)
				a.params[rv] = true
				a.namedResults[rv] = true
			}
		}
	}
	for rv := range a.namedResults {
		if isFreshConstructableRootType(rv.Type()) {
			_, isSl := syntaxutil.UnderlyingType(rv.Type()).(*types.Slice)
			a.sum.vars[rv] = &freshVarState{
				rootVar:    rv,
				declPos:    a.fd.Body.Pos(),
				escapePos:  token.NoPos,
				isValSlice: isSl,
			}
		}
	}
	for i, st := range a.fd.Body.List {
		a.topStmtIndex[st] = i
	}
}

func (a *freshConstructorFuncAnalyzer) collectCandidatesAndFieldWrites() {
	p, sum := a.p, a.sum
	ast.Inspect(a.fd.Body, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		if lit, isLit := n.(*ast.FuncLit); isLit {
			inspectClosureForFieldFreshness(p, lit.Body, a.freshReturnFuncs, sum.nonFreshFields, sum.coneCallees)
			return false
		}
		switch s := n.(type) {
		case *ast.CompositeLit:
			recordCompositeLitNonFreshFieldsWithDeferred(p, s, a.freshReturnFuncs, sum.nonFreshFields, sum, &a.deferredFieldVars)
		case *ast.ForStmt:
			a.loops = append(a.loops, s)
		case *ast.RangeStmt:
			a.loops = append(a.loops, s)
			if s.Key != nil {
				if v := syntaxutil.LookupIdentVar(p.TypesInfo, s.Key); v != nil {
					a.disqualified[v] = true
				}
				if s.Tok == token.ASSIGN {
					markAssignLHSFieldNonFresh(p, s.Key, sum.nonFreshFields)
				}
			}
			if s.Value != nil {
				if v := syntaxutil.LookupIdentVar(p.TypesInfo, s.Value); v != nil {
					a.disqualified[v] = true
				}
				if s.Tok == token.ASSIGN {
					markAssignLHSFieldNonFresh(p, s.Value, sum.nonFreshFields)
				}
			}
		case *ast.DeferStmt:
			a.defers = append(a.defers, s)
		case *ast.ValueSpec:
			a.inspectValueSpec(s)
		case *ast.UnaryExpr:
			if s.Op == token.AND {
				if v := syntaxutil.LookupIdentVar(p.TypesInfo, s.X); v != nil {
					if _, isSl := syntaxutil.UnderlyingType(v.Type()).(*types.Slice); !isSl {
						a.disqualified[v] = true
					}
				}
				if sel, isSel := ast.Unparen(s.X).(*ast.SelectorExpr); isSel {
					if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.FieldVal {
						if fObj, _ := selInfo.Obj().(*types.Var); fObj != nil && isRefOrContainerType(fObj.Type()) {
							sum.nonFreshFields[fObj] = true
						}
					}
				}
			}
		case *ast.AssignStmt:
			a.inspectAssignStmt(s)
		case *ast.ReturnStmt:
			if len(s.Results) > 0 {
				if cl := unwrapCompositeLit(s.Results[0]); cl != nil {
					recordCompositeLitNonFreshFieldsWithDeferred(p, cl, a.freshReturnFuncs, sum.nonFreshFields, sum, &a.deferredFieldVars)
				}
				if call, isCall := ast.Unparen(s.Results[0]).(*ast.CallExpr); isCall {
					if callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun); callee != nil && callee.Origin().Pkg() == p.Types {
						sum.coneCallees[callee.Origin()] = true
					}
				}
			}
		case *ast.CallExpr:
			if callee := syntaxutil.ResolveCalledFuncObj(p, s.Fun); callee != nil && callee.Origin().Pkg() == p.Types {
				sum.coneCallees[callee.Origin()] = true
			}
			if b := syntaxutil.LookupBuiltin(p.TypesInfo, ast.Unparen(s.Fun)); b != nil {
				switch b.Name() {
				case "delete", "clear", "copy":
					if len(s.Args) >= 1 {
						markAssignLHSFieldNonFresh(p, s.Args[0], sum.nonFreshFields)
					}
				}
			}
		}
		return true
	})

	for v := range a.disqualified {
		delete(sum.vars, v)
	}
}

func (a *freshConstructorFuncAnalyzer) inspectValueSpec(s *ast.ValueSpec) {
	p, idx, sum := a.p, a.idx, a.sum
	for i, nm := range s.Names {
		v, ok := p.TypesInfo.Defs[nm].(*types.Var)
		if !ok || v == nil || a.params[v] || v.Parent() == p.Types.Scope() {
			continue
		}
		if idx.DefCounts[v] != 1 || idx.InFuncLit[nm] || idx.InGoStmt[nm] {
			a.disqualified[v] = true
			continue
		}
		if len(s.Values) == 0 {
			if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr && isFreshConstructableRootType(v.Type()) {
				_, isSl := syntaxutil.UnderlyingType(v.Type()).(*types.Slice)
				sum.vars[v] = &freshVarState{rootVar: v, declPos: nm.Pos(), escapePos: token.NoPos, isValSlice: isSl}
			}
		} else if i < len(s.Values) {
			rhs := s.Values[i]
			if isDirectFreshConstructExpr(p, rhs, a.freshReturnFuncs) {
				_, isSl := syntaxutil.UnderlyingType(v.Type()).(*types.Slice)
				sum.vars[v] = &freshVarState{rootVar: v, declPos: nm.Pos(), escapePos: token.NoPos, isValSlice: isSl}
				if cl := unwrapCompositeLit(rhs); cl != nil {
					recordCompositeLitNonFreshFieldsWithDeferred(p, cl, a.freshReturnFuncs, sum.nonFreshFields, sum, &a.deferredFieldVars)
				} else {
					recordAppendElemNonFreshFields(p, rhs, a.freshReturnFuncs, sum.nonFreshFields, &a.deferredAppendVars)
				}
			} else if un, isUn := ast.Unparen(rhs).(*ast.UnaryExpr); isUn && un.Op == token.AND {
				a.aliasDefs = append(a.aliasDefs, freshAliasDef{v: v, pos: nm.Pos(), addrArg: un.X})
			}
		}
	}
}

func (a *freshConstructorFuncAnalyzer) inspectAssignStmt(s *ast.AssignStmt) {
	p, idx, sum := a.p, a.idx, a.sum
	if len(s.Lhs) >= 2 && len(s.Rhs) == 1 {
		if call, isCall := ast.Unparen(s.Rhs[0]).(*ast.CallExpr); isCall {
			if callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun); callee != nil {
				orig := callee.Origin()
				if orig.Pkg() == p.Types {
					sum.coneCallees[orig] = true
				}
				if len(s.Lhs) == 2 && a.freshReturnFuncs[orig] {
					l0 := s.Lhs[0]
					if lid, isID := ast.Unparen(l0).(*ast.Ident); isID {
						if v, _ := p.TypesInfo.Defs[lid].(*types.Var); v != nil && !a.params[v] && v.Parent() != p.Types.Scope() && idx.DefCounts[v] == 1 {
							_, isSl := syntaxutil.UnderlyingType(v.Type()).(*types.Slice)
							sum.vars[v] = &freshVarState{rootVar: v, declPos: lid.Pos(), escapePos: token.NoPos, isValSlice: isSl}
						} else if v, _ := p.TypesInfo.Uses[lid].(*types.Var); v != nil && a.namedResults[v] && s.Tok == token.ASSIGN {
							// Named result assigned from freshReturnFuncs: keep candidate.
						} else if v != nil {
							a.disqualified[v] = true
						}
					}
					if v1 := syntaxutil.LookupIdentVar(p.TypesInfo, s.Lhs[1]); v1 != nil {
						a.disqualified[v1] = true
					}
					markAssignLHSFieldNonFresh(p, s.Lhs[1], sum.nonFreshFields)
					return
				}
			}
		}
		for _, l := range s.Lhs {
			markAssignLHSFieldNonFresh(p, l, sum.nonFreshFields)
			if v := syntaxutil.LookupIdentVar(p.TypesInfo, l); v != nil {
				a.disqualified[v] = true
			}
		}
		return
	}
	if len(s.Lhs) != len(s.Rhs) {
		for _, l := range s.Lhs {
			if v := syntaxutil.LookupIdentVar(p.TypesInfo, l); v != nil {
				a.disqualified[v] = true
			}
		}
		return
	}
	topIdx, isTop := a.topStmtIndex[s]
	for i, l := range s.Lhs {
		rhs := s.Rhs[i]
		if call, isCall := ast.Unparen(rhs).(*ast.CallExpr); isCall {
			if callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun); callee != nil && callee.Origin().Pkg() == p.Types {
				sum.coneCallees[callee.Origin()] = true
			}
		}
		if lid, isID := ast.Unparen(l).(*ast.Ident); isID {
			if defV, isDef := p.TypesInfo.Defs[lid].(*types.Var); isDef && defV != nil && !a.params[defV] && defV.Parent() != p.Types.Scope() {
				if isTop {
					a.initialDefTopIdx[defV] = topIdx
				}
				if idx.DefCounts[defV] != 1 {
					a.disqualified[defV] = true
					continue
				}
				if isDirectFreshConstructExpr(p, rhs, a.freshReturnFuncs) {
					_, isSl := syntaxutil.UnderlyingType(defV.Type()).(*types.Slice)
					sum.vars[defV] = &freshVarState{rootVar: defV, declPos: lid.Pos(), escapePos: token.NoPos, isValSlice: isSl}
					if cl := unwrapCompositeLit(rhs); cl != nil {
						recordCompositeLitNonFreshFieldsWithDeferred(p, cl, a.freshReturnFuncs, sum.nonFreshFields, sum, &a.deferredFieldVars)
					} else {
						recordAppendElemNonFreshFields(p, rhs, a.freshReturnFuncs, sum.nonFreshFields, &a.deferredAppendVars)
					}
				} else if un, isUn := ast.Unparen(rhs).(*ast.UnaryExpr); isUn && un.Op == token.AND {
					a.aliasDefs = append(a.aliasDefs, freshAliasDef{v: defV, pos: lid.Pos(), addrArg: un.X})
				}
				continue
			}
			if useV, isUse := p.TypesInfo.Uses[lid].(*types.Var); isUse && useV != nil {
				if a.namedResults[useV] {
					a.assignCount[useV]++
					if s.Tok != token.ASSIGN || (!syntaxutil.IsNilIdent(p.TypesInfo, rhs) && !isDirectFreshConstructExpr(p, rhs, a.freshReturnFuncs) && !isFreshFieldAssignRHS(p, l, rhs, a.freshReturnFuncs)) {
						a.disqualified[useV] = true
					} else if cl := unwrapCompositeLit(rhs); cl != nil {
						recordCompositeLitNonFreshFieldsWithDeferred(p, cl, a.freshReturnFuncs, sum.nonFreshFields, sum, &a.deferredFieldVars)
					} else {
						recordAppendElemNonFreshFields(p, rhs, a.freshReturnFuncs, sum.nonFreshFields, &a.deferredAppendVars)
					}
					continue
				}
				if !a.params[useV] && !idx.InFuncLit[lid] && !idx.InGoStmt[lid] &&
					sum.vars[useV] != nil && sum.vars[useV].isValSlice &&
					s.Tok == token.ASSIGN && len(s.Lhs) == 1 &&
					isSelfAppendFreshRHS(p, l, rhs, a.freshReturnFuncs) {
					a.selfAppendSeen[useV] = true
					recordAppendElemNonFreshFields(p, rhs, a.freshReturnFuncs, sum.nonFreshFields, &a.deferredAppendVars)
					continue
				}
				a.assignCount[useV]++
				if isTop && a.assignCount[useV] == 1 && !a.selfAppendSeen[useV] {
					if _, hasInit := a.initialDefTopIdx[useV]; hasInit && topIdx > a.initialDefTopIdx[useV] {
						a.rebindTopIdx[useV] = topIdx
						a.rebindAssign[useV] = s
						continue
					}
				}
				a.disqualified[useV] = true
				continue
			}
		}
		if sel, isSel := ast.Unparen(l).(*ast.SelectorExpr); isSel {
			if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.FieldVal {
				if fObj, _ := selInfo.Obj().(*types.Var); fObj != nil {
					if isRefOrContainerType(fObj.Type()) {
						if !isFreshFieldAssignRHSWithDeferred(p, l, rhs, a.freshReturnFuncs, fObj, &a.deferredFieldVars) {
							sum.nonFreshFields[fObj] = true
						} else if cl := unwrapCompositeLit(rhs); cl != nil {
							recordCompositeLitNonFreshFieldsWithDeferred(p, cl, a.freshReturnFuncs, sum.nonFreshFields, sum, &a.deferredFieldVars)
						} else {
							recordAppendElemNonFreshFields(p, rhs, a.freshReturnFuncs, sum.nonFreshFields, &a.deferredAppendVars)
						}
					} else if _, subSt := syntaxutil.DerefAnyStructType(fObj.Type()); subSt != nil {
						if cl := unwrapCompositeLit(rhs); cl != nil {
							recordCompositeLitNonFreshFieldsWithDeferred(p, cl, a.freshReturnFuncs, sum.nonFreshFields, sum, &a.deferredFieldVars)
						} else {
							markValueContainedRefFieldsNonFresh(fObj.Type(), sum.nonFreshFields)
						}
					}
				}
			}
		} else if ix, isIx := ast.Unparen(l).(*ast.IndexExpr); isIx {
			ixType := p.TypesInfo.TypeOf(ix)
			if sel, isSel := unwrapIndexChainBase(ix).(*ast.SelectorExpr); isSel {
				if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.FieldVal {
					if fObj, _ := selInfo.Obj().(*types.Var); fObj != nil && isRefOrContainerType(ixType) && !isFreshFieldAssignRHSWithDeferred(p, ix, rhs, a.freshReturnFuncs, fObj, &a.deferredFieldVars) {
						sum.nonFreshFields[fObj] = true
					}
				}
			}
			if cl := unwrapCompositeLit(rhs); cl != nil {
				recordCompositeLitNonFreshFieldsWithDeferred(p, cl, a.freshReturnFuncs, sum.nonFreshFields, sum, &a.deferredFieldVars)
			} else {
				markValueContainedRefFieldsNonFresh(ixType, sum.nonFreshFields)
			}
		}
	}
}

func (a *freshConstructorFuncAnalyzer) resolveRootOfExpr(expr ast.Expr) *types.Var {
	cur := ast.Unparen(expr)
	for {
		switch e := cur.(type) {
		case *ast.Ident:
			v, _ := a.p.TypesInfo.Uses[e].(*types.Var)
			if st := a.sum.vars[v]; st != nil {
				return st.rootVar
			}
			return nil
		case *ast.SelectorExpr:
			cur = ast.Unparen(e.X)
		case *ast.IndexExpr:
			cur = ast.Unparen(e.X)
		case *ast.SliceExpr:
			cur = ast.Unparen(e.X)
		case *ast.StarExpr:
			cur = ast.Unparen(e.X)
		case *ast.UnaryExpr:
			if e.Op == token.AND {
				cur = ast.Unparen(e.X)
			} else {
				return nil
			}
		default:
			return nil
		}
	}
}

func (a *freshConstructorFuncAnalyzer) resolveRebindsAndAliases() {
	for v := range a.rebindTopIdx {
		if a.disqualified[v] || a.assignCount[v] != 1 {
			delete(a.sum.vars, v)
			continue
		}
		as := a.rebindAssign[v]
		if as == nil || len(as.Rhs) != 1 {
			delete(a.sum.vars, v)
			continue
		}
		wroteBefore := false
		for _, uid := range a.idx.UsesOf[v] {
			if uid.Pos() < as.Pos() && IdentReachesMutatedOrAddrPrefix(a.p, a.idx, uid) {
				wroteBefore = true
				break
			}
		}
		delete(a.sum.vars, v)
		if wroteBefore {
			continue
		}
		if un, isUn := ast.Unparen(as.Rhs[0]).(*ast.UnaryExpr); isUn && un.Op == token.AND {
			a.aliasDefs = append(a.aliasDefs, freshAliasDef{v: v, pos: as.End(), addrArg: un.X})
		}
	}

	for pass := 0; pass < 4; pass++ {
		added := false
		for _, ad := range a.aliasDefs {
			if a.disqualified[ad.v] || a.sum.vars[ad.v] != nil {
				continue
			}
			ptr, isPtr := syntaxutil.UnderlyingType(ad.v.Type()).(*types.Pointer)
			if !isPtr {
				continue
			}
			if _, elemSt := syntaxutil.DerefAnyStructType(ptr.Elem()); elemSt == nil || elemSt.NumFields() == 0 {
				continue
			}
			if a.dummyPF.isFreshContainerAt(a.sum, ad.addrArg, ad.pos) {
				rv := a.resolveRootOfExpr(ad.addrArg)
				if rv != nil && a.sum.vars[rv] != nil {
					a.sum.vars[ad.v] = &freshVarState{
						rootVar:   rv,
						declPos:   ad.pos,
						escapePos: token.NoPos,
					}
					added = true
				}
			}
		}
		if !added {
			break
		}
	}
}

func (a *freshConstructorFuncAnalyzer) clampToLoops(rootDeclPos, usePos token.Pos) token.Pos {
	esc := usePos
	for _, lp := range a.loops {
		if lp.Pos() <= usePos && usePos < lp.End() && !(lp.Pos() <= rootDeclPos && rootDeclPos < lp.End()) {
			if lp.Pos() < esc {
				esc = lp.Pos()
			}
		}
	}
	return esc
}

func (a *freshConstructorFuncAnalyzer) recordEscape(v *types.Var, pos token.Pos) bool {
	st := a.sum.vars[v]
	if st == nil {
		return false
	}
	rootSt := a.sum.vars[st.rootVar]
	if rootSt == nil {
		rootSt = st
	}
	clamped := a.clampToLoops(rootSt.declPos, pos)
	changed := false
	if st.escapePos == token.NoPos || clamped < st.escapePos {
		st.escapePos = clamped
		changed = true
	}
	if rootSt.escapePos == token.NoPos || clamped < rootSt.escapePos {
		rootSt.escapePos = clamped
		changed = true
	}
	return changed
}

func (a *freshConstructorFuncAnalyzer) recordNonReturnEscape(v *types.Var, pos token.Pos) bool {
	if st := a.sum.vars[v]; st != nil {
		a.nonReturnEscaped[v] = true
		if st.rootVar != nil {
			a.nonReturnEscaped[st.rootVar] = true
		}
	}
	return a.recordEscape(v, pos)
}

func (a *freshConstructorFuncAnalyzer) solveEscapeFixpoint() {
	p, idx, sum := a.p, a.idx, a.sum
	for {
		for _, st := range sum.vars {
			st.escapePos = token.NoPos
		}
		a.nonReturnEscaped = map[*types.Var]bool{}
		var couplings []freshEscapeCoupling

		for v, st := range sum.vars {
			usedInDefer := false
			for _, id := range idx.UsesOf[v] {
				if st.declPos != token.NoPos && id.Pos() < st.declPos {
					continue
				}
				if idx.InGoStmt[id] {
					a.recordNonReturnEscape(v, a.fd.Body.Pos())
					continue
				}
				for _, df := range a.defers {
					if df.Pos() <= id.Pos() && id.Pos() < df.End() {
						usedInDefer = true
						break
					}
				}
				if idx.InFuncLit[id] {
					lit := enclosingFuncLit(idx, id)
					ownerRoot, readOnlyFieldClosure, returnsAddrOnly := classifyFieldAssignedClosureUse(p, idx, lit, v, a.resolveRootOfExpr)
					if readOnlyFieldClosure && ownerRoot != nil {
						if returnsAddrOnly {
							a.recordNonReturnEscape(v, lit.Pos())
						} else {
							couplings = append(couplings, freshEscapeCoupling{srcRoot: st.rootVar, dstRoot: ownerRoot, atPos: lit.Pos()})
						}
						continue
					}
					if lit != nil {
						a.recordNonReturnEscape(v, lit.Pos())
					} else {
						a.recordNonReturnEscape(v, a.fd.Body.Pos())
					}
					continue
				}

				if useIsNonEscapingOnFreshVar(
					p,
					idx,
					a.fd,
					sum,
					v,
					id,
					a.freshParamFuncs,
					a.nonEscParams,
					a.mapStoreParams,
					a.retStructParams,
					a.paramGuardPkgs,
					a.nonEscAuxVars,
					a.confinedCacheMaps,
					a.resolveRootOfExpr,
					&couplings,
				) {
					continue
				}
				if (!a.params[v] || a.namedResults[v]) && st.rootVar == v {
					if retStmt, isRet := idx.ParentUnparen(id).(*ast.ReturnStmt); isRet &&
						len(retStmt.Results) >= 1 && ast.Unparen(retStmt.Results[0]) == id {
						pureRet := true
						for ri, re := range retStmt.Results {
							u := ast.Unparen(re)
							if ri > 0 && u == id {
								pureRet = false
								break
							}
							switch u.(type) {
							case *ast.Ident, *ast.BasicLit:
							default:
								pureRet = false
							}
						}
						if pureRet {
							if len(a.defers) > 0 {
								a.recordEscape(v, id.Pos())
							}
							continue
						}
					}
				}
				a.recordNonReturnEscape(v, id.Pos())
			}
			if usedInDefer {
				a.recordNonReturnEscape(v, a.fd.Body.Pos())
			}
		}

		if len(a.namedResults) > 0 {
			ast.Inspect(a.fd.Body, func(n ast.Node) bool {
				if n == nil {
					return false
				}
				if _, isLit := n.(*ast.FuncLit); isLit {
					return false
				}
				if ret, isRet := n.(*ast.ReturnStmt); isRet && len(ret.Results) == 0 {
					for rv := range a.namedResults {
						if sum.vars[rv] != nil {
							a.recordEscape(rv, ret.Pos())
						}
					}
				}
				return true
			})
		}

		for {
			changed := false
			for _, cp := range couplings {
				dstSt := sum.vars[cp.dstRoot]
				if dstSt == nil {
					if !a.nonReturnEscaped[cp.srcRoot] {
						a.nonReturnEscaped[cp.srcRoot] = true
						changed = true
					}
					if a.recordEscape(cp.srcRoot, cp.atPos) {
						changed = true
					}
					continue
				}
				if a.nonReturnEscaped[cp.dstRoot] && !a.nonReturnEscaped[cp.srcRoot] {
					a.nonReturnEscaped[cp.srcRoot] = true
					changed = true
				}
				if dstSt.escapePos != token.NoPos {
					targetPos := dstSt.escapePos
					if cp.atPos >= dstSt.escapePos {
						targetPos = cp.atPos
					}
					if a.recordEscape(cp.srcRoot, targetPos) {
						changed = true
					}
				}
			}
			if !changed {
				break
			}
		}

		evictedAlias := false
		for v, st := range sum.vars {
			if st.rootVar == v {
				continue
			}
			rootSt := sum.vars[st.rootVar]
			bad := st.escapePos != token.NoPos || rootSt == nil
			if !bad && rootSt.escapePos != token.NoPos {
				for _, uid := range idx.UsesOf[v] {
					if st.declPos != token.NoPos && uid.Pos() < st.declPos {
						continue
					}
					if a.clampToLoops(rootSt.declPos, uid.Pos()) >= rootSt.escapePos {
						bad = true
						break
					}
				}
			}
			if bad {
				delete(sum.vars, v)
				evictedAlias = true
			}
		}
		if !evictedAlias {
			break
		}
	}
}

func (a *freshConstructorFuncAnalyzer) resolveDeferredFieldFreshness() {
	sum := a.sum
	aliasAddrByVar := map[*types.Var]freshAliasDef{}
	for _, ad := range a.aliasDefs {
		aliasAddrByVar[ad.v] = ad
	}
	for {
		progressed := false
		for _, ad := range a.aliasDefs {
			st := sum.vars[ad.v]
			if st != nil && st.rootVar != ad.v && !a.dummyPF.isFreshContainerAt(sum, ad.addrArg, ad.pos) {
				delete(sum.vars, ad.v)
				progressed = true
			}
		}
		for _, dv := range a.deferredAppendVars {
			st := sum.vars[dv.v]
			if !a.dummyPF.checkVarLiveAt(sum, dv.v, dv.pos) || st == nil || a.nonReturnEscaped[st.rootVar] {
				before := len(sum.nonFreshFields)
				markValueContainedRefFieldsNonFresh(dv.elemType, sum.nonFreshFields)
				if len(sum.nonFreshFields) > before {
					progressed = true
				}
			}
		}
		for _, df := range a.deferredFieldVars {
			if sum.nonFreshFields[df.field] {
				continue
			}
			if df.addrExpr != nil {
				addrRoot := a.resolveRootOfExpr(df.addrExpr)
				if !a.dummyPF.isFreshContainerAt(sum, df.addrExpr, df.pos) || addrRoot == nil || a.nonReturnEscaped[addrRoot] {
					sum.nonFreshFields[df.field] = true
					progressed = true
				}
				continue
			}
			st := sum.vars[df.v]
			if ad, isAlias := aliasAddrByVar[df.v]; isAlias && !a.dummyPF.isFreshContainerAt(sum, ad.addrArg, ad.pos) {
				st = nil
			}
			if !a.dummyPF.checkVarLiveAt(sum, df.v, df.pos) || st == nil || a.nonReturnEscaped[st.rootVar] {
				sum.nonFreshFields[df.field] = true
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
}
