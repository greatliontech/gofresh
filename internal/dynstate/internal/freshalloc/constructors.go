package freshalloc

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type freshVarState struct {
	rootVar    *types.Var // root fresh variable (either v itself or the parent slice/struct v aliases via &parent[i] / &parent.Field)
	declPos    token.Pos  // position where freshness begins (for dominating top-level overwrite fd = &slice[n], stmt.End())
	escapePos  token.Pos  // earliest external escape position in fd.Body (token.NoPos if never escapes externally)
	isValSlice bool       // true when v has []Struct or StructSlice type
}

type freshFuncSummary struct {
	fd             *ast.FuncDecl
	fn             *types.Func
	vars           map[*types.Var]*freshVarState
	nonFreshFields map[*types.Var]bool // reference fields (*T, []T, map[K]V) ever assigned non-fresh values or &field-taken in this cone
	coneCallees    map[*types.Func]bool
	condGuards     map[syntaxutil.ConditionalStructMutation]bool
}

// PkgFreshConstructors summarizes function-local and unexported-constructor
// fresh struct allocations across a package.
type PkgFreshConstructors struct {
	p                *packages.Package
	idx              *refconfine.PkgIndex
	funcs            map[*ast.FuncDecl]*freshFuncSummary
	freshReturnFuncs map[*types.Func]bool
	condGuards       map[syntaxutil.ConditionalStructMutation]bool
}

// ConditionalGuards returns the conditional struct-mutation guards accumulated
// across p's fresh constructor cones.
func (pf *PkgFreshConstructors) ConditionalGuards() map[syntaxutil.ConditionalStructMutation]bool {
	if pf == nil {
		return nil
	}
	return pf.condGuards
}

// ReturnsFreshAllocation reports whether fd has no conditional guards in its
// constructor cone, executes at least one return statement, and returns only
// nil, a direct fresh allocation, or a live unescaped fresh local variable on
// its primary result across every return path.
func (pf *PkgFreshConstructors) ReturnsFreshAllocation(fd *ast.FuncDecl) bool {
	if pf == nil || pf.p == nil || pf.p.TypesInfo == nil || pf.idx == nil || fd == nil || fd.Body == nil || pf.idx.FlowCache(pf.p).FuncBody(fd).HasGotoAnywhere() {
		return false
	}
	sum := pf.funcs[fd]
	if sum == nil || len(sum.condGuards) > 0 || !funcHasReturnStmt(fd.Body) {
		return false
	}
	var sig *types.Signature
	if sum.fn != nil {
		sig, _ = sum.fn.Type().(*types.Signature)
	} else if fd.Type != nil {
		sig, _ = pf.p.TypesInfo.TypeOf(fd.Type).(*types.Signature)
	}
	return pf.funcDeclReturnsFreshAllocation(fd, sum, sig, pf.freshReturnFuncs)
}

// IsFieldFreshInCone reports whether field is never assigned a non-fresh
// reference/container value or address-taken anywhere in fd's constructor cone.
func (pf *PkgFreshConstructors) IsFieldFreshInCone(fd *ast.FuncDecl, field *types.Var) bool {
	if pf == nil || fd == nil || field == nil {
		return false
	}
	sum := pf.funcs[fd]
	return sum != nil && !sum.nonFreshFields[field]
}

func recordFreshVarGuardPkg(sum *freshFuncSummary, v *types.Var, guardPkg string) {
	if sum == nil || v == nil || !syntaxutil.HasModuleImportPathShape(guardPkg) {
		return
	}
	recordFreshVarCondGuard(sum, v, func(ref syntaxutil.TypeRef) syntaxutil.ConditionalStructMutation {
		return syntaxutil.ConditionalStructMutation{Struct: ref, GuardPkg: guardPkg}
	})
}

func recordFreshVarImmutableCapsuleGuard(sum *freshFuncSummary, v *types.Var, guardStruct syntaxutil.TypeRef) {
	if sum == nil || v == nil || !guardStruct.Valid() {
		return
	}
	recordFreshVarCondGuard(sum, v, func(ref syntaxutil.TypeRef) syntaxutil.ConditionalStructMutation {
		return syntaxutil.ConditionalStructMutation{
			Struct:                       ref,
			GuardStruct:                  guardStruct,
			RequireImmutableCapsuleGuard: true,
		}
	})
}

func recordFreshVarCondGuard(sum *freshFuncSummary, v *types.Var, makeCond func(syntaxutil.TypeRef) syntaxutil.ConditionalStructMutation) {
	if sum.condGuards == nil {
		sum.condGuards = map[syntaxutil.ConditionalStructMutation]bool{}
	}
	addForType := func(t types.Type) {
		if t == nil {
			return
		}
		u := types.Unalias(t)
		if named, isN := u.(*types.Named); isN && named.Obj() != nil && named.Obj().Pkg() != nil {
			if sl, isSl := named.Underlying().(*types.Slice); isSl && !refconfine.TypeContainsRefOrPointer(sl.Elem()) {
				cm := makeCond(syntaxutil.TypeRef{Pkg: named.Obj().Pkg().Path(), Name: named.Obj().Name()})
				if cm.Valid() {
					sum.condGuards[cm] = true
				}
			}
		}
		if sl, isSl := u.Underlying().(*types.Slice); isSl {
			u = types.Unalias(sl.Elem())
		}
		ref, _, st, ok := syntaxutil.TypeRefOfStructFull(u)
		if ok && st != nil && st.NumFields() > 0 && ref.Valid() {
			cm := makeCond(ref)
			if cm.Valid() {
				sum.condGuards[cm] = true
			}
		}
	}
	addForType(v.Type())
	if st := sum.vars[v]; st != nil && st.rootVar != nil && st.rootVar != v {
		addForType(st.rootVar.Type())
	}
}

// IsFreshMutationTarget reports whether expr inside fd mutates a live,
// unescaped fresh local or constructor-returned container.
func (pf *PkgFreshConstructors) IsFreshMutationTarget(fd *ast.FuncDecl, expr ast.Expr) bool {
	if pf == nil || fd == nil || expr == nil {
		return false
	}
	sum := pf.funcs[fd]
	if sum == nil || len(sum.vars) == 0 {
		return false
	}
	cur := ast.Unparen(expr)
	switch e := cur.(type) {
	case *ast.SelectorExpr:
		selInfo := pf.p.TypesInfo.Selections[e]
		if selInfo == nil || selInfo.Kind() != types.FieldVal || syntaxutil.SelectionCrossesEmbeddedPointer(selInfo) {
			return false
		}
		return pf.isFreshContainerAt(sum, e.X, expr.Pos())
	case *ast.IndexExpr:
		return pf.isFreshContainerAt(sum, e.X, expr.Pos())
	case *ast.SliceExpr:
		return pf.isFreshContainerAt(sum, e.X, expr.Pos())
	case *ast.StarExpr:
		if id, isID := ast.Unparen(e.X).(*ast.Ident); isID {
			v, _ := pf.p.TypesInfo.Uses[id].(*types.Var)
			return pf.checkVarLiveAt(sum, v, expr.Pos())
		}
		return false
	}
	return false
}

// IsFreshAddrOrValue reports whether expr inside fd evaluates to or takes the
// address of a live, unescaped fresh local or constructor-returned container.
func (pf *PkgFreshConstructors) IsFreshAddrOrValue(fd *ast.FuncDecl, expr ast.Expr) bool {
	if pf == nil || fd == nil || expr == nil {
		return false
	}
	sum := pf.funcs[fd]
	if sum == nil || len(sum.vars) == 0 {
		return false
	}
	return pf.isFreshContainerAt(sum, expr, expr.Pos())
}

func (pf *PkgFreshConstructors) checkVarLiveAt(sum *freshFuncSummary, v *types.Var, pos token.Pos) bool {
	if sum == nil || v == nil {
		return false
	}
	st := sum.vars[v]
	if st == nil {
		return false
	}
	if st.declPos != token.NoPos && pos < st.declPos {
		return false
	}
	rootSt := sum.vars[st.rootVar]
	if rootSt == nil {
		rootSt = st
	}
	if st.escapePos != token.NoPos && pos >= st.escapePos {
		return false
	}
	if rootSt.escapePos != token.NoPos && pos >= rootSt.escapePos {
		return false
	}
	return true
}

func (pf *PkgFreshConstructors) isFreshContainerAt(sum *freshFuncSummary, expr ast.Expr, pos token.Pos) bool {
	cur := ast.Unparen(expr)
	first := true
	for {
		switch e := cur.(type) {
		case *ast.Ident:
			v, _ := pf.p.TypesInfo.Uses[e].(*types.Var)
			return pf.checkVarLiveAt(sum, v, pos) && pf.checkVarLiveAt(sum, v, e.Pos())
		case *ast.UnaryExpr:
			if e.Op == token.AND && first {
				cur = ast.Unparen(e.X)
				first = false
				continue
			}
			return false
		case *ast.StarExpr:
			if id, isID := ast.Unparen(e.X).(*ast.Ident); isID {
				v, _ := pf.p.TypesInfo.Uses[id].(*types.Var)
				return pf.checkVarLiveAt(sum, v, pos) && pf.checkVarLiveAt(sum, v, id.Pos())
			}
			return false
		case *ast.SelectorExpr:
			selInfo := pf.p.TypesInfo.Selections[e]
			if selInfo == nil || selInfo.Kind() != types.FieldVal || syntaxutil.SelectionCrossesEmbeddedPointer(selInfo) {
				return false
			}
			fObj, _ := selInfo.Obj().(*types.Var)
			if fObj == nil {
				return false
			}
			if isRefOrContainerType(fObj.Type()) && sum.nonFreshFields[fObj] {
				return false
			}
			if _, isPtr := types.Unalias(pf.p.TypesInfo.TypeOf(e.X)).(*types.Pointer); isPtr {
				if _, isID := ast.Unparen(e.X).(*ast.Ident); !isID {
					xSel, isXSel := ast.Unparen(e.X).(*ast.SelectorExpr)
					if !isXSel {
						return false
					}
					xInfo := pf.p.TypesInfo.Selections[xSel]
					if xInfo == nil || xInfo.Kind() != types.FieldVal || syntaxutil.SelectionCrossesEmbeddedPointer(xInfo) {
						return false
					}
					xfObj, _ := xInfo.Obj().(*types.Var)
					if xfObj == nil || sum.nonFreshFields[xfObj] {
						return false
					}
				}
			}
			cur = ast.Unparen(e.X)
			first = false
			continue
		case *ast.IndexExpr:
			xt := syntaxutil.UnderlyingType(pf.p.TypesInfo.TypeOf(e.X))
			switch u := xt.(type) {
			case *types.Array, *types.Map:
				cur = ast.Unparen(e.X)
				first = false
				continue
			case *types.Slice:
				if _, isPtrElem := types.Unalias(u.Elem()).(*types.Pointer); isPtrElem {
					return false
				}
				_, elemSt := syntaxutil.DerefAnyStructType(u.Elem())
				if elemSt == nil || elemSt.NumFields() == 0 {
					return false
				}
				cur = ast.Unparen(e.X)
				first = false
				continue
			}
			return false
		case *ast.SliceExpr:
			cur = ast.Unparen(e.X)
			first = false
			continue
		default:
			return false
		}
	}
}

func isRefOrContainerType(t types.Type) bool {
	if t == nil {
		return false
	}
	switch types.Unalias(t).Underlying().(type) {
	case *types.Pointer, *types.Slice, *types.Map, *types.Interface:
		return true
	}
	return false
}

func isFreshConstructableRootType(t types.Type) bool {
	if t == nil {
		return false
	}
	u := types.Unalias(t)
	if ptr, isPtr := u.Underlying().(*types.Pointer); isPtr {
		_, st := syntaxutil.DerefAnyStructType(ptr.Elem())
		return st != nil && st.NumFields() > 0
	}
	if sl, isSl := u.Underlying().(*types.Slice); isSl {
		if _, isPtrElem := types.Unalias(sl.Elem()).(*types.Pointer); isPtrElem {
			return false
		}
		if _, st := syntaxutil.DerefAnyStructType(sl.Elem()); st != nil && st.NumFields() > 0 {
			return true
		}
		if _, isNamed := u.(*types.Named); isNamed && !refconfine.TypeContainsRefOrPointer(sl.Elem()) {
			return true
		}
		return false
	}
	_, st := syntaxutil.DerefAnyStructType(u)
	return st != nil && st.NumFields() > 0
}

// ComputePackageFreshConstructors computes fresh constructor summaries across p.
func ComputePackageFreshConstructors(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
) *PkgFreshConstructors {
	pf := &PkgFreshConstructors{
		p:     p,
		idx:   idx,
		funcs: map[*ast.FuncDecl]*freshFuncSummary{},
	}
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil {
		return pf
	}
	if confinedCacheMaps == nil {
		confinedCacheMaps = FindMutexConfinedConstructorCaches(p, idx)
	}

	var allFDs []*ast.FuncDecl
	eligibleUnexported := map[*types.Func]*ast.FuncDecl{}
	flowCache := idx.FlowCache(p)
	for fn, fd := range idx.FuncDecls {
		if fn == nil || fd == nil || fd.Body == nil || flowCache == nil {
			continue
		}
		fb := flowCache.FuncBody(fd)
		if fb == nil || fb.HasGotoAnywhere() || fb.HasGoAnywhere() {
			continue
		}
		allFDs = append(allFDs, fd)
		if !fn.Exported() && fn.Pkg() == p.Types {
			allDirectCalls := true
			for _, uid := range idx.UsesOf[fn] {
				if idx.InGoStmt[uid] || idx.InFuncLit[uid] {
					allDirectCalls = false
					break
				}
				if refconfine.EnclosingCallOfCalleeIdent(idx, uid) == nil {
					allDirectCalls = false
					break
				}
			}
			if allDirectCalls {
				eligibleUnexported[fn] = fd
			}
		}
	}

	nonEscAuxVars := computeLocalNonEscapingAuxVars(p, idx, allFDs, eligibleUnexported)
	nonEscParams, mapStoreParams, retStructParams, paramGuardPkgs := initNonEscapingIntraParams(eligibleUnexported)
	aliasIndex := preindexIntraParamAliases(p, idx, eligibleUnexported)

	freshReturnFuncs := map[*types.Func]bool{}
	freshParamFuncs := map[*types.Func]map[int]bool{}
	for _, fd := range allFDs {
		fn, _ := p.TypesInfo.Defs[fd.Name].(*types.Func)
		if fn == nil || fn.Pkg() != p.Types {
			continue
		}
		sig, okSig := fn.Type().(*types.Signature)
		if !okSig {
			continue
		}
		if sig.Results().Len() == 1 || (sig.Results().Len() == 2 && syntaxutil.IsErrorType(sig.Results().At(1).Type())) {
			if isFreshConstructableRootType(sig.Results().At(0).Type()) && funcHasReturnStmt(fd.Body) {
				freshReturnFuncs[fn] = true
			}
		}
	}
	for fn := range eligibleUnexported {
		sig, okSig := fn.Type().(*types.Signature)
		if !okSig {
			continue
		}
		if len(idx.UsesOf[fn]) > 0 {
			for pi := 0; pi < sig.Params().Len(); pi++ {
				if isFreshConstructableRootType(sig.Params().At(pi).Type()) {
					if freshParamFuncs[fn] == nil {
						freshParamFuncs[fn] = map[int]bool{}
					}
					freshParamFuncs[fn][pi] = true
				}
			}
		}
	}

	invariantLeafSums := map[*ast.FuncDecl]*freshFuncSummary{}
	buildAllSummaries := func() {
		pf.funcs = make(map[*ast.FuncDecl]*freshFuncSummary, len(allFDs))
		for _, fd := range allFDs {
			fn, _ := p.TypesInfo.Defs[fd.Name].(*types.Func)
			if cached, ok := invariantLeafSums[fd]; ok {
				pf.funcs[fd] = cached
				continue
			}
			sum := analyzeSingleFreshConstructorFunc(
				p,
				idx,
				fd,
				fn,
				freshReturnFuncs,
				freshParamFuncs,
				nonEscParams,
				mapStoreParams,
				retStructParams,
				paramGuardPkgs,
				nonEscAuxVars,
				confinedCacheMaps,
			)
			pf.funcs[fd] = sum
			if len(sum.coneCallees) == 0 && (fn == nil || len(freshParamFuncs[fn]) == 0) {
				invariantLeafSums[fd] = sum
			}
		}
		// Propagate nonFreshFields across intra-package constructor helper call edges to fixed point.
		changedNF := true
		for changedNF {
			changedNF = false
			for _, sum := range pf.funcs {
				if sum == nil || len(sum.coneCallees) == 0 {
					continue
				}
				for callee := range sum.coneCallees {
					cfd := idx.FuncDecls[callee]
					csum := pf.funcs[cfd]
					if csum == nil {
						continue
					}
					for f := range csum.nonFreshFields {
						if !sum.nonFreshFields[f] {
							sum.nonFreshFields[f] = true
							changedNF = true
						}
					}
					for f := range sum.nonFreshFields {
						if !csum.nonFreshFields[f] {
							if invariantLeafSums[cfd] == csum {
								cloned := *csum
								cloned.nonFreshFields = maps.Clone(csum.nonFreshFields)
								pf.funcs[cfd] = &cloned
								csum = &cloned
							}
							csum.nonFreshFields[f] = true
							changedNF = true
						}
					}
				}
			}
		}
	}

	for {
		buildAllSummaries()
		changed := stepNonEscapingIntraParams(
			p,
			idx,
			pf,
			eligibleUnexported,
			aliasIndex,
			freshReturnFuncs,
			nonEscAuxVars,
			confinedCacheMaps,
			nonEscParams,
			mapStoreParams,
			retStructParams,
			paramGuardPkgs,
		)

		for fn := range freshReturnFuncs {
			fd := idx.FuncDecls[fn]
			sum := pf.funcs[fd]
			sig, _ := fn.Type().(*types.Signature)
			if !pf.funcDeclReturnsFreshAllocation(fd, sum, sig, freshReturnFuncs) {
				delete(freshReturnFuncs, fn)
				changed = true
			}
		}

		for fn, pset := range freshParamFuncs {
			if len(pset) == 0 {
				continue
			}
			fnFD := eligibleUnexported[fn]
			fnSum := pf.funcs[fnFD]
			sig, _ := fn.Type().(*types.Signature)
			for pi := range pset {
				if fnSum == nil || sig == nil || pi < 0 || pi >= sig.Params().Len() {
					delete(pset, pi)
					changed = true
					continue
				}
				pv := sig.Params().At(pi)
				pvSt := fnSum.vars[pv]
				if pvSt == nil || pvSt.escapePos != token.NoPos {
					delete(pset, pi)
					changed = true
				}
			}
			if len(pset) == 0 {
				delete(freshParamFuncs, fn)
				continue
			}
			for _, uid := range idx.UsesOf[fn] {
				call := refconfine.EnclosingCallOfCalleeIdent(idx, uid)
				callerFD := idx.SyncEnclFuncDecl(uid)
				callerSum := pf.funcs[callerFD]
				for pi := range pset {
					offset := 0
					if call != nil {
						if sel, isS := ast.Unparen(call.Fun).(*ast.SelectorExpr); isS {
							if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.MethodExpr {
								offset = 1
							}
						}
					}
					if call == nil || callerSum == nil || call.Ellipsis.IsValid() || pi+offset >= len(call.Args) ||
						!pf.isFreshContainerAt(callerSum, call.Args[pi+offset], call.Pos()) {
						delete(pset, pi)
						changed = true
					}
				}
			}
			if len(pset) == 0 {
				delete(freshParamFuncs, fn)
			}
		}

		if !changed {
			break
		}
	}
	pf.freshReturnFuncs = freshReturnFuncs
	pf.condGuards = map[syntaxutil.ConditionalStructMutation]bool{}
	for _, sum := range pf.funcs {
		if sum == nil {
			continue
		}
		for cm := range sum.condGuards {
			pf.condGuards[cm] = true
		}
	}
	return pf
}

func (pf *PkgFreshConstructors) funcDeclReturnsFreshAllocation(
	fd *ast.FuncDecl,
	sum *freshFuncSummary,
	sig *types.Signature,
	freshReturnFuncs map[*types.Func]bool,
) bool {
	if pf == nil || pf.p == nil || pf.p.TypesInfo == nil || fd == nil || fd.Body == nil || sum == nil || sig == nil {
		return false
	}
	var res0Var *types.Var
	if sig.Results().Len() > 0 {
		res0Var = sig.Results().At(0)
	}
	okRet := true
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if !okRet || n == nil {
			return false
		}
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		ret, isRet := n.(*ast.ReturnStmt)
		if !isRet {
			return true
		}
		if len(ret.Results) == 0 {
			if res0Var == nil || !pf.checkVarLiveAt(sum, res0Var, ret.Pos()) {
				okRet = false
			}
			return false
		}
		r0 := ast.Unparen(ret.Results[0])
		if syntaxutil.IsNilIdent(pf.p.TypesInfo, r0) || isDirectFreshConstructExpr(pf.p, r0, freshReturnFuncs) {
			return false
		}
		if id, isID := r0.(*ast.Ident); isID {
			v, _ := pf.p.TypesInfo.Uses[id].(*types.Var)
			st := sum.vars[v]
			if st != nil && st.rootVar == v && (st.declPos == token.NoPos || ret.Pos() >= st.declPos) &&
				(st.escapePos == token.NoPos || ret.Pos() <= st.escapePos) {
				return false
			}
		}
		okRet = false
		return false
	})
	return okRet
}

func funcHasReturnStmt(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		if _, isRet := n.(*ast.ReturnStmt); isRet {
			found = true
			return false
		}
		return true
	})
	return found
}
