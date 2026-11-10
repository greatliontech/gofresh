package freshstruct

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
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
	p          *packages.Package
	idx        *refconfine.PkgIndex
	funcs      map[*ast.FuncDecl]*freshFuncSummary
	condGuards map[syntaxutil.ConditionalStructMutation]bool
}

func recordFreshVarGuardPkg(sum *freshFuncSummary, v *types.Var, guardPkg string) {
	if sum == nil || v == nil || guardPkg == "" || syntaxutil.IsStandardLibraryPkgPath(guardPkg) {
		return
	}
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
				cm := syntaxutil.ConditionalStructMutation{
					Struct:   syntaxutil.TypeRef{Pkg: named.Obj().Pkg().Path(), Name: named.Obj().Name()},
					GuardPkg: guardPkg,
				}
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
			cm := syntaxutil.ConditionalStructMutation{Struct: ref, GuardPkg: guardPkg}
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
			case *types.Array:
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
	for fn, fd := range idx.FuncDecls {
		if fn == nil || fd == nil || fd.Body == nil || FuncBodyHasGoto(fd.Body) {
			continue
		}
		hasGo := false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if hasGo || n == nil {
				return false
			}
			if _, isGo := n.(*ast.GoStmt); isGo {
				hasGo = true
				return false
			}
			return true
		})
		if hasGo {
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
	for fn, fd := range eligibleUnexported {
		sig, okSig := fn.Type().(*types.Signature)
		if !okSig {
			continue
		}
		if sig.Results().Len() == 1 || (sig.Results().Len() == 2 && syntaxutil.IsErrorType(sig.Results().At(1).Type())) {
			if isFreshConstructableRootType(sig.Results().At(0).Type()) && funcHasReturnStmt(fd.Body) {
				freshReturnFuncs[fn] = true
			}
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

		// Validate freshReturnFuncs: every ReturnStmt in fn must return nil, a fresh alloc, or a live fresh root var!
		for fn := range freshReturnFuncs {
			fd := eligibleUnexported[fn]
			sum := pf.funcs[fd]
			sig, _ := fn.Type().(*types.Signature)
			if sum == nil || sig == nil {
				delete(freshReturnFuncs, fn)
				changed = true
				continue
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
				if syntaxutil.IsNilIdent(p.TypesInfo, r0) || isDirectFreshConstructExpr(p, r0, freshReturnFuncs) {
					return false
				}
				if id, isID := r0.(*ast.Ident); isID {
					v, _ := p.TypesInfo.Uses[id].(*types.Var)
					st := sum.vars[v]
					if st != nil && st.rootVar == v && (st.declPos == token.NoPos || ret.Pos() >= st.declPos) &&
						(st.escapePos == token.NoPos || ret.Pos() <= st.escapePos) {
						return false
					}
				}
				okRet = false
				return false
			})
			if !okRet {
				delete(freshReturnFuncs, fn)
				changed = true
			}
		}

		// Validate freshParamFuncs: inside fn itself pv must remain unescaped (escapePos == token.NoPos),
		// AND every call site in p.Syntax must pass a fresh container at call.Pos()!
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

func isDirectFreshConstructExpr(p *packages.Package, expr ast.Expr, freshReturnFuncs map[*types.Func]bool) bool {
	expr = ast.Unparen(expr)
	switch e := expr.(type) {
	case *ast.CompositeLit:
		return isFreshConstructableRootType(p.TypesInfo.TypeOf(e))
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			if cl, ok := ast.Unparen(e.X).(*ast.CompositeLit); ok {
				return isFreshConstructableRootType(p.TypesInfo.TypeOf(e)) && cl != nil
			}
		}
	case *ast.CallExpr:
		if id, ok := ast.Unparen(e.Fun).(*ast.Ident); ok {
			if b, isB := p.TypesInfo.Uses[id].(*types.Builtin); isB {
				if b.Name() == "new" || b.Name() == "make" {
					return isFreshConstructableRootType(p.TypesInfo.TypeOf(e))
				}
				if b.Name() == "append" && len(e.Args) >= 1 && syntaxutil.IsTypedNilSliceConv(p, e.Args[0]) {
					return isFreshConstructableRootType(p.TypesInfo.TypeOf(e))
				}
			}
		}
		if callee := syntaxutil.ResolveCalledFuncObj(p, e.Fun); callee != nil && freshReturnFuncs[callee.Origin()] {
			return true
		}
	}
	return false
}

func isFreshFieldAssignRHS(p *packages.Package, lhs, rhs ast.Expr, freshReturnFuncs map[*types.Func]bool) bool {
	rhs = ast.Unparen(rhs)
	if syntaxutil.IsNilIdent(p.TypesInfo, rhs) || syntaxutil.IsTypedNilSliceConv(p, rhs) {
		return true
	}
	switch e := rhs.(type) {
	case *ast.CompositeLit:
		return true
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			_, ok := ast.Unparen(e.X).(*ast.CompositeLit)
			return ok
		}
	case *ast.CallExpr:
		if id, ok := ast.Unparen(e.Fun).(*ast.Ident); ok {
			if b, isB := p.TypesInfo.Uses[id].(*types.Builtin); isB {
				if b.Name() == "new" || b.Name() == "make" {
					return true
				}
				if b.Name() == "append" && len(e.Args) >= 1 &&
					(syntaxutil.IsTypedNilSliceConv(p, e.Args[0]) || (lhs != nil && syntaxutil.SameFieldTargetExpr(p, lhs, e.Args[0]))) {
					return true
				}
			}
		}
		if callee := syntaxutil.ResolveCalledFuncObj(p, e.Fun); callee != nil && freshReturnFuncs[callee.Origin()] {
			return true
		}
	}
	return false
}

func markValueContainedRefFieldsNonFresh(t types.Type, out map[*types.Var]bool) {
	seen := map[types.Type]bool{}
	var walk func(cur types.Type)
	walk = func(cur types.Type) {
		if cur == nil {
			return
		}
		cur = types.Unalias(cur)
		if seen[cur] {
			return
		}
		seen[cur] = true
		switch u := cur.Underlying().(type) {
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				f := u.Field(i)
				if isRefOrContainerType(f.Type()) {
					out[f] = true
				}
				walk(f.Type())
			}
		case *types.Array:
			walk(u.Elem())
		}
	}
	walk(t)
}

func recordCompositeLitNonFreshFields(p *packages.Package, cl *ast.CompositeLit, freshReturnFuncs map[*types.Func]bool, nonFresh map[*types.Var]bool) {
	if cl == nil {
		return
	}
	_, st := syntaxutil.DerefAnyStructType(p.TypesInfo.TypeOf(cl))
	if st == nil {
		return
	}
	for i, elt := range cl.Elts {
		var fObj *types.Var
		val := elt
		if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
			val = kv.Value
			if kid, isID := ast.Unparen(kv.Key).(*ast.Ident); isID {
				fObj, _ = p.TypesInfo.Uses[kid].(*types.Var)
			}
		} else if i < st.NumFields() {
			fObj = st.Field(i)
		}
		if fObj == nil {
			continue
		}
		if isRefOrContainerType(fObj.Type()) {
			if !isFreshFieldAssignRHS(p, nil, val, freshReturnFuncs) {
				nonFresh[fObj] = true
			}
		}
		if subCL := unwrapCompositeLit(val); subCL != nil {
			recordCompositeLitNonFreshFields(p, subCL, freshReturnFuncs, nonFresh)
		} else if _, subSt := syntaxutil.DerefAnyStructType(fObj.Type()); subSt != nil && !isRefOrContainerType(fObj.Type()) {
			markValueContainedRefFieldsNonFresh(fObj.Type(), nonFresh)
		}
	}
}

func unwrapCompositeLit(expr ast.Expr) *ast.CompositeLit {
	expr = ast.Unparen(expr)
	if cl, ok := expr.(*ast.CompositeLit); ok {
		return cl
	}
	if un, ok := expr.(*ast.UnaryExpr); ok && un.Op == token.AND {
		if cl, okC := ast.Unparen(un.X).(*ast.CompositeLit); okC {
			return cl
		}
	}
	return nil
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

	params := map[*types.Var]bool{}
	namedResults := map[*types.Var]bool{}
	if fn != nil {
		if sig, okS := fn.Type().(*types.Signature); okS {
			if sig.Recv() != nil {
				params[sig.Recv()] = true
			}
			for i := 0; i < sig.Params().Len(); i++ {
				pv := sig.Params().At(i)
				params[pv] = true
				if freshParamFuncs[fn][i] {
					_, isSl := syntaxutil.UnderlyingType(pv.Type()).(*types.Slice)
					sum.vars[pv] = &freshVarState{
						rootVar:    pv,
						declPos:    fd.Body.Pos(),
						escapePos:  token.NoPos,
						isValSlice: isSl,
					}
				}
			}
			for i := 0; i < sig.Results().Len(); i++ {
				rv := sig.Results().At(i)
				params[rv] = true
				namedResults[rv] = true
			}
		}
	}

	disqualified := map[*types.Var]bool{}
	for rv := range namedResults {
		if isFreshConstructableRootType(rv.Type()) {
			_, isSl := syntaxutil.UnderlyingType(rv.Type()).(*types.Slice)
			sum.vars[rv] = &freshVarState{
				rootVar:    rv,
				declPos:    fd.Body.Pos(),
				escapePos:  token.NoPos,
				isValSlice: isSl,
			}
		}
	}

	topStmtIndex := map[ast.Stmt]int{}
	for i, st := range fd.Body.List {
		topStmtIndex[st] = i
	}
	initialDefTopIdx := map[*types.Var]int{}
	rebindTopIdx := map[*types.Var]int{}
	rebindAssign := map[*types.Var]*ast.AssignStmt{}
	assignCount := map[*types.Var]int{}

	var loops []ast.Node
	var defers []*ast.DeferStmt
	var aliasDefs []struct {
		v       *types.Var
		pos     token.Pos
		addrArg ast.Expr
	}

	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		switch s := n.(type) {
		case *ast.ForStmt:
			loops = append(loops, s)
		case *ast.RangeStmt:
			loops = append(loops, s)
			if s.Key != nil {
				if v := syntaxutil.LookupIdentVar(p.TypesInfo, s.Key); v != nil {
					disqualified[v] = true
				}
			}
			if s.Value != nil {
				if v := syntaxutil.LookupIdentVar(p.TypesInfo, s.Value); v != nil {
					disqualified[v] = true
				}
			}
		case *ast.DeferStmt:
			defers = append(defers, s)
		case *ast.ValueSpec:
			for i, nm := range s.Names {
				v, ok := p.TypesInfo.Defs[nm].(*types.Var)
				if !ok || v == nil || params[v] || v.Parent() == p.Types.Scope() {
					continue
				}
				if idx.DefCounts[v] != 1 || idx.InFuncLit[nm] || idx.InGoStmt[nm] {
					disqualified[v] = true
					continue
				}
				if len(s.Values) == 0 {
					if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr && isFreshConstructableRootType(v.Type()) {
						_, isSl := syntaxutil.UnderlyingType(v.Type()).(*types.Slice)
						sum.vars[v] = &freshVarState{rootVar: v, declPos: nm.Pos(), escapePos: token.NoPos, isValSlice: isSl}
					}
				} else if i < len(s.Values) {
					rhs := s.Values[i]
					if isDirectFreshConstructExpr(p, rhs, freshReturnFuncs) {
						_, isSl := syntaxutil.UnderlyingType(v.Type()).(*types.Slice)
						sum.vars[v] = &freshVarState{rootVar: v, declPos: nm.Pos(), escapePos: token.NoPos, isValSlice: isSl}
						if cl := unwrapCompositeLit(rhs); cl != nil {
							recordCompositeLitNonFreshFields(p, cl, freshReturnFuncs, sum.nonFreshFields)
						}
					} else if un, isUn := ast.Unparen(rhs).(*ast.UnaryExpr); isUn && un.Op == token.AND {
						aliasDefs = append(aliasDefs, struct {
							v       *types.Var
							pos     token.Pos
							addrArg ast.Expr
						}{v: v, pos: nm.Pos(), addrArg: un.X})
					}
				}
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND {
				if v := syntaxutil.LookupIdentVar(p.TypesInfo, s.X); v != nil {
					if _, isSl := syntaxutil.UnderlyingType(v.Type()).(*types.Slice); !isSl {
						disqualified[v] = true
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
			if len(s.Lhs) >= 2 && len(s.Rhs) == 1 {
				if call, isCall := ast.Unparen(s.Rhs[0]).(*ast.CallExpr); isCall {
					if callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun); callee != nil {
						orig := callee.Origin()
						if orig.Pkg() == p.Types {
							sum.coneCallees[orig] = true
						}
						if len(s.Lhs) == 2 && freshReturnFuncs[orig] {
							l0 := s.Lhs[0]
							if lid, isID := ast.Unparen(l0).(*ast.Ident); isID {
								if v, _ := p.TypesInfo.Defs[lid].(*types.Var); v != nil && !params[v] && v.Parent() != p.Types.Scope() && idx.DefCounts[v] == 1 {
									_, isSl := syntaxutil.UnderlyingType(v.Type()).(*types.Slice)
									sum.vars[v] = &freshVarState{rootVar: v, declPos: lid.Pos(), escapePos: token.NoPos, isValSlice: isSl}
								} else if v, _ := p.TypesInfo.Uses[lid].(*types.Var); v != nil && namedResults[v] && s.Tok == token.ASSIGN {
									// Named result assigned from freshReturnFuncs: keep candidate.
								} else if v != nil {
									disqualified[v] = true
								}
							}
							if v1 := syntaxutil.LookupIdentVar(p.TypesInfo, s.Lhs[1]); v1 != nil {
								disqualified[v1] = true
							}
							return true
						}
					}
				}
				for _, l := range s.Lhs {
					if sel, isSel := ast.Unparen(l).(*ast.SelectorExpr); isSel {
						if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.FieldVal {
							if fObj, _ := selInfo.Obj().(*types.Var); fObj != nil {
								if isRefOrContainerType(fObj.Type()) {
									sum.nonFreshFields[fObj] = true
								}
								markValueContainedRefFieldsNonFresh(fObj.Type(), sum.nonFreshFields)
							}
						}
					}
					if v := syntaxutil.LookupIdentVar(p.TypesInfo, l); v != nil {
						disqualified[v] = true
					}
				}
				return true
			}
			if len(s.Lhs) != len(s.Rhs) {
				for _, l := range s.Lhs {
					if v := syntaxutil.LookupIdentVar(p.TypesInfo, l); v != nil {
						disqualified[v] = true
					}
				}
				return true
			}
			topIdx, isTop := topStmtIndex[s]
			for i, l := range s.Lhs {
				rhs := s.Rhs[i]
				if call, isCall := ast.Unparen(rhs).(*ast.CallExpr); isCall {
					if callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun); callee != nil && callee.Origin().Pkg() == p.Types {
						sum.coneCallees[callee.Origin()] = true
					}
				}
				if lid, isID := ast.Unparen(l).(*ast.Ident); isID {
					if defV, isDef := p.TypesInfo.Defs[lid].(*types.Var); isDef && defV != nil && !params[defV] && defV.Parent() != p.Types.Scope() {
						if isTop {
							initialDefTopIdx[defV] = topIdx
						}
						if idx.DefCounts[defV] != 1 {
							disqualified[defV] = true
							continue
						}
						if isDirectFreshConstructExpr(p, rhs, freshReturnFuncs) {
							_, isSl := syntaxutil.UnderlyingType(defV.Type()).(*types.Slice)
							sum.vars[defV] = &freshVarState{rootVar: defV, declPos: lid.Pos(), escapePos: token.NoPos, isValSlice: isSl}
							if cl := unwrapCompositeLit(rhs); cl != nil {
								recordCompositeLitNonFreshFields(p, cl, freshReturnFuncs, sum.nonFreshFields)
							}
						} else if un, isUn := ast.Unparen(rhs).(*ast.UnaryExpr); isUn && un.Op == token.AND {
							aliasDefs = append(aliasDefs, struct {
								v       *types.Var
								pos     token.Pos
								addrArg ast.Expr
							}{v: defV, pos: lid.Pos(), addrArg: un.X})
						}
						continue
					}
					if useV, isUse := p.TypesInfo.Uses[lid].(*types.Var); isUse && useV != nil {
						assignCount[useV]++
						if namedResults[useV] {
							if !syntaxutil.IsNilIdent(p.TypesInfo, rhs) && !isDirectFreshConstructExpr(p, rhs, freshReturnFuncs) && !isFreshFieldAssignRHS(p, l, rhs, freshReturnFuncs) {
								disqualified[useV] = true
							} else if cl := unwrapCompositeLit(rhs); cl != nil {
								recordCompositeLitNonFreshFields(p, cl, freshReturnFuncs, sum.nonFreshFields)
							}
							continue
						}
						if isTop && assignCount[useV] == 1 {
							if _, hasInit := initialDefTopIdx[useV]; hasInit && topIdx > initialDefTopIdx[useV] {
								rebindTopIdx[useV] = topIdx
								rebindAssign[useV] = s
								continue
							}
						}
						disqualified[useV] = true
						continue
					}
				}
				if sel, isSel := ast.Unparen(l).(*ast.SelectorExpr); isSel {
					if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.FieldVal {
						if fObj, _ := selInfo.Obj().(*types.Var); fObj != nil {
							if isRefOrContainerType(fObj.Type()) {
								if !isFreshFieldAssignRHS(p, l, rhs, freshReturnFuncs) {
									sum.nonFreshFields[fObj] = true
								} else if cl := unwrapCompositeLit(rhs); cl != nil {
									recordCompositeLitNonFreshFields(p, cl, freshReturnFuncs, sum.nonFreshFields)
								} else if call, isCall := ast.Unparen(rhs).(*ast.CallExpr); isCall && len(call.Args) >= 2 {
									if cid, isCID := ast.Unparen(call.Fun).(*ast.Ident); isCID {
										if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB && b.Name() == "append" {
											for _, elemArg := range call.Args[1:] {
												if cl := unwrapCompositeLit(elemArg); cl != nil {
													recordCompositeLitNonFreshFields(p, cl, freshReturnFuncs, sum.nonFreshFields)
												} else {
													markValueContainedRefFieldsNonFresh(p.TypesInfo.TypeOf(elemArg), sum.nonFreshFields)
												}
											}
										}
									}
								}
							} else if _, subSt := syntaxutil.DerefAnyStructType(fObj.Type()); subSt != nil {
								if cl := unwrapCompositeLit(rhs); cl != nil {
									recordCompositeLitNonFreshFields(p, cl, freshReturnFuncs, sum.nonFreshFields)
								} else {
									markValueContainedRefFieldsNonFresh(fObj.Type(), sum.nonFreshFields)
								}
							}
						}
					}
				} else if ix, isIx := ast.Unparen(l).(*ast.IndexExpr); isIx {
					if _, isSl := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(ix.X)).(*types.Slice); isSl {
						if cl := unwrapCompositeLit(rhs); cl != nil {
							recordCompositeLitNonFreshFields(p, cl, freshReturnFuncs, sum.nonFreshFields)
						} else {
							markValueContainedRefFieldsNonFresh(p.TypesInfo.TypeOf(ix), sum.nonFreshFields)
						}
					}
				}
			}
		case *ast.ReturnStmt:
			if len(s.Results) > 0 {
				if cl := unwrapCompositeLit(s.Results[0]); cl != nil {
					recordCompositeLitNonFreshFields(p, cl, freshReturnFuncs, sum.nonFreshFields)
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
		}
		return true
	})

	for v := range disqualified {
		delete(sum.vars, v)
	}

	for v := range rebindTopIdx {
		if disqualified[v] || assignCount[v] != 1 {
			delete(sum.vars, v)
			continue
		}
		as := rebindAssign[v]
		if as == nil || len(as.Rhs) != 1 {
			delete(sum.vars, v)
			continue
		}
		wroteBefore := false
		for _, uid := range idx.UsesOf[v] {
			if uid.Pos() < as.Pos() && IdentReachesMutatedOrAddrPrefix(p, idx, uid) {
				wroteBefore = true
				break
			}
		}
		if wroteBefore {
			delete(sum.vars, v)
			continue
		}
		delete(sum.vars, v)
		if un, isUn := ast.Unparen(as.Rhs[0]).(*ast.UnaryExpr); isUn && un.Op == token.AND {
			aliasDefs = append(aliasDefs, struct {
				v       *types.Var
				pos     token.Pos
				addrArg ast.Expr
			}{v: v, pos: as.End(), addrArg: un.X})
		}
	}

	resolveRootOfExpr := func(expr ast.Expr) *types.Var {
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
	dummyPF := &PkgFreshConstructors{p: p, idx: idx, funcs: map[*ast.FuncDecl]*freshFuncSummary{fd: sum}}
	for pass := 0; pass < 4; pass++ {
		added := false
		for _, ad := range aliasDefs {
			if disqualified[ad.v] || sum.vars[ad.v] != nil {
				continue
			}
			ptr, isPtr := syntaxutil.UnderlyingType(ad.v.Type()).(*types.Pointer)
			if !isPtr {
				continue
			}
			if _, elemSt := syntaxutil.DerefAnyStructType(ptr.Elem()); elemSt == nil || elemSt.NumFields() == 0 {
				continue
			}
			if dummyPF.isFreshContainerAt(sum, ad.addrArg, ad.pos) {
				rv := resolveRootOfExpr(ad.addrArg)
				if rv != nil && sum.vars[rv] != nil {
					sum.vars[ad.v] = &freshVarState{
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

	clampToLoops := func(rootDeclPos, usePos token.Pos) token.Pos {
		esc := usePos
		for _, lp := range loops {
			if lp.Pos() <= usePos && usePos < lp.End() && !(lp.Pos() <= rootDeclPos && rootDeclPos < lp.End()) {
				if lp.Pos() < esc {
					esc = lp.Pos()
				}
			}
		}
		return esc
	}
	recordEscape := func(v *types.Var, pos token.Pos) bool {
		st := sum.vars[v]
		if st == nil {
			return false
		}
		rootSt := sum.vars[st.rootVar]
		if rootSt == nil {
			rootSt = st
		}
		clamped := clampToLoops(rootSt.declPos, pos)
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

	for {
		for _, st := range sum.vars {
			st.escapePos = token.NoPos
		}
		var couplings []freshEscapeCoupling

		for v, st := range sum.vars {
			usedInDefer := false
			for _, id := range idx.UsesOf[v] {
				if st.declPos != token.NoPos && id.Pos() < st.declPos {
					continue
				}
				if idx.InGoStmt[id] {
					recordEscape(v, fd.Body.Pos())
					continue
				}
				for _, df := range defers {
					if df.Pos() <= id.Pos() && id.Pos() < df.End() {
						usedInDefer = true
						break
					}
				}
				if idx.InFuncLit[id] {
					lit := enclosingFuncLit(idx, id)
					ownerRoot, readOnlyFieldClosure, returnsAddrOnly := classifyFieldAssignedClosureUse(p, idx, lit, v, resolveRootOfExpr)
					if readOnlyFieldClosure && ownerRoot != nil {
						if returnsAddrOnly {
							recordEscape(v, lit.Pos())
						} else {
							couplings = append(couplings, freshEscapeCoupling{srcRoot: st.rootVar, dstRoot: ownerRoot, atPos: lit.Pos()})
						}
						continue
					}
					if lit != nil {
						recordEscape(v, lit.Pos())
					} else {
						recordEscape(v, fd.Body.Pos())
					}
					continue
				}

				if useIsNonEscapingOnFreshVar(
					p,
					idx,
					fd,
					sum,
					v,
					id,
					freshParamFuncs,
					nonEscParams,
					mapStoreParams,
					retStructParams,
					paramGuardPkgs,
					nonEscAuxVars,
					confinedCacheMaps,
					resolveRootOfExpr,
					&couplings,
				) {
					continue
				}
				if (!params[v] || namedResults[v]) && st.rootVar == v && len(defers) == 0 {
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
							continue
						}
					}
				}
				recordEscape(v, id.Pos())
			}
			if usedInDefer {
				recordEscape(v, fd.Body.Pos())
			}
		}

		if len(namedResults) > 0 {
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if n == nil {
					return false
				}
				if _, isLit := n.(*ast.FuncLit); isLit {
					return false
				}
				if ret, isRet := n.(*ast.ReturnStmt); isRet && len(ret.Results) == 0 {
					for rv := range namedResults {
						if sum.vars[rv] != nil {
							recordEscape(rv, ret.Pos())
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
					if recordEscape(cp.srcRoot, cp.atPos) {
						changed = true
					}
					continue
				}
				if dstSt.escapePos != token.NoPos {
					targetPos := dstSt.escapePos
					if cp.atPos >= dstSt.escapePos {
						targetPos = cp.atPos
					}
					if recordEscape(cp.srcRoot, targetPos) {
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
					if clampToLoops(rootSt.declPos, uid.Pos()) >= rootSt.escapePos {
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

	return sum
}
