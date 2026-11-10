// Package freshstruct analyzes stack-private fresh local struct allocations,
// unexported fresh constructor cones, non-escaping intra-package parameter
// flows, mutex-confined reflect.Type constructor caches, and non-exempted
// struct mutations across a package's syntax.
package freshstruct

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

type freshFuncEntry struct {
	vars      map[*types.Var]bool
	escapePos map[*types.Var]token.Pos
}

// FreshLocalsCache memoizes CollectFreshLocalStructVars per *ast.FuncDecl so
// protoaudit and CollectMutatedStructTypes share the computed sets without
// rescanning function bodies.
type FreshLocalsCache struct {
	p       *packages.Package
	idx     *refconfine.PkgIndex
	entries map[*ast.FuncDecl]freshFuncEntry
}

// NewFreshLocalsCache creates a per-package cache for CollectFreshLocalStructVars.
func NewFreshLocalsCache(p *packages.Package, idx *refconfine.PkgIndex) *FreshLocalsCache {
	return &FreshLocalsCache{
		p:       p,
		idx:     idx,
		entries: map[*ast.FuncDecl]freshFuncEntry{},
	}
}

// Get returns the fresh local struct variables and their earliest escape
// positions in fd, computing and caching the result on first lookup.
func (c *FreshLocalsCache) Get(fd *ast.FuncDecl) (map[*types.Var]bool, map[*types.Var]token.Pos) {
	if c == nil || fd == nil {
		return nil, nil
	}
	if entry, ok := c.entries[fd]; ok {
		return entry.vars, entry.escapePos
	}
	vars, esc := CollectFreshLocalStructVars(c.p, c.idx, fd)
	c.entries[fd] = freshFuncEntry{vars: vars, escapePos: esc}
	return vars, esc
}

// CollectFreshLocalStructVars returns local (non-global) variables in fd whose
// every assignment/initialization in fd.Body constructs a fresh, unaliased struct
// value or pointer (var v S, v := S{...}, v := &S{...}, v := new(S), or a
// non-address-taken stack-private carrier-free value struct parameter/result),
// along with each variable's first non-selection escape position in fd.Body.
func CollectFreshLocalStructVars(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	fd *ast.FuncDecl,
) (map[*types.Var]bool, map[*types.Var]token.Pos) {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || fd == nil || fd.Body == nil {
		return nil, nil
	}
	if FuncBodyHasGoto(fd.Body) {
		return nil, nil
	}

	hasNonEmptyStructElem := func(t types.Type) bool {
		_, st := syntaxutil.DerefAnyStructType(t)
		return st != nil && st.NumFields() > 0
	}
	isStackPrivateValueStruct := func(t types.Type) bool {
		if t == nil {
			return false
		}
		if _, isPtr := types.Unalias(t).(*types.Pointer); isPtr {
			return false
		}
		return hasNonEmptyStructElem(t) && !refconfine.TypeContainsRefOrPointer(t)
	}

	params := map[*types.Var]bool{}
	stackValueVars := map[*types.Var]bool{}
	if fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func); ok && fn != nil {
		if sig, okS := fn.Type().(*types.Signature); okS {
			if sig.Recv() != nil {
				v := sig.Recv()
				params[v] = true
				if isStackPrivateValueStruct(v.Type()) {
					stackValueVars[v] = true
				}
			}
			for i := 0; i < sig.Params().Len(); i++ {
				v := sig.Params().At(i)
				params[v] = true
				if isStackPrivateValueStruct(v.Type()) {
					stackValueVars[v] = true
				}
			}
			for i := 0; i < sig.Results().Len(); i++ {
				v := sig.Results().At(i)
				params[v] = true
				if isStackPrivateValueStruct(v.Type()) {
					stackValueVars[v] = true
				}
			}
		}
	}
	candidates := map[*types.Var]bool{}
	disqualified := map[*types.Var]bool{}
	declPos := map[*types.Var]token.Pos{}
	for v := range stackValueVars {
		candidates[v] = true
		declPos[v] = fd.Body.Pos()
	}

	isAliasableFieldType := func(t types.Type) bool {
		return refconfine.TypeCarriesMutableRef(t)
	}
	var isFreshFieldInit func(expr ast.Expr) bool
	isFreshFieldInit = func(expr ast.Expr) bool {
		expr = ast.Unparen(expr)
		if syntaxutil.IsNilIdent(p.TypesInfo, expr) {
			return true
		}
		switch e := expr.(type) {
		case *ast.CompositeLit:
			for _, elt := range e.Elts {
				val := elt
				if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
					val = kv.Value
				}
				if isAliasableFieldType(p.TypesInfo.TypeOf(val)) && !isFreshFieldInit(val) {
					return false
				}
			}
			return true
		case *ast.UnaryExpr:
			if e.Op == token.AND {
				if cl, ok := ast.Unparen(e.X).(*ast.CompositeLit); ok {
					return isFreshFieldInit(cl)
				}
			}
		case *ast.CallExpr:
			if id, ok := ast.Unparen(e.Fun).(*ast.Ident); ok {
				if b, isB := p.TypesInfo.Uses[id].(*types.Builtin); isB && (b.Name() == "new" || b.Name() == "make") {
					return true
				}
			}
		}
		return false
	}

	isFreshStructAlloc := func(expr ast.Expr) bool {
		expr = ast.Unparen(expr)
		switch e := expr.(type) {
		case *ast.CompositeLit:
			return hasNonEmptyStructElem(p.TypesInfo.TypeOf(e)) && isFreshFieldInit(e)
		case *ast.UnaryExpr:
			if e.Op == token.AND {
				if cl, ok := ast.Unparen(e.X).(*ast.CompositeLit); ok {
					return hasNonEmptyStructElem(p.TypesInfo.TypeOf(cl)) && isFreshFieldInit(cl)
				}
			}
		case *ast.CallExpr:
			if id, ok := ast.Unparen(e.Fun).(*ast.Ident); ok && len(e.Args) == 1 {
				if b, isB := p.TypesInfo.Uses[id].(*types.Builtin); isB && b.Name() == "new" {
					return hasNonEmptyStructElem(p.TypesInfo.TypeOf(e))
				}
			}
		}
		return false
	}

	rootLocalIdent := func(expr ast.Expr) *types.Var {
		cur := ast.Unparen(expr)
		for {
			switch e := cur.(type) {
			case *ast.Ident:
				v, _ := p.TypesInfo.Uses[e].(*types.Var)
				return v
			case *ast.SelectorExpr:
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

	addrTaken := map[*types.Var]bool{}
	var loops []ast.Node
	var defers []*ast.DeferStmt

	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.ForStmt:
			loops = append(loops, s)
		case *ast.RangeStmt:
			loops = append(loops, s)
			if s.Key != nil {
				if v := syntaxutil.LookupIdentVar(p.TypesInfo, s.Key); v != nil && !stackValueVars[v] {
					disqualified[v] = true
				}
			}
			if s.Value != nil {
				if v := syntaxutil.LookupIdentVar(p.TypesInfo, s.Value); v != nil && !stackValueVars[v] {
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
				if isStackPrivateValueStruct(v.Type()) {
					stackValueVars[v] = true
					candidates[v] = true
					declPos[v] = nm.Pos()
					continue
				}
				if len(s.Values) == 0 {
					if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr && hasNonEmptyStructElem(v.Type()) {
						candidates[v] = true
						declPos[v] = nm.Pos()
					} else {
						disqualified[v] = true
					}
				} else if i < len(s.Values) && isFreshStructAlloc(s.Values[i]) {
					candidates[v] = true
					declPos[v] = nm.Pos()
				} else {
					disqualified[v] = true
				}
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND {
				if v := syntaxutil.LookupIdentVar(p.TypesInfo, s.X); v != nil {
					disqualified[v] = true
				}
				if rv := rootLocalIdent(s.X); rv != nil {
					addrTaken[rv] = true
				}
			}
		case *ast.AssignStmt:
			if len(s.Lhs) != len(s.Rhs) {
				for _, l := range s.Lhs {
					if v := syntaxutil.LookupIdentVar(p.TypesInfo, l); v != nil && !stackValueVars[v] {
						disqualified[v] = true
					}
				}
				return true
			}
			for i, l := range s.Lhs {
				if v := syntaxutil.LookupIdentVar(p.TypesInfo, l); v != nil && v.Parent() != p.Types.Scope() {
					if stackValueVars[v] {
						if idx.InFuncLit[l] || idx.InGoStmt[l] {
							disqualified[v] = true
						}
						continue
					}
					if params[v] {
						disqualified[v] = true
						continue
					}
					lid, isID := ast.Unparen(l).(*ast.Ident)
					if !isID || p.TypesInfo.Defs[lid] != v || s.Tok == token.ASSIGN ||
						idx.DefCounts[v] != 1 || idx.InFuncLit[l] || idx.InGoStmt[l] || !isFreshStructAlloc(s.Rhs[i]) {
						disqualified[v] = true
					} else {
						candidates[v] = true
						declPos[v] = lid.Pos()
					}
					continue
				}
				if rv := rootLocalIdent(l); rv != nil && isAliasableFieldType(p.TypesInfo.TypeOf(l)) && !isFreshFieldInit(s.Rhs[i]) {
					disqualified[rv] = true
				}
			}
		}
		return true
	})

	escapePos := map[*types.Var]token.Pos{}
	for v := range candidates {
		if disqualified[v] {
			delete(candidates, v)
			continue
		}
		if stackValueVars[v] {
			if addrTaken[v] {
				delete(candidates, v)
				continue
			}
			badClosure := false
			for _, id := range idx.UsesOf[v] {
				if idx.InFuncLit[id] || idx.InGoStmt[id] {
					badClosure = true
					break
				}
			}
			if badClosure {
				delete(candidates, v)
			}
			continue
		}
		dpos := declPos[v]
		usedInDefer := false
		for _, id := range idx.UsesOf[v] {
			if idx.InFuncLit[id] || idx.InGoStmt[id] {
				delete(candidates, v)
				delete(escapePos, v)
				break
			}
			for _, df := range defers {
				if df.Pos() <= id.Pos() && id.Pos() < df.End() {
					usedInDefer = true
					break
				}
			}
			par := idx.ParentUnparen(id)
			if sel, isSel := par.(*ast.SelectorExpr); isSel && ast.Unparen(sel.X) == id {
				if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.FieldVal {
					continue
				}
			}
			if star, isStar := par.(*ast.StarExpr); isStar && ast.Unparen(star.X) == id {
				continue
			}
			useEsc := id.Pos()
			for _, lp := range loops {
				if lp.Pos() <= id.Pos() && id.Pos() < lp.End() && !(lp.Pos() <= dpos && dpos < lp.End()) {
					if lp.Pos() < useEsc {
						useEsc = lp.Pos()
					}
				}
			}
			if prev, exists := escapePos[v]; !exists || useEsc < prev {
				escapePos[v] = useEsc
			}
		}
		if _, hasEsc := escapePos[v]; hasEsc && (addrTaken[v] || usedInDefer) {
			delete(candidates, v)
			delete(escapePos, v)
		}
	}
	return candidates, escapePos
}

// IsRootedAtFreshLocal reports whether expr is rooted at a fresh local variable
// in fresh and occurs strictly before that variable's escapePos.
func IsRootedAtFreshLocal(
	p *packages.Package,
	expr ast.Expr,
	fresh map[*types.Var]bool,
	escapePos map[*types.Var]token.Pos,
) bool {
	if p == nil || p.TypesInfo == nil || expr == nil || len(fresh) == 0 {
		return false
	}
	checkVar := func(v *types.Var) bool {
		if v == nil || !fresh[v] {
			return false
		}
		if esc, hasEsc := escapePos[v]; hasEsc && esc != token.NoPos && expr.Pos() >= esc {
			return false
		}
		return true
	}
	cur := ast.Unparen(expr)
	for {
		switch e := cur.(type) {
		case *ast.Ident:
			v, _ := p.TypesInfo.Uses[e].(*types.Var)
			return checkVar(v)
		case *ast.SelectorExpr:
			if selInfo := p.TypesInfo.Selections[e]; selInfo != nil && selInfo.Kind() == types.FieldVal {
				if syntaxutil.SelectionCrossesEmbeddedPointer(selInfo) {
					return false
				}
				if _, isIdent := ast.Unparen(e.X).(*ast.Ident); !isIdent {
					if _, isPtr := types.Unalias(p.TypesInfo.TypeOf(e.X)).(*types.Pointer); isPtr {
						return false
					}
				}
				cur = ast.Unparen(e.X)
				continue
			}
			return false
		case *ast.IndexExpr:
			if _, isArr := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(e.X)).(*types.Array); isArr {
				cur = ast.Unparen(e.X)
				continue
			}
			return false
		case *ast.StarExpr:
			if id, isID := ast.Unparen(e.X).(*ast.Ident); isID {
				v, _ := p.TypesInfo.Uses[id].(*types.Var)
				return checkVar(v)
			}
			return false
		default:
			return false
		}
	}
}

// FuncBodyHasGoto reports whether body contains any goto statement.
func FuncBodyHasGoto(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	hasGoto := false
	ast.Inspect(body, func(n ast.Node) bool {
		if hasGoto || n == nil {
			return false
		}
		if br, ok := n.(*ast.BranchStmt); ok && br.Tok == token.GOTO {
			hasGoto = true
			return false
		}
		return true
	})
	return hasGoto
}

// IdentReachesMutatedOrAddrPrefix reports whether id is the root of a field or
// index chain that appears on the LHS of an assignment/inc-dec or as the
// operand of &.
func IdentReachesMutatedOrAddrPrefix(p *packages.Package, idx *refconfine.PkgIndex, id *ast.Ident) bool {
	if p == nil || p.TypesInfo == nil || idx == nil || id == nil {
		return false
	}
	cur := ast.Node(id)
	for {
		par := idx.ParentUnparen(cur)
		switch x := par.(type) {
		case *ast.SelectorExpr:
			if ast.Unparen(x.X) == cur {
				if selInfo := p.TypesInfo.Selections[x]; selInfo != nil && selInfo.Kind() == types.FieldVal {
					cur = x
					continue
				}
			}
			return false
		case *ast.IndexExpr:
			if ast.Unparen(x.X) == cur {
				cur = x
				continue
			}
			return false
		case *ast.UnaryExpr:
			return x.Op == token.AND
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if ast.Unparen(lhs) == cur {
					return true
				}
			}
			return false
		case *ast.IncDecStmt:
			return ast.Unparen(x.X) == cur
		default:
			return false
		}
	}
}

// FindMutexConfinedConstructorCaches identifies unexported map[reflect.Type]T
// package variables guarded exclusively by an unexported package-scope
// sync.Mutex in a single entry function and its exclusive helper cone.
func FindMutexConfinedConstructorCaches(p *packages.Package, idx *refconfine.PkgIndex) map[*types.Var]map[*ast.FuncDecl]bool {
	out := map[*types.Var]map[*ast.FuncDecl]bool{}
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil {
		return out
	}
	for _, name := range p.Types.Scope().Names() {
		mv, isVar := p.Types.Scope().Lookup(name).(*types.Var)
		if !isVar || mv == nil || mv.Exported() {
			continue
		}
		mapT, isMap := syntaxutil.UnderlyingType(mv.Type()).(*types.Map)
		if !isMap || !syntaxutil.IsReflectType(mapT.Key()) {
			continue
		}
		if len(idx.UsesOf[mv]) == 0 {
			continue
		}
		for entryFn, entryFD := range idx.FuncDecls {
			if entryFn == nil || entryFD == nil || entryFD.Body == nil || len(entryFD.Body.List) < 3 {
				continue
			}
			muVar := matchPkgMutexLockDeferUnlock(p, entryFD.Body.List[0], entryFD.Body.List[1])
			if muVar == nil || muVar.Exported() || len(idx.UsesOf[muVar]) != 2 {
				continue
			}
			allMuInEntry := true
			for _, u := range idx.UsesOf[muVar] {
				if !idx.IsSyncInFuncDecl(u, entryFD) ||
					!((entryFD.Body.List[0].Pos() <= u.Pos() && u.Pos() < entryFD.Body.List[0].End()) ||
						(entryFD.Body.List[1].Pos() <= u.Pos() && u.Pos() < entryFD.Body.List[1].End())) {
					allMuInEntry = false
					break
				}
			}
			if !allMuInEntry {
				continue
			}
			coneFuncs := refconfine.ComputeExclusiveHelperCone(p, idx, entryFn)
			coneFDs := map[*ast.FuncDecl]bool{entryFD: true}
			for cf := range coneFuncs {
				if cfd := idx.FuncDecls[cf]; cfd != nil {
					coneFDs[cfd] = true
				}
			}
			allMapOK := true
			for _, u := range idx.UsesOf[mv] {
				encl := idx.SyncEnclFuncDecl(u)
				if !coneFDs[encl] {
					allMapOK = false
					break
				}
				par := idx.ParentUnparen(u)
				switch x := par.(type) {
				case *ast.BinaryExpr:
					if (x.Op != token.EQL && x.Op != token.NEQ) || (!syntaxutil.IsNilIdent(p.TypesInfo, x.X) && !syntaxutil.IsNilIdent(p.TypesInfo, x.Y)) {
						allMapOK = false
					}
				case *ast.AssignStmt:
					if len(x.Lhs) == 1 && len(x.Rhs) == 1 && ast.Unparen(x.Lhs[0]) == u {
						cid, isID := ast.Unparen(x.Rhs[0]).(*ast.CallExpr)
						blk, isBlk := idx.ParentMap[x].(*ast.BlockStmt)
						var enclosingIf *ast.IfStmt
						if isBlk && len(blk.List) == 1 {
							enclosingIf, _ = idx.ParentMap[blk].(*ast.IfStmt)
						}
						condNil := false
						if enclosingIf != nil && enclosingIf.Else == nil {
							if bc, isBC := ast.Unparen(enclosingIf.Cond).(*ast.BinaryExpr); isBC && bc.Op == token.EQL {
								condNil = (syntaxutil.LookupPkgScopeVar(p, bc.X) == mv && syntaxutil.IsNilIdent(p.TypesInfo, bc.Y)) ||
									(syntaxutil.LookupPkgScopeVar(p, bc.Y) == mv && syntaxutil.IsNilIdent(p.TypesInfo, bc.X))
							}
						}
						if !isID || !isMakeCall(p, cid) || !condNil {
							allMapOK = false
						}
					} else {
						allMapOK = false
					}
				case *ast.IndexExpr:
					if ast.Unparen(x.X) != u {
						allMapOK = false
						break
					}
					up := idx.ParentUnparen(x)
					if as, isAs := up.(*ast.AssignStmt); isAs {
						if len(as.Lhs) == 1 && ast.Unparen(as.Lhs[0]) == x {
							continue
						}
						if len(as.Rhs) == 1 && ast.Unparen(as.Rhs[0]) == x && len(as.Lhs) == 2 {
							lid, isID0 := ast.Unparen(as.Lhs[0]).(*ast.Ident)
							okID, isID1 := ast.Unparen(as.Lhs[1]).(*ast.Ident)
							ifStmt, isIfInit := idx.ParentMap[as].(*ast.IfStmt)
							if isID0 && isID1 && isIfInit && ifStmt.Init == as && ifStmt.Else == nil && ifStmt.Body != nil && len(ifStmt.Body.List) == 1 {
								lv, _ := p.TypesInfo.Defs[lid].(*types.Var)
								okV, _ := p.TypesInfo.Defs[okID].(*types.Var)
								condIdent, isCondID := ast.Unparen(ifStmt.Cond).(*ast.Ident)
								retSt, isRet := ifStmt.Body.List[0].(*ast.ReturnStmt)
								if lv != nil && okV != nil && isCondID && p.TypesInfo.Uses[condIdent] == okV &&
									isRet && len(retSt.Results) == 1 {
									if rid, isRID := ast.Unparen(retSt.Results[0]).(*ast.Ident); isRID && p.TypesInfo.Uses[rid] == lv {
										for _, lu := range idx.UsesOf[lv] {
											if IdentReachesMutatedOrAddrPrefix(p, idx, lu) {
												allMapOK = false
												break
											}
										}
										continue
									}
								}
							}
						}
					}
					allMapOK = false
				default:
					allMapOK = false
				}
				if !allMapOK {
					break
				}
			}
			if allMapOK {
				out[mv] = coneFDs
				break
			}
		}
	}
	return out
}

func matchPkgMutexLockDeferUnlock(p *packages.Package, s0, s1 ast.Stmt) *types.Var {
	es0, ok0 := s0.(*ast.ExprStmt)
	df1, ok1 := s1.(*ast.DeferStmt)
	if !ok0 || !ok1 {
		return nil
	}
	c0, okC0 := ast.Unparen(es0.X).(*ast.CallExpr)
	if !okC0 || len(c0.Args) != 0 || len(df1.Call.Args) != 0 {
		return nil
	}
	sel0, okS0 := ast.Unparen(c0.Fun).(*ast.SelectorExpr)
	sel1, okS1 := ast.Unparen(df1.Call.Fun).(*ast.SelectorExpr)
	if !okS0 || !okS1 || sel0.Sel.Name != "Lock" || sel1.Sel.Name != "Unlock" {
		return nil
	}
	v0 := syntaxutil.LookupPkgScopeVar(p, sel0.X)
	v1 := syntaxutil.LookupPkgScopeVar(p, sel1.X)
	if v0 == nil || v0 != v1 || !syntaxutil.IsNamedInPkg(v0.Type(), "sync", "Mutex") {
		return nil
	}
	return v0
}

func isMakeCall(p *packages.Package, call *ast.CallExpr) bool {
	if call == nil {
		return false
	}
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	b, isB := p.TypesInfo.Uses[id].(*types.Builtin)
	return isB && b.Name() == "make"
}

func fdInConfinedCache(fd *ast.FuncDecl, confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool) bool {
	if fd == nil {
		return false
	}
	for _, fds := range confinedCacheMaps {
		if fds[fd] {
			return true
		}
	}
	return false
}
