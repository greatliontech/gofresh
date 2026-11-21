// Package freshalloc analyzes stack-private fresh local struct allocations,
// unexported fresh constructor cones, non-escaping intra-package parameter
// flows, mutex-confined reflect.Type constructor caches, fresh-owned scalar
// containers, and non-ValueOf reflect.Value constructor origins.
package freshalloc

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type freshFuncEntry struct {
	vars      map[*types.Var]bool
	escapePos map[*types.Var]token.Pos
}

// FreshLocalsCache memoizes collectFreshLocalStructVars per *ast.FuncDecl so
// capsule and structmut share the computed sets without rescanning function
// bodies.
type FreshLocalsCache struct {
	p       *packages.Package
	idx     *refconfine.PkgIndex
	entries map[*ast.FuncDecl]freshFuncEntry
}

// NewFreshLocalsCache creates a per-package cache for collectFreshLocalStructVars.
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
	vars, esc := collectFreshLocalStructVars(c.p, c.idx, fd)
	c.entries[fd] = freshFuncEntry{vars: vars, escapePos: esc}
	return vars, esc
}

// collectFreshLocalStructVars returns local (non-global) variables in fd whose
// every assignment/initialization in fd.Body constructs a fresh, unaliased struct
// value or pointer (var v S, v := S{...}, v := &S{...}, v := new(S), or a
// non-address-taken stack-private carrier-free value struct parameter/result),
// along with each variable's first non-selection escape position in fd.Body.
func collectFreshLocalStructVars(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	fd *ast.FuncDecl,
) (map[*types.Var]bool, map[*types.Var]token.Pos) {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || fd == nil || fd.Body == nil {
		return nil, nil
	}
	if idx.FlowCache(p).FuncBody(fd).HasGotoAnywhere() {
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
	isFreshFieldInit := func(expr ast.Expr) bool {
		return IsFreshInlineValue(p, expr)
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
			if syntaxutil.IsBuiltinNewType(p.TypesInfo, e) {
				return hasNonEmptyStructElem(p.TypesInfo.TypeOf(e))
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
		case *ast.SliceExpr:
			if _, isArr := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(s.X)).(*types.Array); isArr {
				if rv := rootLocalIdent(s.X); rv != nil {
					addrTaken[rv] = true
				}
			}
		case *ast.SelectorExpr:
			if selInfo := p.TypesInfo.Selections[s]; selInfo != nil && selInfo.Kind() == types.MethodVal {
				if _, isPtrRecv := types.Unalias(selInfo.Recv()).(*types.Pointer); isPtrRecv {
					if _, isXPtr := types.Unalias(p.TypesInfo.TypeOf(s.X)).(*types.Pointer); !isXPtr {
						if rv := rootLocalIdent(s.X); rv != nil {
							addrTaken[rv] = true
						}
					}
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
		_, hasEsc := escapePos[v]
		if addrTaken[v] || (hasEsc && usedInDefer) {
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

// IsFreshInlineValue reports whether expr directly constructs a fresh,
// unaliased composite, new(T), make(...), or nil value whose reference-carrying
// elements are themselves recursively fresh inline values.
func IsFreshInlineValue(p *packages.Package, expr ast.Expr) bool {
	if p == nil || p.TypesInfo == nil || expr == nil {
		return false
	}
	expr = ast.Unparen(expr)
	if syntaxutil.IsNilIdent(p.TypesInfo, expr) || syntaxutil.IsTypedNilSliceConv(p, expr) {
		return true
	}
	switch e := expr.(type) {
	case *ast.CompositeLit:
		_, isStructComp := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(e)).(*types.Struct)
		for _, elt := range e.Elts {
			val := elt
			if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
				if !isStructComp && refconfine.TypeCarriesMutableRef(p.TypesInfo.TypeOf(kv.Key)) && !IsFreshInlineValue(p, kv.Key) {
					return false
				}
				val = kv.Value
			}
			if refconfine.TypeCarriesMutableRef(p.TypesInfo.TypeOf(val)) && !IsFreshInlineValue(p, val) {
				return false
			}
		}
		return true
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			if cl, ok := ast.Unparen(e.X).(*ast.CompositeLit); ok {
				return IsFreshInlineValue(p, cl)
			}
		}
	case *ast.CallExpr:
		if syntaxutil.IsBuiltinNewType(p.TypesInfo, e) {
			return true
		}
		if id, ok := ast.Unparen(e.Fun).(*ast.Ident); ok {
			if b, isB := p.TypesInfo.Uses[id].(*types.Builtin); isB && b.Name() == "make" {
				return true
			}
		}
	}
	return false
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

// FindMutexConfinedConstructorCaches identifies unexported single-definition
// map[reflect.Type]T package variables guarded exclusively by a dedicated
// unexported single-definition sync.Mutex or sync.RWMutex in a single entry
// function and its write-locked exclusive intra-package helper cone.
func FindMutexConfinedConstructorCaches(p *packages.Package, idx *refconfine.PkgIndex) map[*types.Var]map[*ast.FuncDecl]bool {
	out := map[*types.Var]map[*ast.FuncDecl]bool{}
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || !syntaxutil.IsTrueStdlibInPkg(p, "reflect") {
		return out
	}
	for _, name := range p.Types.Scope().Names() {
		mv, isVar := p.Types.Scope().Lookup(name).(*types.Var)
		if !isVar || mv == nil || mv.Exported() {
			continue
		}
		verified, ok := refconfine.VerifyMutexConfinedMap(p, idx, mv, refconfine.MutexMapConfig{
			AllowNilLazyInit:     true,
			AllowIntraPkgHelpers: true,
			KeyPred:              syntaxutil.IsReflectType,
		})
		if ok && verified != nil && len(verified.ConeDecls) > 0 {
			out[mv] = verified.ConeDecls
		}
	}
	return out
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
