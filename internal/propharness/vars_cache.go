package propharness

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func verifyCachedAndGlobalGeneratorImplsImmutable(
	g *harnessGraph,
	categoryImmutable map[*types.Var]bool,
	syncMapFuncs map[*types.Func]bool,
) (map[*types.Named]bool, bool) {
	sc := g.screen
	if len(sc.generatorOrigins) == 0 {
		return nil, false
	}
	info := g.info
	pkgTypes := g.pkgTypes
	allDecls := g.allDecls
	mutatedOrAddrLocals := g.mutatedOrAddrLocals
	mutatedNamedStructs := g.mutatedNamedStructs
	isGenPtr := sc.isGeneratorPtrType

	checkedStructs := map[*types.Named]bool{}
	var verifyConstructedStruct func(named *types.Named) bool
	var verifyFieldType func(ft types.Type, seen map[types.Type]bool) bool

	verifyFieldType = func(ft types.Type, seen map[types.Type]bool) bool {
		if ft == nil {
			return false
		}
		ft = types.Unalias(ft)
		if _, isTP := ft.(*types.TypeParam); isTP {
			return true
		}
		if isGenPtr(ft) || seen[ft] {
			return true
		}
		seen[ft] = true
		if fnamed, isN := ft.(*types.Named); isN && fnamed.Obj() != nil {
			if fnamed.Obj().Pkg() == pkgTypes {
				if sc.generatorOrigins[fnamed.Origin()] {
					return true
				}
				if _, isSubSt := fnamed.Underlying().(*types.Struct); isSubSt {
					return verifyConstructedStruct(fnamed)
				}
			} else if fnamed.Obj().Pkg() != nil {
				p := fnamed.Obj().Pkg().Path()
				if p == "sync" || p == "sync/atomic" {
					return false
				}
			}
		}
		switch u := ft.Underlying().(type) {
		case *types.Basic:
			return u.Kind() != types.UnsafePointer && u.Kind() != types.Invalid
		case *types.Pointer:
			enamed, isEN := types.Unalias(u.Elem()).(*types.Named)
			if !isEN || enamed.Obj() == nil {
				return false
			}
			if enamed.Obj().Pkg() == pkgTypes {
				if sc.generatorOrigins[enamed.Origin()] {
					return true
				}
				if _, isSubSt := enamed.Underlying().(*types.Struct); isSubSt && !enamed.Obj().Exported() {
					return verifyConstructedStruct(enamed)
				}
				return false
			}
			if enamed.Obj().Pkg() != nil {
				p, n := enamed.Obj().Pkg().Path(), enamed.Obj().Name()
				if ((p == "regexp" && n == "Regexp") || (p == "regexp/syntax" && n == "Regexp") || (p == "unicode" && n == "RangeTable")) && !mutatedNamedStructs[enamed.Origin()] {
					return true
				}
			}
			return false
		case *types.Slice:
			return verifyFieldType(u.Elem(), seen)
		case *types.Array:
			return verifyFieldType(u.Elem(), seen)
		case *types.Map, *types.Chan, *types.Interface:
			return false
		case *types.Struct:
			if _, isN := ft.(*types.Named); !isN && u.NumFields() > 0 {
				return false
			}
			for i := 0; i < u.NumFields(); i++ {
				if !verifyFieldType(u.Field(i).Type(), seen) {
					return false
				}
			}
		}
		return true
	}

	verifyConstructedStruct = func(named *types.Named) bool {
		if named == nil || named.Obj() == nil || named.Obj().Pkg() != pkgTypes {
			return false
		}
		orig := named.Origin()
		if sc.generatorOrigins[orig] {
			return true
		}
		if orig.Obj().Exported() || mutatedNamedStructs[orig] {
			return false
		}
		if checkedStructs[orig] {
			return true
		}
		checkedStructs[orig] = true
		st, isSt := orig.Underlying().(*types.Struct)
		if !isSt {
			return false
		}
		for i := 0; i < st.NumFields(); i++ {
			if !verifyFieldType(st.Field(i).Type(), map[types.Type]bool{}) {
				return false
			}
		}
		return true
	}

	var roots []ast.Node
	visitedFuncs := map[*types.Func]bool{}
	var queue []*types.Func
	enqueueFn := func(fn *types.Func) {
		if fn == nil {
			return
		}
		orig := fn.Origin()
		if allDecls[orig] != nil && !visitedFuncs[orig] {
			visitedFuncs[orig] = true
			queue = append(queue, orig)
		}
	}

	for _, entry := range g.pkgVars {
		if categoryImmutable[entry.v] && entry.val != nil && sc.isCarrierFreeGeneratorPtrType(true, entry.v.Type()) {
			roots = append(roots, entry.val)
		}
	}
	for fn := range syncMapFuncs {
		enqueueFn(fn)
	}

	hasIfaceRecv := func(fn *types.Func) bool {
		sig := fn.Signature()
		if sig == nil || sig.Recv() == nil {
			return false
		}
		_, okIf := sig.Recv().Type().Underlying().(*types.Interface)
		return okIf
	}

	checkSubtree := func(root ast.Node) bool {
		okNode := true
		ast.Inspect(root, func(n ast.Node) bool {
			if !okNode || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.Ident:
				if inst, hasInst := info.Instances[x]; hasInst && inst.TypeArgs != nil {
					for ti := 0; ti < inst.TypeArgs.Len(); ti++ {
						targ := types.Unalias(inst.TypeArgs.At(ti))
						if _, isTP := targ.(*types.TypeParam); isTP {
							continue
						}
						if refconfine.TypeCarriesMutableRefWith(targ, isGenPtr) || types.IsInterface(targ) || !verifyFieldType(targ, map[types.Type]bool{}) {
							okNode = false
							return false
						}
					}
				}
				if fn, isFn := info.Uses[x].(*types.Func); isFn && fn != nil && fn.Pkg() == pkgTypes {
					if hasIfaceRecv(fn) {
						okNode = false
						return false
					}
					enqueueFn(fn)
				}
			case *ast.CompositeLit:
				lt := info.TypeOf(x)
				if lt != nil {
					lt = types.Unalias(lt)
					if ptr, isP := lt.(*types.Pointer); isP {
						lt = types.Unalias(ptr.Elem())
					}
					if named, isN := lt.(*types.Named); isN {
						if _, isSt := named.Underlying().(*types.Struct); isSt {
							if named.Obj() != nil && named.Obj().Pkg() != pkgTypes {
								p, nm := "", named.Obj().Name()
								if named.Obj().Pkg() != nil {
									p = named.Obj().Pkg().Path()
								}
								if !(p == "unicode" && (nm == "RangeTable" || nm == "Range16" || nm == "Range32")) {
									okNode = false
									return false
								}
							} else if !verifyConstructedStruct(named) {
								okNode = false
								return false
							}
						}
					} else if stUnder, isSt := lt.Underlying().(*types.Struct); isSt && stUnder.NumFields() > 0 {
						okNode = false
						return false
					}
				}
			case *ast.CallExpr:
				base := syntaxutil.UnwrapCallee(x.Fun)
				if info.Types[base].IsType() {
					return true
				}
				if b := syntaxutil.LookupBuiltin(info, base); b != nil {
					if b.Name() == "new" && len(x.Args) == 1 {
						named, isN := types.Unalias(info.TypeOf(x.Args[0])).(*types.Named)
						if !isN || !verifyConstructedStruct(named) {
							okNode = false
							return false
						}
					}
					return true
				}
				callee := resolveHarnessFuncExpr(info, x.Fun)
				if callee == nil {
					okNode = false
					return false
				}
				if callee.Pkg() == pkgTypes {
					if hasIfaceRecv(callee) {
						okNode = false
						return false
					}
					enqueueFn(callee)
				}
			case *ast.FuncLit:
				localDefs := map[*types.Var]bool{}
				ast.Inspect(x, func(cn ast.Node) bool {
					if id, isID := cn.(*ast.Ident); isID {
						if dv, isV := info.Defs[id].(*types.Var); isV && dv != nil {
							localDefs[dv] = true
						}
					}
					return true
				})
				ast.Inspect(x.Body, func(cn ast.Node) bool {
					if !okNode || cn == nil {
						return false
					}
					if id, isID := cn.(*ast.Ident); isID {
						if uv, isV := info.Uses[id].(*types.Var); isV && uv != nil && !uv.IsField() &&
							uv.Pkg() == pkgTypes && uv.Parent() != pkgTypes.Scope() && !localDefs[uv] {
							if mutatedOrAddrLocals[uv] || refconfine.TypeCarriesMutableRefWith(uv.Type(), isGenPtr) || !verifyFieldType(uv.Type(), map[types.Type]bool{}) {
								okNode = false
								return false
							}
						}
					}
					return true
				})
			}
			return true
		})
		return okNode
	}

	for _, r := range roots {
		if !checkSubtree(r) {
			return nil, false
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		fd := allDecls[cur]
		if fd == nil || fd.Body == nil || !checkSubtree(fd.Body) {
			return nil, false
		}
	}
	return checkedStructs, true
}

func isErrorOrBoolType(t types.Type) bool {
	if t == nil {
		return false
	}
	if types.Identical(t, types.Universe.Lookup("error").Type()) {
		return true
	}
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	return ok && b.Kind() == types.Bool
}

func isImmutableHarnessCachedType(
	audited bool,
	g *harnessGraph,
	t types.Type,
	mutatedStructs map[*types.Named]bool,
	needsGenImmut *bool,
	sawMutableRef *bool,
	seen map[types.Type]bool,
) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if seen[t] {
		return true
	}
	seen[t] = true

	if g.screen.isCarrierFreeGeneratorPtrType(audited, t) {
		if needsGenImmut != nil {
			*needsGenImmut = true
		}
		return true
	}
	if ptr, ok := t.(*types.Pointer); ok {
		if named, ok := types.Unalias(ptr.Elem()).(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() != nil {
			p, n := named.Obj().Pkg().Path(), named.Obj().Name()
			if ((p == "regexp" && n == "Regexp") || (p == "regexp/syntax" && n == "Regexp")) && !mutatedStructs[named.Origin()] {
				if sawMutableRef != nil {
					*sawMutableRef = true
				}
				return true
			}
		}
		return false
	}
	if named, ok := t.(*types.Named); ok {
		if _, isSt := named.Underlying().(*types.Struct); isSt {
			if named.Obj() == nil || named.Obj().Pkg() != g.pkgTypes || named.Obj().Exported() || mutatedStructs[named.Origin()] {
				return false
			}
		}
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Kind() != types.UnsafePointer && u.Kind() != types.Invalid
	case *types.Array:
		return isImmutableHarnessCachedType(audited, g, u.Elem(), mutatedStructs, needsGenImmut, sawMutableRef, seen)
	case *types.Slice:
		elemBasic, ok := types.Unalias(u.Elem()).Underlying().(*types.Basic)
		if !ok || elemBasic.Kind() == types.UnsafePointer || elemBasic.Kind() == types.Invalid {
			return false
		}
		if sawMutableRef != nil {
			*sawMutableRef = true
		}
		return true
	case *types.Struct:
		if _, isNamed := t.(*types.Named); !isNamed && u.NumFields() > 0 {
			return false
		}
		for i := 0; i < u.NumFields(); i++ {
			if !isImmutableHarnessCachedType(audited, g, u.Field(i).Type(), mutatedStructs, needsGenImmut, sawMutableRef, seen) {
				return false
			}
		}
		return true
	}
	return false
}

// verifyFreshUnaliasedLocalAtStore verifies that a mutable-ref-carrying value
// stored into a Category 3B sync.Map originates from unaliased local
// construction inside fd.Body before storeCall.Pos(), never aliases a parameter
// or package global, is not declared outside any loop enclosing storeCall, and
// (for local slices) is never mutated or aliased at or after storeCall.Pos().
func verifyFreshUnaliasedLocalAtStore(
	g *harnessGraph,
	fd *ast.FuncDecl,
	storeArg ast.Expr,
	storeCall *ast.CallExpr,
) ([]*types.Var, bool) {
	info, pkgTypes := g.info, g.pkgTypes
	if info == nil || pkgTypes == nil || fd == nil || fd.Body == nil || storeArg == nil || storeCall == nil {
		return nil, false
	}
	body := fd.Body
	storePos := storeCall.Pos()
	if g.idx == nil || g.pkg == nil {
		return nil, false
	}
	if fb := g.idx.FlowCache(g.pkg).FuncBody(fd); fb == nil || fb.HasGoto {
		return nil, false
	}

	defCounts := map[*types.Var]int{}
	declPosByVar := map[*types.Var]token.Pos{}
	var loops []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			loops = append(loops, x)
		case *ast.Ident:
			if v, ok := info.Defs[x].(*types.Var); ok && v != nil {
				defCounts[v]++
				declPosByVar[v] = x.Pos()
			}
		}
		return true
	})

	sigVars := map[*types.Var]bool{}
	recordFL := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, nm := range f.Names {
				if v, ok := info.Defs[nm].(*types.Var); ok && v != nil {
					sigVars[v] = true
				}
			}
		}
	}
	recordFL(fd.Recv)
	if fd.Type != nil {
		recordFL(fd.Type.Params)
		recordFL(fd.Type.Results)
	}

	isDeclaredInBodyBefore := func(v *types.Var, limitPos token.Pos, forbidOuterLoopOf ast.Node) (token.Pos, bool) {
		if v == nil || sigVars[v] || v.IsField() || v.Pkg() != pkgTypes || v.Parent() == pkgTypes.Scope() {
			return token.NoPos, false
		}
		declPos := declPosByVar[v]
		if defCounts[v] != 1 || declPos == token.NoPos || declPos >= limitPos {
			return token.NoPos, false
		}
		targetPos, targetEnd := forbidOuterLoopOf.Pos(), forbidOuterLoopOf.End()
		for _, lp := range loops {
			if lp.Pos() <= targetPos && targetEnd <= lp.End() && !(lp.Pos() <= declPos && declPos <= lp.End()) {
				return token.NoPos, false
			}
		}
		return declPos, true
	}

	isScalarType := func(t types.Type) bool {
		if t == nil {
			return false
		}
		b, ok := types.Unalias(t).Underlying().(*types.Basic)
		return ok && b.Kind() != types.UnsafePointer && b.Kind() != types.Invalid
	}

	verifyFreshSliceLocal := func(v *types.Var, freezeNode ast.Node, allowPostReturn bool) bool {
		freezePos := freezeNode.Pos()
		if _, ok := isDeclaredInBodyBefore(v, freezePos, freezeNode); !ok {
			return false
		}
		sl, ok := types.Unalias(v.Type()).Underlying().(*types.Slice)
		if !ok || !isScalarType(sl.Elem()) {
			return false
		}
		approvedUses := map[*ast.Ident]bool{}
		okSlice := true

		isFreshSliceInitRHS := func(rhs ast.Expr) bool {
			rhs = ast.Unparen(rhs)
			if id, isID := rhs.(*ast.Ident); isID {
				_, isNil := info.Uses[id].(*types.Nil)
				return isNil
			}
			switch r := rhs.(type) {
			case *ast.CompositeLit:
				if !types.Identical(types.Unalias(info.TypeOf(r)), types.Unalias(v.Type())) {
					return false
				}
				for _, elt := range r.Elts {
					val := elt
					if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
						val = kv.Value
					}
					if !isScalarType(info.TypeOf(val)) {
						return false
					}
				}
				return true
			case *ast.CallExpr:
				if b := syntaxutil.LookupBuiltin(info, syntaxutil.UnwrapCallee(r.Fun)); b != nil {
					if b.Name() == "make" && len(r.Args) >= 2 && len(r.Args) <= 3 {
						return true
					}
					if b.Name() == "append" && !r.Ellipsis.IsValid() && len(r.Args) >= 2 {
						if aid, isAID := ast.Unparen(r.Args[0]).(*ast.Ident); isAID && info.Uses[aid] == v {
							approvedUses[aid] = true
							return true
						}
					}
				}
			}
			return false
		}

		ast.Inspect(body, func(n ast.Node) bool {
			if !okSlice || n == nil {
				return false
			}
			switch s := n.(type) {
			case *ast.FuncLit, *ast.GoStmt:
				ast.Inspect(s, func(cn ast.Node) bool {
					if id, isID := cn.(*ast.Ident); isID && (info.Uses[id] == v || info.Defs[id] == v) {
						okSlice = false
						return false
					}
					return true
				})
				return false
			case *ast.ValueSpec:
				for i, nm := range s.Names {
					if info.Defs[nm] == v {
						if s.End() > freezePos || (i < len(s.Values) && !isFreshSliceInitRHS(s.Values[i])) {
							okSlice = false
							return false
						}
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range s.Lhs {
					if lid, isID := ast.Unparen(lhs).(*ast.Ident); isID && (info.Defs[lid] == v || info.Uses[lid] == v) {
						if s.End() > freezePos || len(s.Lhs) != len(s.Rhs) || !isFreshSliceInitRHS(s.Rhs[i]) {
							okSlice = false
							return false
						}
						if info.Uses[lid] == v {
							approvedUses[lid] = true
						}
					} else if idx, isIX := ast.Unparen(lhs).(*ast.IndexExpr); isIX {
						if bid, isBID := ast.Unparen(idx.X).(*ast.Ident); isBID && info.Uses[bid] == v {
							if s.End() > freezePos || !isScalarType(info.TypeOf(idx)) {
								okSlice = false
								return false
							}
							approvedUses[bid] = true
						}
					}
				}
			case *ast.IncDecStmt:
				if idx, isIX := ast.Unparen(s.X).(*ast.IndexExpr); isIX {
					if bid, isBID := ast.Unparen(idx.X).(*ast.Ident); isBID && info.Uses[bid] == v {
						if s.End() > freezePos {
							okSlice = false
							return false
						}
						approvedUses[bid] = true
					}
				}
			case *ast.CallExpr:
				if s == storeCall && freezeNode == storeCall && len(s.Args) == 2 {
					if aid, isID := ast.Unparen(s.Args[1]).(*ast.Ident); isID && info.Uses[aid] == v {
						approvedUses[aid] = true
					}
				}
				if b := syntaxutil.LookupBuiltin(info, syntaxutil.UnwrapCallee(s.Fun)); b != nil && (b.Name() == "len" || b.Name() == "cap") && len(s.Args) == 1 {
					if aid, isAID := ast.Unparen(s.Args[0]).(*ast.Ident); isAID && info.Uses[aid] == v {
						approvedUses[aid] = true
					}
				}
			case *ast.ReturnStmt:
				if allowPostReturn && s.Pos() > freezePos {
					for _, res := range s.Results {
						if rid, isID := ast.Unparen(res).(*ast.Ident); isID && info.Uses[rid] == v {
							approvedUses[rid] = true
						}
					}
				}
			case *ast.Ident:
				if info.Uses[s] == v && !approvedUses[s] {
					okSlice = false
					return false
				}
			}
			return true
		})
		return okSlice
	}

	verifyFreshRegexpLocal := func(v *types.Var, limitNode ast.Node) bool {
		if _, ok := isDeclaredInBodyBefore(v, limitNode.Pos(), limitNode); !ok || !isRegexpOrSyntaxRegexpPtr(v.Type()) {
			return false
		}
		initCalls, reassignedOrAddr := 0, false
		isStdRegexpConstructor := func(rhs ast.Expr) bool {
			call, ok := ast.Unparen(rhs).(*ast.CallExpr)
			if !ok {
				return false
			}
			callee := resolveHarnessFuncExpr(info, call.Fun)
			if callee == nil || callee.Pkg() == nil || callee.Signature().Recv() != nil {
				return false
			}
			p := callee.Pkg().Path()
			return p == "regexp" || p == "regexp/syntax"
		}
		ast.Inspect(body, func(n ast.Node) bool {
			if reassignedOrAddr || n == nil {
				return false
			}
			switch s := n.(type) {
			case *ast.FuncLit, *ast.GoStmt:
				ast.Inspect(s, func(cn ast.Node) bool {
					if id, isID := cn.(*ast.Ident); isID && (info.Uses[id] == v || info.Defs[id] == v) {
						reassignedOrAddr = true
						return false
					}
					return true
				})
				return false
			case *ast.ValueSpec:
				for i, nm := range s.Names {
					if info.Defs[nm] == v {
						if (len(s.Values) == 1 && isStdRegexpConstructor(s.Values[0])) ||
							(i < len(s.Values) && len(s.Names) == len(s.Values) && isStdRegexpConstructor(s.Values[i])) {
							initCalls++
						} else {
							reassignedOrAddr = true
							return false
						}
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range s.Lhs {
					lid, isID := ast.Unparen(lhs).(*ast.Ident)
					if !isID {
						continue
					}
					if info.Defs[lid] == v {
						if (len(s.Rhs) == 1 && isStdRegexpConstructor(s.Rhs[0])) ||
							(i < len(s.Rhs) && len(s.Lhs) == len(s.Rhs) && isStdRegexpConstructor(s.Rhs[i])) {
							initCalls++
						} else {
							reassignedOrAddr = true
							return false
						}
					} else if info.Uses[lid] == v {
						reassignedOrAddr = true
						return false
					}
				}
			case *ast.UnaryExpr:
				if s.Op == token.AND {
					if id, isID := ast.Unparen(s.X).(*ast.Ident); isID && info.Uses[id] == v {
						reassignedOrAddr = true
						return false
					}
				}
			}
			return true
		})
		return !reassignedOrAddr && initCalls == 1
	}

	var regexpVars []*types.Var
	var verifyCompositeExpr func(expr ast.Expr, freezeNode ast.Node, isTopStoreArg bool) bool
	verifyCompositeExpr = func(expr ast.Expr, freezeNode ast.Node, isTopStoreArg bool) bool {
		if expr == nil {
			return false
		}
		expr = ast.Unparen(expr)
		et := info.TypeOf(expr)
		if et == nil {
			return false
		}
		if isScalarType(et) || g.screen.isCarrierFreeGeneratorPtrType(true, et) {
			return true
		}
		if isRegexpOrSyntaxRegexpPtr(et) {
			id, ok := expr.(*ast.Ident)
			if !ok {
				return false
			}
			v, ok := info.Uses[id].(*types.Var)
			if !ok || !verifyFreshRegexpLocal(v, freezeNode) {
				return false
			}
			regexpVars = append(regexpVars, v)
			return true
		}
		if _, isSl := types.Unalias(et).Underlying().(*types.Slice); isSl {
			id, ok := expr.(*ast.Ident)
			if !ok {
				return false
			}
			v, ok := info.Uses[id].(*types.Var)
			return ok && verifyFreshSliceLocal(v, freezeNode, isTopStoreArg)
		}
		if cl, isCL := expr.(*ast.CompositeLit); isCL {
			for _, elt := range cl.Elts {
				val := elt
				if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
					val = kv.Value
				}
				if !verifyCompositeExpr(val, cl, false) {
					return false
				}
			}
			return true
		}

		id, isID := expr.(*ast.Ident)
		if !isID {
			return false
		}
		v, isV := info.Uses[id].(*types.Var)
		if !isV || v == nil {
			return false
		}
		if _, ok := isDeclaredInBodyBefore(v, freezeNode.Pos(), freezeNode); !ok {
			return false
		}
		var initCL *ast.CompositeLit
		assigns, badUse := 0, false
		approvedStructUses := map[*ast.Ident]bool{}
		if isTopStoreArg && len(storeCall.Args) == 2 {
			if aid, ok := ast.Unparen(storeCall.Args[1]).(*ast.Ident); ok && info.Uses[aid] == v {
				approvedStructUses[aid] = true
			}
		}
		ast.Inspect(body, func(n ast.Node) bool {
			if badUse || n == nil {
				return false
			}
			switch s := n.(type) {
			case *ast.FuncLit, *ast.GoStmt:
				ast.Inspect(s, func(cn ast.Node) bool {
					if cid, ok := cn.(*ast.Ident); ok && (info.Uses[cid] == v || info.Defs[cid] == v) {
						badUse = true
						return false
					}
					return true
				})
				return false
			case *ast.ValueSpec:
				for i, nm := range s.Names {
					if info.Defs[nm] == v {
						assigns++
						if i < len(s.Values) && len(s.Names) == len(s.Values) && s.End() <= freezeNode.Pos() {
							initCL, _ = ast.Unparen(s.Values[i]).(*ast.CompositeLit)
						}
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range s.Lhs {
					if lid, ok := ast.Unparen(lhs).(*ast.Ident); ok {
						if info.Defs[lid] == v {
							assigns++
							if i < len(s.Rhs) && len(s.Lhs) == len(s.Rhs) && s.End() <= freezeNode.Pos() {
								initCL, _ = ast.Unparen(s.Rhs[i]).(*ast.CompositeLit)
							}
						} else if info.Uses[lid] == v {
							badUse = true
							return false
						}
					}
				}
			case *ast.ReturnStmt:
				if isTopStoreArg && s.Pos() > storePos {
					for _, res := range s.Results {
						if rid, ok := ast.Unparen(res).(*ast.Ident); ok && info.Uses[rid] == v {
							approvedStructUses[rid] = true
						}
					}
				}
			case *ast.Ident:
				if info.Uses[s] == v && !approvedStructUses[s] {
					badUse = true
					return false
				}
			}
			return true
		})
		if badUse || assigns != 1 || initCL == nil {
			return false
		}
		return verifyCompositeExpr(initCL, initCL, false)
	}

	if !verifyCompositeExpr(storeArg, storeCall, true) {
		return nil, false
	}
	return regexpVars, true
}
