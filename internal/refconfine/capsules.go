package refconfine

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func structHasNoExportedFieldsDeep(st *types.Struct) bool {
	if st == nil {
		return false
	}
	seen := map[*types.Struct]bool{}
	var walk func(*types.Struct) bool
	walk = func(cur *types.Struct) bool {
		if cur == nil {
			return false
		}
		if seen[cur] {
			return true
		}
		seen[cur] = true
		for i := 0; i < cur.NumFields(); i++ {
			f := cur.Field(i)
			if f.Exported() {
				return false
			}
			if f.Embedded() {
				emb := types.Unalias(f.Type())
				if ptr, ok := emb.(*types.Pointer); ok {
					emb = types.Unalias(ptr.Elem())
				}
				if embSt, ok := emb.Underlying().(*types.Struct); ok && !walk(embSt) {
					return false
				}
			}
		}
		return true
	}
	return walk(st)
}

func exprHitsStructPred(info *types.Info, expr ast.Expr, match func(*types.Named) bool, includeStarRoot bool) bool {
	if info == nil || match == nil {
		return false
	}
	cur := expr
	for cur != nil {
		switch x := ast.Unparen(cur).(type) {
		case *ast.SelectorExpr:
			selInfo := info.Selections[x]
			if selInfo == nil || selInfo.Kind() != types.FieldVal {
				return false
			}
			hit := false
			syntaxutil.ForEachSelectionHopStruct(selInfo, func(st *types.Named) {
				if st != nil && (match(st) || match(st.Origin())) {
					hit = true
				}
			})
			if hit {
				return true
			}
			cur = x.X
		case *ast.StarExpr:
			if includeStarRoot {
				if st := syntaxutil.DerefNamedStruct(info.TypeOf(x.X)); st != nil && (match(st) || match(st.Origin())) {
					return true
				}
			}
			cur = x.X
		case *ast.IndexExpr:
			if xType := info.TypeOf(x); xType != nil {
				if st, ok := types.Unalias(xType).(*types.Named); ok && st.Obj() != nil && (match(st) || match(st.Origin())) {
					return true
				}
			}
			cur = x.X
		case *ast.SliceExpr:
			cur = x.X
		default:
			return false
		}
	}
	return false
}

func verifyCapsuleStructsWriteFree(p *packages.Package, capsules map[*types.Named]bool) bool {
	info := p.TypesInfo
	match := func(st *types.Named) bool {
		return st != nil && (capsules[st] || capsules[st.Origin()])
	}
	var funcDecls map[*types.Func]*ast.FuncDecl
	ensureFuncDecls := func() map[*types.Func]*ast.FuncDecl {
		if funcDecls != nil {
			return funcDecls
		}
		funcDecls = map[*types.Func]*ast.FuncDecl{}
		for _, f := range p.Syntax {
			for _, d := range f.Decls {
				if fd, okFD := d.(*ast.FuncDecl); okFD && fd.Name != nil {
					if fn, okFn := info.Defs[fd.Name].(*types.Func); okFn && fn != nil {
						funcDecls[fn.Origin()] = fd
					}
				}
			}
		}
		return funcDecls
	}

	ok := true
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !ok || n == nil {
				return false
			}
			switch s := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range s.Lhs {
					if exprHitsStructPred(info, lhs, match, true) && !isIsolatedByValueStructLocalWrite(p, file, lhs, ensureFuncDecls) {
						ok = false
						return false
					}
				}
			case *ast.IncDecStmt:
				if exprHitsStructPred(info, s.X, match, true) && !isIsolatedByValueStructLocalWrite(p, file, s.X, ensureFuncDecls) {
					ok = false
					return false
				}
			case *ast.RangeStmt:
				if s.Tok == token.ASSIGN {
					if (s.Key != nil && exprHitsStructPred(info, s.Key, match, true)) ||
						(s.Value != nil && exprHitsStructPred(info, s.Value, match, true)) {
						ok = false
						return false
					}
				}
			case *ast.UnaryExpr:
				if s.Op == token.AND {
					if _, isCL := ast.Unparen(s.X).(*ast.CompositeLit); !isCL && exprHitsStructPred(info, s.X, match, true) {
						ok = false
						return false
					}
				}
			case *ast.SliceExpr:
				if t := info.TypeOf(s.X); t != nil {
					if _, isArr := types.Unalias(t).Underlying().(*types.Array); isArr && exprHitsStructPred(info, s.X, match, true) {
						ok = false
						return false
					}
				}
			case *ast.SelectorExpr:
				if sel := info.Selections[s]; sel != nil && sel.Kind() == types.MethodVal && !sel.Indirect() && SelectionHasPointerReceiver(sel) {
					if exprHitsStructPred(info, s.X, match, false) {
						ok = false
						return false
					}
				}
			}
			return true
		})
	}
	return ok
}

// isIsolatedByValueStructLocalWrite reports whether lhs is a direct,
// non-indirect field chain `lv.f1.f2` on a function-local by-value struct
// variable `lv` that is never &-addressed, never array-sliced, never captured
// by an inner closure, and whose auto-addressed pointer-receiver method calls
// cannot mutate, retain, or return an address into `lv`. Mutating such a stack
// value copy (e.g. `tt := *t; tt.tilde = true` in go/types) never mutates any
// *S pointer cell.
func isIsolatedByValueStructLocalWrite(
	p *packages.Package,
	file *ast.File,
	lhs ast.Expr,
	getFuncDecls func() map[*types.Func]*ast.FuncDecl,
) bool {
	if p == nil || p.Types == nil || p.TypesInfo == nil || file == nil || lhs == nil {
		return false
	}
	info := p.TypesInfo
	cur := ast.Unparen(lhs)
	depth := 0
	for {
		sel, isSel := cur.(*ast.SelectorExpr)
		if !isSel {
			break
		}
		selInfo := info.Selections[sel]
		if selInfo == nil || selInfo.Kind() != types.FieldVal || selInfo.Indirect() {
			return false
		}
		depth++
		cur = ast.Unparen(sel.X)
	}
	if depth == 0 {
		return false
	}
	rootID, ok := cur.(*ast.Ident)
	if !ok {
		return false
	}
	lv, ok := info.Uses[rootID].(*types.Var)
	if !ok || lv == nil || lv.Parent() == nil || lv.Parent() == p.Types.Scope() {
		return false
	}
	if _, isSt := types.Unalias(lv.Type()).Underlying().(*types.Struct); !isSt {
		return false
	}

	parentOf := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if _, isParen := n.(*ast.ParenExpr); !isParen {
			for i := len(stack) - 1; i >= 0; i-- {
				if _, pParen := stack[i].(*ast.ParenExpr); !pParen {
					parentOf[n] = stack[i]
					break
				}
			}
		}
		stack = append(stack, n)
		return true
	})

	// Find innermost enclosing FuncLit or FuncDecl owning rootID.
	var encl ast.Node
	for anc := parentOf[rootID]; anc != nil; anc = parentOf[anc] {
		switch fnNode := anc.(type) {
		case *ast.FuncLit:
			encl = fnNode
		case *ast.FuncDecl:
			encl = fnNode
		}
		if encl != nil {
			break
		}
	}
	if encl == nil {
		return false
	}
	// Reject named result variables.
	var fnType *ast.FuncType
	switch e := encl.(type) {
	case *ast.FuncLit:
		fnType = e.Type
	case *ast.FuncDecl:
		fnType = e.Type
	}
	if fnType != nil && fnType.Results != nil {
		for _, rf := range fnType.Results.List {
			for _, nm := range rf.Names {
				if info.Defs[nm] == lv {
					return false
				}
			}
		}
	}

	mentionsLV := func(expr ast.Expr) bool {
		if expr == nil {
			return false
		}
		hit := false
		ast.Inspect(expr, func(cn ast.Node) bool {
			if hit || cn == nil {
				return false
			}
			if id, ok := cn.(*ast.Ident); ok && info.Uses[id] == lv {
				hit = true
				return false
			}
			return true
		})
		return hit
	}

	cleanLocal := true
	var scan func(ast.Node)
	scan = func(n ast.Node) {
		if !cleanLocal || n == nil {
			return
		}
		switch x := n.(type) {
		case *ast.FuncLit:
			if n != encl {
				ast.Inspect(x.Body, func(cn ast.Node) bool {
					if id, ok := cn.(*ast.Ident); ok && (info.Uses[id] == lv || info.Defs[id] == lv) {
						cleanLocal = false
						return false
					}
					return true
				})
				return
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND && mentionsLV(x.X) {
				cleanLocal = false
				return
			}
		case *ast.SliceExpr:
			if t := info.TypeOf(x.X); t != nil {
				if _, isArr := types.Unalias(t).Underlying().(*types.Array); isArr && mentionsLV(x.X) {
					cleanLocal = false
					return
				}
			}
		case *ast.SelectorExpr:
			if si := info.Selections[x]; si != nil && si.Kind() == types.MethodVal && mentionsLV(x.X) {
				mFn, _ := si.Obj().(*types.Func)
				if mFn == nil || mFn.Signature() == nil || mFn.Signature().Recv() == nil {
					cleanLocal = false
					return
				}
				if SelectionHasPointerReceiver(si) {
					call, isCall := parentOf[x].(*ast.CallExpr)
					if !isCall || ast.Unparen(call.Fun) != x || !isMethodRecvStrictlyReadOnly(p, getFuncDecls(), mFn) {
						cleanLocal = false
						return
					}
				}
			}
		}
		ast.Inspect(n, func(ch ast.Node) bool {
			if ch == n || ch == nil {
				return true
			}
			scan(ch)
			return false
		})
	}
	scan(encl)
	return cleanLocal
}

func isMethodRecvStrictlyReadOnly(p *packages.Package, funcDecls map[*types.Func]*ast.FuncDecl, mFn *types.Func) bool {
	if p == nil || p.TypesInfo == nil || mFn == nil || mFn.Pkg() != p.Types {
		return false
	}
	fd := funcDecls[mFn.Origin()]
	if fd == nil || fd.Body == nil || fd.Recv == nil || len(fd.Recv.List) != 1 {
		return false
	}
	if len(fd.Recv.List[0].Names) == 0 {
		return true
	}
	info := p.TypesInfo
	rv, ok := info.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
	if !ok || rv == nil {
		return false
	}
	parentOf := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if _, isParen := n.(*ast.ParenExpr); !isParen {
			for i := len(stack) - 1; i >= 0; i-- {
				if _, pParen := stack[i].(*ast.ParenExpr); !pParen {
					parentOf[n] = stack[i]
					break
				}
			}
		}
		stack = append(stack, n)
		return true
	})
	clean := true
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if !clean || n == nil {
			return false
		}
		id, ok := n.(*ast.Ident)
		if !ok || (info.Uses[id] != rv && info.Defs[id] != rv) {
			return true
		}
		switch par := parentOf[id].(type) {
		case *ast.BinaryExpr:
			if (par.Op == token.EQL || par.Op == token.NEQ) &&
				((ast.Unparen(par.X) == id && syntaxutil.IsNilIdent(info, par.Y)) ||
					(ast.Unparen(par.Y) == id && syntaxutil.IsNilIdent(info, par.X))) {
				return true
			}
		case *ast.SelectorExpr:
			if ast.Unparen(par.X) == id {
				if si := info.Selections[par]; si != nil && si.Kind() == types.FieldVal {
					// Walk up any projection chain to ensure the field expression is
					// never assigned, incremented, &-addressed, array-sliced, used as
					// an auto-addressed pointer-receiver method, or mutated via builtins.
					cur := ast.Node(par)
					for cur != nil {
						next := parentOf[cur]
						switch nx := next.(type) {
						case *ast.SelectorExpr:
							if ast.Unparen(nx.X) == cur {
								nsi := info.Selections[nx]
								if nsi == nil {
									clean = false
									return false
								}
								if nsi.Kind() == types.MethodVal && SelectionHasPointerReceiver(nsi) && !nsi.Indirect() {
									clean = false
									return false
								}
								if nsi.Kind() == types.FieldVal {
									cur = nx
									continue
								}
							}
							return true
						case *ast.IndexExpr:
							if ast.Unparen(nx.X) == cur {
								cur = nx
								continue
							}
							return true
						case *ast.StarExpr:
							if ast.Unparen(nx.X) == cur {
								cur = nx
								continue
							}
							return true
						case *ast.AssignStmt:
							for _, l := range nx.Lhs {
								if ast.Unparen(l) == cur {
									clean = false
									return false
								}
							}
							return true
						case *ast.IncDecStmt:
							if ast.Unparen(nx.X) == cur {
								clean = false
								return false
							}
							return true
						case *ast.RangeStmt:
							if nx.Tok == token.ASSIGN && (ast.Unparen(nx.Key) == cur || ast.Unparen(nx.Value) == cur) {
								clean = false
								return false
							}
							return true
						case *ast.SendStmt:
							if ast.Unparen(nx.Chan) == cur {
								clean = false
								return false
							}
							return true
						case *ast.UnaryExpr:
							if nx.Op == token.AND && ast.Unparen(nx.X) == cur {
								clean = false
								return false
							}
							return true
						case *ast.SliceExpr:
							if ast.Unparen(nx.X) == cur {
								if ce, isE := cur.(ast.Expr); isE {
									if t := info.TypeOf(ce); t != nil {
										if _, isArr := types.Unalias(t).Underlying().(*types.Array); isArr {
											clean = false
											return false
										}
									}
								}
							}
							return true
						case *ast.CallExpr:
							if len(nx.Args) > 0 && ast.Unparen(nx.Args[0]) == cur {
								if b := syntaxutil.LookupBuiltin(info, nx.Fun); b != nil {
									switch b.Name() {
									case "copy", "clear", "delete", "append":
										clean = false
										return false
									}
								}
							}
							return true
						default:
							return true
						}
					}
					return true
				}
			}
		}
		clean = false
		return false
	})
	return clean
}

// VerifyProtectedStructOriginConfinement verifies that every struct in protected
// is unexported, never mentioned in exported package signatures or generic
// instantiations, never mutated or address-taken outside allowMutationInFunc,
// never compared by pointer identity against non-nil, never erased into an
// interface or non-identical type, and has all interior reference/container
// fields strictly read-confined across p.Syntax.
func VerifyProtectedStructOriginConfinement(
	p *packages.Package,
	idx *PkgIndex,
	allowMutationInFunc *ast.FuncDecl,
	protected map[*types.Named]bool,
	allowCallArg func(call *ast.CallExpr, argIdx int, arg ast.Expr) bool,
) (bool, string) {
	if p == nil || p.Types == nil || p.TypesInfo == nil {
		return false, "nil package"
	}
	if idx == nil {
		idx = BuildPkgIndex(p)
	}
	isProtected := func(st *types.Named) bool {
		return st != nil && (protected[st] || protected[st.Origin()])
	}
	isPtrToProtected := func(t types.Type) bool {
		if t == nil {
			return false
		}
		ptr, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			return false
		}
		st, ok := types.Unalias(ptr.Elem()).(*types.Named)
		return ok && isProtected(st)
	}
	mentionsProtectedExported := func(root types.Type) bool {
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
			if n, ok := t.(*types.Named); ok && isProtected(n) {
				hit = true
				return
			}
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
					if u.Field(i).Exported() {
						walk(u.Field(i).Type())
					}
				}
			case *types.Signature:
				for i := 0; i < u.Params().Len(); i++ {
					walk(u.Params().At(i).Type())
				}
				for i := 0; i < u.Results().Len(); i++ {
					walk(u.Results().At(i).Type())
				}
			}
		}
		walk(root)
		return hit
	}

	for _, name := range p.Types.Scope().Names() {
		obj := p.Types.Scope().Lookup(name)
		if obj == nil || !obj.Exported() {
			continue
		}
		if mentionsProtectedExported(obj.Type()) {
			return false, "exported mentions protected: " + name
		}
		if tn, ok := obj.(*types.TypeName); ok {
			if named, ok := types.Unalias(tn.Type()).(*types.Named); ok {
				pset := types.NewMethodSet(types.NewPointer(named))
				for i := 0; i < pset.Len(); i++ {
					if m := pset.At(i).Obj(); m != nil && m.Exported() && mentionsProtectedExported(m.Type()) {
						return false, "exported method mentions protected: " + name + "." + m.Name()
					}
				}
			}
		}
	}
	for _, inst := range p.TypesInfo.Instances {
		if inst.TypeArgs != nil {
			for i := 0; i < inst.TypeArgs.Len(); i++ {
				if typeMentionsSeedStruct(inst.TypeArgs.At(i), isProtected) {
					return false, "generic instance mentions protected"
				}
			}
		}
	}
	if !VerifyReadOnlyRefConfinement(p, Config{
		Index:                            idx,
		IsImmutablePtr:                   isPtrToProtected,
		SeedStructOrigin:                 isProtected,
		AllowCompositeLitIntoSeedStruct:  true,
		AllowCallArg:                     allowCallArg,
		ForbidNonNilSeedStructPtrCompare: true,
		AllowSeedStructMutationInFunc:    allowMutationInFunc,
	}) {
		return false, "confinement violated"
	}
	return true, ""
}

func callMutatesSeedStructContainer(info *types.Info, call *ast.CallExpr, isSeedStruct func(*types.Named) bool) bool {
	b := syntaxutil.LookupBuiltin(info, call.Fun)
	if b == nil {
		return false
	}
	switch b.Name() {
	case "delete", "clear", "copy", "append":
		if len(call.Args) > 0 && exprHitsStructPred(info, call.Args[0], isSeedStruct, true) {
			return true
		}
	}
	return false
}

func assignErasesSeedStruct(src, dst types.Type, isSeedStruct func(*types.Named) bool) bool {
	if src == nil || dst == nil || isSeedStruct == nil {
		return false
	}
	type pair struct {
		s, d types.Type
	}
	seen := map[pair]bool{}
	var walk func(s, d types.Type) bool
	walk = func(s, d types.Type) bool {
		if s == nil || d == nil || !typeMentionsSeedStruct(s, isSeedStruct) {
			return false
		}
		s = types.Unalias(s)
		d = types.Unalias(d)
		if types.Identical(s, d) {
			return false
		}
		k := pair{s: s, d: d}
		if seen[k] {
			return false
		}
		seen[k] = true
		if _, isIf := d.Underlying().(*types.Interface); isIf {
			return true
		}
		switch su := s.Underlying().(type) {
		case *types.Pointer:
			if du, ok := d.Underlying().(*types.Pointer); ok {
				return walk(su.Elem(), du.Elem())
			}
		case *types.Slice:
			if du, ok := d.Underlying().(*types.Slice); ok {
				return walk(su.Elem(), du.Elem())
			}
		case *types.Array:
			if du, ok := d.Underlying().(*types.Array); ok && su.Len() == du.Len() {
				return walk(su.Elem(), du.Elem())
			}
		case *types.Chan:
			if du, ok := d.Underlying().(*types.Chan); ok {
				return walk(su.Elem(), du.Elem())
			}
		case *types.Map:
			if du, ok := d.Underlying().(*types.Map); ok {
				return walk(su.Key(), du.Key()) || walk(su.Elem(), du.Elem())
			}
		case *types.Struct:
			if du, ok := d.Underlying().(*types.Struct); ok && su.NumFields() == du.NumFields() {
				for i := 0; i < su.NumFields(); i++ {
					if walk(su.Field(i).Type(), du.Field(i).Type()) {
						return true
					}
				}
				return false
			}
		case *types.Signature:
			if du, ok := d.Underlying().(*types.Signature); ok {
				sp, dp := su.Params(), du.Params()
				sr, dr := su.Results(), du.Results()
				if (sp == nil) != (dp == nil) || (sr == nil) != (dr == nil) {
					return true
				}
				if sp != nil && sp.Len() != dp.Len() {
					return true
				}
				if sr != nil && sr.Len() != dr.Len() {
					return true
				}
				for i := 0; sp != nil && i < sp.Len(); i++ {
					if walk(sp.At(i).Type(), dp.At(i).Type()) {
						return true
					}
				}
				for i := 0; sr != nil && i < sr.Len(); i++ {
					if walk(sr.At(i).Type(), dr.At(i).Type()) {
						return true
					}
				}
				return false
			}
		}
		return true
	}
	return walk(src, dst)
}

func typeMentionsSeedStruct(root types.Type, isSeedStruct func(*types.Named) bool) bool {
	if root == nil || isSeedStruct == nil {
		return false
	}
	seen := map[types.Type]bool{}
	hit := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || hit {
			return
		}
		if alias, isAlias := t.(*types.Alias); isAlias {
			if targs := alias.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					walk(targs.At(i))
				}
			}
			t = types.Unalias(t)
		}
		if seen[t] {
			return
		}
		seen[t] = true
		if named, isNamed := t.(*types.Named); isNamed {
			if isSeedStruct(named) {
				hit = true
				return
			}
			if targs := named.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					walk(targs.At(i))
				}
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			walk(u.Elem())
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Chan:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		case *types.Tuple:
			for i := 0; i < u.Len(); i++ {
				walk(u.At(i).Type())
			}
		case *types.Signature:
			walk(u.Params())
			walk(u.Results())
		case *types.Interface:
			for i := 0; i < u.NumEmbeddeds(); i++ {
				walk(u.EmbeddedType(i))
			}
			for i := 0; i < u.NumExplicitMethods(); i++ {
				walk(u.ExplicitMethod(i).Type())
			}
		}
	}
	walk(root)
	return hit
}
