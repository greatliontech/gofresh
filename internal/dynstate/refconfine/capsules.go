package refconfine

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

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
			if st := syntaxutil.DerefNamedStruct(info.TypeOf(x)); st != nil && (match(st) || match(st.Origin())) {
				return true
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
	ok := true
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !ok || n == nil {
				return false
			}
			switch s := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range s.Lhs {
					if exprHitsStructPred(info, lhs, match, true) {
						ok = false
						return false
					}
				}
			case *ast.IncDecStmt:
				if exprHitsStructPred(info, s.X, match, true) {
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
			}
			return true
		})
	}
	return ok
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
