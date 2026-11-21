package refconfine

import (
	"go/ast"
	"go/types"
)

// IsCompileTimeUnsafeBuiltinName reports whether name is one of package
// unsafe's three Go-specification compile-time layout intrinsics (Alignof,
// Offsetof, Sizeof), whose calls evaluate strictly to compile-time uintptr
// constants without executing runtime code or dereferencing memory.
func IsCompileTimeUnsafeBuiltinName(name string) bool {
	switch name {
	case "Alignof", "Offsetof", "Sizeof":
		return true
	default:
		return false
	}
}

type layoutTypePair struct {
	a, b types.Type
}

// IsomorphicValueLayout reports whether types a and b have identical runtime
// byte size, alignment, GC pointer/header bitmaps, and field/element layout
// under sizes (unwrapping single-field wrapper structs at offset 0 whose size
// and alignment match their sole field). Types exposing UnsafePointer, open
// TypeParams, untyped basic kinds, or Invalid never satisfy IsomorphicValueLayout,
// and pointer/slice/map/chan/func/interface elements must be types.Identical.
func IsomorphicValueLayout(sizes types.Sizes, a, b types.Type) bool {
	if sizes == nil || a == nil || b == nil ||
		typeMentionsOpenTypeParam(a) || typeMentionsOpenTypeParam(b) ||
		typeExposesUnsafeOrInvalid(a) || typeExposesUnsafeOrInvalid(b) {
		return false
	}
	return isomorphicValueLayoutSeen(sizes, a, b, map[layoutTypePair]bool{})
}

type typeIndirKey struct {
	t     types.Type
	indir bool
}

// typeExposesUnsafeOrInvalid reports whether root's value representation or
// reachable reference/container/signature/interface surface (stopping only at
// unexported fields of named structs behind an indirection so private standard-
// library sync primitives inside e.g. *types.TypeParam do not taint unrelated
// value layouts) reaches types.UnsafePointer, types.Invalid, an untyped basic
// kind, a *types.Tuple, or an open *types.TypeParam.
func typeExposesUnsafeOrInvalid(root types.Type) bool {
	if root == nil {
		return true
	}
	seen := map[typeIndirKey]bool{}
	var walk func(types.Type, bool) bool
	walk = func(t types.Type, indir bool) bool {
		if t == nil {
			return true
		}
		t = types.Unalias(t)
		if _, isTP := t.(*types.TypeParam); isTP {
			return true
		}
		if _, isTup := t.(*types.Tuple); isTup {
			return true
		}
		key := typeIndirKey{t: t, indir: indir}
		if seen[key] {
			return false
		}
		seen[key] = true
		_, isNamed := t.(*types.Named)
		switch u := t.Underlying().(type) {
		case *types.Basic:
			return isInvalidOrUntypedBasic(u)
		case *types.Array:
			return u.Len() < 0 || walk(u.Elem(), indir)
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				f := u.Field(i)
				if indir && isNamed && !f.Exported() {
					continue
				}
				if walk(f.Type(), indir) {
					return true
				}
			}
			return false
		case *types.Pointer:
			return walk(u.Elem(), true)
		case *types.Slice:
			return walk(u.Elem(), true)
		case *types.Chan:
			return walk(u.Elem(), true)
		case *types.Map:
			return walk(u.Key(), true) || walk(u.Elem(), true)
		case *types.Signature:
			for _, tup := range []*types.Tuple{u.Params(), u.Results()} {
				for i := 0; tup != nil && i < tup.Len(); i++ {
					if walk(tup.At(i).Type(), true) {
						return true
					}
				}
			}
			return false
		case *types.Interface:
			for i := 0; i < u.NumMethods(); i++ {
				if walk(u.Method(i).Type(), true) {
					return true
				}
			}
			return false
		default:
			return true
		}
	}
	return walk(root, false)
}

func typeMentionsOpenTypeParam(root types.Type) bool {
	if root == nil {
		return false
	}
	seen := map[types.Type]bool{}
	var walk func(types.Type) bool
	walk = func(t types.Type) bool {
		if t == nil {
			return false
		}
		if alias, isAlias := t.(*types.Alias); isAlias {
			if targs := alias.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					if walk(targs.At(i)) {
						return true
					}
				}
			}
			t = types.Unalias(t)
		}
		if _, isTP := t.(*types.TypeParam); isTP {
			return true
		}
		if seen[t] {
			return false
		}
		seen[t] = true
		if named, isNamed := t.(*types.Named); isNamed {
			if named.TypeParams().Len() == 0 {
				return false
			}
			targs := named.TypeArgs()
			if targs == nil || targs.Len() == 0 {
				return true
			}
			for i := 0; i < targs.Len(); i++ {
				if walk(targs.At(i)) {
					return true
				}
			}
			return false
		}
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			return walk(u.Elem())
		case *types.Slice:
			return walk(u.Elem())
		case *types.Array:
			return walk(u.Elem())
		case *types.Chan:
			return walk(u.Elem())
		case *types.Map:
			return walk(u.Key()) || walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if walk(u.Field(i).Type()) {
					return true
				}
			}
		case *types.Signature:
			for _, tup := range []*types.Tuple{u.Params(), u.Results()} {
				for i := 0; tup != nil && i < tup.Len(); i++ {
					if walk(tup.At(i).Type()) {
						return true
					}
				}
			}
		case *types.Interface:
			for i := 0; i < u.NumMethods(); i++ {
				if walk(u.Method(i).Type()) {
					return true
				}
			}
		}
		return false
	}
	return walk(root)
}

func isInvalidOrUntypedBasic(b *types.Basic) bool {
	if b == nil {
		return true
	}
	return b.Kind() == types.Invalid || b.Kind() == types.UnsafePointer || (b.Info()&types.IsUntyped) != 0
}

// hasValidValueLayout reports whether root's own value representation (walking
// value-contained arrays and structs without crossing pointer/slice/map/chan/
// func/interface indirections) has concrete, unsafe.Pointer-free, TypeParam-free
// runtime layout safe to query with types.Sizes.
func hasValidValueLayout(root types.Type) bool {
	if root == nil {
		return false
	}
	seen := map[types.Type]bool{}
	var walk func(types.Type) bool
	walk = func(t types.Type) bool {
		if t == nil {
			return false
		}
		t = types.Unalias(t)
		if _, isTP := t.(*types.TypeParam); isTP {
			return false
		}
		if _, isTup := t.(*types.Tuple); isTup {
			return false
		}
		if seen[t] {
			return true
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Basic:
			return !isInvalidOrUntypedBasic(u)
		case *types.Pointer, *types.Slice, *types.Map, *types.Chan, *types.Signature, *types.Interface:
			return true
		case *types.Array:
			return u.Len() >= 0 && walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if !walk(u.Field(i).Type()) {
					return false
				}
			}
			return true
		default:
			return false
		}
	}
	return walk(root)
}

func unwrapSingleFieldStruct(sizes types.Sizes, t types.Type) types.Type {
	for t != nil {
		u := types.Unalias(t).Underlying()
		st, ok := u.(*types.Struct)
		if !ok || st.NumFields() != 1 {
			return t
		}
		ft := st.Field(0).Type()
		if ft == nil || sizes.Sizeof(st) != sizes.Sizeof(ft) || sizes.Alignof(st) != sizes.Alignof(ft) {
			return t
		}
		offs := sizes.Offsetsof([]*types.Var{st.Field(0)})
		if len(offs) != 1 || offs[0] != 0 {
			return t
		}
		t = ft
	}
	return t
}

func isomorphicValueLayoutSeen(sizes types.Sizes, a, b types.Type, seen map[layoutTypePair]bool) bool {
	if !hasValidValueLayout(a) || !hasValidValueLayout(b) {
		return false
	}
	a = types.Unalias(a)
	b = types.Unalias(b)
	if types.Identical(a, b) {
		return true
	}
	if sizes.Sizeof(a) != sizes.Sizeof(b) || sizes.Alignof(a) != sizes.Alignof(b) {
		return false
	}
	pair := layoutTypePair{a: a, b: b}
	if seen[pair] {
		return true
	}
	seen[pair] = true

	ua := types.Unalias(unwrapSingleFieldStruct(sizes, a))
	ub := types.Unalias(unwrapSingleFieldStruct(sizes, b))
	if !hasValidValueLayout(ua) || !hasValidValueLayout(ub) {
		return false
	}
	if types.Identical(ua, ub) {
		return true
	}
	if sizes.Sizeof(ua) != sizes.Sizeof(ub) || sizes.Alignof(ua) != sizes.Alignof(ub) {
		return false
	}

	switch xa := ua.Underlying().(type) {
	case *types.Basic:
		xb, ok := ub.Underlying().(*types.Basic)
		if !ok || isInvalidOrUntypedBasic(xa) || isInvalidOrUntypedBasic(xb) {
			return false
		}
		return xa.Kind() == xb.Kind()
	case *types.Pointer:
		xb, ok := ub.Underlying().(*types.Pointer)
		return ok && types.Identical(types.Unalias(xa.Elem()), types.Unalias(xb.Elem()))
	case *types.Slice:
		xb, ok := ub.Underlying().(*types.Slice)
		return ok && types.Identical(types.Unalias(xa.Elem()), types.Unalias(xb.Elem()))
	case *types.Array:
		xb, ok := ub.Underlying().(*types.Array)
		if !ok || xa.Len() != xb.Len() || xa.Len() < 0 {
			return false
		}
		if xa.Len() == 0 {
			return hasValidValueLayout(xa.Elem()) && hasValidValueLayout(xb.Elem())
		}
		return isomorphicValueLayoutSeen(sizes, xa.Elem(), xb.Elem(), seen)
	case *types.Struct:
		xb, ok := ub.Underlying().(*types.Struct)
		if !ok || xa.NumFields() != xb.NumFields() {
			return false
		}
		n := xa.NumFields()
		if n == 0 {
			return true
		}
		fa := make([]*types.Var, n)
		fb := make([]*types.Var, n)
		for i := 0; i < n; i++ {
			fa[i] = xa.Field(i)
			fb[i] = xb.Field(i)
		}
		offsA := sizes.Offsetsof(fa)
		offsB := sizes.Offsetsof(fb)
		if len(offsA) != n || len(offsB) != n {
			return false
		}
		for i := 0; i < n; i++ {
			if offsA[i] != offsB[i] {
				return false
			}
			if !isomorphicValueLayoutSeen(sizes, fa[i].Type(), fb[i].Type(), seen) {
				return false
			}
		}
		return true
	case *types.Interface, *types.Map, *types.Chan, *types.Signature:
		return types.Identical(ua.Underlying(), ub.Underlying())
	default:
		return false
	}
}

// IsPureScalarLayoutType reports whether t is a concrete value-contained scalar,
// array, or struct containing only booleans, integers (excluding uintptr),
// floating-point numbers, and complex numbers — with zero pointers, strings,
// slices, maps, channels, functions, interfaces, unsafe.Pointers, or uintptrs.
func IsPureScalarLayoutType(t types.Type) bool {
	if t == nil {
		return false
	}
	seen := map[types.Type]bool{}
	var walk func(types.Type) bool
	walk = func(cur types.Type) bool {
		if cur == nil {
			return false
		}
		cur = types.Unalias(cur)
		if _, isTP := cur.(*types.TypeParam); isTP {
			return false
		}
		if seen[cur] {
			return true
		}
		seen[cur] = true
		switch u := cur.Underlying().(type) {
		case *types.Basic:
			if isInvalidOrUntypedBasic(u) || u.Kind() == types.Uintptr || u.Kind() == types.String {
				return false
			}
			return (u.Info() & (types.IsBoolean | types.IsInteger | types.IsFloat | types.IsComplex)) != 0
		case *types.Array:
			if u.Len() < 0 {
				return false
			}
			return walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if !walk(u.Field(i).Type()) {
					return false
				}
			}
			return true
		default:
			return false
		}
	}
	return walk(t)
}

// IsSafeScalarBitcast reports whether reinterpreting a pointer to src as a
// pointer to dst for a pure value read stays strictly within src's byte extent
// and alignment and touches only initialized, padding-free, pointer-free,
// uintptr-free scalar bytes.
//
// Padding-bearing sources are excluded because Go's register ABI and stack
// allocator do not guarantee deterministic initialization of struct alignment
// padding bytes. Bool-carrying destinations are excluded because arbitrary
// non-{0,1} bit patterns in a Go bool violate compiler value-range invariants.
func IsSafeScalarBitcast(sizes types.Sizes, src, dst types.Type) bool {
	if sizes == nil || !IsPureScalarLayoutType(src) || !IsPureScalarLayoutType(dst) {
		return false
	}
	if !typeHasNoPadding(sizes, src) || typeContainsBool(dst) {
		return false
	}
	return sizes.Sizeof(dst) <= sizes.Sizeof(src) && sizes.Alignof(dst) <= sizes.Alignof(src)
}

func typeHasNoPadding(sizes types.Sizes, root types.Type) bool {
	var walk func(types.Type) bool
	walk = func(cur types.Type) bool {
		if cur == nil {
			return false
		}
		cur = types.Unalias(cur)
		switch u := cur.Underlying().(type) {
		case *types.Basic:
			return !isInvalidOrUntypedBasic(u) && sizes.Sizeof(u) >= 0
		case *types.Array:
			if u.Len() < 0 {
				return false
			}
			if u.Len() == 0 {
				return true
			}
			return walk(u.Elem()) && sizes.Sizeof(u) == u.Len()*sizes.Sizeof(u.Elem())
		case *types.Struct:
			n := u.NumFields()
			if n == 0 {
				return sizes.Sizeof(u) == 0
			}
			fields := make([]*types.Var, n)
			for i := 0; i < n; i++ {
				fields[i] = u.Field(i)
			}
			offs := sizes.Offsetsof(fields)
			if len(offs) != n {
				return false
			}
			var cursor int64
			for i := 0; i < n; i++ {
				ft := fields[i].Type()
				if offs[i] != cursor || !walk(ft) {
					return false
				}
				cursor += sizes.Sizeof(ft)
			}
			return cursor == sizes.Sizeof(u)
		default:
			return false
		}
	}
	return walk(root)
}

func typeContainsBool(root types.Type) bool {
	seen := map[types.Type]bool{}
	var walk func(types.Type) bool
	walk = func(cur types.Type) bool {
		if cur == nil {
			return false
		}
		cur = types.Unalias(cur)
		if seen[cur] {
			return false
		}
		seen[cur] = true
		switch u := cur.Underlying().(type) {
		case *types.Basic:
			return u.Kind() == types.Bool
		case *types.Array:
			return u.Len() >= 0 && walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if walk(u.Field(i).Type()) {
					return true
				}
			}
		}
		return false
	}
	return walk(root)
}

func isUnderlyingUnsafePointer(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	return ok && b.Kind() == types.UnsafePointer
}

func typeParamAdmitsUnsafePointer(tp *types.TypeParam) bool {
	if tp == nil || tp.Constraint() == nil {
		return false
	}
	iface, ok := tp.Constraint().Underlying().(*types.Interface)
	if !ok {
		return false
	}
	// An empty interface constraint cannot be converted directly to/from a pointer,
	// whereas a union/tilde constraint admitting unsafe.Pointer enables U(ptr) or (*T)(u).
	var checkIface func(*types.Interface, map[*types.Interface]bool) bool
	checkIface = func(it *types.Interface, seen map[*types.Interface]bool) bool {
		if it == nil || seen[it] {
			return false
		}
		seen[it] = true
		for i := 0; i < it.NumEmbeddeds(); i++ {
			emb := types.Unalias(it.EmbeddedType(i))
			if isUnderlyingUnsafePointer(emb) {
				return true
			}
			switch x := emb.Underlying().(type) {
			case *types.Union:
				for j := 0; j < x.Len(); j++ {
					if isUnderlyingUnsafePointer(x.Term(j).Type()) {
						return true
					}
				}
			case *types.Interface:
				if checkIface(x, seen) {
					return true
				}
			}
		}
		return false
	}
	return checkIface(iface, map[*types.Interface]bool{})
}

func isUntypedNilExpr(info *types.Info, expr ast.Expr) bool {
	if info == nil || expr == nil {
		return false
	}
	tv, ok := info.Types[ast.Unparen(expr)]
	if !ok || tv.Type == nil {
		return false
	}
	if tv.IsNil() {
		return true
	}
	b, ok := tv.Type.(*types.Basic)
	return ok && b.Kind() == types.UntypedNil
}

func valueTypeExposesUnsafePointer(root types.Type, ownPkg *types.Package) bool {
	if root == nil {
		return false
	}
	seen := map[types.Type]bool{}
	var walk func(types.Type) bool
	walk = func(t types.Type) bool {
		if t == nil {
			return false
		}
		if alias, isAlias := t.(*types.Alias); isAlias {
			if targs := alias.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					if walk(targs.At(i)) {
						return true
					}
				}
			}
			t = types.Unalias(t)
		}
		if seen[t] {
			return false
		}
		seen[t] = true
		if named, isNamed := t.(*types.Named); isNamed {
			if targs := named.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					if walk(targs.At(i)) {
						return true
					}
				}
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Basic:
			return u.Kind() == types.UnsafePointer
		case *types.Tuple:
			for i := 0; i < u.Len(); i++ {
				if walk(u.At(i).Type()) {
					return true
				}
			}
			return false
		case *types.Array:
			return walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				f := u.Field(i)
				if f.Pkg() != nil && f.Pkg() != ownPkg && !f.Exported() {
					if f.Embedded() && walk(f.Type()) {
						return true
					}
					continue
				}
				if walk(f.Type()) {
					return true
				}
			}
			return false
		case *types.Pointer:
			return walk(u.Elem())
		case *types.Slice:
			return walk(u.Elem())
		case *types.Chan:
			return walk(u.Elem())
		case *types.Map:
			return walk(u.Key()) || walk(u.Elem())
		case *types.Signature:
			for _, tup := range []*types.Tuple{u.Params(), u.Results()} {
				for i := 0; tup != nil && i < tup.Len(); i++ {
					if walk(tup.At(i).Type()) {
						return true
					}
				}
			}
			return false
		case *types.Interface:
			for i := 0; i < u.NumMethods(); i++ {
				m := u.Method(i)
				if m != nil && m.Pkg() != ownPkg && !m.Exported() {
					continue
				}
				if walk(m.Type()) {
					return true
				}
			}
			return false
		default:
			return false
		}
	}
	return walk(root)
}
