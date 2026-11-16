package refconfine

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
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

func verifyNamedStructImmutableInDeclPkg(
	named *types.Named,
	declPkg *packages.Package,
	callerPkg *types.Package,
	allowExportedUnexportedFieldElemPtr bool,
	isExemptIface func(*types.Interface) bool,
) (bool, string) {
	if named == nil || declPkg == nil || declPkg.Types == nil || declPkg.TypesInfo == nil || len(declPkg.Syntax) == 0 {
		return false, "missing declPkg syntax"
	}
	orig := named.Origin()
	if orig == nil || orig.Obj() == nil || orig.Obj().Pkg() != declPkg.Types {
		return false, "origin pkg mismatch"
	}
	capsules := map[*types.Named]bool{orig: true}
	match := func(st *types.Named) bool {
		return st != nil && (capsules[st] || capsules[st.Origin()])
	}
	// Close capsules over intra-package pointer (*A <-> *B) and value (A <-> B)
	// struct conversions so helper conversions such as (*term)(t) or raw(*s)
	// cannot hide mutations or leaks, failing closed on conversions to non-named
	// structs or foreign unsafe conversions.
	unapprovedConv := false
	changed := true
	for changed && !unapprovedConv {
		changed = false
		for _, file := range declPkg.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				if unapprovedConv || n == nil {
					return false
				}
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 || call.Ellipsis.IsValid() {
					return true
				}
				tv, ok := declPkg.TypesInfo.Types[call.Fun]
				if !ok || !tv.IsType() || tv.Type == nil {
					return true
				}
				if isUntypedNilExpr(declPkg.TypesInfo, call.Args[0]) {
					return true
				}
				srcT := declPkg.TypesInfo.TypeOf(call.Args[0])
				dstT := tv.Type
				if !match(syntaxutil.DerefNamedStruct(srcT)) && !match(syntaxutil.DerefNamedStruct(dstT)) {
					return true
				}
				if isUnderlyingUnsafePointer(srcT) || isUnderlyingUnsafePointer(dstT) {
					if declPkg.Types == callerPkg {
						return true
					}
					unapprovedConv = true
					return false
				}
				if types.IsInterface(dstT) {
					return true
				}
				srcU := types.Unalias(srcT)
				dstU := types.Unalias(dstT)
				srcPtr, okSP := srcU.(*types.Pointer)
				dstPtr, okDP := dstU.(*types.Pointer)
				if okSP != okDP {
					unapprovedConv = true
					return false
				}
				if okSP {
					srcU = types.Unalias(srcPtr.Elem())
					dstU = types.Unalias(dstPtr.Elem())
				}
				srcNamed, okS := srcU.(*types.Named)
				dstNamed, okD := dstU.(*types.Named)
				if !okS || !okD || srcNamed.Obj() == nil || dstNamed.Obj() == nil ||
					srcNamed.Obj().Pkg() != declPkg.Types || dstNamed.Obj().Pkg() != declPkg.Types {
					unapprovedConv = true
					return false
				}
				if _, isSSt := srcNamed.Underlying().(*types.Struct); !isSSt {
					unapprovedConv = true
					return false
				}
				if _, isDSt := dstNamed.Underlying().(*types.Struct); !isDSt {
					unapprovedConv = true
					return false
				}
				if !capsules[srcNamed.Origin()] {
					capsules[srcNamed.Origin()] = true
					changed = true
				}
				if !capsules[dstNamed.Origin()] {
					capsules[dstNamed.Origin()] = true
					changed = true
				}
				return true
			})
		}
	}
	if unapprovedConv {
		return false, "unapproved conversion touching capsule"
	}
	for id, inst := range declPkg.TypesInfo.Instances {
		if inst.TypeArgs == nil {
			continue
		}
		var tparams *types.TypeParamList
		switch obj := declPkg.TypesInfo.Uses[id].(type) {
		case *types.Func:
			if sig, ok := obj.Origin().Type().(*types.Signature); ok {
				if sig.TypeParams().Len() > 0 {
					tparams = sig.TypeParams()
				} else {
					tparams = sig.RecvTypeParams()
				}
			}
		case *types.TypeName:
			switch gt := obj.Type().(type) {
			case *types.Named:
				tparams = gt.Origin().TypeParams()
			case *types.Alias:
				tparams = gt.Origin().TypeParams()
			}
		}
		for ti := 0; ti < inst.TypeArgs.Len(); ti++ {
			if !match(syntaxutil.DerefNamedStruct(inst.TypeArgs.At(ti))) {
				continue
			}
			if tparams == nil || ti >= tparams.Len() {
				return false, "capsule instantiated in generic type argument"
			}
			iface, okI := tparams.At(ti).Constraint().Underlying().(*types.Interface)
			if !okI || constraintAdmitsTypeTerm(iface) {
				return false, "capsule instantiated in structural type parameter"
			}
		}
	}
	// Reject any unnamed struct type in declPkg whose underlying layout matches a
	// capsule struct, closing implicit named-to-unnamed struct assignments
	// (`var anon struct{...} = *s`) as well as unnamed struct conversions.
	hasMatchingUnnamedStruct := func(root types.Type) bool {
		seen := map[types.Type]bool{}
		var walk func(types.Type) bool
		walk = func(t types.Type) bool {
			if t == nil {
				return false
			}
			t = types.Unalias(t)
			if seen[t] {
				return false
			}
			seen[t] = true
			if named, isN := t.(*types.Named); isN {
				if targs := named.TypeArgs(); targs != nil {
					for i := 0; i < targs.Len(); i++ {
						if walk(targs.At(i)) {
							return true
						}
					}
				}
				if st, isSt := named.Underlying().(*types.Struct); isSt {
					for i := 0; i < st.NumFields(); i++ {
						if walk(st.Field(i).Type()) {
							return true
						}
					}
					return false
				}
			}
			switch u := t.Underlying().(type) {
			case *types.Struct:
				for capOrig := range capsules {
					if capSt, ok := capOrig.Underlying().(*types.Struct); ok && types.IdenticalIgnoreTags(u, capSt) {
						return true
					}
				}
				for i := 0; i < u.NumFields(); i++ {
					if walk(u.Field(i).Type()) {
						return true
					}
				}
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
			case *types.Tuple:
				for i := 0; i < u.Len(); i++ {
					if walk(u.At(i).Type()) {
						return true
					}
				}
			case *types.Signature:
				return walk(u.Params()) || walk(u.Results())
			}
			return false
		}
		return walk(root)
	}
	for _, tv := range declPkg.TypesInfo.Types {
		if tv.IsValue() && hasMatchingUnnamedStruct(tv.Type) {
			return false, "unnamed struct matching capsule layout in declPkg"
		}
	}
	for _, defObj := range declPkg.TypesInfo.Defs {
		if _, isTN := defObj.(*types.TypeName); !isTN && defObj != nil && hasMatchingUnnamedStruct(defObj.Type()) {
			return false, "unnamed struct def matching capsule layout in declPkg"
		}
	}
	if !verifyCapsuleStructsWriteFree(declPkg, capsules) {
		return false, "verifyCapsuleStructsWriteFree failed"
	}
	// Also reject builtin copy/clear/delete mutations into any field/slice/map
	// rooted on a capsule struct inside declPkg.
	cleanBuiltins := true
	for _, file := range declPkg.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !cleanBuiltins || n == nil {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			b := syntaxutil.LookupBuiltin(declPkg.TypesInfo, call.Fun)
			if b == nil {
				return true
			}
			switch b.Name() {
			case "copy", "clear", "delete":
				if exprHitsStructPred(declPkg.TypesInfo, call.Args[0], match, true) {
					cleanBuiltins = false
					return false
				}
			}
			return true
		})
	}
	if !cleanBuiltins {
		return false, "cleanBuiltins failed"
	}
	return verifyCapsuleInteriorRefsConfined(declPkg, capsules, allowExportedUnexportedFieldElemPtr, isExemptIface)
}

func constraintAdmitsTypeTerm(root *types.Interface) bool {
	seen := map[*types.Interface]bool{}
	var walk func(*types.Interface) bool
	walk = func(it *types.Interface) bool {
		if it == nil || seen[it] {
			return false
		}
		seen[it] = true
		for i := 0; i < it.NumEmbeddeds(); i++ {
			emb := types.Unalias(it.EmbeddedType(i))
			if subIface, ok := emb.Underlying().(*types.Interface); ok {
				if walk(subIface) {
					return true
				}
				continue
			}
			return true
		}
		return false
	}
	return walk(root)
}

func typeContainsInterfaceWith(root types.Type, isExemptIface func(*types.Interface) bool) bool {
	seen := map[types.Type]bool{}
	var walk func(types.Type) bool
	walk = func(t types.Type) bool {
		if t == nil {
			return false
		}
		t = types.Unalias(t)
		if seen[t] {
			return false
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Interface:
			return isExemptIface == nil || !isExemptIface(u)
		case *types.Array:
			return walk(u.Elem())
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

// verifyCapsuleInteriorRefsConfined routes capsule interior confinement through
// VerifyReadOnlyRefConfinement so every slice, map, channel, non-exempt
// interface, or non-immutable pointer field read from capsules across declPkg is
// confined against external/closure/generic calls, element writes,
// address-takes, RangeStmt, SendStmt, TypeAssertExpr, and exported escapes.
func verifyCapsuleInteriorRefsConfined(
	declPkg *packages.Package,
	capsules map[*types.Named]bool,
	allowExportedUnexportedFieldElemPtr bool,
	isExemptIface func(*types.Interface) bool,
) (bool, string) {
	info := declPkg.TypesInfo
	idx := BuildPkgIndex(declPkg)
	if idx == nil {
		return false, "nil PkgIndex"
	}
	match := func(st *types.Named) bool {
		return st != nil && (capsules[st] || capsules[st.Origin()])
	}
	isImmutableElemPtr := func(t types.Type) bool {
		ptr, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			return false
		}
		named, ok := types.Unalias(ptr.Elem()).(*types.Named)
		if !ok || named.Obj() == nil {
			return false
		}
		ust, isSt := named.Underlying().(*types.Struct)
		if !isSt {
			return false
		}
		if match(named) {
			return true
		}
		return allowExportedUnexportedFieldElemPtr && named.Obj().Exported() && structHasNoExportedFieldsDeep(ust)
	}
	if !VerifyReadOnlyRefConfinement(declPkg, Config{
		Index:                             idx,
		IsImmutablePtr:                    isImmutableElemPtr,
		AllowCompositeLitFieldPropagation: true,
		AllowReturnFromUnexportedFunc:     true,
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
			if !ok {
				return false, false
			}
			si := info.Selections[sel]
			if si == nil || si.Kind() != types.FieldVal {
				return false, false
			}
			fv, _ := si.Obj().(*types.Var)
			if fv == nil {
				return false, false
			}
			hitsCap := false
			syntaxutil.ForEachSelectionHopStruct(si, func(st *types.Named) {
				if match(st) {
					hitsCap = true
				}
			})
			if !hitsCap && !match(syntaxutil.DerefNamedStruct(info.TypeOf(sel.X))) {
				return false, false
			}
			ft := si.Type()
			if IsDirectMutableRefWith(ft, isImmutableElemPtr) {
				return true, true
			}
			if TypeCarriesMutableRefWith(ft, isImmutableElemPtr) || typeContainsInterfaceWith(ft, isExemptIface) {
				return false, true
			}
			return false, false
		},
		AllowCallArg: func(call *ast.CallExpr, _ int, _ ast.Expr) bool {
			return isReadOnlyStdSliceCall(info, call)
		},
	}) {
		return false, "capsule interior reference confinement failed"
	}
	return true, ""
}

// capsulePubliclyConstructedIfacePred returns a predicate matching non-empty,
// non-void-method interfaces I for which dstDeclPkg publicly exports a
// constructor function accepting a parameter of identical interface type I and
// returning dstNamed or *dstNamed (e.g. go/types.NewTerm(bool, Type) *Term).
func capsulePubliclyConstructedIfacePred(dstNamed *types.Named, dstDeclPkg *packages.Package) func(*types.Interface) bool {
	if dstNamed == nil || dstNamed.Obj() == nil || !dstNamed.Obj().Exported() || dstDeclPkg == nil || dstDeclPkg.Types == nil {
		return nil
	}
	dstOrig := dstNamed.Origin()
	var admitted []*types.Interface
	scope := dstDeclPkg.Types.Scope()
	for _, name := range scope.Names() {
		fn, ok := scope.Lookup(name).(*types.Func)
		if !ok || fn == nil || !fn.Exported() {
			continue
		}
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() != nil || sig.Results().Len() == 0 {
			continue
		}
		returnsDst := false
		for ri := 0; ri < sig.Results().Len(); ri++ {
			rt := types.Unalias(sig.Results().At(ri).Type())
			if ptr, isP := rt.(*types.Pointer); isP {
				rt = types.Unalias(ptr.Elem())
			}
			if rn, isN := rt.(*types.Named); isN && rn.Origin() == dstOrig {
				returnsDst = true
				break
			}
		}
		if !returnsDst {
			continue
		}
		for pi := 0; pi < sig.Params().Len(); pi++ {
			pt := types.Unalias(sig.Params().At(pi).Type())
			iface, okI := pt.Underlying().(*types.Interface)
			if !okI || iface.NumMethods() == 0 {
				continue
			}
			allQueryMethods := true
			for mi := 0; mi < iface.NumMethods(); mi++ {
				msig, okM := iface.Method(mi).Type().(*types.Signature)
				if !okM || msig.Results().Len() == 0 {
					allQueryMethods = false
					break
				}
			}
			if allQueryMethods {
				admitted = append(admitted, iface)
			}
		}
	}
	if len(admitted) == 0 {
		return nil
	}
	return func(cand *types.Interface) bool {
		if cand == nil {
			return false
		}
		for _, okIface := range admitted {
			if types.Identical(cand, okIface) {
				return true
			}
		}
		return false
	}
}

func collectSamePkgNamedStructs(t types.Type, pkg *types.Package) []*types.Named {
	if t == nil || pkg == nil {
		return nil
	}
	seen := map[*types.Named]bool{}
	seenTypes := map[types.Type]bool{}
	var out []*types.Named
	var walk func(types.Type)
	walk = func(cur types.Type) {
		if cur == nil {
			return
		}
		cur = types.Unalias(cur)
		if seenTypes[cur] {
			return
		}
		seenTypes[cur] = true
		if n, ok := cur.(*types.Named); ok && n.Obj() != nil && n.Obj().Pkg() == pkg {
			if _, isSt := n.Underlying().(*types.Struct); isSt {
				orig := n.Origin()
				if !seen[orig] {
					seen[orig] = true
					out = append(out, orig)
				}
			}
		}
		// Only walk value-contained aggregates (arrays and structs) occupying lv's
		// own reinterpreted memory extent; pointer and slice elements are required
		// to be types.Identical by IsomorphicValueLayout.
		switch u := cur.Underlying().(type) {
		case *types.Array:
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		}
	}
	walk(t)
	return out
}

func sameExprObjectOrConstString(info *types.Info, a, b ast.Expr) bool {
	if info == nil || a == nil || b == nil {
		return false
	}
	a = ast.Unparen(a)
	b = ast.Unparen(b)
	tva, oka := info.Types[a]
	tvb, okb := info.Types[b]
	if oka && okb && tva.Value != nil && tvb.Value != nil {
		return tva.Value.ExactString() == tvb.Value.ExactString()
	}
	ia, oka := a.(*ast.Ident)
	ib, okb := b.(*ast.Ident)
	if !oka || !okb {
		return false
	}
	oa := info.Uses[ia]
	ob := info.Uses[ib]
	if oa == nil || oa != ob {
		return false
	}
	switch v := oa.(type) {
	case *types.Const:
		return true
	case *types.Var:
		// Only local/parameter variables (never package globals that could be
		// concurrently mutated between StringData(s) and len(s)).
		return v.Pkg() != nil && v.Parent() != nil && v.Parent() != v.Pkg().Scope()
	default:
		return false
	}
}

func isUnmutatedLocalIdentInFile(info *types.Info, file *ast.File, ident *ast.Ident) bool {
	if info == nil || file == nil || ident == nil {
		return false
	}
	obj, ok := info.Uses[ident].(*types.Var)
	if !ok || obj == nil || obj.Parent() == nil || (obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope()) {
		return false
	}
	mutated := false
	ast.Inspect(file, func(n ast.Node) bool {
		if mutated || n == nil {
			return false
		}
		switch s := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range s.Lhs {
				id, ok := ast.Unparen(lhs).(*ast.Ident)
				if !ok {
					continue
				}
				// := defining obj is in info.Defs; same-scope := redeclarations
				// and = assignments record obj in info.Uses and overwrite it.
				if s.Tok == token.DEFINE && info.Defs[id] == obj {
					continue
				}
				if info.Uses[id] == obj {
					mutated = true
					return false
				}
			}
		case *ast.IncDecStmt:
			if id, ok := ast.Unparen(s.X).(*ast.Ident); ok && info.Uses[id] == obj {
				mutated = true
				return false
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND {
				if id, ok := ast.Unparen(s.X).(*ast.Ident); ok && info.Uses[id] == obj {
					mutated = true
					return false
				}
			}
		case *ast.RangeStmt:
			if s.Tok == token.ASSIGN {
				for _, r := range []ast.Expr{s.Key, s.Value} {
					if id, ok := ast.Unparen(r).(*ast.Ident); ok && info.Uses[id] == obj {
						mutated = true
						return false
					}
				}
			}
		}
		return true
	})
	return !mutated
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

func innermostAtomicStmt(parentOf map[ast.Node]ast.Node, n ast.Node) ast.Stmt {
	for anc := parentOf[n]; anc != nil; anc = parentOf[anc] {
		switch st := anc.(type) {
		case *ast.AssignStmt, *ast.IncDecStmt, *ast.SendStmt, *ast.ExprStmt,
			*ast.ReturnStmt, *ast.DeferStmt, *ast.GoStmt, *ast.DeclStmt,
			*ast.RangeStmt, *ast.ForStmt, *ast.IfStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt:
			return anc.(ast.Stmt)
		default:
			_ = st
		}
	}
	return nil
}

// PackageHasUnconfinedUnsafeMemoryHazard reports whether package p contains any
// unsafe operation or unsafe.Pointer value/conversion (including through
// imported defined/alias types or conversion-free APIs such as
// reflect.Value.UnsafePointer / reflect.NewAt, without p itself importing
// "unsafe") that is not mechanically proven read-only and layout-safe.
//
// Admitted safe shapes:
//  1. Compile-time layout intrinsics: unsafe.Alignof, unsafe.Offsetof, unsafe.Sizeof.
//  2. Read-only unsafe.StringData(s) pointer-identity comparisons (== / !=) and
//     locally reference-confined read-only unsafe.Slice(unsafe.StringData(s), len(s))
//     projections over a constant or unmutated local string binding s.
//  3. Immediate rvalue scalar bitcast reads *(*Dst)(U(srcPtr)) where
//     IsSafeScalarBitcast(sizes, Src, Dst) holds and the dereference is strictly
//     an rvalue read (never assigned, incremented, &-addressed, array-sliced, or
//     invoking a pointer-receiver method).
//  4. Immediate bijective isomorphic-layout casts (*Dst)(U(srcPtr)) where
//     IsomorphicValueLayout(sizes, Src, Dst) holds and either:
//     (a) the cast is immediately dereferenced as an rvalue read producing a
//     mutable-reach-free, uintptr-free value, or
//     (b) Dst is an all-unexported-field named struct verified write-free and
//     interior-reference-confined in its declaring package, any same-package
//     named structs in Src are similarly verified in p, and if srcPtr is &localVar,
//     localVar is fresh (when carrying mutable reach), not a named result, and
//     never mutated or aliased at or after that cast.
func PackageHasUnconfinedUnsafeMemoryHazard(
	p *packages.Package,
	sizes types.Sizes,
	loadedByTypes map[*types.Package]*packages.Package,
) bool {
	return PackageUnsafeMemoryHazardReason(p, sizes, loadedByTypes) != ""
}

// PackageUnsafeMemoryHazardReason returns "" when every unsafe operation or
// unsafe.Pointer value/conversion in p is mechanically proven read-only and
// layout-safe, or a short non-empty diagnostic reason naming the first hazard.
func PackageUnsafeMemoryHazardReason(
	p *packages.Package,
	sizes types.Sizes,
	loadedByTypes map[*types.Package]*packages.Package,
) string {
	if p == nil || p.Types == nil || p.TypesInfo == nil {
		return "missing package types"
	}
	if sizes == nil {
		sizes = p.TypesSizes
	}
	info := p.TypesInfo

	// Reject generic declarations whose type parameters admit unsafe.Pointer
	// and any declared variable/field/parameter whose type exposes unsafe.Pointer.
	for _, defObj := range info.Defs {
		switch obj := defObj.(type) {
		case *types.TypeName:
			if tp, ok := obj.Type().(*types.TypeParam); ok && typeParamAdmitsUnsafePointer(tp) {
				return "typeparam admits unsafe.Pointer: " + obj.Name()
			}
		case *types.Var:
			if valueTypeExposesUnsafePointer(obj.Type(), p.Types) {
				return "declared var/field exposes unsafe.Pointer: " + obj.Name()
			}
		}
	}
	for _, inst := range info.Instances {
		if inst.TypeArgs != nil {
			for i := 0; i < inst.TypeArgs.Len(); i++ {
				if valueTypeExposesUnsafePointer(inst.TypeArgs.At(i), p.Types) {
					return "generic instantiation exposes unsafe.Pointer: " + inst.TypeArgs.At(i).String()
				}
			}
		}
	}

	declPkgFor := func(tpkg *types.Package) *packages.Package {
		if tpkg == nil {
			return nil
		}
		if tpkg == p.Types {
			return p
		}
		if loadedByTypes != nil {
			return loadedByTypes[tpkg]
		}
		return nil
	}

	var seedExprs map[ast.Expr]bool
	noteSeed := func(e ast.Expr) {
		if seedExprs == nil {
			seedExprs = map[ast.Expr]bool{}
		}
		seedExprs[ast.Unparen(e)] = true
	}

	for _, file := range p.Syntax {
		if file == nil {
			continue
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

		isStrictRvalueStarOf := func(conv *ast.CallExpr) bool {
			star, ok := parentOf[conv].(*ast.StarExpr)
			if !ok || ast.Unparen(star.X) != conv {
				return false
			}
			cur := ast.Node(star)
			for {
				next := parentOf[cur]
				switch nx := next.(type) {
				case *ast.AssignStmt:
					for _, lhs := range nx.Lhs {
						if ast.Unparen(lhs) == cur {
							return false
						}
					}
					return true
				case *ast.IncDecStmt:
					if ast.Unparen(nx.X) == cur {
						return false
					}
					return true
				case *ast.RangeStmt:
					if nx.Tok == token.ASSIGN && (ast.Unparen(nx.Key) == cur || ast.Unparen(nx.Value) == cur) {
						return false
					}
					return true
				case *ast.UnaryExpr:
					if nx.Op == token.AND && ast.Unparen(nx.X) == cur {
						return false
					}
					return true
				case *ast.SliceExpr:
					if ast.Unparen(nx.X) == cur {
						if expr, isE := cur.(ast.Expr); isE {
							if b, isB := types.Unalias(info.TypeOf(expr)).Underlying().(*types.Basic); isB && b.Kind() == types.String {
								return true
							}
						}
						return false
					}
					return true
				case *ast.SelectorExpr:
					if ast.Unparen(nx.X) == cur {
						sel := info.Selections[nx]
						if sel == nil {
							return false
						}
						if sel.Kind() == types.MethodVal {
							return !SelectionHasPointerReceiver(sel) && !sel.Indirect()
						}
						if sel.Kind() == types.FieldVal {
							cur = nx
							continue
						}
						return false
					}
					return true
				case *ast.IndexExpr:
					if ast.Unparen(nx.X) == cur {
						cur = nx
						continue
					}
					return true
				default:
					return true
				}
			}
		}

		approvedUPExpr := map[ast.Expr]bool{}
		hazardReason := ""
		ast.Inspect(file, func(n ast.Node) bool {
			if hazardReason != "" || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.Ident:
				obj := info.Uses[x]
				b, isBuiltin := obj.(*types.Builtin)
				if !isBuiltin || b == nil || b.Pkg() != types.Unsafe {
					return true
				}
				var call *ast.CallExpr
				switch par := parentOf[x].(type) {
				case *ast.CallExpr:
					if ast.Unparen(par.Fun) == x {
						call = par
					}
				case *ast.SelectorExpr:
					if par.Sel == x {
						if gp, ok := parentOf[par].(*ast.CallExpr); ok && ast.Unparen(gp.Fun) == par {
							call = gp
						}
					}
				}
				if call == nil {
					hazardReason = "non-call unsafe builtin: " + b.Name()
					return false
				}
				switch b.Name() {
				case "Alignof", "Offsetof", "Sizeof":
					return true
				case "StringData":
					if len(call.Args) != 1 || call.Ellipsis.IsValid() {
						hazardReason = "StringData bad args"
						return false
					}
					// 1. Direct pointer-identity equality / inequality: StringData(a) == StringData(b).
					if bin, isBin := parentOf[call].(*ast.BinaryExpr); isBin && (bin.Op == token.EQL || bin.Op == token.NEQ) &&
						(ast.Unparen(bin.X) == call || ast.Unparen(bin.Y) == call) {
						return true
					}
					// 2. Direct arg 0 of unsafe.Slice(unsafe.StringData(s), len(s)) is validated on Slice below.
					if outer, isOuter := parentOf[call].(*ast.CallExpr); isOuter && len(outer.Args) == 2 && ast.Unparen(outer.Args[0]) == call {
						if ob := syntaxutil.LookupBuiltin(info, outer.Fun); ob != nil && ob.Pkg() == types.Unsafe && ob.Name() == "Slice" {
							return true
						}
					}
					hazardReason = "standalone unsafe.StringData outside ==/!= or unsafe.Slice(StringData(s), len(s))"
					return false
				case "Slice":
					if len(call.Args) != 2 || call.Ellipsis.IsValid() {
						hazardReason = "Slice bad args"
						return false
					}
					sdCall, isSD := ast.Unparen(call.Args[0]).(*ast.CallExpr)
					if !isSD || len(sdCall.Args) != 1 || sdCall.Ellipsis.IsValid() {
						hazardReason = "Slice arg0 not StringData"
						return false
					}
					sdb := syntaxutil.LookupBuiltin(info, sdCall.Fun)
					if sdb == nil || sdb.Pkg() != types.Unsafe || sdb.Name() != "StringData" {
						hazardReason = "Slice arg0 not unsafe.StringData"
						return false
					}
					lenCall, isLen := ast.Unparen(call.Args[1]).(*ast.CallExpr)
					if !isLen || len(lenCall.Args) != 1 || lenCall.Ellipsis.IsValid() {
						hazardReason = "Slice arg1 not len"
						return false
					}
					lb := syntaxutil.LookupBuiltin(info, lenCall.Fun)
					if lb == nil || lb.Name() != "len" || !sameExprObjectOrConstString(info, sdCall.Args[0], lenCall.Args[0]) {
						hazardReason = "Slice len mismatch"
						return false
					}
					if id, isID := ast.Unparen(sdCall.Args[0]).(*ast.Ident); isID {
						if _, isVar := info.Uses[id].(*types.Var); isVar && !isUnmutatedLocalIdentInFile(info, file, id) {
							hazardReason = "Slice mutable string local"
							return false
						}
					}
					noteSeed(call)
					return true
				default:
					hazardReason = "unsafe builtin: " + b.Name()
					return false
				}

			case *ast.CallExpr:
				if approvedUPExpr[x] {
					return true
				}
				tv, ok := info.Types[x.Fun]
				if !ok || !tv.IsType() || len(x.Args) != 1 || x.Ellipsis.IsValid() {
					return true
				}
				dstType := tv.Type
				argExpr := ast.Unparen(x.Args[0])
				srcType := info.TypeOf(argExpr)
				if dstType == nil || srcType == nil {
					hazardReason = "nil conv type"
					return false
				}
				dstIsUP := isUnderlyingUnsafePointer(dstType)
				srcIsUP := isUnderlyingUnsafePointer(srcType)
				if !dstIsUP && !srcIsUP {
					return true
				}
				if dstIsUP && isUntypedNilExpr(info, argExpr) {
					approvedUPExpr[x] = true
					return true
				}
				if dstIsUP {
					outerCall, ok := parentOf[x].(*ast.CallExpr)
					if !ok || len(outerCall.Args) != 1 || outerCall.Ellipsis.IsValid() || ast.Unparen(outerCall.Args[0]) != x {
						hazardReason = "standalone conversion into unsafe.Pointer"
						return false
					}
					otv, ok := info.Types[outerCall.Fun]
					if !ok || !otv.IsType() || isUnderlyingUnsafePointer(otv.Type) {
						hazardReason = "outer conversion not out of unsafe.Pointer"
						return false
					}
					return true
				}
				innerCall, ok := argExpr.(*ast.CallExpr)
				if !ok || len(innerCall.Args) != 1 || innerCall.Ellipsis.IsValid() {
					hazardReason = "conversion from non-immediate unsafe.Pointer"
					return false
				}
				itv, ok := info.Types[innerCall.Fun]
				if !ok || !itv.IsType() || !isUnderlyingUnsafePointer(itv.Type) {
					hazardReason = "inner call not unsafe.Pointer type conv"
					return false
				}
				origExpr := ast.Unparen(innerCall.Args[0])
				if isUntypedNilExpr(info, origExpr) {
					approvedUPExpr[innerCall] = true
					return true
				}
				origPtr, okOrig := types.Unalias(info.TypeOf(origExpr)).(*types.Pointer)
				dstPtr, okDst := types.Unalias(dstType).(*types.Pointer)
				if !okOrig || !okDst || sizes == nil {
					hazardReason = "non-pointer cast endpoint"
					return false
				}
				srcElem := origPtr.Elem()
				dstElem := dstPtr.Elem()

				if IsSafeScalarBitcast(sizes, srcElem, dstElem) && isStrictRvalueStarOf(x) {
					approvedUPExpr[innerCall] = true
					return true
				}
				if IsomorphicValueLayout(sizes, srcElem, dstElem) {
					if isStrictRvalueStarOf(x) && !TypeHandsOutMutableReach(dstElem) && !syntaxutil.ContainsUintptr(dstElem) {
						approvedUPExpr[innerCall] = true
						return true
					}
					if dstNamed, okN := types.Unalias(dstElem).(*types.Named); okN && dstNamed.Obj() != nil {
						if dstSt, okSt := dstNamed.Underlying().(*types.Struct); okSt {
							if !structHasNoExportedFieldsDeep(dstSt) {
								hazardReason = "dst struct has exported fields: " + dstNamed.String()
								return false
							}
							dstDeclPkg := declPkgFor(dstNamed.Obj().Pkg())
							srcOriginOK := false
							if un, isAddr := origExpr.(*ast.UnaryExpr); isAddr && un.Op == token.AND {
								if id, isID := ast.Unparen(un.X).(*ast.Ident); isID {
									if lv, isVar := info.Uses[id].(*types.Var); isVar && lv != nil && lv.Parent() != nil && (lv.Pkg() == nil || lv.Parent() != lv.Pkg().Scope()) {
										if okImm, immReason := verifyNamedStructImmutableInDeclPkg(dstNamed, dstDeclPkg, p.Types, true, nil); !okImm {
											hazardReason = "dst struct not immutable in decl pkg: " + dstNamed.String() + " (" + immReason + ")"
											return false
										}
										isLocalElemImmutablePtr := func(t types.Type) bool {
											ptr, okP := types.Unalias(t).(*types.Pointer)
											if !okP {
												return false
											}
											en, okEN := types.Unalias(ptr.Elem()).(*types.Named)
											if !okEN || en.Obj() == nil {
												return false
											}
											eust, isESt := en.Underlying().(*types.Struct)
											if !isESt || !structHasNoExportedFieldsDeep(eust) {
												return false
											}
											if en.Obj().Pkg() == p.Types {
												okENImm, _ := verifyNamedStructImmutableInDeclPkg(en, p, p.Types, true, nil)
												return okENImm
											}
											return en.Obj().Exported()
										}
										inLoop := false
										var enclBlock ast.Node = file
										var enclFnType *ast.FuncType
										for anc := parentOf[x]; anc != nil; anc = parentOf[anc] {
											switch fn := anc.(type) {
											case *ast.ForStmt, *ast.RangeStmt:
												inLoop = true
											case *ast.FuncDecl:
												if enclBlock == file {
													enclBlock = fn
													enclFnType = fn.Type
												}
											case *ast.FuncLit:
												if enclBlock == file {
													enclBlock = fn
													enclFnType = fn.Type
												}
											}
										}
										isNamedResult := false
										if enclFnType != nil && enclFnType.Results != nil {
											for _, rf := range enclFnType.Results.List {
												for _, nm := range rf.Names {
													if info.Defs[nm] == lv {
														isNamedResult = true
													}
												}
											}
										}
										if !inLoop && enclBlock != file && !isNamedResult {
											cleanLocal := true
											if TypeHandsOutMutableReach(srcElem) {
												foundInit := false
												ast.Inspect(enclBlock, func(in ast.Node) bool {
													if !cleanLocal || in == nil {
														return false
													}
													switch s := in.(type) {
													case *ast.AssignStmt:
														for li, lhs := range s.Lhs {
															lid, ok := ast.Unparen(lhs).(*ast.Ident)
															if !ok {
																continue
															}
															if s.Tok == token.DEFINE && info.Defs[lid] == lv {
																if foundInit || len(s.Lhs) != len(s.Rhs) {
																	cleanLocal = false
																	return false
																}
																foundInit = true
																if !isFreshMakeOrEmptyCompositeExpr(info, s.Rhs[li]) {
																	cleanLocal = false
																	return false
																}
															} else if info.Uses[lid] == lv {
																cleanLocal = false
																return false
															}
														}
													case *ast.ValueSpec:
														for vi, name := range s.Names {
															if info.Defs[name] == lv {
																if foundInit {
																	cleanLocal = false
																	return false
																}
																foundInit = true
																if len(s.Values) != 0 && (len(s.Names) != len(s.Values) || !isFreshMakeOrEmptyCompositeExpr(info, s.Values[vi])) {
																	cleanLocal = false
																	return false
																}
															}
														}
													}
													return true
												})
												if !foundInit {
													cleanLocal = false
												}
											}
											var checkLocal func(ast.Node)
											checkLocal = func(mn ast.Node) {
												if !cleanLocal || mn == nil {
													return
												}
												switch s := mn.(type) {
												case *ast.LabeledStmt:
													cleanLocal = false
													return
												case *ast.BranchStmt:
													if s.Tok == token.GOTO {
														cleanLocal = false
														return
													}
												case *ast.UnaryExpr:
													if s.Op == token.AND && s != un && exprMentionsVar(info, s.X, lv) {
														cleanLocal = false
														return
													}
												case *ast.SliceExpr:
													if exprMentionsVar(info, s.X, lv) {
														cleanLocal = false
														return
													}
												case *ast.SelectorExpr:
													if sel := info.Selections[s]; sel != nil && sel.Kind() == types.MethodVal && exprMentionsVar(info, s.X, lv) {
														_, recvIsPtr := types.Unalias(sel.Recv()).(*types.Pointer)
														if recvIsPtr || SelectionHasPointerReceiver(sel) {
															cleanLocal = false
															return
														}
													}
												case *ast.FuncLit:
													if mn != enclBlock {
														ast.Inspect(s.Body, func(cn ast.Node) bool {
															if id2, ok := cn.(*ast.Ident); ok && (info.Uses[id2] == lv || info.Defs[id2] == lv) {
																cleanLocal = false
																return false
															}
															return true
														})
														return
													}
												case *ast.Ident:
													if info.Uses[s] == lv {
														if s != id {
															if s.Pos() > x.Pos() {
																cleanLocal = false
																return
															}
															if st := innermostAtomicStmt(parentOf, s); st == nil || st.End() >= x.Pos() {
																cleanLocal = false
																return
															}
														}
														if s != id && TypeHandsOutMutableReach(srcElem) {
															allowedUse := false
															switch par := parentOf[s].(type) {
															case *ast.IndexExpr:
																if ast.Unparen(par.X) == s {
																	elemT := info.TypeOf(par)
																	if !TypeHandsOutMutableReach(elemT) {
																		allowedUse = true
																	} else if !TypeCarriesMutableRefWith(elemT, isLocalElemImmutablePtr) && !typeContainsInterfaceWith(elemT, nil) {
																		if as, isAs := parentOf[par].(*ast.AssignStmt); isAs && as.Tok == token.ASSIGN {
																			for _, lhs := range as.Lhs {
																				if ast.Unparen(lhs) == par {
																					allowedUse = true
																					break
																				}
																			}
																		}
																	}
																}
															case *ast.RangeStmt:
																if ast.Unparen(par.X) == s && (par.Value == nil || syntaxutil.IsBlankIdent(par.Value)) {
																	allowedUse = true
																}
															case *ast.CallExpr:
																if len(par.Args) == 1 && !par.Ellipsis.IsValid() && ast.Unparen(par.Args[0]) == s {
																	if b := syntaxutil.LookupBuiltin(info, par.Fun); b != nil && (b.Name() == "len" || b.Name() == "cap") {
																		allowedUse = true
																	}
																}
															}
															if !allowedUse {
																cleanLocal = false
																return
															}
														}
													}
												}
												ast.Inspect(mn, func(ch ast.Node) bool {
													if ch == mn || ch == nil {
														return true
													}
													checkLocal(ch)
													return false
												})
											}
											checkLocal(enclBlock)
											for _, sn := range collectSamePkgNamedStructs(srcElem, p.Types) {
												if okSNImm, _ := verifyNamedStructImmutableInDeclPkg(sn, p, p.Types, true, nil); !okSNImm {
													cleanLocal = false
													break
												}
											}
											srcOriginOK = cleanLocal
										}
									}
								}
							} else if srcNamed, okSN := types.Unalias(srcElem).(*types.Named); okSN && srcNamed.Obj() != nil {
								if srcSt, okSrcSt := srcNamed.Underlying().(*types.Struct); okSrcSt &&
									structHasNoExportedFieldsDeep(srcSt) {
									srcDeclPkg := declPkgFor(srcNamed.Obj().Pkg())
									var exemptIface func(*types.Interface) bool
									if srcNamed.Obj().Pkg() == p.Types && !srcNamed.Obj().Exported() {
										exemptIface = capsulePubliclyConstructedIfacePred(dstNamed, dstDeclPkg)
									}
									if okDstImm, immReason := verifyNamedStructImmutableInDeclPkg(dstNamed, dstDeclPkg, p.Types, false, exemptIface); !okDstImm {
										hazardReason = "dst struct not immutable in decl pkg: " + dstNamed.String() + " (" + immReason + ")"
										return false
									}
									if okSNImm, _ := verifyNamedStructImmutableInDeclPkg(srcNamed, srcDeclPkg, p.Types, false, exemptIface); okSNImm {
										srcOriginOK = true
									}
								}
							}
							if srcOriginOK {
								approvedUPExpr[innerCall] = true
								return true
							}
							hazardReason = "src origin not clean for isomorphic cast to " + dstNamed.String()
							return false
						}
					}
				}
				hazardReason = "unapproved unsafe.Pointer conversion: " + srcElem.String() + " -> " + dstElem.String()
				return false
			}
			return true
		})
		if hazardReason != "" {
			return hazardReason
		}

		// Sweep all runtime value expressions in file so conversion-free
		// unsafe.Pointer channels (e.g. reflect.Value.UnsafePointer + reflect.NewAt,
		// sync/atomic.*Pointer, or composite unsafe.Pointer carriers) cannot bypass
		// conversion inspection.
		ast.Inspect(file, func(n ast.Node) bool {
			if hazardReason != "" || n == nil {
				return false
			}
			expr, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			unp := ast.Unparen(expr)
			if approvedUPExpr[unp] {
				return true
			}
			tv, ok := info.Types[expr]
			if !ok || !tv.IsValue() || tv.Type == nil {
				return true
			}
			if valueTypeExposesUnsafePointer(tv.Type, p.Types) {
				hazardReason = "unapproved unsafe.Pointer value expression: " + tv.Type.String()
				return false
			}
			return true
		})
		if hazardReason != "" {
			return hazardReason
		}
	}

	if len(seedExprs) > 0 {
		idx := BuildPkgIndex(p)
		if !VerifyReadOnlyRefConfinement(p, Config{
			Index: idx,
			SeedExpr: func(expr ast.Expr) (bool, bool) {
				if seedExprs[ast.Unparen(expr)] {
					return true, true
				}
				return false, false
			},
			AllowCallArg: func(call *ast.CallExpr, _ int, _ ast.Expr) bool {
				return isReadOnlyStdSliceCall(info, call)
			},
		}) {
			return "StringData/Slice confinement failed"
		}
	}

	return ""
}

func isFreshMakeOrEmptyCompositeExpr(info *types.Info, expr ast.Expr) bool {
	if info == nil || expr == nil {
		return false
	}
	switch x := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		b := syntaxutil.LookupBuiltin(info, x.Fun)
		return b != nil && b.Name() == "make"
	case *ast.CompositeLit:
		return len(x.Elts) == 0
	default:
		return false
	}
}

func exprMentionsVar(info *types.Info, expr ast.Expr, v *types.Var) bool {
	if info == nil || expr == nil || v == nil {
		return false
	}
	hit := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if hit || n == nil {
			return false
		}
		if id, ok := n.(*ast.Ident); ok && info.Uses[id] == v {
			hit = true
			return false
		}
		return true
	})
	return hit
}

// isReadOnlyStdSliceCall reports whether call invokes a standard-library slice
// inspection function that reads its slice arguments synchronously without user
// callbacks, never mutates or retains them, and returns only scalar values
// (never a sub-slice or pointer alias into its input).
func isReadOnlyStdSliceCall(info *types.Info, call *ast.CallExpr) bool {
	if info == nil || call == nil {
		return false
	}
	funExpr := ast.Unparen(call.Fun)
	switch ix := funExpr.(type) {
	case *ast.IndexExpr:
		funExpr = ast.Unparen(ix.X)
	case *ast.IndexListExpr:
		funExpr = ast.Unparen(ix.X)
	}
	sel, ok := funExpr.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil {
		return false
	}
	if info.Selections[sel] != nil {
		return false
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok || fn == nil || fn.Pkg() == nil {
		return false
	}
	switch fn.Pkg().Path() {
	case "bytes":
		switch fn.Name() {
		case "Equal", "EqualFold", "Compare",
			"Index", "IndexByte", "IndexAny", "IndexRune",
			"LastIndex", "LastIndexByte", "LastIndexAny",
			"Contains", "ContainsAny", "ContainsRune",
			"Count", "HasPrefix", "HasSuffix":
			return true
		}
	case "unicode/utf8":
		switch fn.Name() {
		case "Valid", "DecodeRune", "DecodeLastRune", "RuneCount", "FullRune":
			return true
		}
	case "slices":
		switch fn.Name() {
		case "Index", "Contains", "Equal", "Compare", "BinarySearch":
			return true
		}
	case "reflect":
		if fn.Name() == "TypeOf" {
			return true
		}
	}
	return false
}
