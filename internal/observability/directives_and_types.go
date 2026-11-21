package observability

import (
	"go/token"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/rta"
)

// parameterizedBody reports whether fn's body is generic (uninstantiated):
// either fn itself declares type parameters without concrete type arguments,
// or an enclosing lexical function does (making fn an uninstantiated closure
// inside a generic function whose instructions carry *types.TypeParam
// operands). Instantiations populate TypeArgs and analyze normally.
func parameterizedBody(fn *ssa.Function) bool {
	for cur := fn; cur != nil; cur = cur.Parent() {
		generic := cur.TypeParams().Len() > 0 || (cur.Signature != nil && cur.Signature.RecvTypeParams() != nil)
		if !generic {
			continue
		}
		args := cur.TypeArgs()
		if len(args) == 0 {
			return true
		}
		for _, arg := range args {
			if rta.ContainsTypeParam(arg, nil) {
				return true
			}
		}
	}
	return false
}

func functionSymbolName(fn *ssa.Function) string {
	if fn == nil {
		return ""
	}
	if obj := fn.Object(); obj != nil {
		return obj.Name()
	}
	if origin := fn.Origin(); origin != nil {
		if obj := origin.Object(); obj != nil {
			return obj.Name()
		}
		return origin.Name()
	}
	return fn.Name()
}

func baseFunctionSymbolName(fn *ssa.Function) string {
	return strings.TrimSuffix(strings.TrimSuffix(functionSymbolName(fn), "$bound"), "$thunk")
}

// walkTypeGraph visits the types reachable from t through the structural
// edges listed here — element, key, field, parameter, result, underlying,
// and (when typeArgs is set) type-argument — Unalias-normalized, each
// type at most once per seen map. Interfaces are deliberately terminal:
// their embedded and method types stay unwalked, and the carrier rule
// judges interface-typed state separately — adding interface edges would
// move verdicts. visit returning false stops the whole walk. Callers own
// seen: the analyzer's addType shares one map across calls so a type
// reached once is never re-walked; the per-call predicates pass fresh
// maps. The typeArgs edge stays addType-only: the predicates never
// walked it, and widening their reach could move a verdict.
func walkTypeGraph(t types.Type, typeArgs bool, seen map[types.Type]bool, visit func(types.Type) bool) {
	stop := false
	var walk func(types.Type)
	walk = func(t types.Type) {
		if t == nil || stop {
			return
		}
		t = types.Unalias(t)
		if ssaOpaqueHandle(t) {
			return
		}
		if seen[t] {
			return
		}
		seen[t] = true
		if !visit(t) {
			stop = true
			return
		}
		switch tt := t.(type) {
		case *types.Named:
			if typeArgs {
				for i := 0; i < tt.TypeArgs().Len(); i++ {
					walk(tt.TypeArgs().At(i))
				}
			}
			walk(tt.Underlying())
		case *types.Pointer:
			walk(tt.Elem())
		case *types.Slice:
			walk(tt.Elem())
		case *types.Array:
			walk(tt.Elem())
		case *types.Map:
			walk(tt.Key())
			walk(tt.Elem())
		case *types.Chan:
			walk(tt.Elem())
		case *types.Signature:
			for _, tuple := range []*types.Tuple{tt.Params(), tt.Results()} {
				for i := 0; tuple != nil && i < tuple.Len(); i++ {
					walk(tuple.At(i).Type())
				}
			}
		case *types.Struct:
			for i := 0; i < tt.NumFields(); i++ {
				walk(tt.Field(i).Type())
			}
		case *types.Tuple:
			for i := 0; i < tt.Len(); i++ {
				walk(tt.At(i).Type())
			}
		}
	}
	walk(t)
}

// ssaOpaqueHandle recognizes the builder's two internal tokens and the
// standard library's sync.notifyList wait-queue handle inside sync.Cond.
// None represents a user source pointer operation, and their operands and
// callbacks remain independently scanned.
func ssaOpaqueHandle(t types.Type) bool {
	n, ok := t.(*types.Named)
	if !ok || n.Obj() == nil || n.Obj().Pkg() == nil {
		return false
	}
	if n.Obj().Pkg().Path() == "sync" && n.Obj().Name() == "notifyList" {
		return true
	}
	if n.Obj().Pkg().Path() != "$ssa" || n.Underlying() != types.Typ[types.UnsafePointer] {
		return false
	}
	return n.Obj().Name() == "rangeIter" || n.Obj().Name() == "deferStack"
}

func typeUsesUnsafePointerWith(
	t types.Type,
	typeArgs bool,
	memo map[types.Type]bool,
	onNamed func(tt *types.Named, walk func(types.Type) bool) (uses, handled bool),
) bool {
	if t == nil {
		return false
	}
	if memo != nil {
		if v, ok := memo[t]; ok {
			return v
		}
	}
	seen := make(map[types.Type]bool)
	var walk func(types.Type) bool
	walk = func(cur types.Type) bool {
		if cur == nil {
			return false
		}
		cur = types.Unalias(cur)
		if memo != nil {
			if v, ok := memo[cur]; ok {
				return v
			}
		}
		if ssaOpaqueHandle(cur) || seen[cur] {
			return false
		}
		seen[cur] = true
		switch tt := cur.(type) {
		case *types.Basic:
			return tt.Kind() == types.UnsafePointer
		case *types.Named:
			if obj := tt.Obj(); obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "unsafe" && obj.Name() == "Pointer" {
				return true
			}
			if onNamed != nil {
				if uses, handled := onNamed(tt, walk); handled {
					return uses
				}
			}
			if typeArgs {
				for i := 0; i < tt.TypeArgs().Len(); i++ {
					if walk(tt.TypeArgs().At(i)) {
						return true
					}
				}
			}
			return walk(tt.Underlying())
		case *types.Pointer:
			return walk(tt.Elem())
		case *types.Slice:
			return walk(tt.Elem())
		case *types.Array:
			return walk(tt.Elem())
		case *types.Chan:
			return walk(tt.Elem())
		case *types.Map:
			return walk(tt.Key()) || walk(tt.Elem())
		case *types.Signature:
			for _, tuple := range []*types.Tuple{tt.Params(), tt.Results()} {
				for i := 0; tuple != nil && i < tuple.Len(); i++ {
					if walk(tuple.At(i).Type()) {
						return true
					}
				}
			}
		case *types.Struct:
			for i := 0; i < tt.NumFields(); i++ {
				if walk(tt.Field(i).Type()) {
					return true
				}
			}
		case *types.Tuple:
			for i := 0; i < tt.Len(); i++ {
				if walk(tt.At(i).Type()) {
					return true
				}
			}
		}
		return false
	}
	res := walk(t)
	if memo != nil {
		memo[t] = res
	}
	return res
}

func isTestingTBInterface(t types.Type) bool {
	if t == nil {
		return false
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "testing" && named.Obj().Name() == "TB"
}

func isHarnessPointerType(t types.Type) bool {
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "testing" {
		return false
	}
	switch named.Obj().Name() {
	case "T", "B", "F", "M":
		return true
	default:
		return false
	}
}

type typeAccessKey struct {
	t        types.Type
	addr     bool
	concrete bool
}

type typeAddrKey struct {
	t    types.Type
	addr bool
}

func hasExportedPkgAlias(named *types.Named) bool {
	if named == nil || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	scope := named.Obj().Pkg().Scope()
	if scope == nil {
		return false
	}
	targetOrigin := named.Origin()
	for _, name := range scope.Names() {
		if !token.IsExported(name) {
			continue
		}
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok || !tn.IsAlias() {
			continue
		}
		u := types.Unalias(tn.Type())
		if ptr, ok := u.(*types.Pointer); ok {
			u = types.Unalias(ptr.Elem())
		}
		if uNamed, ok := u.(*types.Named); ok && uNamed.Origin() == targetOrigin {
			return true
		}
	}
	return false
}

func isTypeAssertableOutsidePkg(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	if alias, ok := t.(*types.Alias); ok && alias.Obj() != nil && alias.Obj().Exported() {
		if targs := alias.TypeArgs(); targs != nil {
			for i := 0; i < targs.Len(); i++ {
				if !isTypeAssertableOutsidePkg(targs.At(i), seen) {
					return false
				}
			}
		}
		return true
	}
	t = types.Unalias(t)
	if seen[t] {
		return true
	}
	seen[t] = true
	switch tt := t.(type) {
	case *types.Basic:
		return true
	case *types.Pointer:
		return isTypeAssertableOutsidePkg(tt.Elem(), seen)
	case *types.Slice:
		return isTypeAssertableOutsidePkg(tt.Elem(), seen)
	case *types.Array:
		return isTypeAssertableOutsidePkg(tt.Elem(), seen)
	case *types.Chan:
		return isTypeAssertableOutsidePkg(tt.Elem(), seen)
	case *types.Map:
		return isTypeAssertableOutsidePkg(tt.Key(), seen) && isTypeAssertableOutsidePkg(tt.Elem(), seen)
	case *types.Named:
		obj := tt.Obj()
		if obj == nil {
			return false
		}
		if obj.Pkg() != nil && !obj.Exported() && !hasExportedPkgAlias(tt) {
			return false
		}
		if targs := tt.TypeArgs(); targs != nil {
			for i := 0; i < targs.Len(); i++ {
				if !isTypeAssertableOutsidePkg(targs.At(i), seen) {
					return false
				}
			}
		}
		return true
	case *types.Struct:
		for i := 0; i < tt.NumFields(); i++ {
			if !tt.Field(i).Exported() || !isTypeAssertableOutsidePkg(tt.Field(i).Type(), seen) {
				return false
			}
		}
		return true
	case *types.Interface:
		for i := 0; i < tt.NumMethods(); i++ {
			fn := tt.Method(i)
			if !fn.Exported() || !isTypeAssertableOutsidePkg(fn.Type(), seen) {
				return false
			}
		}
		return true
	case *types.Signature:
		for _, tup := range []*types.Tuple{tt.Params(), tt.Results()} {
			for i := 0; tup != nil && i < tup.Len(); i++ {
				if !isTypeAssertableOutsidePkg(tup.At(i).Type(), seen) {
					return false
				}
			}
		}
		return true
	}
	return false
}

func methodSetExposesMutableCarrier(audited bool, pkgPath string, mset *types.MethodSet, walk func(types.Type, bool, bool) bool) bool {
	for i := 0; mset != nil && i < mset.Len(); i++ {
		fn, ok := mset.At(i).Obj().(*types.Func)
		if !ok || !fn.Exported() {
			continue
		}
		mPkg := pkgPath
		if fn.Pkg() != nil {
			mPkg = fn.Pkg().Path()
		}
		mName := fn.Name()
		if mName == "WriteTo" || mName == "ReadFrom" || (mPkg == "context" && mName == "Value") {
			continue
		}
		if signatureExposesMutableCarrier(audited, fn.Type(), walk) {
			return true
		}
	}
	return false
}

func signatureExposesMutableCarrier(audited bool, sigType types.Type, walk func(types.Type, bool, bool) bool) bool {
	sig, ok := types.Unalias(sigType).(*types.Signature)
	if !ok {
		return false
	}
	for j := 0; sig.Params() != nil && j < sig.Params().Len(); j++ {
		if typeMayCarryDynamicTop(audited, sig.Params().At(j).Type()) {
			return true
		}
	}
	for j := 0; sig.Results() != nil && j < sig.Results().Len(); j++ {
		rt := sig.Results().At(j).Type()
		_, resIface := types.Unalias(rt).Underlying().(*types.Interface)
		if walk(rt, false, !resIface) {
			return true
		}
	}
	return false
}

// isMutableStdCarrierAllocType reports whether a standard-library allocation t
// exposes mutable dynamic-carrier storage to callers outside the subject's cone:
// via whole-value overwrite of an addressable concrete-reachable carrier type
// (*p = *p2), an exported or promoted dynamic-carrying struct field, an exported
// method accepting a dynamic-carrying argument (excluding non-storing stream or
// lookup readers), or an exported method returning a reference-sharing slice,
// map, channel, pointer, or carrier-field handle (such as Unwrap() []error).
// concrete reports whether external callers hold t directly rather than boxed
// inside an interface by the standard library.
func isMutableStdCarrierAllocType(audited bool, t types.Type, concrete bool) bool {
	if t == nil {
		return false
	}
	seen := map[typeAccessKey]bool{}
	structSeen := map[typeAddrKey]bool{}
	var walk func(cur types.Type, addr, conc bool) bool
	var walkStructFields func(st *types.Struct, addr bool) bool
	walkStructFields = func(st *types.Struct, addr bool) bool {
		if st == nil {
			return false
		}
		sKey := typeAddrKey{t: st, addr: addr}
		if structSeen[sKey] {
			return false
		}
		structSeen[sKey] = true
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if f.Exported() {
				if (addr && typeMayCarryDynamicTop(audited, f.Type())) || walk(f.Type(), addr, true) {
					return true
				}
				continue
			}
			if f.Embedded() {
				ft := types.Unalias(f.Type())
				embAddr := addr
				if ptr, ok := ft.(*types.Pointer); ok {
					embAddr = true
					ft = types.Unalias(ptr.Elem())
				}
				if walk(f.Type(), addr, false) {
					return true
				}
				if embSt, ok := ft.Underlying().(*types.Struct); ok && walkStructFields(embSt, embAddr) {
					return true
				}
			}
		}
		return false
	}
	walk = func(cur types.Type, addr, conc bool) bool {
		if cur == nil {
			return false
		}
		if !conc && isTypeAssertableOutsidePkg(cur, map[types.Type]bool{}) {
			conc = true
		}
		cur = types.Unalias(cur)
		if ssaOpaqueHandle(cur) {
			return false
		}
		key := typeAccessKey{t: cur, addr: addr, concrete: conc}
		if seen[key] {
			return false
		}
		seen[key] = true
		switch tt := cur.(type) {
		case *types.Interface:
			if addr {
				return conc
			}
			return methodSetExposesMutableCarrier(audited, "", types.NewMethodSet(tt), walk)
		case *types.Signature:
			if !conc {
				return false
			}
			if addr {
				return true
			}
			return signatureExposesMutableCarrier(audited, tt, walk)
		case *types.Basic:
			return addr && conc && tt.Kind() == types.UnsafePointer
		case *types.Pointer:
			return walk(tt.Elem(), true, conc)
		case *types.Slice:
			if !conc {
				return false
			}
			return typeMayCarryDynamicTop(audited, tt.Elem()) || walk(tt.Elem(), true, true)
		case *types.Map:
			if !conc {
				return false
			}
			return typeMayCarryDynamicTop(audited, tt.Key()) || typeMayCarryDynamicTop(audited, tt.Elem()) || walk(tt.Key(), false, true) || walk(tt.Elem(), false, true)
		case *types.Chan:
			if !conc || tt.Dir() == types.RecvOnly {
				return false
			}
			return typeMayCarryDynamicTop(audited, tt.Elem()) || walk(tt.Elem(), false, true)
		case *types.Array:
			return walk(tt.Elem(), addr, conc)
		case *types.Struct:
			var mset *types.MethodSet
			if addr {
				mset = types.NewMethodSet(types.NewPointer(tt))
			} else {
				mset = types.NewMethodSet(tt)
			}
			if methodSetExposesMutableCarrier(audited, "", mset, walk) {
				return true
			}
			if !conc {
				return false
			}
			if addr && typeMayCarryDynamicTop(audited, tt) {
				return true
			}
			return walkStructFields(tt, addr)
		case *types.Named:
			obj := tt.Obj()
			if obj == nil {
				return false
			}
			if obj.Pkg() == nil {
				return walk(tt.Underlying(), addr, conc)
			}
			pkgPath := obj.Pkg().Path()
			if iface, isIface := tt.Underlying().(*types.Interface); isIface {
				if addr {
					return conc
				}
				return methodSetExposesMutableCarrier(audited, pkgPath, types.NewMethodSet(iface), walk)
			}
			if addr && conc && typeMayCarryDynamicTop(audited, tt) {
				return true
			}
			var mset *types.MethodSet
			if addr {
				mset = types.NewMethodSet(types.NewPointer(tt))
			} else {
				mset = types.NewMethodSet(tt)
			}
			if methodSetExposesMutableCarrier(audited, pkgPath, mset, walk) {
				return true
			}
			if !conc {
				return false
			}
			if st, isStruct := tt.Underlying().(*types.Struct); isStruct {
				return walkStructFields(st, addr)
			}
			return walk(tt.Underlying(), addr, true)
		}
		return false
	}
	return walk(t, false, concrete)
}
