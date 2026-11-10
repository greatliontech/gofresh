package syntaxutil

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
)

// UnderlyingType returns the underlying type of t after unaliasing, or nil
// when t is nil.
func UnderlyingType(t types.Type) types.Type {
	if t = types.Unalias(t); t != nil {
		return t.Underlying()
	}
	return nil
}

// RecvTypeName returns a method declaration's receiver type name with any
// leading pointer star and generic type parameters stripped, or "" for a plain
// function or unnameable receiver.
func RecvTypeName(fd *ast.FuncDecl) string {
	if fd == nil || fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	t := fd.Recv.List[0].Type
	for {
		switch e := t.(type) {
		case *ast.ParenExpr:
			t = e.X
		case *ast.StarExpr:
			t = e.X
		case *ast.IndexExpr:
			t = e.X
		case *ast.IndexListExpr:
			t = e.X
		case *ast.Ident:
			return e.Name
		default:
			return ""
		}
	}
}

// MethodRecvNamedTypeName returns the declared receiver type's bare name
// (unwrapping pointer indirection and aliases), or "" when fn has no named
// receiver.
func MethodRecvNamedTypeName(fn *types.Func) string {
	if fn == nil {
		return ""
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return ""
	}
	t := types.Unalias(sig.Recv().Type())
	if pointer, ok := t.(*types.Pointer); ok {
		t = types.Unalias(pointer.Elem())
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj() == nil {
		return ""
	}
	return named.Obj().Name()
}

// RecvTypeNameOf resolves the receiver type name of a selection's method
// through its declaring type, mirroring RecvTypeName's shape.
func RecvTypeNameOf(p *packages.Package, sel *ast.SelectorExpr) string {
	if p == nil || p.TypesInfo == nil || sel == nil {
		return ""
	}
	selection, ok := p.TypesInfo.Selections[sel]
	if !ok {
		return ""
	}
	fn, ok := selection.Obj().(*types.Func)
	if !ok {
		return ""
	}
	return MethodRecvNamedTypeName(fn)
}

// InterfaceReceiver reports whether fn's receiver is absent or an interface.
func InterfaceReceiver(fn *types.Func) bool {
	if fn == nil {
		return true
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return true
	}
	t := types.Unalias(sig.Recv().Type())
	if pointer, ok := t.(*types.Pointer); ok {
		t = types.Unalias(pointer.Elem())
	}
	_, isInterface := t.Underlying().(*types.Interface)
	return isInterface
}

// DerefNamedStruct unaliases t, dereferences at most one *types.Pointer, and
// returns the *types.Named if it is a package-qualified named struct type.
func DerefNamedStruct(t types.Type) *types.Named {
	if t == nil {
		return nil
	}
	t = types.Unalias(t)
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	n, ok := t.(*types.Named)
	if !ok || n.Obj() == nil || n.Obj().Pkg() == nil {
		return nil
	}
	if _, isSt := n.Underlying().(*types.Struct); !isSt {
		return nil
	}
	return n
}

// ForEachSelectionHopStruct visits the receiver struct and every intermediate
// embedded struct traversed along selInfo.Index() before reaching the selected
// field or method.
func ForEachSelectionHopStruct(selInfo *types.Selection, visit func(*types.Named)) {
	if selInfo == nil {
		return
	}
	cur := DerefNamedStruct(selInfo.Recv())
	if cur == nil {
		return
	}
	visit(cur)
	indices := selInfo.Index()
	for i := 0; i+1 < len(indices); i++ {
		st, ok := cur.Underlying().(*types.Struct)
		if !ok || indices[i] < 0 || indices[i] >= st.NumFields() {
			return
		}
		cur = DerefNamedStruct(st.Field(indices[i]).Type())
		if cur == nil {
			return
		}
		visit(cur)
	}
}

// SelectionCrossesEmbeddedPointer reports whether any intermediate embedded
// field along selInfo.Index() before the final field is a pointer type.
func SelectionCrossesEmbeddedPointer(selInfo *types.Selection) bool {
	if selInfo == nil || len(selInfo.Index()) <= 1 {
		return false
	}
	cur := DerefNamedStruct(selInfo.Recv())
	if cur == nil {
		return false
	}
	indices := selInfo.Index()
	for i := 0; i+1 < len(indices); i++ {
		st, ok := cur.Underlying().(*types.Struct)
		if !ok || indices[i] < 0 || indices[i] >= st.NumFields() {
			return true
		}
		ft := types.Unalias(st.Field(indices[i]).Type())
		if _, isPtr := ft.(*types.Pointer); isPtr {
			return true
		}
		cur = DerefNamedStruct(ft)
		if cur == nil {
			return false
		}
	}
	return false
}

// ForEachValueContainedNamedStruct visits every named struct type stored by
// value inside root (recursing into value struct fields and arrays without
// crossing pointers, slices, maps, or channels).
func ForEachValueContainedNamedStruct(root types.Type, visit func(*types.Named)) {
	seen := map[types.Type]bool{}
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		if n, ok := t.(*types.Named); ok && n.Obj() != nil && n.Obj().Pkg() != nil {
			if _, isSt := n.Underlying().(*types.Struct); isSt {
				visit(n)
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		case *types.Array:
			walk(u.Elem())
		}
	}
	walk(root)
}

// IsNamedInPkg reports whether t (after unaliasing) is a *types.Named declared
// in pkgPath with the given unqualified name.
func IsNamedInPkg(t types.Type, pkgPath, name string) bool {
	if t == nil {
		return false
	}
	n, ok := types.Unalias(t).(*types.Named)
	return ok && n.Obj() != nil && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == pkgPath && n.Obj().Name() == name
}

// IsPtrToNamed reports whether t (after unaliasing) is a pointer to want.
func IsPtrToNamed(t types.Type, want *types.Named) bool {
	if t == nil || want == nil {
		return false
	}
	ptr, ok := types.Unalias(t).(*types.Pointer)
	return ok && types.Identical(types.Unalias(ptr.Elem()), want)
}

// IsReflectType reports whether t (after unaliasing) is reflect.Type.
func IsReflectType(t types.Type) bool {
	return IsNamedInPkg(t, "reflect", "Type")
}

// IsSyncMutexOrRWMutex reports whether t (after unaliasing) is sync.Mutex or sync.RWMutex.
func IsSyncMutexOrRWMutex(t types.Type) bool {
	return IsNamedInPkg(t, "sync", "Mutex") || IsNamedInPkg(t, "sync", "RWMutex")
}

// IsSyncOnceType reports whether t (after unaliasing) is sync.Once.
func IsSyncOnceType(t types.Type) bool {
	return IsNamedInPkg(t, "sync", "Once")
}

// IsUnsafePointerType reports whether t's underlying type is unsafe.Pointer.
func IsUnsafePointerType(t types.Type) bool {
	b, ok := UnderlyingType(t).(*types.Basic)
	return ok && b.Kind() == types.UnsafePointer
}

// IsErrorType reports whether t is identical to the predeclared error type.
func IsErrorType(t types.Type) bool {
	if t == nil {
		return false
	}
	return types.Identical(types.Unalias(t), types.Universe.Lookup("error").Type())
}

// ContainsUintptr reports whether root is uintptr or a value-contained struct
// or array recursively containing uintptr.
func ContainsUintptr(root types.Type) bool {
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
		switch u := t.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.Uintptr {
				hit = true
			}
		case *types.Array:
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		}
	}
	walk(root)
	return hit
}

// IsAnySliceType reports whether t's underlying type is []any.
func IsAnySliceType(t types.Type) bool {
	if t == nil {
		return false
	}
	sl, ok := UnderlyingType(t).(*types.Slice)
	if !ok {
		return false
	}
	iface, ok := UnderlyingType(sl.Elem()).(*types.Interface)
	return ok && iface.NumMethods() == 0
}

// IsByteSliceType reports whether t's underlying type is []byte.
func IsByteSliceType(t types.Type) bool {
	if t == nil {
		return false
	}
	sl, ok := UnderlyingType(t).(*types.Slice)
	if !ok {
		return false
	}
	b, ok := UnderlyingType(sl.Elem()).(*types.Basic)
	return ok && b.Kind() == types.Byte
}

// StructHasExportedIfaceField reports whether st has an exported interface-typed
// field with the given name.
func StructHasExportedIfaceField(st *types.Struct, name string) bool {
	if st == nil {
		return false
	}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Exported() && f.Name() == name && types.IsInterface(f.Type()) {
			return true
		}
	}
	return false
}

// IsStandardLibraryPkgPath reports whether pkgPath has no dot in its first path
// segment.
func IsStandardLibraryPkgPath(pkgPath string) bool {
	if pkgPath == "" {
		return false
	}
	first, _, _ := strings.Cut(pkgPath, "/")
	return !strings.Contains(first, ".")
}


// IsReadOnlyEmptyInterfaceCallee reports whether fn is a standard-library
// function whose empty-interface parameters are inspected without mutation.
func IsReadOnlyEmptyInterfaceCallee(fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	pkgPath := fn.Pkg().Path()
	firstSeg, _, _ := strings.Cut(pkgPath, "/")
	if strings.Contains(firstSeg, ".") {
		return false
	}
	switch pkgPath {
	case "sync", "sync/atomic", "errors", "log", "log/slog", "testing", "runtime", "context", "cmp":
		return true
	case "reflect":
		return fn.Name() == "TypeOf" || fn.Name() == "DeepEqual"
	case "fmt":
		switch fn.Name() {
		case "Scan", "Scanf", "Scanln", "Fscan", "Fscanf", "Fscanln", "Sscan", "Sscanf", "Sscanln":
			return false
		default:
			return true
		}
	}
	return false
}

// TypeMentionsTypeParam reports whether root recursively mentions any
// *types.TypeParam.
func TypeMentionsTypeParam(root types.Type) bool {
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
		if _, isTP := t.(*types.TypeParam); isTP {
			hit = true
			return
		}
		if seen[t] {
			return
		}
		seen[t] = true
		if named, isNamed := t.(*types.Named); isNamed {
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

