package syntaxutil

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"go/types"
	"strconv"
	"strings"
)

const unnamedStructPkgSentinel = "@struct"

// TypeRef identifies a package-level named Go struct type by package import path
// and unqualified type name after unaliasing, or a non-empty unnamed Go struct
// type (including type aliases to unnamed structs such as protoiface.Methods)
// by "@struct" and its canonical tag-ignoring structural SHA-256 digest.
type TypeRef struct {
	Pkg  string `json:"pkg"`
	Name string `json:"name"`
}

// IsZero reports whether r is the empty TypeRef.
func (r TypeRef) IsZero() bool {
	return r.Pkg == "" && r.Name == ""
}

// Valid reports whether r names a non-empty package path and unqualified type
// identifier free of NUL separators.
func (r TypeRef) Valid() bool {
	return r.Pkg != "" && !strings.ContainsRune(r.Pkg, 0) &&
		r.Name != "" && !strings.ContainsAny(r.Name, "\x00.")
}

// Key returns the dot-joined string key of r.
func (r TypeRef) Key() string {
	return r.Pkg + "." + r.Name
}

// TypeRefOfStruct returns the canonical TypeRef for a package-level named struct
// or a non-empty unnamed struct type (after unaliasing and optional single pointer
// dereference). Function-local named structs and zero-field unnamed structs return false.
func TypeRefOfStruct(t types.Type) (TypeRef, bool) {
	ref, _, _, ok := TypeRefOfStructFull(t)
	return ref, ok
}

// TypeRefOfNamedStruct returns the TypeRef and *types.Named for a package-scope
// named struct type (after unaliasing and optional single pointer dereference).
func TypeRefOfNamedStruct(t types.Type) (TypeRef, *types.Named, bool) {
	n := DerefNamedStruct(t)
	if n == nil || n.Obj() == nil || n.Obj().Pkg() == nil {
		return TypeRef{}, nil, false
	}
	if n.Obj().Parent() != n.Obj().Pkg().Scope() {
		return TypeRef{}, nil, false
	}
	ref := TypeRef{Pkg: n.Obj().Pkg().Path(), Name: n.Obj().Name()}
	if !ref.Valid() {
		return TypeRef{}, nil, false
	}
	return ref, n, true
}

// TypeRefOfStructFull returns the TypeRef, optional *types.Named, and underlying
// *types.Struct for a package-scope named struct or non-empty unnamed struct.
func TypeRefOfStructFull(t types.Type) (TypeRef, *types.Named, *types.Struct, bool) {
	if t == nil {
		return TypeRef{}, nil, nil, false
	}
	t = types.Unalias(t)
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	switch u := t.(type) {
	case *types.Named:
		if u.Obj() == nil || u.Obj().Pkg() == nil || u.Obj().Parent() != u.Obj().Pkg().Scope() {
			return TypeRef{}, nil, nil, false
		}
		st, isSt := u.Underlying().(*types.Struct)
		if !isSt {
			return TypeRef{}, nil, nil, false
		}
		ref := TypeRef{Pkg: u.Obj().Pkg().Path(), Name: u.Obj().Name()}
		if !ref.Valid() {
			return TypeRef{}, nil, nil, false
		}
		return ref, u, st, true
	case *types.Struct:
		if u.NumFields() == 0 {
			return TypeRef{}, nil, nil, false
		}
		ref, ok := unnamedStructTypeRef(u)
		if !ok {
			return TypeRef{}, nil, nil, false
		}
		return ref, nil, u, true
	}
	return TypeRef{}, nil, nil, false
}

func unnamedStructTypeRef(st *types.Struct) (TypeRef, bool) {
	if st == nil || st.NumFields() == 0 {
		return TypeRef{}, false
	}
	var b strings.Builder
	if !writeCanonicalType(&b, st, map[types.Type]int{}) {
		return TypeRef{}, false
	}
	sum := sha256.Sum256([]byte(b.String()))
	return TypeRef{Pkg: unnamedStructPkgSentinel, Name: hex.EncodeToString(sum[:])}, true
}

func writeCanonicalType(b *strings.Builder, t types.Type, visiting map[types.Type]int) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	switch u := t.(type) {
	case *types.Basic:
		if u.Kind() == types.Invalid {
			return false
		}
		b.WriteString("B:")
		b.WriteString(strconv.Itoa(int(u.Kind())))
		b.WriteByte(';')
		return true
	case *types.Named:
		obj := u.Obj()
		if obj == nil {
			return false
		}
		if obj.Pkg() == nil {
			b.WriteString("U:")
			b.WriteString(obj.Name())
		} else {
			if obj.Parent() != obj.Pkg().Scope() {
				return false
			}
			b.WriteString("N:")
			b.WriteString(obj.Pkg().Path())
			b.WriteByte('.')
			b.WriteString(obj.Name())
		}
		if targs := u.TypeArgs(); targs.Len() > 0 {
			b.WriteByte('[')
			for i := 0; i < targs.Len(); i++ {
				if i > 0 {
					b.WriteByte(',')
				}
				if !writeCanonicalType(b, targs.At(i), visiting) {
					return false
				}
			}
			b.WriteByte(']')
		}
		b.WriteByte(';')
		return true
	case *types.Pointer:
		b.WriteByte('*')
		return writeCanonicalType(b, u.Elem(), visiting)
	case *types.Slice:
		b.WriteString("[]")
		return writeCanonicalType(b, u.Elem(), visiting)
	case *types.Array:
		b.WriteByte('[')
		b.WriteString(strconv.FormatInt(u.Len(), 10))
		b.WriteByte(']')
		return writeCanonicalType(b, u.Elem(), visiting)
	case *types.Map:
		b.WriteString("map[")
		if !writeCanonicalType(b, u.Key(), visiting) {
			return false
		}
		b.WriteByte(']')
		return writeCanonicalType(b, u.Elem(), visiting)
	case *types.Chan:
		b.WriteString("chan(")
		b.WriteString(strconv.Itoa(int(u.Dir())))
		b.WriteString("):")
		return writeCanonicalType(b, u.Elem(), visiting)
	case *types.Struct:
		if id, active := visiting[t]; active {
			b.WriteString("cycle:")
			b.WriteString(strconv.Itoa(id))
			b.WriteByte(';')
			return true
		}
		nextID := len(visiting) + 1
		visiting[t] = nextID
		defer delete(visiting, t)
		b.WriteString("struct{")
		for i := 0; i < u.NumFields(); i++ {
			f := u.Field(i)
			if f.Embedded() {
				b.WriteString("1:")
			} else {
				b.WriteString("0:")
			}
			if !f.Exported() {
				if f.Pkg() == nil {
					return false
				}
				b.WriteString(f.Pkg().Path())
				b.WriteByte('.')
			}
			b.WriteString(f.Name())
			b.WriteByte(':')
			if !writeCanonicalType(b, f.Type(), visiting) {
				return false
			}
			b.WriteByte(';')
		}
		b.WriteByte('}')
		return true
	case *types.Signature:
		if u.TypeParams().Len() > 0 || u.RecvTypeParams().Len() > 0 {
			return false
		}
		if u.Variadic() {
			b.WriteString("func...(")
		} else {
			b.WriteString("func(")
		}
		if params := u.Params(); params != nil {
			for i := 0; i < params.Len(); i++ {
				if !writeCanonicalType(b, params.At(i).Type(), visiting) {
					return false
				}
				b.WriteByte(',')
			}
		}
		b.WriteString(")(")
		if results := u.Results(); results != nil {
			for i := 0; i < results.Len(); i++ {
				if !writeCanonicalType(b, results.At(i).Type(), visiting) {
					return false
				}
				b.WriteByte(',')
			}
		}
		b.WriteByte(')')
		return true
	case *types.Interface:
		if !u.IsMethodSet() {
			return false
		}
		if id, active := visiting[t]; active {
			b.WriteString("icycle:")
			b.WriteString(strconv.Itoa(id))
			b.WriteByte(';')
			return true
		}
		nextID := len(visiting) + 1
		visiting[t] = nextID
		defer delete(visiting, t)
		b.WriteString("interface{")
		for i := 0; i < u.NumMethods(); i++ {
			m := u.Method(i)
			if !m.Exported() {
				if m.Pkg() == nil {
					return false
				}
				b.WriteString(m.Pkg().Path())
				b.WriteByte('.')
			}
			b.WriteString(m.Name())
			b.WriteByte(':')
			if !writeCanonicalType(b, m.Type(), visiting) {
				return false
			}
			b.WriteByte(';')
		}
		b.WriteByte('}')
		return true
	}
	return false
}

// DerefAnyStructType unaliases t, dereferences at most one *types.Pointer, and
// returns the struct type (named or unnamed) and its underlying *types.Struct.
func DerefAnyStructType(t types.Type) (types.Type, *types.Struct) {
	if t == nil {
		return nil, nil
	}
	t = types.Unalias(t)
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	if st, ok := t.Underlying().(*types.Struct); ok {
		return t, st
	}
	return nil, nil
}

// ForEachSelectionHopStructType visits the receiver struct type and every
// intermediate embedded struct type traversed along selInfo.Index() before
// reaching the selected field or method.
func ForEachSelectionHopStructType(selInfo *types.Selection, visit func(types.Type)) {
	if selInfo == nil {
		return
	}
	curType, st := DerefAnyStructType(selInfo.Recv())
	if curType == nil || st == nil {
		return
	}
	visit(curType)
	indices := selInfo.Index()
	for i := 0; i+1 < len(indices); i++ {
		if indices[i] < 0 || indices[i] >= st.NumFields() {
			return
		}
		curType, st = DerefAnyStructType(st.Field(indices[i]).Type())
		if curType == nil || st == nil {
			return
		}
		visit(curType)
	}
}

// ForEachValueContainedStructType visits every struct type (named or unnamed)
// stored by value inside root (recursing into value struct fields and arrays).
func ForEachValueContainedStructType(root types.Type, visit func(types.Type)) {
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
		if st, isSt := t.Underlying().(*types.Struct); isSt {
			visit(t)
			for i := 0; i < st.NumFields(); i++ {
				walk(st.Field(i).Type())
			}
			return
		}
		if arr, isArr := t.Underlying().(*types.Array); isArr {
			walk(arr.Elem())
		}
	}
	walk(root)
}

// SliceElemNamedStruct returns the TypeRef and *types.Named of a slice's
// by-value named struct element type.
func SliceElemNamedStruct(t types.Type) (TypeRef, *types.Named, bool) {
	if t == nil {
		return TypeRef{}, nil, false
	}
	sl, ok := UnderlyingType(t).(*types.Slice)
	if !ok {
		return TypeRef{}, nil, false
	}
	if _, isPtr := types.Unalias(sl.Elem()).(*types.Pointer); isPtr {
		return TypeRef{}, nil, false
	}
	return TypeRefOfNamedStruct(sl.Elem())
}

// SliceElemStructRef returns the TypeRef of a slice's by-value named struct
// element type.
func SliceElemStructRef(t types.Type) (TypeRef, bool) {
	ref, _, ok := SliceElemNamedStruct(t)
	return ref, ok
}

// ConditionalStructMutation records that Struct must be treated as mutated if
// GuardPkg can retain pointer/interface carriers after init, if GuardStruct is
// itself mutated in the composed cone, if RequireDescBuilderGuard is set and
// GuardStruct is not covered by a verified ProtoRoleDescBuilder in its
// declaring package, or if RequireNonMutatingMethod is set and that method is
// not proven non-mutating across all variants of its declaring package.
type ConditionalStructMutation struct {
	Struct                   TypeRef `json:"struct"`
	GuardPkg                 string  `json:"guardPkg,omitempty"`
	GuardStruct              TypeRef `json:"guardStruct,omitempty"`
	RequireDescBuilderGuard  bool    `json:"requireDescBuilderGuard,omitempty"`
	RequireNonMutatingMethod FuncKey `json:"requireNonMutatingMethod,omitempty"`
}

func (c ConditionalStructMutation) Valid() bool {
	if !c.Struct.Valid() {
		return false
	}
	if c.RequireDescBuilderGuard && c.GuardStruct.IsZero() {
		return false
	}
	modes := 0
	if c.GuardPkg != "" {
		if !ValidNonEmptyPkgKey(c.GuardPkg) {
			return false
		}
		modes++
	}
	if !c.GuardStruct.IsZero() {
		if !c.GuardStruct.Valid() {
			return false
		}
		modes++
	}
	if !c.RequireNonMutatingMethod.IsZero() {
		if !c.RequireNonMutatingMethod.Valid() {
			return false
		}
		modes++
	}
	return modes == 1
}

func (c ConditionalStructMutation) Compare(o ConditionalStructMutation) int {
	if d := cmp.Compare(c.Struct.Key(), o.Struct.Key()); d != 0 {
		return d
	}
	if d := cmp.Compare(c.GuardPkg, o.GuardPkg); d != 0 {
		return d
	}
	if d := cmp.Compare(c.GuardStruct.Key(), o.GuardStruct.Key()); d != 0 {
		return d
	}
	if c.RequireDescBuilderGuard != o.RequireDescBuilderGuard {
		if !c.RequireDescBuilderGuard {
			return -1
		}
		return 1
	}
	return c.RequireNonMutatingMethod.Compare(o.RequireNonMutatingMethod)
}

// ValidFactKey reports whether k is non-empty and free of NUL bytes.
func ValidFactKey(k string) bool {
	return k != "" && !strings.Contains(k, "\x00")
}

// ValidQualifiedVarKey reports whether k is a package-qualified variable key
// ("pkg/path.VarName") free of NUL bytes.
func ValidQualifiedVarKey(k string) bool {
	if strings.Contains(k, "\x00") {
		return false
	}
	dot := strings.LastIndexByte(k, '.')
	return dot > 0 && dot < len(k)-1
}

// ValidNonEmptyPkgKey reports whether pkg is a non-empty package path free of
// NUL and whitespace characters.
func ValidNonEmptyPkgKey(pkg string) bool {
	return pkg != "" && !strings.ContainsRune(pkg, 0) && !strings.ContainsAny(pkg, " \t\r\n")
}

// DynamicVarKey returns the canonical "pkg/path.Name" key for variable.
func DynamicVarKey(variable *types.Var) string {
	if variable == nil {
		return ""
	}
	if variable.Pkg() == nil {
		return variable.Name()
	}
	return variable.Pkg().Path() + "." + variable.Name()
}
