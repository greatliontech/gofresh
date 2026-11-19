package syntaxutil

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"go/types"
	"slices"
	"strconv"
	"strings"
)

const unnamedStructPkgSentinel = "@struct"

// TypeRef identifies a package-level named Go struct type by package import path
// and unqualified type name after unaliasing, or a non-empty unnamed Go struct
// type (including type aliases to unnamed structs) by "@struct" and its
// canonical tag-ignoring structural SHA-256 digest.
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

// IsUnnamed reports whether r identifies an unnamed structural struct digest.
func (r TypeRef) IsUnnamed() bool {
	return r.Pkg == unnamedStructPkgSentinel
}

// Compare orders TypeRefs lexicographically by (Pkg, Name).
func (r TypeRef) Compare(o TypeRef) int {
	if c := cmp.Compare(r.Pkg, o.Pkg); c != 0 {
		return c
	}
	return cmp.Compare(r.Name, o.Name)
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
// itself mutated in the composed cone, if RequireImmutableCapsuleGuard is set
// and GuardStruct is not covered by a verified raw immutable-capsule builder in
// its declaring package, or if RequireNonMutatingMethod is set and that method
// is not proven non-mutating across all variants of its declaring package.
type ConditionalStructMutation struct {
	Struct                       TypeRef  `json:"struct"`
	GuardPkg                     string   `json:"guardPkg,omitempty"`
	GuardStruct                  TypeRef  `json:"guardStruct,omitempty"`
	RequireImmutableCapsuleGuard bool     `json:"requireImmutableCapsuleGuard,omitempty"`
	RequireNonMutatingMethod     FuncKey  `json:"requireNonMutatingMethod,omitempty"`
	BoxedConcreteMethodSet       string   `json:"boxedConcreteMethodSet,omitempty"`
	ForeignReflectPkg            string   `json:"foreignReflectPkg,omitempty"`
	UnlessSafeCapsuleStruct      TypeRef  `json:"unlessSafeCapsuleStruct,omitempty"`
	UnlessSafeCapsuleParam       ParamKey `json:"unlessSafeCapsuleParam,omitempty"`
	UnlessSafeAtomicPtrCopy      FuncKey  `json:"unlessSafeAtomicPtrCopy,omitempty"`
}

func (c ConditionalStructMutation) Valid() bool {
	if !c.Struct.Valid() {
		return false
	}
	if c.RequireImmutableCapsuleGuard && c.GuardStruct.IsZero() {
		return false
	}
	if c.ForeignReflectPkg != "" && !ValidNonEmptyPkgKey(c.ForeignReflectPkg) {
		return false
	}
	if c.UnlessSafeCapsuleStruct.IsZero() != c.UnlessSafeCapsuleParam.IsZero() {
		return false
	}
	if !c.UnlessSafeCapsuleStruct.IsZero() && (!c.UnlessSafeCapsuleStruct.Valid() || !c.UnlessSafeCapsuleParam.Valid() || c.ForeignReflectPkg != "" || !c.UnlessSafeAtomicPtrCopy.IsZero()) {
		return false
	}
	if !c.UnlessSafeAtomicPtrCopy.IsZero() && (!c.UnlessSafeAtomicPtrCopy.Valid() || c.ForeignReflectPkg != "") {
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
	if c.BoxedConcreteMethodSet != "" {
		if !ValidMethodSetKey(c.BoxedConcreteMethodSet) && !ValidFlagROBypassMethodSetKey(c.BoxedConcreteMethodSet) {
			return false
		}
		if !c.UnlessSafeCapsuleStruct.IsZero() || !c.UnlessSafeAtomicPtrCopy.IsZero() {
			return false
		}
		modes++
	} else if c.ForeignReflectPkg != "" || !c.UnlessSafeCapsuleStruct.IsZero() || !c.UnlessSafeAtomicPtrCopy.IsZero() {
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
	if c.RequireImmutableCapsuleGuard != o.RequireImmutableCapsuleGuard {
		if !c.RequireImmutableCapsuleGuard {
			return -1
		}
		return 1
	}
	if d := c.RequireNonMutatingMethod.Compare(o.RequireNonMutatingMethod); d != 0 {
		return d
	}
	if d := cmp.Compare(c.BoxedConcreteMethodSet, o.BoxedConcreteMethodSet); d != 0 {
		return d
	}
	if d := cmp.Compare(c.ForeignReflectPkg, o.ForeignReflectPkg); d != 0 {
		return d
	}
	if d := cmp.Compare(c.UnlessSafeCapsuleStruct.Key(), o.UnlessSafeCapsuleStruct.Key()); d != 0 {
		return d
	}
	if d := c.UnlessSafeCapsuleParam.Compare(o.UnlessSafeCapsuleParam); d != 0 {
		return d
	}
	return c.UnlessSafeAtomicPtrCopy.Compare(o.UnlessSafeAtomicPtrCopy)
}

func canonicalMethodID(fn *types.Func, sigType types.Type) string {
	if fn == nil {
		return ""
	}
	base := fn.Name()
	if !fn.Exported() && fn.Pkg() != nil {
		base = fn.Pkg().Path() + "." + fn.Name()
	}
	if sig, ok := types.Unalias(sigType).(*types.Signature); ok {
		var b strings.Builder
		if writeCanonicalType(&b, sig, map[types.Type]int{}) {
			sum := sha256.Sum256([]byte(b.String()))
			return base + ":" + hex.EncodeToString(sum[:16])
		}
	}
	return base
}

// IfaceMethodSetKey returns a canonical '\x1f'-delimited strictly sorted key of
// method identifiers for a non-empty interface, or "" when iface is nil or empty.
func IfaceMethodSetKey(iface *types.Interface) string {
	if iface == nil || iface.NumMethods() == 0 {
		return ""
	}
	ids := make([]string, 0, iface.NumMethods())
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		if id := canonicalMethodID(m, m.Type()); id != "" {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	return strings.Join(ids, "\x1f")
}

// ConcreteMethodSetKey returns a canonical '\x1f'-delimited strictly sorted key
// of method identifiers in types.NewMethodSet(t), or "" if t has zero methods.
func ConcreteMethodSetKey(t types.Type) string {
	if t == nil {
		return ""
	}
	mset := types.NewMethodSet(t)
	if mset.Len() == 0 {
		return ""
	}
	ids := make([]string, 0, mset.Len())
	for i := 0; i < mset.Len(); i++ {
		sel := mset.At(i)
		if fn, ok := sel.Obj().(*types.Func); ok {
			if id := canonicalMethodID(fn, sel.Type()); id != "" {
				ids = append(ids, id)
			}
		}
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	return strings.Join(ids, "\x1f")
}

// EmptyIfaceMethodSetKey is the sentinel MethodSet key on ReflectedIfaceFact
// recording that a package can reflectively mutate, pass to a non-read-only
// stdlib empty-interface sink, or upward-leak an empty-interface (any) value.
const EmptyIfaceMethodSetKey = "*"

// ReflectFlagROBypassPrefix prefixes a method-set key when unexported
// struct-field carriers require both matching interface reflection and a
// reflect flagRO bypass capability (e.g. Value.UnsafePointer, Value.UnsafeAddr,
// Value.Bytes, Value.Clear, or field-derived Value.Pointer/InterfaceData + unsafe).
const ReflectFlagROBypassPrefix = "**|"

// ReflectFlagROBypassAnyKey is the sentinel MethodSet key recording that a
// package can reflectively mutate an empty-interface (any) value while
// bypassing reflect's unexported-field flagRO guard.
const ReflectFlagROBypassAnyKey = "**|*"

// ReflectFlagROLocalBypassKey is the sentinel MethodSet key recording that a
// package invokes a reflect.Value operation capable of bypassing flagRO on an
// unexported struct field (e.g. UnsafePointer, UnsafeAddr, Bytes, Clear, or
// Pointer/InterfaceData + unsafe).
const ReflectFlagROLocalBypassKey = "**|!"

// ReflectRawUintptrToPtrKey is the sentinel MethodSet key recording that a
// package converts a non-zero uintptr-underlying value outside verified capsule
// offset arithmetic into an unsafe.Pointer-underlying type, enabling pointer
// reconstruction from formatted or integer address bits.
const ReflectRawUintptrToPtrKey = "**|^"

// ContextKeyTheftMethodSetKey is the sentinel MethodSet key guarding values
// stored under confined unexported context.WithValue keys when a non-stdlib
// context.Context implementation defines a non-leak-free Value(any) any method.
const ContextKeyTheftMethodSetKey = "**|ctx"

// ContextKeyTheftFlagROKey is the sentinel BoxedConcreteMethodSet key guarding
// unexported fields of values stored under confined context.WithValue keys when
// both ContextKeyTheftMethodSetKey and flagRO bypass hold in the cone.
const ContextKeyTheftFlagROKey = "**|ctx*"

// ValidMethodSetKey reports whether s is a non-empty '\x1f'-delimited strictly
// sorted sequence of non-empty NUL-free, '*'-free method identifiers.
func ValidMethodSetKey(s string) bool {
	if s == "" || strings.Contains(s, "\x00") || strings.Contains(s, "*") {
		return false
	}
	prev := ""
	for i, part := range strings.Split(s, "\x1f") {
		if part == "" || (i > 0 && part <= prev) {
			return false
		}
		prev = part
	}
	return true
}

// ValidFlagROBypassMethodSetKey reports whether s is one of the "**|" sentinel
// keys or ReflectFlagROBypassPrefix followed by a ValidMethodSetKey.
func ValidFlagROBypassMethodSetKey(s string) bool {
	switch s {
	case ReflectFlagROBypassAnyKey, ReflectFlagROLocalBypassKey, ReflectRawUintptrToPtrKey, ContextKeyTheftMethodSetKey, ContextKeyTheftFlagROKey:
		return true
	}
	rest, ok := strings.CutPrefix(s, ReflectFlagROBypassPrefix)
	return ok && ValidMethodSetKey(rest)
}

// ReflectedIfaceFact records that non-empty interface values matching MethodSet
// are reflected via reflect.ValueOf (or erased to any and potentially reflected),
// optionally gated on at least one imported parameter in UnlessParamLeakFree
// lacking a ParamLeakFree proof, or a package-level capability sentinel.
type ReflectedIfaceFact struct {
	MethodSet                  string     `json:"methodSet"`
	UnlessParamLeakFree        []ParamKey `json:"unlessParamLeakFree,omitempty"`
	UnlessSafeCapsuleStruct    TypeRef    `json:"unlessSafeCapsuleStruct,omitempty"`
	UnlessSafeCapsuleParam     ParamKey   `json:"unlessSafeCapsuleParam,omitempty"`
	UnlessSafeAtomicPtrCopy    FuncKey    `json:"unlessSafeAtomicPtrCopy,omitempty"`
	ErasedToEmptyIface         bool       `json:"erasedToEmptyIface,omitempty"`
	ReflectsEmptyIfaceLocally  bool       `json:"reflectsEmptyIfaceLocally,omitempty"`
	LeaksEmptyIfaceUpward      bool       `json:"leaksEmptyIfaceUpward,omitempty"`
	ReflectValueBoundaryEscape bool       `json:"reflectValueBoundaryEscape,omitempty"`
	UnexportedIfaceField       bool       `json:"unexportedIfaceField,omitempty"`
	ContextValueBoxed          string     `json:"contextValueBoxed,omitempty"`
	UnsafePtrCarrierBoxed      string     `json:"unsafePtrCarrierBoxed,omitempty"`
	NestedInConcreteBox        string     `json:"nestedInConcreteBox,omitempty"`
	NestedOpaqueStruct         TypeRef    `json:"nestedOpaqueStruct,omitempty"`
	NestedOpaqueOwnerPkg       string     `json:"nestedOpaqueOwnerPkg,omitempty"`
}

func (f ReflectedIfaceFact) Valid() bool {
	if f.UnlessSafeCapsuleStruct.IsZero() != f.UnlessSafeCapsuleParam.IsZero() {
		return false
	}
	if !f.UnlessSafeCapsuleStruct.IsZero() && (!f.UnlessSafeCapsuleStruct.Valid() || !f.UnlessSafeCapsuleParam.Valid() || !f.UnlessSafeAtomicPtrCopy.IsZero()) {
		return false
	}
	if !f.UnlessSafeAtomicPtrCopy.IsZero() && !f.UnlessSafeAtomicPtrCopy.Valid() {
		return false
	}
	if !f.NestedOpaqueStruct.IsZero() {
		if !f.NestedOpaqueStruct.Valid() || f.NestedInConcreteBox == "" || !f.UnexportedIfaceField || f.NestedOpaqueOwnerPkg != "" {
			return false
		}
	}
	if f.NestedOpaqueOwnerPkg != "" {
		if !ValidNonEmptyPkgKey(f.NestedOpaqueOwnerPkg) || f.UnsafePtrCarrierBoxed == "" || f.UnexportedIfaceField || !f.NestedOpaqueStruct.IsZero() {
			return false
		}
	}
	hasCapsuleOrCopyGuard := !f.UnlessSafeCapsuleStruct.IsZero() || !f.UnlessSafeAtomicPtrCopy.IsZero()
	if f.NestedInConcreteBox != "" {
		return ValidMethodSetKey(f.NestedInConcreteBox) &&
			(ValidMethodSetKey(f.MethodSet) || (f.MethodSet == EmptyIfaceMethodSetKey && !f.UnexportedIfaceField)) &&
			len(f.UnlessParamLeakFree) == 0 && !hasCapsuleOrCopyGuard &&
			f.ContextValueBoxed == "" && f.UnsafePtrCarrierBoxed == "" &&
			!f.ErasedToEmptyIface && !f.ReflectsEmptyIfaceLocally && !f.LeaksEmptyIfaceUpward &&
			!f.ReflectValueBoundaryEscape
	}
	if f.UnsafePtrCarrierBoxed != "" {
		return f.MethodSet == ReflectFlagROBypassAnyKey && ValidFlagROBypassMethodSetKey(f.UnsafePtrCarrierBoxed) &&
			len(f.UnlessParamLeakFree) == 0 && !hasCapsuleOrCopyGuard && f.ContextValueBoxed == "" &&
			!f.ErasedToEmptyIface && !f.ReflectsEmptyIfaceLocally && !f.LeaksEmptyIfaceUpward &&
			!f.ReflectValueBoundaryEscape && !f.UnexportedIfaceField
	}
	if f.MethodSet != EmptyIfaceMethodSetKey && (f.ReflectsEmptyIfaceLocally || f.LeaksEmptyIfaceUpward) {
		return false
	}
	if f.ContextValueBoxed != "" {
		if f.MethodSet == EmptyIfaceMethodSetKey {
			return f.ContextValueBoxed == ReflectRawUintptrToPtrKey &&
				len(f.UnlessParamLeakFree) == 0 && !hasCapsuleOrCopyGuard &&
				!f.ErasedToEmptyIface && !f.ReflectsEmptyIfaceLocally && !f.LeaksEmptyIfaceUpward &&
				!f.ReflectValueBoundaryEscape && !f.UnexportedIfaceField
		}
		return ValidMethodSetKey(f.MethodSet) &&
			(ValidMethodSetKey(f.ContextValueBoxed) || f.ContextValueBoxed == ContextKeyTheftMethodSetKey || f.ContextValueBoxed == ReflectRawUintptrToPtrKey) &&
			len(f.UnlessParamLeakFree) == 0 && !hasCapsuleOrCopyGuard &&
			!f.ErasedToEmptyIface && !f.ReflectValueBoundaryEscape
	}
	if f.MethodSet == EmptyIfaceMethodSetKey {
		return len(f.UnlessParamLeakFree) == 0 && !f.ErasedToEmptyIface && !f.UnexportedIfaceField
	}
	if f.MethodSet == ReflectFlagROBypassAnyKey || f.MethodSet == ReflectFlagROLocalBypassKey || f.MethodSet == ReflectRawUintptrToPtrKey || f.MethodSet == ContextKeyTheftFlagROKey {
		return len(f.UnlessParamLeakFree) == 0 && !f.ErasedToEmptyIface && !f.ReflectValueBoundaryEscape && !f.UnexportedIfaceField
	}
	if f.MethodSet == ContextKeyTheftMethodSetKey {
		if hasCapsuleOrCopyGuard || f.ErasedToEmptyIface || f.ReflectValueBoundaryEscape || f.UnexportedIfaceField {
			return false
		}
		for i, pk := range f.UnlessParamLeakFree {
			if !pk.Valid() || (i > 0 && f.UnlessParamLeakFree[i-1].Compare(pk) >= 0) {
				return false
			}
		}
		return true
	}
	if !ValidMethodSetKey(f.MethodSet) && !ValidFlagROBypassMethodSetKey(f.MethodSet) {
		return false
	}
	if strings.HasPrefix(f.MethodSet, ReflectFlagROBypassPrefix) && (f.ErasedToEmptyIface || f.ReflectValueBoundaryEscape || f.UnexportedIfaceField) {
		return false
	}
	if f.UnexportedIfaceField && !f.ErasedToEmptyIface && !f.ReflectValueBoundaryEscape {
		return false
	}
	for i, pk := range f.UnlessParamLeakFree {
		if !pk.Valid() || (i > 0 && f.UnlessParamLeakFree[i-1].Compare(pk) >= 0) {
			return false
		}
	}
	return true
}

func (f ReflectedIfaceFact) Compare(o ReflectedIfaceFact) int {
	if c := cmp.Compare(f.MethodSet, o.MethodSet); c != 0 {
		return c
	}
	if c := cmp.Compare(f.ContextValueBoxed, o.ContextValueBoxed); c != 0 {
		return c
	}
	if c := cmp.Compare(f.UnsafePtrCarrierBoxed, o.UnsafePtrCarrierBoxed); c != 0 {
		return c
	}
	if c := cmp.Compare(f.NestedInConcreteBox, o.NestedInConcreteBox); c != 0 {
		return c
	}
	if c := cmp.Compare(f.NestedOpaqueStruct.Key(), o.NestedOpaqueStruct.Key()); c != 0 {
		return c
	}
	if c := cmp.Compare(f.NestedOpaqueOwnerPkg, o.NestedOpaqueOwnerPkg); c != 0 {
		return c
	}
	if c := cmp.Compare(f.UnlessSafeCapsuleStruct.Key(), o.UnlessSafeCapsuleStruct.Key()); c != 0 {
		return c
	}
	if c := f.UnlessSafeCapsuleParam.Compare(o.UnlessSafeCapsuleParam); c != 0 {
		return c
	}
	if c := f.UnlessSafeAtomicPtrCopy.Compare(o.UnlessSafeAtomicPtrCopy); c != 0 {
		return c
	}
	if f.ErasedToEmptyIface != o.ErasedToEmptyIface {
		if !f.ErasedToEmptyIface {
			return -1
		}
		return 1
	}
	if f.ReflectsEmptyIfaceLocally != o.ReflectsEmptyIfaceLocally {
		if !f.ReflectsEmptyIfaceLocally {
			return -1
		}
		return 1
	}
	if f.LeaksEmptyIfaceUpward != o.LeaksEmptyIfaceUpward {
		if !f.LeaksEmptyIfaceUpward {
			return -1
		}
		return 1
	}
	if f.ReflectValueBoundaryEscape != o.ReflectValueBoundaryEscape {
		if !f.ReflectValueBoundaryEscape {
			return -1
		}
		return 1
	}
	if f.UnexportedIfaceField != o.UnexportedIfaceField {
		if !f.UnexportedIfaceField {
			return -1
		}
		return 1
	}
	return slices.CompareFunc(f.UnlessParamLeakFree, o.UnlessParamLeakFree, ParamKey.Compare)
}

// MethodSetSubset reports whether every '\x1f'-delimited method identifier in
// sub is present in sup (matching ReflectFlagROBypassPrefix polarity).
func MethodSetSubset(sub, sup string) bool {
	if sub == "" || sup == "" || sub == EmptyIfaceMethodSetKey || sup == EmptyIfaceMethodSetKey {
		return false
	}
	subBypass, hasSubPfx := strings.CutPrefix(sub, ReflectFlagROBypassPrefix)
	supBypass, hasSupPfx := strings.CutPrefix(sup, ReflectFlagROBypassPrefix)
	if hasSubPfx != hasSupPfx {
		return false
	}
	if hasSubPfx {
		switch {
		case subBypass == "*" || supBypass == "*",
			subBypass == "!" || supBypass == "!",
			subBypass == "^" || supBypass == "^",
			subBypass == "ctx" || supBypass == "ctx",
			subBypass == "ctx*" || supBypass == "ctx*":
			return subBypass == supBypass
		}
		sub = subBypass
		sup = supBypass
	}
	if sub == sup {
		return true
	}
	subParts := strings.Split(sub, "\x1f")
	supParts := strings.Split(sup, "\x1f")
	if len(subParts) > len(supParts) {
		return false
	}
	i, j := 0, 0
	for i < len(subParts) && j < len(supParts) {
		if subParts[i] == supParts[j] {
			i++
			j++
		} else if subParts[i] > supParts[j] {
			j++
		} else {
			return false
		}
	}
	return i == len(subParts)
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
