package syntaxutil

import (
	"cmp"
	"go/token"
	"slices"
)

// ValidExportedIdent reports whether s is a valid exported Go identifier.
func ValidExportedIdent(s string) bool {
	return s != "" && token.IsIdentifier(s) && token.IsExported(s)
}

// LazyOnceCapsuleType records that a named struct type in its defining package
// satisfies deterministic read-only or locked once-initialization capsule
// discipline. GuardTypes names any struct types whose instances are constructed
// or exposed by this capsule and must remain free of non-fresh mutations across
// the package graph. ExportedWriteGuardFields names any exported fields on Type
// that must be provably non-nil on every cluster-bound element so onceCone
// legacy fallback writes to exported fields remain unreachable.
type LazyOnceCapsuleType struct {
	Type                     TypeRef    `json:"type"`
	HasExportedReflectType   bool       `json:"has_exported_reflect_type,omitempty"`
	InitHelper               FuncKey    `json:"init_helper,omitempty"`
	GuardTypes               []TypeRef  `json:"guard_types,omitempty"`
	ExportedWriteGuardFields []string   `json:"exported_write_guard_fields,omitempty"`
	CapsuleReflectSafe       bool       `json:"capsule_reflect_safe,omitempty"`
	SafePtrWrapperParams     []ParamKey `json:"safe_ptr_wrapper_params,omitempty"`
	SafeAtomicPtrCopyFuncs   []FuncKey  `json:"safe_atomic_ptr_copy_funcs,omitempty"`
}

// Valid reports whether f carries well-formed type, helper, guard, and wrapper keys.
func (f LazyOnceCapsuleType) Valid() bool {
	if !f.Type.Valid() || f.Type.IsUnnamed() {
		return false
	}
	if !f.InitHelper.IsZero() && (!f.InitHelper.Valid() || f.InitHelper.Pkg != f.Type.Pkg) {
		return false
	}
	for _, g := range f.GuardTypes {
		if !g.Valid() {
			return false
		}
	}
	for i, gf := range f.ExportedWriteGuardFields {
		if !ValidExportedIdent(gf) || (i > 0 && f.ExportedWriteGuardFields[i-1] >= gf) {
			return false
		}
	}
	if (len(f.SafePtrWrapperParams) > 0 || len(f.SafeAtomicPtrCopyFuncs) > 0) && !f.CapsuleReflectSafe {
		return false
	}
	for _, pk := range f.SafePtrWrapperParams {
		if !pk.Valid() {
			return false
		}
	}
	for _, fk := range f.SafeAtomicPtrCopyFuncs {
		if !fk.Valid() {
			return false
		}
	}
	return true
}

// Compare orders LazyOnceCapsuleType records deterministically.
func (f LazyOnceCapsuleType) Compare(o LazyOnceCapsuleType) int {
	if d := f.Type.Compare(o.Type); d != 0 {
		return d
	}
	if f.HasExportedReflectType != o.HasExportedReflectType {
		if !f.HasExportedReflectType {
			return -1
		}
		return 1
	}
	if d := f.InitHelper.Compare(o.InitHelper); d != 0 {
		return d
	}
	if d := slices.CompareFunc(f.GuardTypes, o.GuardTypes, TypeRef.Compare); d != 0 {
		return d
	}
	if d := slices.Compare(f.ExportedWriteGuardFields, o.ExportedWriteGuardFields); d != 0 {
		return d
	}
	if f.CapsuleReflectSafe != o.CapsuleReflectSafe {
		if !f.CapsuleReflectSafe {
			return -1
		}
		return 1
	}
	if d := slices.CompareFunc(f.SafePtrWrapperParams, o.SafePtrWrapperParams, ParamKey.Compare); d != 0 {
		return d
	}
	return slices.CompareFunc(f.SafeAtomicPtrCopyFuncs, o.SafeAtomicPtrCopyFuncs, FuncKey.Compare)
}

// BuilderSliceSpec describes one exported []ElemType capsule slice field on an
// InitBuilderFact in struct-declaration order.
type BuilderSliceSpec struct {
	Field       string  `json:"field"`
	ElemType    TypeRef `json:"elem_type"`
	TakesSample bool    `json:"takes_sample,omitempty"`
}

// Valid reports whether s names a valid exported field and named struct element type.
func (s BuilderSliceSpec) Valid() bool {
	return ValidExportedIdent(s.Field) && s.ElemType.Valid() && !s.ElemType.IsUnnamed()
}

// Compare orders BuilderSliceSpec records deterministically.
func (s BuilderSliceSpec) Compare(o BuilderSliceSpec) int {
	if d := cmp.Compare(s.Field, o.Field); d != 0 {
		return d
	}
	if d := s.ElemType.Compare(o.ElemType); d != 0 {
		return d
	}
	if s.TakesSample != o.TakesSample {
		if !s.TakesSample {
			return -1
		}
		return 1
	}
	return 0
}

// InitBuilderFact records that an exported named struct type in its defining
// package satisfies either raw immutable-capsule builder discipline
// (CoversImmutableCapsules == true) or sample-aligned capsule-slice builder
// discipline (CoversImmutableCapsules == false).
type InitBuilderFact struct {
	Type                    TypeRef            `json:"type"`
	BuildMethod             string             `json:"build_method"`
	OutIfaceField           string             `json:"out_iface_field"`
	SubBuilderField         string             `json:"sub_builder_field,omitempty"`
	SubBuilder              TypeRef            `json:"sub_builder,omitempty"`
	TypeSampleSliceField    string             `json:"type_sample_slice_field,omitempty"`
	CapsuleSliceFields      []BuilderSliceSpec `json:"capsule_slice_fields,omitempty"`
	AllowedHelpers          []FuncKey          `json:"allowed_helpers,omitempty"`
	GuardTypes              []TypeRef          `json:"guard_types,omitempty"`
	CoversImmutableCapsules bool               `json:"covers_immutable_capsules,omitempty"`
}

// Valid reports whether f carries consistent builder, slice, helper, and guard keys.
func (f InitBuilderFact) Valid() bool {
	if !f.Type.Valid() || f.Type.IsUnnamed() || !ValidExportedIdent(f.BuildMethod) || !ValidExportedIdent(f.OutIfaceField) {
		return false
	}
	if (f.SubBuilderField == "") != f.SubBuilder.IsZero() {
		return false
	}
	if !f.SubBuilder.IsZero() && (!ValidExportedIdent(f.SubBuilderField) || !f.SubBuilder.Valid() || f.SubBuilder.IsUnnamed()) {
		return false
	}
	if f.TypeSampleSliceField != "" && !ValidExportedIdent(f.TypeSampleSliceField) {
		return false
	}
	for _, g := range f.GuardTypes {
		if !g.Valid() {
			return false
		}
	}
	for _, h := range f.AllowedHelpers {
		if !h.Valid() {
			return false
		}
	}
	if f.CoversImmutableCapsules {
		return len(f.GuardTypes) > 0 && f.SubBuilder.IsZero() && f.TypeSampleSliceField == "" &&
			len(f.CapsuleSliceFields) == 0 && len(f.AllowedHelpers) == 0
	}
	if len(f.CapsuleSliceFields) == 0 {
		return false
	}
	seenFields := make(map[string]bool, len(f.CapsuleSliceFields))
	if f.SubBuilderField != "" {
		seenFields[f.SubBuilderField] = true
	}
	if f.TypeSampleSliceField != "" {
		if seenFields[f.TypeSampleSliceField] {
			return false
		}
		seenFields[f.TypeSampleSliceField] = true
	}
	for _, cs := range f.CapsuleSliceFields {
		if !cs.Valid() || seenFields[cs.Field] {
			return false
		}
		seenFields[cs.Field] = true
		if cs.TakesSample && f.TypeSampleSliceField == "" {
			return false
		}
	}
	return true
}

// Compare orders InitBuilderFact records deterministically.
func (f InitBuilderFact) Compare(o InitBuilderFact) int {
	if d := f.Type.Compare(o.Type); d != 0 {
		return d
	}
	if f.CoversImmutableCapsules != o.CoversImmutableCapsules {
		if !f.CoversImmutableCapsules {
			return -1
		}
		return 1
	}
	if d := cmp.Compare(f.BuildMethod, o.BuildMethod); d != 0 {
		return d
	}
	if d := cmp.Compare(f.OutIfaceField, o.OutIfaceField); d != 0 {
		return d
	}
	if d := cmp.Compare(f.SubBuilderField, o.SubBuilderField); d != 0 {
		return d
	}
	if d := f.SubBuilder.Compare(o.SubBuilder); d != 0 {
		return d
	}
	if d := cmp.Compare(f.TypeSampleSliceField, o.TypeSampleSliceField); d != 0 {
		return d
	}
	if d := slices.CompareFunc(f.CapsuleSliceFields, o.CapsuleSliceFields, BuilderSliceSpec.Compare); d != 0 {
		return d
	}
	if d := slices.CompareFunc(f.AllowedHelpers, o.AllowedHelpers, FuncKey.Compare); d != 0 {
		return d
	}
	return slices.CompareFunc(f.GuardTypes, o.GuardTypes, TypeRef.Compare)
}

// ClusterCapsuleSliceBinding records one capsule-slice binding passed to an
// InitBuilderFact composite literal inside an InitSettledClusterFact.
type ClusterCapsuleSliceBinding struct {
	Field               string   `json:"field"`
	CapsuleType         TypeRef  `json:"capsule_type"`
	StaticLiteral       bool     `json:"static_literal,omitempty"`
	NonNilExportedNames []string `json:"non_nil_exported_names,omitempty"`
}

// Valid reports whether b carries a valid field, capsule type, and sorted non-nil field set.
func (b ClusterCapsuleSliceBinding) Valid() bool {
	if !ValidExportedIdent(b.Field) || !b.CapsuleType.Valid() || b.CapsuleType.IsUnnamed() {
		return false
	}
	if !b.StaticLiteral && len(b.NonNilExportedNames) > 0 {
		return false
	}
	for i, nm := range b.NonNilExportedNames {
		if !ValidExportedIdent(nm) || (i > 0 && b.NonNilExportedNames[i-1] >= nm) {
			return false
		}
	}
	return true
}

// Compare orders ClusterCapsuleSliceBinding records deterministically.
func (b ClusterCapsuleSliceBinding) Compare(o ClusterCapsuleSliceBinding) int {
	if d := cmp.Compare(b.Field, o.Field); d != 0 {
		return d
	}
	if d := b.CapsuleType.Compare(o.CapsuleType); d != 0 {
		return d
	}
	if b.StaticLiteral != o.StaticLiteral {
		if !b.StaticLiteral {
			return -1
		}
		return 1
	}
	return slices.Compare(b.NonNilExportedNames, o.NonNilExportedNames)
}

// InitSettledClusterFact records a verified idempotent init-only builder
// cluster in a declaring package.
type InitSettledClusterFact struct {
	InitFn        FuncKey                      `json:"init_fn"`
	Vars          []string                     `json:"vars"`
	BuilderType   TypeRef                      `json:"builder_type"`
	BuildMethod   string                       `json:"build_method"`
	OutIfaceField string                       `json:"out_iface_field"`
	SliceBindings []ClusterCapsuleSliceBinding `json:"slice_bindings,omitempty"`
}

// Valid reports whether c carries well-formed function, variable, builder, and slice keys.
func (c InitSettledClusterFact) Valid() bool {
	if !c.InitFn.Valid() || len(c.Vars) == 0 || !c.BuilderType.Valid() || c.BuilderType.IsUnnamed() ||
		!ValidExportedIdent(c.BuildMethod) || !ValidExportedIdent(c.OutIfaceField) {
		return false
	}
	for _, v := range c.Vars {
		if !ValidQualifiedVarKey(v) {
			return false
		}
	}
	seenFields := make(map[string]bool, len(c.SliceBindings))
	for _, sb := range c.SliceBindings {
		if !sb.Valid() || seenFields[sb.Field] {
			return false
		}
		seenFields[sb.Field] = true
	}
	return true
}

// Compare orders InitSettledClusterFact records deterministically.
func (c InitSettledClusterFact) Compare(o InitSettledClusterFact) int {
	if d := c.InitFn.Compare(o.InitFn); d != 0 {
		return d
	}
	if d := slices.Compare(c.Vars, o.Vars); d != 0 {
		return d
	}
	if d := c.BuilderType.Compare(o.BuilderType); d != 0 {
		return d
	}
	if d := cmp.Compare(c.BuildMethod, o.BuildMethod); d != 0 {
		return d
	}
	if d := cmp.Compare(c.OutIfaceField, o.OutIfaceField); d != 0 {
		return d
	}
	return slices.CompareFunc(c.SliceBindings, o.SliceBindings, ClusterCapsuleSliceBinding.Compare)
}
