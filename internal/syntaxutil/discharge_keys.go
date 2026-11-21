package syntaxutil

import (
	"cmp"
	"slices"
	"strings"
)

// AttributedUse carries a mutation or escape recorded inside a plain named
// function or method: composition discharges it when the whole graph proves the
// function reachable only from init flow, and promotes it otherwise
// (REQ-closure-shared-dynamic-state-init-flow).
type AttributedUse struct {
	Func      FuncKey `json:"func"`
	Key       string  `json:"key"`
	Escape    bool    `json:"escape,omitempty"`
	Literal   bool    `json:"literal,omitempty"`
	HasMethod bool    `json:"hasMethod,omitempty"`
	Method    FuncKey `json:"method,omitempty"`
}

func (u AttributedUse) Valid() bool {
	if !u.Func.Valid() || u.Key == "" || strings.Contains(u.Key, "\x00") {
		return false
	}
	if u.HasMethod {
		return !u.Escape && u.Method.Valid()
	}
	return u.Method == (FuncKey{})
}

func (u AttributedUse) Compare(o AttributedUse) int {
	if c := u.Func.Compare(o.Func); c != 0 {
		return c
	}
	if c := cmp.Compare(u.Key, o.Key); c != 0 {
		return c
	}
	if u.Escape != o.Escape {
		if !u.Escape {
			return -1
		}
		return 1
	}
	if u.Literal != o.Literal {
		if !u.Literal {
			return -1
		}
		return 1
	}
	if u.HasMethod != o.HasMethod {
		if !u.HasMethod {
			return -1
		}
		return 1
	}
	return u.Method.Compare(o.Method)
}

// RefRegionKind classifies the region from which a plain named function is
// referenced.
type RefRegionKind uint8

const (
	RegionInit RefRegionKind = iota + 1
	RegionProg
	RegionFunc
	RegionLitFunc
)

// RefRegion is a reference region in the cross-package init-only / init-reach
// fixed-point graph.
type RefRegion struct {
	Kind   RefRegionKind `json:"kind"`
	Caller FuncKey       `json:"caller,omitempty"`
}

func (r RefRegion) Valid() bool {
	switch r.Kind {
	case RegionInit, RegionProg:
		return r.Caller == (FuncKey{})
	case RegionFunc, RegionLitFunc:
		return r.Caller.Valid()
	default:
		return false
	}
}

func (r RefRegion) Compare(o RefRegion) int {
	if c := cmp.Compare(r.Kind, o.Kind); c != 0 {
		return c
	}
	return r.Caller.Compare(o.Caller)
}

// FuncRef is one reference-region edge for the cross-package init-only and
// init-reach fixed points.
type FuncRef struct {
	Callee FuncKey   `json:"callee"`
	Region RefRegion `json:"region"`
}

func (r FuncRef) Valid() bool {
	return r.Callee.Valid() && r.Region.Valid()
}

func (r FuncRef) Compare(o FuncRef) int {
	if c := r.Callee.Compare(o.Callee); c != 0 {
		return c
	}
	return r.Region.Compare(o.Region)
}

// EnvCallUse records a deferred constructor-registration mark on a carrier
// variable. When Func is non-zero, the registration occurred inside that plain
// named function; a zero Func denotes top-level, init, or method flow.
type EnvCallUse struct {
	Key    string  `json:"key"`
	Callee FuncKey `json:"callee"`
	Func   FuncKey `json:"func,omitempty"`
}

func (u EnvCallUse) Valid() bool {
	if u.Key == "" || strings.Contains(u.Key, "\x00") || !u.Callee.Valid() {
		return false
	}
	return u.Func.IsZero() || u.Func.Valid()
}

func (u EnvCallUse) Compare(o EnvCallUse) int {
	if c := cmp.Compare(u.Key, o.Key); c != 0 {
		return c
	}
	if c := u.Callee.Compare(o.Callee); c != 0 {
		return c
	}
	return u.Func.Compare(o.Func)
}

// EnvCallParamUse records a deferred parameter-leak-free obligation on a
// carrier's environment-free registration (from a registered literal's
// body/enclosing scope or a plain-call mutable-reach argument). When Func is
// non-zero, the registration occurred inside that plain named function.
type EnvCallParamUse struct {
	Key   string   `json:"key"`
	Param ParamKey `json:"param"`
	Func  FuncKey  `json:"func,omitempty"`
}

func (u EnvCallParamUse) Valid() bool {
	if u.Key == "" || strings.Contains(u.Key, "\x00") || !u.Param.Valid() {
		return false
	}
	return u.Func.IsZero() || u.Func.Valid()
}

func (u EnvCallParamUse) Compare(o EnvCallParamUse) int {
	if c := cmp.Compare(u.Key, o.Key); c != 0 {
		return c
	}
	if c := u.Param.Compare(o.Param); c != 0 {
		return c
	}
	return u.Func.Compare(o.Func)
}

// EnvCallMethodUse records a deferred receiver-read-only obligation on a
// carrier's environment-free registration (from a registered literal's body or
// enclosing scope). When Func is non-zero, the registration occurred inside
// that plain named function.
type EnvCallMethodUse struct {
	Key    string  `json:"key"`
	Method FuncKey `json:"method"`
	Func   FuncKey `json:"func,omitempty"`
}

func (u EnvCallMethodUse) Valid() bool {
	if u.Key == "" || strings.Contains(u.Key, "\x00") || !u.Method.Valid() {
		return false
	}
	return u.Func.IsZero() || u.Func.Valid()
}

func (u EnvCallMethodUse) Compare(o EnvCallMethodUse) int {
	if c := cmp.Compare(u.Key, o.Key); c != 0 {
		return c
	}
	if c := u.Method.Compare(o.Method); c != 0 {
		return c
	}
	return u.Func.Compare(o.Func)
}

// OnceMemoTypeFact records that a named struct type in its declaring package
// mechanically satisfies the once-populated immutable struct memoizer contract
// (REQ-closure-shared-dynamic-state-memo).
type OnceMemoTypeFact struct {
	Type           TypeRef    `json:"type"`
	Constructors   []FuncKey  `json:"constructors"`
	GuardTypes     []TypeRef  `json:"guardTypes,omitempty"`
	InputParamDeps []ParamKey `json:"inputParamDeps,omitempty"`
}

func (f OnceMemoTypeFact) Valid() bool {
	if !f.Type.Valid() || len(f.Constructors) == 0 || len(f.GuardTypes) == 0 {
		return false
	}
	hasSelfGuard := false
	for _, c := range f.Constructors {
		if !c.Valid() || c.Pkg != f.Type.Pkg {
			return false
		}
	}
	for _, g := range f.GuardTypes {
		if !g.Valid() {
			return false
		}
		if g == f.Type {
			hasSelfGuard = true
		}
	}
	if !hasSelfGuard {
		return false
	}
	for _, p := range f.InputParamDeps {
		if !p.Valid() {
			return false
		}
	}
	return true
}

func (f OnceMemoTypeFact) Compare(o OnceMemoTypeFact) int {
	return cmp.Compare(f.Type.Key(), o.Type.Key())
}

// OnceMemoVarCandidate records a non-directive package-level *T variable
// initialized once at declaration by a direct call to Constructor, free of
// mutations and non-method-call uses in its declaring package, and passing only
// confined arguments to Constructor.
type OnceMemoVarCandidate struct {
	Key         string  `json:"key"`
	Type        TypeRef `json:"type"`
	Constructor FuncKey `json:"constructor"`
}

func (c OnceMemoVarCandidate) Valid() bool {
	return ValidQualifiedVarKey(c.Key) && c.Type.Valid() && c.Constructor.Valid() && c.Constructor.Pkg == c.Type.Pkg
}

func (c OnceMemoVarCandidate) Compare(o OnceMemoVarCandidate) int {
	if k := cmp.Compare(c.Key, o.Key); k != 0 {
		return k
	}
	if t := cmp.Compare(c.Type.Key(), o.Type.Key()); t != 0 {
		return t
	}
	return c.Constructor.Compare(o.Constructor)
}

// ReadOnlyVarAlias records a non-directive single-definition package-level
// *NamedStruct variable initialized directly from Target (or &Target for a
// by-value NamedStruct Target) and free of post-declaration writes, address
// captures, and mutating builtins in its declaring package.
type ReadOnlyVarAlias struct {
	Key               string `json:"key"`
	Target            string `json:"target"`
	DirectMethodsOnly bool   `json:"directMethodsOnly,omitempty"`
}

func (a ReadOnlyVarAlias) Valid() bool {
	return ValidQualifiedVarKey(a.Key) && ValidQualifiedVarKey(a.Target) && a.Key != a.Target
}

func (a ReadOnlyVarAlias) Compare(o ReadOnlyVarAlias) int {
	if c := cmp.Compare(a.Key, o.Key); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Target, o.Target); c != 0 {
		return c
	}
	if a.DirectMethodsOnly != o.DirectMethodsOnly {
		if !a.DirectMethodsOnly {
			return -1
		}
		return 1
	}
	return 0
}

// StaticCompositeGlobalFact records a closed composite-literal package global
// rooted at a non-empty non-standard named struct (by value or single-level
// pointer) whose complete reachable struct/element schema is covered by
// GuardTypes.
type StaticCompositeGlobalFact struct {
	Key        string    `json:"key"`
	GuardTypes []TypeRef `json:"guardTypes"`
}

func (f StaticCompositeGlobalFact) Valid() bool {
	if !ValidQualifiedVarKey(f.Key) || len(f.GuardTypes) == 0 {
		return false
	}
	for i, g := range f.GuardTypes {
		if !g.Valid() || g.IsUnnamed() {
			return false
		}
		if i > 0 && f.GuardTypes[i-1].Compare(g) >= 0 {
			return false
		}
	}
	return true
}

func (f StaticCompositeGlobalFact) Compare(o StaticCompositeGlobalFact) int {
	if c := cmp.Compare(f.Key, o.Key); c != 0 {
		return c
	}
	return slices.CompareFunc(f.GuardTypes, o.GuardTypes, TypeRef.Compare)
}

// ExportedSeam records an exported plain package function whose body (directly
// or through intra-package helpers) discharges a mutating bracketed seam on
// package variable Key, so composition can reject the discharge if any
// importing package invokes Func non-sequentially, captures it as a value, or
// (when RunnerOnly is set for a testing.Cleanup runner entry) references or
// calls Func from outside the test runner.
type ExportedSeam struct {
	Func       FuncKey `json:"func"`
	Key        string  `json:"key"`
	RunnerOnly bool    `json:"runnerOnly,omitempty"`
}

func (s ExportedSeam) Valid() bool {
	return s.Func.Valid() && s.Key != "" && !strings.Contains(s.Key, "\x00")
}

func (s ExportedSeam) Compare(o ExportedSeam) int {
	if c := s.Func.Compare(o.Func); c != 0 {
		return c
	}
	if c := cmp.Compare(s.Key, o.Key); c != 0 {
		return c
	}
	if s.RunnerOnly != o.RunnerOnly {
		if !s.RunnerOnly {
			return -1
		}
		return 1
	}
	return 0
}
