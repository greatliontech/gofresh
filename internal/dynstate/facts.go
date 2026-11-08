package dynstate

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
)

// PackageClass is the mutability class of one graph package's source, the
// same discrimination the closure hash applies to its contributions:
// standard-library source rides the toolchain guard, module-cache source is
// pinned by its version, and everything else — main module, local replace,
// workspace sibling, vendored copy — is mutable-local and must be observed by
// content on every pass (REQ-closure-mutable-local, REQ-closure-pinned-dep).
type PackageClass int

const (
	MutableLocalPackage PackageClass = iota
	StandardPackage
	PinnedPackage
)

// GraphPackage is one node of a view's test-binary package graph as the
// metadata listing names it: enough identity to classify, key, and walk the
// graph without loading any syntax.
type GraphPackage struct {
	// ImportPath is the listing identity; a test-variant recompilation
	// carries the bracket suffix ("p [p.test]").
	ImportPath string
	// PkgPath is the import path the type checker reports for the node —
	// ImportPath with any variant suffix stripped.
	PkgPath string
	// ForTest names the tested package for a test-variant node, "" otherwise.
	ForTest string
	// TestMain marks the toolchain-generated test main package.
	TestMain bool
	// Imports are the node's resolved import identities (listing form).
	Imports []string
	// Class is the node's source-mutability class.
	Class PackageClass
	// Pin is the module-cache-relative module directory ("modpath@version",
	// replace-correct) for a PinnedPackage — the same identity the closure
	// hash pins the module by. Empty otherwise.
	Pin string
}

// ElemPositionField is the synthetic field name under which slice/array/map
// element registrations and dispatch uses share the field-population solver.
const ElemPositionField = "\x02"

// FuncKey identifies a function or method ("Recv.Method") by declaring package
// path and local name.
type FuncKey struct {
	Pkg  string `json:"pkg"`
	Name string `json:"name"`
}

func (k FuncKey) IsZero() bool {
	return k.Pkg == "" && k.Name == ""
}

func (k FuncKey) Valid() bool {
	return k.Pkg != "" && k.Name != "" && !strings.Contains(k.Pkg, "\x00") && !strings.Contains(k.Name, "\x00")
}

func (k FuncKey) Display() string {
	return k.Pkg + "." + k.Name
}

func (k FuncKey) Compare(o FuncKey) int {
	if c := cmp.Compare(k.Pkg, o.Pkg); c != 0 {
		return c
	}
	return cmp.Compare(k.Name, o.Name)
}

// ParamKey identifies a 0-based parameter of a named function.
type ParamKey struct {
	Func  FuncKey `json:"func"`
	Index int     `json:"index"`
}

func (k ParamKey) Valid() bool {
	return k.Func.Valid() && k.Index >= 0
}

func (k ParamKey) Display() string {
	return k.Func.Display() + " parameter " + strconv.Itoa(k.Index)
}

func (k ParamKey) Compare(o ParamKey) int {
	if c := k.Func.Compare(o.Func); c != 0 {
		return c
	}
	return cmp.Compare(k.Index, o.Index)
}

// FieldPosKey identifies a 0-based parameter position of a function-typed
// field on a carrier variable (or ElemPositionField for container elements).
type FieldPosKey struct {
	Owner string `json:"owner"`
	Field string `json:"field"`
	Index int    `json:"index"`
}

func (k FieldPosKey) Valid(minIdx int) bool {
	return k.Owner != "" && k.Field != "" && !strings.Contains(k.Owner, "\x00") && !strings.Contains(k.Field, "\x00") && k.Index >= minIdx
}

func (k FieldPosKey) Compare(o FieldPosKey) int {
	if c := cmp.Compare(k.Owner, o.Owner); c != 0 {
		return c
	}
	if c := cmp.Compare(k.Field, o.Field); c != 0 {
		return c
	}
	return cmp.Compare(k.Index, o.Index)
}

// ReturnFieldPosKey identifies a 0-based parameter position of a function-typed
// field on a constructor function's returned composite.
type ReturnFieldPosKey struct {
	Func  FuncKey `json:"func"`
	Field string  `json:"field"`
	Index int     `json:"index"`
}

func (k ReturnFieldPosKey) Valid(minIdx int) bool {
	return k.Func.Valid() && k.Field != "" && !strings.Contains(k.Field, "\x00") && k.Index >= minIdx
}

func (k ReturnFieldPosKey) Compare(o ReturnFieldPosKey) int {
	if c := k.Func.Compare(o.Func); c != 0 {
		return c
	}
	if c := cmp.Compare(k.Field, o.Field); c != 0 {
		return c
	}
	return cmp.Compare(k.Index, o.Index)
}

// EnvAuditTarget identifies a dependency in the joint environment-audit fixed
// point: either a return-environment-free function claim (ParamIndex == -1) or
// a parameter-insertion-free claim (ParamIndex >= 0).
type EnvAuditTarget struct {
	Func       FuncKey `json:"func"`
	ParamIndex int     `json:"paramIndex"`
}

func FuncAuditTarget(fn FuncKey) EnvAuditTarget {
	return EnvAuditTarget{Func: fn, ParamIndex: -1}
}

func ParamAuditTarget(p ParamKey) EnvAuditTarget {
	return EnvAuditTarget{Func: p.Func, ParamIndex: p.Index}
}

func (t EnvAuditTarget) IsParam() bool {
	return t.ParamIndex >= 0
}

func (t EnvAuditTarget) Param() ParamKey {
	return ParamKey{Func: t.Func, Index: t.ParamIndex}
}

func (t EnvAuditTarget) Valid() bool {
	return t.Func.Valid() && t.ParamIndex >= -1
}

func (t EnvAuditTarget) Compare(o EnvAuditTarget) int {
	if c := t.Func.Compare(o.Func); c != 0 {
		return c
	}
	return cmp.Compare(t.ParamIndex, o.ParamIndex)
}

// VarMethodUse records a deferred method use on a package-level carrier.
type VarMethodUse struct {
	Key    string  `json:"key"`
	Method FuncKey `json:"method"`
}

func (u VarMethodUse) Valid() bool {
	return u.Key != "" && !strings.Contains(u.Key, "\x00") && u.Method.Valid()
}

func (u VarMethodUse) Compare(o VarMethodUse) int {
	if c := cmp.Compare(u.Key, o.Key); c != 0 {
		return c
	}
	return u.Method.Compare(o.Method)
}

// VarParamUse records a deferred call-argument use of a package-level carrier.
type VarParamUse struct {
	Key   string   `json:"key"`
	Param ParamKey `json:"param"`
}

func (u VarParamUse) Valid() bool {
	return u.Key != "" && !strings.Contains(u.Key, "\x00") && u.Param.Valid()
}

func (u VarParamUse) Compare(o VarParamUse) int {
	if c := cmp.Compare(u.Key, o.Key); c != 0 {
		return c
	}
	return u.Param.Compare(o.Param)
}

// ParamDepEdge records a conditional parameter-forwarding edge between two
// parameter proofs.
type ParamDepEdge struct {
	Own ParamKey `json:"own"`
	Dep ParamKey `json:"dep"`
}

func (e ParamDepEdge) Valid() bool {
	return e.Own.Valid() && e.Dep.Valid()
}

func (e ParamDepEdge) Compare(o ParamDepEdge) int {
	if c := e.Own.Compare(o.Own); c != 0 {
		return c
	}
	return e.Dep.Compare(o.Dep)
}

// OpaqueDep records a conditional object-closed dependency edge between two
// interface-typed package-level variables.
type OpaqueDep struct {
	Own string `json:"own"`
	Dep string `json:"dep"`
}

func (d OpaqueDep) Valid() bool {
	return d.Own != "" && d.Dep != "" && !strings.Contains(d.Own, "\x00") && !strings.Contains(d.Dep, "\x00")
}

func (d OpaqueDep) Compare(o OpaqueDep) int {
	if c := cmp.Compare(d.Own, o.Own); c != 0 {
		return c
	}
	return cmp.Compare(d.Dep, o.Dep)
}

// CarrierLink records an init-flow storage alias link between two carrier
// variables.
type CarrierLink struct {
	From string `json:"from"`
	To   string `json:"to"`
}

func (l CarrierLink) Valid() bool {
	return l.From != "" && l.To != "" && !strings.Contains(l.From, "\x00") && !strings.Contains(l.To, "\x00")
}

func (l CarrierLink) Compare(o CarrierLink) int {
	if c := cmp.Compare(l.From, o.From); c != 0 {
		return c
	}
	return cmp.Compare(l.To, o.To)
}

// ElemParamUse records a deferred dispatch-argument mark on an element of an
// iterated or indexed container carrier.
type ElemParamUse struct {
	Key   string `json:"key"`
	Owner string `json:"owner"`
	Index int    `json:"index"`
}

func (u ElemParamUse) Valid() bool {
	return u.Key != "" && u.Owner != "" && !strings.Contains(u.Key, "\x00") && !strings.Contains(u.Owner, "\x00") && u.Index >= 0
}

func (u ElemParamUse) Compare(o ElemParamUse) int {
	if c := cmp.Compare(u.Key, o.Key); c != 0 {
		return c
	}
	if c := cmp.Compare(u.Owner, o.Owner); c != 0 {
		return c
	}
	return cmp.Compare(u.Index, o.Index)
}

// FieldParamDefer records a registered-population deferral from a carrier field
// parameter position to a registrant function's parameter proof.
type FieldParamDefer struct {
	Pos   FieldPosKey `json:"pos"`
	Param ParamKey    `json:"param"`
}

func (d FieldParamDefer) Valid() bool {
	return d.Pos.Valid(0) && d.Param.Valid()
}

func (d FieldParamDefer) Compare(o FieldParamDefer) int {
	if c := d.Pos.Compare(o.Pos); c != 0 {
		return c
	}
	return d.Param.Compare(o.Param)
}

// FieldParamPoison records a registered-population refusal on a carrier
// variable (whole-variable when !HasPos, or at (Field, Index) when HasPos;
// Index == -1 poisons every parameter index of Field).
type FieldParamPoison struct {
	Owner  string `json:"owner"`
	HasPos bool   `json:"hasPos,omitempty"`
	Field  string `json:"field,omitempty"`
	Index  int    `json:"index,omitempty"`
}

func (p FieldParamPoison) Valid() bool {
	if p.Owner == "" || strings.Contains(p.Owner, "\x00") {
		return false
	}
	if !p.HasPos {
		return p.Field == "" && p.Index == 0
	}
	return p.Field != "" && !strings.Contains(p.Field, "\x00") && p.Index >= -1
}

func (p FieldParamPoison) Compare(o FieldParamPoison) int {
	if c := cmp.Compare(p.Owner, o.Owner); c != 0 {
		return c
	}
	if p.HasPos != o.HasPos {
		if !p.HasPos {
			return -1
		}
		return 1
	}
	if c := cmp.Compare(p.Field, o.Field); c != 0 {
		return c
	}
	return cmp.Compare(p.Index, o.Index)
}

// ReturnFieldParamDefer is the return-value counterpart of FieldParamDefer for
// a return-environment-free constructor function.
type ReturnFieldParamDefer struct {
	Pos   ReturnFieldPosKey `json:"pos"`
	Param ParamKey          `json:"param"`
}

func (d ReturnFieldParamDefer) Valid() bool {
	return d.Pos.Valid(0) && d.Param.Valid()
}

func (d ReturnFieldParamDefer) Compare(o ReturnFieldParamDefer) int {
	if c := d.Pos.Compare(o.Pos); c != 0 {
		return c
	}
	return d.Param.Compare(o.Param)
}

// ReturnFieldParamPoison is the return-value counterpart of FieldParamPoison
// for a return-environment-free constructor function.
type ReturnFieldParamPoison struct {
	Func   FuncKey `json:"func"`
	HasPos bool    `json:"hasPos,omitempty"`
	Field  string  `json:"field,omitempty"`
	Index  int     `json:"index,omitempty"`
}

func (p ReturnFieldParamPoison) Valid() bool {
	if !p.Func.Valid() {
		return false
	}
	if !p.HasPos {
		return p.Field == "" && p.Index == 0
	}
	return p.Field != "" && !strings.Contains(p.Field, "\x00") && p.Index >= -1
}

func (p ReturnFieldParamPoison) Compare(o ReturnFieldParamPoison) int {
	if c := p.Func.Compare(o.Func); c != 0 {
		return c
	}
	if p.HasPos != o.HasPos {
		if !p.HasPos {
			return -1
		}
		return 1
	}
	if c := cmp.Compare(p.Field, o.Field); c != 0 {
		return c
	}
	return cmp.Compare(p.Index, o.Index)
}

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
// variable.
type EnvCallUse struct {
	Key    string  `json:"key"`
	Callee FuncKey `json:"callee"`
}

func (u EnvCallUse) Valid() bool {
	return u.Key != "" && !strings.Contains(u.Key, "\x00") && u.Callee.Valid()
}

func (u EnvCallUse) Compare(o EnvCallUse) int {
	if c := cmp.Compare(u.Key, o.Key); c != 0 {
		return c
	}
	return u.Callee.Compare(o.Callee)
}

// FuncDepEdge records a return-environment-free conditional edge from a
// function to a callee function.
type FuncDepEdge struct {
	Func   FuncKey `json:"func"`
	Callee FuncKey `json:"callee"`
}

func (e FuncDepEdge) Valid() bool {
	return e.Func.Valid() && e.Callee.Valid()
}

func (e FuncDepEdge) Compare(o FuncDepEdge) int {
	if c := e.Func.Compare(o.Func); c != 0 {
		return c
	}
	return e.Callee.Compare(o.Callee)
}

// FuncInsertionDepEdge records a return-environment-free function proof's
// conditional dependency on an argument-insertion proof (or function proof).
type FuncInsertionDepEdge struct {
	Func FuncKey        `json:"func"`
	Dep  EnvAuditTarget `json:"dep"`
}

func (e FuncInsertionDepEdge) Valid() bool {
	return e.Func.Valid() && e.Dep.Valid()
}

func (e FuncInsertionDepEdge) Compare(o FuncInsertionDepEdge) int {
	if c := e.Func.Compare(o.Func); c != 0 {
		return c
	}
	return e.Dep.Compare(o.Dep)
}

// ParamInsertionDepEdge records a parameter-insertion-free proof's conditional
// dependency on another environment-audit target.
type ParamInsertionDepEdge struct {
	Param ParamKey       `json:"param"`
	Dep   EnvAuditTarget `json:"dep"`
}

func (e ParamInsertionDepEdge) Valid() bool {
	return e.Param.Valid() && e.Dep.Valid()
}

func (e ParamInsertionDepEdge) Compare(o ParamInsertionDepEdge) int {
	if c := e.Param.Compare(o.Param); c != 0 {
		return c
	}
	return e.Dep.Compare(o.Dep)
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

func validNonEmptyPkgKey(pkg string) bool {
	return pkg != "" && !strings.ContainsRune(pkg, 0) && !strings.ContainsAny(pkg, " \t\r\n")
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
		if !validNonEmptyPkgKey(c.GuardPkg) {
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
	if d := cmp.Compare(c.Struct.key(), o.Struct.key()); d != 0 {
		return d
	}
	if d := cmp.Compare(c.GuardPkg, o.GuardPkg); d != 0 {
		return d
	}
	if d := cmp.Compare(c.GuardStruct.key(), o.GuardStruct.key()); d != 0 {
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

// Fact is the per-package summary the shared-dynamic-state derivation extracts
// from one typed package and memoizes for version-pinned modules
// (REQ-closure-dynamic-state-memo).
type Fact struct {
	Declares                   []string                    `json:"declares,omitempty"`
	Mutates                    []string                    `json:"mutates,omitempty"`
	Escapes                    []string                    `json:"escapes,omitempty"`
	ExportedSeams              []ExportedSeam              `json:"exportedSeams,omitempty"`
	NonSeqFuncUses             []FuncKey                   `json:"nonSeqFuncUses,omitempty"`
	SeqFuncEdges               []FuncDepEdge               `json:"seqFuncEdges,omitempty"`
	ParallelFuncs              []FuncKey                   `json:"parallelFuncs,omitempty"`
	ParallelEdges              []FuncDepEdge               `json:"parallelEdges,omitempty"`
	ReceiverReadOnly           []FuncKey                   `json:"receiverReadOnly,omitempty"`
	ReceiverRetentionFree      []FuncKey                   `json:"receiverRetentionFree,omitempty"`
	NonMutatingMethods         []FuncKey                   `json:"nonMutatingMethods,omitempty"`
	MethodUses                 []VarMethodUse              `json:"methodUses,omitempty"`
	InitMethodUses             []VarMethodUse              `json:"initMethodUses,omitempty"`
	ParamLeakFree              []ParamKey                  `json:"paramLeakFree,omitempty"`
	ParamLeakFreeDeps          []ParamDepEdge              `json:"paramLeakFreeDeps,omitempty"`
	ParamRetentionFree         []ParamKey                  `json:"paramRetentionFree,omitempty"`
	ParamRetentionFreeDeps     []ParamDepEdge              `json:"paramRetentionFreeDeps,omitempty"`
	ParamUses                  []VarParamUse               `json:"paramUses,omitempty"`
	InitParamUses              []VarParamUse               `json:"initParamUses,omitempty"`
	FieldParamUses             []FieldPosKey               `json:"fieldParamUses,omitempty"`
	ElemParamUses              []ElemParamUse              `json:"elemParamUses,omitempty"`
	FieldParamDefer            []FieldParamDefer           `json:"fieldParamDefer,omitempty"`
	FieldParamPoison           []FieldParamPoison          `json:"fieldParamPoison,omitempty"`
	ReturnFieldParamDefer      []ReturnFieldParamDefer     `json:"returnFieldParamDefer,omitempty"`
	ReturnFieldParamPoison     []ReturnFieldParamPoison    `json:"returnFieldParamPoison,omitempty"`
	AttributedUses             []AttributedUse             `json:"attributedUses,omitempty"`
	FuncRefs                   []FuncRef                   `json:"funcRefs,omitempty"`
	Opaque                     []string                    `json:"opaque,omitempty"`
	OpacityBreaks              []string                    `json:"opacityBreaks,omitempty"`
	OpaqueDeps                 []OpaqueDep                 `json:"opaqueDeps,omitempty"`
	CarrierLinks               []CarrierLink               `json:"carrierLinks,omitempty"`
	EnvCarrying                []string                    `json:"envCarrying,omitempty"`
	EnvCallable                []string                    `json:"envCallable,omitempty"`
	EnvCallUses                []EnvCallUse                `json:"envCallUses,omitempty"`
	ReturnEnvFree              []FuncKey                   `json:"returnEnvFree,omitempty"`
	ReturnEnvDeps              []FuncDepEdge               `json:"returnEnvDeps,omitempty"`
	ParamInsertionFree         []ParamKey                  `json:"paramInsertionFree,omitempty"`
	ReturnEnvInsertionDeps     []FuncInsertionDepEdge      `json:"returnEnvInsertionDeps,omitempty"`
	ParamInsertionDeps         []ParamInsertionDepEdge     `json:"paramInsertionDeps,omitempty"`
	PureMethods                map[string]string           `json:"pureMethods,omitempty"`
	ExternalMethods            map[string]string           `json:"externalMethods,omitempty"`
	PoolDischarges             []string                    `json:"poolDischarges,omitempty"`
	SingleSubjectVars          []string                    `json:"singleSubjectVars,omitempty"`
	MappingDischarges          []string                    `json:"mappingDischarges,omitempty"`
	MemoDischarges             []string                    `json:"memoDischarges,omitempty"`
	ProtoClusters              []ProtoClusterFact          `json:"protoClusters,omitempty"`
	ProtoExtAliases            []ProtoExtAlias             `json:"protoExtAliases,omitempty"`
	ProtoRuntimeTypes          []ProtoRuntimeTypeFact      `json:"protoRuntimeTypes,omitempty"`
	GrpcServiceVars            []GrpcServiceVarFact        `json:"grpcServiceVars,omitempty"`
	MutatedStructTypes         []TypeRef                   `json:"mutatedStructTypes,omitempty"`
	ConditionalStructMutations []ConditionalStructMutation `json:"conditionalStructMutations,omitempty"`
	NoPostInitCarrierWrites    bool                        `json:"noPostInitCarrierWrites,omitempty"`
	CarrierImportCalls         []string                    `json:"carrierImportCalls,omitempty"`
	DirectVarWrites            []string                    `json:"directVarWrites,omitempty"`
}

// DeferralResolvent carries the typed resolvent of an explain deferral
// observation.
type DeferralResolvent struct {
	Param    ParamKey
	Method   FuncKey
	FieldPos FieldPosKey
	ElemUse  ElemParamUse
}

// ExplainHookSet carries the observation callbacks one explain re-derivation
// arms.
type ExplainHookSet struct {
	Site             func(p *packages.Package, kind, key string, pos token.Pos)
	ExportedSeamSite func(p *packages.Package, fn FuncKey, key string, pos token.Pos)
	Store            func(p *packages.Package, key string, pos token.Pos)
	Deferral         func(p *packages.Package, kind byte, key string, resolvent DeferralResolvent, at token.Pos)
	Refusal          func(p *packages.Package, fn string, e ast.Expr, clause string)
}

func explainMark(hooks *ExplainHookSet, p *packages.Package, kind, key string, at token.Pos) {
	if hooks != nil && hooks.Site != nil {
		hooks.Site(p, kind, key, at)
	}
}

func explainExportedSeamMark(hooks *ExplainHookSet, p *packages.Package, fn FuncKey, key string, at token.Pos) {
	if hooks != nil && hooks.ExportedSeamSite != nil {
		hooks.ExportedSeamSite(p, fn, key, at)
	}
}

func explainDeferralMark(hooks *ExplainHookSet, p *packages.Package, kind byte, key string, resolvent DeferralResolvent, at token.Pos) {
	if hooks != nil && hooks.Deferral != nil {
		hooks.Deferral(p, kind, key, resolvent, at)
	}
}

func explainStoreMark(hooks *ExplainHookSet, p *packages.Package, key string, at token.Pos) {
	if hooks != nil && hooks.Store != nil {
		hooks.Store(p, key, at)
	}
}

func explainRefusalMark(hooks *ExplainHookSet, p *packages.Package, fn string, e ast.Expr, clause string) {
	if hooks != nil && hooks.Refusal != nil {
		hooks.Refusal(p, fn, e, clause)
	}
}

// MethodDirectivesFactOf extracts only the method purity and externality
// directives declared in p, skipping dynamic-state and fixed-point derivation
// for pure-directive-only scans.
func MethodDirectivesFactOf(p *packages.Package) Fact {
	var fact Fact
	recordPackageMethodDirectives(p, &fact)
	return fact
}

func recordPackageMethodDirectives(p *packages.Package, fact *Fact) {
	if p == nil {
		return
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil {
				continue
			}
			recv := RecvTypeName(fd)
			if recv == "" {
				continue
			}
			key := recv + "." + fd.Name.Name
			if HasDirective(fd.Doc, "//gofresh:pure") {
				if fact.PureMethods == nil {
					fact.PureMethods = map[string]string{}
				}
				fact.PureMethods[key] = NodeDeclarationKey(p, fd.Name)
			}
			if HasDirective(fd.Doc, "//gofresh:external") {
				if fact.ExternalMethods == nil {
					fact.ExternalMethods = map[string]string{}
				}
				fact.ExternalMethods[key] = NodeDeclarationKey(p, fd.Name)
			}
		}
	}
}

// FactOf derives one package's dynamic-state fact from its syntax and type
// information.
func FactOf(audited bool, p *packages.Package, singleSubject bool) Fact {
	return FactOfWithHooks(audited, p, singleSubject, nil)
}

// FactOfWithHooks derives one package's dynamic-state fact with optional
// explain observation hooks armed.
func FactOfWithHooks(audited bool, p *packages.Package, singleSubject bool, hooks *ExplainHookSet) Fact {
	var fact Fact
	if p == nil {
		return fact
	}
	initOnly := initOnlyReachableHelpers(p)
	mutated := map[string]bool{}
	escaped := map[string]bool{}
	methodUses := map[string]map[FuncKey]bool{}
	paramUses := map[string]map[ParamKey]bool{}
	initParamUses := map[string]map[ParamKey]bool{}
	initMethodUses := map[string]map[FuncKey]bool{}
	fieldUses := map[string]map[FieldPosKey]bool{}
	elemUses := map[string]map[ElemParamUse]bool{}
	carrierLinks := map[string]map[string]bool{}
	var attributedUses []AttributedUse
	var poolDischarged map[string]bool
	if singleSubject {
		poolDischarged = map[string]bool{}
	}
	seams := analyzeBracketedSeams(audited, p, hooks)
	fact.ExportedSeams = seams.exportedSeams
	fact.NonSeqFuncUses = seams.nonSeqFuncUses
	fact.SeqFuncEdges = seams.seqFuncEdges
	fact.ParallelFuncs = seams.parallelFuncs
	fact.ParallelEdges = seams.parallelEdges
	recordDynamicGlobalUses(audited, p, seams.exempt, mutated, escaped, initOnly, methodUses, paramUses, initParamUses, initMethodUses, fieldUses, elemUses, carrierLinks, &attributedUses, singleSubject, poolDischarged, hooks)
	for key := range poolDischarged {
		fact.PoolDischarges = append(fact.PoolDischarges, key)
	}
	sort.Strings(fact.PoolDischarges)
	funcRefs := map[FuncKey]map[RefRegion]bool{}
	recordFunctionReferenceRegions(p, initOnly, funcRefs)
	opaque := map[string]bool{}
	breaks := map[string]bool{}
	opaqueDeps := map[string]map[string]bool{}
	recordOpaqueDynamicVars(p, opaque, breaks, opaqueDeps)
	for own, deps := range opaqueDeps {
		for dep := range deps {
			fact.OpaqueDeps = append(fact.OpaqueDeps, OpaqueDep{Own: own, Dep: dep})
		}
	}
	slices.SortFunc(fact.OpaqueDeps, OpaqueDep.Compare)
	envCarrying := map[string]bool{}
	envCalls := map[string]map[FuncKey]bool{}
	fieldDefer := map[FieldPosKey]map[ParamKey]bool{}
	fieldPoison := map[string]map[FieldParamPoison]bool{}
	recordEnvCarryingRegistrations(audited, p, seams.exempt, envCarrying, envCalls, fieldDefer, fieldPoison, hooks)
	for pos, params := range fieldDefer {
		for param := range params {
			fact.FieldParamDefer = append(fact.FieldParamDefer, FieldParamDefer{Pos: pos, Param: param})
		}
	}
	slices.SortFunc(fact.FieldParamDefer, FieldParamDefer.Compare)
	for _, entries := range fieldPoison {
		for entry := range entries {
			fact.FieldParamPoison = append(fact.FieldParamPoison, entry)
		}
	}
	slices.SortFunc(fact.FieldParamPoison, FieldParamPoison.Compare)
	for _, wants := range fieldUses {
		for want := range wants {
			fact.FieldParamUses = append(fact.FieldParamUses, want)
		}
	}
	slices.SortFunc(fact.FieldParamUses, FieldPosKey.Compare)
	for _, wants := range elemUses {
		for want := range wants {
			fact.ElemParamUses = append(fact.ElemParamUses, want)
		}
	}
	slices.SortFunc(fact.ElemParamUses, ElemParamUse.Compare)
	for key := range envCarrying {
		fact.EnvCarrying = append(fact.EnvCarrying, key)
	}
	sort.Strings(fact.EnvCarrying)
	ownPrefix := ""
	if p.Types != nil {
		ownPrefix = p.Types.Path() + "."
	}
	for key := range envCarrying {
		callable := true
		if ownPrefix != "" && strings.HasPrefix(key, ownPrefix) {
			if variable, ok := p.Types.Scope().Lookup(strings.TrimPrefix(key, ownPrefix)).(*types.Var); ok {
				if _, isFunc := types.Unalias(variable.Type()).Underlying().(*types.Signature); !isFunc {
					callable = false
				}
			}
		}
		if callable {
			fact.EnvCallable = append(fact.EnvCallable, key)
		}
	}
	sort.Strings(fact.EnvCallable)
	for varKey, callees := range envCalls {
		for callee := range callees {
			fact.EnvCallUses = append(fact.EnvCallUses, EnvCallUse{Key: varKey, Callee: callee})
		}
	}
	slices.SortFunc(fact.EnvCallUses, EnvCallUse.Compare)
	fact.AttributedUses = append(fact.AttributedUses, attributedUses...)
	slices.SortFunc(fact.AttributedUses, AttributedUse.Compare)
	for callee, regions := range funcRefs {
		for region := range regions {
			fact.FuncRefs = append(fact.FuncRefs, FuncRef{Callee: callee, Region: region})
		}
	}
	slices.SortFunc(fact.FuncRefs, FuncRef.Compare)
	readOnly := receiverReadOnlyMethods(audited, p)
	retentionMethods := receiverRetentionFreeMethods(audited, p, readOnly)
	if p.Types != nil {
		pkgPath := p.Types.Path()
		for method := range readOnly {
			fact.ReceiverReadOnly = append(fact.ReceiverReadOnly, FuncKey{Pkg: pkgPath, Name: method})
		}
		slices.SortFunc(fact.ReceiverReadOnly, FuncKey.Compare)
		for method := range retentionMethods {
			fact.ReceiverRetentionFree = append(fact.ReceiverRetentionFree, FuncKey{Pkg: pkgPath, Name: method})
		}
		slices.SortFunc(fact.ReceiverRetentionFree, FuncKey.Compare)
	}
	for varKey, methodKeys := range methodUses {
		for methodKey := range methodKeys {
			fact.MethodUses = append(fact.MethodUses, VarMethodUse{Key: varKey, Method: methodKey})
		}
	}
	slices.SortFunc(fact.MethodUses, VarMethodUse.Compare)
	if p.Types != nil {
		paramLeakFree, paramDeps, paramRetention, paramRetentionDeps := paramLeakFreeFunctions(audited, p, readOnly, retentionMethods)
		for paramKey := range paramLeakFree {
			fact.ParamLeakFree = append(fact.ParamLeakFree, paramKey)
		}
		slices.SortFunc(fact.ParamLeakFree, ParamKey.Compare)
		for ownKey, edges := range paramDeps {
			for dep := range edges {
				fact.ParamLeakFreeDeps = append(fact.ParamLeakFreeDeps, ParamDepEdge{Own: ownKey, Dep: dep})
			}
		}
		slices.SortFunc(fact.ParamLeakFreeDeps, ParamDepEdge.Compare)
		for paramKey := range paramRetention {
			fact.ParamRetentionFree = append(fact.ParamRetentionFree, paramKey)
		}
		slices.SortFunc(fact.ParamRetentionFree, ParamKey.Compare)
		for ownKey, edges := range paramRetentionDeps {
			for dep := range edges {
				fact.ParamRetentionFreeDeps = append(fact.ParamRetentionFreeDeps, ParamDepEdge{Own: ownKey, Dep: dep})
			}
		}
		slices.SortFunc(fact.ParamRetentionFreeDeps, ParamDepEdge.Compare)
		envFree, envDeps, retFieldDefer, retFieldPoison, insFree, insDeps, callerInsDeps := returnEnvFreeFunctions(audited, p, paramLeakFree, readOnly, hooks)
		pkgPath := p.Types.Path()
		for fnName := range envFree {
			fnKey := FuncKey{Pkg: pkgPath, Name: fnName}
			fact.ReturnEnvFree = append(fact.ReturnEnvFree, fnKey)
			for callee := range envDeps[fnName] {
				fact.ReturnEnvDeps = append(fact.ReturnEnvDeps, FuncDepEdge{Func: fnKey, Callee: callee})
			}
			for dep := range callerInsDeps[fnName] {
				fact.ReturnEnvInsertionDeps = append(fact.ReturnEnvInsertionDeps, FuncInsertionDepEdge{Func: fnKey, Dep: dep})
			}
			for entry := range retFieldDefer[fnName] {
				fact.ReturnFieldParamDefer = append(fact.ReturnFieldParamDefer, entry)
			}
			for entry := range retFieldPoison[fnName] {
				fact.ReturnFieldParamPoison = append(fact.ReturnFieldParamPoison, entry)
			}
		}
		slices.SortFunc(fact.ReturnEnvFree, FuncKey.Compare)
		slices.SortFunc(fact.ReturnEnvDeps, FuncDepEdge.Compare)
		slices.SortFunc(fact.ReturnEnvInsertionDeps, FuncInsertionDepEdge.Compare)
		slices.SortFunc(fact.ReturnFieldParamDefer, ReturnFieldParamDefer.Compare)
		slices.SortFunc(fact.ReturnFieldParamPoison, ReturnFieldParamPoison.Compare)
		for ownKey := range insFree {
			fact.ParamInsertionFree = append(fact.ParamInsertionFree, ownKey)
			for dep := range insDeps[ownKey] {
				fact.ParamInsertionDeps = append(fact.ParamInsertionDeps, ParamInsertionDepEdge{Param: ownKey, Dep: dep})
			}
		}
		slices.SortFunc(fact.ParamInsertionFree, ParamKey.Compare)
		slices.SortFunc(fact.ParamInsertionDeps, ParamInsertionDepEdge.Compare)
	}
	for varKey, paramKeys := range paramUses {
		for paramKey := range paramKeys {
			fact.ParamUses = append(fact.ParamUses, VarParamUse{Key: varKey, Param: paramKey})
		}
	}
	slices.SortFunc(fact.ParamUses, VarParamUse.Compare)
	for varKey, paramKeys := range initParamUses {
		for paramKey := range paramKeys {
			fact.InitParamUses = append(fact.InitParamUses, VarParamUse{Key: varKey, Param: paramKey})
		}
	}
	slices.SortFunc(fact.InitParamUses, VarParamUse.Compare)
	for varKey, methodKeys := range initMethodUses {
		for methodKey := range methodKeys {
			fact.InitMethodUses = append(fact.InitMethodUses, VarMethodUse{Key: varKey, Method: methodKey})
		}
	}
	slices.SortFunc(fact.InitMethodUses, VarMethodUse.Compare)
	for keyA, others := range carrierLinks {
		for keyB := range others {
			fact.CarrierLinks = append(fact.CarrierLinks, CarrierLink{From: keyA, To: keyB})
		}
	}
	slices.SortFunc(fact.CarrierLinks, CarrierLink.Compare)
	for key := range mutated {
		fact.Mutates = append(fact.Mutates, key)
	}
	sort.Strings(fact.Mutates)
	for key := range escaped {
		fact.Escapes = append(fact.Escapes, key)
	}
	sort.Strings(fact.Escapes)
	for key := range opaque {
		fact.Opaque = append(fact.Opaque, key)
	}
	sort.Strings(fact.Opaque)
	for key := range breaks {
		fact.OpacityBreaks = append(fact.OpacityBreaks, key)
	}
	sort.Strings(fact.OpacityBreaks)
	if p.Types != nil && p.Module != nil {
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			if variable, ok := scope.Lookup(name).(*types.Var); ok && TypeMayCarryUnknownDynamic(audited, variable.Type()) {
				fact.Declares = append(fact.Declares, dynamicVarKey(variable))
			}
		}
		sort.Strings(fact.Declares)
	}
	recordPackageMethodDirectives(p, &fact)
	var idx *pkgSyntaxIndex
	if p.Types != nil && p.TypesInfo != nil && len(p.Syntax) > 0 {
		idx = buildPkgSyntaxIndex(p)
		fact.DirectVarWrites = collectDirectCrossPkgVarWrites(audited, p, idx)
	}
	if p.Types != nil && p.Module != nil {
		for _, file := range p.Syntax {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					doc := vs.Doc
					if doc == nil && len(gd.Specs) == 1 {
						doc = gd.Doc
					}
					if !HasDirective(doc, "//gofresh:single-subject") {
						continue
					}
					for _, name := range vs.Names {
						variable, ok := p.TypesInfo.Defs[name].(*types.Var)
						if !ok || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
							continue
						}
						if !TypeMayCarryUnknownDynamic(audited, variable.Type()) {
							continue
						}
						fact.SingleSubjectVars = append(fact.SingleSubjectVars, dynamicVarKey(variable))
					}
				}
			}
		}
		sort.Strings(fact.SingleSubjectVars)
		if idx != nil {
			fact.MappingDischarges = deriveMappingDischarges(audited, p, idx)
			fact.MemoDischarges = deriveMemoDischarges(audited, p, idx)
			fact.ProtoClusters, fact.ProtoExtAliases, fact.ProtoRuntimeTypes, fact.GrpcServiceVars, fact.MutatedStructTypes, fact.ConditionalStructMutations =
				deriveProtoAndStructFacts(audited, p, idx, initOnly, mutated)
			fact.NonMutatingMethods = deriveNonMutatingMethods(audited, p, idx)
			fact.NoPostInitCarrierWrites, fact.CarrierImportCalls =
				deriveNoPostInitCarrierWrites(audited, p, idx, initOnly, fact.DirectVarWrites)
		}
	} else if idx != nil {
		fact.MutatedStructTypes, fact.ConditionalStructMutations = collectMutatedStructTypes(p, idx, nil, nil, nil)
		fact.NonMutatingMethods = deriveNonMutatingMethods(audited, p, idx)
		fact.NoPostInitCarrierWrites, fact.CarrierImportCalls =
			deriveNoPostInitCarrierWrites(audited, p, idx, initOnly, fact.DirectVarWrites)
	}
	return fact
}

type CulpritVerb uint8

const (
	CulpritMutated CulpritVerb = iota + 1
	CulpritEscapes
	CulpritEnvCarrying
)

func (v CulpritVerb) Clause() string {
	switch v {
	case CulpritMutated:
		return " is mutated"
	case CulpritEscapes:
		return " escapes writable"
	case CulpritEnvCarrying:
		return " registers function values outside the environment-free audit"
	default:
		return ""
	}
}

type CulpritChannel uint8

const (
	ChannelCallerVouch CulpritChannel = iota + 1
	ChannelCallerVouchEnvFree
	ChannelRestructureOrDirective
	ChannelRestructureDirectiveSingleSubjectOnly
	ChannelRestructureUnbackedDirective
)

func (ch CulpritChannel) Clause(pkgPath, key string) string {
	switch ch {
	case ChannelRestructureUnbackedDirective:
		return " (its //gofresh:single-subject directive is backed by no single-subject attestation here; dischargeable by restructuring the state)"
	case ChannelRestructureDirectiveSingleSubjectOnly:
		return " (dischargeable by restructuring the state; the //gofresh:single-subject directive discharges only under the caller's single-subject attestation, which the package-process model does not give)"
	case ChannelRestructureOrDirective:
		return " (dischargeable by restructuring the state, or by the //gofresh:single-subject directive on the declaration under the caller's single-subject attestation)"
	case ChannelCallerVouch, ChannelCallerVouchEnvFree:
		imp, bare := pkgPath, key
		if i := strings.LastIndexByte(key, '.'); i >= 0 {
			imp, bare = key[:i], key[i+1:]
		}
		obligation := "initialized once and never written"
		if ch == ChannelCallerVouchEnvFree {
			obligation += ", registering only environment-free function values"
		}
		return " (dischargeable by a caller vouch for " + imp + "." + bare + " — e.g. --vouch " + imp + ":" + bare + " where the consumer takes flags — on a source audit that the variable is " + obligation + ")"
	default:
		return ""
	}
}

// Culprit is one open package's named culprit in the downgrade walk's order
// (REQ-closure-shared-dynamic-state, REQ-closure-shared-dynamic-state-reason).
type Culprit struct {
	PkgPath string
	Key     string
	Verb    CulpritVerb
	Channel CulpritChannel
}

func (c Culprit) ReasonBody() string {
	return c.PkgPath + ": " + c.Key + c.Verb.Clause() + c.Channel.Clause(c.PkgPath, c.Key)
}

func (c Culprit) SubjectParts() (pkg, sym string) {
	imp, bare := c.PkgPath, c.Key
	if i := strings.LastIndexByte(c.Key, '.'); i >= 0 {
		imp, bare = c.Key[:i], c.Key[i+1:]
	}
	return imp, bare
}

// CulpritSiteSet is one culprit variable's marking-site inventory for the
// per-subject reachability re-judgment (REQ-closure-shared-dynamic-state).
type CulpritSiteSet struct {
	Fns          map[string]bool
	Unattributed bool
}

// ConeState is one view package's composed dynamic-state judgment over its own
// test-binary cone.
type ConeState struct {
	Downgraded            string
	CulpritPkg            string
	CulpritSym            string
	VouchDischarges       string
	AttestationDischarges string
	RootCulprits          []Culprit
	CulpritSites          map[string]CulpritSiteSet
}

// Cone selects the metadata nodes and the facts of one view package's
// test-binary graph out of a view-wide gathering.
func Cone(meta []GraphPackage, byListing map[string]GraphPackage, factsByListing map[string]Fact, viewPackage string) ([]GraphPackage, map[string][]Fact) {
	in := map[string]bool{}
	var visit func(listing string)
	visit = func(listing string) {
		if in[listing] {
			return
		}
		node, ok := byListing[listing]
		if !ok {
			return
		}
		in[listing] = true
		for _, imported := range node.Imports {
			visit(imported)
		}
	}
	testVariant := false
	for _, node := range meta {
		if node.PkgPath == viewPackage && node.ForTest == viewPackage {
			testVariant = true
			break
		}
	}
	for _, node := range meta {
		if (node.PkgPath == viewPackage && node.ForTest == "" && !testVariant) || node.ForTest == viewPackage {
			visit(node.ImportPath)
		}
	}
	var cone []GraphPackage
	facts := map[string][]Fact{}
	for _, node := range meta {
		if !in[node.ImportPath] {
			continue
		}
		cone = append(cone, node)
		if fact, ok := factsByListing[node.ImportPath]; ok {
			facts[node.PkgPath] = append(facts[node.PkgPath], fact)
		}
	}
	return cone, facts
}

// PinnedBuckets derives, per pinned module, the memo bucket completing its
// facts' input identity (REQ-closure-dynamic-state-memo, REQ-closure-mutable-local).
func PinnedBuckets(meta []GraphPackage) (buckets map[string]string, unkeyable map[string]bool) {
	imports := make(map[string][]string, len(meta))
	pins := make(map[string]string, len(meta))
	local := make(map[string]bool, len(meta))
	for _, node := range meta {
		imports[node.ImportPath] = node.Imports
		if node.Class == PinnedPackage {
			pins[node.ImportPath] = node.Pin
		}
		if node.Class == MutableLocalPackage {
			local[node.ImportPath] = true
		}
	}
	reachable := func(from string) (pinSet map[string]bool, localReached bool) {
		pinSet = map[string]bool{}
		seen := map[string]bool{}
		var walk func(string)
		walk = func(listing string) {
			if seen[listing] {
				return
			}
			seen[listing] = true
			if pin := pins[listing]; pin != "" {
				pinSet[pin] = true
			}
			if local[listing] {
				localReached = true
			}
			for _, imported := range imports[listing] {
				walk(imported)
			}
		}
		walk(from)
		return pinSet, localReached
	}
	coneByModule := map[string]map[string]bool{}
	unkeyable = map[string]bool{}
	for _, node := range meta {
		if node.Class != PinnedPackage {
			continue
		}
		pinSet, localReached := reachable(node.ImportPath)
		if localReached {
			unkeyable[node.Pin] = true
			continue
		}
		if coneByModule[node.Pin] == nil {
			coneByModule[node.Pin] = map[string]bool{}
		}
		for pin := range pinSet {
			coneByModule[node.Pin][pin] = true
		}
	}
	buckets = make(map[string]string, len(coneByModule))
	for pin, cone := range coneByModule {
		if unkeyable[pin] {
			continue
		}
		keys := make([]string, 0, len(cone))
		for k := range cone {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sum := sha256.Sum256([]byte(fmt.Sprintf("%q", keys)))
		buckets[pin] = pin + "|" + hex.EncodeToString(sum[:8])
	}
	return buckets, unkeyable
}
