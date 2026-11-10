package syntaxutil

import (
	"cmp"
	"go/ast"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
)

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

func (k FuncKey) SiteKey() string {
	return k.Pkg + "\x00" + k.Name
}

func (k FuncKey) Compare(o FuncKey) int {
	if c := cmp.Compare(k.Pkg, o.Pkg); c != 0 {
		return c
	}
	return cmp.Compare(k.Name, o.Name)
}

// MethodFactKey returns the cross-package identity of a method's receiver-effect
// proof: declaring package path, receiver type name, and method name.
func MethodFactKey(fn *types.Func) FuncKey {
	recvName := MethodRecvNamedTypeName(fn)
	pkg := ""
	if fn != nil && fn.Pkg() != nil {
		pkg = fn.Pkg().Path()
	}
	name := ""
	if fn != nil {
		name = recvName + "." + fn.Name()
	}
	return FuncKey{Pkg: pkg, Name: name}
}

// CallableFactKey returns the FuncKey for a plain function or named-receiver
// method, reporting whether fn has a valid cross-package fact key.
func CallableFactKey(fn *types.Func) (FuncKey, bool) {
	if fn == nil || fn.Pkg() == nil {
		return FuncKey{}, false
	}
	fn = fn.Origin()
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig == nil {
		return FuncKey{}, false
	}
	if sig.Recv() == nil {
		fk := FuncKey{Pkg: fn.Pkg().Path(), Name: fn.Name()}
		return fk, fk.Valid()
	}
	if MethodRecvNamedTypeName(fn) == "" {
		return FuncKey{}, false
	}
	fk := MethodFactKey(fn)
	return fk, fk.Valid()
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

func ExplainMark(hooks *ExplainHookSet, p *packages.Package, kind, key string, at token.Pos) {
	if hooks != nil && hooks.Site != nil {
		hooks.Site(p, kind, key, at)
	}
}

func ExplainExportedSeamMark(hooks *ExplainHookSet, p *packages.Package, fn FuncKey, key string, at token.Pos) {
	if hooks != nil && hooks.ExportedSeamSite != nil {
		hooks.ExportedSeamSite(p, fn, key, at)
	}
}

func ExplainDeferralMark(hooks *ExplainHookSet, p *packages.Package, kind byte, key string, resolvent DeferralResolvent, at token.Pos) {
	if hooks != nil && hooks.Deferral != nil {
		hooks.Deferral(p, kind, key, resolvent, at)
	}
}

func ExplainStoreMark(hooks *ExplainHookSet, p *packages.Package, key string, at token.Pos) {
	if hooks != nil && hooks.Store != nil {
		hooks.Store(p, key, at)
	}
}

func ExplainRefusalMark(hooks *ExplainHookSet, p *packages.Package, fn string, e ast.Expr, clause string) {
	if hooks != nil && hooks.Refusal != nil {
		hooks.Refusal(p, fn, e, clause)
	}
}
