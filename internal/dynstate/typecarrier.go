package dynstate

import (
	"go/ast"
	"go/types"
	"strconv"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
)

// CarrierWalkPolicy parameterizes WalkDynamicCarrier across the three carrier
// walk surfaces:
//   - CarrierPolicyClosure: the closure tier's carries-dynamic walk
//     (typeMayCarryDynamic), sharing seen into TypeParam constraint bounds.
//   - CarrierPolicyConsumer: the consumer tier's carries-dynamic walk
//     (typeMayCarryUnknownDynamic), entering TypeParam constraint bounds with
//     a fresh seen map.
//   - CarrierPolicyAlias: the consumer tier's alias-handing walk
//     (typeHandsOutDynamicAlias), where Signature is not an alias, TypeParam
//     recurses into t.Constraint() with seen, and reference-header elements
//     delegate to CarrierPolicyConsumer with a fresh seen map.
type CarrierWalkPolicy uint8

const (
	CarrierPolicyClosure CarrierWalkPolicy = iota
	CarrierPolicyConsumer
	CarrierPolicyAlias
)

// SignatureOpenWorldTerm names the first term of a signature that confers
// openness on its subject — a type parameter whose constraint does not bound
// its type set away from dynamic carriers, or a receiver or parameter whose
// type carries dynamic reach under policy — and returns "" for a closed
// signature (REQ-closure-analysis, REQ-closure-refusal-channels).
func SignatureOpenWorldTerm(audited bool, sig *types.Signature, extraTypeParams *types.TypeParamList, allowHarnessSignature bool, policy CarrierWalkPolicy) string {
	if sig == nil {
		return "unresolved signature"
	}
	for _, list := range []*types.TypeParamList{extraTypeParams, sig.TypeParams(), sig.RecvTypeParams()} {
		for i := 0; list != nil && i < list.Len(); i++ {
			if param := list.At(i); !TypeParamBoundsAwayFromDynamic(audited, param) {
				return "type parameter " + param.Obj().Name() + " constrained by " + types.TypeString(param.Constraint(), packageNameQualifier)
			}
		}
	}
	if allowHarnessSignature && isHarnessSubjectSignature(sig) {
		return ""
	}
	// One fresh map per parameter: sharing across parameters would let
	// one walk's marks short-circuit another's (a constraint interface
	// marked by a bounding evaluation reading clean as a later value
	// type); within one parameter's evaluation the map is shared - the
	// cycle guard for recursive constraints.
	if recv := sig.Recv(); recv != nil && WalkDynamicCarrier(audited, recv.Type(), make(map[types.Type]bool), policy) {
		return "receiver " + types.TypeString(recv.Type(), packageNameQualifier)
	}
	params := sig.Params()
	for i := 0; params != nil && i < params.Len(); i++ {
		param := params.At(i)
		if WalkDynamicCarrier(audited, param.Type(), make(map[types.Type]bool), policy) {
			name := param.Name()
			if name == "" || name == "_" {
				name = "#" + strconv.Itoa(i+1)
			}
			return "parameter " + name + " " + types.TypeString(param.Type(), packageNameQualifier)
		}
	}
	return ""
}

// OpenWorldTerm names the first term of a signature that confers openness on
// its subject under the consumer carrier walk policy (REQ-closure-refusal-channels).
func OpenWorldTerm(audited bool, sig *types.Signature) string {
	return SignatureOpenWorldTerm(audited, sig, nil, true, CarrierPolicyConsumer)
}

func packageNameQualifier(pkg *types.Package) string {
	if pkg == nil {
		return ""
	}
	return pkg.Name()
}

func isHarnessSubjectSignature(sig *types.Signature) bool {
	if sig == nil || sig.Recv() != nil || sig.Params().Len() != 1 {
		return false
	}
	pointer, ok := sig.Params().At(0).Type().(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := pointer.Elem().(*types.Named)
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

// AuditedAtomicPointerElem reports whether t is the toolchain's
// sync/atomic.Pointer[T] instantiation, yielding T: under the audited
// atomic transparency the carrier walks see the type as *T — its
// internal unsafe pointer is an implementation cell the zero-width *T
// field and the whole method set type-pin to *T, never an unsafe
// channel (REQ-closure-shared-dynamic-state). The audit covers exactly
// the toolchain's type: a defined wrapper inherits no methods and its
// cell is reached only through an address conversion the ordinary
// escape rules already mark, so it keeps the fail-closed judgment and
// never matches here (its Obj is not sync/atomic's). One helper for
// every carrier walk, so the tiers cannot diverge on this rule
// (REQ-closure-analysis's one-answer arm).
func AuditedAtomicPointerElem(audited bool, t *types.Named) (types.Type, bool) {
	if !audited {
		return nil, false
	}
	obj := t.Obj()
	if obj == nil || obj.Pkg() == nil ||
		obj.Pkg().Path() != "sync/atomic" || obj.Name() != "Pointer" ||
		t.TypeArgs() == nil || t.TypeArgs().Len() != 1 {
		return nil, false
	}
	return t.TypeArgs().At(0), true
}

// WalkDynamicCarrier is the one structural carrier walk shared by the closure
// and consumer tiers (REQ-closure-analysis, REQ-closure-shared-dynamic-state).
func WalkDynamicCarrier(audited bool, t types.Type, seen map[types.Type]bool, policy CarrierWalkPolicy) bool {
	if t == nil || seen[t] {
		return false
	}
	seen[t] = true
	aliasMode := policy == CarrierPolicyAlias
	refElem := func(elem types.Type) bool {
		if aliasMode {
			return WalkDynamicCarrier(audited, elem, make(map[types.Type]bool), CarrierPolicyConsumer)
		}
		return WalkDynamicCarrier(audited, elem, seen, policy)
	}
	switch t := types.Unalias(t).(type) {
	case *types.Basic:
		return t.Kind() == types.UnsafePointer
	case *types.Interface:
		return true
	case *types.Signature:
		return !aliasMode
	case *types.TypeParam:
		switch policy {
		case CarrierPolicyClosure:
			return !constraintBoundsAwayFromDynamic(audited, t.Constraint(), seen)
		case CarrierPolicyConsumer:
			return !TypeParamBoundsAwayFromDynamic(audited, t)
		case CarrierPolicyAlias:
			return WalkDynamicCarrier(audited, t.Constraint(), seen, policy)
		}
	case *types.Named:
		if elem, ok := AuditedAtomicPointerElem(audited, t); ok {
			return refElem(elem)
		}
		return WalkDynamicCarrier(audited, t.Underlying(), seen, policy)
	case *types.Pointer:
		return refElem(t.Elem())
	case *types.Slice:
		return refElem(t.Elem())
	case *types.Chan:
		return refElem(t.Elem())
	case *types.Map:
		return refElem(t.Key()) || refElem(t.Elem())
	case *types.Array:
		return WalkDynamicCarrier(audited, t.Elem(), seen, policy)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if WalkDynamicCarrier(audited, t.Field(i).Type(), seen, policy) {
				return true
			}
		}
	case *types.Tuple:
		for i := 0; i < t.Len(); i++ {
			if WalkDynamicCarrier(audited, t.At(i).Type(), seen, policy) {
				return true
			}
		}
	}
	return false
}

// TypeMayCarryUnknownDynamic reports whether t may carry dynamic reach under
// the consumer policy.
func TypeMayCarryUnknownDynamic(audited bool, t types.Type) bool {
	return WalkDynamicCarrier(audited, t, make(map[types.Type]bool), CarrierPolicyConsumer)
}

func typeMayCarryDynamic(audited bool, t types.Type, seen map[types.Type]bool) bool {
	return WalkDynamicCarrier(audited, t, seen, CarrierPolicyClosure)
}

// TypeHandsOutDynamicAlias reports whether reading the type hands out
// shared mutable access to dynamic state: an interface value (its
// concrete object is shared), a channel, a pointer, map, or slice
// reaching a dynamic carrier, or an unsafe pointer. Function values
// and by-value composites of them are copies — reading them cannot
// reach the shared cell (REQ-closure-shared-dynamic-state).
func TypeHandsOutDynamicAlias(audited bool, t types.Type) bool {
	return WalkDynamicCarrier(audited, t, make(map[types.Type]bool), CarrierPolicyAlias)
}

// TypeParamBoundsAwayFromDynamic reports whether one type parameter's
// constraint provably bounds its type set away from dynamic carriers -
// the openness question a parameterized subject asks per parameter,
// shared with the view tier so both tiers give one answer
// (REQ-closure-analysis's parameterized-subject arm).
func TypeParamBoundsAwayFromDynamic(audited bool, tp *types.TypeParam) bool {
	if tp == nil {
		return false
	}
	return constraintBoundsAwayFromDynamic(audited, tp.Constraint(), make(map[types.Type]bool))
}

// constraintBoundsAwayFromDynamic reports whether a type parameter's
// constraint provably bounds its type set away from dynamic carriers: the
// complete interface is methodless (a constraint method is a dispatch
// surface this analysis does not narrow), and at least one embedded
// element bounds the set - a union or specific type whose every term is
// free of interface, function, channel, and unsafe reach, or an embedded
// interface that itself bounds. Intersection semantics make one clean
// bounded element sufficient: the type set is the intersection of every
// element's set, so a dirty sibling only shrinks a clean bound, never
// widens it. `any` and `comparable` embed nothing and bound nothing.
func constraintBoundsAwayFromDynamic(audited bool, constraint types.Type, seen map[types.Type]bool) bool {
	iface, ok := types.Unalias(constraint).Underlying().(*types.Interface)
	if !ok {
		return false
	}
	return interfaceBoundsAwayFromDynamic(audited, iface, seen)
}

func interfaceBoundsAwayFromDynamic(audited bool, iface *types.Interface, seen map[types.Type]bool) bool {
	if iface == nil || iface.NumMethods() > 0 {
		return false
	}
	if seen[iface] {
		return false
	}
	seen[iface] = true
	bounded := false
	for i := 0; i < iface.NumEmbeddeds(); i++ {
		switch e := types.Unalias(iface.EmbeddedType(i)).(type) {
		case *types.Union:
			clean := true
			for j := 0; j < e.Len(); j++ {
				if typeMayCarryDynamic(audited, e.Term(j).Type(), seen) {
					clean = false
					break
				}
			}
			if clean {
				bounded = true
			}
		default:
			if under, ok := types.Unalias(e).Underlying().(*types.Interface); ok {
				if interfaceBoundsAwayFromDynamic(audited, under, seen) {
					bounded = true
				}
				continue
			}
			if !typeMayCarryDynamic(audited, e, seen) {
				bounded = true
			}
		}
	}
	return bounded
}

// walkTypeStructure traverses a type graph with cycle detection, invoking
// classify on each unaliased leaf/composite node. When classify returns
// decided=true, walkTypeStructure returns hit immediately; otherwise it
// descends into structural children (Named underlying, Struct fields, Array
// element).
func walkTypeStructure(t types.Type, seen map[types.Type]bool, nilResult bool, classify func(types.Type) (hit, decided bool)) bool {
	if t == nil {
		return nilResult
	}
	if seen[t] {
		return false
	}
	seen[t] = true
	u := types.Unalias(t)
	if hit, decided := classify(u); decided {
		return hit
	}
	switch u := u.(type) {
	case *types.Named:
		return walkTypeStructure(u.Underlying(), seen, nilResult, classify)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if walkTypeStructure(u.Field(i).Type(), seen, nilResult, classify) {
				return true
			}
		}
		return false
	case *types.Array:
		return walkTypeStructure(u.Elem(), seen, nilResult, classify)
	default:
		return true
	}
}

// typeCarriesSignature reports whether a type can hold a function value — a
// signature directly, or a container reaching one through struct fields,
// array/slice/map elements, pointers, or channels. Interfaces report false - a
// method call through a carrier-held interface value refuses in the use-shape
// engine, and a type assertion extracting a function is an unrecognized use
// there too, so the environment audit owes interfaces nothing.
func typeCarriesSignature(t types.Type) bool {
	return typeCarriesSignatureSeen(t, make(map[types.Type]bool))
}

func typeCarriesSignatureSeen(t types.Type, seen map[types.Type]bool) bool {
	return walkTypeStructure(t, seen, false, func(u types.Type) (bool, bool) {
		switch u := u.(type) {
		case *types.Signature:
			return true, true
		case *types.Basic, *types.Interface:
			return false, true
		case *types.Pointer:
			return typeCarriesSignatureSeen(u.Elem(), seen), true
		case *types.Slice:
			return typeCarriesSignatureSeen(u.Elem(), seen), true
		case *types.Chan:
			return typeCarriesSignatureSeen(u.Elem(), seen), true
		case *types.Map:
			return typeCarriesSignatureSeen(u.Elem(), seen), true
		case *types.Named, *types.Struct, *types.Array:
			return false, false
		default:
			return true, true
		}
	})
}

// callResultHandsOut reports whether a call's result set can hand its
// consumer carrier-derived state: any result - the single result type, or
// any element of a multi-result tuple - that hands out mutable reach or
// carries a signature refuses. A void call hands out nothing. Missing
// type information refuses, fail-closed like every judged value position.
func callResultHandsOut(t types.Type) bool {
	if t == nil {
		return true
	}
	if tuple, ok := t.(*types.Tuple); ok {
		for i := 0; i < tuple.Len(); i++ {
			rt := tuple.At(i).Type()
			if typeHandsOutMutableReach(rt) || typeCarriesSignature(rt) {
				return true
			}
		}
		return false
	}
	return typeHandsOutMutableReach(t) || typeCarriesSignature(t)
}

// typeHandsOutMutableReach reports whether holding a value of the type
// hands out write access to the memory it aliases: pointers, maps,
// slices, channels, unsafe pointers, and interfaces (concrete type
// unknown) do; function values do not - calling one executes program
// code whose own writes are judged where they are written, but the
// value itself cannot be written through. The receiver-effect and
// carrier read discharges gate on this, not on dynamic reach: a write
// through any aliased part of a tracked carrier is mutation
// (REQ-closure-shared-dynamic-state).
func typeHandsOutMutableReach(t types.Type) bool {
	return walkTypeStructure(t, make(map[types.Type]bool), false, func(u types.Type) (bool, bool) {
		switch u := u.(type) {
		case *types.Basic:
			return u.Kind() == types.UnsafePointer, true
		case *types.Interface, *types.Pointer, *types.Map, *types.Slice, *types.Chan, *types.TypeParam:
			return true, true
		case *types.Signature:
			return false, true
		case *types.Named, *types.Struct, *types.Array:
			return false, false
		default:
			return true, true
		}
	})
}

// rangeBindsAlias reports whether ranging the type binds an
// alias-handing value into the iteration variables.
func rangeBindsAlias(t types.Type) bool {
	switch t := types.Unalias(t).Underlying().(type) {
	case *types.Map:
		return typeHandsOutMutableReach(t.Key()) || typeHandsOutMutableReach(t.Elem())
	case *types.Slice:
		return typeHandsOutMutableReach(t.Elem())
	case *types.Array:
		return typeHandsOutMutableReach(t.Elem())
	case *types.Pointer:
		if arr, ok := types.Unalias(t.Elem()).Underlying().(*types.Array); ok {
			return typeHandsOutMutableReach(arr.Elem())
		}
		return true
	default:
		return false
	}
}

func fillSelection(info *types.Info, expr ast.Expr) bool {
	switch expr.(type) {
	case *ast.SelectorExpr, *ast.IndexExpr:
		return !typeReachesOnce(info.TypeOf(expr))
	}
	return false
}

// typeReachesOnce reports whether a type is or contains sync.Once by
// value — through named, struct, and array types.
func typeReachesOnce(t types.Type) bool {
	return walkTypeStructure(t, make(map[types.Type]bool), true, func(u types.Type) (bool, bool) {
		switch u := u.(type) {
		case *types.Named:
			if u.Obj() != nil && u.Obj().Pkg() != nil && u.Obj().Pkg().Path() == "sync" && u.Obj().Name() == "Once" {
				return true, true
			}
			return false, false
		case *types.Struct, *types.Array:
			return false, false
		default:
			return false, true
		}
	})
}

// onceFieldCount counts the by-value sync.Once fields of a receiver
// type (through its pointer), the memo bound's denominator.
func onceFieldCount(recv types.Type) int {
	if ptr, ok := types.Unalias(recv).(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	st, ok := types.Unalias(recv).Underlying().(*types.Struct)
	if !ok {
		return 0
	}
	n := 0
	for i := 0; i < st.NumFields(); i++ {
		if named, ok := types.Unalias(st.Field(i).Type()).(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "sync" && named.Obj().Name() == "Once" {
			n++
		}
	}
	return n
}

func instantiatedResultsHandOutNothing(audited bool, t types.Type) bool {
	sig, ok := types.Unalias(t).(*types.Signature)
	if !ok {
		return false
	}
	results := sig.Results()
	for i := 0; results != nil && i < results.Len(); i++ {
		rt := results.At(i).Type()
		if AuditedImmutableType(audited, rt) {
			continue
		}
		if typeHandsOutMutableReach(rt) || typeCarriesSignature(rt) {
			return false
		}
	}
	return true
}

// AuditedImmutableType is the audited set of types whose values are
// immutable by construction even though their kind hands out reach:
// reflect.Type is runtime-canonical and never written after
// construction. Grows only by source audit
// (REQ-closure-shared-dynamic-state).
func AuditedImmutableType(audited bool, t types.Type) bool {
	if !audited {
		return false
	}
	return immutableRuntimeType(t)
}

// immutableRuntimeType is the one spelling of the audited-immutable
// reflect types — the effect tiers' ruling and the object-closed
// store rule read it alike.
func immutableRuntimeType(t types.Type) bool {
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == "reflect" && auditset.ReflectImmutable(named.Obj().Name()) ||
		named.Obj().Pkg().Path() == "go/constant" && auditset.ConstantImmutable(named.Obj().Name())
}

// interfaceReceiver reports whether the method's receiver is an
// interface - dispatch the per-package proof cannot resolve.
func interfaceReceiver(fn *types.Func) bool {
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

// methodRecvNamedTypeName returns the declared receiver type's bare name
// (unwrapping pointer indirection and aliases), or "" when fn has no named
// receiver.
func methodRecvNamedTypeName(fn *types.Func) string {
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

// methodFactKey is the cross-package identity of a method's
// receiver-effect proof: declaring package path, receiver type name,
// method name.
func methodFactKey(fn *types.Func) FuncKey {
	recvName := methodRecvNamedTypeName(fn)
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

// AuditedSynchronization reports whether the method is in the audited
// synchronization set: sync.Mutex and sync.RWMutex lock operations,
// receiver-neutral because lock state cannot change dispatch. Grows
// only by source audit (REQ-closure-shared-dynamic-state).
func AuditedSynchronization(audited bool, fn *types.Func) bool {
	return audited && auditset.ReceiverMethod(fn, "sync", auditset.SyncMethod)
}

// AuditedPooling reports whether the method is in the audited pooling
// set: sync.Pool's Get and Put (REQ-closure-shared-dynamic-state).
func AuditedPooling(audited bool, fn *types.Func) bool {
	return audited && auditset.ReceiverMethod(fn, "sync", auditset.PoolMethod)
}

// dataMemoMethod reports whether the method is sync.Map's Load, Store,
// or LoadOrStore — the operations a data memo admits.
func dataMemoMethod(audited bool, fn *types.Func) bool {
	return audited && auditset.ReceiverMethod(fn, "sync", auditset.MemoMethod)
}

// auditedOnceDo reports whether the method is sync.Once's Do, the
// audited synchronization set's memo guard.
func auditedOnceDo(audited bool, fn *types.Func) bool {
	return audited && auditset.ReceiverMethod(fn, "sync", func(receiver, method string) bool {
		return receiver == "Once" && method == "Do"
	})
}

// RecvTypeName is a method's receiver type name with the leading pointer star
// and any generic parameters stripped — "" for a plain function or an
// unnameable receiver.
func RecvTypeName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
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

// recvTypeNameOf resolves the receiver type name of a selection's
// method through its declaring type, mirroring RecvTypeName's shape.
func recvTypeNameOf(p *packages.Package, sel *ast.SelectorExpr) string {
	selection, ok := p.TypesInfo.Selections[sel]
	if !ok {
		return ""
	}
	fn, ok := selection.Obj().(*types.Func)
	if !ok {
		return ""
	}
	return methodRecvNamedTypeName(fn)
}

// dynamicVarKey identifies a package-level variable stably across the
// test-variant recompilations packages.Load produces: variant type
// objects differ per graph, the (package path, name) pair does not.
func dynamicVarKey(variable *types.Var) string {
	if variable.Pkg() == nil {
		return variable.Name()
	}
	return variable.Pkg().Path() + "." + variable.Name()
}
