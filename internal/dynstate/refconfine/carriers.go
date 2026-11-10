package refconfine

import (
	"go/ast"
	"go/types"
	"strconv"

	"github.com/greatliontech/gofresh/internal/auditset"
)

// CarrierWalkPolicy parameterizes WalkDynamicCarrier across the three carrier
// walk surfaces:
//   - CarrierPolicyClosure: the closure tier's carries-dynamic walk
//     (TypeMayCarryDynamic), sharing seen into TypeParam constraint bounds.
//   - CarrierPolicyConsumer: the consumer tier's carries-dynamic walk
//     (TypeMayCarryUnknownDynamic), entering TypeParam constraint bounds with
//     a fresh seen map.
//   - CarrierPolicyAlias: the consumer tier's alias-handing walk
//     (TypeHandsOutDynamicAlias), where Signature is not an alias, TypeParam
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
// channel (REQ-closure-shared-dynamic-state).
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

// TypeMayCarryDynamic reports whether t may carry dynamic reach under the
// closure policy using seen for cycle detection.
func TypeMayCarryDynamic(audited bool, t types.Type, seen map[types.Type]bool) bool {
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
// constraint provably bounds its type set away from dynamic carriers.
func TypeParamBoundsAwayFromDynamic(audited bool, tp *types.TypeParam) bool {
	if tp == nil {
		return false
	}
	return constraintBoundsAwayFromDynamic(audited, tp.Constraint(), make(map[types.Type]bool))
}

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
				if TypeMayCarryDynamic(audited, e.Term(j).Type(), seen) {
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
			if !TypeMayCarryDynamic(audited, e, seen) {
				bounded = true
			}
		}
	}
	return bounded
}

// WalkTypeStructure traverses a type graph with cycle detection, invoking
// classify on each unaliased leaf/composite node.
func WalkTypeStructure(t types.Type, seen map[types.Type]bool, nilResult bool, classify func(types.Type) (hit, decided bool)) bool {
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
		return WalkTypeStructure(u.Underlying(), seen, nilResult, classify)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if WalkTypeStructure(u.Field(i).Type(), seen, nilResult, classify) {
				return true
			}
		}
		return false
	case *types.Array:
		return WalkTypeStructure(u.Elem(), seen, nilResult, classify)
	case *types.Tuple:
		for i := 0; i < u.Len(); i++ {
			if WalkTypeStructure(u.At(i).Type(), seen, nilResult, classify) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

// TypeCarriesSignature reports whether a type can hold a function value — a
// signature directly, or a container reaching one through struct fields,
// array/slice/map elements, pointers, or channels.
func TypeCarriesSignature(t types.Type) bool {
	return typeCarriesSignatureSeen(t, make(map[types.Type]bool))
}

func typeCarriesSignatureSeen(t types.Type, seen map[types.Type]bool) bool {
	return WalkTypeStructure(t, seen, false, func(u types.Type) (bool, bool) {
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
		case *types.Named, *types.Struct, *types.Array, *types.Tuple:
			return false, false
		default:
			return true, true
		}
	})
}

// CallResultHandsOut reports whether a call's result set can hand its
// consumer carrier-derived state.
func CallResultHandsOut(t types.Type) bool {
	if t == nil {
		return true
	}
	return TypeHandsOutMutableReach(t) || TypeCarriesSignature(t)
}

// TypeHandsOutMutableReach reports whether holding a value of the type
// hands out write access to the memory it aliases.
func TypeHandsOutMutableReach(t types.Type) bool {
	return WalkTypeStructure(t, make(map[types.Type]bool), false, func(u types.Type) (bool, bool) {
		switch u := u.(type) {
		case *types.Basic:
			return u.Kind() == types.UnsafePointer, true
		case *types.Interface, *types.Pointer, *types.Map, *types.Slice, *types.Chan, *types.TypeParam:
			return true, true
		case *types.Signature:
			return false, true
		case *types.Named, *types.Struct, *types.Array, *types.Tuple:
			return false, false
		default:
			return true, true
		}
	})
}

// RangeBindsAlias reports whether ranging the type binds an
// alias-handing value into the iteration variables.
func RangeBindsAlias(t types.Type) bool {
	switch t := types.Unalias(t).Underlying().(type) {
	case *types.Map:
		return TypeHandsOutMutableReach(t.Key()) || TypeHandsOutMutableReach(t.Elem())
	case *types.Slice:
		return TypeHandsOutMutableReach(t.Elem())
	case *types.Array:
		return TypeHandsOutMutableReach(t.Elem())
	case *types.Pointer:
		if arr, ok := types.Unalias(t.Elem()).Underlying().(*types.Array); ok {
			return TypeHandsOutMutableReach(arr.Elem())
		}
		return true
	default:
		return false
	}
}

// FillSelection reports whether expr is a selector or index expression whose
// type does not reach sync.Once by value.
func FillSelection(info *types.Info, expr ast.Expr) bool {
	switch expr.(type) {
	case *ast.SelectorExpr, *ast.IndexExpr:
		return !TypeReachesOnce(info.TypeOf(expr))
	}
	return false
}

// TypeReachesOnce reports whether a type is or contains sync.Once by value.
func TypeReachesOnce(t types.Type) bool {
	return WalkTypeStructure(t, make(map[types.Type]bool), true, func(u types.Type) (bool, bool) {
		switch u := u.(type) {
		case *types.Named:
			if u.Obj() != nil && u.Obj().Pkg() != nil && u.Obj().Pkg().Path() == "sync" && u.Obj().Name() == "Once" {
				return true, true
			}
			return false, false
		case *types.Struct, *types.Array, *types.Tuple:
			return false, false
		default:
			return false, true
		}
	})
}

// OnceFieldCount counts the by-value sync.Once fields of a receiver type.
func OnceFieldCount(recv types.Type) int {
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

// InstantiatedResultsHandOutNothing reports whether every result of sig is
// either audited-immutable or free of mutable reach and signatures.
func InstantiatedResultsHandOutNothing(audited bool, t types.Type) bool {
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
		if TypeHandsOutMutableReach(rt) || TypeCarriesSignature(rt) {
			return false
		}
	}
	return true
}

// AuditedImmutableType is the audited set of types whose values are
// immutable by construction even though their kind hands out reach.
func AuditedImmutableType(audited bool, t types.Type) bool {
	if !audited {
		return false
	}
	return ImmutableRuntimeType(t)
}

// ImmutableRuntimeType reports whether t is in the audited-immutable reflect or
// go/constant type sets.
func ImmutableRuntimeType(t types.Type) bool {
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == "reflect" && auditset.ReflectImmutable(named.Obj().Name()) ||
		named.Obj().Pkg().Path() == "go/constant" && auditset.ConstantImmutable(named.Obj().Name())
}

// AuditedSynchronization reports whether fn is in the audited sync.Mutex /
// sync.RWMutex method set.
func AuditedSynchronization(audited bool, fn *types.Func) bool {
	return audited && auditset.ReceiverMethod(fn, "sync", auditset.SyncMethod)
}

// AuditedPooling reports whether fn is sync.Pool.Get or sync.Pool.Put.
func AuditedPooling(audited bool, fn *types.Func) bool {
	return audited && auditset.ReceiverMethod(fn, "sync", auditset.PoolMethod)
}

// DataMemoMethod reports whether fn is sync.Map.Load, Store, or LoadOrStore.
func DataMemoMethod(audited bool, fn *types.Func) bool {
	return audited && auditset.ReceiverMethod(fn, "sync", auditset.MemoMethod)
}

// AuditedOnceDo reports whether fn is sync.Once.Do.
func AuditedOnceDo(audited bool, fn *types.Func) bool {
	return audited && auditset.ReceiverMethod(fn, "sync", func(receiver, method string) bool {
		return receiver == "Once" && method == "Do"
	})
}
