package closure

import (
	"go/types"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// A typed nil pointer carried by an interface is not a nil interface. Exact nil
// tests can exclude a callee's dereference path, but never assume that path
// harmless when the receiver is unknown.
func regionNilEquality(a, b regionValue) (bool, bool) {
	if a.kind != regionNil && b.kind != regionNil {
		return false, false
	}
	if a.kind == regionNil && b.kind == regionNil {
		return true, true
	}
	other := a
	if a.kind == regionNil {
		other = b
	}
	switch other.kind {
	case regionPointer, regionSlice, regionCallable, regionInterface:
		return false, true
	}
	return false, false
}

// interfaceTarget binds the actual invoke method to the carried concrete type
// and receiver. FuncValue is a read-only object lookup. MethodValue/LookupMethod
// are deliberately not used: they may materialize forwarding wrappers and thus
// change the supposedly immutable source owner during checking.
func (k *regionKernel) interfaceTarget(call *ssa.Call, carrier regionValue) (*ssa.Function, regionValue, error) {
	refuse := func(message string) (*ssa.Function, regionValue, error) {
		return nil, regionValue{}, regionError(message)
	}
	method := call.Call.Method
	static, ok := call.Call.Value.Type().Underlying().(*types.Interface)
	if !ok || method == nil || !types.Identical(carrier.typ, call.Call.Value.Type()) {
		return refuse("invoke has no exact static interface method")
	}
	if carrier.kind != regionInterface || len(carrier.elements) != 1 {
		return refuse("nil interface or unknown dynamic type cannot be dispatched")
	}
	receiver := carrier.elements[0]
	if _, isInterface := receiver.typ.Underlying().(*types.Interface); isInterface {
		return refuse("interface receiver does not identify a concrete dynamic type")
	}
	if err := k.methodSetBudget(receiver.typ); err != nil {
		return nil, regionValue{}, err
	}
	if static.NumMethods() > k.meter.limits.nodes {
		return refuse("interface method count budget exhausted")
	}
	for i := 0; i < static.NumMethods(); i++ {
		if err := k.meter.tick(); err != nil {
			return nil, regionValue{}, err
		}
	}
	declared := types.NewMethodSet(call.Call.Value.Type()).Lookup(method.Pkg(), method.Name())
	if declared == nil || declared.Obj() != method {
		return refuse("invoke method is not the actual interface member")
	}
	selection := types.NewMethodSet(receiver.typ).Lookup(method.Pkg(), method.Name())
	if selection == nil || selection.Kind() != types.MethodVal || !types.Identical(selection.Recv(), receiver.typ) {
		return refuse("dynamic type has no matching typed method")
	}
	if len(selection.Index()) != 1 {
		return refuse("promoted interface method requires an unproved receiver adjustment")
	}
	object, ok := selection.Obj().(*types.Func)
	if !ok {
		return refuse("selected method has no function object")
	}
	signature, ok := object.Type().(*types.Signature)
	want, valid := method.Type().(*types.Signature)
	if !ok || !valid || signature.Recv() == nil || signature.TypeParams().Len() != 0 || signature.RecvTypeParams().Len() != 0 || object.Origin() != object {
		return refuse("generic or absent concrete method binding is unsupported")
	}
	if !types.Identical(signature.Recv().Type(), receiver.typ) {
		return refuse("interface receiver adjustment is unproved")
	}
	if signature.Variadic() != want.Variadic() || !types.Identical(signature.Params(), want.Params()) || !types.Identical(signature.Results(), want.Results()) {
		return refuse("concrete method signature differs from actual invoke")
	}
	target := k.input.owner.FuncValue(object)
	if target == nil {
		return refuse("canonical SSA method is not materialized in the selected owner")
	}
	if target.Prog != k.input.owner || target.Object() != object || target.Signature.Recv() == nil || !types.Identical(target.Signature.Recv().Type(), receiver.typ) || target.Synthetic != "" || target.Origin() != nil || len(target.FreeVars) != 0 {
		return refuse("selected method is not an ordinary non-adjusted canonical body")
	}
	if err := k.meter.tick(); err != nil {
		return nil, regionValue{}, err
	}
	return target, receiver, nil
}

// Price the declared methods and embedded-type surface before asking go/types
// for a method set. Type sets with generic receivers are not interpreted here.
// The traversal is independent of the SSA program's mutable method-set caches.
func (k *regionKernel) methodSetBudget(root types.Type) error {
	seen := map[types.Type]bool{}
	var visit func(types.Type, int) error
	visit = func(t types.Type, depth int) error {
		if err := k.meter.tick(); err != nil {
			return err
		}
		if depth > k.meter.limits.depth {
			return regionError("method-set depth budget exhausted")
		}
		if seen[t] {
			return nil
		}
		seen[t] = true
		switch x := t.(type) {
		case *types.Alias:
			return visit(x.Rhs(), depth+1)
		case *types.Pointer:
			return visit(x.Elem(), depth+1)
		case *types.TypeParam:
			return regionError("generic dynamic receiver is unsupported")
		case *types.Named:
			if x.TypeArgs().Len() != 0 || x.TypeParams().Len() != 0 {
				return regionError("generic dynamic receiver is unsupported")
			}
			if x.NumMethods() > k.meter.limits.nodes {
				return regionError("method count budget exhausted")
			}
			for i := 0; i < x.NumMethods(); i++ {
				if err := k.meter.tick(); err != nil {
					return err
				}
			}
			return visit(x.Underlying(), depth+1)
		case *types.Struct:
			if x.NumFields() > k.meter.limits.nodes {
				return regionError("method-set field budget exhausted")
			}
			for i := 0; i < x.NumFields(); i++ {
				if err := k.meter.tick(); err != nil {
					return err
				}
				if x.Field(i).Embedded() {
					if err := visit(x.Field(i).Type(), depth+1); err != nil {
						return err
					}
				}
			}
		case *types.Interface:
			if x.NumMethods() > k.meter.limits.nodes {
				return regionError("embedded interface method budget exhausted")
			}
			for i := 0; i < x.NumMethods(); i++ {
				if err := k.meter.tick(); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return visit(root, 0)
}
