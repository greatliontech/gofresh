package closure

import (
	"go/token"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// abstractTransfer supplies language normal-success over-approximations where
// exact evaluation is unnecessary. It is never used by the finite effect arm.
// Exceptional outcomes have no frame or prefix-safety authority in this scope.
func (k *regionKernel) abstractTransfer(s *regionState, ins ssa.Instruction) (bool, error) {
	if !k.input.normalReturns {
		return false, nil
	}
	get := func(v ssa.Value) regionValue { return k.value(*s, v) }
	unknown := func(v ssa.Value) (bool, error) { return true, k.setValue(s, v, regionUnknownValue(v.Type())) }
	switch x := ins.(type) {
	case *ssa.FieldAddr:
		if get(x.X).kind != regionPointer {
			return unknown(x)
		}
	case *ssa.UnOp:
		if x.Op == token.MUL && get(x.X).kind != regionPointer {
			return unknown(x)
		}
	case *ssa.IndexAddr:
		base := get(x.X)
		if base.kind != regionPointer && base.kind != regionSlice {
			return unknown(x)
		}
		if _, exact := regionInt(get(x.Index)); !exact {
			loc := base.location
			loc.path = append(slices.Clone(loc.path), regionStep{summary: true})
			v := regionValue{typ: x.Type(), kind: regionPointer, location: loc}
			return true, k.setValue(s, x, v)
		}
	case *ssa.Index:
		if _, exact := regionInt(get(x.Index)); !exact {
			return unknown(x)
		}
		if get(x.X).kind == regionUnknown {
			return unknown(x)
		}
	case *ssa.Slice:
		if get(x.X).kind == regionUnknown {
			return unknown(x)
		}
	case *ssa.BinOp:
		if b, ok := x.X.Type().Underlying().(*types.Basic); ok && b.Info()&types.IsInteger != 0 && !regionIsComparison(x.Op) {
			switch x.Op {
			case token.ADD, token.SUB, token.MUL, token.QUO, token.REM, token.AND, token.OR, token.XOR, token.AND_NOT, token.SHL, token.SHR:
				return unknown(x)
			}
		}
	case *ssa.Convert:
		a, aok := x.X.Type().Underlying().(*types.Basic)
		b, bok := x.Type().Underlying().(*types.Basic)
		if aok && bok && a.Info()&types.IsNumeric != 0 && b.Info()&types.IsNumeric != 0 {
			return unknown(x)
		}
	case *ssa.Store:
		addr := get(x.Addr)
		if addr.kind != regionPointer {
			if k.escapingView(get(x.Val)) {
				return true, regionError("storage view cannot escape through memory")
			}
			_, ok := x.Addr.Type().Underlying().(*types.Pointer)
			if !ok {
				return true, regionError("abstract write has no typed target")
			}
			return true, k.havocUnknownStorage(s)
		}
	case *ssa.Call:
		b, ok := x.Call.Value.(*ssa.Builtin)
		if !ok {
			return false, nil
		}
		switch b.Name() {
		case "len", "cap":
			if len(x.Call.Args) != 1 {
				return true, regionError("invalid builtin arguments")
			}
			v := get(x.Call.Args[0])
			if v.kind == regionUnknown || v.kind == regionMap {
				return unknown(x)
			}
		case "append":
			if len(x.Call.Args) != 2 {
				return true, regionError("unsupported append arguments")
			}
			t, ok := x.Call.Args[0].Type().Underlying().(*types.Slice)
			if !ok {
				return true, regionError("append lacks slice storage")
			}
			if err := k.havocTypedStorage(s, t.Elem()); err != nil {
				return true, err
			}
			return unknown(x)
		}
	}
	return false, nil
}

// Language backing-array writes carry their element type. With additional bit
// interpretations and no bounded backing provenance, even that type cannot
// supply disjointness: retain the unknown-object footprint instead.
func (k *regionKernel) havocTypedStorage(s *regionState, typ types.Type) error {
	if k.input.storageModel.interpretation == regionIEEE754LittleEndian && k.input.storageModel.valid(k.input) {
		return k.havocUnknownStorage(s)
	}
	if err := k.addFrameType(&k.frame.typed, typ); err != nil {
		return err
	}
	for object := range s.memory {
		if err := k.meter.tick(); err != nil {
			return err
		}
		if object.kind == regionMapAllocation {
			continue
		}
		storage := k.objectType(object)
		if storage == nil {
			delete(s.memory, object)
			continue
		}
		yes, err := k.typedStorageOverlaps(storage, typ, 0)
		if err != nil {
			return err
		}
		if yes {
			delete(s.memory, object)
		}
	}
	return nil
}
