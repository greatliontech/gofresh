package closure

import (
	"go/constant"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

func regionIntegerKind(typ types.Type) (types.BasicKind, bool) {
	if typ == nil {
		return types.Invalid, false
	}
	basic, ok := typ.Underlying().(*types.Basic)
	if ok {
		switch basic.Kind() {
		case types.Int, types.Int8, types.Int16, types.Int32, types.Int64,
			types.Uint, types.Uint8, types.Uint16, types.Uint32, types.Uint64:
			return basic.Kind(), true
		}
	}
	return types.Invalid, false
}

// regionIntegerWidth returns bytes, with word widths supplied only by the
// selected typed owner. Fixed-width language types require no storage premise.
func regionIntegerWidth(typ types.Type, sizes types.Sizes) (int, bool) {
	kind, ok := regionIntegerKind(typ)
	if !ok {
		return 0, false
	}
	switch kind {
	case types.Int8, types.Uint8:
		return 1, true
	case types.Int16, types.Uint16:
		return 2, true
	case types.Int32, types.Uint32:
		return 4, true
	case types.Int64, types.Uint64:
		return 8, true
	default:
		if sizes != nil {
			width := sizes.Sizeof(typ)
			if width == 4 || width == 8 {
				return int(width), true
			}
		}
		return 0, false
	}
}

// regionIntegerOperation recognizes the type/operator grammar independently of
// incoming state and selected word width. Exactness is checked at transfer time.
func regionIntegerOperation(op *ssa.BinOp) bool {
	if op == nil || op.X == nil || op.Y == nil || !types.Identical(op.Type(), op.X.Type()) {
		return false
	}
	if _, ok := regionIntegerKind(op.Type()); !ok {
		return false
	}
	switch op.Op {
	case token.ADD:
		return types.Identical(op.Type(), op.Y.Type())
	case token.SHL:
		if _, ok := regionIntegerKind(op.Y.Type()); ok {
			return true
		}
		// Untyped counts occur only as actual SSA constants, never as an
		// independently invented untyped region value.
		c, ok := op.Y.(*ssa.Const)
		if !ok || c.Type() == nil {
			return false
		}
		b, ok := c.Type().Underlying().(*types.Basic)
		return ok && (b.Kind() == types.UntypedInt || b.Kind() == types.UntypedRune)
	}
	return false
}

// scalarConstant retains the common-32-bit policy without selection, extending
// only int/uint facts when their selected word extent is available.
func (k *regionKernel) scalarConstant(typ types.Type, value constant.Value) bool {
	kind, _ := regionIntegerKind(typ)
	if k.sizes == nil || kind != types.Int && kind != types.Uint {
		return regionScalarConstant(typ, value)
	}
	width, ok := regionIntegerWidth(typ, k.sizes)
	if !ok {
		return false
	}
	_, ok = regionReferenceWord(regionValue{typ: typ, kind: regionConstant, scalar: value}, width)
	return ok
}

func (k *regionKernel) integerBinary(op *ssa.BinOp, left, right regionValue) (regionValue, error) {
	if err := k.meter.tick(); err != nil {
		return regionValue{}, err
	}
	if !regionIntegerOperation(op) || !types.Identical(left.typ, op.X.Type()) || !types.Identical(right.typ, op.Y.Type()) {
		return regionValue{}, regionError("unsupported integer operation or operand types")
	}
	width, ok := regionIntegerWidth(op.Type(), k.sizes)
	if !ok {
		return regionValue{}, regionError("integer operation lacks its selected word width")
	}
	a, ok := regionReferenceWord(left, width)
	if !ok {
		return regionValue{}, regionError("integer operation lacks an exact left operand")
	}
	b := br.NewBuilder(k.meter.limits.nodes)
	sort := br.Bits(width * 8)
	x, err := b.Const(sort, a)
	if err != nil {
		return regionValue{}, err
	}
	var term br.Term
	if op.Op == token.ADD {
		value, ok := regionReferenceWord(right, width)
		if !ok {
			return regionValue{}, regionError("integer addition lacks an exact right operand")
		}
		y, err := b.Const(sort, value)
		if err != nil {
			return regionValue{}, err
		}
		term, err = b.Make(br.Add, sort, 0, x, y)
	} else {
		count := right.scalar
		if c, literal := op.Y.(*ssa.Const); literal {
			count = c.Value
		} else if right.kind != regionConstant || !k.scalarConstant(right.typ, count) {
			return regionValue{}, regionError("integer shift lacks an exact count")
		}
		if count == nil || count.Kind() != constant.Int || constant.Sign(count) < 0 {
			return regionValue{}, regionError("integer shift count is not a nonnegative integer")
		}
		n, ok := constant.Uint64Val(count)
		if !ok {
			return regionValue{}, regionError("integer shift count exceeds the supported extent")
		}
		// Go shifts do not mask the count to an architectural count register.
		term, err = b.Make(br.Shl, sort, n, x)
	}
	if err != nil {
		return regionValue{}, err
	}
	ctx := regionProofContext{Context: k.meter.ctx, meter: k.meter}
	bits, err := checkedScalarConstant(ctx, term, br.Limits{Nodes: k.meter.limits.nodes, Work: k.meter.limits.work})
	if err == errScalarConstantEndpoints || err == errScalarConstantUnknown {
		return regionValue{}, regionError(err.Error())
	}
	if err != nil {
		return regionValue{}, err
	}
	return regionReferenceValue(bits, op.Type(), width)
}
