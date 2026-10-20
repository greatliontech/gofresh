package closure

import (
	"context"
	"errors"
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func regionFixture(t testing.TB, source string) regionInput {
	t.Helper()
	s := computationFixture(t, source)
	fn := s.prog.Roots["F"]
	var use regionUse
	for _, b := range fn.Blocks {
		for i, ins := range b.Instrs {
			if ret, ok := ins.(*ssa.Return); ok {
				use.at = regionPoint{b, i}
				if len(ret.Results) != 0 {
					use.operand = ret.Results[0]
				}
			}
		}
	}
	return regionInput{owner: s.prog.Prog, root: fn, entry: regionPoint{fn.Blocks[0], 0}, use: use,
		premises: []string{"immutable typed SSA; selected-source binding open", "entry heap/parameters as specified; omitted initialization and interference open"}}
}

func proveRegionFixture(t testing.TB, in regionInput) (*checkedRegion, *regionProposal) {
	t.Helper()
	p, err := proposeRegion(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	c, err := checkRegion(t.Context(), in, p, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	return c, p
}

func regionAtCall(t testing.TB, in regionInput, name string, arg int) regionInput {
	t.Helper()
	for _, block := range in.root.Blocks {
		for i, instruction := range block.Instrs {
			if call, ok := instruction.(*ssa.Call); ok && call.Call.StaticCallee() != nil && call.Call.StaticCallee().Name() == name {
				in.use = regionUse{regionPoint{block, i}, call.Call.Args[arg]}
				return in
			}
		}
	}
	t.Fatal("actual call missing")
	return in
}

// The oracle below is a concrete interpreter with fresh heap objects on EACH
// allocation, mutable field cells, and actual predecessor execution. It shares
// no abstract transfer, inclusion, join, zero, or path helper with the kernel.
// Its bounded execution is only a test oracle for these terminating fixtures.
type regionConcretePointer struct{ cell *any }
type regionConcreteSlice struct {
	cells                   []any
	start, length, capacity int
}
type regionConcreteFunction struct {
	target      *ssa.Function
	environment []any
}
type regionConcreteInterface struct {
	typ   types.Type
	value any
}
type regionConcreteResults []any

func regionConcreteCopy(value any) any {
	if fields, ok := value.([]any); ok {
		copy := make([]any, len(fields))
		for i, field := range fields {
			copy[i] = regionConcreteCopy(field)
		}
		return copy
	}
	return value // pointers, slices and function values preserve their aliases
}

// Assignment evaluates the whole RHS before writing any destination cell.
// Aggregate objects retain their field/element cells, so a pointer taken before
// an overwrite still designates the corresponding cell afterward. The snapshot
// also handles self-assignment and overlapping source/destination arrays.
func regionConcreteStore(destination *any, source any) {
	regionConcreteWrite(destination, regionConcreteCopy(source))
}

func regionConcreteWrite(destination *any, snapshot any) {
	if fields, aggregate := snapshot.([]any); aggregate {
		cells, ok := (*destination).([]any)
		if !ok || len(cells) != len(fields) {
			panic("oracle aggregate assignment type mismatch")
		}
		for i, field := range fields {
			regionConcreteWrite(&cells[i], field)
		}
		return
	}
	*destination = snapshot
}

// Concrete Go equality evaluates fields/elements in order. Interface values
// first compare dynamic types and may then panic on incomparable dynamic data.
// This executes actual values; it does not use the kernel's static totality
// predicate or abstract joins.
func regionConcreteEqual(typ types.Type, a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if !types.Comparable(typ) {
		panic("oracle comparison of incomparable dynamic type")
	}
	switch t := typ.Underlying().(type) {
	case *types.Basic:
		if t.Kind() == types.Float32 {
			x, xok := a.(float32)
			y, yok := b.(float32)
			if !xok || !yok {
				panic(regionConcreteFailure{"oracle float32 equality type mismatch"})
			}
			return x == y
		}
		if t.Kind() == types.Float64 {
			x, xok := a.(float64)
			y, yok := b.(float64)
			if !xok || !yok {
				panic(regionConcreteFailure{"oracle float64 equality type mismatch"})
			}
			return x == y
		}
		return a == b
	case *types.Interface:
		x, y := a.(regionConcreteInterface), b.(regionConcreteInterface)
		if !types.Identical(x.typ, y.typ) {
			return false
		}
		if !types.Comparable(x.typ) {
			panic("oracle comparison of incomparable dynamic type")
		}
		return regionConcreteEqual(x.typ, x.value, y.value)
	case *types.Struct:
		x, y := a.([]any), b.([]any)
		for i := 0; i < t.NumFields(); i++ {
			if t.Field(i).Name() != "_" && !regionConcreteEqual(t.Field(i).Type(), x[i], y[i]) {
				return false
			}
		}
		return true
	case *types.Array:
		x, y := a.([]any), b.([]any)
		for i := int64(0); i < t.Len(); i++ {
			if !regionConcreteEqual(t.Elem(), x[i], y[i]) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}

func regionConcreteZero(t types.Type) any {
	return regionConcreteZeroTyped(t, false)
}

func regionConcreteZeroTyped(t types.Type, unsigned bool) any {
	switch u := t.Underlying().(type) {
	case *types.Basic:
		switch {
		case u.Info()&types.IsBoolean != 0:
			return false
		case u.Info()&types.IsString != 0:
			return ""
		case u.Kind() == types.Float32:
			return float32(0)
		case u.Kind() == types.Float64:
			return float64(0)
		case u.Info()&types.IsInteger != 0:
			if unsigned && u.Info()&types.IsUnsigned != 0 {
				return uint64(0)
			}
			return int64(0)
		}
	case *types.Struct:
		v := make([]any, u.NumFields())
		for i := range v {
			v[i] = regionConcreteZeroTyped(u.Field(i).Type(), unsigned)
		}
		return v
	case *types.Array:
		v := make([]any, u.Len())
		for i := range v {
			v[i] = regionConcreteZeroTyped(u.Elem(), unsigned)
		}
		return v
	case *types.Pointer, *types.Signature, *types.Interface, *types.Slice:
		return nil
	}
	panic("oracle unsupported type")
}

// Bounds are decoded before conversion to the host index type. The limit is an
// actual concrete string/array/slice extent, so a successful check also proves
// that conversion to int cannot truncate a large unsigned language value.
// Slice endpoints may equal their limit; element indices must be strictly below it.
func regionConcreteBound(value any, limit int, endpoint bool) int {
	var index uint64
	switch value := value.(type) {
	case int64:
		if value < 0 {
			panic(regionConcreteFailure{"oracle negative index or slice bound"})
		}
		index = uint64(value)
	case uint64:
		index = value
	default:
		panic(regionConcreteFailure{"oracle index or slice bound is not an integer"})
	}
	if limit < 0 || index > uint64(limit) || !endpoint && index == uint64(limit) {
		panic(regionConcreteFailure{"oracle index or slice bound out of range"})
	}
	return int(index)
}

// Both simple and full slicing obey low <= high <= max <= capacity; a simple
// slice uses the original capacity as max. An omitted high defaults to length,
// even when the operand is a shortened view with a larger capacity.
func regionConcreteSliceBounds(ins *ssa.Slice, length, capacity int, get func(ssa.Value) any) (low, high, max int) {
	bound := func(operand ssa.Value, fallback, limit int) int {
		value := any(int64(fallback))
		if operand != nil {
			value = get(operand)
		}
		return regionConcreteBound(value, limit, true)
	}
	max = bound(ins.Max, capacity, capacity)
	high = bound(ins.High, length, max)
	low = bound(ins.Low, 0, high)
	return low, high, max
}

func executeRegionConcrete(t testing.TB, in regionInput, args ...any) any {
	steps := 0
	return executeRegionConcreteFrame(t, in, map[*ssa.Global]*any{}, args, nil, false, 0, &steps, nil, 0)
}

func executeRegionConcreteFrame(t testing.TB, in regionInput, globals map[*ssa.Global]*any, args, environment []any, whole bool, depth int, steps *int, run *regionConcreteExecution, invocation uint64) any {
	t.Helper()
	if depth > 32 {
		if run != nil {
			panic(regionConcreteFailure{"concrete oracle call depth exhausted"})
		}
		t.Fatal("concrete oracle call depth exhausted")
	}
	values := map[ssa.Value]any{}
	for i, parameter := range in.root.Params {
		values[parameter] = args[i]
	}
	for i, free := range in.root.FreeVars {
		values[free] = environment[i]
	}
	get := func(value ssa.Value) any {
		switch x := value.(type) {
		case *ssa.Const:
			if x.IsNil() {
				return nil
			}
			if x.Value == nil {
				return regionConcreteZeroTyped(x.Type(), run != nil)
			}
			if basic, ok := x.Type().Underlying().(*types.Basic); ok && basic.Info()&types.IsFloat != 0 {
				var value any
				switch basic.Kind() {
				case types.Float32:
					v, _ := constant.Float32Val(x.Value)
					if math.IsInf(float64(v), 0) {
						panic(regionConcreteFailure{"oracle float32 constant overflow"})
					}
					if v == 0 {
						v = 0 // Language constants have unsigned zero, even after underflow.
					}
					value = v
				case types.Float64:
					v, _ := constant.Float64Val(x.Value)
					if math.IsInf(v, 0) {
						panic(regionConcreteFailure{"oracle float64 constant overflow"})
					}
					if v == 0 {
						v = 0
					}
					value = v
				default:
					panic(regionConcreteFailure{"oracle unsupported float constant type"})
				}
				if run != nil {
					return run.checkedValue(x.Type(), value)
				}
				return value
			}
			switch x.Value.Kind() {
			case constant.Bool:
				return constant.BoolVal(x.Value)
			case constant.String:
				return constant.StringVal(x.Value)
			case constant.Int:
				if run != nil && x.Type().Underlying().(*types.Basic).Info()&types.IsUnsigned != 0 {
					n, ok := constant.Uint64Val(x.Value)
					if !ok {
						t.Fatal("oracle unsigned integer range")
					}
					return n
				}
				n, ok := constant.Int64Val(x.Value)
				if !ok {
					t.Fatal("oracle integer range")
				}
				return n
			}
		case *ssa.Global:
			if globals[x] == nil {
				if run != nil {
					panic(regionConcreteFailure{fmt.Sprintf("missing explicit initial global %s", x)})
				}
				z := regionConcreteZero(x.Type().Underlying().(*types.Pointer).Elem())
				globals[x] = &z
			}
			return regionConcretePointer{globals[x]}
		case *ssa.Function:
			return regionConcreteFunction{target: x}
		}
		v, ok := values[value]
		if !ok {
			t.Fatalf("oracle missing %s", value)
		}
		return v
	}
	block, predecessor, start := in.entry.block, (*ssa.BasicBlock)(nil), in.entry.index
	for work := 0; run != nil || work < 1000; work++ {
		phis := map[ssa.Value]any{}
		for _, ins := range block.Instrs {
			p, ok := ins.(*ssa.Phi)
			if !ok {
				break
			}
			phis[p] = get(p.Edges[slices.Index(block.Preds, predecessor)])
		}
		for key, value := range phis {
			values[key] = value
		}
		var next *ssa.BasicBlock
		for i := start; i < len(block.Instrs); i++ {
			if !whole && block == in.use.at.block && i == in.use.at.index {
				if run != nil {
					call, ok := block.Instrs[i].(*ssa.Call)
					if !ok {
						panic(regionConcreteFailure{"joint operand endpoint is not an actual call"})
					}
					run.cut = call
					run.operands = make([]any, len(call.Call.Args))
					for j, arg := range call.Call.Args {
						run.operands[j] = run.snapshot(get(arg))
					}
				}
				if in.use.operand == nil {
					return nil
				}
				return get(in.use.operand)
			}
			*steps++
			if run != nil && *steps > run.maxSteps {
				panic(regionConcreteFailure{"concrete oracle instruction budget exhausted"})
			}
			if run == nil && *steps > 10000 {
				t.Fatal("concrete oracle execution bound exhausted")
			}
			ins := block.Instrs[i]
			observation := -1
			if run != nil {
				observation = run.instruction(ins, invocation, predecessor)
				if phi, ok := ins.(*ssa.Phi); ok {
					run.instructions[observation].Value = run.snapshot(values[phi])
				}
			}
			switch x := ins.(type) {
			case *ssa.Phi, *ssa.DebugRef:
			case *ssa.Alloc:
				z := regionConcreteZeroTyped(x.Type().Underlying().(*types.Pointer).Elem(), run != nil)
				values[x] = regionConcretePointer{&z}
				if run != nil {
					run.allocate(x, invocation, &z)
				}
			case *ssa.FieldAddr:
				p := get(x.X).(regionConcretePointer)
				cells := (*p.cell).([]any)
				values[x] = regionConcretePointer{&cells[x.Field]}
			case *ssa.IndexAddr:
				index := get(x.Index)
				switch p := get(x.X).(type) {
				case nil:
					panic(regionConcreteFailure{"oracle index through nil slice or array pointer"})
				case regionConcretePointer:
					cells := (*p.cell).([]any)
					values[x] = regionConcretePointer{&cells[regionConcreteBound(index, len(cells), false)]}
				case regionConcreteSlice:
					values[x] = regionConcretePointer{&p.cells[p.start+regionConcreteBound(index, p.length, false)]}
				}
			case *ssa.Store:
				p := get(x.Addr).(regionConcretePointer)
				value := get(x.Val)
				if run != nil {
					run.store(p, x.Addr.Type(), x.Val.Type(), value)
					run.access(x, invocation, p, x.Val.Type(), value, true)
				} else {
					regionConcreteStore(p.cell, value)
				}
			case *ssa.UnOp:
				if x.Op == token.MUL {
					p := get(x.X).(regionConcretePointer)
					values[x] = regionConcreteCopy(*p.cell)
					if run != nil {
						values[x] = run.load(p, x.X.Type(), x.Type())
						run.access(x, invocation, p, x.Type(), values[x], false)
					}
				} else if x.Op == token.NOT {
					values[x] = !get(x.X).(bool)
				} else {
					t.Fatalf("oracle unary %v", x)
				}
			case *ssa.Slice:
				base := get(x.X)
				if text, ok := base.(string); ok {
					lo, hi, _ := regionConcreteSliceBounds(x, len(text), len(text), get)
					values[x] = text[lo:hi]
					break
				}
				if base == nil {
					if _, slice := x.X.Type().Underlying().(*types.Slice); !slice {
						panic(regionConcreteFailure{"oracle slice through nil array pointer"})
					}
					regionConcreteSliceBounds(x, 0, 0, get)
					values[x] = nil
					break
				}
				var s regionConcreteSlice
				switch base := base.(type) {
				case regionConcretePointer:
					cells := (*base.cell).([]any)
					s = regionConcreteSlice{cells: cells, length: len(cells), capacity: len(cells)}
				case regionConcreteSlice:
					s = base
				}
				lo, hi, max := regionConcreteSliceBounds(x, s.length, s.capacity, get)
				s.start += lo
				s.length, s.capacity = hi-lo, max-lo
				values[x] = s
			case *ssa.MakeClosure:
				f := regionConcreteFunction{target: x.Fn.(*ssa.Function)}
				for _, b := range x.Bindings {
					f.environment = append(f.environment, regionConcreteCopy(get(b)))
				}
				values[x] = f
			case *ssa.MakeInterface:
				values[x] = regionConcreteInterface{x.X.Type(), regionConcreteCopy(get(x.X))}
			case *ssa.ChangeInterface:
				values[x] = get(x.X)
			case *ssa.ChangeType:
				// Typed SSA defines ChangeType as value-preserving, including
				// names, pointer views, channel directions and instantiations.
				// Numeric and unsafe reinterpretations are Convert instructions.
				values[x] = get(x.X)
			case *ssa.Convert:
				if run == nil {
					t.Fatalf("oracle unsupported conversion %s", x)
				}
				values[x] = run.convert(get(x.X), x.X.Type(), x.Type())
			case *ssa.Field:
				values[x] = get(x.X).([]any)[x.Field]
			case *ssa.Index:
				base, index := get(x.X), get(x.Index)
				if text, ok := base.(string); ok {
					at := regionConcreteBound(index, len(text), false)
					values[x] = int64(text[at])
					if run != nil {
						values[x] = uint64(text[at])
					}
				} else {
					array := base.([]any)
					values[x] = array[regionConcreteBound(index, len(array), false)]
				}
			case *ssa.BinOp:
				a, b := get(x.X), get(x.Y)
				if run != nil {
					run.instructions[observation].Operands = []any{run.snapshot(a), run.snapshot(b)}
					if x.Op == token.ADD || x.Op == token.SHL {
						values[x] = run.integerBinary(x, a, b)
						run.instructions[observation].Value = run.snapshot(values[x])
						break
					}
				}
				if run != nil && (x.Op == token.EQL || x.Op == token.NEQ) {
					run.checkEquality(x.X.Type(), x.Y.Type(), a, b)
				}
				if x.Op == token.EQL {
					values[x] = regionConcreteEqual(x.X.Type(), a, b)
				} else if x.Op == token.NEQ {
					values[x] = !regionConcreteEqual(x.X.Type(), a, b)
				} else if left, ok := a.(uint64); ok {
					right := b.(uint64)
					switch x.Op {
					case token.LSS:
						values[x] = left < right
					case token.LEQ:
						values[x] = left <= right
					case token.GTR:
						values[x] = left > right
					case token.GEQ:
						values[x] = left >= right
					default:
						t.Fatalf("oracle unsigned comparison %s", x)
					}
				} else if left, ok := a.(int64); ok {
					right := b.(int64)
					switch x.Op {
					case token.LSS:
						values[x] = left < right
					case token.LEQ:
						values[x] = left <= right
					case token.GTR:
						values[x] = left > right
					case token.GEQ:
						values[x] = left >= right
					default:
						t.Fatalf("oracle comparison %s", x)
					}
				} else {
					t.Fatalf("oracle comparison %s", x)
				}
				if run != nil {
					run.instructions[observation].Value = run.snapshot(values[x])
				}
			case *ssa.If:
				condition := get(x.Cond).(bool)
				if condition {
					next = block.Succs[0]
				} else {
					next = block.Succs[1]
				}
				if run != nil {
					run.instructions[observation].Value = condition
					run.instructions[observation].Successor = 0
					if !condition {
						run.instructions[observation].Successor = 1
					}
				}
			case *ssa.Jump:
				next = block.Succs[0]
				if run != nil {
					run.instructions[observation].Successor = 0
				}
			case *ssa.Call:
				b, builtin := x.Call.Value.(*ssa.Builtin)
				if !builtin {
					var callee regionConcreteFunction
					var actual []any
					if x.Call.IsInvoke() {
						box := get(x.Call.Value).(regionConcreteInterface)
						object, index, _ := types.LookupFieldOrMethod(box.typ, false, x.Call.Method.Pkg(), x.Call.Method.Name())
						method, ok := object.(*types.Func)
						if !ok || len(index) != 1 {
							t.Fatal("oracle unsupported interface receiver adjustment")
						}
						callee.target = in.root.Prog.FuncValue(method)
						if callee.target == nil {
							t.Fatal("oracle missing concrete method body")
						}
						actual = append(actual, regionConcreteCopy(box.value))
					} else {
						callee = get(x.Call.Value).(regionConcreteFunction)
					}
					for _, arg := range x.Call.Args {
						actual = append(actual, regionConcreteCopy(get(arg)))
					}
					childInvocation := uint64(0)
					if run != nil {
						childInvocation = run.call(x, invocation, callee.target, actual)
					}
					if callee.target == nil || len(callee.target.Blocks) == 0 {
						t.Fatal("concrete oracle has no actual callee body")
					}
					child := regionInput{root: callee.target, entry: regionPoint{callee.target.Blocks[0], 0}}
					result := executeRegionConcreteFrame(t, child, globals, actual, callee.environment, true, depth+1, steps, run, childInvocation).(regionConcreteResults)
					if len(result) == 1 {
						values[x] = result[0]
					} else {
						values[x] = result
					}
					break
				}
				argument := get(x.Call.Args[0])
				if text, ok := argument.(string); ok && b.Name() == "len" {
					values[x] = int64(len(text))
					break
				}
				if _, slice := x.Call.Args[0].Type().Underlying().(*types.Slice); argument == nil && slice && (b.Name() == "len" || b.Name() == "cap") {
					values[x] = int64(0)
					break
				}
				s := argument.(regionConcreteSlice)
				n := s.length
				if b.Name() == "cap" {
					n = s.capacity
				}
				values[x] = int64(n)
			case *ssa.Extract:
				values[x] = get(x.Tuple).(regionConcreteResults)[x.Index]
			case *ssa.Return:
				if !whole {
					t.Fatal("oracle returned outside requested use")
				}
				result := make(regionConcreteResults, len(x.Results))
				for i, operand := range x.Results {
					result[i] = regionConcreteCopy(get(operand))
				}
				if run != nil {
					run.returned(x, invocation, result)
				}
				return result
			default:
				t.Fatalf("oracle unsupported instruction %T: %s", ins, ins)
			}
		}
		if next == nil {
			t.Fatal("oracle missing successor")
		}
		predecessor, block, start = block, next, 0
	}
	t.Fatal("concrete test execution did not terminate")
	return nil
}

// Match concretizes terms only for comparison with the independent interpreter.
// Unknown includes any concrete value; exact aggregates compare in their order.
func regionMatchesConcrete(v regionValue, state regionState, concrete any, depth int) bool {
	if depth > 40 {
		return false
	}
	if v.kind == regionUnknown {
		return true
	}
	switch v.kind {
	case regionNil:
		return concrete == nil
	case regionConstant:
		switch c := concrete.(type) {
		case bool:
			return v.scalar.Kind() == constant.Bool && constant.BoolVal(v.scalar) == c
		case string:
			return v.scalar.Kind() == constant.String && constant.StringVal(v.scalar) == c
		case int64:
			n, ok := constant.Int64Val(v.scalar)
			return ok && n == c
		case uint64:
			n, ok := constant.Uint64Val(v.scalar)
			return ok && n == c
		}
	case regionFloat:
		basic, ok := v.typ.Underlying().(*types.Basic)
		if !ok {
			return false
		}
		switch c := concrete.(type) {
		case float32:
			return basic.Kind() == types.Float32 && v.floatBits == uint64(math.Float32bits(c))
		case float64:
			return basic.Kind() == types.Float64 && v.floatBits == math.Float64bits(c)
		}
	case regionPointer:
		p, ok := concrete.(regionConcretePointer)
		if !ok {
			return false
		}
		return regionMatchesConcrete(readRegionLocation(state, v.location, v.typ.Underlying().(*types.Pointer).Elem()), state, *p.cell, depth+1)
	case regionSlice:
		s, ok := concrete.(regionConcreteSlice)
		if !ok || int64(s.length) != v.length || int64(s.capacity) != v.capacity {
			return false
		}
		for i := int64(0); i < v.length; i++ {
			loc := v.location
			loc.path = append(slices.Clone(loc.path), regionStep{index: v.start + i})
			item := readRegionLocation(state, loc, v.typ.Underlying().(*types.Slice).Elem())
			if !regionMatchesConcrete(item, state, s.cells[s.start+int(i)], depth+1) {
				return false
			}
		}
		return true
	case regionCallable:
		f, ok := concrete.(regionConcreteFunction)
		if !ok || f.target != v.target || len(f.environment) != len(v.environment) {
			return false
		}
		for i := range f.environment {
			if !regionMatchesConcrete(v.environment[i], state, f.environment[i], depth+1) {
				return false
			}
		}
		return true
	case regionAggregate:
		a, ok := concrete.([]any)
		if !ok || len(a) != len(v.elements) {
			return false
		}
		for i := range a {
			if !regionMatchesConcrete(v.elements[i], state, a[i], depth+1) {
				return false
			}
		}
		return true
	case regionInterface:
		i, ok := concrete.(regionConcreteInterface)
		return ok && len(v.elements) == 1 && types.Identical(v.elements[0].typ, i.typ) && regionMatchesConcrete(v.elements[0], state, i.value, depth+1)
	}
	return false
}

func assertRegionCovers(t testing.TB, checked *checkedRegion, concrete any) {
	t.Helper()
	for _, outcome := range checked.observations {
		if regionMatchesConcrete(outcome.value, outcome.state, concrete, 0) {
			return
		}
	}
	t.Fatal("checked relation omitted concrete execution")
}

func regionTestPrecise(v regionValue, state regionState, depth int) bool {
	if depth > 40 || v.kind == regionUnknown {
		return false
	}
	if v.kind == regionPointer {
		return regionTestPrecise(readRegionLocation(state, v.location, v.typ.Underlying().(*types.Pointer).Elem()), state, depth+1)
	}
	if v.kind == regionSlice {
		for i := int64(0); i < v.length; i++ {
			loc := v.location
			loc.path = append(slices.Clone(loc.path), regionStep{index: v.start + i})
			if !regionTestPrecise(readRegionLocation(state, loc, v.typ.Underlying().(*types.Slice).Elem()), state, depth+1) {
				return false
			}
		}
	}
	for _, list := range [][]regionValue{v.elements, v.environment} {
		for _, item := range list {
			if !regionTestPrecise(item, state, depth+1) {
				return false
			}
		}
	}
	return true
}

func TestRegionConstructionAndAliasOracle(t *testing.T) {
	for _, text := range []string{
		`type Row struct{Name string; F func()}; func a(){}; func b(){}; var rows []Row; func F()[]Row { rows=[]Row{{"a",a},{"b",b}}; return rows }`,
		`type Row[T any] struct{Name string; F T}; func a(){}; func b(){}; func F()[]Row[func()] { x:=[]Row[func()]{{"a",a},{"b",b}}; y:=x; y[0].F=b; y[0].Name="changed";return x }`,
		`type Row struct{Name string;F func()};func a(){};func b(){};func F()[]Row{r:=Row{"a",a};x:=[]Row{r};r.Name="changed";r.F=b;return x}`,
		`func F()func()int { x:=1; f:=func()int{return x}; x=2; return f }`,
		`func F()[]func()int { x,y:=1,2; a:=func()int{return x}; b:=func()int{return y}; x=3;return []func()int{a,b} }`,
		`func F(flag bool)func()int { x:=1;if flag{x=2};return func()int{return x} }`,
		`type Fn func();func a(){};func F()Fn{return Fn(a)}`,
		`func identity[T any](x T)T{return x};func F()func(int)int{return identity[int]}`,
		`type S struct{X any}; func F()S { return S{X:7} }`,
		`type Deps struct{}; func F()any { return Deps{} }`,
		`func F()[]int { return []int{} }`,
		`func F()[]int { x:=[]int{2,3,4}; return x[1:2:3] }`,
		`func F()int { x:=[]int{2,3,4}; return cap(x[1:2]) }`,
		`func a(){};func b(){}; type Row struct{Name string; F func()}; func F(flag bool)[]Row { var x []Row; if flag { x=[]Row{{"a",a}} } else { x=[]Row{{"b",b}} }; return x }`,
	} {
		t.Run(text, func(t *testing.T) {
			in := regionFixture(t, text)
			c, _ := proveRegionFixture(t, in)
			for _, outcome := range c.observations {
				if !regionTestPrecise(outcome.value, outcome.state, 0) {
					t.Fatal("positive widened its result")
				}
			}
			if len(in.root.Params) == 0 {
				assertRegionCovers(t, c, executeRegionConcrete(t, in))
			} else {
				for _, flag := range []bool{false, true} {
					assertRegionCovers(t, c, executeRegionConcrete(t, in, flag))
				}
			}
			if c.rules != regionRules || len(c.openObligations()) != 5 {
				t.Fatal("conditional boundaries lost")
			}
		})
	}
}

func TestRegionConcreteAggregateAssignment(t *testing.T) {
	for _, tc := range []struct{ name, source string }{
		{"struct", `type S struct{X int};func F()int{s:=S{X:1};p:=&s.X;v:=S{X:2};s=v;return *p}`},
		{"array", `func F()int{s:=[2]int{1,3};p:=&s[0];v:=[2]int{2,4};s=v;return *p}`},
		{"nested", `type I struct{X int};type S struct{A [1]I};func F()int{s:=S{A:[1]I{{1}}};p:=&s.A[0].X;s=S{A:[1]I{{2}}};return *p}`},
		{"self-struct", `type S struct{X int};func F()int{s:=S{X:1};p:=&s.X;s=s;s.X=2;return *p}`},
		{"self-array", `func F()int{s:=[2]int{1,3};p:=&s[0];s=s;s[0]=2;return *p}`},
		{"overlap-struct", `type S struct{X,Y int};func F()int{s:=S{1,2};p:=&s.X;s=S{s.Y,s.X};return *p}`},
		{"overlap-array", `func F()int{s:=[2]int{1,2};p:=&s[0];s=[2]int{s[1],s[0]};return *p}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := regionFixture(t, tc.source)
			concrete := executeRegionConcrete(t, in)
			// The concrete oracle must independently agree with Go assignment
			// semantics, before its answer is compared to the abstract checker.
			if concrete != int64(2) {
				t.Fatalf("overwrite through an existing field/element pointer = %v, want 2", concrete)
			}
			checked, _ := proveRegionFixture(t, in)
			for _, outcome := range checked.observations {
				if !regionTestPrecise(outcome.value, outcome.state, 0) {
					t.Fatal("aggregate overwrite lost the exact result")
				}
			}
			assertRegionCovers(t, checked, concrete)
		})
	}
	// These are concrete overlapping array views, corresponding to assigning
	// through *[2]int pointers into one backing array. No abstract paths or
	// transfer helpers participate in the oracle's read-before-write assertion.
	for _, tc := range []struct {
		name     string
		from, to int
		want     []any
	}{
		{"forward", 0, 1, []any{int64(1), int64(1), int64(2)}},
		{"backward", 1, 0, []any{int64(2), int64(3), int64(3)}},
		{"self", 0, 0, []any{int64(1), int64(2), int64(3)}},
	} {
		t.Run("array-view/"+tc.name, func(t *testing.T) {
			backing := []any{int64(1), int64(2), int64(3)}
			pointer := &backing[tc.to+1]
			var destination any = backing[tc.to : tc.to+2]
			regionConcreteStore(&destination, backing[tc.from:tc.from+2])
			if !slices.Equal(backing, tc.want) || *pointer != tc.want[tc.to+1] {
				t.Fatalf("overlapping assignment = %v, pointer = %v; want %v", backing, *pointer, tc.want)
			}
		})
	}
}

func TestRegionActualCallOperandAndScope(t *testing.T) {
	const text = `type Row struct{Name string; F func()};func a(){};func use([]Row){opaque()};func opaque();func F(){opaque();unused:=[]Row{{"decoy",a}};_ = unused;actual:=[]Row{{"actual",a}};use(actual)}`
	in := regionAtCall(t, regionFixture(t, text), "use", 0)
	if _, err := proposeRegion(t.Context(), in, defaultRegionLimits()); err == nil {
		t.Fatal("unknown preceding call skipped")
	}
	for i, ins := range in.entry.block.Instrs {
		if call, ok := ins.(*ssa.Call); ok && call.Call.StaticCallee().Name() == "opaque" {
			in.entry.index = i + 1
			break
		}
	}
	in.premises = append(in.premises, "opaque prefix has completed; entry heap and frame are a condition, not established here")
	c, p := proveRegionFixture(t, in)
	if c.input.entry.index == 0 {
		t.Fatal("cutpoint erased")
	}
	bad := in
	for _, ins := range in.root.Blocks[0].Instrs {
		if slice, ok := ins.(*ssa.Slice); ok && slice != in.use.operand {
			bad.use.operand = slice
			break
		}
	}
	if bad.use.operand == in.use.operand {
		t.Fatal("missing decoy")
	}
	if _, err := checkRegion(t.Context(), bad, p, defaultRegionLimits()); err == nil {
		t.Fatal("endpoint replacement admitted")
	}
	if _, err := proposeRegion(t.Context(), bad, defaultRegionLimits()); err == nil {
		t.Fatal("lookalike table admitted as actual operand")
	}
	// Moving the cut past use requires proving that call's effects.
	in.use = regionUse{at: regionPoint{in.use.at.block, len(in.use.at.block.Instrs) - 1}}
	if _, err := proposeRegion(t.Context(), in, defaultRegionLimits()); err == nil {
		t.Fatal("unproved call inside graph admitted")
	}
}

func TestRegionRefusesUnmodeledEffectsAndExceptions(t *testing.T) {
	for _, body := range []string{
		`func opaque();func F()int{opaque();return 1}`,
		`func F()int{go func(){}();return 1}`,
		`func F()int{defer func(){}();return 1}`,
		`func F(p *int)int{*p=1;return 1}`,
		`func F(p *int)int{return *p}`,
		`func F()int{x:=[]int{1};return x[1]}`,
		`func F(i int)int{x:=[]int{1};return x[i]}`,
		`func F()int{return F()}`,
		`func F()int{return g()};func g()int{return F()}`,
	} {
		t.Run(body, func(t *testing.T) {
			in := regionFixture(t, body)
			if _, err := proposeRegion(t.Context(), in, defaultRegionLimits()); err == nil {
				t.Fatal("unsupported effect/exception was hidden")
			}
		})
	}
}

func TestRegionInductionAndSummaryAllocations(t *testing.T) {
	in := regionFixture(t, `func F(again,next bool)*int { var old *int; for again { p:=new(int); *p=7; if old==nil { old=p }; again=next; next=false }; return old }`)
	c, p := proveRegionFixture(t, in)
	for _, args := range [][2]bool{{false, false}, {true, false}, {true, true}} {
		assertRegionCovers(t, c, executeRegionConcrete(t, in, args[0], args[1]))
	}
	// At any repeated allocation site, even a constant store cannot establish a
	// singleton fact about every older instance.
	for _, states := range p.entries {
		for _, s := range states {
			for o, v := range s.memory {
				if o.kind == regionAllocation && v.kind != regionUnknown {
					t.Fatal("summary allocation acquired a strong value")
				}
			}
		}
	}
	// Stable control-flow cycles are proved by edge inclusion, not a step count.
	stable := regionFixture(t, `func F(again bool)int { for again {};return 7 }`)
	_, candidate := proveRegionFixture(t, stable)
	for block := range candidate.entries {
		if len(block.Preds) > 1 {
			delete(candidate.entries, block)
			break
		}
	}
	if _, err := checkRegion(t.Context(), stable, candidate, defaultRegionLimits()); err == nil {
		t.Fatal("omitted backedge invariant accepted")
	}
	// Keep every node and forward edge but narrow the loop invariant to its
	// first-entry value. Only checking the backedge can reject this candidate.
	changing := regionFixture(t, `func F(again bool)bool{x:=false;for again{x=true};return x}`)
	_, candidate = proveRegionFixture(t, changing)
	narrowed := false
	for block, states := range candidate.entries {
		if len(block.Preds) < 2 {
			continue
		}
		kept := slices.DeleteFunc(slices.Clone(states), func(state regionState) bool {
			for value, term := range state.values {
				if phi, ok := value.(*ssa.Phi); ok && phi.Block() == block {
					if b, known := regionBool(term); known && b {
						return true
					}
				}
			}
			return false
		})
		if len(kept) > 0 && len(kept) < len(states) {
			candidate.entries[block] = kept
			narrowed = true
			break
		}
	}
	if !narrowed {
		t.Fatal("test did not narrow loop invariant")
	}
	if _, err := checkRegion(t.Context(), changing, candidate, defaultRegionLimits()); err == nil {
		t.Fatal("noninductive first-iteration loop invariant accepted")
	}
}

func TestRegionForgedInvariants(t *testing.T) {
	const text = `type Row struct{Name string; F func()};func a(){};func b(){};func F(flag bool)[]Row { x:=[]Row{{"a",a},{"b",b}};if flag{x[0].Name="changed"};return x }`
	for _, corruption := range []string{"edge", "store", "rows", "root", "initial", "extra"} {
		t.Run(corruption, func(t *testing.T) {
			in := regionFixture(t, text)
			_, p := proveRegionFixture(t, in)
			switch corruption {
			case "root":
				other := regionFixture(t, `func F()int{return 1}`)
				p.input.root = other.root
			case "initial":
				p.input.premises = []string{"replacement condition"}
			case "extra":
				p.entries[nil] = []regionState{{}}
			case "edge":
				for block := range p.entries {
					if block != in.entry.block {
						delete(p.entries, block)
						break
					}
				}
			case "store", "rows":
				for i, state := range p.entries[in.use.at.block] {
					for object, v := range state.memory {
						if v.kind != regionAggregate || len(v.elements) != 2 || v.elements[0].kind != regionAggregate {
							continue
						}
						v.elements = slices.Clone(v.elements)
						v.elements[0].elements = slices.Clone(v.elements[0].elements)
						v.elements[1].elements = slices.Clone(v.elements[1].elements)
						if corruption == "store" {
							v.elements[0].elements[0].scalar = constant.MakeString("omitted")
						} else {
							v.elements[0].elements[1], v.elements[1].elements[1] = v.elements[1].elements[1], v.elements[0].elements[1]
						}
						state.memory[object] = v
					}
					p.entries[in.use.at.block][i] = state
				}
			}
			if _, err := checkRegion(t.Context(), in, p, defaultRegionLimits()); err == nil {
				t.Fatal("forged invariant accepted")
			}
		})
	}
	phi := regionFixture(t, `func F(flag bool)string { x:="a";if flag{x="b"};return x }`)
	_, p := proveRegionFixture(t, phi)
	for block, states := range p.entries {
		for i, state := range states {
			for key, value := range state.values {
				if _, ok := key.(*ssa.Phi); ok {
					value.scalar = constant.MakeString("a")
					state.values[key] = value
				}
			}
			p.entries[block][i] = state
		}
	}
	if _, err := checkRegion(t.Context(), phi, p, defaultRegionLimits()); err == nil {
		t.Fatal("phi predecessor/value association was ignored")
	}
}

type regionMutatingContext struct {
	context.Context
	once   bool
	mutate func()
}

func (c *regionMutatingContext) Err() error {
	if !c.once {
		c.once = true
		c.mutate()
	}
	return c.Context.Err()
}

func TestRegionOwnershipBudgetsAndCancellation(t *testing.T) {
	in := regionFixture(t, `func F(flag bool)[]int { x:=[]int{1,2};if flag{x[0]=3};return x }`)
	_, p := proveRegionFixture(t, in)
	ctx := &regionMutatingContext{Context: t.Context(), mutate: func() {
		for _, states := range p.entries {
			for _, state := range states {
				for object, value := range state.memory {
					for i := range value.elements {
						value.elements[i] = regionUnknownValue(value.elements[i].typ)
					}
					state.memory[object] = regionUnknownValue(value.typ)
				}
				clear(state.values)
			}
		}
		p.input.use.operand = nil
		p.entries = nil
		in.premises[0] = "changed by context callback"
	}}
	c, err := checkRegion(ctx, in, p, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	if c.input.premises[0] == in.premises[0] || c.input.use.operand == nil {
		t.Fatal("checked packet borrowed callback-mutated containers")
	}
	for _, flag := range []bool{false, true} {
		assertRegionCovers(t, c, executeRegionConcrete(t, c.input, flag))
	}
	for _, dimension := range []string{"nodes", "states", "locations", "depth", "work"} {
		t.Run(dimension, func(t *testing.T) {
			limits := defaultRegionLimits()
			switch dimension {
			case "nodes":
				limits.nodes = 1
			case "states":
				limits.states = 1
			case "locations":
				limits.locations = 1
			case "depth":
				limits.depth = 1
			case "work":
				limits.work = 1
			}
			input := regionFixture(t, `type S struct{X struct{Y int}};func F()*S{return &S{}}`)
			candidate, e := proposeRegion(t.Context(), input, limits)
			if e == nil {
				_, e = checkRegion(t.Context(), input, candidate, limits)
			}
			if e == nil {
				t.Fatal("exhausted dimension accepted")
			}
		})
	}
	limits := defaultRegionLimits()
	limits.alternatives = 1
	input := regionFixture(t, `func F(flag bool)int{x:=1;if flag{x=2};return x}`)
	candidate, err := proposeRegion(t.Context(), input, limits)
	if err != nil {
		t.Fatal(err)
	}
	widened, err := checkRegion(t.Context(), input, candidate, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(widened.observations) != 1 || widened.observations[0].value.kind != regionUnknown {
		t.Fatal("alternative widening fabricated a precise result")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if candidate, err := proposeRegion(cancelled, input, defaultRegionLimits()); candidate != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled proposal: %v", err)
	}
	candidate, err = proposeRegion(t.Context(), input, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	if packet, err := checkRegion(cancelled, input, candidate, defaultRegionLimits()); packet != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled check: %v", err)
	}
}

func TestRegionFormalAliasesInvalidateConcreteFacts(t *testing.T) {
	for _, text := range []string{
		`var g int;func F(p *int)int{*p=2;return g}`,
		`var g int;func F(p *int)int{g=2;return *p}`,
	} {
		in := regionFixture(t, text)
		global := in.owner.Package(in.root.Pkg.Pkg).Members["g"].(*ssa.Global)
		formal := regionObject{kind: regionFormal, site: in.root.Params[0], context: in.root}
		g := regionObject{kind: regionGlobal, site: global}
		one := regionValue{typ: types.Typ[types.Int], kind: regionConstant, scalar: constant.MakeInt64(1)}
		in.initial = regionState{values: map[ssa.Value]regionValue{in.root.Params[0]: {typ: in.root.Params[0].Type(), kind: regionPointer, location: regionLocation{object: formal}}}, memory: map[regionObject]regionValue{formal: one, g: one}}
		in.premises = append(in.premises, "p is nonnil; p may equal &g; both cells initially contain one")
		checked, _ := proveRegionFixture(t, in)
		if len(checked.observations) != 1 || checked.observations[0].value.kind != regionUnknown {
			t.Fatal("possible formal/global alias retained stale facts")
		}
	}
}

func TestRegionEarlierInvocationAllocationIsNotReset(t *testing.T) {
	in := regionFixture(t, `var old *int;func F()*int{p:=new(int);*p=2;return old}`)
	var allocation *ssa.Alloc
	for _, ins := range in.root.Blocks[0].Instrs {
		if a, ok := ins.(*ssa.Alloc); ok {
			allocation = a
			break
		}
	}
	if allocation == nil {
		t.Fatal("allocation missing")
	}
	old := in.root.Pkg.Members["old"].(*ssa.Global)
	object := regionObject{kind: regionAllocation, site: allocation, context: in.root}
	ptr := regionValue{typ: allocation.Type(), kind: regionPointer, location: regionLocation{object: object}}
	in.initial = regionState{memory: map[regionObject]regionValue{
		object:                          {typ: types.Typ[types.Int], kind: regionConstant, scalar: constant.MakeInt64(1)},
		{kind: regionGlobal, site: old}: ptr,
	}}
	in.premises = append(in.premises, "old references a previous invocation's object at this site")
	checked, _ := proveRegionFixture(t, in)
	out := checked.observations[0]
	if got := readRegionLocation(out.state, out.value.location, types.Typ[types.Int]); got.kind != regionUnknown {
		t.Fatal("fresh allocation overwrote earlier instance fact")
	}
}

func TestRegionCaptureBoundaryRetainsInvocationObligations(t *testing.T) {
	for _, word := range []string{"go", "defer"} {
		in := regionFixture(t, `func F(){x:=1;`+word+` func(){x=2}();_ = x}`)
		found := false
		for _, block := range in.root.Blocks {
			for i, ins := range block.Instrs {
				switch call := ins.(type) {
				case *ssa.Go:
					in.use = regionUse{regionPoint{block, i}, call.Call.Value}
					found = true
				case *ssa.Defer:
					in.use = regionUse{regionPoint{block, i}, call.Call.Value}
					found = true
				}
			}
		}
		if !found {
			t.Fatal("capture instruction missing")
		}
		checked, _ := proveRegionFixture(t, in)
		if checked.observations[0].value.kind != regionCallable || len(checked.openObligations()) != 5 {
			t.Fatal("capture erased open invocation")
		}
	}
}

func TestRegionMalformedProposalValuesRefuse(t *testing.T) {
	for _, kind := range []string{"nil-key", "wrong-type", "hidden-offset", "nil-object", "foreign-target"} {
		t.Run(kind, func(t *testing.T) {
			in := regionFixture(t, `func F(p *[3]int)int{return 1}`)
			_, proposal := proveRegionFixture(t, in)
			state := regionState{values: map[ssa.Value]regionValue{}, memory: map[regionObject]regionValue{}}
			parameter := in.root.Params[0]
			switch kind {
			case "nil-key":
				state.values[nil] = regionUnknownValue(types.Typ[types.Int])
			case "wrong-type":
				state.values[parameter] = regionUnknownValue(types.Typ[types.Int])
			case "hidden-offset":
				state.values[parameter] = regionValue{typ: parameter.Type(), kind: regionPointer, start: 1, location: regionLocation{object: regionObject{kind: regionFormal, site: parameter, context: in.root}}}
			case "nil-object":
				state.values[parameter] = regionValue{typ: parameter.Type(), kind: regionPointer, location: regionLocation{object: regionObject{kind: regionGlobal, site: (*ssa.Global)(nil)}}}
			case "foreign-target":
				other := regionFixture(t, `func F(){}`)
				state.values[parameter] = regionValue{typ: parameter.Type(), kind: regionCallable, target: other.root}
			}
			proposal.entries[in.entry.block] = []regionState{state}
			if _, err := checkRegion(t.Context(), in, proposal, defaultRegionLimits()); err == nil {
				t.Fatal("malformed value acquired authority")
			}
		})
	}
}

func TestRegionMalformedInterfaceChildRefusesWithoutPanic(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(fmt.Sprintf("nested=%t", nested), func(t *testing.T) {
			in := regionFixture(t, `func F(x any)int{return 1}`)
			_, proposal := proveRegionFixture(t, in)
			parameter := in.root.Params[0]
			value := regionValue{typ: parameter.Type(), kind: regionInterface, elements: []regionValue{{}}}
			if nested {
				value = regionValue{typ: parameter.Type(), kind: regionInterface, elements: []regionValue{value}}
			}
			proposal.entries[in.entry.block][0].values = map[ssa.Value]regionValue{parameter: value}
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("malformed interface child panicked instead of returning a refusal: %v", recovered)
				}
			}()
			checked, err := checkRegion(t.Context(), in, proposal, defaultRegionLimits())
			if checked != nil || err == nil {
				t.Fatalf("malformed child returned packet=%v, error=%v; want no packet and a refusal", checked != nil, err)
			}
		})
	}
}

func FuzzRegionRegistrationOracle(f *testing.F) {
	f.Add("first", "second", false)
	f.Add("same", "same", true)
	f.Fuzz(func(t *testing.T, a, b string, swap bool) {
		if len(a) > 64 || len(b) > 64 || strings.ContainsRune(a, 0) || strings.ContainsRune(b, 0) {
			t.Skip()
		}
		// Retain an element-field pointer across a whole-row overwrite, then
		// read through it. This exercises both aggregate copying and stable cells.
		text := fmt.Sprintf(`type Row[T any] struct{Name string; F T};func a(){};func b(){};func F(flag bool)[]Row[func()]{ x:=[]Row[func()]{{%s,a},{%s,b}};p:=&x[0].F;if flag{x[0]=Row[func()]{x[0].Name,b};x[1].F=a};x[0].F=*p;return x }`, strconv.Quote(a), strconv.Quote(b))
		in := regionFixture(t, text)
		c, _ := proveRegionFixture(t, in)
		assertRegionCovers(t, c, executeRegionConcrete(t, in, swap))
	})
}
