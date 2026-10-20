package closure

import (
	"fmt"
	"go/constant"
	"go/types"
	"math"
	"slices"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// The concrete oracle's cell type is fixed at allocation. A pointer conversion
// never creates storage: loads decode the current cell and stores encode back to
// that same cell. This test model uses only go/types layout and math's bit casts;
// it deliberately has no dependency on the region checker's float/view helpers.
func (r *regionConcreteExecution) scalarBits(typ types.Type, value any) uint64 {
	value = r.checkedValue(typ, value)
	u, ok := typ.Underlying().(*types.Basic)
	if !ok {
		panic(regionConcreteFailure{"oracle bit view needs a scalar cell"})
	}
	switch u.Kind() {
	case types.Float32:
		return uint64(math.Float32bits(value.(float32)))
	case types.Float64:
		return math.Float64bits(value.(float64))
	default:
		if u.Info()&types.IsInteger == 0 {
			panic(regionConcreteFailure{"oracle bit view needs integer or float"})
		}
		if u.Info()&types.IsUnsigned != 0 {
			return value.(uint64)
		}
		return uint64(value.(int64))
	}
}

func (r *regionConcreteExecution) scalarFromBits(typ types.Type, bits uint64) any {
	u, ok := typ.Underlying().(*types.Basic)
	if !ok {
		panic(regionConcreteFailure{"oracle bit decoding needs a scalar"})
	}
	switch u.Kind() {
	case types.Float32:
		return r.checkedValue(typ, math.Float32frombits(uint32(bits)))
	case types.Float64:
		return r.checkedValue(typ, math.Float64frombits(bits))
	default:
		return r.convertInteger(bits, typ)
	}
}

func (r *regionConcreteExecution) viewWidth(typ types.Type) int64 {
	u, ok := typ.Underlying().(*types.Basic)
	if !ok {
		panic(regionConcreteFailure{"oracle bit view is not scalar"})
	}
	var width int64
	switch u.Kind() {
	case types.Int32, types.Uint32, types.Float32:
		width = 4
	case types.Int64, types.Uint64, types.Float64:
		width = 8
	case types.Int, types.Uint:
		width = r.sizes.Sizeof(typ)
		if width != 4 && width != 8 {
			panic(regionConcreteFailure{"oracle bit view word width"})
		}
	default:
		panic(regionConcreteFailure{"oracle unsupported bit view type"})
	}
	if r.sizes.Sizeof(typ) != width {
		panic(regionConcreteFailure{"oracle bit view selected width mismatch"})
	}
	return width
}

func (r *regionConcreteExecution) checkView(p regionConcretePointer, typ types.Type) types.Type {
	loc := r.location(p)
	if loc.Object < 1 || loc.Object > len(r.objects) || loc.Object > len(r.roots) {
		panic(regionConcreteFailure{"oracle view lacks allocation metadata"})
	}
	object := r.objects[loc.Object-1]
	if object.Type == nil || r.roots[loc.Object-1] == nil {
		panic(regionConcreteFailure{"oracle view lacks its owning type or cells"})
	}
	// Cross-check the location metadata against the actual owning aggregate
	// cells. Matching width alone cannot turn a sibling into this pointer's cell.
	actualCell, actualType, offset := r.roots[loc.Object-1], object.Type, int64(0)
	for _, index := range loc.Path {
		if index < 0 {
			panic(regionConcreteFailure{"oracle view has a negative subobject index"})
		}
		switch u := actualType.Underlying().(type) {
		case *types.Array:
			if int64(index) >= u.Len() {
				panic(regionConcreteFailure{"oracle view exceeds array subobjects"})
			}
			offset += int64(index) * r.sizes.Sizeof(u.Elem())
			actualType = u.Elem()
		case *types.Struct:
			if index >= u.NumFields() {
				panic(regionConcreteFailure{"oracle view exceeds struct subobjects"})
			}
			fields := make([]*types.Var, u.NumFields())
			for i := range fields {
				fields[i] = u.Field(i)
			}
			offset += r.sizes.Offsetsof(fields)[index]
			actualType = u.Field(index).Type()
		default:
			panic(regionConcreteFailure{"oracle view traverses a scalar"})
		}
		values, ok := (*actualCell).([]any)
		if !ok || index >= len(values) {
			panic(regionConcreteFailure{"oracle view lost aggregate cells"})
		}
		actualCell = &values[index]
	}
	if actualCell != p.cell || offset != loc.Offset || object.Size != r.sizes.Sizeof(object.Type) || object.Alignment != r.sizes.Alignof(object.Type) {
		panic(regionConcreteFailure{"oracle view metadata differs from owning cells"})
	}
	canonical := actualType
	width := r.sizes.Sizeof(canonical)
	if !types.IdenticalIgnoreTags(canonical.Underlying(), typ.Underlying()) {
		if width != r.viewWidth(typ) || width != r.viewWidth(canonical) {
			panic(regionConcreteFailure{"oracle bit view changes cell width"})
		}
	}
	for _, view := range []types.Type{canonical, typ} {
		alignment := r.sizes.Alignof(view)
		if width < 0 || r.sizes.Sizeof(view) != width || loc.Offset < 0 || width > object.Size || loc.Offset > object.Size-width || alignment <= 0 || object.Alignment <= 0 || object.Alignment%alignment != 0 || loc.Offset%alignment != 0 {
			panic(regionConcreteFailure{"oracle view has invalid extent or alignment"})
		}
	}
	return canonical
}

func (r *regionConcreteExecution) accessType(p regionConcretePointer, address, typ types.Type) types.Type {
	pointer, ok := address.Underlying().(*types.Pointer)
	if !ok || !types.Identical(pointer.Elem(), typ) {
		panic(regionConcreteFailure{"oracle access type differs from pointer view"})
	}
	return r.checkView(p, typ)
}

func (r *regionConcreteExecution) load(p regionConcretePointer, address, typ types.Type) any {
	canonical := r.accessType(p, address, typ)
	value := r.checkedValue(canonical, *p.cell)
	if types.IdenticalIgnoreTags(canonical.Underlying(), typ.Underlying()) {
		return regionConcreteCopy(value)
	}
	return r.scalarFromBits(typ, r.scalarBits(canonical, value))
}

func (r *regionConcreteExecution) store(p regionConcretePointer, address, typ types.Type, value any) {
	canonical := r.accessType(p, address, typ)
	value = r.checkedValue(typ, value)
	if !types.IdenticalIgnoreTags(canonical.Underlying(), typ.Underlying()) {
		value = r.scalarFromBits(canonical, r.scalarBits(typ, value))
	}
	regionConcreteStore(p.cell, value)
}

func oraclePointerType(typ types.Type) bool {
	if _, ok := typ.Underlying().(*types.Pointer); ok {
		return true
	}
	basic, ok := typ.Underlying().(*types.Basic)
	return ok && basic.Kind() == types.UnsafePointer
}

func (r *regionConcreteExecution) convert(value any, from, to types.Type) any {
	if oraclePointerType(from) || oraclePointerType(to) {
		p, ok := value.(regionConcretePointer)
		if !ok || !oraclePointerType(from) || !oraclePointerType(to) {
			panic(regionConcreteFailure{"oracle conversion needs a live pointer, not a numeric address"})
		}
		r.location(p)
		for _, typ := range []types.Type{from, to} {
			if ptr, ok := typ.Underlying().(*types.Pointer); ok {
				r.checkView(p, ptr.Elem())
			}
		}
		return p
	}
	fromBasic, ok := from.Underlying().(*types.Basic)
	if !ok || fromBasic.Info()&types.IsInteger == 0 {
		panic(regionConcreteFailure{"oracle numeric conversion is not integer-to-integer"})
	}
	r.checkedValue(from, value)
	return r.convertInteger(value, to)
}

func (r *regionConcreteExecution) checkEquality(left, right types.Type, a, b any) {
	if !types.Identical(left, right) {
		panic(regionConcreteFailure{"oracle equality operand types differ"})
	}
	// Preserve the old pointer/interface grammar; validate scalar and aggregate
	// values recursively, including exact selected float widths, before equality.
	switch left.Underlying().(type) {
	case *types.Basic, *types.Array, *types.Struct:
		r.checkedValue(left, a)
		r.checkedValue(right, b)
	}
}

// Both signs are generated for every IEEE class, including distinct quiet and
// signaling NaN payloads. This finite population supplements arbitrary fuzz bits.
func floatOracleBits(width int) []uint64 {
	positive := []uint64{0, 1, 0x007fffff, 0x00800000, 0x3f800000, 0x7f7fffff, 0x7f800000, 0x7fc00000, 0x7fc12345, 0x7f800001, 0x7fa12345}
	if width == 8 {
		positive = []uint64{0, 1, 0x000fffffffffffff, 0x0010000000000000, 0x3ff0000000000000, 0x7fefffffffffffff, 0x7ff0000000000000, 0x7ff8000000000000, 0x7ff8123456789abc, 0x7ff0000000000001, 0x7ff4123456789abc}
	}
	out := slices.Clone(positive)
	for _, bits := range positive {
		out = append(out, bits|uint64(1)<<(width*8-1))
	}
	return out
}

func floatOracleEqual(width int, a, b uint64) bool {
	if width == 4 {
		return math.Float32frombits(uint32(a)) == math.Float32frombits(uint32(b))
	}
	return math.Float64frombits(a) == math.Float64frombits(b)
}

func floatOracleText(width int, named bool) string {
	floatType, intType := fmt.Sprintf("float%d", width*8), fmt.Sprintf("uint%d", width*8)
	declarations := ""
	if named {
		declarations = fmt.Sprintf("type Real %s;type Word %s;", floatType, intType)
		floatType, intType = "Real", "Word"
	}
	return fmt.Sprintf(`import "unsafe"
%s
var A,B %s
type Box struct{Head byte; Values [2]%s; Tail byte}
func Read(p *%s)%s{return *p}
func F()(bool,bool,bool,%s,%s){
 var box Box
 p:=&box.Values[1]
 q:=(*%s)(unsafe.Pointer(p))
 again:=(*%s)(unsafe.Pointer(q))
 *q=A
 first:=Read(p)
 *again=B
 second:=Read(p)
 equal:=first==second
 unequal:=first!=second
 self:=second==second
 *p=first
 return equal,unequal,self,*q,*again
}`, declarations, intType, floatType, floatType, floatType, intType, intType, intType, intType)
}

func checkFloatStorageOracle(t testing.TB, source computationSource, in regionInput, width int, a, b uint64) {
	t.Helper()
	if width == 4 {
		a, b = uint64(uint32(a)), uint64(uint32(b))
	}
	sizes := source.prog.Pkgs[0].TypesSizes
	globals := map[*ssa.Global]any{in.root.Pkg.Members["A"].(*ssa.Global): a, in.root.Pkg.Members["B"].(*ssa.Global): b}
	prefix, err := executeStorageSource(t, in, storageSourceRun{Globals: globals, Sizes: sizes})
	if err != nil {
		t.Fatal(err)
	}
	whole, err := executeStorageSource(t, in, storageSourceRun{Globals: globals, Sizes: sizes, Whole: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []any{floatOracleEqual(width, a, b), !floatOracleEqual(width, a, b), floatOracleEqual(width, b, b), a, a}
	if !slices.Equal(whole.Results, want) || !whole.Returned || prefix.Returned || prefix.Cut == nil || whole.Cut != nil || len(prefix.Operands) != 1 {
		t.Fatalf("float source cut/return differs: bits %x/%x got %v want %v", a, b, whole.Results, want)
	}
	loc, ok := prefix.Operands[0].(storageSourceLocation)
	if !ok || loc.Object != 3 || !slices.Equal(loc.Path, []int{1, 1}) || len(whole.Objects) != 3 || len(prefix.Objects) != 3 || len(whole.Invocations) != 3 {
		t.Fatalf("float pointer lost actual subobject/activation identity: %+v", prefix)
	}
	object := whole.Objects[loc.Object-1]
	structure := object.Type.Underlying().(*types.Struct)
	fields := []*types.Var{structure.Field(0), structure.Field(1), structure.Field(2)}
	offset := sizes.Offsetsof(fields)[1] + int64(width)
	if loc.Offset != offset || object.Invocation != 1 || object.Site != prefix.Objects[loc.Object-1].Site {
		t.Fatal("float view changed allocation instance or selected offset")
	}
	for _, result := range []storageSourceResult{prefix, whole} {
		bytes := storageSourceBytes(sizes, object.Type, result.Objects[loc.Object-1].Value)
		for lane := range width {
			if bytes[offset+int64(lane)] != byte(a>>(8*lane)) {
				t.Fatal("canonical float storage lost exact bits")
			}
		}
		for at, value := range bytes {
			if (at < offset || at >= offset+int64(width)) && value != 0 {
				t.Fatal("subobject view changed a sibling")
			}
		}
	}
	var accesses []storageSourceEvent
	for _, event := range whole.Events {
		if event.Location.Object == loc.Object && (event.Kind == "read" || event.Kind == "write") {
			accesses = append(accesses, event)
		}
	}
	wantKinds := []string{"write", "read", "write", "read", "write", "read", "read"}
	wantBits := []uint64{a, a, b, b, a, a, a}
	if len(accesses) != len(wantKinds) {
		t.Fatalf("float effects lost: %+v", accesses)
	}
	for i, event := range accesses {
		if event.Kind != wantKinds[i] || event.Location.Offset != offset || !slices.Equal(event.Location.Path, loc.Path) || event.Width != int64(width) || event.Instruction == nil || event.Invocation == 0 {
			t.Fatalf("float effect %d lost location/type/occurrence: %+v", i, event)
		}
		var bits uint64
		switch value := event.Value.(type) {
		case uint64:
			bits = value
		case float32:
			bits = uint64(math.Float32bits(value))
		case float64:
			bits = math.Float64bits(value)
		default:
			t.Fatalf("unexpected float event value %T", value)
		}
		if bits != wantBits[i] {
			t.Fatalf("float effect %d got bits %x want %x", i, bits, wantBits[i])
		}
	}
	if accesses[1].Instruction != accesses[3].Instruction || accesses[1].Invocation == accesses[3].Invocation {
		t.Fatal("repeated read helper lost distinct dynamic invocation identity")
	}
	for _, event := range prefix.Events {
		if event.Kind == "call" || event.Kind == "return" {
			t.Fatal("source cut executed its boundary")
		}
	}
	// Independent native intent supplies its own bytes. It models raw storage
	// only, not SSE comparisons or their exception/status applicability.
	at := storageByteLocation{Offset: -48}
	initial := map[storageByteLocation]byte{}
	for lane := -1; lane <= width; lane++ {
		initial[storageAt(at, int64(lane))] = 0xa5
	}
	program := []storageByteStep{
		{Kind: "store", At: at, Width: width, Value: a},
		{Kind: "load", At: at, Width: width, Register: 0},
		{Kind: "store", At: at, Width: width, Value: b},
		{Kind: "load", At: at, Width: width, Register: 1},
		{Kind: "store", At: at, Width: width, Register: 0, FromLoaded: true},
		{Kind: "load", At: at, Width: width, Register: 2},
	}
	native, err := executeStorageBytes(initial, program)
	if err != nil || native.Loaded[0] != a || native.Loaded[1] != b || native.Loaded[2] != a || native.Memory[storageAt(at, -1)] != 0xa5 || native.Memory[storageAt(at, int64(width))] != 0xa5 {
		t.Fatalf("float bit-storage byte intent differs: %+v %v", native, err)
	}
	checkFloatOracleRegion(t, source, in, globals, prefix, whole)
}

// Only this adapter inspects production results. All expected values, actual
// cell identities and source effects above were computed without its helpers.
func checkFloatOracleRegion(t testing.TB, source computationSource, in regionInput, globals map[*ssa.Global]any, prefix, whole storageSourceResult) {
	t.Helper()
	in.premises = []string{"immutable selected typed source; exact supplied initial globals; omitted initialization and external interference remain open"}
	in.selection = source.prog
	in.storageModel = conditionalRegionStorageModel()
	in.initial = regionState{memory: map[regionObject]regionValue{}}
	for global, value := range globals {
		typ := global.Type().Underlying().(*types.Pointer).Elem()
		in.initial.memory[regionObject{kind: regionGlobal, site: global}] = regionValue{typ: typ, kind: regionConstant, scalar: constant.MakeUint64(value.(uint64))}
	}
	checked, _ := proveRegionFixture(t, in)
	if len(checked.observations) != 1 || checked.input.storageModel != in.storageModel {
		t.Fatal("checked float cut lost precision or conditional model")
	}
	observation := checked.observations[0]
	loc := prefix.Operands[0].(storageSourceLocation)
	object := prefix.Objects[loc.Object-1]
	if observation.value.kind != regionPointer || observation.value.location.object.kind != regionAllocation || observation.value.location.object.site != object.Site || !slices.Equal(observation.value.location.path, []regionStep{{field: true, index: 1}, {index: 1}}) {
		t.Fatal("checked float cut differs from concrete allocation/subobject")
	}
	assertFloatOracleValue(t, observation.state.memory[observation.value.location.object], object.Type, object.Value)
	returns := storageOracleInstructions[*ssa.Return](in.root)
	if len(returns) != 1 || len(returns[0].Results) != len(whole.Results) {
		t.Fatal("float differential grammar lost its single complete return")
	}
	ret := returns[0]
	in.use = regionUse{at: regionPoint{ret.Block(), slices.Index(ret.Block().Instrs, ssa.Instruction(ret))}, operand: ret.Results[0]}
	checked, _ = proveRegionFixture(t, in)
	if len(checked.observations) != 1 || checked.input.storageModel != in.storageModel {
		t.Fatal("checked float return lost precision or conditional model")
	}
	observation = checked.observations[0]
	for i, operand := range ret.Results {
		assertFloatOracleValue(t, observation.state.values[operand], operand.Type(), whole.Results[i])
	}
	assertFloatOracleValue(t, observation.state.memory[checkedFloatObject(t, observation.state, object.Site)], object.Type, whole.Objects[loc.Object-1].Value)
}

func checkedFloatObject(t testing.TB, state regionState, site ssa.Value) regionObject {
	t.Helper()
	var found regionObject
	count := 0
	for object := range state.memory {
		if object.site == site {
			found = object
			count++
		}
	}
	if count != 1 {
		t.Fatalf("checked float state has %d objects for one executed allocation", count)
	}
	return found
}

func assertFloatOracleValue(t testing.TB, got regionValue, typ types.Type, want any) {
	t.Helper()
	if !types.Identical(got.typ, typ) {
		t.Fatalf("checked float oracle type=%v want %v", got.typ, typ)
	}
	switch value := want.(type) {
	case float32:
		if got.kind != regionFloat || got.floatBits != uint64(math.Float32bits(value)) {
			t.Fatalf("checked float32 bits=%x kind=%v want %x", got.floatBits, got.kind, math.Float32bits(value))
		}
	case float64:
		if got.kind != regionFloat || got.floatBits != math.Float64bits(value) {
			t.Fatalf("checked float64 bits=%x kind=%v want %x", got.floatBits, got.kind, math.Float64bits(value))
		}
	case bool:
		if got.kind != regionConstant || got.scalar.Kind() != constant.Bool || constant.BoolVal(got.scalar) != value {
			t.Fatalf("checked IEEE equality=%+v want %v", got, value)
		}
	case uint64:
		if got.kind != regionConstant {
			t.Fatalf("checked integer read has kind %v", got.kind)
		}
		integer, exact := constant.Uint64Val(got.scalar)
		if !exact || integer != value {
			t.Fatalf("checked integer bits=%x want %x", integer, value)
		}
	case []any:
		if got.kind != regionAggregate || len(got.elements) != len(value) {
			t.Fatal("checked aggregate shape differs from actual cells")
		}
		for i, element := range value {
			var elem types.Type
			switch u := typ.Underlying().(type) {
			case *types.Array:
				elem = u.Elem()
			case *types.Struct:
				elem = u.Field(i).Type()
			default:
				t.Fatal("unexpected concrete aggregate type")
			}
			assertFloatOracleValue(t, got.elements[i], elem, element)
		}
	default:
		t.Fatalf("unsupported differential scalar %T", want)
	}
}

func TestFloatStorageOraclePopulation(t *testing.T) {
	count := 0
	for _, word := range []int{32, 64} {
		for _, width := range []int{4, 8} {
			for _, named := range []bool{false, true} {
				t.Run(fmt.Sprintf("word%d/float%d/named=%t", word, width*8, named), func(t *testing.T) {
					source := relationFixture(t, floatOracleText(width, named), word)
					root := source.prog.Roots["F"]
					in := regionAtCall(t, regionInput{root: root, owner: root.Prog, entry: regionPoint{block: root.Blocks[0]}}, "Read", 0)
					for _, a := range floatOracleBits(width) {
						for _, b := range floatOracleBits(width) {
							checkFloatStorageOracle(t, source, in, width, a, b)
							count++
						}
					}
				})
			}
		}
	}
	if count != 3872 {
		t.Fatalf("float reference configurations=%d, want 3872", count)
	}
	t.Log("3872 finite source cut/whole-return and byte-intent cases, checked against conditional region proofs; no native correspondence judgment")
}

func FuzzFloatStorageOracle(f *testing.F) {
	for _, width := range []int{4, 8} {
		for i, bits := range floatOracleBits(width) {
			f.Add(width == 8, i%2 == 0, i%3 == 0, bits, floatOracleBits(width)[(i+1)%22])
		}
	}
	f.Fuzz(func(t *testing.T, wide, named, word32 bool, a, b uint64) {
		width, word := 4, 64
		if wide {
			width = 8
		}
		if word32 {
			word = 32
		}
		source := relationFixture(t, floatOracleText(width, named), word)
		root := source.prog.Roots["F"]
		in := regionAtCall(t, regionInput{root: root, owner: root.Prog, entry: regionPoint{block: root.Blocks[0]}}, "Read", 0)
		checkFloatStorageOracle(t, source, in, width, a, b)
	})
}

func TestFloatStorageOracleConstants(t *testing.T) {
	for _, word := range []int{32, 64} {
		for _, tc := range []struct {
			typ, expression string
			bits            uint64
		}{
			{"float32", "0", 0},
			{"float32", "-0.0", 0},
			{"float32", "-0x1p-150", 0},
			{"float32", "0x1p-149", 1},
			{"float32", "0x1.fffffcp-127", 0x007fffff},
			{"float32", "0x1p-126", 0x00800000},
			{"float32", "0x1.fffffep127", 0x7f7fffff},
			{"float32", "0x1.000001p0", 0x3f800000},
			{"float32", "0x1.000003p0", 0x3f800002},
			{"float32", "0.1", 0x3dcccccd},
			{"float64", "0", 0},
			{"float64", "-0.0", 0},
			{"float64", "-0x1p-1075", 0},
			{"float64", "0x1p-1074", 1},
			{"float64", "0x1.ffffffffffffep-1023", 0x000fffffffffffff},
			{"float64", "0x1p-1022", 0x0010000000000000},
			{"float64", "0x1.fffffffffffffp1023", 0x7fefffffffffffff},
			{"float64", "0x1.00000000000008p0", 0x3ff0000000000000},
			{"float64", "0x1.00000000000018p0", 0x3ff0000000000002},
			{"float64", "0.1", 0x3fb999999999999a},
		} {
			t.Run(fmt.Sprintf("word%d/%s/%s", word, tc.typ, tc.expression), func(t *testing.T) {
				source := relationFixture(t, fmt.Sprintf(`type Real %s
func Read(p *Real)Real{return *p}
func F()(Real,Real){var zero Real;var value Real=%s;Read(&zero);return zero,value}`, tc.typ, tc.expression), word)
				root := source.prog.Roots["F"]
				in := regionAtCall(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, "Read", 0)
				sizes := source.prog.Pkgs[0].TypesSizes
				prefix, err := executeStorageSource(t, in, storageSourceRun{Sizes: sizes})
				if err != nil || prefix.Cut == nil || prefix.Returned {
					t.Fatalf("zero cut: %+v %v", prefix, err)
				}
				result, err := executeStorageSource(t, in, storageSourceRun{Sizes: sizes, Whole: true})
				if err != nil || !result.Returned || len(result.Results) != 2 {
					t.Fatalf("constant return: %+v %v", result, err)
				}
				for i, want := range []uint64{0, tc.bits} {
					var bits uint64
					if tc.typ == "float32" {
						bits = uint64(math.Float32bits(result.Results[i].(float32)))
					} else {
						bits = math.Float64bits(result.Results[i].(float64))
					}
					if bits != want {
						t.Fatalf("constant %s result %d bits=%x want %x", tc.expression, i, bits, want)
					}
				}
				ret := storageOracleInstructions[*ssa.Return](root)[0]
				in.owner = root.Prog
				in.premises = []string{"immutable selected typed source; closed local construction; omitted external interference remains open"}
				in.use = regionUse{at: regionPoint{ret.Block(), slices.Index(ret.Block().Instrs, ssa.Instruction(ret))}, operand: ret.Results[1]}
				checked, _ := proveRegionFixture(t, in)
				if len(checked.observations) != 1 {
					t.Fatal("checked constant lost exact outcome")
				}
				assertFloatOracleValue(t, checked.observations[0].value, ret.Results[1].Type(), result.Results[1])
			})
		}
	}
}

func TestFloatStorageOracleAllocationAndAggregateAliases(t *testing.T) {
	for _, width := range []int{4, 8} {
		source := relationFixture(t, fmt.Sprintf(`import "unsafe"
type Real float%d
type Word int%d
type Pair struct{X Real;Y Real}
func Make()*Pair{var p Pair;return &p}
func F()(Word,Word,Real,Real){
 a:=Make();b:=Make()
 p:=(*Word)(unsafe.Pointer(&a.Y));q:=(*Word)(unsafe.Pointer(&a.Y))
 *p=-1
 old:=*q
 *a=Pair{X:2,Y:3}
 current:=*q
 *q=0
 return old,current,a.X,b.Y
}`, width*8, width*8), 64)
		root := source.prog.Roots["F"]
		result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true})
		if err != nil {
			t.Fatal(err)
		}
		var first, second *storageSourceObject
		for i := range result.Objects {
			object := &result.Objects[i]
			if object.Site.Parent().Name() != "Make" {
				continue
			}
			if first == nil {
				first = object
			} else if second == nil {
				second = object
			} else {
				t.Fatal("unexpected third helper allocation")
			}
		}
		if first == nil || second == nil || first.ID == second.ID || first.Site != second.Site || first.Invocation == second.Invocation || !result.Invocations[first.Invocation-1].Returned || !result.Invocations[second.Invocation-1].Returned {
			t.Fatal("float allocations collapsed across completed helper invocations")
		}
		var three int64 = int64(math.Float64bits(3))
		var two, zero any = float64(2), float64(0)
		if width == 4 {
			three, two, zero = int64(math.Float32bits(3)), float32(2), float32(0)
		}
		if !slices.Equal(result.Results, []any{int64(-1), three, two, zero}) || !slices.Equal(first.Value.([]any), []any{two, zero}) || !slices.Equal(second.Value.([]any), []any{zero, zero}) {
			t.Fatalf("float aggregate overwrite retained stale alias or changed other allocation: %+v", result)
		}
	}
}

func TestFloatStorageOracleIntegerBackedViews(t *testing.T) {
	for _, word := range []int{32, 64} {
		for _, width := range []int{4, 8} {
			source := relationFixture(t, fmt.Sprintf(`import "unsafe"
type Real float%d
type Word uint%d
var A,B Word
func Read(p *Real)Real{return *p}
func F()(bool,bool,Word){
 x:=A;y:=B
 p:=(*Real)(unsafe.Pointer(&x));q:=(*Real)(unsafe.Pointer(&x))
 first:=Read(p)
 *q=*(*Real)(unsafe.Pointer(&y))
 return first==*p,*p!=*p,x
}`, width*8, width*8), word)
			root := source.prog.Roots["F"]
			for i, a := range floatOracleBits(width) {
				b := floatOracleBits(width)[(i+1)%22]
				globals := map[*ssa.Global]any{root.Pkg.Members["A"].(*ssa.Global): a, root.Pkg.Members["B"].(*ssa.Global): b}
				in := regionAtCall(t, regionInput{owner: root.Prog, root: root, entry: regionPoint{block: root.Blocks[0]}}, "Read", 0)
				prefix, err := executeStorageSource(t, in, storageSourceRun{Globals: globals, Sizes: source.prog.Pkgs[0].TypesSizes})
				if err != nil {
					t.Fatal(err)
				}
				whole, err := executeStorageSource(t, in, storageSourceRun{Globals: globals, Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true})
				if err != nil || !whole.Returned || !slices.Equal(whole.Results, []any{floatOracleEqual(width, a, b), !floatOracleEqual(width, b, b), b}) {
					t.Fatalf("integer-backed view lost IEEE read/write: %+v %v", whole, err)
				}
				loc := prefix.Operands[0].(storageSourceLocation)
				if prefix.Objects[loc.Object-1].Value != a || whole.Objects[loc.Object-1].Value != b || loc.Offset != 0 || len(loc.Path) != 0 {
					t.Fatal("float write failed to update the canonical integer cell")
				}
				in.premises = []string{"immutable selected typed source; exact supplied initial globals; omitted initialization and interference remain open"}
				in.selection = source.prog
				in.storageModel = conditionalRegionStorageModel()
				in.initial.memory = map[regionObject]regionValue{}
				for global, value := range globals {
					in.initial.memory[regionObject{kind: regionGlobal, site: global}] = regionValue{typ: global.Type().Underlying().(*types.Pointer).Elem(), kind: regionConstant, scalar: constant.MakeUint64(value.(uint64))}
				}
				ret := storageOracleInstructions[*ssa.Return](root)[0]
				in.use = regionUse{at: regionPoint{ret.Block(), slices.Index(ret.Block().Instrs, ssa.Instruction(ret))}, operand: ret.Results[0]}
				checked, _ := proveRegionFixture(t, in)
				if len(checked.observations) != 1 {
					t.Fatal("integer-backed checked return lost precision")
				}
				for i, operand := range ret.Results {
					assertFloatOracleValue(t, checked.observations[0].state.values[operand], operand.Type(), whole.Results[i])
				}
			}
		}
	}
}

func TestFloatStorageOraclePointerCells(t *testing.T) {
	source := relationFixture(t, `import "unsafe"
type Pointer *float64
func F()(float64,bool){
 var x float64
 var nilPointer Pointer
 var pointers [2]*float64
 pointers[0]=&x;pointers[1]=pointers[0]
 var raw unsafe.Pointer=unsafe.Pointer(pointers[0])
 *(*uint64)(raw)=0x3ff0000000000000
 return *pointers[1],nilPointer==nil
}`, 64)
	root := source.prog.Roots["F"]
	result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true})
	if err != nil || !result.Returned || !slices.Equal(result.Results, []any{float64(1), true}) {
		t.Fatalf("pointer-valued cells lost the old oracle grammar: %+v %v", result, err)
	}
}

func TestFloatStorageOracleOrdinaryEmptyAndNilCells(t *testing.T) {
	for _, tc := range []struct{ name, typ, equal string }{
		{"empty-array", "[0]float64", "*p==v"},
		{"empty-struct", "struct{}", "*p==v"},
		{"nil-interface", "any", "*p==nil"},
		{"nil-function", "func()", "*p==nil"},
		{"nil-slice", "[]uint64", "*p==nil"},
		{"nil-fields", "struct{I any;F func();S []uint64}", "p.I==nil&&p.F==nil&&p.S==nil"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := relationFixture(t, "type T "+tc.typ+";func Round(p *T)bool{v:=*p;*p=v;return "+tc.equal+"};func F()bool{var x T;return Round(&x)}", 64)
			root := source.prog.Roots["F"]
			result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true})
			if err != nil || !result.Returned || !slices.Equal(result.Results, []any{true}) {
				t.Fatalf("ordinary cell round trip lost existing oracle grammar: %+v %v", result, err)
			}
			reads, writes := 0, 0
			for _, event := range result.Events {
				switch event.Kind {
				case "read":
					reads++
				case "write":
					writes++
				}
			}
			if reads < 2 || writes != 1 {
				t.Fatal("ordinary cell regression did not execute both load and store validation")
			}
		})
	}
}

func TestFloatStorageOracleOrdinaryTypeChanges(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"named-function", `type Thunk func()bool;func Yes()bool{return true};func F()bool{return Thunk(Yes)()}`},
		{"named-slice", `type Words []uint64;func F()bool{a:=[2]uint64{7,9};s:=Words(a[:]);s[0]=11;return a[0]==11&&s[1]==9}`},
		{"nil-pointee", `type Word uint64;func NilWord(p *uint64)bool{return (*Word)(p)==nil};func F()bool{return NilWord(nil)}`},
		{"tagged-pointee", "type A struct{X uint64 `a`};type B struct{X uint64 `b`};func F()bool{a:=A{7};p:=(*B)(&a);p.X=9;v:=*p;*p=v;return a.X==9}"},
		{"receive-channel", `func Read(c chan uint64)bool{return (<-chan uint64)(c)==nil};func F()bool{return Read(nil)}`},
		{"send-channel", `func Send(c chan uint64)bool{return (chan<- uint64)(c)==nil};func F()bool{return Send(nil)}`},
		{"named-source-receive", `type Full chan uint64;func Read(c Full)bool{return (<-chan uint64)(c)==nil};func F()bool{return Read(nil)}`},
		{"named-source-send", `type Full chan uint64;func Send(c Full)bool{return (chan<- uint64)(c)==nil};func F()bool{return Send(nil)}`},
		{"named-target-receive", `type Reader <-chan uint64;func Read(c chan uint64)bool{return Reader(c)==nil};func F()bool{return Read(nil)}`},
		{"named-target-send", `type Sender chan<- uint64;func Send(c chan uint64)bool{return Sender(c)==nil};func F()bool{return Send(nil)}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := relationFixture(t, tc.text, 64)
			root := source.prog.Roots["F"]
			result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true})
			if err != nil || !result.Returned || !slices.Equal(result.Results, []any{true}) {
				t.Fatalf("ordinary Go type change lost value or aliases: %+v %v", result, err)
			}
		})
	}
}

func TestFloatStorageOracleSourceRefusals(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"wide-read", `import "unsafe";func F()float64{var x uint32;return *(*float64)(unsafe.Pointer(&x))}`},
		{"narrow-read", `import "unsafe";func F()float32{var x uint64;return *(*float32)(unsafe.Pointer(&x))}`},
		{"aggregate-view", `import "unsafe";func F()float64{var x [2]uint32;return *(*float64)(unsafe.Pointer(&x))}`},
		{"bool-view", `import "unsafe";func F()float32{var x bool;return *(*float32)(unsafe.Pointer(&x))}`},
		{"numeric-to-float", `func F()float32{var x uint32=3;return float32(x)}`},
		{"float-to-numeric", `func F()uint32{var x float32=3;return uint32(x)}`},
		{"float-to-float", `func F()float64{var x float32=3;return float64(x)}`},
		{"numeric-address", `import "unsafe";func F()float64{var x uintptr=8;return *(*float64)(unsafe.Pointer(x))}`},
		{"pointer-address", `import "unsafe";func F()uintptr{var x float64;return uintptr(unsafe.Pointer(&x))}`},
		{"nil-view", `import "unsafe";func F()float64{var p *uint64;return *(*float64)(unsafe.Pointer(p))}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := relationFixture(t, tc.text, 64)
			root := source.prog.Roots["F"]
			result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true})
			if err == nil || result.Returned || len(result.Events) != 0 || len(result.Objects) != 0 {
				t.Fatalf("invalid float oracle input yielded a partial answer: %+v %v", result, err)
			}
		})
	}
}

type floatOracleSizes struct {
	types.Sizes
	floatSize, floatAlign int64
}

func (s floatOracleSizes) Sizeof(typ types.Type) int64 {
	if basic, ok := typ.Underlying().(*types.Basic); ok && basic.Kind() == types.Float32 && s.floatSize != 0 {
		return s.floatSize
	}
	return s.Sizes.Sizeof(typ)
}

func (s floatOracleSizes) Alignof(typ types.Type) int64 {
	if basic, ok := typ.Underlying().(*types.Basic); ok && basic.Kind() == types.Float32 && s.floatAlign != 0 {
		return s.floatAlign
	}
	return s.Sizes.Alignof(typ)
}

func floatOracleMustRefuse(t testing.TB, action func()) {
	t.Helper()
	defer func() {
		recovered := recover()
		if _, ok := recovered.(regionConcreteFailure); !ok {
			t.Fatalf("oracle control wanted explicit refusal, got %v", recovered)
		}
	}()
	action()
}

func TestFloatStorageOracleMetadataRefusals(t *testing.T) {
	for _, name := range []string{"size", "alignment", "extent", "offset", "object-id", "missing-cell", "missing-type", "value-type", "access-type", "equality-type", "equality-value"} {
		t.Run(name, func(t *testing.T) {
			r := &regionConcreteExecution{sizes: types.SizesFor("gc", "amd64"), cells: map[*any]storageSourceLocation{}}
			var value any = uint64(0x3f800000)
			r.object(nil, 1, types.Typ[types.Uint32], &value)
			p := regionConcretePointer{&value}
			floatType := types.Typ[types.Float32]
			action := func() { r.load(p, types.NewPointer(floatType), floatType) }
			switch name {
			case "size":
				r.sizes = floatOracleSizes{Sizes: r.sizes, floatSize: 8}
			case "alignment":
				r.sizes = floatOracleSizes{Sizes: r.sizes, floatAlign: 8}
			case "extent":
				r.objects[0].Size = 3
			case "offset":
				r.cells[&value] = storageSourceLocation{Object: 1, Offset: 1}
			case "object-id":
				r.cells[&value] = storageSourceLocation{Object: 2}
			case "missing-cell":
				delete(r.cells, &value)
			case "missing-type":
				r.objects[0].Type = nil
			case "value-type":
				value = float32(1)
			case "access-type":
				action = func() { r.load(p, types.NewPointer(types.Typ[types.Uint32]), floatType) }
			case "equality-type":
				action = func() { r.checkEquality(floatType, types.Typ[types.Float64], float32(1), float64(1)) }
			case "equality-value":
				action = func() { regionConcreteEqual(floatType, uint64(1), uint64(1)) }
			}
			floatOracleMustRefuse(t, action)
		})
	}
	for _, name := range []string{"path", "type", "offset"} {
		t.Run("subobject-"+name, func(t *testing.T) {
			r := &regionConcreteExecution{sizes: types.SizesFor("gc", "amd64"), cells: map[*any]storageSourceLocation{}}
			cells := []any{uint64(0), uint64(0)}
			var root any = cells
			r.object(nil, 1, types.NewArray(types.Typ[types.Uint32], 2), &root)
			p := regionConcretePointer{&cells[1]}
			switch name {
			case "path":
				r.cells[p.cell] = storageSourceLocation{Object: 1, Path: []int{0}}
			case "type":
				r.objects[0].Type = types.NewArray(types.Typ[types.Float32], 2)
			case "offset":
				r.cells[p.cell] = storageSourceLocation{Object: 1, Path: []int{1}}
			}
			floatOracleMustRefuse(t, func() { r.load(p, types.NewPointer(types.Typ[types.Float32]), types.Typ[types.Float32]) })
		})
	}
}
