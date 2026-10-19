package closure

import (
	"errors"
	"fmt"
	"go/types"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// This is a concrete reference for a finite test grammar, not correspondence
// evidence. Source answers come from the interpreter in region_test.go, executing
// actual SSA. Neither source traces nor storage helpers of the checker participate.
type regionConcreteFailure struct{ reason string }

func (e regionConcreteFailure) Error() string { return e.reason }

type storageSourceRun struct {
	Globals map[*ssa.Global]any
	Sizes   types.Sizes
	Whole   bool
}

// Locations identify actual cells. An allocation site alone never identifies an
// object: repeated executions and distinct helper invocations get distinct IDs.
type storageSourceLocation struct {
	Object int
	Path   []int
	Offset int64
}

// Objects retain their current contents even after their allocating invocation
// returns. Returned identifies control completion, not object death or nonescape.
// A correspondence adapter must derive those lifetime/projection obligations.
type storageSourceObject struct {
	ID         int
	Site       ssa.Value
	Invocation uint64
	Type       types.Type
	Size       int64
	Alignment  int64
	Value      any
}

type storageSourceEvent struct {
	Kind        string
	Instruction ssa.Instruction
	Invocation  uint64
	Child       uint64
	Location    storageSourceLocation
	Type        types.Type
	Width       int64
	Value       any
	Operands    []any
}

type storageSourceInvocation struct {
	ID, Parent uint64
	Call       *ssa.Call
	Target     *ssa.Function
	Returned   bool
}

type storageSourceResult struct {
	Cut         *ssa.Call
	Operands    []any
	Results     []any
	Objects     []storageSourceObject
	Events      []storageSourceEvent
	Invocations []storageSourceInvocation
	Returned    bool
}

type regionConcreteExecution struct {
	sizes       types.Sizes
	cells       map[*any]storageSourceLocation
	objects     []storageSourceObject
	roots       []*any
	events      []storageSourceEvent
	invocations []storageSourceInvocation
	cut         *ssa.Call
	operands    []any
}

// executeStorageSource runs the same interpreter as executeRegionConcrete, with
// explicit globals and exact unsigned values. Errors cover invalid joint inputs;
// unsupported interpreter instructions remain test failures, never broad unknowns.
// Returned snapshots own their containers and contain no mutable heap-cell pointers.
func executeStorageSource(t testing.TB, in regionInput, config storageSourceRun) (result storageSourceResult, err error) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			if failure, ok := recovered.(regionConcreteFailure); ok {
				result, err = storageSourceResult{}, failure
				return
			}
			panic(recovered)
		}
	}()
	if config.Sizes == nil || in.root == nil || len(in.root.Params) != 0 || len(in.root.FreeVars) != 0 {
		return result, errors.New("joint oracle needs selected sizes and a closed zero-argument root")
	}
	run := &regionConcreteExecution{sizes: config.Sizes, cells: map[*any]storageSourceLocation{},
		invocations: []storageSourceInvocation{{ID: 1, Target: in.root}}}
	globals := map[*ssa.Global]*any{}
	keys := make([]*ssa.Global, 0, len(config.Globals))
	for global := range config.Globals {
		if global == nil || global.Pkg == nil || global.Pkg.Prog != in.root.Prog {
			return result, errors.New("joint oracle global belongs to another source owner")
		}
		keys = append(keys, global)
	}
	slices.SortFunc(keys, func(a, b *ssa.Global) int { return strings.Compare(a.String(), b.String()) })
	for _, global := range keys {
		typ := global.Type().Underlying().(*types.Pointer).Elem()
		value := run.checkedValue(typ, config.Globals[global])
		globals[global] = &value
		run.object(global, 0, typ, &value)
	}
	steps := 0
	returned := executeRegionConcreteFrame(t, in, globals, nil, nil, config.Whole, 0, &steps, run, 1)
	result.Cut, result.Operands = run.cut, run.operands
	if config.Whole {
		for _, value := range returned.(regionConcreteResults) {
			result.Results = append(result.Results, run.snapshot(value))
		}
		result.Returned = run.invocations[0].Returned
	}
	for i, object := range run.objects {
		object.Value = run.snapshot(*run.roots[i])
		result.Objects = append(result.Objects, object)
	}
	result.Events, result.Invocations = run.events, run.invocations
	return result, nil
}

func (r *regionConcreteExecution) checkedValue(typ types.Type, value any) any {
	switch u := typ.Underlying().(type) {
	case *types.Basic:
		if u.Info()&types.IsInteger != 0 {
			width := uint(r.sizes.Sizeof(typ) * 8)
			if width == 0 || width > 64 {
				panic(regionConcreteFailure{"unsupported concrete integer width"})
			}
			if u.Info()&types.IsUnsigned != 0 {
				v, ok := value.(uint64)
				if ok && (width == 64 || v < uint64(1)<<width) {
					return v
				}
			} else if v, ok := value.(int64); ok && (width == 64 || v >= -(int64(1)<<(width-1)) && v < int64(1)<<(width-1)) {
				return v
			}
		} else if u.Info()&types.IsBoolean != 0 {
			if v, ok := value.(bool); ok {
				return v
			}
		} else if u.Info()&types.IsString != 0 {
			if v, ok := value.(string); ok {
				return v
			}
		}
	case *types.Array:
		if values, ok := value.([]any); ok && int64(len(values)) == u.Len() {
			out := make([]any, len(values))
			for i := range values {
				out[i] = r.checkedValue(u.Elem(), values[i])
			}
			return out
		}
	case *types.Struct:
		if values, ok := value.([]any); ok && len(values) == u.NumFields() {
			out := make([]any, len(values))
			for i := range values {
				out[i] = r.checkedValue(u.Field(i).Type(), values[i])
			}
			return out
		}
	}
	panic(regionConcreteFailure{fmt.Sprintf("missing exact concrete value of %s: %T", typ, value)})
}

func (r *regionConcreteExecution) convertInteger(value any, typ types.Type) any {
	u, ok := typ.Underlying().(*types.Basic)
	if !ok || u.Info()&types.IsInteger == 0 {
		panic(regionConcreteFailure{"oracle conversion is not integer-to-integer"})
	}
	var bits uint64
	switch value := value.(type) {
	case uint64:
		bits = value
	case int64:
		bits = uint64(value)
	default:
		panic(regionConcreteFailure{"oracle conversion has no integer operand"})
	}
	width := uint(r.sizes.Sizeof(typ) * 8)
	if width == 0 || width > 64 {
		panic(regionConcreteFailure{"oracle conversion has unsupported selected width"})
	}
	if width < 64 {
		bits &= uint64(1)<<width - 1
	}
	if u.Info()&types.IsUnsigned != 0 {
		return bits
	}
	if width < 64 && bits&(uint64(1)<<(width-1)) != 0 {
		bits |= ^uint64(0) << width
	}
	return int64(bits)
}

func (r *regionConcreteExecution) object(site ssa.Value, invocation uint64, typ types.Type, cell *any) storageSourceLocation {
	id := len(r.objects) + 1
	r.objects = append(r.objects, storageSourceObject{ID: id, Site: site, Invocation: invocation, Type: typ, Size: r.sizes.Sizeof(typ), Alignment: r.sizes.Alignof(typ)})
	r.roots = append(r.roots, cell)
	loc := storageSourceLocation{Object: id}
	r.registerCells(cell, typ, loc)
	return loc
}

func (r *regionConcreteExecution) registerCells(cell *any, typ types.Type, loc storageSourceLocation) {
	r.cells[cell] = loc
	switch u := typ.Underlying().(type) {
	case *types.Array:
		values := (*cell).([]any)
		for i := range values {
			child := storageSourceLocation{loc.Object, append(slices.Clone(loc.Path), i), loc.Offset + int64(i)*r.sizes.Sizeof(u.Elem())}
			r.registerCells(&values[i], u.Elem(), child)
		}
	case *types.Struct:
		fields := make([]*types.Var, u.NumFields())
		for i := range fields {
			fields[i] = u.Field(i)
		}
		offsets := r.sizes.Offsetsof(fields)
		values := (*cell).([]any)
		for i := range values {
			child := storageSourceLocation{loc.Object, append(slices.Clone(loc.Path), i), loc.Offset + offsets[i]}
			r.registerCells(&values[i], fields[i].Type(), child)
		}
	}
}

func (r *regionConcreteExecution) location(pointer regionConcretePointer) storageSourceLocation {
	loc, ok := r.cells[pointer.cell]
	if !ok {
		panic(regionConcreteFailure{"pointer has no concrete allocated cell"})
	}
	loc.Path = slices.Clone(loc.Path)
	return loc
}

func (r *regionConcreteExecution) snapshot(value any) any {
	switch value := value.(type) {
	case nil, uint64, int64, bool, string:
		return value
	case regionConcretePointer:
		return r.location(value)
	case []any:
		out := make([]any, len(value))
		for i := range value {
			out[i] = r.snapshot(value[i])
		}
		return out
	default:
		panic(regionConcreteFailure{fmt.Sprintf("unsupported joint snapshot %T", value)})
	}
}

func (r *regionConcreteExecution) allocate(ins *ssa.Alloc, invocation uint64, cell *any) {
	typ := ins.Type().Underlying().(*types.Pointer).Elem()
	loc := r.object(ins, invocation, typ, cell)
	r.events = append(r.events, storageSourceEvent{Kind: "allocate", Instruction: ins, Invocation: invocation, Location: loc, Type: typ, Width: r.sizes.Sizeof(typ), Value: r.snapshot(*cell)})
}

func (r *regionConcreteExecution) access(ins ssa.Instruction, invocation uint64, pointer regionConcretePointer, typ types.Type, value any, write bool) {
	kind := "read"
	if write {
		kind = "write"
	}
	r.events = append(r.events, storageSourceEvent{Kind: kind, Instruction: ins, Invocation: invocation, Location: r.location(pointer), Type: typ, Width: r.sizes.Sizeof(typ), Value: r.snapshot(value)})
}

func (r *regionConcreteExecution) call(ins *ssa.Call, parent uint64, target *ssa.Function, actual []any) uint64 {
	id := uint64(len(r.invocations) + 1)
	r.invocations = append(r.invocations, storageSourceInvocation{ID: id, Parent: parent, Call: ins, Target: target})
	operands := make([]any, len(actual))
	for i := range actual {
		operands[i] = r.snapshot(actual[i])
	}
	r.events = append(r.events, storageSourceEvent{Kind: "call", Instruction: ins, Invocation: parent, Child: id, Operands: operands})
	return id
}

func (r *regionConcreteExecution) returned(ins *ssa.Return, invocation uint64, values regionConcreteResults) {
	operands := make([]any, len(values))
	for i := range values {
		operands[i] = r.snapshot(values[i])
	}
	r.invocations[invocation-1].Returned = true
	r.events = append(r.events, storageSourceEvent{Kind: "return", Instruction: ins, Invocation: invocation, Operands: operands})
}

// Native intent is a small byte-machine grammar, not an ISA interpreter. Its
// locations/domain and initial values precede any encoding or proof. It admits
// address formation, exact-width loads/stores and equality guards only. Future
// encoding/adaptation must independently account for actual machine transfers.
type storageByteLocation struct {
	Image  bool
	Offset int64
}

type storageByteStep struct {
	Kind       string
	At         storageByteLocation
	Width      int
	Value      uint64
	Register   int
	Indirect   bool
	FromLoaded bool
}

type storageByteEvent struct {
	Step  int
	Write bool
	At    storageByteLocation
	Width int
	Value uint64
}

type storageByteResult struct {
	Memory    map[storageByteLocation]byte
	Loaded    map[int]uint64
	Addresses map[int]storageByteLocation
	Events    []storageByteEvent
}

func executeStorageBytes(initial map[storageByteLocation]byte, program []storageByteStep) (storageByteResult, error) {
	r := storageByteResult{Memory: map[storageByteLocation]byte{}, Loaded: map[int]uint64{}, Addresses: map[int]storageByteLocation{}}
	for at, value := range initial {
		r.Memory[at] = value
	}
	for index, step := range program {
		at := step.At
		if step.Kind == "address" {
			r.Addresses[step.Register] = at
			continue
		}
		if step.Kind == "guard" {
			value, ok := r.Loaded[step.Register]
			if !ok || value != step.Value {
				return storageByteResult{}, fmt.Errorf("byte oracle guard %d differs", index)
			}
			continue
		}
		if step.Indirect {
			var ok bool
			at, ok = r.Addresses[step.Register]
			if !ok {
				return storageByteResult{}, errors.New("byte oracle has no address operand")
			}
		}
		if step.Kind != "load" && step.Kind != "store" || step.Width != 1 && step.Width != 4 && step.Width != 8 || at.Offset > int64(^uint64(0)>>1)-int64(step.Width-1) {
			return storageByteResult{}, errors.New("unsupported byte oracle operation/extent")
		}
		value := step.Value
		if step.FromLoaded {
			var ok bool
			value, ok = r.Loaded[step.Register]
			if !ok {
				return storageByteResult{}, errors.New("byte oracle has no loaded operand")
			}
		}
		for lane := range step.Width {
			cell := storageByteLocation{at.Image, at.Offset + int64(lane)}
			if _, ok := r.Memory[cell]; !ok {
				return storageByteResult{}, fmt.Errorf("byte oracle uncovered byte %+v", cell)
			}
		}
		if step.Kind == "load" {
			value = 0
			for lane := range step.Width {
				value |= uint64(r.Memory[storageByteLocation{at.Image, at.Offset + int64(lane)}]) << (8 * lane)
			}
			r.Loaded[step.Register] = value
		} else {
			if step.Width < 8 {
				value &= uint64(1)<<(8*step.Width) - 1
			}
			for lane := range step.Width {
				r.Memory[storageByteLocation{at.Image, at.Offset + int64(lane)}] = byte(value >> (8 * lane))
			}
		}
		r.Events = append(r.Events, storageByteEvent{index, step.Kind == "store", at, step.Width, value})
	}
	return r, nil
}

type storageOracleTemplate struct {
	Name, Kind, Type string
	Globals          int
	Width            int
	Combined         bool
	Value            uint64
	Array            [4]byte
	Head, Tail       byte
	Reverse          bool
	ReadChoice       storageOracleReadChoice
	RetainZeroRead   bool
}

type storageOracleReadChoice uint8

const (
	storageDeferFirstRead storageOracleReadChoice = iota
	storageRetainBothReads
	storageDeferLastRead
)

const (
	storageOracleAllZeroSeed   uint64 = 1 << 63
	storageOracleMixedZeroSeed uint64 = 1 << 62
)

type storageOracleValueCase struct {
	name     string
	template int
	seed     uint64
}

// Supplements retain the same 22 shapes. They select three causal value/order
// cases, not another constructor or a claim about all possible optimizations.
func storageOracleValueCases() []storageOracleValueCase {
	return []storageOracleValueCase{
		{"combined-array-all-zero", 17, storageOracleAllZeroSeed},
		{"reversed-array-mixed-zero", 16, storageOracleMixedZeroSeed},
		{"combined-padding-typed-zero", 19, storageOracleAllZeroSeed},
	}
}

// Deterministic tests and fuzzing use exactly this constructor. The 22 templates
// vary source construction and native intent independently of checker acceptance.
func storageOracleTemplates(seed uint64) []storageOracleTemplate {
	var out []storageOracleTemplate
	for _, count := range []int{0, 1, 3} {
		for _, width := range []int{1, 4, 8} {
			out = append(out, storageOracleTemplate{Kind: "materialized", Globals: count, Width: width})
		}
	}
	for _, kind := range []string{"zero", "write-only"} {
		for _, width := range []int{1, 4, 8} {
			out = append(out, storageOracleTemplate{Kind: kind, Width: width})
		}
	}
	out = append(out, storageOracleTemplate{Kind: "zero-arg", Globals: 1, Width: 4})
	for _, kind := range []string{"array", "padding"} {
		for _, combined := range []bool{false, true} {
			out = append(out, storageOracleTemplate{Kind: kind, Width: 4, Combined: combined})
		}
	}
	out = append(out, storageOracleTemplate{Kind: "eliminated", Width: 8}, storageOracleTemplate{Kind: "alias", Width: 1})
	for i := range out {
		c := &out[i]
		c.Type = fmt.Sprintf("uint%d", c.Width*8)
		c.Value = (seed ^ 0x87654321fedcba98) | uint64(1)<<(c.Width*8-1) | 1
		if c.Width < 8 {
			c.Value &= uint64(1)<<(c.Width*8) - 1
		}
		for lane := range c.Array {
			c.Array[lane] = byte(17*(lane+1)) ^ byte(seed>>uint(8*lane))
		}
		c.Head, c.Tail = 0x11^byte(seed), 0x33^byte(seed>>8)
		if seed&storageOracleAllZeroSeed != 0 {
			c.Array = [4]byte{}
			c.Head, c.Tail = 0, 0
			if c.Kind == "padding" {
				c.Value = 0
			}
		} else if seed&storageOracleMixedZeroSeed != 0 {
			c.Array[0] |= 1
			c.Array[1] = 0
			c.Array[2] |= 1
			c.Array[3] = 0
			c.Reverse = c.Kind == "array" && !c.Combined
			c.Head = 0
			c.Tail |= 1
			if c.Kind == "padding" {
				c.Value = 0
			}
		}
		c.Name = fmt.Sprintf("%s/g%d/w%d/combined=%t", c.Kind, c.Globals, c.Width, c.Combined)
	}
	return out
}

// Three additional shapes share one source computation. Native intent may delete
// either known read or retain both after an actual optional initializer.
// The base constructor remains exactly 22 shapes for its separately counted run.
func storageOracleReadChoiceTemplates(seed uint64) []storageOracleTemplate {
	value := uint64(uint32(seed)^7) | 1
	return []storageOracleTemplate{
		{Name: "read-choice/deferred", Kind: "read-choice", Type: "uint32", Width: 4, Value: value},
		{Name: "read-choice/initializer-retained", Kind: "read-choice", Type: "uint32", Width: 4, Value: value, ReadChoice: storageRetainBothReads},
		{Name: "read-choice/last-read-eliminated", Kind: "read-choice", Type: "uint32", Width: 4, Value: value, ReadChoice: storageDeferLastRead},
	}
}

func storageOracleFuzzTemplates(seed uint64) []storageOracleTemplate {
	return append(append(storageOracleTemplates(seed), storageOracleReadChoiceTemplates(seed)...), storageOracleSourceZeroTemplates(seed)...)
}

func storageOracleSourceZeroTemplates(seed uint64) []storageOracleTemplate {
	value := uint64(uint32(seed)^7) | 1
	return []storageOracleTemplate{
		{Name: "source-zero/eliminated", Kind: "source-zero", Type: "uint32", Width: 4, Value: value},
		{Name: "source-zero/materialized-retained", Kind: "source-zero", Type: "uint32", Width: 4, Value: value, RetainZeroRead: true},
	}
}

func (c storageOracleTemplate) sourceText() string {
	var text strings.Builder
	for i := range c.Globals {
		fmt.Fprintf(&text, "var g%d %s;", i, c.Type)
	}
	helperType := c.Type
	if c.Kind == "array" {
		helperType = "uint8"
	}
	fmt.Fprintf(&text, "func Read(p *%s)%s{return *p};func Write(p *%s,v %s){*p=v};", helperType, helperType, helperType, helperType)
	if c.Kind == "zero-arg" {
		fmt.Fprintf(&text, "func Tick(){g0=%d};func F(){Tick();if g0!=%d{panic(1)}}", c.Value, c.Value)
		return text.String()
	}
	if c.Kind == "padding" {
		text.WriteString("type P struct{B uint8;W uint32;T uint8};")
	}
	if c.Kind == "read-choice" || c.Kind == "source-zero" {
		text.WriteString("type P struct{X,Y uint32};func Keep(){};")
	}
	text.WriteString("func F(){")
	for i := range c.Globals {
		fmt.Fprintf(&text, "g%d=%d;", i, c.Value-uint64(i))
	}
	switch c.Kind {
	case "array":
		text.WriteString("var l [4]byte;")
		for lane, value := range c.Array {
			fmt.Fprintf(&text, "l[%d]=%d;", lane, value)
		}
		fmt.Fprintf(&text, "if Read(&l[2])!=%d{panic(1)}", c.Array[2])
	case "padding":
		fmt.Fprintf(&text, "var l P;l.B=%d;l.W=%d;l.T=%d;if Read(&l.W)!=%d{panic(1)}", c.Head, c.Value, c.Tail, c.Value)
	case "alias":
		text.WriteString("l:=[4]byte{1,2,3,4};p:=&l[2];Write(p,9);l=[4]byte{5,6,7,8};if Read(p)!=7{panic(1)};Write(p,11);if Read(p)!=11{panic(2)}")
	case "read-choice":
		fmt.Fprintf(&text, "var l P;Keep();l.Y=%d;if Read(&l.Y)!=%d{panic(1)};l.X=0;if Read(&l.Y)!=%d{panic(2)}", c.Value, c.Value, c.Value)
	case "source-zero":
		fmt.Fprintf(&text, "var l P;Keep();if Read(&l.X)!=0{panic(1)};l.X=%d", c.Value)
	default:
		fmt.Fprintf(&text, "var l %s;", c.Type)
		switch c.Kind {
		case "zero":
			text.WriteString("if Read(&l)!=0{panic(1)}")
		case "write-only":
			fmt.Fprintf(&text, "Write(&l,%d);if Read(&l)!=%d{panic(1)}", c.Value, c.Value)
		default:
			fmt.Fprintf(&text, "l=%d;if Read(&l)!=%d{panic(1)}", c.Value, c.Value)
		}
	}
	text.WriteString("}")
	return text.String()
}

type storageOracleLayout struct {
	Local   storageByteLocation
	Globals []storageByteLocation
}

func storageOraclePlacement(count, permutation int) storageOracleLayout {
	layout := storageOracleLayout{Local: storageByteLocation{Offset: -96 + int64(permutation)*32}}
	for i := range count {
		slot := i
		if permutation != 0 {
			slot = count - i - 1
		}
		layout.Globals = append(layout.Globals, storageByteLocation{true, 0x700010 + int64(slot)*16 + int64(permutation)*64})
	}
	return layout
}

func storageAt(at storageByteLocation, offset int64) storageByteLocation {
	return storageByteLocation{at.Image, at.Offset + offset}
}

// All bytes, including padding and unrelated neighbors, start independently of
// Go zero values. A selected global valuation overwrites only its scalar lanes.
func storageInitialBytes(c storageOracleTemplate, layout storageOracleLayout, valuation int, seed uint64) map[storageByteLocation]byte {
	initial := map[storageByteLocation]byte{}
	for i := range 256 {
		initial[storageByteLocation{true, 0x700000 + int64(i)}] = byte((uint64(i)*37+seed+uint64(valuation)*19)%255 + 1)
	}
	for offset := int64(-128); offset < 16; offset++ {
		initial[storageByteLocation{Offset: offset}] = byte((uint64(offset+128)*53+seed+uint64(valuation)*29)%255 + 1)
	}
	for i, at := range layout.Globals {
		value := storagePriorValue(c.Width, i, valuation)
		for lane := range c.Width {
			initial[storageAt(at, int64(lane))] = byte(value >> (8 * lane))
		}
	}
	return initial
}

func storagePriorValue(width, index, valuation int) uint64 {
	var value uint64
	switch valuation {
	case 0:
		value = 0
	case 1:
		value = ^uint64(0)
	case 2:
		value = 0x8091a2b3c4d5e6f7 ^ (uint64(index+1) * 0x11223344556677)
	default:
		panic("invalid bounded global valuation")
	}
	if width < 8 {
		value &= uint64(1)<<(8*width) - 1
	}
	return value
}

func (c storageOracleTemplate) nativeIntent(layout storageOracleLayout) (program []storageByteStep, prefix int) {
	store := func(at storageByteLocation, width int, value uint64) {
		program = append(program, storageByteStep{Kind: "store", At: at, Width: width, Value: value})
	}
	read := func(at storageByteLocation, width int, value uint64) {
		program = append(program, storageByteStep{Kind: "address", At: at}, storageByteStep{Kind: "load", Width: width, Indirect: true}, storageByteStep{Kind: "guard", Value: value})
	}
	if c.Kind == "zero-arg" {
		store(layout.Globals[0], c.Width, c.Value)
		read(layout.Globals[0], c.Width, c.Value)
		return program, 0
	}
	for i, at := range layout.Globals {
		store(at, c.Width, c.Value-uint64(i))
	}
	switch c.Kind {
	case "source-zero":
		if c.RetainZeroRead {
			store(layout.Local, 4, 0)
			read(layout.Local, 4, 0)
		}
		store(layout.Local, 4, c.Value)
		return program, 0
	case "read-choice":
		store(storageAt(layout.Local, 4), 4, c.Value)
		if c.ReadChoice == storageRetainBothReads {
			store(layout.Local, 4, 0)
			read(storageAt(layout.Local, 4), 4, c.Value)
		}
		store(layout.Local, 4, 0)
		read(storageAt(layout.Local, 4), 4, c.Value)
		if c.ReadChoice == storageDeferLastRead {
			store(layout.Local, 4, 0)
		}
		return program, 0 // Actual zero-argument Keep cut, before either body's effects.
	case "eliminated":
		return program, len(program)
	case "array":
		if c.Combined {
			var word uint64
			for lane, value := range c.Array {
				word |= uint64(value) << uint(8*lane)
			}
			store(layout.Local, 4, word)
		} else {
			for ordinal := range 4 {
				lane := ordinal
				if c.Reverse {
					lane = 3 - ordinal
				}
				store(storageAt(layout.Local, int64(lane)), 1, uint64(c.Array[lane]))
			}
		}
		prefix = len(program) + 1 // The address exists; the dependent load is unexecuted.
		read(storageAt(layout.Local, 2), 1, uint64(c.Array[2]))
	case "padding":
		if c.Combined {
			// Internal padding is deliberately nonzero, not a source zero fact.
			store(layout.Local, 8, c.Value<<32|0xccbbaa00|uint64(c.Head))
		} else {
			store(layout.Local, 1, uint64(c.Head))
			store(storageAt(layout.Local, 4), 4, c.Value)
		}
		store(storageAt(layout.Local, 8), 1, uint64(c.Tail))
		prefix = len(program) + 1
		read(storageAt(layout.Local, 4), 4, c.Value)
	case "alias":
		store(layout.Local, 4, 0x04030201)
		program = append(program, storageByteStep{Kind: "address", At: storageAt(layout.Local, 2)})
		prefix = len(program)
		store(storageAt(layout.Local, 2), 1, 9)
		store(layout.Local, 4, 0x08070605)
		read(storageAt(layout.Local, 2), 1, 7)
		store(storageAt(layout.Local, 2), 1, 11)
		read(storageAt(layout.Local, 2), 1, 11)
	case "write-only":
		program = append(program, storageByteStep{Kind: "address", At: layout.Local})
		prefix = len(program)
		store(layout.Local, c.Width, c.Value)
		read(layout.Local, c.Width, c.Value)
	default:
		value := c.Value
		if c.Kind == "zero" {
			value = 0
		}
		store(layout.Local, c.Width, value)
		prefix = len(program) + 1
		read(layout.Local, c.Width, value)
	}
	return program, prefix
}

func storageOracleLocalID(t testing.TB, c storageOracleTemplate, prefix storageSourceResult) int {
	t.Helper()
	if c.Kind == "zero-arg" {
		return 0
	}
	if c.Kind == "read-choice" || c.Kind == "source-zero" {
		if len(prefix.Operands) != 0 {
			t.Fatal("aggregate entry boundary is not the actual zero-argument Keep call")
		}
		id := 0
		for _, object := range prefix.Objects {
			if _, allocation := object.Site.(*ssa.Alloc); allocation && object.Invocation == 1 {
				if id != 0 {
					t.Fatal("aggregate Keep entry has multiple local objects")
				}
				id = object.ID
			}
		}
		if id == 0 {
			t.Fatal("aggregate Keep entry lost its actual local allocation")
		}
		return id
	}
	if len(prefix.Operands) == 0 {
		t.Fatal("source prefix lacks its expected pointer operand")
	}
	pointer, ok := prefix.Operands[0].(storageSourceLocation)
	if !ok {
		t.Fatal("source pointer lacks its independently executed cell identity")
	}
	return pointer.Object
}

func storageSourceFixture(t testing.TB, c storageOracleTemplate, word int) (computationSource, regionInput, *ssa.Call) {
	t.Helper()
	source := relationFixture(t, c.sourceText(), word)
	root := source.prog.Roots["F"]
	var first *ssa.Call
	for _, block := range root.Blocks {
		for _, instruction := range block.Instrs {
			if call, ok := instruction.(*ssa.Call); ok && (first == nil || call.Pos() < first.Pos()) {
				first = call
			}
		}
	}
	if first == nil {
		t.Fatal("generated source has no actual call")
	}
	in := regionInput{root: root, owner: root.Prog, entry: regionPoint{block: root.Blocks[0]}, use: regionUse{at: regionPoint{first.Block(), slices.Index(first.Block().Instrs, ssa.Instruction(first))}, operand: first.Call.Value}}
	return source, in, first
}

func storageGlobals(c storageOracleTemplate, root *ssa.Function, valuation int) map[*ssa.Global]any {
	globals := map[*ssa.Global]any{}
	for i := range c.Globals {
		globals[root.Pkg.Members[fmt.Sprintf("g%d", i)].(*ssa.Global)] = storagePriorValue(c.Width, i, valuation)
	}
	return globals
}

// Scalar leaves only: padding has no language value. Layout is independently
// calculated with the selected standard-library types.Sizes, not production
// storage-representation offsets. Bytes are explicitly little endian in this
// bounded native model; that choice grants no other target model applicability.
func storageSourceBytes(sizes types.Sizes, typ types.Type, value any) map[int64]byte {
	out := map[int64]byte{}
	var emit func(types.Type, any, int64)
	emit = func(typ types.Type, value any, offset int64) {
		switch u := typ.Underlying().(type) {
		case *types.Array:
			for i, element := range value.([]any) {
				emit(u.Elem(), element, offset+int64(i)*sizes.Sizeof(u.Elem()))
			}
		case *types.Struct:
			fields := make([]*types.Var, u.NumFields())
			for i := range fields {
				fields[i] = u.Field(i)
			}
			offsets := sizes.Offsetsof(fields)
			for i, field := range value.([]any) {
				emit(fields[i].Type(), field, offset+offsets[i])
			}
		case *types.Basic:
			if u.Info()&types.IsInteger == 0 {
				panic("unsupported source byte leaf")
			}
			var bits uint64
			switch v := value.(type) {
			case uint64:
				bits = v
			case int64:
				bits = uint64(v)
			default:
				panic("nonconcrete source byte leaf")
			}
			for lane := int64(0); lane < sizes.Sizeof(typ); lane++ {
				out[offset+lane] = byte(bits >> (8 * lane))
			}
		default:
			panic("unsupported source byte type")
		}
	}
	emit(typ, value, 0)
	return out
}

func checkStorageOracleCase(t testing.TB, c storageOracleTemplate, source computationSource, in regionInput, first *ssa.Call, permutation, valuation int, seed uint64) {
	t.Helper()
	sizes := source.prog.Pkgs[0].TypesSizes
	globals := storageGlobals(c, in.root, valuation)
	prefix, err := executeStorageSource(t, in, storageSourceRun{Globals: globals, Sizes: sizes})
	if err != nil {
		t.Fatal(err)
	}
	whole, err := executeStorageSource(t, in, storageSourceRun{Globals: globals, Sizes: sizes, Whole: true})
	if err != nil {
		t.Fatal(err)
	}
	if prefix.Cut != first || prefix.Returned || len(prefix.Operands) != len(first.Call.Args) || !whole.Returned || whole.Cut != nil || len(whole.Results) != 0 {
		t.Fatal("source reference endpoint/operand scope differs")
	}
	if (c.Kind == "zero-arg" || c.Kind == "read-choice" || c.Kind == "source-zero") && prefix.Operands == nil {
		t.Fatal("zero-argument source call has no captured operand list")
	}
	for _, event := range prefix.Events {
		if event.Kind == "call" || event.Kind == "return" {
			t.Fatal("first source call executed in its operand prefix")
		}
	}
	wantCalls := 1
	if c.Kind == "write-only" || c.Kind == "source-zero" {
		wantCalls = 2
	} else if c.Kind == "alias" {
		wantCalls = 4
	} else if c.Kind == "read-choice" {
		wantCalls = 3
	}
	calls, returns := 0, 0
	for _, event := range whole.Events {
		if event.Instruction == nil || event.Invocation == 0 || event.Invocation > uint64(len(whole.Invocations)) {
			t.Fatal("event lost actual instruction/invocation ownership")
		}
		switch event.Kind {
		case "call":
			calls++
			if c.Kind == "zero-arg" && (event.Operands == nil || len(event.Operands) != 0) {
				t.Fatal("zero-argument call event lost its evaluated empty operands")
			}
			invocation := whole.Invocations[event.Child-1]
			if invocation.Parent != event.Invocation || invocation.Call != event.Instruction || !invocation.Returned || invocation.Target != invocation.Call.Call.StaticCallee() {
				t.Fatal("call lost actual selected body, ancestry or return")
			}
		case "return":
			returns++
		case "read", "write":
			if event.Width != sizes.Sizeof(event.Type) || event.Location.Object < 1 || event.Location.Object > len(whole.Objects) {
				t.Fatal("access lost typed extent/object identity")
			}
			object := whole.Objects[event.Location.Object-1]
			if event.Location.Offset < 0 || event.Location.Offset+event.Width > object.Size {
				t.Fatal("access escaped its concrete object")
			}
		}
	}
	if calls != wantCalls || returns != wantCalls+1 || len(whole.Invocations) != wantCalls+1 || whole.Events[len(whole.Events)-1].Kind != "return" || whole.Events[len(whole.Events)-1].Invocation != 1 {
		t.Fatalf("source event population calls=%d returns=%d; want %d and root return", calls, returns, wantCalls)
	}
	for global, initial := range globals {
		if initial != storageGlobals(c, in.root, valuation)[global] {
			t.Fatal("reference execution mutated caller initial globals")
		}
	}
	layout := storageOraclePlacement(c.Globals, permutation)
	initial := storageInitialBytes(c, layout, valuation, seed)
	program, cut := c.nativeIntent(layout)
	nativePrefix, err := executeStorageBytes(initial, program[:cut])
	if err != nil {
		t.Fatal(err)
	}
	native, err := executeStorageBytes(initial, program)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind == "read-choice" {
		storageOracleCheckReadChoice(t, c, whole, native, layout)
	}
	if c.Kind == "source-zero" {
		storageOracleCheckSourceZero(t, c, whole, native, layout, initial)
	}
	localID := storageOracleLocalID(t, c, prefix)
	for _, object := range prefix.Objects {
		var at storageByteLocation
		if global, ok := object.Site.(*ssa.Global); ok {
			found := false
			for i := range c.Globals {
				if global == in.root.Pkg.Members[fmt.Sprintf("g%d", i)] {
					at, found = layout.Globals[i], true
				}
			}
			if !found {
				t.Fatal("prefix global has no fixture location")
			}
		} else {
			if c.Kind == "zero-arg" || c.Kind == "write-only" || c.Kind == "eliminated" || c.Kind == "read-choice" || c.Kind == "source-zero" || object.ID != localID {
				continue
			}
			at = layout.Local
		}
		for offset, value := range storageSourceBytes(sizes, object.Type, object.Value) {
			if nativePrefix.Memory[storageAt(at, offset)] != value {
				t.Fatal("source/native reference prefix current bytes differ")
			}
		}
	}
	want := map[storageByteLocation]byte{}
	for at, value := range initial {
		want[at] = value
	}
	if localID != 0 {
		if c.Kind == "read-choice" || c.Kind == "source-zero" {
			if len(nativePrefix.Events) != 0 || len(nativePrefix.Addresses) != 0 || !reflect.DeepEqual(nativePrefix.Memory, initial) || !reflect.DeepEqual(prefix.Objects[localID-1].Value, []any{uint64(0), uint64(0)}) {
				t.Fatal("Keep prefix executed body effects or borrowed source zeros for native bytes")
			}
		} else if c.Kind == "eliminated" {
			// A source cut is observable to this interpreter, but no native
			// pointer operand exists. Only a complete-function elimination claim
			// can relate this variant; an operand adapter must not invent one.
			if len(nativePrefix.Addresses) != 0 {
				t.Fatal("eliminated source pointer acquired a native address")
			}
		} else if nativePrefix.Addresses[0] != storageAt(layout.Local, prefix.Operands[0].(storageSourceLocation).Offset) {
			t.Fatal("represented source operand differs from native address intent")
		}
		object := whole.Objects[localID-1]
		var expected any = c.Value
		switch c.Kind {
		case "zero":
			expected = uint64(0)
		case "array":
			expected = []any{uint64(c.Array[0]), uint64(c.Array[1]), uint64(c.Array[2]), uint64(c.Array[3])}
		case "padding":
			expected = []any{uint64(c.Head), c.Value, uint64(c.Tail)}
		case "alias":
			expected = []any{uint64(5), uint64(6), uint64(11), uint64(8)}
		case "read-choice":
			expected = []any{uint64(0), c.Value}
		case "source-zero":
			expected = []any{c.Value, uint64(0)}
		}
		if !reflect.DeepEqual(object.Value, expected) || object.Invocation != 1 || prefix.Objects[localID-1].Site != object.Site {
			t.Fatalf("concrete local identity/current value differs: %+v want %v", object, expected)
		}
		if c.Kind == "write-only" {
			if prefix.Objects[localID-1].Value != uint64(0) {
				t.Fatal("source allocation did not establish typed zero")
			}
			for lane := range c.Width {
				at := storageAt(layout.Local, int64(lane))
				if nativePrefix.Memory[at] == 0 || nativePrefix.Memory[at] != initial[at] {
					t.Fatal("source zero leaked into unmaterialized native scratch")
				}
			}
		}
	}
	for _, object := range whole.Objects {
		var at storageByteLocation
		if global, ok := object.Site.(*ssa.Global); ok {
			index := -1
			for i := range c.Globals {
				if global == in.root.Pkg.Members[fmt.Sprintf("g%d", i)] {
					index = i
				}
			}
			if index < 0 || object.Value != c.Value-uint64(index) {
				t.Fatal("global current value differs from independent construction")
			}
			at = layout.Globals[index]
		} else {
			if object.ID != localID || c.Kind == "eliminated" {
				continue // Retained source temporaries do not invent native storage.
			}
			at = layout.Local
		}
		for offset, value := range storageSourceBytes(sizes, object.Type, object.Value) {
			// The unused Y field has a language zero, not a native value. This
			// complete-function intent accesses only X and retains residual Y.
			if c.Kind == "source-zero" && object.ID == localID && offset >= 4 {
				continue
			}
			want[storageAt(at, offset)] = value
		}
	}
	if c.Kind == "padding" && c.Combined {
		want[storageAt(layout.Local, 1)] = 0xaa
		want[storageAt(layout.Local, 2)] = 0xbb
		want[storageAt(layout.Local, 3)] = 0xcc
	}
	if !reflect.DeepEqual(native.Memory, want) || len(native.Memory) != 400 {
		t.Fatal("native byte reference differs from concrete source leaves, explicit padding, or untouched sentinel domain")
	}
	if !reflect.DeepEqual(initial, storageInitialBytes(c, layout, valuation, seed)) {
		t.Fatal("byte reference mutated initial storage")
	}
	if c.Kind == "eliminated" && (len(native.Events) != 0 || !reflect.DeepEqual(native.Memory, initial)) {
		t.Fatal("isolated eliminated local acquired native effects/storage")
	}
	// Result containers are caller-owned. A mutation cannot rewrite another run,
	// its earlier events, or the initial domain used by a future adapter.
	priorByte := nativePrefix.Memory[layout.Local]
	native.Memory[layout.Local] ^= 0xff
	if nativePrefix.Memory[layout.Local] != priorByte {
		t.Fatal("native result aliases another endpoint")
	}
}

func TestStorageOraclePopulation(t *testing.T) {
	templates := storageOracleTemplates(0)
	if len(templates) != 22 {
		t.Fatal("bounded reference template population changed")
	}
	count := 0
	for _, c := range templates {
		t.Run(c.Name, func(t *testing.T) {
			source, in, first := storageSourceFixture(t, c, 64)
			for permutation := range 2 {
				for valuation := range 3 {
					checkStorageOracleCase(t, c, source, in, first, permutation, valuation, 0)
					count++
				}
			}
		})
	}
	if count != 132 {
		t.Fatalf("reference configurations=%d, want 132", count)
	}
	t.Log("132 finite reference configurations; each executes source prefix and whole return plus independent byte intent; no production correspondence judgment")
}

func FuzzStorageOraclePopulation(f *testing.F) {
	for index := range 22 {
		f.Add(uint8(index), uint8(index%2), uint8(index%3), uint64(index)*0x102030405060708)
	}
	for _, tc := range storageOracleValueCases() {
		f.Add(uint8(tc.template), uint8(0), uint8(2), tc.seed)
	}
	for i := range storageOracleReadChoiceTemplates(0) {
		f.Add(uint8(22+i), uint8(0), uint8(2), uint64(0))
	}
	for i := range storageOracleSourceZeroTemplates(0) {
		f.Add(uint8(25+i), uint8(0), uint8(2), uint64(0))
	}
	f.Fuzz(func(t *testing.T, index, permutation, valuation uint8, seed uint64) {
		templates := storageOracleFuzzTemplates(seed)
		c := templates[int(index)%len(templates)]
		source, in, first := storageSourceFixture(t, c, 64)
		checkStorageOracleCase(t, c, source, in, first, int(permutation%2), int(valuation%3), seed)
	})
}

func storageOracleCheckReadChoice(t testing.TB, c storageOracleTemplate, source storageSourceResult, native storageByteResult, layout storageOracleLayout) {
	t.Helper()
	var events []storageSourceEvent
	for _, event := range source.Events {
		if event.Kind == "read" || event.Kind == "write" {
			events = append(events, event)
		}
	}
	if len(events) != 4 || len(source.Objects) != 1 || len(source.Invocations) != 4 {
		t.Fatal("read-choice source no longer has one object and two actual read calls after Keep")
	}
	for i, want := range []struct {
		kind       string
		offset     int64
		value      uint64
		invocation uint64
	}{{"write", 4, c.Value, 1}, {"read", 4, c.Value, 3}, {"write", 0, 0, 1}, {"read", 4, c.Value, 4}} {
		got := events[i]
		if got.Kind != want.kind || got.Location.Object != source.Objects[0].ID || got.Location.Offset != want.offset || got.Value != want.value || got.Width != 4 || got.Invocation != want.invocation {
			t.Fatalf("read-choice source effect %d differs: %+v", i, got)
		}
	}
	if events[1].Instruction != events[3].Instruction || source.Invocations[2].Call == source.Invocations[3].Call || source.Invocations[2].Target != source.Invocations[3].Target {
		t.Fatal("read-choice reads lost their repeated instruction/distinct actual calls")
	}
	y := storageAt(layout.Local, 4)
	want := []storageByteEvent{{0, true, y, 4, c.Value}, {1, true, layout.Local, 4, 0}, {3, false, y, 4, c.Value}}
	if c.ReadChoice == storageRetainBothReads {
		want = []storageByteEvent{{0, true, y, 4, c.Value}, {1, true, layout.Local, 4, 0}, {3, false, y, 4, c.Value}, {5, true, layout.Local, 4, 0}, {7, false, y, 4, c.Value}}
	} else if c.ReadChoice == storageDeferLastRead {
		want = append(want, storageByteEvent{5, true, layout.Local, 4, 0})
	}
	if !reflect.DeepEqual(native.Events, want) {
		t.Fatalf("read-choice native effects differ from independently specified retained/deleted-read intent: got %+v want %+v", native.Events, want)
	}
}

func TestStorageOracleReadChoiceSupplements(t *testing.T) {
	count := 0
	cases := storageOracleReadChoiceTemplates(0)
	if len(cases) != 3 {
		t.Fatal("read-choice grammar must retain all three valid native variants")
	}
	placement := storageOraclePlacement(0, 0)
	first, _ := cases[0].nativeIntent(placement)
	last, _ := cases[2].nativeIntent(placement)
	if cases[0].sourceText() != cases[1].sourceText() || cases[0].sourceText() != cases[2].sourceText() || !reflect.DeepEqual(last, append(slices.Clone(first), storageByteStep{Kind: "store", At: placement.Local, Width: 4, Value: 0})) {
		t.Fatal("one appended zero write no longer supplies the same source's valid last-read-eliminated alternative")
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			source, in, first := storageSourceFixture(t, c, 64)
			for permutation := range 2 {
				for valuation := range 3 {
					checkStorageOracleCase(t, c, source, in, first, permutation, valuation, 0)
					count++
				}
			}
		})
	}
	if count != 18 {
		t.Fatalf("read-choice reference configurations=%d want 18", count)
	}
	t.Log("18 read-choice supplemental configurations; base 132 and zero/mixed 18 remain separately counted")
}

func storageOracleCheckSourceZero(t testing.TB, c storageOracleTemplate, source storageSourceResult, native storageByteResult, layout storageOracleLayout, initial map[storageByteLocation]byte) {
	t.Helper()
	var accesses []storageSourceEvent
	for _, event := range source.Events {
		if event.Kind == "read" || event.Kind == "write" {
			accesses = append(accesses, event)
		}
	}
	if len(source.Objects) != 1 || source.Objects[0].Size != 8 || len(source.Invocations) != 3 || len(accesses) != 2 {
		t.Fatal("source-zero grammar lost its one two-field allocation and actual Keep/Read calls")
	}
	for i, want := range []struct {
		kind       string
		value      uint64
		invocation uint64
	}{{"read", 0, 3}, {"write", c.Value, 1}} {
		got := accesses[i]
		if got.Kind != want.kind || got.Value != want.value || got.Invocation != want.invocation || got.Location.Object != source.Objects[0].ID || got.Location.Offset != 0 || !slices.Equal(got.Location.Path, []int{0}) || got.Width != 4 {
			t.Fatalf("source-zero effect %d differs from actual X-only source semantics: %+v", i, got)
		}
	}
	want := []storageByteEvent{{0, true, layout.Local, 4, c.Value}}
	if c.RetainZeroRead {
		want = []storageByteEvent{{0, true, layout.Local, 4, 0}, {2, false, layout.Local, 4, 0}, {4, true, layout.Local, 4, c.Value}}
	}
	if !reflect.DeepEqual(native.Events, want) {
		t.Fatalf("source-zero native effects differ from independent retained/eliminated-read intent: got %+v want %+v", native.Events, want)
	}
	for lane := int64(4); lane < 8; lane++ {
		at := storageAt(layout.Local, lane)
		if initial[at] == 0 || native.Memory[at] != initial[at] {
			t.Fatal("unused Y bytes acquired their source language zero without a native write")
		}
	}
}

func TestStorageOracleSourceZeroSupplements(t *testing.T) {
	count := 0
	for _, c := range storageOracleSourceZeroTemplates(0) {
		t.Run(c.Name, func(t *testing.T) {
			source, in, first := storageSourceFixture(t, c, 64)
			for permutation := range 2 {
				for valuation := range 3 {
					checkStorageOracleCase(t, c, source, in, first, permutation, valuation, 0)
					count++
				}
			}
		})
	}
	if count != 12 {
		t.Fatalf("source-zero reference configurations=%d want 12", count)
	}
	t.Log("12 source-zero configurations; 132 base, 18 zero/mixed, and 18 read-choice remain separate")
}

func TestStorageOracleZeroValueSupplements(t *testing.T) {
	count := 0
	for _, tc := range storageOracleValueCases() {
		t.Run(tc.name, func(t *testing.T) {
			c := storageOracleTemplates(tc.seed)[tc.template]
			switch tc.name {
			case "combined-array-all-zero":
				if c.Kind != "array" || !c.Combined || c.Array != ([4]byte{}) {
					t.Fatal("all-zero array supplement lost its typed zero lanes")
				}
			case "reversed-array-mixed-zero":
				if c.Kind != "array" || !c.Reverse || c.Combined || c.Array != ([4]byte{17, 0, 51, 0}) {
					t.Fatal("mixed-zero supplement lost its reversed zero-first native write")
				}
			case "combined-padding-typed-zero":
				if c.Kind != "padding" || !c.Combined || c.Head != 0 || c.Value != 0 || c.Tail != 0 {
					t.Fatal("padded supplement lost its all-zero typed leaves")
				}
			}
			source, in, first := storageSourceFixture(t, c, 64)
			for permutation := range 2 {
				for valuation := range 3 {
					checkStorageOracleCase(t, c, source, in, first, permutation, valuation, tc.seed)
					count++
				}
			}
		})
	}
	if count != 18 {
		t.Fatalf("zero/mixed reference configurations=%d want 18", count)
	}
	t.Log("18 supplemental configurations across three shared zero/mixed value cases; base population remains 132")
}

func TestStorageOracleExplicitGlobalsAndSnapshots(t *testing.T) {
	legacy := regionFixture(t, "var g uint64;func F()uint64{return g}")
	if got := executeRegionConcrete(t, legacy); got != int64(0) {
		t.Fatalf("legacy absent-global zero behavior changed: %v", got)
	}
	c := storageOracleTemplates(0)[3] // One uint8 global and a materialized local.
	source, in, first := storageSourceFixture(t, c, 64)
	sizes := source.prog.Pkgs[0].TypesSizes
	for _, globals := range []map[*ssa.Global]any{nil, {in.root.Pkg.Members["g0"].(*ssa.Global): struct{}{}}} {
		if result, err := executeStorageSource(t, in, storageSourceRun{Globals: globals, Sizes: sizes, Whole: true}); err == nil || result.Returned || len(result.Events) != 0 {
			t.Fatal("missing/unknown explicit global produced a partial answer")
		}
	}
	prefix, err := executeStorageSource(t, in, storageSourceRun{Globals: storageGlobals(c, in.root, 2), Sizes: sizes})
	if err != nil {
		t.Fatal(err)
	}
	whole, err := executeStorageSource(t, in, storageSourceRun{Globals: storageGlobals(c, in.root, 2), Sizes: sizes, Whole: true})
	if err != nil {
		t.Fatal(err)
	}
	loc := prefix.Operands[0].(storageSourceLocation)
	if whole.Objects[loc.Object-1].Value != c.Value || prefix.Cut != first {
		t.Fatal("source snapshot lost its concrete operand")
	}
	prefix.Objects[loc.Object-1].Value = uint64(0)
	for _, event := range whole.Events {
		if event.Kind == "allocate" && event.Value != uint64(0) {
			t.Fatal("later writes mutated the allocation's zero snapshot")
		}
	}
	if whole.Objects[loc.Object-1].Value != c.Value {
		t.Fatal("one returned snapshot aliases another execution")
	}
	for i := range whole.Events {
		if whole.Events[i].Kind == "write" && whole.Events[i].Location.Object == loc.Object {
			whole.Events[i].Value = uint64(0)
		}
	}
	if whole.Objects[loc.Object-1].Value != c.Value {
		t.Fatal("event value snapshot aliases final object storage")
	}
}

func TestStorageOracleInitialAggregateOwnership(t *testing.T) {
	source := relationFixture(t, `var g [4]uint8;func Read(p *uint8)uint8{return *p};func F(){g[0]=9;if Read(&g[1])!=2{panic(1)}}`, 64)
	root := source.prog.Roots["F"]
	global := root.Pkg.Members["g"].(*ssa.Global)
	input := []any{uint64(1), uint64(2), uint64(3), uint64(4)}
	result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, storageSourceRun{Globals: map[*ssa.Global]any{global: input}, Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true})
	if err != nil {
		t.Fatal(err)
	}
	if input[0] != uint64(1) || len(result.Objects) != 1 || !reflect.DeepEqual(result.Objects[0].Value, []any{uint64(9), uint64(2), uint64(3), uint64(4)}) {
		t.Fatal("concrete execution borrowed caller aggregate cells or lost current values")
	}
	input[1] = uint64(99)
	if result.Objects[0].Value.([]any)[1] != uint64(2) {
		t.Fatal("retained object snapshot borrows caller initial aggregate")
	}
	for _, event := range result.Events {
		if event.Kind == "read" && (event.Value != uint64(2) || event.Location.Offset != 1 || !slices.Equal(event.Location.Path, []int{1})) {
			t.Fatal("aggregate read lost its actual cell snapshot")
		}
	}
}

func TestStorageOracleAllocationAndAliasOwnership(t *testing.T) {
	source := relationFixture(t, `func Make(v uint64)*uint64{x:=v;return &x};func F(){a:=Make(7);b:=Make(9);*a=11;if *b!=9{panic(1)}}`, 64)
	root := source.prog.Roots["F"]
	in := regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}
	result, err := executeStorageSource(t, in, storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Objects) != 2 || result.Objects[0].Site != result.Objects[1].Site || result.Objects[0].ID == result.Objects[1].ID || result.Objects[0].Invocation == result.Objects[1].Invocation || result.Objects[0].Value != uint64(11) || result.Objects[1].Value != uint64(9) {
		t.Fatalf("same allocation site did not retain independent invocation cells: %+v", result.Objects)
	}
	// A returned allocation is not discarded when its allocating frame returns.
	for _, object := range result.Objects {
		if !result.Invocations[object.Invocation-1].Returned {
			t.Fatal("allocation did not survive its actual completed invocation")
		}
	}
	c := storageOracleTemplates(0)[21]
	source, in, _ = storageSourceFixture(t, c, 64)
	result, err = executeStorageSource(t, in, storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true})
	if err != nil {
		t.Fatal(err)
	}
	var reads []storageSourceEvent
	aggregateReads := 0
	for _, event := range result.Events {
		if event.Kind == "read" {
			if event.Invocation == 1 {
				if event.Width != 4 || !reflect.DeepEqual(event.Value, []any{uint64(1 + 4*aggregateReads), uint64(2 + 4*aggregateReads), uint64(3 + 4*aggregateReads), uint64(4 + 4*aggregateReads)}) {
					t.Fatal("aggregate assignment lost its read-before-write snapshot")
				}
				aggregateReads++
				continue
			}
			reads = append(reads, event)
		}
	}
	if aggregateReads != 2 || len(reads) != 2 || reads[0].Value != uint64(7) || reads[1].Value != uint64(11) || reads[0].Location.Object != reads[1].Location.Object || reads[0].Location.Offset != 2 || reads[1].Location.Offset != 2 || reads[0].Invocation == reads[1].Invocation {
		t.Fatalf("aggregate overwrite/alias or helper invocation changed: %+v", reads)
	}
	// Mutation of one event path cannot rewrite its neighbor's owned path.
	reads[0].Location.Path[0] = 0
	if reads[1].Location.Path[0] != 2 {
		t.Fatal("event paths alias mutable containers")
	}
}

// Instruction coordinates come from the actual source, not from recorded oracle
// events. Each anchor below fixes its expected dynamic order independently.
func storageOracleInstructions[T ssa.Instruction](function *ssa.Function) []T {
	var instructions []T
	for _, block := range function.Blocks {
		for _, instruction := range block.Instrs {
			if typed, ok := instruction.(T); ok {
				instructions = append(instructions, typed)
			}
		}
	}
	return instructions
}

func TestStorageOracleNestedEventOrder(t *testing.T) {
	source := relationFixture(t, `var g uint64
func Leaf(p *uint64,v uint64)uint64{*p=v;return *p}
func Middle(p *uint64)uint64{a:=Leaf(p,7);b:=Leaf(p,9);if a!=7{panic(1)};return b}
func F(){g=1;if Middle(&g)!=9{panic(2)};g=11}`, 64)
	root := source.prog.Roots["F"]
	middle, leaf := root.Pkg.Func("Middle"), root.Pkg.Func("Leaf")
	global := root.Pkg.Members["g"].(*ssa.Global)
	rootCalls, middleCalls := storageOracleInstructions[*ssa.Call](root), storageOracleInstructions[*ssa.Call](middle)
	rootStores, leafStores := storageOracleInstructions[*ssa.Store](root), storageOracleInstructions[*ssa.Store](leaf)
	leafReads := storageOracleInstructions[*ssa.UnOp](leaf)
	rootReturns, middleReturns, leafReturns := storageOracleInstructions[*ssa.Return](root), storageOracleInstructions[*ssa.Return](middle), storageOracleInstructions[*ssa.Return](leaf)
	if len(rootCalls) != 1 || len(middleCalls) != 2 || len(rootStores) != 2 || len(leafStores) != 1 || len(leafReads) != 1 || len(rootReturns) != 1 || len(middleReturns) != 1 || len(leafReturns) != 1 {
		t.Fatal("nested source no longer has the anchor's exact static operations")
	}
	loc := storageSourceLocation{Object: 1}
	word := types.Typ[types.Uint64]
	// Two executions of the very same leaf instructions have different actual
	// invoking calls. The sequence includes each parent/child return, not merely
	// a kind-filtered access inventory or a count derived from observed events.
	want := []storageSourceEvent{
		{Kind: "write", Instruction: rootStores[0], Invocation: 1, Location: loc, Type: word, Width: 8, Value: uint64(1)},
		{Kind: "call", Instruction: rootCalls[0], Invocation: 1, Child: 2, Operands: []any{loc}},
		{Kind: "call", Instruction: middleCalls[0], Invocation: 2, Child: 3, Operands: []any{loc, uint64(7)}},
		{Kind: "write", Instruction: leafStores[0], Invocation: 3, Location: loc, Type: word, Width: 8, Value: uint64(7)},
		{Kind: "read", Instruction: leafReads[0], Invocation: 3, Location: loc, Type: word, Width: 8, Value: uint64(7)},
		{Kind: "return", Instruction: leafReturns[0], Invocation: 3, Operands: []any{uint64(7)}},
		{Kind: "call", Instruction: middleCalls[1], Invocation: 2, Child: 4, Operands: []any{loc, uint64(9)}},
		{Kind: "write", Instruction: leafStores[0], Invocation: 4, Location: loc, Type: word, Width: 8, Value: uint64(9)},
		{Kind: "read", Instruction: leafReads[0], Invocation: 4, Location: loc, Type: word, Width: 8, Value: uint64(9)},
		{Kind: "return", Instruction: leafReturns[0], Invocation: 4, Operands: []any{uint64(9)}},
		{Kind: "return", Instruction: middleReturns[0], Invocation: 2, Operands: []any{uint64(9)}},
		{Kind: "write", Instruction: rootStores[1], Invocation: 1, Location: loc, Type: word, Width: 8, Value: uint64(11)},
		{Kind: "return", Instruction: rootReturns[0], Invocation: 1, Operands: []any{}},
	}
	wantInvocations := []storageSourceInvocation{
		{ID: 1, Target: root, Returned: true},
		{ID: 2, Parent: 1, Call: rootCalls[0], Target: middle, Returned: true},
		{ID: 3, Parent: 2, Call: middleCalls[0], Target: leaf, Returned: true},
		{ID: 4, Parent: 2, Call: middleCalls[1], Target: leaf, Returned: true},
	}
	result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, storageSourceRun{Globals: map[*ssa.Global]any{global: uint64(0xa5)}, Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Events, want) || !reflect.DeepEqual(result.Invocations, wantInvocations) || len(result.Objects) != 1 || result.Objects[0].Value != uint64(11) {
		t.Fatalf("nested event order/actual invocation association differs:\ngot %+v\nwant %+v\ninvocations %+v", result.Events, want, result.Invocations)
	}
}

func TestStorageOracleAggregateProjectionIsolation(t *testing.T) {
	source := relationFixture(t, `type S struct{A [2]uint64};var g S
func Copy(p *S)S{return *p}
func F(){g.A[0]=7;v:=Copy(&g);g=v;g.A[1]=9}`, 64)
	root := source.prog.Roots["F"]
	global := root.Pkg.Members["g"].(*ssa.Global)
	initial := []any{[]any{uint64(1), uint64(2)}}
	result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, storageSourceRun{Globals: map[*ssa.Global]any{global: initial}, Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Objects) != 1 || !reflect.DeepEqual(result.Objects[0].Value, []any{[]any{uint64(7), uint64(9)}}) {
		t.Fatal("aggregate final projection differs from executed assignments")
	}
	// Three independently owned historical aggregates: Copy's read, its return,
	// and the caller's whole-object store. Final projection edits cannot reach any.
	var read, returned, stored *storageSourceEvent
	for i := range result.Events {
		event := &result.Events[i]
		switch {
		case event.Kind == "read" && event.Instruction.Parent() == root.Pkg.Func("Copy"):
			read = event
		case event.Kind == "return" && event.Instruction.Parent() == root.Pkg.Func("Copy"):
			returned = event
		case event.Kind == "write" && event.Type == global.Type().Underlying().(*types.Pointer).Elem():
			stored = event
		}
	}
	if read == nil || returned == nil || stored == nil || len(returned.Operands) != 1 {
		t.Fatal("actual aggregate read/return/store snapshots are absent")
	}
	result.Objects[0].Value.([]any)[0].([]any)[0] = uint64(99)
	history := []any{[]any{uint64(7), uint64(2)}}
	if !reflect.DeepEqual(read.Value, history) || !reflect.DeepEqual(returned.Operands[0], history) || !reflect.DeepEqual(stored.Value, history) || !reflect.DeepEqual(initial, []any{[]any{uint64(1), uint64(2)}}) {
		t.Fatal("final aggregate projection rewrote historical snapshots or caller cells")
	}
	read.Value.([]any)[0].([]any)[1] = uint64(88)
	if !reflect.DeepEqual(returned.Operands[0], history) || !reflect.DeepEqual(stored.Value, history) {
		t.Fatal("historical aggregate snapshots share nested mutable cells")
	}
	// Exercise the same snapshot operation against a still-live interpreter cell,
	// with a preexisting element alias. Unlike the public result, this local cell
	// remains directly inspectable after projecting it.
	var cell any = []any{[]any{uint64(7), uint64(9)}}
	alias := regionConcretePointer{cell: &cell.([]any)[0].([]any)[1]}
	run := &regionConcreteExecution{}
	projection := run.snapshot(cell).([]any)
	projection[0].([]any)[1] = uint64(77)
	if *alias.cell != uint64(9) || !reflect.DeepEqual(cell, []any{[]any{uint64(7), uint64(9)}}) {
		t.Fatal("aggregate snapshot borrowed original live cells")
	}
	regionConcreteStore(alias.cell, uint64(11))
	if projection[0].([]any)[1] != uint64(77) {
		t.Fatal("later original-cell write changed its detached projection")
	}
}

func TestStorageOracleNamedPointerAlias(t *testing.T) {
	source := relationFixture(t, `type Pointer *uint64
func Write(p Pointer){*p=9}
func Read(p *uint64)uint64{return *p}
func F(){var x uint64;p:=Pointer(&x);Write(p);if Read((*uint64)(p))!=9{panic(1)}}`, 64)
	root := source.prog.Roots["F"]
	changes := storageOracleInstructions[*ssa.ChangeType](root)
	if len(changes) != 2 {
		t.Fatalf("fixture must execute both named-pointer ChangeType operations, got %d", len(changes))
	}
	for _, change := range changes {
		if _, from := change.X.Type().Underlying().(*types.Pointer); !from {
			t.Fatal("ChangeType source is not a pointer")
		}
		if _, to := change.Type().Underlying().(*types.Pointer); !to {
			t.Fatal("ChangeType destination is not a pointer")
		}
	}
	result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Objects) != 1 || result.Objects[0].Value != uint64(9) {
		t.Fatal("named pointer manufactured or detached a concrete object")
	}
	loc := storageSourceLocation{Object: 1}
	var calls, reads, writes int
	for _, event := range result.Events {
		switch event.Kind {
		case "call":
			calls++
			if !reflect.DeepEqual(event.Operands, []any{loc}) {
				t.Fatal("named/unnamed pointer call lost the same actual cell")
			}
		case "read", "write":
			if !reflect.DeepEqual(event.Location, loc) || event.Value != uint64(9) || event.Width != 8 {
				t.Fatal("named-pointer access changed location, width or current value")
			}
			if event.Kind == "read" {
				reads++
			} else {
				writes++
			}
		}
	}
	if calls != 2 || reads != 1 || writes != 1 {
		t.Fatal("named-pointer source did not execute both alias uses")
	}
}

func TestStorageOracleRepeatedLoopAllocation(t *testing.T) {
	// Exactly two visits, controlled by Boolean phis; no arithmetic transfer or
	// general termination inference is added. The earlier helper-allocation anchor
	// covers distinct invocations; this one repeats a site in the SAME invocation.
	source := relationFixture(t, `func F(){var first *uint64;again,next:=true,true
for again {p:=new(uint64);if first==nil{first=p;*p=7}else{*p=9};again=next;next=false}
if *first!=7{panic(1)}}`, 64)
	root := source.prog.Roots["F"]
	allocations := storageOracleInstructions[*ssa.Alloc](root)
	phis := storageOracleInstructions[*ssa.Phi](root)
	if len(allocations) != 1 || len(phis) == 0 {
		t.Fatal("fixture does not contain one allocation site under actual SSA phis")
	}
	result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Returned || len(result.Invocations) != 1 || len(result.Objects) != 2 {
		t.Fatal("Boolean loop did not execute two allocations in one invocation")
	}
	for i, object := range result.Objects {
		if object.ID != i+1 || object.Site != allocations[0] || object.Invocation != 1 || object.Value != uint64(7+2*i) {
			t.Fatalf("repeated site lost fresh identity/current contents: %+v", result.Objects)
		}
	}
	// The complete observable reference event sequence is fixed by this source;
	// neither object-site keys nor invocation-only keys can collapse its visits.
	wantKinds := []string{"allocate", "write", "allocate", "write", "read", "return"}
	wantObjects := []int{1, 1, 2, 2, 1, 0}
	wantValues := []any{uint64(0), uint64(7), uint64(0), uint64(9), uint64(7), nil}
	if len(result.Events) != len(wantKinds) {
		t.Fatalf("loop event population=%+v", result.Events)
	}
	for i, event := range result.Events {
		if event.Kind != wantKinds[i] || event.Invocation != 1 || event.Location.Object != wantObjects[i] || event.Value != wantValues[i] {
			t.Fatalf("loop event %d=%+v differs from two-visit execution", i, event)
		}
		if event.Kind == "allocate" && event.Instruction != allocations[0] {
			t.Fatal("dynamic allocation did not retain its actual repeated instruction")
		}
	}
}

func TestStorageOracleUnsignedSignedAndSelectedLayout(t *testing.T) {
	for _, word := range []int{32, 64} {
		wantWord := ^uint64(0)
		if word == 32 {
			wantWord = 0xffffffff
		}
		source := relationFixture(t, fmt.Sprintf(`func Read(p *uint64)uint64{return *p};func F(){var u uint64=18446744073709551615;x:=Read(&u);if x<=9223372036854775808{panic(1)};s:=int8(x);if s>=0{panic(2)};n:=uint8(x);if n!=255{panic(3)};w:=uint(x);if uint64(w)!=%d{panic(4)}}`, wantWord), word)
		root := source.prog.Roots["F"]
		result, err := executeStorageSource(t, regionInput{root: root, entry: regionPoint{block: root.Blocks[0]}}, storageSourceRun{Sizes: source.prog.Pkgs[0].TypesSizes, Whole: true})
		if err != nil || !result.Returned || result.Objects[0].Value != ^uint64(0) {
			t.Fatalf("selected %d-bit signed/unsigned reference: %v", word, err)
		}
		sizes := source.prog.Pkgs[0].TypesSizes
		fields := []*types.Var{types.NewField(0, nil, "B", types.Typ[types.Uint8], false), types.NewField(0, nil, "W", types.Typ[types.Uint], false)}
		typ := types.NewStruct(fields, nil)
		bytes := storageSourceBytes(sizes, typ, []any{uint64(17), uint64(0x12345678)})
		if sizes.Sizeof(typ) != int64(word/4) || len(bytes) != 1+word/8 || bytes[int64(word/8)] != 0x78 {
			t.Fatal("selected word layout followed verifier host or invented padding values")
		}
		if _, padding := bytes[1]; padding {
			t.Fatal("source leaves supplied a padding value")
		}
	}
}

func TestStorageByteOracleAnchorsAndCounterexamples(t *testing.T) {
	at := storageByteLocation{Offset: -8}
	initial := map[storageByteLocation]byte{}
	for i := range 12 {
		initial[storageAt(at, int64(i))] = byte(0x80 + i)
	}
	program := []storageByteStep{
		{Kind: "address", At: at, Register: 3},
		{Kind: "load", Width: 4, Register: 3, Indirect: true},
		{Kind: "store", At: storageAt(at, 4), Width: 4, Register: 3, FromLoaded: true},
		{Kind: "store", At: at, Width: 1, Value: 0xff},
		{Kind: "load", At: at, Width: 4, Register: 4},
		{Kind: "guard", Register: 4, Value: 0x838281ff},
	}
	result, err := executeStorageBytes(initial, program)
	if err != nil {
		t.Fatal(err)
	}
	wantEvents := []storageByteEvent{{1, false, at, 4, 0x83828180}, {2, true, storageAt(at, 4), 4, 0x83828180}, {3, true, at, 1, 0xff}, {4, false, at, 4, 0x838281ff}}
	if !reflect.DeepEqual(result.Events, wantEvents) || result.Memory[storageAt(at, 4)] != 0x80 || result.Memory[storageAt(at, 7)] != 0x83 || result.Memory[storageAt(at, 8)] != 0x88 || len(result.Memory) != len(initial) || initial[at] != 0x80 {
		t.Fatal("byte endian/order/extent/current-value/input ownership anchor failed")
	}
	for _, negative := range [][]storageByteStep{
		{{Kind: "load", At: storageAt(at, 8), Width: 8}},
		{{Kind: "load", At: at, Width: 4}, {Kind: "guard", Value: 0}},
		{{Kind: "store", At: at, Width: 1, Value: 1}, {Kind: "load", At: at, Width: 4}, {Kind: "guard", Value: 1}},
		{{Kind: "load", Width: 1, Indirect: true}},
		{{Kind: "store", At: at, Width: 4, FromLoaded: true}},
		{{Kind: "load", At: storageByteLocation{Offset: int64(^uint64(0) >> 1)}, Width: 4}},
	} {
		if result, err := executeStorageBytes(initial, negative); err == nil || result.Memory != nil || len(result.Events) != 0 {
			t.Fatal("invalid/reference counterexample returned a partial positive answer")
		}
	}
	// An early read is a real event even when a later overwrite makes final bytes
	// equal. A future correspondence adapter must account for that difference.
	write := storageByteStep{Kind: "store", At: at, Width: 4, Value: 7}
	plain, err := executeStorageBytes(initial, []storageByteStep{write})
	if err != nil {
		t.Fatal(err)
	}
	early, err := executeStorageBytes(initial, []storageByteStep{{Kind: "load", At: at, Width: 4}, write})
	if err != nil || !reflect.DeepEqual(early.Memory, plain.Memory) || len(early.Events) != 2 || early.Events[0].Value != 0x83828180 {
		t.Fatal("early read was hidden by endpoint equality")
	}
}
