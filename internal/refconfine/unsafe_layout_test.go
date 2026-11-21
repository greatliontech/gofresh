package refconfine

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"pgregory.net/rapid"
)

type inMemPkgSpec struct {
	pkgPath string
	files   map[string]string
}

func mustTypecheckInMemDAG(t testing.TB, arch string, specs []inMemPkgSpec) (map[string]*packages.Package, map[*types.Package]*packages.Package) {
	t.Helper()
	sizes := types.SizesFor("gc", arch)
	if sizes == nil {
		t.Fatalf("nil SizesFor(%q)", arch)
	}
	stdImp := importer.Default()
	byPath := make(map[string]*packages.Package, len(specs))
	byTypes := make(map[*types.Package]*packages.Package, len(specs))

	imp := importerFunc(func(path string) (*types.Package, error) {
		if path == "unsafe" {
			return types.Unsafe, nil
		}
		if p, ok := byPath[path]; ok && p.Types != nil {
			return p.Types, nil
		}
		return stdImp.Import(path)
	})

	for _, sp := range specs {
		fset := token.NewFileSet()
		var syntax []*ast.File
		var pkgName string
		for name, src := range sp.files {
			f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
			if err != nil {
				t.Fatalf("ParseFile(%s/%s): %v\n%s", sp.pkgPath, name, err, src)
			}
			pkgName = f.Name.Name
			syntax = append(syntax, f)
		}
		info := &types.Info{
			Types:      make(map[ast.Expr]types.TypeAndValue),
			Instances:  make(map[*ast.Ident]types.Instance),
			Defs:       make(map[*ast.Ident]types.Object),
			Uses:       make(map[*ast.Ident]types.Object),
			Implicits:  make(map[ast.Node]types.Object),
			Selections: make(map[*ast.SelectorExpr]*types.Selection),
			Scopes:     make(map[ast.Node]*types.Scope),
		}
		tp, err := (&types.Config{
			Importer: imp,
			Sizes:    sizes,
		}).Check(sp.pkgPath, fset, syntax, info)
		if err != nil {
			t.Fatalf("Check(%s): %v", sp.pkgPath, err)
		}
		p := &packages.Package{
			ID:        sp.pkgPath,
			Name:      pkgName,
			PkgPath:   sp.pkgPath,
			Fset:      fset,
			Syntax:    syntax,
			Types:     tp,
			TypesInfo: info,
			TypesSizes: sizes,
		}
		byPath[sp.pkgPath] = p
		byTypes[tp] = p
	}
	return byPath, byTypes
}

type oracleByteRole uint8

const (
	rolePadding oracleByteRole = iota
	roleBasic
	roleStrPtr
	roleStrLen
	rolePointer
	roleSlicePtr
	roleSliceLen
	roleSliceCap
	roleOpaqueRef // map, chan, signature, interface
)

type oracleByteSlot struct {
	role      oracleByteRole
	basicKind types.BasicKind
	slotStart int64
	elemType  types.Type // for rolePointer / roleSlicePtr, or underlying for roleOpaqueRef
}

func oracleContainsUnsafeOrInvalid(root types.Type) bool {
	if typeMentionsOpenTypeParam(root) {
		return true
	}
	type key struct {
		t     types.Type
		indir bool
	}
	seen := map[key]bool{}
	bad := false
	var walk func(types.Type, bool)
	walk = func(t types.Type, indir bool) {
		if t == nil {
			bad = true
			return
		}
		if bad {
			return
		}
		t = types.Unalias(t)
		k := key{t: t, indir: indir}
		if seen[k] {
			return
		}
		seen[k] = true
		if _, isTP := t.(*types.TypeParam); isTP {
			bad = true
			return
		}
		if _, isTup := t.(*types.Tuple); isTup {
			bad = true
			return
		}
		_, isNamed := t.(*types.Named)
		switch u := t.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.Invalid || u.Kind() == types.UnsafePointer || u.Info()&types.IsUntyped != 0 {
				bad = true
			}
		case *types.Pointer:
			walk(u.Elem(), true)
		case *types.Slice:
			walk(u.Elem(), true)
		case *types.Chan:
			walk(u.Elem(), true)
		case *types.Map:
			walk(u.Key(), true)
			walk(u.Elem(), true)
		case *types.Signature:
			for _, tup := range []*types.Tuple{u.Params(), u.Results()} {
				for i := 0; tup != nil && i < tup.Len(); i++ {
					walk(tup.At(i).Type(), true)
				}
			}
		case *types.Interface:
			for i := 0; i < u.NumMethods(); i++ {
				walk(u.Method(i).Type(), true)
			}
		case *types.Array:
			walk(u.Elem(), indir)
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				f := u.Field(i)
				if indir && isNamed && !f.Exported() {
					continue
				}
				walk(f.Type(), indir)
			}
		default:
			bad = true
		}
	}
	walk(root, false)
	return bad
}

// buildByteMemoryMap constructs an independent byte-by-byte memory representation
// of value type t across [0..sizes.Sizeof(t)) using go/types.Sizes.
func buildByteMemoryMap(sizes types.Sizes, t types.Type) ([]oracleByteSlot, bool) {
	if t == nil || oracleContainsUnsafeOrInvalid(t) {
		return nil, false
	}
	t = types.Unalias(t)
	if _, isTP := t.(*types.TypeParam); isTP {
		return nil, false
	}
	total := sizes.Sizeof(t)
	if total < 0 || total > 512 {
		return nil, false
	}
	slots := make([]oracleByteSlot, total)
	ptrSize := sizes.Sizeof(types.Typ[types.Uintptr])

	var fill func(cur types.Type, base int64) bool
	fill = func(cur types.Type, base int64) bool {
		cur = types.Unalias(cur)
		if _, isTP := cur.(*types.TypeParam); isTP {
			return false
		}
		sz := sizes.Sizeof(cur)
		switch u := cur.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.String {
				for i := int64(0); i < ptrSize; i++ {
					slots[base+i] = oracleByteSlot{role: roleStrPtr, slotStart: base}
				}
				for i := int64(0); i < ptrSize; i++ {
					slots[base+ptrSize+i] = oracleByteSlot{role: roleStrLen, slotStart: base + ptrSize}
				}
				return true
			}
			for i := int64(0); i < sz; i++ {
				slots[base+i] = oracleByteSlot{role: roleBasic, basicKind: u.Kind(), slotStart: base}
			}
			return true
		case *types.Pointer:
			for i := int64(0); i < sz; i++ {
				slots[base+i] = oracleByteSlot{role: rolePointer, slotStart: base, elemType: u.Elem()}
			}
			return true
		case *types.Slice:
			for i := int64(0); i < ptrSize; i++ {
				slots[base+i] = oracleByteSlot{role: roleSlicePtr, slotStart: base, elemType: u.Elem()}
			}
			for i := int64(0); i < ptrSize; i++ {
				slots[base+ptrSize+i] = oracleByteSlot{role: roleSliceLen, slotStart: base + ptrSize}
			}
			for i := int64(0); i < ptrSize; i++ {
				slots[base+2*ptrSize+i] = oracleByteSlot{role: roleSliceCap, slotStart: base + 2*ptrSize}
			}
			return true
		case *types.Array:
			if u.Len() == 0 {
				return true
			}
			stride := sz / u.Len()
			for idx := int64(0); idx < u.Len(); idx++ {
				if !fill(u.Elem(), base+idx*stride) {
					return false
				}
			}
			return true
		case *types.Struct:
			n := u.NumFields()
			if n == 0 {
				return true
			}
			fields := make([]*types.Var, n)
			for i := 0; i < n; i++ {
				fields[i] = u.Field(i)
			}
			offs := sizes.Offsetsof(fields)
			for i := 0; i < n; i++ {
				if !fill(fields[i].Type(), base+offs[i]) {
					return false
				}
			}
			return true
		case *types.Map, *types.Chan, *types.Signature, *types.Interface:
			for i := int64(0); i < sz; i++ {
				slots[base+i] = oracleByteSlot{role: roleOpaqueRef, slotStart: base, elemType: u}
			}
			return true
		default:
			return false
		}
	}
	if !fill(t, 0) {
		return nil, false
	}
	return slots, true
}

func oracleAllComponentsPureScalar(root types.Type, forbidBool bool) bool {
	if root == nil {
		return false
	}
	var walk func(types.Type) bool
	walk = func(t types.Type) bool {
		if t == nil {
			return false
		}
		t = types.Unalias(t)
		if _, isTP := t.(*types.TypeParam); isTP {
			return false
		}
		switch u := t.Underlying().(type) {
		case *types.Basic:
			if u.Info()&types.IsUntyped != 0 || u.Kind() == types.Invalid || u.Kind() == types.Uintptr || u.Kind() == types.String || u.Kind() == types.UnsafePointer {
				return false
			}
			if forbidBool && u.Kind() == types.Bool {
				return false
			}
			return (u.Info() & (types.IsBoolean | types.IsInteger | types.IsFloat | types.IsComplex)) != 0
		case *types.Array:
			return u.Len() >= 0 && walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if !walk(u.Field(i).Type()) {
					return false
				}
			}
			return true
		default:
			return false
		}
	}
	return walk(root)
}

func oracleSafeScalarBitcast(sizes types.Sizes, src, dst types.Type) (bool, bool) {
	srcMap, okS := buildByteMemoryMap(sizes, src)
	dstMap, okD := buildByteMemoryMap(sizes, dst)
	if !okS || !okD {
		return false, false
	}
	if !oracleAllComponentsPureScalar(src, false) || !oracleAllComponentsPureScalar(dst, true) {
		return false, true
	}
	for _, b := range srcMap {
		if b.role != roleBasic || b.basicKind == types.Uintptr {
			return false, true
		}
	}
	for _, b := range dstMap {
		if b.role != rolePadding && (b.role != roleBasic || b.basicKind == types.Bool || b.basicKind == types.Uintptr) {
			return false, true
		}
	}
	return sizes.Sizeof(dst) <= sizes.Sizeof(src) && sizes.Alignof(dst) <= sizes.Alignof(src), true
}

func drawSyntheticType(rt *rapid.T, pkg *types.Package, tp *types.TypeParam, depth int, tag string) types.Type {
	if depth <= 0 {
		choice := rapid.IntRange(0, 12).Draw(rt, tag+"_leaf")
		switch choice {
		case 0:
			return types.Typ[types.Bool]
		case 1:
			return types.Typ[types.Uint8]
		case 2:
			return types.Typ[types.Int16]
		case 3:
			return types.Typ[types.Int32]
		case 4:
			return types.Typ[types.Uint32]
		case 5:
			return types.Typ[types.Int64]
		case 6:
			return types.Typ[types.Uint64]
		case 7:
			return types.Typ[types.Float32]
		case 8:
			return types.Typ[types.Float64]
		case 9:
			return types.Typ[types.Complex64]
		case 10:
			return types.Typ[types.String]
		case 11:
			return types.Typ[types.Uintptr]
		default:
			return types.Typ[types.UnsafePointer]
		}
	}
	kind := rapid.IntRange(0, 9).Draw(rt, tag+"_kind")
	switch kind {
	case 0:
		return drawSyntheticType(rt, pkg, tp, 0, tag+"_b")
	case 1: // Defined type
		under := drawSyntheticType(rt, pkg, tp, depth-1, tag+"_def")
		tn := types.NewTypeName(token.NoPos, pkg, "Def_"+tag, nil)
		return types.NewNamed(tn, under.Underlying(), nil)
	case 2: // Alias type
		rhs := drawSyntheticType(rt, pkg, tp, depth-1, tag+"_al")
		tn := types.NewTypeName(token.NoPos, pkg, "Alias_"+tag, nil)
		return types.NewAlias(tn, rhs)
	case 3: // Single-field wrapper struct
		ft := drawSyntheticType(rt, pkg, tp, depth-1, tag+"_wf")
		f := types.NewField(token.NoPos, pkg, "v", ft, false)
		return types.NewStruct([]*types.Var{f}, nil)
	case 4: // Multi-field struct (including optional zero-sized trailing field)
		nf := rapid.IntRange(0, 3).Draw(rt, tag+"_nf")
		fields := make([]*types.Var, 0, nf)
		for i := 0; i < nf; i++ {
			var ft types.Type
			if rapid.IntRange(0, 5).Draw(rt, tag+"_zf") == 0 {
				ft = types.NewStruct(nil, nil)
			} else {
				ft = drawSyntheticType(rt, pkg, tp, depth-1, tag+"_f")
			}
			fields = append(fields, types.NewField(token.NoPos, pkg, "f"+string(rune('a'+i)), ft, false))
		}
		return types.NewStruct(fields, nil)
	case 5: // Array
		n := int64(rapid.SampledFrom([]int{0, 1, 2, 3}).Draw(rt, tag+"_alen"))
		el := drawSyntheticType(rt, pkg, tp, depth-1, tag+"_ael")
		return types.NewArray(el, n)
	case 6: // Pointer
		el := drawSyntheticType(rt, pkg, tp, depth-1, tag+"_pel")
		return types.NewPointer(el)
	case 7: // Slice
		el := drawSyntheticType(rt, pkg, tp, depth-1, tag+"_sel")
		return types.NewSlice(el)
	case 8: // Map or Chan or Interface
		sub := rapid.IntRange(0, 2).Draw(rt, tag+"_mci")
		switch sub {
		case 0:
			return types.NewMap(types.Typ[types.String], types.Typ[types.Int])
		case 1:
			return types.NewChan(types.SendRecv, types.Typ[types.Int])
		default:
			return types.NewInterfaceType(nil, nil)
		}
	default:
		return tp
	}
}

func mutateIsomorphically(rt *rapid.T, pkg *types.Package, t types.Type, tag string) types.Type {
	mode := rapid.IntRange(0, 5).Draw(rt, tag+"_iso")
	switch mode {
	case 0:
		tn := types.NewTypeName(token.NoPos, pkg, "IsoDef_"+tag, nil)
		return types.NewNamed(tn, t.Underlying(), nil)
	case 1:
		tn := types.NewTypeName(token.NoPos, pkg, "IsoAlias_"+tag, nil)
		return types.NewAlias(tn, t)
	case 2:
		f := types.NewField(token.NoPos, pkg, "only", t, false)
		return types.NewStruct([]*types.Var{f}, nil)
	case 3:
		// Also probe pointer/slice element wrapping to verify non-identical
		// pointee/slice element types are rejected while aliases stay identical.
		switch u := types.Unalias(t).Underlying().(type) {
		case *types.Pointer:
			tn := types.NewTypeName(token.NoPos, pkg, "ElemDef_"+tag, nil)
			return types.NewPointer(types.NewNamed(tn, u.Elem().Underlying(), nil))
		case *types.Slice:
			tn := types.NewTypeName(token.NoPos, pkg, "SliceElemDef_"+tag, nil)
			return types.NewSlice(types.NewNamed(tn, u.Elem().Underlying(), nil))
		}
		return t
	case 4:
		switch u := types.Unalias(t).Underlying().(type) {
		case *types.Pointer:
			tn := types.NewTypeName(token.NoPos, pkg, "ElemAlias_"+tag, nil)
			return types.NewPointer(types.NewAlias(tn, u.Elem()))
		case *types.Slice:
			tn := types.NewTypeName(token.NoPos, pkg, "SliceElemAlias_"+tag, nil)
			return types.NewSlice(types.NewAlias(tn, u.Elem()))
		}
		return t
	default:
		return t
	}
}

func TestPropertyIsomorphicAndScalarBitcastByteLayoutOracle(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		arch := rapid.SampledFrom([]string{"amd64", "arm64", "386"}).Draw(rt, "arch")
		sizes := types.SizesFor("gc", arch)
		pkg := types.NewPackage("example.com/prop", "prop")
		tpName := types.NewTypeName(token.NoPos, pkg, "T", nil)
		tp := types.NewTypeParam(tpName, types.Universe.Lookup("any").Type())

		a := drawSyntheticType(rt, pkg, tp, 2, "a")
		var b types.Type
		if rapid.Bool().Draw(rt, "correlated") {
			b = mutateIsomorphically(rt, pkg, a, "b")
		} else {
			b = drawSyntheticType(rt, pkg, tp, 2, "b")
		}
		c := mutateIsomorphically(rt, pkg, b, "c")

		// 1. Symmetry.
		ab := IsomorphicValueLayout(sizes, a, b)
		ba := IsomorphicValueLayout(sizes, b, a)
		if ab != ba {
			rt.Fatalf("asymmetry on arch=%s: Isomorphic(%v, %v)=%v vs reverse=%v", arch, a, b, ab, ba)
		}

		// 2. Reflexivity iff free of unsafe.Pointer / invalid basics.
		aa := IsomorphicValueLayout(sizes, a, a)
		wantRefl := !oracleContainsUnsafeOrInvalid(a)
		if aa != wantRefl {
			rt.Fatalf("reflexivity mismatch on %v: got %v, want %v", a, aa, wantRefl)
		}

		// 3. Transitivity.
		bc := IsomorphicValueLayout(sizes, b, c)
		ac := IsomorphicValueLayout(sizes, a, c)
		if ab && bc && !ac {
			rt.Fatalf("transitivity violated: a=%v, b=%v, c=%v", a, b, c)
		}

		// 4. Byte-by-byte memory layout soundness: IsomorphicValueLayout(a, b) => identical byte maps!
		mapA, okA := buildByteMemoryMap(sizes, a)
		mapB, okB := buildByteMemoryMap(sizes, b)
		if ab {
			if sizes.Sizeof(a) != sizes.Sizeof(b) || sizes.Alignof(a) != sizes.Alignof(b) {
				rt.Fatalf("Isomorphic(%v, %v) violated size/align on %s", a, b, arch)
			}
			if okA && okB {
				if len(mapA) != len(mapB) {
					rt.Fatalf("byte map len %d != %d for (%v, %v)", len(mapA), len(mapB), a, b)
				}
				for i := range mapA {
					sa, sb := mapA[i], mapB[i]
					if sa.role != sb.role || sa.basicKind != sb.basicKind || sa.slotStart != sb.slotStart {
						rt.Fatalf("byte[%d] layout mismatch on %s for (%v, %v): %+v vs %+v", i, arch, a, b, sa, sb)
					}
					if (sa.role == rolePointer || sa.role == roleSlicePtr) &&
						!types.Identical(types.Unalias(sa.elemType), types.Unalias(sb.elemType)) {
						rt.Fatalf("byte[%d] pointee/slice elem not identical: %v vs %v", i, sa.elemType, sb.elemType)
					}
					if sa.role == roleOpaqueRef && !types.Identical(sa.elemType, sb.elemType) {
						rt.Fatalf("byte[%d] opaque ref mismatch: %v vs %v", i, sa.elemType, sb.elemType)
					}
				}
			}
		}

		// 5. Exact equivalence of IsSafeScalarBitcast against the independent byte-map oracle.
		gotCast := IsSafeScalarBitcast(sizes, a, b)
		if wantCast, applicable := oracleSafeScalarBitcast(sizes, a, b); applicable && gotCast != wantCast {
			rt.Fatalf("IsSafeScalarBitcast(%v -> %v) on %s = %v, oracle = %v", a, b, arch, gotCast, wantCast)
		}
	})

	// Explicit recursive cycle termination, pointer-element identity, *unsafe.Pointer
	// non-reflexivity, and custom types.Sizes field-offset divergence checks:
	sizes := types.SizesFor("gc", "amd64")
	pkg := types.NewPackage("example.com/rec", "rec")
	makeRecNode := func(name string, leaf types.Type) *types.Named {
		tn := types.NewTypeName(token.NoPos, pkg, name, nil)
		named := types.NewNamed(tn, nil, nil)
		st := types.NewStruct([]*types.Var{
			types.NewField(token.NoPos, pkg, "next", types.NewPointer(named), false),
			types.NewField(token.NoPos, pkg, "val", leaf, false),
		}, nil)
		named.SetUnderlying(st)
		return named
	}
	intAlias := types.NewNamed(types.NewTypeName(token.NoPos, pkg, "MyInt64", nil), types.Typ[types.Int64], nil)
	n1 := makeRecNode("Node1", types.Typ[types.Int64])
	n1Wrap := types.NewStruct([]*types.Var{types.NewField(token.NoPos, pkg, "only", n1, false)}, nil)
	n2 := makeRecNode("Node2", intAlias)
	if !IsomorphicValueLayout(sizes, n1, n1Wrap) {
		t.Fatal("recursive single-field wrapper around Node1 rejected")
	}
	if IsomorphicValueLayout(sizes, n1, n2) {
		t.Fatal("distinct recursive pointer-element structs Node1 (*Node1) and Node2 (*Node2) accepted")
	}
	ptrUP := types.NewPointer(types.Typ[types.UnsafePointer])
	if IsomorphicValueLayout(sizes, ptrUP, ptrUP) {
		t.Fatal("*unsafe.Pointer accepted as IsomorphicValueLayout")
	}

	// Custom types.Sizes implementation with equal total Sizeof/Alignof and equal
	// field Sizeof/Alignof but diverging Offsetsof on the second field.
	fA1 := types.NewField(token.NoPos, pkg, "x", types.Typ[types.Int32], false)
	fA2 := types.NewField(token.NoPos, pkg, "y", types.Typ[types.Int32], false)
	stA := types.NewStruct([]*types.Var{fA1, fA2}, nil)
	fB1 := types.NewField(token.NoPos, pkg, "x", types.NewNamed(types.NewTypeName(token.NoPos, pkg, "I32", nil), types.Typ[types.Int32], nil), false)
	fB2 := types.NewField(token.NoPos, pkg, "y", types.Typ[types.Int32], false)
	stB := types.NewStruct([]*types.Var{fB1, fB2}, nil)
	skewSizes := skewedOffsetSizes{base: sizes, skewField: fB2}
	if IsomorphicValueLayout(skewSizes, stA, stB) {
		t.Fatal("IsomorphicValueLayout ignored diverging types.Sizes.Offsetsof")
	}
}

type skewedOffsetSizes struct {
	base      types.Sizes
	skewField *types.Var
}

func (s skewedOffsetSizes) Alignof(T types.Type) int64 { return s.base.Alignof(T) }
func (s skewedOffsetSizes) Sizeof(T types.Type) int64  { return s.base.Sizeof(T) }
func (s skewedOffsetSizes) Offsetsof(fields []*types.Var) []int64 {
	offs := s.base.Offsetsof(fields)
	for i, f := range fields {
		if f == s.skewField {
			offs[i] += 2
		}
	}
	return offs
}

func TestUnsafeLayoutAndPackageHazardMatrix(t *testing.T) {
	cases := []struct {
		name       string
		specs      []inMemPkgSpec
		targetPkg  string
		wantHazard bool
	}{
		{
			name: "compile_time_intrinsics_only",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type S struct { a uint8; b int64 }
func Layout[T any](x S) uintptr {
	var z T
	return unsafe.Sizeof(x) + unsafe.Alignof(x.b) + unsafe.Offsetof(x.b) + unsafe.Sizeof(z)
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: false,
		},
		{
			name: "typed_nil_unsafe_pointer",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type UP unsafe.Pointer
func NilPtrs() (unsafe.Pointer, UP) { return unsafe.Pointer(nil), UP(nil) }`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: false,
		},
		{
			name: "go_x_tools_typeparamlist_shape_safe",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type TypeParam struct { name string }
type TypeParamList struct { tparams []*TypeParam }
func (l *TypeParamList) Len() int {
	if l == nil { return 0 }
	return len(l.tparams)
}
func Wrap(n int) *TypeParamList {
	tpars := make([]*TypeParam, n)
	for i := range tpars {
		tpars[i] = &TypeParam{name: "T"}
	}
	return (*TypeParamList)(unsafe.Pointer(&tpars))
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: false,
		},
		{
			name: "go_x_tools_term_capsule_shape_safe",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type Term term
type term struct { tilde bool; typ string }
func (m *Term) Tilde() bool { return m.tilde }
func Convert(t *term) *Term { return (*Term)(unsafe.Pointer(t)) }`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: false,
		},
		{
			name: "cross_pkg_capsule_immutable_safe",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/def",
					files: map[string]string{"def.go": `package def
type Src struct { a int64; s string }
type Dst struct { a int64; s string }
func NewSrc(a int64, s string) *Src { return &Src{a: a, s: s} }
func (d *Dst) S() string { return d.s }`},
				},
				{
					pkgPath: "example.com/use",
					files: map[string]string{"use.go": `package use
import (
	"unsafe"
	"example.com/def"
)
func Cast(x *def.Src) *def.Dst { return (*def.Dst)(unsafe.Pointer(x)) }`},
				},
			},
			targetPkg:  "example.com/use",
			wantHazard: false,
		},
		{
			name: "cross_pkg_capsule_mutated_in_decl_pkg_hazard",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/def",
					files: map[string]string{"def.go": `package def
type Src struct { a int64; s string }
type Dst struct { a int64; s string }
func Mutate(x *Src) { x.a = 99 }`},
				},
				{
					pkgPath: "example.com/use",
					files: map[string]string{"use.go": `package use
import (
	"unsafe"
	"example.com/def"
)
func Cast(x *def.Src) *def.Dst { return (*def.Dst)(unsafe.Pointer(x)) }`},
				},
			},
			targetPkg:  "example.com/use",
			wantHazard: true,
		},
		{
			name: "shadow_capsule_mutation_fake_guidance_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import (
	"sync"
	"unsafe"
)
type OnceGuidance struct {
	once sync.Once
	val  string
}
type fakeGuidance struct {
	once sync.Once
	val  string
}
func Smuggle() (*OnceGuidance, func()) {
	fg := &fakeGuidance{val: "a"}
	return (*OnceGuidance)(unsafe.Pointer(fg)), func() { fg.val = "b" }
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "exported_field_target_struct_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type PubList struct { Items []int }
func Wrap() *PubList {
	items := make([]int, 2)
	return (*PubList)(unsafe.Pointer(&items))
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "tpars_mutated_after_cast_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type List struct { xs []int }
func Bad() *List {
	xs := []int{1, 2}
	out := (*List)(unsafe.Pointer(&xs))
	xs[0] = 99
	return out
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "tpars_inside_loop_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type List struct { xs []int }
func Bad() []*List {
	var out []*List
	for i := 0; i < 2; i++ {
		xs := []int{i}
		out = append(out, (*List)(unsafe.Pointer(&xs)))
	}
	return out
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "tpars_captured_by_closure_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type List struct { xs []int }
func Bad() (*List, func()) {
	xs := []int{1}
	mut := func() { xs[0] = 2 }
	return (*List)(unsafe.Pointer(&xs)), mut
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "tpars_aliased_from_caller_param_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type List struct { xs []int }
func Bad(in []int) *List {
	xs := in
	return (*List)(unsafe.Pointer(&xs))
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "trailing_zero_sized_field_padding_mismatch_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type A struct { x int64; z struct{} }
type B struct { z struct{}; x int64 }
func Bad(a A) B { return *(*B)(unsafe.Pointer(&a)) }`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "field_offset_padding_shift_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type A struct { a uint8; b uint8; c uint16 }
type B struct { a uint16; b uint8; c uint8 }
func ReadIsomorphic(a *A) uint16 {
	p := (*B)(unsafe.Pointer(a))
	return p.a
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "rvalue_scalar_bitcast_float64_and_prefix_bytes_safe",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
func Bits(f float64) (uint64, byte) {
	u := *(*uint64)(unsafe.Pointer(&f))
	arr := *(*[4]byte)(unsafe.Pointer(&f))
	return u, arr[0]
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: false,
		},
		{
			name: "scalar_bitcast_padding_source_uninitialized_bytes_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type Padded struct { a uint8; b uint64 }
func LeakStackPadding(x Padded) [16]byte {
	return *(*[16]byte)(unsafe.Pointer(&x))
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "rvalue_array_slice_alias_attack_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
func AliasMutate(x uint64) uint64 {
	s := (*(*[4]byte)(unsafe.Pointer(&x)))[:]
	s[0] = 0xff
	return x
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "lvalue_scalar_bitcast_write_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
func WriteBits(f float64) float64 {
	*(*uint64)(unsafe.Pointer(&f)) = 1
	return f
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "scalar_bitcast_overrun_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
func Overrun(x uint32) uint64 { return *(*uint64)(unsafe.Pointer(&x)) }`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "scalar_bitcast_alignment_widening_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
func Misaligned(b [8]byte) uint64 { return *(*uint64)(unsafe.Pointer(&b)) }`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "scalar_bitcast_bool_dst_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
func BadBool(x uint8) bool { return *(*bool)(unsafe.Pointer(&x)) }`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "scalar_bitcast_uintptr_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
func BadUintptr(x uintptr) uint64 { return *(*uint64)(unsafe.Pointer(&x)) }`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "stringdata_eq_and_readonly_slice_safe",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import (
	"bytes"
	"unsafe"
)
func SameAndScan(a, b string) (bool, int) {
	eq := unsafe.StringData(a) == unsafe.StringData(b)
	view := unsafe.Slice(unsafe.StringData(a), len(a))
	return eq, bytes.IndexByte(view, 'x')
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: false,
		},
		{
			name: "stringdata_slice_append_zero_cap_overwrite_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
func CorruptRODATA(s string) []byte {
	view := unsafe.Slice(unsafe.StringData(s), len(s))
	return append(view[:0], 'X')
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "stringdata_slice_mismatched_len_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
func BadLen(a, b string) byte {
	view := unsafe.Slice(unsafe.StringData(a), len(b))
	if len(view) > 0 { return view[0] }
	return 0
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "stringdata_slice_reassigned_local_race_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
func RaceLen(a, b string) int {
	s := a
	go func() { s = b }()
	view := unsafe.Slice(unsafe.StringData(s), len(s))
	return len(view)
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "two_pkg_defined_unsafe_pointer_without_import_unsafe_hazard",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/up",
					files: map[string]string{"up.go": `package up
import "unsafe"
type Ptr unsafe.Pointer`},
				},
				{
					pkgPath: "example.com/noimp",
					files: map[string]string{"noimp.go": `package noimp
import "example.com/up"
func Corrupt(p *int) {
	*(*uint64)(up.Ptr(p)) = 42
}`},
				},
			},
			targetPkg:  "example.com/noimp",
			wantHazard: true,
		},
		{
			name: "generic_tilde_unsafe_pointer_launder_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
func Launder[U ~unsafe.Pointer](p *int) U { return U(p) }`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "go_x_tools_ssa_exact_for_range_int_shape_safe",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/gt",
					files: map[string]string{"gt.go": `package gt
type TypeParam struct { index int }
func (tp *TypeParam) SetIndex(i int) { tp.index = i }
type TypeParamList struct { tparams []*TypeParam }
func (l *TypeParamList) Len() int { return len(l.list()) }
func (l *TypeParamList) At(i int) *TypeParam { return l.tparams[i] }
func (l *TypeParamList) list() []*TypeParam {
	if l == nil { return nil }
	return l.tparams
}`},
				},
				{
					pkgPath: "example.com/ssa",
					files: map[string]string{"ssa.go": `package ssa
import (
	"reflect"
	"unsafe"
	"example.com/gt"
)
func consTypeParamLists(l, r *gt.TypeParamList) *gt.TypeParamList {
	if l.Len() == 0 { return r }
	if r.Len() == 0 { return l }
	tpars := make([]*gt.TypeParam, l.Len()+r.Len())
	for i := range l.Len() {
		tpars[i] = l.At(i)
	}
	for i := range r.Len() {
		tpars[i+l.Len()] = r.At(i)
	}
	t := reflect.TypeOf(gt.TypeParamList{})
	if t.NumField() != 1 { panic("unexpected") }
	return (*gt.TypeParamList)(unsafe.Pointer(&tpars))
}`},
				},
			},
			targetPkg:  "example.com/ssa",
			wantHazard: false,
		},
		{
			name: "tpars_elem_addr_taken_before_cast_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type List struct { xs []int }
func Bad() *List {
	xs := make([]int, 1)
	slot := &xs[0]
	out := (*List)(unsafe.Pointer(&xs))
	*slot = 77
	return out
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "stringdata_slice_bytes_trimspace_subslice_escape_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import (
	"bytes"
	"unsafe"
)
func SubsliceEscape(s string) int {
	view := unsafe.Slice(unsafe.StringData(s), len(s))
	sub := bytes.TrimSpace(view)
	return len(sub)
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "capsule_exported_slice_getter_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type Dst struct { xs []int }
func (d *Dst) Leak() []int { return d.xs }
func Wrap() *Dst {
	xs := make([]int, 2)
	return (*Dst)(unsafe.Pointer(&xs))
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "capsule_aliased_slice_field_write_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type Dst struct { xs []int }
func (d *Dst) MutateViaLocal() {
	s := d.xs
	s[0] = 99
}
func Wrap() *Dst {
	xs := make([]int, 2)
	return (*Dst)(unsafe.Pointer(&xs))
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "generic_value_embedded_typeparam_array_cast_no_panic_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type Box[T any] struct { a [1]T }
func Cast[T any](p *[1]T) *Box[T] {
	return (*Box[T])(unsafe.Pointer(p))
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "capsule_isolated_by_value_local_copy_mutation_safe",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type Term term
type term struct { tilde bool; typ string }
func (x *term) includes(s string) bool {
	if x == nil { return false }
	return x.tilde && x.typ == s
}
func Probe(t *term) bool {
	tt := *t
	tt.tilde = true
	return tt.includes("int")
}
func Convert(t *term) *Term { return (*Term)(unsafe.Pointer(t)) }`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: false,
		},
		{
			name: "capsule_by_value_local_self_returning_method_escape_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type Term term
type term struct { tilde bool; typ string }
func (x *term) Self() *term { return x }
func LeakAndMutate(t *term) *Term {
	tt := *t
	alias := tt.Self()
	out := (*Term)(unsafe.Pointer(alias))
	tt.tilde = true
	return out
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "slice_elem_pointer_transmutation_forge_mutable_secret_hazard",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/def",
					files: map[string]string{"def.go": `package def
type Secret struct { val string }
func (s *Secret) Val() string { return s.val }`},
				},
				{
					pkgPath: "example.com/use",
					files: map[string]string{"use.go": `package use
import (
	"unsafe"
	"example.com/def"
)
type fakeSecret struct { val string }
type Holder struct { list []*def.Secret }
func (h *Holder) At(i int) *def.Secret { return h.list[i] }
func Forge() (*def.Secret, func()) {
	fs := &fakeSecret{val: "initial"}
	xs := make([]*fakeSecret, 1)
	xs[0] = fs
	h := (*Holder)(unsafe.Pointer(&xs))
	return h.At(0), func() { fs.val = "corrupted" }
}`},
				},
			},
			targetPkg:  "example.com/use",
			wantHazard: true,
		},
		{
			name: "slice_value_elem_transmutation_forge_secret_hazard",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/def",
					files: map[string]string{"def.go": `package def
type Secret struct { val string }
func (s Secret) Val() string { return s.val }`},
				},
				{
					pkgPath: "example.com/use",
					files: map[string]string{"use.go": `package use
import (
	"unsafe"
	"example.com/def"
)
type fakeSecret struct { val string }
type Holder struct { list []def.Secret }
func (h *Holder) At(i int) def.Secret { return h.list[i] }
func Forge() def.Secret {
	xs := make([]fakeSecret, 1)
	h := (*Holder)(unsafe.Pointer(&xs))
	return h.At(0)
}`},
				},
			},
			targetPkg:  "example.com/use",
			wantHazard: true,
		},
		{
			name: "ptr_field_elem_transmutation_unmutated_forge_secret_hazard",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/def",
					files: map[string]string{"def.go": `package def
type Secret struct { val string }
func (s *Secret) Val() string { return s.val }`},
				},
				{
					pkgPath: "example.com/use",
					files: map[string]string{"use.go": `package use
import (
	"unsafe"
	"example.com/def"
)
type fakeSecret struct { val string }
type fakeBox struct { p *fakeSecret }
type Holder struct { p *def.Secret }
func (h *Holder) Get() *def.Secret { return h.p }
func Forge() *def.Secret {
	var fb fakeBox
	h := (*Holder)(unsafe.Pointer(&fb))
	return h.Get()
}`},
				},
			},
			targetPkg:  "example.com/use",
			wantHazard: true,
		},
		{
			name: "rvalue_auto_addressed_ptr_recv_clobber_scalar_bitcast_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type Overwriter [8]byte
func (o *Overwriter) Clobber() { o[0] = 0xff }
func MutateFloat(f float64) float64 {
	(*(*Overwriter)(unsafe.Pointer(&f))).Clobber()
	return f
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "rvalue_auto_addressed_ptr_recv_clobber_isomorphic_hazard",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/def",
					files: map[string]string{"def.go": `package def
type Imm struct { s string }
func New(s string) *Imm { return &Imm{s: s} }`},
				},
				{
					pkgPath: "example.com/use",
					files: map[string]string{"use.go": `package use
import (
	"unsafe"
	"example.com/def"
)
type MutStr struct { s string }
func (m *MutStr) Clobber() { m.s = "evil" }
func Corrupt(x *def.Imm) {
	(*(*MutStr)(unsafe.Pointer(x))).Clobber()
}`},
				},
			},
			targetPkg:  "example.com/use",
			wantHazard: true,
		},
		{
			name: "capsule_stdlib_slices_reverse_on_slice_field_hazard",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/def",
					files: map[string]string{"def.go": `package def
type Guidance struct { vals []string }
func New() *Guidance { return &Guidance{vals: []string{"a", "b"}} }`},
				},
				{
					pkgPath: "example.com/use",
					files: map[string]string{"use.go": `package use
import (
	"slices"
	"unsafe"
	"example.com/def"
)
type rawGuidance struct { vals []string }
func Corrupt(g *def.Guidance) {
	rg := (*rawGuidance)(unsafe.Pointer(g))
	slices.Reverse(rg.vals)
}`},
				},
			},
			targetPkg:  "example.com/use",
			wantHazard: true,
		},
		{
			name: "capsule_slices_index_on_slice_field_safe",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import (
	"slices"
	"unsafe"
)
type List struct { xs []int }
func (l *List) Index(v int) int { return slices.Index(l.xs, v) }
func Wrap() *List {
	xs := make([]int, 2)
	return (*List)(unsafe.Pointer(&xs))
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: false,
		},
		{
			name: "capsule_ptr_int_and_any_field_mutation_hazards",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/def",
					files: map[string]string{"def.go": `package def
type Box struct { p *int; a any }
func New(v int) *Box { return &Box{p: &v, a: []string{"ok"}} }`},
				},
				{
					pkgPath: "example.com/use",
					files: map[string]string{"use.go": `package use
import (
	"unsafe"
	"example.com/def"
)
type rawBox struct { p *int; a any }
func Corrupt(b *def.Box) {
	rb := (*rawBox)(unsafe.Pointer(b))
	rb.a.([]string)[0] = "bad"
}`},
				},
			},
			targetPkg:  "example.com/use",
			wantHazard: true,
		},
		{
			name: "capsule_value_array_field_slicing_mutation_hazard",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/def",
					files: map[string]string{"def.go": `package def
type Buf struct { data [8]byte }
func New() *Buf { return &Buf{} }`},
				},
				{
					pkgPath: "example.com/use",
					files: map[string]string{"use.go": `package use
import (
	"unsafe"
	"example.com/def"
)
type rawBuf struct { data [8]byte }
func Corrupt(b *def.Buf) {
	rb := (*rawBuf)(unsafe.Pointer(b))
	rb.data[:][0] = 0xff
}`},
				},
			},
			targetPkg:  "example.com/use",
			wantHazard: true,
		},
		{
			name: "capsule_subselector_by_value_local_self_escape_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type Guidance struct { val string }
type fakeGuidance struct { val string }
func (f *fakeGuidance) Self() *fakeGuidance { return f }
func Escape() *Guidance {
	var holder struct { fg fakeGuidance }
	escaped := (*Guidance)(unsafe.Pointer(holder.fg.Self()))
	holder.fg.val = "corrupted"
	return escaped
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "conversion_free_reflect_unsafe_pointer_newat_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "reflect"
type Secret struct { val string }
func Corrupt(sec *Secret) {
	up := reflect.ValueOf(sec).UnsafePointer()
	reflect.NewAt(reflect.TypeOf(""), up).Elem().SetString("CORRUPTED")
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "valuespec_multi_return_slice_alias_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type List struct { xs []int }
func pair(in []int) (int, []int) { return 0, in }
func Bad(callerSlice []int) *List {
	var _, xs = pair(callerSlice)
	return (*List)(unsafe.Pointer(&xs))
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "named_result_local_addr_overwrite_on_return_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type Capsule struct { v int64 }
func Bad() (lv int64, out *Capsule) {
	lv = 1
	out = (*Capsule)(unsafe.Pointer(&lv))
	return 2, out
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "same_statement_multi_assign_phase2_overwrite_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type Capsule struct { val int64 }
type rawCapsule struct { val int64 }
func observe(c *Capsule) *Capsule { return c }
func Bad() *Capsule {
	var lv rawCapsule
	var out *Capsule
	lv, out = rawCapsule{val: 2}, observe((*Capsule)(unsafe.Pointer(&lv)))
	return out
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "stringdata_slice_redeclared_local_race_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
func RaceRedecl(a, b string) int {
	s := a
	go func() {
		view := unsafe.Slice(unsafe.StringData(s), len(s))
		_ = len(view)
	}()
	s, dummy := b, 1
	return dummy
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "standalone_stringdata_dereference_oob_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
func DerefEmpty(s string) byte {
	return *unsafe.StringData(s)
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "tpwalker_field_propagation_scratch_map_safe",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import (
	"slices"
	"unsafe"
)
type TypeParam struct { idx int }
type TypeParamList struct { tparams []*TypeParam }
func (l *TypeParamList) list() []*TypeParam {
	if l == nil { return nil }
	return l.tparams
}
type tpWalker struct {
	tparams []*TypeParam
	seen    map[int]bool
}
func (w *tpWalker) check(tp *TypeParam, k int) bool {
	if v, ok := w.seen[k]; ok { return v }
	w.seen[k] = false
	res := slices.Index(w.tparams, tp) >= 0
	w.seen[k] = res
	return res
}
func HasParam(l *TypeParamList, tp *TypeParam) bool {
	w := tpWalker{tparams: l.list(), seen: make(map[int]bool)}
	return w.check(tp, 1)
}
func Wrap(n int) *TypeParamList {
	tpars := make([]*TypeParam, n)
	return (*TypeParamList)(unsafe.Pointer(&tpars))
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: false,
		},
		{
			name: "tpwalker_field_propagation_mutating_tainted_field_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type TypeParam struct { idx int }
type TypeParamList struct { tparams []*TypeParam }
func (l *TypeParamList) list() []*TypeParam { return l.tparams }
type tpWalker struct {
	tparams []*TypeParam
	seen    map[int]bool
}
func (w *tpWalker) clobber() {
	w.tparams[0] = nil
}
func Bad(l *TypeParamList) {
	w := tpWalker{tparams: l.list(), seen: make(map[int]bool)}
	w.clobber()
}
func Wrap(n int) *TypeParamList {
	tpars := make([]*TypeParam, n)
	return (*TypeParamList)(unsafe.Pointer(&tpars))
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "tpwalker_field_propagation_exported_sig_escape_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type TypeParam struct { idx int }
type TypeParamList struct { tparams []*TypeParam }
func (l *TypeParamList) list() []*TypeParam { return l.tparams }
type tpWalker struct { tparams []*TypeParam }
func LeakWalker(l *TypeParamList) *tpWalker {
	return &tpWalker{tparams: l.list()}
}
func Wrap(n int) *TypeParamList {
	tpars := make([]*TypeParam, n)
	return (*TypeParamList)(unsafe.Pointer(&tpars))
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "cross_pkg_capsule_leaking_exported_mutable_ptr_hazard",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/def",
					files: map[string]string{"def.go": `package def
type ExportedMut struct { X int }
type SrcCapsule struct { ptr *ExportedMut }
func New() *SrcCapsule { return &SrcCapsule{ptr: &ExportedMut{X: 1}} }`},
				},
				{
					pkgPath: "example.com/use",
					files: map[string]string{"use.go": `package use
import (
	"unsafe"
	"example.com/def"
)
type fakeCapsule struct { ptr *def.ExportedMut }
func (f *fakeCapsule) Leak() *def.ExportedMut { return f.ptr }
func Corrupt(s *def.SrcCapsule) {
	((*fakeCapsule)(unsafe.Pointer(s))).Leak().X = 999
}`},
				},
			},
			targetPkg:  "example.com/use",
			wantHazard: true,
		},
		{
			name: "cross_pkg_capsule_boxed_mutable_interface_hazard",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/def",
					files: map[string]string{"def.go": `package def
type Runner interface { Mutate() }
type mutImpl struct { x int }
func (m *mutImpl) Mutate() { m.x++ }
type SrcCapsule struct { r Runner }
func New() *SrcCapsule { return &SrcCapsule{r: &mutImpl{x: 1}} }`},
				},
				{
					pkgPath: "example.com/use",
					files: map[string]string{"use.go": `package use
import (
	"unsafe"
	"example.com/def"
)
type dstCapsule struct { r def.Runner }
func (d *dstCapsule) R() def.Runner { return d.r }
func Corrupt(s *def.SrcCapsule) {
	((*dstCapsule)(unsafe.Pointer(s))).R().Mutate()
}`},
				},
			},
			targetPkg:  "example.com/use",
			wantHazard: true,
		},
		{
			name: "foreign_atomic_pointer_safe_typearg_safe",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "sync/atomic"
type hookSet struct { enabled bool }
var hooks atomic.Pointer[hookSet]
func LoadHook() *hookSet { return hooks.Load() }`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: false,
		},
		{
			name: "foreign_atomic_pointer_unsafe_pointer_typearg_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import (
	"sync/atomic"
	"unsafe"
)
var raw atomic.Pointer[unsafe.Pointer]`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "cross_pkg_capsule_preboxed_iface_and_nonvoid_mutator_hazard",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/def",
					files: map[string]string{"def.go": `package def
type Counter interface { Inc() int }
type mutCounter struct { n int }
func (c *mutCounter) Inc() int { c.n++; return c.n }
type SrcCapsule struct { c Counter }
func New() *SrcCapsule {
	var c Counter = &mutCounter{n: 1}
	return &SrcCapsule{c: c}
}`},
				},
				{
					pkgPath: "example.com/use",
					files: map[string]string{"use.go": `package use
import (
	"unsafe"
	"example.com/def"
)
type dstCapsule struct { c def.Counter }
func (d *dstCapsule) C() def.Counter { return d.c }
func Corrupt(s *def.SrcCapsule) int {
	return ((*dstCapsule)(unsafe.Pointer(s))).C().Inc()
}`},
				},
			},
			targetPkg:  "example.com/use",
			wantHazard: true,
		},
		{
			name: "capsule_aggregate_array_interface_field_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type Runner interface { Mutate() }
type mutImpl struct { x int }
func (m *mutImpl) Mutate() { m.x++ }
type DstCapsule struct { arr [1]Runner }
func (d *DstCapsule) Fire() { d.arr[0].Mutate() }
func Wrap() *DstCapsule {
	var lv [1]Runner
	lv[0] = &mutImpl{}
	return (*DstCapsule)(unsafe.Pointer(&lv))
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "go_x_tools_typeparams_as_types_term_iface_shape_safe",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/gt",
					files: map[string]string{"gt.go": `package gt
type Type interface {
	Underlying() Type
	String() string
}
type Term term
type term struct {
	tilde bool
	typ   Type
}
func NewTerm(tilde bool, typ Type) *Term { return &Term{tilde, typ} }
func (t *Term) Tilde() bool              { return t.tilde }
func (t *Term) Type() Type               { return t.typ }
func (t *Term) String() string           { return (*term)(t).str() }
func (t *term) str() string              { return t.typ.String() }`},
				},
				{
					pkgPath: "example.com/tp",
					files: map[string]string{"tp.go": `package tp
import (
	"unsafe"
	"example.com/gt"
)
type term struct {
	tilde bool
	typ   gt.Type
}
func makeSingle(t gt.Type) []*term {
	single := &struct {
		term term
		list [1]*term
	}{term: term{false, t}}
	single.list[0] = &single.term
	return single.list[:]
}
func asTypesTerm(t *term) *gt.Term {
	return (*gt.Term)(unsafe.Pointer(t))
}
func Under(t *term) gt.Type {
	return t.typ.Underlying()
}`},
				},
			},
			targetPkg:  "example.com/tp",
			wantHazard: false,
		},
		{
			name: "capsule_declpkg_unnamed_struct_conv_and_assign_hazard",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/def",
					files: map[string]string{"def.go": `package def
type Src struct { xs []int }
func CorruptAssign(s *Src) {
	var anon struct { xs []int } = *s
	anon.xs[0] = 999
}`},
				},
				{
					pkgPath: "example.com/use",
					files: map[string]string{"use.go": `package use
import (
	"unsafe"
	"example.com/def"
)
type dst struct { xs []int }
func Cast(s *def.Src) *dst { return (*dst)(unsafe.Pointer(s)) }`},
				},
			},
			targetPkg:  "example.com/use",
			wantHazard: true,
		},
		{
			name: "capsule_declpkg_named_value_conv_mutation_hazard",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/def",
					files: map[string]string{"def.go": `package def
type raw struct { xs []int }
type Src raw
func Corrupt(s *Src) {
	r := raw(*s)
	r.xs[0] = 999
}`},
				},
				{
					pkgPath: "example.com/use",
					files: map[string]string{"use.go": `package use
import (
	"unsafe"
	"example.com/def"
)
type dst struct { xs []int }
func Cast(s *def.Src) *dst { return (*dst)(unsafe.Pointer(s)) }`},
				},
			},
			targetPkg:  "example.com/use",
			wantHazard: true,
		},
		{
			name: "capsule_declpkg_generic_tilde_struct_mutation_hazard",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/def",
					files: map[string]string{"def.go": `package def
type raw struct { xs []int }
type Src struct { xs []int }
func clobber[T ~struct{ xs []int }](x T) {
	raw(x).xs[0] = 999
}
func Corrupt(s *Src) { clobber(*s) }`},
				},
				{
					pkgPath: "example.com/use",
					files: map[string]string{"use.go": `package use
import (
	"unsafe"
	"example.com/def"
)
type dst struct { xs []int }
func Cast(s *def.Src) *dst { return (*dst)(unsafe.Pointer(s)) }`},
				},
			},
			targetPkg:  "example.com/use",
			wantHazard: true,
		},
		{
			name: "local_slice_of_slices_caller_elem_alias_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type MatrixCapsule struct { rows [][]int }
func AliasCallerSlice(callerSlice []int) *MatrixCapsule {
	rows := make([][]int, 1)
	rows[0] = callerSlice
	return (*MatrixCapsule)(unsafe.Pointer(&rows))
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "foreign_unnamed_struct_unexported_unsafe_field_safe",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/foreign",
					files: map[string]string{"foreign.go": `package foreign
import "unsafe"
type Config struct {
	Opts struct {
		Pub  int
		priv unsafe.Pointer
	}
}`},
				},
				{
					pkgPath: "example.com/use",
					files: map[string]string{"use.go": `package use
import "example.com/foreign"
func ReadPub(c foreign.Config) int { return c.Opts.Pub }`},
				},
			},
			targetPkg:  "example.com/use",
			wantHazard: false,
		},
		{
			name: "foreign_embedded_unexported_iface_exposing_unsafe_pointer_hazard",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/foreign",
					files: map[string]string{"foreign.go": `package foreign
import "unsafe"
type privIface interface { Raw() unsafe.Pointer }
type Carrier struct { privIface }`},
				},
				{
					pkgPath: "example.com/use",
					files: map[string]string{"use.go": `package use
import "example.com/foreign"
var c foreign.Carrier`},
				},
			},
			targetPkg:  "example.com/use",
			wantHazard: true,
		},
		{
			name: "generic_call_instance_exposing_unsafe_pointer_typearg_hazard",
			specs: []inMemPkgSpec{
				{
					pkgPath: "example.com/up",
					files: map[string]string{"up.go": `package up
import "unsafe"
type Ptr unsafe.Pointer
func Touch[T any]() {}`},
				},
				{
					pkgPath: "example.com/use",
					files: map[string]string{"use.go": `package use
import "example.com/up"
func Run() { up.Touch[up.Ptr]() }`},
				},
			},
			targetPkg:  "example.com/use",
			wantHazard: true,
		},
		{
			name: "tpwalker_field_propagation_promoted_exported_method_escape_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type TypeParam struct { idx int }
type TypeParamList struct { tparams []*TypeParam }
func (l *TypeParamList) list() []*TypeParam { return l.tparams }
type tpWalker struct { tparams []*TypeParam }
type unexpHelper struct{}
func (unexpHelper) MakeWalker(l *TypeParamList) *tpWalker {
	return &tpWalker{tparams: l.list()}
}
type Pub struct { unexpHelper }
func Wrap(n int) *TypeParamList {
	tpars := make([]*TypeParam, n)
	return (*TypeParamList)(unsafe.Pointer(&tpars))
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
		{
			name: "local_addr_isomorphic_cast_in_loop_reuses_outer_local_hazard",
			specs: []inMemPkgSpec{{
				pkgPath: "example.com/p",
				files: map[string]string{"p.go": `package p
import "unsafe"
type TypeParam struct { idx int }
type TypeParamList struct { tparams []*TypeParam }
func WrapInLoop() []*TypeParamList {
	tpars := make([]*TypeParam, 2)
	var out []*TypeParamList
	for i := 0; i < 2; i++ {
		tpars[0] = &TypeParam{idx: i}
		out = append(out, (*TypeParamList)(unsafe.Pointer(&tpars)))
	}
	return out
}`},
			}},
			targetPkg:  "example.com/p",
			wantHazard: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			byPath, byTypes := mustTypecheckInMemDAG(t, "amd64", tc.specs)
			p := byPath[tc.targetPkg]
			if p == nil {
				t.Fatalf("missing target pkg %s", tc.targetPkg)
			}
			reason := PackageUnsafeMemoryHazardReason(p, p.TypesSizes, byTypes)
			got := reason != ""
			if got != tc.wantHazard {
				t.Fatalf("PackageHasUnconfinedUnsafeMemoryHazard(%s) = %v (reason=%q), want %v", tc.name, got, reason, tc.wantHazard)
			}
		})
	}
}

func FuzzPackageHasUnconfinedUnsafeMemoryHazard(f *testing.F) {
	seeds := []string{
		`package p; import "unsafe"; func F(x int) uintptr { return unsafe.Sizeof(x) + unsafe.Alignof(x) }`,
		`package p; import "unsafe"; func F(x float64) uint64 { return *(*uint64)(unsafe.Pointer(&x)) }`,
		`package p; import "unsafe"; func F(s string) []byte { b := unsafe.Slice(unsafe.StringData(s), len(s)); return append(b[:0], 1) }`,
		`package p; import "unsafe"; type L struct{ s []int }; func F() *L { var x []int; return (*L)(unsafe.Pointer(&x)) }`,
		`package p; import "unsafe"; func F[U ~unsafe.Pointer](p *int) U { return U(p) }`,
		`package p; import "unsafe"; func F(s string) { *unsafe.StringData(s) = 'a' }`,
		"package A;import\"unsafe\";func A(s string)[]byte{A:=unsafe.Slic%(unsafe.StringData(0%A000000%\"000000000000",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	stdImp := importer.Default()
	sizes := types.SizesFor("gc", "amd64")
	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 16<<10 {
			return
		}
		fset := token.NewFileSet()
		file, _ := parser.ParseFile(fset, "fuzz.go", src, parser.ParseComments)
		if file == nil {
			return
		}
		info := &types.Info{
			Types:      make(map[ast.Expr]types.TypeAndValue),
			Instances:  make(map[*ast.Ident]types.Instance),
			Defs:       make(map[*ast.Ident]types.Object),
			Uses:       make(map[*ast.Ident]types.Object),
			Implicits:  make(map[ast.Node]types.Object),
			Selections: make(map[*ast.SelectorExpr]*types.Selection),
			Scopes:     make(map[ast.Node]*types.Scope),
		}
		tp, _ := (&types.Config{
			Error:    func(error) {},
			Importer: stdImp,
			Sizes:    sizes,
		}).Check("example.com/fuzz", fset, []*ast.File{file}, info)
		if tp == nil {
			return
		}
		p := &packages.Package{
			ID:         "example.com/fuzz",
			Name:       file.Name.Name,
			PkgPath:    "example.com/fuzz",
			Fset:       fset,
			Syntax:     []*ast.File{file},
			Types:      tp,
			TypesInfo:  info,
			TypesSizes: sizes,
		}
		loaded := map[*types.Package]*packages.Package{tp: p}
		r1 := PackageHasUnconfinedUnsafeMemoryHazard(p, sizes, loaded)
		r2 := PackageHasUnconfinedUnsafeMemoryHazard(p, sizes, loaded)
		if r1 != r2 {
			t.Fatalf("non-deterministic result %v != %v on:\n%s", r1, r2, src)
		}
	})
}
