package freshstruct

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"slices"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"pgregory.net/rapid"
)

func typecheckTestPkg(t *testing.T, pkgPath, src string) *packages.Package {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Implicits:  map[ast.Node]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
		Instances:  map[*ast.Ident]types.Instance{},
	}
	cfg := &types.Config{Importer: importer.Default()}
	pkg, err := cfg.Check(pkgPath, fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatalf("types.Check: %v", err)
	}
	return &packages.Package{
		PkgPath:   pkgPath,
		Fset:      fset,
		Syntax:    []*ast.File{file},
		Types:     pkg,
		TypesInfo: info,
	}
}

func TestCollectFreshLocalStructVarsAndMutatedTypes(t *testing.T) {
	p := typecheckTestPkg(t, "example.com/p", `package p

type FreshBuilt struct {
	Count int
	Items []int
}

type MutatedAfterReturn struct {
	Count int
}

func NewFresh(n int) *FreshBuilt {
	f := &FreshBuilt{}
	fillFresh(f, n)
	return f
}

func fillFresh(f *FreshBuilt, n int) {
	f.Count = n
	f.Items = make([]int, n)
}

func MutateExisting(m *MutatedAfterReturn) {
	m.Count++
}
`)
	idx := refconfine.BuildPkgIndex(p)
	cache := NewFreshLocalsCache(p, idx)
	mutated, conds := CollectMutatedStructTypes(p, idx, cache, nil, nil, nil, nil)
	if len(conds) != 0 {
		t.Fatalf("unexpected conds: %+v", conds)
	}
	want := []syntaxutil.TypeRef{{Pkg: "example.com/p", Name: "MutatedAfterReturn"}}
	if !slices.Equal(mutated, want) {
		t.Fatalf("MutatedStructTypes = %+v, want %+v", mutated, want)
	}
}

func TestFindMutexConfinedConstructorCaches(t *testing.T) {
	p := typecheckTestPkg(t, "example.com/p", `package p

import (
	"reflect"
	"sync"
)

type Desc struct {
	Name string
}

var (
	cacheMu sync.Mutex
	cache   map[reflect.Type]*Desc
)

func GetDesc(rt reflect.Type) *Desc {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if cache == nil {
		cache = make(map[reflect.Type]*Desc)
	}
	if d, ok := cache[rt]; ok {
		return d
	}
	d := &Desc{Name: rt.Name()}
	cache[rt] = d
	return d
}
`)
	idx := refconfine.BuildPkgIndex(p)
	confined := FindMutexConfinedConstructorCaches(p, idx)
	if len(confined) != 1 {
		t.Fatalf("len(confined) = %d, want 1", len(confined))
	}
	cache := NewFreshLocalsCache(p, idx)
	mutated, _ := CollectMutatedStructTypes(p, idx, cache, confined, nil, nil, nil)
	if len(mutated) != 0 {
		t.Fatalf("expected 0 mutated struct types for mutex-confined constructor cache, got %+v", mutated)
	}
}

func TestReturnOnlyVarsTypeConversionAndDescBuilderGuard(t *testing.T) {
	fset := token.NewFileSet()
	parse := func(name, src string) *ast.File {
		f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", name, err)
		}
		return f
	}
	defvalFile := parse("defval.go", `package defval

type EnumValue interface {
	Number() int
}

type EnumValues interface {
	ByName(string) EnumValue
}

type FieldDesc interface {
	Enum() EnumValues
	FullName() string
}

type Value struct {
	anyVal any
}

func ValueOfEnum(n int) Value {
	return Value{anyVal: n}
}

func Unmarshal(s string, evs EnumValues) (Value, EnumValue, error) {
	return ValueOfEnum(0), evs.ByName(s), nil
}
`)
	defvalInfo := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Implicits:  map[ast.Node]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
		Instances:  map[*ast.Ident]types.Instance{},
	}
	defvalPkg, err := (&types.Config{Importer: importer.Default()}).Check("example.com/defval", fset, []*ast.File{defvalFile}, defvalInfo)
	if err != nil {
		t.Fatalf("types.Check(defval): %v", err)
	}

	extFile := parse("ext.go", `package ext

import "example.com/defval"

type PlaceholderEnumValue string

func (PlaceholderEnumValue) Number() int { return 0 }

type defaultValue struct {
	has  bool
	val  defval.Value
	enum defval.EnumValue
}

func DefaultValue(v defval.Value, ev defval.EnumValue) defaultValue {
	return defaultValue{has: true, val: v, enum: ev}
}

type Field struct {
	Default defaultValue
}

func (*Field) Enum() defval.EnumValues { return nil }
func (*Field) FullName() string { return "f" }
`)
	extInfo := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Implicits:  map[ast.Node]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
		Instances:  map[*ast.Ident]types.Instance{},
	}
	extImp := importerFunc(func(path string) (*types.Package, error) {
		if path == "example.com/defval" {
			return defvalPkg, nil
		}
		return importer.Default().Import(path)
	})
	extPkg, err := (&types.Config{Importer: extImp}).Check("example.com/ext", fset, []*ast.File{extFile}, extInfo)
	if err != nil {
		t.Fatalf("types.Check(ext): %v", err)
	}

	pFile := parse("p.go", `package p

import (
	"example.com/defval"
	"example.com/ext"
)

func BuildField(s string, allowUnresolvable bool) (*ext.Field, error) {
	f := &ext.Field{}
	if err := resolveField(f, s, allowUnresolvable); err != nil {
		return nil, err
	}
	return f, nil
}

func resolveField(f *ext.Field, s string, allowUnresolvable bool) error {
	v, ev, err := unmarshalDefault(s, f, allowUnresolvable)
	if err != nil {
		return err
	}
	f.Default = ext.DefaultValue(v, ev)
	return nil
}

func unmarshalDefault(s string, fd defval.FieldDesc, allowUnresolvable bool) (defval.Value, defval.EnumValue, error) {
	var evs defval.EnumValues
	if fd.Enum() != nil {
		evs = fd.Enum()
	}
	v, ev, err := defval.Unmarshal(s, evs)
	if err != nil && allowUnresolvable {
		v = defval.ValueOfEnum(0)
		ev = ext.PlaceholderEnumValue(fd.FullName())
	} else if err != nil {
		return v, ev, err
	}
	return v, ev, nil
}
`)
	pInfo := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Implicits:  map[ast.Node]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
		Instances:  map[*ast.Ident]types.Instance{},
	}
	imp := importerFunc(func(path string) (*types.Package, error) {
		switch path {
		case "example.com/defval":
			return defvalPkg, nil
		case "example.com/ext":
			return extPkg, nil
		}
		return importer.Default().Import(path)
	})
	pTypes, err := (&types.Config{Importer: imp}).Check("example.com/p", fset, []*ast.File{pFile}, pInfo)
	if err != nil {
		t.Fatalf("types.Check(p): %v", err)
	}
	p := &packages.Package{
		PkgPath:   "example.com/p",
		Fset:      fset,
		Syntax:    []*ast.File{pFile},
		Types:     pTypes,
		TypesInfo: pInfo,
	}
	idx := refconfine.BuildPkgIndex(p)
	cache := NewFreshLocalsCache(p, idx)
	mutated, conds := CollectMutatedStructTypes(p, idx, cache, nil, nil, nil, nil)
	if len(mutated) != 0 {
		t.Fatalf("MutatedStructTypes = %+v, want empty", mutated)
	}
	badGuardPkg := syntaxutil.ConditionalStructMutation{
		Struct:   syntaxutil.TypeRef{Pkg: "example.com/ext", Name: "Field"},
		GuardPkg: "example.com/ext",
	}
	if slices.Contains(conds, badGuardPkg) {
		t.Fatalf("conds unexpectedly contained self-package GuardPkg %+v: got %+v", badGuardPkg, conds)
	}
	wantDescGuard := syntaxutil.ConditionalStructMutation{
		Struct:                  syntaxutil.TypeRef{Pkg: "example.com/ext", Name: "Field"},
		GuardStruct:             syntaxutil.TypeRef{Pkg: "example.com/ext", Name: "defaultValue"},
		RequireDescBuilderGuard: true,
	}
	if !slices.Contains(conds, wantDescGuard) {
		t.Fatalf("conds = %+v, missing %+v", conds, wantDescGuard)
	}
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) {
	return f(path)
}

func findFuncDeclByName(p *packages.Package, name string) *ast.FuncDecl {
	for _, f := range p.Syntax {
		for _, decl := range f.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == name {
				return fd
			}
		}
	}
	return nil
}

func findStructFieldVar(p *packages.Package, typeName, fieldName string) *types.Var {
	tn, _ := p.Types.Scope().Lookup(typeName).(*types.TypeName)
	if tn == nil {
		return nil
	}
	st, _ := tn.Type().Underlying().(*types.Struct)
	if st == nil {
		return nil
	}
	for i := 0; i < st.NumFields(); i++ {
		if st.Field(i).Name() == fieldName {
			return st.Field(i)
		}
	}
	return nil
}

func TestTwoLevelMapCommaOkSelfAppendAndClosureFieldFreshness(t *testing.T) {
	const commonTypes = `package p

import "unsafe"

type Item struct {
	Name string
}

type Inner struct {
	Val int
}

type Doc struct {
	Count int
	inner Inner
	index map[string]map[string]int
	tags  map[string][]string
	items []Item
	ptrs  []*Item
}

var (
	extTopMap   map[string]map[string]int
	extSubMap   map[string]int
	extItems    []Item
	extItemPtr  *Item
	extItemPtrs []*Item
	extMapSink  map[string]int
	extDocSink  *Doc
	extInnerPtr *Inner
	extItemSink []Item
)

var _ = unsafe.Sizeof(0)
`

	cases := []struct {
		name           string
		body           string
		funcName       string
		checkField     string
		mutatedType    string
		wantRetFresh   bool
		wantFieldFresh bool
		wantMutated    bool
	}{
		{
			name: "clean_2level_map_and_scalar_comma_ok_and_self_append",
			body: `
func Build(keys []string) *Doc {
	doc := &Doc{
		index: map[string]map[string]int{},
		tags:  map[string][]string{},
	}
	var items []Item
	for i, k := range keys {
		if doc.index[k] == nil {
			doc.index[k] = map[string]int{}
		}
		if prev, taken := doc.index[k]["first"]; !taken {
			doc.index[k]["first"] = i + prev
		}
		doc.tags[k] = append(doc.tags[k], k)
		items = append(items, Item{Name: k})
	}
	doc.items = items
	doc.Count = len(items)
	return doc
}
`,
			funcName:       "Build",
			checkField:     "index",
			wantRetFresh:   true,
			wantFieldFresh: true,
			wantMutated:    false,
		},
		{
			name: "nonfresh_submap_poisons_field_and_marks_2level_write_mutated",
			body: `
func Build() *Doc {
	doc := &Doc{index: map[string]map[string]int{}}
	doc.index["a"] = extSubMap
	doc.index["a"]["b"] = 1
	return doc
}
`,
			funcName:       "Build",
			checkField:     "index",
			wantRetFresh:   true,
			wantFieldFresh: false,
			wantMutated:    true,
		},
		{
			name: "param_2level_map_write_marks_struct_mutated",
			body: `
func Build(d *Doc) *Doc {
	d.index["a"]["b"] = 42
	return &Doc{}
}
`,
			funcName:       "Build",
			checkField:     "index",
			wantRetFresh:   true,
			wantFieldFresh: true,
			wantMutated:    true,
		},
		{
			name: "ref_comma_ok_read_escaping_to_global_breaks_freshness_and_marks_subsequent_submap_write",
			body: `
func Build() *Doc {
	doc := &Doc{index: map[string]map[string]int{"a": {"b": 1}}}
	if sub, ok := doc.index["a"]; ok {
		extMapSink = sub
	}
	doc.index["a"]["b"] = 9
	return doc
}
`,
			funcName:       "Build",
			checkField:     "index",
			wantRetFresh:   false,
			wantFieldFresh: true,
			wantMutated:    true,
		},
		{
			name: "self_append_escaped_after_field_assign_still_poisons_field_freshness",
			body: `
func Build(names []string) *Doc {
	doc := &Doc{}
	var items []Item
	for _, n := range names {
		items = append(items, Item{Name: n})
	}
	doc.items = items
	extItemSink = items
	return doc
}
`,
			funcName:       "Build",
			checkField:     "items",
			wantRetFresh:   true,
			wantFieldFresh: false,
			wantMutated:    false,
		},
		{
			name: "protobuf_style_fresh_slice_elem_addr_alias_append_keeps_ptr_slice_field_fresh",
			body: `
func Build(names []string) *Doc {
	doc := &Doc{items: make([]Item, len(names))}
	for i := range names {
		it := &doc.items[i]
		it.Name = names[i]
		doc.ptrs = append(doc.ptrs, it)
	}
	return doc
}
`,
			funcName:       "Build",
			checkField:     "ptrs",
			wantRetFresh:   true,
			wantFieldFresh: true,
			wantMutated:    false,
		},
		{
			name: "composite_lit_fresh_local_slice_keeps_field_fresh_unless_slice_escapes_later",
			body: `
func Build(names []string) *Doc {
	var items []Item
	for _, n := range names {
		items = append(items, Item{Name: n})
	}
	return &Doc{items: items}
}
`,
			funcName:       "Build",
			checkField:     "items",
			wantRetFresh:   true,
			wantFieldFresh: true,
			wantMutated:    false,
		},
		{
			name: "addr_of_value_field_escaping_without_doc_return_still_marks_inner_mutated",
			body: `
func Build() *Doc {
	doc := &Doc{}
	extInnerPtr = &doc.inner
	doc.inner.Val = 42
	return &Doc{}
}
`,
			funcName:       "Build",
			checkField:     "index",
			mutatedType:    "Inner",
			wantRetFresh:   true,
			wantFieldFresh: true,
			wantMutated:    true,
		},
		{
			name: "self_append_fresh_struct_elements_keeps_field_fresh",
			body: `
func Build(names []string) *Doc {
	doc := &Doc{}
	var items []Item
	for _, n := range names {
		items = append(items, Item{Name: n})
	}
	doc.items = items
	return doc
}
`,
			funcName:       "Build",
			checkField:     "items",
			wantRetFresh:   true,
			wantFieldFresh: true,
			wantMutated:    false,
		},
		{
			name: "self_append_escaped_local_slice_poisons_field_freshness",
			body: `
func Build(names []string) *Doc {
	doc := &Doc{}
	var items []Item
	for _, n := range names {
		items = append(items, Item{Name: n})
	}
	extItemSink = items
	doc.items = items
	return doc
}
`,
			funcName:       "Build",
			checkField:     "items",
			wantRetFresh:   true,
			wantFieldFresh: false,
			wantMutated:    false,
		},
		{
			name: "self_append_external_ptr_poisons_field_freshness",
			body: `
func Build() *Doc {
	doc := &Doc{}
	var ptrs []*Item
	ptrs = append(ptrs, extItemPtr)
	doc.ptrs = ptrs
	return doc
}
`,
			funcName:       "Build",
			checkField:     "ptrs",
			wantRetFresh:   true,
			wantFieldFresh: false,
			wantMutated:    false,
		},
		{
			name: "self_append_external_spread_poisons_field_freshness",
			body: `
func Build() *Doc {
	doc := &Doc{}
	var items []Item
	items = append(items, extItems...)
	doc.items = items
	return doc
}
`,
			funcName:       "Build",
			checkField:     "items",
			wantRetFresh:   true,
			wantFieldFresh: false,
			wantMutated:    false,
		},
		{
			name: "closure_hidden_nonfresh_field_assign_poisons_field",
			body: `
func Build() *Doc {
	doc := &Doc{}
	fill := func() {
		doc.index = extTopMap
	}
	fill()
	return doc
}
`,
			funcName:       "Build",
			checkField:     "index",
			wantRetFresh:   false,
			wantFieldFresh: false,
			wantMutated:    true,
		},
		{
			name: "closure_hidden_composite_lit_nonfresh_field_poisons_field",
			body: `
func Build() *Doc {
	mk := func() *Doc {
		return &Doc{index: extTopMap}
	}
	_ = mk
	return &Doc{index: map[string]map[string]int{}}
}
`,
			funcName:       "Build",
			checkField:     "index",
			wantRetFresh:   true,
			wantFieldFresh: false,
			wantMutated:    false,
		},
		{
			name: "closure_hidden_copy_into_slice_field_poisons_field",
			body: `
func Build() *Doc {
	doc := &Doc{ptrs: make([]*Item, 1)}
	fill := func() {
		copy(doc.ptrs, extItemPtrs)
	}
	fill()
	return doc
}
`,
			funcName:       "Build",
			checkField:     "ptrs",
			wantRetFresh:   false,
			wantFieldFresh: false,
			wantMutated:    true,
		},
		{
			name: "outer_range_assign_into_map_field_poisons_field",
			body: `
func Build(seq map[string]map[string]map[string]int) *Doc {
	doc := &Doc{}
	for _, doc.index = range seq {
	}
	return doc
}
`,
			funcName:       "Build",
			checkField:     "index",
			wantRetFresh:   false,
			wantFieldFresh: false,
			wantMutated:    false,
		},
		{
			name: "closure_range_assign_into_map_field_poisons_field",
			body: `
func Build(seq map[string]map[string]map[string]int) *Doc {
	doc := &Doc{}
	fill := func() {
		for _, doc.index = range seq {
		}
	}
	fill()
	return doc
}
`,
			funcName:       "Build",
			checkField:     "index",
			wantRetFresh:   false,
			wantFieldFresh: false,
			wantMutated:    true,
		},
		{
			name: "unsafe_slicedata_on_nonfresh_struct_field_marks_mutated",
			body: `
func Build(d *Doc) *Doc {
	_ = unsafe.SliceData(d.items)
	return &Doc{}
}
`,
			funcName:       "Build",
			checkField:     "items",
			mutatedType:    "Item",
			wantRetFresh:   true,
			wantFieldFresh: true,
			wantMutated:    true,
		},
		{
			name: "multi_func_cone_propagates_nonfresh_field_to_caller",
			body: `
func fillDirty(doc *Doc) {
	doc.ptrs = extItemPtrs
}

func Build() *Doc {
	doc := &Doc{}
	fillDirty(doc)
	return doc
}
`,
			funcName:       "Build",
			checkField:     "ptrs",
			wantRetFresh:   true,
			wantFieldFresh: false,
			wantMutated:    false,
		},
		{
			name: "goto_rejects_returns_fresh_allocation_and_field_freshness",
			body: `
func Build() *Doc {
	doc := &Doc{Count: 1}
	goto done
done:
	return doc
}
`,
			funcName:       "Build",
			checkField:     "index",
			wantRetFresh:   false,
			wantFieldFresh: false,
			wantMutated:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := typecheckTestPkg(t, "example.com/p", commonTypes+tc.body)
			idx := refconfine.BuildPkgIndex(p)
			pf := ComputePackageFreshConstructors(p, idx, nil)
			fd := findFuncDeclByName(p, tc.funcName)
			if fd == nil {
				t.Fatalf("missing FuncDecl %s", tc.funcName)
			}
			fVar := findStructFieldVar(p, "Doc", tc.checkField)
			if fVar == nil {
				t.Fatalf("missing field Doc.%s", tc.checkField)
			}
			if got := pf.ReturnsFreshAllocation(fd); got != tc.wantRetFresh {
				t.Errorf("ReturnsFreshAllocation(%s) = %v, want %v", tc.funcName, got, tc.wantRetFresh)
			}
			if got := pf.IsFieldFreshInCone(fd, fVar); got != tc.wantFieldFresh {
				t.Errorf("IsFieldFreshInCone(%s, Doc.%s) = %v, want %v", tc.funcName, tc.checkField, got, tc.wantFieldFresh)
			}
			cache := NewFreshLocalsCache(p, idx)
			mutated, _ := CollectMutatedStructTypes(p, idx, cache, nil, nil, nil, nil)
			targetName := tc.mutatedType
			if targetName == "" {
				targetName = "Doc"
			}
			targetRef := syntaxutil.TypeRef{Pkg: "example.com/p", Name: targetName}
			if gotMut := slices.Contains(mutated, targetRef); gotMut != tc.wantMutated {
				t.Errorf("CollectMutatedStructTypes contains %s = %v, want %v (mutated=%+v)", targetName, gotMut, tc.wantMutated, mutated)
			}
		})
	}
}

func TestRapidFreshStructConstructorAndFieldFreshnessOracle(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		useHelper := rapid.Bool().Draw(rt, "useHelper")
		writeTwoLevelFresh := rapid.Bool().Draw(rt, "writeTwoLevelFresh")
		injectNonFreshSubmap := rapid.Bool().Draw(rt, "injectNonFreshSubmap")
		readScalarCommaOk := rapid.Bool().Draw(rt, "readScalarCommaOk")
		escapeRefCommaOk := rapid.Bool().Draw(rt, "escapeRefCommaOk")
		escapeDoc := rapid.Bool().Draw(rt, "escapeDoc")
		appendFreshItem := rapid.Bool().Draw(rt, "appendFreshItem")
		escapeLocalItems := rapid.Bool().Draw(rt, "escapeLocalItems")
		escapeLocalItemsAfter := rapid.Bool().Draw(rt, "escapeLocalItemsAfter")
		closureNonFreshItems := rapid.Bool().Draw(rt, "closureNonFreshItems")
		writeSubmapAfterEscape := rapid.Bool().Draw(rt, "writeSubmapAfterEscape")
		writeDocAfterEscape := rapid.Bool().Draw(rt, "writeDocAfterEscape")

		src := `package p

type SubMap map[string]int

type Item struct {
	Label string
}

type Doc struct {
	Count int
	index map[string]SubMap
	items []Item
}

var (
	extSubMap SubMap
	extItems  []Item
	sinkMap   SubMap
	sinkItems []Item
	sinkDoc   *Doc
)
`
		buildSteps := "\tdoc := &Doc{index: map[string]SubMap{}}\n"
		helperBody := ""

		if injectNonFreshSubmap {
			buildSteps += "\tdoc.index[\"ext\"] = extSubMap\n"
		}
		if writeTwoLevelFresh {
			if useHelper {
				helperBody += "\td.index[\"k\"] = SubMap{}\n\td.index[\"k\"][\"v\"] = 1\n"
			} else {
				buildSteps += "\tdoc.index[\"k\"] = SubMap{}\n\tdoc.index[\"k\"][\"v\"] = 1\n"
			}
		}
		if readScalarCommaOk {
			buildSteps += "\tif prev, ok := doc.index[\"k\"][\"v\"]; ok { doc.Count += prev }\n"
		}
		if appendFreshItem {
			sliceBlock := "\tvar localItems []Item\n\tlocalItems = append(localItems, Item{Label: \"ok\"})\n"
			if escapeLocalItems {
				sliceBlock += "\tsinkItems = localItems\n"
			}
			if useHelper {
				helperBody += sliceBlock + "\td.items = localItems\n"
				if escapeLocalItemsAfter {
					helperBody += "\tsinkItems = localItems\n"
				}
			} else {
				buildSteps += sliceBlock + "\tdoc.items = localItems\n"
				if escapeLocalItemsAfter {
					buildSteps += "\tsinkItems = localItems\n"
				}
			}
		}
		if closureNonFreshItems {
			buildSteps += "\tleak := func() *Doc { return &Doc{items: extItems} }\n\t_ = leak\n"
		}
		if escapeRefCommaOk {
			buildSteps += "\tif sub, ok := doc.index[\"k\"]; ok { sinkMap = sub }\n"
		}
		if escapeDoc {
			buildSteps += "\tsinkDoc = doc\n"
		}
		if writeSubmapAfterEscape {
			buildSteps += "\tif doc.index[\"k\"] != nil { doc.index[\"k\"][\"after\"] = 88 }\n"
		}
		if writeDocAfterEscape {
			buildSteps += "\tdoc.Count = 77\n"
		}
		if useHelper {
			src += "func fill(d *Doc) {\n" + helperBody + "}\n\n"
			buildSteps += "\tfill(doc)\n"
		}
		src += "func Build() *Doc {\n" + buildSteps + "\treturn doc\n}\n"

		p := typecheckTestPkg(t, "example.com/p", src)
		idx := refconfine.BuildPkgIndex(p)
		pf := ComputePackageFreshConstructors(p, idx, nil)
		fd := findFuncDeclByName(p, "Build")
		indexField := findStructFieldVar(p, "Doc", "index")
		itemsField := findStructFieldVar(p, "Doc", "items")

		anyEscapedBeforeTail := escapeRefCommaOk || escapeDoc
		wantIndexFresh := !injectNonFreshSubmap
		wantItemsFresh := !(appendFreshItem && (escapeLocalItems || escapeLocalItemsAfter || (useHelper && anyEscapedBeforeTail) || (!useHelper && anyEscapedBeforeTail))) && !closureNonFreshItems
		wantRetFresh := !escapeRefCommaOk && !escapeDoc
		helperMutatesSubMap := useHelper && writeTwoLevelFresh
		helperMutatesDoc := useHelper && (writeTwoLevelFresh || appendFreshItem)
		twoLevelWriteOnNonFresh := (injectNonFreshSubmap && (writeTwoLevelFresh || writeSubmapAfterEscape)) ||
			(anyEscapedBeforeTail && (writeSubmapAfterEscape || helperMutatesSubMap))
		wantSubMapMutated := escapeRefCommaOk || twoLevelWriteOnNonFresh
		docInSimpleFresh := !(appendFreshItem && !useHelper)
		docWriteMutates := writeDocAfterEscape && (escapeDoc || (!docInSimpleFresh && escapeRefCommaOk))
		wantDocMutated := injectNonFreshSubmap || twoLevelWriteOnNonFresh || docWriteMutates || (anyEscapedBeforeTail && helperMutatesDoc)

		if got := pf.IsFieldFreshInCone(fd, indexField); got != wantIndexFresh {
			rt.Fatalf("IsFieldFreshInCone(index) = %v, want %v\nsrc:\n%s", got, wantIndexFresh, src)
		}
		if got := pf.IsFieldFreshInCone(fd, itemsField); got != wantItemsFresh {
			rt.Fatalf("IsFieldFreshInCone(items) = %v, want %v\nsrc:\n%s", got, wantItemsFresh, src)
		}
		if got := pf.ReturnsFreshAllocation(fd); got != wantRetFresh {
			rt.Fatalf("ReturnsFreshAllocation = %v, want %v\nsrc:\n%s", got, wantRetFresh, src)
		}
		cache := NewFreshLocalsCache(p, idx)
		mutated, _ := CollectMutatedStructTypes(p, idx, cache, nil, nil, nil, nil)
		docRef := syntaxutil.TypeRef{Pkg: "example.com/p", Name: "Doc"}
		subMapRef := syntaxutil.TypeRef{Pkg: "example.com/p", Name: "SubMap"}
		if gotMut := slices.Contains(mutated, docRef); gotMut != wantDocMutated {
			rt.Fatalf("MutatedStructTypes contains Doc = %v, want %v (mutated=%+v)\nsrc:\n%s", gotMut, wantDocMutated, mutated, src)
		}
		if gotSubMut := slices.Contains(mutated, subMapRef); gotSubMut != wantSubMapMutated {
			rt.Fatalf("MutatedStructTypes contains SubMap = %v, want %v (mutated=%+v)\nsrc:\n%s", gotSubMut, wantSubMapMutated, mutated, src)
		}
	})
}

func TestIntraParamReadOnlyRangeLenCapVsScalarAddrEscape(t *testing.T) {
	t.Parallel()

	t.Run("shared helper with len cap and scalar range preserves caller fresh slice field", func(t *testing.T) {
		p := typecheckTestPkg(t, "example.com/p", `package p

type SurfaceName struct {
	Surface string
	Name    string
}

type Knob struct {
	Name     string
	Surfaces []SurfaceName
}

type Verb struct {
	Name     string
	Surfaces []SurfaceName
	Knobs    []Knob
}

func matchSurface(declared []SurfaceName, target string) (string, bool) {
	if len(declared) == 0 || cap(declared) < 0 {
		return "default", true
	}
	for _, s := range declared {
		if s.Surface == target {
			return s.Name, true
		}
	}
	return "", false
}

func makeKnob(n string) *Knob {
	return &Knob{Name: n}
}

func makeVerb(n string) *Verb {
	v := &Verb{Name: n}
	kn := makeKnob("flag")
	v.Knobs = append(v.Knobs, *kn)
	return v
}

func Build() *Verb {
	v := makeVerb("run")
	_, _ = matchSurface(v.Surfaces, "cli")
	return v
}

func ExternalCaller(ext *Verb) bool {
	_, ok := matchSurface(ext.Surfaces, "mcp")
	return ok
}
`)
		idx := refconfine.BuildPkgIndex(p)
		pf := ComputePackageFreshConstructors(p, idx, nil)
		fd := findFuncDeclByName(p, "Build")
		knobsField := findStructFieldVar(p, "Verb", "Knobs")
		if !pf.ReturnsFreshAllocation(fd) {
			t.Fatalf("ReturnsFreshAllocation(Build) = false, want true")
		}
		if !pf.IsFieldFreshInCone(fd, knobsField) {
			t.Fatalf("IsFieldFreshInCone(Build, Verb.Knobs) = false, want true")
		}
		cache := NewFreshLocalsCache(p, idx)
		mutated, _ := CollectMutatedStructTypes(p, idx, cache, nil, nil, nil, nil)
		if slices.Contains(mutated, syntaxutil.TypeRef{Pkg: "example.com/p", Name: "Knob"}) {
			t.Fatalf("Knob unexpectedly marked in MutatedStructTypes: %+v", mutated)
		}
	})

	t.Run("helper taking address of scalar field or incdec rejects non-escaping param", func(t *testing.T) {
		for _, badHelper := range []string{
			`var leakedPtr *int
func touch(d *Doc) { leakedPtr = &d.Count }`,
			`func touch(d *Doc) { d.Count++ }`,
		} {
			p := typecheckTestPkg(t, "example.com/p", `package p

type Doc struct {
	Count int
	items []int
}

`+badHelper+`

func Build(ext *Doc) *Doc {
	touch(ext)
	d := &Doc{items: make([]int, 1)}
	touch(d)
	return d
}
`)
			idx := refconfine.BuildPkgIndex(p)
			pf := ComputePackageFreshConstructors(p, idx, nil)
			fd := findFuncDeclByName(p, "Build")
			if pf.ReturnsFreshAllocation(fd) {
				t.Fatalf("ReturnsFreshAllocation(Build) = true for escaping/mutating helper:\n%s", badHelper)
			}
		}
	})
}


