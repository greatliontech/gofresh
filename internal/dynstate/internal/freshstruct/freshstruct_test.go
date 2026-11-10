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
