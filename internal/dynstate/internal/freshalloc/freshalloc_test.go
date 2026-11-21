package freshalloc

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func typecheckFreshAllocPkg(t *testing.T, pkgPath, src string) *packages.Package {
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

func TestFindMutexConfinedConstructorCaches(t *testing.T) {
	p := typecheckFreshAllocPkg(t, "example.com/p", `package p

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
	d := &Desc{}
	d.Name = rt.Name()
	cache[rt] = d
	return d
}
`)
	idx := refconfine.BuildPkgIndex(p)
	confined := FindMutexConfinedConstructorCaches(p, idx)
	if len(confined) != 1 {
		t.Fatalf("len(confined) = %d, want 1", len(confined))
	}
	cacheVar, _ := p.Types.Scope().Lookup("cache").(*types.Var)
	getDescFD := findFuncDeclByName(p, "GetDesc")
	if cacheVar == nil || getDescFD == nil || !confined[cacheVar][getDescFD] {
		t.Fatalf("expected confined[cache][GetDesc] == true, got %v", confined)
	}
	pf := ComputePackageFreshConstructors(p, idx, confined)
	if pf.ReturnsFreshAllocation(getDescFD) {
		t.Fatal("GetDesc returns cached *Desc on hits and must NOT report ReturnsFreshAllocation")
	}
	var fieldLHS *ast.SelectorExpr
	ast.Inspect(getDescFD.Body, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == 1 {
			if sel, ok := as.Lhs[0].(*ast.SelectorExpr); ok && sel.Sel.Name == "Name" {
				fieldLHS = sel
			}
		}
		return true
	})
	if fieldLHS == nil || !pf.IsFreshMutationTarget(getDescFD, fieldLHS) {
		t.Fatalf("expected d.Name write inside mutex-confined GetDesc to satisfy IsFreshMutationTarget, got %v", fieldLHS)
	}
}

func TestIntraParamReadOnlyRangeLenCapVsScalarAddrEscape(t *testing.T) {
	t.Parallel()

	t.Run("shared helper with len cap and scalar range preserves caller fresh slice field", func(t *testing.T) {
		p := typecheckFreshAllocPkg(t, "example.com/p", `package p

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
	})

	t.Run("helper taking address of scalar field or incdec or nested go rejects constructor", func(t *testing.T) {
		for _, badCase := range []string{
			`var leakedPtr *int
func touch(d *Doc) { leakedPtr = &d.Count }
func Build(ext *Doc) *Doc {
	touch(ext)
	d := &Doc{items: make([]int, 1)}
	touch(d)
	return d
}`,
			`func touch(d *Doc) { d.Count++ }
func Build(ext *Doc) *Doc {
	touch(ext)
	d := &Doc{items: make([]int, 1)}
	touch(d)
	return d
}`,
			`func Build(ext *Doc) *Doc {
	d := &Doc{items: make([]int, 1)}
	func() {
		go func() {}()
	}()
	return d
}`,
		} {
			p := typecheckFreshAllocPkg(t, "example.com/p", `package p

type Doc struct {
	Count int
	items []int
}

`+badCase)
			idx := refconfine.BuildPkgIndex(p)
			pf := ComputePackageFreshConstructors(p, idx, nil)
			fd := findFuncDeclByName(p, "Build")
			if pf.ReturnsFreshAllocation(fd) {
				t.Fatalf("ReturnsFreshAllocation(Build) = true for unsafe constructor:\n%s", badCase)
			}
		}
	})
}

func TestOwnedContainersAndReflectOriginScreening(t *testing.T) {
	p := typecheckFreshAllocPkg(t, "example.com/p", `package p

import "reflect"

type holder struct {
	owned   map[string]int
	tainted map[string]int
}

type ExportedHolder struct {
	owned map[string]int
}

func makeHolder(clean, tainted map[string]int) *holder {
	return &holder{
		owned:   clean,
		tainted: tainted,
	}
}

func BuildHolder(ext map[string]int) *holder {
	return makeHolder(map[string]int{"a": 1}, ext)
}

func NewExported() *ExportedHolder {
	return &ExportedHolder{owned: map[string]int{"a": 1}}
}

func makeFreshRV(rt reflect.Type) reflect.Value {
	return reflect.New(rt).Elem()
}

func StepFreshOnly(rt reflect.Type) int {
	rv := makeFreshRV(rt)
	return rv.Field(0).Len()
}
`)
	idx := refconfine.BuildPkgIndex(p)
	fc := flowir.NewPkgCache(p.TypesInfo, p.Types, p.Syntax)
	owned := ComputeFreshOwnedContainers(p, idx, fc, func(tp *types.Package) bool {
		return tp != nil && syntaxutil.IsTrueStdlibInPkg(p, tp.Path())
	})
	ownedField := findStructFieldVar(p, "holder", "owned")
	taintedField := findStructFieldVar(p, "holder", "tainted")
	expField := findStructFieldVar(p, "ExportedHolder", "owned")
	if !owned.FreshFields[ownedField] {
		t.Fatal("holder.owned should remain fresh-owned in ComputeFreshOwnedContainers")
	}
	if owned.FreshFields[taintedField] {
		t.Fatal("holder.tainted assigned from external param must NOT remain fresh-owned")
	}
	if owned.FreshFields[expField] {
		t.Fatal("ExportedHolder.owned on exported struct must NOT enter FreshFields")
	}

	ctors := CollectNonValueOfReflectConstructors(p, idx)
	makeFn, _ := p.Types.Scope().Lookup("makeFreshRV").(*types.Func)
	if makeFn == nil || !ctors[makeFn] {
		t.Fatalf("makeFreshRV missing from CollectNonValueOfReflectConstructors: %v", ctors)
	}
	if PkgCanStepUnexportedReflectField(p, idx) {
		t.Fatal("StepFreshOnly steps only reflect.New-rooted local RV; expected PkgCanStepUnexportedReflectField == false")
	}

	bad := typecheckFreshAllocPkg(t, "example.com/p", `package p

import "reflect"

func StepCallerValueOf(x any) reflect.Value {
	return reflect.ValueOf(x).Field(0)
}
`)
	badIdx := refconfine.BuildPkgIndex(bad)
	if !PkgCanStepUnexportedReflectField(bad, badIdx) {
		t.Fatal("StepCallerValueOf steps reflect.ValueOf(x).Field(0); expected PkgCanStepUnexportedReflectField == true")
	}

	// Fail-closed nil/missing-index boundary checks on ComputeFreshOwnedContainers
	// and CollectUnexportedStructCandFields.
	if got := CollectUnexportedStructCandFields(p, nil, nil, nil); len(got) != 0 {
		t.Fatalf("CollectUnexportedStructCandFields(..., nil keepType) = %v, want empty", got)
	}
	for _, failClosed := range []OwnedContainerSummary{
		ComputeFreshOwnedContainers(nil, idx, fc, nil),
		ComputeFreshOwnedContainers(p, nil, fc, nil),
		ComputeFreshOwnedContainers(p, idx, nil, nil),
		ComputeFreshOwnedContainers(p, idx, &flowir.PkgCache{}, nil),
	} {
		if len(failClosed.FreshVars) != 0 || len(failClosed.FreshFields) != 0 ||
			failClosed.IsFreshOwnedVal == nil || failClosed.IsFreshOwnedVal(&flowir.Value{IsNil: true, Type: types.Typ[types.Int]}) ||
			failClosed.IsCallerSafeIfaceVal == nil || failClosed.IsCallerSafeIfaceVal(&flowir.Value{IsNil: true}) {
			t.Fatalf("ComputeFreshOwnedContainers did not fail closed on nil input: %+v", failClosed)
		}
	}
	// Valid (p, idx, fc) with nil isTrueStdPkg must not panic on stdlib calls.
	stdCallPkg := typecheckFreshAllocPkg(t, "example.com/p", `package p
import "slices"
func CloneClean(xs []int) []int {
	local := []int{1, 2}
	return slices.Clone(local)
}
`)
	stdIdx := refconfine.BuildPkgIndex(stdCallPkg)
	stdFC := flowir.NewPkgCache(stdCallPkg.TypesInfo, stdCallPkg.Types, stdCallPkg.Syntax)
	stdOwned := ComputeFreshOwnedContainers(stdCallPkg, stdIdx, stdFC, nil)
	if len(stdOwned.FreshVars) != 1 {
		t.Fatalf("expected 1 FreshVar (local) with nil isTrueStdPkg without panic, got %v", stdOwned.FreshVars)
	}
}
