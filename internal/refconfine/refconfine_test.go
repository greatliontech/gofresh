package refconfine

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
)

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }

func mustTypecheckPkg(t *testing.T, pkgPath string, src string) *packages.Package {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
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
		Importer: importerFunc(func(path string) (*types.Package, error) {
			if path == "unsafe" {
				return types.Unsafe, nil
			}
			if path == "sync" {
				syncPkg := types.NewPackage("sync", "sync")
				for _, spec := range []struct {
					name    string
					methods []string
				}{
					{"Once", []string{"Do"}},
					{"Cond", []string{"Signal", "Broadcast", "Wait"}},
					{"Mutex", []string{"Lock", "Unlock", "TryLock"}},
					{"RWMutex", []string{"Lock", "Unlock", "RLock", "RUnlock", "TryLock", "TryRLock"}},
				} {
					tn := types.NewTypeName(token.NoPos, syncPkg, spec.name, nil)
					named := types.NewNamed(tn, types.NewStruct(nil, nil), nil)
					for _, m := range spec.methods {
						recv := types.NewVar(token.NoPos, syncPkg, "r", types.NewPointer(named))
						sig := types.NewSignatureType(recv, nil, nil, nil, nil, false)
						named.AddMethod(types.NewFunc(token.NoPos, syncPkg, m, sig))
					}
					syncPkg.Scope().Insert(tn)
				}
				syncPkg.MarkComplete()
				return syncPkg, nil
			}
			return nil, fmt.Errorf("unexpected import %q", path)
		}),
	}).Check(pkgPath, fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatalf("types.Check: %v", err)
	}
	return &packages.Package{
		ID:        pkgPath,
		PkgPath:   pkgPath,
		Name:      tp.Name(),
		Fset:      fset,
		Syntax:    []*ast.File{file},
		Types:     tp,
		TypesInfo: info,
		Module:    &packages.Module{Path: "example.com/mod"},
	}
}

func TestVerifyReadOnlyRefConfinementUnsafeConstantBuiltins(t *testing.T) {
	pkg := mustTypecheckPkg(t, "example.com/unsafeconfine", `package unsafeconfine

import "unsafe"

type holder struct {
	items []int
	tag   int
}

var seed = holder{items: []int{1, 2, 3}, tag: 7}

const (
	seedSize  = unsafe.Sizeof(seed)
	seedAlign = unsafe.Alignof(seed)
	itemsOff  = unsafe.Offsetof(seed.items)
)

func Inspect() uintptr {
	h := &seed
	return unsafe.Sizeof(*h) + unsafe.Alignof(*h) + unsafe.Offsetof(h.items) + uintptr(len(h.items))
}
`)
	idx := BuildPkgIndex(pkg)
	seedObj, ok := pkg.Types.Scope().Lookup("seed").(*types.Var)
	if !ok || seedObj == nil {
		t.Fatal("missing seed var")
	}
	holderType, ok := pkg.Types.Scope().Lookup("holder").(*types.TypeName)
	if !ok || holderType == nil {
		t.Fatal("missing holder type")
	}
	holderNamed, ok := holderType.Type().(*types.Named)
	if !ok || holderNamed == nil {
		t.Fatal("holder is not a *types.Named")
	}
	cfg := Config{
		Index: idx,
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			id, ok := ast.Unparen(expr).(*ast.Ident)
			if ok && pkg.TypesInfo.Uses[id] == seedObj {
				return false, true
			}
			return false, false
		},
		SeedStructOrigin: func(named *types.Named) bool {
			return named != nil && named.Origin() == holderNamed.Origin()
		},
	}
	if !VerifyReadOnlyRefConfinement(pkg, cfg) {
		t.Fatal("VerifyReadOnlyRefConfinement rejected compile-time constant unsafe.{Sizeof,Alignof,Offsetof} on seed struct")
	}
	// Verify repeated query reusing idx produces identical result.
	if !VerifyReadOnlyRefConfinement(pkg, cfg) {
		t.Fatal("VerifyReadOnlyRefConfinement failed on second query with shared PkgIndex")
	}

	badPkg := mustTypecheckPkg(t, "example.com/unsafeconfinebad", `package unsafeconfinebad

import "unsafe"

type holder struct {
	items []int
}

var seed = holder{items: []int{1, 2, 3}}

func Leak() *int {
	return unsafe.SliceData(seed.items)
}
`)
	badSeedObj := badPkg.Types.Scope().Lookup("seed").(*types.Var)
	badHolderNamed := badPkg.Types.Scope().Lookup("holder").(*types.TypeName).Type().(*types.Named)
	if VerifyReadOnlyRefConfinement(badPkg, Config{
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			id, ok := ast.Unparen(expr).(*ast.Ident)
			if ok && badPkg.TypesInfo.Uses[id] == badSeedObj {
				return false, true
			}
			return false, false
		},
		SeedStructOrigin: func(named *types.Named) bool {
			return named != nil && named.Origin() == badHolderNamed.Origin()
		},
	}) {
		t.Fatal("VerifyReadOnlyRefConfinement unexpectedly accepted unsafe.SliceData on seed slice")
	}
}

func TestVerifyProtectedStructOriginConfinement(t *testing.T) {
	pkg := mustTypecheckPkg(t, "example.com/memo", `package memo

type entry struct {
	names []string
	count int
}

func buildEntry() *entry {
	e := &entry{names: []string{"a", "b"}}
	e.count = len(e.names)
	return e
}

func ReadFirst() string {
	e := buildEntry()
	if e == nil || len(e.names) == 0 {
		return ""
	}
	return e.names[0]
}
`)
	idx := BuildPkgIndex(pkg)
	entryNamed := pkg.Types.Scope().Lookup("entry").(*types.TypeName).Type().(*types.Named)
	buildFD := idx.PlainByName["buildEntry"][0]
	ok, reason := VerifyProtectedStructOriginConfinement(pkg, idx, buildFD, map[*types.Named]bool{entryNamed: true}, nil)
	if !ok {
		t.Fatalf("VerifyProtectedStructOriginConfinement(clean) = false (%s), want true", reason)
	}

	mutPkg := mustTypecheckPkg(t, "example.com/memomut", `package memomut

type entry struct {
	names []string
}

func buildEntry() *entry {
	return &entry{names: []string{"a"}}
}

func Mutate() {
	e := buildEntry()
	e.names[0] = "b"
}
`)
	mutIdx := BuildPkgIndex(mutPkg)
	mutEntryNamed := mutPkg.Types.Scope().Lookup("entry").(*types.TypeName).Type().(*types.Named)
	mutBuildFD := mutIdx.PlainByName["buildEntry"][0]
	if ok, _ := VerifyProtectedStructOriginConfinement(mutPkg, mutIdx, mutBuildFD, map[*types.Named]bool{mutEntryNamed: true}, nil); ok {
		t.Fatal("VerifyProtectedStructOriginConfinement unexpectedly accepted slice element write outside buildEntry")
	}
}

func TestTuplePredicatesTraverseElements(t *testing.T) {
	intType := types.Typ[types.Int]
	boolType := types.Typ[types.Bool]
	ptrIntType := types.NewPointer(intType)
	sigType := types.NewSignatureType(nil, nil, nil, nil, nil, false)

	sigBoolTuple := types.NewTuple(
		types.NewVar(0, nil, "fn", sigType),
		types.NewVar(0, nil, "ok", boolType),
	)
	if TypeHandsOutMutableReach(sigBoolTuple) {
		t.Fatal("TypeHandsOutMutableReach((func(), bool)) = true, want false")
	}
	if !TypeCarriesSignature(sigBoolTuple) {
		t.Fatal("TypeCarriesSignature((func(), bool)) = false, want true")
	}
	if TypeCarriesMutableRef(sigBoolTuple) {
		t.Fatal("TypeCarriesMutableRef((func(), bool)) = true, want false")
	}
	if !TypeContainsRefOrPointer(sigBoolTuple) {
		t.Fatal("TypeContainsRefOrPointer((func(), bool)) = false, want true")
	}
	if TypeReachesOnce(sigBoolTuple) {
		t.Fatal("TypeReachesOnce((func(), bool)) = true, want false")
	}

	ptrBoolTuple := types.NewTuple(
		types.NewVar(0, nil, "p", ptrIntType),
		types.NewVar(0, nil, "ok", boolType),
	)
	if !TypeHandsOutMutableReach(ptrBoolTuple) {
		t.Fatal("TypeHandsOutMutableReach((*int, bool)) = false, want true")
	}
	if !TypeCarriesMutableRef(ptrBoolTuple) {
		t.Fatal("TypeCarriesMutableRef((*int, bool)) = false, want true")
	}
	if !TypeContainsRefOrPointer(ptrBoolTuple) {
		t.Fatal("TypeContainsRefOrPointer((*int, bool)) = false, want true")
	}
	if !TypeContainsRefOrPointer(nil) {
		t.Fatal("TypeContainsRefOrPointer(nil) = false, want fail-closed true")
	}

	carrierStruct := types.NewStruct([]*types.Var{types.NewVar(0, nil, "fn", sigType)}, nil)
	sigKeyMap := types.NewMap(types.NewPointer(carrierStruct), intType)
	if !TypeCarriesSignature(sigKeyMap) {
		t.Fatal("TypeCarriesSignature(map[*carrier]int) = false, want true")
	}
	scalarMap := types.NewMap(types.Typ[types.String], intType)
	if TypeCarriesSignature(scalarMap) {
		t.Fatal("TypeCarriesSignature(map[string]int) = true, want false")
	}
}

func TestVerifyReadOnlyRefConfinementRejectsBuiltinNewExprSeedCopy(t *testing.T) {
	badPkg := mustTypecheckPkg(t, "example.com/newexprbad", `package newexprbad

type holder struct {
	items []int
}

var seed = holder{items: []int{1, 2, 3}}

func LeakViaNewExpr() *holder {
	return new(seed)
}
`)
	badSeedObj := badPkg.Types.Scope().Lookup("seed").(*types.Var)
	badHolderNamed := badPkg.Types.Scope().Lookup("holder").(*types.TypeName).Type().(*types.Named)
	if VerifyReadOnlyRefConfinement(badPkg, Config{
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			id, ok := ast.Unparen(expr).(*ast.Ident)
			if ok && badPkg.TypesInfo.Uses[id] == badSeedObj {
				return false, true
			}
			return false, false
		},
		SeedStructOrigin: func(named *types.Named) bool {
			return named != nil && named.Origin() == badHolderNamed.Origin()
		},
	}) {
		t.Fatal("VerifyReadOnlyRefConfinement unexpectedly accepted Go 1.26+ new(seed) escaping seed slice")
	}
}

func TestAuditedSynchronizationOnceFieldCountAndInPlaceSyncReceiver(t *testing.T) {
	syncPkg := types.NewPackage("sync", "sync")
	makeMethod := func(recvName, methodName string) *types.Func {
		tn := types.NewTypeName(token.NoPos, syncPkg, recvName, nil)
		named := types.NewNamed(tn, types.NewStruct(nil, nil), nil)
		recv := types.NewVar(token.NoPos, syncPkg, "r", types.NewPointer(named))
		sig := types.NewSignatureType(recv, nil, nil, nil, nil, false)
		fn := types.NewFunc(token.NoPos, syncPkg, methodName, sig)
		named.AddMethod(fn)
		return fn
	}
	for _, okCase := range [][2]string{
		{"Mutex", "Lock"},
		{"Mutex", "Unlock"},
		{"Mutex", "TryLock"},
		{"RWMutex", "Lock"},
		{"RWMutex", "Unlock"},
		{"RWMutex", "RLock"},
		{"RWMutex", "RUnlock"},
		{"RWMutex", "TryLock"},
		{"RWMutex", "TryRLock"},
		{"Cond", "Signal"},
		{"Cond", "Broadcast"},
	} {
		fn := makeMethod(okCase[0], okCase[1])
		if !AuditedSynchronization(true, fn) || AuditedSynchronization(false, fn) {
			t.Fatalf("AuditedSynchronization mismatch on %s.%s", okCase[0], okCase[1])
		}
	}
	for _, badCase := range [][2]string{
		{"Cond", "Wait"},
		{"Once", "Do"},
		{"RWMutex", "RLocker"},
		{"WaitGroup", "Wait"},
	} {
		if AuditedSynchronization(true, makeMethod(badCase[0], badCase[1])) {
			t.Fatalf("AuditedSynchronization(true, %s.%s) = true, want false", badCase[0], badCase[1])
		}
	}

	pkg := mustTypecheckPkg(t, "example.com/p", `package p

import "sync"

type subOnce struct{ once sync.Once }
type embeddedTwoOnce struct {
	subOnce
	once sync.Once
}
type ptrEmbeddedTwoOnce struct {
	*subOnce
	once sync.Once
}
type dupSubOnce struct{ a, b subOnce }
type arrayTwoOnce struct{ onces [2]sync.Once }
type arrayOneOnce struct{ onces [1]sync.Once }
type arrayZeroOnce struct{ onces [0]sync.Once }
type ptrSubOnce struct {
	sub  *subOnce
	once sync.Once
}
type mutexHolder struct{ mu sync.Mutex }
type condHolder struct{ cond sync.Cond }
type ptrCondHolder struct{ cond *sync.Cond }

func retMutexHolder() mutexHolder     { return mutexHolder{} }
func retPtrMutexHolder() *mutexHolder { return nil }
func byPtr(h *condHolder)             { h.cond.Signal() }
func byVal(h condHolder)              { h.cond.Signal() }
func ptrFieldByVal(h ptrCondHolder)   { h.cond.Signal() }
func derefCopy(h *condHolder)         { cp := *h; cp.cond.Signal() }
`)
	lookupType := func(name string) types.Type {
		obj := pkg.Types.Scope().Lookup(name)
		if obj == nil {
			t.Fatalf("missing type %s", name)
		}
		return obj.Type()
	}
	for _, tc := range []struct {
		name string
		typ  types.Type
		want int
	}{
		{"nil", nil, 0},
		{"subOnce", lookupType("subOnce"), 1},
		{"*subOnce", types.NewPointer(lookupType("subOnce")), 1},
		{"embeddedTwoOnce", lookupType("embeddedTwoOnce"), 2},
		{"ptrEmbeddedTwoOnce", lookupType("ptrEmbeddedTwoOnce"), 2},
		{"dupSubOnce", lookupType("dupSubOnce"), 2},
		{"arrayTwoOnce", lookupType("arrayTwoOnce"), 2},
		{"arrayOneOnce", lookupType("arrayOneOnce"), 1},
		{"arrayZeroOnce", lookupType("arrayZeroOnce"), 0},
		{"ptrSubOnce", lookupType("ptrSubOnce"), 1},
	} {
		if got := OnceFieldCount(tc.typ); got != tc.want {
			t.Fatalf("OnceFieldCount(%s) = %d, want %d", tc.name, got, tc.want)
		}
	}
	if !CallResultHandsOut(lookupType("mutexHolder")) {
		t.Fatal("CallResultHandsOut(mutexHolder) = false, want true")
	}
	if InstantiatedResultsHandOutNothing(true, pkg.Types.Scope().Lookup("retMutexHolder").Type()) {
		t.Fatal("InstantiatedResultsHandOutNothing(retMutexHolder) = true, want false")
	}
	if !TypeReachesSyncNoCopyByValue(lookupType("condHolder")) || TypeReachesSyncNoCopyByValue(types.NewPointer(lookupType("condHolder"))) || TypeReachesSyncNoCopyByValue(lookupType("ptrCondHolder")) {
		t.Fatal("TypeReachesSyncNoCopyByValue mismatch")
	}

	idx := BuildPkgIndex(pkg)
	callRecv := func(fnName string) ast.Expr {
		fd := idx.PlainByName[fnName][0]
		var recv ast.Expr
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if ce, ok := n.(*ast.CallExpr); ok {
				recv = ce.Fun.(*ast.SelectorExpr).X
			}
			return true
		})
		return recv
	}
	if !InPlaceSyncReceiver(pkg.TypesInfo, callRecv("byPtr")) {
		t.Fatal("InPlaceSyncReceiver(byPtr) = false, want true")
	}
	if InPlaceSyncReceiver(pkg.TypesInfo, callRecv("byVal")) {
		t.Fatal("InPlaceSyncReceiver(byVal) = true, want false")
	}
	if !InPlaceSyncReceiver(pkg.TypesInfo, callRecv("ptrFieldByVal")) {
		t.Fatal("InPlaceSyncReceiver(ptrFieldByVal) = false, want true")
	}
	if InPlaceSyncReceiver(pkg.TypesInfo, callRecv("derefCopy")) {
		t.Fatal("InPlaceSyncReceiver(derefCopy) = true, want false")
	}
}

func TestCallMutatesNamedStructContainer(t *testing.T) {
	pkg := mustTypecheckPkg(t, "example.com/cont", `package cont

type guarded struct {
	m  map[string]int
	sl []int
}

type unrelated struct {
	m  map[string]int
	sl []int
}

func MutDelete(g *guarded)              { delete(g.m, "k") }
func MutClearMap(g *guarded)            { clear(g.m) }
func MutClearSlice(g *guarded)          { clear(g.sl) }
func MutCopyDst(g *guarded, s []int)    { copy(g.sl, s) }
func ReadCopySrc(g *guarded, d []int)   { copy(d, g.sl) }
func ReadLen(g *guarded) int            { return len(g.m) + cap(g.sl) }
func MutOther(u *unrelated)             { delete(u.m, "k"); clear(u.sl) }
`)
	guardedNamed := pkg.Types.Scope().Lookup("guarded").(*types.TypeName).Type().(*types.Named)
	seeds := map[*types.Named]bool{guardedNamed: true}
	idx := BuildPkgIndex(pkg)

	checkFunc := func(name string) bool {
		fd := idx.PlainByName[name][0]
		found := false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if ce, ok := n.(*ast.CallExpr); ok && CallMutatesNamedStructContainer(pkg, ce, seeds) {
				found = true
			}
			return true
		})
		return found
	}

	for _, mutFn := range []string{"MutDelete", "MutClearMap", "MutClearSlice", "MutCopyDst"} {
		if !checkFunc(mutFn) {
			t.Errorf("%s: CallMutatesNamedStructContainer = false, want true", mutFn)
		}
	}
	for _, readFn := range []string{"ReadCopySrc", "ReadLen", "MutOther"} {
		if checkFunc(readFn) {
			t.Errorf("%s: CallMutatesNamedStructContainer = true, want false", readFn)
		}
	}
}

func TestVerifyReadOnlyRefConfinementPanicRecoverNamedResult(t *testing.T) {
	pkg := mustTypecheckPkg(t, "example.com/panicres", `package panicres

type holder struct {
	items []int
}

func LeakViaPanicRecover(h *holder) (out []int) {
	defer func() { _ = recover() }()
	out = h.items
	panic("done")
}
`)
	holderNamed := pkg.Types.Scope().Lookup("holder").(*types.TypeName).Type().(*types.Named)
	var gotClause string
	ok := VerifyReadOnlyRefConfinement(pkg, Config{
		SeedStructOrigin: func(n *types.Named) bool { return n == holderNamed },
		OnReject: func(_ token.Pos, clause string) {
			gotClause = clause
		},
	})
	if ok || gotClause != "tainted named result variable out" {
		t.Fatalf("VerifyReadOnlyRefConfinement = (%v, %q), want (false, %q)", ok, gotClause, "tainted named result variable out")
	}
}
