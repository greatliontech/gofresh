package propharness

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
)

const testBaseRapidSrc = `package rapid

import (
	"flag"
	"fmt"
	"hash/maphash"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

var flags struct {
	checks   int
	seed     uint64
	failfile string
	debugvis bool
}

var visTmpl = template.Must(template.New("rapid-vis").Parse("{{.Title}}"))

type visTmplData struct {
	Title string
	Style template.CSS
}

func envInt(key string, lookup func(string) (string, bool)) int {
	if v, ok := lookup(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 100
}

func init() {
	flags.checks = envInt("RAPID_CHECKS", os.LookupEnv)
	if v, ok := os.LookupEnv("RAPID_FAILFILE"); ok && v != "" {
		flags.failfile = v
	}
	flag.IntVar(&flags.checks, "rapid.checks", 100, "number of checks")
	flag.Uint64Var(&flags.seed, "rapid.seed", 0, "PRNG seed")
	flag.StringVar(&flags.failfile, "rapid.failfile", "", "failure file")
	flag.BoolVar(&flags.debugvis, "rapid.debugvis", false, "debug vis")
}

var strMapCache sync.Map
var genCache sync.Map

func cachedWords(k string) []string {
	if v, ok := strMapCache.Load(k); ok {
		return v.([]string)
	}
	res := []string{k}
	strMapCache.Store(k, res)
	return res
}

type TB interface {
	Helper()
	Logf(format string, args ...any)
	Errorf(format string, args ...any)
	Name() string
}

type tb TB

type T struct {
	tb
	state uint64
	fail  bool
}

func (t *T) Errorf(format string, args ...any) { t.fail = true }

type exampleTB struct{}

func (*exampleTB) Helper()                         {}
func (*exampleTB) Logf(format string, args ...any) {}
func (*exampleTB) Errorf(format string, args ...any) {}
func (*exampleTB) Name() string                    { return "example" }

func baseSeed() uint64 {
	if flags.seed != 0 {
		return flags.seed
	}
	var h maphash.Hash
	h.SetSeed(maphash.MakeSeed())
	return h.Sum64()
}

type generatorImpl[V any] interface {
	value(*T) V
}

type Generator[V any] struct {
	impl generatorImpl[V]
	gen  func(*T) V
}

func newGenerator[V any](impl generatorImpl[V]) *Generator[V] {
	return &Generator[V]{impl: impl}
}

type statelessIntGen struct{}

func (*statelessIntGen) value(t *T) int { return int(t.state >> 33) }

type statelessSliceGen struct {
	items []int
}

func (s *statelessSliceGen) value(t *T) int { return s.items[0] }
func (s *statelessSliceGen) maybeValue() (int, bool) {
	if len(s.items) == 0 {
		return 0, false
	}
	return s.items[0], true
}

var defaultIntGen = newGenerator[int](&statelessIntGen{})

func cachedSliceGen(k string) *Generator[int] {
	if v, ok := genCache.Load(k); ok {
		return v.(*Generator[int])
	}
	impl := &statelessSliceGen{items: []int{1, 2}}
	_ = impl.maybeValue
	g := newGenerator[int](impl)
	genCache.Store(k, g)
	return g
}

func (g *Generator[V]) Draw(t *T, label string) V {
	t.state = t.state*6364136223846793005 + 1442695040888963407
	if g.impl != nil {
		return g.impl.value(t)
	}
	return g.gen(t)
}

func (g *Generator[V]) Example(seed ...int) V {
	s := baseSeed()
	if len(seed) > 0 {
		s = uint64(seed[0])
	}
	return g.Draw(&T{tb: &exampleTB{}, state: s}, "example")
}

func ID[V any](v V) V { return v }

func Int() *Generator[int] {
	return &Generator[int]{gen: func(t *T) int { return int(t.state >> 33) }}
}

func Check(t *testing.T, prop func(*T)) {
	t.Helper()
	checkTB(t, prop)
}

func MakeCheck(prop func(*T)) func(*testing.T) {
	return func(t *testing.T) { checkTB(t, prop) }
}

var failReporter = reportFailure

func reportFailure(tb TB, seed uint64) {
	tb.Errorf("[rapid] failed (seed=%d)", seed)
}

func defaultFailFile(name string) string {
	if flags.failfile != "" {
		return flags.failfile
	}
	return filepath.Join("testdata", "rapid", name)
}

func saveFailFile(filename string, data []byte) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0o775); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".rapid-fail-*")
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return err
	}
	return os.Rename(f.Name(), filename)
}

func loadFailFiles(name string) {
	matches, err := filepath.Glob(defaultFailFile(name))
	if err != nil {
		return
	}
	for _, m := range matches {
		f, err := os.Open(m)
		if err == nil {
			_ = f.Close()
		}
	}
}

func saveVis(id int) {
	if flags.debugvis {
		f, err := os.Create(fmt.Sprintf("rapid-vis-%d.html", id))
		if err == nil {
			_ = visTmpl.Execute(f, &visTmplData{Title: "ok", Style: template.CSS("body{}")})
			_ = f.Close()
		}
	}
}

func runSynctest(fn func()) {
	ch := make(chan struct{})
	go func() {
		defer func() { ch <- struct{}{} }()
		synctest.Test(&testing.T{}, func(*testing.T) { fn() })
	}()
	<-ch
}

func checkTB(tb TB, prop func(*T)) {
	start := time.Now()
	seed := baseSeed()
	_ = defaultIntGen
	_ = cachedSliceGen("seed")
	_ = ID(1)
	_ = len(cachedWords("seed"))
	loadFailFiles(tb.Name())
	saveVis(0)
	runSynctest(func() {})
	t := &T{tb: tb, state: seed}
	for i := 0; i < flags.checks && !t.fail; i++ {
		prop(t)
	}
	if t.fail {
		_ = saveFailFile(defaultFailFile(tb.Name()), []byte(fmt.Sprintf("seed=%d", t.state)))
		failReporter(tb, t.state)
		return
	}
	_ = io.EOF
	tb.Logf("[rapid] OK, passed %v tests (%v)", flags.checks, time.Since(start))
}
`

func parseRapidPackage(t *testing.T, src string) *packages.Package {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "rapid.go", src, parser.ParseComments)
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
	conf := types.Config{Importer: importer.Default()}
	tp, err := conf.Check(ModulePath, fset, []*ast.File{f}, info)
	if err != nil {
		t.Fatalf("types.Check: %v", err)
	}
	imps := make(map[string]*packages.Package, len(tp.Imports()))
	for _, dep := range tp.Imports() {
		imps[dep.Path()] = &packages.Package{ID: dep.Path(), PkgPath: dep.Path(), Name: dep.Name(), Types: dep}
	}
	return &packages.Package{
		ID:        ModulePath,
		PkgPath:   ModulePath,
		Name:      "rapid",
		Fset:      fset,
		Syntax:    []*ast.File{f},
		Types:     tp,
		TypesInfo: info,
		Imports:   imps,
		Module: &packages.Module{
			Path:    ModulePath,
			Version: "v1.3.0",
		},
	}
}

func TestIsHarnessPathAndStructHasNoExportedFields(t *testing.T) {
	if !IsHarnessPath("pgregory.net/rapid") || IsHarnessPath("testing") || IsHarnessPath("pgregory.net/rapid/sub") {
		t.Fatal("IsHarnessPath misclassified package path")
	}
	if StructHasNoExportedFields(nil) {
		t.Fatal("StructHasNoExportedFields(nil) = true, want false")
	}
	pkg := types.NewPackage("pgregory.net/rapid", "rapid")
	closedSt := types.NewStruct([]*types.Var{
		types.NewField(token.NoPos, pkg, "x", types.Typ[types.Int], false),
	}, nil)
	openSt := types.NewStruct([]*types.Var{
		types.NewField(token.NoPos, pkg, "X", types.Typ[types.Int], false),
	}, nil)
	embOpenSt := types.NewStruct([]*types.Var{
		types.NewField(token.NoPos, pkg, "open", openSt, true),
	}, nil)
	if !StructHasNoExportedFields(closedSt) {
		t.Fatal("StructHasNoExportedFields(closedSt) = false, want true")
	}
	if StructHasNoExportedFields(openSt) {
		t.Fatal("StructHasNoExportedFields(openSt) = true, want false")
	}
	if StructHasNoExportedFields(embOpenSt) {
		t.Fatal("StructHasNoExportedFields(embOpenSt) = true, want false")
	}
}

func TestVerifyPackageGates(t *testing.T) {
	if VerifyPackage(false, nil) || VerifyPackage(true, nil) {
		t.Fatal("VerifyPackage accepted nil package")
	}
	cleanPkg := parseRapidPackage(t, testBaseRapidSrc)
	if ok, reason := VerifyPackageWithReason(true, cleanPkg); !ok {
		t.Fatalf("VerifyPackageWithReason(true, cleanPkg) = false (%s), want true", reason)
	}
	if VerifyPackage(false, cleanPkg) {
		t.Fatal("VerifyPackage(false, cleanPkg) = true, want false")
	}

	idx, errReason := buildHarnessPkgIndex(cleanPkg)
	if errReason != "" || idx == nil {
		t.Fatalf("buildHarnessPkgIndex failed: %s", errReason)
	}
	if fn := cleanPkg.Types.Scope().Lookup("envInt").(*types.Func); !idx.initOnly[fn] {
		t.Fatal("expected envInt to be indexed as initOnly")
	}

	rejections := []struct {
		name  string
		extra string
	}{
		{"forbidden_directive", "//go:linkname bad runtime.nanotime\n"},
		{"non_rapid_env", "func init() { _ = os.Getenv(\"HOME\") }\n"},
		{"env_outside_init", "func LeakEnv() string { return os.Getenv(\"RAPID_CHECKS\") }\n"},
		{"exported_global", "var ExportedGlobal int\n"},
		{"maphash_leaked_to_draw", "func badSeed() uint64 { var h maphash.Hash; h.SetSeed(maphash.MakeSeed()); return h.Sum64() }\nfunc BadInt() *Generator[int] { _ = badSeed(); return Int() }\n"},
		{"unjoined_goroutine", "func Spawn() { go func() {}() }\n"},
		{"syncmap_mutated_slice", "func badMut() { s := cachedWords(\"k\"); s[0] = \"mut\" }\n"},
		{"exported_any_return", "func AnyOut() any { return 1 }\n"},
		{"path_traversal_failfile", "func badOpen() { f, _ := os.Open(filepath.Join(flags.failfile, \"..\", \"x\")); if f != nil { _ = f.Close() } }\n"},
	}
	for _, tc := range rejections {
		t.Run(tc.name, func(t *testing.T) {
			badPkg := parseRapidPackage(t, testBaseRapidSrc+"\n"+tc.extra)
			if VerifyPackage(true, badPkg) {
				t.Fatalf("VerifyPackage accepted %s", tc.name)
			}
		})
	}

	t.Run("tampered_example_seed", func(t *testing.T) {
		badSrc := strings.Replace(testBaseRapidSrc, "if len(seed) > 0 {\n\t\ts = uint64(seed[0])\n\t}", "_ = seed", 1)
		if VerifyPackage(true, parseRapidPackage(t, badSrc)) {
			t.Fatal("VerifyPackage accepted Example ignoring seed")
		}
	})
}
