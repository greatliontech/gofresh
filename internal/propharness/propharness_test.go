package propharness

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"pgregory.net/rapid"

	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/trace"
)

const testRapidPkgPath = "pgregory.net/rapid"

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

var pureLookup [4]int

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
	for i := range pureLookup {
		pureLookup[i] = i + 1
	}
	flags.checks = envInt("RAPID_CHECKS", os.LookupEnv)
	if v, ok := os.LookupEnv("RAPID_FAILFILE"); ok && v != "" {
		flags.failfile = v
	}
	flag.IntVar(&flags.checks, "rapid.checks", 100, "number of checks")
	flag.Uint64Var(&flags.seed, "rapid.seed", 0, "PRNG seed")
	flag.StringVar(&flags.failfile, "rapid.failfile", "", "failure file")
	flag.BoolVar(&flags.debugvis, "rapid.debugvis", false, "debug vis")
}

func PureTableVal() int { return pureLookup[0] }

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

func (*exampleTB) Helper()                           {}
func (*exampleTB) Logf(format string, args ...any)   {}
func (*exampleTB) Errorf(format string, args ...any) {}
func (*exampleTB) Name() string                      { return "example" }

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

const testPropcheckSrc = `package propcheck

import (
	"flag"
	"fmt"
	"hash/maphash"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

var cfg struct {
	runs     int
	seed     uint64
	failfile string
}

func init() {
	if v, ok := os.LookupEnv("PROPCHECK_FAILFILE"); ok && v != "" {
		cfg.failfile = v
	}
	flag.IntVar(&cfg.runs, "propcheck.runs", 50, "runs")
	flag.Uint64Var(&cfg.seed, "propcheck.seed", 0, "seed")
	flag.StringVar(&cfg.failfile, "propcheck.failfile", "", "failfile")
}

type Logger interface {
	Helper()
	Logf(format string, args ...any)
	Fatalf(format string, args ...any)
	Name() string
}

type Context struct {
	log   Logger
	state uint64
}

func (c *Context) next() uint64 {
	c.state = c.state*2862933555777941757 + 3037000493
	return c.state
}

type noopLogger struct{}

func (*noopLogger) Helper()                           {}
func (*noopLogger) Logf(format string, args ...any)   {}
func (*noopLogger) Fatalf(format string, args ...any) {}
func (*noopLogger) Name() string                      { return "sample" }

type Arb[V any] struct {
	draw func(*Context) V
}

func (a *Arb[V]) Take(c *Context) V {
	return a.draw(c)
}

func (a *Arb[V]) Sample(seed ...int) V {
	var s uint64
	if len(seed) > 0 {
		s = uint64(seed[0])
	} else {
		s = freshSeed()
	}
	return a.Take(&Context{log: &noopLogger{}, state: s})
}

func Int64() *Arb[int64] {
	return &Arb[int64]{draw: func(c *Context) int64 { return int64(c.next() >> 1) }}
}

func Synth[V any]() *Arb[V] {
	return &Arb[V]{draw: func(c *Context) V {
		rt := reflect.TypeOf((*V)(nil)).Elem()
		rv := reflect.New(rt).Elem()
		if rv.Kind() == reflect.Struct {
			for i := 0; i < rv.NumField(); i++ {
				f := rv.Field(i)
				if f.CanSet() && f.Kind() == reflect.Int {
					f.SetInt(int64(c.next() & 0xff))
				}
			}
		}
		return rv.Interface().(V)
	}}
}

func freshSeed() uint64 {
	if cfg.seed != 0 {
		return cfg.seed
	}
	var h maphash.Hash
	h.SetSeed(maphash.MakeSeed())
	return h.Sum64()
}

func failPath(name string) string {
	if cfg.failfile != "" {
		return cfg.failfile
	}
	return filepath.Join("testdata", "propcheck", name)
}

func persistFail(name string, seed uint64) {
	p := failPath(name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".propcheck-*")
	if err != nil {
		return
	}
	_, _ = f.WriteString(fmt.Sprintf("%d", seed))
	_ = f.Close()
	_ = os.Rename(f.Name(), p)
}

func runVerify(l Logger, fn func(*Context)) {
	l.Helper()
	start := time.Now()
	n := cfg.runs
	if ` + "testing." + `Short() {
		n /= 2
	}
	s := freshSeed()
	c := &Context{log: l, state: s}
	for i := 0; i < n; i++ {
		fn(c)
	}
	if s == 1 {
		persistFail(l.Name(), s)
	}
	l.Logf("[propcheck] ok (%v)", time.Since(start))
}

func Verify(l Logger, fn func(*Context)) {
	runVerify(l, fn)
}

func BuildVerify(fn func(*Context)) func(*testing.T) {
	return func(t *testing.T) { runVerify(t, fn) }
}
`

func parseHarnessPackage(t *testing.T, pkgPath, pkgName, fileName, src string, withModule bool) *packages.Package {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, fileName, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile(%s): %v", fileName, err)
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
	tp, err := conf.Check(pkgPath, fset, []*ast.File{f}, info)
	if err != nil {
		t.Fatalf("types.Check(%s): %v", pkgPath, err)
	}
	pkg := &packages.Package{
		ID:        pkgPath,
		PkgPath:   pkgPath,
		Name:      pkgName,
		Fset:      fset,
		Syntax:    []*ast.File{f},
		Types:     tp,
		TypesInfo: info,
	}
	if withModule {
		imps := make(map[string]*packages.Package, len(tp.Imports()))
		for _, dep := range tp.Imports() {
			imps[dep.Path()] = &packages.Package{ID: dep.Path(), PkgPath: dep.Path(), Name: dep.Name(), Types: dep}
		}
		pkg.Imports = imps
		pkg.Module = &packages.Module{Path: pkgPath, Version: "v1.0.0"}
	}
	return pkg
}

func parseRapidPackage(t *testing.T, src string) *packages.Package {
	return parseHarnessPackage(t, testRapidPkgPath, "rapid", "rapid.go", src, true)
}

func TestStructHasNoExportedFieldsAndScreening(t *testing.T) {
	if !MayBeHarnessPkgPath("pgregory.net/rapid") || !MayBeHarnessPkgPath("example.com/propcheck/sub") ||
		MayBeHarnessPkgPath("testing") || MayBeHarnessPkgPath("fmt") || MayBeHarnessPkgPath("main") || MayBeHarnessPkgPath("") {
		t.Fatal("MayBeHarnessPkgPath misclassified package path")
	}
	if !MayBeHarnessImports("example.com/propcheck", []string{"testing", "reflect", "time"}) {
		t.Fatal("MayBeHarnessImports rejected clean stdlib + testing import set")
	}
	if MayBeHarnessImports("example.com/propcheck", []string{"reflect", "time"}) {
		t.Fatal("MayBeHarnessImports accepted package missing testing import")
	}
	if MayBeHarnessImports("example.com/propcheck", []string{"testing", "unsafe"}) ||
		MayBeHarnessImports("example.com/propcheck", []string{"testing", "net/http"}) {
		t.Fatal("MayBeHarnessImports accepted disallowed import")
	}
	if StructHasNoExportedFields(nil) {
		t.Fatal("StructHasNoExportedFields(nil) = true, want false")
	}
	pkg := types.NewPackage("example.com/propcheck", "propcheck")
	closedSt := types.NewStruct([]*types.Var{
		types.NewField(token.NoPos, pkg, "x", types.Typ[types.Int], false),
	}, nil)
	openSt := types.NewStruct([]*types.Var{
		types.NewField(token.NoPos, pkg, "X", types.Typ[types.Int], false),
	}, nil)
	embOpenSt := types.NewStruct([]*types.Var{
		types.NewField(token.NoPos, pkg, "open", openSt, true),
	}, nil)
	if !StructHasNoExportedFields(closedSt) || StructHasNoExportedFields(openSt) || StructHasNoExportedFields(embOpenSt) {
		t.Fatal("StructHasNoExportedFields misclassified struct visibility")
	}
}

func TestVerifyPropcheckSyntheticHarnessAndPinnedCache(t *testing.T) {
	ResetPinnedMemoForTest()
	t.Cleanup(ResetPinnedMemoForTest)

	// Synthetic in-memory package with Module == nil and Imports == nil (types.Imports() only).
	pkg := parseHarnessPackage(t, "example.com/propcheck", "propcheck", "propcheck.go", testPropcheckSrc, false)

	screened, reason := ScreenPackage(true, pkg)
	if reason != "" || screened == nil {
		t.Fatalf("ScreenPackage(propcheck) failed: %s", reason)
	}

	rec := trace.NewRecorder()
	ctx := trace.WithSink(t.Context(), rec)
	vp, reason := VerifyPackageWithIndex(ctx, trace.DomainClosure, true, pkg, nil)
	if reason != "" || vp == nil {
		t.Fatalf("VerifyPackageWithIndex(propcheck) = nil (%s), want verified", reason)
	}
	if vp.PkgPath != "example.com/propcheck" || vp.PkgName != "propcheck" || vp.PrimaryDriver != "Verify" {
		t.Fatalf("unexpected VerifiedPackage header: %+v", vp)
	}
	assertBoolMapEq(t, "HandleStructs", vp.HandleStructs, map[string]bool{"Context": true})
	assertBoolMapEq(t, "HandleIfaces", vp.HandleIfaces, map[string]bool{"Logger": true})
	assertBoolMapEq(t, "DriverFuncs", vp.DriverFuncs, map[string]bool{"Verify": true})
	assertBoolMapEq(t, "WrapperFactoryFuncs", vp.WrapperFactoryFuncs, map[string]bool{"BuildVerify": true})
	assertBoolMapEq(t, "GeneratorTypes", vp.GeneratorTypes, map[string]bool{"Arb": true})
	assertBoolMapEq(t, "ReflectSynthFuncs", vp.ReflectSynthFuncs, map[string]bool{"Synth": true})
	wantSeeded := map[MethodKey]bool{{Recv: "Arb", Method: "Sample"}: true}
	if !maps.Equal(vp.SeededSampleMethods, wantSeeded) {
		t.Fatalf("SeededSampleMethods = %v, want %v", vp.SeededSampleMethods, wantSeeded)
	}
	events := rec.ByName("propharness.verify.done")
	if len(events) != 1 || events[0].Target != "example.com/propcheck" {
		t.Fatalf("expected 1 propharness.verify.done trace event, got %v", events)
	}

	// Verify shared pinned memo caches both positive and negative verdicts.
	loads := 0
	keyPos := BuildPinnedMemoKey("ssa", "tc", "pol", "example.com/propcheck@v1.0.0", nil, nil, []string{"propcheck.go"})
	for range 2 {
		got := VerifyPackagePinnedCached(ctx, trace.DomainClosure, true, keyPos, func() ([]*packages.Package, error) {
			loads++
			return []*packages.Package{pkg}, nil
		})
		if got == nil || got.PrimaryDriver != "Verify" {
			t.Fatalf("VerifyPackagePinnedCached positive = %+v, want Verify", got)
		}
	}
	if loads != 1 {
		t.Fatalf("expected 1 load for positive cached key, got %d", loads)
	}

	badPkg := parseHarnessPackage(t, "example.com/propcheck", "propcheck", "propcheck.go", testPropcheckSrc+"\nvar ExportedBad int\n", false)
	negLoads := 0
	keyNeg := BuildPinnedMemoKey("ssa", "tc", "pol", "example.com/propcheck@v1.0.1", nil, nil, []string{"propcheck.go"})
	for range 2 {
		got := VerifyPackagePinnedCached(ctx, trace.DomainClosure, true, keyNeg, func() ([]*packages.Package, error) {
			negLoads++
			return []*packages.Package{badPkg}, nil
		})
		if got != nil {
			t.Fatalf("VerifyPackagePinnedCached negative = %+v, want nil", got)
		}
	}
	if negLoads != 1 {
		t.Fatalf("expected 1 load for negative cached key, got %d", negLoads)
	}
}

func TestVerifyPackageGatesAndCausalRefusals(t *testing.T) {
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

	rejections := []struct {
		name       string
		pkgPath    string
		pkgName    string
		base       string
		extra      string
		wantReason string
	}{
		{
			name:       "forbidden_directive",
			pkgPath:    testRapidPkgPath,
			pkgName:    "rapid",
			base:       testBaseRapidSrc,
			extra:      "//go:linkname bad runtime.nanotime\n",
			wantReason: "forbidden directive",
		},
		{
			name:       "go_embed_directive",
			pkgPath:    testRapidPkgPath,
			pkgName:    "rapid",
			base:       testBaseRapidSrc,
			extra:      "//go:embed rapid.go\nvar embedded string\n",
			wantReason: "forbidden directive",
		},
		{
			name:       "mismatched_env_namespace_rapid_in_propcheck",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       testPropcheckSrc,
			extra:      "func init() { _, _ = os.LookupEnv(\"RAPID_CHECKS\") }\n",
			wantReason: "want PROPCHECK_",
		},
		{
			name:       "mismatched_flag_namespace_rapid_in_propcheck",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       testPropcheckSrc,
			extra:      "func init() { flag.IntVar(&cfg.runs, \"rapid.runs\", 10, \"bad\") }\n",
			wantReason: "want propcheck.",
		},
		{
			name:       "mismatched_failfile_subdir_rapid_in_propcheck",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       strings.Replace(testPropcheckSrc, `filepath.Join("testdata", "propcheck", name)`, `filepath.Join("testdata", "rapid", name)`, 1),
			wantReason: "os.MkdirAll",
		},
		{
			name:       "exported_helper_reading_time_now",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       testPropcheckSrc,
			extra:      "func NowNano() int64 { return time.Now().UnixNano() }\n",
			wantReason: "clock/fs/template reaches disallowed exported symbol NowNano",
		},
		{
			name:       "exported_helper_reading_os_getpid",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       testPropcheckSrc,
			extra:      "func CurPID() int { return os.Getpid() }\n",
			wantReason: "clock/fs/template reaches disallowed exported symbol CurPID",
		},
		{
			name:       "exported_helper_reading_testing_short_without_handle",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       testPropcheckSrc,
			extra:      "func IsShortMode() bool { return " + "testing." + "Short() }\n",
			wantReason: "testing config reaches disallowed exported symbol IsShortMode",
		},
		{
			name:       "exported_helper_reading_env_flag_global",
			pkgPath:    testRapidPkgPath,
			pkgName:    "rapid",
			base:       testBaseRapidSrc,
			extra:      "func ConfiguredChecks() int { return flags.checks }\n",
			wantReason: "env/flag global reaches disallowed exported symbol ConfiguredChecks",
		},
		{
			name:       "generator_closure_reading_env_flag_global",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       testPropcheckSrc,
			extra:      "func RunsGen() *Arb[int] { return &Arb[int]{draw: func(c *Context) int { _ = c; return cfg.runs }} }\n",
			wantReason: "env/flag global reaches disallowed exported symbol RunsGen",
		},
		{
			name:       "sealed_handle_callable_with_result_reading_env_flag_global",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       strings.Replace(testPropcheckSrc, "return a.draw(c)", "_ = cfg.runs\n\treturn a.draw(c)", 1),
			extra:      "",
			wantReason: "env/flag global reaches disallowed exported symbol Take",
		},
		{
			name:       "seeded_sample_reaching_non_overridden_env_flag_global",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       strings.Replace(testPropcheckSrc, "return a.Take(", "_ = cfg.runs\n\treturn a.Take(", 1),
			extra:      "",
			wantReason: "env/flag global reaches disallowed exported symbol Sample",
		},
		{
			name:       "named_result_leaking_bool_flag",
			pkgPath:    testRapidPkgPath,
			pkgName:    "rapid",
			base:       testBaseRapidSrc,
			extra:      "func LeakedFlag() (out string) {\n\tif flags.debugvis {\n\t\tout = \"on\"\n\t}\n\treturn\n}\n",
			wantReason: "env/flag global reaches disallowed exported symbol LeakedFlag",
		},
		{
			name:       "loop_carried_string_leaking_bool_flag",
			pkgPath:    testRapidPkgPath,
			pkgName:    "rapid",
			base:       testBaseRapidSrc,
			extra:      "func LoopFlag() string {\n\tvar msg string\n\tfor i := 0; i < 2; i++ {\n\t\tif i == 1 && msg != \"\" {\n\t\t\treturn msg\n\t\t}\n\t\tif flags.debugvis {\n\t\t\tmsg = \"on\"\n\t\t}\n\t}\n\treturn \"\"\n}\n",
			wantReason: "env/flag global reaches disallowed exported symbol LoopFlag",
		},
		{
			name:    "handle_helper_method_mutating_state_on_bool_flag",
			pkgPath: testRapidPkgPath,
			pkgName: "rapid",
			base: strings.Replace(
				strings.Replace(
					testBaseRapidSrc,
					"fail  bool",
					"fail  bool\n\tdbg   bool",
					1,
				),
				"return g.Draw(&T{tb: &exampleTB{}, state: s}, \"example\")",
				"h := newFlaggedT(s, flags.debugvis)\n\th.Helper()\n\treturn g.Draw(h, \"example\")",
				1,
			),
			extra:      "func newFlaggedT(s uint64, dbg bool) *T { return &T{tb: &exampleTB{}, state: s, dbg: dbg} }\nfunc (t *T) Helper() {\n\tif t.dbg {\n\t\tt.state += 999\n\t}\n}\n",
			wantReason: "env/flag global reaches disallowed exported symbol Example",
		},
		{
			name:    "handle_output_method_returning_scalar_on_bool_flag",
			pkgPath: testRapidPkgPath,
			pkgName: "rapid",
			base: strings.Replace(
				strings.Replace(
					testBaseRapidSrc,
					"fail  bool",
					"fail  bool\n\tdbg   bool",
					1,
				),
				"return g.Draw(&T{tb: &exampleTB{}, state: s}, \"example\")",
				"h := newFlaggedT(s, flags.debugvis)\n\treturn g.Draw(h, \"example\")",
				1,
			),
			extra:      "func newFlaggedT(s uint64, dbg bool) *T { return &T{tb: &exampleTB{}, state: s, dbg: dbg} }\nfunc (t *T) Output() int {\n\tif t.dbg {\n\t\treturn 1\n\t}\n\treturn 0\n}\n",
			wantReason: "env/flag global reaches disallowed exported symbol Example",
		},
		{
			name:       "chan_recv_leaking_bool_flag",
			pkgPath:    testRapidPkgPath,
			pkgName:    "rapid",
			base:       testBaseRapidSrc,
			extra:      "func LeakViaChan() int {\n\tch := make(chan int, 1)\n\tch <- 1\n\tif flags.debugvis {\n\t\t<-ch\n\t}\n\tselect {\n\tcase v := <-ch:\n\t\treturn v\n\tdefault:\n\t\treturn 0\n\t}\n}\n",
			wantReason: "env/flag global reaches disallowed exported symbol LeakViaChan",
		},
		{
			name:       "log_new_buffer_leaking_bool_flag",
			pkgPath:    testRapidPkgPath,
			pkgName:    "rapid",
			base:       strings.Replace(testBaseRapidSrc, "\t\"io\"\n", "\t\"bytes\"\n\t\"io\"\n\t\"log\"\n", 1),
			extra:      "func LeakViaLogger() string {\n\tvar buf bytes.Buffer\n\tif flags.debugvis {\n\t\tlog.New(&buf, \"\", 0).Print(\"on\")\n\t}\n\treturn buf.String()\n}\n",
			wantReason: "env/flag global reaches disallowed exported symbol LeakViaLogger",
		},
		{
			name:    "tb_errorf_on_bool_flag",
			pkgPath: testRapidPkgPath,
			pkgName: "rapid",
			base: strings.Replace(
				strings.Replace(
					testBaseRapidSrc,
					"fail  bool",
					"fail  bool\n\tdbg   bool",
					1,
				),
				"return g.Draw(&T{tb: &exampleTB{}, state: s}, \"example\")",
				"h := newFlaggedT(s, flags.debugvis)\n\tif h.dbg {\n\t\th.tb.Errorf(\"boom\")\n\t}\n\treturn g.Draw(h, \"example\")",
				1,
			),
			extra:      "func newFlaggedT(s uint64, dbg bool) *T { return &T{tb: &exampleTB{}, state: s, dbg: dbg} }\n",
			wantReason: "env/flag global reaches disallowed exported symbol Example",
		},
		{
			name:       "handle_tb_buffer_leaking_bool_flag",
			pkgPath:    testRapidPkgPath,
			pkgName:    "rapid",
			base:       testBaseRapidSrc,
			extra:      "type bufTB struct { out string }\nfunc (b *bufTB) Helper() {}\nfunc (b *bufTB) Logf(format string, args ...any) { b.out = format }\nfunc (b *bufTB) Errorf(format string, args ...any) {}\nfunc (b *bufTB) Name() string { return \"\" }\nfunc LeakViaHandleTB() string {\n\tb := &bufTB{}\n\th := &T{tb: b}\n\tif flags.debugvis {\n\t\th.tb.Logf(\"on\")\n\t}\n\treturn b.out\n}\n",
			wantReason: "env/flag global reaches disallowed exported symbol LeakViaHandleTB",
		},
		{
			name:       "tb_param_buffer_leaking_bool_flag",
			pkgPath:    testRapidPkgPath,
			pkgName:    "rapid",
			base:       testBaseRapidSrc,
			extra:      "type bufTB struct { out string }\nfunc (b *bufTB) Helper() {}\nfunc (b *bufTB) Logf(format string, args ...any) { b.out = format }\nfunc (b *bufTB) Errorf(format string, args ...any) {}\nfunc (b *bufTB) Name() string { return \"\" }\nfunc logViaParam(l TB) {\n\tif flags.debugvis {\n\t\tl.Logf(\"on\")\n\t}\n}\nfunc LeakViaParamTB() string {\n\tb := &bufTB{}\n\tlogViaParam(b)\n\treturn b.out\n}\n",
			wantReason: "env/flag global reaches disallowed exported symbol LeakViaParamTB",
		},
		{
			name:       "embedded_testing_tb_buffer_leaking_bool_flag",
			pkgPath:    testRapidPkgPath,
			pkgName:    "rapid",
			base:       testBaseRapidSrc,
			extra:      "type embedTB struct { testing.TB; out string }\nfunc (e *embedTB) Logf(format string, args ...any) { e.out = format }\nfunc LeakViaTestingTB() string {\n\te := &embedTB{}\n\tvar tb testing.TB = e\n\th := &T{tb: tb}\n\tif flags.debugvis {\n\t\th.tb.Logf(\"on\")\n\t}\n\treturn e.out\n}\n",
			wantReason: "env/flag global reaches disallowed exported symbol LeakViaTestingTB",
		},
		{
			name:    "mutating_stringer_leaking_bool_flag",
			pkgPath: testRapidPkgPath,
			pkgName: "rapid",
			base: strings.Replace(
				strings.Replace(
					testBaseRapidSrc,
					"fail  bool",
					"fail  bool\n\tdbg   bool",
					1,
				),
				"return g.Draw(&T{tb: &exampleTB{}, state: s}, \"example\")",
				"m := &mutStringer{}\n\th := newFlaggedT(s, flags.debugvis)\n\tif h.dbg {\n\t\th.tb.Logf(\"%s\", m)\n\t}\n\treturn g.Draw(h, \"example\")",
				1,
			),
			extra:      "type mutStringer struct { n int }\nfunc (m *mutStringer) String() string { m.n++; return \"\" }\nfunc newFlaggedT(s uint64, dbg bool) *T { return &T{tb: &exampleTB{}, state: s, dbg: dbg} }\n",
			wantReason: "env/flag global reaches disallowed exported symbol Example",
		},
		{
			name:    "buf_stringer_method_leaking_bool_flag",
			pkgPath: testRapidPkgPath,
			pkgName: "rapid",
			base: strings.Replace(
				strings.Replace(
					strings.Replace(
						testBaseRapidSrc,
						"\t\"io\"\n",
						"\t\"io\"\n\t\"strings\"\n",
						1,
					),
					"fail  bool",
					"fail  bool\n\tdbg   bool",
					1,
				),
				"return g.Draw(&T{tb: &exampleTB{}, state: s}, \"example\")",
				"m := bufStringer{buf: make([]byte, 2)}\n\th := newFlaggedT(s, flags.debugvis)\n\tif h.dbg {\n\t\th.tb.Logf(\"%s\", m)\n\t}\n\treturn g.Draw(h, \"example\")",
				1,
			),
			extra:      "type bufStringer struct { buf []byte }\nfunc (m bufStringer) String() string { _, _ = strings.NewReader(\"on\").Read(m.buf); return \"\" }\nfunc newFlaggedT(s uint64, dbg bool) *T { return &T{tb: &exampleTB{}, state: s, dbg: dbg} }\n",
			wantReason: "env/flag global reaches disallowed exported symbol Example",
		},
		{
			name:    "strconv_append_stringer_leaking_bool_flag",
			pkgPath: testRapidPkgPath,
			pkgName: "rapid",
			base: strings.Replace(
				strings.Replace(
					testBaseRapidSrc,
					"fail  bool",
					"fail  bool\n\tdbg   bool",
					1,
				),
				"return g.Draw(&T{tb: &exampleTB{}, state: s}, \"example\")",
				"m := appendStringer{buf: make([]byte, 0, 8)}\n\th := newFlaggedT(s, flags.debugvis)\n\tif h.dbg {\n\t\th.tb.Logf(\"%s\", m)\n\t}\n\treturn g.Draw(h, \"example\")",
				1,
			),
			extra:      "type appendStringer struct { buf []byte }\nfunc (m appendStringer) String() string { _ = strconv.AppendInt(m.buf, 1, 10); return \"\" }\nfunc newFlaggedT(s uint64, dbg bool) *T { return &T{tb: &exampleTB{}, state: s, dbg: dbg} }\n",
			wantReason: "env/flag global reaches disallowed exported symbol Example",
		},
		{
			name:    "once_memo_stringer_field_read_leaking_bool_flag",
			pkgPath: testRapidPkgPath,
			pkgName: "rapid",
			base: strings.Replace(
				strings.Replace(
					testBaseRapidSrc,
					"fail  bool",
					"fail  bool\n\tdbg   bool",
					1,
				),
				"return g.Draw(&T{tb: &exampleTB{}, state: s}, \"example\")",
				"m := &lazyStr{}\n\th := newFlaggedT(s, flags.debugvis)\n\tif h.dbg {\n\t\th.tb.Logf(\"%s\", m)\n\t}\n\treturn g.Draw(h, \"example\")",
				1,
			),
			extra:      "type lazyStr struct { once sync.Once; s string }\nfunc (l *lazyStr) String() string { l.once.Do(func() { l.s = \"on\" }); return l.s }\nfunc newFlaggedT(s uint64, dbg bool) *T { return &T{tb: &exampleTB{}, state: s, dbg: dbg} }\n",
			wantReason: "env/flag global reaches disallowed exported symbol Example",
		},
		{
			name:    "ext_struct_format_arg_leaking_bool_flag",
			pkgPath: testRapidPkgPath,
			pkgName: "rapid",
			base: strings.Replace(
				strings.Replace(
					testBaseRapidSrc,
					"fail  bool",
					"fail  bool\n\tdbg   bool",
					1,
				),
				"return g.Draw(&T{tb: &exampleTB{}, state: s}, \"example\")",
				"var tm time.Time\n\th := newFlaggedT(s, flags.debugvis)\n\tif h.dbg {\n\t\th.tb.Logf(\"%v\", tm)\n\t}\n\treturn g.Draw(h, \"example\")",
				1,
			),
			extra:      "func newFlaggedT(s uint64, dbg bool) *T { return &T{tb: &exampleTB{}, state: s, dbg: dbg} }\n",
			wantReason: "env/flag global reaches disallowed exported symbol Example",
		},
		{
			name:    "fmt_sprintf_on_typeparam_leaking_bool_flag",
			pkgPath: testRapidPkgPath,
			pkgName: "rapid",
			base: strings.Replace(
				strings.Replace(
					testBaseRapidSrc,
					"fail  bool",
					"fail  bool\n\tdbg   bool",
					1,
				),
				"return g.Draw(&T{tb: &exampleTB{}, state: s}, \"example\")",
				"h := newFlaggedT(s, flags.debugvis)\n\tv := g.Draw(h, \"example\")\n\tif h.dbg {\n\t\tmsg := fmt.Sprintf(\"%v\", v)\n\t\th.tb.Logf(\"%s\", msg)\n\t}\n\treturn v",
				1,
			),
			extra:      "func newFlaggedT(s uint64, dbg bool) *T { return &T{tb: &exampleTB{}, state: s, dbg: dbg} }\n",
			wantReason: "env/flag global reaches disallowed exported symbol Example",
		},
		{
			name:    "noop_tb_calling_fmt_sprintf_leaking_bool_flag",
			pkgPath: testRapidPkgPath,
			pkgName: "rapid",
			base: strings.Replace(
				strings.Replace(
					strings.Replace(
						testBaseRapidSrc,
						"fail  bool",
						"fail  bool\n\tdbg   bool",
						1,
					),
					"func (*exampleTB) Logf(format string, args ...any)   {}",
					"func (*exampleTB) Logf(format string, args ...any)   { _ = fmt.Sprintf(format, args...) }",
					1,
				),
				"return g.Draw(&T{tb: &exampleTB{}, state: s}, \"example\")",
				"h := newFlaggedT(s, flags.debugvis)\n\tv := g.Draw(h, \"example\")\n\tif h.dbg {\n\t\th.tb.Logf(\"%v\", v)\n\t}\n\treturn v",
				1,
			),
			extra:      "func newFlaggedT(s uint64, dbg bool) *T { return &T{tb: &exampleTB{}, state: s, dbg: dbg} }\n",
			wantReason: "env/flag global reaches disallowed exported symbol Example",
		},
		{
			name:       "init_incdec_env_var_leaked",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       testPropcheckSrc,
			extra:      "var extraEnvCount int\nfunc init() {\n\tif _, ok := os.LookupEnv(\"PROPCHECK_EXTRA\"); ok {\n\t\textraEnvCount++\n\t}\n}\nfunc LeakedEnv() int { return extraEnvCount }\n",
			wantReason: "env/flag global reaches disallowed exported symbol LeakedEnv",
		},
		{
			name:       "init_helper_under_env_cond_leaked",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       testPropcheckSrc,
			extra:      "var extraCondVar int\nfunc setExtraCond() { extraCondVar = 1 }\nfunc init() {\n\tif _, ok := os.LookupEnv(\"PROPCHECK_EXTRA\"); ok {\n\t\tsetExtraCond()\n\t}\n}\nfunc LeakedCondEnv() int { return extraCondVar }\n",
			wantReason: "env/flag global reaches disallowed exported symbol LeakedCondEnv",
		},
		{
			name:       "init_slice_alias_env_write_leaked",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       testPropcheckSrc,
			extra:      "var extraSlice = make([]int, 1)\nfunc init() {\n\ts := extraSlice\n\tif _, ok := os.LookupEnv(\"PROPCHECK_EXTRA\"); ok {\n\t\ts[0] = 1\n\t}\n}\nfunc LeakedSliceEnv() int { return extraSlice[0] }\n",
			wantReason: "env/flag global reaches disallowed exported symbol LeakedSliceEnv",
		},
		{
			name:       "init_if_cond_shortcircuit_helper_leaked",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       testPropcheckSrc,
			extra:      "var extraShortVar int\nfunc enableShort() bool { extraShortVar = 1; return true }\nfunc init() {\n\tif v, ok := os.LookupEnv(\"PROPCHECK_EXTRA\"); ok && v != \"\" && enableShort() {\n\t}\n}\nfunc LeakedShortEnv() int { return extraShortVar }\n",
			wantReason: "env/flag global reaches disallowed exported symbol LeakedShortEnv",
		},
		{
			name:       "init_bare_return_named_result_leaked",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       testPropcheckSrc,
			extra:      "var extraNamedSlice = make([]int, 1)\nfunc getNamedSliceAlias() (out []int) { out = extraNamedSlice; return }\nfunc init() {\n\ts := getNamedSliceAlias()\n\tif _, ok := os.LookupEnv(\"PROPCHECK_EXTRA\"); ok {\n\t\ts[0] = 1\n\t}\n}\nfunc LeakedNamedRetEnv() int { return extraNamedSlice[0] }\n",
			wantReason: "env/flag global reaches disallowed exported symbol LeakedNamedRetEnv",
		},
		{
			name:    "utf8_encode_rune_stringer_leaking_bool_flag",
			pkgPath: testRapidPkgPath,
			pkgName: "rapid",
			base: strings.Replace(
				strings.Replace(
					strings.Replace(
						testBaseRapidSrc,
						"\t\"io\"\n",
						"\t\"io\"\n\t\"unicode/utf8\"\n",
						1,
					),
					"fail  bool",
					"fail  bool\n\tdbg   bool",
					1,
				),
				"return g.Draw(&T{tb: &exampleTB{}, state: s}, \"example\")",
				"m := utf8Stringer{buf: make([]byte, 4)}\n\th := newFlaggedT(s, flags.debugvis)\n\tif h.dbg {\n\t\th.tb.Logf(\"%s\", m)\n\t}\n\treturn g.Draw(h, \"example\")",
				1,
			),
			extra:      "type utf8Stringer struct { buf []byte }\nfunc (m utf8Stringer) String() string { _ = utf8.EncodeRune(m.buf, 'Z'); return \"\" }\nfunc newFlaggedT(s uint64, dbg bool) *T { return &T{tb: &exampleTB{}, state: s, dbg: dbg} }\n",
			wantReason: "env/flag global reaches disallowed exported symbol Example",
		},
		{
			name:    "strings_indexfunc_stringer_leaking_bool_flag",
			pkgPath: testRapidPkgPath,
			pkgName: "rapid",
			base: strings.Replace(
				strings.Replace(
					strings.Replace(
						testBaseRapidSrc,
						"\t\"io\"\n",
						"\t\"io\"\n\t\"strings\"\n",
						1,
					),
					"fail  bool",
					"fail  bool\n\tdbg   bool",
					1,
				),
				"return g.Draw(&T{tb: &exampleTB{}, state: s}, \"example\")",
				"m := fnStringer{fn: func(rune) bool { return true }}\n\th := newFlaggedT(s, flags.debugvis)\n\tif h.dbg {\n\t\th.tb.Logf(\"%s\", m)\n\t}\n\treturn g.Draw(h, \"example\")",
				1,
			),
			extra:      "type fnStringer struct { fn func(rune) bool }\nfunc (m fnStringer) String() string { _ = strings.IndexFunc(\"x\", m.fn); return \"\" }\nfunc newFlaggedT(s uint64, dbg bool) *T { return &T{tb: &exampleTB{}, state: s, dbg: dbg} }\n",
			wantReason: "env/flag global reaches disallowed exported symbol Example",
		},
		{
			name:    "sealed_iface_mutating_stringer_leaking_bool_flag",
			pkgPath: testRapidPkgPath,
			pkgName: "rapid",
			base: strings.Replace(
				strings.Replace(
					testBaseRapidSrc,
					"fail  bool",
					"fail  bool\n\tdbg   bool",
					1,
				),
				"return g.Draw(&T{tb: &exampleTB{}, state: s}, \"example\")",
				"var si sealedFmtIface = &mutSealed{}\n\th := newFlaggedT(s, flags.debugvis)\n\tif h.dbg {\n\t\th.tb.Logf(\"%s\", si)\n\t}\n\treturn g.Draw(h, \"example\")",
				1,
			),
			extra:      "type sealedFmtIface interface { sealed() }\ntype mutSealed struct { n int }\nfunc (*mutSealed) sealed() {}\nfunc (m *mutSealed) String() string { m.n++; return \"on\" }\nfunc newFlaggedT(s uint64, dbg bool) *T { return &T{tb: &exampleTB{}, state: s, dbg: dbg} }\n",
			wantReason: "env/flag global reaches disallowed exported symbol Example",
		},
		{
			name:    "unconditional_handle_logf_mutating_stringer_leaking_bool_flag",
			pkgPath: testRapidPkgPath,
			pkgName: "rapid",
			base: strings.Replace(
				strings.Replace(
					testBaseRapidSrc,
					"fail  bool",
					"fail  bool\n\tdbg   bool",
					1,
				),
				"return g.Draw(&T{tb: &exampleTB{}, state: s}, \"example\")",
				"m := &mutLogStringer{}\n\th := newFlaggedT(s, flags.debugvis)\n\th.dbgLogf(\"%s\", m)\n\treturn g.Draw(h, \"example\")",
				1,
			),
			extra:      "type mutLogStringer struct { n int }\nfunc (m *mutLogStringer) String() string { m.n++; return \"on\" }\nfunc (t *T) dbgLogf(format string, args ...any) { if t.dbg { t.tb.Logf(format, args...) } }\nfunc newFlaggedT(s uint64, dbg bool) *T { return &T{tb: &exampleTB{}, state: s, dbg: dbg} }\n",
			wantReason: "env/flag global reaches disallowed exported symbol Example",
		},
		{
			name:       "init_ptr_alias_category_a_var_rejected",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       testPropcheckSrc,
			extra:      "var extraPtrVar int\nfunc init() {\n\tp := &extraPtrVar\n\t*p = 1\n}\n",
			wantReason: "verifyHarnessPackageVars failed",
		},
		{
			name:       "init_shared_helper_calling_time_now_rejected",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       strings.Replace(testPropcheckSrc, "_ = time.Now()", "readClock()", 1),
			extra:      "func readClock() { _ = time.Now() }\nfunc init() { func() { readClock() }() }\n",
			wantReason: "clock/fs/template in init or global initializer",
		},
		{
			name:    "unexported_mutator_iface_on_bool_flag",
			pkgPath: testRapidPkgPath,
			pkgName: "rapid",
			base: strings.Replace(
				strings.Replace(
					testBaseRapidSrc,
					"fail  bool",
					"fail  bool\n\tdbg   bool\n\tmut   mutIface",
					1,
				),
				"return g.Draw(&T{tb: &exampleTB{}, state: s}, \"example\")",
				"h := newFlaggedT(s, flags.debugvis)\n\tif h.dbg {\n\t\th.mut.Log()\n\t}\n\treturn g.Draw(h, \"example\")",
				1,
			),
			extra:      "type mutIface interface { Log() }\ntype stateMut struct { t *T }\nfunc (m stateMut) Log() { m.t.state += 999 }\nfunc newFlaggedT(s uint64, dbg bool) *T { h := &T{tb: &exampleTB{}, state: s, dbg: dbg}; h.mut = stateMut{t: h}; return h }\n",
			wantReason: "env/flag global reaches disallowed exported symbol Example",
		},
		{
			name:       "exported_typeparam_method_guarded_only_by_unsealed_tb_iface",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       testPropcheckSrc,
			extra:      "func (a *Arb[V]) UnsealedDraw(l Logger) V { var zero V; _ = l; return zero }\n",
			wantReason: "disallowed exported method result on type Arb",
		},
		{
			name:       "exported_typeparam_func_guarded_only_by_unsealed_tb_iface",
			pkgPath:    testRapidPkgPath,
			pkgName:    "rapid",
			base:       testBaseRapidSrc,
			extra:      "func DrawWithTB[V any](tb TB, g *Generator[V]) V { var zero V; _, _ = tb, g; return zero }\n",
			wantReason: "disallowed result type on exported func DrawWithTB",
		},
		{
			name:       "exported_detached_handle_constructor",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       testPropcheckSrc,
			extra:      "func NewDetachedContext() *Context { return &Context{} }\n",
			wantReason: "disallowed result type on exported func NewDetachedContext",
		},
		{
			name:       "maphash_leaked_to_generator_constructor",
			pkgPath:    testRapidPkgPath,
			pkgName:    "rapid",
			base:       testBaseRapidSrc,
			extra:      "func badSeed() uint64 { var h maphash.Hash; h.SetSeed(maphash.MakeSeed()); return h.Sum64() }\nfunc BadInt() *Generator[int] { _ = badSeed(); return Int() }\n",
			wantReason: "hash/maphash reaches disallowed exported symbol BadInt",
		},
		{
			name:       "value_taken_clock_helper",
			pkgPath:    "example.com/propcheck",
			pkgName:    "propcheck",
			base:       testPropcheckSrc,
			extra:      "func sneakyClock() int64 { return time.Now().UnixNano() }\nfunc init() { _ = sneakyClock }\n",
			wantReason: "clock/fs/template",
		},
		{
			name:       "exported_global",
			pkgPath:    testRapidPkgPath,
			pkgName:    "rapid",
			base:       testBaseRapidSrc,
			extra:      "var ExportedGlobal int\n",
			wantReason: "exported var: ExportedGlobal",
		},
		{
			name:       "unjoined_goroutine",
			pkgPath:    testRapidPkgPath,
			pkgName:    "rapid",
			base:       testBaseRapidSrc,
			extra:      "func Spawn() { go func() {}() }\n",
			wantReason: "unjoined go stmt",
		},
		{
			name:       "syncmap_mutated_slice",
			pkgPath:    testRapidPkgPath,
			pkgName:    "rapid",
			base:       testBaseRapidSrc,
			extra:      "func badMut() { s := cachedWords(\"k\"); s[0] = \"mut\" }\n",
			wantReason: "refconfine",
		},
		{
			name:       "exported_any_return",
			pkgPath:    testRapidPkgPath,
			pkgName:    "rapid",
			base:       testBaseRapidSrc,
			extra:      "func AnyOut() any { return 1 }\n",
			wantReason: "disallowed result type on exported func AnyOut",
		},
		{
			name:       "path_traversal_failfile",
			pkgPath:    testRapidPkgPath,
			pkgName:    "rapid",
			base:       testBaseRapidSrc,
			extra:      "func badOpen() { f, _ := os.Open(filepath.Join(flags.failfile, \"..\", \"x\")); if f != nil { _ = f.Close() } }\n",
			wantReason: "os.Open",
		},
	}
	for _, tc := range rejections {
		t.Run(tc.name, func(t *testing.T) {
			badPkg := parseHarnessPackage(t, tc.pkgPath, tc.pkgName, tc.pkgName+".go", tc.base+"\n"+tc.extra, true)
			rec := trace.NewRecorder()
			ctx := trace.WithSink(t.Context(), rec)
			vp, reason := VerifyPackageWithIndex(ctx, trace.DomainClosure, true, badPkg, nil)
			if vp != nil {
				t.Fatalf("VerifyPackageWithIndex accepted %s", tc.name)
			}
			if !strings.Contains(reason, tc.wantReason) {
				t.Fatalf("VerifyPackageWithIndex(%s) reason = %q, want substring %q", tc.name, reason, tc.wantReason)
			}
			if strings.HasSuffix(tc.name, "_leaking_bool_flag") {
				if len(rec.ByName("propharness.logging.reject")) == 0 {
					t.Fatalf("expected propharness.logging.reject trace event for %s, got %+v", tc.name, rec.Events())
				}
			}
		})
	}

	t.Run("tampered_seeded_sample_ignoring_seed", func(t *testing.T) {
		badSrc := strings.Replace(testBaseRapidSrc, "if len(seed) > 0 {\n\t\ts = uint64(seed[0])\n\t}", "_ = seed", 1)
		ok, reason := VerifyPackageWithReason(true, parseRapidPackage(t, badSrc))
		if ok || !strings.Contains(reason, "seeded sample method failed seed-override check: Example") {
			t.Fatalf("expected seed-override failure, got ok=%v reason=%q", ok, reason)
		}
	})
}

func TestVerifyRealRapidDependency(t *testing.T) {
	loaded, err := gotool.LoadPackages(
		t.Context(),
		packages.NeedName|packages.NeedFiles|packages.NeedCompiledGoFiles|packages.NeedEmbedFiles|packages.NeedEmbedPatterns|packages.NeedSyntax|packages.NeedTypes|packages.NeedTypesInfo|packages.NeedImports|packages.NeedModule|packages.NeedForTest,
		"../..",
		os.Environ(),
		nil,
		testRapidPkgPath,
	)
	if err != nil || len(loaded) == 0 {
		t.Fatalf("LoadPackages(%s): err=%v len=%d", testRapidPkgPath, err, len(loaded))
	}
	checked := 0
	for _, p := range loaded {
		if p == nil || p.PkgPath != testRapidPkgPath || p.ForTest != "" {
			continue
		}
		checked++
		vp, reason := VerifyPackageWithIndex(t.Context(), trace.DomainClosure, true, p, nil)
		if vp == nil {
			t.Fatalf("VerifyPackageWithIndex(real %s) = nil (%s), want verified", p.ID, reason)
		}
		if vp.PrimaryDriver != "Check" {
			t.Fatalf("PrimaryDriver = %q, want Check", vp.PrimaryDriver)
		}
		assertBoolMapEq(t, "HandleStructs", vp.HandleStructs, map[string]bool{"T": true})
		assertBoolMapEq(t, "HandleIfaces", vp.HandleIfaces, map[string]bool{"TB": true})
		assertBoolMapEq(t, "DriverFuncs", vp.DriverFuncs, map[string]bool{"Check": true})
		assertBoolMapEq(t, "WrapperFactoryFuncs", vp.WrapperFactoryFuncs, map[string]bool{"MakeCheck": true, "MakeFuzz": true})
		assertBoolMapEq(t, "GeneratorTypes", vp.GeneratorTypes, map[string]bool{"Generator": true})
		assertBoolMapEq(t, "ReflectSynthFuncs", vp.ReflectSynthFuncs, map[string]bool{"Make": true, "MakeCustom": true})
		wantSeeded := map[MethodKey]bool{{Recv: "Generator", Method: "Example"}: true}
		if !maps.Equal(vp.SeededSampleMethods, wantSeeded) {
			t.Fatalf("SeededSampleMethods = %v, want %v", vp.SeededSampleMethods, wantSeeded)
		}
	}
	if checked == 0 {
		t.Fatalf("found zero non-test %s packages in %d loaded roots", testRapidPkgPath, len(loaded))
	}
}

func TestMayBeHarnessImportsProperty(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		host := rapid.SampledFrom([]string{"example.com/h", "github.com/org/qc", "fmt", "testing", "main", ""}).Draw(rt, "host")
		imps := rapid.SliceOfN(rapid.SampledFrom([]string{
			"testing", "reflect", "time", "os", "flag", "hash/maphash",
			"unsafe", "C", "embed", "net/http", "example.com/dep",
		}), 0, 6).Draw(rt, "imps")

		got := MayBeHarnessImports(host, imps)
		wantHost := host == "example.com/h" || host == "github.com/org/qc"
		hasTesting := false
		allAllowed := true
		for _, imp := range imps {
			if imp == "testing" {
				hasTesting = true
			}
			if imp == "unsafe" || imp == "C" || imp == "embed" || imp == "net/http" || imp == "example.com/dep" {
				allAllowed = false
			}
		}
		want := wantHost && hasTesting && allAllowed
		if got != want {
			rt.Fatalf("MayBeHarnessImports(%q, %v) = %v, want %v", host, imps, got, want)
		}
	})
}

func assertBoolMapEq(t *testing.T, label string, got, want map[string]bool) {
	t.Helper()
	if !maps.Equal(got, want) {
		t.Fatalf("%s = %v, want %v", label, got, want)
	}
}
