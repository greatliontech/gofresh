package closure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/greatliontech/go-x-tools/go/callgraph/rta"
	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/closure/internal/cprep"
	"github.com/greatliontech/gofresh/internal/closure/internal/propharness"
	arta "github.com/greatliontech/gofresh/internal/closure/internal/rta"
	"github.com/greatliontech/gofresh/internal/dynstate"
	"github.com/greatliontech/gofresh/internal/dynstate/protoaudit"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

// inMemoryFixtureRegistry holds the single-purpose in-memory test fixtures
// for package-level observability and reachability scans.
var inMemoryFixtureRegistry = map[string]map[string]map[string]string{
	"github.com/greatliontech/gofresh/internal/closure/testdata/batchisolation": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/batchisolation": {
			"batchisolation.go":      "package batchisolation\n\ntype callback func() int\n\nvar (\n\tcallbackSlot  callback\n\tinterfaceSlot any\n\tstartupValue  = startupHelper()\n)\n\nfunc startupHelper() int { return 1 }\n\nfunc dynamicTarget() int { return 2 }\n\nfunc AddressTaker() int {\n\tcallbackSlot = dynamicTarget\n\treturn startupValue\n}\n\nfunc DynamicCaller() int { return callbackSlot() }\n\nfunc alternateDynamicTarget() int { return 5 }\n\nfunc KnownDynamic() int {\n\tfn := callback(dynamicTarget)\n\tif startupValue < 0 {\n\t\tfn = alternateDynamicTarget\n\t}\n\treturn fn()\n}\n\nfunc CallbackRoot(fn callback) int { return fn() }\n\ntype runner interface {\n\tRun() int\n}\n\ntype nested struct{}\n\nfunc (nested) Exported() int { return 4 }\n\ntype concrete struct {\n\tvalue nested\n}\n\nfunc (concrete) Run() int { return concreteMethodHelper() }\n\nfunc concreteMethodHelper() int { return 3 }\n\nfunc Materializer() int {\n\tinterfaceSlot = concrete{value: nested{}}\n\treturn startupValue\n}\n\nfunc Invoker(value runner) int { return value.Run() }\n\nfunc Production() int { return startupValue }\n",
			"batchisolation_test.go": "package batchisolation\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc testMainHelper() { _ = os.Getenv(\"GOFRESH_BATCH_TEST\") }\n\nfunc TestStandardDynamic(t *testing.T) {\n\tvar value interface{ TempDir() string } = t\n\t_ = value.TempDir()\n}\n\nfunc TestMain(m *testing.M) {\n\ttestMainHelper()\n\tos.Exit(m.Run())\n}\n\nfunc BenchmarkHarness(b *testing.B) {\n\tfor b.Loop() {\n\t\t_ = startupValue\n\t}\n}\n\nfunc BenchmarkSibling(b *testing.B) {\n\tfor b.Loop() {\n\t\tbenchmarkSiblingHelper()\n\t}\n}\n\nfunc benchmarkSiblingHelper() {}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/benchpacing": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/benchpacing": {
			"benchpacing_test.go": "package benchpacing\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc BenchmarkLoopOnly(b *testing.B) {\n\tn := 0\n\tfor b.Loop() {\n\t\tn++\n\t}\n\t_ = n\n}\n\nfunc BenchmarkLoopReadsFile(b *testing.B) {\n\tfor b.Loop() {\n\t\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\t\tb.Fatal(err)\n\t\t}\n\t}\n}\n\nfunc BenchmarkResultField(b *testing.B) {\n\tr := testing.BenchmarkResult{N: 3}\n\tfor b.Loop() {\n\t\t_ = r.N\n\t}\n}\n\nfunc BenchmarkReporting(b *testing.B) {\n\tb.ReportAllocs()\n\tb.SetBytes(8)\n\tb.ReportMetric(1, \"widgets/op\")\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/constgroup": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/constgroup": {
			"constgroup_test.go": "package constgroup\n\nimport \"testing\"\n\nconst (\n\tSeed = iota\n\tUsed\n)\n\nfunc BenchmarkConstGroup(b *testing.B) {\n\tfor b.Loop() {\n\t\t_ = Used\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/copyfs": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/copyfs": {
			"copyfs_test.go": "package copyfs\n\nimport (\n\t\"os\"\n\t\"testing\"\n\t\"testing/fstest\"\n)\n\nfunc BenchmarkCopyFS(b *testing.B) {\n\tfor b.Loop() {\n\t\t_ = os.CopyFS(\"out\", fstest.MapFS{\"x\": {Data: []byte(\"x\")}})\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/createtemp": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/createtemp": {
			"createtemp_test.go": "package createtemp\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc BenchmarkCreateTemp(b *testing.B) {\n\tfor b.Loop() {\n\t\tf, _ := os.CreateTemp(\"\", \"pew-*\")\n\t\tif f != nil {\n\t\t\t_ = f.Close()\n\t\t}\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/depdispatch": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/depdispatch": {
			"depdispatch_test.go": "// Package depdispatch pins the subject-determined dispatch admission:\n// an unresolved interface invoke inside a helper body stops widening\n// the subject world when the operand's dynamic types derive wholly\n// from subject-attributed flow and every enumerated target is analyzed\n// content - the targets' own effects then decide the verdict.\npackage depdispatch\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\ntype sizer interface{ size() int }\n\ntype word struct{ s string }\n\nfunc (w word) size() int { return len(w.s) }\n\ntype filer struct{ path string }\n\nfunc (f filer) size() int {\n\t_ = os.WriteFile(f.path, []byte(\"x\"), 0o600)\n\treturn 1\n}\n\n// measureVia dispatches on its parameter: the operand closes by\n// crossing to the subject-attributed call sites.\nfunc measureVia(s sizer) int { return s.size() }\n\n// RunLocalDispatch hands measureVia a locally constructed value: the\n// operand is subject-determined, the enumerated target set is analyzed\n// and pure, and the subject closes observable.\nfunc RunLocalDispatch(n int) int { return measureVia(word{s: \"xy\"}) + n }\n\n// RunEffectDispatch hands in a value whose method mutates the\n// filesystem: the admission holds on shape, and the target's own\n// effect refuses the subject.\nfunc RunEffectDispatch(n int) int { return measureVia(filer{path: \"x\"}) + n }\n\n// shared is process-shared mutable state: a load feeding the operand\n// refuses the admission and the open-world refusal stands.\nvar shared sizer = word{s: \"z\"}\n\nfunc RunSharedDispatch(n int) int { return measureVia(shared) + n }\n\nfunc TestRunLocalDispatch(t *testing.T) {\n\tif RunLocalDispatch(1) != 3 {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n\nfunc TestRunSharedDispatch(t *testing.T) {\n\tif RunSharedDispatch(1) != 2 {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n\n// never has no implementation anywhere in the program: the dispatch\n// site's enumerated target set is empty, and an empty set never admits\n// - absence of provenance is refused, never a vacuous pass.\ntype never interface{ nope() int }\n\nfunc dispatchNever(v never) int {\n\tif v == nil {\n\t\treturn 0\n\t}\n\treturn v.nope()\n}\n\nfunc RunNilDispatch(n int) int { return dispatchNever(nil) + n }\n\nfunc TestRunNilDispatch(t *testing.T) {\n\tif RunNilDispatch(1) != 1 {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/dyncaller": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/dyncaller": {
			"dyncaller_test.go": "package dyncaller\n\nimport (\n\t\"fmt\"\n\t\"os\"\n\t\"strings\"\n\t\"testing\"\n)\n\n// RunCheck is the enumeration-closed shape: a dynamic-carrying subject\n// whose only references are direct static calls passing closed values.\nfunc RunCheck(check func(int) int, n int) int {\n\treturn check(n)\n}\n\n// RunEffect is called with a closure that mutates the filesystem: the\n// closure body is analyzed view content whose blocking effect belongs\n// to the subject.\nfunc RunEffect(check func(int) int, n int) int {\n\treturn check(n)\n}\n\n// RunEscaped is also referenced as a value (stored to a package\n// variable), so it keeps the open world.\nfunc RunEscaped(check func(int) int, n int) int {\n\treturn check(n)\n}\n\n// RunUncalled has no references at all: absence of provenance.\nfunc RunUncalled(check func(int) int, n int) int {\n\treturn check(n)\n}\n\n// RunMixed has one caller passing a value the caller-frame walk cannot\n// close (its own parameter).\nfunc RunMixed(check func(int) int, n int) int {\n\treturn check(n)\n}\n\n// Sizer is the interface-parameter shape: the enumerated caller\n// materializes a concrete type, so the subject's invoke resolves to it.\n// The method is unexported on purpose: an exported name would make\n// every same-named standard-library method an RTA dispatch candidate.\ntype Sizer interface {\n\tsize() int\n}\n\ntype wordSizer struct{ s string }\n\nfunc (w wordSizer) size() int { return len(strings.Fields(w.s)) }\n\ntype fileSizer struct{ path string }\n\nfunc (f fileSizer) size() int {\n\t_ = os.WriteFile(f.path, []byte(\"x\"), 0o600)\n\treturn 1\n}\n\nfunc Measure(s Sizer) int {\n\treturn s.size()\n}\n\n// MeasureFile's enumerated caller hands it a type whose method mutates\n// the filesystem: the blocking effect is the subject's own.\nfunc MeasureFile(s Sizer) int {\n\treturn s.size()\n}\n\nvar escaped = RunEscaped\n\n// namedHook is held by a package-level variable; a computed call\n// through the variable dispatches a value with a stable identity. The\n// signature is distinct from every other fixture subject's — dyninit's\n// included, which documents that distinctness — so the address-taken\n// value enters no sibling subject's dispatch candidates under any mask\n// (docs/issues/enumeration-targets-over-approximated.md).\nfunc namedHook(b byte) byte { return b }\n\nvar hook = namedHook\n\n// RunViaVar calls through a package-level function variable: the\n// refusal names the variable it dispatches.\nfunc RunViaVar(b byte) byte { return hook(b) }\n\n// RunDead has zero references and never moves its parameter: only the\n// absence-of-provenance arm refuses it.\nfunc RunDead(check func(int) int, n int) int {\n\treturn n\n}\n\n// boxed carries a value whose concrete type the caller-frame walk\n// cannot pin: FormatLoaded must keep the open world, because its\n// parameter flows into fmt's reflective formatting where no dispatch\n// site exists to refuse per-site.\nvar boxed any = strings.NewReplacer()\n\nfunc FormatLoaded(v any) string {\n\treturn fmt.Sprintf(\"%v\", v)\n}\n\n// FormatLocal is the positive std-flow shape: the enumerated caller\n// materializes the concrete type, so the reflective argument premise\n// holds and the subject closes with no dispatch at all.\nfunc FormatLocal(v any) string {\n\treturn fmt.Sprintf(\"%v\", v)\n}\n\n// Runner.RunM is referenced once directly and once as a method value:\n// the synthetic wrapper re-dispatches it where no enumeration can\n// judge, so the wrapper's existence keeps the open world.\ntype Runner struct{}\n\nfunc (Runner) RunM(check func(int) int, n int) int {\n\treturn check(n)\n}\n\n// Counter.RunP is a pointer-receiver method with only direct calls: a\n// receiver-bearing subject keeps the open world outright, because an\n// interface invoke of it would leave no reference the scan can see.\ntype Counter struct{ n int }\n\nfunc (c *Counter) RunP(check func(int) int, n int) int {\n\tc.n++\n\treturn check(n)\n}\n\n// RunGen is called from a generic helper: neither the parameterized\n// origin nor its synthetic instantiations can be judged as callers.\nfunc RunGen(check func(int) int, n int) int {\n\treturn check(n)\n}\n\nfunc callGen[T any](f func(int) int, n int) int {\n\treturn RunGen(f, n)\n}\n\n// RunGo's enumerated callers include a go statement: provenance is\n// concurrency-independent, so the site judges like any other.\nfunc RunGo(check func(int) int, n int) int {\n\treturn check(n)\n}\n\n// RunCallArg's caller passes a call result at the dynamic position:\n// the caller-frame walk cannot see through the call, so it refuses.\nfunc RunCallArg(check func(int) int, n int) int {\n\treturn check(n)\n}\n\nfunc mkCheck() func(int) int {\n\treturn func(n int) int { return n }\n}\n\nfunc TestRunCheck(t *testing.T) {\n\tif RunCheck(func(n int) int { return n + 1 }, 1) != 2 {\n\t\tt.Fatal(\"wrong\")\n\t}\n\tif RunCheck(func(n int) int { return n * 2 }, 2) != 4 {\n\t\tt.Fatal(\"wrong\")\n\t}\n\t// A cell-loaded closure — the recursive local closure's idiom — is\n\t// a closed argument at the enumeration: RunCheck stays observable.\n\tvar down func(int) int\n\tdown = func(n int) int {\n\t\tif n <= 0 {\n\t\t\treturn 0\n\t\t}\n\t\treturn 1 + down(n-1)\n\t}\n\tif RunCheck(down, 3) != 3 {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n\nfunc TestRunEffect(t *testing.T) {\n\tdir := t.TempDir()\n\tgot := RunEffect(func(n int) int {\n\t\t_ = os.WriteFile(dir+\"/out.txt\", []byte(\"x\"), 0o600)\n\t\treturn n\n\t}, 1)\n\tif got != 1 {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n\n// The direct call and the value use live in different functions: the\n// direct caller (and the closure parent it binds) is clean, so the\n// package-level value reference alone must keep the open world.\nfunc TestRunEscapedDirect(t *testing.T) {\n\tif RunEscaped(func(n int) int { return n }, 1) != 1 {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n\nfunc TestRunEscaped(t *testing.T) {\n\tif escaped(func(n int) int { return n }, 1) != 1 {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n\nfunc TestFormatLoaded(t *testing.T) {\n\tif FormatLoaded(boxed) == \"\" {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n\nfunc TestFormatLocal(t *testing.T) {\n\tif FormatLocal(wordSizer{s: \"a b\"}) == \"\" {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n\nfunc TestRunPointerMethod(t *testing.T) {\n\tc := &Counter{}\n\tif c.RunP(func(n int) int { return n }, 1) != 1 {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n\nfunc TestRunGen(t *testing.T) {\n\tif callGen[int](func(n int) int { return n }, 1) != 1 {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n\nfunc TestRunGo(t *testing.T) {\n\tdone := make(chan int, 1)\n\tgo RunGo(func(n int) int { done <- n; return n }, 1)\n\tif RunGo(func(n int) int { return n + 1 }, 1) != 2 {\n\t\tt.Fatal(\"wrong\")\n\t}\n\tif <-done != 1 {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n\nfunc TestRunCallArg(t *testing.T) {\n\tif RunCallArg(mkCheck(), 1) != 1 {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n\nfunc TestRunMethod(t *testing.T) {\n\tvar r Runner\n\tif r.RunM(func(n int) int { return n }, 1) != 1 {\n\t\tt.Fatal(\"wrong\")\n\t}\n\tm := r.RunM\n\tif m(func(n int) int { return n + 1 }, 1) != 2 {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n\nfunc TestRunMixed(t *testing.T) {\n\thelperMixed(t, func(n int) int { return n })\n}\n\nfunc helperMixed(t *testing.T, f func(int) int) {\n\tif RunMixed(f, 1) != 1 {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n\nfunc TestMeasure(t *testing.T) {\n\tif Measure(wordSizer{s: \"a b\"}) != 2 {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n\nfunc TestMeasureFile(t *testing.T) {\n\tif MeasureFile(fileSizer{path: t.TempDir() + \"/out.txt\"}) != 1 {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/dyninit": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/dyninit": {
			"dyninit_test.go": "package dyninit\n\nimport \"testing\"\n\n// RunInit is called from a package-variable initializer: the synthetic\n// initializer body cannot be judged as a caller, so the reference\n// refuses even beside a clean test caller. The package holds nothing\n// else, so a wrong admission here would read observable — the arm's\n// only net. Its parameter signature is also distinct from the dyncaller\n// package's subjects: an initializer closure is address-taken under\n// every mask, and a matching signature would enter sibling subjects'\n// dispatch candidates\n// (docs/issues/enumeration-targets-over-approximated.md).\nfunc RunInit(check func(string) string, s string) string {\n\treturn check(s)\n}\n\nvar initResult = RunInit(func(s string) string { return s }, \"x\")\n\nfunc TestRunInit(t *testing.T) {\n\tif initResult != \"x\" || RunInit(func(s string) string { return s }, \"x\") != \"x\" {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/dyninitbound": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/dyninitbound": {
			"dyninitbound_test.go": "// Package dyninitbound pins the enumeration-target narrowing's value\n// provenance: init-planted values that are not anonymous closures — a\n// method value materialized in a package initializer (the shape go1.27's\n// encoding/json/v2 plants for base32 bound methods in every test binary)\n// and a named function registered there — collide with a closed\n// subject's dispatch signature under every mask, and must stay out of\n// its target set exactly as an init-parented closure does.\npackage dyninitbound\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// Run is enumeration-closed: its only reference is the direct static\n// test call passing a closed literal.\nfunc Run(check func(int) int, n int) int { return check(n) }\n\ntype lener struct{ path string }\n\n// EncLen mutates the filesystem: visible to a subject only if the\n// init-planted method value drags into its target set.\nfunc (l lener) EncLen(n int) int {\n\t_ = os.WriteFile(l.path, []byte(\"x\"), 0o600)\n\treturn n\n}\n\n// named mutates the filesystem: visible to a subject only if the\n// init-planted function reference drags into its target set.\nfunc named(n int) int {\n\t_ = os.WriteFile(\"named.txt\", []byte(\"x\"), 0o600)\n\treturn n\n}\n\nvar std = lener{path: \"enc.txt\"}\n\n// Both registrations happen in a user init body: the method value\n// creates a parentless synthetic bound wrapper (the go1.27\n// encoding/json/v2 shape), the named reference takes a plain function\n// address — neither is an init-parented closure itself, so a\n// parent-shaped narrowing misses both. The subject flow references\n// nothing that reaches the registrations textually — the object walk\n// prices any transitively referenced declaration's content on its own\n// conservative terms — so this fixture pins exactly the RTA\n// signature-collision channel: address-taken under every mask by the\n// init roots, visible to the subject only through its dispatch target\n// set.\nvar hooks []func(int) int\n\nfunc init() {\n\thooks = append(hooks, std.EncLen, named)\n}\n\nfunc TestRun(t *testing.T) {\n\tif Run(func(n int) int { return n + 1 }, 1) != 2 {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/dyninitcollide": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/dyninitcollide": {
			"dyninitcollide_test.go": "// Package dyninitcollide pins the enumeration-target narrowing: an\n// init-flow closure of matching signature is address-taken under every\n// mask, but an enumeration-closed subject's pinned operand set can\n// never carry it, so it must not drag its latent effect into the\n// subject's scan.\npackage dyninitcollide\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// Run is enumeration-closed: its only reference is the direct static\n// test call passing a closed literal.\nfunc Run(check func(int) int, n int) int { return check(n) }\n\n// hooks receives an init-registered closure matching Run's dispatch\n// signature; the closure is never called during initialization, so its\n// write is latent - visible to a subject only if the whole-mask target\n// set drags it in.\nvar hooks []func(int) int\n\nvar boot = func() int {\n\tf := func(n int) int {\n\t\t_ = os.WriteFile(\"boot.txt\", []byte(\"x\"), 0o600)\n\t\treturn n\n\t}\n\thooks = append(hooks, f)\n\treturn len(hooks)\n}()\n\nfunc TestRun(t *testing.T) {\n\tif Run(func(n int) int { return n + boot - boot }, 1) != 1 {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/dyninitstdframe": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/dyninitstdframe": {
			"dyninitstdframe_test.go": "// Package dyninitstdframe pins the enumeration narrowing's std-frame\n// keep as load-bearing: an init-planted comparator handed to a\n// standard-library generic as a plain argument reaches a dispatch\n// site inside the std frame, where no operand proof ever runs - the\n// whole-mask drag must never drop there, so the comparator's latent\n// write refuses the subject at the subject tier.\npackage dyninitstdframe\n\nimport (\n\t\"os\"\n\t\"slices\"\n\t\"testing\"\n)\n\nvar hooks []func(int, int) int\n\nvar boot = func() int {\n\thooks = append(hooks, func(a, b int) int {\n\t\t_ = os.WriteFile(\"boot.txt\", []byte(\"x\"), 0o600)\n\t\treturn a - b\n\t})\n\treturn len(hooks)\n}()\n\n// RunSort is enumeration-closed through driveSort's direct call; the\n// driver is referenced nowhere and never executes, so the write stays\n// latent.\nfunc RunSort(check func(int) int, n int) int {\n\ts := []int{2, 1}\n\tslices.SortFunc(s, hooks[0])\n\treturn check(n) + s[0] - s[0] + boot - boot\n}\n\nfunc driveSort() int { return RunSort(func(n int) int { return n }, 1) }\n\nfunc TestNothing(t *testing.T) {}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/filemutations": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/filemutations": {
			"filemutations_test.go": "package filemutations\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc BenchmarkCreate(b *testing.B) {\n\tfor b.Loop() {\n\t\tf, _ := os.Create(\"out-create\")\n\t\tif f != nil {\n\t\t\t_ = f.Close()\n\t\t}\n\t}\n}\n\nfunc BenchmarkOpenFileCreate(b *testing.B) {\n\tfor b.Loop() {\n\t\tf, _ := os.OpenFile(\"out-openfile\", os.O_CREATE|os.O_WRONLY, 0o600)\n\t\tif f != nil {\n\t\t\t_ = f.Close()\n\t\t}\n\t}\n}\n\nfunc BenchmarkWriteFile(b *testing.B) {\n\tfor b.Loop() {\n\t\t_ = os.WriteFile(\"out-writefile\", []byte(\"x\"), 0o600)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flaglookupsubject": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flaglookupsubject": {
			"flaglookupsubject.go":      "package flaglookupsubject\n\nfunc Prod() int { return 7 }\n",
			"flaglookupsubject_test.go": "package flaglookupsubject\n\nimport (\n\t\"flag\"\n\t\"testing\"\n)\n\n// A subject-flow flag lookup keeps the exclusion, and its refusal\n// names the lookup - the flag package's internal usage prints are\n// help-path only and never outrank the real cause.\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 || flag.Lookup(\"flaglookupsubject.x\") != nil {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagparsemain": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagparsemain": {
			"flagparsemain.go":      "package flagparsemain\n\nfunc Prod() int { return 7 }\n",
			"flagparsemain_test.go": "package flagparsemain\n\nimport (\n\t\"flag\"\n\t\"os\"\n\t\"testing\"\n)\n\n// Parse is the read side of the registration channel - the registered\n// pointers' values change here, a channel the test log cannot audit -\n// so it keeps its refusal even in test-main flow.\nfunc TestMain(m *testing.M) {\n\t_ = flag.String(\"flagparsemain.mode\", \"fast\", \"fixture flag\")\n\tflag.Parse()\n\tos.Exit(m.Run())\n}\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagregalias": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregalias": {
			"flagregalias.go":      "package flagregalias\n\nimport \"flag\"\n\n// An init that escapes the registered storage's address into another\n// package variable creates an alias the mark cannot follow: the\n// startup-flow reference refusal blocks it at the escape site, so the\n// subject's laundered read (*q) can never prove observable.\nvar (\n\tquiet bool\n\tq     *bool\n)\n\nfunc init() {\n\tflag.BoolVar(&quiet, \"flagregalias.quiet\", false, \"fixture flag\")\n\tq = &quiet\n}\n\nfunc Prod() bool { return *q }\n",
			"flagregalias_test.go": "package flagregalias\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagregcallback": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregcallback": {
			"flagregcallback.go":      "package flagregcallback\n\nimport \"flag\"\n\n// Callback-family registration (Var, TextVar, Func, BoolFunc) runs\n// arbitrary code at flag.Parse: no sink judgment can bound what it\n// writes, so the family keeps the audited-pure exclusion outright.\nfunc init() {\n\tflag.BoolFunc(\"flagregcallback.trace\", \"fixture flag\", func(string) error { return nil })\n}\n\nfunc Prod() int { return 7 }\n",
			"flagregcallback_test.go": "package flagregcallback\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagregdep": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregdep": {
			"flagregdep.go":      "package flagregdep\n\nimport (\n\t_ \"github.com/greatliontech/gofresh/internal/closure/testdata/flagregescape\"\n)\n\n// A dependency's untraceable registration sink blocks this package's\n// subjects too: the poison covers every subject sharing the test\n// binary, not just the registering package's own.\nfunc Prod() int { return 7 }\n",
			"flagregdep_test.go": "package flagregdep\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregescape": {
			"flagregescape.go":      "package flagregescape\n\nimport \"flag\"\n\n// The registration target reaches the call through a helper parameter:\n// a sink the registration-facts judgment cannot trace to a\n// package-level variable. The package poisons - every subject blocks -\n// because an admitted registration with unguarded storage would be an\n// unobserved input channel.\nvar quiet bool\n\nfunc register(p *bool) { flag.BoolVar(p, \"flagregescape.quiet\", false, \"fixture flag\") }\n\nfunc init() { register(&quiet) }\n\nfunc Prod() int { return 7 }\n",
			"flagregescape_test.go": "package flagregescape\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagregescape": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregescape": {
			"flagregescape.go":      "package flagregescape\n\nimport \"flag\"\n\n// The registration target reaches the call through a helper parameter:\n// a sink the registration-facts judgment cannot trace to a\n// package-level variable. The package poisons - every subject blocks -\n// because an admitted registration with unguarded storage would be an\n// unobserved input channel.\nvar quiet bool\n\nfunc register(p *bool) { flag.BoolVar(p, \"flagregescape.quiet\", false, \"fixture flag\") }\n\nfunc init() { register(&quiet) }\n\nfunc Prod() int { return 7 }\n",
			"flagregescape_test.go": "package flagregescape\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagreginit": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagreginit": {
			"flagreginit.go":      "package flagreginit\n\nimport \"flag\"\n\n// Registration from a package initializer is a process-local registry\n// mutation - admitted. The subject never references the registered\n// variable; a reference would be the covert channel's read side and\n// refuses (the flag-backed reference refusal).\nvar verbose = flag.Bool(\"flagreginit.verbose\", false, \"fixture flag\")\n\nfunc Prod() int { return 7 }\n",
			"flagreginit_test.go": "package flagreginit\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagreginvoke": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagreginvoke": {
			"flagreginvoke.go":      "package flagreginvoke\n\nfunc Prod() int { return 7 }\n",
			"flagreginvoke_test.go": "package flagreginvoke\n\nimport (\n\t\"flag\"\n\t\"os\"\n\t\"testing\"\n)\n\ntype registrar interface {\n\tBoolVar(p *bool, name string, value bool, usage string)\n}\n\nvar quiet bool\n\n// A dynamically dispatched registration target is admitted nowhere:\n// the facts walk can sink-judge only static call sites, so the\n// family-named invoke target keeps its blocking classification.\nfunc TestMain(m *testing.M) {\n\tvar r registrar = flag.CommandLine\n\tr.BoolVar(&quiet, \"flagreginvoke.quiet\", false, \"fixture flag\")\n\tcode := m.Run()\n\tif quiet {\n\t\tcode = 0\n\t}\n\tos.Exit(code)\n}\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagreginvokeinit": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagreginvokeinit": {
			"flagreginvokeinit.go":      "package flagreginvokeinit\n\nimport \"flag\"\n\ntype registrar interface {\n\tBoolVar(p *bool, name string, value bool, usage string)\n}\n\nvar quiet bool\n\n// A dynamically dispatched registration target in startup flow keeps\n// its blocking classification: the facts walk can sink-judge only\n// static call sites, so admitting the invoke would leave the\n// registered storage unguarded.\nfunc init() {\n\tvar r registrar = flag.CommandLine\n\tr.BoolVar(&quiet, \"flagreginvokeinit.quiet\", false, \"fixture flag\")\n}\n\nfunc Prod() int { return 7 }\n",
			"flagreginvokeinit_test.go": "package flagreginvokeinit\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagreglocalmain": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagreglocalmain": {
			"flagreglocalmain.go":      "package flagreglocalmain\n\nfunc Prod() int { return 7 }\n",
			"flagreglocalmain_test.go": "package flagreglocalmain\n\nimport (\n\t\"flag\"\n\t\"os\"\n\t\"testing\"\n)\n\n// A registration result held in a local and read later is a sink the\n// registration-facts judgment cannot trace: the package poisons, so\n// the harness's post-run read of parsed state cannot slip through as\n// an unobserved input channel.\nfunc TestMain(m *testing.M) {\n\tv := flag.Bool(\"flagreglocalmain.v\", false, \"fixture flag\")\n\tcode := m.Run()\n\tif *v {\n\t\tcode = 0\n\t}\n\tos.Exit(code)\n}\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagregmain": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregmain": {
			"flagregmain.go":      "package flagregmain\n\nfunc Prod() int { return 7 }\n",
			"flagregmain_test.go": "package flagregmain\n\nimport (\n\t\"flag\"\n\t\"os\"\n\t\"testing\"\n)\n\n// Registration in user test-main flow is the same process-local\n// registry mutation - the covert channel is the read side, not the\n// registration: the call's own reference to the registered variable\n// and the store of a returned pointer are the sanctioned write shapes,\n// and nothing here ever reads either back.\nvar (\n\tmode  string\n\tmode2 *string\n)\n\nfunc TestMain(m *testing.M) {\n\tflag.StringVar(&mode, \"flagregmain.mode\", \"fast\", \"fixture flag\")\n\tmode2 = flag.String(\"flagregmain.mode2\", \"slow\", \"fixture flag\")\n\tos.Exit(m.Run())\n}\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagregmainread": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregmainread": {
			"flagregmainread.go":      "package flagregmainread\n\nimport \"flag\"\n\n// Registered storage read in user test-main flow: the implicit\n// flag.Parse inside m.Run can have written it before the read, so the\n// reference is the covert channel's read side - here it masks the\n// harness exit code on command-line state the test log cannot audit.\nvar verbose = flag.Bool(\"flagregmainread.verbose\", false, \"fixture flag\")\n\nfunc Prod() int { return 7 }\n",
			"flagregmainread_test.go": "package flagregmainread\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestMain(m *testing.M) {\n\tcode := m.Run()\n\tif *verbose {\n\t\tcode = 0\n\t}\n\tos.Exit(code)\n}\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagregmethod": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregmethod": {
			"flagregmethod.go":      "package flagregmethod\n\nimport \"flag\"\n\n// Method-form registration and the method-expression form judge the\n// pointer argument past the receiver: flag.CommandLine is an audited\n// selector, the storage is marked, and a subject reading none of it\n// proves observable. The white-box facts assertions pin the receiver\n// judgment itself.\nvar (\n\tverbose bool\n\tquiet   bool\n)\n\nfunc init() {\n\tflag.CommandLine.BoolVar(&verbose, \"flagregmethod.v\", false, \"fixture flag\")\n\treg := (*flag.FlagSet).BoolVar\n\treg(flag.CommandLine, &quiet, \"flagregmethod.q\", false, \"fixture flag\")\n}\n\nfunc Prod() int { return 7 }\n",
			"flagregmethod_test.go": "package flagregmethod\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagregstruct": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregstruct": {
			"flagregstruct.go":      "package flagregstruct\n\nimport \"flag\"\n\n// Registration into a field of a package-level struct roots at the\n// struct variable through the field selection: the whole variable\n// carries flag-registered state, so a subject-flow reference to it\n// refuses while subjects that never touch it stay observable.\nvar cfg struct {\n\tChecks int\n}\n\n// An array-element target roots at the array variable through the\n// index selection exactly as a field does.\nvar arr [2]int\n\n// A value-family result stored through a field selection is the same\n// sanctioned write: the selection computing the store's address passes\n// with it.\nvar holder struct{ V *bool }\n\nfunc init() {\n\tflag.IntVar(&cfg.Checks, \"flagregstruct.checks\", 100, \"fixture flag\")\n\tflag.IntVar(&arr[0], \"flagregstruct.n\", 1, \"fixture flag\")\n\tholder.V = flag.Bool(\"flagregstruct.v\", false, \"fixture flag\")\n}\n\nfunc Prod() int { return 7 }\n\nfunc ProdRead() int { return cfg.Checks }\n\n// Passing the registered field's address to an ordinary call escapes\n// it - only the registration write's own argument computation passes.\nfunc deref(p *int) int { return *p }\n\nfunc ProdEscape() int { return deref(&cfg.Checks) }\n",
			"flagregstruct_test.go": "package flagregstruct\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n\nfunc TestProdRead(t *testing.T) {\n\tif ProdRead() < 0 {\n\t\tt.Fatal()\n\t}\n}\n\nfunc TestProdEscape(t *testing.T) {\n\tif ProdEscape() < 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagregsubject": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregsubject": {
			"flagregsubject.go":      "package flagregsubject\n\nimport \"flag\"\n\n// Registration reached from subject flow keeps the exclusion whatever\n// its sink: the admission is tier-scoped to startup and test-main\n// flow, so the subject-tier walk classifies flag.Bool itself - the\n// traceable store keeps the package unpoisoned, pinning that the\n// refusal comes from the walk's own classification.\nvar late *bool\n\nfunc Prod() int {\n\tlate = flag.Bool(\"flagregsubject.late\", false, \"fixture flag\")\n\treturn 7\n}\n",
			"flagregsubject_test.go": "package flagregsubject\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/fmtsink": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/fmtsink": {
			"fmtsink_test.go": "package fmtsink\n\nimport (\n\t\"bytes\"\n\t\"fmt\"\n\t\"io\"\n\t\"strings\"\n\t\"testing\"\n)\n\nfunc TestFprintfBuffer(t *testing.T) {\n\tvar b bytes.Buffer\n\tfmt.Fprintf(&b, \"value %d\", 1)\n\tif b.Len() == 0 {\n\t\tt.Fatal(\"empty\")\n\t}\n}\n\nfunc TestFprintlnBuilder(t *testing.T) {\n\tvar b strings.Builder\n\tfmt.Fprintln(&b, \"value\")\n\tif b.Len() == 0 {\n\t\tt.Fatal(\"empty\")\n\t}\n}\n\nfunc TestFprintfHelperBuffer(t *testing.T) {\n\tvar b bytes.Buffer\n\tformatInto(&b, 1)\n\tif b.Len() == 0 {\n\t\tt.Fatal(\"empty\")\n\t}\n}\n\nfunc TestFprintfPhiBuffers(t *testing.T) {\n\tvar a, b bytes.Buffer\n\tw := io.Writer(&a)\n\tif len(strings.Repeat(\"a\", 2)) > 1 {\n\t\tw = &b\n\t}\n\tfmt.Fprintf(w, \"value %d\", 1)\n}\n\nfunc TestFprintfCallResult(t *testing.T) {\n\tfmt.Fprintf(newWriter(), \"value %d\", 1)\n}\n\nfunc TestFprintfPhiCallEscape(t *testing.T) {\n\tvar a bytes.Buffer\n\tw := io.Writer(&a)\n\tif len(strings.Repeat(\"a\", 2)) > 1 {\n\t\tw = newWriter()\n\t}\n\tfmt.Fprintf(w, \"value %d\", 1)\n}\n\nfunc TestFprintfHelperMixed(t *testing.T) {\n\tvar b bytes.Buffer\n\tformatMixed(&b, 1)\n\tformatMixed(newWriter(), 2)\n}\n\nfunc formatInto(w io.Writer, n int) {\n\tfmt.Fprintf(w, \"value %d\", n)\n}\n\nfunc formatMixed(w io.Writer, n int) {\n\tfmt.Fprintf(w, \"mixed %d\", n)\n}\n\nfunc newWriter() io.Writer {\n\treturn &bytes.Buffer{}\n}\n\n// shared and cfg pin the concrete-expression arm: a *bytes.Buffer\n// expression pins the sink type regardless of which instance it\n// denotes — global and field-loaded buffers admit exactly as a direct\n// Write on the audited type would.\nvar shared bytes.Buffer\n\ntype holder struct{ Buf *bytes.Buffer }\n\nvar cfg = holder{Buf: &bytes.Buffer{}}\n\nfunc TestFprintfGlobalBuffer(t *testing.T) {\n\tfmt.Fprintf(&shared, \"value %d\", 1)\n\tif shared.Len() == 0 {\n\t\tt.Fatal(\"empty\")\n\t}\n}\n\nfunc TestFprintfFieldBuffer(t *testing.T) {\n\tfmt.Fprintf(cfg.Buf, \"value %d\", 1)\n\tif cfg.Buf.Len() == 0 {\n\t\tt.Fatal(\"empty\")\n\t}\n}\n\n// nullWriter is in-memory in fact but outside the audited sink pair —\n// the admission is a bounded audit, not an inference.\ntype nullWriter struct{}\n\nfunc (*nullWriter) Write(p []byte) (int, error) { return len(p), nil }\n\nfunc TestFprintfLocalWriterType(t *testing.T) {\n\tfmt.Fprintf(&nullWriter{}, \"value %d\", 1)\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/fmtsinkstdout": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/fmtsinkstdout": {
			"fmtsinkstdout_test.go": "package fmtsinkstdout\n\nimport (\n\t\"fmt\"\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestFprintfStdout(t *testing.T) {\n\tfmt.Fprintf(os.Stdout, \"value %d\", 1)\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/fmtsinkvalue": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/fmtsinkvalue": {
			"fmtsinkvalue_test.go": "package fmtsinkvalue\n\nimport (\n\t\"bytes\"\n\t\"fmt\"\n\t\"testing\"\n)\n\n// format carries fmt.Fprintf through a package-level value so the\n// subject's call site stays a dynamic reach — the writer-sink admission\n// applies to static calls only, whatever the arguments carry.\nvar format = fmt.Fprintf\n\nfunc TestValueFormatBuffer(t *testing.T) {\n\tvar b bytes.Buffer\n\t_, _ = format(&b, \"value %d\", 1)\n\tif b.Len() == 0 {\n\t\tt.Fatal(\"empty\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/fuzzsibling": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/fuzzsibling": {
			"fuzzsibling_test.go": "package fuzzsibling\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc FuzzDecode(f *testing.F) {\n\tf.Fuzz(func(t *testing.T, data []byte) {\n\t\t_ = len(data)\n\t})\n}\n\nfunc TestSiblingRead(t *testing.T) {\n\t_, _ = os.ReadFile(\"fixture.txt\")\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/genericescape": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/genericescape": {
			"genericescape.go":      "// Package genericescape pins that a generic method reached only by interface\n// escape (never called, so not RTA-reachable) is still analyzed. The\n// benchmark boxes Box[int] into an interface; addInterfaceMethodSet enqueues\n// the instantiated method, whose own object carries no source decl node —\n// its generic origin must be resolved and scanned, or the method's effect\n// stays invisible and a proof over it is a false-valid.\npackage genericescape\n\nimport \"os\"\n\ntype Box[T any] struct{ v T }\n\nfunc (b Box[T]) Secret() int { return 4096 + len(os.Getenv(\"ESCAPE\")) }\n\nvar sink any\n\nfunc leak(x any) { sink = x }\n",
			"genericescape_test.go": "package genericescape\n\nimport \"testing\"\n\nfunc BenchmarkGenericEscape(b *testing.B) {\n\tfor b.Loop() {\n\t\tleak(Box[int]{})\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/genericmethod": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/genericmethod": {
			"genericmethod.go": "// Package genericmethod exercises method subjects on a generic receiver type:\n// each method reaches a distinct helper, so per-method closures stay distinct.\npackage genericmethod\n\ntype Box[T any] struct{ v T }\n\n// Get is a value-receiver method on a generic type, reaching getHelper.\nfunc (b Box[T]) Get() int { return getHelper() }\n\n// Set is a pointer-receiver method on a generic type, reaching setHelper.\nfunc (b *Box[T]) Set() int { return setHelper() }\n\nfunc getHelper() int { return 1 }\n\nfunc setHelper() int { return 2 }\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/globalcallback": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/globalcallback": {
			"globalcallback.go": "package globalcallback\n\ntype callback func() int\n\nvar current = callback(local)\n\nfunc local() int { return 1 }\n\nfunc alternate() int { return 2 }\n\nfunc Set() { current = alternate }\n\nfunc F() int { return current() }\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnessarg": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnessarg": {
			"harnessarg_test.go": "package harnessarg\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// loud's String reads a non-constant path, so the subject tier must\n// refuse the proof — and the only path that keeps String reachable is\n// the argument method set of the t.Log call, pinning that the audited\n// harness channel leaves argument methods visible to reachability.\ntype loud struct{ path string }\n\nfunc (l loud) String() string {\n\tdata, _ := os.ReadFile(l.path)\n\treturn string(data)\n}\n\nfunc TestLogEffectfulArgument(t *testing.T) {\n\tt.Log(loud{path: \"baseline.txt\"})\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnessclock": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnessclock": {
			"harnessclock_test.go": "package harnessclock\n\nimport (\n\t\"testing\"\n\t\"time\"\n)\n\n// TestLogAmbientClock mixes the audited harness channel with a sibling\n// weakest-rank classification (the ambient clock's unaudited-standard\n// read): the legacy projection must keep the causal reason — the\n// harness fact ranks strictly below every other classification.\nfunc TestLogAmbientClock(t *testing.T) {\n\tt.Log(\"clock heartbeat at\", time.Now())\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnesserrshared": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnesserrshared": {
			"harnesserrshared_test.go": "package harnesserrshared\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// sharedErr is the universe-interface form of the planted channel: the\n// wrapper wraps error.Error — a method with no declaring package — and\n// its receiver provenance must refuse exactly like any other interface\n// wrapper over shared mutable state.\nvar sharedErr error\n\ntype envErr struct{}\n\nfunc (envErr) Error() string { return os.Getenv(\"HARNESSERRSHARED_SECRET\") }\n\nfunc TestPlant(t *testing.T) {\n\tsharedErr = envErr{}\n}\n\nfunc TestUseErrBound(t *testing.T) {\n\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n\tif sharedErr != nil {\n\t\tf := sharedErr.Error\n\t\t_ = f()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnessexitoutside": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnessexitoutside": {
			"harnessexitoutside.go":      "package harnessexitoutside\n\nfunc Prod() int { return 7 }\n",
			"harnessexitoutside_test.go": "package harnessexitoutside\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// The os.Exit epilogue admission is scoped to the TestMain declaration:\n// an os.Exit in a helper outside it keeps the package-scan finding even\n// in a TestMain-bearing file.\nfunc hardStop() {\n\tos.Exit(3)\n}\n\nfunc TestMain(m *testing.M) {\n\tos.Exit(m.Run())\n}\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\thardStop()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnesslog": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnesslog": {
			"harnesslog_test.go": "package harnesslog\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestReadFileFatal(t *testing.T) {\n\tdata, err := os.ReadFile(\"baseline.txt\")\n\tif err != nil {\n\t\tt.Fatal(err)\n\t}\n\tif len(data) == 0 {\n\t\tt.Fatalf(\"empty baseline: %q\", data)\n\t}\n}\n\nfunc TestReadFileLogAndError(t *testing.T) {\n\tdata, err := os.ReadFile(\"baseline.txt\")\n\tif err != nil {\n\t\tt.Error(err)\n\t}\n\tt.Log(\"read bytes:\", len(data))\n\tt.Logf(\"read %d bytes\", len(data))\n\tif len(data) == 0 {\n\t\tt.Errorf(\"empty baseline\")\n\t}\n}\n\n// executeFailureFixture stays false at runtime; reachability analysis does\n// not evaluate it, so the failure methods stay statically reached.\nvar executeFailureFixture bool\n\nfunc TestReadFileSkipAndFail(t *testing.T) {\n\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\tt.Skip(\"no baseline:\", err)\n\t}\n\tif len(\"baseline\") == 0 {\n\t\tt.Skipf(\"impossible length\")\n\t}\n\tif executeFailureFixture {\n\t\tt.Fail()\n\t\tif t.Failed() {\n\t\t\tt.FailNow()\n\t\t}\n\t\tt.SkipNow()\n\t}\n}\n\n// TestLocalTBFatal reaches the harness failure channel through a\n// locally-closed testing.TB value, so the call is an RTA-resolved\n// interface dispatch decided by the dynamic-target admission rather\n// than a static call.\nfunc TestLocalTBFatal(t *testing.T) {\n\tvar tb testing.TB\n\ttb = t\n\tdata, err := os.ReadFile(\"baseline.txt\")\n\tif err != nil {\n\t\ttb.Fatal(err)\n\t}\n\tif len(data) == 0 {\n\t\ttb.Fatalf(\"empty baseline\")\n\t}\n}\n\n// TestLogOnly reaches nothing but the harness logging channel: the\n// observation proof grants, while the legacy projection must still\n// refuse to call it verifiable — an audited harness call is not purity\n// evidence.\nfunc TestLogOnly(t *testing.T) {\n\tt.Log(\"baseline fixture heartbeat\")\n}\n\n// TestBoundMethodFatal reaches the harness failure channel through a\n// bound method value: the SSA wrapper carries the method object, so the\n// admission must classify it exactly as the direct call form.\nfunc TestBoundMethodFatal(t *testing.T) {\n\tfail := t.Fatal\n\tdata, err := os.ReadFile(\"baseline.txt\")\n\tif err != nil {\n\t\tfail(err)\n\t}\n\tif len(data) == 0 {\n\t\tfail(\"empty baseline\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnessmain": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnessmain": {
			"harnessmain_test.go": "package harnessmain\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// planted is the post-run channel: a test plants an implementation, and\n// TestMain dispatches it after m.Run — the one startup flow that can\n// carry a test-planted value, refused because the startup walk cannot\n// enumerate the dispatch.\nvar planted testing.TB\n\ntype envTB struct{ *testing.T }\n\nfunc (envTB) Fatal(...any) { _ = os.Getenv(\"HARNESSMAIN_SECRET\") }\n\nfunc TestMain(m *testing.M) {\n\t_ = m.Run()\n\tif planted != nil {\n\t\tplanted.Fatal(\"late\")\n\t}\n}\n\nfunc TestPlant(t *testing.T) {\n\tplanted = envTB{t}\n}\n\nfunc TestRead(t *testing.T) {\n\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnessmainbound": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnessmainbound": {
			"harnessmainbound_test.go": "package harnessmainbound\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// planted is the method-value form of the post-run channel: TestMain\n// eta-expands the planted value's method, so the dispatch hides inside\n// a synthetic bound wrapper whose std-attributed body the startup walk\n// never scans — the wrapper's bound receiver carries the provenance.\nvar planted testing.TB\n\ntype envTB struct{ *testing.T }\n\nfunc (envTB) Fatal(...any) { _ = os.Getenv(\"HARNESSMAINBOUND_SECRET\") }\n\nfunc TestMain(m *testing.M) {\n\t_ = m.Run()\n\tif planted != nil {\n\t\tf := planted.Fatal\n\t\tf(\"bound late\")\n\t}\n}\n\nfunc TestPlant(t *testing.T) {\n\tplanted = envTB{t}\n}\n\nfunc TestRead(t *testing.T) {\n\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnessmainfmt": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnessmainfmt": {
			"harnessmainfmt.go":      "package harnessmainfmt\n\nfunc Prod() int { return 7 }\n",
			"harnessmainfmt_test.go": "package harnessmainfmt\n\nimport (\n\t\"bytes\"\n\t\"fmt\"\n\t\"os\"\n\t\"testing\"\n)\n\n// The writer-sink admission holds in test-main flow exactly as in the\n// other tiers: a format into a locally constructed in-memory sink is\n// value computation, not an effect.\nfunc TestMain(m *testing.M) {\n\tvar b bytes.Buffer\n\tfmt.Fprintf(&b, \"setup %d\", Prod())\n\t_ = b.Len()\n\tos.Exit(m.Run())\n}\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnessmainfunc": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnessmainfunc": {
			"harnessmainfunc_test.go": "package harnessmainfunc\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// token's package-local signature keeps standard-library function values\n// out of the planted variable's enumerated flow, so the refusal below is\n// the operand-provenance widen itself, never an incidental std target.\ntype token struct{ n int }\n\n// planted is the function-value form of the post-run channel: a test\n// plants a closure, TestMain calls it after m.Run — a computed call,\n// not an interface invoke, refused on the same operand provenance.\nvar planted func(token) token\n\nfunc TestMain(m *testing.M) {\n\t_ = m.Run()\n\tif planted != nil {\n\t\t_ = planted(token{n: 1})\n\t}\n}\n\nfunc TestPlant(t *testing.T) {\n\tplanted = func(v token) token { _ = os.Getenv(\"HARNESSMAINFUNC_SECRET\"); return v }\n}\n\nfunc TestRead(t *testing.T) {\n\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnessmainlaunder": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnessmainlaunder": {
			"harnessmainlaunder_test.go": "package harnessmainlaunder\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// planted reaches TestMain's call laundered through the empty\n// interface: the interface hop must not wash the wrapper obligation\n// off the closed-value walk.\nvar planted testing.TB\n\ntype envTB struct{ *testing.T }\n\nfunc (envTB) Fatal(...any) { _ = os.Getenv(\"HARNESSMAINLAUNDER_SECRET\") }\n\nfunc TestMain(m *testing.M) {\n\t_ = m.Run()\n\tif planted != nil {\n\t\tvar x any = planted.Fatal\n\t\tf := x.(func(...any))\n\t\tf(\"laundered late\")\n\t}\n}\n\nfunc TestPlant(t *testing.T) {\n\tplanted = envTB{t}\n}\n\nfunc TestRead(t *testing.T) {\n\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnessmainlocal": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnessmainlocal": {
			"harnessmainlocal_test.go": "package harnessmainlocal\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\ntype quiet interface{ Quiet() }\n\ntype quietDoer struct{}\n\nfunc (quietDoer) Quiet() {}\n\n// TestMain dispatches only its own locally-constructed value through a\n// package-local interface: the startup widen must not fire — the\n// planted channel is shared mutable state, never a test-main's own\n// constructions.\nfunc TestMain(m *testing.M) {\n\tvar q quiet = quietDoer{}\n\t_ = m.Run()\n\tq.Quiet()\n}\n\nfunc TestRead(t *testing.T) {\n\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnessmainphi": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnessmainphi": {
			"harnessmainphi_test.go": "package harnessmainphi\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// planted reaches TestMain's call through a phi of bound-method values:\n// the closed-value walk's binding obligation, not the call site's\n// syntax, must carry the refusal.\nvar planted testing.TB\n\ntype envTB struct{ *testing.T }\n\nfunc (envTB) Fatal(...any) { _ = os.Getenv(\"HARNESSMAINPHI_SECRET\") }\n\nfunc TestMain(m *testing.M) {\n\t_ = m.Run()\n\tif planted != nil {\n\t\tf := planted.Fatal\n\t\tif len(\"x\") == 1 {\n\t\t\tf = planted.Fatal\n\t\t}\n\t\tf(\"phi late\")\n\t}\n}\n\nfunc TestPlant(t *testing.T) {\n\tplanted = envTB{t}\n}\n\nfunc TestRead(t *testing.T) {\n\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnessmainthunk": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnessmainthunk": {
			"harnessmainthunk_test.go": "package harnessmainthunk\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// planted is the method-expression form of the post-run channel: the\n// thunk is a static callee and the planted value rides as its receiver\n// argument, so the argument carries the dispatch provenance.\nvar planted testing.TB\n\ntype envTB struct{ *testing.T }\n\nfunc (envTB) Fatal(...any) { _ = os.Getenv(\"HARNESSMAINTHUNK_SECRET\") }\n\nfunc TestMain(m *testing.M) {\n\t_ = m.Run()\n\tif planted != nil {\n\t\tf := testing.TB.Fatal\n\t\tf(planted, \"late\")\n\t}\n}\n\nfunc TestPlant(t *testing.T) {\n\tplanted = envTB{t}\n}\n\nfunc TestRead(t *testing.T) {\n\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnessmainwrite": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnessmainwrite": {
			"harnessmainwrite.go":      "package harnessmainwrite\n\nfunc Prod() int { return 7 }\n",
			"harnessmainwrite_test.go": "package harnessmainwrite\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// TestMain performs an unobserved filesystem mutation: a write is not\n// a bracketed observation input, so the test-main walk's per-effect\n// classification blocks the proof with the write's own reason.\nfunc TestMain(m *testing.M) {\n\t_ = os.WriteFile(\"out.txt\", []byte(\"x\"), 0o644)\n\t_ = os.Remove(\"out.txt\")\n\tos.Exit(m.Run())\n}\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnessobserved": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnessobserved": {
			"harnessobserved.go":      "package harnessobserved\n\nfunc Prod() int { return 7 }\n",
			"harnessobserved_test.go": "package harnessobserved\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// setup runs inside TestMain and reads a fixture file - test-main flow\n// runs with the test log installed (the log installs in the\n// toolchain-generated test-main package's initializer, after every\n// dependency initializer and before the user test main), so the\n// admitted read is a bracketed observation input, not a startup\n// effect.\nfunc setup() {\n\tif f, err := os.Open(\"fixture.dat\"); err == nil {\n\t\tf.Close()\n\t}\n}\n\nfunc TestMain(m *testing.M) {\n\tsetup()\n\tos.Exit(m.Run())\n}\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnesssetenv": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnesssetenv": {
			"harnesssetenv_test.go": "package harnesssetenv\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestSetenvStaysBlocked(t *testing.T) {\n\tt.Setenv(\"HARNESSLOG_FIXTURE\", \"1\")\n\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n\n// TestCleanRead reaches no ambient surface itself: its refusal can come\n// only from the package-scan backstop over the sibling's Setenv, so the\n// row pins the blocker boundary one exemption too wide would erase.\nfunc TestCleanRead(t *testing.T) {\n\tdata, err := os.ReadFile(\"baseline.txt\")\n\tif err != nil {\n\t\tt.Fatal(err)\n\t}\n\tif len(data) == 0 {\n\t\tt.Fatal(\"empty baseline\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnessshared": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnessshared": {
			"harnessshared_test.go": "package harnessshared\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// shared is the cross-subject channel: analysis is subject-scoped, the\n// process heap is not. TestPlant's runtime flow populates it with an\n// implementation TestConsume's attributed enumeration cannot see.\nvar shared testing.TB\n\ntype envTB struct{ *testing.T }\n\nfunc (envTB) Fatal(...any) { _ = os.Getenv(\"HARNESSSHARED_SECRET\") }\n\nfunc TestPlant(t *testing.T) {\n\tshared = envTB{t}\n}\n\nfunc helper(tb testing.TB) []byte {\n\tdata, err := os.ReadFile(\"baseline.txt\")\n\tif err != nil {\n\t\ttb.Fatal(err)\n\t}\n\treturn data\n}\n\nfunc TestConsume(t *testing.T) {\n\t_ = helper(t)\n\tif shared != nil {\n\t\t_ = helper(shared)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnessshareddispatch": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnessshareddispatch": {
			"harnessshareddispatch_test.go": "package harnessshareddispatch\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// shared is the subject-tier form of the wrapper channel: sibling\n// runtime flow plants an implementation, and the consuming subjects\n// dispatch it through the synthetic wrapper family — the bound method\n// value and the method-expression thunk — whose receiver provenance\n// must refuse exactly as a direct invoke's operand would.\nvar shared testing.TB\n\ntype envTB struct{ *testing.T }\n\nfunc (envTB) Fatal(...any) { _ = os.Getenv(\"HARNESSSHAREDDISPATCH_SECRET\") }\n\nfunc TestPlant(t *testing.T) {\n\tshared = envTB{t}\n}\n\nfunc TestUseBound(t *testing.T) {\n\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n\tif shared != nil {\n\t\tf := shared.Fatal\n\t\tf(\"bound\")\n\t}\n}\n\nfunc TestUseThunk(t *testing.T) {\n\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n\tif shared != nil {\n\t\tf := testing.TB.Fatal\n\t\tf(shared, \"thunk\")\n\t}\n}\n\n// TestUsePhi carries the wrapper through a phi so the call operand is\n// a merge of closure values: the binding obligation rides the value\n// walk, not the call site's syntax.\nfunc TestUsePhi(t *testing.T) {\n\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n\tif shared != nil {\n\t\tf := shared.Fatal\n\t\tif len(\"x\") == 1 {\n\t\t\tf = shared.Fatal\n\t\t}\n\t\tf(\"phi\")\n\t}\n}\n\n// TestUseThunkLocal is the closed-receiver control: the thunk's\n// receiver argument derives from the subject's own flow, so the\n// dispatch keeps the wrapped method's ordinary classification.\nfunc TestUseThunkLocal(t *testing.T) {\n\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n\tvar tb testing.TB = t\n\tf := testing.TB.Fatal\n\tif len(\"x\") == 0 {\n\t\tf(tb, \"never\")\n\t}\n}\n\n// TestUseThunkPhi carries the method-expression thunk through a phi:\n// a thunk VALUE is never closed — its receiver arrives at call sites\n// the value walk cannot see — so the computed call must refuse.\nfunc TestUseThunkPhi(t *testing.T) {\n\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n\tif shared != nil {\n\t\tf := testing.TB.Fatal\n\t\tif len(\"x\") == 1 {\n\t\t\tf = testing.TB.Fatal\n\t\t}\n\t\tf(shared, \"thunk phi\")\n\t}\n}\n\n// TestUseLaunder washes the planted wrapper through the empty\n// interface and a type assertion: the interface hop must not launder\n// the binding obligation.\nfunc TestUseLaunder(t *testing.T) {\n\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n\tif shared != nil {\n\t\tvar x any = shared.Fatal\n\t\tf := x.(func(...any))\n\t\tf(\"laundered\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnesstb": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnesstb": {
			"harnesstb_test.go": "package harnesstb\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// mustBaseline routes the harness failure channel through testing.TB, so\n// the subject reaches Fatal as an RTA-resolved interface dispatch rather\n// than a static call.\nfunc mustBaseline(tb testing.TB) []byte {\n\tdata, err := os.ReadFile(\"baseline.txt\")\n\tif err != nil {\n\t\ttb.Fatal(err)\n\t}\n\treturn data\n}\n\nfunc TestHelperTBFatal(t *testing.T) {\n\tif len(mustBaseline(t)) == 0 {\n\t\tt.Fatalf(\"empty baseline\")\n\t}\n}\n\n// TestHelperTBTwice feeds one interface value to two call sites of the\n// same helper: a completed provenance evaluation of the shared value\n// must not poison the second site's check.\nfunc TestHelperTBTwice(t *testing.T) {\n\tvar tb testing.TB = t\n\tif len(mustBaseline(tb)) == 0 {\n\t\tt.Fatalf(\"empty baseline\")\n\t}\n\tif len(mustBaseline(tb)) == 0 {\n\t\tt.Fatalf(\"still empty\")\n\t}\n}\n\n// mustBaselineDeep threads the interface value through its own\n// recursion: the provenance walk's cycle guard must refuse fail-closed\n// (and terminate) rather than admit or diverge.\nfunc mustBaselineDeep(tb testing.TB, n int) []byte {\n\tif n > 0 {\n\t\treturn mustBaselineDeep(tb, n-1)\n\t}\n\tdata, err := os.ReadFile(\"baseline.txt\")\n\tif err != nil {\n\t\ttb.Fatal(err)\n\t}\n\treturn data\n}\n\nfunc TestHelperTBRecursive(t *testing.T) {\n\tif len(mustBaselineDeep(t, 2)) == 0 {\n\t\tt.Fatalf(\"empty baseline\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnesstbenv": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnesstbenv": {
			"harnesstbenv_test.go": "package harnesstbenv\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// mustEnv routes a non-audited harness method through the interface\n// dispatch shape: the subject-determined dispatch admission classifies\n// the enumerated targets instead of widening, and testing.Setenv's own\n// process-mutation classification refuses the subject causally.\nfunc mustEnv(tb testing.TB) {\n\ttb.Setenv(\"HARNESSTBENV_FIXTURE\", \"1\")\n}\n\nfunc TestHelperTBSetenv(t *testing.T) {\n\tmustEnv(t)\n\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnesswrap": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnesswrap": {
			"harnesswrap_test.go": "package harnesswrap\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// quietT satisfies testing.TB through the embedded core while\n// overriding Fatal with an effect-free body: the dispatch target set is\n// no longer harness-only, so the subject-determined dispatch admission\n// classifies the enumerated targets instead of widening - the admission\n// keys on operand provenance and target analyzability, never on what\n// the override's body happens to do. The wrapper type's promoted\n// method set drains testing's bodies into the walk, and the subject\n// then refuses causally on the file I/O reached there.\ntype quietT struct{ *testing.T }\n\nfunc (quietT) Fatal(...any) {}\n\nfunc helper(tb testing.TB) []byte {\n\tdata, err := os.ReadFile(\"baseline.txt\")\n\tif err != nil {\n\t\ttb.Fatal(err)\n\t}\n\treturn data\n}\n\nfunc TestQuietWrappedFatal(t *testing.T) {\n\tif len(helper(quietT{t})) == 0 {\n\t\tt.Fatalf(\"empty baseline\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/importbinding": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/importbinding": {
			"importbinding_test.go": "package importbinding\n\nimport (\n\tcodec \"encoding/json\"\n\t\"testing\"\n)\n\nfunc BenchmarkImportBinding(b *testing.B) {\n\tfor b.Loop() {\n\t\t_, _ = codec.Marshal(1)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/initcwd": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/initcwd": {
			"initcwd_test.go": "package initcwd\n\nimport (\n\t\"os\"\n\t\"syscall\"\n\t\"testing\"\n)\n\nfunc init() {\n\t_ = syscall.Chdir(\"data\")\n}\n\nfunc BenchmarkInitCWD(b *testing.B) {\n\tfor b.Loop() {\n\t\t_, _ = os.ReadFile(\"fixture.txt\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/initdynamic": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/initdynamic": {
			"initdynamic_test.go": "package initdynamic\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nvar initData []byte\n\ntype reader interface {\n\tread()\n}\n\ntype source struct{}\n\nfunc (source) read() {\n\tinitData, _ = os.ReadFile(\"pre.txt\")\n}\n\nfunc init() {\n\tvar r reader = source{}\n\tr.read()\n}\n\nfunc BenchmarkInitDynamic(b *testing.B) {\n\tfor b.Loop() {\n\t\t_ = len(initData)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/initfmthelper": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/initfmthelper": {
			"initfmthelper_test.go": "package initfmthelper\n\nimport (\n\t\"bytes\"\n\t\"fmt\"\n\t\"io\"\n\t\"testing\"\n)\n\nvar banner string\n\nfunc init() {\n\tvar b bytes.Buffer\n\tdescribe(&b, 1)\n\tbanner = b.String()\n}\n\n// describe receives its writer across a call boundary: startup flow\n// carries no subject-attributed parameter analysis, so the crossing\n// refuses and the Fprintf keeps its effect even though every caller\n// passes a local buffer.\nfunc describe(w io.Writer, n int) {\n\tfmt.Fprintf(w, \"ready %d\", n)\n}\n\nfunc TestAfterInitHelperFormat(t *testing.T) {\n\tif banner == \"\" {\n\t\tt.Fatal(\"empty\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/initfmtsink": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/initfmtsink": {
			"initfmtsink_test.go": "package initfmtsink\n\nimport (\n\t\"bytes\"\n\t\"fmt\"\n\t\"testing\"\n)\n\nvar banner string\n\nfunc init() {\n\tvar b bytes.Buffer\n\tfmt.Fprintf(&b, \"ready %d\", 1)\n\tbanner = b.String()\n}\n\nfunc TestAfterInitFormat(t *testing.T) {\n\tif banner == \"\" {\n\t\tt.Fatal(\"empty\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/initfmtvalue": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/initfmtvalue": {
			"initfmtvalue_test.go": "package initfmtvalue\n\nimport (\n\t\"bytes\"\n\t\"fmt\"\n\t\"testing\"\n)\n\nvar banner string\n\n// format carries fmt.Fprintf through a package-level value so the init\n// call site stays a dynamic reach — a single-assignment local would\n// SSA-resolve to a static call and take the static leg's admission.\nvar format = fmt.Fprintf\n\nfunc init() {\n\tvar b bytes.Buffer\n\t_, _ = format(&b, \"ready %d\", 1)\n\tbanner = b.String()\n}\n\nfunc TestAfterInitValueFormat(t *testing.T) {\n\tif banner == \"\" {\n\t\tt.Fatal(\"empty\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/initglobaldispatch": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/initglobaldispatch": {
			"initglobaldispatch_test.go": "package initglobaldispatch\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\ntype noter interface{ note() }\n\ntype quietNote struct{}\n\nfunc (quietNote) note() {}\n\n// handler is shared mutable state an initializer dispatches through:\n// initializer flow stays unwidened — nothing is plantable before tests\n// run — so this package's subjects keep their proofs.\nvar handler noter = quietNote{}\n\nfunc init() {\n\thandler.note()\n}\n\nfunc TestRead(t *testing.T) {\n\tif _, err := os.ReadFile(\"baseline.txt\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/initstdcallback": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/initstdcallback": {
			"initstdcallback_test.go": "package initstdcallback\n\nimport (\n\t\"os\"\n\t\"sort\"\n\t\"testing\"\n)\n\nvar initData []byte\n\nfunc init() {\n\txs := []int{2, 1}\n\tsort.Slice(xs, func(i, j int) bool {\n\t\tinitData, _ = os.ReadFile(\"pre.txt\")\n\t\treturn xs[i] < xs[j]\n\t})\n}\n\nfunc BenchmarkInitStdCallback(b *testing.B) {\n\tfor b.Loop() {\n\t\t_ = len(initData)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/initstdhelper": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/initstdhelper": {
			"initstdhelper_test.go": "package initstdhelper\n\nimport (\n\t\"path/filepath\"\n\t\"testing\"\n)\n\nvar matches []string\n\nfunc init() {\n\tmatches, _ = filepath.Glob(\"fixtures/*\")\n}\n\nfunc BenchmarkInitStdHelper(b *testing.B) {\n\tfor b.Loop() {\n\t\t_ = len(matches)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/mixedexternal": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/mixedexternal": {
			"mixedexternal_test.go": "package mixedexternal\n\nimport (\n\t\"net\"\n\t\"os\"\n\t\"testing\"\n)\n\nfunc BenchmarkMixedExternal(b *testing.B) {\n\tfor b.Loop() {\n\t\t_, _ = os.ReadFile(\"fixture.txt\")\n\t\tconn, _ := net.Dial(\"tcp\", \"127.0.0.1:1\")\n\t\tif conn != nil {\n\t\t\t_ = conn.Close()\n\t\t}\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/mkdir": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/mkdir": {
			"mkdir_test.go": "package mkdir\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc BenchmarkMkdir(b *testing.B) {\n\tfor b.Loop() {\n\t\t_ = os.Mkdir(\"scratch\", 0o700)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/mkdirtemp": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/mkdirtemp": {
			"mkdirtemp_test.go": "package mkdirtemp\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc BenchmarkMkdirTemp(b *testing.B) {\n\tfor b.Loop() {\n\t\t_, _ = os.MkdirTemp(\"\", \"pew-*\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/observablecallbackbad": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/observablecallbackbad": {
			"observablecallbackbad_test.go": "package observablecallbackbad\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestSubtestRead(t *testing.T) {\n\tt.Run(\"child\", func(*testing.T) {\n\t\t_, _ = os.ReadFile(\"fixture.txt\")\n\t})\n}\n\nfunc TestNestedSubtestRead(t *testing.T) {\n\tt.Run(\"outer\", func(t *testing.T) {\n\t\tt.Run(\"inner\", func(*testing.T) {\n\t\t\t_, _ = os.ReadFile(\"fixture.txt\")\n\t\t})\n\t})\n}\n\nvar never bool\n\nfunc TestConstructedMRun(t *testing.T) {\n\tif never {\n\t\t_ = new(testing.M).Run()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/observableconcurrent": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/observableconcurrent": {
			"observableconcurrent_test.go": "package observableconcurrent\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestConcurrentFileRead(*testing.T) {\n\tfile, _ := os.Open(\"fixture.txt\")\n\tif file != nil {\n\t\tbuffer := make([]byte, 1)\n\t\tgo file.Read(buffer)\n\t\t_ = file.Close()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/observablefreshinit": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/observablefreshinit": {
			"observablefreshinit_test.go": "package observablefreshinit\n\nimport (\n\t\"os\"\n\t\"path/filepath\"\n\t\"testing\"\n)\n\n// The startup stage calls the same helper with a non-fresh argument:\n// caller-site enumeration is per-subject reachability, so the init call\n// is invisible to the boundary analysis — soundness rests on the\n// startup walk blocking every startup-reachable effect first, and this\n// package pins exactly that mask.\nfunc init() {\n\tsharedHelper(\"/tmp/fixture-startup\")\n}\n\nfunc sharedHelper(dir string) {\n\ttarget := filepath.Join(dir, \"s.txt\")\n\tif err := os.WriteFile(target, []byte(\"fixture\"), 0o600); err != nil {\n\t\treturn\n\t}\n\t_ = os.Remove(target)\n}\n\nfunc TestFreshHelperShadowedByStartupCaller(t *testing.T) {\n\tsharedHelper(t.TempDir())\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/observableopenfile": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/observableopenfile": {
			"observableopenfile_test.go": "package observableopenfile\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestOpenFile(*testing.T) {\n\t_, _ = os.OpenFile(\"fixture.txt\", os.O_RDONLY, 0)\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/observableprocess": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/observableprocess": {
			"observableprocess_test.go": "package observableprocess\n\nimport (\n\t\"os/exec\"\n\t\"testing\"\n)\n\nfunc TestCommand(*testing.T) {\n\t_ = exec.Command(\"true\").Run()\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/observablestat": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/observablestat": {
			"observablestat_test.go": "package observablestat\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestStat(*testing.T) {\n\t_, _ = os.Stat(\"fixture.txt\")\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/openfileread": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/openfileread": {
			"openfileread_test.go": "package openfileread\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc BenchmarkOpenFileRead(b *testing.B) {\n\tfor b.Loop() {\n\t\tf, _ := os.OpenFile(\"fixture.txt\", os.O_RDONLY, 0)\n\t\tif f != nil {\n\t\t\t_ = f.Close()\n\t\t}\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/openrootread": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/openrootread": {
			"openrootread_test.go": "package openrootread\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc BenchmarkRootOpenFileRead(b *testing.B) {\n\troot, _ := os.OpenRoot(\".\")\n\tif root != nil {\n\t\tdefer root.Close()\n\t}\n\tfor b.Loop() {\n\t\tf, _ := root.OpenFile(\"fixture.txt\", os.O_RDONLY, 0)\n\t\tif f != nil {\n\t\t\t_ = f.Close()\n\t\t}\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/pathbinding": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/pathbinding": {
			"pathbinding_test.go": "package pathbinding\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nvar initBytes []byte\n\nfunc load() []byte {\n\tb, _ := os.ReadFile(\"link\")\n\treturn b\n}\n\nfunc init() {\n\t_ = os.Remove(\"link\")\n\t_ = os.Symlink(\"pre.txt\", \"link\")\n\tinitBytes = load()\n}\n\nfunc BenchmarkPathBinding(b *testing.B) {\n\t_ = os.Remove(\"link\")\n\t_ = os.Symlink(\"post.txt\", \"link\")\n\tfor b.Loop() {\n\t\t_ = len(initBytes) + len(load())\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/reflectexternal": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/reflectexternal": {
			"reflectexternal_test.go": "package reflectexternal\n\nimport (\n\t\"os\"\n\t\"reflect\"\n\t\"testing\"\n)\n\nfunc target() {\n\t_, _ = os.ReadFile(\"fixture.txt\")\n}\n\nfunc BenchmarkReflectExternal(b *testing.B) {\n\tv := reflect.ValueOf(target)\n\tfor b.Loop() {\n\t\tv.Call(nil)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/reflectfixture": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/reflectfixture": {
			"reflect_test.go": "package reflectfixture\n\nimport (\n\t\"reflect\"\n\t\"testing\"\n)\n\nfunc target() {}\n\nfunc BenchmarkReflect(b *testing.B) {\n\tv := reflect.ValueOf(target)\n\tfor b.Loop() {\n\t\tv.Call(nil)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/scalarglobalslice": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/scalarglobalslice": {
			"scalarglobalslice.go":      "// Package scalarglobalslice is the scalar-global boundary's\n// unsafe.Slice channel, deliberately its own package: the call site\n// carries no unsafe.Pointer-typed value the subject walk can price,\n// so the refusal is the package scan's — and that block is\n// package-wide (only the unsafe.Pointer class is narrowed to subject\n// attribution), which is why this channel cannot share\n// scalarglobalwrite's package without pre-blocking its clean\n// direct-write subject.\npackage scalarglobalslice\n\nimport \"unsafe\"\n\n// Count is the non-carrier scalar global.\nvar Count int\n\n// BumpSlice mutates the global with NO unsafe.Pointer-typed value\n// anywhere in the body (operands *int and a length, result []int).\nfunc BumpSlice() int {\n\ts := unsafe.Slice(&Count, 1)\n\ts[0]++\n\treturn Count\n}\n",
			"scalarglobalslice_test.go": "package scalarglobalslice\n\nimport \"testing\"\n\n// TestSliceWrite mutates the scalar global through unsafe.Slice and\n// must refuse at the package scan, the channel's only arm.\nfunc TestSliceWrite(*testing.T) {\n\t_ = BumpSlice()\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/scalarglobalwrite": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/scalarglobalwrite": {
			"scalarglobalwrite.go":      "// Package scalarglobalwrite is the named anchor for the scalar-global\n// mutation boundary: a plain package-level variable sits outside the\n// shared-dynamic-state carrier net by clause, its direct mutation is\n// admitted (per-process-deterministic content the whole-graph hash\n// covers; the admission's enforcement is the view-tier plain-data\n// builder test), and an unsafe-mediated mutation refuses on the\n// channel it uses — an unsafe.Pointer-typed value refuses at the\n// subject walk, while unsafe.Slice and kin, whose call sites carry no\n// such value, keep the package-scan block. The laundered-address\n// entry shape (a plain uintptr crossing the signature) is pinned by\n// the closure-verdict test for a uintptr address input — the\n// re-materializing conversion is the same walk tripwire, and go vet's\n// unsafeptr check keeps that variant out of tree.\npackage scalarglobalwrite\n\nimport \"unsafe\"\n\n// Count is the non-carrier scalar global: no function, interface,\n// channel, or unsafe pointer anywhere in its type.\nvar Count int\n\n// BumpDirect is the admitted twin: a direct write to the scalar.\nfunc BumpDirect() int {\n\tCount++\n\treturn Count\n}\n\n// BumpUnsafe mutates the global through an unsafe.Pointer-typed\n// value — the subject walk's channel.\nfunc BumpUnsafe() int {\n\tp := (*int)(unsafe.Pointer(&Count))\n\t*p++\n\treturn Count\n}\n",
			"scalarglobalwrite_test.go": "package scalarglobalwrite\n\nimport \"testing\"\n\n// TestDirectWrite mutates the scalar global directly: no external\n// effect, no carrier, no unsafe — the observability proof grants.\nfunc TestDirectWrite(*testing.T) {\n\t_ = BumpDirect()\n}\n\n// TestUnsafeWrite mutates the same global through an\n// unsafe.Pointer-typed value and must refuse at the subject tier\n// (the widen path), never the package scan.\nfunc TestUnsafeWrite(*testing.T) {\n\t_ = BumpUnsafe()\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/sharedchdir": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/sharedchdir": {
			"sharedchdir_test.go": "package sharedchdir\n\nimport (\n\t\"os\"\n\t\"syscall\"\n\t\"testing\"\n)\n\nvar initBytes []byte\n\nfunc load() []byte {\n\tb, _ := os.ReadFile(\"fixture.txt\")\n\treturn b\n}\n\nfunc init() {\n\t_ = syscall.Chdir(\"pre\")\n\tinitBytes = load()\n}\n\nfunc BenchmarkSharedChdir(b *testing.B) {\n\t_ = syscall.Chdir(\"../post\")\n\tfor b.Loop() {\n\t\t_ = len(initBytes) + len(load())\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/sharedfchdir": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/sharedfchdir": {
			"sharedfchdir_test.go": "//go:build !plan9\n\n// Plan 9 has a different syscall.Open signature; this fixture exercises the\n// descriptor-based POSIX-compatible call surface.\npackage sharedfchdir\n\nimport (\n\t\"os\"\n\t\"syscall\"\n\t\"testing\"\n)\n\nvar initBytes []byte\n\nfunc load() []byte {\n\tb, _ := os.ReadFile(\"fixture.txt\")\n\treturn b\n}\n\nfunc chdir(name string) {\n\tfd, err := syscall.Open(name, syscall.O_RDONLY, 0)\n\tif err != nil {\n\t\treturn\n\t}\n\tdefer syscall.Close(fd)\n\t_ = syscall.Fchdir(fd)\n}\n\nfunc init() {\n\tchdir(\"pre\")\n\tinitBytes = load()\n}\n\nfunc BenchmarkSharedFchdir(b *testing.B) {\n\tchdir(\"../post\")\n\tfor b.Loop() {\n\t\t_ = len(initBytes) + len(load())\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/sharedfile": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/sharedfile": {
			"sharedfile_test.go": "package sharedfile\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nvar initBytes []byte\n\nfunc load() []byte {\n\tb, _ := os.ReadFile(\"fixture.txt\")\n\treturn b\n}\n\nfunc init() {\n\tinitBytes = load()\n}\n\nfunc BenchmarkSharedFile(b *testing.B) {\n\tfor b.Loop() {\n\t\t_ = len(initBytes) + len(load())\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/sharedglobal": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/sharedglobal": {
			"sharedglobal_test.go": "package sharedglobal\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nvar (\n\tpath = \"pre.txt\"\n\tdata []byte\n)\n\nfunc load() {\n\tdata, _ = os.ReadFile(path)\n}\n\nfunc init() {\n\tload()\n}\n\nfunc BenchmarkSharedGlobal(b *testing.B) {\n\tpath = \"post.txt\"\n\tfor b.Loop() {\n\t\tload()\n\t\t_ = len(data)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/sharedparam": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/sharedparam": {
			"sharedparam_test.go": "package sharedparam\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nvar preBytes []byte\n\nfunc load(name string) []byte {\n\tb, _ := os.ReadFile(name)\n\treturn b\n}\n\nfunc init() {\n\tpreBytes = load(\"pre.txt\")\n}\n\nfunc BenchmarkSharedParam(b *testing.B) {\n\tfor b.Loop() {\n\t\t_ = len(preBytes) + len(load(\"post.txt\"))\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/stdcallback": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/stdcallback": {
			"stdcallback_test.go": "package stdcallback\n\nimport (\n\t\"sort\"\n\t\"testing\"\n)\n\ntype byLen []string\n\nfunc (b byLen) Len() int { return len(b) }\n\nfunc (b byLen) Less(i, j int) bool { return len(b[i]) < len(b[j]) }\n\nfunc (b byLen) Swap(i, j int) { b[i], b[j] = b[j], b[i] }\n\nfunc BenchmarkSortCallback(b *testing.B) {\n\tvalues := byLen{\"bbb\", \"a\", \"cc\"}\n\tfor b.Loop() {\n\t\tsort.Sort(values)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/stdwrapper": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/stdwrapper": {
			"stdwrapper_test.go": "package stdwrapper\n\nimport (\n\t\"html/template\"\n\t\"testing\"\n)\n\nfunc BenchmarkTemplateParseFiles(b *testing.B) {\n\tfor b.Loop() {\n\t\t_, _ = template.ParseFiles(\"fixture.tmpl\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/subtestbench": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/subtestbench": {
			"subtestbench_test.go": "package subtestbench\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc BenchmarkSubRead(b *testing.B) {\n\tb.Run(\"child\", func(*testing.B) {\n\t\t_, _ = os.ReadFile(\"fixture.txt\")\n\t})\n}\n\nfunc BenchmarkSubPure(b *testing.B) {\n\tb.Run(\"child\", func(*testing.B) {\n\t\t_ = len(\"x\")\n\t})\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/subtestparallel": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/subtestparallel": {
			"subtestparallel_test.go": "package subtestparallel\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestParallelChild(t *testing.T) {\n\tt.Run(\"child\", func(t *testing.T) {\n\t\tt.Parallel()\n\t\t_, _ = os.ReadFile(\"fixture.txt\")\n\t})\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/syscallbinding": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/syscallbinding": {
			"syscallbinding_test.go": "//go:build !plan9\n\n// Plan 9 has no syscall.Unlink; this fixture exercises that binding mutation.\npackage syscallbinding\n\nimport (\n\t\"os\"\n\t\"syscall\"\n\t\"testing\"\n)\n\nvar initBytes []byte\n\nfunc load() []byte {\n\tb, _ := os.ReadFile(\"link\")\n\treturn b\n}\n\nfunc init() {\n\t_ = syscall.Unlink(\"link\")\n\t_ = syscall.Symlink(\"pre.txt\", \"link\")\n\tinitBytes = load()\n}\n\nfunc BenchmarkSyscallBinding(b *testing.B) {\n\t_ = syscall.Unlink(\"link\")\n\t_ = syscall.Symlink(\"post.txt\", \"link\")\n\tfor b.Loop() {\n\t\t_ = len(initBytes) + len(load())\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/tempdir": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/tempdir": {
			"tempdir_test.go": "package tempdir\n\nimport \"testing\"\n\nfunc BenchmarkTempDir(b *testing.B) {\n\tfor b.Loop() {\n\t\t_ = b.TempDir()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/testmainfile": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/testmainfile": {
			"testmainfile_test.go": "package testmainfile\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nvar mainData []byte\n\nfunc TestMain(m *testing.M) {\n\tmainData, _ = os.ReadFile(\"fixture.txt\")\n\tos.Exit(m.Run())\n}\n\nfunc BenchmarkTestMainFile(b *testing.B) {\n\tfor b.Loop() {\n\t\t_ = len(mainData)\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/testmainhelper": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/testmainhelper": {
			"testmainhelper_test.go": "package testmainhelper\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc run(m *testing.M) int {\n\treturn m.Run()\n}\n\nfunc TestMain(m *testing.M) {\n\trun(m)\n}\n\nfunc TestRead(*testing.T) {\n\t_, _ = os.ReadFile(\"fixture.txt\")\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/testmainroot": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/testmainroot": {
			"testmainroot_test.go": "package testmainroot\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nvar scale int\nvar sink int\n\nfunc TestMain(m *testing.M) {\n\tscale = setup()\n\tos.Exit(m.Run())\n}\n\nfunc setup() int { return 1 }\n\nfunc BenchmarkTestMainRoot(b *testing.B) {\n\tfor b.Loop() {\n\t\tsink += scale\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/testmainruntimefile": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/testmainruntimefile": {
			"testmainruntimefile_test.go": "package testmainruntimefile\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestMain(m *testing.M) {\n\tos.Exit(m.Run())\n}\n\nfunc BenchmarkTestMainRuntimeFile(b *testing.B) {\n\tfor b.Loop() {\n\t\t_, _ = os.ReadFile(\"fixture.txt\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/toolchainindirect": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/toolchainindirect": {
			"toolchainindirect_test.go": "package toolchainindirect\n\nimport (\n\t\"testing\"\n\n\t\"github.com/greatliontech/gofresh/internal/closure/testdata/toolchainindirect/helper\"\n)\n\nfunc TestIndirectRuntimeSurface(*testing.T) {\n\t_ = helper.Cores()\n}\n",
		},
		"github.com/greatliontech/gofresh/internal/closure/testdata/toolchainindirect/helper": {
			"helper.go": "// Package helper reaches a non-admitted runtime surface from outside\n// the subject's own package, so the subject-tier classification — not\n// the maximal AST scan of the test file — must catch it.\npackage helper\n\nimport \"runtime\"\n\n// Cores reports the scheduler-visible core count.\nfunc Cores() int { return runtime.NumCPU() }\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/toolchaininit": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/toolchaininit": {
			"toolchaininit_test.go": "package toolchaininit\n\nimport (\n\t\"os\"\n\t\"path/filepath\"\n\t\"runtime\"\n\t\"testing\"\n)\n\n// The accessor admission is subject-stage only: capturing it at package\n// scope is a startup effect and blocks uniformly.\nvar root = runtime.GOROOT()\n\nfunc TestReadThroughInitRoot(*testing.T) {\n\t_, _ = os.ReadFile(filepath.Join(root, \"VERSION\"))\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/toolchainread": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/toolchainread": {
			"toolchainread_test.go": "package toolchainread\n\nimport (\n\t\"os\"\n\t\"path/filepath\"\n\t\"runtime\"\n\t\"testing\"\n)\n\nfunc TestAccessorAlone(*testing.T) {\n\t_ = runtime.GOROOT()\n}\n\nfunc TestReadVersion(*testing.T) {\n\t_, _ = os.ReadFile(filepath.Join(runtime.GOROOT(), \"VERSION\"))\n}\n\nfunc TestOpenUnderToolchain(*testing.T) {\n\tfile, _ := os.Open(filepath.Join(runtime.GOROOT(), \"VERSION\"))\n\tif file != nil {\n\t\t_ = file.Close()\n\t}\n}\n\nfunc TestReadDirUnderToolchain(*testing.T) {\n\tentries, _ := os.ReadDir(filepath.Join(runtime.GOROOT(), \"src\"))\n\tfor _, entry := range entries {\n\t\t_ = entry.Name()\n\t\t_ = entry.IsDir()\n\t\t_ = entry.Type()\n\t}\n}\n\nfunc TestWriteIntoToolchain(*testing.T) {\n\t// The nonexistent intermediate directory makes the write fail on\n\t// every host - executing this fixture must never touch a writable\n\t// toolchain tree - while the analyzer still sees the os.WriteFile\n\t// shape it must refuse.\n\t_ = os.WriteFile(filepath.Join(runtime.GOROOT(), \"gofresh-fixture-never-created\", \"scratch.txt\"), []byte(\"x\"), 0o644)\n}\n\nfunc TestDynamicComponent(*testing.T) {\n\tname := os.Getenv(\"GOFRESH_COMPONENT\")\n\t_, _ = os.ReadFile(filepath.Join(runtime.GOROOT(), name))\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/toolchainruntime": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/toolchainruntime": {
			"toolchainruntime_test.go": "package toolchainruntime\n\nimport (\n\t\"runtime\"\n\t\"testing\"\n)\n\nfunc TestOtherRuntimeSurface(*testing.T) {\n\t_ = runtime.NumCPU()\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/unixatbinding": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/unixatbinding": {
			"unixatbinding_test.go": "//go:build unix\n\npackage unixatbinding\n\nimport (\n\t\"os\"\n\t\"testing\"\n\n\t\"golang.org/x/sys/unix\"\n)\n\nvar initBytes []byte\n\nfunc load() []byte {\n\tb, _ := os.ReadFile(\"link\")\n\treturn b\n}\n\nfunc init() {\n\t_ = unix.Unlinkat(unix.AT_FDCWD, \"link\", 0)\n\t_ = unix.Symlinkat(\"pre.txt\", unix.AT_FDCWD, \"link\")\n\tinitBytes = load()\n}\n\nfunc BenchmarkUnixAtBinding(b *testing.B) {\n\t_ = unix.Unlinkat(unix.AT_FDCWD, \"link\", 0)\n\t_ = unix.Symlinkat(\"post.txt\", unix.AT_FDCWD, \"link\")\n\tfor b.Loop() {\n\t\t_ = len(initBytes) + len(load())\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/unixcwd": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/unixcwd": {
			"unixcwd_test.go": "//go:build unix\n\npackage unixcwd\n\nimport (\n\t\"os\"\n\t\"testing\"\n\n\t\"golang.org/x/sys/unix\"\n)\n\nfunc init() {\n\t_ = unix.Chdir(\"data\")\n}\n\nfunc BenchmarkUnixCWD(b *testing.B) {\n\tfor b.Loop() {\n\t\t_, _ = os.ReadFile(\"fixture.txt\")\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/unixfchdir": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/unixfchdir": {
			"unixfchdir_test.go": "//go:build unix\n\npackage unixfchdir\n\nimport (\n\t\"os\"\n\t\"testing\"\n\n\t\"golang.org/x/sys/unix\"\n)\n\nvar initBytes []byte\n\nfunc load() []byte {\n\tb, _ := os.ReadFile(\"fixture.txt\")\n\treturn b\n}\n\nfunc chdir(name string) {\n\tfd, err := unix.Open(name, unix.O_RDONLY, 0)\n\tif err != nil {\n\t\treturn\n\t}\n\tdefer unix.Close(fd)\n\t_ = unix.Fchdir(fd)\n}\n\nfunc init() {\n\tchdir(\"pre\")\n\tinitBytes = load()\n}\n\nfunc BenchmarkUnixFchdir(b *testing.B) {\n\tchdir(\"../post\")\n\tfor b.Loop() {\n\t\t_ = len(initBytes) + len(load())\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/unixopencreate": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/unixopencreate": {
			"unixopencreate_test.go": "//go:build unix\n\npackage unixopencreate\n\nimport (\n\t\"testing\"\n\n\t\"golang.org/x/sys/unix\"\n)\n\nfunc BenchmarkUnixOpenCreate(b *testing.B) {\n\tfor b.Loop() {\n\t\tfd, err := unix.Open(\"out\", unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY, 0o600)\n\t\tif err == nil {\n\t\t\t_ = unix.Close(fd)\n\t\t}\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/unsafesibling": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/unsafesibling": {
			"grammar.go":            "package unsafesibling\n\nimport \"unsafe\"\n\n// Grammar and Carry model an operator-grammar fixture file: unsafe\n// references a clean sibling subject never reaches.\ntype Grammar unsafe.Pointer\n\nfunc Carry(p unsafe.Pointer) unsafe.Pointer { return p }\n",
			"unsafesibling_test.go": "package unsafesibling\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// TestCleanRead never reaches the sibling grammar file's unsafe\n// declarations: its observability proof must not be pre-blocked by\n// the package scan on their account.\nfunc TestCleanRead(*testing.T) {\n\t_, _ = os.ReadFile(\"fixture.txt\")\n}\n\n// TestReachesUnsafe carries an unsafe-typed value through its own\n// walk and must refuse at the subject tier.\nfunc TestReachesUnsafe(*testing.T) {\n\tp := Carry(nil)\n\t_ = p\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/unsafeslice": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/unsafeslice": {
			"doc.go":              "// Package unsafeslice exercises the scan-blocking unsafe symbols whose\n// call sites the subject walk's type-graph arm cannot price.\npackage unsafeslice\n",
			"unsafeslice_test.go": "package unsafeslice\n\nimport (\n\t\"testing\"\n\t\"unsafe\"\n)\n\n// TestSliceHeader's unsafe.Slice site carries no unsafe.Pointer-typed\n// value - operands are a *byte and a length, the result a []byte - so\n// the subject walk's type-graph arm cannot price it and the package\n// scan must keep blocking: an out-of-bounds read through the fabricated\n// slice is a testlog-invisible input.\nfunc TestSliceHeader(*testing.T) {\n\tvar b byte\n\ts := unsafe.Slice(&b, 1)\n\t_ = s[0]\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/unsafewrapped": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/unsafewrapped": {
			"unsafewrapped_test.go": "package unsafewrapped\n\nimport (\n\t\"testing\"\n\n\t\"github.com/greatliontech/gofresh/internal/closure/testdata/unsafewrapped/handle\"\n)\n\n// TestWrappedUnsafeHandle reaches a value whose named type wraps\n// unsafe.Pointer without any reachable code producing an unsafe-typed\n// value directly: the analysis discovers the fact only through the named\n// type's underlying structure, and the proof must refuse.\nfunc TestWrappedUnsafeHandle(t *testing.T) {\n\tif handle.New().Size() != 1 {\n\t\tt.Fatal(\"handle\")\n\t}\n}\n",
		},
		"github.com/greatliontech/gofresh/internal/closure/testdata/unsafewrapped/handle": {
			"handle.go": "// Package handle wraps an opaque pointer whose unsafe payload is visible\n// only through the named type's underlying structure: no exported path\n// produces an unsafe.Pointer-typed value, so an analysis that stops at the\n// named type without walking its underlying misses the fact entirely.\npackage handle\n\nimport \"unsafe\"\n\n// Handle carries an opaque pointer.\ntype Handle struct {\n\tp unsafe.Pointer\n}\n\n// New returns an empty handle without touching the pointer field.\nfunc New() Handle { return Handle{} }\n\n// Size reports a fixed size without touching the pointer field.\nfunc (h Handle) Size() int { return 1 }\n",
		},
	},
}

const batchIsolationPackage = "github.com/greatliontech/gofresh/internal/closure/testdata/batchisolation"

func TestAttributedRTAEqualsIndependentRTA(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	supplyRegisteredFixtures(t, h, batchIsolationPackage)
	prog, err := h.loadCached(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{
		{Package: batchIsolationPackage, Symbol: "AddressTaker"},
		{Package: batchIsolationPackage, Symbol: "DynamicCaller"},
		{Package: batchIsolationPackage, Symbol: "Materializer"},
		{Package: batchIsolationPackage, Symbol: "Invoker"},
		{Package: batchIsolationPackage, Symbol: "Production"},
		{Package: batchIsolationPackage, Symbol: "BenchmarkHarness"},
	}
	got, err := attributedReachableSets(context.Background(), true, h.source.pureDelegates, prog, subjects)
	if err != nil {
		t.Fatal(err)
	}
	for i, subject := range subjects {
		solo, err := attributedReachableSets(context.Background(), true, h.source.pureDelegates, prog, []Subject{subject})
		if err != nil {
			t.Fatalf("solo attributedReachableSets(%s): %v", subject.Symbol, err)
		}
		assertSameReachable(t, subject.Symbol+" (batched vs solo)", got[i].functions, solo[0].functions)
		want := independentReachableSet(t, prog, subject.Symbol)
		assertSameReachable(t, subject.Symbol+" (attributed vs upstream)", got[i].functions, want)
	}
}

func TestAttributedRTADynamicFactsRemainIsolated(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	supplyRegisteredFixtures(t, h, batchIsolationPackage)
	prog, err := h.loadCached(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{
		{Package: batchIsolationPackage, Symbol: "AddressTaker"},
		{Package: batchIsolationPackage, Symbol: "DynamicCaller"},
		{Package: batchIsolationPackage, Symbol: "Materializer"},
		{Package: batchIsolationPackage, Symbol: "Invoker"},
	}
	reachable, err := attributedReachableSets(context.Background(), true, h.source.pureDelegates, prog, subjects)
	if err != nil {
		t.Fatal(err)
	}

	dynamicTarget := prog.Roots["dynamicTarget"]
	if dynamicTarget == nil || !reachable[0].functions[dynamicTarget] {
		t.Fatal("address-taking subject did not reach dynamicTarget")
	}
	if reachable[1].functions[dynamicTarget] {
		t.Fatal("dynamic-call subject inherited another subject's address-taken function")
	}

	concreteMethod := prog.Roots["concrete.Run"]
	if concreteMethod == nil || !reachable[2].functions[concreteMethod] {
		t.Fatal("materializing subject did not reach concrete.Run")
	}
	if reachable[3].functions[concreteMethod] {
		t.Fatal("invoke subject inherited another subject's concrete runtime type")
	}
	nestedMethod := prog.Roots["nested.Exported"]
	if nestedMethod == nil || !reachable[2].functions[nestedMethod] {
		t.Fatal("materializing subject did not reach exported method of recursive runtime type")
	}
	if reachable[3].functions[nestedMethod] {
		t.Fatal("invoke subject inherited another subject's recursive runtime type")
	}

}

func TestTier2UsesOnlyResolvedAttributedDispatch(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	fixtures := newFixturePrograms(t, h)
	for _, tc := range []struct {
		symbol string
		widen  bool
	}{
		{symbol: "KnownDynamic", widen: false},
		{symbol: "CallbackRoot", widen: true},
		{symbol: "Invoker", widen: true},
	} {
		t.Run(tc.symbol, func(t *testing.T) {
			fixtures.supply(t, batchIsolationPackage)
			result, err := computeTier2Result(h, batchIsolationPackage, tc.symbol)
			if err != nil {
				t.Fatal(err)
			}
			if result.widen != tc.widen {
				t.Fatalf("widen = %v (%s), want %v", result.widen, result.widenReason, tc.widen)
			}
		})
	}
}

func TestTier2WidensInitializedMutableGlobalDispatch(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	result, err := computeTier2Result(h, "github.com/greatliontech/gofresh/internal/closure/testdata/globalcallback", "F")
	if err != nil {
		t.Fatal(err)
	}
	if !result.widen {
		t.Fatalf("initialized mutable global did not widen: %+v", result)
	}
}

func TestAttributedRTARootMasks(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	supplyRegisteredFixtures(t, h, batchIsolationPackage)
	prog, err := h.loadCached(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{
		{Package: batchIsolationPackage, Symbol: "Production"},
		{Package: batchIsolationPackage, Symbol: "BenchmarkHarness"},
	}
	reachable, err := attributedReachableSets(context.Background(), true, h.source.pureDelegates, prog, subjects)
	if err != nil {
		t.Fatal(err)
	}
	startup := prog.Roots["startupHelper"]
	testMainHelper := prog.Roots["testMainHelper"]
	if startup == nil || !reachable[0].functions[startup] || !reachable[1].functions[startup] {
		t.Fatal("initializer root did not propagate to every subject")
	}
	if testMainHelper == nil || reachable[0].functions[testMainHelper] {
		t.Fatal("production subject reached conditional TestMain setup")
	}
	if !reachable[1].functions[testMainHelper] {
		t.Fatal("test-file subject did not reach TestMain setup")
	}
	siblingHelper := prog.Roots["benchmarkSiblingHelper"]
	if siblingHelper == nil || reachable[1].functions[siblingHelper] {
		t.Fatal("selected benchmark reached a sibling through generated harness registration")
	}
}

func TestAttributedRTAHonorsCancellationDuringTraversal(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	supplyRegisteredFixtures(t, h, batchIsolationPackage)
	prog, err := h.loadCached(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &cancelAfterContext{Context: context.Background(), remaining: 2}
	_, err = attributedReachableSets(ctx, true, h.source.pureDelegates, prog, []Subject{{Package: batchIsolationPackage, Symbol: "Materializer"}})
	if err == nil {
		t.Fatal("attributed RTA ignored cancellation during traversal")
	}
}

func TestTier2ProjectionHonorsCancellationDuringTraversal(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	supplyRegisteredFixtures(t, h, batchIsolationPackage)
	prog, err := h.loadCached(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: batchIsolationPackage, Symbol: "Materializer"}
	reachable, err := attributedReachableSets(context.Background(), true, h.source.pureDelegates, prog, []Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	metas, err := h.list(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	base := newTier2Base(h, prog, metas)
	h.ctx = &cancelAfterContext{Context: context.Background(), remaining: 3}
	if _, err := h.tier2Reachable(base, reachable[0]); err == nil {
		t.Fatal("tier-2 projection ignored cancellation during traversal")
	}
}

func TestObservabilityBatchSplitsAttributedStateAtMaskWidth(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/batchbound\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The first slice's last subject and the second slice's first both
	// dispatch through an interface variable no walk closes, so each
	// refusal is the subject's own: a slice wider than the mask would
	// shift the first's bit off the word and prove it observable, and a
	// walk that dropped the second slice would do the same to the other.
	var source strings.Builder
	source.WriteString("package batchbound\n\nvar Sink interface{ M() }\n\n")
	subjects := make([]Subject, maxAttributedSubjects+1)
	for i := range subjects {
		symbol := fmt.Sprintf("F%d", i)
		if i == len(subjects)-1 || i == maxAttributedSubjects-1 {
			fmt.Fprintf(&source, "func %s() int { Sink.M(); return %d }\n", symbol, i)
		} else {
			fmt.Fprintf(&source, "func %s() int { return %d }\n", symbol, i)
		}
		subjects[i] = Subject{Package: "example.com/batchbound", Symbol: symbol}
	}
	if err := os.WriteFile(filepath.Join(dir, "batchbound.go"), []byte(source.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	last := subjects[len(subjects)-1]
	solo, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	want, err := solo.ComputeObservabilityBatch([]Subject{last})
	if err != nil {
		t.Fatal(err)
	}
	if got[last] != want[last] {
		t.Fatalf("boundary subject proof = %+v, independent = %+v", got[last], want[last])
	}
	if got[last].Observable || got[last].Reason == "" {
		t.Fatalf("the second slice's subject lost its own refusal: %+v", got[last])
	}
	edge := subjects[maxAttributedSubjects-1]
	if got[edge].Observable || got[edge].Reason == "" {
		t.Fatalf("the first slice's last subject lost its bit: %+v", got[edge])
	}
	if !got[subjects[0]].Observable {
		t.Fatalf("a pure first-slice subject was refused: %+v", got[subjects[0]])
	}
	// The rooted inventories slice on the same width over the whole
	// batch: a subject past the word would report a complete inventory
	// with nothing in it, which discharges everything.
	rooted, err := h.ComputeRootedFunctions(h.ctx, subjects)
	if err != nil {
		t.Fatal(err)
	}
	if proof := rooted[subjects[0]]; !proof.Complete || len(proof.Fns) == 0 {
		t.Fatalf("a pure subject's rooted inventory is not a complete, non-empty set: %+v", proof)
	}
	for _, subject := range []Subject{edge, last} {
		if proof := rooted[subject]; proof.Complete && len(proof.Fns) == 0 {
			t.Fatalf("%s: a complete but empty rooted inventory", subject.Symbol)
		}
	}
}

func TestStandardDynamicTargetMasksRemainSubjectLocal(t *testing.T) {
	subjects := []Subject{
		{Package: batchIsolationPackage, Symbol: "TestStandardDynamic"},
		{Package: batchIsolationPackage, Symbol: "Production"},
	}
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	supplyRegisteredFixtures(t, h, batchIsolationPackage)
	prog, err := h.loadCached(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	reachable, err := attributedReachableSets(context.Background(), true, h.source.pureDelegates, prog, subjects)
	if err != nil {
		t.Fatal(err)
	}
	metas, err := h.list(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	base := newTier2Base(h, prog, metas)
	batched := make([]tier2Result, len(subjects))
	for i, subject := range subjects {
		batched[i], err = h.tier2Reachable(base, reachable[i])
		if err != nil {
			t.Fatalf("batched analysis (%s): %v", subject.Symbol, err)
		}
		independentHasher, err := newAt("")
		if err != nil {
			t.Fatal(err)
		}
		independent, err := computeTier2Result(independentHasher, subject.Package, subject.Symbol)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(batched[i].effects, independent.effects) ||
			batched[i].widen != independent.widen ||
			batched[i].widenReason != independent.widenReason ||
			batched[i].unverifiable != independent.unverifiable ||
			batched[i].reason != independent.reason {
			t.Fatalf("batched %s = %+v, independent = %+v", subject.Symbol, batched[i], independent)
		}
	}
	if !batched[0].unverifiable {
		t.Fatalf("standard dynamic target was verifiable: %+v", batched[0])
	}
}

func independentReachableSet(t *testing.T, prog *program, symbol string) map[*ssa.Function]bool {
	t.Helper()
	root := prog.Roots[symbol]
	if root == nil {
		t.Fatalf("subject root %s not found", symbol)
	}
	roots := []*ssa.Function{root}
	if prog.TestMain != nil && subjectRunsThroughHarness(prog, root) {
		roots = append(roots, prog.TestMain)
	}
	for _, pkg := range prog.Prog.AllPackages() {
		if isGeneratedTestMainPackage(prog, pkg) {
			continue
		}
		if init := pkg.Func("init"); init != nil {
			roots = append(roots, init)
		}
	}
	result := rta.Analyze(roots, false)
	if result == nil {
		t.Fatal("independent RTA returned nil")
	}
	reachable := make(map[*ssa.Function]bool, len(result.Reachable))
	for fn := range result.Reachable {
		// Upstream x/tools rta records inaccessibility in result.RuntimeTypes
		// (true means reached only via an inaccessible underlying/tuple step)
		// yet still synthesizes exported promoted wrappers on that skipped
		// unnamed struct; attributed RTA honors skip and omits those phantoms.
		if isUnnamedStructPromotedWrapper(fn) {
			recv := types.Unalias(fn.Signature.Recv().Type())
			if inaccess, ok := result.RuntimeTypes.At(recv).(bool); ok && inaccess {
				continue
			}
		}
		reachable[fn] = true
	}
	return reachable
}

func assertSameReachable(t *testing.T, subject string, got, want map[*ssa.Function]bool) {
	t.Helper()
	for fn := range want {
		if !got[fn] {
			t.Errorf("%s: attributed RTA omitted %s", subject, functionName(fn))
		}
	}
	for fn := range got {
		if !want[fn] {
			t.Errorf("%s: attributed RTA added %s", subject, functionName(fn))
		}
	}
}

func functionName(fn *ssa.Function) string {
	if fn == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s (%s)", fn.String(), fn.RelString(nil))
}

// TestWidenReasonIsDeterministic pins the selection rule: the recorded
// widen reason is the lexicographically least of the requested set,
// whatever order the walk fires the requests in — the reason lands
// verbatim in persisted proofs, so it must be a function of the set.
func TestWidenReasonIsDeterministic(t *testing.T) {
	a := &tier2Analyzer{}
	a.requestWiden("zebra cause")
	a.requestWiden("alpha cause")
	a.requestWiden("mid cause")
	if !a.widen || a.widenReason != "alpha cause" {
		t.Fatalf("widenReason = %q, want the lexicographically least of the requested set", a.widenReason)
	}
}

// A type mentioning a type parameter denotes no runtime type: seeded
// into the walk (the shape that reached the field recover as
// "unsupported analysis shape: T"), it must be skipped wholesale, never
// panicked on — its concrete counterparts enter through their own
// instantiation sites (REQ-closure-analysis).
func TestAttributedRTASkipsTypeParameterShapes(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	supplyRegisteredFixtures(t, h, batchIsolationPackage)
	prog, err := h.loadCached(batchIsolationPackage)
	if err != nil {
		t.Fatal(err)
	}
	root := prog.Roots["Production"]
	if root == nil {
		t.Fatal("no Production root")
	}
	fixtureTypes := root.Pkg.Pkg
	tparam := types.NewTypeParam(types.NewTypeName(0, nil, "T", nil), types.NewInterfaceType(nil, nil))
	named := types.NewNamed(types.NewTypeName(0, fixtureTypes, "Box", nil), types.NewStruct(nil, nil), nil)
	named.SetTypeParams([]*types.TypeParam{types.NewTypeParam(types.NewTypeName(0, nil, "U", nil), types.NewInterfaceType(nil, nil))})
	// reviewLocal is a type declared inside a generic body that looks
	// concrete (no own params, no args) and mentions the enclosing
	// parameter only through its underlying - with an embedded interface
	// whose promoted method drives the exported-method walk into a nil
	// MethodValue.
	nestedObj := fixtureTypes.Scope().Lookup("nested")
	if nestedObj == nil {
		t.Fatal("fixture type nested not found")
	}
	msig := types.NewSignatureType(nil, nil, nil, types.NewTuple(),
		types.NewTuple(types.NewVar(0, fixtureTypes, "", nestedObj.Type())), false)
	iface := types.NewInterfaceType([]*types.Func{types.NewFunc(0, fixtureTypes, "M", msig)}, nil)
	iface.Complete()
	ifaceNamed := types.NewNamed(types.NewTypeName(0, fixtureTypes, "ReviewIface", nil), iface, nil)
	localUnderlying := types.NewStruct([]*types.Var{
		types.NewField(0, fixtureTypes, "ReviewIface", ifaceNamed, true),
		types.NewField(0, fixtureTypes, "x", tparam, false),
	}, nil)
	local := types.NewNamed(types.NewTypeName(0, fixtureTypes, "reviewLocal", nil), localUnderlying, nil)
	for _, seed := range []types.Type{tparam, types.NewSlice(tparam), named, local} {
		result, err := arta.Analyze(context.Background(), map[*ssa.Function]uint64{root: 1}, &arta.Seeds{
			RuntimeTypes: []arta.TypeSeed{{Type: seed, Masks: 1}},
		})
		if err != nil {
			t.Fatalf("type-parameter shape %v panicked the walk: %v", seed, err)
		}
		// The skip is WHOLESALE: a param-mentioning type contributes
		// nothing - not even through its method set, whose signature
		// types would otherwise register real concrete types and make
		// their exported methods phantom-reachable.
		for fn := range result.Reachable {
			if strings.Contains(fn.String(), "nested") {
				t.Fatalf("seed %v contributed phantom reachability: %s", seed, fn)
			}
		}
	}
}

// One unanalyzable subject degrades alone; a package-scoped
// provocation degrades every subject with the probe's own error; two
// independent subject-scoped offenders on opposite bisection halves
// isolate individually (the conflation that once darkened their 62
// sound siblings); and non-shape failures stay batch-wide
// (REQ-closure-analysis).
func TestAttributedBisectionIsolatesUnsupportedShapes(t *testing.T) {
	shapeErr := func(sym string) error {
		return fmt.Errorf("closure: attributed reachability: unsupported analysis shape: T (visiting p.%s)", sym)
	}
	sound := func(subjects []Subject) []attributedReachability {
		rows := make([]attributedReachability, len(subjects))
		for i := range rows {
			rows[i] = attributedReachability{openWorld: true}
		}
		return rows
	}
	poisonWorker := func(poisoned map[Subject]bool) func(context.Context, bool, map[string]bool, *program, []Subject) ([]attributedReachability, error) {
		return func(ctx context.Context, audited bool, pureDelegates map[string]bool, prog *program, subjects []Subject) ([]attributedReachability, error) {
			for _, s := range subjects {
				if poisoned[s] {
					return nil, shapeErr(s.Symbol)
				}
			}
			return sound(subjects), nil
		}
	}
	noopProbe := func(ctx context.Context, prog *program, subjects []Subject) error { return nil }

	bad1 := Subject{Package: "p", Symbol: "Bad1"}
	bad2 := Subject{Package: "p", Symbol: "Bad2"}
	subjects := []Subject{
		bad1,
		{Package: "p", Symbol: "A"}, {Package: "p", Symbol: "B"},
		{Package: "p", Symbol: "C"},
		bad2,
	}

	// One offender isolates alone.
	withClosureTestHooks(analysisTestHookSet{
		analyzeBatch:  poisonWorker(map[Subject]bool{bad1: true}),
		probePkgScope: noopProbe,
	}, func() {
		rows, err := attributedReachableSets(context.Background(), true, nil, nil, subjects)
		if err != nil || len(rows) != len(subjects) {
			t.Fatalf("single-offender isolation: rows=%d err=%v", len(rows), err)
		}
		for i, s := range subjects {
			if (s == bad1) != (rows[i].unavailable != "") {
				t.Fatalf("single-offender row %d (%v) misdispositioned: %+v", i, s, rows[i])
			}
		}
	})

	// Two offenders on opposite halves isolate individually - the
	// sound siblings keep their evidence.
	withClosureTestHooks(analysisTestHookSet{
		analyzeBatch:  poisonWorker(map[Subject]bool{bad1: true, bad2: true}),
		probePkgScope: noopProbe,
	}, func() {
		rows, err := attributedReachableSets(context.Background(), true, nil, nil, subjects)
		if err != nil || len(rows) != len(subjects) {
			t.Fatalf("two-offender isolation: rows=%d err=%v", len(rows), err)
		}
		for i, s := range subjects {
			offender := s == bad1 || s == bad2
			if offender != (rows[i].unavailable != "") {
				t.Fatalf("two-offender row %d (%v) misdispositioned: %+v", i, s, rows[i])
			}
			// Equality against the offender's own single-subject batch
			// error pins the real guarantee - each row carries the error
			// of the analysis whose only subject was this one. (Real
			// provenance names the VISITED function, not the subject; the
			// fake's symbol-bearing message is its own convention, and
			// the memoized reason substitutes a fixed constant anyway -
			// field attribution rides the diagnostic channel's
			// symbol-prefixed detail.)
			if offender && rows[i].unavailable != shapeErr(s.Symbol).Error() {
				t.Fatalf("offender %v carries a sibling's failure: %q", s, rows[i].unavailable)
			}
		}
	})

	// A package-scoped provocation degrades everything at ONE worker
	// run, each row carrying the probe's own error.
	calls := 0
	withClosureTestHooks(analysisTestHookSet{
		analyzeBatch: func(ctx context.Context, audited bool, pureDelegates map[string]bool, prog *program, subjects []Subject) ([]attributedReachability, error) {
			calls++
			return nil, shapeErr("init")
		},
		probePkgScope: func(ctx context.Context, prog *program, subjects []Subject) error {
			return fmt.Errorf("closure: attributed reachability: unsupported analysis shape: T (visiting p.init)")
		},
	}, func() {
		rows, err := attributedReachableSets(context.Background(), true, nil, nil, subjects)
		if err != nil {
			t.Fatalf("package-scoped failure surfaced batch-wide: %v", err)
		}
		for i := range rows {
			if !strings.Contains(rows[i].unavailable, "p.init") {
				t.Fatalf("row %d does not carry the package-scoped provenance: %+v", i, rows[i])
			}
		}
		if calls != 1 {
			t.Fatalf("package-scoped failure ran %d worker calls, want 1 (the probe decides)", calls)
		}
	})

	// A non-shape failure keeps the batch-wide error.
	withClosureTestHooks(analysisTestHookSet{
		analyzeBatch: func(ctx context.Context, audited bool, pureDelegates map[string]bool, prog *program, subjects []Subject) ([]attributedReachability, error) {
			return nil, fmt.Errorf("closure: analysis cancelled: context deadline exceeded")
		},
		probePkgScope: noopProbe,
	}, func() {
		if _, err := attributedReachableSets(context.Background(), true, nil, nil, subjects); err == nil {
			t.Fatal("a non-shape failure was swallowed by the bisection")
		}
	})
}

func writeGenericFixture(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/generic\n\ngo 1.26\n",
		"lib.go": body,
		"lib_test.go": `package generic

import "testing"

func TestKey(t *testing.T) {
	if UseInt() == "" {
		t.Fatal("empty key")
	}
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const genericFixtureBody = `package generic

import "fmt"

// Key boxes its type parameter into an interface - the exact shape whose
// runtime-type walk must handle a parameterized subject.
func Key[K comparable](k K) string {
	var boxed any = k
	return fmt.Sprint(boxed)
}

func UseInt() string { return Key[int](1) }
`

// A parameterized subject analyzes through its materialized instantiations:
// no panic, a real observability disposition, and precise contributions that
// move when the generic body moves (REQ-closure-analysis: instantiations
// dispatch concretely; a parameterized body is not a runtime dispatch
// surface, but its source is still the subject's content).
func TestAttributedAnalysisCoversGenericSubjects(t *testing.T) {
	dir := writeGenericFixture(t, genericFixtureBody)
	const pkg = "example.com/generic"
	subject := Subject{Package: pkg, Symbol: "Key"}

	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := newFixturePrograms(t, h)
	fixtures.supply(t, pkg)
	refined, err := computeTier2Result(h, pkg, subject.Symbol)
	if err != nil {
		t.Fatalf("precise analysis over a generic subject: %v", err)
	}
	fixtures.supply(t, pkg)
	proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatalf("observability over a generic subject: %v", err)
	}
	proof, ok := proofs[subject]
	if !ok {
		t.Fatalf("no observability disposition for the generic subject: %+v", proofs)
	}
	// A parameterized subject is open to caller-chosen instantiations, so
	// its observability refuses on the open subject world - the same
	// verdict signature-level dynamism gets everywhere.
	if proof.Observable || !strings.Contains(proof.Reason, "open subject world") {
		t.Fatalf("generic subject disposition = %+v, want the open-world refusal", proof)
	}
	fixtures.release()

	edited := writeGenericFixture(t, `package generic

import "fmt"

import "os"

func Key[K comparable](k K) string {
	var boxed any = k
	return os.Getenv("GENERIC") + fmt.Sprint(boxed)
}

func UseInt() string { return Key[int](1) }
`)
	h2, err := newAt(edited)
	if err != nil {
		t.Fatal(err)
	}
	refinedEdited, err := computeTier2Result(h2, pkg, subject.Symbol)
	if err != nil {
		t.Fatal(err)
	}
	envReason := "reaches os.Getenv (environment input)"
	if hasEffectReason(refined.effects, envReason) {
		t.Fatalf("base fixture already carries the probe effect: %+v", refined)
	}
	if !hasEffectReason(refinedEdited.effects, envReason) {
		t.Fatal("an effect added to the generic body is missing from the analysis - the origin's content left the subject")
	}
}

// A parameterized subject's instantiation-reachable effects stay visible:
// dropping the instantiations from traversal would let an effectful generic
// read as observable - the flattering direction.
func TestAttributedAnalysisSeesEffectsThroughInstantiations(t *testing.T) {
	dir := writeGenericFixture(t, `package generic

import (
	"fmt"
	"os"
)

func Key[K comparable](k K) string {
	var boxed any = k
	return fmt.Sprint(boxed)
}

func UseInt() string { return Key[int](1) }

// Effectful reaches ambient state through its instantiated body.
func Effectful[K comparable](k K) string {
	var boxed any = k
	_ = boxed
	return os.Getenv("GENERIC_EFFECT")
}

func UseEffect() string { return Effectful[int](1) }
`)
	const pkg = "example.com/generic"
	subject := Subject{Package: pkg, Symbol: "Effectful"}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	proof, ok := proofs[subject]
	if !ok {
		t.Fatalf("no disposition: %+v", proofs)
	}
	if proof.Observable {
		t.Fatal("an effectful generic subject read as observable - instantiation traversal lost its effects")
	}
}

// A parameterized subject nothing instantiates still analyzes: its own
// source remains its content, and the analysis neither panics nor errors.
func TestAttributedAnalysisCoversUninstantiatedGenericSubjects(t *testing.T) {
	dir := writeGenericFixture(t, genericFixtureBody+`
// Orphan has no instantiation anywhere in the binary.
func Orphan[K comparable](k K) string {
	var boxed any = k
	_ = boxed
	return "orphan"
}
`)
	const pkg = "example.com/generic"
	subject := Subject{Package: pkg, Symbol: "Orphan"}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := newFixturePrograms(t, h)
	fixtures.supply(t, pkg)
	refined, err := computeTier2Result(h, pkg, subject.Symbol)
	if err != nil {
		t.Fatalf("precise analysis over an uninstantiated generic subject: %v", err)
	}
	if refined.widen {
		t.Fatalf("uninstantiated generic subject widened: %+v", refined)
	}
	fixtures.supply(t, pkg)
	if _, err := h.ComputeObservabilityBatch([]Subject{subject}); err != nil {
		t.Fatalf("observability over an uninstantiated generic subject: %v", err)
	}
	fixtures.release()
	// The origin declaration is the subject's own content even with no
	// instantiation to traverse: a body edit moves the precise contributions.
	edited := writeGenericFixture(t, strings.Replace(genericFixtureBody, `import "fmt"`, "import (\n\t\"fmt\"\n\t\"os\"\n)", 1)+`
// Orphan has no instantiation anywhere in the binary.
func Orphan[K comparable](k K) string {
	var boxed any = k
	_ = boxed
	return orphanProbe()
}

func orphanProbe() string { return os.Getenv("ORPHAN") }
`)
	h2, err := newAt(edited)
	if err != nil {
		t.Fatal(err)
	}
	refinedEdited, err := computeTier2Result(h2, pkg, subject.Symbol)
	if err != nil {
		t.Fatal(err)
	}
	if !hasEffectReason(refinedEdited.effects, "reaches os.Getenv (environment input)") {
		t.Fatal("an effect added to the uninstantiated generic body is missing - the origin fold lost the subject's own content")
	}
}

// The attributed analysis converts an unsupported shape into an error
// instead of panicking the embedding process: a parameterized body handed
// directly to the analyzer - the shape the instantiation-rooting fix keeps
// out of production paths - degrades to per-subject unavailability upstream,
// never a crash.
func TestAttributedAnalysisConvertsUnsupportedShapesToErrors(t *testing.T) {
	dir := writeGenericFixture(t, genericFixtureBody)
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := h.loadCached("example.com/generic")
	if err != nil {
		t.Fatal(err)
	}
	origin := prog.Roots["Key"]
	if origin == nil {
		t.Fatal("generic origin not rooted")
	}
	if _, err := arta.Analyze(context.Background(), map[*ssa.Function]uint64{origin: 1}, nil); err == nil {
		t.Fatal("a parameterized body walked without error")
	}
}

// A zero-parameter generic subject is forced open-world: a signature walk
// alone reads it closed, which would grant observability while its
// instantiations run arbitrary caller-chosen shapes, and would serve a
// refined hash missing every callee (REQ-closure-analysis's
// parameterized-subject arm).
func TestZeroParameterGenericSubjectIsForcedOpenWorld(t *testing.T) {
	const body = `package generic

import "os"

func helper() {
	_ = os.WriteFile("/tmp/generic-fixture-x", []byte("x"), 0o644)
}

// Value takes no parameters at all: only TypeParams carry its genericity.
func Value[T any]() int {
	helper()
	return 1
}

func UseInt() string {
	Value[int]()
	return "v"
}
`
	dir := writeGenericFixture(t, body)
	const pkg = "example.com/generic"
	subject := Subject{Package: pkg, Symbol: "Value"}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	proof := proofs[subject]
	if proof.Observable || !strings.Contains(proof.Reason, "open subject world") {
		t.Fatalf("zero-parameter generic disposition = %+v, want the forced open-world refusal", proof)
	}
}

// A generic METHOD subject is forced open-world through the receiver's type
// parameters - the RecvTypeParams arm of parameterizedBody - and its
// callee edits move the refined closure exactly as for generic functions.
func TestGenericMethodSubjectIsForcedOpenWorld(t *testing.T) {
	const body = `package generic

import "os"

func helper() {
	_ = os.WriteFile("/tmp/generic-fixture-m", []byte("m"), 0o644)
}

type Counter[T any] struct{ n int }

func (c Counter[T]) N() int {
	helper()
	return c.n
}

func UseInt() string {
	var c Counter[int]
	c.N()
	return "c"
}
`
	dir := writeGenericFixture(t, body)
	const pkg = "example.com/generic"
	subject := Subject{Package: pkg, Symbol: "Counter.N"}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	proof := proofs[subject]
	if proof.Observable || !strings.Contains(proof.Reason, "open subject world") {
		t.Fatalf("generic method disposition = %+v, want the forced open-world refusal", proof)
	}
}

// A generic calling a generic with its own type parameter materializes a
// PARAMETERIZED instance (Inner[T], type argument still a type param) in
// the SSA program. The instantiation rooting must yield those to their
// concrete counterparts: rooting one walks a body whose MakeInterface
// boxes a bare type parameter, and the runtime-type walk has no arm for
// it — the bldc field campaign's "unsupported analysis shape: T",
// 567/1164 targets dark (REQ-closure-analysis).
func TestAttributedAnalysisSkipsParameterizedInstances(t *testing.T) {
	dir := writeGenericFixture(t, `package generic

import "fmt"

func Inner[U any](v U) string {
	var boxed any = v
	return fmt.Sprint(boxed)
}

func Outer[T any](v T) string { return Inner(v) }

func UseInt() string { return Outer[int](1) }
`)
	const pkg = "example.com/generic"
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := newFixturePrograms(t, h)
	for _, symbol := range []string{"Inner", "Outer"} {
		fixtures.supply(t, pkg)
		if _, err := computeTier2Result(h, pkg, symbol); err != nil {
			t.Fatalf("precise analysis over %s: %v", symbol, err)
		}
	}
	fixtures.supply(t, pkg)
	proofs, err := h.ComputeObservabilityBatch([]Subject{
		{Package: pkg, Symbol: "Inner"},
		{Package: pkg, Symbol: "UseInt"},
	})
	if err != nil {
		t.Fatalf("observability batch with a nested-generic subject: %v", err)
	}
	inner, ok := proofs[Subject{Package: pkg, Symbol: "Inner"}]
	if !ok || inner.Observable == (inner.Reason != "") {
		t.Fatalf("no sound disposition for the nested-generic subject: %+v", proofs)
	}
	if strings.Contains(inner.Reason, "unsupported analysis shape") {
		t.Fatalf("the nested-generic subject still refuses on the analysis shape: %+v", inner)
	}
	use, ok := proofs[Subject{Package: pkg, Symbol: "UseInt"}]
	if !ok || use.Observable == (use.Reason != "") || strings.Contains(use.Reason, "unsupported analysis shape") {
		t.Fatalf("the plain sibling lost its evidence to the generic's batch: %+v", proofs)
	}
}

// A type declared inside a generic body mentions the enclosing type
// parameters only through its underlying: Inner[local]'s type argument
// looks concrete while local's struct carries T. Both the type-parameter
// guard and the embedded interface method walk must analyze clean.
func TestAttributedAnalysisSkipsLocalTypeInstances(t *testing.T) {
	dir := writeGenericFixture(t, `package generic

type Iface interface{ M() }

type impl struct{}

func (impl) M() {}

func Inner[U any](v U) any {
	var boxed any = v
	return boxed
}

func Outer[T any](t T, i Iface) any {
	type local struct {
		Iface
		x T
	}
	return Inner(local{i, t})
}

func UseInt() string {
	if Outer[int](1, impl{}) == nil {
		return ""
	}
	return "ok"
}
`)
	const pkg = "example.com/generic"
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := newFixturePrograms(t, h)
	for _, symbol := range []string{"Inner", "Outer", "UseInt"} {
		fixtures.supply(t, pkg)
		if _, err := computeTier2Result(h, pkg, symbol); err != nil {
			t.Fatalf("precise analysis over %s: %v", symbol, err)
		}
	}
	fixtures.supply(t, pkg)
	proofs, err := h.ComputeObservabilityBatch([]Subject{
		{Package: pkg, Symbol: "Inner"},
		{Package: pkg, Symbol: "UseInt"},
	})
	if err != nil {
		t.Fatalf("observability batch with a local-type instance: %v", err)
	}
	for _, symbol := range []string{"Inner", "UseInt"} {
		proof, ok := proofs[Subject{Package: pkg, Symbol: symbol}]
		if !ok {
			t.Fatalf("no disposition for %s: %+v", symbol, proofs)
		}
		if proof.Observable == (proof.Reason != "") {
			t.Fatalf("%s carries an inconsistent disposition: %+v", symbol, proof)
		}
		if strings.Contains(proof.Reason, "unsupported analysis shape") {
			t.Fatalf("%s still refuses on the analysis shape: %+v", symbol, proof)
		}
	}
}

// writeBoundedFixture is a module with one constraint-bounded generic
// subject: Sum's Number constraint (~int | ~float64) is methodless and
// every term excludes dynamic carriers, helper is reached only through
// Sum's body, and UseSum materializes the int instantiation.
func writeBoundedFixture(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/bounded\n\ngo 1.26\n",
		"lib.go": body,
		"lib_test.go": `package bounded

import "testing"

func TestUse(t *testing.T) {
	if UseSum() != 3 {
		t.Fatal("broken")
	}
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const boundedBody = `package bounded

type Number interface{ ~int | ~float64 }

const fixtureConstant = 1

func helper(x int) int { return x + fixtureConstant }

func Sum[T Number](a, b T) T {
	_ = helper(1)
	return a + b
}

func UseSum() int { return Sum(1, 2) }

func Unrelated() string { return "quiet" }
`

// A constraint-bounded generic subject analyzes closed: observability
// answers instead of refusing on the open subject world, the analysis
// does not widen, an edit to a helper reached only through the
// instantiation moves the hash (the purity-override audit:
// instantiation-reachable content is in the hash), a generic-body edit moves it (the
// origin fold), and an unrelated edit leaves it alone — the serving
// precision the open-world wall cost (REQ-closure-analysis's
// parameterized-subject arm).
func TestConstraintBoundedGenericSubjectAnalyzesClosed(t *testing.T) {
	subject := Subject{Package: "example.com/bounded", Symbol: "Sum"}
	compute := func(body string) (tier2Result, Observability) {
		t.Helper()
		dir := writeBoundedFixture(t, body)
		h, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		// Each body remains a separate fixture and load. Release this body's
		// representation at the helper return, not at the outer test's end.
		fixtures := &fixturePrograms{h: h}
		defer fixtures.release()
		fixtures.supply(t, subject.Package)
		refined, err := computeTier2Result(h, subject.Package, subject.Symbol)
		if err != nil {
			t.Fatal(err)
		}
		fixtures.supply(t, subject.Package)
		proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		return refined, proofs[subject]
	}

	base, proof := compute(boundedBody)
	if base.widen || base.unverifiable {
		t.Fatalf("bounded generic widened: %+v", base)
	}
	if strings.Contains(proof.Reason, "open subject world") {
		t.Fatalf("bounded generic refused as open world: %+v", proof)
	}

	// The analysis surface is effects: an effect added to content reached
	// only through the instantiation must appear, and an unrelated
	// effectful edit must not leak in — the precision the narrowing
	// exists for.
	envReason := "reaches os.Getenv (environment input)"
	if hasEffectReason(base.effects, envReason) {
		t.Fatalf("base fixture already carries the probe effect: %+v", base)
	}
	withOS := strings.Replace(boundedBody, "package bounded", "package bounded\n\nimport \"os\"", 1)
	helperEdit, _ := compute(strings.Replace(withOS, "return x + fixtureConstant", "return x + fixtureConstant + len(os.Getenv(\"BOUNDED\"))", 1))
	if !hasEffectReason(helperEdit.effects, envReason) {
		t.Fatal("an effect in a helper reached only through the instantiation is missing from the analysis")
	}

	bodyEdit, _ := compute(strings.Replace(withOS, "return a + b", "_ = os.Getenv(\"BOUNDED\")\n\treturn a + b", 1))
	if !hasEffectReason(bodyEdit.effects, envReason) {
		t.Fatal("an effect in the generic body is missing from the analysis")
	}

	unrelatedEdit, _ := compute(strings.Replace(withOS, `return "quiet"`, `return "quiet" + os.Getenv("BOUNDED")`, 1))
	if !reflect.DeepEqual(unrelatedEdit.effects, base.effects) {
		t.Fatalf("an unrelated effectful edit leaked into the bounded generic's analysis: %+v vs %+v", unrelatedEdit.effects, base.effects)
	}
}

// Unbounded or method-bearing constraints keep the open world: any and
// comparable bound nothing, a constraint method is a dispatch surface
// the narrowing does not cover, and a specific interface term makes the
// parameter itself a dynamic carrier (REQ-closure-analysis).
func TestUnboundedConstraintsStayOpenWorld(t *testing.T) {
	for name, decl := range map[string]string{
		"comparable":     "func Sum[T comparable](a, b T) T {\n\t_ = helper(1)\n\treturn a\n}\n\nfunc UseSum() int { return Sum(1, 2) + 2 }",
		"method-bearing": "type Stringy interface {\n\t~int\n\tString() string\n}\n\ntype myInt int\n\nfunc (m myInt) String() string { return \"m\" }\n\nfunc Sum[T Stringy](a, b T) int {\n\t_ = helper(1)\n\t_ = a.String()\n\treturn 3\n}\n\nfunc UseSum() int { return Sum(myInt(1), myInt(2)) }",
		"dirty-union":    "type IntOrFunc interface{ ~int | ~func() }\n\nfunc Sum[T IntOrFunc](a, b T) int {\n\t_ = helper(1)\n\treturn 3\n}\n\nfunc UseSum() int { return Sum(1, 2) + 0 }",
		"interface-term": "type Readerish interface{ interface{ Read([]byte) (int, error) } }\n\nfunc Sum[T Readerish](a, b T) int {\n\t_ = helper(1)\n\treturn 3\n}\n\nfunc UseSum() int { return 3 }",
	} {
		body := "package bounded\n\nconst fixtureConstant = 1\n\nfunc helper(x int) int { return x + fixtureConstant }\n\n" + decl + "\n\nfunc Unrelated() string { return \"quiet\" }\n"
		dir := writeBoundedFixture(t, body)
		h, err := newAt(dir)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		subject := Subject{Package: "example.com/bounded", Symbol: "Sum"}
		proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// The refusal reason carries the widen cause when the open
		// origin's own body also widens (a method-bearing constraint's
		// dispatch site); either text is the open-world wall standing.
		if p := proofs[subject]; p.Observable || !(strings.Contains(p.Reason, "open subject world") || strings.Contains(p.Reason, "reachability is not closed")) {
			t.Fatalf("%s: constraint read bounded, want the open-world refusal: %+v", name, p)
		}
	}
}

// A bounded generic with no in-binary instantiation keeps the origin
// fold's own closure: its declaration and static callees still move the
// hash (the fold's pre-existing load), it does not widen, and — pinned
// by TestBoundedGenericRootsInstantiationFlow's negative arm —
// instantiation-only content stays out (REQ-closure-analysis).
func TestBoundedGenericWithoutInstantiationKeepsOriginFold(t *testing.T) {
	orphan := strings.Replace(boundedBody, "func UseSum() int { return Sum(1, 2) }", "func UseSum() int { return 3 }", 1)
	subject := Subject{Package: "example.com/bounded", Symbol: "Sum"}
	compute := func(body string) tier2Result {
		t.Helper()
		dir := writeBoundedFixture(t, body)
		h, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		refined, err := computeTier2Result(h, subject.Package, subject.Symbol)
		if err != nil {
			t.Fatal(err)
		}
		return refined
	}
	base := compute(orphan)
	if base.widen || base.unverifiable {
		t.Fatalf("uninstantiated bounded generic widened: %+v", base)
	}
	if hasEffectReason(base.effects, "reaches os.Getenv (environment input)") {
		t.Fatalf("base fixture already carries the probe effect: %+v", base)
	}
	withOS := strings.Replace(orphan, "package bounded", "package bounded\n\nimport \"os\"", 1)
	bodyEdit := compute(strings.Replace(withOS, "return a + b", "_ = os.Getenv(\"BOUNDED\")\n\treturn a + b", 1))
	if !hasEffectReason(bodyEdit.effects, "reaches os.Getenv (environment input)") {
		t.Fatal("an effect in the uninstantiated generic's body is missing from the origin fold's analysis")
	}
}

// Analyzing a bounded generic beside an ordinary subject in one shared
// attributed traversal yields exactly the solo analysis: instantiation
// roots attribute under the subject's own mask, never a sibling's.
func TestBoundedGenericBatchEquivalence(t *testing.T) {
	dir := writeBoundedFixture(t, boundedBody)
	sum := Subject{Package: "example.com/bounded", Symbol: "Sum"}
	unrelated := Subject{Package: "example.com/bounded", Symbol: "Unrelated"}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := h.loadCached(sum.Package)
	if err != nil {
		t.Fatal(err)
	}
	reachable, err := attributedReachableSets(h.ctx, true, h.source.pureDelegates, prog, []Subject{sum, unrelated})
	if err != nil {
		t.Fatal(err)
	}
	metas, err := h.list(sum.Package)
	if err != nil {
		t.Fatal(err)
	}
	base := newTier2Base(h, prog, metas)
	batchedSum, err := h.tier2Reachable(base, reachable[0])
	if err != nil {
		t.Fatal(err)
	}
	batchedUnrelated, err := h.tier2Reachable(base, reachable[1])
	if err != nil {
		t.Fatal(err)
	}
	solo, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	soloSum, err := computeTier2Result(solo, sum.Package, sum.Symbol)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(batchedSum.effects, soloSum.effects) || batchedSum.widen != soloSum.widen || batchedSum.unverifiable != soloSum.unverifiable {
		t.Fatalf("batch %+v != solo %+v for the bounded generic", batchedSum, soloSum)
	}
	if batchedUnrelated.unverifiable || strings.Contains(batchedUnrelated.reason, "open") || strings.Contains(batchedUnrelated.widenReason, "open") {
		t.Fatalf("sibling polluted by the generic's instantiation roots: %+v", batchedUnrelated)
	}
}

// flowBody dispatches through a boxed T inside the generic body: the
// origin's site is open over T (unresolvable, a widen), while the
// Tagged instantiation's site resolves concretely to TagUniq. The
// unwidened base therefore pins BOTH halves of the mechanism - the
// instantiation rooting that resolves the site and the origin scan
// yielding to it - and the TagUniq edit-move pins that the resolved
// content is in the hash (the purity-override audit). TagUniq's body
// sits BELOW every other declaration so a position shift cannot fake
// the edit-move signal.
const flowBody = `package bounded

type Number interface{ ~int | ~float64 }

func Sum[T Number](a, b T) T {
	if s, ok := any(a).(interface{ TagUniq() string }); ok {
		_ = s.TagUniq()
	}
	return a + b
}

func UseSum() int {
	_ = Sum(Tagged(1), Tagged(2))
	return 3
}

func Unrelated() string { return "quiet" }

type Tagged int

func (t Tagged) TagUniq() string { return "tag" }
`

func TestBoundedGenericRootsInstantiationFlow(t *testing.T) {
	subject := Subject{Package: "example.com/bounded", Symbol: "Sum"}
	compute := func(body string) tier2Result {
		t.Helper()
		dir := writeBoundedFixture(t, body)
		h, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		refined, err := computeTier2Result(h, subject.Package, subject.Symbol)
		if err != nil {
			t.Fatal(err)
		}
		return refined
	}
	base := compute(flowBody)
	if base.widen || base.unverifiable {
		t.Fatalf("instantiation-rooted dispatch did not resolve: %+v", base)
	}
	if hasEffectReason(base.effects, "reaches os.Getenv (environment input)") {
		t.Fatalf("base fixture already carries the probe effect: %+v", base)
	}
	withOS := strings.Replace(flowBody, "package bounded", "package bounded\n\nimport \"os\"", 1)
	tagEdit := compute(strings.Replace(withOS, `return "tag"`, `return os.Getenv("TAG") + "tag"`, 1))
	if !hasEffectReason(tagEdit.effects, "reaches os.Getenv (environment input)") {
		t.Fatal("an effect in the instantiation-reached method body is missing from the analysis: a purity-asserted serve would go stale-valid")
	}
}

// The observability effect walk sees instantiation-reached sites: a
// dispatch target reached only through a boxed T carrying a
// subject-tier-only refusal (a computed function call — invisible to the
// maximal AST backstop) must refuse the proof; granting from the origin
// alone would answer without ever seeing the site
// (REQ-closure-analysis's parameterized-subject arm,
// REQ-closure-observability-analysis).
func TestBoundedGenericObservabilitySeesInstantiationEffects(t *testing.T) {
	const effectBody = `package bounded

type Number interface{ ~int | ~float64 }

func Sum[T Number](a, b T) T {
	if s, ok := any(a).(interface{ TagUniq() string }); ok {
		_ = s.TagUniq()
	}
	return a + b
}

func UseSum() int {
	_ = Sum(Tagged(1), Tagged(2))
	return 3
}

var fns = map[string]func() string{"a": func() string { return "a" }}

type Tagged int

func (t Tagged) TagUniq() string { return fns["a"]() }
`
	dir := writeBoundedFixture(t, effectBody)
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/bounded", Symbol: "Sum"}
	proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if p := proofs[subject]; p.Observable || !strings.Contains(p.Reason, "computed function call") {
		t.Fatalf("instantiation-reached computed call invisible to the proof: %+v", p)
	}
}

// Self- and mutually-referential constraints are legal Go; the bounding
// walk must terminate on them (the cycle guard), answering conservatively
// open - a recursive type set is never proven bounded
// (REQ-closure-analysis's parameterized-subject arm).
func TestRecursiveConstraintsTerminateOpen(t *testing.T) {
	for name, decl := range map[string]string{
		"self":   "func Sum[A interface{ ~[]A }](a A) int {\n\t_ = helper(1)\n\treturn 1\n}\n\nfunc UseSum() int { return 1 + fixtureConstant - fixtureConstant }",
		"mutual": "func Sum[A interface{ ~[]B }, B interface{ ~[]A }](a A, b B) int {\n\t_ = helper(1)\n\treturn 1\n}\n\nfunc UseSum() int { return 1 + fixtureConstant - fixtureConstant }",
	} {
		body := "package bounded\n\nconst fixtureConstant = 1\n\nfunc helper(x int) int { return x + fixtureConstant }\n\n" + decl + "\n\nfunc Unrelated() string { return \"quiet\" }\n"
		dir := writeBoundedFixture(t, body)
		h, err := newAt(dir)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		subject := Subject{Package: "example.com/bounded", Symbol: "Sum"}
		proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if p := proofs[subject]; p.Observable || !(strings.Contains(p.Reason, "open subject world") || strings.Contains(p.Reason, "reachability is not closed")) {
			t.Fatalf("%s: recursive constraint did not answer conservatively open: %+v", name, p)
		}
	}
}

// TestBoundedGenericOriginEscapeEffectsStayVisible pins the analyzer-only
// escape path: an uninstantiated bounded generic boxes a package-local
// concrete type, so RTA never sees the interface conversion — only the
// origin fold's own scan models the escaped type's method set, and the
// method's effect must surface; losing it grants a proof over an
// unanalyzed effect (REQ-closure-observability-analysis's no-false-valid
// direction).
func TestBoundedGenericOriginEscapeEffectsStayVisible(t *testing.T) {
	body := `package bounded

import "os"

type Number interface{ ~int | ~float64 }

type probe struct{}

func (p probe) Peek() string { return os.Getenv("ESCAPE") }

func Sum[T Number](a, b T) T {
	var sink any = probe{}
	_ = sink
	return a + b
}

func UseSum() int { return 3 }

func Unrelated() string { return "quiet" }
`
	dir := writeBoundedFixture(t, body)
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := computeTier2Result(h, "example.com/bounded", "Sum")
	if err != nil {
		t.Fatal(err)
	}
	if !hasEffectReason(tr.effects, "reaches os.Getenv (environment input)") {
		t.Fatalf("the escaped local type's method effect is missing from the analysis: %+v", tr.effects)
	}
}

// go1.27 generic METHODS (math/rand/v2's Rand.N is the stdlib shape)
// must analyze like any parameterized subject — the field failure was
// "unsupported analysis shape: Int" wherever a closure reached one.
func TestAttributedAnalysisCoversGenericMethods(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/gm\n\ngo 1.27\n",
		"lib.go": `package gm

type Ring struct{ n uint64 }

func (r *Ring) next() uint64 { r.n++; return r.n }

// N mirrors math/rand/v2's go1.27 generic-method shape.
func (r *Ring) N[Int ~int | ~int64](n Int) Int {
	return Int(r.next() % uint64(n))
}

func Use() int { r := &Ring{}; return int(r.N(7)) }
`,
		"lib_test.go": `package gm

import "testing"

func TestUse(t *testing.T) {
	if Use() != 1 {
		t.Fatal(Use())
	}
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const pkg = "example.com/gm"
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := newFixturePrograms(t, h)
	fixtures.supply(t, pkg)
	if _, err := computeTier2Result(h, pkg, "Use"); err != nil {
		t.Fatalf("precise analysis over a generic-method closure: %v", err)
	}
	fixtures.supply(t, pkg)
	proofs, err := h.ComputeObservabilityBatch([]Subject{{Package: pkg, Symbol: "Use"}})
	if err != nil {
		t.Fatalf("observability over a generic-method closure: %v", err)
	}
	if len(proofs) != 1 {
		t.Fatalf("dispositions = %+v, want one", proofs)
	}
}

// The stdlib field shape: a closure reaching math/rand/v2 (whose
// Rand.N is a generic method on go1.27) must not lose its whole
// target to one edge.
func TestAttributedAnalysisSurvivesStdlibGenericMethods(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/gms\n\ngo 1.27\n",
		"lib.go": `package gms

import "math/rand/v2"

func Draw() int {
	r := rand.New(rand.NewPCG(1, 2))
	return int(r.N(7))
}
`,
		"lib_test.go": `package gms

import "testing"

func TestDraw(t *testing.T) {
	if Draw() < 0 || Draw() >= 7 {
		t.Fatal("out of range")
	}
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const pkg = "example.com/gms"
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := newFixturePrograms(t, h)
	fixtures.supply(t, pkg)
	if _, err := computeTier2Result(h, pkg, "Draw"); err != nil {
		t.Fatalf("precise analysis reaching stdlib generic methods: %v", err)
	}
	fixtures.supply(t, pkg)
	if _, err := h.ComputeObservabilityBatch([]Subject{{Package: pkg, Symbol: "Draw"}}); err != nil {
		t.Fatalf("observability reaching stdlib generic methods: %v", err)
	}
}

// Init functions root positionally - init#<file>#<ordinal>, the
// declaration ledger's identity: 0-based within the declaring file in
// declaration order, file-scoped so inits elsewhere in the package
// never shift a key. The precise per-subject analysis (tier 2 and the
// observability proof) resolves those roots exactly like named
// functions; an ordinal naming no declaration errors with the subject
// named.
func TestInitSubjectRootsResolvePositionally(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/initroot\n\ngo 1.26\n")
	writeFile(t, dir, "a.go", `package initroot

var registry []string

func wireA() { registry = append(registry, "a") }

func init() { wireA() }

func init() { registry = append(registry, "second") }
`)
	writeFile(t, dir, "aa.go", "package initroot\n\nfunc init() { registry = append(registry, \"aa\") }\n")
	writeFile(t, dir, "a_test.go", `package initroot

import "testing"

func TestRegistry(t *testing.T) {
	if len(registry) == 0 {
		t.Fatal("registry empty")
	}
}
`)
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "example.com/initroot"
	fixtures := newFixturePrograms(t, h)
	for _, symbol := range []string{"init#a.go#0", "init#a.go#1", "init#aa.go#0"} {
		fixtures.supply(t, pkg)
		if _, err := computeTier2Result(h, pkg, symbol); err != nil {
			t.Fatalf("tier-2 analysis for %s: %v", symbol, err)
		}
	}
	// Reach is not asserted per init: package initialization is in every
	// subject's reachable set by design (the blanket init rooting), so
	// init subjects share reach - the root's load-bearing role is
	// resolution, and the wiring content rides every subject's closure.
	fixtures.supply(t, pkg)
	if _, err := computeTier2Result(h, pkg, "init#a.go#2"); err == nil || !strings.Contains(err.Error(), "init#a.go#2 not found in "+pkg) {
		t.Fatalf("past-the-end ordinal = %v, want a not-found error naming the subject", err)
	}
	fixtures.supply(t, pkg)
	proofs, err := h.ComputeObservabilityBatch([]Subject{
		{Package: pkg, Symbol: "init#a.go#0"},
		{Package: pkg, Symbol: "init#aa.go#0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for subject, proof := range proofs {
		if strings.Contains(proof.Reason, "not found") {
			t.Fatalf("observability proof for %s degraded to not-found: %+v", subject.Symbol, proof)
		}
	}
}

// A computed call through a closed cell — the recursive local closure's
// idiom — takes the cell's stored closures as its targets, at startup
// and in subject flow alike, so a standard closure of the same
// signature in the mask never classifies. A cell any other use opens —
// a store of an unclosed value, its address passed, a store through a
// capturing closure of an unclosed value — keeps the enumeration's
// targets and the computed-call refusal
// (REQ-closure-observability-dispatch).
func TestClosedCellNarrowsComputedCallTargets(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/narrow\n\ngo 1.26\n")
	const recursive = "\tvar visit func(string) bool\n\tvisit = func(s string) bool {\n\t\tif s == \"\" {\n\t\t\treturn true\n\t\t}\n\t\treturn visit(s[1:])\n\t}\n"
	cases := []struct{ pkg, source, refusal string }{
		// The idiom in an initializer, its result read by the subject.
		// The blank import of an audited-pure package links the standard
		// library's own closures of the signature into the mask (the
		// FIPS module reaches internal/godebugs) — the class the
		// whole-mask projection dragged in.
		{"startup", "package startup\n\nimport _ \"crypto/sha256\"\n\nfunc walk(s string) bool {\n" + recursive + "\treturn visit(s)\n}\n\nvar ok = walk(\"abc\")\n\nfunc Subject() bool { return ok }\n", ""},
		// The idiom in the subject's own flow.
		{"subject", "package subject\n\nimport _ \"crypto/sha256\"\n\nfunc Subject() bool {\n" + recursive + "\treturn visit(\"abc\")\n}\n", ""},
		// A second store of an unclosed value — a package-level function
		// variable's load — opens the cell.
		{"openstore", "package openstore\n\nvar hook func(string) bool\n\nfunc Subject() bool {\n" + recursive + "\tvisit = hook\n\treturn visit(\"abc\")\n}\n", "computed function call"},
		// The cell's address passed opens it.
		{"openaddr", "package openaddr\n\nfunc set(p *func(string) bool) {}\n\nfunc Subject() bool {\n" + recursive + "\tset(&visit)\n\treturn visit(\"abc\")\n}\n", "computed function call"},
		// A captured cell holding a standard function value names a
		// body no walk scans: the held set resolves nothing at the
		// subject tier's scan of the drained frame, and the computed
		// call keeps its refusal (an uncaptured local is no cell — SSA
		// lifts it and the call is static).
		{"stdheld", "package stdheld\n\nimport \"strings\"\n\nfunc walk(s string) bool {\n\tvar pick func(string, string) bool\n\tpick = strings.HasPrefix\n\tvia := func() bool { return pick(s, \"a\") }\n\treturn via()\n}\n\nvar ok = walk(\"abc\")\n\nfunc Subject() bool { return ok }\n", "computed function call"},
		// A drained frame's held closure is scanned by the route that
		// resolves through it: its effect classifies (a path mutation —
		// an effect no tier admits, where an environment read would be
		// a priced observable input at the subject tier).
		{"drained", "package drained\n\nimport \"os\"\n\nfunc helper(n int) bool {\n\tvar visit func(int) bool\n\tvisit = func(n int) bool {\n\t\tif n == 0 {\n\t\t\treturn os.Remove(\"x\") == nil\n\t\t}\n\t\treturn visit(n - 1)\n\t}\n\treturn visit(n)\n}\n\nvar handler = helper\n\nfunc Subject() bool { return handler != nil }\n", "os.Remove"},
		// A drained frame's nested closure called statically is scanned
		// as the frame's own content.
		{"drainedstatic", "package drainedstatic\n\nimport \"os\"\n\nfunc helper() bool {\n\tf := func() bool { return os.Remove(\"x\") == nil }\n\treturn f()\n}\n\nvar handler = helper\n\nfunc Subject() bool { return handler != nil }\n", "os.Remove"},
		// A store of the cell's own load is the walk's one cycle: refused.
		{"selfstore", "package selfstore\n\nfunc Subject() bool {\n" + recursive + "\tvisit = visit\n\treturn visit(\"abc\")\n}\n", "computed function call"},
		// A capturing closure storing an unclosed value opens it.
		{"opencapture", "package opencapture\n\nvar hook func(string) bool\n\nfunc Subject() bool {\n" + recursive + "\tswap := func() { visit = hook }\n\tswap()\n\treturn visit(\"abc\")\n}\n", "computed function call"},
	}
	subjects := make([]Subject, 0, len(cases))
	for _, tc := range cases {
		if err := os.MkdirAll(filepath.Join(dir, tc.pkg), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, tc.pkg+"/"+tc.pkg+".go", tc.source)
		subjects = append(subjects, Subject{Package: "example.com/narrow/" + tc.pkg, Symbol: "Subject"})
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		proof := proofs[Subject{Package: "example.com/narrow/" + tc.pkg, Symbol: "Subject"}]
		if tc.refusal == "" {
			if !proof.Observable || proof.Reason != "" {
				t.Errorf("%s = %+v, want observable", tc.pkg, proof)
			}
			continue
		}
		if proof.Observable || !strings.Contains(proof.Reason, tc.refusal) {
			t.Errorf("%s = %+v, want refused with %q", tc.pkg, proof, tc.refusal)
		}
	}
}

// A callee's function-typed parameter closes through the subject's
// attributed call sites for every closed-world subject — the iterator's
// yield bound by a range statement, by a direct call, by an iterator
// literal; an initializer's own call to the callee is startup flow
// outside the subject's frames, judged by the startup walk — while the
// crossing refuses where provenance is absent: a variadic callee (its
// non-variadic twin closes), a capturing callee, a callee that is also
// a dynamic target anywhere in the mask, a subject-frame site passing a
// value the walk cannot close
// (REQ-closure-observability-dispatch).
func TestCalleeParameterClosesThroughAttributedSites(t *testing.T) {
	const seq = "func seq(yield func(int) bool) {\n\tfor i := 0; i < 3; i++ {\n\t\tif !yield(i) {\n\t\t\treturn\n\t\t}\n\t}\n}\n"
	const closure = "func(v int) bool { total += v; return true }"
	// One table: every fixture is judged, every judgment has a fixture.
	cases := []struct{ pkg, source, refusal string }{
		{"ranged", "package ranged\n\n" + seq + "\nfunc Subject() int {\n\ttotal := 0\n\tfor v := range seq {\n\t\ttotal += v\n\t}\n\treturn total\n}\n", ""},
		{"called", "package called\n\n" + seq + "\nfunc Subject() int {\n\ttotal := 0\n\tseq(" + closure + ")\n\treturn total\n}\n", ""},
		{"literal", "package literal\n\nfunc Subject() int {\n\ttotal := 0\n\tfor v := range func(yield func(int) bool) {\n\t\tfor i := 0; i < 3; i++ {\n\t\t\tif !yield(i) {\n\t\t\t\treturn\n\t\t\t}\n\t\t}\n\t} {\n\t\ttotal += v\n\t}\n\treturn total\n}\n", ""},
		// An initializer's own call is startup flow outside the subject's frames.
		{"initbound", "package initbound\n\n" + seq + "\nvar hooks = map[string]func(int) bool{\"a\": func(v int) bool { return v < 2 }}\n\nfunc init() {\n\tseq(hooks[\"a\"])\n}\n\nfunc Subject() int {\n\ttotal := 0\n\tseq(" + closure + ")\n\treturn total\n}\n", ""},
		// A variadic callee refuses at its parameter; its non-variadic twin closes.
		{"variadicparam", "package variadicparam\n\nfunc each(y func(int) bool, rest ...int) { y(1) }\n\nfunc Subject() int {\n\ttotal := 0\n\teach(" + closure + ", 1, 2)\n\treturn total\n}\n", "computed function call in example.com/cross/variadicparam.each calling parameter y"},
		{"fixedparam", "package fixedparam\n\nfunc each(y func(int) bool, rest int) { y(rest) }\n\nfunc Subject() int {\n\ttotal := 0\n\teach(" + closure + ", 1)\n\treturn total\n}\n", ""},
		// A capturing callee refuses: its closure over captured state would run unjudged.
		{"capturing", "package capturing\n\nfunc Subject() int {\n\tlimit := 3\n\tseq := func(yield func(int) bool) {\n\t\tfor i := 0; i < limit; i++ {\n\t\t\tif !yield(i) {\n\t\t\t\treturn\n\t\t\t}\n\t\t}\n\t}\n\ttotal := 0\n\tseq(" + closure + ")\n\treturn total\n}\n", "computed function call in example.com/cross/capturing.Subject$1 calling parameter yield"},
		// A callee also reached as a dynamic target refuses at its parameter: its provenance is not its static sites alone — the clause's discipline, pinned here by a verdict flip (the dynamic dispatch passes a map-loaded callback the static site never shows; the whole-mask target drag still scans that callback's body, so the flip is provenance, not a missed effect). The subject's bool parameter carries no dynamic reach, so the subject stays closed-world and the refusal is the callee's.
		{"dyntargeted", "package dyntargeted\n\n" + seq + "\nfunc other(yield func(int) bool) { yield(7) }\n\nvar hooks = map[string]func(int) bool{\"a\": func(v int) bool { return v < 2 }}\n\nfunc Subject(pick bool) int {\n\ttotal := 0\n\tseq(" + closure + ")\n\tother(" + closure + ")\n\trun := seq\n\tif pick {\n\t\trun = other\n\t}\n\trun(hooks[\"a\"])\n\treturn total\n}\n", "computed function call in example.com/cross/dyntargeted.other calling parameter yield"},
		// A subject-frame site passing a value the walk cannot close refuses.
		{"unclosedarg", "package unclosedarg\n\n" + seq + "\nvar hooks = map[string]func(int) bool{\"a\": func(v int) bool { return v < 2 }}\n\nfunc Subject() int {\n\tseq(hooks[\"a\"])\n\treturn 1\n}\n", "computed function call in example.com/cross/unclosedarg.seq calling parameter yield"},
	}
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/cross\n\ngo 1.26\n")
	for _, tc := range cases {
		if err := os.MkdirAll(filepath.Join(dir, tc.pkg), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, tc.pkg+"/"+tc.pkg+".go", tc.source)
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subjects := make([]Subject, 0, len(cases))
	for _, tc := range cases {
		subjects = append(subjects, Subject{Package: "example.com/cross/" + tc.pkg, Symbol: "Subject"})
	}
	proofs, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		proof := proofs[Subject{Package: "example.com/cross/" + tc.pkg, Symbol: "Subject"}]
		if tc.refusal == "" && (!proof.Observable || proof.Reason != "") {
			t.Errorf("%s = %+v, want observable", tc.pkg, proof)
		}
		if tc.refusal != "" && (proof.Observable || !strings.Contains(proof.Reason, tc.refusal)) {
			t.Errorf("%s = %+v, want refused naming %q", tc.pkg, proof, tc.refusal)
		}
	}
}

// TestObservabilityBatchReleasesPrograms pins the bounded-peak discipline:
// programs are per-package test binaries no later group can reuse, so the
// batch releases each group's whole-program SSA with the group — peak
// memory follows the largest single binary, never the batch's package
// count.
func TestObservabilityBatchReleasesPrograms(t *testing.T) {
	const base = "github.com/greatliontech/gofresh/internal/closure/testdata/"
	subjects := []Subject{
		{Package: base + "observable", Symbol: "TestReadFile"},
		{Package: base + "observablebad", Symbol: "TestOpenStat"},
	}
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	supplyRegisteredFixtures(t, h, base+"observable", base+"observablebad")
	results, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(subjects) {
		t.Fatalf("results = %d, want %d", len(results), len(subjects))
	}
	if len(h.progs) != 0 {
		retained := make([]string, 0, len(h.progs))
		for pkg := range h.progs {
			retained = append(retained, pkg)
		}
		t.Fatalf("batch retained %d whole-program SSAs: %v", len(retained), retained)
	}
}

// TestObservabilityBatchReleasesProgramOnUnrootedGroup pins the release on
// the all-unrooted exit: the group loaded a program to discover its
// subjects cannot root, and that program is released like any other.
func TestObservabilityBatchReleasesProgramOnUnrootedGroup(t *testing.T) {
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/observable"
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	supplyRegisteredFixtures(t, h, pkg)
	results, err := h.ComputeObservabilityBatch([]Subject{{Package: pkg, Symbol: "NoSuchSubject"}})
	if err != nil {
		t.Fatal(err)
	}
	if proof := results[Subject{Package: pkg, Symbol: "NoSuchSubject"}]; proof.Observable {
		t.Fatalf("unrooted subject granted a proof: %+v", proof)
	}
	if len(h.progs) != 0 {
		t.Fatalf("all-unrooted group retained %d programs", len(h.progs))
	}
}

// A dynamic-state fact entry serves only under its exact scope and bucket —
// the key IS the freshness (REQ-closure-dynamic-state-memo).
func TestDynamicStateFactStoreMissesOnScopeAndBucketChange(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	facts := map[string]json.RawMessage{"example.com/dep": json.RawMessage(`{"mutates":["example.com/dep.Hook"]}`)}
	cachefile.Merge("dynamicstate", "scope-a", "modpath@v1|cone", facts)

	var got map[string]json.RawMessage
	if !cachefile.Load("dynamicstate", "scope-a", "modpath@v1|cone", &got) || string(got["example.com/dep"]) != string(facts["example.com/dep"]) {
		t.Fatalf("exact key did not serve: %v", got)
	}
	got = nil
	if cachefile.Load("dynamicstate", "scope-b", "modpath@v1|cone", &got) {
		t.Fatalf("moved scope served stale facts: %v", got)
	}
	got = nil
	if cachefile.Load("dynamicstate", "scope-a", "modpath@v2|cone", &got) {
		t.Fatalf("moved bucket served stale facts: %v", got)
	}
	got = nil
	if cachefile.Load("dynamicstate", "", "modpath@v1|cone", &got) {
		t.Fatalf("empty scope must disable the memo, served: %v", got)
	}
}

// verifyPropertyHarnessPackage judges pgregory.net/rapid mechanically from
// source across any version pin or local checkout, admitting real v1.3.0 and
// clean protocol implementations while failing closed on any structural
// violation regardless of version or local replace origin
// (REQ-closure-observability-property-harness).
func TestVerifyPropertyHarnessPackageStructuralGates(t *testing.T) {
	baseRapidSrc := `package rapid

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

func (*exampleTB) Helper()                       {}
func (*exampleTB) Logf(format string, args ...any) {}
func (*exampleTB) Errorf(format string, args ...any) {}
func (*exampleTB) Name() string                  { return "example" }

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

type testError struct {
	msg string
}

func runSynctestBuffered(fn func()) {
	resultCh := make(chan *testError, 1)
	go func() {
		var res *testError
		defer func() { resultCh <- res }()
		synctest.Test(&testing.T{}, func(*testing.T) { fn() })
	}()
	if err := <-resultCh; err != nil {
		_ = err.msg
	}
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
	runSynctestBuffered(func() {})
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
	parseRapid := func(t *testing.T, src, version string, mainMod bool) *packages.Package {
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
		tp, err := conf.Check("pgregory.net/rapid", fset, []*ast.File{f}, info)
		if err != nil {
			t.Fatalf("types.Check: %v", err)
		}
		imps := make(map[string]*packages.Package, len(tp.Imports()))
		for _, dep := range tp.Imports() {
			imps[dep.Path()] = &packages.Package{ID: dep.Path(), PkgPath: dep.Path(), Name: dep.Name(), Types: dep}
		}
		return &packages.Package{
			ID:        "pgregory.net/rapid",
			PkgPath:   "pgregory.net/rapid",
			Name:      "rapid",
			Fset:      fset,
			Syntax:    []*ast.File{f},
			Types:     tp,
			TypesInfo: info,
			Imports:   imps,
			Module: &packages.Module{
				Path:    "pgregory.net/rapid",
				Version: version,
				Main:    mainMod,
			},
		}
	}

	// 0. Length-prefixed pinned memo key resists delimiter collisions across slices and fields.
	k1 := buildPinnedHarnessMemoKey("fe", "tc", "pol", "rapid@v1.3.0", []string{"A=1|B=2"}, []string{"-tags=a"}, []string{"a.go\x00b.go"})
	k2 := buildPinnedHarnessMemoKey("fe", "tc", "pol", "rapid@v1.3.0", []string{"A=1", "B=2"}, []string{"-tags=a"}, []string{"a.go\x00b.go"})
	k3 := buildPinnedHarnessMemoKey("fe", "tc", "pol", "rapid@v1.3.0", []string{"A=1|B=2"}, []string{"-tags=a"}, []string{"a.go", "b.go"})
	if k1 == k2 || k1 == k3 || k2 == k3 {
		t.Fatalf("buildPinnedHarnessMemoKey collision: k1=%q k2=%q k3=%q", k1, k2, k3)
	}

	// 1. Clean implementation passes across arbitrary versions and main/replace origins when audited=true,
	// and fails closed when audited=false.
	for _, version := range []string{"", "v0.0.1", "v1.3.0", "v1.4.0", "v2.0.0"} {
		cleanPkg := parseRapid(t, baseRapidSrc, version, version == "")
		if ok, reason := propharness.VerifyPackageWithReason(true, cleanPkg); !ok {
			t.Fatalf("VerifyPackage(true, version=%q) = false (%s), want true", version, reason)
		}
		if propharness.VerifyPackage(false, cleanPkg) {
			t.Fatalf("VerifyPackage(false, version=%q) = true, want false", version)
		}
	}

	// 2. Structural violations fail closed even when stamped v1.3.0 or local main/replace.
	violations := []struct {
		name  string
		extra string
	}{
		{"non_rapid_env_key", "func init() { _ = os.Getenv(\"SECRET_KEY\") }\n"},
		{"env_read_outside_init", "func ReadEnvLater() string { v, _ := os.LookupEnv(\"RAPID_CHECKS\"); return v }\n"},
		{"timer_sleep", "func Nap() { time.Sleep(time.Millisecond) }\n"},
		{"exported_var", "var ExportedSeed uint64\n"},
		{"post_init_callable_mutation", "func SwapReporter() { failReporter = reportFailure }\n"},
		{"unparameterized_any_return", "func LeakAny() any { return 0 }\n"},
		{"imported_std_var_write", "func ClobberStd() { io.EOF = nil }\n"},
		// TypeParam return & maphash caller confinement
		{"exported_typeparam_return_without_tb", "func BadSample[V any](g *Generator[V]) V { return g.Example(1) }\n"},
		{"exported_two_arg_typeparam_return", "func PickFirst[V any](a, b V) V { return a }\n"},
		{"maphash_called_from_draw", "func leakSeed() uint64 { var h maphash.Hash; h.SetSeed(maphash.MakeSeed()); return h.Sum64() }\nfunc BadGen() *Generator[int] { _ = leakSeed(); return Int() }\n"},
		{"maphash_called_from_init", "func init() { _ = maphash.MakeSeed() }\n"},
		// Goroutine & synctest join hazards
		{"unjoined_goroutine", "func Spawn() { go func() {}() }\n"},
		{"synctest_early_return_before_join", "func BadBubble() { ch := make(chan struct{}); go func() { synctest.Test(&testing.T{}, func(*testing.T) {}); ch <- struct{}{} }(); if flags.checks > 0 { return }; <-ch }\n"},
		{"synctest_dead_branch_join", "func BadDeadJoin() { ch := make(chan struct{}); go func() { defer func() { ch <- struct{}{} }(); synctest.Test(&testing.T{}, func(*testing.T) {}) }(); if false { <-ch } }\n"},
		{"synctest_send_before_bubble", "func BadEarlySend() { ch := make(chan struct{}, 1); go func() { ch <- struct{}{}; synctest.Test(&testing.T{}, func(*testing.T) {}) }(); <-ch }\n"},
		{"synctest_work_after_send", "func BadPostSend() { ch := make(chan struct{}); go func() { synctest.Test(&testing.T{}, func(*testing.T) {}); ch <- struct{}{}; _ = cachedWords(\"late\") }(); <-ch }\n"},
		{"synctest_buffered_two_chan", "func BadBufTwo() { ch := make(chan struct{}, 2); go func() { defer func() { ch <- struct{}{} }(); synctest.Test(&testing.T{}, func(*testing.T) {}) }(); <-ch }\n"},
		{"synctest_prepopulated_buffered_chan", "func BadPreSend() { ch := make(chan struct{}, 1); ch <- struct{}{}; go func() { defer func() { ch <- struct{}{} }(); synctest.Test(&testing.T{}, func(*testing.T) {}) }(); <-ch }\n"},
		{"init_goroutine_env_read", "func init() { go func() { _, _ = os.LookupEnv(\"RAPID_ASYNC\") }() }\n"},
		{"init_goroutine_flag_write", "func init() { go func() { flags.checks = 1 }() }\n"},
		{"goroutine_syncmap_store", "func RaceCache() { ch := make(chan struct{}); go func() { strMapCache.Store(\"k\", []string{\"a\"}); synctest.Test(&testing.T{}, func(*testing.T) {}); ch <- struct{}{} }(); <-ch }\n"},
		// sync.Map cached value & global Generator impl immutability
		{"syncmap_store_mutable_int_ptr", "func badCachePtr() { p := new(int); strMapCache.Store(\"k\", p) }\n"},
		{"syncmap_store_mutable_map", "func badCacheMap() { m := make(map[string]int); strMapCache.Store(\"k\", m) }\n"},
		{"syncmap_store_callable", "func badCacheFn() { strMapCache.Store(\"k\", func() {}) }\n"},
		{"syncmap_store_slice_mutated_after_store", "func badCacheSlice() { s := []string{\"a\"}; strMapCache.Store(\"k\", s); s[0] = \"b\" }\n"},
		{"syncmap_caller_mutates_returned_slice", "func badCallerMut() { s := cachedWords(\"x\"); s[0] = \"evil\" }\n"},
		{"syncmap_mutated_named_struct", "type mutBox struct{ x int }\nfunc badBox() { b := mutBox{x: 1}; b.x = 2; strMapCache.Store(\"k\", b) }\n"},
		{"global_generator_stateful_impl", "type counterImpl struct{ n int }\nfunc (c *counterImpl) value(t *T) int { c.n++; return c.n }\nvar badGlobalGen = newGenerator[int](&counterImpl{})\n"},
		{"global_generator_generic_slice_mutated", "type sliceMutImpl[V any] struct{ buf []V }\nfunc (s *sliceMutImpl[V]) value(t *T) V { var z V; s.buf[0] = z; return s.buf[0] }\nvar badGenericSliceGen = newGenerator[int](&sliceMutImpl[int]{buf: []int{0}})\n"},
		{"syncmap_cached_generator_stateful_impl", "type cacheCounterImpl struct{ n int }\nfunc (c *cacheCounterImpl) value(t *T) int { c.n++; return c.n }\nfunc badCacheGen() { genCache.Store(\"bad\", newGenerator[int](&cacheCounterImpl{})) }\n"},
		// Exported & unexported Rule-2 return surface & promoted methods
		{"unexported_handle_leaks_any", "type secretHandle struct{ x int }\nfunc (h *secretHandle) Leak() any { return 0 }\nfunc NewSecret() *secretHandle { return &secretHandle{} }\n"},
		{"promoted_embedded_method_leaks_ptr", "type embBase struct{ x int }\nfunc (b *embBase) LeakPtr() *int { return &b.x }\ntype ExportedHolder struct{ embBase }\n"},
		{"embedded_interface_method_leaks_any", "type badIface interface{ LeakAny() any }\ntype ExportedIfaceHolder struct{ badIface }\n"},
		// os.* & filepath.Glob provenance and non-value-taken discipline
		{"os_readfile_evicted", "func badReadFile() { _, _ = os.ReadFile(flags.failfile) }\n"},
		{"os_writefile_evicted", "func badWriteFile() { _ = os.WriteFile(flags.failfile, nil, 0o644) }\n"},
		{"os_open_arbitrary_path", "func badOpen() { f, _ := os.Open(\"/etc/hosts\"); if f != nil { _ = f.Close() } }\n"},
		{"os_create_unguarded_by_flag", "func badCreate() { f, _ := os.Create(fmt.Sprintf(\"vis-%d.html\", 1)); if f != nil { _ = f.Close() } }\n"},
		{"os_create_non_html_path", "func badCreateExt() { if flags.debugvis { f, _ := os.Create(fmt.Sprintf(\"vis-%d.txt\", 1)); if f != nil { _ = f.Close() } } }\n"},
		{"os_remove_non_tempfile", "func badRemove() { _ = os.Remove(flags.failfile) }\n"},
		{"filepath_glob_arbitrary_pattern", "func badGlob() { _, _ = filepath.Glob(\"*.go\") }\n"},
		{"filepath_join_dotdot_traversal", "func badJoinDotDot() { f, _ := os.Open(filepath.Join(flags.failfile, \"..\", \"secret\")); if f != nil { _ = f.Close() } }\n"},
		{"os_open_value_taken", "func badValOpen() { fn := os.Open; _ = fn }\n"},
		{"filepath_glob_value_taken", "func badValGlob() { fn := filepath.Glob; _ = fn }\n"},
		{"html_template_parsefiles", "func badTmplParseFiles() { _, _ = template.ParseFiles(\"/etc/hosts\") }\n"},
		{"html_template_execute_method_data", "type methodVisData struct{ Title string }\nfunc (methodVisData) Secret() string { return \"x\" }\nfunc badTmplExec() { _ = visTmpl.Execute(io.Discard, &methodVisData{Title: \"a\"}) }\n"},
		{"html_template_value_taken", "func badTmplVal() { fn := template.New; _ = fn }\n"},
		// Package-scope variable reference/pointer/channel confinement & range-assign hazards
		{"category_a_int_ptr_alias_mutated", "var sharedCount = new(int)\nfunc bumpPtr() { p := sharedCount; *p++ }\n"},
		{"category_a_struct_slice_field_mutated", "var sharedBuf struct{ buf []int }\nfunc init() { sharedBuf.buf = []int{0} }\nfunc mutStructBuf() { s := sharedBuf.buf; s[0] = 9 }\n"},
		{"category_a_nested_slice_row_mutated", "var sharedMatrix = [][]int{{0}}\nfunc mutRow() { row := sharedMatrix[0]; row[0]++ }\n"},
		{"category_a_chan_global_forbidden", "var sharedChan = make(chan int, 1)\n"},
		{"category_a_range_assign_scalar_global", "var rangeCalls int\nfunc mutViaRange() { for rangeCalls = range []int{1} {} }\n"},
		{"category_a_param_slice_aliased_mutated", "var sharedSlice = []int{0}\nfunc mutViaAlias(pv []int) { alias := pv; alias[0] = 1 }\nfunc callMutAlias() { mutViaAlias(sharedSlice) }\n"},
		{"exported_slice_var", "var ExportedTable = []int{0}\n"},
		// Generator implementation pointer/closure/aliased-field/unnamed-struct/type-arg immutability
		{"global_generator_ptr_field_type_forbidden", "type ptrHolderImpl struct{ calls *int }\nfunc (c *ptrHolderImpl) value(t *T) int { return 0 }\nvar badPtrHolderGen = newGenerator[int](&ptrHolderImpl{})\n"},
		{"global_generator_ptr_field_mutated", "type ptrCounterImpl struct{ calls *int }\nfunc (c *ptrCounterImpl) value(t *T) int { *c.calls++; return *c.calls }\nvar badPtrGen = newGenerator[int](&ptrCounterImpl{calls: new(int)})\n"},
		{"global_generator_closure_captures_ptr_local", "func makeStatefulClosureGen() *Generator[int] {\n\tp := new(int)\n\treturn &Generator[int]{gen: func(t *T) int { *p++; return *p }}\n}\nvar badClosurePtrGen = makeStatefulClosureGen()\n"},
		{"global_generator_closure_captures_aliased_slice_local", "func makeStatefulSliceClosureGen() *Generator[int] {\n\ts := []int{0}\n\treturn &Generator[int]{gen: func(t *T) int { a := s; a[0]++; return a[0] }}\n}\nvar badClosureSliceGen = makeStatefulSliceClosureGen()\n"},
		{"global_generator_aliased_slice_field_mutated", "type aliasedBufImpl struct{ buf []int }\nfunc (g *aliasedBufImpl) value(t *T) int { s := g.buf; s[0]++; return s[0] }\nvar badAliasedBufGen = newGenerator[int](&aliasedBufImpl{buf: []int{0}})\n"},
		{"global_generator_unnamed_struct_impl", "func badUnnamedGen() *Generator[int] { return newGenerator[int](&struct{ statelessIntGen }{}) }\nvar badUnnamedGlobalGen = badUnnamedGen()\n"},
		{"global_generator_generic_mutable_type_arg", "type sampledImpl[V any] struct{ vals []V }\nfunc (s *sampledImpl[V]) value(t *T) V { return s.vals[0] }\nvar badSliceGen = newGenerator[[]int](&sampledImpl[[]int]{vals: [][]int{{0}}})\nfunc corruptViaDraw(t *T) { s := badSliceGen.Draw(t, \"x\"); s[0]++ }\n"},
		// sync.Map fresh-at-store & capsule/forwarded-return slice confinement
		{"syncmap_store_reslice_expr", "func badStoreReslice() { s := []string{\"a\", \"b\"}; strMapCache.Store(\"k\", s[:1]); s[0] = \"x\" }\n"},
		{"syncmap_store_pre_aliased_local_mutated", "func badPreAliasStore() { s := []string{\"a\"}; alias := s; strMapCache.Store(\"k\", s); alias[0] = \"x\" }\n"},
		{"syncmap_store_outer_loop_reused_slice", "func badLoopStore() {\n\ts := make([]string, 1)\n\tfor i := 0; i < 2; i++ {\n\t\ts[0] = fmt.Sprint(i)\n\t\tstrMapCache.Store(fmt.Sprint(i), s)\n\t}\n}\n"},
		{"syncmap_store_backward_goto_mutated", "func badGotoStore() {\n\ts := []string{\"a\"}\n\tif flags.debugvis { goto store }\nmut:\n\ts[0] = \"evil\"\n\treturn\nstore:\n\tstrMapCache.Store(\"k\", s)\n\tgoto mut\n}\n"},
		{"syncmap_cached_capsule_struct_slice_mutated", "type cachedEntry struct{ items []string }\nfunc loadEntry(k string) cachedEntry {\n\tif v, ok := strMapCache.Load(k); ok { return v.(cachedEntry) }\n\ts := []string{k}\n\te := cachedEntry{items: s}\n\tstrMapCache.Store(k, e)\n\treturn e\n}\nfunc badMutEntry() { e := loadEntry(\"x\"); e.items[0] = \"mut\" }\n"},
		{"syncmap_load_only_typeassert_mutated", "func readOnlyCorrupt() {\n\tif v, ok := strMapCache.Load(\"k\"); ok {\n\t\ts := v.([]string)\n\t\ts[0] = \"mut\"\n\t}\n}\n"},
		{"syncmap_store_only_return_mutated", "func storeWithoutLoadAssert() []string {\n\ts := []string{\"a\"}\n\tstrMapCache.Store(\"k\", s)\n\treturn s\n}\nfunc corruptStoreRet() { x := storeWithoutLoadAssert(); x[0] = \"mut\" }\n"},
		{"syncmap_caller_mutates_forwarded_returned_slice", "func forwardWords(k string) []string { return cachedWords(k) }\nfunc badMutForwarded() { x := forwardWords(\"k\"); x[0] = \"mut\" }\n"},
		{"global_generator_bound_method_val_mutates_slice", "type boundMutImpl struct{ buf []int }\nfunc (b *boundMutImpl) value(t *T) int { return b.buf[0] }\nfunc (b *boundMutImpl) mut() { b.buf[0]++ }\nfunc makeBoundMut() *Generator[int] { impl := &boundMutImpl{buf: []int{0}}; fn := impl.mut; _ = fn; return newGenerator[int](impl) }\nvar badBoundMutGen = makeBoundMut()\n"},
		{"global_generator_bound_method_val_returns_slice", "type boundLeakImpl struct{ buf []int }\nfunc (b *boundLeakImpl) value(t *T) int { return b.buf[0] }\nfunc (b *boundLeakImpl) leak() []int { return b.buf }\nfunc makeBoundLeak() *Generator[int] { impl := &boundLeakImpl{buf: []int{0}}; fn := impl.leak; _ = fn; return newGenerator[int](impl) }\nvar badBoundLeakGen = makeBoundLeak()\n"},
		{"syncmap_cached_generator_helper_captures_tb_in_closure", "func makeBaseWithParent(parent *T) *Generator[int] { return &Generator[int]{gen: func(t *T) int { parent.state++; return int(parent.state) }} }\nfunc cachedEvil(parent *T) *Generator[int] {\n\tif v, ok := genCache.Load(\"p\"); ok { return v.(*Generator[int]) }\n\tg := makeBaseWithParent(parent)\n\tgenCache.Store(\"p\", g)\n\treturn g\n}\n"},
		{"syncmap_unexported_iface_dispatch_returns_cached_slice_mutated", "type wordGetter interface { rawWords() []string }\ntype wordBox struct{ w []string }\nfunc (b wordBox) rawWords() []string { return b.w }\nfunc cachedWordBox() wordBox {\n\tif v, ok := strMapCache.Load(\"wb\"); ok { return v.(wordBox) }\n\ts := []string{\"a\"}\n\tb := wordBox{w: s}\n\tstrMapCache.Store(\"wb\", b)\n\treturn b\n}\nfunc mutViaWordIface() { var g wordGetter = cachedWordBox(); g.rawWords()[0] = \"mut\" }\n"},
	}
	for _, tc := range violations {
		t.Run(tc.name, func(t *testing.T) {
			badPkg := parseRapid(t, baseRapidSrc+"\n"+tc.extra, "v1.3.0", false)
			if propharness.VerifyPackage(true, badPkg) {
				t.Fatalf("VerifyPackage accepted %s under v1.3.0", tc.name)
			}
			badLocal := parseRapid(t, baseRapidSrc+"\n"+tc.extra, "", true)
			if propharness.VerifyPackage(true, badLocal) {
				t.Fatalf("VerifyPackage accepted %s under local main", tc.name)
			}
		})
	}
	t.Run("tampered_example_ignoring_seed", func(t *testing.T) {
		badExampleSrc := strings.Replace(baseRapidSrc, "if len(seed) > 0 {\n\t\ts = uint64(seed[0])\n\t}", "_ = seed", 1)
		if propharness.VerifyPackage(true, parseRapid(t, badExampleSrc, "v1.3.0", false)) {
			t.Fatal("VerifyPackage accepted Example(seed ...int) ignoring explicit seed")
		}
	})
	t.Run("exported_field_on_T", func(t *testing.T) {
		badTSrc := strings.Replace(baseRapidSrc, "state uint64", "State uint64", 1)
		badTSrc = strings.ReplaceAll(badTSrc, "t.state", "t.State")
		badTSrc = strings.ReplaceAll(badTSrc, "state:", "State:")
		if propharness.VerifyPackage(true, parseRapid(t, badTSrc, "v1.3.0", false)) {
			t.Fatal("VerifyPackage accepted exported field on rapid.T")
		}
	})

	// End-to-end check on a local replace checkout violating the protocol:
	// unlike the retired unverified local-checkout trust rule, a tampered local rapid refuses!
	t.Run("tampered_local_replace_refused", func(t *testing.T) {
		tamperedDir := t.TempDir()
		for _, sub := range []string{"rapid", "app"} {
			if err := os.MkdirAll(filepath.Join(tamperedDir, sub), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		writeFile(t, tamperedDir, "rapid/go.mod", "module pgregory.net/rapid\n\ngo 1.26\n")
		writeFile(t, tamperedDir, "rapid/rapid.go", baseRapidSrc+"\nfunc init() { _ = os.Getenv(\"UNLOGGED_SECRET\") }\n")
		writeFile(t, tamperedDir, "app/go.mod", "module example.com/app\n\ngo 1.26\n\nrequire pgregory.net/rapid v0.0.0\n\nreplace pgregory.net/rapid => ../rapid\n")
		writeFile(t, tamperedDir, "app/app_test.go", "package app\n\nimport (\n\t\"testing\"\n\t\"pgregory.net/rapid\"\n)\n\nfunc TestProp(t *testing.T) {\n\trapid.Check(t, func(rt *rapid.T) {\n\t\t_ = rapid.Int().Draw(rt, \"x\")\n\t})\n}\n")
		tamperedH, err := newAt(filepath.Join(tamperedDir, "app"))
		if err != nil {
			t.Fatal(err)
		}
		tamperedProofs, err := tamperedH.ComputeObservabilityBatch([]Subject{{Package: "example.com/app", Symbol: "TestProp"}})
		if err != nil {
			t.Fatal(err)
		}
		if got := tamperedProofs[Subject{Package: "example.com/app", Symbol: "TestProp"}]; got.Observable {
			t.Fatalf("tampered local rapid checkout proved Observable = %+v, want refusal", got)
		}
	})
}

func TestRealGOMODCACHEPackagesMechanicalVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("loads real GOMODCACHE modules via go/packages")
	}
	modCacheOut, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Skipf("go env GOMODCACHE unavailable: %v", err)
	}
	modCache := strings.TrimSpace(string(modCacheOut))
	loadCachedBatch := func(t *testing.T, relModDir string, patterns ...string) map[string]*packages.Package {
		t.Helper()
		fullDir := filepath.Join(modCache, filepath.FromSlash(relModDir))
		info, statErr := os.Stat(fullDir)
		if statErr != nil || !info.IsDir() {
			t.Skipf("%s not present in GOMODCACHE (%s)", relModDir, fullDir)
		}
		mode := packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedModule
		pkgs, loadErr := packages.Load(&packages.Config{
			Mode: mode,
			Dir:  fullDir,
		}, patterns...)
		hasPkgErr := loadErr != nil || len(pkgs) != len(patterns)
		if !hasPkgErr {
			for _, pkg := range pkgs {
				if len(pkg.Errors) > 0 {
					hasPkgErr = true
					break
				}
			}
		}
		if hasPkgErr && strings.Contains(relModDir, "@") {
			modPath, modVer, _ := strings.Cut(relModDir, "@")
			impPatterns := make([]string, len(patterns))
			for i, pat := range patterns {
				impPath := modPath
				if trimmed := strings.TrimPrefix(pat, "./"); trimmed != "." && trimmed != pat {
					impPath = modPath + "/" + trimmed
				}
				impPatterns[i] = impPath
			}
			wrapDir := t.TempDir()
			gomod := "module testload\n\ngo 1.24\n\nrequire " + modPath + " " + modVer + "\n\nreplace " + modPath + " => " + fullDir + "\n"
			if wErr := os.WriteFile(filepath.Join(wrapDir, "go.mod"), []byte(gomod), 0o644); wErr == nil {
				pkgs, loadErr = packages.Load(&packages.Config{
					Mode: mode,
					Dir:  wrapDir,
				}, impPatterns...)
			}
		}
		if loadErr != nil || len(pkgs) != len(patterns) {
			t.Fatalf("packages.Load(%s, %v): err=%v len=%d", fullDir, patterns, loadErr, len(pkgs))
		}
		byPath := make(map[string]*packages.Package, len(pkgs))
		for _, pkg := range pkgs {
			if len(pkg.Errors) > 0 {
				t.Fatalf("packages.Load(%s, %s) errors: %v", fullDir, pkg.PkgPath, pkg.Errors)
			}
			byPath[pkg.PkgPath] = pkg
		}
		return byPath
	}

	// 1. Real pgregory.net/rapid@v1.3.0 (both direct verifyPropertyHarnessPackage and end-to-end ComputeObservabilityBatch)
	t.Run("rapid@v1.3.0", func(t *testing.T) {
		rapidPkg := loadCachedBatch(t, "pgregory.net/rapid@v1.3.0", ".")["pgregory.net/rapid"]
		if ok, reason := propharness.VerifyPackageWithReason(true, rapidPkg); !ok {
			t.Fatalf("VerifyPackage(true, real pgregory.net/rapid@v1.3.0) = false (%s), want true", reason)
		}
		if propharness.VerifyPackage(false, rapidPkg) {
			t.Fatal("VerifyPackage(false, real pgregory.net/rapid@v1.3.0) = true, want false")
		}
		e2eDir := t.TempDir()
		rapidCacheDir := filepath.Join(modCache, "pgregory.net", "rapid@v1.3.0")
		writeFile(t, e2eDir, "go.mod", "module example.com/realrapid\n\ngo 1.24\n\nrequire pgregory.net/rapid v1.3.0\n\nreplace pgregory.net/rapid => "+rapidCacheDir+"\n")
		writeFile(t, e2eDir, "real_test.go", `package realrapid

import (
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"strconv"
	"testing"
	"unsafe"
	"pgregory.net/rapid"
)

type realPair struct {
	A int
	B string
}

type cleanSM struct {
	n int
}

func (m *cleanSM) Check(t *rapid.T) {
	if m.n < 0 {
		t.Fatalf("negative")
	}
}

func (m *cleanSM) Step(t *rapid.T) {
	_ = crc32.ChecksumIEEE([]byte("abc"))
	m.n += rapid.IntRange(0, 3).Draw(t, "d")
}

func (m *cleanSM) Reset() {
	m.n = 0
}

type dirtySM struct{}

func (m *dirtySM) Check(t *rapid.T) {}

func (m *dirtySM) Leak(t *rapid.T) {
	_, _ = os.Hostname()
}

type lazyEnv struct{}

func (lazyEnv) String() string {
	return os.Getenv("REAL_RAPID_SECRET")
}

type lazyEnvWrapper struct {
	inner lazyEnv
}

type lazyUnobs struct{}

func (lazyUnobs) String() string {
	h, _ := os.Hostname()
	return h
}

type lazyUnobsWrapper struct {
	inner lazyUnobs
}

var sharedMutCounter int

type lazyMut struct{}

func (lazyMut) String() string {
	sharedMutCounter++
	return "mut"
}

var sharedGen *rapid.Generator[int]

func TestRealRapidCheck(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.Int().Draw(rt, "n")
		if n+0 != n {
			rt.Fatalf("broken")
		}
	})
}

func TestRealRapidMakeAndError(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		p := rapid.Make[realPair]().Draw(rt, "p")
		if _, err := strconv.Atoi(p.B); err != nil && errors.Is(err, strconv.ErrSyntax) {
			_ = p.A
		}
		errs := []error{errors.New(p.B)}
		_ = errs[0].Error()
		_ = rt.Context().Err()
	})
}

func TestRealRapidStateMachineAndMake(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		_ = rapid.Make[realPair]().Draw(rt, "p")
		rt.Repeat(rapid.StateMachineActions(&cleanSM{}))
	})
}

func TestRealRapidDirtyStateMachine(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		rt.Repeat(rapid.StateMachineActions(&dirtySM{}))
	})
}

func TestRealRapidUnsafeGenerator(t *testing.T) {
	g := rapid.Just[unsafe.Pointer](nil)
	_ = g
}

func TestRealRapidSharedGeneratorFormat(t *testing.T) {
	_ = fmt.Sprintf("%v", sharedGen)
}

func TestRealRapidLazyEnvStringer(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		_ = rapid.Just(lazyEnv{}).Draw(rt, "x")
	})
}

func TestRealRapidNestedLazyEnvStringer(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		_ = rapid.Just(lazyEnvWrapper{}).Draw(rt, "x")
	})
}

func TestRealRapidNestedLazyUnobsStringer(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		_ = rapid.Just(lazyUnobsWrapper{}).Draw(rt, "x")
	})
}

func TestRealRapidLazyMutStringer(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		_ = rapid.Just(lazyMut{}).Draw(rt, "x")
	})
}
`)
		hReal, err := newAt(e2eDir)
		if err != nil {
			t.Fatal(err)
		}
		realProofs, err := hReal.ComputeObservabilityBatch([]Subject{
			{Package: "example.com/realrapid", Symbol: "TestRealRapidCheck"},
			{Package: "example.com/realrapid", Symbol: "TestRealRapidMakeAndError"},
			{Package: "example.com/realrapid", Symbol: "TestRealRapidStateMachineAndMake"},
			{Package: "example.com/realrapid", Symbol: "TestRealRapidDirtyStateMachine"},
			{Package: "example.com/realrapid", Symbol: "TestRealRapidUnsafeGenerator"},
			{Package: "example.com/realrapid", Symbol: "TestRealRapidSharedGeneratorFormat"},
			{Package: "example.com/realrapid", Symbol: "TestRealRapidLazyEnvStringer"},
			{Package: "example.com/realrapid", Symbol: "TestRealRapidNestedLazyEnvStringer"},
			{Package: "example.com/realrapid", Symbol: "TestRealRapidNestedLazyUnobsStringer"},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, sym := range []string{"TestRealRapidCheck", "TestRealRapidMakeAndError", "TestRealRapidStateMachineAndMake"} {
			gotReal := realProofs[Subject{Package: "example.com/realrapid", Symbol: sym}]
			if !gotReal.Observable || !gotReal.EffectFree {
				t.Fatalf("end-to-end real pgregory.net/rapid@v1.3.0 %s = %+v, want Observable=true EffectFree=true", sym, gotReal)
			}
		}
		if gotDirty := realProofs[Subject{Package: "example.com/realrapid", Symbol: "TestRealRapidDirtyStateMachine"}]; gotDirty.Observable || !strings.Contains(gotDirty.Reason, "os.Hostname") {
			t.Fatalf("end-to-end real pgregory.net/rapid@v1.3.0 TestRealRapidDirtyStateMachine = %+v, want Observable=false witnessing os.Hostname", gotDirty)
		}
		if gotUnsafe := realProofs[Subject{Package: "example.com/realrapid", Symbol: "TestRealRapidUnsafeGenerator"}]; gotUnsafe.Observable || !strings.Contains(gotUnsafe.Reason, "unsafe pointer reachable") {
			t.Fatalf("end-to-end real pgregory.net/rapid@v1.3.0 TestRealRapidUnsafeGenerator = %+v, want Observable=false with unsafe pointer reachable", gotUnsafe)
		}
		if gotShared := realProofs[Subject{Package: "example.com/realrapid", Symbol: "TestRealRapidSharedGeneratorFormat"}]; gotShared.Observable {
			t.Fatalf("end-to-end real pgregory.net/rapid@v1.3.0 TestRealRapidSharedGeneratorFormat = %+v, want Observable=false", gotShared)
		}
		for _, sym := range []string{"TestRealRapidLazyEnvStringer", "TestRealRapidNestedLazyEnvStringer"} {
			gotEnv := realProofs[Subject{Package: "example.com/realrapid", Symbol: sym}]
			if !gotEnv.Observable || gotEnv.EffectFree {
				t.Fatalf("end-to-end real pgregory.net/rapid@v1.3.0 %s = %+v, want Observable=true EffectFree=false", sym, gotEnv)
			}
		}
		if gotUnobs := realProofs[Subject{Package: "example.com/realrapid", Symbol: "TestRealRapidNestedLazyUnobsStringer"}]; gotUnobs.Observable || !strings.Contains(gotUnobs.Reason, "os.Hostname") {
			t.Fatalf("end-to-end real pgregory.net/rapid@v1.3.0 TestRealRapidNestedLazyUnobsStringer = %+v, want Observable=false witnessing os.Hostname", gotUnobs)
		}
		rooted, err := hReal.ComputeRootedFunctions(context.Background(), []Subject{
			{Package: "example.com/realrapid", Symbol: "TestRealRapidLazyMutStringer"},
		})
		if err != nil {
			t.Fatal(err)
		}
		mutSubj := Subject{Package: "example.com/realrapid", Symbol: "TestRealRapidLazyMutStringer"}
		mutRooted := rooted[mutSubj]
		if !mutRooted.Complete {
			t.Fatalf("ComputeRootedFunctions(TestRealRapidLazyMutStringer) Complete=false, want Complete=true with lazyMut.String")
		}
		sawLazyMutString := false
		for fn := range mutRooted.Fns {
			if strings.Contains(fn, "example.com/realrapid") && strings.Contains(fn, "lazyMut") && strings.HasSuffix(fn, "String") {
				sawLazyMutString = true
				break
			}
		}
		if !sawLazyMutString {
			t.Fatalf("ComputeRootedFunctions(TestRealRapidLazyMutStringer) = %+v, want lazyMut.String attributed", mutRooted.Fns)
		}
	})

	// 2. Real gopkg.in/yaml.v3@v3.0.1
	t.Run("yaml.v3@v3.0.1", func(t *testing.T) {
		yamlPkg := loadCachedBatch(t, "gopkg.in/yaml.v3@v3.0.1", ".")["gopkg.in/yaml.v3"]
		fact := dynstate.FactOf(true, yamlPkg)
		if !slices.Contains(fact.MemoDischarges, "gopkg.in/yaml.v3.structMap") {
			t.Fatalf("real gopkg.in/yaml.v3@v3.0.1 MemoDischarges = %v, want gopkg.in/yaml.v3.structMap", fact.MemoDischarges)
		}
	})

	// 3. Real golang.org/x/sys/unix across multiple upstream versions
	for _, sysVer := range []string{"v0.42.0", "v0.48.0"} {
		t.Run("x_sys_unix@"+sysVer, func(t *testing.T) {
			unixPkg := loadCachedBatch(t, "golang.org/x/sys@"+sysVer, "./unix")["golang.org/x/sys/unix"]
			fact := dynstate.FactOf(true, unixPkg)
			if !slices.Contains(fact.MappingDischarges, "golang.org/x/sys/unix.mapper") {
				t.Fatalf("real golang.org/x/sys@%s/unix MappingDischarges = %v, want golang.org/x/sys/unix.mapper", sysVer, fact.MappingDischarges)
			}
		})
	}

	// 4. Real google.golang.org/protobuf across multiple upstream versions (Classic + Edition 2023 Opaque API),
	// loading the full transitive google.golang.org/protobuf/... package cone from reflect/protodesc and types/descriptorpb.
	for _, pbVer := range []string{"v1.33.0", "v1.35.1", "v1.36.10", "v1.36.11"} {
		t.Run("protobuf@"+pbVer, func(t *testing.T) {
			loaded := loadCachedBatch(
				t,
				"google.golang.org/protobuf@"+pbVer,
				"./internal/filedesc",
				"./internal/filetype",
				"./internal/encoding/tag",
				"./internal/impl",
				"./runtime/protoimpl",
				"./reflect/protodesc",
				"./types/descriptorpb",
			)
			allPB := map[string]*packages.Package{}
			var collectPBCone func(p *packages.Package)
			collectPBCone = func(p *packages.Package) {
				if p == nil || !strings.HasPrefix(p.PkgPath, "google.golang.org/protobuf/") {
					return
				}
				if allPB[p.PkgPath] != nil {
					return
				}
				allPB[p.PkgPath] = p
				for _, imp := range p.Imports {
					collectPBCone(imp)
				}
			}
			for _, rootPkg := range loaded {
				collectPBCone(rootPkg)
			}
			pbPaths := make([]string, 0, len(allPB))
			for pkgPath := range allPB {
				pbPaths = append(pbPaths, pkgPath)
			}
			slices.Sort(pbPaths)
			pbPatterns := make([]string, len(pbPaths))
			for i, pkgPath := range pbPaths {
				pbPatterns[i] = "./" + strings.TrimPrefix(pkgPath, "google.golang.org/protobuf/")
			}
			allPB = loadCachedBatch(t, "google.golang.org/protobuf@"+pbVer, pbPatterns...)
			for _, pkgPath := range pbPaths {
				p := allPB[pkgPath]
				if p == nil || (len(p.GoFiles) > 0 && (len(p.Syntax) == 0 || p.TypesInfo == nil)) {
					t.Fatalf("real protobuf@%s package %s missing AST/TypesInfo after full-cone load", pbVer, pkgPath)
				}
			}

			pbFacts := make(map[string]dynstate.Fact, len(pbPaths))
			meta := make([]dynstate.GraphPackage, 0, len(pbPaths))
			facts := make(map[string][]dynstate.Fact, len(pbPaths))
			for _, pkgPath := range pbPaths {
				p := allPB[pkgPath]
				f := dynstate.FactOf(true, p)
				pbFacts[pkgPath] = f
				facts[pkgPath] = []dynstate.Fact{f}
				var imps []string
				for impPath := range p.Imports {
					if allPB[impPath] != nil {
						imps = append(imps, impPath)
					}
				}
				slices.Sort(imps)
				meta = append(meta, dynstate.GraphPackage{
					ImportPath: pkgPath,
					PkgPath:    pkgPath,
					Imports:    imps,
					Class:      dynstate.PinnedPackage,
					Pin:        "google.golang.org/protobuf@" + pbVer,
				})
			}

			implPkg := allPB["google.golang.org/protobuf/internal/impl"]
			fdFact := pbFacts["google.golang.org/protobuf/internal/filedesc"]
			ftFact := pbFacts["google.golang.org/protobuf/internal/filetype"]
			implFact := pbFacts["google.golang.org/protobuf/internal/impl"]
			descFact := pbFacts["google.golang.org/protobuf/types/descriptorpb"]

			var fdBuilderFact *protoaudit.ProtoRuntimeTypeFact
			for i := range fdFact.ProtoRuntimeTypes {
				rt := &fdFact.ProtoRuntimeTypes[i]
				if rt.Type.Name == "Builder" && rt.Role == protoaudit.ProtoRoleDescBuilder {
					fdBuilderFact = rt
				}
			}
			if fdBuilderFact == nil {
				t.Fatalf("real protobuf@%s/internal/filedesc ProtoRuntimeTypes = %+v, missing desc_builder Builder", pbVer, fdFact.ProtoRuntimeTypes)
			}
			fileGuardRef := syntaxutil.TypeRef{Pkg: "google.golang.org/protobuf/internal/filedesc", Name: "File"}
			if !slices.Contains(fdBuilderFact.GuardTypes, fileGuardRef) {
				t.Fatalf("real protobuf@%s/internal/filedesc Builder GuardTypes = %+v, missing File", pbVer, fdBuilderFact.GuardTypes)
			}

			var ftBuilderFact *protoaudit.ProtoRuntimeTypeFact
			for i := range ftFact.ProtoRuntimeTypes {
				rt := &ftFact.ProtoRuntimeTypes[i]
				if rt.Type.Name == "Builder" && rt.Role == protoaudit.ProtoRoleBuilder {
					ftBuilderFact = rt
				}
			}
			wantSubBuilder := syntaxutil.TypeRef{Pkg: "google.golang.org/protobuf/internal/filedesc", Name: "Builder"}
			if ftBuilderFact == nil || ftBuilderFact.SubBuilder != wantSubBuilder {
				t.Fatalf("real protobuf@%s/internal/filetype Builder = %+v, want SubBuilder=%+v", pbVer, ftFact.ProtoRuntimeTypes, wantSubBuilder)
			}

			roles := map[string]protoaudit.ProtoRuntimeTypeFact{}
			for _, rt := range implFact.ProtoRuntimeTypes {
				roles[rt.Type.Name] = rt
			}
			if roles["EnumInfo"].Role != protoaudit.ProtoRoleEnum ||
				roles["MessageInfo"].Role != protoaudit.ProtoRoleMessage ||
				roles["ExtensionInfo"].Role != protoaudit.ProtoRoleExtension {
				t.Fatalf("real protobuf@%s/internal/impl ProtoRuntimeTypes = %+v", pbVer, implFact.ProtoRuntimeTypes)
			}
			var methodsGuardRef syntaxutil.TypeRef
			for _, imp := range implPkg.Types.Imports() {
				if imp.Path() == "google.golang.org/protobuf/runtime/protoiface" {
					if mObj := imp.Scope().Lookup("Methods"); mObj != nil {
						var okRef bool
						methodsGuardRef, okRef = syntaxutil.TypeRefOfStruct(mObj.Type())
						if !okRef {
							t.Fatalf("real protobuf@%s TypeRefOfStruct(protoiface.Methods) returned false", pbVer)
						}
					}
				}
			}
			atomicNilGuardRef := syntaxutil.TypeRef{Pkg: "google.golang.org/protobuf/internal/impl", Name: "atomicNilMessage"}
			if !methodsGuardRef.Valid() || !slices.Contains(roles["MessageInfo"].GuardTypes, methodsGuardRef) || !slices.Contains(roles["MessageInfo"].GuardTypes, atomicNilGuardRef) {
				t.Fatalf("real protobuf@%s/internal/impl MessageInfo GuardTypes = %+v, missing %+v or %+v", pbVer, roles["MessageInfo"].GuardTypes, methodsGuardRef, atomicNilGuardRef)
			}

			allGuarded := map[syntaxutil.TypeRef]string{}
			for _, g := range fdBuilderFact.GuardTypes {
				allGuarded[g] = "filedesc.Builder"
			}
			for _, g := range ftBuilderFact.GuardTypes {
				allGuarded[g] = "filetype.Builder"
			}
			for _, g := range roles["MessageInfo"].GuardTypes {
				allGuarded[g] = "impl.MessageInfo"
			}
			for _, g := range roles["ExtensionInfo"].GuardTypes {
				allGuarded[g] = "impl.ExtensionInfo"
			}
			var guardHits []string
			for _, pkgPath := range pbPaths {
				f := pbFacts[pkgPath]
				for _, mut := range f.MutatedStructTypes {
					if owner, guarded := allGuarded[mut]; guarded {
						guardHits = append(guardHits, pkgPath+" -> "+owner+":"+mut.Pkg+"."+mut.Name)
					}
					if mut.Pkg == "google.golang.org/protobuf/internal/impl" &&
						(mut.Name == "EnumInfo" || mut.Name == "MessageInfo" || mut.Name == "ExtensionInfo") {
						guardHits = append(guardHits, pkgPath+" -> impl:"+mut.Name)
					}
				}
			}
			if len(guardHits) > 0 {
				t.Fatalf("real protobuf@%s unexpectedly marked guarded structs in MutatedStructTypes:\n  %s", pbVer, strings.Join(guardHits, "\n  "))
			}

			if len(descFact.ProtoClusters) == 0 {
				t.Fatalf("real protobuf@%s/types/descriptorpb ProtoClusters = empty, want >= 1", pbVer)
			}
			for _, rootPkgPath := range []string{
				"google.golang.org/protobuf/reflect/protodesc",
				"google.golang.org/protobuf/types/descriptorpb",
			} {
				st := dynstate.Compose(meta, facts, rootPkgPath, nil, true, false)
				discharged := strings.Split(st.AttestationDischarges, ",")
				for _, wantKey := range []string{
					"google.golang.org/protobuf/types/descriptorpb.file_google_protobuf_descriptor_proto_enumTypes",
					"google.golang.org/protobuf/types/descriptorpb.file_google_protobuf_descriptor_proto_goTypes",
					"google.golang.org/protobuf/types/descriptorpb.file_google_protobuf_descriptor_proto_msgTypes",
				} {
					if !slices.Contains(discharged, wantKey) {
						t.Fatalf("real protobuf@%s (%s) AttestationDischarges = %q, missing %s", pbVer, rootPkgPath, st.AttestationDischarges, wantKey)
					}
				}
				for _, c := range st.RootCulprits {
					if c.PkgPath == "google.golang.org/protobuf/types/descriptorpb" ||
						c.PkgPath == "google.golang.org/protobuf/runtime/protoimpl" {
						t.Fatalf("real protobuf@%s (%s) unexpectedly retained cluster/protoimpl culprit %+v", pbVer, rootPkgPath, c)
					}
				}
			}

			// Mutating either protoiface.Methods or filedesc.File in a caller package must revoke descriptorpb discharges!
			for _, poisonRef := range []syntaxutil.TypeRef{methodsGuardRef, fileGuardRef} {
				metaPoison := append([]dynstate.GraphPackage{{
					ImportPath: "example.com/caller",
					PkgPath:    "example.com/caller",
					Imports:    []string{"google.golang.org/protobuf/reflect/protodesc"},
					Class:      dynstate.MutableLocalPackage,
				}}, meta...)
				factsPoison := make(map[string][]dynstate.Fact, len(facts)+1)
				for k, v := range facts {
					factsPoison[k] = v
				}
				factsPoison["example.com/caller"] = []dynstate.Fact{{MutatedStructTypes: []syntaxutil.TypeRef{poisonRef}}}
				stPoison := dynstate.Compose(metaPoison, factsPoison, "example.com/caller", nil, true, false)
				if slices.Contains(strings.Split(stPoison.AttestationDischarges, ","), "google.golang.org/protobuf/types/descriptorpb.file_google_protobuf_descriptor_proto_msgTypes") {
					t.Fatalf("real protobuf@%s GuardTypes mutation on %+v failed to revoke msgTypes AttestationDischarges: %q", pbVer, poisonRef, stPoison.AttestationDischarges)
				}
			}
		})
	}

	// 5. Real google.golang.org/grpc across multiple upstream versions
	for _, grpcVer := range []string{"v1.80.0", "v1.82.1", "v1.83.2"} {
		t.Run("grpc@"+grpcVer, func(t *testing.T) {
			grpcPkg := loadCachedBatch(t, "google.golang.org/grpc@"+grpcVer, ".")["google.golang.org/grpc"]
			grpcFact := dynstate.FactOf(true, grpcPkg)
			for _, mut := range grpcFact.MutatedStructTypes {
				if mut.Pkg == "google.golang.org/grpc" &&
					(mut.Name == "ServiceDesc" || mut.Name == "MethodDesc" || mut.Name == "StreamDesc") {
					t.Fatalf("real grpc@%s unexpectedly marked %+v in MutatedStructTypes", grpcVer, mut)
				}
			}
		})
	}
}

// The property-harness audit: a distilled pgregory.net/rapid - the
// real v1.3.0 shape's blockers in miniature (computed property
// dispatch, clock reads, failure-artifact writes, flag-registered
// configuration, interface log calls, the concrete *testing.T entry
// boundary) - proves observable behind the package audit exactly when
// every value crossing the harness boundary passes the gate, and
// widens when one does not
// (REQ-closure-observability-property-harness).
func TestPropertyHarnessAudit(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{
		"rapid",
		"prop",
		"prop/propinit",
		"prop/propmain",
		"prop/propquiet",
		"prop/propexampleinit",
		"prop/propexamplemain",
		"prop/propenum",
		"prop/propenummut",
		"prop/propinitbox",
	} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, dir, "rapid/go.mod", "module pgregory.net/rapid\n\ngo 1.26\n")
	writeFile(t, dir, "rapid/rapid.go", `package rapid

import (
	"flag"
	"fmt"
	"hash/maphash"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

var flags struct {
	checks   int
	seed     uint64
	failfile string
}

func init() {
	flag.IntVar(&flags.checks, "rapid.checks", 100, "number of checks")
	flag.Uint64Var(&flags.seed, "rapid.seed", 0, "PRNG seed")
	flag.StringVar(&flags.failfile, "rapid.failfile", "", "failure file")
}

type TB interface {
	Helper()
	Logf(format string, args ...any)
	Errorf(format string, args ...any)
	Name() string
}

type T struct {
	tb         TB
	customHook interface{ RapidInternalNeverInvoked() }
	state      uint64
	fail       bool
}

func (t *T) Helper()                           { t.tb.Helper() }
func (t *T) Name() string                      { return t.tb.Name() }
func (t *T) Logf(format string, args ...any)   { t.tb.Logf(format, args...) }
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

type Generator[V any] struct {
	gen func(*T) V
}

func (g *Generator[V]) Draw(t *T, label string) V {
	t.state = t.state*6364136223846793005 + 1442695040888963407
	v := g.gen(t)
	if t.fail && t.tb != nil {
		_ = fmt.Sprintf("%s=%v/%#v", label, v, v)
	}
	return v
}

func (g *Generator[V]) Example(seed ...int) V {
	s := baseSeed()
	if len(seed) > 0 {
		s = uint64(seed[0])
	}
	return g.Draw(&T{tb: &exampleTB{}, state: s}, "example")
}

func Int() *Generator[int] {
	return &Generator[int]{gen: func(t *T) int { return int(t.state >> 33) }}
}

func Just[V any](v V) *Generator[V] {
	return &Generator[V]{gen: func(t *T) V { return v }}
}

func Custom[V any](fn func(*T) V) *Generator[V] {
	return &Generator[V]{gen: fn}
}

func Deriv[V any](g *Generator[V]) *Generator[V] {
	return &Generator[V]{gen: g.gen}
}

// The real v1.3.0 boundary: a concrete *testing.T entry, the TB
// interface only internal.
func Check(t *testing.T, prop func(*T)) {
	t.Helper()
	checkTB(t, prop)
}

func MakeCheck(prop func(*T)) func(*testing.T) {
	return func(t *testing.T) {
		checkTB(t, prop)
	}
}

// A named internal function dispatched through a package variable -
// the harness's own function-valued internals, whose sites must stay
// harness frames rather than subject content.
var failReporter = reportFailure

func reportFailure(tb TB, seed uint64) {
	tb.Errorf("[rapid] failed (seed=%d)", seed)
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
	_, _ = f.Write(data)
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return err
	}
	return os.Rename(f.Name(), filename)
}

func checkTB(tb TB, prop func(*T)) {
	start := time.Now()
	t := &T{tb: tb, state: flags.seed}
	for i := 0; i < flags.checks && !t.fail; i++ {
		checkOnce(t, prop)
	}
	if t.fail {
		if flags.failfile != "" {
			_ = saveFailFile(flags.failfile, []byte(fmt.Sprintf("seed=%d", t.state)))
		}
		failReporter(tb, t.state)
		return
	}
	_ = io.EOF
	tb.Logf("[rapid] OK, passed %v tests (%v)", flags.checks, time.Since(start))
}

func checkOnce(t *T, prop func(*T)) {
	prop(t)
}

type StateMachine interface {
	Check(*T)
}

func StateMachineActions(sm StateMachine) map[string]func(*T) {
	v := reflect.ValueOf(sm)
	typ := v.Type()
	actions := make(map[string]func(*T))
	for i := 0; i < typ.NumMethod(); i++ {
		name := typ.Method(i).Name
		if name == "Check" {
			continue
		}
		if fn, ok := v.Method(i).Interface().(func(*T)); ok {
			actions[name] = fn
		} else if fnTB, ok := v.Method(i).Interface().(func(TB)); ok {
			actions[name] = func(t *T) { fnTB(t) }
		}
	}
	return actions
}

func StateMachineSetActions(sm StateMachine) map[string]func(*T) {
	v := reflect.ValueOf(sm)
	typ := v.Type()
	actions := make(map[string]func(*T))
	mv := reflect.ValueOf(actions)
	for i := 0; i < typ.NumMethod(); i++ {
		name := typ.Method(i).Name
		if name == "Check" {
			continue
		}
		m := v.Method(i)
		if m.Type().AssignableTo(mv.Type().Elem()) {
			mv.SetMapIndex(reflect.ValueOf(name), m)
		}
	}
	return actions
}

func (t *T) Repeat(actions map[string]func(*T)) {
	for _, fn := range actions {
		fn(t)
	}
}
`)
	if rapidPkgs, rErr := packages.Load(&packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedModule,
		Dir: filepath.Join(dir, "rapid"),
	}, "."); rErr != nil || len(rapidPkgs) != 1 {
		t.Fatalf("load rapid fixture: err=%v pkgs=%v", rErr, rapidPkgs)
	} else if ok, reason := propharness.VerifyPackageWithReason(true, rapidPkgs[0]); !ok {
		t.Fatalf("VerifyPackage(rapid fixture) = false (%s), want true", reason)
	}
	writeFile(t, dir, "prop/go.mod", `module example.com/prop

go 1.26

require pgregory.net/rapid v0.0.0

replace pgregory.net/rapid => ../rapid
`)
	writeFile(t, dir, "prop/prop.go", `package prop

import "pgregory.net/rapid"

func Add(a, b int) int { return a + b }

// Startup-flow generator composition: the inner call result crosses
// the boundary gate exactly as it would in subject flow.
var derived = rapid.Deriv(rapid.Int())

func Derived() *rapid.Generator[int] { return derived }
`)
	writeFile(t, dir, "prop/prop_test.go", `package prop

import (
	"os"
	"testing"
	"time"

	"pgregory.net/rapid"
)

func TestCheckLiteral(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.Int().Draw(rt, "n")
		rt.Logf("n=%v", n)
		if Add(n, 0) != n {
			rt.Errorf("bad add")
		}
	})
}

// A property loaded from mutable state is not locally closed: the
// harness boundary refuses it.
var openProp func(*rapid.T)

func TestCheckOpen(t *testing.T) {
	rapid.Check(t, openProp)
}

func TestMakeCheck(t *testing.T) {
	t.Run("prop", rapid.MakeCheck(func(rt *rapid.T) {
		g := rapid.Custom(func(rt *rapid.T) int { return 42 })
		if Add(g.Draw(rt, "x"), 0) != 42 {
			rt.Errorf("bad custom")
		}
	}))
}

// The harness-wrapped callback is a closed value: a computed call of
// MakeCheck's result dispatches only the gate-judged property.
func TestMakeCheckComputed(t *testing.T) {
	f := rapid.MakeCheck(func(rt *rapid.T) {
		if Add(1, 1) != 2 {
			rt.Errorf("bad")
		}
	})
	f(t)
}

// A generator callback loaded from mutable state refuses at the
// boundary like the property itself.
var openGen func(*rapid.T) int

func TestCustomOpen(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		g := rapid.Custom(openGen)
		if g.Draw(rt, "x") < 0 {
			rt.Errorf("bad")
		}
	})
}

// A generator loaded from shared mutable state is a sibling's plant:
// the receiver refuses at the boundary - harness-owned TYPES confer
// no admission, only handle parameters and gated call results do.
var sharedGen *rapid.Generator[int]

func TestDrawShared(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		if sharedGen.Draw(rt, "s") < 0 {
			rt.Errorf("bad")
		}
	})
}

// A generator laundered through a helper parameter refuses the same
// way: the parameter crossing judges the caller's argument.
func drawDirect(rt *rapid.T, g *rapid.Generator[int]) int { return g.Draw(rt, "d") }

var sharedGen2 *rapid.Generator[int]

func TestParamLaunder(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		if drawDirect(rt, sharedGen2) < 0 {
			rt.Errorf("bad")
		}
	})
}

// A harness function reached as a dynamic target keeps the
// conservative refusal: no static site exists to gate the crossing.
var flip bool

func altCheck(t *testing.T, prop func(*rapid.T)) {}

func TestDynamicDriver(t *testing.T) {
	f := rapid.Check
	if flip {
		f = altCheck
	}
	f(t, func(rt *rapid.T) {})
}

func TestExampleSeeded(t *testing.T) {
	if rapid.Int().Example(42) < -1<<60 {
		t.Fatal("bad")
	}
}

func TestExampleUnseeded(t *testing.T) {
	if rapid.Int().Example() < -1<<60 {
		t.Fatal("bad")
	}
}

var dynamicSeeds []int

func TestExampleDynamicSeedSlice(t *testing.T) {
	if rapid.Int().Example(dynamicSeeds...) < -1<<60 {
		t.Fatal("bad")
	}
}

func altExample(seed ...int) int { return 0 }

func TestExampleValueTaken(t *testing.T) {
	fn := rapid.Int().Example
	if flip {
		fn = altExample
	}
	if fn(42) < -1<<60 {
		t.Fatal("bad")
	}
}

func TestExampleBoundSeeded(t *testing.T) {
	fn := rapid.Int().Example
	if fn(42) < -1<<60 {
		t.Fatal("bad")
	}
}

func TestExampleBoundUnseeded(t *testing.T) {
	fn := rapid.Int().Example
	if fn() < -1<<60 {
		t.Fatal("bad")
	}
}

func TestDrawBoundShared(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		draw := sharedGen.Draw
		if draw(rt, "s") < 0 {
			rt.Errorf("bad")
		}
	})
}

func TestSmuggleHarnessValue(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		g := rapid.Just(rapid.Int().Example)
		if g == nil {
			rt.Errorf("nil")
		}
	})
}

func PlainExampleUnseeded() int {
	return rapid.Int().Example()
}

type cleanMachine struct{ sum int }

func (m *cleanMachine) AddOne(rt *rapid.T) { m.sum = Add(m.sum, 1) }
func (m *cleanMachine) Check(rt *rapid.T) {
	if m.sum < 0 {
		rt.Errorf("negative")
	}
}

func TestStateMachineClean(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		m := &cleanMachine{}
		rt.Repeat(rapid.StateMachineActions(m))
		m.Check(rt)
	})
}

func TestStateMachineSubtest(t *testing.T) {
	t.Run("sub", func(t *testing.T) {
		rapid.Check(t, func(rt *rapid.T) {
			m := &cleanMachine{}
			rt.Repeat(rapid.StateMachineActions(m))
			m.Check(rt)
		})
	})
}

type impureMachine struct{}

func (m *impureMachine) LeakClock(rt *rapid.T) { _ = time.Now() }
func (m *impureMachine) Check(rt *rapid.T)     {}

func TestStateMachineImpureClock(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		m := &impureMachine{}
		rt.Repeat(rapid.StateMachineActions(m))
		m.Check(rt)
	})
}

type impureTBMachine struct{}

func (m *impureTBMachine) LeakTB(tb rapid.TB) { _ = time.Now() }
func (m *impureTBMachine) Check(rt *rapid.T)  {}

func TestStateMachineImpureTB(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		m := &impureTBMachine{}
		rt.Repeat(rapid.StateMachineActions(m))
		m.Check(rt)
	})
}

type envMachine struct{}

func (m *envMachine) ReadEnv(rt *rapid.T) { _ = os.Getenv("LOGGED_VAR") }
func (m *envMachine) Check(rt *rapid.T)   {}

func TestStateMachineEnvNotEffectFree(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		m := &envMachine{}
		rt.Repeat(rapid.StateMachineActions(m))
		m.Check(rt)
	})
}

func TestStateMachineSetMapSubtest(t *testing.T) {
	t.Run("sub", func(t *testing.T) {
		rapid.Check(t, func(rt *rapid.T) {
			m := &cleanMachine{}
			rt.Repeat(rapid.StateMachineSetActions(m))
			m.Check(rt)
		})
	})
}

func TestStateMachineSetMapImpure(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		m := &impureMachine{}
		rt.Repeat(rapid.StateMachineSetActions(m))
		m.Check(rt)
	})
}
`)
	writeFile(t, dir, "prop/propquiet/propquiet.go", `package propquiet

import "fmt"

// The fmt import feeds only the audited Sprint family: an unbacked
// potential-external import fallback beside the harness fact, pinning
// that the backed fact wins the diagnostic.
func Ok() bool { return fmt.Sprintf("%d", 1) != "" }
`)
	writeFile(t, dir, "prop/propquiet/propquiet_test.go", `package propquiet

import (
	"testing"

	"pgregory.net/rapid"
)

// A test that touches neither the harness handle's classified surface
// nor any other effect-bearing selector: without the recorded harness
// fact this package would verify by hash alone.
func TestQuiet(t *testing.T) {
	if rapid.Int() == nil || !Ok() {
		panic("quiet fixture broke")
	}
}
`)
	writeFile(t, dir, "prop/propinit/propinit.go", `package propinit

import "pgregory.net/rapid"

// A harness value created in startup flow carries the gate there: the
// anonymous-target admission downstream rests on every flow judging
// what crosses the boundary.
var openInitProp func(*rapid.T)

var wrapped = rapid.MakeCheck(openInitProp)

func Prod() int {
	if wrapped == nil {
		return 0
	}
	return 7
}
`)
	writeFile(t, dir, "prop/propinit/propinit_test.go", `package propinit

import "testing"

func TestProd(t *testing.T) {
	if Prod() == 0 {
		t.Fatal()
	}
}
`)
	writeFile(t, dir, "prop/propmain/propmain.go", `package propmain

func Prod() int { return 7 }
`)
	writeFile(t, dir, "prop/propmain/propmain_test.go", `package propmain

import (
	"os"
	"testing"

	"pgregory.net/rapid"
)

// The boundary gate holds in test-main flow: an unclosed callable
// crossing into the harness there widens exactly as in subject flow.
var openMainProp func(*rapid.T)

func TestMain(m *testing.M) {
	_ = rapid.MakeCheck(openMainProp)
	os.Exit(m.Run())
}

func TestProd(t *testing.T) {
	if Prod() == 0 {
		t.Fatal()
	}
}
`)
	writeFile(t, dir, "prop/propexampleinit/propexampleinit.go", `package propexampleinit

import "pgregory.net/rapid"

var boot = rapid.Int().Example()

func Prod() int { return boot + 1 }
`)
	writeFile(t, dir, "prop/propexampleinit/propexampleinit_test.go", `package propexampleinit

import "testing"

func TestProd(t *testing.T) {
	if Prod() == -999999999 {
		t.Fatal()
	}
}
`)
	writeFile(t, dir, "prop/propexamplemain/propexamplemain.go", `package propexamplemain

func Prod() int { return 7 }
`)
	writeFile(t, dir, "prop/propexamplemain/propexamplemain_test.go", `package propexamplemain

import (
	"os"
	"testing"

	"pgregory.net/rapid"
)

func TestMain(m *testing.M) {
	_ = rapid.Int().Example()
	os.Exit(m.Run())
}

func TestProd(t *testing.T) {
	if Prod() == 0 {
		t.Fatal()
	}
}
`)
	writeFile(t, dir, "prop/propenum/propenum.go", `package propenum

func Ok() int { return 1 }
`)
	writeFile(t, dir, "prop/propenum/propenum_test.go", `package propenum

import (
	"fmt"
	"os"
	"testing"

	"pgregory.net/rapid"
)

const deadEnumMode = os.ModeDir

type cleanTag struct{}

func (cleanTag) String() string { return "tag" }

type enumDirtySM struct{}

func (*enumDirtySM) Leak(rt *rapid.T) { _, _ = os.Hostname() }
func (*enumDirtySM) Check(rt *rapid.T) {}

func RunStateMachine(t *testing.T, tag fmt.Stringer) {
	_ = tag
	rapid.Check(t, func(rt *rapid.T) {
		m := &enumDirtySM{}
		rt.Repeat(rapid.StateMachineActions(m))
		m.Check(rt)
	})
}

func TestCallerStateMachine(t *testing.T) {
	RunStateMachine(t, cleanTag{})
}

type enumCleanSM struct{ n int }

func (m *enumCleanSM) Step(rt *rapid.T) { m.n++ }
func (m *enumCleanSM) Check(rt *rapid.T) {
	if m.n < 0 {
		rt.Errorf("neg")
	}
}

func RunCleanStateMachine(t *testing.T, tag fmt.Stringer) {
	_ = tag
	rapid.Check(t, func(rt *rapid.T) {
		m := &enumCleanSM{}
		rt.Repeat(rapid.StateMachineActions(m))
		m.Check(rt)
	})
}

func TestCallerCleanStateMachine(t *testing.T) {
	RunCleanStateMachine(t, cleanTag{})
}

func TestCallerCleanWithUnusedDeadTag(t *testing.T) {
	RunCleanStateMachine(t, enumDeadLinkStringer{})
}

type enumHostStringer struct{}

func (enumHostStringer) String() string {
	h, _ := os.Hostname()
	return h
}

func RunStringerProp(t *testing.T, s fmt.Stringer) {
	rapid.Check(t, func(rt *rapid.T) {
		_ = rapid.Just(s).Draw(rt, "s")
	})
}

func TestCallerStringerProp(t *testing.T) {
	RunStringerProp(t, enumHostStringer{})
}

type enumDeadLinkStringer struct{}

func (enumDeadLinkStringer) String() string {
	if deadEnumMode == 0 {
		return ""
	}
	return "ok"
}

func RunDeadAstStringerProp(t *testing.T, s fmt.Stringer) {
	rapid.Check(t, func(rt *rapid.T) {
		_ = rapid.Just(s).Draw(rt, "s")
	})
}

func TestCallerDeadAstStringerProp(t *testing.T) {
	RunDeadAstStringerProp(t, enumDeadLinkStringer{})
}
`)
	writeFile(t, dir, "prop/propenummut/propenummut.go", `package propenummut

func Ok() int { return 1 }
`)
	writeFile(t, dir, "prop/propenummut/propenummut_test.go", `package propenummut

import (
	"fmt"
	"testing"

	"pgregory.net/rapid"
)

var enumMutCounter int

type mutCleanTag struct{}

func (mutCleanTag) String() string { return "clean" }

type mutSM struct{}

func (*mutSM) Bump(rt *rapid.T) { enumMutCounter++ }
func (*mutSM) Check(rt *rapid.T) {}

func RunMutStateMachine(t *testing.T, tag fmt.Stringer) {
	_ = tag
	rapid.Check(t, func(rt *rapid.T) {
		m := &mutSM{}
		rt.Repeat(rapid.StateMachineActions(m))
		m.Check(rt)
	})
}

func TestMutSMCaller(t *testing.T) {
	RunMutStateMachine(t, mutCleanTag{})
}

type mutStringer struct{}

func (*mutStringer) String() string {
	enumMutCounter++
	return "m"
}

func RunMutStringer(t *testing.T, s fmt.Stringer) {
	rapid.Check(t, func(rt *rapid.T) {
		_ = rapid.Just(s).Draw(rt, "s")
	})
}

func TestMutStringerCaller(t *testing.T) {
	RunMutStringer(t, &mutStringer{})
}
`)
	writeFile(t, dir, "prop/propinitbox/propinitbox.go", `package propinitbox

import (
	"os"

	"pgregory.net/rapid"
)

type customIface interface{ Tag() }

type initHostStringer struct{}

func (initHostStringer) Tag() {}
func (initHostStringer) GoString() string {
	return os.Getenv("INIT_BOX_ENV")
}
func (initHostStringer) Error() string {
	return os.Getenv("INIT_BOX_ENV")
}

var sharedInitMut int

type initMutStringer struct{}

func (*initMutStringer) Tag() {}
func (*initMutStringer) GoString() string {
	sharedInitMut++
	return "m"
}

type carrierBox struct {
	v customIface
}

var (
	initLiveStringer customIface
	initMutBox       customIface = &initMutStringer{}
)

func initHelperBox() {
	initLiveStringer = initHostStringer{}
}

func init() {
	initHelperBox()
}

func UseInitBoxedStringer() int {
	_ = rapid.Custom(func(rt *rapid.T) customIface { return initLiveStringer }).Example(42)
	return 0
}

func UseInitMutBoxed() int {
	_ = rapid.Custom(func(rt *rapid.T) customIface { return initMutBox }).Example(42)
	return 0
}

func UnrelatedRapidClean() int {
	return rapid.Int().Example(42)
}
`)
	writeFile(t, dir, "prop/propinitdead/propinitdead.go", `package propinitdead

import (
	"os"

	"pgregory.net/rapid"
)

func deadEnvHelper() string {
	return os.Getenv("DEAD_INIT_ENV")
}

type deadCustomIface interface{ Tag() }

type initDeadLinkStringer struct{}

func (initDeadLinkStringer) Tag() {
	if false {
		_ = deadEnvHelper()
	}
}

var initDeadStringer deadCustomIface = initDeadLinkStringer{}

func UseInitBoxedDeadAst() int {
	_ = rapid.Custom(func(rt *rapid.T) deadCustomIface { return initDeadStringer }).Example(42)
	return 0
}

func UnrelatedRapidDeadClean() int {
	return rapid.Int().Example(42)
}
`)
	writeFile(t, dir, "prop/propinitcall/propinitcall.go", `package propinitcall

import (
	"os"

	"pgregory.net/rapid"
)

type initCallIface interface{ Tag() }

type initCallStringer struct{}

func (initCallStringer) Tag() {}
func (initCallStringer) GoString() string {
	return os.Getenv("INIT_CALL_ENV")
}

var initCallLive initCallIface = initCallStringer{}

func init() {
	_ = rapid.Custom(func(rt *rapid.T) initCallIface { return initCallLive }).Example(42)
}

func StartupCallsHarnessFormat() int {
	return 0
}
`)
	writeFile(t, dir, "prop/propenumdead/propenumdead_test.go", `package propenumdead

import (
	"os"
	"testing"

	"pgregory.net/rapid"
)

func enumDeadEnvHelper() string {
	return os.Getenv("ENUM_DEAD_AST_ENV")
}

type enumDeadIface interface {
	Tag()
	Clean()
}

type enumDeadImpl struct{}

func (enumDeadImpl) Clean() {}

func (enumDeadImpl) Tag() {
	if false {
		_ = enumDeadEnvHelper()
	}
}

func (enumDeadImpl) RapidInternalNeverInvoked() {
	if false {
		_ = enumDeadEnvHelper()
	}
}

func RunEnumDeadAstTag(t *testing.T, v enumDeadIface) {
	rapid.Check(t, func(rt *rapid.T) {
		_ = rapid.Just(v).Draw(rt, "v")
	})
}

func TestCallerEnumDeadAstTag(t *testing.T) {
	RunEnumDeadAstTag(t, enumDeadImpl{})
}

func RunEnumUnrelatedClean(t *testing.T, v enumDeadIface) {
	v.Clean()
	rapid.Check(t, func(rt *rapid.T) {
		_ = rapid.Int().Draw(rt, "n")
	})
}

func TestCallerEnumUnrelatedClean(t *testing.T) {
	RunEnumUnrelatedClean(t, enumDeadImpl{})
}
`)
	h, err := newAt(filepath.Join(dir, "prop"))
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{
		{Package: "example.com/prop", Symbol: "TestCheckLiteral"},
		{Package: "example.com/prop", Symbol: "TestCheckOpen"},
		{Package: "example.com/prop", Symbol: "TestMakeCheck"},
		{Package: "example.com/prop", Symbol: "TestMakeCheckComputed"},
		{Package: "example.com/prop", Symbol: "TestCustomOpen"},
		{Package: "example.com/prop", Symbol: "TestDrawShared"},
		{Package: "example.com/prop", Symbol: "TestParamLaunder"},
		{Package: "example.com/prop", Symbol: "TestDynamicDriver"},
		{Package: "example.com/prop", Symbol: "TestExampleSeeded"},
		{Package: "example.com/prop", Symbol: "TestExampleUnseeded"},
		{Package: "example.com/prop", Symbol: "TestExampleDynamicSeedSlice"},
		{Package: "example.com/prop", Symbol: "TestExampleValueTaken"},
		{Package: "example.com/prop", Symbol: "TestExampleBoundSeeded"},
		{Package: "example.com/prop", Symbol: "TestExampleBoundUnseeded"},
		{Package: "example.com/prop", Symbol: "TestDrawBoundShared"},
		{Package: "example.com/prop", Symbol: "TestSmuggleHarnessValue"},
		{Package: "example.com/prop", Symbol: "PlainExampleUnseeded"},
		{Package: "example.com/prop", Symbol: "TestStateMachineClean"},
		{Package: "example.com/prop", Symbol: "TestStateMachineSubtest"},
		{Package: "example.com/prop", Symbol: "TestStateMachineImpureClock"},
		{Package: "example.com/prop", Symbol: "TestStateMachineImpureTB"},
		{Package: "example.com/prop", Symbol: "TestStateMachineEnvNotEffectFree"},
		{Package: "example.com/prop", Symbol: "TestStateMachineSetMapSubtest"},
		{Package: "example.com/prop", Symbol: "TestStateMachineSetMapImpure"},
		{Package: "example.com/prop/propinit", Symbol: "TestProd"},
		{Package: "example.com/prop/propmain", Symbol: "TestProd"},
		{Package: "example.com/prop/propexampleinit", Symbol: "TestProd"},
		{Package: "example.com/prop/propexamplemain", Symbol: "TestProd"},
		{Package: "example.com/prop/propenum", Symbol: "RunStateMachine"},
		{Package: "example.com/prop/propenum", Symbol: "TestCallerStateMachine"},
		{Package: "example.com/prop/propenum", Symbol: "RunCleanStateMachine"},
		{Package: "example.com/prop/propenum", Symbol: "TestCallerCleanStateMachine"},
		{Package: "example.com/prop/propenum", Symbol: "TestCallerCleanWithUnusedDeadTag"},
		{Package: "example.com/prop/propenum", Symbol: "RunStringerProp"},
		{Package: "example.com/prop/propenum", Symbol: "TestCallerStringerProp"},
		{Package: "example.com/prop/propenum", Symbol: "RunDeadAstStringerProp"},
		{Package: "example.com/prop/propenum", Symbol: "TestCallerDeadAstStringerProp"},
		{Package: "example.com/prop/propenumdead", Symbol: "RunEnumDeadAstTag"},
		{Package: "example.com/prop/propenumdead", Symbol: "RunEnumUnrelatedClean"},
		{Package: "example.com/prop/propinitbox", Symbol: "UseInitBoxedStringer"},
		{Package: "example.com/prop/propinitbox", Symbol: "UnrelatedRapidClean"},
		{Package: "example.com/prop/propinitdead", Symbol: "UseInitBoxedDeadAst"},
		{Package: "example.com/prop/propinitdead", Symbol: "UnrelatedRapidDeadClean"},
		{Package: "example.com/prop/propinitcall", Symbol: "StartupCallsHarnessFormat"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		pkg, symbol string
		observable  bool
		effectFree  bool
		reason      string
	}{
		{pkg: "example.com/prop", symbol: "TestCheckLiteral", observable: true, effectFree: true},
		{pkg: "example.com/prop", symbol: "TestCheckOpen", reason: "property-harness argument is not locally closed"},
		{pkg: "example.com/prop", symbol: "TestMakeCheck", observable: true, effectFree: true},
		{pkg: "example.com/prop", symbol: "TestMakeCheckComputed", observable: true, effectFree: true},
		{pkg: "example.com/prop", symbol: "TestCustomOpen", reason: "property-harness argument is not locally closed"},
		{pkg: "example.com/prop", symbol: "TestDrawShared", reason: "property-harness argument is not locally closed"},
		{pkg: "example.com/prop", symbol: "TestParamLaunder", reason: "property-harness argument is not locally closed"},
		{pkg: "example.com/prop", symbol: "TestDynamicDriver", reason: "property harness reached as a dynamic target"},
		{pkg: "example.com/prop", symbol: "TestExampleSeeded", observable: true, effectFree: true},
		{pkg: "example.com/prop", symbol: "TestExampleUnseeded", reason: "Generator.Example without an explicit seed (entropy)"},
		{pkg: "example.com/prop", symbol: "TestExampleDynamicSeedSlice", reason: "Generator.Example without an explicit seed (entropy)"},
		{pkg: "example.com/prop", symbol: "TestExampleValueTaken", reason: "property harness reached as a dynamic target"},
		{pkg: "example.com/prop", symbol: "TestExampleBoundSeeded", observable: true, effectFree: true},
		{pkg: "example.com/prop", symbol: "TestExampleBoundUnseeded", reason: "Generator.Example without an explicit seed (entropy)"},
		{pkg: "example.com/prop", symbol: "TestDrawBoundShared", reason: "property-harness argument is not locally closed"},
		{pkg: "example.com/prop", symbol: "TestSmuggleHarnessValue", reason: "property-harness argument is not locally closed"},
		{pkg: "example.com/prop", symbol: "PlainExampleUnseeded", reason: "Generator.Example without an explicit seed (entropy)"},
		{pkg: "example.com/prop", symbol: "TestStateMachineClean", observable: true, effectFree: true},
		{pkg: "example.com/prop", symbol: "TestStateMachineSubtest", observable: true, effectFree: true},
		{pkg: "example.com/prop", symbol: "TestStateMachineImpureClock", reason: "time.Now"},
		{pkg: "example.com/prop", symbol: "TestStateMachineImpureTB", reason: "time.Now"},
		{pkg: "example.com/prop", symbol: "TestStateMachineEnvNotEffectFree", observable: true, effectFree: false},
		{pkg: "example.com/prop", symbol: "TestStateMachineSetMapSubtest", observable: true, effectFree: true},
		{pkg: "example.com/prop", symbol: "TestStateMachineSetMapImpure", reason: "time.Now"},
		{pkg: "example.com/prop/propinit", symbol: "TestProd", reason: "property-harness argument is not locally closed in startup flow"},
		{pkg: "example.com/prop/propmain", symbol: "TestProd", reason: "property-harness argument is not locally closed"},
		{pkg: "example.com/prop/propexampleinit", symbol: "TestProd", reason: "Generator.Example without an explicit seed (entropy)"},
		{pkg: "example.com/prop/propexamplemain", symbol: "TestProd", reason: "Generator.Example without an explicit seed (entropy)"},
		{pkg: "example.com/prop/propenum", symbol: "RunStateMachine", reason: "os.Hostname"},
		{pkg: "example.com/prop/propenum", symbol: "TestCallerStateMachine", reason: "os.Hostname"},
		{pkg: "example.com/prop/propenum", symbol: "RunCleanStateMachine", observable: true, effectFree: true},
		{pkg: "example.com/prop/propenum", symbol: "TestCallerCleanStateMachine", observable: true, effectFree: true},
		{pkg: "example.com/prop/propenum", symbol: "TestCallerCleanWithUnusedDeadTag", reason: "os.ModeDir"},
		{pkg: "example.com/prop/propenum", symbol: "RunStringerProp", reason: "os.Hostname"},
		{pkg: "example.com/prop/propenum", symbol: "TestCallerStringerProp", reason: "os.Hostname"},
		{pkg: "example.com/prop/propenum", symbol: "RunDeadAstStringerProp", reason: "os.ModeDir"},
		{pkg: "example.com/prop/propenum", symbol: "TestCallerDeadAstStringerProp", reason: "os.ModeDir"},
		{pkg: "example.com/prop/propenumdead", symbol: "RunEnumDeadAstTag", observable: true, effectFree: false},
		{pkg: "example.com/prop/propenumdead", symbol: "RunEnumUnrelatedClean", observable: true, effectFree: true},
		{pkg: "example.com/prop/propinitbox", symbol: "UseInitBoxedStringer", observable: true, effectFree: false},
		{pkg: "example.com/prop/propinitbox", symbol: "UnrelatedRapidClean", observable: true, effectFree: true},
		{pkg: "example.com/prop/propinitdead", symbol: "UseInitBoxedDeadAst", observable: true, effectFree: false},
		{pkg: "example.com/prop/propinitdead", symbol: "UnrelatedRapidDeadClean", observable: true, effectFree: true},
		{pkg: "example.com/prop/propinitcall", symbol: "StartupCallsHarnessFormat", reason: "startup effect:"},
	} {
		got := proofs[Subject{Package: tc.pkg, Symbol: tc.symbol}]
		if got.Observable != tc.observable || got.EffectFree != tc.effectFree || tc.reason != "" && !strings.Contains(got.Reason, tc.reason) {
			t.Fatalf("%s/%s = %+v, want observable=%v effectFree=%v reason containing %q", tc.pkg, tc.symbol, got, tc.observable, tc.effectFree, tc.reason)
		}
	}

	// Verify order-independent non-contamination of init-boxed interface globals
	// when clean unrelated subjects run before init-boxed subjects on a fresh Hasher.
	hRev, err := newAt(filepath.Join(dir, "prop"))
	if err != nil {
		t.Fatal(err)
	}
	revProofs, err := hRev.ComputeObservabilityBatch([]Subject{
		{Package: "example.com/prop/propinitdead", Symbol: "UnrelatedRapidDeadClean"},
		{Package: "example.com/prop/propinitdead", Symbol: "UseInitBoxedDeadAst"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := revProofs[Subject{Package: "example.com/prop/propinitdead", Symbol: "UnrelatedRapidDeadClean"}]; !got.Observable || !got.EffectFree {
		t.Fatalf("reversed UnrelatedRapidDeadClean = %+v, want observable=true effectFree=true", got)
	}
	if got := revProofs[Subject{Package: "example.com/prop/propinitdead", Symbol: "UseInitBoxedDeadAst"}]; !got.Observable || got.EffectFree {
		t.Fatalf("reversed UseInitBoxedDeadAst = %+v, want observable=true effectFree=false", got)
	}

	// Verify ComputeRootedFunctions attributes enumerated StateMachine action methods,
	// enumerated Plane-1 fmt.Stringer methods, and init-boxed Plane-1 fmt.GoStringer methods
	// without dropping bound wrappers or polluting unrelated clean rapid subjects.
	rooted, err := h.ComputeRootedFunctions(context.Background(), []Subject{
		{Package: "example.com/prop/propenum", Symbol: "RunCleanStateMachine"},
		{Package: "example.com/prop/propenummut", Symbol: "RunMutStateMachine"},
		{Package: "example.com/prop/propenummut", Symbol: "RunMutStringer"},
		{Package: "example.com/prop/propinitbox", Symbol: "UseInitMutBoxed"},
		{Package: "example.com/prop/propinitbox", Symbol: "UnrelatedRapidClean"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, rc := range []struct {
		subj       Subject
		wantFn     string
		wantAbsent string
	}{
		{
			subj:   Subject{Package: "example.com/prop/propenum", Symbol: "RunCleanStateMachine"},
			wantFn: "example.com/prop/propenum\x00enumCleanSM.Step",
		},
		{
			subj:   Subject{Package: "example.com/prop/propenummut", Symbol: "RunMutStateMachine"},
			wantFn: "example.com/prop/propenummut\x00mutSM.Bump",
		},
		{
			subj:   Subject{Package: "example.com/prop/propenummut", Symbol: "RunMutStringer"},
			wantFn: "example.com/prop/propenummut\x00mutStringer.String",
		},
		{
			subj:   Subject{Package: "example.com/prop/propinitbox", Symbol: "UseInitMutBoxed"},
			wantFn: "example.com/prop/propinitbox\x00initMutStringer.GoString",
		},
		{
			subj:       Subject{Package: "example.com/prop/propinitbox", Symbol: "UnrelatedRapidClean"},
			wantAbsent: "example.com/prop/propinitbox\x00initMutStringer.GoString",
		},
	} {
		rf := rooted[rc.subj]
		if !rf.Complete {
			t.Fatalf("ComputeRootedFunctions(%v) Complete = false, want true (Fns=%v)", rc.subj, rf.Fns)
		}
		if rc.wantFn != "" && !rf.Fns[rc.wantFn] {
			t.Fatalf("ComputeRootedFunctions(%v) missing %q in Fns=%v", rc.subj, rc.wantFn, rf.Fns)
		}
		if rc.wantAbsent != "" && rf.Fns[rc.wantAbsent] {
			t.Fatalf("ComputeRootedFunctions(%v) unexpectedly attributed %q in Fns=%v", rc.subj, rc.wantAbsent, rf.Fns)
		}
	}

	// The audit admits observation, never purity: a package reaching the
	// harness stays unverifiable at the closure tier, so validity is
	// proven through the observation path rather than the source hash.
	// propquiet pins the fact itself - nothing else in that package
	// records a maximal EFFECT (its fmt import feeds only an unbacked
	// fallback reason) - and the diagnostic must name the backed fact,
	// never the fallback.
	for _, pkg := range []string{"example.com/prop", "example.com/prop/propquiet"} {
		effects, selected, err := h.maximalExternalEffects(pkg)
		if err != nil {
			t.Fatal(err)
		}
		if len(effects) == 0 {
			t.Fatalf("%s verified by hash alone: the audit must admit observation, never purity", pkg)
		}
		if selected == "" {
			t.Fatalf("%s unverifiable with an empty diagnostic", pkg)
		}
		if pkg == "example.com/prop/propquiet" && !strings.Contains(selected, "pgregory.net/rapid") {
			t.Fatalf("propquiet diagnostic = %q, want the harness fact named", selected)
		}
	}
}

// A top-level name declared by both the package's in-package test variant
// and its external test package tombstones that root alone: the requested
// ambiguous subject fails precise analysis with an error naming the
// collision and degrades to a refusing observability proof naming it,
// while sibling subjects of the same package analyze normally
// (REQ-closure-analysis's subject-local ambiguity arm).
func TestAmbiguousRootDegradesSubjectLocally(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":           "module example.com/ambroot\n\ngo 1.26\n",
		"lib.go":           "package ambroot\n\nfunc Compute(x int) int { return x * 2 }\n",
		"internal_test.go": "package ambroot\n\nimport \"testing\"\n\nfunc mustHelper(t *testing.T) int {\n\tt.Helper()\n\treturn 21\n}\n\nfunc TestInternal(t *testing.T) {\n\tif Compute(mustHelper(t)) != 42 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
		"external_test.go": "package ambroot_test\n\nimport (\n\t\"testing\"\n\n\t\"example.com/ambroot\"\n)\n\nfunc mustHelper(t *testing.T) int {\n\tt.Helper()\n\treturn 5\n}\n\nfunc TestExternal(t *testing.T) {\n\tif ambroot.Compute(mustHelper(t)) != 10 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const pkg = "example.com/ambroot"
	ambiguous := Subject{Package: pkg, Symbol: "mustHelper"}
	sibling := Subject{Package: pkg, Symbol: "Compute"}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := newFixturePrograms(t, h)
	fixtures.supply(t, pkg)
	if _, err := computeTier2Result(h, pkg, ambiguous.Symbol); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous subject analysis error = %v, want an error naming the collision", err)
	}
	fixtures.supply(t, pkg)
	sib, err := computeTier2Result(h, pkg, sibling.Symbol)
	if err != nil {
		t.Fatalf("sibling subject failed because of the collision: %v", err)
	}
	if sib.unverifiable || strings.Contains(sib.reason, "ambiguous") {
		t.Fatalf("sibling subject degraded by the collision: %+v", sib)
	}
	fixtures.supply(t, pkg)
	proofs, err := h.ComputeObservabilityBatch([]Subject{ambiguous, sibling})
	if err != nil {
		t.Fatal(err)
	}
	if p := proofs[ambiguous]; p.Observable || !strings.Contains(p.Reason, "ambiguous") {
		t.Fatalf("ambiguous subject proof = %+v, want a refusal naming the collision", p)
	}
	if p := proofs[sibling]; strings.Contains(p.Reason, "ambiguous") {
		t.Fatalf("sibling proof polluted by the collision: %+v", p)
	}
}

// A production symbol whose package has only an external test variant cannot be
// rooted in the loaded test-binary program. That is a subject-local fact: precise
// analysis errors naming exactly that subject, the observability proof degrades
// to an unavailable-evidence refusal for that subject alone, and a rootable
// sibling of the same package analyzes normally (REQ-closure-analysis's
// missing-root subject-local degradation arm).
func TestMissingRootDegradesSubjectLocally(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/external\n\ngo 1.26\n")
	writeFile(t, dir, "external.go", "package external\n\nfunc Ok() bool { return true }\n")
	writeFile(t, dir, "external_test.go", `package external_test

import (
	"testing"

	"example.com/external"
)

func TestExternal(t *testing.T) {
	if !external.Ok() {
		t.Fatal("not ok")
	}
}
`)
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "example.com/external"
	unrootable := Subject{Package: pkg, Symbol: "Ok"}
	sibling := Subject{Package: pkg, Symbol: "TestExternal"}
	fixtures := newFixturePrograms(t, h)
	fixtures.supply(t, pkg)
	if _, err := computeTier2Result(h, pkg, unrootable.Symbol); err == nil || !strings.Contains(err.Error(), "Ok not found in "+pkg) {
		t.Fatalf("unrootable subject analysis error = %v, want an error naming the subject", err)
	}
	fixtures.supply(t, pkg)
	_, siblingReach, err := computeTier2ResultAndReach(h, pkg, sibling.Symbol)
	if err != nil {
		t.Fatalf("sibling analysis disturbed by the unrootable subject: %v", err)
	}
	if len(siblingReach) == 0 {
		t.Fatal("sibling analysis reached nothing, want normal analysis undisturbed by the unrootable subject")
	}
	fixtures.supply(t, pkg)
	proofs, err := h.ComputeObservabilityBatch([]Subject{unrootable, sibling})
	if err != nil {
		t.Fatalf("missing root failed the whole observability batch: %v", err)
	}
	degraded := proofs[unrootable]
	if degraded.Observable || !strings.Contains(degraded.Reason, "observation analysis unavailable") || !strings.Contains(degraded.Reason, "Ok not found in "+pkg) {
		t.Fatalf("unrootable proof = %+v, want unavailable-evidence attribution", degraded)
	}
	if p := proofs[sibling]; strings.Contains(p.Reason, "unavailable") {
		t.Fatalf("sibling proof degraded by the unrootable subject: %+v", p)
	}
}

func init() {
	extra := map[string]map[string]map[string]string{
		"github.com/greatliontech/gofresh/internal/closure/testdata/ambiguousroot": {
			"github.com/greatliontech/gofresh/internal/closure/testdata/ambiguousroot": {
				"ambiguousroot.go":      "package ambiguousroot\n\nfunc Size() int { return 1 }\n",
				"ambiguousroot_test.go": "package ambiguousroot\n\nimport \"testing\"\n\nfunc TestSize(t *testing.T) {\n\tif Size() != 1 {\n\t\tt.Fatal()\n\t}\n}\n",
				"external_test.go":      "package ambiguousroot_test\n\nimport (\n\t\"testing\"\n\n\t\"github.com/greatliontech/gofresh/internal/closure/testdata/ambiguousroot\"\n)\n\nfunc TestSize(t *testing.T) {\n\tif ambiguousroot.Size() != 1 {\n\t\tt.Fatal()\n\t}\n}\n",
			},
		},
		"github.com/greatliontech/gofresh/internal/closure/testdata/asmcall": {
			"github.com/greatliontech/gofresh/internal/closure/testdata/asmcall": {
				"asm_amd64.s":     "#include \"textflag.h\"\n\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL ·helper(SB)\n\tRET\n",
				"asmcall.go":      "package asmcall\n\nimport \"os\"\n\nfunc asmEntry()\n\nfunc helper() int {\n\t_, _ = os.ReadFile(\"fixture.txt\")\n\treturn 1\n}\n",
				"asmcall_test.go": "package asmcall\n\nimport \"testing\"\n\nfunc BenchmarkASMCall(b *testing.B) {\n\tfor b.Loop() {\n\t\tasmEntry()\n\t}\n}\n",
			},
		},
		"github.com/greatliontech/gofresh/internal/closure/testdata/asminvoke": {
			"github.com/greatliontech/gofresh/internal/closure/testdata/asminvoke": {
				"asm_amd64.s":       "#include \"textflag.h\"\n\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL ·helper(SB)\n\tRET\n",
				"asminvoke.go":      "package asminvoke\n\ntype iface interface {\n\tM() int\n}\n\ntype concrete struct{}\n\nfunc (concrete) M() int { return 1 }\n\nvar sink iface\n\nfunc init() {\n\tsink = concrete{}\n}\n\nfunc asmEntry()\n\nfunc helper() int {\n\treturn sink.M()\n}\n",
				"asminvoke_test.go": "package asminvoke\n\nimport \"testing\"\n\nfunc BenchmarkASMInvoke(b *testing.B) {\n\tfor b.Loop() {\n\t\tasmEntry()\n\t}\n}\n",
			},
		},
		"github.com/greatliontech/gofresh/internal/closure/testdata/externalbench": {
			"github.com/greatliontech/gofresh/internal/closure/testdata/externalbench": {
				"externalbench.go":      "package externalbench\n",
				"externalbench_test.go": "package externalbench_test\n\nimport \"testing\"\n\nfunc BenchmarkExternal(b *testing.B) {\n\tfor b.Loop() {\n\t}\n}\n",
			},
		},
		"github.com/greatliontech/gofresh/internal/closure/testdata/genericpostrta": {
			"github.com/greatliontech/gofresh/internal/closure/testdata/genericpostrta": {
				"asm_amd64.s":            "#include \"textflag.h\"\n\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL ·helper(SB)\n\tRET\n",
				"genericpostrta.go":      "package genericpostrta\n\ntype caller interface {\n\tM() int\n}\n\ntype direct struct{}\n\nfunc (direct) M() int { return 1 }\n\ntype viaASM struct{}\n\nfunc (viaASM) M() int { return 2 }\n\nfunc call[T caller](v T) int {\n\treturn v.M()\n}\n\nfunc asmEntry()\n\nfunc helper() int {\n\treturn call(viaASM{})\n}\n",
				"genericpostrta_test.go": "package genericpostrta\n\nimport \"testing\"\n\nfunc BenchmarkGenericPostRTA(b *testing.B) {\n\tfor b.Loop() {\n\t\t_ = call(direct{})\n\t\tasmEntry()\n\t}\n}\n",
			},
		},
		"github.com/greatliontech/gofresh/internal/closure/testdata/initregistry/bench": {
			"github.com/greatliontech/gofresh/internal/closure/testdata/initregistry/bench": {
				"bench_test.go": "package bench\n\nimport (\n\t\"testing\"\n\n\t_ \"github.com/greatliontech/gofresh/internal/closure/testdata/initregistry/codec\"\n\t\"github.com/greatliontech/gofresh/internal/closure/testdata/initregistry/registry\"\n)\n\nvar data = []byte(\"payload\")\n\nfunc BenchmarkDecode(b *testing.B) {\n\tc := registry.Get(\"gzip\")\n\tfor b.Loop() {\n\t\t_ = c.Decode(data)\n\t}\n}\n",
			},
			"github.com/greatliontech/gofresh/internal/closure/testdata/initregistry/codec": {
				"codec.go": "package codec\n\nimport \"github.com/greatliontech/gofresh/internal/closure/testdata/initregistry/registry\"\n\ntype gz struct{}\n\nfunc (gz) Decode(b []byte) []byte {\n\tout := make([]byte, len(b))\n\tcopy(out, b)\n\treturn out\n}\n\nfunc init() {\n\tregistry.Register(\"gzip\", gz{})\n}\n",
			},
			"github.com/greatliontech/gofresh/internal/closure/testdata/initregistry/registry": {
				"registry.go": "package registry\n\ntype Codec interface {\n\tDecode([]byte) []byte\n}\n\nvar impls = map[string]Codec{}\n\nfunc Register(name string, c Codec) {\n\timpls[name] = c\n}\n\nfunc Get(name string) Codec {\n\treturn impls[name]\n}\n",
			},
		},
		"github.com/greatliontech/gofresh/internal/closure/testdata/initregistry/codec": {
			"github.com/greatliontech/gofresh/internal/closure/testdata/initregistry/codec": {
				"codec.go": "package codec\n\nimport \"github.com/greatliontech/gofresh/internal/closure/testdata/initregistry/registry\"\n\ntype gz struct{}\n\nfunc (gz) Decode(b []byte) []byte {\n\tout := make([]byte, len(b))\n\tcopy(out, b)\n\treturn out\n}\n\nfunc init() {\n\tregistry.Register(\"gzip\", gz{})\n}\n",
			},
			"github.com/greatliontech/gofresh/internal/closure/testdata/initregistry/registry": {
				"registry.go": "package registry\n\ntype Codec interface {\n\tDecode([]byte) []byte\n}\n\nvar impls = map[string]Codec{}\n\nfunc Register(name string, c Codec) {\n\timpls[name] = c\n}\n\nfunc Get(name string) Codec {\n\treturn impls[name]\n}\n",
			},
		},
		"github.com/greatliontech/gofresh/internal/closure/testdata/linknamelocal/bench": {
			"github.com/greatliontech/gofresh/internal/closure/testdata/linknamelocal/bench": {
				"bench_test.go": "package bench\n\nimport (\n\t\"testing\"\n\n\t_ \"github.com/greatliontech/gofresh/internal/closure/testdata/linknamelocal/target\"\n\t_ \"unsafe\"\n)\n\n//go:linkname hidden github.com/greatliontech/gofresh/internal/closure/testdata/linknamelocal/target.Hidden\nfunc hidden() int\n\nfunc BenchmarkLinknameLocal(b *testing.B) {\n\tfor b.Loop() {\n\t\t_ = hidden()\n\t}\n}\n",
			},
			"github.com/greatliontech/gofresh/internal/closure/testdata/linknamelocal/target": {
				"target.go": "package target\n\nconst LocalOnly = 5\n\nfunc Hidden() int {\n\treturn LocalOnly\n}\n",
			},
		},
		"github.com/greatliontech/gofresh/internal/closure/testdata/methodsubject": {
			"github.com/greatliontech/gofresh/internal/closure/testdata/methodsubject": {
				"methodsubject.go": "package methodsubject\n\ntype Adder struct{ base int }\n\nfunc (a Adder) Value() int { return a.base + valueHelper() }\n\nfunc (a *Adder) Ptr() int { return a.base + ptrHelper() }\n\nfunc valueHelper() int { return 1 }\n\nfunc ptrHelper() int { return 2 }\n",
			},
		},
		"github.com/greatliontech/gofresh/internal/closure/testdata/opaqueasm": {
			"github.com/greatliontech/gofresh/internal/closure/testdata/opaqueasm": {
				"asm_amd64.s":       "#include \"textflag.h\"\n\n#ifdef WANT\n#define NOOP MOVQ AX, AX\n#endif\n\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tRET\n",
				"defs.inc":          "opaque assembly input\n",
				"opaqueasm.go":      "package opaqueasm\n\nfunc asmEntry()\n",
				"opaqueasm_test.go": "package opaqueasm\n\nimport \"testing\"\n\nfunc BenchmarkOpaqueASM(b *testing.B) {\n\tfor b.Loop() {\n\t\tasmEntry()\n\t}\n}\n",
			},
		},
		"github.com/greatliontech/gofresh/internal/closure/testdata/rootcollision/bench": {
			"github.com/greatliontech/gofresh/internal/closure/testdata/rootcollision/bench": {
				"bench_test.go": "package bench\n\nimport (\n\t\"testing\"\n\n\t\"github.com/greatliontech/gofresh/internal/closure/testdata/rootcollision/dep\"\n)\n\nconst RealOnly = 2\n\nfunc BenchmarkSame(b *testing.B) {\n\tdep.Use()\n\tfor b.Loop() {\n\t\t_ = RealOnly\n\t}\n}\n",
			},
			"github.com/greatliontech/gofresh/internal/closure/testdata/rootcollision/dep": {
				"dep.go": "package dep\n\nimport \"testing\"\n\nconst DepOnly = 1\n\nfunc Use() {}\n\nfunc BenchmarkSame(b *testing.B) {\n\tfor b.Loop() {\n\t\t_ = DepOnly\n\t}\n}\n",
			},
		},
		"github.com/greatliontech/gofresh/internal/closure/testdata/rootcollision/dep": {
			"github.com/greatliontech/gofresh/internal/closure/testdata/rootcollision/dep": {
				"dep.go": "package dep\n\nimport \"testing\"\n\nconst DepOnly = 1\n\nfunc Use() {}\n\nfunc BenchmarkSame(b *testing.B) {\n\tfor b.Loop() {\n\t\t_ = DepOnly\n\t}\n}\n",
			},
		},
	}
	for k, v := range extra {
		inMemoryFixtureRegistry[k] = v
	}
	if entries, err := os.ReadDir("testdata"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			pkgPath := "github.com/greatliontech/gofresh/internal/closure/testdata/" + e.Name()
			if _, exists := inMemoryFixtureRegistry[pkgPath]; exists {
				continue
			}
			subEntries, rerr := os.ReadDir(filepath.Join("testdata", e.Name()))
			if rerr != nil {
				continue
			}
			files := map[string]string{}
			hasGo := false
			for _, se := range subEntries {
				if se.IsDir() {
					continue
				}
				if b, ferr := os.ReadFile(filepath.Join("testdata", e.Name(), se.Name())); ferr == nil {
					files[se.Name()] = string(b)
					if strings.HasSuffix(se.Name(), ".go") {
						hasGo = true
					}
				}
			}
			if hasGo {
				inMemoryFixtureRegistry[pkgPath] = map[string]map[string]string{pkgPath: files}
			}
		}
	}
}

// crypto/rand's operations are the entropy class — an external system
// call named as such in the one classification table both tiers
// consult, never the unaudited fallback; the exported Reader refuses as
// an unaudited selector at the file fold; the unseeded math/rand sources
// keep the unaudited fallback at both tiers until their own audit, the
// fold binding math/rand/v2's declared name as a secondary beside its
// last element, never shadowing a primary; and two imports binding one
// identifier — what the language forbids — refuse the file fail-closed
// (REQ-closure-observability-entropy).
func TestCryptoRandIsTheEntropyClass(t *testing.T) {
	for _, name := range []string{"Read", "Text", "Int", "Prime"} {
		effect, ok := classBEffect("crypto/rand", name)
		if !ok || effect.kind != externalEffectNative || !strings.HasPrefix(effect.reason, "reaches crypto/rand."+name+" (entropy)") || effect.observable {
			t.Errorf("crypto/rand.%s = %+v ok=%v, want the entropy class", name, effect, ok)
		}
		if classBPureStandard(true, "crypto/rand", name) {
			t.Errorf("crypto/rand.%s admitted as pure", name)
		}
	}
	if _, ok := classBEffect("crypto/rand", "Reader"); ok {
		t.Error("crypto/rand.Reader classified as an operation — it is a selector the file fold refuses on its own")
	}
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/entropy\n\ngo 1.26\n")
	cases := []struct{ pkg, source, refusal string }{
		{"read", "package read\n\nimport \"crypto/rand\"\n\nfunc Subject() int {\n\tb := make([]byte, 4)\n\tn, _ := rand.Read(b)\n\treturn n\n}\n", "package scan: reaches crypto/rand.Read (entropy)"},
		{"text", "package text\n\nimport \"crypto/rand\"\n\nfunc Subject() string { return rand.Text() }\n", "package scan: reaches crypto/rand.Text (entropy)"},
		// Int reads the reader it is given — fail-closed on an unproven operand, in the same class.
		{"intop", "package intop\n\nimport (\n\t\"bytes\"\n\t\"crypto/rand\"\n\t\"math/big\"\n)\n\nfunc Subject() int64 {\n\tn, _ := rand.Int(bytes.NewReader([]byte{1, 2, 3, 4}), big.NewInt(10))\n\treturn n.Int64()\n}\n", "package scan: reaches crypto/rand.Int (entropy)"},
		{"prime", "package prime\n\nimport (\n\t\"bytes\"\n\t\"crypto/rand\"\n)\n\nfunc Subject() int {\n\tp, _ := rand.Prime(bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8}), 8)\n\treturn p.BitLen()\n}\n", "package scan: reaches crypto/rand.Prime (entropy)"},
		{"reader", "package reader\n\nimport (\n\t\"crypto/rand\"\n\t\"io\"\n)\n\nfunc Subject() int {\n\tb := make([]byte, 4)\n\tn, _ := io.ReadFull(rand.Reader, b)\n\treturn n\n}\n", "package scan: reaches unaudited standard operation crypto/rand.Reader"},
		// The unseeded math/rand sources keep the fallback at both tiers: the fold binds the unnamed v2 import to rand, so a reached sibling declaration refuses at the fold as v1's does, while an unreached sibling does not block the closed-world subject.
		{"mathrand", "package mathrand\n\nimport \"math/rand/v2\"\n\nfunc Subject() int { return rand.IntN(3) }\n", "package scan: reaches unaudited standard operation math/rand/v2.IntN"},
		{"mathrandsibling", "package mathrandsibling\n\nimport \"math/rand/v2\"\n\nfunc Subject() int { return Other() }\n\nfunc Other() int { return rand.IntN(3) }\n", "package scan: reaches unaudited standard operation math/rand/v2.IntN"},
		{"mathrandsiblingunreached", "package mathrandsiblingunreached\n\nimport \"math/rand/v2\"\n\nfunc Subject() int { return 3 }\n\nfunc Other() int { return rand.IntN(3) }\n", ""},
		{"mathrandv1", "package mathrandv1\n\nimport \"math/rand\"\n\nfunc Subject() int { return Other() }\n\nfunc Other() int { return rand.Int() }\n", "package scan: reaches unaudited standard operation math/rand.Int"},
		// A guessed secondary name never shadows a primary: net stays the standard package beside an API-version directory whose last element is v1, so a reached sibling's net.Dial keeps its classification.
		{"collide", "package collide\n\nimport (\n\t\"net\"\n\n\t\"example.com/entropy/collide/net/v1\"\n)\n\nfunc Subject() int {\n\tOther()\n\treturn v1.N()\n}\n\nfunc Other() {\n\tc, _ := net.Dial(\"tcp\", \"x\")\n\t_ = c\n}\n", "package scan: reaches net.Dial (network I/O)"},
		// Two modules at the same major version bind alpha and beta as the compiler does; their version-element primaries clash on v2 but neither is a name source spells, so nothing records and the pure file proves observable.
		{"twomods", "package twomods\n\nimport (\n\t\"example.com/entropy/twomods/alpha/v2\"\n\t\"example.com/entropy/twomods/beta/v2\"\n)\n\nfunc Subject() int { return alpha.N() + beta.N() }\n", ""},
		// An explicit alias is ground truth: a derived version-element primary never displaces it, so the reached sibling's dial through the alias keeps its classification in either import order.
		{"aliasver", "package aliasver\n\nimport (\n\tv2 \"net\"\n\n\t\"example.com/entropy/aliasver/mod/v2\"\n)\n\nfunc Subject() int {\n\tOther()\n\treturn mod.N()\n}\n\nfunc Other() {\n\tc, _ := v2.Dial(\"tcp\", \"x\")\n\t_ = c\n}\n", "package scan: reaches net.Dial (network I/O)"},
		{"aliasverlate", "package aliasverlate\n\nimport (\n\t\"example.com/entropy/aliasverlate/mod/v2\"\n\n\tv2 \"net\"\n)\n\nfunc Subject() int {\n\tOther()\n\treturn mod.N()\n}\n\nfunc Other() {\n\tc, _ := v2.Dial(\"tcp\", \"x\")\n\t_ = c\n}\n", "package scan: reaches net.Dial (network I/O)"},
		// Two API versions of one group bind v1 and v2 as the compiler does; the secondary they would share binds nothing, and the pure file proves observable.
		{"apiver", "package apiver\n\nimport (\n\t\"example.com/entropy/apiver/core/v1\"\n\t\"example.com/entropy/apiver/core/v2\"\n)\n\nfunc Subject() int { return v1.N() + v2.N() }\n", ""},
	}
	subjects := make([]Subject, 0, len(cases))
	for _, tc := range cases {
		if err := os.MkdirAll(filepath.Join(dir, tc.pkg), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, tc.pkg+"/"+tc.pkg+".go", tc.source)
		subjects = append(subjects, Subject{Package: "example.com/entropy/" + tc.pkg, Symbol: "Subject"})
	}
	if err := os.MkdirAll(filepath.Join(dir, "collide", "net", "v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "collide/net/v1/v1.go", "package v1\n\nfunc N() int { return 1 }\n")
	for _, sub := range []string{"apiver/core/v1", "apiver/core/v2"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, sub+"/"+path.Base(sub)+".go", "package "+path.Base(sub)+"\n\nfunc N() int { return 1 }\n")
	}
	for _, mod := range []string{"alpha", "beta"} {
		if err := os.MkdirAll(filepath.Join(dir, "twomods", mod, "v2"), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, "twomods/"+mod+"/v2/"+mod+".go", "package "+mod+"\n\nfunc N() int { return 1 }\n")
	}
	for _, pkg := range []string{"aliasver", "aliasverlate"} {
		if err := os.MkdirAll(filepath.Join(dir, pkg, "mod", "v2"), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, pkg+"/mod/v2/mod.go", "package mod\n\nfunc N() int { return 1 }\n")
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		proof := proofs[Subject{Package: "example.com/entropy/" + tc.pkg, Symbol: "Subject"}]
		if tc.refusal == "" {
			if !proof.Observable || proof.Reason != "" {
				t.Errorf("%s = %+v, want observable", tc.pkg, proof)
			}
			continue
		}
		if proof.Observable || !strings.HasPrefix(proof.Reason, tc.refusal) {
			t.Errorf("%s = %+v, want refused with %q", tc.pkg, proof, tc.refusal)
		}
		if strings.Contains(tc.refusal, "(entropy)") && !strings.HasSuffix(proof.Reason, " (dischargeable by restructuring the subject away from the reach, or by "+PurityResponsibility+")") {
			t.Errorf("%s = %q, want the entropy refusal to carry the ambient discharge channel", tc.pkg, proof.Reason)
		}
	}
}

// auditset.ClassBPackages matches classBTable's keys so the classifier
// and the maximal tier's dot-import backstop (packageHasClassifiedExternalAPI)
// stay aligned by test (REQ-closure-observability-audited-set).
func TestClassBPackagesMatchTheArms(t *testing.T) {
	samples := map[string]string{
		"fmt": "Println", "os": "Getenv", "syscall": "Mkdir", "golang.org/x/sys/unix": "Mkdir", "testing": "Short",
		"net": "Dial", "net/http": "Get", "html/template": "ParseFiles", "text/template": "ParseFiles", "plugin": "Open",
		"crypto/rand": "Read",
	}
	for _, pkgPath := range auditset.ClassBPackages() {
		name, ok := samples[pkgPath]
		if !ok {
			t.Errorf("%s is listed but this test carries no sample name for it — add one", pkgPath)
			continue
		}
		if _, classified := classBEffect(pkgPath, name); !classified {
			t.Errorf("%s is listed but %s.%s does not classify", pkgPath, pkgPath, name)
		}
		if !packageHasClassifiedExternalAPI(pkgPath) {
			t.Errorf("%s classifies but the dot-import backstop does not list it", pkgPath)
		}
	}
	for pkgPath := range classBTable {
		if !auditset.ClassBPackage(pkgPath) {
			t.Errorf("%s is in classBTable but not in auditset.ClassBPackages", pkgPath)
		}
	}
	for pkgPath := range samples {
		if !auditset.ClassBPackage(pkgPath) {
			t.Errorf("%s carries a sample but is not listed", pkgPath)
		}
	}
	for _, pkgPath := range []string{"math/rand", "math/rand/v2", "strings", "encoding/json/v2"} {
		if packageHasClassifiedExternalAPI(pkgPath) {
			t.Errorf("%s listed as classified", pkgPath)
		}
	}
}

// An unnamed import binds the identifier the toolchain's package
// clause declares for a major-versioned path: the last element past
// the version (REQ-closure-observability-declaration-bindings).
func TestImplicitImportNameSkipsMajorVersionElements(t *testing.T) {
	for pkgPath, want := range map[string]string{
		"math/rand/v2": "rand", "math/rand": "rand", "encoding/json/v2": "json", "fmt": "fmt",
		"example.com/mod/v3": "mod", "example.com/v": "v", "example.com/v2x": "v2x", "v2": "v2",
	} {
		if got := implicitImportName(pkgPath); got != want {
			t.Errorf("implicitImportName(%q) = %q, want %q", pkgPath, got, want)
		}
	}
}

func TestContributionCgoOutsideIncludeRootFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	outside := filepath.Join(root, "cfg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, outside, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CgoCFLAGS:  []string{"-I${SRCDIR}/../cfg"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include root outside package dir") {
		t.Fatalf("contribution error = %v, want cgo include root outside package dir", err)
	}
}

func TestContributionCgoRelativeIncludeEscapeFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"../cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

// TestContributionCgoSystemIncludeSkipped: a system/toolchain header not found in
// the package's in-tree search space is build environment (REQ-closure-coverage) — covered by the
// toolchain and machine guards within the single-machine scope — so it is skipped
// rather than failing closed, both for quoted (`"stdio.h"`) and angle-bracket
// (`<stdio.h>`, `<sys/types.h>`) forms. The package's own C source is still hashed.
func TestContributionCgoSystemIncludeSkipped(t *testing.T) {
	for _, inc := range []string{`"stdio.h"`, `<stdio.h>`, `<sys/types.h>`} {
		t.Run(inc, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
			writeFile(t, dir, "bridge.c", "#include "+inc+"\nvoid bridge(void) { GoCallback(); }\n")
			h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
			pkg := listPkg{
				ImportPath: "example/cgocallback",
				Dir:        dir,
				CgoFiles:   []string{"cg.go"},
				CFiles:     []string{"bridge.c"},
				Module:     &listMod{Main: true, Dir: dir},
			}
			got, err := h.contribution(pkg)
			if err != nil {
				t.Fatalf("contribution: %v, want system include skipped", err)
			}
			if got == "" {
				t.Fatal("contribution empty; want package source hashed")
			}
			// The package's own C source must still be hashed: editing bridge.c moves it.
			writeFile(t, dir, "bridge.c", "#include "+inc+"\nvoid bridge(void) { GoCallback(); GoCallback(); }\n")
			again, err := h.contribution(pkg)
			if err != nil {
				t.Fatalf("contribution after edit: %v", err)
			}
			if got == again {
				t.Fatal("editing in-tree cgo source did not move the contribution")
			}
		})
	}
}

// TestContributionCgoNonPackageIncludeRootFailsClosed: a `-I` root outside the
// package and outside the module cache holds mutable first-party C source the analysis cannot
// prove is version-pinned — a local `replace => ../sibling` header, a `go.work`
// sibling, or an unidentifiable system dir. Editing such a header changes the
// benchmark, so the root must fail closed rather than be skipped (the analysis cannot
// distinguish it from a genuine system root; system headers reached by the
// compiler's default search fail-closed-free via the not-found path). Regression for
// the local-replace false-valid: without it, `#include "api.h"` via the outside-
// module `-I` root would be skipped and an api.h edit would report valid.
func TestContributionCgoNonPackageIncludeRootFailsClosed(t *testing.T) {
	parent := t.TempDir()
	mod := filepath.Join(parent, "mod")
	dir := filepath.Join(mod, "pkg")
	shared := filepath.Join(parent, "shared", "include") // local-replace sibling, outside mod, not under cache
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"api.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, shared, "api.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.Join(parent, "gomodcache")}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CgoCFLAGS:  []string{"-I" + shared},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: mod},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include root outside package dir") {
		t.Fatalf("contribution error = %v, want cgo include root outside package dir", err)
	}
}

// TestContributionCgoCacheIncludeRootAllowed: a `-I` root under GOMODCACHE is a
// version-pinned dependency (REQ-closure-mutable-local) whose C headers ride the cache guard, so it is
// allowed rather than failing closed.
func TestContributionCgoCacheIncludeRootAllowed(t *testing.T) {
	cache := t.TempDir()
	dir := t.TempDir()
	dep := filepath.Join(cache, "dep@v1.0.0", "include")
	if err := os.MkdirAll(dep, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include <dep.h>\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, dep, "dep.h", "#define N 1\n")
	h := &Hasher{modCache: cache}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CgoCFLAGS:  []string{"-I" + dep},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: dir},
	}
	if _, err := h.contribution(pkg); err != nil {
		t.Fatalf("contribution: %v, want cache -I root allowed", err)
	}
}

func TestContributionCgoNestedIncIncludeFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"local.inc\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, dir, "local.inc", "#include \"../cfg.h\"\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoNestedSoHeaderIncludeFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"local.so.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, dir, "local.so.h", "#include \"../cfg.h\"\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoNestedVersionedSoIncludeFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"local.so.1\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, dir, "local.so.1", "#include \"../cfg.h\"\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoSplicedIncludeFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#\\\ninclude \"../cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoGoPreambleSplicedIncludeFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\n// #\\\n// include \"../cfg.h\"\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "void bridge(void) { GoCallback(); }\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoImportFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.m", "#import \"../cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		MFiles:     []string{"bridge.m"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoSymlinkIncludeDirFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	outside := filepath.Join(root, "cfg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"include/cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, outside, "cfg.h", "#define N 1\n")
	if err := os.Symlink(outside, filepath.Join(dir, "include")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoSymlinkIncludeDirDotDotFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(outside, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"include/../cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, outside, "cfg.h", "#define N 1\n")
	if err := os.Symlink(filepath.Join(outside, "sub"), filepath.Join(dir, "include")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoIncludeRootSymlinkDotDotFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(outside, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, outside, "cfg.h", "#define N 1\n")
	if err := os.Symlink(filepath.Join(outside, "sub"), filepath.Join(dir, "include")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CgoCFLAGS:  []string{"-I${SRCDIR}/include/.."},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include root outside package dir") {
		t.Fatalf("contribution error = %v, want cgo include root outside package dir", err)
	}
}

func TestContributionCgoMacroIncludeFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#define CFG \"../cfg.h\"\n#include CFG\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "unresolved cgo include") {
		t.Fatalf("contribution error = %v, want unresolved cgo include", err)
	}
}

func TestContributionCgoCommentedIncludeDirectiveFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#/**/include \"../cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoMultilineCommentedIncludeFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"local.inc\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, dir, "local.inc", "/*\n*/ #include \"../cfg.h\"\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoCharConstantDoesNotHideInclude(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "int x = '/*';\n#include \"../cfg.h\"\nint y = '*/';\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoRawStringFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.cc", "const char *x = R\"raw(\"/*)raw\";\n#include \"../cfg.h\"\nconst char *y = R\"raw(*/)raw\";\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CXXFiles:   []string{"bridge.cc"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "unsupported cgo raw string") {
		t.Fatalf("contribution error = %v, want unsupported cgo raw string", err)
	}
}

func TestContributionCgoHeaderRawStringFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.cc", "#include \"local.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, dir, "local.h", "const char *x = R\"raw(\"/*)raw\";\n#include \"../cfg.h\"\nconst char *y = R\"raw(*/)raw\";\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CXXFiles:   []string{"bridge.cc"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "unsupported cgo raw string") {
		t.Fatalf("contribution error = %v, want unsupported cgo raw string", err)
	}
}

func TestContributionCgoOrdinaryStringEndingInRAllowed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "cg.go", "package cgotest\n/*\n// C comment inside block preamble mentioning R\"(x)\" and \"OR\"\n#define PREAMBLE_BLOCK_R \"R\"\n*/\n// /* preamble comment mentioning \"OR\" and R\" */\n// #define PREAMBLE_R \"R\"\nimport \"C\"\n\nconst goRaw = `R\"raw(/*)raw\"`\n")
	writeFile(t, dir, "local.h", "#define HDR_R \"META_ECLASS_XOR\"\n")
	writeFile(t, dir, "bridge.c", `
#include "local.h"
/* Comment mentioning "OR" and R" inside a block comment */
// Line comment mentioning "ERR" and R"raw(x)raw"
#define STR_R "R"
void bridge(void) {
	const char *a = "META_DOLLAR";
	const char *b = "\\R";
	const char *escaped = "quoted \"R\" inside string";
	char ch = 'R';
	(void)a;
	(void)b;
	(void)escaped;
	(void)ch;
}
`)
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgotest",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		HFiles:     []string{"local.h"},
		Module:     &listMod{Main: true, Dir: dir},
	}
	if _, err := h.contribution(pkg); err != nil {
		t.Fatalf("contribution error = %v, want nil for ordinary C strings and comments", err)
	}
}

func TestContributionCgoLineCommentBlockStartDoesNotHideInclude(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "// line comment with /* block opener\n#include \"../cfg.h\"\n// closing */ marker\nvoid bridge(void) {}\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoDigitSeparatorDoesNotHideInclude(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.cc", "int n = 1'000; const char *s = \"'/*\";\n#include \"../cfg.h\"\nconst char *t = \"*/\";\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CXXFiles:   []string{"bridge.cc"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
		t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
	}
}

func TestContributionCgoGoPackageCommentDoesNotHidePreambleInclude(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
	}{
		{
			name: "package_comment_before_single_import",
			src:  "// /* package doc comment with unclosed block marker\npackage cgocallback\n\n// #include \"../cfg.h\"\nimport \"C\"\n",
		},
		{
			name: "import_group_doc_before_c_spec_doc",
			src:  "package cgocallback\n\n// /* import group doc with unclosed block marker\nimport (\n\t\"fmt\"\n\n\t// #include \"../cfg.h\"\n\t\"C\"\n)\nvar _ = fmt.Sprintf\n",
		},
		{
			name: "adjacent_block_comments_in_preamble",
			src:  "package cgocallback\n\n/*#include */ /*\"../cfg.h\"*/\nimport \"C\"\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "pkg")
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, dir, "cg.go", tc.src)
			writeFile(t, root, "cfg.h", "#define N 1\n")
			h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
			pkg := listPkg{
				ImportPath: "example/cgocallback",
				Dir:        dir,
				CgoFiles:   []string{"cg.go"},
				Module:     &listMod{Main: true, Dir: root},
			}
			if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "cgo include escapes package dir") {
				t.Fatalf("contribution error = %v, want cgo include escapes package dir", err)
			}
		})
	}
}

func TestContributionCgoIncludeGoFileFailsClosed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "helper.go", "//go:build ignore\n\npackage cgocallback;\n#include \"../cfg.h\"\n")
	writeFile(t, dir, "bridge.c", "#define package typedef int\n#include \"helper.go\"\nvoid bridge(void) {}\n")
	writeFile(t, root, "cfg.h", "#define N 1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "unsupported cgo include source") {
		t.Fatalf("contribution error = %v, want unsupported cgo include source", err)
	}
}

func TestContributionCgoObjectFileNotScannedAsIncludeSource(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"_cgo_export.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, dir, "blob.obj", "#include <not-source.h>\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: dir},
	}
	if _, err := h.contribution(pkg); err != nil {
		t.Fatalf("contribution: %v", err)
	}
}

func TestContributionCgoReferencedObjectIncludeFailsClosed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"local.o\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, dir, "local.o", "#include \"../cfg.h\"\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: dir},
	}
	if _, err := h.contribution(pkg); err == nil || !strings.Contains(err.Error(), "unsupported cgo include source") {
		t.Fatalf("contribution error = %v, want unsupported cgo include source", err)
	}
}

func TestContributionCgoSymlinkHeaderHashesTarget(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	outside := filepath.Join(root, "cfg")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "include"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "cg.go", "package cgocallback\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", "#include \"include/cfg.h\"\nvoid bridge(void) { GoCallback(); }\n")
	writeFile(t, outside, "cfg.h", "#define N 1\n")
	if err := os.Symlink(filepath.Join(outside, "cfg.h"), filepath.Join(dir, "include", "cfg.h")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgocallback",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: root},
	}
	one, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution: %v", err)
	}
	writeFile(t, outside, "cfg.h", "#define N 2\n")
	two, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution after symlink target edit: %v", err)
	}
	if one == two {
		t.Fatalf("symlinked cgo header edit did not change contribution: %q", one)
	}
}

// TestAnalysisRootsAnySubject pins the generalized root seam: the analysis
// resolves any top-level function as a subject — a production function, not only
// a Benchmark* — through both the test-variant package (a package that also has
// tests) and the plain-package fallback (a package with no test files), and
// errors clearly on a name that resolves to no function. Before generalization
// the root index held only Benchmark*/TestMain, so a production symbol was
// reported "not found".
func TestAnalysisRootsAnySubject(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// (a) A production function in a package that also has tests: resolved via the
	// test-variant package, which compiles the package WITH its test files and so
	// holds production and test symbols alike.
	const withTests = "github.com/greatliontech/gofresh/internal/closure/testdata/harnessroot"
	const noTests = "github.com/greatliontech/gofresh/internal/closure/testdata/rootcollision/dep"
	supplyRegisteredFixtures(t, h, withTests, noTests)
	a, aReach, err := computeTier2ResultAndReach(h, withTests, "Prod")
	if err != nil {
		t.Fatalf("analysis of production func Coordinate: %v", err)
	}
	if len(aReach) == 0 {
		t.Fatal("empty reachability for a resolvable production subject")
	}
	if again, err := computeTier2Result(h, withTests, "Prod"); err != nil || !reflect.DeepEqual(again, a) {
		t.Errorf("nondeterministic: %+v vs %+v (err %v)", again, a, err)
	}
	// The projection's total order is what makes the equality above — and
	// the proof diagnostic — deterministic across recomputations.
	if !sort.SliceIsSorted(a.effects, func(i, j int) bool { return effectLess(a.effects[i], a.effects[j]) }) {
		t.Errorf("effect projection is not sorted: %+v", a.effects)
	}

	// (b) A function in a package with NO test files: resolved via the plain-package
	// fallback (no ForTest variant exists).
	_, bReach, err := computeTier2ResultAndReach(h, noTests, "BenchmarkSame")
	if err != nil {
		t.Fatalf("analysis of func in a no-test package: %v", err)
	}
	if len(bReach) == 0 {
		t.Fatal("empty reachability via the plain-package fallback")
	}

	// A name that resolves to no function is a clear error, not a silent empty root.
	if _, err := computeTier2Result(h, withTests, "NoSuchFunction"); err == nil {
		t.Error("a name resolving to no function: want error, got nil")
	}
}

// TestMethodSubjectsRootAtSpecificMethod pins method-subject resolution: a
// method is named "Type.Method" (matching the consumer symbol grammar with the
// package prefix stripped), resolves through both value- and pointer-receiver
// method sets, roots at that specific method, and errors on a missing method name.
func TestMethodSubjectsRootAtSpecificMethod(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/methodsubject"

	fixtures := newFixturePrograms(t, h)
	fixtures.supply(t, pkg)
	_, valReach, err := computeTier2ResultAndReach(h, pkg, "Adder.Value") // value receiver
	if err != nil {
		t.Fatalf("analysis of value-receiver method Adder.Value: %v", err)
	}
	if len(valReach) == 0 {
		t.Fatal("empty reachability for a method subject")
	}
	fixtures.supply(t, pkg)
	_, ptrReach, err := computeTier2ResultAndReach(h, pkg, "Adder.Ptr") // pointer receiver
	if err != nil {
		t.Fatalf("analysis of pointer-receiver method Adder.Ptr: %v", err)
	}
	// The two methods reach distinct helpers, so rooting at the specific method (not
	// the whole type or package) yields distinct reachable sets.
	if maps.Equal(ptrReach, valReach) {
		t.Error("Adder.Value and Adder.Ptr reach identically; not rooting at the specific method")
	}
	fixtures.supply(t, pkg)
	if _, err := computeTier2Result(h, pkg, "Adder.Missing"); err == nil {
		t.Error("a missing method name: want error, got nil")
	}
}

// TestGenericMethodSubjectsRootPerMethod pins that method subjects on a generic
// receiver type resolve — the pointer star and generics are dropped from the type
// name (Box[T] → "Box"), and each method roots at its own closure. SSA
// materializes the receiver, so no deferral is needed.
func TestGenericMethodSubjectsRootPerMethod(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/genericmethod"
	fixtures := newFixturePrograms(t, h)
	fixtures.supply(t, pkg)
	_, getReach, err := computeTier2ResultAndReach(h, pkg, "Box.Get") // value receiver on Box[T]
	if err != nil {
		t.Fatalf("analysis of Box.Get: %v", err)
	}
	fixtures.supply(t, pkg)
	_, setReach, err := computeTier2ResultAndReach(h, pkg, "Box.Set") // pointer receiver on Box[T]
	if err != nil {
		t.Fatalf("analysis of Box.Set: %v", err)
	}
	if len(getReach) == 0 || len(setReach) == 0 {
		t.Fatal("empty reachability for a generic-receiver method")
	}
	if maps.Equal(getReach, setReach) {
		t.Error("Box.Get and Box.Set reach identically; not rooting at the specific method")
	}
}

// TestTestMainRootedOnlyForTestSubjects pins the harness-root design call
// (REQ-closure-analysis): the test main is a root of a subject's closure only when
// the subject runs through the test harness. A benchmark runs after TestMain setup,
// so file I/O that setup reaches makes the benchmark's closure unverifiable; a
// production function never executes through TestMain, so the same setup is not in
// its closure and it stays verifiable. Rooting the test main unconditionally (the
// prior behavior) would wrongly mark the production subject unverifiable.
func TestTestMainRootedOnlyForTestSubjects(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/harnessroot"

	fixtures := newFixturePrograms(t, h)
	fixtures.supply(t, pkg)
	bench, err := computeTier2Result(h, pkg, "BenchmarkProd")
	if err != nil {
		t.Fatalf("analysis of BenchmarkProd: %v", err)
	}
	if !bench.unverifiable {
		t.Error("test subject: want unverifiable (its closure reaches TestMain's file I/O), got verifiable")
	}

	fixtures.supply(t, pkg)
	prod, err := computeTier2Result(h, pkg, "Prod")
	if err != nil {
		t.Fatalf("analysis of Prod: %v", err)
	}
	if prod.unverifiable {
		t.Errorf("production subject: want verifiable (TestMain not in its closure), got unverifiable: %s", prod.reason)
	}
}

// TestClosureIncludesInitRegisteredSideEffectPackage pins REQ-fresh-sound for
// registry patterns: a side-effect import's init can register an implementation
// that the benchmark later observes through package-level state and interface
// dispatch. The analysis roots linked startup code so the registering package
// source is hashed even though the benchmark never names it directly.
func TestClosureIncludesInitRegisteredSideEffectPackage(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const benchPkg = "github.com/greatliontech/gofresh/internal/closure/testdata/initregistry/bench"
	const codecPkg = "github.com/greatliontech/gofresh/internal/closure/testdata/initregistry/codec"

	_, reach, err := computeTier2ResultAndReach(h, benchPkg, "BenchmarkDecode")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	// The benchmark dispatches gz.Decode through registry state and an
	// interface without naming codec, so gz.Decode is analyzed only
	// because all package inits are RTA roots; losing that root would
	// leave the registered method's effects invisible
	// (REQ-closure-coverage reference/side-effect closure). The bodies'
	// bytes ride the maximal hash.
	if !reachContains(reach, codecPkg, "Decode") {
		t.Fatalf("init-registered method gz.Decode missing from the subject's reach: %v", reach)
	}
}

func TestReachIncludesTestMainRoot(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/testmainroot"
	_, reach, err := computeTier2ResultAndReach(h, pkg, "BenchmarkTestMainRoot")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !reachContains(reach, "TestMain") || !reachContains(reach, "setup") {
		t.Fatalf("TestMain/setup missing from the subject's reach: %v", reach)
	}
}

func TestAnalysisReachStaysSubjectPrecise(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/direct"
	tr, reach, err := computeTier2ResultAndReach(h, pkg, "BenchmarkDirect")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if tr.widen {
		t.Fatalf("direct fixture widened: %+v", tr)
	}
	if !reachContains(reach, "used") {
		t.Fatalf("subject-reached function missing from the reach: %v", reach)
	}
	if reachContains(reach, "unused") {
		t.Fatalf("subject-unreached function leaked into the reach: %v", reach)
	}
}

func TestBuildIndexTrustsGoListStandardForDotlessModule(t *testing.T) {
	typesPkg := types.NewPackage("myapp", "myapp")
	ssaProg := ssa.NewProgram(token.NewFileSet(), ssa.InstantiateGenerics)
	a := &tier2Analyzer{
		h:          &Hasher{},
		prog:       &program{Prog: ssaProg},
		metaByPath: map[string]*listPkg{"myapp": &listPkg{ImportPath: "myapp", Standard: false, Module: &listMod{Main: true}}},
	}
	idx := a.buildIndex(&packages.Package{ID: "myapp", PkgPath: "myapp", Types: typesPkg})
	if idx == nil {
		t.Fatal("buildIndex returned nil")
	}
	if idx.std {
		t.Fatalf("dotless package with go-list Standard=false classified std")
	}
}

func TestExternalTestBenchmarkRoots(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/externalbench"
	_, reach, err := computeTier2ResultAndReach(h, pkg, "BenchmarkExternal")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !reachContains(reach, "BenchmarkExternal") {
		t.Fatalf("external test benchmark root missing from the subject's reach: %v", reach)
	}
}

// TestNonToolchainAssemblyReachedPackagesWiden pins the conservative analyzer
// contract (REQ-closure-blindspot): a reached non-toolchain assembly-bearing
// package — mutable-local or cache — is never scanned. It widens the subject
// naming the package and records the "reaches non-standard assembly" effect
// that makes the subject unverifiable and blocks its observability proof.
func TestNonToolchainAssemblyReachedPackagesWiden(t *testing.T) {
	requireConservative := func(t *testing.T, a *tier2Analyzer, pkgID string) {
		t.Helper()
		if !a.widen || a.widenReason != "non-toolchain assembly in "+pkgID {
			t.Fatalf("widen = %v/%q, want non-toolchain assembly in %s", a.widen, a.widenReason, pkgID)
		}
		if !a.unverifiable {
			t.Fatal("non-toolchain assembly did not make the subject unverifiable")
		}
		found := false
		for _, effect := range a.effects {
			if effect.kind == externalEffectNative && effect.reason == opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly").reason {
				found = true
			}
		}
		if !found {
			t.Fatalf("effects = %+v, want native \"reaches non-standard assembly\"", a.effects)
		}
	}

	t.Run("mutable", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "defs.inc", "#define RETVAL $1\n")
		writeFile(t, dir, "asm.s", "#include \"defs.inc\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tMOVQ RETVAL, AX\n\tRET\n")
		idx := &pkgIndex{id: "example.com/mutableasm", mutable: true, meta: &listPkg{Dir: dir, SFiles: []string{"asm.s"}}}
		a := &tier2Analyzer{
			filePkgs: map[*pkgIndex]bool{idx: true},
		}
		if err := a.addReachedPackageFiles(); err != nil {
			t.Fatalf("addReachedPackageFiles: %v", err)
		}
		requireConservative(t, a, "example.com/mutableasm")
	})

	t.Run("cache", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "cache_amd64.s"), []byte("#include \"textflag.h\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tCALL AX\n\tRET\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		typesPkg := types.NewPackage("example.com/cacheasm", "cacheasm")
		idx := &pkgIndex{
			id:    "example.com/cacheasm",
			cache: true,
			meta:  &listPkg{ImportPath: "example.com/cacheasm", Dir: dir, SFiles: []string{"cache_amd64.s"}},
		}
		a := &tier2Analyzer{
			idxByTypes: map[*types.Package]*pkgIndex{typesPkg: idx},
			filePkgs:   map[*pkgIndex]bool{},
		}
		a.scanFunction(&ssa.Function{Pkg: &ssa.Package{Pkg: typesPkg}})
		if err := a.addReachedPackageFiles(); err != nil {
			t.Fatalf("addReachedPackageFiles: %v", err)
		}
		requireConservative(t, a, "example.com/cacheasm")
	})
}

func TestStdWrapperClassBUnverifiable(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/stdwrapper"
	tr, err := computeTier2Result(h, pkg, "BenchmarkTemplateParseFiles")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !tr.unverifiable || !strings.Contains(tr.reason, "file I/O") {
		t.Fatalf("std wrapper Class-B = %v/%q, want file I/O", tr.unverifiable, tr.reason)
	}
}

func TestStdCallbackMethodStaysReached(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/stdcallback"
	_, reach, err := computeTier2ResultAndReach(h, pkg, "BenchmarkSortCallback")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !reachContains(reach, "Less") {
		t.Fatalf("std callback method Less missing from the subject's reach: %v", reach)
	}
}

func TestAnalysisReachesUnverifiable(t *testing.T) {
	// Every benchmark here reaches a Class-B external dependence in its closure
	// (file I/O, filesystem/path mutation, or network), so the closure is
	// unverifiable with the matching reason. File I/O is
	// unverifiable regardless of when it runs relative to the testlog stream: the
	// runtime-input manifest is evidence of observed identities, never a proof
	// that every reachable file-I/O path was covered, so the closure never
	// promotes observed file I/O to valid (REQ-closure-blindspot, REQ-inputs-guard). The fixtures span the
	// pre-testlog window (init/TestMain/CWD-relative) and post-testlog reads, plus
	// path/filesystem mutations and mixed file+network dependence.
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const base = "github.com/greatliontech/gofresh/internal/closure/testdata/"
	// retainedEffect pins a classified fact that must survive among the
	// subject's effects when a higher-ranked diagnostic is preferred: the
	// unix fixtures reach golang.org/x/sys/unix, whose non-toolchain assembly
	// downgrades the subject (REQ-closure-blindspot) ahead of the file-I/O
	// classification of the wrapper itself.
	cases := []struct{ pkg, bench, reason, retainedEffect string }{
		{"external", "BenchmarkReadFile", "file I/O", ""},
		{"initfile", "BenchmarkInitFile", "file I/O", ""},
		{"initcwd", "BenchmarkInitCWD", "file I/O", ""},
		{"unixcwd", "BenchmarkUnixCWD", "non-standard assembly", "file I/O"},
		{"initstdhelper", "BenchmarkInitStdHelper", "file I/O", ""},
		{"sharedfile", "BenchmarkSharedFile", "file I/O", ""},
		{"sharedparam", "BenchmarkSharedParam", "file I/O", ""},
		{"sharedglobal", "BenchmarkSharedGlobal", "file I/O", ""},
		{"sharedchdir", "BenchmarkSharedChdir", "file I/O", ""},
		{"sharedfchdir", "BenchmarkSharedFchdir", "file I/O", ""},
		{"unixfchdir", "BenchmarkUnixFchdir", "non-standard assembly", "file I/O"},
		{"openfileread", "BenchmarkOpenFileRead", "file I/O", ""},
		{"openrootread", "BenchmarkRootOpenFileRead", "file I/O", ""},
		{"initdynamic", "BenchmarkInitDynamic", "file I/O", ""},
		{"initstdcallback", "BenchmarkInitStdCallback", "file I/O", ""},
		{"testmainfile", "BenchmarkTestMainFile", "file I/O", ""},
		{"testmainruntimefile", "BenchmarkTestMainRuntimeFile", "file I/O", ""},
		{"pathbinding", "BenchmarkPathBinding", "path mutation", ""},
		{"syscallbinding", "BenchmarkSyscallBinding", "path mutation", ""},
		{"mkdirtemp", "BenchmarkMkdirTemp", "path mutation", ""},
		{"mkdir", "BenchmarkMkdir", "path mutation", ""},
		{"unixatbinding", "BenchmarkUnixAtBinding", "path mutation", ""},
		{"tempdir", "BenchmarkTempDir", "path mutation", ""},
		{"copyfs", "BenchmarkCopyFS", "path mutation", ""},
		{"createtemp", "BenchmarkCreateTemp", "filesystem mutation", ""},
		{"filemutations", "BenchmarkCreate", "filesystem mutation", ""},
		{"filemutations", "BenchmarkOpenFileCreate", "filesystem mutation", ""},
		{"filemutations", "BenchmarkWriteFile", "filesystem mutation", ""},
		{"unixopencreate", "BenchmarkUnixOpenCreate", "filesystem mutation", ""},
		{"mixedexternal", "BenchmarkMixedExternal", "network I/O", ""},
	}
	var roster []string
	for _, tc := range cases {
		roster = append(roster, base+tc.pkg)
	}
	fixtures := newFixturePrograms(t, h, roster...)
	transitions, previous := 0, ""
	for _, tc := range cases {
		t.Run(tc.pkg+"/"+tc.bench, func(t *testing.T) {
			if previous != tc.pkg {
				transitions++
				previous = tc.pkg
			}
			fixtures.supply(t, base+tc.pkg)
			tr, err := computeTier2Result(h, base+tc.pkg, tc.bench)
			if err != nil {
				t.Fatalf("analysis: %v", err)
			}
			if !tr.unverifiable || !strings.Contains(tr.reason, tc.reason) {
				t.Fatalf("unverifiable = %v, reason = %q, want reason containing %q", tr.unverifiable, tr.reason, tc.reason)
			}
			if tc.retainedEffect != "" {
				found := false
				for _, effect := range tr.effects {
					if strings.Contains(effect.reason, tc.retainedEffect) {
						found = true
					}
				}
				if !found {
					t.Fatalf("effects = %+v, want a retained effect containing %q", tr.effects, tc.retainedEffect)
				}
			}
		})
	}
	fixtures.checkPreparationCounts(t, transitions)
}

func TestTier2RetainsEveryReachedExternalEffect(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/mixedexternal"
	result, err := computeTier2Result(h, pkg, "BenchmarkMixedExternal")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range [][2]string{{"os", "ReadFile"}, {"net", "Dial"}} {
		found := false
		for _, effect := range result.effects {
			found = found || effect.packagePath == want[0] && effect.symbol == want[1]
		}
		if !found {
			t.Errorf("missing reached effect %s.%s from %+v", want[0], want[1], result.effects)
		}
	}
	if !strings.Contains(result.reason, "network I/O") {
		t.Fatalf("legacy diagnostic = %q, want network I/O", result.reason)
	}
}

func TestReadOnlyObservabilityProof(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	const base = "github.com/greatliontech/gofresh/internal/closure/testdata/"
	cases := []struct {
		fixture, subject string
		observable       bool
		reason           string
		// absent, when set, asserts the reason does NOT contain the
		// substring - it pins WHICH arm produced the refusal (walk vs
		// package-scan backstop), not just its cause.
		absent string
	}{
		{fixture: "observable", subject: "TestReadFile", observable: true},
		{fixture: "observable", subject: "TestGetenv", observable: true},
		{fixture: "observable", subject: "TestLookupEnv", observable: true},
		{fixture: "observable", subject: "TestOpen", observable: true},
		{fixture: "observable", subject: "TestReadDir", observable: true},
		{fixture: "observableopenfile", subject: "TestOpenFile", observable: true},
		{fixture: "harnesslog", subject: "TestReadFileFatal", observable: true},
		{fixture: "harnesslog", subject: "TestReadFileLogAndError", observable: true},
		{fixture: "harnesslog", subject: "TestReadFileSkipAndFail", observable: true},
		{fixture: "harnesslog", subject: "TestLocalTBFatal", observable: true},
		{fixture: "harnesslog", subject: "TestLogOnly", observable: true},
		{fixture: "harnesslog", subject: "TestBoundMethodFatal", observable: true},
		{fixture: "harnessarg", subject: "TestLogEffectfulArgument", reason: "os.ReadFile"},
		{fixture: "harnesssetenv", subject: "TestSetenvStaysBlocked", reason: "testing.Setenv"},
		{fixture: "harnesstb", subject: "TestHelperTBFatal", observable: true},
		{fixture: "harnesstb", subject: "TestHelperTBTwice", observable: true},
		// The open-world refusal names the dispatch edge: the enclosing
		// function and the interface method the unresolved invoke calls.
		{fixture: "harnesstb", subject: "TestHelperTBRecursive", reason: "interface invoke outside RTA: github.com/greatliontech/gofresh/internal/closure/testdata/harnesstb.mustBaselineDeep dispatches testing.TB.Fatal"},
		{fixture: "harnesstbenv", subject: "TestHelperTBSetenv", reason: "package scan: reaches testing.Setenv (process or path mutation)"},
		// The subject-determined dispatch admission classifies the
		// enumerated targets instead of widening; the wrapper type's
		// promoted method set drains testing's bodies into the walk and
		// the subject refuses causally on the file I/O reached there -
		// at the subject tier (absent discriminates the backstop). The
		// specific std symbol is toolchain-dependent, so the pin holds
		// the class.
		{fixture: "harnesswrap", subject: "TestQuietWrappedFatal", reason: "(file I/O)", absent: "package scan:"},
		{fixture: "harnessshared", subject: "TestConsume", reason: "interface invoke outside RTA"},
		{fixture: "harnesssetenv", subject: "TestCleanRead", reason: "package scan: reaches testing.Setenv"},
		{fixture: "observablefresh", subject: "TestTempDirWriteReadCleanup", observable: true},
		{fixture: "observablefresh", subject: "TestTempDirOpenFile", observable: true},
		// A sibling file's unsafe declarations no longer pre-block a
		// clean subject at the package scan; a subject carrying an
		// unsafe-typed value through its own walk still refuses, on the
		// widen path (REQ-closure-observability-dispatch
		// unsafe class).
		{fixture: "unsafesibling", subject: "TestCleanRead", observable: true},
		{fixture: "unsafesibling", subject: "TestReachesUnsafe", reason: "unsafe pointer reachable", absent: "package scan:"},
		// The carve is symbol-exact: unsafe.Slice's call site carries
		// no unsafe.Pointer-typed value for the type-graph arm to
		// price, so it must keep the scan block - the row that pins
		// the carve's breadth.
		{fixture: "unsafeslice", subject: "TestSliceHeader", reason: "package scan: reaches unaudited standard operation unsafe.Slice"},
		// The scalar-global mutation boundary (the scalarglobalwrite
		// and scalarglobalslice package docs carry the full story,
		// the slice channel's separate-package placement included).
		// The direct-write row is the
		// carve's guard for this package — observable despite the
		// sibling unsafe declarations; the admission itself is
		// enforced at the view tier's plain-data builder test. The
		// two unsafe rows pin the per-channel refusal: an
		// unsafe.Pointer-typed value refuses at the walk (never the
		// scan — the absent discriminator), and the unsafe.Slice
		// write, carrying no such value, refuses at the scan, its
		// only arm.
		{fixture: "scalarglobalwrite", subject: "TestDirectWrite", observable: true},
		{fixture: "scalarglobalwrite", subject: "TestUnsafeWrite", reason: "unsafe pointer reachable", absent: "package scan:"},
		{fixture: "scalarglobalslice", subject: "TestSliceWrite", reason: "package scan: reaches unaudited standard operation unsafe.Slice"},
		{fixture: "observablestat", subject: "TestStat"},
		{fixture: "observablemutation", subject: "TestRemove"},
		{fixture: "observableprocess", subject: "TestCommand"},
		{fixture: "observableconcurrent", subject: "TestConcurrentFileRead", reason: "os.Open"},
		{fixture: "observablefresh", subject: "TestRemoveOrdinary", reason: "os.Remove"},
		{fixture: "observablefresh", subject: "TestOpenFileMutatesOrdinary", reason: "reaches os.OpenFile (filesystem mutation)"},
		{fixture: "observablefresh", subject: "TestRemoveNeverCreated", reason: "os.Remove"},
		{fixture: "observablefresh", subject: "TestOpenFileMutatesNeverCreated", reason: "reaches os.OpenFile (filesystem mutation)"},
		{fixture: "observablefresh", subject: "TestOpenDynamicHandleClose", reason: "os.File.Close on an unattributed file handle"},
		{fixture: "observablefresh", subject: "TestOpenFileUnknownFlags", reason: "reaches testing.TempDir (process or path mutation)"},
		{fixture: "observablefresh", subject: "TestOpenFreshDirectoryRead", reason: "reaches testing.TempDir (process or path mutation)"},
		{fixture: "observablefresh", subject: "TestWriteFileUncheckedBeforeRead", reason: "reaches testing.TempDir (process or path mutation)"},
		{fixture: "observablefresh", subject: "TestWriteFileMutationBeforeRead", reason: "reaches testing.TempDir (process or path mutation)"},
		{fixture: "observablefresh", subject: "TestWriteFileMutationAcrossLoop", reason: "testing.TempDir"},
		{fixture: "observablefresh", subject: "TestWriteFileMutationThroughAlias", reason: "os.WriteFile"},
		{fixture: "observablefresh", subject: "TestWriteFileMutationThroughDuplicateJoin", reason: "testing.TempDir"},
		{fixture: "observablefresh", subject: "TestAncestorCleanupBeforeRead", reason: "reaches testing.TempDir (process or path mutation)"},
		{fixture: "observablefresh", subject: "TestJoinParentTraversal", reason: "reaches testing.TempDir (process or path mutation)"},
		{fixture: "observablefresh", subject: "TestReservedDevicePath", reason: "reaches testing.TempDir (process or path mutation)"},
		{fixture: "observablefresh", subject: "TestPathConcatenation", reason: "reaches testing.TempDir (process or path mutation)"},
		{fixture: "observablefresh", subject: "TestGeneratedPathComparison", reason: "testing.TempDir"},
		{fixture: "observablefresh", subject: "TestFreshPathHelperEscape"},
		// The boundary extension admits an ignored parameter — nothing
		// is observed — and the disciplined helper; every refusal shape
		// (mixed callers, recursion, goroutine crossing, global leak)
		// stays refused.
		{fixture: "observablefresh", subject: "TestFreshPathNoopEscape", observable: true},
		{fixture: "observablefresh", subject: "TestFreshPathHelperFullDiscipline", observable: true},
		{fixture: "observablefresh", subject: "TestFreshPathHelperMixedCallers"},
		{fixture: "observablefresh", subject: "TestFreshPathHelperRecursive"},
		{fixture: "observablefresh", subject: "TestFreshPathHelperGoroutine"},
		{fixture: "observablefresh", subject: "TestFreshPathHelperLeak"},
		{fixture: "observablefresh", subject: "TestFreshPathHelperDirectGo"},
		{fixture: "observablefresh", subject: "TestFreshPathHelperInLoop"},
		{fixture: "observablefresh", subject: "TestFreshPathHelperClosureCallee"},
		{fixture: "observablefresh", subject: "TestFreshFileProbeEscape", reason: "reaches os.OpenFile (filesystem mutation)"},
		{fixture: "observablefresh", subject: "TestFreshFileNameEscape", reason: "reaches os.OpenFile (filesystem mutation)"},
		{fixture: "observablefresh", subject: "TestFreshPathGlobalEscape", reason: "testing.TempDir"},
		// The startup caller is invisible to per-subject call-site
		// enumeration by design; the startup walk blocks first, and
		// this row pins that mask (the soundness argument for
		// callers-from-subject-reach-only).
		{fixture: "observablefreshinit", subject: "TestFreshHelperShadowedByStartupCaller", reason: "startup effect"},
		// The unsafe payload is visible only through the named type's
		// underlying structure — no reachable value has an unsafe type
		// directly — so this row discriminates the type walk's
		// underlying edge.
		{fixture: "unsafewrapped", subject: "TestWrappedUnsafeHandle", reason: "unsafe pointer"},
		{fixture: "toolchainread", subject: "TestAccessorAlone", observable: true},
		{fixture: "toolchainread", subject: "TestReadVersion", observable: true},
		{fixture: "toolchainread", subject: "TestOpenUnderToolchain", observable: true},
		{fixture: "toolchainread", subject: "TestReadDirUnderToolchain", observable: true},
		{fixture: "toolchainread", subject: "TestWriteIntoToolchain", reason: "os.WriteFile"},
		{fixture: "toolchainread", subject: "TestDynamicComponent", reason: "os.ReadFile"},
		{fixture: "toolchainruntime", subject: "TestOtherRuntimeSurface", reason: "runtime.NumCPU"},
		{fixture: "toolchainindirect", subject: "TestIndirectRuntimeSurface", reason: "runtime.NumCPU"},
		{fixture: "toolchaininit", subject: "TestReadThroughInitRoot", reason: "startup effect"},
		{fixture: "testmainhelper", subject: "TestRead", observable: true},
		{fixture: "harnessmain", subject: "TestRead", reason: "test-main dispatch on unattributable state"},
		{fixture: "harnessmainlocal", subject: "TestRead", observable: true},
		{fixture: "harnessmainfunc", subject: "TestRead", reason: "test-main dispatch on unattributable state"},
		{fixture: "harnessmainbound", subject: "TestRead", reason: "test-main dispatch on unattributable state"},
		{fixture: "harnessmainthunk", subject: "TestRead", reason: "test-main dispatch on unattributable state"},
		{fixture: "harnessshareddispatch", subject: "TestUseBound", reason: "interface dispatch on unattributable state"},
		{fixture: "harnessshareddispatch", subject: "TestUseThunk", reason: "interface dispatch on unattributable state"},
		{fixture: "harnessshareddispatch", subject: "TestUsePhi", reason: "computed function call"},
		{fixture: "harnessshareddispatch", subject: "TestUseThunkLocal", observable: true},
		{fixture: "harnessshareddispatch", subject: "TestUseThunkPhi", reason: "computed function call"},
		{fixture: "harnessshareddispatch", subject: "TestUseLaunder", reason: "computed function call"},
		{fixture: "harnessmainlaunder", subject: "TestRead", reason: "test-main dispatch on unattributable state"},
		{fixture: "harnesserrshared", subject: "TestUseErrBound", reason: "interface dispatch on unattributable state"},
		{fixture: "harnessmainphi", subject: "TestRead", reason: "test-main dispatch on unattributable state"},
		{fixture: "initglobaldispatch", subject: "TestRead", observable: true},
		// The writer-sink admission: fmt's writer-first print family is
		// Sprint-equivalent when the writer provably pins an audited
		// in-memory sink; every unproven provenance — call results, phi
		// escapes, mixed helper callers — keeps the formatted-output
		// refusal (REQ-closure-observability-writer-sink).
		{fixture: "fmtsink", subject: "TestFprintfBuffer", observable: true},
		{fixture: "fmtsink", subject: "TestFprintlnBuilder", observable: true},
		{fixture: "fmtsink", subject: "TestFprintfHelperBuffer", observable: true},
		{fixture: "fmtsink", subject: "TestFprintfPhiBuffers", observable: true},
		{fixture: "fmtsink", subject: "TestFprintfCallResult", reason: "fmt.Fprintf"},
		{fixture: "fmtsink", subject: "TestFprintfPhiCallEscape", reason: "fmt.Fprintf"},
		{fixture: "fmtsink", subject: "TestFprintfHelperMixed", reason: "fmt.Fprintf"},
		{fixture: "fmtsink", subject: "TestFprintfLocalWriterType", reason: "fmt.Fprintf"},
		{fixture: "fmtsink", subject: "TestFprintfGlobalBuffer", observable: true},
		{fixture: "fmtsink", subject: "TestFprintfFieldBuffer", observable: true},
		// A dynamic reach in subject flow is never admitted, whatever
		// the arguments carry — the site refuses before the writer is
		// ever consulted.
		{fixture: "fmtsinkvalue", subject: "TestValueFormatBuffer"},
		// The AST scan's Fprint carve-out never unblocks the escaping
		// sink itself: the os.Stdout selector still pre-blocks the
		// package, so a stdout writer refuses before the subject tier.
		{fixture: "fmtsinkstdout", subject: "TestFprintfStdout", reason: "package scan: reaches unaudited standard operation os.Stdout"},
		// Startup flow closes locally constructed writers — an init
		// formatting into its own buffer is pure value computation —
		// while a dynamically reached Fprint keeps its effect
		// regardless of site arguments (the writer-sink admission's
		// static-leg bound) and a writer crossing a call boundary
		// refuses (startup carries no attributed parameter analysis).
		// Whole-view caller enumeration: a dynamic-carrying subject
		// whose only references are direct static calls with
		// caller-frame-closed arguments analyzes closed; a caller-passed
		// closure's or materialized type's effects are the subject's
		// own; value references, zero references, and unclosed
		// arguments keep the open world (REQ-closure-analysis).
		{fixture: "dyncaller", subject: "RunCheck", observable: true},
		{fixture: "dyncaller", subject: "RunEffect", reason: "os.WriteFile"},
		// A computed call names the value it calls where that value has
		// a stable identity - here the escaped parameter.
		{fixture: "dyncaller", subject: "RunEscaped", reason: "computed function call in github.com/greatliontech/gofresh/internal/closure/testdata/dyncaller.RunEscaped calling parameter check"},
		// A computed call through a package-level function variable
		// names the variable it dispatches.
		{fixture: "dyncaller", subject: "RunViaVar", reason: "computed function call in github.com/greatliontech/gofresh/internal/closure/testdata/dyncaller.RunViaVar calling github.com/greatliontech/gofresh/internal/closure/testdata/dyncaller.hook"},
		// The subject-determined dispatch admission: a helper-interior
		// invoke whose operand derives wholly from subject flow and
		// whose enumerated targets are analyzed content stops widening -
		// the targets' own effects decide (REQ-closure-observability-dispatch). A load from
		// shared mutable state keeps the refusal.
		{fixture: "depdispatch", subject: "RunLocalDispatch", observable: true},
		{fixture: "depdispatch", subject: "RunEffectDispatch", reason: "os.WriteFile"},
		{fixture: "depdispatch", subject: "RunSharedDispatch", reason: "interface invoke outside RTA: github.com/greatliontech/gofresh/internal/closure/testdata/depdispatch.measureVia dispatches github.com/greatliontech/gofresh/internal/closure/testdata/depdispatch.sizer.size"},
		// The enumeration-target narrowing: an init-parented closure of
		// matching signature stays out of an enumeration-closed
		// subject's target set, so the initializer's read no longer
		// drags a spurious refusal in (the startup walk still judges
		// the initializer itself on its own terms).
		{fixture: "dyninitcollide", subject: "Run", observable: true},
		// The narrowing is value-provenance, not closure-shape: an
		// init-materialized method value (a parentless synthetic bound
		// wrapper — the go1.27 encoding/json/v2 base32 shape every test
		// binary links) and an init-registered named function stay out
		// of a closed subject's target set exactly as the init-parented
		// closure above does.
		{fixture: "dyninitbound", subject: "Run", observable: true},
		// The std-frame keep is load-bearing: an init-planted
		// comparator passed as a plain argument into a std generic
		// dispatches inside the std frame where no operand proof runs,
		// so the whole-mask drag stays and the latent write refuses at
		// the subject tier.
		{fixture: "dyninitstdframe", subject: "RunSort", reason: "os.WriteFile", absent: "startup effect:"},
		{fixture: "depdispatch", subject: "RunNilDispatch", reason: "interface invoke outside RTA: github.com/greatliontech/gofresh/internal/closure/testdata/depdispatch.dispatchNever dispatches github.com/greatliontech/gofresh/internal/closure/testdata/depdispatch.never.nope"},
		{fixture: "dyncaller", subject: "RunUncalled", reason: "computed function call"},
		{fixture: "dyncaller", subject: "RunMixed", reason: "computed function call"},
		{fixture: "dyncaller", subject: "RunDead", reason: "open subject world"},
		{fixture: "dyncaller", subject: "FormatLoaded", reason: "open subject world"},
		{fixture: "dyncaller", subject: "FormatLocal", observable: true},
		{fixture: "dyncaller", subject: "Runner.RunM", reason: "computed function call"},
		{fixture: "dyncaller", subject: "Counter.RunP", reason: "computed function call"},
		{fixture: "dyninit", subject: "RunInit", reason: "computed function call"},
		{fixture: "dyncaller", subject: "RunGen", reason: "computed function call"},
		{fixture: "dyncaller", subject: "RunGo", observable: true},
		{fixture: "dyncaller", subject: "RunCallArg", reason: "computed function call"},
		{fixture: "dyncaller", subject: "Measure", observable: true},
		{fixture: "dyncaller", subject: "MeasureFile", reason: "os.WriteFile"},
		{fixture: "initfmtsink", subject: "TestAfterInitFormat", observable: true},
		{fixture: "initfmtvalue", subject: "TestAfterInitValueFormat", reason: "startup effect: reaches fmt.Fprintf"},
		{fixture: "initfmthelper", subject: "TestAfterInitHelperFormat", reason: "startup effect: reaches fmt.Fprintf"},
		{fixture: "observablebad", subject: "TestOpenStat", reason: "os.Open"},
		{fixture: "observablebad", subject: "TestReadDirInfo", reason: "interface invoke"},
		{fixture: "observablecallbackbad", subject: "TestSubtestRead", observable: true},
		{fixture: "observablecallbackbad", subject: "TestNestedSubtestRead", observable: true},
		// A user-constructed testing.M is subject flow: its Run is the
		// test-main driver, never the subtest-driver admission - the
		// refusal names whichever of M.Run's own effects ranks highest.
		{fixture: "observablecallbackbad", subject: "TestConstructedMRun", reason: "reaches"},
		{fixture: "subtestparallel", subject: "TestParallelChild", reason: "testing.Parallel"},
		// The b.Run driver is admitted like t.Run, and the startup walk
		// cuts non-testing dynamic collisions with (*testing.B).launch so
		// benchmark callbacks stay attributed to subject flow.
		{fixture: "subtestbench", subject: "BenchmarkSubRead", observable: true},
		{fixture: "subtestbench", subject: "BenchmarkSubPure", observable: true},
		{fixture: "fuzzsibling", subject: "FuzzDecode", reason: "testing.Fuzz"},
		{fixture: "fuzzsibling", subject: "TestSiblingRead", observable: true},
		// A *os.File parameter no longer opens the subject: os.File's
		// only dynamic-looking member is its atomic dirinfo cell
		// (atomic.Pointer[dirInfo], data-only pointee), which the
		// audited atomic transparency reads as *dirInfo — so the
		// openness refusal yields to the real blocker, the unaudited
		// os.File operations themselves.
		{fixture: "observablebad", subject: "ReadUnattributed", reason: "package scan: reaches unaudited standard operation os.File"},
		{fixture: "initfile", subject: "TestInitFile", reason: "startup effect"},
		// TestMain flow classifies within subject-time observation: the
		// test log is installed before the user test main runs, so its
		// admitted fixture read is a bracketed observation input
		// (REQ-closure-observability-analysis).
		{fixture: "harnessobserved", subject: "TestProd", observable: true},
		// A test-main write is not a bracketed observation input: the
		// per-effect classification blocks with the write's own reason.
		{fixture: "harnessmainwrite", subject: "TestProd", reason: "os.WriteFile"},
		// The os.Exit epilogue admission is declaration-scoped: an
		// os.Exit outside TestMain keeps the package-scan finding.
		{fixture: "harnessexitoutside", subject: "TestProd", reason: "package scan: reaches unaudited standard operation os.Exit"},
		// The writer-sink admission holds in test-main flow: a format
		// into a locally constructed in-memory sink is value
		// computation.
		{fixture: "harnessmainfmt", subject: "TestProd", observable: true},
		// Flag REGISTRATION is a process-local registry mutation in
		// startup and test-main flow - the covert channel is the read
		// side, which keeps the exclusion in subject and test-main
		// flow, guarded by the registration-facts sink judgment.
		{fixture: "flagreginit", subject: "TestProd", observable: true},
		{fixture: "flagregmain", subject: "TestProd", observable: true},
		// The subject-tier registration refusal comes from the walk,
		// not the scan: the scan admits registration by name.
		{fixture: "flagregsubject", subject: "TestProd", reason: "flag.Bool", absent: "package scan:"},
		// The test-main walk refuses Parse before the scan is ever
		// consulted; the subject-flow Lookup falls to the scan because
		// the subject arm's blocking loop runs after it.
		{fixture: "flagparsemain", subject: "TestProd", reason: "flag.Parse", absent: "package scan:"},
		{fixture: "flaglookupsubject", subject: "TestProd", reason: "package scan: reaches unaudited standard operation flag.Lookup"},
		// A field registration roots at the struct variable: untouched,
		// the subject stays observable; referenced, the reference is the
		// covert channel's read side and refuses.
		{fixture: "flagregstruct", subject: "TestProd", observable: true},
		{fixture: "flagregstruct", subject: "TestProdRead", reason: "flag-registered state"},
		// The field address escaping into an ordinary call refuses:
		// only the registration write's own argument computation
		// passes the reference refusal.
		{fixture: "flagregstruct", subject: "TestProdEscape", reason: "flag-registered state"},
		// A sink the registration-facts judgment cannot trace poisons
		// the package: admission by name stays sound because the
		// unguarded storage blocks every subject sharing the program.
		{fixture: "flagregescape", subject: "TestProd", reason: "untraceable sink"},
		{fixture: "flagreglocalmain", subject: "TestProd", reason: "untraceable sink"},
		// Callback families run arbitrary code at Parse and keep the
		// exclusion outright.
		{fixture: "flagregcallback", subject: "TestProd", reason: "flag.BoolFunc"},
		// Registered storage read in test-main flow refuses: the
		// implicit Parse inside m.Run precedes the read.
		{fixture: "flagregmainread", subject: "TestProd", reason: "flag-registered state", absent: "package scan:"},
		// A dynamically dispatched registration target is admitted
		// nowhere - the facts walk sink-judges only static sites - so
		// the family-named invoke target blocks in test-main and
		// startup flow alike.
		{fixture: "flagreginvoke", subject: "TestProd", reason: "flag.BoolVar", absent: "package scan:"},
		{fixture: "flagreginvokeinit", subject: "TestProd", reason: "flag.BoolVar", absent: "package scan:"},
		// Method-form registration on the default set rides the same
		// sink judgment through its receiver: flag.CommandLine is an
		// audited selector at the fold, the storage is marked, and the
		// subject reading none of it proves observable — the
		// deliberate flip of the former unaudited-symbol pin
		// (REQ-closure-observability-flag-registration's FlagSet forms).
		{fixture: "flagregmethod", subject: "TestProd", observable: true},
		// An init escaping the registered storage's address (q =
		// &quiet) refuses at the escape site: the alias would carry
		// parsed state past the mark.
		{fixture: "flagregalias", subject: "TestProd", reason: "startup effect: references flag-registered state"},
		// A dependency's untraceable sink blocks this package's
		// subjects too - the poison spans the test binary.
		{fixture: "flagregdep", subject: "TestProd", reason: "untraceable sink in github.com/greatliontech/gofresh/internal/closure/testdata/flagregescape"},
		// The benchmark-bearing sibling proves observable: b.Loop is
		// benchmark pacing, an admitted harness fact the fold ignores
		// (REQ-closure-observability-benchmark-pacing) — the deliberate
		// flip of the former package-scan pin.
		{fixture: "harnessroot", subject: "BenchmarkProd", observable: true},
		{fixture: "mixedexternal", subject: "BenchmarkMixedExternal", reason: "subject reachability"},
	}
	var roster []string
	byFixture := map[string][]Subject{}
	for _, tc := range cases {
		pkg := base + tc.fixture
		roster = append(roster, pkg)
		byFixture[tc.fixture] = append(byFixture[tc.fixture], Subject{Package: pkg, Symbol: tc.subject})
	}
	fixtures := newFixturePrograms(t, h, roster...)
	proofs := map[Subject]Observability{}
	computed := map[string]bool{}
	transitions := 0
	for _, tc := range cases {
		t.Run(tc.fixture+"/"+tc.subject, func(t *testing.T) {
			pkg := base + tc.fixture
			if !computed[tc.fixture] {
				computed[tc.fixture] = true
				transitions++
				fixtures.supply(t, pkg)
				res, err := h.ComputeObservabilityBatch(byFixture[tc.fixture])
				if err != nil {
					t.Fatal(err)
				}
				maps.Copy(proofs, res)
			}
			subject := Subject{Package: pkg, Symbol: tc.subject}
			got := proofs[subject]
			if got.Observable != tc.observable || tc.reason != "" && !strings.Contains(got.Reason, tc.reason) || tc.observable && got.Reason != "" {
				t.Fatalf("observability = %+v, want observable=%v reason containing %q", got, tc.observable, tc.reason)
			}
			if tc.absent != "" && strings.Contains(got.Reason, tc.absent) {
				t.Fatalf("observability = %+v, want reason without %q", got, tc.absent)
			}
		})
	}
	fixtures.checkPreparationCounts(t, transitions)
}

// The registration-facts sink judgment is pinned white-box for the
// shapes whose packages the scan blocks anyway (the method form rides
// a flag.CommandLine mention, itself an unaudited symbol): the marks
// and the poison must be right independent of which tier's verdict
// surfaces first.
func TestFlagRegistrationFacts(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	const base = "github.com/greatliontech/gofresh/internal/closure/testdata/"
	facts := func(t *testing.T, pkgPath string) (map[string]bool, map[string]string) {
		t.Helper()
		supplyRegisteredFixtures(t, h, pkgPath)
		prog, err := h.loadCached(pkgPath)
		if err != nil {
			t.Fatal(err)
		}
		metas, err := h.list(pkgPath)
		if err != nil {
			t.Fatal(err)
		}
		backed, poisoned := newTier2Base(h, prog, metas).flagRegistrationFacts()
		names := map[string]bool{}
		for g := range backed {
			if g.Pkg != nil && g.Pkg.Pkg != nil && g.Pkg.Pkg.Path() == pkgPath {
				names[g.Name()] = true
			}
		}
		return names, poisoned
	}
	t.Run("method and method-expression forms judge past the receiver", func(t *testing.T) {
		names, poisoned := facts(t, base+"flagregmethod")
		if !names["verbose"] || !names["quiet"] {
			t.Fatalf("marked globals = %v, want verbose and quiet", names)
		}
		if len(poisoned) != 0 {
			t.Fatalf("poisoned = %v, want none", poisoned)
		}
	})
	t.Run("field and index selections chase to the variable", func(t *testing.T) {
		names, poisoned := facts(t, base+"flagregstruct")
		if !names["cfg"] || !names["arr"] || !names["holder"] {
			t.Fatalf("marked globals = %v, want cfg, arr, and holder", names)
		}
		if len(poisoned) != 0 {
			t.Fatalf("poisoned = %v, want none", poisoned)
		}
	})
	t.Run("untraceable sink poisons its package", func(t *testing.T) {
		_, poisoned := facts(t, base+"flagregescape")
		if !strings.Contains(poisoned[base+"flagregescape"], "untraceable sink") {
			t.Fatalf("poisoned = %v, want the escape package poisoned", poisoned)
		}
	})
}

func TestOrdinaryOpenFileRequiresZeroFlags(t *testing.T) {
	if !ordinaryOpenFileFlagsObservable(0) {
		t.Fatal("zero-valued read-only mode was rejected")
	}
	if ordinaryOpenFileFlagsObservable(1 << 40) {
		t.Fatal("target-specific nonzero flag was interpreted with host flag values")
	}
}

func TestSubjectProvenanceIncludesTestingCallbacks(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/observablecallbackbad"
	supplyRegisteredFixtures(t, h, pkg)
	prog, err := h.loadCached(pkg)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: pkg, Symbol: "TestSubtestRead"}
	reachable, err := attributedReachableSets(context.Background(), true, h.source.pureDelegates, prog, []Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for fn := range reachable[0].subjectFunctions {
		names = append(names, fn.String())
		if funcPkgPath(fn) == pkg && strings.Contains(fn.Name(), "TestSubtestRead$1") {
			return
		}
	}
	sort.Strings(names)
	t.Fatalf("testing callback was omitted from subject provenance: %v", names)
}

func TestObservabilityBatchMatchesIndependentAnalysis(t *testing.T) {
	// The corpus spans every disposition class the observability fixtures pin —
	// observable subjects, startup and subject effect rejections, callback and
	// concurrency escapes, mutation and process effects — with several subjects
	// sharing one package so shared reachability masks and package effect scans
	// are genuinely exercised (REQ-closure-observability-batch-equivalence).
	const base = "github.com/greatliontech/gofresh/internal/closure/testdata/"
	subjects := []Subject{
		{Package: base + "observable", Symbol: "TestReadFile"},
		{Package: base + "observable", Symbol: "TestReadDir"},
		{Package: base + "observable", Symbol: "TestGetenv"},
		{Package: base + "observable", Symbol: "TestOpen"},
		{Package: base + "observable", Symbol: "TestLookupEnv"},
		{Package: base + "observablebad", Symbol: "TestOpenStat"},
		{Package: base + "observablebad", Symbol: "TestReadDirInfo"},
		{Package: base + "observablecallbackbad", Symbol: "TestSubtestRead"},
		{Package: base + "observableconcurrent", Symbol: "TestConcurrentFileRead"},
		{Package: base + "observablefresh", Symbol: "TestAncestorCleanupBeforeRead"},
		{Package: base + "observablefresh", Symbol: "TestFreshFileNameEscape"},
		{Package: base + "observablemutation", Symbol: "TestRemove"},
		{Package: base + "observableopenfile", Symbol: "TestOpenFile"},
		{Package: base + "observableprocess", Symbol: "TestCommand"},
		{Package: base + "observablestat", Symbol: "TestStat"},
		{Package: base + "toolchainread", Symbol: "TestReadVersion"},
		{Package: base + "toolchainread", Symbol: "TestWriteIntoToolchain"},
		{Package: base + "toolchainruntime", Symbol: "TestOtherRuntimeSurface"},
		{Package: base + "initfile", Symbol: "TestInitFile"},
		{Package: base + "initfile", Symbol: "BenchmarkInitFile"},
		{Package: base + "harnessmain", Symbol: "TestRead"},
		{Package: base + "harnessmain", Symbol: "TestPlant"},
		{Package: base + "harnesslog", Symbol: "TestReadFileFatal"},
	}
	var subjectPkgs []string
	for _, s := range subjects {
		subjectPkgs = append(subjectPkgs, s.Package)
	}
	batchHasher, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	supplyRegisteredFixtures(t, batchHasher, subjectPkgs...)
	batch, err := batchHasher.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	independentResults := make([]Observability, len(subjects))
	// Each comparison keeps a genuinely independent hasher and singleton load.
	// Join the cohort before aggregating or beginning the maximal->observe arm.
	t.Run("independent", func(t *testing.T) {
		for i, subject := range subjects {
			t.Run(subject.Package+"/"+subject.Symbol, func(t *testing.T) {
				independentHasher, err := newAt("")
				if err != nil {
					t.Fatal(err)
				}
				supplyRegisteredFixtures(t, independentHasher, subject.Package)
				independent, err := independentHasher.ComputeObservabilityBatch([]Subject{subject})
				if err != nil {
					t.Fatal(err)
				}
				if batch[subject] != independent[subject] {
					t.Errorf("%s.%s batch=%+v independent=%+v", subject.Package, subject.Symbol, batch[subject], independent[subject])
				}
				independentResults[i] = independent[subject]
			})
		}
	})
	statuses := map[bool]int{}
	for _, independent := range independentResults {
		statuses[independent.Observable]++
	}
	if statuses[true] == 0 || statuses[false] == 0 {
		t.Fatalf("corpus lost its disposition spread: %v", statuses)
	}
	// Subject-local attribution inside one package's shared mask is witnessed
	// only if some package's subjects disagree; a corpus refactor must not
	// silently lose that witness.
	bad1 := batch[Subject{Package: base + "observablebad", Symbol: "TestOpenStat"}]
	bad2 := batch[Subject{Package: base + "observablebad", Symbol: "TestReadDirInfo"}]
	if bad1 == bad2 {
		t.Fatalf("observablebad subjects share one disposition (%+v); the corpus lost its within-package variance witness", bad1)
	}
	if startup := batch[Subject{Package: base + "initfile", Symbol: "TestInitFile"}]; !strings.HasPrefix(startup.Reason, "startup effect:") {
		t.Fatalf("initfile subject = %+v, want a startup-effect rejection", startup)
	}

	// One shared Hasher running the production maximal→observe sequence
	// over warm list and effect caches must yield the same dispositions as
	// the fresh batch above.
	sharedHasher, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	supplyRegisteredFixtures(t, sharedHasher, subjectPkgs...)
	if _, _, err := sharedHasher.ComputeMaximalBatch(subjects); err != nil {
		t.Fatal(err)
	}
	shared, err := sharedHasher.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range subjects {
		if shared[subject] != batch[subject] {
			t.Errorf("%s.%s shared-sequence=%+v batch=%+v", subject.Package, subject.Symbol, shared[subject], batch[subject])
		}
	}
}

func TestProvenanceReachabilityHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provenanceReachable(ctx, nil, 1, &arta.Result{}, false, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("provenanceReachable = %v, want context.Canceled", err)
	}
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/observable"
	supplyRegisteredFixtures(t, h, pkg)
	prog, err := h.loadCached(pkg)
	if err != nil {
		t.Fatal(err)
	}
	root := prog.Roots["TestReadFile"]
	bounded := &cancelProvenanceContext{Context: context.Background(), remaining: 1}
	if _, err := provenanceReachable(bounded, []*ssa.Function{root}, 1, &arta.Result{Reachable: map[*ssa.Function]uint64{root: 1}}, false, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("provenanceReachable during traversal = %v, want context.Canceled", err)
	}
}

type cancelProvenanceContext struct {
	context.Context
	remaining int
}

func (c *cancelProvenanceContext) Err() error {
	if c.remaining == 0 {
		return context.Canceled
	}
	c.remaining--
	return nil
}

func TestTier2ReflectWidens(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/reflectfixture"
	tr, err := computeTier2Result(h, pkg, "BenchmarkReflect")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !tr.widen {
		t.Fatal("reflect dispatch did not widen to Tier-1")
	}
}

func TestTier2GenericInterfaceEscapeAnalyzesMethodBody(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/genericescape"
	tr, err := computeTier2Result(h, pkg, "BenchmarkGenericEscape")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if tr.widen {
		t.Fatalf("generic interface escape widened (imprecise): %+v", tr)
	}
	// Secret is reached only via interface escape (never called → not
	// RTA-reachable); its instantiated object has no decl node, so the
	// origin body must be resolved and scanned — the fixture plants an
	// environment read there, and losing the resolution loses the effect.
	if !hasEffectReason(tr.effects, "reaches os.Getenv (environment input)") {
		t.Fatalf("generic method body reached via interface escape was not analyzed: %+v", tr.effects)
	}
}

func TestTier2ConstGroupAnalyzesWithoutWiden(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/constgroup"
	tr, err := computeTier2Result(h, pkg, "BenchmarkConstGroup")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if tr.widen {
		t.Fatalf("const group fixture widened: %+v", tr)
	}
}

// TestNonToolchainAssemblyWidensAndBlocks pins the conservative contract
// end-to-end (REQ-closure-blindspot): a subject reaching a non-toolchain
// assembly-bearing package widens to the maximal closure (whose hash covers
// the package directory whole), names the assembly as the widening cause, and
// is unverifiable via the "reaches non-standard assembly" effect that blocks
// its observability proof. The assembly is never analyzed for call targets.
func TestNonToolchainAssemblyWidensAndBlocks(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/asmcall"
	tr, err := computeTier2Result(h, pkg, "BenchmarkASMCall")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !tr.widen || !strings.Contains(tr.widenReason, "non-toolchain assembly in "+pkg) {
		t.Fatalf("widen = %v/%q, want non-toolchain assembly in %s", tr.widen, tr.widenReason, pkg)
	}
	if !tr.unverifiable {
		t.Fatal("non-toolchain assembly subject was not unverifiable")
	}
	found := false
	for _, effect := range tr.effects {
		if effect.kind == externalEffectNative && effect.reason == opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly").reason {
			found = true
		}
	}
	if !found {
		t.Fatalf("effects = %+v, want native \"reaches non-standard assembly\"", tr.effects)
	}
}

func TestTier2WasmImportUnverifiable(t *testing.T) {
	typesPkg := types.NewPackage("example.com/wasmdep", "wasmdep")
	file := &ast.File{
		Name:     ast.NewIdent("wasmdep"),
		Comments: []*ast.CommentGroup{{List: []*ast.Comment{{Text: "//go:wasmimport env imported"}}}},
	}
	ssaProg := ssa.NewProgram(token.NewFileSet(), ssa.InstantiateGenerics)
	a := &tier2Analyzer{
		h:          &Hasher{},
		prog:       &program{Prog: ssaProg},
		metaByPath: map[string]*listPkg{},
	}
	idx := a.buildIndex(&packages.Package{ID: "example.com/wasmdep", PkgPath: "example.com/wasmdep", Types: typesPkg, Syntax: []*ast.File{file}})
	if idx == nil || !idx.wasmImport {
		t.Fatalf("buildIndex wasmImport = %v, want true", idx != nil && idx.wasmImport)
	}
	a.idxByTypes = map[*types.Package]*pkgIndex{typesPkg: idx}
	a.filePkgs = map[*pkgIndex]bool{}
	a.scanned = map[*ssa.Function]bool{}

	a.scanFunction(&ssa.Function{Pkg: &ssa.Package{Pkg: typesPkg}, Blocks: []*ssa.BasicBlock{{}}})
	if !a.unverifiable || !strings.Contains(a.selected.reason, "go:wasmimport") {
		t.Fatalf("wasmimport Class-B = %v/%q, want go:wasmimport", a.unverifiable, a.selected.reason)
	}
}

func TestTier2InterfaceMethodSetUsesPackageMetadata(t *testing.T) {
	dotlessTypes := types.NewPackage("myapp", "myapp")
	typeName := types.NewTypeName(token.NoPos, dotlessTypes, "T", nil)
	named := types.NewNamed(typeName, types.NewStruct(nil, nil), nil)
	recv := types.NewVar(token.NoPos, dotlessTypes, "", named)
	method := types.NewFunc(token.NoPos, dotlessTypes, "M", types.NewSignatureType(recv, nil, nil, types.NewTuple(), types.NewTuple(), false))
	named.AddMethod(method)
	idx := &pkgIndex{pkg: &packages.Package{Types: dotlessTypes}, mutable: true}
	a := &tier2Analyzer{
		idxByTypes:  map[*types.Package]*pkgIndex{dotlessTypes: idx},
		seenObjects: map[types.Object]bool{},
	}

	a.addInterfaceMethodSet(named)
	if len(a.objectQueue) != 1 || a.objectQueue[0] != method {
		t.Fatalf("dotless package method queue = %v, want M", a.objectQueue)
	}
}

func TestTier2InterfaceMethodSetSeesEmbeddedStructField(t *testing.T) {
	localTypes := types.NewPackage("example.com/local", "local")
	typeName := types.NewTypeName(token.NoPos, localTypes, "E", nil)
	named := types.NewNamed(typeName, types.NewStruct(nil, nil), nil)
	recv := types.NewVar(token.NoPos, localTypes, "", named)
	method := types.NewFunc(token.NoPos, localTypes, "M", types.NewSignatureType(recv, nil, nil, types.NewTuple(), types.NewTuple(), false))
	named.AddMethod(method)
	embedded := types.NewField(token.NoPos, localTypes, "E", named, true)
	concrete := types.NewStruct([]*types.Var{embedded}, []string{""})
	idx := &pkgIndex{pkg: &packages.Package{Types: localTypes}, mutable: true}
	a := &tier2Analyzer{
		idxByTypes:  map[*types.Package]*pkgIndex{localTypes: idx},
		seenObjects: map[types.Object]bool{},
	}

	a.addInterfaceMethodSet(concrete)
	if len(a.objectQueue) != 1 || a.objectQueue[0] != method {
		t.Fatalf("embedded method queue = %v, want E.M", a.objectQueue)
	}
}

func TestTier2InterfaceMethodsUseDeclaringTypeSource(t *testing.T) {
	pkg := types.NewPackage("example.com/cache", "cache")
	method := types.NewFunc(token.NoPos, pkg, "Read", types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false))
	iface := types.NewInterfaceType([]*types.Func{method}, nil)
	iface.Complete()
	name := types.NewTypeName(token.NoPos, pkg, "Reader", nil)
	types.NewNamed(name, iface, nil)
	node := &ast.TypeSpec{Name: ast.NewIdent("Reader")}
	idx := &pkgIndex{decls: map[types.Object]ast.Node{}}

	addTypeDeclaration(idx, name, node)
	if idx.decls[method] != node {
		t.Fatal("interface method was not attributed to its declaring type")
	}
}

func TestTier2CacheDeclarationTraversesMutableReference(t *testing.T) {
	cacheTypes := types.NewPackage("example.com/cachedep", "cachedep")
	localTypes := types.NewPackage("example.com/localdep", "localdep")
	cacheObj := types.NewConst(token.NoPos, cacheTypes, "C", types.Typ[types.Int], nil)
	localObj := types.NewConst(token.NoPos, localTypes, "LocalC", types.Typ[types.Int], nil)
	cacheTypes.Scope().Insert(cacheObj)
	localTypes.Scope().Insert(localObj)
	localIdent := ast.NewIdent("LocalC")
	node := &ast.ValueSpec{Names: []*ast.Ident{ast.NewIdent("C")}, Values: []ast.Expr{localIdent}}
	cacheIdx := &pkgIndex{
		pkg:   &packages.Package{Types: cacheTypes, TypesInfo: &types.Info{Uses: map[*ast.Ident]types.Object{localIdent: localObj}}},
		cache: true,
		decls: map[types.Object]ast.Node{cacheObj: node},
	}
	localIdx := &pkgIndex{pkg: &packages.Package{Types: localTypes}, mutable: true, decls: map[types.Object]ast.Node{}}
	a := &tier2Analyzer{
		idxByTypes:  map[*types.Package]*pkgIndex{cacheTypes: cacheIdx, localTypes: localIdx},
		seenObjects: map[types.Object]bool{},
		seenTypes:   map[types.Type]bool{},
	}

	a.addObject(cacheObj)
	if len(a.objectQueue) != 1 || a.objectQueue[0] != localObj {
		t.Fatalf("cache declaration queue = %v, want localdep.LocalC", a.objectQueue)
	}
}

func TestTier2CacheFunctionTraversesMutableReference(t *testing.T) {
	cacheTypes := types.NewPackage("example.com/cachedep", "cachedep")
	localTypes := types.NewPackage("example.com/localdep", "localdep")
	cacheFn := types.NewFunc(token.NoPos, cacheTypes, "F", types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(types.NewVar(token.NoPos, nil, "", types.Typ[types.Int])), false))
	localObj := types.NewConst(token.NoPos, localTypes, "C", types.Typ[types.Int], nil)
	cacheTypes.Scope().Insert(cacheFn)
	localTypes.Scope().Insert(localObj)
	fnName := ast.NewIdent("F")
	localIdent := ast.NewIdent("C")
	fnDecl := &ast.FuncDecl{
		Name: fnName,
		Type: &ast.FuncType{
			Params:  &ast.FieldList{},
			Results: &ast.FieldList{List: []*ast.Field{{Type: ast.NewIdent("int")}}},
		},
		Body: &ast.BlockStmt{List: []ast.Stmt{&ast.ReturnStmt{Results: []ast.Expr{localIdent}}}},
	}
	info := &types.Info{
		Defs: map[*ast.Ident]types.Object{fnName: cacheFn},
		Uses: map[*ast.Ident]types.Object{localIdent: localObj},
	}
	ssaProg := ssa.NewProgram(token.NewFileSet(), ssa.InstantiateGenerics)
	ssaPkg := ssaProg.CreatePackage(cacheTypes, []*ast.File{{Name: ast.NewIdent("cachedep"), Decls: []ast.Decl{fnDecl}}}, info, true)
	ssaFn := ssaPkg.Func("F")
	if ssaFn == nil {
		t.Fatal("ssa function F missing")
	}
	ssaFn.Blocks = []*ssa.BasicBlock{{}}
	cacheIdx := &pkgIndex{
		pkg:   &packages.Package{Types: cacheTypes, TypesInfo: info},
		cache: true,
		decls: map[types.Object]ast.Node{cacheFn: fnDecl},
	}
	localIdx := &pkgIndex{pkg: &packages.Package{Types: localTypes}, mutable: true, decls: map[types.Object]ast.Node{}}
	a := &tier2Analyzer{
		idxByTypes:  map[*types.Package]*pkgIndex{cacheTypes: cacheIdx, localTypes: localIdx},
		seenObjects: map[types.Object]bool{},
		seenTypes:   map[types.Type]bool{},
		filePkgs:    map[*pkgIndex]bool{},
		scanned:     map[*ssa.Function]bool{},
	}

	a.scanFunction(ssaFn)
	if len(a.objectQueue) != 1 || a.objectQueue[0] != localObj {
		t.Fatalf("cache function body queue = %v, want localdep.C", a.objectQueue)
	}
}

func TestTier2CacheInitTraversesMutableReference(t *testing.T) {
	cacheTypes := types.NewPackage("example.com/cachedep", "cachedep")
	localTypes := types.NewPackage("example.com/localdep", "localdep")
	localObj := types.NewConst(token.NoPos, localTypes, "C", types.Typ[types.Int], nil)
	localTypes.Scope().Insert(localObj)
	localIdent := ast.NewIdent("C")
	initDecl := &ast.FuncDecl{
		Name: ast.NewIdent("init"),
		Type: &ast.FuncType{Params: &ast.FieldList{}},
		Body: &ast.BlockStmt{List: []ast.Stmt{&ast.AssignStmt{
			Lhs: []ast.Expr{ast.NewIdent("_")},
			Tok: token.ASSIGN,
			Rhs: []ast.Expr{localIdent},
		}}},
	}
	info := &types.Info{Uses: map[*ast.Ident]types.Object{localIdent: localObj}}
	cacheIdx := &pkgIndex{
		pkg:   &packages.Package{Types: cacheTypes, TypesInfo: info},
		cache: true,
		inits: []ast.Node{initDecl},
	}
	localIdx := &pkgIndex{pkg: &packages.Package{Types: localTypes}, mutable: true, decls: map[types.Object]ast.Node{}}
	a := &tier2Analyzer{
		idxByTypes:  map[*types.Package]*pkgIndex{cacheTypes: cacheIdx, localTypes: localIdx},
		seenObjects: map[types.Object]bool{},
		seenTypes:   map[types.Type]bool{},
		filePkgs:    map[*pkgIndex]bool{},
		scanned:     map[*ssa.Function]bool{},
	}

	a.scanFunction(&ssa.Function{Synthetic: "package initializer", Pkg: &ssa.Package{Pkg: cacheTypes}, Blocks: []*ssa.BasicBlock{{}}})
	if len(a.objectQueue) != 1 || a.objectQueue[0] != localObj {
		t.Fatalf("cache init body queue = %v, want localdep.C", a.objectQueue)
	}
}

func TestImportBindingAnalyzesWithoutWiden(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/importbinding"
	tr, err := computeTier2Result(h, pkg, "BenchmarkImportBinding")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if tr.widen {
		t.Fatalf("import binding fixture widened unexpectedly: %+v", tr)
	}
}

func TestTier2ASMTargetInterfaceInvokeWidens(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/asminvoke"
	tr, err := computeTier2Result(h, pkg, "BenchmarkASMInvoke")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !tr.widen {
		t.Fatalf("widen = false, want post-RTA interface dispatch or computed-call widening")
	}
}

func TestTier2GenericPostRTAInvokeWidens(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/genericpostrta"
	tr, err := computeTier2Result(h, pkg, "BenchmarkGenericPostRTA")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !tr.widen {
		t.Fatalf("widen = false, want generic post-RTA dispatch widening")
	}
}

func TestTier2ReflectReferenceScansClassB(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/reflectexternal"
	tr, err := computeTier2Result(h, pkg, "BenchmarkReflectExternal")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if !tr.unverifiable || !strings.Contains(tr.reason, "file I/O") {
		t.Fatalf("reflect target Class-B = %v/%q, want file I/O", tr.unverifiable, tr.reason)
	}
}

func TestUnverifiableReasonSelectionIsDeterministic(t *testing.T) {
	effects := []externalEffect{
		symbolExternalEffect(externalEffectFormattedOutput, "fmt", "Print", "reaches fmt.Print (formatted output)"),
		symbolExternalEffect(externalEffectNetwork, "net", "Dial", "reaches net.Dial (network I/O)"),
		symbolExternalEffect(externalEffectFileIO, "os", "ReadFile", "reaches os.ReadFile (file I/O)"),
	}
	first := &tier2Analyzer{}
	for _, effect := range effects {
		first.recordExternalEffect(effect)
	}
	second := &tier2Analyzer{}
	for i := len(effects) - 1; i >= 0; i-- {
		second.recordExternalEffect(effects[i])
	}
	if first.selected.reason != second.selected.reason {
		t.Fatalf("unverifiable reason depends on traversal order: %q != %q", first.selected.reason, second.selected.reason)
	}
	if !strings.Contains(first.selected.reason, "network I/O") {
		t.Fatalf("legacy reason = %q, want the top-ranked network cause", first.selected.reason)
	}
}

// TestEffectCauseRankStrata pins the cause-preference strata boundaries
// themselves — a flatten of any adjacent pair is a diagnostic-semantics
// change that owes an ObservationRTA bump, so it must fail here rather
// than pass silently.
func TestEffectCauseRankStrata(t *testing.T) {
	mutation := symbolExternalEffect(externalEffectPathMutation, "os", "Remove", "reaches os.Remove (path mutation)")
	read := symbolExternalEffect(externalEffectFileIO, "os", "ReadFile", "reaches os.ReadFile (file I/O)")
	output := symbolExternalEffect(externalEffectFormattedOutput, "fmt", "Print", "reaches fmt.Print (formatted output)")
	unaudited := symbolExternalEffect(externalEffectUnauditedStandard, "time", "Now", "reaches unaudited standard operation time.Now")
	harness := harnessLoggingEffect("Log")
	ordered := []externalEffect{mutation, read, output, unaudited, harness}
	for i := 0; i+1 < len(ordered); i++ {
		if effectCauseRank(ordered[i]) <= effectCauseRank(ordered[i+1]) {
			t.Errorf("effectCauseRank(%s) = %d, want above %s (%d)", ordered[i].reason, effectCauseRank(ordered[i]), ordered[i+1].reason, effectCauseRank(ordered[i+1]))
		}
	}
	// The strata drive the legacy projection end to end: a generic read
	// outranks ambient output and the unaudited classification.
	a := &tier2Analyzer{}
	for _, effect := range []externalEffect{unaudited, output, read} {
		a.recordExternalEffect(effect)
	}
	if !strings.Contains(a.selected.reason, "file I/O") {
		t.Fatalf("legacy reason = %q, want the file I/O cause over output and unaudited", a.selected.reason)
	}
	b := &tier2Analyzer{}
	for _, effect := range []externalEffect{unaudited, output} {
		b.recordExternalEffect(effect)
	}
	if !strings.Contains(b.selected.reason, "formatted output") {
		t.Fatalf("legacy reason = %q, want the formatted-output cause over unaudited", b.selected.reason)
	}
}

func TestTypedEffectsAreCompleteAndDiagnosticSelectionIsDeterministic(t *testing.T) {
	effects := []externalEffect{
		symbolExternalEffect(externalEffectFormattedOutput, "fmt", "Print", "reaches fmt.Print (formatted output)"),
		symbolExternalEffect(externalEffectNetwork, "net", "Dial", "reaches net.Dial (network I/O)"),
		symbolExternalEffect(externalEffectFileIO, "os", "ReadFile", "reaches os.ReadFile (file I/O)"),
	}
	first := &tier2Analyzer{}
	for _, effect := range effects {
		first.recordExternalEffect(effect)
	}
	second := &tier2Analyzer{}
	for i := len(effects) - 1; i >= 0; i-- {
		second.recordExternalEffect(effects[i])
	}
	if first.selected.reason != second.selected.reason {
		t.Fatalf("typed effect diagnostic depends on traversal order: %q != %q", first.selected.reason, second.selected.reason)
	}
	if len(first.effects) != len(effects) || len(second.effects) != len(effects) {
		t.Fatalf("typed effects lost: first=%+v second=%+v", first.effects, second.effects)
	}
	for _, want := range effects {
		for _, got := range [][]externalEffect{first.effects, second.effects} {
			found := false
			for _, effect := range got {
				found = found || effect == want
			}
			if !found {
				t.Errorf("missing typed effect %+v from %+v", want, got)
			}
		}
	}
}

func TestPreferredDiagnosticProjectsAfterSecondaryEffectDeduplication(t *testing.T) {
	rdtsc := opaqueExternalEffect(externalEffectNative, "reaches assembly instruction RDTSC (external runtime state)")
	cpuid := opaqueExternalEffect(externalEffectNative, "reaches assembly instruction CPUID (external runtime state)")
	analyzer := &tier2Analyzer{}
	analyzer.recordExternalEffect(rdtsc)
	analyzer.collectExternalEffect(cpuid)
	analyzer.recordExternalEffect(cpuid)
	if analyzer.selected.reason != cpuid.reason {
		t.Fatalf("preferred diagnostic = %q, want later package preference %q", analyzer.selected.reason, cpuid.reason)
	}
	if len(analyzer.effects) != 2 {
		t.Fatalf("deduplicated effects = %+v, want two", analyzer.effects)
	}
}

func TestStandardLinknameTargetIsUnverifiable(t *testing.T) {
	for _, target := range []string{"runtime.nanotime", "sync.runtime_procPin"} {
		analyzer := &tier2Analyzer{objByName: map[string]types.Object{}}
		analyzer.addLinknameTarget(target)
		if !analyzer.unverifiable || !strings.Contains(analyzer.selected.reason, target) {
			t.Fatalf("standard linkname target %s disposition = %v/%q, want unverifiable", target, analyzer.unverifiable, analyzer.selected.reason)
		}
	}
}

func TestUnsafePointerBasicTypeIsDetected(t *testing.T) {
	if !typeUsesUnsafePointer(types.Typ[types.UnsafePointer]) {
		t.Fatal("unsafe.Pointer basic type was not detected")
	}
}

func TestLinknameLocalTargetResolvesWithoutWiden(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/linknamelocal/bench"
	tr, err := computeTier2Result(h, pkg, "BenchmarkLinknameLocal")
	if err != nil {
		t.Fatalf("analysis: %v", err)
	}
	if tr.widen {
		t.Fatalf("locally resolvable linkname widened: %+v", tr)
	}
}

func TestTier2ReverseLinknameTargetEnqueued(t *testing.T) {
	upperTypes := types.NewPackage("example.com/upper", "upper")
	lowerTypes := types.NewPackage("example.com/lower", "lower")
	upperG := types.NewFunc(token.NoPos, upperTypes, "g", types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false))
	lowerF := types.NewFunc(token.NoPos, lowerTypes, "f", types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false))
	upperTypes.Scope().Insert(upperG)
	lowerTypes.Scope().Insert(lowerF)
	upperIdx := &pkgIndex{pkg: &packages.Package{Types: upperTypes}, mutable: true, decls: map[types.Object]ast.Node{upperG: &ast.FuncDecl{Name: ast.NewIdent("g")}}}
	lowerIdx := &pkgIndex{pkg: &packages.Package{Types: lowerTypes}, mutable: true, decls: map[types.Object]ast.Node{lowerF: &ast.FuncDecl{Name: ast.NewIdent("f")}}, linknames: map[types.Object]string{lowerF: "example.com/upper.g"}}
	a := &tier2Analyzer{
		prog:             &program{Prog: ssa.NewProgram(token.NewFileSet(), ssa.InstantiateGenerics)},
		idxByTypes:       map[*types.Package]*pkgIndex{upperTypes: upperIdx, lowerTypes: lowerIdx},
		objsByLinkTarget: map[string][]types.Object{},
		seenObjects:      map[types.Object]bool{},
		seenTypes:        map[types.Type]bool{},
		filePkgs:         map[*pkgIndex]bool{},
	}
	a.addReverseLinkname("example.com/upper.g", lowerF)

	a.addObject(upperG)
	if len(a.objectQueue) != 1 || a.objectQueue[0] != lowerF {
		t.Fatalf("reverse linkname queue = %v, want lower.f", a.objectQueue)
	}
}

func TestBuildIndexVarLinknameHashesGenDeclDoc(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.go")
	const source = `package p

//go:linkname linked example.com/cachedep.A
var linked int
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, source, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	typesPkg, err := new(types.Config).Check("example.com/p", fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatalf("type check: %v", err)
	}
	a := &tier2Analyzer{
		h:          &Hasher{},
		prog:       &program{Prog: ssa.NewProgram(fset, ssa.InstantiateGenerics)},
		metaByPath: map[string]*listPkg{},
	}
	idx := a.buildIndex(&packages.Package{ID: "example.com/p", PkgPath: "example.com/p", Dir: dir, Types: typesPkg, TypesInfo: info, Syntax: []*ast.File{file}})
	obj := typesPkg.Scope().Lookup("linked")
	if obj == nil {
		t.Fatal("linked object missing")
	}
	if got := idx.linknames[obj]; got != "example.com/cachedep.A" {
		t.Fatalf("linkname target = %q, want example.com/cachedep.A", got)
	}
	if _, ok := idx.decls[obj].(*ast.GenDecl); !ok {
		t.Fatalf("linked var declaration node = %T, want *ast.GenDecl to include directive doc", idx.decls[obj])
	}
}

func TestBenchmarkRootScopedToTargetPackage(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/rootcollision/bench"
	supplyRegisteredFixtures(t, h, pkg)
	prog, err := h.loadCached(pkg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Both packages declare a BenchmarkSame; the subject must root at the
	// target package's own benchmark, never the recompiled dependency's.
	root := prog.Roots["BenchmarkSame"]
	if root == nil || !strings.Contains(root.String(), "rootcollision/bench") {
		t.Fatalf("BenchmarkSame root = %v, want the target package's own benchmark", root)
	}
	if strings.Contains(root.String(), "rootcollision/dep") {
		t.Fatalf("BenchmarkSame rooted at the dependency's benchmark: %v", root)
	}
}

// The rooted-flow inventory runs under the analysis context its caller
// passes — the budget-bounded one — and a context that ends during the
// pass ends it with the context's error while memoizing no load
// failure: the next analysis under a live context loads again
// (REQ-closure-shared-dynamic-state-reachability's budget sentence).
func TestRootedFunctionsUnderAnEndedContextMemoizeNoLoadFailure(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/observable"
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.ComputeRootedFunctions(ended, []Subject{{Package: pkg, Symbol: "TestReadFile"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("ComputeRootedFunctions under an ended context = %v, want context.Canceled", err)
	}
	// The pass's own check returns before any load; the load itself,
	// reached under the ended context, fails and memoizes nothing.
	if _, err := h.loadCachedContext(ended, pkg); err == nil {
		t.Fatal("a program load under an ended context succeeded")
	}
	if _, memoized := h.progErrs[pkg]; memoized {
		t.Fatal("the ended context's load failure was memoized — a later live analysis would inherit the cut")
	}
	// The reachability itself reads the caller's context, not the
	// Hasher's: with the program already loaded (the load's own context
	// reads would count too), a counting context sees the traversal's
	// checks beyond the pass's own two and the trailing one, so a reach
	// bound to the Hasher's context would leave the count at three.
	supplyRegisteredFixtures(t, h, pkg)
	if _, err := h.loadCached(pkg); err != nil {
		t.Fatal(err)
	}
	counting := &countingContext{Context: h.ctx}
	rooted, err := h.ComputeRootedFunctions(counting, []Subject{{Package: pkg, Symbol: "TestReadFile"}})
	if err != nil {
		t.Fatalf("the live analysis after a cut failed: %v", err)
	}
	if proof := rooted[Subject{Package: pkg, Symbol: "TestReadFile"}]; !proof.Complete {
		t.Fatalf("the live analysis after a cut granted no inventory: %+v", proof)
	}
	if counting.calls <= 3 {
		t.Fatalf("the reachability read the caller's context %d times — the pass's own checks alone; the traversal ran under another context", counting.calls)
	}
}

// countingContext counts its Err reads; it never ends.
type countingContext struct {
	context.Context
	calls int
}

func (c *countingContext) Err() error {
	c.calls++
	return c.Context.Err()
}

// The rooted-flow inventory releases each package group's whole-program
// SSA at the end of that group — never across groups, so peak memory
// does not grow with the pass's package count — and holds none when the
// pass returns (REQ-closure-shared-dynamic-state-reachability).
func TestRootedFunctionsReleaseEachGroupsProgram(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	const first = "github.com/greatliontech/gofresh/internal/closure/testdata/observable"
	const second = "github.com/greatliontech/gofresh/internal/closure/testdata/observablebad"
	supplyRegisteredFixtures(t, h, first)
	var retainedAtSecondLoad int
	h.OnProgress(func(phase, pkgPath string) {
		if phase == "load" && pkgPath == second {
			retainedAtSecondLoad = len(h.progs)
		}
	})
	rooted, err := h.ComputeRootedFunctions(h.ctx, []Subject{{Package: first, Symbol: "TestReadFile"}, {Package: second, Symbol: "TestOpenStat"}})
	if err != nil {
		t.Fatal(err)
	}
	if !rooted[Subject{Package: first, Symbol: "TestReadFile"}].Complete || !rooted[Subject{Package: second, Symbol: "TestOpenStat"}].Complete {
		t.Fatalf("inventories incomplete: %+v", rooted)
	}
	if retainedAtSecondLoad != 0 {
		t.Fatalf("the first group's program was still held when the second loaded (%d retained) — programs are released per group", retainedAtSecondLoad)
	}
	if len(h.progs) != 0 {
		t.Fatalf("%d programs retained after the pass", len(h.progs))
	}
}

// The binary inventory releases a package's program on every exit of
// the package — the tombstoned-root exit included, where the inventory
// is incomplete and no per-root pass ran to release it
// (REQ-closure-shared-dynamic-state-reachability).
func TestBinaryRootedFunctionsReleaseThePackagesProgram(t *testing.T) {
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	const ambiguous = "github.com/greatliontech/gofresh/internal/closure/testdata/ambiguousroot"
	supplyRegisteredFixtures(t, h, ambiguous)
	inventories, err := h.ComputeBinaryRootedFunctions(h.ctx, []string{ambiguous})
	if err != nil {
		t.Fatal(err)
	}
	if inventories[ambiguous].Complete {
		t.Fatalf("an ambiguous harness root granted an inventory: %+v", inventories[ambiguous])
	}
	if len(h.progs) != 0 {
		t.Fatalf("%d programs retained after the incomplete exit", len(h.progs))
	}
}

func TestWalkDynamicCarrierPolicies(t *testing.T) {
	const src = `package p
type Fn func()
type FnStruct struct{ f func() }
type FnArray [1]func()
type ErrStruct struct{ err error }
type Node struct {
	fn   func()
	next *Node
}
type Tree struct {
	fn       func()
	children []Tree
}
type ScalarNode struct {
	x    int
	next *ScalarNode
}
type ScalarChan chan int
type FnChan chan func()
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	conf := types.Config{}
	pkg, err := conf.Check("example/p", fset, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name                      string
		wantClosure, wantConsumer bool
		wantAlias                 bool
	}{
		{name: "Fn", wantClosure: true, wantConsumer: true, wantAlias: false},
		{name: "FnStruct", wantClosure: true, wantConsumer: true, wantAlias: false},
		{name: "FnArray", wantClosure: true, wantConsumer: true, wantAlias: false},
		{name: "ErrStruct", wantClosure: true, wantConsumer: true, wantAlias: true},
		{name: "Node", wantClosure: true, wantConsumer: true, wantAlias: true},
		{name: "Tree", wantClosure: true, wantConsumer: true, wantAlias: true},
		{name: "ScalarNode", wantClosure: false, wantConsumer: false, wantAlias: false},
		{name: "ScalarChan", wantClosure: false, wantConsumer: false, wantAlias: false},
		{name: "FnChan", wantClosure: true, wantConsumer: true, wantAlias: true},
	}
	for _, tc := range cases {
		typ := pkg.Scope().Lookup(tc.name).Type()
		for _, p := range []struct {
			name   string
			policy refconfine.CarrierWalkPolicy
			want   bool
		}{
			{"Closure", refconfine.CarrierPolicyClosure, tc.wantClosure},
			{"Consumer", refconfine.CarrierPolicyConsumer, tc.wantConsumer},
			{"Alias", refconfine.CarrierPolicyAlias, tc.wantAlias},
		} {
			if got := refconfine.WalkDynamicCarrier(true, typ, make(map[types.Type]bool), p.policy); got != p.want {
				t.Errorf("WalkDynamicCarrier(%s, %s) = %v, want %v", tc.name, p.name, got, p.want)
			}
		}
	}
}

func TestClosedInvokeTargetsAndStaticCallReturnWalk(t *testing.T) {
	const src = `package p

type I interface {
	Do() int
}

type goodImpl struct{}
func (goodImpl) Do() int { return 1 }

type badImpl struct{}
func (badImpl) Do() int { return 2 }

func newGood() I {
	return goodImpl{}
}

func seqOf(a, b int) func(func(int) bool) {
	return func(yield func(int) bool) {
		if !yield(a) {
			return
		}
		yield(b)
	}
}

func UseGood() int {
	var _ I = badImpl{}
	var i I = goodImpl{}
	return i.Do()
}

func UseStaticHelper() int {
	var _ I = badImpl{}
	h := newGood()
	return h.Do()
}

func UseIterator() int {
	sum := 0
	for x := range seqOf(1, 2) {
		sum += x
	}
	return sum
}

func UseOpen(i I) int {
	return i.Do()
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	typesPkg, err := (&types.Config{}).Check("strings", fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatal(err)
	}
	ssaProg := ssa.NewProgram(fset, ssa.InstantiateGenerics)
	ssaPkg := ssaProg.CreatePackage(typesPkg, []*ast.File{file}, info, true)
	ssaPkg.Build()
	fp := newBitOnlyFreshParamAnalysis(false, true, nil, nil, nil, nil)

	firstCallSite := func(fnName string, invoke bool) ssa.CallInstruction {
		fn := ssaPkg.Func(fnName)
		if fn == nil {
			t.Fatalf("missing function %s", fnName)
		}
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				site, ok := instr.(ssa.CallInstruction)
				if !ok {
					continue
				}
				if site.Common().IsInvoke() == invoke {
					return site
				}
			}
		}
		t.Fatalf("no matching call site in %s", fnName)
		return nil
	}

	for _, fnName := range []string{"UseGood", "UseStaticHelper"} {
		site := firstCallSite(fnName, true)
		targets, ok := closedInvokeTargets(site, fp)
		var only *ssa.Function
		for fn := range targets {
			only = fn
		}
		if !ok || len(targets) != 1 || only.Name() != "Do" || !strings.Contains(only.String(), "goodImpl") {
			t.Fatalf("%s closedInvokeTargets = (%v, %v), want [(goodImpl).Do]", fnName, targets, ok)
		}
	}

	openSite := firstCallSite("UseOpen", true)
	if targets, ok := closedInvokeTargets(openSite, fp); ok {
		t.Fatalf("UseOpen closedInvokeTargets = (%v, true), want false for open parameter", targets)
	}

	// Range-over-func calls the iterator returned by seqOf(1, 2): the second
	// static/dynamic call instruction in UseIterator is the computed call to
	// the returned iterator closure.
	iterFn := ssaPkg.Func("UseIterator")
	var computedSite ssa.CallInstruction
	for _, b := range iterFn.Blocks {
		for _, instr := range b.Instrs {
			site, ok := instr.(ssa.CallInstruction)
			if ok && site.Common().StaticCallee() == nil {
				computedSite = site
			}
		}
	}
	if computedSite == nil {
		t.Fatal("missing computed iterator call in UseIterator")
	}
	targets, ok := closedDynamicTargets(computedSite.Common().Value, fp)
	var onlyIter *ssa.Function
	for fn := range targets {
		onlyIter = fn
	}
	if !ok || len(targets) != 1 || !strings.Contains(onlyIter.Name(), "seqOf$") {
		t.Fatalf("UseIterator closedDynamicTargets = (%v, %v), want [seqOf$1]", targets, ok)
	}

	// Non-standard package calls (when isStd returns false) must NOT be
	// traversed by staticCallResultDynamicValue.
	userFP := newBitOnlyFreshParamAnalysis(false, true, nil, nil, nil, func(*ssa.Function) bool { return false })
	if targets, ok := closedInvokeTargets(firstCallSite("UseStaticHelper", true), userFP); ok {
		t.Fatalf("non-std UseStaticHelper closedInvokeTargets = (%v, true), want false", targets)
	}
}

func TestCachedDependencyNestedClosureWalked(t *testing.T) {
	const src = `package dep

var Captured = 1

func Outer() int {
	fn := func() int {
		return Captured
	}
	return fn()
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "dep.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	typesPkg, err := (&types.Config{}).Check("example.com/dep", fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatal(err)
	}
	ssaProg := ssa.NewProgram(fset, ssa.InstantiateGenerics)
	ssaPkg := ssaProg.CreatePackage(typesPkg, []*ast.File{file}, info, true)
	ssaPkg.Build()

	depIdx := &pkgIndex{
		pkg:       &packages.Package{ID: "example.com/dep", PkgPath: "example.com/dep", Types: typesPkg, TypesInfo: info, Syntax: []*ast.File{file}},
		cache:     true,
		decls:     map[types.Object]ast.Node{},
		linknames: map[types.Object]string{},
	}
	a := &tier2Analyzer{
		h:           &Hasher{},
		prog:        &program{Prog: ssaProg},
		idxByTypes:  map[*types.Package]*pkgIndex{typesPkg: depIdx},
		seenObjects: map[types.Object]bool{},
		seenTypes:   map[types.Type]bool{},
		filePkgs:    map[*pkgIndex]bool{},
		rtaReach:    map[*ssa.Function]bool{},
		scanned:     map[*ssa.Function]bool{},
	}
	outerFn := ssaPkg.Func("Outer")
	if len(outerFn.AnonFuncs) != 1 {
		t.Fatalf("Outer.AnonFuncs = %d, want 1", len(outerFn.AnonFuncs))
	}
	anonFn := outerFn.AnonFuncs[0]
	a.addFunction(anonFn)
	if !a.scanned[anonFn] {
		t.Fatal("cached dependency anonymous closure was skipped by addFunction instead of scanning its SSA body")
	}
}

func TestWalkCellReferrersStructAndArrayCells(t *testing.T) {
	const src = `package p

func UseStructCell() int {
	var s struct {
		fn    func() int
		other any
	}
	s.fn = func() int { return 7 }
	s.other = "unrelated"
	return s.fn()
}

func UseArrayCell() int {
	var a [1]func() int
	a[0] = func() int { return 9 }
	return a[0]()
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	typesPkg, err := (&types.Config{}).Check("example.com/p", fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatal(err)
	}
	ssaProg := ssa.NewProgram(fset, ssa.InstantiateGenerics)
	ssaPkg := ssaProg.CreatePackage(typesPkg, []*ast.File{file}, info, true)
	ssaPkg.Build()
	fp := newBitOnlyFreshParamAnalysis(false, true, nil, nil, nil, nil)

	for _, fnName := range []string{"UseStructCell", "UseArrayCell"} {
		fn := ssaPkg.Func(fnName)
		if fn == nil {
			t.Fatalf("missing function %s", fnName)
		}
		var computedSite ssa.CallInstruction
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				site, ok := instr.(ssa.CallInstruction)
				if ok && site.Common().StaticCallee() == nil {
					computedSite = site
				}
			}
		}
		if computedSite == nil {
			t.Fatalf("missing computed call in %s", fnName)
		}
		targets, ok := closedDynamicTargets(computedSite.Common().Value, fp)
		if !ok || len(targets) != 1 {
			t.Fatalf("%s closedDynamicTargets = (%v, %v), want 1 closed target", fnName, targets, ok)
		}
	}
}

func TestStandardSentinelGlobalsAndContextObservability(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(rel, content string) {
		t.Helper()
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("go.mod", "module example.com/ctxdiscard\n\ngo 1.24\n")
	writeFile("service_test.go", `package ctxdiscard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
)

func runService(ctx context.Context, w io.Writer) error {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ctx.Err()
	}
	if _, err := fmt.Fprintln(w, "pkt"); err != nil {
		return err
	}
	_, err := w.Write([]byte("ok"))
	return err
}

func TestServiceWithCancelAndDiscard(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runService(ctx, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkSubService(b *testing.B) {
	b.Run("sub", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err := runService(context.TODO(), io.Discard); err != nil {
				b.Fatal(err)
			}
		}
	})
}
`)
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "example.com/ctxdiscard"
	subjects := []Subject{
		{Package: pkg, Symbol: "runService"},
		{Package: pkg, Symbol: "TestServiceWithCancelAndDiscard"},
		{Package: pkg, Symbol: "BenchmarkSubService"},
	}
	got, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range subjects {
		obs := got[s]
		if !obs.Observable {
			t.Errorf("%s.%s Observable = false (Reason = %q), want true", s.Package, s.Symbol, obs.Reason)
		}
	}

	// Mutating io.Discard in the program must invalidate the sentinel-global
	// admission and fail closed.
	writeFile("mutate_test.go", `package ctxdiscard

import (
	"io"
	"os"
	"testing"
)

type fileWriter struct{}

func (fileWriter) Write(p []byte) (int, error) {
	return len(p), os.WriteFile("out.txt", p, 0o600)
}

func TestMutatedDiscardRefused(t *testing.T) {
	io.Discard = fileWriter{}
	if err := runService(nil, io.Discard); err != nil {
		t.Fatal(err)
	}
}
`)
	hMut, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	gotMut, err := hMut.ComputeObservabilityBatch([]Subject{{Package: pkg, Symbol: "TestServiceWithCancelAndDiscard"}})
	if err != nil {
		t.Fatal(err)
	}
	if obs := gotMut[Subject{Package: pkg, Symbol: "TestServiceWithCancelAndDiscard"}]; obs.Observable {
		t.Fatalf("TestServiceWithCancelAndDiscard Observable = true when sibling mutates io.Discard, want false")
	}
}

func TestStructReceiverEnumerationAndSha1Pacing(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(rel, content string) {
		t.Helper()
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("go.mod", "module example.com/operr\n\ngo 1.24\n")
	writeFile("operr.go", `package operr

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
)

type CanceledError struct {
	Subject   string
	SignalErr error
}

func (e *CanceledError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return "canceled: " + e.Subject
}

func (e *CanceledError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.SignalErr
}

type CallbackFailedError struct {
	Callback string
	Cause    error
}

func (e *CallbackFailedError) Error() string {
	return fmt.Sprintf("callback %q failed: %v", e.Callback, e.Cause)
}

func CheckCancel(ctx context.Context, subject string) error {
	if ctx == nil {
		panic("nil context")
	}
	if err := ctx.Err(); err != nil {
		return &CanceledError{Subject: subject, SignalErr: err}
	}
	return nil
}

func SumSHA1(data []byte) [20]byte {
	h := sha1.New()
	_, _ = h.Write(data)
	var out [20]byte
	copy(out[:], h.Sum(nil))
	return out
}

func SumSHA256(data []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
`)
	writeFile("operr_test.go", `package operr

import (
	"context"
	"errors"
	"testing"
)

func TestCheckCancelAndErrorMethods(t *testing.T) {
	if err := CheckCancel(context.Background(), "op"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := CheckCancel(ctx, "op")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	if err.Error() == "" {
		t.Fatal("empty error string")
	}
	cbErr := &CallbackFailedError{Callback: "visit", Cause: errors.New("boom")}
	if cbErr.Error() == "" {
		t.Fatal("empty callback error string")
	}
	defer func() {
		if r := recover(); r != "nil context" {
			t.Fatalf("recover = %v, want nil context", r)
		}
	}()
	_ = CheckCancel(nil, "op")
}

func BenchmarkSumSHA1(b *testing.B) {
	payload := []byte("hello")
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		_ = SumSHA1(payload)
		_ = SumSHA256(payload)
	}
}
`)
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "example.com/operr"
	subjects := []Subject{
		{Package: pkg, Symbol: "CanceledError.Error"},
		{Package: pkg, Symbol: "CanceledError.Unwrap"},
		{Package: pkg, Symbol: "CallbackFailedError.Error"},
		{Package: pkg, Symbol: "CheckCancel"},
		{Package: pkg, Symbol: "SumSHA1"},
		{Package: pkg, Symbol: "SumSHA256"},
		{Package: pkg, Symbol: "TestCheckCancelAndErrorMethods"},
		{Package: pkg, Symbol: "BenchmarkSumSHA1"},
	}
	got, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range subjects {
		obs := got[s]
		if !obs.Observable {
			t.Errorf("%s.%s Observable = false (Reason = %q), want true", s.Package, s.Symbol, obs.Reason)
		}
	}
}

func TestSubjectScopedMaximalScanAndTestingContext(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(rel, content string) {
		t.Helper()
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("go.mod", "module example.com/scoped\n\ngo 1.26\n")
	writeFile("clean/clean.go", `package clean

import (
	"bytes"
	"context"
	"os"
	"os/exec"
)

func PureWithContext(ctx context.Context, s string) (string, error) {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := cctx.Err(); err != nil {
		return "", err
	}
	return s + "!", nil
}

func UnreachedExec() error {
	var buf bytes.Buffer
	cmd := exec.Command("git", "status")
	cmd.Stdout = &buf
	if err := os.RemoveAll("/tmp/nonexistent-gofresh-test"); err != nil {
		return err
	}
	return cmd.Run()
}
`)
	writeFile("clean/clean_test.go", `package clean

import "testing"

func checkTBContext(tb testing.TB) {
	if err := tb.Context().Err(); err != nil {
		tb.Fatalf("unexpected context err: %v", err)
	}
}

func TestPureWithContext(t *testing.T) {
	got, err := PureWithContext(t.Context(), "hi")
	if err != nil || got != "hi!" {
		t.Fatalf("got (%q, %v)", got, err)
	}
	checkTBContext(t)
}

func BenchmarkPureWithContext(b *testing.B) {
	for b.Loop() {
		_, _ = PureWithContext(b.Context(), "bench")
	}
}

func TestUnreachedIntegration(t *testing.T) {
	_ = t.TempDir()
	_ = UnreachedExec()
}
`)
	writeFile("hazards/setenv.go", `package hazards

import "os"

func Pure() int { return 42 }

func UnreachedSetenv() {
	_ = os.Setenv("X", "1")
}
`)
	writeFile("exitpkg/exitpkg.go", `package exitpkg

import "os"

func Pure() int { return 42 }

func UnreachedExit() {
	os.Exit(1)
}
`)
	writeFile("genmethod/genmethod.go", `package genmethod

import "math/rand/v2"

type Runner interface {
	run() int
}

type Box[T any] struct {
	V T
}

func (b Box[T]) run() int {
	return rand.IntN(10)
}

func MakeRunner() Runner {
	return Box[int]{V: 1}
}
`)
	writeFile("customtb/customtb_test.go", `package customtb

import (
	"context"
	"testing"
)

var ambientCtx context.Context

type fakeTB struct {
	testing.TB
}

func (fakeTB) Context() context.Context {
	return ambientCtx
}

func TestCustomTBContextRefused(t *testing.T) {
	var tb testing.TB = fakeTB{TB: t}
	_ = tb.Context().Err()
}
`)
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{
		{Package: "example.com/scoped/clean", Symbol: "PureWithContext"},
		{Package: "example.com/scoped/clean", Symbol: "TestPureWithContext"},
		{Package: "example.com/scoped/clean", Symbol: "BenchmarkPureWithContext"},
		{Package: "example.com/scoped/clean", Symbol: "UnreachedExec"},
		{Package: "example.com/scoped/clean", Symbol: "TestUnreachedIntegration"},
		{Package: "example.com/scoped/hazards", Symbol: "Pure"},
		{Package: "example.com/scoped/exitpkg", Symbol: "Pure"},
		{Package: "example.com/scoped/genmethod", Symbol: "MakeRunner"},
		{Package: "example.com/scoped/customtb", Symbol: "TestCustomTBContextRefused"},
	}
	got, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, sym := range []string{"PureWithContext", "TestPureWithContext", "BenchmarkPureWithContext"} {
		s := Subject{Package: "example.com/scoped/clean", Symbol: sym}
		if obs := got[s]; !obs.Observable {
			t.Errorf("%s.%s Observable = false (Reason = %q), want true", s.Package, s.Symbol, obs.Reason)
		}
	}
	for _, tc := range []struct {
		pkg, sym, wantReason string
	}{
		{"example.com/scoped/clean", "UnreachedExec", "unsafe pointer reachable"},
		{"example.com/scoped/clean", "TestUnreachedIntegration", "unsafe pointer reachable"},
		{"example.com/scoped/hazards", "Pure", "package scan: reaches unaudited standard operation os.Setenv"},
		{"example.com/scoped/exitpkg", "Pure", "package scan: reaches unaudited standard operation os.Exit"},
		{"example.com/scoped/genmethod", "MakeRunner", "package scan: reaches unaudited standard operation math/rand/v2.IntN"},
		{"example.com/scoped/customtb", "TestCustomTBContextRefused", "interface invoke outside RTA: example.com/scoped/customtb.TestCustomTBContextRefused dispatches context.Context.Err"},
	} {
		s := Subject{Package: tc.pkg, Symbol: tc.sym}
		if obs := got[s]; obs.Observable || !strings.Contains(obs.Reason, tc.wantReason) {
			t.Errorf("%s.%s = %+v, want Observable=false Reason containing %q", tc.pkg, tc.sym, obs, tc.wantReason)
		}
	}
}

func TestSubjectScopedTypeConstAndExpandedAuditedSurface(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(rel, content string) {
		t.Helper()
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("go.mod", "module example.com/expanded\n\ngo 1.24\n")
	writeFile("surface/surface.go", `package surface

import (
	"bytes"
	"crypto/fips140"
	"encoding/binary"
	"io"
	"io/fs"
	"math"
	"math/rand"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type unusedZipfHolder struct {
	z *rand.Zipf
}

const unusedFileMode = os.ModeDir

type reachedZipfHolder struct {
	z *rand.Zipf
}

const reachedFileMode = os.ModeDir

func UseReachedType() int {
	var h reachedZipfHolder
	if h.z != nil {
		return 1
	}
	return 0
}

func UseReachedConst() int {
	return int(reachedFileMode)
}

type Item interface {
	Value() int
}

type concreteItem struct {
	v int
}

func (c concreteItem) Value() int { return c.v }

type promotedItem struct {
	Item
	extra int
}

type impureItem struct{}

func (impureItem) Value() int {
	return len(os.Environ())
}

type badPromotedItem struct {
	Item
}

func MakeBadPromoted() badPromotedItem {
	return badPromotedItem{Item: impureItem{}}
}

func PromotedImpureRefused() int {
	var it Item = badPromotedItem{Item: concreteItem{v: 1}}
	return it.Value()
}

type itemHolder struct {
	Items []Item
}

func sumHolderItems(h *itemHolder) int {
	total := 0
	for _, it := range h.Items {
		total += it.Value()
	}
	return total
}

func joinVariadic(items ...Item) int {
	total := 0
	for _, it := range items {
		total += it.Value()
	}
	return total
}

func PureExpandedSurface() int {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(math.MaxInt32))
	le := binary.LittleEndian.Uint64(buf[:])

	var count atomic.Int64
	count.Add(int64(le & 7))
	var raw int32
	atomic.AddInt32(&raw, 1)

	var mu sync.Mutex
	cond := sync.NewCond(&mu)
	cond.Signal()
	cond.Broadcast()

	var fipsRes int
	fips140.WithoutEnforcement(func() {
		if fips140.Enforced() {
			fipsRes = 1
		}
	})

	mr := io.MultiReader(strings.NewReader("ab"), bytes.NewReader([]byte("cd")))
	var out bytes.Buffer
	mw := io.MultiWriter(&out, io.Discard)
	_, err := io.Copy(mw, mr)
	if err == io.EOF || err == fs.ErrNotExist {
		fipsRes++
	}

	tsUTC := time.Unix(1700000000, 0).UTC().Unix()
	loc := time.FixedZone("UTC+2", 7200)
	tsFixed := time.UnixMilli(1700000000000).In(loc).Unix()

	base := concreteItem{v: int(count.Load()) + int(raw) + fipsRes + out.Len() + int(tsUTC-tsFixed)}
	var captured Item = promotedItem{Item: base, extra: 1}
	readCaptured := func() int {
		return captured.Value()
	}
	boundVal := base.Value

	sliceItems := []Item{base, captured}
	holder := &itemHolder{Items: []Item{base, captured}}
	mapItems := map[string]Item{"k": base}

	return readCaptured() + boundVal() + sliceItems[0].Value() + sumHolderItems(holder) + mapItems["k"].Value() + joinVariadic(base, captured)
}

func EnvObservableNotEffectFree() string {
	return os.Getenv("EXPANDED_SURFACE_ENV")
}

func ImpureFIPSCallback() []string {
	var s []string
	fips140.WithoutEnforcement(func() {
		s = os.Environ()
	})
	return s
}

func BareTimeUnix() time.Time {
	return time.Unix(1700000000, 0)
}

func AtomicValueRefused() any {
	var v atomic.Value
	v.Store(1)
	return v.Load()
}

func AppendInPlaceOverwriteRefused() int {
	s := make([]Item, 1, 2)
	s[0] = concreteItem{v: 1}
	_ = append(s[:0], impureItem{})
	return s[0].Value()
}

func CloneSliceMutatedRefused() int {
	base := []Item{concreteItem{v: 1}}
	cloned := append([]Item(nil), base...)
	cloned[0] = impureItem{}
	return cloned[0].Value()
}

func CellSliceCopyOverwriteRefused() int {
	var s []Item
	keepInCell := func() int { return len(s) }
	s = []Item{concreteItem{v: 1}}
	copy(s, []Item{impureItem{}})
	return s[0].Value() + keepInCell()
}
`)
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{
		{Package: "example.com/expanded/surface", Symbol: "PureExpandedSurface"},
		{Package: "example.com/expanded/surface", Symbol: "EnvObservableNotEffectFree"},
		{Package: "example.com/expanded/surface", Symbol: "UseReachedType"},
		{Package: "example.com/expanded/surface", Symbol: "UseReachedConst"},
		{Package: "example.com/expanded/surface", Symbol: "PromotedImpureRefused"},
		{Package: "example.com/expanded/surface", Symbol: "ImpureFIPSCallback"},
		{Package: "example.com/expanded/surface", Symbol: "BareTimeUnix"},
		{Package: "example.com/expanded/surface", Symbol: "AtomicValueRefused"},
		{Package: "example.com/expanded/surface", Symbol: "AppendInPlaceOverwriteRefused"},
		{Package: "example.com/expanded/surface", Symbol: "CloneSliceMutatedRefused"},
		{Package: "example.com/expanded/surface", Symbol: "CellSliceCopyOverwriteRefused"},
	}
	got, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if obs := got[Subject{Package: "example.com/expanded/surface", Symbol: "PureExpandedSurface"}]; !obs.Observable || !obs.EffectFree {
		t.Errorf("PureExpandedSurface = %+v, want Observable=true EffectFree=true", obs)
	}
	if obs := got[Subject{Package: "example.com/expanded/surface", Symbol: "EnvObservableNotEffectFree"}]; !obs.Observable || obs.EffectFree {
		t.Errorf("EnvObservableNotEffectFree = %+v, want Observable=true EffectFree=false", obs)
	}
	for _, tc := range []struct {
		sym, wantReason string
	}{
		{"UseReachedType", "package scan: reaches unaudited standard operation math/rand.Zipf"},
		{"UseReachedConst", "package scan: reaches unaudited standard operation os.ModeDir"},
		{"PromotedImpureRefused", "reaches os.Environ"},
		{"ImpureFIPSCallback", "reaches os.Environ"},
		{"BareTimeUnix", "package scan: reaches unaudited standard operation time.Unix"},
		{"AtomicValueRefused", "package scan: reaches unaudited standard operation sync/atomic.Value"},
		{"AppendInPlaceOverwriteRefused", "reaches os.Environ"},
		{"CloneSliceMutatedRefused", "reaches os.Environ"},
		{"CellSliceCopyOverwriteRefused", "reaches os.Environ"},
	} {
		s := Subject{Package: "example.com/expanded/surface", Symbol: tc.sym}
		if obs := got[s]; obs.Observable || !strings.Contains(obs.Reason, tc.wantReason) {
			t.Errorf("%s = %+v, want Observable=false Reason containing %q", tc.sym, obs, tc.wantReason)
		}
	}

	writeFile("initunsafe/p.go", `package initunsafe
import "unsafe"
var x int
func init() {
	*(*int)(unsafe.Pointer(&x)) = 1
}
func ReadX() int { return x }
`)
	writeFile("initunsafe/p_test.go", `package initunsafe
import (
	"os"
	"testing"
	"unsafe"
)
var tm int
func TestMain(m *testing.M) {
	*(*int)(unsafe.Pointer(&tm)) = 2
	os.Exit(m.Run())
}
func TestClean(t *testing.T) {}
`)
	primeHasherFromDir(t, h, dir)
	gotUnsafe, err := h.ComputeObservabilityBatch([]Subject{
		{Package: "example.com/expanded/initunsafe", Symbol: "ReadX"},
		{Package: "example.com/expanded/initunsafe", Symbol: "TestClean"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, sym := range []string{"ReadX", "TestClean"} {
		obs := gotUnsafe[Subject{Package: "example.com/expanded/initunsafe", Symbol: sym}]
		if obs.Observable || !strings.Contains(obs.Reason, "unsafe pointer reachable") {
			t.Errorf("%s = %+v, want Observable=false with unsafe pointer reachable", sym, obs)
		}
	}

	rootSep := string(filepath.Separator)
	if !cprep.PathWithin(filepath.Join(rootSep, "tmp", "cfg.h"), rootSep) || !cprep.PathWithin(rootSep, rootSep) {
		t.Fatal("PathWithin must accept paths under the filesystem root")
	}
	for _, src := range []string{
		"package p\nimport \"testing\"\nfunc TestMain[T any](m *testing.M) {}\n",
		"package p\nimport \"testing\"\nfunc TestMain(m *testing.M) int { return 0 }\n",
	} {
		parsed, err := parser.ParseFile(token.NewFileSet(), "p_test.go", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := userTestMainDecl(parsed, map[string]string{"testing": "testing"}); got != nil {
			t.Fatalf("userTestMainDecl(%q) = %v, want nil", src, got)
		}
	}
}

// walkTypeGraph must descend into *types.Tuple so multi-return SSA call
// values (whose Value().Type() is *types.Tuple) have all element types
// visited by poisonContainedTypes, addType, and typeUsesUnsafePointer.
func TestWalkTypeGraphTupleAndMultiReturnBodylessPoisoning(t *testing.T) {
	pkg := types.NewPackage("example.com/tuplepkg", "tuplepkg")
	namedObj := types.NewTypeName(token.NoPos, pkg, "Carrier", nil)
	sig := types.NewSignatureType(nil, nil, nil, nil, types.NewTuple(types.NewVar(token.NoPos, pkg, "", types.Typ[types.Int])), false)
	st := types.NewStruct([]*types.Var{types.NewField(token.NoPos, pkg, "fn", sig, false)}, nil)
	named := types.NewNamed(namedObj, st, nil)
	tuple := types.NewTuple(
		types.NewVar(token.NoPos, pkg, "c", named),
		types.NewVar(token.NoPos, pkg, "p", types.Typ[types.UnsafePointer]),
	)
	visitedNamed := false
	walkTypeGraph(tuple, true, map[types.Type]bool{}, func(t types.Type) bool {
		if t == named {
			visitedNamed = true
		}
		return true
	})
	if !visitedNamed {
		t.Fatal("walkTypeGraph did not visit *types.Named inside *types.Tuple")
	}
	if !typeUsesUnsafePointer(tuple) {
		t.Fatal("typeUsesUnsafePointer(*types.Tuple with unsafe.Pointer) = false, want true")
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/multireturn\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := `package multireturn

import "os"

type Carrier struct {
	fn func() int
}

// Bodyless multi-return declaration: its SSA call value has type *types.Tuple.
func makeCarrier() (Carrier, error)

func impureTarget() int {
	return len(os.Environ())
}

// keepAddressTaken ensures impureTarget is in the RTA address-taken pool for func() int.
var Sink = impureTarget

func UseMultiReturnBodyless() int {
	c, _ := makeCarrier()
	return c.fn()
}
`
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subj := Subject{Package: "example.com/multireturn", Symbol: "UseMultiReturnBodyless"}
	got, err := h.ComputeObservabilityBatch([]Subject{subj})
	if err != nil {
		t.Fatal(err)
	}
	if obs := got[subj]; obs.Observable {
		t.Fatalf("UseMultiReturnBodyless = %+v, want Observable=false (Carrier struct returned in tuple from bodyless call must be poisoned)", obs)
	}
}

func TestClosurePrecisionAndProvenanceFixes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/precision\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := `package precision

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func openReadHelper(t *testing.T, path string) {
	if err := os.WriteFile(path, []byte("abcd"), 0o600); err != nil {
		t.Fatal("write failed")
	}
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal("open failed")
	}
	var buf [4]byte
	if _, err := f.Read(buf[:]); err != nil {
		_ = f.Close()
		t.Fatal("read failed")
	}
	if err := f.Close(); err != nil {
		t.Fatal("close failed")
	}
}

func TestParamBackedOpenFileDominated(t *testing.T) {
	p1 := filepath.Join(t.TempDir(), "data1.txt")
	openReadHelper(t, p1)
}

func openFileNameHelper(path string) string {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	return f.Name()
}

func TestParamBackedFreshOpenFileNameRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "data.txt")
	if err := os.WriteFile(p, []byte("abcd"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = openFileNameHelper(p)
}

func ParseAndFormatNumError(s string) string {
	n, err := strconv.Atoi(s)
	if err != nil {
		u := errors.Unwrap(err)
		if u != nil {
			return err.Error() + ":" + u.Error()
		}
		return err.Error()
	}
	return strconv.Itoa(n)
}

type impureCustomErr struct{}

func (impureCustomErr) Error() string {
	return strconv.Itoa(len(os.Environ()))
}

type impureStringer struct{}

func (impureStringer) String() string {
	return strconv.Itoa(len(os.Environ()))
}

func UnrelatedImpureStringerCaller() string {
	var e error = impureCustomErr{}
	var s interface{ String() string } = impureStringer{}
	return e.Error() + s.String()
}

func PureItoaCaller(x int) string {
	return strconv.Itoa(x)
}

func absWrapper(dir string) (string, error) {
	return filepath.Abs(dir)
}

type absErrHolder struct {
	err error
}

func StoreAbsWrapperError(dir string) absErrHolder {
	_, err := absWrapper(dir)
	return absErrHolder{err: err}
}

func FormatPureHolderError() string {
	h := absErrHolder{err: errors.New("pure")}
	return h.err.Error()
}

func AssertAbsWrapperTimeout() bool {
	h := absErrHolder{err: errors.New("pure")}
	if u, ok := h.err.(interface{ Timeout() bool }); ok {
		return u.Timeout()
	}
	return false
}

type carrierDiamond struct {
	err error
}

func (c *carrierDiamond) checkErr() error {
	if c == nil {
		return nil
	}
	return c.err
}

func cdStep0(c *carrierDiamond) string {
	return cdStep1(c) + cdStep1(c)
}

func cdStep1(c *carrierDiamond) string {
	return cdStep2(c) + cdStep2(c)
}

func cdStep2(c *carrierDiamond) string {
	return cdStep3(c) + cdStep3(c)
}

func cdStep3(c *carrierDiamond) string {
	return cdStep4(c) + cdStep4(c)
}

func cdStep4(c *carrierDiamond) string {
	if err := c.checkErr(); err != nil {
		return err.Error()
	}
	return ""
}

func CarrierDiamondInvoke() string {
	c := &carrierDiamond{err: errors.New("diamond")}
	return cdStep0(c)
}

type carrierCycleStruct struct {
	clean error
	bad   error
}

func stepSliceCycle(xs []*carrierCycleStruct) *carrierCycleStruct {
	return &carrierCycleStruct{clean: xs[0].bad, bad: xs[0].bad}
}

func CarrierCycleSliceUnclosedField(n int) string {
	v := &carrierCycleStruct{clean: errors.New("clean"), bad: impureCustomErr{}}
	for i := 0; i < n; i++ {
		v = stepSliceCycle([]*carrierCycleStruct{v})
	}
	return v.clean.Error()
}
`
	if err := os.WriteFile(filepath.Join(dir, "p_test.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	poisonDir := filepath.Join(dir, "poisonednumerr")
	if err := os.MkdirAll(poisonDir, 0o755); err != nil {
		t.Fatal(err)
	}
	poisonSrc := `package poisonednumerr

import (
	"os"
	"strconv"
)

type envErr struct{}

func (envErr) Error() string {
	return strconv.Itoa(len(os.Environ()))
}

func WrapImpureNumError() string {
	var e error = &strconv.NumError{Func: "Atoi", Num: "x", Err: envErr{}}
	return e.Error()
}
`
	if err := os.WriteFile(filepath.Join(poisonDir, "p.go"), []byte(poisonSrc), 0o600); err != nil {
		t.Fatal(err)
	}

	initFlagDir := filepath.Join(dir, "initflag")
	if err := os.MkdirAll(initFlagDir, 0o755); err != nil {
		t.Fatal(err)
	}
	initFlagSrc := `package initflag

import "io"

type initBoxed struct{ x int }

var boxedSink any
var discardSink io.Writer

func init() {
	boxedSink = initBoxed{x: 1}
	discardSink = io.Discard
}

func PureFn() int { return 1 }
`
	if err := os.WriteFile(filepath.Join(initFlagDir, "p.go"), []byte(initFlagSrc), 0o600); err != nil {
		t.Fatal(err)
	}

	mutatedPathErrDir := filepath.Join(dir, "mutatedpatherr")
	if err := os.MkdirAll(mutatedPathErrDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mutatedPathErrSrc := `package mutatedpatherr

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
)

type envErr struct{}

func (envErr) Error() string {
	return strconv.Itoa(len(os.Environ()))
}

type errHolder struct {
	err error
}

func StoreMutatedAbsError(dir string) errHolder {
	_, err := filepath.Abs(dir)
	if pe, ok := err.(*os.PathError); ok {
		pe.Err = envErr{}
	}
	return errHolder{err: err}
}

func FormatMutatedHolderError() string {
	h := errHolder{err: errors.New("pure")}
	return h.err.Error()
}
`
	if err := os.WriteFile(filepath.Join(mutatedPathErrDir, "p.go"), []byte(mutatedPathErrSrc), 0o600); err != nil {
		t.Fatal(err)
	}

	reflectSCCDir := filepath.Join(dir, "reflectscc")
	if err := os.MkdirAll(reflectSCCDir, 0o755); err != nil {
		t.Fatal(err)
	}
	reflectSCCSrc := `package reflectscc

import (
	"errors"
	"os"
	"reflect"
	"strconv"
)

type envErr struct{}

func (envErr) Error() string {
	return strconv.Itoa(len(os.Environ()))
}

type dummy struct {
	X int
}

type holder struct {
	Err error
}

type nodeA struct{}
type nodeC struct{}

func (a *nodeA) step(n int, h *holder) {
	var d dummy
	_ = reflect.ValueOf(&d)
	if n <= 0 {
		var c nodeC
		c.step(n, h)
		return
	}
	var c nodeC
	c.step(n-1, h)
}

func (c *nodeC) step(n int, h *holder) {
	v := reflect.ValueOf(h)
	if n <= 0 {
		v.Elem().Field(0).Set(reflect.ValueOf(error(envErr{})))
		return
	}
	var a nodeA
	a.step(n-1, h)
}

func TriggerReflectSCC() string {
	h := holder{Err: errors.New("pure")}
	var a nodeA
	a.step(2, &h)
	return h.Err.Error()
}
`
	if err := os.WriteFile(filepath.Join(reflectSCCDir, "p.go"), []byte(reflectSCCSrc), 0o600); err != nil {
		t.Fatal(err)
	}

	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	primeHasherFromDir(t, h, dir)
	subjects := []Subject{
		{Package: "example.com/precision", Symbol: "TestParamBackedOpenFileDominated"},
		{Package: "example.com/precision", Symbol: "TestParamBackedFreshOpenFileNameRefused"},
		{Package: "example.com/precision", Symbol: "ParseAndFormatNumError"},
		{Package: "example.com/precision", Symbol: "PureItoaCaller"},
		{Package: "example.com/precision", Symbol: "FormatPureHolderError"},
		{Package: "example.com/precision", Symbol: "AssertAbsWrapperTimeout"},
		{Package: "example.com/precision", Symbol: "CarrierDiamondInvoke"},
		{Package: "example.com/precision", Symbol: "CarrierCycleSliceUnclosedField"},
		{Package: "example.com/precision", Symbol: "UnrelatedImpureStringerCaller"},
	}
	got, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if obs := got[Subject{Package: "example.com/precision", Symbol: "TestParamBackedOpenFileDominated"}]; !obs.Observable {
		t.Errorf("TestParamBackedOpenFileDominated = %+v, want Observable=true", obs)
	}
	if obs := got[Subject{Package: "example.com/precision", Symbol: "TestParamBackedFreshOpenFileNameRefused"}]; obs.Observable {
		t.Errorf("TestParamBackedFreshOpenFileNameRefused = %+v, want Observable=false", obs)
	}
	if obs := got[Subject{Package: "example.com/precision", Symbol: "ParseAndFormatNumError"}]; !obs.Observable || !obs.EffectFree {
		t.Errorf("ParseAndFormatNumError = %+v, want Observable=true EffectFree=true", obs)
	}
	if obs := got[Subject{Package: "example.com/precision", Symbol: "PureItoaCaller"}]; !obs.Observable || !obs.EffectFree {
		t.Errorf("PureItoaCaller = %+v, want Observable=true EffectFree=true", obs)
	}
	if obs := got[Subject{Package: "example.com/precision", Symbol: "FormatPureHolderError"}]; !obs.Observable || !obs.EffectFree {
		t.Errorf("FormatPureHolderError = %+v, want Observable=true EffectFree=true", obs)
	}
	if obs := got[Subject{Package: "example.com/precision", Symbol: "AssertAbsWrapperTimeout"}]; obs.Observable {
		t.Errorf("AssertAbsWrapperTimeout = %+v, want Observable=false", obs)
	}
	if obs := got[Subject{Package: "example.com/precision", Symbol: "CarrierDiamondInvoke"}]; !obs.Observable || !obs.EffectFree {
		t.Errorf("CarrierDiamondInvoke = %+v, want Observable=true EffectFree=true", obs)
	}
	if obs := got[Subject{Package: "example.com/precision", Symbol: "CarrierCycleSliceUnclosedField"}]; obs.Observable {
		t.Errorf("CarrierCycleSliceUnclosedField = %+v, want Observable=false", obs)
	}
	mutatedSubj := Subject{Package: "example.com/precision/mutatedpatherr", Symbol: "FormatMutatedHolderError"}
	mutatedGot, err := h.ComputeObservabilityBatch([]Subject{mutatedSubj})
	if err != nil {
		t.Fatal(err)
	}
	if obs := mutatedGot[mutatedSubj]; obs.Observable {
		t.Errorf("FormatMutatedHolderError = %+v, want Observable=false when *os.PathError is mutated", obs)
	}
	reflectSubj := Subject{Package: "example.com/precision/reflectscc", Symbol: "TriggerReflectSCC"}
	reflectGot, err := h.ComputeObservabilityBatch([]Subject{reflectSubj})
	if err != nil {
		t.Fatal(err)
	}
	if obs := reflectGot[reflectSubj]; obs.Observable {
		t.Errorf("TriggerReflectSCC = %+v, want Observable=false when cyclic SCC reaches reflect mutation", obs)
	}
	poisonSubj := Subject{Package: "example.com/precision/poisonednumerr", Symbol: "WrapImpureNumError"}
	poisonGot, err := h.ComputeObservabilityBatch([]Subject{poisonSubj})
	if err != nil {
		t.Fatal(err)
	}
	if obs := poisonGot[poisonSubj]; obs.Observable {
		t.Errorf("WrapImpureNumError = %+v, want Observable=false", obs)
	}
	initProg, err := h.loadCached("example.com/precision/initflag")
	if err != nil {
		t.Fatal(err)
	}
	initUserPaths := userModulePaths(initProg.Pkgs)
	initRoots, harnessStdInitRoots := partitionHarnessInitRoots(initProg, true, initUserPaths)
	baseStartup, err := cachedBaseStartupReachability(context.Background(), true, initProg, initRoots, harnessStdInitRoots, true, initUserPaths)
	if err != nil {
		t.Fatal(err)
	}
	foundStdGlobal := false
	for g := range baseStartup.userTouchedStdGlobals {
		if g != nil && g.Pkg != nil && g.Pkg.Pkg != nil && g.Pkg.Pkg.Path() == "io" && g.Name() == "Discard" {
			foundStdGlobal = true
		}
	}
	if !foundStdGlobal {
		t.Errorf("userTouchedStdGlobals = %v, want io.Discard recorded when touched by user init", baseStartup.userTouchedStdGlobals)
	}
}
