package closure

// inMemoryFixtureRegistry holds the 106 single-purpose Tier 1 test fixtures
// inlined from the retired internal/closure/fixtures directory.
var inMemoryFixtureRegistry = map[string]map[string]map[string]string{
	"github.com/greatliontech/gofresh/internal/closure/testdata/batchisolation": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/batchisolation": {
			"batchisolation.go": "package batchisolation\n\ntype callback func() int\n\nvar (\n\tcallbackSlot  callback\n\tinterfaceSlot any\n\tstartupValue  = startupHelper()\n)\n\nfunc startupHelper() int { return 1 }\n\nfunc dynamicTarget() int { return 2 }\n\nfunc AddressTaker() int {\n\tcallbackSlot = dynamicTarget\n\treturn startupValue\n}\n\nfunc DynamicCaller() int { return callbackSlot() }\n\nfunc alternateDynamicTarget() int { return 5 }\n\nfunc KnownDynamic() int {\n\tfn := callback(dynamicTarget)\n\tif startupValue < 0 {\n\t\tfn = alternateDynamicTarget\n\t}\n\treturn fn()\n}\n\nfunc CallbackRoot(fn callback) int { return fn() }\n\ntype runner interface {\n\tRun() int\n}\n\ntype nested struct{}\n\nfunc (nested) Exported() int { return 4 }\n\ntype concrete struct {\n\tvalue nested\n}\n\nfunc (concrete) Run() int { return concreteMethodHelper() }\n\nfunc concreteMethodHelper() int { return 3 }\n\nfunc Materializer() int {\n\tinterfaceSlot = concrete{value: nested{}}\n\treturn startupValue\n}\n\nfunc Invoker(value runner) int { return value.Run() }\n\nfunc Production() int { return startupValue }\n",
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
			"flaglookupsubject.go": "package flaglookupsubject\n\nfunc Prod() int { return 7 }\n",
			"flaglookupsubject_test.go": "package flaglookupsubject\n\nimport (\n\t\"flag\"\n\t\"testing\"\n)\n\n// A subject-flow flag lookup keeps the exclusion, and its refusal\n// names the lookup - the flag package's internal usage prints are\n// help-path only and never outrank the real cause.\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 || flag.Lookup(\"flaglookupsubject.x\") != nil {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagparsemain": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagparsemain": {
			"flagparsemain.go": "package flagparsemain\n\nfunc Prod() int { return 7 }\n",
			"flagparsemain_test.go": "package flagparsemain\n\nimport (\n\t\"flag\"\n\t\"os\"\n\t\"testing\"\n)\n\n// Parse is the read side of the registration channel - the registered\n// pointers' values change here, a channel the test log cannot audit -\n// so it keeps its refusal even in test-main flow.\nfunc TestMain(m *testing.M) {\n\t_ = flag.String(\"flagparsemain.mode\", \"fast\", \"fixture flag\")\n\tflag.Parse()\n\tos.Exit(m.Run())\n}\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagregalias": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregalias": {
			"flagregalias.go": "package flagregalias\n\nimport \"flag\"\n\n// An init that escapes the registered storage's address into another\n// package variable creates an alias the mark cannot follow: the\n// startup-flow reference refusal blocks it at the escape site, so the\n// subject's laundered read (*q) can never prove observable.\nvar (\n\tquiet bool\n\tq     *bool\n)\n\nfunc init() {\n\tflag.BoolVar(&quiet, \"flagregalias.quiet\", false, \"fixture flag\")\n\tq = &quiet\n}\n\nfunc Prod() bool { return *q }\n",
			"flagregalias_test.go": "package flagregalias\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagregcallback": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregcallback": {
			"flagregcallback.go": "package flagregcallback\n\nimport \"flag\"\n\n// Callback-family registration (Var, TextVar, Func, BoolFunc) runs\n// arbitrary code at flag.Parse: no sink judgment can bound what it\n// writes, so the family keeps the audited-pure exclusion outright.\nfunc init() {\n\tflag.BoolFunc(\"flagregcallback.trace\", \"fixture flag\", func(string) error { return nil })\n}\n\nfunc Prod() int { return 7 }\n",
			"flagregcallback_test.go": "package flagregcallback\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagregdep": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregdep": {
			"flagregdep.go": "package flagregdep\n\nimport (\n\t_ \"github.com/greatliontech/gofresh/internal/closure/testdata/flagregescape\"\n)\n\n// A dependency's untraceable registration sink blocks this package's\n// subjects too: the poison covers every subject sharing the test\n// binary, not just the registering package's own.\nfunc Prod() int { return 7 }\n",
			"flagregdep_test.go": "package flagregdep\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregescape": {
			"flagregescape.go": "package flagregescape\n\nimport \"flag\"\n\n// The registration target reaches the call through a helper parameter:\n// a sink the registration-facts judgment cannot trace to a\n// package-level variable. The package poisons - every subject blocks -\n// because an admitted registration with unguarded storage would be an\n// unobserved input channel.\nvar quiet bool\n\nfunc register(p *bool) { flag.BoolVar(p, \"flagregescape.quiet\", false, \"fixture flag\") }\n\nfunc init() { register(&quiet) }\n\nfunc Prod() int { return 7 }\n",
			"flagregescape_test.go": "package flagregescape\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagregescape": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregescape": {
			"flagregescape.go": "package flagregescape\n\nimport \"flag\"\n\n// The registration target reaches the call through a helper parameter:\n// a sink the registration-facts judgment cannot trace to a\n// package-level variable. The package poisons - every subject blocks -\n// because an admitted registration with unguarded storage would be an\n// unobserved input channel.\nvar quiet bool\n\nfunc register(p *bool) { flag.BoolVar(p, \"flagregescape.quiet\", false, \"fixture flag\") }\n\nfunc init() { register(&quiet) }\n\nfunc Prod() int { return 7 }\n",
			"flagregescape_test.go": "package flagregescape\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagreginit": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagreginit": {
			"flagreginit.go": "package flagreginit\n\nimport \"flag\"\n\n// Registration from a package initializer is a process-local registry\n// mutation - admitted. The subject never references the registered\n// variable; a reference would be the covert channel's read side and\n// refuses (the flag-backed reference refusal).\nvar verbose = flag.Bool(\"flagreginit.verbose\", false, \"fixture flag\")\n\nfunc Prod() int { return 7 }\n",
			"flagreginit_test.go": "package flagreginit\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagreginvoke": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagreginvoke": {
			"flagreginvoke.go": "package flagreginvoke\n\nfunc Prod() int { return 7 }\n",
			"flagreginvoke_test.go": "package flagreginvoke\n\nimport (\n\t\"flag\"\n\t\"os\"\n\t\"testing\"\n)\n\ntype registrar interface {\n\tBoolVar(p *bool, name string, value bool, usage string)\n}\n\nvar quiet bool\n\n// A dynamically dispatched registration target is admitted nowhere:\n// the facts walk can sink-judge only static call sites, so the\n// family-named invoke target keeps its blocking classification.\nfunc TestMain(m *testing.M) {\n\tvar r registrar = flag.CommandLine\n\tr.BoolVar(&quiet, \"flagreginvoke.quiet\", false, \"fixture flag\")\n\tcode := m.Run()\n\tif quiet {\n\t\tcode = 0\n\t}\n\tos.Exit(code)\n}\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagreginvokeinit": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagreginvokeinit": {
			"flagreginvokeinit.go": "package flagreginvokeinit\n\nimport \"flag\"\n\ntype registrar interface {\n\tBoolVar(p *bool, name string, value bool, usage string)\n}\n\nvar quiet bool\n\n// A dynamically dispatched registration target in startup flow keeps\n// its blocking classification: the facts walk can sink-judge only\n// static call sites, so admitting the invoke would leave the\n// registered storage unguarded.\nfunc init() {\n\tvar r registrar = flag.CommandLine\n\tr.BoolVar(&quiet, \"flagreginvokeinit.quiet\", false, \"fixture flag\")\n}\n\nfunc Prod() int { return 7 }\n",
			"flagreginvokeinit_test.go": "package flagreginvokeinit\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagreglocalmain": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagreglocalmain": {
			"flagreglocalmain.go": "package flagreglocalmain\n\nfunc Prod() int { return 7 }\n",
			"flagreglocalmain_test.go": "package flagreglocalmain\n\nimport (\n\t\"flag\"\n\t\"os\"\n\t\"testing\"\n)\n\n// A registration result held in a local and read later is a sink the\n// registration-facts judgment cannot trace: the package poisons, so\n// the harness's post-run read of parsed state cannot slip through as\n// an unobserved input channel.\nfunc TestMain(m *testing.M) {\n\tv := flag.Bool(\"flagreglocalmain.v\", false, \"fixture flag\")\n\tcode := m.Run()\n\tif *v {\n\t\tcode = 0\n\t}\n\tos.Exit(code)\n}\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagregmain": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregmain": {
			"flagregmain.go": "package flagregmain\n\nfunc Prod() int { return 7 }\n",
			"flagregmain_test.go": "package flagregmain\n\nimport (\n\t\"flag\"\n\t\"os\"\n\t\"testing\"\n)\n\n// Registration in user test-main flow is the same process-local\n// registry mutation - the covert channel is the read side, not the\n// registration: the call's own reference to the registered variable\n// and the store of a returned pointer are the sanctioned write shapes,\n// and nothing here ever reads either back.\nvar (\n\tmode  string\n\tmode2 *string\n)\n\nfunc TestMain(m *testing.M) {\n\tflag.StringVar(&mode, \"flagregmain.mode\", \"fast\", \"fixture flag\")\n\tmode2 = flag.String(\"flagregmain.mode2\", \"slow\", \"fixture flag\")\n\tos.Exit(m.Run())\n}\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagregmainread": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregmainread": {
			"flagregmainread.go": "package flagregmainread\n\nimport \"flag\"\n\n// Registered storage read in user test-main flow: the implicit\n// flag.Parse inside m.Run can have written it before the read, so the\n// reference is the covert channel's read side - here it masks the\n// harness exit code on command-line state the test log cannot audit.\nvar verbose = flag.Bool(\"flagregmainread.verbose\", false, \"fixture flag\")\n\nfunc Prod() int { return 7 }\n",
			"flagregmainread_test.go": "package flagregmainread\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestMain(m *testing.M) {\n\tcode := m.Run()\n\tif *verbose {\n\t\tcode = 0\n\t}\n\tos.Exit(code)\n}\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagregmethod": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregmethod": {
			"flagregmethod.go": "package flagregmethod\n\nimport \"flag\"\n\n// Method-form registration and the method-expression form judge the\n// pointer argument past the receiver: flag.CommandLine is an audited\n// selector, the storage is marked, and a subject reading none of it\n// proves observable. The white-box facts assertions pin the receiver\n// judgment itself.\nvar (\n\tverbose bool\n\tquiet   bool\n)\n\nfunc init() {\n\tflag.CommandLine.BoolVar(&verbose, \"flagregmethod.v\", false, \"fixture flag\")\n\treg := (*flag.FlagSet).BoolVar\n\treg(flag.CommandLine, &quiet, \"flagregmethod.q\", false, \"fixture flag\")\n}\n\nfunc Prod() int { return 7 }\n",
			"flagregmethod_test.go": "package flagregmethod\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagregstruct": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregstruct": {
			"flagregstruct.go": "package flagregstruct\n\nimport \"flag\"\n\n// Registration into a field of a package-level struct roots at the\n// struct variable through the field selection: the whole variable\n// carries flag-registered state, so a subject-flow reference to it\n// refuses while subjects that never touch it stay observable.\nvar cfg struct {\n\tChecks int\n}\n\n// An array-element target roots at the array variable through the\n// index selection exactly as a field does.\nvar arr [2]int\n\n// A value-family result stored through a field selection is the same\n// sanctioned write: the selection computing the store's address passes\n// with it.\nvar holder struct{ V *bool }\n\nfunc init() {\n\tflag.IntVar(&cfg.Checks, \"flagregstruct.checks\", 100, \"fixture flag\")\n\tflag.IntVar(&arr[0], \"flagregstruct.n\", 1, \"fixture flag\")\n\tholder.V = flag.Bool(\"flagregstruct.v\", false, \"fixture flag\")\n}\n\nfunc Prod() int { return 7 }\n\nfunc ProdRead() int { return cfg.Checks }\n\n// Passing the registered field's address to an ordinary call escapes\n// it - only the registration write's own argument computation passes.\nfunc deref(p *int) int { return *p }\n\nfunc ProdEscape() int { return deref(&cfg.Checks) }\n",
			"flagregstruct_test.go": "package flagregstruct\n\nimport \"testing\"\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n\nfunc TestProdRead(t *testing.T) {\n\tif ProdRead() < 0 {\n\t\tt.Fatal()\n\t}\n}\n\nfunc TestProdEscape(t *testing.T) {\n\tif ProdEscape() < 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/flagregsubject": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/flagregsubject": {
			"flagregsubject.go": "package flagregsubject\n\nimport \"flag\"\n\n// Registration reached from subject flow keeps the exclusion whatever\n// its sink: the admission is tier-scoped to startup and test-main\n// flow, so the subject-tier walk classifies flag.Bool itself - the\n// traceable store keeps the package unpoisoned, pinning that the\n// refusal comes from the walk's own classification.\nvar late *bool\n\nfunc Prod() int {\n\tlate = flag.Bool(\"flagregsubject.late\", false, \"fixture flag\")\n\treturn 7\n}\n",
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
			"genericescape.go": "// Package genericescape pins that a generic method reached only by interface\n// escape (never called, so not RTA-reachable) is still analyzed. The\n// benchmark boxes Box[int] into an interface; addInterfaceMethodSet enqueues\n// the instantiated method, whose own object carries no source decl node —\n// its generic origin must be resolved and scanned, or the method's effect\n// stays invisible and a proof over it is a false-valid.\npackage genericescape\n\nimport \"os\"\n\ntype Box[T any] struct{ v T }\n\nfunc (b Box[T]) Secret() int { return 4096 + len(os.Getenv(\"ESCAPE\")) }\n\nvar sink any\n\nfunc leak(x any) { sink = x }\n",
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
			"harnessexitoutside.go": "package harnessexitoutside\n\nfunc Prod() int { return 7 }\n",
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
			"harnessmainfmt.go": "package harnessmainfmt\n\nfunc Prod() int { return 7 }\n",
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
			"harnessmainwrite.go": "package harnessmainwrite\n\nfunc Prod() int { return 7 }\n",
			"harnessmainwrite_test.go": "package harnessmainwrite\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// TestMain performs an unobserved filesystem mutation: a write is not\n// a bracketed observation input, so the test-main walk's per-effect\n// classification blocks the proof with the write's own reason.\nfunc TestMain(m *testing.M) {\n\t_ = os.WriteFile(\"out.txt\", []byte(\"x\"), 0o644)\n\t_ = os.Remove(\"out.txt\")\n\tos.Exit(m.Run())\n}\n\nfunc TestProd(t *testing.T) {\n\tif Prod() == 0 {\n\t\tt.Fatal()\n\t}\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/harnessobserved": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/harnessobserved": {
			"harnessobserved.go": "package harnessobserved\n\nfunc Prod() int { return 7 }\n",
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
			"scalarglobalslice.go": "// Package scalarglobalslice is the scalar-global boundary's\n// unsafe.Slice channel, deliberately its own package: the call site\n// carries no unsafe.Pointer-typed value the subject walk can price,\n// so the refusal is the package scan's — and that block is\n// package-wide (only the unsafe.Pointer class is narrowed to subject\n// attribution), which is why this channel cannot share\n// scalarglobalwrite's package without pre-blocking its clean\n// direct-write subject.\npackage scalarglobalslice\n\nimport \"unsafe\"\n\n// Count is the non-carrier scalar global.\nvar Count int\n\n// BumpSlice mutates the global with NO unsafe.Pointer-typed value\n// anywhere in the body (operands *int and a length, result []int).\nfunc BumpSlice() int {\n\ts := unsafe.Slice(&Count, 1)\n\ts[0]++\n\treturn Count\n}\n",
			"scalarglobalslice_test.go": "package scalarglobalslice\n\nimport \"testing\"\n\n// TestSliceWrite mutates the scalar global through unsafe.Slice and\n// must refuse at the package scan, the channel's only arm.\nfunc TestSliceWrite(*testing.T) {\n\t_ = BumpSlice()\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/scalarglobalwrite": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/scalarglobalwrite": {
			"scalarglobalwrite.go": "// Package scalarglobalwrite is the named anchor for the scalar-global\n// mutation boundary: a plain package-level variable sits outside the\n// shared-dynamic-state carrier net by clause, its direct mutation is\n// admitted (per-process-deterministic content the whole-graph hash\n// covers; the admission's enforcement is the view-tier plain-data\n// builder test), and an unsafe-mediated mutation refuses on the\n// channel it uses — an unsafe.Pointer-typed value refuses at the\n// subject walk, while unsafe.Slice and kin, whose call sites carry no\n// such value, keep the package-scan block. The laundered-address\n// entry shape (a plain uintptr crossing the signature) is pinned by\n// the closure-verdict test for a uintptr address input — the\n// re-materializing conversion is the same walk tripwire, and go vet's\n// unsafeptr check keeps that variant out of tree.\npackage scalarglobalwrite\n\nimport \"unsafe\"\n\n// Count is the non-carrier scalar global: no function, interface,\n// channel, or unsafe pointer anywhere in its type.\nvar Count int\n\n// BumpDirect is the admitted twin: a direct write to the scalar.\nfunc BumpDirect() int {\n\tCount++\n\treturn Count\n}\n\n// BumpUnsafe mutates the global through an unsafe.Pointer-typed\n// value — the subject walk's channel.\nfunc BumpUnsafe() int {\n\tp := (*int)(unsafe.Pointer(&Count))\n\t*p++\n\treturn Count\n}\n",
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
			"grammar.go": "package unsafesibling\n\nimport \"unsafe\"\n\n// Grammar and Carry model an operator-grammar fixture file: unsafe\n// references a clean sibling subject never reaches.\ntype Grammar unsafe.Pointer\n\nfunc Carry(p unsafe.Pointer) unsafe.Pointer { return p }\n",
			"unsafesibling_test.go": "package unsafesibling\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// TestCleanRead never reaches the sibling grammar file's unsafe\n// declarations: its observability proof must not be pre-blocked by\n// the package scan on their account.\nfunc TestCleanRead(*testing.T) {\n\t_, _ = os.ReadFile(\"fixture.txt\")\n}\n\n// TestReachesUnsafe carries an unsafe-typed value through its own\n// walk and must refuse at the subject tier.\nfunc TestReachesUnsafe(*testing.T) {\n\tp := Carry(nil)\n\t_ = p\n}\n",
		},
	},
	"github.com/greatliontech/gofresh/internal/closure/testdata/unsafeslice": {
		"github.com/greatliontech/gofresh/internal/closure/testdata/unsafeslice": {
			"doc.go": "// Package unsafeslice exercises the scan-blocking unsafe symbols whose\n// call sites the subject walk's type-graph arm cannot price.\npackage unsafeslice\n",
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
