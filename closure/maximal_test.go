package closure

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestComputeMaximalBatchSharesPackageClosureWithoutSharingIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/maximal\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "maximal.go")
	if err := os.WriteFile(path, []byte("package maximal\n\nfunc F() int { return 1 }\nfunc G() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{
		{Package: "example.com/maximal", Symbol: "F"},
		{Package: "example.com/maximal", Symbol: "G"},
	}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := h.ComputeMaximalBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if before[subjects[0]].Hash == before[subjects[1]].Hash {
		t.Fatal("distinct subject identities shared one closure hash")
	}

	if err := os.WriteFile(path, []byte("package maximal\n\nfunc F() int { return 1 }\nfunc G() int { return 3 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := h.ComputeMaximalBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range subjects {
		if before[subject].Hash == after[subject].Hash {
			t.Fatalf("sibling edit did not move maximal closure for %s", subject.Symbol)
		}
	}
}

func TestComputeMaximalBatchWithSourcesIncludesWidenedPackageFiles(t *testing.T) {
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/opaqueasm"
	subject := Subject{Package: pkg, Symbol: "BenchmarkOpaqueASM"}
	h, err := NewAt("..")
	if err != nil {
		t.Fatal(err)
	}
	_, sources, err := h.ComputeMaximalBatchWithSources([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.Abs(filepath.Join("fixtures", "opaqueasm", "defs.inc"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, path := range sources[subject] {
		if path == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("widened sources omit %s: %v", want, sources[subject])
	}
}

func TestComputeMaximalBatchConservativelyMarksExternalPackageCode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/external\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "external.go"), []byte("package external\n\nimport \"os\"\n\nfunc Read() { _, _ = os.ReadFile(\"fixture\") }\nfunc Pure() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/external", Symbol: "Pure"}
	closures, err := h.ComputeMaximalBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	got := closures[subject]
	if !got.Unverifiable || !strings.Contains(got.Reason, "os.ReadFile") {
		t.Fatalf("maximal external scan = %+v, want os.ReadFile unverifiable", got)
	}
}

func TestComputeMaximalBatchConservativelyMarksDotImportedExternalCode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/dotexternal\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "external.go"), []byte("package dotexternal\n\nimport . \"os\"\n\nfunc Read() { _, _ = ReadFile(\"fixture\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/dotexternal", Symbol: "Read"}
	closures, err := h.ComputeMaximalBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if got := closures[subject]; !got.Unverifiable || !strings.Contains(got.Reason, "os") {
		t.Fatalf("dot-imported external scan = %+v, want os unverifiable", got)
	}
}

func TestComputeMaximalBatchConservativelyMarksStandardWrappers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
		symbol string
		reason string
	}{
		{
			name:   "archive zip function value",
			source: "package wrapper\n\nimport \"archive/zip\"\n\nfunc Read() { open := zip.OpenReader; _, _ = open(\"fixture.zip\") }\n",
			symbol: "Read",
			reason: "archive/zip",
		},
		{
			name:   "external process",
			source: "package wrapper\n\nimport \"os/exec\"\n\nfunc Run() { _, _ = exec.Command(\"tool\").Output() }\n",
			symbol: "Run",
			reason: "os/exec",
		},
		{
			name:   "unlisted standard wrapper",
			source: "package wrapper\n\nimport \"io/ioutil\"\n\nfunc Read() { _, _ = ioutil.ReadFile(\"fixture\") }\n",
			symbol: "Read",
			reason: "io/ioutil",
		},
		{
			name:   "whitelisted package external function value",
			source: "package wrapper\n\nimport \"fmt\"\n\nfunc Scan() { scan := fmt.Scan; _, _ = scan() }\n",
			symbol: "Scan",
			reason: "fmt.Scan",
		},
		{
			name:   "formatted output",
			source: "package wrapper\n\nimport \"fmt\"\n\nfunc Print() { _, _ = fmt.Print(\"value\") }\n",
			symbol: "Print",
			reason: "fmt.Print",
		},
		{
			name:   "formatted reader input",
			source: "package wrapper\n\nimport (\"fmt\"; \"os\")\n\nfunc Scan() { var value int; _, _ = fmt.Fscan(os.Stdin, &value) }\n",
			symbol: "Scan",
			reason: "fmt.Fscan",
		},
		{
			name:   "testing runtime configuration",
			source: "package wrapper\n\nimport \"testing\"\n\nfunc TestShort(t *testing.T) { _ = testing.Short() }\n",
			symbol: "TestShort",
			reason: "testing.Short",
		},
		{
			name:   "testing subtest selection",
			source: "package wrapper\n\nimport \"testing\"\n\nfunc TestParent(t *testing.T) { t.Run(\"child\", func(t *testing.T) {}) }\n",
			symbol: "TestParent",
			reason: "testing.Run",
		},
		{
			name:   "aliased testing receiver",
			source: "package wrapper\n\nimport \"testing\"\n\nfunc TestAlias(t *testing.T) { other := t; _ = other.TempDir() }\n",
			symbol: "TestAlias",
			reason: "testing.TempDir",
		},
		{
			name:   "parenthesized testing receiver alias",
			source: "package wrapper\n\nimport \"testing\"\n\nfunc TestAlias(t *testing.T) { other := (t); _ = other.TempDir() }\n",
			symbol: "TestAlias",
			reason: "testing.TempDir",
		},
		{
			name:   "benchmark elapsed time",
			source: "package wrapper\n\nimport \"testing\"\n\nfunc BenchmarkElapsed(b *testing.B) { _ = b.Elapsed() }\n",
			symbol: "BenchmarkElapsed",
			reason: "testing.Elapsed",
		},
		{
			name:   "benchmark iteration count",
			source: "package wrapper\n\nimport \"testing\"\n\nfunc BenchmarkN(b *testing.B) { _ = b.N }\n",
			symbol: "BenchmarkN",
			reason: "testing.N",
		},
		{
			name:   "escaped testing receiver",
			source: "package wrapper\n\nimport \"testing\"\n\ntype tempDir interface { TempDir() string }\nfunc use(value tempDir) { _ = value.TempDir() }\nfunc TestEscape(t *testing.T) { use(t) }\n",
			symbol: "TestEscape",
			reason: "escapes analyzable receiver",
		},
		{
			name:   "testing receiver in composite",
			source: "package wrapper\n\nimport \"testing\"\n\nfunc BenchmarkComposite(b *testing.B) { handles := []*testing.B{b}; _ = handles[0].N }\n",
			symbol: "BenchmarkComposite",
			reason: "testing.N",
		},
		{
			name:   "testing TempDir method value",
			source: "package wrapper\n\nimport \"testing\"\n\nfunc BenchmarkTemp(b *testing.B) { temp := b.TempDir; _ = temp() }\n",
			symbol: "BenchmarkTemp",
			reason: "testing.TempDir",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/wrapper\n\ngo 1.26\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			name := "wrapper.go"
			if strings.Contains(tc.symbol, "Benchmark") {
				name = "wrapper_test.go"
			}
			if err := os.WriteFile(filepath.Join(dir, name), []byte(tc.source), 0o644); err != nil {
				t.Fatal(err)
			}
			h, err := NewAt(dir)
			if err != nil {
				t.Fatal(err)
			}
			subject := Subject{Package: "example.com/wrapper", Symbol: tc.symbol}
			closures, err := h.ComputeMaximalBatch([]Subject{subject})
			if err != nil {
				t.Fatal(err)
			}
			if got := closures[subject]; !got.Unverifiable || !strings.Contains(got.Reason, tc.reason) {
				t.Fatalf("standard wrapper scan = %+v, want %s unverifiable", got, tc.reason)
			}
		})
	}
}

func TestMaximalTestingMethodClassificationUsesHarnessReceiver(t *testing.T) {
	dir := t.TempDir()
	filename := filepath.Join(dir, "wrapper_test.go")
	source := "package wrapper\n\nimport \"testing\"\n\ntype Config struct{}\nfunc (Config) Setenv() {}\nfunc TestConfig(t *testing.T) { var config Config; config.Setenv() }\n"
	if err := os.WriteFile(filename, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	scan, err := maximalFileEffects(filename)
	if err != nil {
		t.Fatal(err)
	}
	if scan.preferred != "" {
		t.Fatalf("unrelated Setenv method classified as testing API: %q", scan.preferred)
	}
}

func TestComputeMaximalBatchClassifiesCrossFileTestingAlias(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/wrapper\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "alias_test.go"), []byte("package wrapper\n\nimport \"testing\"\n\ntype Bench struct { *testing.B }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "benchmark_test.go"), []byte("package wrapper\n\nfunc F(b *Bench) { _ = b.N }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/wrapper", Symbol: "F"}
	closures, err := h.ComputeMaximalBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if got := closures[subject]; !got.Unverifiable || !strings.Contains(got.Reason, "testing.N") {
		t.Fatalf("cross-file testing alias = %+v, want testing.N unverifiable", got)
	}
}

func TestComputeMaximalBatchClassifiesImportedTestingAlias(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/wrapper\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "dep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dep", "dep.go"), []byte("package dep\n\nimport \"testing\"\n\ntype B = testing.B\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "wrapper.go"), []byte("package wrapper\n\nimport \"example.com/wrapper/dep\"\n\ntype B = dep.B\nfunc F(b *B) { _ = b.N }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/wrapper", Symbol: "F"}
	closures, err := h.ComputeMaximalBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if got := closures[subject]; !got.Unverifiable || !strings.Contains(got.Reason, "testing.N") {
		t.Fatalf("imported testing alias = %+v, want testing.N unverifiable", got)
	}
}

func TestComputeMaximalBatchDoesNotClassifyUnrelatedPackageMethod(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/wrapper\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "worker.go"), []byte("package wrapper\n\ntype worker struct{}\nfunc (worker) Run() {}\nfunc F() { worker{}.Run() }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "worker_test.go"), []byte("package wrapper\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/wrapper", Symbol: "F"}
	closures, err := h.ComputeMaximalBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if got := closures[subject]; got.Unverifiable {
		t.Fatalf("unrelated package Run method classified as testing API: %+v", got)
	}
}

func TestComputeMaximalBatchConservativelyMarksNonGoEdges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		goFile string
		asm    string
		reason string
	}{
		{
			name:   "linkname",
			goFile: "package edge\n\nimport _ \"unsafe\"\n\n//go:linkname nanotime runtime.nanotime\nfunc nanotime() int64\n\nfunc F() int64 { return nanotime() }\n",
			reason: "go:linkname",
		},
		{
			name:   "assembly",
			goFile: "package edge\n\nfunc F()\n",
			asm:    "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n",
			reason: "assembly",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/edge\n\ngo 1.26\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "edge.go"), []byte(tc.goFile), 0o644); err != nil {
				t.Fatal(err)
			}
			if tc.asm != "" {
				if err := os.WriteFile(filepath.Join(dir, "edge.s"), []byte(tc.asm), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			h, err := NewAt(dir)
			if err != nil {
				t.Fatal(err)
			}
			subject := Subject{Package: "example.com/edge", Symbol: "F"}
			closures, err := h.ComputeMaximalBatch([]Subject{subject})
			if err != nil {
				t.Fatal(err)
			}
			if got := closures[subject]; !got.Unverifiable || !strings.Contains(got.Reason, tc.reason) {
				t.Fatalf("non-Go edge scan = %+v, want %s unverifiable", got, tc.reason)
			}
		})
	}
}

func TestMaximalPackageMarksImplicitCgoExternal(t *testing.T) {
	pkg := &listPkg{CgoFiles: []string{"cgo.go"}}
	if reason := maximalPackageExternalEffects(pkg).preferred; !strings.Contains(reason, "cgo") {
		t.Fatalf("implicit cgo reason = %q, want cgo external disposition", reason)
	}
}

func TestMaximalNativeReasonsAreUnrefinable(t *testing.T) {
	for _, reason := range []string{
		"reaches cgo external library",
		"reaches system object",
		"reaches go:wasmimport",
	} {
		if !maximalReasonUnrefinable(reason) {
			t.Fatalf("native reason %q was refinable", reason)
		}
	}
	for _, reason := range []string{"reaches assembly", "reaches cgo or native source", "reaches go:linkname (opaque linkage)"} {
		if maximalReasonUnrefinable(reason) {
			t.Fatalf("resolvable native reason %q was permanently opaque", reason)
		}
	}
}

func TestMaximalFileEffectsRetainAllFactsAndLegacyDiagnostic(t *testing.T) {
	dir := t.TempDir()
	filename := filepath.Join(dir, "effects.go")
	source := `package effects
import (
	"net"
	"os"
)
func F() {
	_, _ = os.ReadFile("fixture")
	_, _ = net.Dial("tcp", "example.invalid:1")
}
`
	if err := os.WriteFile(filename, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	scan, err := maximalFileEffects(filename)
	if err != nil {
		t.Fatal(err)
	}
	if scan.preferred != "reaches net (network I/O)" {
		t.Fatalf("preferred diagnostic = %q, want the always-external import to outrank the body walk", scan.preferred)
	}
	for _, want := range [][2]string{{"os", "ReadFile"}, {"net", "Dial"}} {
		found := false
		for _, effect := range scan.effects {
			found = found || effect.packagePath == want[0] && effect.symbol == want[1]
		}
		if !found {
			t.Errorf("missing typed effect %s.%s in %+v", want[0], want[1], scan.effects)
		}
	}
	for _, effect := range scan.effects {
		if effect.packagePath == "" && effect.kind == externalEffectUnauditedStandard {
			t.Fatalf("classified selectors retained a spurious package blocker: %+v", scan.effects)
		}
	}
}

// A file whose only external-capable content is an unaudited standard
// operation names that operation in the preferred diagnostic — first in
// walk order when several occur — instead of serving the name-free
// import fallback; the fallback still covers a classified import with
// no effect-bearing use (REQ-closure-observability-analysis's
// cause-preference order).
func TestMaximalUnauditedOperationNamesThePreferredDiagnostic(t *testing.T) {
	dir := t.TempDir()
	write := func(name, source string) string {
		t.Helper()
		filename := filepath.Join(dir, name)
		if err := os.WriteFile(filename, []byte(source), 0o644); err != nil {
			t.Fatal(err)
		}
		return filename
	}
	named := write("unaudited.go", `package effects
import "fmt"
type wrap struct{ s fmt.State }
func F(w wrap) string { return fmt.Sprintf("%v", w.s) }
`)
	scan, err := maximalFileEffects(named)
	if err != nil {
		t.Fatal(err)
	}
	if scan.preferred != "reaches unaudited standard operation fmt.State" {
		t.Fatalf("preferred diagnostic = %q, want the unaudited operation named - the name-free fallback hides the sink", scan.preferred)
	}
	first := write("unaudited_two.go", `package effects
import "fmt"
type pair struct {
	a fmt.State
	b fmt.Formatter
}
`)
	scan, err = maximalFileEffects(first)
	if err != nil {
		t.Fatal(err)
	}
	if scan.preferred != "reaches unaudited standard operation fmt.State" {
		t.Fatalf("preferred diagnostic = %q, want the first unaudited operation in walk order", scan.preferred)
	}
	fallback := write("pure_only.go", `package effects
import "fmt"
func G(v int) string { return fmt.Sprintf("%d", v) }
`)
	scan, err = maximalFileEffects(fallback)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.effects) != 0 || scan.preferred != "reaches fmt (potential external dependence)" {
		t.Fatalf("audited-pure-only file = effects %+v preferred %q, want no effects and the import fallback preserved", scan.effects, scan.preferred)
	}
	stringerOnly := write("stringer_only.go", `package effects
import "fmt"
type labeled struct{ s fmt.Stringer }
func H(l labeled) string { return fmt.Sprint(l.s) }
`)
	scan, err = maximalFileEffects(stringerOnly)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.effects) != 0 || scan.preferred != "reaches fmt (potential external dependence)" {
		t.Fatalf("Stringer-reference file = effects %+v preferred %q, want the interface-type reference admitted as executing nothing", scan.effects, scan.preferred)
	}
}

// A sibling file with no effects offers only the import fallback; the
// package fold must keep the effect-backed named reason regardless of
// lexicographic order, else the verdict's cause is displaced by a file
// that contributes no blocker
// (REQ-closure-observability-analysis's cause-preference order).
func TestMaximalPackageFoldPrefersEffectBackedReasons(t *testing.T) {
	backed := maximalEffectScan{preferred: "reaches unaudited standard operation fmt.State"}
	backed.add(symbolExternalEffect(externalEffectUnauditedStandard, "fmt", "State", "reaches unaudited standard operation fmt.State"))
	fallback := maximalEffectScan{preferred: "reaches fmt (potential external dependence)"}

	selected, isBacked := foldMaximalPreferred("", false, fallback)
	if selected != "reaches fmt (potential external dependence)" || isBacked {
		t.Fatalf("effectless-first fold = %q backed=%v, want the fallback held as effectless", selected, isBacked)
	}
	selected, isBacked = foldMaximalPreferred(selected, isBacked, backed)
	if selected != "reaches unaudited standard operation fmt.State" || !isBacked {
		t.Fatalf("backed reason did not displace the effectless fallback: %q backed=%v", selected, isBacked)
	}
	selected, isBacked = foldMaximalPreferred(selected, isBacked, fallback)
	if selected != "reaches unaudited standard operation fmt.State" || !isBacked {
		t.Fatalf("effectless fallback displaced the effect-backed cause: %q backed=%v", selected, isBacked)
	}
	stronger := maximalEffectScan{preferred: "reaches cgo external library"}
	stronger.add(opaqueExternalEffect(externalEffectNative, "reaches cgo external library"))
	selected, isBacked = foldMaximalPreferred(selected, isBacked, stronger)
	if selected != "reaches cgo external library" || !isBacked {
		t.Fatalf("within the backed class the unrefinable reason must win: %q backed=%v", selected, isBacked)
	}
}

func TestMaximalPackageEffectsRetainEveryNativeFact(t *testing.T) {
	pkg := &listPkg{
		CgoLDFLAGS: []string{"-lm"},
		CFiles:     []string{"native.c"},
		SFiles:     []string{"asm.s"},
		SysoFiles:  []string{"object.syso"},
	}
	scan := maximalPackageExternalEffects(pkg)
	if scan.preferred != "reaches cgo external library" {
		t.Fatalf("preferred package diagnostic = %q", scan.preferred)
	}
	if len(scan.effects) != 4 {
		t.Fatalf("package effects = %+v, want four complete facts", scan.effects)
	}
}

func TestComputeMaximalBatchHonorsCancellationDuringTraversal(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	h.ctx = &cancelAfterContext{Context: context.Background(), remaining: 1}
	_, err = h.ComputeMaximalBatch([]Subject{{
		Package: "github.com/greatliontech/gofresh/closure/fixtures/direct",
		Symbol:  "BenchmarkDirect",
	}})
	if err == nil {
		t.Fatal("maximal traversal ignored cancellation")
	}
}

// TestMaximalHashCoversEmbeddedData pins byte coverage of go:embed data at
// the maximal layer (REQ-closure-coverage): an embedded file's bytes are
// part of the closure a subject exercises, so editing only the data file
// moves the maximal hash.
func TestMaximalHashCoversEmbeddedData(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/embedhash\n\ngo 1.26\n")
	writeFile(t, dir, "embed.go", "package embedhash\n\nimport _ \"embed\"\n\n//go:embed data.txt\nvar data string\n\nfunc Data() string { return data }\n")
	writeFile(t, dir, "data.txt", "before\n")
	subject := Subject{Package: "example.com/embedhash", Symbol: "Data"}

	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := h.ComputeMaximalBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "data.txt", "after\n")
	h2, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	after, err := h2.ComputeMaximalBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if before[subject].Hash == after[subject].Hash {
		t.Fatal("editing embedded data did not move the maximal hash")
	}
}
