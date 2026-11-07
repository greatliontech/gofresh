package closure

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
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
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	before, _, err := h.ComputeMaximalBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if before[subjects[0]].Hash == before[subjects[1]].Hash {
		t.Fatal("distinct subject identities shared one closure hash")
	}

	if err := os.WriteFile(path, []byte("package maximal\n\nfunc F() int { return 1 }\nfunc G() int { return 3 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, _, err := h.ComputeMaximalBatch(subjects)
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
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/opaqueasm"
	subject := Subject{Package: pkg, Symbol: "BenchmarkOpaqueASM"}
	h := newInMemoryHasher(t)
	supplyRegisteredFixtures(t, h, pkg)
	_, sources, err := h.ComputeMaximalBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.Abs(filepath.Join("testdata", "opaqueasm", "defs.inc"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, path := range sources[subject] {
		if path == want || strings.HasSuffix(filepath.ToSlash(path), "/defs.inc") {
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
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/external", Symbol: "Pure"}
	closures, _, err := h.ComputeMaximalBatch([]Subject{subject})
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
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/dotexternal", Symbol: "Read"}
	closures, _, err := h.ComputeMaximalBatch([]Subject{subject})
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
			name:   "escaped testing receiver",
			source: "package wrapper\n\nimport \"testing\"\n\ntype tempDir interface { TempDir() string }\nfunc use(value tempDir) { _ = value.TempDir() }\nfunc TestEscape(t *testing.T) { use(t) }\n",
			symbol: "TestEscape",
			reason: "escapes analyzable receiver",
		},
		{
			// The receiver escape is the structural finding and ranks
			// top, so the diagnostic names it over the down-ranked
			// testing.Elapsed classification the escape also records
			// (REQ-closure-observability-cause-order
			// order).
			name:   "testing receiver in composite",
			source: "package wrapper\n\nimport \"testing\"\n\nfunc BenchmarkComposite(b *testing.B) { handles := []*testing.B{b}; _ = handles[0].Elapsed() }\n",
			symbol: "BenchmarkComposite",
			reason: "escapes analyzable receiver",
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
			h, err := newAt(dir)
			if err != nil {
				t.Fatal(err)
			}
			subject := Subject{Package: "example.com/wrapper", Symbol: tc.symbol}
			closures, _, err := h.ComputeMaximalBatch([]Subject{subject})
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
	scan, err := maximalFileEffects(true, filename)
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
	if err := os.WriteFile(filepath.Join(dir, "benchmark_test.go"), []byte("package wrapper\n\nfunc F(b *Bench) { _ = b.Elapsed() }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/wrapper", Symbol: "F"}
	closures, _, err := h.ComputeMaximalBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if got := closures[subject]; !got.Unverifiable || !strings.Contains(got.Reason, "testing.Elapsed") {
		t.Fatalf("cross-file testing alias = %+v, want testing.Elapsed unverifiable", got)
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
	if err := os.WriteFile(filepath.Join(dir, "wrapper.go"), []byte("package wrapper\n\nimport \"example.com/wrapper/dep\"\n\ntype B = dep.B\nfunc F(b *B) { _ = b.Elapsed() }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/wrapper", Symbol: "F"}
	closures, _, err := h.ComputeMaximalBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if got := closures[subject]; !got.Unverifiable || !strings.Contains(got.Reason, "testing.Elapsed") {
		t.Fatalf("imported testing alias = %+v, want testing.Elapsed unverifiable", got)
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
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/wrapper", Symbol: "F"}
	closures, _, err := h.ComputeMaximalBatch([]Subject{subject})
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
			h, err := newAt(dir)
			if err != nil {
				t.Fatal(err)
			}
			subject := Subject{Package: "example.com/edge", Symbol: "F"}
			closures, _, err := h.ComputeMaximalBatch([]Subject{subject})
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

// The preferred-diagnostic comparator implements the shared
// cause-preference order exactly as the legacy projection does: rank
// strata first, lexicographic least within a rank - the unrefinable
// bit earns no tie-break, so both instances of the one shared order
// resolve every tie identically
// (REQ-closure-observability-cause-order).
func TestPreferredReasonOrdersRankThenLexicographic(t *testing.T) {
	native := opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly")
	unaudited := symbolExternalEffect(externalEffectUnauditedStandard, "os", "Getpid", "reaches unaudited standard operation os.Getpid")
	if !preferEffectReason(native, unaudited) || preferEffectReason(unaudited, native) {
		t.Fatal("rank stratum did not dominate")
	}
	assembly := opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly")
	syso := opaqueExternalEffect(externalEffectNative, "reaches non-standard system object")
	if !preferEffectReason(assembly, syso) || preferEffectReason(syso, assembly) {
		t.Fatal("equal rank did not fall to the lexicographic least")
	}
	object := opaqueExternalEffect(externalEffectNative, "reaches non-standard system object")
	object.unrefinable = true
	if !preferEffectReason(assembly, object) || preferEffectReason(object, assembly) {
		t.Fatal("the unrefinable bit displaced the lexicographic tie-break")
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
	scan, err := maximalFileEffects(true, filename)
	if err != nil {
		t.Fatal(err)
	}
	if scan.preferred != trueExternalEffect("net").reason {
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
// operation names that operation in the preferred diagnostic — the
// lexicographic least when several occur — instead of serving the name-free
// import fallback; the fallback still covers a classified import with
// no effect-bearing use (REQ-closure-observability-cause-order).
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
	scan, err := maximalFileEffects(true, named)
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
	scan, err = maximalFileEffects(true, first)
	if err != nil {
		t.Fatal(err)
	}
	if scan.preferred != "reaches unaudited standard operation fmt.Formatter" {
		t.Fatalf("preferred diagnostic = %q, want the lexicographic least within the rank", scan.preferred)
	}
	fallback := write("pure_only.go", `package effects
import "fmt"
func G(v int) string { return fmt.Sprintf("%d", v) }
`)
	scan, err = maximalFileEffects(true, fallback)
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
	scan, err = maximalFileEffects(true, stringerOnly)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.effects) != 0 || scan.preferred != "reaches fmt (potential external dependence)" {
		t.Fatalf("Stringer-reference file = effects %+v preferred %q, want the interface-type reference admitted as executing nothing", scan.effects, scan.preferred)
	}
}

// The package selection is one comparator argmax over the effect
// union; an effect-less scan's import fallback names a dependence only
// when no scan backed a real blocker, so a backed reason is never
// displaced by a file contributing nothing
// (REQ-closure-observability-cause-order).
func TestMaximalPackageSelectionRanksTheEffectUnion(t *testing.T) {
	if selected := preferredEffectReason(nil); selected != "" {
		t.Fatalf("empty union selected %q", selected)
	}
	union := []externalEffect{symbolExternalEffect(externalEffectUnauditedStandard, "fmt", "State", "reaches unaudited standard operation fmt.State")}
	if selected := preferredEffectReason(union); selected != "reaches unaudited standard operation fmt.State" {
		t.Fatalf("single-effect union selected %q", selected)
	}
	library := opaqueExternalEffect(externalEffectNative, "reaches cgo external library")
	library.unrefinable = true
	union = append(union, library)
	if selected := preferredEffectReason(union); selected != library.reason {
		t.Fatalf("the top-rank blocker was not selected: %q", selected)
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
	if scan.preferred != opaqueExternalEffect(externalEffectNative, "reaches cgo external library").reason {
		t.Fatalf("preferred package diagnostic = %q, want the lexicographic least of the native facts", scan.preferred)
	}
	if len(scan.effects) != 4 {
		t.Fatalf("package effects = %+v, want four complete facts", scan.effects)
	}
}

func TestMaximalFileEffectsDeclaredImportNames(t *testing.T) {
	src := []byte(`package p
import (
	"example.com/a/client"
	"example.com/b/client"
)
func Use() { _ = aclient.New(); _ = bclient.New() }
`)
	// Without declared names from the listing, two unnamed imports sharing
	// path.Base("client") collide fail-closed.
	fallbackScan, err := maximalFileEffectsContent(true, "p.go", src)
	if err != nil {
		t.Fatal(err)
	}
	if len(fallbackScan.effects) != 1 || !strings.Contains(fallbackScan.preferred, "import name collision") {
		t.Fatalf("fallback scan = %+v, want fail-closed collision", fallbackScan)
	}
	// With declared names from the listing, each unnamed import binds its
	// declared package name without false collision.
	declared := listedDeclaredNames([]listPkg{
		{ImportPath: "example.com/a/client", Name: "aclient"},
		{ImportPath: "example.com/b/client", Name: "bclient"},
	})
	resolvedScan, err := maximalFileEffectsContentWithNames(true, "p.go", src, declared)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolvedScan.effects) != 0 || resolvedScan.preferred != "" {
		t.Fatalf("declared-names scan = %+v, want no false collision", resolvedScan)
	}

	// Conflicting listing nodes for the same SourcePath leave the binding
	// unresolved in both listing orders rather than picking whichever node
	// appeared first.
	conflictAB := listedDeclaredNames([]listPkg{
		{ImportPath: "example.com/a/client", Name: "aclient"},
		{ImportPath: "example.com/a/client [p.test]", Name: "other"},
		{ImportPath: "example.com/b/client", Name: "bclient"},
	})
	conflictBA := listedDeclaredNames([]listPkg{
		{ImportPath: "example.com/a/client [p.test]", Name: "other"},
		{ImportPath: "example.com/a/client", Name: "aclient"},
		{ImportPath: "example.com/b/client", Name: "bclient"},
	})
	if conflictAB["example.com/a/client"] != "" || conflictBA["example.com/a/client"] != "" {
		t.Fatalf("conflicting SourcePath bindings = %q / %q, want empty (unresolved)", conflictAB["example.com/a/client"], conflictBA["example.com/a/client"])
	}
	if declaredOverridesKey(conflictAB) != declaredOverridesKey(conflictBA) {
		t.Fatalf("declaredOverridesKey order mismatch: %q != %q", declaredOverridesKey(conflictAB), declaredOverridesKey(conflictBA))
	}

	// Major-versioned imports (/v2) have distinct alias-binding states for
	// nil declaredNames, declared "v2", and declared "foo", so each must
	// produce a distinct overridesKey and never serve a stale cached scan.
	v2Src := []byte(`package p
import (
	"example.com/a/foo"
	"example.com/b/foo/v2"
)
func Use() { _ = foo.A() }
`)
	dir := t.TempDir()
	filePath := filepath.Join(dir, "v2.go")
	if err := os.WriteFile(filePath, v2Src, 0o600); err != nil {
		t.Fatal(err)
	}
	h := &Hasher{
		maximalFiles:      map[string]maximalEffectScan{},
		selectionResolved: true,
	}
	unlistedScan, err := h.maximalFileEffectsCached("example.com/p", filePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(unlistedScan.effects) != 0 {
		t.Fatalf("unlisted /v2 scan = %+v, want clean secondary fallback", unlistedScan)
	}
	declaredFoo := map[string]string{
		"example.com/a/foo":    "foo",
		"example.com/b/foo/v2": "foo",
	}
	declaredV2 := map[string]string{
		"example.com/a/foo":    "foo",
		"example.com/b/foo/v2": "v2",
	}
	if kFoo, kV2 := declaredOverridesKey(declaredFoo), declaredOverridesKey(declaredV2); kFoo == "" || kV2 == "" || kFoo == kV2 {
		t.Fatalf("versioned overridesKey = (%q, %q), want distinct non-empty keys", kFoo, kV2)
	}
	collisionScan, err := h.maximalFileEffectsCachedWithNames("example.com/p", filePath, declaredFoo, declaredOverridesKey(declaredFoo))
	if err != nil {
		t.Fatal(err)
	}
	if len(collisionScan.effects) != 1 || !strings.Contains(collisionScan.preferred, "import name collision") {
		t.Fatalf("declared foo /v2 scan = %+v, want collision on foo", collisionScan)
	}
}

func TestComputeMaximalBatchHonorsCancellationDuringTraversal(t *testing.T) {
	h := newInMemoryHasher(t)
	supplyRegisteredFixtures(t, h, "github.com/greatliontech/gofresh/internal/closure/testdata/direct")
	h.ctx = &cancelAfterContext{Context: context.Background(), remaining: 1}
	_, _, err := h.ComputeMaximalBatch([]Subject{{
		Package: "github.com/greatliontech/gofresh/internal/closure/testdata/direct",
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

	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	before, _, err := h.ComputeMaximalBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "data.txt", "after\n")
	h2, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	after, _, err := h2.ComputeMaximalBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if before[subject].Hash == after[subject].Hash {
		t.Fatal("editing embedded data did not move the maximal hash")
	}
}

// Property pin for the preferred-diagnostic selection
// (REQ-closure-observability-cause-order): over
// generated effect sets the selection is total (any reasoned effect
// yields a non-empty preferred), permutation-invariant, and names a
// maximal-rank effect, lexicographic-least within the rank. The oracle
// recomputes the expected
// selection by filtering rather than the production streaming compare,
// so a shared misunderstanding cannot pass both; the seed corpus runs
// in every ordinary go test invocation.
func FuzzPreferredReasonTotalAndRankMaximal(f *testing.F) {
	f.Add(int64(1), uint8(4))
	f.Add(int64(42), uint8(8))
	f.Add(int64(7), uint8(0))
	f.Add(int64(-3), uint8(2))
	f.Fuzz(func(t *testing.T, seed int64, count uint8) {
		rng := rand.New(rand.NewSource(seed))
		kinds := []externalEffectKind{
			externalEffectUnauditedStandard, externalEffectTestRuntime,
			externalEffectFormattedOutput, externalEffectEnvironment,
			externalEffectFileIO, externalEffectNative, externalEffectLinkage,
		}
		packagePaths := []string{"", "os", "fmt", "testing"}
		reasons := []string{"", "reaches a", "reaches b", "reaches c"}
		effects := make([]externalEffect, 0, count%9)
		for i := 0; i < int(count%9); i++ {
			effects = append(effects, externalEffect{
				kind:        kinds[rng.Intn(len(kinds))],
				packagePath: packagePaths[rng.Intn(len(packagePaths))],
				reason:      reasons[rng.Intn(len(reasons))],
				unrefinable: rng.Intn(2) == 0,
				observable:  rng.Intn(2) == 0,
			})
		}
		selected := preferredEffectReason(effects)
		var reasoned []externalEffect
		for _, effect := range effects {
			if effect.reason != "" {
				reasoned = append(reasoned, effect)
			}
		}
		if len(reasoned) == 0 {
			if selected != "" {
				t.Fatalf("reasonless set selected %q", selected)
			}
			return
		}
		if selected == "" {
			t.Fatalf("reasoned set selected nothing: %+v", reasoned)
		}
		bestRank := effectCauseRank(reasoned[0])
		for _, effect := range reasoned[1:] {
			if rank := effectCauseRank(effect); rank > bestRank {
				bestRank = rank
			}
		}
		var want string
		for _, candidate := range reasoned {
			if effectCauseRank(candidate) != bestRank {
				continue
			}
			if want == "" || candidate.reason < want {
				want = candidate.reason
			}
		}
		if selected != want {
			t.Fatalf("selected %q, want %q over %+v", selected, want, reasoned)
		}
		shuffled := append([]externalEffect(nil), effects...)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		if again := preferredEffectReason(shuffled); again != selected {
			t.Fatalf("selection is order-dependent: %q vs %q", selected, again)
		}
	})
}

// The shared rank table's symbol-free arms
// (REQ-closure-observability-cause-order): a symbol-free unaudited-import
// effect ranks with the down-ranked unaudited classification - never as
// a structural finding - while the receiver-escape structural finding
// (test-runtime kind, no symbol) keeps the top stratum, and the
// observable test-runtime classification stays last-resort.
func TestEffectCauseRankSymbolFreeStrata(t *testing.T) {
	if rank := effectCauseRank(opaqueExternalEffect(externalEffectUnauditedStandard, "reaches os (potential external dependence)")); rank != 0 {
		t.Fatalf("symbol-free unaudited import ranked %d, want the unaudited stratum", rank)
	}
	if rank := effectCauseRank(opaqueExternalEffect(externalEffectTestRuntime, "testing runtime value escapes analyzable receiver")); rank != 4 {
		t.Fatalf("receiver-escape structural finding ranked %d, want the top stratum", rank)
	}
	observable := opaqueExternalEffect(externalEffectTestRuntime, "testing.Short")
	observable.observable = true
	if rank := effectCauseRank(observable); rank != -1 {
		t.Fatalf("observable test-runtime effect ranked %d, want last resort", rank)
	}
	if rank := effectCauseRank(opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly")); rank != 4 {
		t.Fatalf("native finding ranked %d, want the top stratum", rank)
	}
	if rank := effectCauseRank(symbolExternalEffect(externalEffectUnauditedStandard, "os", "Getpid", "reaches unaudited standard operation os.Getpid")); rank != 0 {
		t.Fatalf("unaudited symbol ranked %d, want the unaudited stratum", rank)
	}
}

func TestListedNonStandardPathsPreservesDottedExternalClassifications(t *testing.T) {
	mod := &listMod{Path: "golang.org/x/sys", Version: "v0.30.0"}
	appMod := &listMod{Path: "app", Main: true}
	nonStd := listedNonStandardPaths([]listPkg{
		{ImportPath: "golang.org/x/sys/unix", Name: "unix", Module: mod},
		{ImportPath: "app/sub", Name: "sub", Module: appMod},
	})
	if nonStd["golang.org/x/sys/unix"] {
		t.Fatalf("listedNonStandardPaths included dotted external module: %+v", nonStd)
	}
	if !nonStd["app/sub"] {
		t.Fatalf("listedNonStandardPaths missed dotless user package app/sub: %+v", nonStd)
	}
	src := []byte(`package p

import (
	"app/sub"
	"golang.org/x/sys/unix"
)

func Reached() int {
	return sub.Add(1, 2)
}

func UnreachedUnixMutate() {
	_ = unix.Unlink("/tmp/x")
}

func UnreachedUnixHazard() {
	_ = unix.Chdir("/tmp")
}
`)
	// Even if a caller passes a map containing both dotted and dotless paths,
	// dotted external modules keep their import candidates, class-B effects,
	// and package-wide process-state hazards while dotless user packages are
	// never misclassified as unaudited standard operations.
	callerMap := map[string]bool{
		"golang.org/x/sys/unix": true,
		"app/sub":               true,
	}
	unfiltered, err := maximalFileEffectsContentWithContextFiltered(true, "/dir/p.go", src, nil, callerMap, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(unfiltered.importCandidates) == 0 || !strings.Contains(unfiltered.importCandidates[0].reason, "golang.org/x/sys/unix") {
		t.Fatalf("unfiltered importCandidates = %+v, want golang.org/x/sys/unix candidate", unfiltered.importCandidates)
	}
	sawUnlink, sawChdir := false, false
	for _, eff := range unfiltered.effects {
		if strings.Contains(eff.reason, "app/sub") {
			t.Fatalf("dotless user package misclassified as standard effect: %+v", eff)
		}
		if eff.packagePath == "golang.org/x/sys/unix" && eff.symbol == "Unlink" {
			sawUnlink = true
		}
		if eff.packagePath == "golang.org/x/sys/unix" && eff.symbol == "Chdir" {
			sawChdir = true
		}
	}
	if !sawUnlink || !sawChdir {
		t.Fatalf("unfiltered effects = %+v, want both unix.Unlink and unix.Chdir", unfiltered.effects)
	}

	reached := map[funcDeclKey]bool{{dir: "/dir", pkgClause: "p", name: "Reached"}: true}
	filtered, err := maximalFileEffectsContentWithContextFiltered(true, "/dir/p.go", src, nil, callerMap, reached)
	if err != nil {
		t.Fatal(err)
	}
	sawChdirFiltered := false
	for _, eff := range filtered.effects {
		if eff.packagePath == "golang.org/x/sys/unix" && eff.symbol == "Unlink" {
			t.Fatalf("unreached non-hazard unix.Unlink leaked into filtered scan: %+v", eff)
		}
		if eff.packagePath == "golang.org/x/sys/unix" && eff.symbol == "Chdir" {
			sawChdirFiltered = true
		}
	}
	if !sawChdirFiltered {
		t.Fatalf("filtered effects = %+v, want package-wide unix.Chdir hazard preserved", filtered.effects)
	}
}

func TestMaximalFactsRetainHiddenBlockers(t *testing.T) {
	identity := MaximalIdentity{Hash: "core", TestVariants: "tests", ToolchainContent: "content", AdmissionPolicy: "rules"}
	network := trueExternalEffect("net")
	environment, ok := classBEffect("os", "Getenv")
	if !ok {
		t.Fatal("missing environment classification")
	}
	one := newMaximalFacts(identity, []externalEffect{network}, network.reason)
	complete := newMaximalFacts(identity, []externalEffect{network, environment}, network.reason)
	if one.Closure() != complete.Closure() {
		t.Fatal("fixture must hide the environment blocker behind the same preferred reason")
	}
	if one.Equal(complete) || complete.Equal(one) {
		t.Fatal("equal legacy projections hid a changed blocker inventory")
	}
	if !complete.Equal(newMaximalFacts(identity, []externalEffect{environment, network}, network.reason)) {
		t.Fatal("scan traversal order changed complete facts")
	}
	want := []Blocker{
		{Kind: BlockerEnvironment, Package: "os", Symbol: "Getenv", Reason: environment.reason},
		{Kind: BlockerNetwork, Package: "net", Reason: network.reason},
	}
	if got := complete.Effects; !slices.Equal(got, want) {
		t.Fatalf("blockers = %+v, want %+v", got, want)
	}
	if complete.Identity != identity {
		t.Fatalf("identity = %+v, want %+v", complete.Identity, identity)
	}
	// Change every retained field independently, while holding the selected
	// reason and identity fixed. No field may disappear through projection.
	for name, change := range map[string]func(*externalEffect){
		"kind":        func(e *externalEffect) { e.kind = externalEffectFileIO },
		"package":     func(e *externalEffect) { e.packagePath = "other" },
		"symbol":      func(e *externalEffect) { e.symbol = "LookupEnv" },
		"detail":      func(e *externalEffect) { e.detail = "detail" },
		"reason":      func(e *externalEffect) { e.reason = "different diagnostic" },
		"observable":  func(e *externalEffect) { e.observable = true },
		"unrefinable": func(e *externalEffect) { e.unrefinable = true },
	} {
		t.Run(name, func(t *testing.T) {
			changed := environment
			change(&changed)
			other := newMaximalFacts(identity, []externalEffect{network, changed}, network.reason)
			if complete.Equal(other) || slices.Equal(complete.Effects, other.Effects) {
				t.Fatalf("changed %s disappeared from retained/projected facts", name)
			}
		})
	}
	for name, change := range map[string]func(*MaximalIdentity){
		"hash":     func(i *MaximalIdentity) { i.Hash += "x" },
		"variants": func(i *MaximalIdentity) { i.TestVariants += "x" },
		"content":  func(i *MaximalIdentity) { i.ToolchainContent += "x" },
		"policy":   func(i *MaximalIdentity) { i.AdmissionPolicy += "x" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := identity
			change(&changed)
			if complete.Equal(newMaximalFacts(changed, []externalEffect{environment, network}, network.reason)) {
				t.Fatalf("changed %s disappeared from identity equality", name)
			}
		})
	}
	if complete.Equal(newMaximalFacts(identity, []externalEffect{environment, network}, "another preferred diagnostic")) {
		t.Fatal("preferred diagnostic disappeared from full equality")
	}
}

func TestMaximalFactsOwnTheirInputsAndProjections(t *testing.T) {
	effect := externalEffect{kind: externalEffectNative, packagePath: "native", symbol: "F", detail: "body", reason: "native body", observable: true, unrefinable: true}
	input := []externalEffect{effect}
	facts := newMaximalFacts(MaximalIdentity{Hash: "core"}, input, effect.reason)
	want := Blocker{Kind: BlockerNative, Package: "native", Symbol: "F", Detail: "body", Reason: "native body", Observable: true, Unrefinable: true}
	input[0] = externalEffect{}
	copyOfFacts := facts.Clone()
	if len(facts.Effects) != 1 || facts.Effects[0] != want {
		t.Fatalf("constructor retained caller storage or lost fields: %+v", facts.Effects)
	}
	identity := facts.Identity
	identity.Hash = "changed"
	closure := facts.Closure()
	closure.Unverifiable = false
	closure.Hash = "changed"
	for _, retained := range []MaximalFacts{facts, copyOfFacts} {
		if got := retained.Effects; len(got) != 1 || got[0] != want {
			t.Fatalf("caller changed retained facts: %+v", got)
		}
		if retained.Identity.Hash != "core" || !retained.Closure().Unverifiable {
			t.Fatal("caller changed identity or closure through a projection")
		}
	}
	facts.Effects[0] = Blocker{}
	facts.Identity.Hash = "changed"
	facts.Diagnostic = "changed"
	if copyOfFacts.Effects[0] != want || copyOfFacts.Identity.Hash != "core" || copyOfFacts.Diagnostic != effect.reason {
		t.Fatal("caller changed cloned facts")
	}
}

func TestMaximalFactsAvailabilityAndDiagnosticOnlyCandidate(t *testing.T) {
	for _, facts := range []MaximalFacts{{}, {Identity: MaximalIdentity{TestVariants: "partial"}}} {
		if got := facts.Closure(); !got.Unverifiable || got.Reason == "" {
			t.Fatalf("unavailable facts supplied a positive projection: %+v", got)
		}
	}
	// An unused plain import can be a diagnostic candidate without being a
	// blocker. Preserve that distinction rather than reading Reason as evidence.
	scan, err := maximalFileEffectsContent(true, "candidate.go", []byte("package p\nimport \"net\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.effects) != 0 || scan.preferred == "" {
		t.Fatalf("fixture did not produce a diagnostic-only candidate: %+v", scan)
	}
	identity := MaximalIdentity{Hash: "core", TestVariants: "tests", ToolchainContent: "content", AdmissionPolicy: "rules"}
	facts := newMaximalFacts(identity, scan.effects, scan.preferred)
	want := Closure{Hash: "core", TestVariants: "tests", ToolchainContent: "content", AdmissionPolicy: "rules", Reason: scan.preferred}
	if got := facts.Closure(); got != want || len(facts.Effects) != 0 {
		t.Fatalf("diagnostic-only projection = %+v, want %+v", got, want)
	}
}

func TestComputeMaximalFactsBatchPreservesCompleteScanAndProjection(t *testing.T) {
	dir := t.TempDir()
	for name, text := range map[string]string{
		"go.mod": "module example.com/facts\n\ngo 1.26\n",
		"p.go": `package facts
import ("os"; "net"; "crypto/rand")
func Pure() {}
func Effects() { _ = os.Getenv("INPUT"); _, _ = net.Dial("tcp", "example.invalid:1"); _, _ = rand.Read(nil) }
`,
		"p_test.go": "package facts\nimport (\"testing\"; \"os\")\nfunc TestPure(t *testing.T) { Pure(); _ = os.Getenv(\"OTHER\") }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{{Package: "example.com/facts", Symbol: "Pure"}, {Package: "example.com/facts", Symbol: "TestPure"}}
	facts, sources, err := h.ComputeMaximalFactsBatch(append(slices.Clone(subjects), subjects[0]))
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != len(subjects) || len(sources) != len(subjects) {
		t.Fatalf("batch membership = %d facts, %d sources", len(facts), len(sources))
	}
	for _, subject := range subjects {
		got := facts[subject]
		if !got.Closure().Unverifiable {
			t.Fatalf("package-wide effects disappeared for %s", subject.Symbol)
		}
		for _, want := range []Blocker{
			{Kind: BlockerEnvironment, Package: "os", Symbol: "Getenv"},
			{Kind: BlockerNetwork, Package: "net", Symbol: "Dial"},
			{Kind: BlockerNative, Package: "crypto/rand", Symbol: "Read"},
		} {
			count := 0
			for _, blocker := range got.Effects {
				if blocker.Kind == want.Kind && blocker.Package == want.Package && blocker.Symbol == want.Symbol {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("%s: classification %+v has %d entries in %+v", subject.Symbol, want, count, got.Effects)
			}
		}
		if len(sources[subject]) != 2 {
			t.Fatalf("%s: incomplete source set: %v", subject.Symbol, sources[subject])
		}
	}
	if facts[subjects[0]].Identity.Hash == facts[subjects[1]].Identity.Hash ||
		!slices.Equal(facts[subjects[0]].Effects, facts[subjects[1]].Effects) {
		t.Fatal("subjects must retain distinct identities beside shared package-wide classifications")
	}
	legacy, legacySources, err := h.ComputeMaximalBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range subjects {
		if got := facts[subject].Closure(); got != legacy[subject] || !reflect.DeepEqual(sources[subject], legacySources[subject]) {
			t.Fatalf("%s: facts and legacy projections differ: %+v / %+v", subject.Symbol, got, legacy[subject])
		}
	}
	sources[subjects[0]][0] = "caller-owned"
	if sources[subjects[1]][0] == "caller-owned" {
		t.Fatal("subjects share mutable source slices")
	}
	// A later pass on the same hasher cannot rewrite the facts already returned.
	if !slices.Equal(facts[subjects[0]].Effects, facts[subjects[1]].Effects) {
		t.Fatal("later computation mutated retained facts")
	}
	facts[subjects[0]].Effects[0] = Blocker{}
	if facts[subjects[1]].Effects[0] == (Blocker{}) {
		t.Fatal("subjects share caller-mutable effect slices")
	}
}

func TestComputeMaximalFactsBatchCancellationReturnsNoFacts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := &Hasher{ctx: ctx}
	facts, sources, err := h.ComputeMaximalFactsBatch([]Subject{{Package: "example.com/facts", Symbol: "F"}})
	if !errors.Is(err, context.Canceled) || facts != nil || sources != nil {
		t.Fatalf("cancelled batch = %v, %v, %v", facts, sources, err)
	}
}

// effectScanCorpusFiles composes a deterministic corpus over the scan's
// input surface: import shapes (plain, aliased, dot, underscore, testing,
// always-external, classified-API standard, source-only standard,
// non-standard), directive markers (as directives and as string-literal
// decoys), Class-B and unaudited selector uses, testing-handle flows
// (methods, escapes through assignments, call arguments, returns, spec
// propagation, wrapper handle types), and unparseable inputs.
func effectScanCorpusFiles() map[string]string {
	imports := []string{
		"",
		"import \"os\"\n",
		"import o \"os\"\n",
		"import . \"os\"\n",
		"import _ \"os\"\n",
		"import \"strings\"\n",
		"import . \"strings\"\n",
		"import \"net\"\n",
		"import _ \"net\"\n",
		"import \"testing\"\n",
		"import . \"testing\"\n",
		"import \"example.com/dep\"\n",
		"import (\n\t\"os\"\n\t\"testing\"\n)\n",
		// A major-versioned path binds the element before the version;
		// two imports deriving one identifier refuse the file.
		"import \"math/rand/v2\"\n",
		"import r \"math/rand/v2\"\n",
		"import . \"math/rand/v2\"\n",
		"import (\n\t\"net\"\n\t\"example.com/dep/net/v1\"\n)\n",
		"import (\n\t\"os\"\n\t\"example.com/dep/os/v2\"\n)\n",
		"import (\n\t\"example.com/dep/core/v1\"\n\t\"example.com/dep/core/v2\"\n)\n",
		"import (\n\t\"example.com/dep/alpha/v2\"\n\t\"example.com/dep/beta/v2\"\n)\n",
		"import (\n\t\"net/http\"\n\t\"example.com/dep/http\"\n)\n",
		"import (\n\tv2 \"net\"\n\t\"example.com/dep/mod/v2\"\n)\n",
		"import (\n\t\"example.com/dep/mod/v2\"\n\tv2 \"net\"\n)\n",
	}
	bodies := []string{
		"",
		"func F() { _, _ = os.ReadFile(\"x\") }\n",
		"func F() { _ = os.ReadFile }\n",
		"func F() { _ = time.Now() }\n",
		"func F() { _ = strings.Join(nil, \"\") }\n",
		"func F() { _, _ = net.Dial(\"tcp\", \"x\") }\n",
		"func F() { _ = dep.G() }\n",
		"func F() { _ = rand.IntN(3) }\n",
		"func F() { _ = r.IntN(3) }\n",
		"func F() { _ = IntN(3) }\n",
		"func F() { _ = v1.N() + v2.N() }\n",
		"func F() { _ = alpha.N() + beta.N() }\n",
		"func F() { _, _ = v2.Dial(\"tcp\", \"x\"); _ = mod.N() }\n",
		"func TestX(t *testing.T) { t.Setenv(\"K\", \"V\") }\n",
		"func TestX(t *testing.T) { u := t; u.TempDir() }\n",
		"func TestX(t *testing.T) { var u = t; _ = u }\n",
		"func TestX(t *testing.T) { use(t) }\nfunc use(any) {}\n",
		"func TestX(t *testing.T) *testing.T { return t }\n",
		"type Bench struct{ *testing.B }\nfunc G(b *Bench) { _ = b.N }\n",
		"func F() { s := \"//go:wasmimport\"; _ = s }\n",
		"func F() { s := \"//go:linkname\"; _ = s }\n",
		"//go:linkname F runtime.f\nfunc F()\n",
		// TestMain shapes: the os.Exit epilogue admission is
		// declaration-scoped in the scan, and the dot-imported bare *M
		// form is a valid harness TestMain.
		"func TestMain(m *testing.M) { os.Exit(m.Run()) }\n",
		"func TestMain(m *M) { os.Exit(m.Run()) }\n",
		"func TestMain(m *testing.M) { os.Exit(m.Run()) }\nfunc H() { os.Exit(3) }\n",
		"func TestMain(m *testing.M) { _ = m }\nfunc TestMain2() { os.Exit(1) }\n",
	}
	directives := []string{"", "//go:wasmimport env f\n"}
	files := map[string]string{}
	n := 0
	for i, imp := range imports {
		for j, body := range bodies {
			// Sample the cross-product diagonally plus both axes so the
			// corpus stays small while every row and column appears.
			if i != 0 && j != 0 && (i+j)%3 != 0 {
				continue
			}
			for k, directive := range directives {
				if k == 1 && (i+j)%5 != 0 {
					continue
				}
				files[fmt.Sprintf("case%03d.go", n)] = directive + "package corpus\n\n" + imp + "\n" + body
				n++
			}
		}
	}
	files["unparseable_body.go"] = "package corpus\n\nfunc F() {\n"
	files["nul_import_path.go"] = "package corpus\n\nimport \"\\x00\"\n"
	files["import_syntax_error.go"] = "package corpus\n\nimport foo\n\nfunc F() {\n"
	files["wasm_and_unparseable.go"] = "//go:wasmimport env f\npackage corpus\n\nfunc F() {\n"
	// Named TestMain pairs the diagonal sampling cannot guarantee: the
	// os.Exit epilogue admission is declaration-scoped, and the
	// dot-imported bare *M form is a valid harness TestMain.
	files["testmain_exit.go"] = "package corpus\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestMain(m *testing.M) { os.Exit(m.Run()) }\n"
	files["testmain_dot_exit.go"] = "package corpus\n\nimport (\n\t\"os\"\n\t. \"testing\"\n)\n\nfunc TestMain(m *M) { os.Exit(m.Run()) }\n"
	files["testmain_helper_exit.go"] = "package corpus\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestMain(m *testing.M) { os.Exit(m.Run()) }\n\nfunc H() { os.Exit(3) }\n"
	files["testmain_wrong_name.go"] = "package corpus\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestMain(m *testing.M) { _ = m }\n\nfunc TestMain2() { os.Exit(1) }\n"
	// L3 named pairs the diagonal sampling misses, plus alias collisions —
	// this corpus is also the walk-consolidation refactor's oracle.
	files["pair_os_readfile.go"] = "package corpus\n\nimport \"os\"\n\nfunc F() { _, _ = os.ReadFile(\"x\") }\n"
	files["pair_dot_strings_join.go"] = "package corpus\n\nimport . \"strings\"\n\nfunc F() { _ = Join(nil, \"\") }\n"
	files["pair_group_setenv.go"] = "package corpus\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestX(t *testing.T) { t.Setenv(\"K\", \"V\"); _ = os.Args }\n"
	files["pair_dot_os_selector.go"] = "package corpus\n\nimport . \"os\"\nimport \"os\"\n\nfunc F() { _, _ = os.ReadFile(\"x\") }\n"
	files["dup_alias.go"] = "package corpus\n\nimport o \"os\"\nimport o \"strings\"\n\nfunc F() { _ = o.Join }\n"
	files["dup_path.go"] = "package corpus\n\nimport \"os\"\nimport osx \"os\"\n\nfunc F() { _, _ = osx.ReadFile(\"x\") }\n"
	// Backward receiver propagation: v is reachable from t only on the
	// fixed-point's second iteration (v = u precedes u = t in source
	// order), so v.TempDir classifies only if the propagation iterates.
	files["fixedpoint_backward.go"] = "package corpus\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {\n\tvar u, v *testing.T\n\tfor i := 0; i < 2; i++ {\n\t\tv = u\n\t\tu = t\n\t}\n\tv.TempDir()\n}\n"
	// A package-level shadow makes the pre-declaration read legal, and the
	// walker is name-based and scope-blind: w is reachable from t only when
	// the ValueSpec-triggered iteration re-runs the earlier assignment.
	files["fixedpoint_valuespec_backward.go"] = "package corpus\n\nimport \"testing\"\n\nvar v *testing.T\n\nfunc TestX(t *testing.T) {\n\tw := v\n\tvar v = t\n\tv.Helper()\n\tw.TempDir()\n}\n"
	// The dot-testing potential-external overwrite fires after another
	// dot import already set the fallback, and in the reverse order.
	files["dot_os_then_dot_testing.go"] = "package corpus\n\nimport . \"os\"\nimport . \"testing\"\n\nfunc F() {}\n"
	// A dot always-external import records the effect outright and
	// feeds no candidate; in the dot+plain mix the plain alias adds
	// the candidate beside the dot spelling's effect.
	files["dot_net.go"] = "package corpus\n\nimport . \"net\"\n\nfunc F() { _ = IPv4len }\n"
	files["dot_plus_plain_net.go"] = "package corpus\n\nimport . \"net\"\nimport nn \"net\"\n\nfunc F() { _ = nn.IPv4len }\n"
	files["dot_testing_then_dot_os.go"] = "package corpus\n\nimport . \"testing\"\nimport . \"os\"\n\nfunc F() {}\n"
	// Two test functions with distinct non-empty testing reasons pin the
	// rank-and-lexicographic selection across function walks.
	files["two_testing_reasons.go"] = "package corpus\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) { t.Setenv(\"K\", \"V\") }\n\nfunc TestB(t *testing.T) { t.TempDir() }\n"
	return files
}

// TestFileEffectScanMatchesTwoPassReference pins the single-pass scan to
// the reference two-pass implementation over the generated corpus: for
// every input, identical scans (effects, order, preferred diagnostic) and
// identical error dispositions. The scan is a pure function of file bytes,
// so reference equality is the refactor's complete correctness oracle.
func TestFileEffectScanMatchesTwoPassReference(t *testing.T) {
	dir := t.TempDir()
	for name, content := range effectScanCorpusFiles() {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		got, gotErr := maximalFileEffects(true, path)
		want, wantErr := referenceMaximalFileEffects(path)
		if (gotErr == nil) != (wantErr == nil) {
			t.Fatalf("%s: error disposition diverged: got %v, reference %v\ninput:\n%s", name, gotErr, wantErr, content)
		}
		if gotErr != nil {
			// Error DISPOSITION is the oracle; text is not contract (the
			// single parse legitimately reports trailing errors the
			// reference's imports-only first parse never reached).
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: scan diverged:\n got %+v\nwant %+v\ninput:\n%s", name, got, want, content)
		}
	}
}

// TestFileEffectScanMatchesReferenceOverRepository sweeps every parseable
// Go file of this repository through both implementations — real-world
// inputs beyond the generated grammar.
func TestFileEffectScanMatchesReferenceOverRepository(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == ".stipulator" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		got, gotErr := maximalFileEffects(true, path)
		want, wantErr := referenceMaximalFileEffects(path)
		if (gotErr == nil) != (wantErr == nil) {
			t.Fatalf("%s: error disposition diverged: got %v, reference %v", path, gotErr, wantErr)
		}
		if gotErr == nil && !reflect.DeepEqual(got, want) {
			t.Errorf("%s: scan diverged:\n got %+v\nwant %+v", path, got, want)
		}
		count++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count < 50 {
		t.Fatalf("swept only %d files; expected the repository", count)
	}
}

//gofresh:pure
func BenchmarkMaximalFileEffects(b *testing.B) {
	dir := b.TempDir()
	var sb strings.Builder
	sb.WriteString("package bench\n\nimport (\n\t\"os\"\n\t\"strings\"\n\t\"testing\"\n)\n\n")
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&sb, "func F%d() { _, _ = os.ReadFile(\"x\"); _ = strings.Join(nil, \"\") }\n", i)
	}
	sb.WriteString("func TestX(t *testing.T) { t.Setenv(\"K\", \"V\") }\n")
	path := filepath.Join(dir, "big.go")
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := maximalFileEffects(true, path); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkTestingHeavyFileEffects exercises the receiver-propagation
// machinery the production-function benchmark above cannot: every
// function is a test with a propagation chain, so the fixed point and
// the testing walks dominate.
//
//gofresh:pure
func BenchmarkTestingHeavyFileEffects(b *testing.B) {
	dir := b.TempDir()
	var sb strings.Builder
	sb.WriteString("package bench\n\nimport \"testing\"\n\n")
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&sb, "func TestX%d(t *testing.T) { u := t; u.TempDir(); v := u; _ = v }\n", i)
	}
	path := filepath.Join(dir, "big_test.go")
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := maximalFileEffects(true, path); err != nil {
			b.Fatal(err)
		}
	}
}

func referenceMaximalFileReason(filename string) (string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	if strings.Contains(string(content), "//go:wasmimport") {
		return "reaches go:wasmimport", nil
	}
	if strings.Contains(string(content), "//go:linkname") && !auditedLinknamesOnly(true, string(content)) {
		return "reaches go:linkname (opaque linkage)", nil
	}
	file, err := parser.ParseFile(token.NewFileSet(), filename, content, parser.ImportsOnly)
	if err != nil {
		return "", fmt.Errorf("closure: parse %s: %w", filename, err)
	}
	aliases := make(map[string]string, len(file.Imports))
	potentialExternal := ""
	unauditedReason := ""
	collisionReason := ""
	secondaries := map[string][]string{}
	versioned := map[string]bool{}
	explicit := map[string]bool{}
	for _, spec := range file.Imports {
		pkgPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return "", fmt.Errorf("closure: parse import in %s: %w", filename, err)
		}
		alias := path.Base(pkgPath)
		named := spec.Name != nil
		if named {
			alias = spec.Name.Name
		} else if derived := referenceImportName(pkgPath); derived != alias {
			secondaries[derived] = append(secondaries[derived], pkgPath)
			versioned[pkgPath] = true
		}
		prior, taken := aliases[alias]
		clash := taken && prior != pkgPath && alias != "_" && alias != "."
		if named {
			clash = clash && explicit[alias]
			explicit[alias] = true
		} else {
			if explicit[alias] {
				clash = false
			}
			clash = clash && !(versioned[prior] && versioned[pkgPath])
		}
		if clash {
			if c := "import name collision at the file scan: " + prior + " and " + pkgPath + " both bind " + alias; collisionReason == "" || c < collisionReason {
				collisionReason = c
			}
		}
		if named || !explicit[alias] {
			aliases[alias] = pkgPath
		}
		if pkgPath == "testing" {
			if alias == "." {
				potentialExternal = pkgPath
				if unauditedReason == "" {
					unauditedReason = "reaches testing (potential external dependence)"
				}
			}
			continue
		}
		if isAlwaysExternalPackage(pkgPath) {
			return trueReason(pkgPath), nil
		}
		if alias == "." && packageHasClassifiedExternalAPI(pkgPath) && potentialExternal == "" {
			potentialExternal = pkgPath
		}
		if potentialExternal == "" && !(alias == "_" && pkgPath == "unsafe") && isStdImportPath(pkgPath) && !isSourceOnlyStandardPackage(true, pkgPath) {
			potentialExternal = pkgPath
		}
		if (alias == "." || (alias == "_" && pkgPath != "unsafe")) && (packageHasClassifiedExternalAPI(pkgPath) || isStdImportPath(pkgPath) && !isSourceOnlyStandardPackage(true, pkgPath)) && unauditedReason == "" {
			unauditedReason = "reaches " + pkgPath + " (potential external dependence)"
		}
	}

	for name, paths := range secondaries {
		if _, claimed := aliases[name]; !claimed && len(paths) == 1 {
			aliases[name] = paths[0]
		}
	}
	// Reparse with bodies only when imports include packages whose individual
	// calls distinguish external operations from ordinary deterministic APIs.
	file, err = parser.ParseFile(token.NewFileSet(), filename, content, 0)
	if err != nil {
		return "", fmt.Errorf("closure: parse %s: %w", filename, err)
	}
	var reason string
	ast.Inspect(file, func(node ast.Node) bool {
		if reason != "" {
			return false
		}
		if sel, ok := node.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if pkgPath := aliases[ident.Name]; pkgPath != "" {
					if classified := classBReason(pkgPath, sel.Sel.Name); classified != "" {
						reason = classified
						return false
					}
					if pkgPath != "testing" && !flagRegistrationSymbol(pkgPath, sel.Sel.Name) && !auditedStandardSymbol(true, pkgPath, sel.Sel.Name) && (isAlwaysExternalPackage(pkgPath) || isStdImportPath(pkgPath) && !isSourceOnlyStandardPackage(true, pkgPath)) && unauditedReason == "" {
						unauditedReason = "reaches unaudited standard operation " + pkgPath + "." + sel.Sel.Name
					}
				}
			}
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if pkgPath := aliases[ident.Name]; pkgPath != "" {
			reason = classBReason(pkgPath, sel.Sel.Name)
		}
		return true
	})
	if reason == "" {
		reason = referenceTestingMethodReason(file, aliases)
	}
	// A derived-name collision is an unaudited-class refusal like the
	// selector fallback: within the class the least reason wins.
	if collisionReason != "" && (unauditedReason == "" || collisionReason < unauditedReason) {
		unauditedReason = collisionReason
	}
	if reason == "" {
		reason = unauditedReason
	}
	if reason != "" {
		return reason, nil
	}
	if potentialExternal != "" {
		return "reaches " + potentialExternal + " (potential external dependence)", nil
	}
	return "", nil
}

// referencePreferredOverPool is the filter-style selection oracle: max
// cause rank, lexicographic least within it - independent of
// production's streaming compare.
func referencePreferredOverPool(pool []externalEffect) string {
	var reasoned []externalEffect
	for _, effect := range pool {
		if effect.reason != "" {
			reasoned = append(reasoned, effect)
		}
	}
	if len(reasoned) == 0 {
		return ""
	}
	bestRank := effectCauseRank(reasoned[0])
	for _, effect := range reasoned[1:] {
		if rank := effectCauseRank(effect); rank > bestRank {
			bestRank = rank
		}
	}
	want := ""
	for _, effect := range reasoned {
		if effectCauseRank(effect) != bestRank {
			continue
		}
		if want == "" || effect.reason < want {
			want = effect.reason
		}
	}
	return want
}

func referenceMaximalFileEffects(filename string) (maximalEffectScan, error) {
	var scan maximalEffectScan
	content, err := os.ReadFile(filename)
	if err != nil {
		return maximalEffectScan{}, err
	}
	if strings.Contains(string(content), "//go:wasmimport") {
		effect := opaqueExternalEffect(externalEffectLinkage, "reaches go:wasmimport")
		effect.unrefinable = true
		scan.add(effect)
	}
	if strings.Contains(string(content), "//go:linkname") && !auditedLinknamesOnly(true, string(content)) {
		scan.add(opaqueExternalEffect(externalEffectLinkage, "reaches go:linkname (opaque linkage)"))
	}
	file, err := parser.ParseFile(token.NewFileSet(), filename, content, 0)
	if err != nil {
		return maximalEffectScan{}, fmt.Errorf("closure: parse %s: %w", filename, err)
	}
	aliases := make(map[string]string, len(file.Imports))
	secondaries := map[string][]string{}
	versioned := map[string]bool{}
	explicit := map[string]bool{}
	for _, spec := range file.Imports {
		pkgPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return maximalEffectScan{}, fmt.Errorf("closure: parse import in %s: %w", filename, err)
		}
		alias := path.Base(pkgPath)
		named := spec.Name != nil
		if named {
			alias = spec.Name.Name
		} else if derived := referenceImportName(pkgPath); derived != alias {
			secondaries[derived] = append(secondaries[derived], pkgPath)
			versioned[pkgPath] = true
		}
		prior, taken := aliases[alias]
		clash := taken && prior != pkgPath && alias != "_" && alias != "."
		if named {
			clash = clash && explicit[alias]
			explicit[alias] = true
		} else {
			if explicit[alias] {
				clash = false
			}
			clash = clash && !(versioned[prior] && versioned[pkgPath])
		}
		if clash {
			scan.add(opaqueExternalEffect(externalEffectUnauditedStandard, "import name collision at the file scan: "+prior+" and "+pkgPath+" both bind "+alias))
		}
		if named || !explicit[alias] {
			aliases[alias] = pkgPath
		}
		if pkgPath == "testing" {
			if alias == "." {
				scan.add(opaqueExternalEffect(externalEffectUnauditedStandard, "reaches testing (potential external dependence)"))
			}
			continue
		}
		if isAlwaysExternalPackage(pkgPath) && alias != "." && alias != "_" {
			scan.importCandidates = append(scan.importCandidates, trueExternalEffect(pkgPath))
		}
		if alias == "." || (alias == "_" && pkgPath != "unsafe") {
			if isAlwaysExternalPackage(pkgPath) {
				scan.add(trueExternalEffect(pkgPath))
			} else if packageHasClassifiedExternalAPI(pkgPath) || isStdImportPath(pkgPath) && !isSourceOnlyStandardPackage(true, pkgPath) {
				scan.add(opaqueExternalEffect(externalEffectUnauditedStandard, "reaches "+pkgPath+" (potential external dependence)"))
			}
		}
	}
	for name, paths := range secondaries {
		if _, claimed := aliases[name]; !claimed && len(paths) == 1 {
			aliases[name] = paths[0]
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		sel, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		pkgPath := aliases[ident.Name]
		if effect, ok := classBEffect(pkgPath, sel.Sel.Name); ok {
			scan.add(effect)
		} else if pkgPath == "os" && sel.Sel.Name == "Exit" && referenceInTestMain(file, aliases, sel) {
			// admitted test-main epilogue - mirrors the production
			// carve-out
		} else if flagRegistrationSymbol(pkgPath, sel.Sel.Name) {
			// mirrors the production flag-registration admission
		} else if pkgPath != "testing" && !auditedStandardSymbol(true, pkgPath, sel.Sel.Name) && (isAlwaysExternalPackage(pkgPath) || isStdImportPath(pkgPath) && !isSourceOnlyStandardPackage(true, pkgPath)) {
			scan.add(symbolExternalEffect(externalEffectUnauditedStandard, pkgPath, sel.Sel.Name, "reaches unaudited standard operation "+pkgPath+"."+sel.Sel.Name))
		}
		return true
	})
	for _, effect := range referenceTestingMethodEffects(file, aliases) {
		scan.add(effect)
	}
	scan.preferred = referencePreferredOverPool(append(append([]externalEffect(nil), scan.effects...), scan.importCandidates...))
	if scan.preferred == "" {
		// An empty pool reduces the frozen reason ladder to its
		// potential-external fallback, the one arm the selection keeps.
		fallback, err := referenceMaximalFileReason(filename)
		if err != nil {
			return maximalEffectScan{}, err
		}
		scan.preferred = fallback
	}
	return scan, nil
}

// Frozen reason-walk twins the production scan collapsed onto the
// effects walk; the reference two-pass shape still consults them.
func referenceTestingMethodReason(file *ast.File, aliases map[string]string) string {
	return referenceTestingMethodReasonWithHandleTypes(file, aliases, testingHandleTypeNames(file, aliases))
}

func referenceTestingMethodReasonWithHandleTypes(file *ast.File, aliases map[string]string, handleTypes map[string]bool) string {
	if file == nil {
		return ""
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Type.Params == nil || function.Body == nil {
			continue
		}
		receivers := map[string]bool{}
		for _, field := range function.Type.Params.List {
			if isTestingHandleType(field.Type, aliases, handleTypes) {
				for _, name := range field.Names {
					receivers[name.Name] = true
				}
			}
		}
		changed := true
		for changed {
			changed = false
			ast.Inspect(function.Body, func(node ast.Node) bool {
				if specification, ok := node.(*ast.ValueSpec); ok {
					for i, value := range specification.Values {
						name, ok := identifierName(value)
						if ok && receivers[name] && i < len(specification.Names) && !receivers[specification.Names[i].Name] {
							receivers[specification.Names[i].Name] = true
							changed = true
						}
					}
				}
				assignment, ok := node.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for i, rhs := range assignment.Rhs {
					name, ok := identifierName(rhs)
					if !ok || !receivers[name] || i >= len(assignment.Lhs) {
						continue
					}
					if lhs, ok := assignment.Lhs[i].(*ast.Ident); ok && !receivers[lhs.Name] {
						receivers[lhs.Name] = true
						changed = true
					}
				}
				return true
			})
		}
		parents := make(map[ast.Node]ast.Node)
		var stack []ast.Node
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if node == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			if len(stack) != 0 {
				parents[node] = stack[len(stack)-1]
			}
			stack = append(stack, node)
			return true
		})
		var reason string
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.AssignStmt:
				for i, rhs := range node.Rhs {
					name, ok := identifierName(rhs)
					if !ok || !receivers[name] || i >= len(node.Lhs) {
						continue
					}
					if _, ok := node.Lhs[i].(*ast.Ident); !ok {
						reason = "testing runtime value escapes analyzable receiver"
						return false
					}
				}
			case *ast.CallExpr:
				for _, argument := range node.Args {
					if name, ok := identifierName(argument); ok && receivers[name] {
						reason = "testing runtime value escapes analyzable receiver"
						return false
					}
				}
			case *ast.ReturnStmt:
				for _, result := range node.Results {
					if name, ok := identifierName(result); ok && receivers[name] {
						reason = "testing runtime value escapes analyzable receiver"
						return false
					}
				}
			case *ast.Ident:
				if receivers[node.Name] && !testingIdentifierUseSupported(node, parents) {
					reason = "testing runtime value escapes analyzable receiver"
					return false
				}
			}
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			receiver, ok := selector.X.(*ast.Ident)
			if !ok || !receivers[receiver.Name] {
				return true
			}
			reason = classBReason("testing", selector.Sel.Name)
			return reason == ""
		})
		if reason != "" {
			return reason
		}
	}
	return ""
}

func referenceTestingMethodEffects(file *ast.File, aliases map[string]string) []externalEffect {
	if file == nil {
		return nil
	}
	handleTypes := testingHandleTypeNames(file, aliases)
	var effects []externalEffect
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Type.Params == nil || function.Body == nil {
			continue
		}
		receivers := map[string]bool{}
		for _, field := range function.Type.Params.List {
			if isTestingHandleType(field.Type, aliases, handleTypes) {
				for _, name := range field.Names {
					receivers[name.Name] = true
				}
			}
		}
		changed := true
		for changed {
			changed = false
			ast.Inspect(function.Body, func(node ast.Node) bool {
				if specification, ok := node.(*ast.ValueSpec); ok {
					for i, value := range specification.Values {
						name, ok := identifierName(value)
						if ok && receivers[name] && i < len(specification.Names) && !receivers[specification.Names[i].Name] {
							receivers[specification.Names[i].Name] = true
							changed = true
						}
					}
				}
				assignment, ok := node.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for i, rhs := range assignment.Rhs {
					name, ok := identifierName(rhs)
					if !ok || !receivers[name] || i >= len(assignment.Lhs) {
						continue
					}
					if lhs, ok := assignment.Lhs[i].(*ast.Ident); ok && !receivers[lhs.Name] {
						receivers[lhs.Name] = true
						changed = true
					}
				}
				return true
			})
		}
		parents := make(map[ast.Node]ast.Node)
		var stack []ast.Node
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if node == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			if len(stack) != 0 {
				parents[node] = stack[len(stack)-1]
			}
			stack = append(stack, node)
			return true
		})
		escape := opaqueExternalEffect(externalEffectTestRuntime, "testing runtime value escapes analyzable receiver")
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.AssignStmt:
				for i, rhs := range node.Rhs {
					name, ok := identifierName(rhs)
					if ok && receivers[name] && i < len(node.Lhs) {
						if _, ok := node.Lhs[i].(*ast.Ident); !ok {
							effects = appendExternalEffect(effects, escape)
						}
					}
				}
			case *ast.CallExpr:
				for _, argument := range node.Args {
					if name, ok := identifierName(argument); ok && receivers[name] {
						effects = appendExternalEffect(effects, escape)
					}
				}
			case *ast.ReturnStmt:
				for _, result := range node.Results {
					if name, ok := identifierName(result); ok && receivers[name] {
						effects = appendExternalEffect(effects, escape)
					}
				}
			case *ast.Ident:
				if receivers[node.Name] && !testingIdentifierUseSupported(node, parents) {
					effects = appendExternalEffect(effects, escape)
				}
			}
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			receiver, ok := selector.X.(*ast.Ident)
			if !ok || !receivers[receiver.Name] {
				return true
			}
			if effect, ok := classBEffect("testing", selector.Sel.Name); ok {
				effects = appendExternalEffect(effects, effect)
			}
			return true
		})
	}
	return effects
}

// referenceInTestMain is an independently written check that node lies
// inside the user TestMain(*testing.M) declaration - the reference's
// own walk, not a call into the production detector.
func referenceInTestMain(file *ast.File, aliases map[string]string, node ast.Node) bool {
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Name == nil || fd.Name.Name != "TestMain" {
			continue
		}
		if fd.Type == nil || fd.Type.Params == nil || len(fd.Type.Params.List) != 1 || len(fd.Type.Params.List[0].Names) > 1 {
			continue
		}
		star, ok := fd.Type.Params.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		// Both harness shapes: *testing.M under the file's own import
		// alias, and bare *M under a dot-imported testing.
		switch x := star.X.(type) {
		case *ast.SelectorExpr:
			pkgIdent, ok := x.X.(*ast.Ident)
			if !ok || x.Sel == nil || x.Sel.Name != "M" || aliases[pkgIdent.Name] != "testing" {
				continue
			}
		case *ast.Ident:
			if x.Name != "M" || aliases["."] != "testing" {
				continue
			}
		default:
			continue
		}
		return node.Pos() >= fd.Pos() && node.End() <= fd.End()
	}
	return false
}

// referenceImportName is the reference scan's own spelling of the
// unnamed-import rule: the path's last element, past a trailing
// major-version element — kept independent of the production helper
// so the equivalence pin judges the rule, not one implementation.
func referenceImportName(pkgPath string) string {
	base := path.Base(pkgPath)
	if len(base) > 1 && base[0] == 'v' {
		digits := true
		for _, r := range base[1:] {
			if r < '0' || r > '9' {
				digits = false
				break
			}
		}
		if digits {
			if dir := path.Dir(pkgPath); dir != "." && dir != "/" {
				return path.Base(dir)
			}
		}
	}
	return base
}
