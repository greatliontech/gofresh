package closure

import (
	"context"
	"go/token"
	"go/types"
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
	reason, err := maximalFileReason(filename)
	if err != nil {
		t.Fatal(err)
	}
	if reason != "" {
		t.Fatalf("unrelated Setenv method classified as testing API: %q", reason)
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
	if reason := maximalPackageExternalReason(pkg); !strings.Contains(reason, "cgo") {
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

func TestAssemblyExternalStateInstructionIsClassified(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "external.s"), []byte("TEXT ·F(SB), $0-0\n\tRDTSC\n\tRET\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reason, err := asmExternalStateReason(dir, []string{"external.s"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reason, "RDTSC") {
		t.Fatalf("assembly external-state reason = %q, want RDTSC", reason)
	}
}

func TestAssemblySystemInstructionClassesAreExternal(t *testing.T) {
	for _, opcode := range []string{"MRS", "XGETBV", "RDPMC", "CSRRW", "SYSCALL", "MFTB"} {
		if !asmOpcodeReadsExternalState(opcode) {
			t.Fatalf("assembly system opcode %s was treated as deterministic", opcode)
		}
	}
	if asmOpcodeReadsExternalState("ADDQ") {
		t.Fatal("ordinary arithmetic opcode ADDQ treated as external state")
	}
}

func TestAssemblyExternalStateOperandsAreClassified(t *testing.T) {
	for _, fields := range [][]string{{"MOVQ", "TLS", "AX"}, {"MOVQ", "0(FS)", "AX"}, {"MOVQ", "0(GS)", "AX"}, {"MOVQ", "0(AX)", "BX"}} {
		if operand := asmExternalStateOperand(fields); operand == "" {
			t.Fatalf("assembly operands %v were treated as deterministic", fields)
		}
	}
	if operand := asmExternalStateOperand([]string{"MOVQ", "0(SP)", "AX"}); operand != "" {
		t.Fatalf("ordinary stack operand classified external: %q", operand)
	}
	if operand := asmExternalStateOperand([]string{"MOVQ", "os·Stdout(SB)", "AX"}); operand != "cross-package SB symbol" {
		t.Fatalf("cross-package SB operand = %q, want external", operand)
	}
	if operand := asmExternalStateOperand([]string{"MOVQ", "·local(SB)", "AX"}); operand != "" {
		t.Fatalf("local SB operand classified external: %q", operand)
	}
}

func TestAssemblySymbolAddressRelocationIsExternal(t *testing.T) {
	fields := []string{"DATA", "·targetPC(SB)/8", "$·target(SB)"}
	if operand := asmExternalStateOperand(fields); operand != "SB symbol address" {
		t.Fatalf("assembly symbol relocation = %q, want SB symbol address", operand)
	}
}

func TestStandardAssemblyTargetIsUnverifiable(t *testing.T) {
	runtimePkg := types.NewPackage("runtime", "runtime")
	signature := types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false)
	target := types.NewFunc(token.NoPos, runtimePkg, "nanotime", signature)
	if reason := standardASMTargetReason(target); !strings.Contains(reason, "runtime.nanotime") {
		t.Fatalf("standard assembly target reason = %q, want runtime.nanotime", reason)
	}
}

func TestAssemblyExternalStateInstructionInIncludeIsClassified(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "external.s"), []byte("#include \"ops.inc\"\nTEXT ·F(SB), $0-0\n\tRET\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ops.inc"), []byte("RDTSC\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var reason string
	_, _, _, _, err := asmCallTargetsObserved(&reason, dir, []string{"external.s"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reason, "RDTSC") {
		t.Fatalf("included assembly external-state reason = %q, want RDTSC", reason)
	}
}

func TestAssemblyExternalStateMacroAndStatementAreClassified(t *testing.T) {
	dir := t.TempDir()
	source := "#define READSYS RDTSC\nTEXT ·F(SB), $0-0; READSYS; RET\n"
	if err := os.WriteFile(filepath.Join(dir, "external.s"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	var reason string
	_, _, _, _, err := asmCallTargetsObserved(&reason, dir, []string{"external.s"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reason, "RDTSC") {
		t.Fatalf("expanded assembly external-state reason = %q, want RDTSC", reason)
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
