package closure

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

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
	}
	bodies := []string{
		"",
		"func F() { _, _ = os.ReadFile(\"x\") }\n",
		"func F() { _ = os.ReadFile }\n",
		"func F() { _ = time.Now() }\n",
		"func F() { _ = strings.Join(nil, \"\") }\n",
		"func F() { _, _ = net.Dial(\"tcp\", \"x\") }\n",
		"func F() { _ = dep.G() }\n",
		"func TestX(t *testing.T) { t.Setenv(\"K\", \"V\") }\n",
		"func TestX(t *testing.T) { u := t; u.TempDir() }\n",
		"func TestX(t *testing.T) { var u = t; _ = u }\n",
		"func TestX(t *testing.T) { use(t) }\nfunc use(any) {}\n",
		"func TestX(t *testing.T) *testing.T { return t }\n",
		"type Bench struct{ *testing.B }\nfunc G(b *Bench) { _ = b.N }\n",
		"func F() { s := \"//go:wasmimport\"; _ = s }\n",
		"func F() { s := \"//go:linkname\"; _ = s }\n",
		"//go:linkname F runtime.f\nfunc F()\n",
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
	// L3 named pairs the diagonal sampling misses, plus alias collisions —
	// this corpus is also the walk-consolidation refactor's oracle.
	files["pair_os_readfile.go"] = "package corpus\n\nimport \"os\"\n\nfunc F() { _, _ = os.ReadFile(\"x\") }\n"
	files["pair_dot_strings_join.go"] = "package corpus\n\nimport . \"strings\"\n\nfunc F() { _ = Join(nil, \"\") }\n"
	files["pair_group_setenv.go"] = "package corpus\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestX(t *testing.T) { t.Setenv(\"K\", \"V\"); _ = os.Args }\n"
	files["pair_dot_os_selector.go"] = "package corpus\n\nimport . \"os\"\nimport \"os\"\n\nfunc F() { _, _ = os.ReadFile(\"x\") }\n"
	files["dup_alias.go"] = "package corpus\n\nimport o \"os\"\nimport o \"strings\"\n\nfunc F() { _ = o.Join }\n"
	files["dup_path.go"] = "package corpus\n\nimport \"os\"\nimport osx \"os\"\n\nfunc F() { _, _ = osx.ReadFile(\"x\") }\n"
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
		got, gotErr := maximalFileEffects(path)
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
		got, gotErr := maximalFileEffects(path)
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
		if _, err := maximalFileEffects(path); err != nil {
			b.Fatal(err)
		}
	}
}
