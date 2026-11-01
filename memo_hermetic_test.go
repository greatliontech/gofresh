package gofresh

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/testenv"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// Tests must never read or write the real user proof cache: the observability
// memo (REQ-closure-observability-memo) keys under it, and shared state
// would let one run's proofs leak into another's assertions.
func TestMain(m *testing.M) {
	cache, err := gotool.GoBuildCache(context.Background(), os.Environ())
	if err != nil {
		panic(err)
	}
	if err := os.Setenv("GOCACHE", cache); err != nil {
		panic(err)
	}
	tmp, err := os.MkdirTemp("", "gofresh-cache-*")
	if err != nil {
		panic(err)
	}
	os.Setenv("XDG_CACHE_HOME", tmp)
	code := m.Run()
	cleanupSharedTestBinaries()
	testenv.CleanupShared()
	os.RemoveAll(tmp)
	os.Exit(code)
}

// raceShard is one entry of the gate's race-shard list: the job's name
// and the `-run` regex selecting its tests.
type raceShard struct {
	Name string `json:"name"`
	Run  string `json:"run"`
}

// raceShardsOf reads the race tier's shard list from the CI caller:
// exactly one line whose key is `race-shards`, its value a single-quoted
// JSON list with nothing after the closing quote (a folded, double-quoted
// or comment-trailed value, or a second line, refuses).
func raceShardsOf(t *testing.T, workflow string) []raceShard {
	t.Helper()
	data, err := os.ReadFile(workflow)
	if err != nil {
		t.Fatal(err)
	}
	shards, err := parseRaceShards(string(data))
	if err != nil {
		t.Fatalf("%s: %v", workflow, err)
	}
	return shards
}

// parseRaceShards is raceShardsOf's reading over the workflow's text.
func parseRaceShards(workflow string) ([]raceShard, error) {
	var shards []raceShard
	seen := false
	for _, line := range strings.Split(workflow, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found || key != "race-shards" {
			continue
		}
		if seen {
			return nil, fmt.Errorf("race-shards is named twice")
		}
		seen = true
		value = strings.TrimSpace(value)
		if len(value) < 2 || value[0] != '\'' || value[len(value)-1] != '\'' {
			return nil, fmt.Errorf("race-shards is not a single-quoted JSON list: %q", value)
		}
		if err := json.Unmarshal([]byte(value[1:len(value)-1]), &shards); err != nil {
			return nil, fmt.Errorf("race-shards: %w", err)
		}
	}
	if !seen {
		return nil, fmt.Errorf("names no race-shards input")
	}
	return shards, nil
}

// isTestName is the go command's rule for a test, example or fuzz
// function's name: the prefix followed by nothing or by a rune that is
// not lower case.
func isTestName(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	if len(name) == len(prefix) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(name[len(prefix):])
	return !unicode.IsLower(r)
}

// testFunctions walks every _test.go file `go test ./...` reaches under
// root — never a directory named testdata or vendor, one beginning with
// `.` or `_`, or a nested module (a directory below the root holding a
// go.mod) — and returns the top-level Test, Example and Fuzz function
// names, each with its package directory. TestMain is a test exactly
// when it has a test's shape (one parameter of type *T, qualified or
// not, no result), as the go command counts it; otherwise it is the
// harness.
func testFunctions(root string) ([]string, error) {
	var names []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			if name := d.Name(); strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "vendor" {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, filepath.Dir(path))
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			name := fn.Name.Name
			if name == "TestMain" && !takesPointerTo(fn, "T") {
				continue
			}
			if isTestName(name, "Test") || isTestName(name, "Example") || isTestName(name, "Fuzz") {
				names = append(names, rel+":"+name)
			}
		}
		return nil
	})
	sort.Strings(names)
	return names, err
}

// takesPointerTo is the go command's shape test for a test function:
// exactly one parameter, its type a pointer to a type of the given
// name, package-qualified (`*testing.T`) or bare under a dot import
// (`*T`). The go command also demands no result, but a TestMain with
// one makes it refuse the whole package, so no tree the gate judges
// carries that shape and the walk judges none.
func takesPointerTo(fn *ast.FuncDecl, name string) bool {
	if fn.Type.Params == nil || len(fn.Type.Params.List) != 1 || len(fn.Type.Params.List[0].Names) > 1 {
		return false
	}
	star, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	switch x := star.X.(type) {
	case *ast.Ident:
		return x.Name == name
	case *ast.SelectorExpr:
		return x.Sel.Name == name
	}
	return false
}

// shardPartitionFaults judges a shard list against test names as `go
// test -run` judges a regex with no subtest part (the whole regex over
// the top-level name): a name no shard selects runs under no race job
// and its races never red the gate; a name two shards select runs
// twice. Both are faults, named. A regex carrying a `/` is refused: the
// go command would run only the subtests its later parts match, and
// the partition is over top-level names alone. The gate single-quotes
// a regex for the shell and keys the build cache save on the first
// shard's name, so a single quote, an empty name and a repeated name
// are refused too.
func shardPartitionFaults(shards []raceShard, names []string) ([]string, error) {
	if len(shards) == 0 {
		return nil, fmt.Errorf("no shards")
	}
	var matchers []*regexp.Regexp
	seenNames := map[string]bool{}
	for _, s := range shards {
		if s.Name == "" {
			return nil, fmt.Errorf("a shard has no name")
		}
		if seenNames[s.Name] {
			return nil, fmt.Errorf("shard %q is named twice", s.Name)
		}
		seenNames[s.Name] = true
		if strings.Contains(s.Run, "'") {
			return nil, fmt.Errorf("shard %q: the regex carries a single quote, which the gate's quoting cannot pass", s.Name)
		}
		if strings.Contains(s.Run, "/") {
			return nil, fmt.Errorf("shard %q: the regex carries a subtest part; a shard selects top-level tests only", s.Name)
		}
		re, err := regexp.Compile(s.Run)
		if err != nil {
			return nil, fmt.Errorf("shard %q: %w", s.Name, err)
		}
		matchers = append(matchers, re)
	}
	var faults []string
	for _, qualified := range names {
		_, name, _ := strings.Cut(qualified, ":")
		var hits []string
		for i, re := range matchers {
			if re.MatchString(name) {
				hits = append(hits, shards[i].Name)
			}
		}
		switch len(hits) {
		case 1:
		case 0:
			faults = append(faults, qualified+" in no shard")
		default:
			faults = append(faults, qualified+" in shards "+strings.Join(hits, ","))
		}
	}
	return faults, nil
}

// The race tier's shards partition this module's tests: every Test,
// Example and Fuzz function of every package `go test ./...` reaches is
// selected by exactly one shard's `-run` regex, so no test leaves the
// race tier and none runs twice. The walk reads the tree (a hand-edit
// oracle); the judgment's logic is pinned over synthetic names below.
func TestRaceShardsPartitionEveryTest(t *testing.T) {
	shards := raceShardsOf(t, filepath.Join(".github", "workflows", "ci.yaml"))
	if len(shards) < 2 {
		t.Fatalf("the race tier is not sharded: %v", shards)
	}
	names, err := testFunctions(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) < 100 {
		t.Fatalf("the walk found %d test functions; the module has hundreds", len(names))
	}
	faults, err := shardPartitionFaults(shards, names)
	if err != nil {
		t.Fatal(err)
	}
	if len(faults) != 0 {
		t.Fatalf("%d tests outside the partition:\n%s", len(faults), strings.Join(faults, "\n"))
	}
}

// The judgment over synthetic names: a name in exactly one shard
// passes; one in none and one in two are named faults; an Example and
// a Fuzz name need their shard like a Test; a top-level alternation
// judges whole; a malformed regex, a subtest part, a single quote, an
// empty name and a repeated name refuse.
func TestShardPartitionJudgesEveryName(t *testing.T) {
	shards := []raceShard{{Name: "a-m", Run: "^Test[A-M]"}, {Name: "n-z", Run: "^Test[N-Z]|^Example|^Fuzz"}}
	faults, err := shardPartitionFaults(shards, []string{"p:TestAlpha", "p:TestZulu", "q:ExampleOne", "q:FuzzOne"})
	if err != nil || len(faults) != 0 {
		t.Fatalf("a partition judged %v, %v", faults, err)
	}
	faults, err = shardPartitionFaults(shards, []string{"p:Test_under", "p:TestAlpha"})
	if err != nil || len(faults) != 1 || !strings.Contains(faults[0], "p:Test_under in no shard") {
		t.Fatalf("an unselected name judged %v, %v", faults, err)
	}
	overlapping := []raceShard{{Name: "a", Run: "^TestA"}, {Name: "al", Run: "^TestAl"}}
	faults, err = shardPartitionFaults(overlapping, []string{"p:TestAlpha"})
	if err != nil || len(faults) != 1 || !strings.Contains(faults[0], "in shards a,al") {
		t.Fatalf("a doubly selected name judged %v, %v", faults, err)
	}
	if _, err := shardPartitionFaults([]raceShard{{Name: "bad", Run: "^Test["}}, []string{"p:TestA"}); err == nil {
		t.Fatal("a malformed regex was admitted")
	}
	if _, err := shardPartitionFaults([]raceShard{{Name: "quoted", Run: "^Test'"}}, []string{"p:TestA"}); err == nil {
		t.Fatal("a regex carrying a single quote was admitted")
	}
	faults, err = shardPartitionFaults([]raceShard{{Name: "alt", Run: "^TestA/x|^TestB"}}, []string{"p:TestBeta"})
	if err == nil {
		t.Fatalf("a subtest part inside an alternation was admitted: %v", faults)
	}
	faults, err = shardPartitionFaults([]raceShard{{Name: "alt", Run: "^TestAx|^TestB"}}, []string{"p:TestBeta"})
	if err != nil || len(faults) != 0 {
		t.Fatalf("a top-level alternation judged %v, %v", faults, err)
	}
	for _, refused := range [][]raceShard{
		{{Name: "sub", Run: "^TestA/case"}},
		{{Name: "", Run: "^TestA"}},
		{{Name: "twice", Run: "^TestA"}, {Name: "twice", Run: "^TestB"}},
	} {
		if _, err := shardPartitionFaults(refused, []string{"p:TestAlpha"}); err == nil {
			t.Fatalf("admitted %v", refused)
		}
	}
}

// The workflow reading: one single-quoted line serves; a second line,
// a double-quoted or folded value, a trailing comment, and an absent
// key refuse.
func TestRaceShardsReadingRefusesEveryOtherShape(t *testing.T) {
	one := "with:\n  race: true\n  race-shards: '[{\"name\":\"a\",\"run\":\"^TestA\"}]'\n  records: true\n"
	shards, err := parseRaceShards(one)
	if err != nil || len(shards) != 1 || shards[0].Name != "a" || shards[0].Run != "^TestA" {
		t.Fatalf("one line read %v, %v", shards, err)
	}
	for name, text := range map[string]string{
		"twice":    one + "  race-shards: '[]'\n",
		"double":   "race-shards: \"[]\"\n",
		"folded":   "race-shards: >-\n  '[]'\n",
		"comment":  "race-shards: '[]' # none\n",
		"absent":   "race: true\n",
		"notalist": "race-shards: '{}'\n",
		"unclosed": "race-shards: '[{\"name\":\"a\",\"run\":\"^TestA\"}]x\n",
	} {
		if _, err := parseRaceShards(text); err == nil {
			t.Fatalf("%s was read", name)
		}
	}
}

// The walk mirrors `go test ./...`: it reaches a package in any plain
// directory and skips testdata, vendor, dot and underscore directories
// and a nested module; it collects by the go command's name rule
// (Test, Example and Fuzz functions, the rune after the prefix not
// lower case; TestMain only with a test's shape — never the harness's,
// dot-imported or not) and only top-level functions.
func TestTestFunctionsWalkMirrorsGoTest(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module m\n")
	write("a/a_test.go", "package a\n\nimport \"testing\"\n\nfunc TestMain(m *testing.M) {}\nfunc TestOne(t *testing.T) {}\nfunc Test_two(t *testing.T) {}\nfunc Test1(t *testing.T) {}\nfunc Testify() {}\nfunc ExampleOne() {}\nfunc Examplefoo() {}\nfunc FuzzOne(f *testing.F) {}\nfunc Fuzzy() {}\nfunc Test(t *testing.T) {}\n\ntype s struct{}\n\nfunc (s) TestMethod(t *testing.T) {}\n")
	write("a/notatest.go", "package a\n\nfunc TestNotAFile() {}\n")
	write("b/testdata/x_test.go", "package x\n\nfunc TestSkipped() {}\n")
	write("vendor/v/v_test.go", "package v\n\nfunc TestSkipped() {}\n")
	write(".hidden/h_test.go", "package h\n\nfunc TestSkipped() {}\n")
	write("_under/u_test.go", "package u\n\nfunc TestSkipped() {}\n")
	write("nested/go.mod", "module m/nested\n")
	write("nested/n_test.go", "package nested\n\nfunc TestSkipped() {}\n")
	write("b/deep/d_test.go", "package deep\n\nimport \"testing\"\n\nfunc TestMain(t *testing.T) {}\nfunc TestDeep(t *testing.T) {}\n")
	write("c/c_test.go", "package c\n\nimport (\n\t\"os\"\n\t. \"testing\"\n)\n\nfunc TestMain(m *M) { os.Exit(m.Run()) }\nfunc TestDot(t *T) {}\n")
	names, err := testFunctions(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a:ExampleOne", "a:FuzzOne", "a:Test", "a:Test1", "a:TestOne", "a:Test_two", "b/deep:TestDeep", "b/deep:TestMain", "c:TestDot"}
	if strings.Join(names, " ") != strings.Join(want, " ") {
		t.Fatalf("the walk found %v, want %v", names, want)
	}
}

// scanMemoModule writes a two-package module whose view package imports
// a sibling and whose subject carries a purity directive, a dynamic mark,
// and an external mark — every scan output class the memo persists.
func scanMemoModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":            "module example.com/scanmemo\n\ngo 1.26\n",
		"dep/dep.go":        "package dep\n\nvar Hooks = map[string]func(){}\n\nfunc Bump() { Hooks[\"x\"] = func() {} }\n\nfunc Add(a, b int) int { return a + b }\n",
		"view/view.go":      "package view\n\nimport \"example.com/scanmemo/dep\"\n\n//gofresh:pure\nfunc Pure(x int) int { return dep.Add(x, 1) }\n\nfunc Mutating() { dep.Bump() }\n\n//gofresh:external\nfunc External() int { return 0 }\n",
		"view/view_test.go": "package view\n\nimport \"testing\"\n\nfunc TestPure(t *testing.T) {\n\tif Pure(1) != 2 {\n\t\tt.Fatal()\n\t}\n}\n",
		"other/other.go":    "package other\n\nfunc Unrelated() int { return 3 }\n",
	}
	for path, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

var scanMemoSubjects = []Subject{
	{Package: "example.com/scanmemo/view", Symbol: "Pure"},
	{Package: "example.com/scanmemo/view", Symbol: "Mutating"},
	{Package: "example.com/scanmemo/view", Symbol: "External"},
	{Package: "example.com/scanmemo/view", Symbol: "TestPure"},
}

// scanOutputs captures a view's scan-derived facts for every subject: the
// projection a served scan must reproduce exactly.
func scanOutputs(t *testing.T, view *Snapshot, subjects []Subject) map[Subject]string {
	t.Helper()
	out := map[Subject]string{}
	for _, s := range subjects {
		fp, err := view.Capture(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		d := view.facts.discharges[s]
		out[s] = fp.MaximalClosure + "|" + fp.PurityAssertion + "|" + boolWord(view.facts.closure(s).Unverifiable) + "|" + view.facts.closure(s).Reason + "|" + view.facts.vouchDischarges[s] + "|" + d.packageProcess + "|" + d.singleSubject
	}
	return out
}

func boolWord(b bool) string {
	if b {
		return "unverifiable"
	}
	return "verifiable"
}

// leakModule writes a four-package module in which package d owns a
// function-valued variable, a reads it, c rebinds it, and b reaches c:
// a's test binary never links the mutation, b's does.
func leakModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":      "module example.com/leak\n\ngo 1.26\n",
		"a/a.go":      "package a\n\nimport \"example.com/leak/d\"\n\nfunc F() { d.Run() }\n",
		"b/b.go":      "package b\n\nimport \"example.com/leak/c\"\n\nfunc G(f func()) { c.Rebind(f) }\n",
		"c/c.go":      "package c\n\nimport \"example.com/leak/d\"\n\nfunc Rebind(f func()) { d.Callback = f }\n",
		"d/d.go":      "package d\n\nvar Callback = func() {}\n\nfunc Run() { Callback() }\n",
		"a/a_test.go": "package a\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) { F() }\n",
	}
	for path, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

var (
	leakA        = Subject{Package: "example.com/leak/a", Symbol: "F"}
	leakB        = Subject{Package: "example.com/leak/b", Symbol: "G"}
	leakSubjects = []Subject{leakA, leakB}
)

func newLeakView(t *testing.T, dir string, subjects []Subject, opts ...option) *Snapshot {
	t.Helper()
	engine, err := newEngine(append([]option{withDir(dir)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), subjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	return view
}

// Every scan output class survives the entry's persisted form: a scan
// projected to entries, marshalled, unmarshalled, and rebuilt is the
// same scan (REQ-closure-scan-memo).
func TestScanEntryRoundTripsEveryOutput(t *testing.T) {
	pkg := "example.com/p"
	s := func(sym string) Subject { return Subject{Package: pkg, Symbol: sym} }
	scan := &subjectScan{
		known: map[Subject]bool{s("A"): true, s("B"): true, s("C"): true}, pure: map[Subject]bool{s("A"): true},
		openWorld: map[Subject]string{s("B"): "parameter f func()"}, external: map[Subject]bool{s("C"): true},
		downgradeReason:  map[Subject]string{s("B"): "reason"},
		downgradeCulprit: map[Subject]Subject{s("B"): {Package: "example.com/dep", Symbol: "Hooks"}},
		vouchDischarges:  map[Subject]string{s("A"): "v"},
		discharges:       map[Subject]attestationDischarges{s("B"): {singleSubject: "att"}, s("C"): {packageProcess: "pp"}},
		ambiguous:        map[Subject]string{s("C"): "declared twice"},
	}
	raw, err := json.Marshal(entryOf(scan, pkg))
	if err != nil {
		t.Fatal(err)
	}
	var entry packageScanEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Version != scanEntryVersion {
		t.Fatalf("version %d, want %d", entry.Version, scanEntryVersion)
	}
	got := scanFromEntries(map[string]packageScanEntry{pkg: entry})
	if !reflect.DeepEqual(got, scan) {
		t.Fatalf("round trip lost an output:\n got %+v\nwant %+v", got, scan)
	}
}
