package gofresh

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

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
