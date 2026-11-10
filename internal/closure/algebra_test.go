package closure

import (
	"context"
	"fmt"
	"github.com/greatliontech/gofresh/internal/closure/internal/compartment"
	"github.com/greatliontech/gofresh/internal/closure/internal/listing"
	"github.com/greatliontech/gofresh/internal/closure/internal/propharness"
	"github.com/greatliontech/gofresh/internal/testenv"
	"github.com/greatliontech/gofresh/internal/testvariant"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// A retained comment's attachment in the canonical form is the
// parser's doc rule: for every retained comment of any class — line or
// block directive, export, build constraint, generated marker —
// immediately preceding a declaration, the form's lead-group bit equals whether go/parser
// attaches that comment as the declaration's doc — under a blank line,
// a block comment, and a `//line` directive between the comment and the
// declaration, whose adjusted positions the form never reads
// (REQ-closure-canonical-member).
func TestRetainedCommentAttachmentFollowsTheParser(t *testing.T) {
	sources := map[string]string{
		"adjacent":              "package p\n\n//go:noinline\nfunc F(a int) int { return a }\n",
		"blank line":            "package p\n\n//go:noinline\n\nfunc F(a int) int { return a }\n",
		"line directive after":  "package p\n\n//go:noinline\n//line other.go:10\nfunc F(a int) int { return a }\n",
		"line directive before": "package p\n\n//line other.go:10\n//go:noinline\nfunc F(a int) int { return a }\n",
		"line directive far":    "package p\n\n//go:noinline\n//line other.go:100\nfunc F(a int) int { return a }\n",
		"block between":         "package p\n\n//go:noinline\n/* x */ func F(a int) int { return a }\n",
		"same-line group":       "package p\n\n//go:noinline\n/* a */ /* x\ny */\nfunc F(a int) int { return a }\n",
		"same-line group blank": "package p\n\n//go:noinline\n/* a */ /* x\ny */\n\nfunc F(a int) int { return a }\n",
		"twice":                 "package p\n\n//go:noinline\nfunc F(a int) int { return a }\n\n//go:noinline\n\nfunc G(a int) int { return a }\n",
		"on a var":              "package p\n\n//go:embed x\nvar X string\n\n//go:embed y\n\nvar Y string\n",
		"block directive":       "package p\n\n/*go:noinline*/\nfunc F(a int) int { return a }\n\n/*go:noinline*/\n\nfunc G(a int) int { return a }\n",
		"export and build":      "//go:build linux\n\npackage p\n\n//export F\nfunc F(a int) int { return a }\n",
	}
	for name, src := range sources {
		items, ok := scanCanonical([]byte(src))
		if !ok {
			t.Fatalf("%s: the scanner refused", name)
		}
		lead := leadGroups(items)
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "p.go", src, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// A doc comment is identified by its unadjusted line and text,
		// so two identical directives never collapse; every doc-bearing
		// node counts, not functions alone.
		doc := map[string]bool{}
		note := func(g *ast.CommentGroup) {
			if g == nil {
				return
			}
			for _, c := range g.List {
				doc[fmt.Sprintf("%d:%s", fset.PositionFor(c.Pos(), false).Line, c.Text)] = true
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch d := n.(type) {
			case *ast.FuncDecl:
				note(d.Doc)
			case *ast.GenDecl:
				note(d.Doc)
			case *ast.TypeSpec:
				note(d.Doc)
			case *ast.ValueSpec:
				note(d.Doc)
			case *ast.ImportSpec:
				note(d.Doc)
			case *ast.Field:
				note(d.Doc)
			}
			return true
		})
		for i, it := range items {
			if it.tok != token.COMMENT || !retainedComment(it.lit) {
				continue
			}
			key := fmt.Sprintf("%d:%s", it.line, it.lit)
			if lead[i] != doc[key] {
				t.Errorf("%s: %q at line %d lead=%v, parser doc=%v", name, it.lit, it.line, lead[i], doc[key])
			}
		}
	}
}

// This is a go-list graph fixture: it exercises the collector's CgoFiles
// membership and syntax evidence without invoking a C compiler or claiming
// coverage of cgo-generated code. The pseudo-import C remains unresolved.
func TestCgoFilesEnterBaseBindingEvidence(t *testing.T) {
	const pkg = "example.com/bindings"
	dir := writeTestVariantModule(t, map[string]string{
		"plain.go":  "package p\nfunc Plain() {}\n",
		"cgo.go":    "package p\nimport \"C\"\nfunc Truth() bool { return true }\n",
		"p_test.go": "package p\nfunc Helper() {}\n",
	})
	module := &listMod{Path: pkg, Main: true, Dir: dir}
	h := &Hasher{
		lists: map[string][]listPkg{pkg: {
			{ImportPath: pkg, Name: "p", Dir: dir, Module: module, GoFiles: []string{"plain.go"}, CgoFiles: []string{"cgo.go"}},
			{ImportPath: pkg + " [" + pkg + ".test]", ForTest: pkg, Name: "p", Dir: dir, Module: module, GoFiles: []string{"plain.go", "p_test.go"}, CgoFiles: []string{"cgo.go"}},
		}},
		testVariants: map[string]compartment.Identity{},
		fileDigests:  map[string]string{},
		contents:     map[string]fileBytes{},
	}
	ledger, err := h.TestVariantLedger(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if ledger.BindingStrategy != testvariant.BindingStrategy || len(ledger.BaseFiles) != 2 {
		t.Fatalf("base evidence = %+v, want both GoFiles and CgoFiles", ledger)
	}
	cgo := ledger.BaseFiles[0]
	if cgo.File != "cgo.go" || cgo.Hash != "" || cgo.Embedded || cgo.Bindings == nil || cgo.Bindings.Package != "p" {
		t.Fatalf("cgo base entry = %+v", cgo)
	}
	if !slices.Contains(cgo.Bindings.References, "true") || !reflect.DeepEqual(cgo.Bindings.Imports, []testvariant.TestVariantImport{{Path: "C"}}) {
		t.Fatalf("cgo reference/import evidence = %+v", cgo.Bindings)
	}
	if len(ledger.FileHeaders) != 1 || ledger.FileHeaders[0].File != "p_test.go" {
		t.Fatalf("base cgo file leaked into compartment: %+v", ledger.FileHeaders)
	}
	if testvariant.DiffTestVariantLedgers(ledger, ledger.Clone()).Inert() {
		t.Fatal("unresolved pseudo-import supplied binding proof")
	}
}

// The real in-memory parse memo shares nested slices and pointers. Listing
// resolution must leave those syntax-only entries unresolved for later views,
// and must not rewrite a ledger already returned to a caller.
func TestBindingResolutionPreservesSharedParseMemo(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writeTestVariantModule(t, map[string]string{
		"p.go":      "package p\nimport \"example.com/dependency\"\nfunc Base() int { return selected.Value }\n",
		"p_test.go": "package p\nimport \"example.com/dependency\"\nfunc Helper() int { return selected.Value }\n",
	})
	h := &Hasher{fileMemo: newFileMemos(), contents: map[string]fileBytes{}}
	memo := variantParseMemo{h: h, dir: dir, pkgPath: "example.com/p"}
	var first testvariant.TestVariantLedger
	for _, name := range []string{"selected", "renamed", ""} {
		identity, err := compartment.ComputeIdentity(dir, []string{"p_test.go"}, map[string]bool{"p_test.go": true}, nil, nil, h, memo)
		if err != nil {
			t.Fatal(err)
		}
		if err := compartment.AddBaseBindings(&identity, []string{"p.go"}, map[string]string{"example.com/dependency": name}, h, memo); err != nil {
			t.Fatal(err)
		}
		h.flushFileMemos()
		for _, header := range []testvariant.TestVariantFileHeader{identity.Ledger.BaseFiles[0], identity.Ledger.FileHeaders[0]} {
			if got := header.Bindings.Imports[0].Name; got != name {
				t.Fatalf("%s: resolved name %q, want %q", header.File, got, name)
			}
		}
		if len(h.fileMemo.parses.loaded[dir]) != 2 {
			t.Fatalf("memo has %d entries, want base and test files", len(h.fileMemo.parses.loaded[dir]))
		}
		for key, payload := range h.fileMemo.parses.loaded[dir] {
			if payload.Header.Hash == "" || payload.Header.Bindings.Imports[0].Name != "" {
				t.Fatalf("listing resolution contaminated syntax memo %s: %+v", key, payload.Header)
			}
		}
		if name == "selected" {
			first = identity.Ledger
		} else {
			for _, header := range []testvariant.TestVariantFileHeader{first.BaseFiles[0], first.FileHeaders[0]} {
				if header.Bindings.Imports[0].Name != "selected" {
					t.Fatal("later resolution changed first caller's ledger")
				}
			}
			if !h.ServedSummary()["compartment parse"]["example.com/p"] {
				t.Fatal("later pass did not exercise shared memo entries")
			}
		}
		if name == "" && testvariant.DiffTestVariantLedgers(identity.Ledger, identity.Ledger.Clone()).Inert() {
			t.Fatal("unresolved listing reused an earlier binding")
		}
	}
}

// TestLanguageShapeCanaries runs the language-shape canary corpus
// (testenv.ShapeEntries) through this frontend — load, precise analysis,
// observability — pinning each entry's DISPOSITION, not merely the
// absence of one failure string: a probe showed the
// any-disposition tolerance green over an unjudged shape, so a
// release flipping a disposition in either direction is a red canary
// here. Runs under the CI matrix's next-rc leg like every test.
func TestLanguageShapeCanaries(t *testing.T) {
	for _, entry := range testenv.ShapeEntries() {
		t.Run(entry.Name, func(t *testing.T) {
			dir := t.TempDir()
			for file, content := range entry.TestFiles() {
				if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			h, err := newAt(dir)
			if err != nil {
				t.Errorf("canary load: %v", err)
				return
			}
			subject := Subject{Package: "example.com/shape", Symbol: "Subject"}
			fixtures := newFixturePrograms(t, h)
			fixtures.supply(t, subject.Package)
			if _, err := computeTier2Result(h, subject.Package, subject.Symbol); err != nil {
				t.Errorf("canary precise analysis: %v", err)
				return
			}
			fixtures.supply(t, subject.Package)
			proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
			if err != nil {
				t.Errorf("canary observability: %v", err)
				return
			}
			proof, ok := proofs[subject]
			if !ok {
				t.Errorf("canary produced no disposition: %+v", proofs)
				return
			}
			if proof.Observable != entry.SubjectObservable {
				t.Errorf("disposition = %+v, corpus pins observable=%v", proof, entry.SubjectObservable)
			}
			if entry.SubjectReason != "" && !strings.Contains(proof.Reason, entry.SubjectReason) {
				t.Errorf("refusal reason %q does not carry the pinned cause %q", proof.Reason, entry.SubjectReason)
			}
			if strings.Contains(proof.Reason, "unsupported analysis shape") {
				t.Errorf("canary refused on an analysis-class failure: %+v", proof)
			}
		})
	}
}

// The canonical digest is what a compiled Go member contributes: equal
// across comment-only and gofmt-only edits, moved by any token change
// and by any retained comment — a directive, a cgo preamble, the
// generated-file marker — and absent for text that does not scan
// (REQ-closure-canonical-member).
//
//gofresh:pure
func TestCanonicalDigestFoldsSyntaxAndRetainedComments(t *testing.T) {
	base := "package p\n\n// Doc comment.\nfunc F(a int) int {\n\t// inner\n\treturn a + 1\n}\n"
	digest, ok := canonicalDigest([]byte(base))
	if !ok {
		t.Fatal("base did not parse")
	}
	same := map[string]string{
		"comment removed":     "package p\n\nfunc F(a int) int {\n\treturn a + 1\n}\n",
		"comment reworded":    "package p\n\n// Another doc.\nfunc F(a int) int {\n\t/* block */ return a + 1\n}\n",
		"layout changed":      "package p\n\n\n\nfunc F(a  int)   int {\n\n\n\treturn a+1\n\n}\n",
		"nolint kept alike":   "package p\n\nfunc F(a int) int {\n\treturn a + 1 // nolint\n}\n",
		"line directive":      "package p\n\n//line other.go:10\nfunc F(a int) int {\n\treturn a + 1\n}\n",
		"explicit semicolons": "package p\n\n// Doc comment.\nfunc F(a int) int {\n\treturn a + 1;\n};\n",
	}
	for name, variant := range same {
		got, ok := canonicalDigest([]byte(variant))
		if !ok || got != digest {
			t.Errorf("%s: digest %s (parsed %v), want the base's %s", name, got, ok, digest)
		}
	}
	moved := map[string]string{
		"token changed":         "package p\n\nfunc F(a int) int {\n\treturn a + 2\n}\n",
		"semicolon moved":       "package p\n\nfunc F(a int) int { return a + 1 }\n",
		"go directive":          "package p\n\n//go:noinline\nfunc F(a int) int {\n\treturn a + 1\n}\n",
		"gofresh directive":     "package p\n\n//gofresh:pure\nfunc F(a int) int {\n\treturn a + 1\n}\n",
		"tool directive":        "package p\n\n//nolint:all\nfunc F(a int) int {\n\treturn a + 1\n}\n",
		"generated marker":      "// Code generated by gen. DO NOT EDIT.\n\npackage p\n\nfunc F(a int) int {\n\treturn a + 1\n}\n",
		"export directive":      "package p\n\n//export F\nfunc F(a int) int {\n\treturn a + 1\n}\n",
		"block directive":       "package p\n\n/*go:linkname F other.F*/\nfunc F(a int) int {\n\treturn a + 1\n}\n",
		"legacy build tag":      "// +build linux\n\npackage p\n\nfunc F(a int) int {\n\treturn a + 1\n}\n",
		"trailing-space marker": "// Code generated by gen. DO NOT EDIT. \n\npackage p\n\nfunc F(a int) int {\n\treturn a + 1\n}\n",
	}
	for name, variant := range moved {
		got, ok := canonicalDigest([]byte(variant))
		if !ok || got == digest {
			t.Errorf("%s: digest %s (parsed %v) equals the base's — a retained class or a token was dropped", name, got, ok)
		}
	}
	// Retained comments fold by their text, so a change inside one moves
	// the digest exactly as a token change does.
	a, _ := canonicalDigest([]byte("package p\n\n//go:noinline\nfunc F() {}\n"))
	b, _ := canonicalDigest([]byte("package p\n\n//go:nosplit\nfunc F() {}\n"))
	if a == b {
		t.Fatal("two directives folded alike")
	}
	// The cgo preamble is C code: any change to it moves the digest,
	// whether it documents a lone import or a grouped spec.
	preamble := "package p\n\n// #include <stdio.h>\nimport \"C\"\n\nfunc F() { C.puts(nil) }\n"
	edited := "package p\n\n// #include <stdlib.h>\nimport \"C\"\n\nfunc F() { C.puts(nil) }\n"
	grouped := "package p\n\nimport (\n\t// #include <stdio.h>\n\t\"C\"\n)\n\nfunc F() { C.puts(nil) }\n"
	groupedEdited := "package p\n\nimport (\n\t// #include <stdlib.h>\n\t\"C\"\n)\n\nfunc F() { C.puts(nil) }\n"
	for _, pair := range [][2]string{{preamble, edited}, {grouped, groupedEdited}} {
		x, okx := canonicalDigest([]byte(pair[0]))
		y, oky := canonicalDigest([]byte(pair[1]))
		if !okx || !oky || x == y {
			t.Fatalf("cgo preamble edit did not move the digest (%s / %s)", x, y)
		}
	}
	// A retained comment folds with its attachment: a blank line between
	// a directive and its declaration detaches the doc the parser (and
	// gofresh's directive readers) see, with an identical token stream.
	attached, _ := canonicalDigest([]byte("package p\n\n//gofresh:pure\nfunc F() int { return 1 }\n"))
	detached, _ := canonicalDigest([]byte("package p\n\n//gofresh:pure\n\nfunc F() int { return 1 }\n"))
	if attached == detached {
		t.Fatal("a detached directive folded like an attached one")
	}
	// The rule is the parser's, per group: a directive first in a doc
	// group stays live when the group is contiguous and dies when a
	// blank line splits the group; a group closed by a block comment on
	// the declaration's own line is no doc group at all.
	contiguous, _ := canonicalDigest([]byte("package p\n\n//gofresh:pure\n// docs\nfunc F() {}\n"))
	split, _ := canonicalDigest([]byte("package p\n\n//gofresh:pure\n\n// docs\nfunc F() {}\n"))
	if contiguous == split {
		t.Fatal("a directive split from its doc group folded like a contiguous one")
	}
	plain, _ := canonicalDigest([]byte("package p\n\n//gofresh:pure\nfunc F() {}\n"))
	closedOnLine, _ := canonicalDigest([]byte("package p\n\n//gofresh:pure\n/* x */ func F() {}\n"))
	if plain == closedOnLine {
		t.Fatal("a group closed by a block comment on the declaration's line folded like a lead group")
	}
	// A legacy constraint is read by its field, in any spelling: two
	// no-space lines naming different tags are two forms.
	tightLinux, _ := canonicalDigest([]byte("//go:build linux\n//+build linux\n\npackage p\n"))
	tightDarwin, _ := canonicalDigest([]byte("//go:build linux\n//+build darwin\n\npackage p\n"))
	if tightLinux == tightDarwin {
		t.Fatal("a no-space +build line was dropped")
	}
	// A comment before a "C" string outside an import group is not a
	// preamble: the group tracking closes with its parenthesis.
	before, _ := canonicalDigest([]byte("package p\n\nimport (\n\t\"fmt\"\n)\n\nvar x = // alpha\n\"C\"\n\nvar _ = fmt.Sprint\n"))
	afterEdit, _ := canonicalDigest([]byte("package p\n\nimport (\n\t\"fmt\"\n)\n\nvar x = // beta\n\"C\"\n\nvar _ = fmt.Sprint\n"))
	if before != afterEdit {
		t.Fatal("a comment before a plain \"C\" literal after an import group was retained as a preamble")
	}
	// The stream keeps its semicolons: two programs differing only by
	// a line break that inserts one are two forms.
	call, _ := canonicalDigest([]byte("package p\n\nfunc F() { x := y(z); _ = x }\n"))
	statement, _ := canonicalDigest([]byte("package p\n\nfunc F() { x := y\n\t(z); _ = x }\n"))
	if call == statement {
		t.Fatal("a call and a statement break folded alike — the automatic semicolon was dropped")
	}
	// Text the scanner refuses (an unterminated literal) has no
	// canonical form: the member folds its bytes.
	unscannable := []byte("package p\n\nvar s = \"unterminated\n")
	if _, ok := canonicalDigest(unscannable); ok {
		t.Fatal("unscannable text produced a canonical digest")
	}
	h := &Hasher{}
	if got := h.canonicalFileDigest(t.TempDir(), "bytes-digest", unscannable); got != "bytes-digest" {
		t.Fatalf("unscannable member folded %q, want its byte digest", got)
	}
}

// For every syntactically valid member, inserting non-retained comments
// anywhere between lines and re-indenting the whitespace leaves the
// canonical digest unchanged, while changing one token moves it —
// over a seeded enumeration of members and edits.
func TestCanonicalDigestIsInvariantUnderCommentAndLayoutEdits(t *testing.T) {
	rng := rand.New(rand.NewSource(129))
	for round := 0; round < 200; round++ {
		n := 1 + rng.Intn(4)
		body := "package p\n\n"
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("f%d%c", rng.Intn(1000), 'a'+rune(i))
			body += "func " + name + "(x int) int {\n\tif x > " + fmt.Sprint(rng.Intn(9)) + " {\n\t\treturn x\n\t}\n\treturn -x\n}\n\n"
		}
		base, ok := canonicalDigest([]byte(body))
		if !ok {
			t.Fatalf("round %d: generated member did not parse:\n%s", round, body)
		}
		commented := ""
		for _, line := range splitLines(body) {
			if rng.Intn(2) == 0 {
				text := make([]byte, rng.Intn(20))
				for k := range text {
					text[k] = byte(' ' + rng.Intn('~'-' '+1))
				}
				commented += "// " + string(text) + "\n"
			}
			if rng.Intn(2) == 0 {
				line = "    " + line
			}
			commented += line + "\n"
		}
		if got, ok := canonicalDigest([]byte(commented)); !ok || got != base {
			t.Fatalf("round %d: comment/layout edit moved the digest:\n%s", round, commented)
		}
		if renamed, ok := canonicalDigest([]byte(body[:len(body)-8] + "-x - 1\n}\n\n")); !ok || renamed == base {
			t.Fatalf("round %d: token edit did not move the digest", round)
		}
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// A comment-only edit to a mutable-local member leaves every subject's
// maximal closure standing, and its canonical digest serves from the
// memo on a byte-equal pass while a byte-moved member derives once
// (REQ-closure-canonical-member, REQ-closure-effect-scan-memo).
func TestCommentOnlyEditKeepsTheMaximalClosure(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := fileMemoModule(t)
	before, _, _, derived := foldOnceWithCanonical(t, dir, true)
	if len(derived) == 0 {
		t.Fatal("the cold pass derived no canonical digest")
	}
	if _, _, _, derived = foldOnceWithCanonical(t, dir, true); len(derived) != 0 {
		t.Fatalf("a byte-equal warm pass derived %d canonical digest(s), want the memo to serve", len(derived))
	}
	helper := filepath.Join(dir, "helper.go")
	// Comments and layout only — no line break that would insert a
	// semicolon (a different syntax tree is a different form).
	if err := os.WriteFile(helper, []byte("package fm\n\n\n// helper is documented now.\nfunc   helper() int { /* one */ return 1 } // trailing\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, _, _, derived := foldOnceWithCanonical(t, dir, true)
	if len(derived) == 0 {
		t.Fatal("a byte-moved member derived no canonical digest")
	}
	for _, subject := range fileMemoSubjects {
		if before[subject].Hash != after[subject].Hash {
			t.Fatalf("%s: a comment-only edit moved the maximal closure %s → %s", subject.Symbol, before[subject].Hash, after[subject].Hash)
		}
	}
	if err := os.WriteFile(helper, []byte("package fm\n\nfunc helper() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, _, _ := foldOnce(t, dir, true)
	for _, subject := range fileMemoSubjects {
		if before[subject].Hash == changed[subject].Hash {
			t.Fatalf("%s: a token edit left the maximal closure at %s", subject.Symbol, changed[subject].Hash)
		}
	}
}

// A member reaching the binary as data contributes its bytes whatever
// its name: an embedded text member, and a compiled Go member a
// go:embed directive names too — its comment edit changes the program
// (the embedded string) with an unchanged canonical form, so its form
// must never be its contribution (REQ-closure-canonical-member,
// REQ-closure-floor).
func TestEmbeddedMembersContributeBytes(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/em\n\ngo 1.26\n")
	write("self.go", "package em\n\nimport _ \"embed\"\n\n//go:embed self.go\nvar Self string\n\n//go:embed data.txt\nvar Data string\n\n// a comment\nfunc Len() int { return len(Self) + len(Data) }\n")
	write("data.txt", "// data\n")
	write("self_test.go", "package em\n\nimport \"testing\"\n\nfunc TestLen(t *testing.T) { _ = Len() }\n")
	subjects := []Subject{{Package: "example.com/em", Symbol: "Len"}}
	fold := func() string {
		t.Helper()
		h, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		got, _, err := h.ComputeMaximalBatch(subjects)
		if err != nil {
			t.Fatal(err)
		}
		return got[subjects[0]].Hash
	}
	base := fold()
	write("self.go", "package em\n\nimport _ \"embed\"\n\n//go:embed self.go\nvar Self string\n\n//go:embed data.txt\nvar Data string\n\n// a longer comment now\nfunc Len() int { return len(Self) + len(Data) }\n")
	if fold() == base {
		t.Fatal("a comment edit to a self-embedded compiled member left the closure standing — its bytes are the program")
	}
	write("self.go", "package em\n\nimport _ \"embed\"\n\n//go:embed self.go\nvar Self string\n\n//go:embed data.txt\nvar Data string\n\n// a comment\nfunc Len() int { return len(Self) + len(Data) }\n")
	if fold() != base {
		t.Fatal("restoring the member did not restore the closure")
	}
	write("data.txt", "// data edited\n")
	if fold() == base {
		t.Fatal("a comment-looking edit to an embedded text member left the closure standing")
	}
}

// genCompartment draws one package's files from the seeded source: the
// base file, then 1-5 test-only members over the member-kind surface — an
// in-package or external test file, a build constraint drawn from a small
// tag set, an embed of a generated data file, an embed of a constrained
// sibling (the shape that makes a member's kind follow the selection), and
// a dual compiled-and-embedded member. A compiled non-Go member is not
// drawn: the listing splits only .go files by the _test suffix, so an
// assembly file lands in the base package and is never a compartment
// member. The returned non-members are what the twin may vary: the base
// file's body, an extra base file, an unembedded data file.
func genCompartment(r *rand.Rand) (members, nonMembers map[string]string) {
	members = map[string]string{}
	nonMembers = map[string]string{
		"go.mod": "module example.com/gen\n\ngo 1.26\n",
		"gen.go": "package gen\n\nfunc F() int { return 1 }\n",
	}
	n := 1 + r.Intn(5)
	var constrained []string
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("m%d_%d_test.go", i, r.Intn(1000))
		pkg := "gen"
		if r.Intn(4) == 0 {
			pkg = "gen_test"
		}
		body := ""
		if r.Intn(3) == 0 {
			body = "//go:build " + []string{"extra", "other", "extra && other"}[r.Intn(3)] + "\n\n"
			constrained = append(constrained, name)
		}
		body += "package " + pkg + "\n\nimport (\n\t_ \"embed\"\n\t\"testing\"\n)\n\n"
		if pkg == "gen_test" {
			body = strings.Replace(body, "\t\"testing\"\n", "\t\"testing\"\n\n\t\"example.com/gen\"\n", 1)
		}
		switch r.Intn(4) {
		case 0:
			data := fmt.Sprintf("data%d.txt", i)
			members[data] = fmt.Sprintf("payload %d\n", r.Intn(100000))
			body += "//go:embed " + data + "\nvar blob" + fmt.Sprint(i) + " string\n\n"
		case 1:
			if len(constrained) > 0 {
				body += "//go:embed " + constrained[r.Intn(len(constrained))] + "\nvar sibling" + fmt.Sprint(i) + " string\n\n"
			}
		case 2:
			// A dual member: this file embeds itself.
			body += "//go:embed " + name + "\nvar self" + fmt.Sprint(i) + " string\n\n"
		}
		call := "F()"
		if pkg == "gen_test" {
			call = "gen.F()"
		}
		for j, k := 0, r.Intn(3); j <= k; j++ {
			body += fmt.Sprintf("func Test%d_%d(t *testing.T) { if %s != 1 { t.Fatal(%d) } }\n\n", i, j, call, r.Intn(1000))
		}
		// Exercise both implicit and explicit file-local imports, and
		// predeclared references in the binding surface beside named calls.
		if r.Intn(2) == 0 {
			body = strings.ReplaceAll(body, `"testing"`, `check "testing"`)
			body = strings.ReplaceAll(body, "testing.T", "check.T")
		}
		body += fmt.Sprintf("func helper%d() int { if true { return len([]int{1}) }; return 0 }\n", i)
		members[name] = body
	}
	return members, nonMembers
}

func union(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// Under one listing configuration the compartment declarations and headers
// are a function of the compartment hash: twins that share every member's bytes and
// differ in every non-member — the base file's body, an extra base file,
// an unembedded data file — give equal hashes and equal compartment entries,
// but distinct base binding evidence. A member's edit moves the hash
// (REQ-closure-test-variant-hash).
func TestCompartmentLedgerIsAFunctionOfTheHashUnderOneListingConfiguration(t *testing.T) {
	r := rand.New(rand.NewSource(168))
	const pkg = "example.com/gen"
	subject := Subject{Package: pkg, Symbol: "F"}
	for i := 0; i < 12; i++ {
		members, nonMembers := genCompartment(r)
		twin := map[string]string{}
		for k, v := range nonMembers {
			twin[k] = v
		}
		twin["gen.go"] = "package gen\n\n// a different base body\nfunc F() int { return 1 }\n\nfunc G() int { return 2 }\n"
		twin["extra.go"] = "package gen\n\nvar extra = 3\n"
		twin["loose.txt"] = "unembedded data\n"
		a, b := writeTestVariantModule(t, union(nonMembers, members)), writeTestVariantModule(t, union(twin, members))
		var ha, hb string
		var la, lb testvariant.TestVariantLedger
		var filesA []string
		// Keep the generator and its later member draw serial. The four
		// independent preparations finish before B's source is edited.
		t.Run(fmt.Sprintf("draw %d preparations", i), func(t *testing.T) {
			t.Run("hash A", func(t *testing.T) {
				t.Parallel()
				ha = computeAt(t, a, subject)[subject].TestVariants
			})
			t.Run("hash B", func(t *testing.T) {
				t.Parallel()
				hb = computeAt(t, b, subject)[subject].TestVariants
			})
			t.Run("ledger A", func(t *testing.T) {
				t.Parallel()
				la, filesA = ledgerUnder(t, a, nil, nil, pkg)
			})
			t.Run("ledger B", func(t *testing.T) {
				t.Parallel()
				lb, _ = ledgerUnder(t, b, nil, nil, pkg)
			})
		})
		if ha == "" || ha != hb {
			t.Fatalf("draw %d: hashes %q vs %q over the same members\n%v", i, ha, hb, members)
		}
		if !reflect.DeepEqual(la.Declarations, lb.Declarations) || !reflect.DeepEqual(la.FileHeaders, lb.FileHeaders) {
			t.Fatalf("draw %d: equal hashes, differing compartment entries:\n%+v\n%+v", i, la, lb)
		}
		if reflect.DeepEqual(la.BaseFiles, lb.BaseFiles) {
			t.Fatalf("draw %d: differing base source lost from binding context", i)
		}
		// One member's edit moves the hash: a member the listing itself
		// names, so a constrained-out file is never the one edited.
		if len(filesA) == 0 {
			// Every member constrained out under the plain selection: an
			// empty compartment, the defined empty identity — nothing to
			// edit; the equality arms above still held.
			continue
		}
		member := filesA[r.Intn(len(filesA))]
		body, known := members[member]
		if !known {
			t.Fatalf("draw %d: the listing names %s, which the generator did not write", i, member)
		}
		if err := os.WriteFile(filepath.Join(b, member), []byte(body+"\n// edited\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if hc := computeAt(t, b, subject)[subject].TestVariants; hc == ha {
			t.Fatalf("draw %d: an edited member %s kept the hash %q", i, member, ha)
		}
	}
}

// envWith is the process environment with one variable set, one entry.
func envWith(key, value string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, key+"=") {
			env = append(env, kv)
		}
	}
	return append(env, key+"="+value)
}

// The compartment hash is unsalted by the listing configuration and the
// ledger is not: a constrained test file embedded by a compiled sibling
// is a compartment member under both configurations — embedded data
// under one, a dual compiled-and-embedded member under the other — so
// the same members and bytes give one hash and two ledgers, on the
// build-selection axis (a tag), the platform axis (GOOS), and the cgo
// axis (CGO_ENABLED) alike; the reason the entailment is stated per
// listing configuration (REQ-closure-test-variant-hash).
func TestCompartmentHashIsUnsaltedByTheListingConfigurationAndTheLedgerIsNot(t *testing.T) {
	const pkg = "example.com/sel"
	subject := Subject{Package: pkg, Symbol: "F"}
	type arm struct {
		name, member, constraint string
		envA, envB               []string
		flagsA, flagsB           []string
	}
	arms := []arm{
		{name: "tag", member: "extra_test.go", constraint: "//go:build extra\n\n", flagsB: []string{"-tags=extra"}},
		{name: "platform", member: "extra_linux_test.go", envA: envWith("GOOS", "darwin"), envB: envWith("GOOS", "linux")},
		// cgo cannot appear in a test file; the axis reaches a test-only
		// member through the `cgo` build tag CGO_ENABLED sets.
		{name: "cgo", member: "extra_cgo_test.go", constraint: "//go:build cgo\n\n", envA: envWith("CGO_ENABLED", "0"), envB: envWith("CGO_ENABLED", "1")},
	}
	for _, a := range arms {
		t.Run(a.name, func(t *testing.T) {
			dir := writeTestVariantModule(t, map[string]string{
				"go.mod":      "module example.com/sel\n\ngo 1.26\n",
				"sel.go":      "package sel\n\nfunc F() int { return 1 }\n",
				"sel_test.go": "package sel\n\nimport (\n\t_ \"embed\"\n\t\"testing\"\n)\n\n//go:embed " + a.member + "\nvar sibling string\n\nfunc TestF(t *testing.T) { if F() != 1 || sibling == \"\" { t.Fatal(1) } }\n",
				a.member:      a.constraint + "package sel\n\nimport \"testing\"\n\nfunc TestExtra(t *testing.T) { if F() != 1 { t.Fatal(2) } }\n",
			})
			ca := computeUnder(t, dir, a.envA, a.flagsA, subject)[subject].TestVariants
			cb := computeUnder(t, dir, a.envB, a.flagsB, subject)[subject].TestVariants
			if ca == "" || ca != cb {
				t.Fatalf("the configuration salted the compartment hash: %q vs %q", ca, cb)
			}
			la, _ := ledgerUnder(t, dir, a.envA, a.flagsA, pkg)
			lb, _ := ledgerUnder(t, dir, a.envB, a.flagsB, pkg)
			if reflect.DeepEqual(la, lb) {
				t.Fatalf("two configurations, one ledger: %+v", la)
			}
			has := func(l testvariant.TestVariantLedger) bool {
				for _, d := range l.Declarations {
					if d.Name == "TestExtra" {
						return true
					}
				}
				return false
			}
			if has(la) || !has(lb) {
				t.Fatalf("the constrained member's declaration: excluded-side %v, included-side %v", has(la), has(lb))
			}
			// The member is a member under both, its header the whole
			// content marked embedded either way: embedded data under the
			// excluding configuration, a dual member under the including one.
			headerOf := func(l testvariant.TestVariantLedger) (testvariant.TestVariantFileHeader, bool) {
				for _, h := range l.FileHeaders {
					if h.File == a.member {
						return h, true
					}
				}
				return testvariant.TestVariantFileHeader{}, false
			}
			hp, okp := headerOf(la)
			ht, okt := headerOf(lb)
			if !okp || !okt || !hp.Embedded || !ht.Embedded || hp.Hash == "" || hp.Hash != ht.Hash {
				t.Fatalf("constrained member's headers: %+v (%v), %+v (%v); want both embedded over the same bytes", hp, okp, ht, okt)
			}
		})
	}
}

func TestContentIdentityIncludesEverySelectedPackage(t *testing.T) {
	r := rand.New(rand.NewSource(310))
	for draw := 0; draw < 12; draw++ {
		dir := t.TempDir()
		inventory := surfaceListing{}
		for i := 0; i < 2+r.Intn(5); i++ {
			name := string(rune('a' + i))
			pkgDir := filepath.Join(dir, name)
			writeTree(t, pkgDir, map[string]string{"one.go": "package p\n", "two.go": "package p\nvar X = 1\n"})
			inventory.Packages = append(inventory.Packages, listedPackage{ImportPath: name, Dir: pkgDir, Files: []string{"one.go", "two.go"}, Audited: i == 0})
		}
		read := func(l surfaceListing) sourceDigests {
			t.Helper()
			d, err := digestListing(context.Background(), l)
			if err != nil {
				t.Fatal(err)
			}
			return d
		}
		base := read(inventory)
		permuted := inventory
		permuted.Packages = slices.Clone(inventory.Packages)
		r.Shuffle(len(permuted.Packages), func(i, j int) {
			permuted.Packages[i], permuted.Packages[j] = permuted.Packages[j], permuted.Packages[i]
		})
		if got := read(permuted); !reflect.DeepEqual(got, base) {
			t.Fatal("package order changed the content identity")
		}
		for i, pkg := range inventory.Packages {
			// Both files of every package, not just the audited subset.
			for _, name := range pkg.Files {
				path := filepath.Join(pkg.Dir, name)
				original, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				changedSource := append(slices.Clone(original), '\n', '/', '/', byte('a'+r.Intn(26)), '\n')
				if err := os.WriteFile(path, changedSource, 0o600); err != nil {
					t.Fatal(err)
				}
				changed := read(inventory)
				if changed.Content == base.Content {
					t.Fatalf("package %d file %s missing from content identity", i, name)
				}
				if !pkg.Audited && !reflect.DeepEqual(changed.Packages, base.Packages) {
					t.Fatal("non-audited edit changed the audited projection")
				}
				if err := os.WriteFile(path, original, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestHasherSuppliesCompleteMemoDependencies(t *testing.T) {
	caller := AnalysisScope{ProofStrategy: "proof", FactStrategy: "facts", Toolchain: "tc", BuildConfig: "bc"}
	first := (&Hasher{source: sourceDigests{Content: "source-a", Policy: "policy-a"}}).SetAnalysisScope(caller)
	for _, source := range []sourceDigests{{Content: "source-b", Policy: "policy-a"}, {Content: "source-a", Policy: "policy-b"}} {
		// Even a previously completed caller scope cannot lend its dependency.
		moved := (&Hasher{source: source}).SetAnalysisScope(first)
		if moved.Proofs() == first.Proofs() || moved.Facts() == first.Facts() || moved.TestingScan() == first.TestingScan() || moved.Scan() == first.Scan() {
			t.Fatal("hasher dependency did not replace caller scope")
		}
	}
	for _, clear := range []func(*AnalysisScope){
		func(s *AnalysisScope) { s.Toolchain = "" },
		func(s *AnalysisScope) { s.BuildConfig = "" },
		func(s *AnalysisScope) { s.toolchainContent = "" },
		func(s *AnalysisScope) { s.admissionPolicy = "" },
	} {
		partial := first
		clear(&partial)
		if partial.Proofs() != "" || partial.Facts() != "" || partial.TestingScan() != "" || partial.Scan() != "" {
			t.Fatal("partial dependency set armed a memo")
		}
	}
}

func TestAdmissionPolicyTracksInventoryNotLabels(t *testing.T) {
	original := maps.Clone(auditedLinknameTargets)
	t.Cleanup(func() { auditedLinknameTargets = original })
	base := admissionPolicy()
	if base == "" {
		t.Fatal("empty policy identity")
	}
	auditedLinknameTargets["runtime.extraTargetForTest"] = true
	if admissionPolicy() == base {
		t.Fatal("changed admission inventory did not move policy")
	}
	if (&Hasher{}).AdmissionPolicy() != "" {
		t.Fatal("an unconstructed hasher claimed a policy dependency")
	}
}

func TestPositionBearingProofMemoTracksSourceSpelling(t *testing.T) {
	cache, dir := t.TempDir(), t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	const source = "package escape\nimport \"flag\"\nvar quiet bool\nfunc register(p *bool) { flag.BoolVar(p, \"memo.quiet\", false, \"fixture\") }\nfunc init() { register(&quiet) }\nfunc Prod() int { return 7 }\n"
	writeTree(t, dir, map[string]string{
		"go.mod":             "module example.com/positions\n\ngo 1.27\n",
		"escape/escape.go":   source,
		"consumer/p.go":      "package consumer\nimport \"example.com/positions/escape\"\nfunc Prod() int { return escape.Prod() }\n",
		"consumer/p_test.go": "package consumer\nimport \"testing\"\nfunc TestProd(t *testing.T) { Prod() }\n",
	})
	subject := Subject{Package: "example.com/positions/consumer", Symbol: "TestProd"}
	read := func() (Closure, Observability, bool) {
		t.Helper()
		h, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		h.SetAnalysisScope(AnalysisScope{ProofStrategy: "position-test", Toolchain: "toolchain", BuildConfig: "build"})
		cls, _, err := h.ComputeMaximalBatch([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		return cls[subject], proofs[subject], h.ServedSummary()["observability proof"][subject.Package]
	}
	before, oldProof, served := read()
	if served || oldProof.Observable || !strings.Contains(oldProof.Reason, "escape.go:4:") {
		t.Fatalf("position control: %+v served=%t", oldProof, served)
	}
	if _, unchanged, served := read(); !served || unchanged != oldProof {
		t.Fatal("unchanged proof did not serve identically")
	}
	writeTree(t, dir, map[string]string{"escape/escape.go": strings.Replace(source, "func register", "\n\nfunc register", 1)})
	after, warm, served := read()
	if before.Hash != after.Hash || before.TestVariants != after.TestVariants {
		t.Fatal("layout edit moved public canonical source equivalence")
	}
	if served || warm == oldProof || !strings.Contains(warm.Reason, "escape.go:6:") {
		t.Fatalf("stale position served=%t: %+v", served, warm)
	}
	if err := os.RemoveAll(filepath.Join(cache, "gofresh")); err != nil {
		t.Fatal(err)
	}
	_, cold, served := read()
	if served || cold != warm {
		t.Fatalf("discarded-cache proof differs: warm=%+v cold=%+v", warm, cold)
	}
}

// The FlagSet forms are admitted beside the registration families: a set an
// initializer constructs and registers into package-level storage rides the
// sink judgment through its receiver, and a subject touching none of the
// storage proves observable; a subject-time read of the default set keeps the
// standard-global refusal, and the parsed state readers keep their class
// (REQ-closure-observability-flag-registration's FlagSet forms).
func TestFlagSetFormsRideTheRegistrationJudgment(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/flagset\n\ngo 1.26\n")
	cases := []struct{ pkg, source, refusal string }{
		{"customset", "package customset\n\nimport \"flag\"\n\nvar verbose bool\n\nvar set = flag.NewFlagSet(\"customset\", flag.ContinueOnError)\n\nfunc init() {\n\tset.BoolVar(&verbose, \"v\", false, \"fixture flag\")\n}\n\nfunc Subject() int { return 7 }\n", ""},
		// A package-held set never parsed is proven (every Parse closes
		// vacuously): its storage holds the default forever, ordinary
		// initialized state a subject may read.
		{"customread", "package customread\n\nimport \"flag\"\n\nvar verbose bool\n\nvar set = flag.NewFlagSet(\"customread\", flag.ContinueOnError)\n\nfunc init() {\n\tset.BoolVar(&verbose, \"v\", false, \"fixture flag\")\n}\n\nfunc Subject() int {\n\tif verbose {\n\t\treturn 1\n\t}\n\treturn 7\n}\n", ""},
		// The fold admits the selector; the walk's standard-global arm
		// refuses the subject-time read of the default set.
		{"defaultread", "package defaultread\n\nimport \"flag\"\n\nfunc Subject() *flag.FlagSet { return flag.CommandLine }\n", "reaches standard global flag.CommandLine"},
		// The parsed-state readers and Parse itself keep their class on
		// either set, refused by name at the walk's call fallback (the
		// fold's selector arm sees only a package-qualified identifier,
		// which these method calls do not spell).
		{"defaultargs", "package defaultargs\n\nimport \"flag\"\n\nfunc Subject() int { return len(flag.CommandLine.Args()) }\n", "reaches unaudited standard operation flag.Args"},
		{"customparse", "package customparse\n\nimport \"flag\"\n\nvar set = flag.NewFlagSet(\"customparse\", flag.ContinueOnError)\n\nfunc Subject() error { return set.Parse(nil) }\n", "reaches unaudited standard operation flag.Parse"},
		{"setname", "package setname\n\nimport \"flag\"\n\nvar set = flag.NewFlagSet(\"setname\", flag.ContinueOnError)\n\nfunc Subject() string { return set.Name() }\n", "reaches unaudited standard operation flag.Name"},
		// Constructing a set is an allocation in every flow; the
		// ErrorHandling accessor rides the constant's name.
		{"subjectnew", "package subjectnew\n\nimport \"flag\"\n\nfunc Subject() flag.ErrorHandling { return flag.NewFlagSet(\"s\", flag.PanicOnError).ErrorHandling() }\n", ""},
		// A function-local set registering the function's own local is
		// proven: the storage is that function's, no command line
		// reaches it.
		{"subjectreg", "package subjectreg\n\nimport \"flag\"\n\nfunc Subject() bool {\n\tvar v bool\n\tset := flag.NewFlagSet(\"s\", flag.ContinueOnError)\n\tset.BoolVar(&v, \"v\", false, \"fixture flag\")\n\treturn v\n}\n", ""},
		// The default set replaced by a constructed one is never proven:
		// the standard bodies load flag.CommandLine unscanned, so the
		// package-level families' registrations keep the mark.
		{"defaultreplaceread", "package defaultreplaceread\n\nimport \"flag\"\n\nvar verbose bool\n\nfunc init() {\n\tflag.CommandLine = flag.NewFlagSet(\"x\", flag.ContinueOnError)\n\tflag.BoolVar(&verbose, \"v\", false, \"fixture flag\")\n}\n\nfunc Subject() bool { return verbose }\n", "flag-registered state"},
		// The swapped-in set is never proven even as a method-form
		// receiver: the harness parses the command line into whatever
		// flag.CommandLine holds, a load the standard bodies make.
		{"defaultreplacemethod", "package defaultreplacemethod\n\nimport \"flag\"\n\nvar verbose bool\n\nfunc init() {\n\tflag.CommandLine = flag.NewFlagSet(\"x\", flag.ContinueOnError)\n\tflag.CommandLine.BoolVar(&verbose, \"v\", false, \"fixture flag\")\n}\n\nfunc Subject() bool { return verbose }\n", "flag-registered state"},
		// A startup-flow replacement of the default set adds no channel:
		// the storage judgment is per registration call, set-blind.
		{"defaultreplace", "package defaultreplace\n\nimport \"flag\"\n\nfunc init() { flag.CommandLine = flag.NewFlagSet(\"x\", flag.ContinueOnError) }\n\nfunc Subject() int { return 7 }\n", ""},
	}
	subjects := make([]Subject, 0, len(cases))
	for _, tc := range cases {
		if err := os.MkdirAll(filepath.Join(dir, tc.pkg), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, tc.pkg+"/"+tc.pkg+".go", tc.source)
		subjects = append(subjects, Subject{Package: "example.com/flagset/" + tc.pkg, Symbol: "Subject"})
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
		proof := proofs[Subject{Package: "example.com/flagset/" + tc.pkg, Symbol: "Subject"}]
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

// A FlagSet the program itself closes is ordinary state: its
// registrations mark and poison nothing and its Parse is admitted in
// the flow that proves it, while every shape the provenance cannot
// close keeps the mark-and-poison judgment
// (REQ-closure-observability-flag-registration's FlagSet provenance rule).
func TestClosedFlagSetsAreOrdinaryState(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/flagprov\n\ngo 1.26\n")
	// An os.Args reference refuses at the file fold before any
	// provenance question, so the command line reaches a set only
	// through the standard bodies — the default set, never proven.
	pkgSet := func(name, parse, subject string) string {
		return "package " + name + "\n\nimport \"flag\"\n\nvar verbose bool\n\nvar set = flag.NewFlagSet(\"" + name + "\", flag.ContinueOnError)\n\nfunc init() {\n\tset.BoolVar(&verbose, \"v\", false, \"fixture flag\")\n" + parse + "}\n\n" + subject + "\n"
	}
	readVerbose := "func Subject() bool { return verbose }"
	cases := []struct{ pkg, source, refusal string }{
		// Package-held set, parsed in init from a literal: the storage
		// is initializer-written package state.
		{"startupclosed", pkgSet("startupclosed", "\t_ = set.Parse([]string{\"-v\"})\n", readVerbose), ""},
		{"startupnil", pkgSet("startupnil", "\t_ = set.Parse(nil)\n", readVerbose), ""},
		{"startupempty", pkgSet("startupempty", "\t_ = set.Parse([]string{})\n", readVerbose), ""},
		// A computed argument is not the program's literal: unproven,
		// so the startup walk refuses Parse by name.
		{"startupcomputed", pkgSet("startupcomputed", "\t_ = set.Parse(args())\n", "func args() []string { return []string{\"-v\"} }\n\n"+readVerbose), "startup effect: reaches unaudited standard operation flag.Parse"},
		{"startupsliced", pkgSet("startupsliced", "\t_ = set.Parse([]string{\"-v\", \"x\"}[:1])\n", readVerbose), "startup effect: reaches unaudited standard operation flag.Parse"},
		// A subject-flow Parse of a package-held set writes package
		// state where the walk cannot see the write: unproven, and Parse
		// keeps its class.
		{"startupparsesubject", pkgSet("startupparsesubject", "", "func Subject() bool {\n\t_ = set.Parse([]string{\"-v\"})\n\treturn verbose\n}"), "flag-registered state"},
		{"startupparseonly", pkgSet("startupparseonly", "", "func Subject() error { return set.Parse([]string{\"-v\"}) }"), "reaches unaudited standard operation flag.Parse"},
		// A site launched as a goroutine or placed in a closure literal
		// is not the initializer's own frame: the write races or
		// outlives the flow that would prove it, so the set stays
		// unproven and the startup walk refuses its Parse by name.
		{"gostartup", pkgSet("gostartup", "\tgo func() { _ = set.Parse([]string{\"-v\"}) }()\n", readVerbose), "startup effect: reaches unaudited standard operation flag.Parse"},
		{"closurestartup", pkgSet("closurestartup", "\tfunc() { _ = set.Parse([]string{\"-v\"}) }()\n", readVerbose), "startup effect: reaches unaudited standard operation flag.Parse"},
		// The holder stored outside initializer flow is a set the
		// initializer does not own.
		{"startupsetup", "package startupsetup\n\nimport \"flag\"\n\nvar verbose bool\n\nvar set *flag.FlagSet\n\nfunc Setup() { set = flag.NewFlagSet(\"s\", flag.ContinueOnError) }\n\nfunc init() {\n\tset.BoolVar(&verbose, \"v\", false, \"fixture flag\")\n}\n\nfunc Subject() bool { return verbose }\n", "flag-registered state"},
		// The value family's package-level storage on a proven set is
		// initializer-written state; the same set left unproven keeps
		// the mark.
		{"startupvalueptr", "package startupvalueptr\n\nimport \"flag\"\n\nvar set = flag.NewFlagSet(\"s\", flag.ContinueOnError)\n\nvar verbose = set.Bool(\"v\", false, \"fixture flag\")\n\nfunc init() { _ = set.Parse([]string{\"-v\"}) }\n\nfunc Subject() bool { return *verbose }\n", ""},
		{"startupvalueusage", "package startupvalueusage\n\nimport \"flag\"\n\nvar set = flag.NewFlagSet(\"s\", flag.ContinueOnError)\n\nvar verbose = set.Bool(\"v\", false, \"fixture flag\")\n\nfunc init() { set.Usage = nil }\n\nfunc Subject() bool { return *verbose }\n", "flag-registered state"},
		// Any other use of the set — a field write, an escape into a
		// helper, a second store into the holder — keeps it unproven:
		// Parse-free, so the surviving refusal is the mark itself.
		{"startupusage", pkgSet("startupusage", "\tset.Usage = func() {}\n", readVerbose), "flag-registered state"},
		{"startupescape", pkgSet("startupescape", "\tuse(set)\n", "func use(*flag.FlagSet) {}\n\n"+readVerbose), "flag-registered state"},
		{"startuprestore", pkgSet("startuprestore", "\tset = flag.NewFlagSet(\"again\", flag.ContinueOnError)\n", readVerbose), "flag-registered state"},
		// Function-local set, local storage, literal Parse: the subject's
		// own state in every form.
		{"localclosed", "package localclosed\n\nimport \"flag\"\n\nfunc Subject() bool {\n\tvar v bool\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tfs.BoolVar(&v, \"v\", false, \"fixture flag\")\n\t_ = fs.Parse([]string{\"-v\"})\n\treturn v\n}\n", ""},
		{"localvalue", "package localvalue\n\nimport \"flag\"\n\nfunc Subject() bool {\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tv := fs.Bool(\"v\", false, \"fixture flag\")\n\t_ = fs.Parse([]string{\"-v\"})\n\treturn *v\n}\n", ""},
		{"localstruct", "package localstruct\n\nimport \"flag\"\n\ntype opts struct{ v bool }\n\nfunc Subject() bool {\n\tvar o opts\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tfs.BoolVar(&o.v, \"v\", false, \"fixture flag\")\n\t_ = fs.Parse([]string{\"-v\"})\n\treturn o.v\n}\n", ""},
		// A computed argument on a local set keeps the poison.
		{"localcomputed", "package localcomputed\n\nimport \"flag\"\n\nfunc args() []string { return []string{\"-v\"} }\n\nfunc Subject() bool {\n\tvar v bool\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tfs.BoolVar(&v, \"v\", false, \"fixture flag\")\n\t_ = fs.Parse(args())\n\treturn v\n}\n", "BoolVar target is not a package-level variable"},
		// A write through the result is the function's own storage.
		{"localwrite", "package localwrite\n\nimport \"flag\"\n\nfunc Subject() bool {\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tv := fs.Bool(\"v\", false, \"fixture flag\")\n\t*v = true\n\t_ = fs.Parse(nil)\n\treturn *v\n}\n", ""},
		// A goroutine-launched Parse on a local set races the subject.
		{"golocal", "package golocal\n\nimport \"flag\"\n\nfunc Subject() bool {\n\tvar v bool\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tfs.BoolVar(&v, \"v\", false, \"fixture flag\")\n\tgo fs.Parse([]string{\"-v\"})\n\treturn v\n}\n", "BoolVar target is not a package-level variable"},
		// The local storage's address held in package state outlives
		// the frame: an escape, poisoned as on every other set.
		{"localescapeaddr", "package localescapeaddr\n\nimport \"flag\"\n\nvar esc *bool\n\nfunc Subject() bool {\n\tvar v bool\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tfs.BoolVar(&v, \"v\", false, \"fixture flag\")\n\tesc = &v\n\t_ = fs.Parse([]string{\"-v\"})\n\treturn *esc\n}\n", "BoolVar target is not a package-level variable"},
		// The local storage's address passed to a helper is an escape
		// of the storage alone, the set itself proven.
		{"localescapecall", "package localescapecall\n\nimport \"flag\"\n\nfunc use(*bool) {}\n\nfunc Subject() bool {\n\tvar v bool\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tfs.BoolVar(&v, \"v\", false, \"fixture flag\")\n\tuse(&v)\n\t_ = fs.Parse([]string{\"-v\"})\n\treturn v\n}\n", "BoolVar target is not a package-level variable"},
		// The result stored into package state keeps the mark.
		{"localvalueglobal", "package localvalueglobal\n\nimport \"flag\"\n\nvar late *bool\n\nfunc Subject() bool {\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tlate = fs.Bool(\"v\", false, \"fixture flag\")\n\t_ = fs.Parse(nil)\n\treturn *late\n}\n", "flag-registered state"},
		// A local set registering package-level storage: the mark stays
		// on the storage Parse writes in subject flow.
		{"localglobalroot", "package localglobalroot\n\nimport \"flag\"\n\nvar verbose bool\n\nfunc Subject() bool {\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tfs.BoolVar(&verbose, \"v\", false, \"fixture flag\")\n\t_ = fs.Parse([]string{\"-v\"})\n\treturn verbose\n}\n", "flag-registered state"},
		// A local set handed to a helper escapes the proving function.
		{"localescape", "package localescape\n\nimport \"flag\"\n\nfunc register(fs *flag.FlagSet, v *bool) { fs.BoolVar(v, \"v\", false, \"fixture flag\") }\n\nfunc Subject() bool {\n\tvar v bool\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\tregister(fs, &v)\n\t_ = fs.Parse([]string{\"-v\"})\n\treturn v\n}\n", "BoolVar target is not a package-level variable"},
		// The parsed-state readers keep their class on a proven set.
		{"localreader", "package localreader\n\nimport \"flag\"\n\nfunc Subject() int {\n\tfs := flag.NewFlagSet(\"l\", flag.ContinueOnError)\n\t_ = fs.Parse([]string{\"a\"})\n\treturn fs.NArg()\n}\n", "reaches unaudited standard operation flag.NArg"},
	}
	subjects := make([]Subject, 0, len(cases))
	for _, tc := range cases {
		if err := os.MkdirAll(filepath.Join(dir, tc.pkg), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, tc.pkg+"/"+tc.pkg+".go", tc.source)
		subjects = append(subjects, Subject{Package: "example.com/flagprov/" + tc.pkg, Symbol: "Subject"})
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
		proof := proofs[Subject{Package: "example.com/flagprov/" + tc.pkg, Symbol: "Subject"}]
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

// floorModule writes a small generated module whose shape is a pure
// function of the seed: a chain of packages with cross-imports, bodies
// with and without external effects, and test files on some packages.
func floorModule(t testing.TB, seed uint64) (string, []Subject) {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/floor\n\ngo 1.26\n")
	packages := int(seed%3) + 2
	var subjects []Subject
	for i := 0; i < packages; i++ {
		name := fmt.Sprintf("p%d", i)
		body := fmt.Sprintf("package %s\n\n", name)
		if i > 0 {
			body += fmt.Sprintf("import \"example.com/floor/p%d\"\n\n", i-1)
		}
		if seed>>(uint(i))&1 == 1 {
			body += "import \"os\"\n\nfunc init() { _ = os.Args }\n\n"
		}
		if i > 0 {
			body += fmt.Sprintf("func F() int { return p%d.F() + %d }\n", i-1, i)
		} else {
			body += fmt.Sprintf("func F() int { return %d }\n", int(seed%97))
		}
		write(name+"/"+name+".go", body)
		if seed>>(uint(i+3))&1 == 1 {
			write(name+"/"+name+"_test.go", fmt.Sprintf("package %s\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) { _ = F() }\n", name))
		}
		subjects = append(subjects, Subject{Package: "example.com/floor/" + name, Symbol: "F"})
	}
	return dir, subjects
}

// FuzzMaximalClosureFloor pins REQ-closure-floor as a property: the shared,
// memoized batch derivation never narrows below independent fresh
// derivation — hashes, compartments, and source sets are equal per subject —
// and the hash is sensitive to every mutable closure file (editing any
// package on the subject's import chain moves the subject's hash).
func FuzzMaximalClosureFloor(f *testing.F) {
	f.Add(uint64(0))
	f.Add(uint64(7))
	f.Add(uint64(42))
	f.Add(uint64(255))
	f.Fuzz(func(t *testing.T, seed uint64) {
		dir, subjects := floorModule(t, seed)
		batchHasher, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer unprimeHasher(batchHasher)
		batched, batchedSources, err := batchHasher.ComputeMaximalBatch(subjects)
		if err != nil {
			t.Fatal(err)
		}
		for _, subject := range subjects {
			fresh, err := newAt(dir)
			if err != nil {
				t.Fatal(err)
			}
			independent, independentSources, err := fresh.ComputeMaximalBatch([]Subject{subject})
			unprimeHasher(fresh)
			if err != nil {
				t.Fatal(err)
			}
			if batched[subject] != independent[subject] {
				t.Fatalf("seed %d: batched %v = %+v, independent %+v", seed, subject, batched[subject], independent[subject])
			}
			if !reflect.DeepEqual(batchedSources[subject], independentSources[subject]) {
				t.Fatalf("seed %d: batched sources %v, independent %v", seed, batchedSources[subject], independentSources[subject])
			}
		}
		// Never-narrow sensitivity: editing the root package moves every
		// subject downstream of it (all subjects import transitively).
		last := subjects[len(subjects)-1]
		before := batched[last].Hash
		rootFile := filepath.Join(dir, "p0", "p0.go")
		content, err := os.ReadFile(rootFile)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rootFile, append(content, []byte("\nfunc edited() {}\n")...), 0o644); err != nil {
			t.Fatal(err)
		}
		edited, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer unprimeHasher(edited)
		after, _, err := edited.ComputeMaximalBatch([]Subject{last})
		if err != nil {
			t.Fatal(err)
		}
		if after[last].Hash == before {
			t.Fatalf("seed %d: a dependency edit did not move the downstream subject's hash", seed)
		}
	})
}

func TestStandardInventoryCoversPGOCopiesWithoutLosingSourceChecks(t *testing.T) {
	h := &Hasher{source: sourceDigests{Content: "present", inventory: map[string]listedPackage{
		"internal/example": {Dir: "/goroot/src/internal/example", Files: []string{"body.go", "data.bin", "fast.s"}},
	}}}
	for _, identity := range []struct{ path, forTest string }{
		{"internal/example", ""},
		{"internal/example [example.com/p.test]", "example.com/p"},
		{"internal/example [example.com/main]", ""},
	} {
		t.Run(identity.path, func(t *testing.T) {
			base := listPkg{ImportPath: identity.path, ForTest: identity.forTest, Standard: true,
				Dir: "/goroot/src/internal/example", GoFiles: []string{"body.go"}, SFiles: []string{"fast.s"}, EmbedFiles: []string{"data.bin"}}
			if err := h.standardInventoryCovers([]listPkg{base}); err != nil {
				t.Fatalf("same selected source refused: %v", err)
			}
			for name, change := range map[string]func(*listPkg){
				"unknown source": func(p *listPkg) { p.ImportPath = "internal/unknown [example.com/p.test]" },
				"directory":      func(p *listPkg) { p.Dir = "/different/internal/example" },
				"test source":    func(p *listPkg) { p.GoFiles = []string{"body.go", "body_test.go"} },
				"missing source": func(p *listPkg) { p.GoFiles = nil },
				"assembly":       func(p *listPkg) { p.SFiles = []string{"other.s"} },
				"embed":          func(p *listPkg) { p.EmbedFiles = []string{"other.bin"} },
			} {
				t.Run(name, func(t *testing.T) {
					changed := base
					change(&changed)
					// A matching copy never covers a later mismatching copy.
					if err := h.standardInventoryCovers([]listPkg{base, changed}); err == nil {
						t.Fatal("uncovered source inherited another build copy's inventory")
					}
				})
			}
		})
	}
}

// A nil reader refuses at every entry — never a nil dereference deep in
// a load.
func TestNilReaderRefusesAtEveryEntry(t *testing.T) {
	ctx := context.Background()
	if _, err := NewAt(ctx, nil); err == nil || !strings.Contains(err.Error(), "nil environment reader") {
		t.Fatalf("NewAt(nil) = %v", err)
	}
	if _, err := NewBracketAt(ctx, nil); err == nil || !strings.Contains(err.Error(), "nil environment reader") {
		t.Fatalf("NewBracketAt(nil) = %v", err)
	}
	if _, err := LoadViewPackages(ctx, nil, nil, "x"); err == nil || !strings.Contains(err.Error(), "nil environment reader") {
		t.Fatalf("LoadViewPackages(nil) = %v", err)
	}
	if _, err := LoadViewGraph(ctx, nil, nil, "x"); err == nil || !strings.Contains(err.Error(), "nil environment reader") {
		t.Fatalf("LoadViewGraph(nil) = %v", err)
	}
}

func TestOutcomeInventorySeparatesAdmissionFromDerivation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the immutable environment outcome method is audited for Linux")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/outcomes\n\ngo 1.26\n")
	cases := []struct {
		name, source string
		observable   bool
		supported    bool
	}{
		{"empty", `import "testing"
func TestSubject(t *testing.T) { if 1 + 1 != 2 { t.Fatal("arithmetic") } }`, true, true},
		{"pure", `import "testing"
func TestSubject(t *testing.T) {}`, true, true},
		{"getenv", `import ("os"; "testing")
func TestSubject(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE") }`, true, true},
		{"lookup", `import ("os"; "testing")
func TestSubject(t *testing.T) { _, _ = os.LookupEnv("OUTCOME_VALUE") }`, true, true},
		{"failure", `import ("os"; "testing")
func TestSubject(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE"); t.Error("ordinary failure") }`, true, true},
		{"pacing", `import ("os"; "testing")
func BenchmarkSubject(b *testing.B) { b.ResetTimer(); b.StopTimer(); b.StartTimer(); for b.Loop() { _ = os.Getenv("OUTCOME_VALUE") }; _ = b.N }`, true, true},
		{"subtest", `import ("os"; "testing")
func TestSubject(t *testing.T) { t.Run("child", func(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE") }) }`, true, true},
		{"subtestfile", `import ("os"; "testing")
func TestSubject(t *testing.T) { t.Run("child", func(t *testing.T) { _, _ = os.ReadFile("input.txt") }) }`, true, false},
		{"file", `import ("os"; "testing")
func TestSubject(t *testing.T) { _, _ = os.ReadFile("input.txt") }`, true, false},
		{"mixed", `import ("os"; "testing")
func TestSubject(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE"); _, _ = os.ReadFile("input.txt") }`, true, false},
		{"mainenv", `import ("os"; "testing")
func TestMain(m *testing.M) { _ = os.Getenv("OUTCOME_VALUE"); os.Exit(m.Run()) }
func TestSubject(t *testing.T) {}`, true, true},
		{"mainfile", `import ("os"; "testing")
func TestMain(m *testing.M) { _, _ = os.ReadFile("input.txt"); os.Exit(m.Run()) }
func TestSubject(t *testing.T) {}`, true, false},
		{"initenv", `import ("os"; "testing")
var value = os.Getenv("OUTCOME_VALUE")
func TestSubject(t *testing.T) { _ = value }`, false, false},
		{"mutation", `import ("os"; "testing")
func TestSubject(t *testing.T) { _ = os.Setenv("OUTCOME_VALUE", "changed"); _ = os.Getenv("OUTCOME_VALUE") }`, false, false},
		{"siblingmutation", `import ("os"; "testing")
func TestOther(t *testing.T) { _ = os.Setenv("OUTCOME_VALUE", "changed") }
func TestSubject(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE") }`, false, false},
		{"cleanupenv", `import ("os"; "testing")
func TestSubject(t *testing.T) { t.Cleanup(func() { _ = os.Getenv("OUTCOME_VALUE") }) }`, false, false},
		{"cleanupfile", `import ("os"; "testing")
func TestSubject(t *testing.T) { t.Cleanup(func() { _, _ = os.ReadFile("input.txt") }) }`, false, false},
	}
	var subjects []Subject
	for _, tc := range cases {
		if err := os.MkdirAll(filepath.Join(dir, tc.name), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, tc.name+"/subject_test.go", "package "+tc.name+"\n"+tc.source+"\n")
		symbol := "TestSubject"
		if tc.name == "pacing" {
			symbol = "BenchmarkSubject"
		}
		subjects = append(subjects, Subject{Package: "example.com/outcomes/" + tc.name, Symbol: symbol})
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !h.SelectionAudited() {
		t.Fatalf("test requires audited toolchain: %s", h.SelectionNotice())
	}
	scope := AnalysisScope{ProofStrategy: "outcome-inventory-test@1", Toolchain: "test-selection", BuildConfig: "build"}
	h.SetAnalysisScope(scope)
	cold, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for i, tc := range cases {
		proof := cold[subjects[i]]
		wantMethod := ""
		if tc.supported {
			wantMethod = ImmutableEnvironmentOutcomes
		}
		if proof.Observable != tc.observable || proof.OutcomeMethod != wantMethod {
			t.Errorf("%s = %+v; want observable=%t method=%q", tc.name, proof, tc.observable, wantMethod)
		}
	}
	// The cold fill is complete before these independent readers begin. Each
	// reader owns its hasher; the parent keeps the cache home and source stable.
	t.Run("after cold", func(t *testing.T) {
		t.Run("warm", func(t *testing.T) {
			t.Parallel()
			warmHasher, err := newAt(dir)
			if err != nil {
				t.Fatal(err)
			}
			warmHasher.SetAnalysisScope(scope)
			warmHasher.OnProgress(func(phase, pkg string) {
				if phase == "load" || phase == "prove" {
					t.Errorf("warm inventory recomputed %s for %s", phase, pkg)
				}
			})
			warm, err := warmHasher.ComputeObservabilityBatch(subjects)
			if err != nil {
				t.Fatal(err)
			}
			for _, subject := range subjects {
				if warm[subject] != cold[subject] {
					t.Errorf("warm %s = %+v; cold %+v", subject.Package, warm[subject], cold[subject])
				}
			}
		})
		// The source model, not the analyzer's host platform, selects the method.
		t.Run("other platform", func(t *testing.T) {
			t.Parallel()
			other, err := newAtEnv(context.Background(), dir, environmentWith("GOOS=plan9", "GOARCH=amd64"))
			if err == nil {
				primeHasherFromDir(t, other, dir)
			}
			if err != nil {
				t.Fatal(err)
			}
			proofs, err := other.ComputeObservabilityBatch(subjects[:3])
			if err != nil {
				t.Fatal(err)
			}
			for subject, proof := range proofs {
				if proof.OutcomeMethod != "" {
					t.Errorf("unaudited outcome platform granted %s: %+v", subject.Symbol, proof)
				}
			}
		})
		// Keep the analyzed Linux snapshot and an empty effect set; independently
		// withdraw the audit verdict so neither the platform guard nor an ordinary
		// external-effect refusal can hide a missing outcome-audit prerequisite.
		t.Run("unaudited", func(t *testing.T) {
			t.Parallel()
			unaudited, err := newAt(dir)
			if err != nil {
				t.Fatal(err)
			}
			unaudited.selectionResolved = false
			pure := Subject{Package: "example.com/outcomes/pure", Symbol: "TestSubject"}
			unsupported, err := unaudited.ComputeObservabilityBatch([]Subject{pure})
			if err != nil {
				t.Fatal(err)
			}
			if proof := unsupported[pure]; !proof.Observable || proof.OutcomeMethod != "" {
				t.Fatalf("empty effects under unaudited Linux selection = %+v; want observable without outcome support", proof)
			}
		})
	})
}

func FuzzOutcomeInventoryRejectsUnsupportedEffects(f *testing.F) {
	f.Add([]byte{0, 1, 0})
	f.Add([]byte{0, 2, 1})
	f.Add([]byte{3})
	f.Add([]byte{})
	f.Add([]byte{4, 5, 6})
	f.Add([]byte{4, 7, 6})
	f.Fuzz(func(t *testing.T, grammar []byte) {
		var effects []externalEffect
		want := ImmutableEnvironmentOutcomes
		for _, b := range grammar {
			var effect externalEffect
			switch b % 8 {
			case 0:
				effect, _ = classBEffect("os", "Getenv")
				effect.observable = true
			case 1:
				effect, _ = classBEffect("os", "LookupEnv")
				effect.observable = true
			case 2:
				effect, _ = classBEffect("os", "ReadFile")
				effect.observable = true
				want = ""
			case 3:
				effect, _ = classBEffect("os", "Getenv")
				want = ""
			case 4:
				effect = harnessLoggingEffect("Error")
			case 5:
				pacing := []string{"Loop", "ResetTimer", "StartTimer", "StopTimer", "B.N"}
				effect = harnessPacingEffect(pacing[int(b/8)%len(pacing)])
			case 6:
				effect = harnessSubtestDriverEffect()
			case 7:
				effect, _ = classBEffect("testing", "TempDir")
				effect.observable = true
				want = ""
			}
			effects = append(effects, effect)
		}
		for split := 0; split <= len(effects); split++ {
			if got := immutableEnvironmentMethod(effects[:split], effects[split:]); got != want {
				t.Fatalf("partition %d of %v gave %q; want %q", split, grammar, got, want)
			}
		}
	})
}

// Every ambient-effect reason — a network, plugin, or native reach,
// symbol-level or package-level, opaque or named — carries the
// subject-level discharge channel, composed by the constructors so no
// site can omit it; the kinds whose lift lives elsewhere (the
// observation bracket, the toolchain audit) carry none
// (REQ-closure-refusal-channels).
func TestAmbientEffectReasonsNameTheirDischargeChannel(t *testing.T) {
	const channel = " (dischargeable by restructuring the subject away from the reach, or by " + PurityResponsibility + ")"
	carrying := []externalEffect{
		symbolExternalEffect(externalEffectNetwork, "net", "Dial", "reaches net.Dial (network I/O)"),
		symbolExternalEffect(externalEffectPlugin, "plugin", "Open", "reaches plugin.Open"),
		opaqueExternalEffect(externalEffectNative, "reaches cgo external library"),
		trueExternalEffect("syscall"),
		trueExternalEffect("net/http"),
		trueExternalEffect("plugin"),
	}
	for _, effect := range carrying {
		if !strings.HasSuffix(effect.reason, channel) {
			t.Fatalf("%v reason %q carries no discharge channel", effect.kind, effect.reason)
		}
		if strings.Count(effect.reason, "dischargeable") != 1 {
			t.Fatalf("%v reason %q composes the channel more than once", effect.kind, effect.reason)
		}
	}
	if got := trueExternalEffect("syscall").reason; got != "reaches syscall (external system call)"+channel {
		t.Fatalf("native package reason = %q", got)
	}
	bare := []externalEffect{
		symbolExternalEffect(externalEffectFileIO, "os", "File.Read", "reaches os.File.Read on an unattributed file handle (file I/O)"),
		symbolExternalEffect(externalEffectUnauditedStandard, "fmt", "State", "reaches unaudited standard operation fmt.State"),
		symbolExternalEffect(externalEffectFilesystemMutation, "os", "OpenFile", "reaches os.OpenFile (filesystem mutation)"),
		opaqueExternalEffect(externalEffectLinkage, "reaches go:linkname (opaque linkage)"),
	}
	for _, effect := range bare {
		if strings.Contains(effect.reason, "dischargeable") {
			t.Fatalf("%v reason %q names a channel it does not afford", effect.kind, effect.reason)
		}
	}
}

// The observability tier attributes an unaudited selection at the
// batch's return — past the memo, so a cold pass and a warm pass served
// from the memo render the same single attribution — and an audited
// selection attributes nothing (REQ-closure-refusal-channels,
// REQ-closure-observability-memo).
func TestObservabilityRefusalAttributesTheUnauditedSelection(t *testing.T) {
	isolateProofCache(t)
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  "module example.com/attributed\n\ngo 1.26\n",
		"read.go": "package attributed\n\nimport \"os\"\n\nfunc Read(name string) int {\n\tb, _ := os.ReadFile(name)\n\treturn len(b)\n}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	subject := Subject{Package: "example.com/attributed", Symbol: "Read"}
	probe, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	stringsDigest := probe.source.Packages["strings"]
	if stringsDigest == "" {
		t.Fatal("missing strings digest on audited probe")
	}
	isolateProofCache(t)
	stringsMemoKey := verifiedPackageMemoKey("strings", stringsDigest)

	axis := " (judged under an unaudited toolchain selection: the audited surface of " + runtime.Version() + " moved in 1 keys: strings)"
	withClosureTestHooks(analysisTestHookSet{
		packageVerdictOverride: func(memoKey string) (verifiedPackageVerdict, bool) {
			if memoKey == stringsMemoKey {
				return verifiedPackageVerdict{OK: false}, true
			}
			return verifiedPackageVerdict{}, false
		},
	}, func() {
		var cold Observability
		for pass, want := range []int{1, 0} {
			h, err := newAt(dir, "-tags=dup")
			if err != nil {
				t.Fatal(err)
			}
			h.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "t", BuildConfig: "badstd"})
			loads := 0
			h.OnProgress(func(phase, _ string) {
				if phase == "load" || phase == "prove" {
					loads++
				}
			})
			proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
			if err != nil {
				t.Fatal(err)
			}
			if (loads == 0) != (want == 0) {
				t.Fatalf("pass %d emitted %d load/prove events, want %s", pass, loads, map[int]string{1: "a cold derivation", 0: "a memo serve"}[want])
			}
			proof := proofs[subject]
			if proof.Observable || !strings.HasSuffix(proof.Reason, axis) || strings.Count(proof.Reason, "judged under") != 1 {
				t.Fatalf("pass %d under unaudited selection: %+v, want the refusal with the axis appended once", pass, proof)
			}
			if pass == 0 {
				cold = proof
			} else if proof != cold {
				t.Fatalf("warm proof %+v differs from cold %+v", proof, cold)
			}
		}
	})
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if proof := proofs[subject]; strings.Contains(proof.Reason, "judged under") {
		t.Fatalf("audited selection attributed: %+v", proof)
	}
}

// Each memo's scope renders exactly the axes its derivation reads: the
// proofs, facts and typed scans share the complete guard/dependency identity;
// the view scan additionally joins the sorted vouch set. A partial identity
// and the zero value arm nothing.
func TestAnalysisScopeRendersEachMemosAxes(t *testing.T) {
	scope := AnalysisScope{ProofStrategy: "rta@1", FactStrategy: "facts@2", Toolchain: "tc", BuildConfig: "bc", Vouches: []string{"b:y", "a:x"}, toolchainContent: "content", admissionPolicy: "policy"}
	if got, want := scope.Proofs(), "rta@1|tc|bc|"+AnalyzingFrontend()+"|content|policy"; got != want {
		t.Errorf("Proofs = %q, want %q", got, want)
	}
	if got, want := scope.TestingScan(), testingScanStrategy+"|tc|bc|"+AnalyzingFrontend()+"|content|policy"; got != want {
		t.Errorf("TestingScan = %q, want %q", got, want)
	}
	if got, want := scope.Facts(), "facts@2|tc|bc|"+AnalyzingFrontend()+"|content|policy"; got != want {
		t.Errorf("Facts = %q, want %q", got, want)
	}
	if got, want := scope.Scan(), "facts@2|tc|bc|"+AnalyzingFrontend()+"|content|policy|vouches:a:x,b:y"; got != want {
		t.Errorf("Scan = %q, want %q", got, want)
	}
	attested := scope
	attested.SingleSubject, attested.PackageProcess = true, true
	if got, want := attested.Facts(), "facts@2|tc|bc|"+AnalyzingFrontend()+"|content|policy|single-subject-execution|package-process-execution"; got != want {
		t.Errorf("attested Facts = %q, want %q", got, want)
	}
	if attested.Proofs() != scope.Proofs() || attested.TestingScan() != scope.TestingScan() {
		t.Error("an attestation moved a scope that does not read it")
	}
	var zero AnalysisScope
	if zero.Proofs() != "" || zero.TestingScan() != "" || zero.Facts() != "" || zero.Scan() != "" {
		t.Errorf("the zero scope arms a memo: %q %q %q %q", zero.Proofs(), zero.TestingScan(), zero.Facts(), zero.Scan())
	}
	// A rendering is inert exactly when the axis that versions it is
	// absent, never armed under a partial identity.
	guardsOnly := AnalysisScope{Toolchain: "tc", BuildConfig: "bc", SingleSubject: true, Vouches: []string{"a:x"}, toolchainContent: "content", admissionPolicy: "policy"}
	if guardsOnly.Proofs() != "" || guardsOnly.Facts() != "" || guardsOnly.Scan() != "" {
		t.Errorf("guards without a strategy armed a memo: %q %q %q", guardsOnly.Proofs(), guardsOnly.Facts(), guardsOnly.Scan())
	}
	if guardsOnly.TestingScan() != testingScanStrategy+"|tc|bc|"+AnalyzingFrontend()+"|content|policy" {
		t.Errorf("the testing scan, which reads the guards alone, is inert under them: %q", guardsOnly.TestingScan())
	}
	strategiesOnly := AnalysisScope{ProofStrategy: "rta@1", FactStrategy: "facts@2"}
	if strategiesOnly.TestingScan() != "" {
		t.Errorf("the testing scan armed without guards: %q", strategiesOnly.TestingScan())
	}
}

func TestAnalysisScopeRendersRootedMemoAxes(t *testing.T) {
	scope := AnalysisScope{
		ProofStrategy:    "rta@1",
		FactStrategy:     "facts@2",
		Toolchain:        "tc",
		BuildConfig:      "bc",
		Vouches:          []string{"a:x"},
		toolchainContent: "content",
		admissionPolicy:  "policy",
	}
	want := rootedFunctionsStrategy + "|tc|bc|" + AnalyzingFrontend() + "|content|policy"
	if got := scope.Rooted(); got != want {
		t.Fatalf("Rooted() = %q, want %q", got, want)
	}
	var zero AnalysisScope
	if got := zero.Rooted(); got != "" {
		t.Fatalf("zero.Rooted() = %q, want empty", got)
	}
	attested := scope
	attested.SingleSubject = true
	attested.PackageProcess = true
	attested.Vouches = []string{"other:vouch"}
	if attested.Rooted() != scope.Rooted() {
		t.Fatalf("attestations/vouches changed Rooted(): %q vs %q", attested.Rooted(), scope.Rooted())
	}
}

// The partition inverse of
// TestComputeMaximalBatchSharesPackageClosureWithoutSharingIdentity: a sibling
// test added to the package moves only the test-variant compartment, never a
// subject's core maximal hash (REQ-closure-view-maximal,
// REQ-closure-test-variant-hash).
func TestSiblingTestAdditionMovesCompartmentNotCore(t *testing.T) {
	files := map[string]string{
		"go.mod":            "module example.com/partition\n\ngo 1.26\n",
		"partition.go":      "package partition\n\nfunc F() int { return 1 }\nfunc G() int { return 2 }\n",
		"partition_test.go": "package partition\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
	}
	dir := writeTestVariantModule(t, files)
	subjects := []Subject{
		{Package: "example.com/partition", Symbol: "F"},
		{Package: "example.com/partition", Symbol: "G"},
	}
	before := computeAt(t, dir, subjects...)
	if err := os.WriteFile(filepath.Join(dir, "partition_test.go"), []byte(files["partition_test.go"]+"\nfunc TestG(t *testing.T) {\n\tif G() != 2 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := computeAt(t, dir, subjects...)
	for _, subject := range subjects {
		if before[subject].Hash != after[subject].Hash {
			t.Fatalf("sibling test addition moved core maximal closure for %s", subject.Symbol)
		}
		if before[subject].TestVariants == after[subject].TestVariants {
			t.Fatalf("sibling test addition did not move the compartment for %s", subject.Symbol)
		}
	}
}

// A production edit keeps today's semantics: the core moves; the compartment,
// whose files are untouched, does not (REQ-closure-view-maximal).
func TestProductionEditMovesCoreNotCompartment(t *testing.T) {
	files := map[string]string{
		"go.mod":            "module example.com/partition\n\ngo 1.26\n",
		"partition.go":      "package partition\n\nfunc F() int { return 1 }\n",
		"partition_test.go": "package partition\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
	}
	dir := writeTestVariantModule(t, files)
	subject := Subject{Package: "example.com/partition", Symbol: "F"}
	before := computeAt(t, dir, subject)
	if err := os.WriteFile(filepath.Join(dir, "partition.go"), []byte("package partition\n\nfunc F() int { return 3 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := computeAt(t, dir, subject)
	if before[subject].Hash == after[subject].Hash {
		t.Fatal("production edit did not move the core maximal closure")
	}
	if before[subject].TestVariants != after[subject].TestVariants {
		t.Fatal("production edit moved the test-variant compartment")
	}
}

// A test file importing a NEW dependency package moves the core: the new
// package's init behavior enters the test binary, so its node is a core
// contribution even though only test files import it. Importing an
// already-present package moves only the compartment
// (REQ-closure-test-variant-hash).
func TestNewTestOnlyDependencyMovesCore(t *testing.T) {
	files := map[string]string{
		"go.mod":            "module example.com/partition\n\ngo 1.26\n",
		"partition.go":      "package partition\n\nfunc F() int { return 1 }\n",
		"partition_test.go": "package partition\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
		"dep/dep.go":        "package dep\n\nfunc Two() int { return 2 }\n",
	}
	dir := writeTestVariantModule(t, files)
	subject := Subject{Package: "example.com/partition", Symbol: "F"}
	before := computeAt(t, dir, subject)
	if err := os.WriteFile(filepath.Join(dir, "extra_test.go"), []byte("package partition\n\nimport (\n\t\"testing\"\n\n\t\"example.com/partition/dep\"\n)\n\nfunc TestDep(t *testing.T) {\n\tif dep.Two() != 2 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := computeAt(t, dir, subject)
	if before[subject].Hash == after[subject].Hash {
		t.Fatal("test-only import of a new package did not move the core")
	}
	if before[subject].TestVariants == after[subject].TestVariants {
		t.Fatal("new test file did not move the compartment")
	}

	// The dependency is now present: a further test-only use of it moves the
	// compartment alone — its node already contributes to the core.
	if err := os.WriteFile(filepath.Join(dir, "extra_test.go"), []byte("package partition\n\nimport (\n\t\"testing\"\n\n\t\"example.com/partition/dep\"\n)\n\nfunc TestDep(t *testing.T) {\n\tif dep.Two() != 2 {\n\t\tt.Fatal(\"still broken\")\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	final := computeAt(t, dir, subject)
	if after[subject].Hash != final[subject].Hash {
		t.Fatal("test edit importing an already-present package moved the core")
	}
	if after[subject].TestVariants == final[subject].TestVariants {
		t.Fatal("test edit did not move the compartment")
	}
}

// A package with no test files has the defined constant compartment identity,
// stable across recomputation (REQ-closure-test-variant-identity).
func TestNoTestPackageCompartmentIsStableEmptyIdentity(t *testing.T) {
	dir := writeTestVariantModule(t, map[string]string{
		"go.mod":  "module example.com/notest\n\ngo 1.26\n",
		"main.go": "package notest\n\nfunc F() int { return 1 }\n",
	})
	subject := Subject{Package: "example.com/notest", Symbol: "F"}
	first := computeAt(t, dir, subject)
	if first[subject].TestVariants != testvariant.EmptyTestVariantClosure {
		t.Fatalf("no-test compartment = %q, want the defined empty identity %q", first[subject].TestVariants, testvariant.EmptyTestVariantClosure)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package notest\n\nfunc F() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	second := computeAt(t, dir, subject)
	if second[subject].TestVariants != testvariant.EmptyTestVariantClosure {
		t.Fatalf("no-test compartment drifted to %q after a production edit", second[subject].TestVariants)
	}
	ledger := ledgerAt(t, dir, "example.com/notest")
	if len(ledger.Declarations) != 0 || len(ledger.FileHeaders) != 0 {
		t.Fatalf("no-test ledger = %+v, want empty", ledger)
	}
}

// An external test package's files are test-only whole: they enter the
// compartment and the ledger with their declarations and file header
// (REQ-closure-test-variant-hash).
func TestExternalTestPackageFilesEnterCompartmentAndLedger(t *testing.T) {
	files := map[string]string{
		"go.mod":      "module example.com/external\n\ngo 1.26\n",
		"external.go": "package external\n\nfunc F() int { return 1 }\n",
	}
	dir := writeTestVariantModule(t, files)
	subject := Subject{Package: "example.com/external", Symbol: "F"}
	before := computeAt(t, dir, subject)
	if err := os.WriteFile(filepath.Join(dir, "external_test.go"), []byte("package external_test\n\nimport (\n\t\"testing\"\n\n\t\"example.com/external\"\n)\n\nfunc TestF(t *testing.T) {\n\tif external.F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := computeAt(t, dir, subject)
	if before[subject].Hash != after[subject].Hash {
		t.Fatal("external test file moved the core")
	}
	if before[subject].TestVariants == after[subject].TestVariants {
		t.Fatal("external test file did not move the compartment")
	}
	ledger := ledgerAt(t, dir, "example.com/external")
	if len(ledger.Declarations) != 1 || ledger.Declarations[0].Name != "TestF" || ledger.Declarations[0].Kind != "func" || ledger.Declarations[0].File != "external_test.go" {
		t.Fatalf("external test ledger declarations = %+v, want TestF in external_test.go", ledger.Declarations)
	}
	if len(ledger.FileHeaders) != 1 || ledger.FileHeaders[0].File != "external_test.go" || ledger.FileHeaders[0].Hash == "" {
		t.Fatalf("external test ledger headers = %+v, want one external_test.go header", ledger.FileHeaders)
	}
}

// Editing an existing test function moves the compartment and exactly that
// declaration's ledger hash; appending a test to an existing file adds a
// ledger entry without moving the existing ones or the file header
// (REQ-closure-test-variant-ledger).
func TestLedgerNamesTheEditedAndAppendedDeclarations(t *testing.T) {
	const original = "package ledger\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n"
	dir := writeTestVariantModule(t, map[string]string{
		"go.mod":         "module example.com/ledger\n\ngo 1.26\n",
		"ledger.go":      "package ledger\n\nfunc F() int { return 1 }\n",
		"ledger_test.go": original,
	})
	const pkg = "example.com/ledger"
	subject := Subject{Package: pkg, Symbol: "F"}
	entry := func(ledger testvariant.TestVariantLedger, name string) (testvariant.TestVariantDeclaration, bool) {
		for _, declaration := range ledger.Declarations {
			if declaration.Name == name {
				return declaration, true
			}
		}
		return testvariant.TestVariantDeclaration{}, false
	}
	before := computeAt(t, dir, subject)
	beforeLedger := ledgerAt(t, dir, pkg)

	// Edit the existing test's body.
	if err := os.WriteFile(filepath.Join(dir, "ledger_test.go"), []byte("package ledger\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"edited\")\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	edited := computeAt(t, dir, subject)
	editedLedger := ledgerAt(t, dir, pkg)
	if before[subject].TestVariants == edited[subject].TestVariants {
		t.Fatal("edited test did not move the compartment")
	}
	was, _ := entry(beforeLedger, "TestF")
	now, ok := entry(editedLedger, "TestF")
	if !ok || was.Hash == now.Hash {
		t.Fatalf("edited test declaration hash unmoved: %+v -> %+v", was, now)
	}
	if beforeLedger.FileHeaders[0].Hash != editedLedger.FileHeaders[0].Hash {
		t.Fatal("body edit moved the file header identity")
	}

	// Append a new test to the same file: added-only.
	if err := os.WriteFile(filepath.Join(dir, "ledger_test.go"), []byte("package ledger\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"edited\")\n\t}\n}\n\nfunc TestAgain(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"again\")\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	appendedLedger := ledgerAt(t, dir, pkg)
	if len(appendedLedger.Declarations) != len(editedLedger.Declarations)+1 {
		t.Fatalf("appended ledger = %+v, want one added declaration", appendedLedger.Declarations)
	}
	kept, ok := entry(appendedLedger, "TestF")
	if !ok || kept.Hash != now.Hash {
		t.Fatalf("append moved the existing declaration: %+v -> %+v", now, kept)
	}
	if _, ok := entry(appendedLedger, "TestAgain"); !ok {
		t.Fatalf("appended declaration missing from ledger: %+v", appendedLedger.Declarations)
	}
}

// The ledger is deterministic data: recomputation yields byte-identical
// entries, sorted by (File, Kind, Receiver, Name, Hash) with headers sorted by
// file, whatever order declarations appear in source
// (REQ-closure-test-variant-ledger).
func TestTestVariantLedgerIsDeterministicallySorted(t *testing.T) {
	dir := writeTestVariantModule(t, map[string]string{
		"go.mod":    "module example.com/sorted\n\ngo 1.26\n",
		"sorted.go": "package sorted\n\nfunc F() int { return 1 }\n",
		"z_test.go": "package sorted\n\nimport \"testing\"\n\ntype harness struct{ n int }\n\nfunc (h harness) run() int { return h.n }\n\nvar fixtures = []int{1}\n\nconst limit = 3\n\nfunc init() { fixtures = append(fixtures, 2) }\n\nfunc TestZ(t *testing.T) { _ = harness{1}.run() }\n\nfunc TestA(t *testing.T) { _ = fixtures[0] }\n",
		"a_test.go": "package sorted\n\nimport \"testing\"\n\nfunc TestMain(m *testing.M) { m.Run() }\n",
	})
	const pkg = "example.com/sorted"
	first := ledgerAt(t, dir, pkg)
	second := ledgerAt(t, dir, pkg)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("ledger not deterministic:\n%+v\n%+v", first, second)
	}
	for i := 1; i < len(first.Declarations); i++ {
		a, b := first.Declarations[i-1], first.Declarations[i]
		if a.File > b.File || (a.File == b.File && a.Kind > b.Kind) ||
			(a.File == b.File && a.Kind == b.Kind && a.Receiver > b.Receiver) ||
			(a.File == b.File && a.Kind == b.Kind && a.Receiver == b.Receiver && a.Name > b.Name) {
			t.Fatalf("ledger unsorted at %d: %+v then %+v", i, a, b)
		}
	}
	want := map[string]string{
		"TestMain": "func", "TestZ": "func", "TestA": "func",
		"harness": "type", "run": "method", "fixtures": "var", "limit": "const", "init": "init",
	}
	got := map[string]string{}
	for _, declaration := range first.Declarations {
		got[declaration.Name] = declaration.Kind
		if declaration.Name == "run" && declaration.Receiver != "harness" {
			t.Fatalf("method receiver = %q, want harness", declaration.Receiver)
		}
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("ledger kinds = %+v, want %+v", got, want)
	}
	if len(first.FileHeaders) != 2 || first.FileHeaders[0].File != "a_test.go" || first.FileHeaders[1].File != "z_test.go" {
		t.Fatalf("headers = %+v, want per-file entries sorted by file", first.FileHeaders)
	}
}

// Batching subjects shares each package's compartment exactly as it shares the
// core: batch results equal independent per-subject computation for both
// hashes (REQ-closure-batch-equivalence).
func TestComputeMaximalBatchMatchesIndependentComputeForBothHashes(t *testing.T) {
	// a and b share the dependency node: the batch derives its
	// contribution once and both packages' closures consume it — the
	// equivalence against independent computation pins that sharing
	// changes cost, never evidence (REQ-closure-batch-equivalence).
	dir := writeTestVariantModule(t, map[string]string{
		"go.mod":      "module example.com/batch\n\ngo 1.26\n",
		"shared/s.go": "package shared\n\nfunc S() int { return 3 }\n",
		"a/a.go":      "package a\n\nimport \"example.com/batch/shared\"\n\nfunc A() int { return shared.S() - 2 }\n",
		"a/a_test.go": "package a\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) {\n\tif A() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
		"b/b.go":      "package b\n\nimport \"example.com/batch/shared\"\n\nfunc B() int { return shared.S() - 1 }\n",
	})
	subjects := []Subject{
		{Package: "example.com/batch/a", Symbol: "A"},
		{Package: "example.com/batch/a", Symbol: "TestA"},
		{Package: "example.com/batch/b", Symbol: "B"},
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	batched, batchedSources, err := h.ComputeMaximalBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range subjects {
		independent := computeAt(t, dir, subject)
		if batched[subject] != independent[subject] {
			t.Fatalf("batched %v = %+v, independent = %+v", subject, batched[subject], independent[subject])
		}
		hIndependent, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		_, independentSources, err := hIndependent.ComputeMaximalBatch([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(batchedSources[subject], independentSources[subject]) {
			t.Fatalf("batched sources for %v = %v, independent = %v", subject, batchedSources[subject], independentSources[subject])
		}
	}
	if batched[subjects[2]].TestVariants != testvariant.EmptyTestVariantClosure {
		t.Fatalf("no-test package in batch = %q, want empty identity", batched[subjects[2]].TestVariants)
	}
	if batched[subjects[0]].TestVariants != batched[subjects[1]].TestVariants {
		t.Fatal("subjects of one package did not share the compartment")
	}
}

// A real dependency package whose import path ends in "_test" is not the
// subject's external test package: recompiled against the test binary it
// shares the suffixed import path shape but compiles from its own directory,
// so it keeps its core contribution and never enters the compartment. Go
// refuses to build this layout (the test import is a cycle), but go list
// still describes it, and hashing must stay fail-safe over it
// (REQ-closure-view-maximal).
func TestDependencyPackageNamedLikeExternalTestKeepsItsCoreContribution(t *testing.T) {
	files := map[string]string{
		"go.mod":           "module example.com/m\n\ngo 1.26\n",
		"foo/foo.go":       "package foo\n\nfunc F() int { return 1 }\n",
		"foo/in_test.go":   "package foo\n\nimport \"testing\"\n\nfunc TestInPackage(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
		"foo/ext_test.go":  "package foo_test\n\nimport (\n\t\"testing\"\n\n\ttrap \"example.com/m/foo_test\"\n)\n\nfunc TestTrap(t *testing.T) {\n\tif trap.Two() != 2 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
		"foo_test/trap.go": "package trap\n\nimport \"example.com/m/foo\"\n\nfunc Two() int { return foo.F() + 1 }\n",
	}
	dir := writeTestVariantModule(t, files)
	subject := Subject{Package: "example.com/m/foo", Symbol: "F"}
	before := computeAt(t, dir, subject)
	ledger := ledgerAt(t, dir, "example.com/m/foo")
	for _, declaration := range ledger.Declarations {
		if declaration.File == "trap.go" {
			t.Fatalf("dependency package file entered the compartment ledger: %+v", ledger.Declarations)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "foo_test/trap.go"), []byte("package trap\n\nimport \"example.com/m/foo\"\n\nfunc Two() int { return foo.F() * 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := computeAt(t, dir, subject)
	if before[subject].Hash == after[subject].Hash {
		t.Fatal("dependency edit did not move the core maximal closure")
	}
	if before[subject].TestVariants != after[subject].TestVariants {
		t.Fatal("dependency edit moved the test-variant compartment")
	}
}

// A package whose core contribution widens to its whole directory (opaque
// assembly) keeps test files in the core as well — sound, merely
// undiscriminated — while the same files also sit in the compartment
// (REQ-closure-test-variant-identity whole-dir-widening exception).
func TestWidenedCoreKeepsTestFilesUndiscriminated(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("opaque-asm fixture is amd64-only")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/opq\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"asm_amd64.s", "defs.inc", "opaqueasm.go", "opaqueasm_test.go"} {
		content, err := os.ReadFile(filepath.Join("testdata", "opaqueasm", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	subject := Subject{Package: "example.com/opq", Symbol: "BenchmarkOpaqueASM"}
	before := computeAt(t, dir, subject)
	testPath := filepath.Join(dir, "opaqueasm_test.go")
	source, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(testPath, append(source, []byte("\nfunc sibling() {}\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	after := computeAt(t, dir, subject)
	if before[subject].Hash == after[subject].Hash {
		t.Fatal("widened core did not keep the test file: sibling test edit left the core unmoved")
	}
	if before[subject].TestVariants == after[subject].TestVariants {
		t.Fatal("test file left the compartment under a widened core")
	}
}

// A test-only embedded fixture whose name ends in .go is data, not source:
// it is never parsed (even unparseable bytes analyze fine), contributes no
// declarations, carries an Embedded whole-content header, and its movement
// defeats inertness like any embedded member's
// (REQ-closure-test-variant-ledger compiled-vs-embedded split).
func TestEmbeddedGoFixtureIsDataNotSource(t *testing.T) {
	files := map[string]string{
		"go.mod":              "module example.com/embedded\n\ngo 1.26\n",
		"embedded.go":         "package embedded\n\nfunc F() int { return 1 }\n",
		"embedded_test.go":    "package embedded\n\nimport (\n\t_ \"embed\"\n\t\"testing\"\n)\n\n//go:embed testdata/fixture.go\nvar fixture string\n\n//go:embed testdata/broken.go\nvar broken string\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 || fixture == \"\" || broken == \"\" {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
		"testdata/fixture.go": "package fixture\n\nfunc Fixture() int { return 1 }\n",
		"testdata/broken.go":  "this is not go source at all {{{\n",
	}
	dir := writeTestVariantModule(t, files)
	const pkg = "example.com/embedded"
	before := ledgerAt(t, dir, pkg)
	for _, declaration := range before.Declarations {
		if declaration.File != "embedded_test.go" {
			t.Fatalf("embedded fixture contributed declarations: %+v", before.Declarations)
		}
	}
	embedded := 0
	for _, header := range before.FileHeaders {
		switch header.File {
		case "testdata/fixture.go", "testdata/broken.go":
			if !header.Embedded {
				t.Fatalf("embedded member not marked: %+v", header)
			}
			embedded++
		case "embedded_test.go":
			if header.Embedded {
				t.Fatalf("compiled test file marked embedded: %+v", header)
			}
		}
	}
	if embedded != 2 {
		t.Fatalf("embedded members missing from ledger headers: %+v", before.FileHeaders)
	}
	if err := os.WriteFile(filepath.Join(dir, "testdata/fixture.go"), []byte(files["testdata/fixture.go"]+"\nfunc Extra() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	delta := testvariant.DiffTestVariantLedgers(before, ledgerAt(t, dir, pkg))
	if delta.Inert() || len(delta.Added) != 0 {
		t.Fatalf("embedded .go fixture edit = %+v (inert=%v), want a non-inert header-only movement", delta, delta.Inert())
	}
}

// A member both compiled and embedded — a sibling test file that an embed
// directive names — keeps its parsed declarations but carries the
// embedded whole-content header: appending an otherwise-inert declaration
// moves bytes an unchanged test reads as data, so the delta is never inert
// (REQ-closure-test-variant-inertness dual membership).
func TestCompiledAndEmbeddedTestFileFailsClosed(t *testing.T) {
	files := map[string]string{
		"go.mod":         "module example.com/dual\n\ngo 1.26\n",
		"dual.go":        "package dual\n\nfunc F() int { return 1 }\n",
		"helper_test.go": "package dual\n\nfunc helperValue() int { return 1 }\n",
		"embed_test.go":  "package dual\n\nimport (\n\t_ \"embed\"\n\t\"testing\"\n)\n\n//go:embed helper_test.go\nvar helperSource string\n\nfunc TestF(t *testing.T) {\n\tif F() != helperValue() || helperSource == \"\" {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
	}
	dir := writeTestVariantModule(t, files)
	const pkg = "example.com/dual"
	before := ledgerAt(t, dir, pkg)
	declared := false
	for _, declaration := range before.Declarations {
		declared = declared || (declaration.File == "helper_test.go" && declaration.Name == "helperValue")
	}
	if !declared {
		t.Fatalf("dual member lost its declarations: %+v", before.Declarations)
	}
	for _, header := range before.FileHeaders {
		if header.File == "helper_test.go" && !header.Embedded {
			t.Fatalf("dual member header not marked embedded: %+v", header)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "helper_test.go"), []byte(files["helper_test.go"]+"\nfunc extraHelper() int { return 3 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	delta := testvariant.DiffTestVariantLedgers(before, ledgerAt(t, dir, pkg))
	if delta.Inert() {
		t.Fatalf("dual-member edit classified inert: %+v", delta)
	}
}

// End to end over real ledgers: a sibling test appended to an existing file
// diffs to an inert added-only delta, and editing that test's body flips the
// judgment (REQ-closure-test-variant-inertness).
func TestLedgerDeltaOverRealLedgers(t *testing.T) {
	const original = "package delta\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n"
	dir := writeTestVariantModule(t, map[string]string{
		"go.mod":        "module example.com/delta\n\ngo 1.26\n",
		"delta.go":      "package delta\n\nfunc F() int { return 1 }\n",
		"delta_test.go": original,
	})
	const pkg = "example.com/delta"
	recorded := ledgerAt(t, dir, pkg)
	if err := os.WriteFile(filepath.Join(dir, "delta_test.go"), []byte(original+"\nfunc TestSibling(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	appended := testvariant.DiffTestVariantLedgers(recorded, ledgerAt(t, dir, pkg))
	if !appended.Inert() || len(appended.Added) != 1 || appended.Added[0].Name != "TestSibling" {
		t.Fatalf("appended sibling delta = %+v (inert=%v), want inert added-only TestSibling", appended, appended.Inert())
	}
	if err := os.WriteFile(filepath.Join(dir, "delta_test.go"), []byte("package delta\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"edited\")\n\t}\n}\n\nfunc TestSibling(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	edited := testvariant.DiffTestVariantLedgers(recorded, ledgerAt(t, dir, pkg))
	if edited.Inert() || len(edited.Changed) != 1 || edited.Changed[0].After.Name != "TestF" {
		t.Fatalf("edited body delta = %+v (inert=%v), want non-inert with TestF changed", edited, edited.Inert())
	}
}

func TestPropHashFilesSensitive(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.go", "package p\n")
	write("b.go", "package p\nvar X = 1\n")

	h1, err := hashFilesWith(dir, []string{"a.go", "b.go"}, nil, nil, readBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(h1) != 32 {
		t.Errorf("hash len: got %d", len(h1))
	}

	// Order-insensitive (files sorted internally).
	if h2, _ := hashFilesWith(dir, []string{"b.go", "a.go"}, nil, nil, readBytes, nil); h2 != h1 {
		t.Errorf("hash not order-insensitive: %q vs %q", h1, h2)
	}

	// Content change ⇒ different hash (REQ-closure-mutable-local / REQ-closure-coverage at the file level).
	write("b.go", "package p\nvar X = 2\n")
	if h3, _ := hashFilesWith(dir, []string{"a.go", "b.go"}, nil, nil, readBytes, nil); h3 == h1 {
		t.Error("hash insensitive to content change")
	}

	// Missing file ⇒ error, never silently skipped.
	if _, err := hashFilesWith(dir, []string{"missing.go"}, nil, nil, readBytes, nil); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestContribution(t *testing.T) {
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}

	// Excluded: stdlib, pseudo-package, synthesized test main.
	for _, p := range []listPkg{
		{ImportPath: "fmt", Standard: true},
		{ImportPath: "C"},
		{ImportPath: "example/x.test", Name: "main", Module: &listMod{Main: true}},
	} {
		if c, err := h.contributionFor("example/x", p); err != nil || c != "" {
			t.Errorf("contribution(%s): got %q, %v; want \"\"", p.ImportPath, c, err)
		}
	}

	// An ordinary importable package may legitimately end in .test.
	dotTestDir := t.TempDir()
	writeFile(t, dotTestDir, "dep.go", "package dep\nconst Value = 1\n")
	dotTest, err := h.contribution(listPkg{
		ImportPath: "example/dep.test", Name: "dep", Dir: dotTestDir,
		GoFiles: []string{"dep.go"}, Module: &listMod{Main: true, Dir: dotTestDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(dotTest, "src:example/dep.test=") {
		t.Fatalf("ordinary .test package contribution = %q", dotTest)
	}
	commandDotTestDir := t.TempDir()
	writeFile(t, commandDotTestDir, "main.go", "package main\nfunc F() int { return 1 }\n")
	commandDotTest, err := h.contributionFor("example/root", listPkg{
		ImportPath: "example/tool.test", Name: "main", Dir: commandDotTestDir,
		GoFiles: []string{"main.go"}, Module: &listMod{Main: true, Dir: commandDotTestDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(commandDotTest, "src:example/tool.test=") {
		t.Fatalf("ordinary command .test package contribution = %q", commandDotTest)
	}

	// Cache dep (classified on the package Dir under GOMODCACHE): pinned by
	// modpath@version, no file read.
	modDir := filepath.FromSlash("/gomodcache/golang.org/x/tools@v0.46.0")
	c, err := h.contribution(listPkg{
		ImportPath: "golang.org/x/tools/go/ssa",
		Dir:        filepath.Join(modDir, "go", "ssa"),
		Module:     &listMod{Path: "golang.org/x/tools", Version: "v0.46.0", Dir: modDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c, "cache:") || !strings.Contains(c, "golang.org/x/tools@v0.46.0") {
		t.Errorf("cache contribution: %q", c)
	}

	// Vendored dep (Dir outside the cache, Module.Dir empty, not Main) is
	// mutable-local → hashed by content (REQ-closure-mutable-local), not pinned.
	vdir := t.TempDir()
	if err := os.WriteFile(filepath.Join(vdir, "v.go"), []byte("package v\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err = h.contribution(listPkg{
		ImportPath: "vendored/dep", Dir: vdir, GoFiles: []string{"v.go"},
		Module: &listMod{Path: "vendored/dep", Version: "v1.0.0"}, // Dir empty (vendored)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c, "src:vendored/dep=") {
		t.Errorf("vendored dep should hash by content, got %q", c)
	}

	// Main module: hashed by content.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte("package p\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err = h.contribution(listPkg{
		ImportPath: "example/p", Dir: dir, GoFiles: []string{"x.go"},
		Module: &listMod{Main: true, Dir: dir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c, "src:example/p=") {
		t.Errorf("src contribution: %q", c)
	}
}

// TestAssemblyPackageHashesWholeDirectory pins the conservative contract for
// assembly-bearing mutable-local packages (REQ-closure-blindspot): the package
// contributes its whole directory, so an edit to ANY file in the directory —
// a header an .s file includes, or a file no build list names — moves the
// contribution, and so the maximal hash the subject widens to.
func TestAssemblyPackageHashesWholeDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "defs.inc", "#define RETVAL $1\n")
	writeFile(t, dir, "asm.s", "#include \"defs.inc\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tMOVQ RETVAL, AX\n\tRET\n")
	writeFile(t, dir, "unlisted.txt", "v1\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{ImportPath: "example/p", Dir: dir, SFiles: []string{"asm.s"}, Module: &listMod{Main: true, Dir: dir}}
	base, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution: %v", err)
	}
	writeFile(t, dir, "defs.inc", "#define RETVAL $2\n")
	afterInclude, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution after include edit: %v", err)
	}
	if afterInclude == base {
		t.Fatalf("asm include edit did not change contribution: %q", base)
	}
	writeFile(t, dir, "unlisted.txt", "v2\n")
	afterUnlisted, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution after unlisted-file edit: %v", err)
	}
	if afterUnlisted == afterInclude {
		t.Fatalf("edit to a file no build list names did not change contribution: %q", afterInclude)
	}
	writeFile(t, dir, "extra.h", "#define EXTRA 1\n")
	afterNew, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution after new file: %v", err)
	}
	if afterNew == afterUnlisted {
		t.Fatalf("new file in the package directory did not change contribution: %q", afterUnlisted)
	}
}

// TestAssemblyUnresolvedIncludeHashesWholeDirectory: includes in non-toolchain
// assembly are no longer resolved — an include naming a missing file or an
// absolute path outside the package directory is not an error and is not
// separately tracked. The package hashes its whole directory and every subject
// reaching it is unverifiable via the non-standard-assembly effect
// (REQ-closure-blindspot downgrade arm), so outside-directory content can
// never silently narrow a verdict.
func TestAssemblyUnresolvedIncludeHashesWholeDirectory(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	writeFile(t, outside, "defs.inc", "#define RETVAL $1\n")
	writeFile(t, dir, "asm.s", "#include \"missing.inc\"\n#include \""+filepath.ToSlash(filepath.Join(outside, "defs.inc"))+"\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tRET\n")
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{ImportPath: "example/p", Dir: dir, SFiles: []string{"asm.s"}, Module: &listMod{Main: true, Dir: dir}}
	base, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution with unresolved includes: %v", err)
	}
	if !strings.HasPrefix(base, "src:example/p=") {
		t.Fatalf("contribution = %q, want src:example/p=", base)
	}
	writeFile(t, dir, "asm.s", "#include \"missing.inc\"\nTEXT ·asmEntry(SB), NOSPLIT, $0-0\n\tRET\n")
	edited, err := h.contribution(pkg)
	if err != nil {
		t.Fatalf("contribution after in-dir edit: %v", err)
	}
	if edited == base {
		t.Fatalf("in-dir asm edit did not change contribution: %q", base)
	}
}

func TestUnderCache(t *testing.T) {
	h := &Hasher{modCache: filepath.FromSlash("/home/u/go/pkg/mod")}
	yes := filepath.FromSlash("/home/u/go/pkg/mod/golang.org/x/tools@v0.46.0")
	if !h.underCache(yes) {
		t.Errorf("underCache(%q) = false", yes)
	}
	no := filepath.FromSlash("/home/u/repo/internal/foo")
	if h.underCache(no) {
		t.Errorf("underCache(%q) = true", no)
	}
	// Prefix-but-not-a-path-segment must not match.
	sib := filepath.FromSlash("/home/u/go/pkg/modificator")
	if h.underCache(sib) {
		t.Errorf("underCache(%q) = true (segment-boundary bug)", sib)
	}
}

// TestPropSourceFilesComplete pins the compiled-file-kind set: dropping a kind (a
// silent under-coverage / false-valid hole) changes the count.
func TestPropSourceFilesComplete(t *testing.T) {
	p := listPkg{
		GoFiles: []string{"g.go"}, CgoFiles: []string{"cg.go"}, CFiles: []string{"c.c"},
		CXXFiles: []string{"cc.cc"}, MFiles: []string{"m.m"}, HFiles: []string{"h.h"},
		FFiles: []string{"f.f"}, SFiles: []string{"s.s"}, SwigFiles: []string{"w.swig"},
		SwigCXXFiles: []string{"wc.swigcxx"}, SysoFiles: []string{"o.syso"}, EmbedFiles: []string{"e.txt"},
	}
	if got := len(p.SourceFiles()); got != 12 {
		t.Errorf("sourceFiles count: got %d, want 12 — a compiled file kind is missing", got)
	}
}

func TestPropMutableLocalContentSensitivity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.go")
	if err := os.WriteFile(path, []byte("package p\nconst Value = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := listPkg{
		ImportPath: "example.com/p",
		Dir:        dir,
		GoFiles:    []string{"p.go"},
		Module:     &listMod{Main: true, Dir: dir},
	}
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	before, err := h.contribution(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("package p\nconst Value = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := h.contribution(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("mutable-local source edit did not move its contribution")
	}
}

// TestParseListError: a package reporting a load Error must fail the parse, never
// be silently dropped from the closure (REQ-fresh-sound).
func TestParseListError(t *testing.T) {
	const stream = `{"ImportPath":"ok/pkg","Dir":"/x","Module":{"Main":true}}
{"ImportPath":"bad/pkg","Error":{"Err":"cannot find package"}}`
	if _, err := listing.Parse(strings.NewReader(stream)); err == nil {
		t.Error("expected error when a package reports a load Error")
	}
}

//gofresh:pure
func BenchmarkHashFiles(b *testing.B) {
	dir := b.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte("package p\nvar X = 1\n"), 0o644); err != nil {
		b.Fatal(err)
	}
	files := []string{"x.go"}
	for b.Loop() {
		if _, err := hashFilesWith(dir, files, nil, nil, readBytes, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzToolchainFloorLattice(f *testing.F) {
	f.Add("fmt", "Sprint", "//go:linkname a runtime.getAuxv\n", true)
	f.Add("os", "Getenv", "//go:linkname a runtime.unapproved\n", false)
	f.Add("reflect", "DeepEqual", "// normal comment\n", true)
	f.Add("testing", "Fatal", "//go:noescape\n", true)

	f.Fuzz(func(t *testing.T, pkg, sym, commentLine string, audited bool) {
		if classBPureStandard(false, pkg, sym) {
			t.Fatalf("classBPureStandard admitted (%q, %q) when audited=false", pkg, sym)
		}
		if isSourceOnlyStandardPackage(false, pkg) {
			t.Fatalf("isSourceOnlyStandardPackage admitted %q when audited=false", pkg)
		}
		if auditedStandardSymbol(false, pkg, sym) {
			t.Fatalf("auditedStandardSymbol admitted (%q, %q) when audited=false", pkg, sym)
		}
		if auditedHarnessLogging(false, pkg, sym) {
			t.Fatalf("auditedHarnessLogging admitted (%q, %q) when audited=false", pkg, sym)
		}
		if auditedHarnessPacing(false, pkg, sym) {
			t.Fatalf("auditedHarnessPacing admitted (%q, %q) when audited=false", pkg, sym)
		}
		if fmtFprintFamily(false, pkg, sym) {
			t.Fatalf("fmtFprintFamily admitted (%q, %q) when audited=false", pkg, sym)
		}
		if auditedLinknamesOnly(false, commentLine) && strings.Contains(commentLine, "//go:linkname") {
			t.Fatalf("auditedLinknamesOnly admitted %q when audited=false", commentLine)
		}
		gorootEff := symbolExternalEffect(externalEffectUnauditedStandard, "runtime", "GOROOT", "reaches unaudited standard operation runtime.GOROOT")
		gomaxEff := symbolExternalEffect(externalEffectUnauditedStandard, "runtime", "GOMAXPROCS", "reaches unaudited standard operation runtime.GOMAXPROCS")
		if maximalObservabilityBlocker(audited, gorootEff) || !maximalObservabilityBlocker(audited, gomaxEff) {
			t.Fatal("maximalObservabilityBlocker misclassified runtime.GOROOT vs runtime.GOMAXPROCS")
		}
	})
}

func FuzzAuditedStdlibClosure(f *testing.F) {
	f.Add("fmt", "Sprint", true, uint8(0))
	f.Add("os", "Getenv", false, uint8(1))
	f.Add("reflect", "DeepEqual", true, uint8(2))
	f.Add("testing", "Fatal", true, uint8(3))
	f.Add("crypto/rand", "Read", true, uint8(4))

	driver := harnessSubtestDriverForTest(f)
	atomicPkg := types.NewPackage("sync/atomic", "atomic")
	tparam := types.NewTypeParam(types.NewTypeName(token.NoPos, atomicPkg, "T", nil), types.NewInterfaceType(nil, nil))
	atomicGeneric := types.NewNamed(types.NewTypeName(token.NoPos, atomicPkg, "Pointer", nil), types.NewStruct(nil, nil), nil)
	atomicGeneric.SetTypeParams([]*types.TypeParam{tparam})

	f.Fuzz(func(t *testing.T, pkg, sym string, audited bool, choice uint8) {
		if isSourceOnlyStandardPackage(true, pkg) {
			if isAlwaysExternalPackage(pkg) {
				t.Fatalf("package %q is both source-only audited-pure and always-external", pkg)
			}
			if _, ok := classBEffect(pkg, sym); ok {
				t.Fatalf("package %q is source-only audited-pure but has classBEffect for %q", pkg, sym)
			}
		}

		for _, forbiddenReflect := range []string{"ValueOf", "Value", "MakeFunc", "Call", "Method", "MethodByName", "Set", "Pointer", "UnsafePointer"} {
			if classBPureStandard(audited, "reflect", forbiddenReflect) || auditedStandardSymbol(audited, "reflect", forbiddenReflect) {
				t.Fatalf("reflect dispatch/value surface %q was admitted", forbiddenReflect)
			}
		}
		if classBPureStandard(audited, "reflect", "DeepEqual") != audited || classBPureStandard(audited, "reflect", "TypeOf") != audited {
			t.Fatalf("reflect DeepEqual/TypeOf admission did not track audited=%v", audited)
		}
		for _, entropyOp := range []string{"Read", "Text", "Int", "Prime"} {
			eff, ok := classBEffect("crypto/rand", entropyOp)
			if !ok || eff.kind != externalEffectNative || !strings.Contains(eff.reason, "(entropy)") || !maximalObservabilityBlocker(audited, eff) {
				t.Fatalf("crypto/rand.%s classification = (%+v, %v), want blocking native entropy effect", entropyOp, eff, ok)
			}
		}
		if isSourceOnlyStandardPackage(audited, "math/rand") || isSourceOnlyStandardPackage(audited, "math/rand/v2") {
			t.Fatal("math/rand or math/rand/v2 admitted as source-only pure standard package")
		}
		fprintEff := symbolExternalEffect(externalEffectFormattedOutput, "fmt", "Fprintf", "reaches fmt.Fprintf")
		if fmtFprintFamily(audited, "fmt", "Println") || fmtFprintFamily(audited, "fmt", "Fprintf") != audited || maximalObservabilityBlocker(audited, fprintEff) != !audited {
			t.Fatalf("fmtFprintFamily / maximalObservabilityBlocker misclassified Println vs Fprintf under audited=%v", audited)
		}
		logOps := []string{"Fatal", "Fatalf", "Error", "Errorf", "Log", "Logf", "Skip", "Skipf", "SkipNow", "Fail", "FailNow"}
		if auditedHarnessLogging(audited, "testing", logOps[int(choice)%len(logOps)]) != audited || auditedHarnessLogging(audited, "testing", "Verbose") {
			t.Fatal("auditedHarnessLogging misclassified logging method vs Verbose")
		}
		paceOps := []string{"N", "Loop", "ResetTimer", "StartTimer", "StopTimer"}
		if auditedHarnessPacing(audited, "testing", paceOps[int(choice)%len(paceOps)]) != audited || auditedHarnessPacing(audited, "testing", "Elapsed") {
			t.Fatal("auditedHarnessPacing misclassified pacing vs Elapsed")
		}
		if auditedHarnessSubtestDriver(audited, driver) != audited {
			t.Fatalf("auditedHarnessSubtestDriver(audited=%v) != %v", audited, audited)
		}
		runEff := symbolExternalEffect(externalEffectTestRuntime, "testing", "Run", "reaches testing.Run")
		fuzzEff := symbolExternalEffect(externalEffectTestRuntime, "testing", "Fuzz", "reaches testing.Fuzz")
		if maximalObservabilityBlocker(audited, runEff) || maximalObservabilityBlocker(audited, fuzzEff) {
			t.Fatal("testing.Run or testing.Fuzz blocked at maximal package-scan floor")
		}

		elemType := types.Type(types.Typ[types.Int])
		if choice%2 == 1 {
			elemType = types.Typ[types.String]
		}
		inst, err := types.Instantiate(nil, atomicGeneric, []types.Type{elemType}, false)
		if err != nil {
			t.Fatal(err)
		}
		if elem, ok := auditedAtomicPointerElem(audited, inst.(*types.Named)); ok != audited || (ok && elem != elemType) {
			t.Fatalf("auditedAtomicPointerElem(%v) = (%v, %v)", audited, elem, ok)
		}
	})
}

func FuzzMaximalEffectsMonotonicity(f *testing.F) {
	f.Add("Sprint", true)
	f.Add("Getenv", false)
	f.Add("DeepEqual", true)

	f.Fuzz(func(t *testing.T, sym string, audited bool) {
		cleanSym := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				return r
			}
			return 'X'
		}, sym)
		if cleanSym == "" {
			cleanSym = "Sym"
		}

		if !flagRegistrationSymbol("flag", "String") || !flagRegistrationSymbol("flag", "BoolVar") || flagRegistrationSymbol("flag", "Parse") {
			t.Fatal("flagRegistrationSymbol misclassified registration vs Parse")
		}
		flagRegScan, err := maximalFileEffectsContent(audited, "flag_test.go", []byte("package p\nimport \"flag\"\nvar f = flag.String(\"name\", \"v\", \"u\")\n"))
		if err != nil || len(flagRegScan.effects) != 0 {
			t.Fatalf("flag registration recorded file-scan effect: %+v, err=%v", flagRegScan.effects, err)
		}
		testMainExitSrc := "package p\nimport (\n\t\"os\"\n\t\"testing\"\n)\nfunc TestMain(m *testing.M) {\n\tos.Exit(m.Run())\n}\n"
		tmScan, err := maximalFileEffectsContent(audited, "main_test.go", []byte(testMainExitSrc))
		if err != nil {
			t.Fatalf("maximalFileEffectsContent(TestMain): %v", err)
		}
		for _, eff := range tmScan.effects {
			if eff.symbol == "Exit" || maximalObservabilityBlocker(audited, eff) {
				t.Fatalf("os.Exit in TestMain(*testing.M) recorded blocking or Exit file-scan effect: %+v", tmScan.effects)
			}
		}
		nonTestMainExitSrc := "package p\nimport \"os\"\nfunc Helper() {\n\tos.Exit(1)\n}\n"
		nonTMScan, err := maximalFileEffectsContent(audited, "helper_test.go", []byte(nonTestMainExitSrc))
		if err != nil || len(nonTMScan.effects) == 0 {
			t.Fatalf("os.Exit outside TestMain was not flagged by file scan: %+v, err=%v", nonTMScan.effects, err)
		}
		unsafePtrEff := symbolExternalEffect(externalEffectUnauditedStandard, "unsafe", "Pointer", "reaches unsafe.Pointer")
		unsafeSliceEff := symbolExternalEffect(externalEffectUnauditedStandard, "unsafe", "Slice", "reaches unsafe.Slice")
		unsafeStringEff := symbolExternalEffect(externalEffectUnauditedStandard, "unsafe", "String", "reaches unsafe.String")
		if maximalObservabilityBlocker(audited, unsafePtrEff) || !maximalObservabilityBlocker(audited, unsafeSliceEff) || !maximalObservabilityBlocker(audited, unsafeStringEff) {
			t.Fatal("maximalObservabilityBlocker misclassified unsafe.Pointer narrowing vs unsafe.Slice/String")
		}

		declBindSrc := "package p\nimport \"example.com/custom/v2\"\nfunc Call() { realpkg." + cleanSym + "() }\n"
		if _, err := maximalFileEffectsContentWithNames(audited, "decl.go", []byte(declBindSrc), map[string]string{"example.com/custom/v2": "realpkg"}); err != nil {
			t.Fatalf("maximalFileEffectsContentWithNames: %v", err)
		}
		collideSrc := "package p\nimport (\n\ta \"fmt\"\n\ta \"os\"\n)\n"
		collideScan, err := maximalFileEffectsContentWithNames(audited, "collide.go", []byte(collideSrc), nil)
		if err != nil || !strings.Contains(collideScan.preferred, "import name collision") {
			t.Fatalf("colliding explicit import aliases did not fail closed: %+v, err=%v", collideScan, err)
		}

		if !propharness.IsHarnessPath("pgregory.net/rapid") || propharness.IsHarnessPath("testing") {
			t.Fatal("IsHarnessPath misclassified pgregory.net/rapid vs testing")
		}
		if propharness.VerifyPackage(false, nil) || propharness.VerifyPackage(true, nil) {
			t.Fatal("VerifyPackage accepted nil package")
		}
		rapidPkg := types.NewPackage("pgregory.net/rapid", "rapid")
		closedT := types.NewNamed(
			types.NewTypeName(token.NoPos, rapidPkg, "T", nil),
			types.NewStruct([]*types.Var{types.NewField(token.NoPos, rapidPkg, "seed", types.Typ[types.Uint64], false)}, nil),
			nil,
		)
		openT := types.NewNamed(
			types.NewTypeName(token.NoPos, rapidPkg, "T", nil),
			types.NewStruct([]*types.Var{types.NewField(token.NoPos, rapidPkg, "Seed", types.Typ[types.Uint64], false)}, nil),
			nil,
		)
		if !propertyHarnessHandleType(types.NewPointer(closedT)) || propertyHarnessHandleType(types.NewPointer(openT)) {
			t.Fatal("propertyHarnessHandleType misclassified unexported-field vs exported-field rapid.T")
		}
		phFact := propertyHarnessFact()
		if !phFact.observable || maximalObservabilityBlocker(audited, phFact) {
			t.Fatalf("propertyHarnessFact = %+v, want observable non-blocker", phFact)
		}
	})
}

func FuzzObservabilityLattice(f *testing.F) {
	f.Add("fmt", "Sprint", true)
	f.Add("os", "Getenv", false)
	f.Add("reflect", "DeepEqual", true)

	f.Fuzz(func(t *testing.T, pkg, sym string, audited bool) {
		cleanSym := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				return r
			}
			return 'X'
		}, sym)
		if cleanSym == "" {
			cleanSym = "Sym"
		}

		closedSig := types.NewSignatureType(nil, nil, nil, types.NewTuple(types.NewVar(token.NoPos, nil, "x", types.Typ[types.Int])), nil, false)
		openSig := types.NewSignatureType(nil, nil, nil, types.NewTuple(types.NewVar(token.NoPos, nil, "fn", types.NewSignatureType(nil, nil, nil, nil, nil, false))), nil, false)
		if term := signatureOpenWorldTerm(audited, closedSig, nil, false, carrierPolicyClosure); term != "" {
			t.Fatalf("closed signature reported open-world term %q", term)
		}
		if term := signatureOpenWorldTerm(audited, openSig, nil, false, carrierPolicyClosure); !strings.Contains(term, "parameter fn") {
			t.Fatalf("open signature term = %q, want parameter fn", term)
		}
		gomaxEff := symbolExternalEffect(externalEffectUnauditedStandard, "runtime", "GOMAXPROCS", "reaches unaudited standard operation runtime.GOMAXPROCS")
		fileIOEff := symbolExternalEffect(externalEffectFileIO, "os", "Open", "reaches os.Open (file I/O)")
		phFact := propertyHarnessFact()
		if !preferEffectReason(fileIOEff, gomaxEff) || !preferEffectReason(gomaxEff, phFact) {
			t.Fatal("preferEffectReason violated cause-preference rank order")
		}

		subjA := Subject{Package: "example.com/p", Symbol: "A_" + cleanSym}
		subjB := Subject{Package: "example.com/p", Symbol: "B_" + cleanSym}
		if maximalSubjectHash(pkg, subjA) == maximalSubjectHash(pkg, subjB) {
			t.Fatalf("maximalSubjectHash collided across distinct subjects %v and %v", subjA, subjB)
		}
		baseFacts := newMaximalFacts(MaximalIdentity{ToolchainContent: "tc", AdmissionPolicy: "ap"}, []externalEffect{gomaxEff, fileIOEff}, preferredEffectReason([]externalEffect{gomaxEff, fileIOEff}))
		cloneA := baseFacts.Clone()
		cloneB := baseFacts.Clone()
		if cloneA.Closure() != cloneB.Closure() || !cloneA.Closure().Unverifiable {
			t.Fatalf("cloned maximal facts diverged across batch subjects: %+v vs %+v", cloneA.Closure(), cloneB.Closure())
		}
	})
}
