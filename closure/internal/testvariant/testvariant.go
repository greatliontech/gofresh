// Package testvariant computes the test-variant compartment: the identity
// and declaration ledger of a package's own test-only source, partitioned
// out of the core closure (REQ-closure-test-variant-compartment).
package testvariant

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/greatliontech/gofresh/closure/internal/digest"
	"github.com/greatliontech/gofresh/closure/internal/listing"
)

// EmptyTestVariantClosure is the test-variant compartment identity of a package
// with no test files: the empty-file-set hash under the same name\x00sha256
// discipline as every other compartment. It is a stable constant — a recorded
// compartment equal to it stays valid for as long as the package has no test
// files — and it is never the empty string, so an empty recorded compartment
// unambiguously identifies a recording that predates the partition
// (REQ-closure-test-variant-compartment).
const EmptyTestVariantClosure = "e3b0c44298fc1c149afbf4c8996fb924"

// TestVariantLedger is the declaration-level read surface over a package's
// test-variant compartment: every top-level declaration in the compartment's Go
// files and a per-file header identity over each file's non-declaration
// remainder. It is data for a consumer to persist at capture and diff at check;
// gofresh renders no judgment about which deltas are benign
// (REQ-closure-test-variant-compartment).
type TestVariantLedger struct {
	// Declarations is sorted by (File, Kind, Receiver, Name, Hash).
	Declarations []TestVariantDeclaration
	// FileHeaders is sorted by File and carries one entry per compartment
	// file: for a compiled Go member the hash covers the non-declaration
	// remainder — package clause, imports, build constraints, and comments
	// outside declarations; for every other member (embedded data whatever
	// its name, non-Go compiled inputs) it covers the whole file, with
	// Embedded set.
	FileHeaders []TestVariantFileHeader
}

// TestVariantDeclaration identifies one top-level declaration in a compartment
// file. Kind is one of "func", "method", "init", "var", "const", "type", or
// "directive" — a directive-shaped comment (//go:… other than //go:build)
// ledgered wherever it sits, its Name the directive verb (e.g. "go:linkname");
// TestMain is an ordinary "func" whose name stays visible to the consumer.
// Receiver is the receiver type's source text for methods and empty otherwise.
// Hash is 32 hex characters of SHA-256 over the declaration's source range,
// its doc comment included; for a grouped var/const/type declaration the range
// is the individual spec, so sibling entries in one group move independently.
// Positions Go gives semantics are folded into the hash alongside the bytes:
// a const spec's ordinal within its group (iota and implicit expression
// repetition depend on it), and a var spec's or an init function's ordinal in
// its file (package-level initialization order depends on it) — so a
// value-shifting insertion or an order-sensitive reorder surfaces as changed
// declarations, never as a silent add or an empty delta.
type TestVariantDeclaration struct {
	File     string // relative to the package directory
	Kind     string
	Name     string
	Receiver string
	Hash     string
	// Package is the declaring file's package clause name — the base name
	// for the in-package variant, the "_test"-suffixed name for the
	// external one — so a consumer can tell same-named declarations of the
	// two compartment packages apart (a method's receiver type resolves
	// within its own package only). Unlike References it is NOT derivable
	// from the hash-pinned bytes (the clause lives in the file header), so
	// it is part of the diff identity: a package-clause-only rename
	// re-homes every declaration semantically (methods re-attach across
	// same-named types, unexported access changes) and surfaces as removed
	// and added declarations, never as an empty delta. It stays outside
	// the content hash.
	Package string
	// References is the declaration's referenced-name list: every identifier
	// appearing in its declaring node — selector members, receiver and
	// parameter type names, and local names included; the blank identifier
	// excluded — deduplicated and sorted. It is a syntax-only
	// over-approximation of the top-level names the declaration's compiled
	// code can resolve by identifier, derived from the bytes the hash
	// vouches for: equal hashes carry equal reference lists, except an
	// omitted-list const spec, whose fold also tracks its group's governing
	// expression list — there the governing spec's declared names always
	// ride the fold, the blank name included (naming the ledger entry
	// itself when the governor declares nothing else), and a change in
	// that list is the governing entry's own movement, so a consumer
	// walking current references still observes every movement an
	// unchanged declaration can textually repeat. It is
	// served for a consumer to attribute a compartment delta to the
	// declarations that can reach it; gofresh itself renders no
	// reachability judgment. Directive entries carry none.
	References []string
}

// TestVariantFileHeader is one compartment file's non-declaration identity.
// A compiled Go member's hash covers its non-declaration remainder; every
// other member — embedded data whatever its name, a .go-named testdata
// fixture included, and non-Go compiled inputs — carries Embedded true and a
// whole-content hash, because its bytes feed unchanged code rather than
// declare any (REQ-closure-test-variant-compartment).
type TestVariantFileHeader struct {
	File     string // relative to the package directory
	Hash     string
	Embedded bool
}

// TestVariantDelta is the classified difference between two compartment
// ledgers — a recorded one and a current one. Added, Changed, and Removed are
// sorted with the ledger's declaration ordering; HeaderChanges is sorted by
// file. It is data plus Go semantics: Inert reports whether the delta can
// change the behavior of any unchanged declaration, and nothing about what a
// consumer should do with that fact (REQ-closure-test-variant-compartment).
type TestVariantDelta struct {
	Added   []TestVariantDeclaration
	Changed []TestVariantDeclarationChange
	Removed []TestVariantDeclaration
	// HeaderChanges carries every file whose header identity moved: an empty
	// Before is a file new to the compartment, an empty After a file that
	// left it.
	HeaderChanges []TestVariantHeaderChange
}

// TestVariantDeclarationChange pairs a declaration's recorded and current
// ledger entries.
type TestVariantDeclarationChange struct {
	Before TestVariantDeclaration
	After  TestVariantDeclaration
}

// TestVariantHeaderChange is one file's header-identity movement. Embedded
// reports that either side is an embedded (non-compiled) member, whose
// movement defeats inertness fail-closed.
type TestVariantHeaderChange struct {
	File     string
	Before   string // empty when the file is new to the compartment
	After    string // empty when the file left the compartment
	Embedded bool
}

// Inert reports whether this delta is behavior-inert for unchanged code: no
// declaration changed or was removed, and every added declaration is one no
// unchanged declaration can observe — a plain function (no receiver, not init,
// not TestMain), a const, or a type (an accompanying method would be its own
// added "method" entry and defeat inertness). The rejected kinds each name a
// mechanism reaching unchanged code: a package var's initializer runs during
// test-binary initialization; an init function likewise; TestMain replaces
// the harness entry wrapping every unchanged test; a method can flip
// interface satisfaction observed by unchanged type assertions and dispatch.
// Additions that shift what an existing declaration means are not silent
// adds: positional semantics — a const's ordinal in its group, a var's or an
// init's ordinal in its file — are folded into declaration hashes (see
// TestVariantDeclaration), so an insertion that shifts iota siblings or a
// reorder of initialization surfaces as Changed and defeats inertness here.
// Go-file header-only changes — imports, build-constraint text, comments
// outside declarations — do not defeat inertness: this is the one place the
// judgment leans on the partition rule, because test-only dependency NODES
// stay in the core closure, so the core equality under which a consumer sees
// this delta already proves no new dependency package entered the test
// binary, making an import edit among already-present packages init-benign.
// Compiler and linker directives are NOT header content: they are ledgered
// as their own "directive" entries wherever they sit (see
// TestVariantDeclaration), and the unknown-kind default below fails closed
// on them — a //go:debug or //go:linkname addition is never inert.
// An embedded (non-compiled) member's delta defeats inertness fail-closed —
// whatever its name, a .go-named testdata fixture included: its bytes feed
// unchanged declarations that read it, and its whole content is its header,
// so a header move IS a content move.
func (d TestVariantDelta) Inert() bool {
	if len(d.Changed) != 0 || len(d.Removed) != 0 {
		return false
	}
	for _, added := range d.Added {
		switch added.Kind {
		case "const", "type":
		case "func":
			if added.Name == "TestMain" {
				return false
			}
		default: // method, init, var, and anything unrecognized fail closed
			return false
		}
	}
	for _, header := range d.HeaderChanges {
		if header.Embedded {
			return false
		}
	}
	return true
}

// DiffTestVariantLedgers classifies the delta from a recorded ledger to a
// current one. Declarations are matched by (File, Package, Kind, Receiver,
// Name) — the package clause is diff identity, so an entry recorded without
// one (a pre-clause ledger) matches nothing and classifies removed;
// entries sharing that identity (several init functions in one file) pair by
// sorted hash, surplus recorded entries reporting as removed and surplus
// current ones as added. The result is deterministic for any two ledgers.
func DiffTestVariantLedgers(before, after TestVariantLedger) TestVariantDelta {
	type identity struct {
		file, pkg, kind, receiver, name string
	}
	group := func(declarations []TestVariantDeclaration) (map[identity][]TestVariantDeclaration, []identity) {
		grouped := make(map[identity][]TestVariantDeclaration, len(declarations))
		var order []identity
		for _, declaration := range declarations {
			key := identity{declaration.File, declaration.Package, declaration.Kind, declaration.Receiver, declaration.Name}
			if _, ok := grouped[key]; !ok {
				order = append(order, key)
			}
			grouped[key] = append(grouped[key], declaration)
		}
		return grouped, order
	}
	recorded, recordedOrder := group(before.Declarations)
	current, currentOrder := group(after.Declarations)
	var delta TestVariantDelta
	for _, key := range recordedOrder {
		was := recorded[key]
		now := current[key]
		shared := map[string]int{}
		for _, declaration := range now {
			shared[declaration.Hash]++
		}
		var leftBefore []TestVariantDeclaration
		for _, declaration := range was {
			if shared[declaration.Hash] > 0 {
				shared[declaration.Hash]--
				continue
			}
			leftBefore = append(leftBefore, declaration)
		}
		var leftAfter []TestVariantDeclaration
		matched := map[string]int{}
		for _, declaration := range was {
			matched[declaration.Hash]++
		}
		for _, declaration := range now {
			if matched[declaration.Hash] > 0 {
				matched[declaration.Hash]--
				continue
			}
			leftAfter = append(leftAfter, declaration)
		}
		for i := 0; i < len(leftBefore) && i < len(leftAfter); i++ {
			delta.Changed = append(delta.Changed, TestVariantDeclarationChange{Before: leftBefore[i], After: leftAfter[i]})
		}
		if len(leftBefore) > len(leftAfter) {
			delta.Removed = append(delta.Removed, leftBefore[len(leftAfter):]...)
		}
		if len(leftAfter) > len(leftBefore) {
			delta.Added = append(delta.Added, leftAfter[len(leftBefore):]...)
		}
	}
	for _, key := range currentOrder {
		if _, ok := recorded[key]; !ok {
			delta.Added = append(delta.Added, current[key]...)
		}
	}
	headers := func(ledger TestVariantLedger) map[string]TestVariantFileHeader {
		byFile := make(map[string]TestVariantFileHeader, len(ledger.FileHeaders))
		for _, header := range ledger.FileHeaders {
			byFile[header.File] = header
		}
		return byFile
	}
	recordedHeaders := headers(before)
	currentHeaders := headers(after)
	for _, header := range before.FileHeaders {
		now, ok := currentHeaders[header.File]
		if !ok {
			delta.HeaderChanges = append(delta.HeaderChanges, TestVariantHeaderChange{File: header.File, Before: header.Hash, Embedded: header.Embedded})
			continue
		}
		if now.Hash != header.Hash || now.Embedded != header.Embedded {
			delta.HeaderChanges = append(delta.HeaderChanges, TestVariantHeaderChange{File: header.File, Before: header.Hash, After: now.Hash, Embedded: header.Embedded || now.Embedded})
		}
	}
	for _, header := range after.FileHeaders {
		if _, ok := recordedHeaders[header.File]; !ok {
			delta.HeaderChanges = append(delta.HeaderChanges, TestVariantHeaderChange{File: header.File, After: header.Hash, Embedded: header.Embedded})
		}
	}
	sortDeclarations := func(declarations []TestVariantDeclaration) {
		sort.Slice(declarations, func(i, j int) bool { return lessDeclaration(declarations[i], declarations[j]) })
	}
	sortDeclarations(delta.Added)
	sortDeclarations(delta.Removed)
	sort.Slice(delta.Changed, func(i, j int) bool { return lessDeclaration(delta.Changed[i].After, delta.Changed[j].After) })
	sort.Slice(delta.HeaderChanges, func(i, j int) bool { return delta.HeaderChanges[i].File < delta.HeaderChanges[j].File })
	return delta
}

func lessDeclaration(a, b TestVariantDeclaration) bool {
	switch {
	case a.File != b.File:
		return a.File < b.File
	case a.Kind != b.Kind:
		return a.Kind < b.Kind
	case a.Receiver != b.Receiver:
		return a.Receiver < b.Receiver
	case a.Name != b.Name:
		return a.Name < b.Name
	default:
		return a.Hash < b.Hash
	}
}

// Clone returns a caller-owned deep copy of the ledger.
func (l TestVariantLedger) Clone() TestVariantLedger {
	declarations := append([]TestVariantDeclaration(nil), l.Declarations...)
	for i := range declarations {
		declarations[i].References = append([]string(nil), declarations[i].References...)
	}
	return TestVariantLedger{
		Declarations: declarations,
		FileHeaders:  append([]TestVariantFileHeader(nil), l.FileHeaders...),
	}
}

// Identity is one package's computed compartment: the compartment
// hash, its declaration ledger, and the sorted relative test-only file names,
// all derived from one read of each file so the hash vouches for exactly the
// bytes the ledger describes.
type Identity struct {
	Hash   string
	Ledger TestVariantLedger
	dir    string
	Files  []string
}

// OwnVariantOf reports whether p is pkgPath's own test-variant node — the
// in-package variant (pkg [pkg.test]) or the external test package
// (pkg_test [pkg.test]) — as opposed to a dependency recompiled against the
// test binary, which keeps its core contribution. Both own variants compile
// from the base package's directory, so baseDir disambiguates a real
// dependency package whose import path happens to end in "_test" (a legal
// directory name): recompiled against the test variant it shares the base's
// suffixed import path but never its directory. Go refuses to build that
// configuration (importing it from the test is a cycle), so the check keeps
// go-list-only analysis of such a tree fail-safe rather than fixing a
// reachable wrong verdict.
func OwnVariantOf(p listing.Package, pkgPath, baseDir string) bool {
	if p.ForTest != pkgPath || p.IsGeneratedTestMainFor(pkgPath) {
		return false
	}
	if baseDir != "" && p.Dir != baseDir {
		return false
	}
	base := strings.TrimSuffix(p.ImportPath, " ["+pkgPath+".test]")
	return base == pkgPath || base == pkgPath+"_test"
}

// ComputeIdentity hashes the compartment's files and derives the
// declaration ledger from the same reads: each file is read once, its bytes
// folded into the compartment hash under hashFiles's name\x00sha256 discipline
// and, for compiled Go members, parsed syntax-only for the ledger — no type
// checking. Membership comes from go list's file-kind facts, never the file
// name: an embedded .go-named fixture is data, taking the whole-content
// Embedded header path and never the parser; a member that is BOTH compiled
// and embedded keeps its parsed declarations but carries the Embedded
// whole-content header, because its bytes also feed unchanged code as data
// and any movement in them must defeat inertness. An empty file set yields
// EmptyTestVariantClosure and an empty ledger.
func ComputeIdentity(dir string, files []string, compiledGo, embeddedData map[string]bool, digests map[string]string) (Identity, error) {
	files = listing.UniqueStrings(append([]string(nil), files...))
	sort.Strings(files)
	hasher := sha256.New()
	var ledger TestVariantLedger
	for _, f := range files {
		path := filepath.Join(dir, f)
		content, err := os.ReadFile(path)
		if err != nil {
			return Identity{}, fmt.Errorf("closure: read %s: %w", path, err)
		}
		fmt.Fprintf(hasher, "%s\x00%x\n", f, sha256.Sum256(content))
		if digests != nil {
			// Compartment members are observed source identities like any
			// core member: their per-file digests ride to the Hasher's memo
			// (FileDigest) so drift naming covers them without a re-read.
			digests[path] = digest.Content(content)
		}
		if compiledGo[f] {
			declarations, header, err := parseTestVariantFile(f, content)
			if err != nil {
				return Identity{}, err
			}
			ledger.Declarations = append(ledger.Declarations, declarations...)
			if embeddedData[f] {
				// Dual member: compiled and embedded. The declarations keep
				// their granularity, but the header is the whole content,
				// marked Embedded — an edit anywhere in the file moves the
				// bytes some unchanged declaration reads.
				header = TestVariantFileHeader{File: f, Hash: digest.Content(content), Embedded: true}
			}
			ledger.FileHeaders = append(ledger.FileHeaders, header)
			continue
		}
		// Every non-compiled member — embedded data whatever its name, and
		// non-Go compiled inputs — has no declarations; its whole content is
		// its header identity, marked Embedded so movement defeats inertness.
		ledger.FileHeaders = append(ledger.FileHeaders, TestVariantFileHeader{File: f, Hash: digest.Content(content), Embedded: true})
	}
	sort.Slice(ledger.Declarations, func(i, j int) bool {
		return lessDeclaration(ledger.Declarations[i], ledger.Declarations[j])
	})
	sort.Slice(ledger.FileHeaders, func(i, j int) bool {
		return ledger.FileHeaders[i].File < ledger.FileHeaders[j].File
	})
	return Identity{
		Hash:   hex.EncodeToString(hasher.Sum(nil))[:32],
		Ledger: ledger,
		dir:    dir,
		Files:  files,
	}, nil
}

// positionalDigest folds a position Go gives semantics into a declaration's
// content digest, so a declaration whose own bytes are untouched still reads
// as changed when its semantically load-bearing ordinal moves (a const spec
// shifted by an insertion above it in its iota group, a var spec or init
// function reordered in its file).
func positionalDigest(content []byte, ordinal int) string {
	hasher := sha256.New()
	hasher.Write(content)
	fmt.Fprintf(hasher, "\x00%d", ordinal)
	return hex.EncodeToString(hasher.Sum(nil))[:32]
}

// referencedNames collects every identifier name appearing under node,
// deduplicated and sorted — the syntax-only reference surface a consumer
// attributes compartment deltas with. Locals and field names over-count by
// name collision; over-counting is the safe direction (a consumer re-checks
// more, never less). The blank identifier resolves nothing and is dropped.
func referencedNames(node ast.Node) []string {
	if node == nil {
		return nil
	}
	seen := map[string]bool{}
	var names []string
	ast.Inspect(node, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && ident.Name != "_" && !seen[ident.Name] {
			seen[ident.Name] = true
			names = append(names, ident.Name)
		}
		return true
	})
	sort.Strings(names)
	return names
}

// mergedNames unions two sorted-unique name lists into a sorted-unique one.
func mergedNames(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a)+len(b))
	merged := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, name := range list {
			if !seen[name] {
				seen[name] = true
				merged = append(merged, name)
			}
		}
	}
	sort.Strings(merged)
	return merged
}

// parseTestVariantFile extracts one Go file's ledger entries from its bytes:
// one declaration entry per top-level function, method, init, var, const, and
// type name, plus the file header over the non-declaration remainder. Import
// declarations belong to the header remainder, not the declaration list.
func parseTestVariantFile(name string, content []byte) ([]TestVariantDeclaration, TestVariantFileHeader, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, content, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, TestVariantFileHeader{}, fmt.Errorf("closure: parse %s: %w", name, err)
	}
	tokenFile := fset.File(file.Pos())
	offset := func(pos token.Pos) int { return tokenFile.Offset(pos) }
	type span struct{ start, end int }
	var spans []span
	var declarations []TestVariantDeclaration
	declStart := func(doc *ast.CommentGroup, pos token.Pos) int {
		if doc != nil {
			return offset(doc.Pos())
		}
		return offset(pos)
	}
	// File-level ordinals with initialization-order semantics: package-level
	// var specs initialize in source order (dependency edges aside) and init
	// functions run in source order within a file, so both fold their ordinal
	// into the declaration hash and a pure reorder reads as changed.
	varOrdinal, initOrdinal := 0, 0
	for _, decl := range file.Decls {
		switch decl := decl.(type) {
		case *ast.FuncDecl:
			start, end := declStart(decl.Doc, decl.Pos()), offset(decl.End())
			spans = append(spans, span{start, end})
			kind, receiver := "func", ""
			hash := digest.Content(content[start:end])
			if decl.Recv != nil && len(decl.Recv.List) > 0 {
				kind = "method"
				receiver = strings.TrimSpace(string(content[offset(decl.Recv.List[0].Type.Pos()):offset(decl.Recv.List[0].Type.End())]))
			} else if decl.Name.Name == "init" {
				kind = "init"
				hash = positionalDigest(content[start:end], initOrdinal)
				initOrdinal++
			}
			declarations = append(declarations, TestVariantDeclaration{
				File: name, Kind: kind, Name: decl.Name.Name, Receiver: receiver,
				Hash: hash, References: referencedNames(decl), Package: file.Name.Name,
			})
		case *ast.GenDecl:
			if decl.Tok == token.IMPORT {
				continue
			}
			start, end := declStart(decl.Doc, decl.Pos()), offset(decl.End())
			spans = append(spans, span{start, end})
			var kind string
			switch decl.Tok {
			case token.VAR:
				kind = "var"
			case token.CONST:
				kind = "const"
			case token.TYPE:
				kind = "type"
			default:
				continue
			}
			// A const spec with an omitted expression list repeats the
			// group's governing (nearest preceding non-empty) list
			// textually, so its compiled code resolves that list's names
			// without writing them; the governing spec's references fold
			// into the empty-listed sibling to keep the reference surface
			// an over-approximation of what the code can resolve.
			var governingConstRefs []string
			for si, spec := range decl.Specs {
				specStart, specEnd := start, end
				if decl.Lparen.IsValid() {
					// Grouped declaration: each spec's range stands
					// alone, so sibling specs move independently.
					switch spec := spec.(type) {
					case *ast.TypeSpec:
						specStart, specEnd = declStart(spec.Doc, spec.Pos()), offset(spec.End())
					case *ast.ValueSpec:
						specStart, specEnd = declStart(spec.Doc, spec.Pos()), offset(spec.End())
					}
				}
				var hash string
				switch decl.Tok {
				case token.CONST:
					// A const spec's value can depend on its position in its
					// group (iota, implicit expression repetition), so the
					// ordinal folds into the hash: inserting above a spec
					// changes that spec, appending after it does not.
					hash = positionalDigest(content[specStart:specEnd], si)
				case token.VAR:
					hash = positionalDigest(content[specStart:specEnd], varOrdinal)
					varOrdinal++
				default:
					hash = digest.Content(content[specStart:specEnd])
				}
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					declarations = append(declarations, TestVariantDeclaration{File: name, Kind: kind, Name: spec.Name.Name, Hash: hash, References: referencedNames(spec), Package: file.Name.Name})
				case *ast.ValueSpec:
					references := referencedNames(spec)
					if decl.Tok == token.CONST {
						if len(spec.Values) > 0 {
							// The fold carries the governing spec's declared
							// names too, the blank name included: a test can
							// never write "_", but the ledger's "_" entry is
							// a walkable node, and without that edge an
							// empty-listed sibling's textual repetition of a
							// blank-named governor would be attributable to
							// nothing.
							governingConstRefs = references
							for _, specName := range spec.Names {
								governingConstRefs = mergedNames(governingConstRefs, []string{specName.Name})
							}
						} else {
							references = mergedNames(references, governingConstRefs)
						}
					}
					for _, specName := range spec.Names {
						declarations = append(declarations, TestVariantDeclaration{File: name, Kind: kind, Name: specName.Name, Hash: hash, References: references, Package: file.Name.Name})
					}
				}
			}
		}
	}
	// Compiler and linker directives are behavior-bearing wherever they sit —
	// //go:debug before the package clause, a floating //go:linkname inside a
	// group's span but outside every spec range — so every directive-shaped
	// comment is its own ledger entry, and the delta classifier's
	// unknown-kind fail-closed default makes any directive movement defeat
	// inertness. Build constraints are the exclusion: their text compiles to
	// nothing under the current configuration, and a membership change they
	// cause already surfaces as declaration and file-header movement. Other
	// intra-group non-spec bytes are comments and whitespace only — benign
	// once directives are ledgered.
	for _, group := range file.Comments {
		for _, comment := range group.List {
			text := comment.Text
			if !strings.HasPrefix(text, "//go:") {
				continue
			}
			verb := text
			if i := strings.IndexAny(verb, " \t"); i >= 0 {
				verb = verb[:i]
			}
			if verb == "//go:build" {
				continue
			}
			declarations = append(declarations, TestVariantDeclaration{
				File: name, Kind: "directive", Name: strings.TrimPrefix(verb, "//"),
				Hash: digest.Content([]byte(text)), Package: file.Name.Name,
			})
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	remainder := sha256.New()
	previous := 0
	for _, s := range spans {
		if s.start > previous {
			remainder.Write(content[previous:s.start])
		}
		if s.end > previous {
			previous = s.end
		}
	}
	if previous < len(content) {
		remainder.Write(content[previous:])
	}
	header := TestVariantFileHeader{File: name, Hash: hex.EncodeToString(remainder.Sum(nil))[:32]}
	return declarations, header, nil
}
