// Package compartment computes a package's test-variant compartment —
// the hash and declaration ledger of its test-only files, derived from
// one read of each file — for the closure engine; the vocabulary the
// ledger is written in is closure/testvariant, the public half.
package compartment

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
	"github.com/greatliontech/gofresh/closure/testvariant"
)

// Identity is one package's computed compartment: the compartment
// hash, its declaration ledger, and the sorted relative test-only file names,
// all derived from one read of each file so the hash vouches for exactly the
// bytes the ledger describes.
type Identity struct {
	Hash   string
	Ledger testvariant.TestVariantLedger
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

// Source supplies a file's bytes and their SHA-256 sum — a Hasher's
// once-per-pass reads, or the file system directly when nil.
type Source interface {
	ReadFile(path string) ([]byte, [32]byte, error)
}

type osSource struct{}

func (osSource) ReadFile(path string) ([]byte, [32]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return content, sha256.Sum256(content), nil
}

// ParseMemo serves a compiled member's derivation — its declarations and
// header — under the member's name and content digest, and records a
// fresh one: the derivation is a pure function of the bytes, so a served
// entry is exactly what parsing would yield.
type ParseMemo interface {
	Parsed(name, digest string) ([]testvariant.TestVariantDeclaration, testvariant.TestVariantFileHeader, bool)
	Record(name, digest string, declarations []testvariant.TestVariantDeclaration, header testvariant.TestVariantFileHeader)
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
// testvariant.EmptyTestVariantClosure and an empty ledger.
func ComputeIdentity(dir string, files []string, compiledGo, embeddedData map[string]bool, digests map[string]string, source Source, memo ParseMemo) (Identity, error) {
	if source == nil {
		source = osSource{}
	}
	files = listing.UniqueStrings(append([]string(nil), files...))
	sort.Strings(files)
	hasher := sha256.New()
	var ledger testvariant.TestVariantLedger
	for _, f := range files {
		path := filepath.Join(dir, f)
		content, sum, err := source.ReadFile(path)
		if err != nil {
			return Identity{}, fmt.Errorf("closure: read %s: %w", path, err)
		}
		fmt.Fprintf(hasher, "%s\x00%x\n", f, sum)
		contentDigest := digest.FromSum(sum)
		if digests != nil {
			// Compartment members are observed source identities like any
			// core member: their per-file digests ride to the Hasher's memo
			// (FileDigest) so drift naming covers them without a re-read.
			digests[path] = contentDigest
		}
		if compiledGo[f] {
			declarations, header, served := []testvariant.TestVariantDeclaration(nil), testvariant.TestVariantFileHeader{}, false
			if memo != nil {
				declarations, header, served = memo.Parsed(f, contentDigest)
			}
			if !served {
				declarations, header, err = parseTestVariantFile(f, content)
				if err != nil {
					return Identity{}, err
				}
				if memo != nil {
					memo.Record(f, contentDigest, declarations, header)
				}
			}
			ledger.Declarations = append(ledger.Declarations, declarations...)
			if embeddedData[f] {
				// Dual member: compiled and embedded. The declarations keep
				// their granularity, but the header is the whole content,
				// marked Embedded — an edit anywhere in the file moves the
				// bytes some unchanged declaration reads.
				header = testvariant.TestVariantFileHeader{File: f, Hash: contentDigest, Embedded: true}
			}
			ledger.FileHeaders = append(ledger.FileHeaders, header)
			continue
		}
		// Every non-compiled member — embedded data, whatever its name —
		// has no declarations; its whole content is its header identity,
		// marked Embedded so movement defeats inertness. (A non-Go
		// compiled input never reaches here: the variant node repeats
		// the base's SFiles and CFiles, so one is never test-only; a
		// constrained-out one rides no listing, and a test file that
		// embeds one makes it a member as embedded data.)
		ledger.FileHeaders = append(ledger.FileHeaders, testvariant.TestVariantFileHeader{File: f, Hash: contentDigest, Embedded: true})
	}
	sort.Slice(ledger.Declarations, func(i, j int) bool {
		return testvariant.LessDeclaration(ledger.Declarations[i], ledger.Declarations[j])
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
// The derivation is persisted per member under closure's
// variantParseStrategy: any change here that can move a declaration
// hash, a reference list, or a header bumps that version.
func parseTestVariantFile(name string, content []byte) ([]testvariant.TestVariantDeclaration, testvariant.TestVariantFileHeader, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, content, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, testvariant.TestVariantFileHeader{}, fmt.Errorf("closure: parse %s: %w", name, err)
	}
	tokenFile := fset.File(file.Pos())
	offset := func(pos token.Pos) int { return tokenFile.Offset(pos) }
	type span struct{ start, end int }
	var spans []span
	var declarations []testvariant.TestVariantDeclaration
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
			declarations = append(declarations, testvariant.TestVariantDeclaration{
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
					declarations = append(declarations, testvariant.TestVariantDeclaration{File: name, Kind: kind, Name: spec.Name.Name, Hash: hash, References: referencedNames(spec), Package: file.Name.Name})
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
						declarations = append(declarations, testvariant.TestVariantDeclaration{File: name, Kind: kind, Name: specName.Name, Hash: hash, References: references, Package: file.Name.Name})
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
			declarations = append(declarations, testvariant.TestVariantDeclaration{
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
	header := testvariant.TestVariantFileHeader{File: name, Hash: hex.EncodeToString(remainder.Sum(nil))[:32]}
	return declarations, header, nil
}
