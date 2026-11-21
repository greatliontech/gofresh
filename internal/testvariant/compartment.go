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
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Identity is one package's computed test-variant compartment: the compartment
// hash, its declaration ledger, and the sorted relative test-only file names,
// all derived from one read of each file so the hash vouches for exactly the
// bytes the ledger describes.
type Identity struct {
	Hash   string
	Ledger TestVariantLedger
	dir    string
	Files  []string
}

// ReadFileFunc supplies a file's bytes and their SHA-256 sum — a caller's
// once-per-pass read cache, or os.ReadFile directly when nil.
type ReadFileFunc func(path string) ([]byte, [32]byte, error)

// ParseFileFunc returns a compiled Go member's syntax-only declarations and
// header identity under its relative file name, truncated content digest, and
// raw bytes. When nil, ComputeIdentity and AddBaseBindings call ParseFile
// directly.
type ParseFileFunc func(name, contentDigest string, content []byte) ([]TestVariantDeclaration, TestVariantFileHeader, error)

func osReadFile(path string) ([]byte, [32]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return content, sha256.Sum256(content), nil
}

func shortSumHex(sum [32]byte) string {
	return hex.EncodeToString(sum[:16])
}

func shortContentHex(content []byte) string {
	return shortSumHex(sha256.Sum256(content))
}

// ComputeIdentity hashes the compartment's files and derives the declaration
// ledger from the same reads: each file is read once, its bytes folded into
// the compartment hash under hashFiles's name\x00sha256 discipline and, for
// compiled Go members, parsed syntax-only for the ledger — no type checking.
// Membership comes from go list's file-kind facts, never the file name: an
// embedded .go-named fixture is data, taking the whole-content Embedded header
// path and never the parser; a member that is BOTH compiled and embedded keeps
// its parsed declarations but carries the Embedded whole-content header,
// because its bytes also feed unchanged code as data and any movement in them
// must defeat inertness. An empty file set yields EmptyTestVariantClosure and
// an empty ledger.
func ComputeIdentity(dir string, files []string, compiledGo, embeddedData map[string]bool, digests map[string]string, readFile ReadFileFunc, parseFile ParseFileFunc) (Identity, error) {
	if readFile == nil {
		readFile = osReadFile
	}
	files = slices.Clone(files)
	slices.Sort(files)
	files = slices.Compact(files)
	hasher := sha256.New()
	var ledger TestVariantLedger
	for _, f := range files {
		path := filepath.Join(dir, f)
		content, sum, err := readFile(path)
		if err != nil {
			return Identity{}, fmt.Errorf("closure: read %s: %w", path, err)
		}
		fmt.Fprintf(hasher, "%s\x00%x\n", f, sum)
		contentDigest := shortSumHex(sum)
		if digests != nil {
			// Compartment members are observed source identities like any
			// core member: their per-file digests ride to the caller's memo
			// so drift naming covers them without a re-read.
			digests[path] = contentDigest
		}
		if compiledGo[f] {
			var declarations []TestVariantDeclaration
			var header TestVariantFileHeader
			if parseFile != nil {
				declarations, header, err = parseFile(f, contentDigest, content)
			} else {
				declarations, header, err = parseTestVariantFile(f, content)
			}
			if err != nil {
				return Identity{}, err
			}
			ledger.Declarations = append(ledger.Declarations, declarations...)
			if embeddedData[f] {
				// Dual member: compiled and embedded. The declarations keep
				// their granularity, but the header is the whole content,
				// marked Embedded — an edit anywhere in the file moves the
				// bytes some unchanged declaration reads.
				header.Hash, header.Embedded = contentDigest, true
			}
			ledger.FileHeaders = append(ledger.FileHeaders, header)
			continue
		}
		// Every non-compiled member — embedded data, whatever its name —
		// has no declarations; its whole content is its header identity,
		// marked Embedded so movement defeats inertness.
		ledger.FileHeaders = append(ledger.FileHeaders, TestVariantFileHeader{File: f, Hash: contentDigest, Embedded: true})
	}
	sort.Slice(ledger.Declarations, func(i, j int) bool {
		return LessDeclaration(ledger.Declarations[i], ledger.Declarations[j])
	})
	sort.Slice(ledger.FileHeaders, func(i, j int) bool {
		return ledger.FileHeaders[i].File < ledger.FileHeaders[j].File
	})
	return Identity{
		Hash:   hex.EncodeToString(hasher.Sum(nil)[:16]),
		Ledger: ledger,
		dir:    dir,
		Files:  files,
	}, nil
}

// AddBaseBindings completes the ledger's binding context using the same source
// observation as the core fold. Default import names come from go list, never
// from a path basename. Parse memo entries remain pure functions of source bytes.
func AddBaseBindings(identity *Identity, baseGo []string, importNames map[string]string, readFile ReadFileFunc, parseFile ParseFileFunc) error {
	if readFile == nil {
		readFile = osReadFile
	}
	for _, name := range baseGo {
		content, sum, err := readFile(filepath.Join(identity.dir, name))
		if err != nil {
			return err
		}
		d := shortSumHex(sum)
		var header TestVariantFileHeader
		if parseFile != nil {
			_, header, err = parseFile(name, d, content)
		} else {
			_, header, err = parseTestVariantFile(name, content)
		}
		if err != nil {
			return err
		}
		// The core already guards base content using its canonical fold.
		// Retaining a raw header hash here would make comment-only base edits
		// move the ledger under an unchanged core and compartment.
		header.Hash = ""
		identity.Ledger.BaseFiles = append(identity.Ledger.BaseFiles, header)
	}
	// Resolution must not mutate any shared parse memo.
	identity.Ledger = identity.Ledger.Clone()
	for _, headers := range [][]TestVariantFileHeader{identity.Ledger.BaseFiles, identity.Ledger.FileHeaders} {
		for _, header := range headers {
			b := header.Bindings
			if b == nil {
				continue
			}
			for i := range b.Imports {
				if b.Imports[i].Name == "" {
					b.Imports[i].Name = importNames[b.Imports[i].Path]
				}
			}
		}
	}
	sort.Slice(identity.Ledger.BaseFiles, func(i, j int) bool { return identity.Ledger.BaseFiles[i].File < identity.Ledger.BaseFiles[j].File })
	identity.Ledger.BindingStrategy = BindingStrategy
	return nil
}

// ParseFile extracts one Go file's syntax-only ledger entries and header
// identity from its bytes.
func ParseFile(name string, content []byte) ([]TestVariantDeclaration, TestVariantFileHeader, error) {
	return parseTestVariantFile(name, content)
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
	return hex.EncodeToString(hasher.Sum(nil)[:16])
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
			hash := shortContentHex(content[start:end])
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
			var governingConstRefs []string
			for si, spec := range decl.Specs {
				specStart, specEnd := start, end
				if decl.Lparen.IsValid() {
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
					hash = positionalDigest(content[specStart:specEnd], si)
				case token.VAR:
					hash = positionalDigest(content[specStart:specEnd], varOrdinal)
					varOrdinal++
				default:
					hash = shortContentHex(content[specStart:specEnd])
				}
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					declarations = append(declarations, TestVariantDeclaration{File: name, Kind: kind, Name: spec.Name.Name, Hash: hash, References: referencedNames(spec), Package: file.Name.Name})
				case *ast.ValueSpec:
					references := referencedNames(spec)
					if decl.Tok == token.CONST {
						if len(spec.Values) > 0 {
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
				Hash: shortContentHex([]byte(text)), Package: file.Name.Name,
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
	header := TestVariantFileHeader{File: name, Hash: hex.EncodeToString(remainder.Sum(nil)[:16])}
	header.Bindings = &TestVariantFileBindings{Package: file.Name.Name}
	for _, d := range declarations {
		header.Bindings.References = mergedNames(header.Bindings.References, d.References)
	}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return nil, TestVariantFileHeader{}, err
		}
		local := ""
		if imp.Name != nil {
			local = imp.Name.Name
		}
		header.Bindings.Imports = append(header.Bindings.Imports, TestVariantImport{Name: local, Path: path})
	}
	sort.Slice(header.Bindings.Imports, func(i, j int) bool {
		a, b := header.Bindings.Imports[i], header.Bindings.Imports[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Path < b.Path
	})
	return declarations, header, nil
}
