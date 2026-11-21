package gotool

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// PackageClass is the mutability class of one graph package's source, the
// same discrimination the closure hash applies to its contributions:
// standard-library source rides the toolchain guard, module-cache source is
// pinned by its version, and everything else — main module, local replace,
// workspace sibling, vendored copy — is mutable-local and must be observed by
// content on every pass (REQ-closure-mutable-local, REQ-closure-pinned-dep).
type PackageClass int

const (
	MutableLocalPackage PackageClass = iota
	StandardPackage
	PinnedPackage
)

// GraphPackage is one node of a view's test-binary package graph as the
// metadata listing names it: enough identity to classify, key, and walk the
// graph without loading any syntax.
type GraphPackage struct {
	// ImportPath is the listing identity; a test-variant recompilation
	// carries the bracket suffix ("p [p.test]").
	ImportPath string
	// PkgPath is the import path the type checker reports for the node —
	// ImportPath with any variant suffix stripped.
	PkgPath string
	// ForTest names the tested package for a test-variant node, "" otherwise.
	ForTest string
	// TestMain marks the toolchain-generated test main package.
	TestMain bool
	// Imports are the node's resolved import identities (listing form).
	Imports []string
	// Class is the node's source-mutability class.
	Class PackageClass
	// Pin is the module-cache-relative module directory ("modpath@version",
	// replace-correct) for a PinnedPackage — the same identity the closure
	// hash pins the module by. Empty otherwise.
	Pin string
}

// ListedPackage is one `go list -json -deps -test` node.
type ListedPackage struct {
	ImportPath   string
	Name         string
	Standard     bool
	Dir          string
	GoFiles      []string
	CgoFiles     []string
	CgoCFLAGS    []string
	CgoCPPFLAGS  []string
	CgoCXXFLAGS  []string
	CgoFFLAGS    []string
	CgoPkgConfig []string
	CFiles       []string
	CXXFiles     []string
	MFiles       []string
	HFiles       []string
	FFiles       []string
	SFiles       []string
	SwigFiles    []string
	SwigCXXFiles []string
	SysoFiles    []string
	EmbedFiles   []string
	// The embed patterns of the package and its test variants: the
	// listing memo records the trees they resolve over.
	EmbedPatterns      []string
	TestEmbedPatterns  []string
	XTestEmbedPatterns []string
	CgoLDFLAGS         []string
	Imports            []string
	Deps               []string
	ForTest            string
	Module             *ListedModule
	Error              *ListedError
}

// SourcePath is the package's source import path. Go list decorates build
// copies for test binaries and PGO mains; ForTest names only the former.
// The decorated ImportPath remains the graph identity of each build copy.
func (p ListedPackage) SourcePath() string {
	path, _, _ := strings.Cut(p.ImportPath, " [")
	return path
}

// IsGeneratedTestMainFor reports the toolchain-generated test main of
// pkgPath's test binary.
func (p ListedPackage) IsGeneratedTestMainFor(pkgPath string) bool {
	return p.Name == "main" && p.ImportPath == pkgPath+".test"
}

// OwnVariantOf reports whether p is pkgPath's own test-variant node — the
// in-package variant (pkg [pkg.test]) or the external test package
// (pkg_test [pkg.test]) — as opposed to a dependency recompiled against the
// test binary, which keeps its core contribution. Both own variants compile
// from the base package's directory, so baseDir disambiguates a real
// dependency package whose import path happens to end in "_test" (a legal
// directory name): recompiled against the test variant it shares the base's
// suffixed import path but never its directory.
func (p ListedPackage) OwnVariantOf(pkgPath, baseDir string) bool {
	if p.ForTest != pkgPath || p.IsGeneratedTestMainFor(pkgPath) {
		return false
	}
	if baseDir != "" && p.Dir != baseDir {
		return false
	}
	base := strings.TrimSuffix(p.ImportPath, " ["+pkgPath+".test]")
	return base == pkgPath || base == pkgPath+"_test"
}

// ListedModule is a listed node's module identity.
type ListedModule struct {
	Path    string
	Version string
	Dir     string
	GoMod   string
	Main    bool
	Replace *ListedModule
}

// ListedError is go list's per-package load failure.
type ListedError struct {
	Err string
}

// SourceFiles is every compiled/linked input of the package: a change to any of
// these can move the benchmark's behavior, so all must be hashed (REQ-fresh-sound).
// Keep this in lockstep with go list's file-kind fields (TestPropSourceFilesComplete).
func (p ListedPackage) SourceFiles() []string {
	var f []string
	for _, set := range [][]string{
		p.GoFiles, p.CgoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.FFiles,
		p.SFiles, p.SwigFiles, p.SwigCXXFiles, p.SysoFiles, p.EmbedFiles,
	} {
		f = append(f, set...)
	}
	return f
}

// ParseListing decodes a `go list -json` stream until io.EOF, refusing
// non-object JSON values, stray closing delimiters, malformed JSON, and any
// node carrying a per-package load error so surviving packages can never
// silently under-cover the closure (REQ-fresh-sound).
func ParseListing(r io.Reader) ([]ListedPackage, error) {
	dec := json.NewDecoder(r)
	var pkgs []ListedPackage
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if err == io.EOF {
				return pkgs, nil
			}
			return nil, fmt.Errorf("closure: decode go list: %w", err)
		}
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			return nil, fmt.Errorf("closure: decode go list: expected JSON object")
		}
		var p ListedPackage
		if err := json.Unmarshal(trimmed, &p); err != nil {
			return nil, fmt.Errorf("closure: decode go list: %w", err)
		}
		if p.Error != nil {
			return nil, fmt.Errorf("closure: package %s failed to load: %s", p.ImportPath, p.Error.Err)
		}
		pkgs = append(pkgs, p)
	}
}

// UniqueStrings keeps the first occurrence of every value, in order.
func UniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := values[:0]
	for _, v := range values {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
