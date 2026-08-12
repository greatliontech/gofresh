// Package listing parses `go list -json -deps -test` output into the
// dependency graph the closure analyses consume.
package listing

import (
	"encoding/json"
	"fmt"
	"io"
)

// Package is one go-list node.
type Package struct {
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
	CgoLDFLAGS   []string
	Imports      []string
	ForTest      string
	Module       *Module
	Error        *Error
}

// IsGeneratedTestMainFor reports the toolchain-generated test main of
// pkgPath's test binary.
func (p Package) IsGeneratedTestMainFor(pkgPath string) bool {
	return p.Name == "main" && p.ImportPath == pkgPath+".test"
}

// Module is a node's module identity.
type Module struct {
	Path    string
	Version string
	Dir     string
	Main    bool
	Replace *Module
}

// Error is go list's per-package load failure.
type Error struct {
	Err string
}

// SourceFiles is every compiled/linked input of the package: a change to any of
// these can move the benchmark's behavior, so all must be hashed (REQ-fresh-sound). Keep
// this in lockstep with go list's file-kind fields (TestPropSourceFilesComplete).
func (p Package) SourceFiles() []string {
	var f []string
	for _, set := range [][]string{
		p.GoFiles, p.CgoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.FFiles,
		p.SFiles, p.SwigFiles, p.SwigCXXFiles, p.SysoFiles, p.EmbedFiles,
	} {
		f = append(f, set...)
	}
	return f
}

// Parse decodes a go list -json stream. A node carrying a load error fails
// the whole parse: hashing the surviving packages would silently
// under-cover the closure — false-valid (REQ-fresh-sound).
func Parse(r io.Reader) ([]Package, error) {
	dec := json.NewDecoder(r)
	var pkgs []Package
	for dec.More() {
		var p Package
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("closure: decode go list: %w", err)
		}
		if p.Error != nil {
			return nil, fmt.Errorf("closure: package %s failed to load: %s", p.ImportPath, p.Error.Err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
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
