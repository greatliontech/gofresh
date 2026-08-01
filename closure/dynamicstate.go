package closure

import (
	"encoding/json"
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

// GraphMetadata returns the deduplicated test-binary package graphs of
// pkgPaths from the metadata listing — the same listing the closure hash
// walks, so classification here and classification there cannot disagree.
func (h *Hasher) GraphMetadata(pkgPaths ...string) ([]GraphPackage, error) {
	var nodes []GraphPackage
	seen := map[string]bool{}
	for _, pkgPath := range pkgPaths {
		pkgs, err := h.list(pkgPath)
		if err != nil {
			return nil, err
		}
		for _, p := range pkgs {
			if err := h.contextErr(); err != nil {
				return nil, err
			}
			if seen[p.ImportPath] {
				continue
			}
			seen[p.ImportPath] = true
			node := GraphPackage{
				ImportPath: p.ImportPath,
				PkgPath:    p.ImportPath,
				ForTest:    p.ForTest,
				Imports:    append([]string(nil), p.Imports...),
			}
			if i := strings.Index(node.PkgPath, " ["); i >= 0 {
				node.PkgPath = node.PkgPath[:i]
			}
			if p.Name == "main" && strings.HasSuffix(p.ImportPath, ".test") {
				node.TestMain = true
			}
			switch {
			case p.Standard || p.Module == nil:
				node.Class = StandardPackage
			case h.pinnedPackage(&p):
				node.Class = PinnedPackage
				node.Pin = h.modulePin(p.Module)
			default:
				node.Class = MutableLocalPackage
			}
			nodes = append(nodes, node)
		}
	}
	return nodes, nil
}

// The dynamic-state fact memo is the observability memo's sibling: facts for
// version-pinned packages are pure functions of their key — the caller's
// scope (fact-strategy version and code guards) plus the module pin and the
// import-cone version signature — so a hit is fact-equivalent to
// recomputation and any miss, corruption, or mismatch recomputes silently
// (cache-never-record, REQ-closure-dynamic-state-memo). Entries batch per
// (scope, bucket): one file holds every package fact of one pinned module.

// dynamicStateDirName is the dynamic-state memo's sibling user-cache
// directory under the shared cache-file mechanism.
const dynamicStateDirName = "dynamicstate"

// LoadDynamicStateFacts returns the persisted facts for (scope, bucket) by
// package path — nil on any failure; the key IS the freshness, so no entry
// is trusted beyond it.
func LoadDynamicStateFacts(scope, bucket string) map[string]json.RawMessage {
	if scope == "" {
		return nil
	}
	var facts map[string]json.RawMessage
	if !loadCacheEntry(dynamicStateDirName, scope, bucket, &facts) {
		return nil
	}
	return facts
}

// StoreDynamicStateFacts merges facts into the (scope, bucket) entry with an
// atomic replace; failures are silent — a lost store costs one
// recomputation, never a wrong fact.
func StoreDynamicStateFacts(scope, bucket string, facts map[string]json.RawMessage) {
	if scope == "" {
		return
	}
	mergeCacheEntry(dynamicStateDirName, scope, bucket, facts)
}
