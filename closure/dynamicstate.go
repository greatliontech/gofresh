package closure

import (
	"strings"

	"github.com/greatliontech/gofresh/internal/dynstate"
)

// PackageClass is the mutability class of one graph package's source, the
// same discrimination the closure hash applies to its contributions:
// standard-library source rides the toolchain guard, module-cache source is
// pinned by its version, and everything else — main module, local replace,
// workspace sibling, vendored copy — is mutable-local and must be observed by
// content on every pass (REQ-closure-mutable-local, REQ-closure-pinned-dep).
type PackageClass = dynstate.PackageClass

const (
	MutableLocalPackage = dynstate.MutableLocalPackage
	StandardPackage     = dynstate.StandardPackage
	PinnedPackage       = dynstate.PinnedPackage
)

// GraphPackage is one node of a view's test-binary package graph as the
// metadata listing names it: enough identity to classify, key, and walk the
// graph without loading any syntax.
type GraphPackage = dynstate.GraphPackage

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
				PkgPath:    p.SourcePath(),
				ForTest:    p.ForTest,
				Imports:    append([]string(nil), p.Imports...),
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
