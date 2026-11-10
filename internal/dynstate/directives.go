// Package dynstate derives per-package dynamic-state facts (FactOf,
// FactOfWithHooks) over a single precomputed refconfine.PkgIndex and composes
// them across test-binary dependency cones (Compose, NewDeferralResolution,
// ResolveEnvAudit, BlockedExportedSeams, CarrierLinkGraph).
package dynstate

import (
	"fmt"
	"go/ast"
	"go/types"
	"path/filepath"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// MethodDirectives resolves a promoted method's purity and externality
// directives from its declaring package's fact inside the view package's
// own cone — the declaration keys, empty when absent.
func MethodDirectives(cones map[string]map[string][]Fact, viewPackage string, m *types.Func) (pureKey, externalKey string) {
	if cones == nil || m == nil || m.Pkg() == nil {
		return "", ""
	}
	recvName := syntaxutil.MethodRecvNamedTypeName(m)
	if recvName == "" {
		return "", ""
	}
	key := recvName + "." + m.Name()
	for _, fact := range cones[viewPackage][m.Pkg().Path()] {
		if pureKey == "" {
			pureKey = fact.PureMethods[key]
		}
		if externalKey == "" {
			externalKey = fact.ExternalMethods[key]
		}
	}
	return pureKey, externalKey
}

// ScannedSymbol is one symbol sighting emitted by WalkLoadedSubjects.
type ScannedSymbol struct {
	Package     string
	Symbol      string
	Declaration string
	Pure        bool
	External    bool
	OpenWorld   string
}

// WalkLoadedSubjects enumerates every function and promoted method subject
// across pkgs for the requested pkgPaths, checking directive conflicts and
// computing open-world signature terms when computeOpenWorld is true
// (REQ-fresh-coherent-view, REQ-purity-directive, REQ-external-precedence).
func WalkLoadedSubjects(audited, computeOpenWorld bool, pkgs []*packages.Package, cones map[string]map[string][]Fact, pkgPaths []string, visit func(ScannedSymbol)) error {
	requestedPackages := make(map[string]bool, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		requestedPackages[pkgPath] = true
	}
	var scanErr error
	for _, p := range pkgs {
		if p == nil {
			continue
		}
		pkgPath := p.PkgPath
		if p.ForTest != "" && (p.PkgPath == p.ForTest || p.PkgPath == p.ForTest+"_test") {
			pkgPath = p.ForTest
		}
		if requestedPackages[pkgPath] {
			for _, f := range p.Syntax {
				if f == nil {
					continue
				}
				initOrdinal := 0
				for _, decl := range f.Decls {
					fd, ok := decl.(*ast.FuncDecl)
					if !ok || fd.Name == nil {
						continue
					}
					sym := fd.Name.Name
					if recv := syntaxutil.RecvTypeName(fd); recv != "" {
						sym = recv + "." + sym
					} else if fd.Recv != nil {
						continue
					} else if sym == "init" {
						if p.Fset == nil {
							continue
						}
						sym = fmt.Sprintf("init#%s#%d", filepath.Base(p.Fset.PositionFor(f.Pos(), false).Filename), initOrdinal)
						initOrdinal++
					}
					declKey := syntaxutil.NodeDeclarationKey(p, fd.Name)
					isPure := syntaxutil.HasDirective(fd.Doc, "//gofresh:pure")
					isExternal := syntaxutil.HasDirective(fd.Doc, "//gofresh:external")
					if isPure && isExternal && scanErr == nil {
						scanErr = fmt.Errorf("gofresh: %s carries both //gofresh:pure and //gofresh:external", declKey)
					}
					var term string
					if computeOpenWorld && p.TypesInfo != nil && p.TypesInfo.Defs != nil {
						if fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func); ok {
							if sig, ok := fn.Type().(*types.Signature); ok {
								term = refconfine.OpenWorldTerm(audited, sig)
							}
						}
					}
					visit(ScannedSymbol{
						Package:     pkgPath,
						Symbol:      sym,
						Declaration: declKey,
						Pure:        isPure,
						External:    isExternal,
						OpenWorld:   term,
					})
				}
			}
		}
		if p.Types == nil || !requestedPackages[pkgPath] {
			continue
		}
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			typeName, ok := scope.Lookup(name).(*types.TypeName)
			if !ok {
				continue
			}
			for _, methods := range []*types.MethodSet{
				types.NewMethodSet(types.NewPointer(typeName.Type())),
				types.NewMethodSet(typeName.Type()),
			} {
				for i := 0; i < methods.Len(); i++ {
					method, ok := methods.At(i).Obj().(*types.Func)
					if !ok {
						continue
					}
					var term string
					if computeOpenWorld {
						if sig, ok := method.Type().(*types.Signature); ok {
							term = refconfine.OpenWorldTerm(audited, sig)
						}
					}
					pureKey, externalKey := MethodDirectives(cones, pkgPath, method)
					if pureKey != "" && externalKey != "" && scanErr == nil {
						scanErr = fmt.Errorf("gofresh: %s carries both //gofresh:pure and //gofresh:external", pureKey)
					}
					visit(ScannedSymbol{
						Package:     pkgPath,
						Symbol:      name + "." + method.Name(),
						Declaration: syntaxutil.ObjectDeclarationKey(p, method),
						Pure:        pureKey != "",
						External:    externalKey != "",
						OpenWorld:   term,
					})
				}
			}
		}
	}
	return scanErr
}
