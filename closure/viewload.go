package closure

import (
	"context"
	"errors"
	"fmt"

	"github.com/greatliontech/gofresh/internal/buildflags"
	"github.com/greatliontech/gofresh/internal/processenv"
	"golang.org/x/tools/go/packages"
)

// ViewLoad is one typed load of an analysis view's packages: syntax, types,
// and module identity for the view's package variants and their dependency
// graph. Every consumer inside one observation pass that needs typed source —
// the subject scan and the testing-type effect scan — reads this one load, so
// no two derivations of the same pass can straddle an edit
// (REQ-fresh-coherent-view: never a mixture of generations inside one view).
type ViewLoad struct {
	pkgs []*packages.Package
}

// Packages returns the load's root packages: the requested packages' build
// variants. The graph beneath them is reachable through Imports. Read-only.
func (v *ViewLoad) Packages() []*packages.Package {
	if v == nil {
		return nil
	}
	return v.pkgs
}

// LoadViewPackagesEnv performs the single typed load of one observation pass
// under the caller's complete immutable environment and executable build
// flags — the same selection discipline as every other load of the view
// (REQ-closure-analysis).
func LoadViewPackagesEnv(ctx context.Context, dir string, env, buildFlags []string, pkgPaths ...string) (*ViewLoad, error) {
	if ctx == nil {
		return nil, errors.New("closure: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: view load cancelled: %w", err)
	}
	normalized, err := processenv.Normalize(env)
	if err != nil {
		return nil, fmt.Errorf("closure: %w", err)
	}
	packageEnv, err := processenv.ForGoPackages(normalized)
	if err != nil {
		return nil, fmt.Errorf("closure: %w", err)
	}
	if err := buildflags.ValidateEnv(ctx, dir, normalized, buildFlags); err != nil {
		return nil, err
	}
	cfg := &packages.Config{
		Context: ctx,
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedImports | packages.NeedDeps | packages.NeedModule | packages.NeedForTest,
		Tests:      true,
		Dir:        dir,
		Env:        append([]string(nil), packageEnv...),
		BuildFlags: append([]string(nil), buildFlags...),
	}
	pkgs, err := packages.Load(cfg, pkgPaths...)
	if err != nil {
		return nil, err
	}
	return &ViewLoad{pkgs: pkgs}, nil
}
