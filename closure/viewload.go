package closure

import (
	"context"
	"errors"
	"fmt"

	"github.com/greatliontech/gofresh/internal/buildflags"
	"github.com/greatliontech/gofresh/internal/gotool"
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
	return LoadViewPackagesEnvSnapshot(ctx, dir, env, buildFlags, nil, pkgPaths...)
}

// LoadViewPackagesEnvSnapshot is LoadViewPackagesEnv validating GOFLAGS from
// the pass's one env snapshot when non-nil.
func LoadViewPackagesEnvSnapshot(ctx context.Context, dir string, env, buildFlags []string, snapshot *gotool.EnvSnapshot, pkgPaths ...string) (*ViewLoad, error) {
	// Roots-only syntax: dependency types come from export data. Every
	// consumer needing dependency-graph syntax names its packages as
	// patterns (the view path adds mutable-local graph packages;
	// version-pinned facts ride the dynamic-state memo instead of a load,
	// REQ-closure-dynamic-state-memo).
	return loadView(ctx, dir, env, buildFlags, snapshot, false, pkgPaths...)
}

// LoadViewGraphEnv is LoadViewPackagesEnv with whole-graph syntax: every
// dependency of the patterns is source-loaded too. Reserved for the shapes a
// roots-only load cannot express — a test-cycle intermediate recompilation
// ("r [a.test]") exists only inside a test binary's graph, so its syntax is
// reachable solely through a dependency-expanded load of the tested package.
func LoadViewGraphEnv(ctx context.Context, dir string, env, buildFlags []string, pkgPaths ...string) (*ViewLoad, error) {
	return loadView(ctx, dir, env, buildFlags, nil, true, pkgPaths...)
}

func loadView(ctx context.Context, dir string, env, buildFlags []string, snapshot *gotool.EnvSnapshot, deps bool, pkgPaths ...string) (*ViewLoad, error) {
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
	if err := buildflags.ValidateEnvSnapshot(ctx, dir, normalized, buildFlags, snapshot); err != nil {
		return nil, err
	}
	mode := packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
		packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo |
		packages.NeedImports | packages.NeedModule | packages.NeedForTest
	if deps {
		mode |= packages.NeedDeps
	}
	cfg := &packages.Config{
		Context:    ctx,
		Mode:       mode,
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
