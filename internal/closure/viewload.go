package closure

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/trace"
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

// LoadViewPackages performs the single typed load of one observation pass
// under the caller's complete immutable environment and executable build
// flags — the same selection discipline as every other load of the view
// (REQ-closure-analysis). GOFLAGS validates from the reader's one
// snapshot.
func LoadViewPackages(ctx context.Context, reader *gotool.EnvReader, buildFlags []string, pkgPaths ...string) (*ViewLoad, error) {
	// Roots-only syntax: dependency types come from export data. Every
	// consumer needing dependency-graph syntax names its packages as
	// patterns (the view path adds mutable-local graph packages;
	// version-pinned facts ride the dynamic-state memo instead of a load,
	// REQ-closure-dynamic-state-memo).
	return loadView(ctx, reader, buildFlags, false, pkgPaths...)
}

// LoadViewGraph is LoadViewPackages with whole-graph syntax: every
// dependency of the patterns is source-loaded too. Reserved for the shapes
// a roots-only load cannot express — a test-cycle intermediate
// recompilation ("r [a.test]") exists only inside a test binary's graph, so
// its syntax is reachable solely through a dependency-expanded load of the
// tested package, and ExplainDynamicState walks cross-package dependency syntax.
func LoadViewGraph(ctx context.Context, reader *gotool.EnvReader, buildFlags []string, pkgPaths ...string) (*ViewLoad, error) {
	return loadView(ctx, reader, buildFlags, true, pkgPaths...)
}

func loadView(ctx context.Context, reader *gotool.EnvReader, buildFlags []string, deps bool, pkgPaths ...string) (*ViewLoad, error) {
	if ctx == nil {
		return nil, errors.New("closure: nil context")
	}
	if reader == nil {
		return nil, errors.New("closure: nil environment reader")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: view load cancelled: %w", err)
	}
	dir := reader.Dir
	normalized, err := gotool.NormalizeEnv(reader.Env)
	if err != nil {
		return nil, fmt.Errorf("closure: %w", err)
	}
	packageEnv, err := gotool.EnvForPackages(normalized)
	if err != nil {
		return nil, fmt.Errorf("closure: %w", err)
	}
	if err := gotool.ValidateBuildFlags(ctx, reader, buildFlags); err != nil {
		return nil, err
	}
	mode := packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
		packages.NeedEmbedFiles | packages.NeedEmbedPatterns |
		packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo |
		packages.NeedImports | packages.NeedModule | packages.NeedForTest
	if deps {
		mode |= packages.NeedDeps
	}
	target := ""
	if len(pkgPaths) > 0 {
		target = pkgPaths[0]
	}
	tracing := trace.Enabled(ctx, trace.DomainClosure, target)
	var start time.Time
	if tracing {
		start = time.Now()
	}
	pkgs, err := gotool.LoadPackages(ctx, mode, dir, packageEnv, buildFlags, pkgPaths...)
	if tracing {
		trace.Emit(ctx, trace.DomainClosure, "viewload.packages.done", target,
			trace.Int("patterns", len(pkgPaths)),
			trace.Int("packages", len(pkgs)),
			trace.Bool("deps", deps),
			trace.Int64("elapsed_ns", time.Since(start).Nanoseconds()),
			trace.Err(err),
		)
	}
	if err != nil {
		return nil, err
	}
	return &ViewLoad{pkgs: pkgs}, nil
}

// LoadedPackageDirs resolves p's effective package directory and module
// directory across GoFiles, OtherFiles, EmbedFiles, and Module.Replace.
func LoadedPackageDirs(p *packages.Package) (pkgDir, modDir string) {
	if p == nil {
		return "", ""
	}
	if p.Module != nil {
		modDir = p.Module.Dir
		if p.Module.Replace != nil && p.Module.Replace.Dir != "" {
			modDir = p.Module.Replace.Dir
		}
	}
	pkgDir = p.Dir
	if pkgDir == "" && len(p.GoFiles) > 0 {
		pkgDir = filepath.Dir(p.GoFiles[0])
	}
	if pkgDir == "" && len(p.OtherFiles) > 0 {
		pkgDir = filepath.Dir(p.OtherFiles[0])
	}
	if pkgDir == "" && len(p.EmbedFiles) > 0 {
		pkgDir = filepath.Dir(p.EmbedFiles[0])
	}
	if pkgDir == "" {
		pkgDir = modDir
	}
	return pkgDir, modDir
}

// ClassifyLoadedPackage classifies p into StandardPackage, PinnedPackage, or
// MutableLocalPackage under modCache, returning the module-cache-relative pin
// identity when pinned.
func ClassifyLoadedPackage(p *packages.Package, modCache string) (PackageClass, string) {
	if p == nil || p.Module == nil {
		return StandardPackage, ""
	}
	pkgDir, modDir := LoadedPackageDirs(p)
	if !p.Module.Main && ((pkgDir == "" && modCache == "") || IsPinnedPackageDir(false, pkgDir, modCache)) {
		pin := ""
		if modDir != "" && modCache != "" {
			pin = filepath.ToSlash(strings.TrimPrefix(filepath.Clean(modDir), filepath.Clean(modCache)+string(filepath.Separator)))
		}
		return PinnedPackage, pin
	}
	return MutableLocalPackage, ""
}

// ClassifyLoadedPackage classifies p under h's module cache.
func (h *Hasher) ClassifyLoadedPackage(p *packages.Package) (PackageClass, string) {
	if h == nil {
		return ClassifyLoadedPackage(p, "")
	}
	return ClassifyLoadedPackage(p, h.modCache)
}
