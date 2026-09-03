package runtimeinput

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/processenv"
)

// The classification roots a producing run's reads classify under are
// facts of the run's own environment, not declarations: the toolchain
// reports GOROOT, GOMODCACHE, and GOCACHE for exactly the environment
// and package directory the process ran in, and the temp root is what
// the process's os.TempDir resolved. The facade resolves them once per
// (package directory, environment) and the caller declares nothing —
// except a per-run scratch root it minted and keeps out of the recorded
// environment, which no environment read can reveal
// (REQ-inputs-guard-covered, REQ-inputs-ephemeral-root,
// REQ-inputs-producer-facade).

// resolvedRoots are one environment's classification roots; an empty
// field declares no root of that class.
type resolvedRoots struct {
	toolchain, moduleCache, buildCache, temp string
}

// rootsCache memoizes resolutions per (package directory, environment)
// for the process's lifetime: a producer ingests many runs under one
// environment. The key is the whole environment less PWD — which the
// facade has already required to name the package directory — so no
// setting the toolchain consults can be left out of it; a producer that
// injects a per-run value into the environment it ingests pays one
// toolchain query per run and one entry per value.
var rootsCache sync.Map

func rootsCacheKey(pkgDir string, env []string) string {
	var key strings.Builder
	key.WriteString(pkgDir)
	for _, entry := range env {
		if name, _, _ := strings.Cut(entry, "="); name == "PWD" {
			continue
		}
		key.WriteString("\x00" + entry)
	}
	return key.String()
}

// resolveRoots answers the classification roots of a run of pkgDir under
// env: the three guard roots as the toolchain reports them — each
// declaring nothing when it lies inside, equals, or contains the tree —
// and the temp root as the run's os.TempDir resolved. A toolchain that
// cannot answer is an error the caller fails closed on.
func resolveRoots(ctx context.Context, treeRoot, pkgDir string, env []string) (resolvedRoots, error) {
	key := rootsCacheKey(pkgDir, env)
	if cached, ok := rootsCache.Load(key); ok {
		return cached.(resolvedRoots), nil
	}
	out, err := gotool.RunInContextEnv(ctx, pkgDir, env, "env", "GOROOT", "GOMODCACHE", "GOCACHE")
	if err != nil {
		return resolvedRoots{}, err
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(lines) != 3 {
		return resolvedRoots{}, fmt.Errorf("go env returned %d values, want 3", len(lines))
	}
	roots := resolvedRoots{
		toolchain:   usableGuardRootOutside(strings.TrimRight(lines[0], "\r"), treeRoot),
		moduleCache: usableGuardRootOutside(strings.TrimRight(lines[1], "\r"), treeRoot),
		buildCache:  usableGuardRootOutside(strings.TrimRight(lines[2], "\r"), treeRoot),
		temp:        tempRootFromEnv(env),
	}
	rootsCache.Store(key, roots)
	return roots, nil
}

// usableGuardRootOutside additionally degrades a guard root that lies
// inside, equals, or contains the tree — in its given or resolved form —
// to none: such a root would admit reads of the tree's own content as
// guard-covered, vacating the observation the bracket exists to make,
// while its absence only costs re-observation.
func usableGuardRootOutside(root, treeRoot string) string {
	root = usableGuardRoot(root)
	if root == "" {
		return ""
	}
	for _, form := range []string{root, resolveOrSelf(root)} {
		for _, tree := range []string{treeRoot, resolveOrSelf(treeRoot)} {
			if contains(form, tree) || contains(tree, form) {
				return ""
			}
		}
	}
	return root
}

// contains reports whether path equals dir or lies beneath it.
func contains(dir, path string) bool {
	if dir == path {
		return true
	}
	if dir == string(filepath.Separator) {
		return filepath.IsAbs(path)
	}
	return strings.HasPrefix(path, dir+string(filepath.Separator))
}

// usableGuardRoot returns root cleaned when it can serve as a guard
// root, and "" — no root of that class — when it cannot: an unset
// setting, one that is not an absolute path (a disabled cache reports
// "off"), or a path with a ".." component, which is refused outright
// rather than cleaned because lexical elimination across a symlink can
// rebind it to a directory no guard pins. Absence of a root costs
// re-observation, never soundness.
func usableGuardRoot(root string) string {
	if root == "" {
		return ""
	}
	for _, seg := range strings.Split(filepath.ToSlash(root), "/") {
		if seg == ".." {
			return ""
		}
	}
	cleaned := filepath.Clean(root)
	if !filepath.IsAbs(cleaned) {
		return ""
	}
	return cleaned
}

// tempRootFromEnv resolves the producing environment's temp root the way
// the run's os.TempDir did: TMPDIR when set, the platform default
// otherwise. Windows runs ignore TMPDIR (the temp path is per-process)
// and plan9 stays undeclared, so neither declares a root.
func tempRootFromEnv(env []string) string {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		return ""
	}
	if v, ok := processenv.Lookup(env, "TMPDIR"); ok && v != "" {
		return v
	}
	if runtime.GOOS == "android" {
		return "/data/local/tmp"
	}
	return "/tmp"
}

// usableTempRoot degrades a temp root lying inside the tree — in its
// given or resolved form — to none: a module-interior ephemeral root
// would admit reads the bracket exists to observe, and the ingest
// refuses such a declaration loudly, which would fail every observation
// of a producer whose scratch happens to live in-tree, while the absence
// of the root only costs re-observation.
func usableTempRoot(root, treeRoot string) string {
	root = usableGuardRoot(root)
	if root == "" {
		return ""
	}
	// The inside direction only: a temp root containing the tree (/tmp
	// over a checkout under it) is the common case, and the ingest's own
	// module-interior gate keeps in-tree reads observed under it.
	for _, form := range []string{root, resolveOrSelf(root)} {
		for _, tree := range []string{treeRoot, resolveOrSelf(treeRoot)} {
			if contains(tree, form) {
				return ""
			}
		}
	}
	return root
}

// resolveOrSelf resolves path's links through its nearest existing
// ancestor — a root need not exist yet for a link above it to redirect
// it — and returns path itself when nothing of it resolves.
func resolveOrSelf(path string) string {
	rest := ""
	for p := path; ; {
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Join(resolved, rest)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return path
		}
		rest = filepath.Join(filepath.Base(p), rest)
		p = parent
	}
}
