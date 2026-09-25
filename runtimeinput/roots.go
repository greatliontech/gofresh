package runtimeinput

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/greatliontech/gofresh/gotool"
)

// The classification roots a producing run's reads classify under are
// facts of the run's own environment, not declarations: the toolchain
// reports GOROOT, GOMODCACHE, GOCACHE, and GOTMPDIR for exactly the
// environment and package directory the process ran in, and the temp
// root is what the process's os.TempDir resolved. The facade resolves them once per
// (package directory, environment) and the caller declares nothing —
// except a per-run scratch root it minted and keeps out of the recorded
// environment, which no environment read can reveal
// (REQ-inputs-guard-covered, REQ-inputs-ephemeral-root,
// REQ-inputs-producer-facade).

// resolvedRoots are one environment's classification roots; an empty
// field declares no root of that class.
type resolvedRoots struct {
	toolchain, moduleCache, buildCache, temp string
	// goTemp is the go command's own temp root, GOTMPDIR as the
	// toolchain answers it (the environment's, else the go env
	// file's): the directory the testing package mints its per-test
	// directories under and the command its per-invocation work
	// trees, both of which fall back to the process temp root only
	// while the setting is empty. An ephemeral root exactly as the
	// temp root is.
	goTemp string
}

// ephemeralRoots lists the temp roots a run's reads classify under as
// ephemeral, each under the in-tree degrade: the process temp root —
// the scratch root a producer minted where it declares one, else
// what the run's os.TempDir resolved — and the go command's own where
// it is set and differs.
func (r resolvedRoots) ephemeralRoots(scratch, treeRoot string) []string {
	temp := scratch
	if temp == "" {
		temp = r.temp
	}
	var roots []string
	if temp = usableTempRoot(temp, treeRoot); temp != "" {
		roots = append(roots, temp)
	}
	if goTemp := usableTempRoot(r.goTemp, treeRoot); goTemp != "" && goTemp != temp {
		roots = append(roots, goTemp)
	}
	return roots
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
// the go command's temp root as it reports that, and the temp root as
// the run's os.TempDir resolved. A toolchain that
// cannot answer is an error the caller fails closed on.
func resolveRoots(ctx context.Context, runner gotool.Runner, treeRoot, pkgDir string, env []string) (resolvedRoots, error) {
	key := rootsCacheKey(pkgDir, env)
	if cached, ok := rootsCache.Load(key); ok {
		return cached.(resolvedRoots), nil
	}
	// The document form: one answer shape, one wholeness test — a
	// document that parses to its four keys. The answer a cleanly
	// exited process wrote beside a descendant's pipe hold serves when
	// it is that document (a banner glued before it, or a torn tail,
	// parses as nothing); a torn one refuses with the hold named.
	out, err := runner.Run(ctx, pkgDir, env, "env", "-json", "GOROOT", "GOMODCACHE", "GOCACHE", "GOTMPDIR")
	if err != nil && !gotool.Salvaged(ctx, err) {
		return resolvedRoots{}, err
	}
	values, parseErr := gotool.ParseEnvDocument(out)
	if parseErr == nil {
		// Every requested key is answered, an unset one as the empty
		// value the guard degrades to none; a document missing a key is
		// no answer to this probe, the earliest missing key named.
		for _, key := range []string{"GOROOT", "GOMODCACHE", "GOCACHE", "GOTMPDIR"} {
			if _, answered := values[key]; !answered {
				parseErr = fmt.Errorf("go env -json answered no %s", key)
				break
			}
		}
	}
	if parseErr != nil {
		if err != nil {
			return resolvedRoots{}, err
		}
		return resolvedRoots{}, parseErr
	}
	roots := resolvedRoots{
		toolchain:   usableGuardRootOutside(values["GOROOT"], treeRoot),
		moduleCache: usableGuardRootOutside(values["GOMODCACHE"], treeRoot),
		buildCache:  usableGuardRootOutside(values["GOCACHE"], treeRoot),
		temp:        tempRootFromEnv(env),
		goTemp:      usableGuardRoot(values["GOTMPDIR"]),
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
	if v, ok := gotool.LookupEnv(env, "TMPDIR"); ok && v != "" {
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
