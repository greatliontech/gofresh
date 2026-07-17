// Package closure computes the closure hash (REQ-closure-coverage): a sound fingerprint
// of the source a benchmark exercises, used to decide whether a stored result is
// still valid for HEAD.
//
// Compute is the Tier-2 entry point: reachable mutable-local declarations are
// hashed by source, linked cache modules are pinned by module version, stdlib is
// cut by the toolchain guard, and unresolved source blind spots widen to the
// Tier-1 maximal closure. Soundness (REQ-fresh-sound): the hashed set is always a superset
// of the source able to affect the benchmark — never false-valid.
package closure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/greatliontech/gofresh/internal/buildflags"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/processenv"
)

// Closure is the result of analyzing one benchmark (spec REQ-fresh-sound): the hash of its
// closure, and whether that closure reaches an unhashable external dependence
// (Class B, REQ-closure-blindspot) which makes validity unprovable — `unverifiable` rather than
// `valid`/`stale`. Unverifiable is a check-time verdict; the hash is always
// computed (and recorded at run time, REQ-guard-recompute) regardless.
type Closure struct {
	Hash         string
	Unverifiable bool
	Reason       string // why unverifiable (e.g. "reaches os.Open (file I/O)")
	Widened      bool   // declaration refinement fell back to the maximal package closure
	Unrefinable  bool   // refinement cannot prove this opaque maximal dependence absent
}

// Hasher computes closure hashes. New resolves GOMODCACHE once for the
// cache-vs-mutable classification; loaded whole-program SSA is cached per package
// (the dominant cost, REQ-closure-analysis) so repeated per-benchmark Compute calls amortize it.
type Hasher struct {
	// dir roots every package load and go invocation; "" = the process
	// working directory. The analyzed tree is an explicit input.
	dir        string
	modCache   string
	ctx        context.Context
	env        []string
	packageEnv []string
	// buildFlags are the producing go command's executable flags. They select
	// every package and dependency load used to construct this closure.
	buildFlags     []string
	progs          map[string]*program          // by package import path
	progErrs       map[string]error             // memoized load failures, by package import path
	lists          map[string][]listPkg         // parsed `go list -deps -test`, by package import path
	maximalTesting map[string]maximalEffectScan // typed testing-runtime effects by requested package
	maximalEffects map[string]maximalEffectsResult // package external-effect scans by requested package
	maximalFiles   map[string]maximalEffectScan    // per-file effect scans by absolute path
}

func New() (*Hasher, error) { return NewAt("") }

// NewAt builds a Hasher rooted at dir ("" = the process working directory) and
// the producing build's executable flags: every package load and go invocation
// resolves under both, so the analyzed tree and build selection are explicit
// inputs, never implicit cwd or default-build coupling (REQ-closure-analysis).
func NewAt(dir string, buildFlags ...string) (*Hasher, error) {
	return NewAtContext(context.Background(), dir, buildFlags...)
}

// NewAtContext is NewAt with caller-owned cancellation for closure analysis.
func NewAtContext(ctx context.Context, dir string, buildFlags ...string) (*Hasher, error) {
	return NewAtContextEnv(ctx, dir, os.Environ(), buildFlags...)
}

// NewAtContextEnv builds a Hasher using env as the complete immutable process
// environment for package loading, Go commands, and source selection.
func NewAtContextEnv(ctx context.Context, dir string, env []string, buildFlags ...string) (*Hasher, error) {
	if ctx == nil {
		return nil, errors.New("closure: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
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
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	out, err := gotool.RunInContextEnv(ctx, dir, normalized, "env", "GOMODCACHE")
	if err != nil {
		return nil, err
	}
	mc := strings.TrimSpace(string(out))
	if mc == "" {
		return nil, errors.New("closure: empty GOMODCACHE")
	}
	return &Hasher{
		dir: dir, modCache: filepath.Clean(mc), ctx: ctx, env: normalized, packageEnv: packageEnv, buildFlags: append([]string(nil), buildFlags...),
		progs: map[string]*program{}, progErrs: map[string]error{}, lists: map[string][]listPkg{}, maximalTesting: map[string]maximalEffectScan{},
		maximalEffects: map[string]maximalEffectsResult{}, maximalFiles: map[string]maximalEffectScan{},
	}, nil
}

type listPkg struct {
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
	Module       *listMod
	Error        *listErr
}

func (p listPkg) isGeneratedTestMainFor(pkgPath string) bool {
	return p.Name == "main" && p.ImportPath == pkgPath+".test"
}

type listMod struct {
	Path    string
	Version string
	Dir     string
	Main    bool
}

type listErr struct {
	Err string
}

// sourceFiles is every compiled/linked input of the package: a change to any of
// these can move the benchmark's behavior, so all must be hashed (REQ-fresh-sound). Keep
// this in lockstep with go list's file-kind fields (TestPropSourceFilesComplete).
func (p listPkg) sourceFiles() []string {
	var f []string
	for _, set := range [][]string{
		p.GoFiles, p.CgoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.FFiles,
		p.SFiles, p.SwigFiles, p.SwigCXXFiles, p.SysoFiles, p.EmbedFiles,
	} {
		f = append(f, set...)
	}
	return f
}

// maximalHash returns the Tier-1 closure hash for the test binary of pkgPath:
// every non-std reachable package hashed whole. This is the maximal sound closure
// (REQ-closure-floor) and the target every blind spot widens to (REQ-closure-blindspot). It needs no SSA, so
// it also serves as the analysis-failure-free floor.
func (h *Hasher) maximalHash(pkgPath string) (string, error) {
	contribs, _, err := h.maximalContributionsAndFiles(pkgPath)
	if err != nil {
		return "", err
	}
	return hashContributions(pkgPath, contribs)
}

func (h *Hasher) maximalContributions(pkgPath string) ([]string, error) {
	contribs, _, err := h.maximalContributionsAndFiles(pkgPath)
	return contribs, err
}

func (h *Hasher) maximalContributionsAndFiles(pkgPath string) ([]string, []string, error) {
	pkgs, err := h.list(pkgPath)
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]bool{}
	seenFile := map[string]bool{}
	var contribs []string
	var sourceFiles []string
	for _, p := range pkgs {
		if err := h.contextErr(); err != nil {
			return nil, nil, err
		}
		c, files, err := h.contributionAndFilesFor(pkgPath, p)
		if err != nil {
			return nil, nil, err
		}
		if c != "" && !seen[c] {
			seen[c] = true
			contribs = append(contribs, c)
		}
		for _, file := range files {
			if !seenFile[file] {
				seenFile[file] = true
				sourceFiles = append(sourceFiles, file)
			}
		}
	}
	sort.Strings(contribs)
	sort.Strings(sourceFiles)
	return contribs, sourceFiles, nil
}

func (h *Hasher) contextErr() error {
	if h == nil || h.ctx == nil {
		return nil
	}
	if err := h.ctx.Err(); err != nil {
		return fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	return nil
}

func hashContributions(pkgPath string, contribs []string) (string, error) {
	if len(contribs) == 0 {
		return "", fmt.Errorf("closure: %s reaches no non-stdlib source", pkgPath)
	}
	sort.Strings(contribs)
	h := sha256.New()
	for i, contribution := range contribs {
		if i > 0 {
			_, _ = h.Write([]byte{'\n'})
		}
		_, _ = h.Write([]byte(contribution))
	}
	return hex.EncodeToString(h.Sum(nil))[:32], nil
}

// contribution returns this package's contribution to the closure, or "" if it
// is excluded (stdlib, a pseudo-package, or the synthesized test-main).
func (h *Hasher) contribution(p listPkg) (string, error) {
	return h.contributionFor("", p)
}

func (h *Hasher) contributionFor(pkgPath string, p listPkg) (string, error) {
	contribution, _, err := h.contributionAndFilesFor(pkgPath, p)
	return contribution, err
}

func (h *Hasher) contributionAndFilesFor(pkgPath string, p listPkg) (string, []string, error) {
	if p.Standard || p.Module == nil || (pkgPath != "" && p.isGeneratedTestMainFor(pkgPath)) {
		// stdlib cut (REQ-closure-coverage); pseudo-package ("C", whose C source rides in the
		// importing package); or the toolchain-generated test main (boilerplate
		// in a transient dir — deterministic, carries no source information).
		return "", nil, nil
	}
	if !p.Module.Main && h.underCache(p.Dir) {
		// Immutable, version-locked cache dep (classified on the package Dir per
		// REQ-closure-mutable-local): pin once by the module's content dir (modpath@version,
		// replace-correct via Module.Dir), never read its source. p.Dir and
		// Module.Dir agree on under-cache classification for every reachable config;
		// REQ-closure-mutable-local names the package Dir, so we use it.
		rel := strings.TrimPrefix(filepath.Clean(p.Module.Dir), h.modCache+string(filepath.Separator))
		return "cache:" + filepath.ToSlash(rel), nil, nil
	}
	// Mutable-local (main module, local replace, workspace, vendor): hash content
	// so a silent edit moves the hash (REQ-closure-mutable-local).
	files := p.sourceFiles()
	if hasCgoCallbackBlindspot(&p) {
		if root := cgoIncludeRootOutsideDir(&p, h.modCache); root != "" {
			return "", nil, fmt.Errorf("closure: cgo include root outside package dir: %s", root)
		}
		var err error
		files, err = allPackageFiles(p.Dir)
		if err != nil {
			return "", nil, err
		}
		if include, err := cgoEscapingInclude(&p, files); err != nil {
			return "", nil, err
		} else if include != "" {
			return "", nil, fmt.Errorf("closure: cgo include escapes package dir: %s", include)
		}
	}
	if len(p.SFiles) > 0 {
		_, _, opaque, includes, err := asmCallTargetsEnv(h.ctx, p.Dir, h.env, p.SFiles, h.buildFlags...)
		if err != nil {
			return "", nil, err
		}
		if opaque {
			files, err = allPackageFiles(p.Dir)
			if err != nil {
				return "", nil, err
			}
		}
		for _, path := range includes {
			rel, err := filepath.Rel(p.Dir, path)
			if err != nil {
				rel = path
			}
			files = append(files, rel)
		}
	}
	files = uniqueStrings(files)
	fh, err := hashFiles(p.Dir, files)
	if err != nil {
		return "", nil, err
	}
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, filepath.Join(p.Dir, file))
	}
	return "src:" + p.ImportPath + "=" + fh, paths, nil
}

func allPackageFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			if d.Type()&os.ModeSymlink == 0 {
				return nil
			}
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("closure: walk %s: %w", dir, err)
	}
	return files, nil
}

// resolveReal follows symlinks to a path's real target, resolving `..` at the OS
// level so a directory-symlink component cannot be lexically cleaned away. Falls
// back to a lexical clean when the path does not exist.
func resolveReal(path string) string {
	if r, err := filepath.EvalSymlinks(path); err == nil {
		return r
	}
	return filepath.Clean(path)
}

// cgoIncludeRootOutsideDir returns a cgo `-I` search root the caller must fail
// closed on because it can pull in-tree headers the package-dir hash would miss.
// A root is safe only when it is under the package dir (hashed by allPackageFiles)
// or under the module cache (a version-pinned dependency whose C headers ride the
// cache guard, REQ-closure-mutable-local). Any other root — an in-module sibling, a local `replace`/
// `go.work` sibling module, or a directory the analysis cannot prove is a pinned dependency —
// is mutable in-tree source and fails closed. A genuine system `-I` root is
// indistinguishable from a mutable local one, so it fails closed too; system headers
// reached by the C compiler's *default* search (no in-tree `-I`) are still skipped
// via the not-found path in cgoEscapingInclude. The `-I` value is resolved through
// symlink components before the check (a lexical clean would hide a `symlink/..`
// escape). modCache is GOMODCACHE (empty when unknown → fail closed, never skipped).
func cgoIncludeRootOutsideDir(p *listPkg, modCache string) string {
	if p == nil || p.Dir == "" {
		return ""
	}
	pkgDir := resolveReal(p.Dir)
	for _, dir := range cgoIncludeFlagDirs(p) {
		raw := expandCgoIncludeDir(p, dir)
		if !filepath.IsAbs(raw) {
			raw = p.Dir + string(filepath.Separator) + raw
		}
		real := resolveReal(raw)
		if pathWithin(real, pkgDir) {
			continue // under the package dir → hashed by allPackageFiles
		}
		if modCache != "" && pathWithin(real, resolveReal(modCache)) {
			// Module-cache dependency → version-pinned (REQ-closure-mutable-local); its C headers ride the
			// cache guard. We trust the cached tree whole: the module cache is immutable
			// and module zips carry no symlinks, so a header inside it cannot symlink
			// back out to mutable in-tree source.
			continue
		}
		return real
	}
	return ""
}

func cgoIncludeFlagDirs(p *listPkg) []string {
	flags := append([]string{}, p.CgoCPPFLAGS...)
	flags = append(flags, p.CgoCFLAGS...)
	flags = append(flags, p.CgoCXXFLAGS...)
	flags = append(flags, p.CgoFFLAGS...)
	var dirs []string
	for i := 0; i < len(flags); i++ {
		flag := flags[i]
		dir := ""
		switch {
		case flag == "-I" || flag == "-iquote" || flag == "-isystem" || flag == "-idirafter":
			if i+1 >= len(flags) {
				continue
			}
			i++
			dir = flags[i]
		case strings.HasPrefix(flag, "-I") && flag != "-I":
			dir = flag[2:]
		case strings.HasPrefix(flag, "-iquote") && flag != "-iquote":
			dir = strings.TrimSpace(strings.TrimPrefix(flag, "-iquote"))
		case strings.HasPrefix(flag, "-isystem") && flag != "-isystem":
			dir = strings.TrimSpace(strings.TrimPrefix(flag, "-isystem"))
		case strings.HasPrefix(flag, "-idirafter") && flag != "-idirafter":
			dir = strings.TrimSpace(strings.TrimPrefix(flag, "-idirafter"))
		}
		if dir == "" {
			continue
		}
		dirs = append(dirs, dir)
	}
	return dirs
}

func cgoIncludeSearchDirs(p *listPkg) []string {
	if p == nil || p.Dir == "" {
		return nil
	}
	var dirs []string
	for _, dir := range cgoIncludeFlagDirs(p) {
		dir = cleanCgoIncludeDir(p, expandCgoIncludeDir(p, dir))
		if pathWithin(dir, p.Dir) {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

func expandCgoIncludeDir(p *listPkg, dir string) string {
	return strings.ReplaceAll(dir, "${SRCDIR}", p.Dir)
}

func cleanCgoIncludeDir(p *listPkg, dir string) string {
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(p.Dir, dir)
	}
	return filepath.Clean(dir)
}

func cgoEscapingInclude(p *listPkg, files []string) (string, error) {
	if p == nil || p.Dir == "" {
		return "", nil
	}
	includeDirs := cgoIncludeSearchDirs(p)
	for _, rel := range files {
		if !isNativeIncludeSource(rel) {
			continue
		}
		path := filepath.Join(p.Dir, rel)
		content, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("closure: read %s: %w", path, err)
		}
		goFile := strings.EqualFold(filepath.Ext(rel), ".go")
		text := string(content)
		if goFile {
			text = stripGoCgoCommentMarkers(text)
			goFile = false
		}
		text = spliceCPreprocessorLines(text)
		if cgoNativeFileHasRawString(rel, text) {
			return "", fmt.Errorf("closure: unsupported cgo raw string in %s", path)
		}
		lines := strings.Split(text, "\n")
		if !goFile {
			lines = stripCBlockComments(lines)
		}
		for _, line := range lines {
			include, quoted, ok := cgoIncludeDirective(line, goFile)
			if !ok {
				continue
			}
			if !quoted {
				// `#include <name>` is an angle-bracket header: resolve it like a
				// quoted include; if it is not found in-tree it is a system/toolchain
				// header (skipped below, REQ-closure-coverage). A bare token that is neither quoted nor
				// angle-bracketed is an opaque macro/computed include whose expansion
				// could reach in-tree source, so fail closed.
				if !strings.HasPrefix(include, "<") || !strings.HasSuffix(include, ">") {
					return "", fmt.Errorf("closure: unresolved cgo include %s", include)
				}
				include = strings.TrimSpace(include[1 : len(include)-1])
				if include == "" {
					return "", fmt.Errorf("closure: empty cgo include directive")
				}
			}
			if include == "_cgo_export.h" {
				continue
			}
			if symlinkDir := symlinkDirInPath(include, filepath.Dir(path)); symlinkDir != "" {
				return symlinkDir, nil
			}
			searchDirs := []string{filepath.Dir(path)}
			if !filepath.IsAbs(include) {
				searchDirs = append(searchDirs, includeDirs...)
			}
			found := false
			for _, dir := range searchDirs {
				if symlinkDir := symlinkDirInPath(include, dir); symlinkDir != "" {
					return symlinkDir, nil
				}
				resolved := include
				if !filepath.IsAbs(resolved) {
					resolved = filepath.Join(dir, resolved)
				}
				resolved = filepath.Clean(resolved)
				if !pathWithin(resolved, p.Dir) {
					return resolved, nil
				}
				parent := filepath.Dir(resolved)
				if realParent, err := filepath.EvalSymlinks(parent); err == nil && !pathWithin(realParent, p.Dir) {
					return realParent, nil
				}
				if _, err := os.Stat(resolved); err == nil {
					if relResolved, err := filepath.Rel(p.Dir, resolved); err == nil && !isNativeIncludeSource(relResolved) {
						return "", fmt.Errorf("closure: unsupported cgo include source %s", include)
					}
					found = true
					break
				}
			}
			if !found {
				// Not found under the package or its in-package `-I` roots → a
				// system/toolchain header found by the C compiler's default search
				// path (REQ-closure-coverage). Skip; build environment, not hashed. cgoIncludeRootOutsideDir
				// has already refused any in-module `-I` root, so no in-tree source hides here.
				continue
			}
		}
	}
	return "", nil
}

func spliceCPreprocessorLines(text string) string {
	text = strings.ReplaceAll(text, "\\\r\n", "")
	return strings.ReplaceAll(text, "\\\n", "")
}

func stripGoCgoCommentMarkers(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		line = strings.TrimSpace(strings.TrimPrefix(line, "//"))
		line = strings.TrimSpace(strings.TrimPrefix(line, "/*"))
		line = strings.TrimSpace(strings.TrimPrefix(line, "*"))
		line = strings.TrimSpace(strings.TrimSuffix(line, "*/"))
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}

func isNativeIncludeSource(rel string) bool {
	ext := strings.ToLower(filepath.Ext(rel))
	switch ext {
	case ".syso", ".a", ".o", ".obj", ".so", ".dylib", ".dll", ".lib":
		return false
	}
	return true
}

func cgoNativeFileHasRawString(_ string, text string) bool {
	return strings.Contains(text, "R\"")
}

func cgoIncludeDirective(line string, goFile bool) (string, bool, bool) {
	line = strings.TrimSpace(line)
	if goFile {
		line = strings.TrimSpace(strings.TrimPrefix(line, "//"))
		line = strings.TrimSpace(strings.TrimPrefix(line, "/*"))
		line = strings.TrimSpace(strings.TrimPrefix(line, "*"))
		line = strings.TrimSpace(strings.TrimSuffix(line, "*/"))
	}
	line = strings.TrimSpace(stripCLineComments(line))
	if !strings.HasPrefix(line, "#") {
		return "", false, false
	}
	line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
	if strings.HasPrefix(line, "include") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "include"))
	} else if strings.HasPrefix(line, "import") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "import"))
	} else {
		return "", false, false
	}
	if !strings.HasPrefix(line, "\"") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return "", false, false
		}
		return fields[0], false, true
	}
	line = strings.TrimPrefix(line, "\"")
	end := strings.IndexByte(line, '"')
	if end < 0 {
		return "", false, false
	}
	return line[:end], true, true
}

func stripCLineComments(line string) string {
	var b strings.Builder
	inString := false
	escaped := false
	for i := 0; i < len(line); {
		if inString {
			c := line[i]
			b.WriteByte(c)
			i++
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		if line[i] == '"' {
			inString = true
			b.WriteByte(line[i])
			i++
			continue
		}
		if i+1 < len(line) && line[i:i+2] == "//" {
			break
		}
		if i+1 < len(line) && line[i:i+2] == "/*" {
			b.WriteByte(' ')
			end := strings.Index(line[i+2:], "*/")
			if end < 0 {
				break
			}
			i += len("/*") + end + len("*/")
			continue
		}
		b.WriteByte(line[i])
		i++
	}
	return b.String()
}

func stripCBlockComments(lines []string) []string {
	inBlock := false
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		var b strings.Builder
		inString := false
		inChar := false
		escaped := false
		for i := 0; i < len(line); {
			if inBlock {
				end := strings.Index(line[i:], "*/")
				if end < 0 {
					break
				}
				i += end + len("*/")
				inBlock = false
				b.WriteByte(' ')
				continue
			}
			c := line[i]
			if inString || inChar {
				b.WriteByte(c)
				i++
				if escaped {
					escaped = false
					continue
				}
				if c == '\\' {
					escaped = true
					continue
				}
				if inString && c == '"' {
					inString = false
				}
				if inChar && c == '\'' {
					inChar = false
				}
				continue
			}
			if c == '"' {
				inString = true
				b.WriteByte(c)
				i++
				continue
			}
			if c == '\'' {
				inChar = true
				b.WriteByte(c)
				i++
				continue
			}
			if i+1 < len(line) && line[i:i+2] == "/*" {
				inBlock = true
				b.WriteByte(' ')
				i += len("/*")
				continue
			}
			b.WriteByte(c)
			i++
		}
		out = append(out, b.String())
	}
	return out
}

func symlinkDirInPath(path, base string) string {
	path = filepath.FromSlash(path)
	if !filepath.IsAbs(path) {
		path = filepath.Clean(base) + string(filepath.Separator) + path
	}
	volume := filepath.VolumeName(path)
	rest := path[len(volume):]
	current := volume
	if strings.HasPrefix(rest, string(filepath.Separator)) {
		current += string(filepath.Separator)
		rest = strings.TrimLeft(rest, string(filepath.Separator))
	}
	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			current = filepath.Dir(strings.TrimSuffix(current, string(filepath.Separator)))
			continue
		}
		next := filepath.Join(current, part)
		info, err := os.Lstat(next)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			if targetInfo, err := os.Stat(next); err == nil && targetInfo.IsDir() {
				return next
			}
		}
		current = next
	}
	return ""
}

func pathWithin(path, root string) bool {
	if root == "" {
		return false
	}
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

func uniqueStrings(values []string) []string {
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

// underCache reports whether dir is inside the module cache (a path segment
// boundary, so "/mod" does not match "/modificator").
func (h *Hasher) underCache(dir string) bool {
	if dir == "" {
		return false
	}
	dir = filepath.Clean(dir)
	return dir == h.modCache || strings.HasPrefix(dir, h.modCache+string(filepath.Separator))
}

func hashFiles(dir string, files []string) (string, error) {
	sort.Strings(files)
	hasher := sha256.New()
	for _, f := range files {
		path := filepath.Join(dir, f)
		content, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("closure: read %s: %w", path, err)
		}
		fmt.Fprintf(hasher, "%s\x00%x\n", f, sha256.Sum256(content))
	}
	return hex.EncodeToString(hasher.Sum(nil))[:32], nil
}

func hashFile(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("closure: read %s: %w", path, err)
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])[:32], nil
}

// list runs `go list -json -deps -test` for pkgPath and returns the parsed
// dependency graph. The result is memoized per package path for the life of the
// Hasher: every per-benchmark Compute call in a package (and the maximalHash
// widen path) needs the identical listing, and its inputs are immutable within a
// single process run, so one subprocess+decode is amortized across them (same
// lifetime and rationale as the SSA program cache). Callers treat the slice as
// read-only, so sharing one backing array across them is safe.
func (h *Hasher) list(pkgPath string) ([]listPkg, error) {
	if pkgs, ok := h.lists[pkgPath]; ok {
		return pkgs, nil
	}
	args := []string{"list", "-json", "-deps", "-test"}
	args = append(args, h.buildFlags...)
	args = append(args, pkgPath)
	out, err := gotool.RunInContextEnv(h.ctx, h.dir, h.env, args...)
	if err != nil {
		return nil, err
	}
	pkgs, err := parseList(bytes.NewReader(out))
	if err != nil {
		return nil, err
	}
	h.lists[pkgPath] = pkgs
	return pkgs, nil
}

func parseList(r io.Reader) ([]listPkg, error) {
	dec := json.NewDecoder(r)
	var pkgs []listPkg
	for dec.More() {
		var p listPkg
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("closure: decode go list: %w", err)
		}
		if p.Error != nil {
			// go list -deps -test exits 0 but reports an unloadable package via
			// its Error field. Hashing the surviving packages would silently
			// under-cover the closure → false-valid. Fail loud (REQ-fresh-sound).
			return nil, fmt.Errorf("closure: package %s failed to load: %s", p.ImportPath, p.Error.Err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}
