package runtimeinput

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/guard"
)

type classifiedPath struct {
	id     pathID
	reason string
}

type canonicalChdirTarget struct {
	path string
	ok   bool
}

// pathClassifier holds the resolved root-classification state and per-ingest
// memos shared by testlog ingestion (fromTestLog) and explicit-file preflight
// (FileInputEligibility).
type pathClassifier struct {
	moduleDir       string
	resolvedModule  string
	cfg             testLogConfig
	guardRoots      []guardRootPair
	ephemeralRoots  [][2]string
	ephemera        bracketEphemera
	guardMemo       map[string]bool
	scratchMemo     map[string]bool
	ephemeraMemo    map[string]bool
	classifyMemo    map[string]classifiedPath
	chdirTargetMemo map[string]canonicalChdirTarget
}

func newPathClassifier(moduleDir string, cfg testLogConfig) (pathClassifier, error) {
	resolvedModule, resolvedOK := resolveModuleRootStatus(moduleDir)
	return newPathClassifierWithModuleRoot(moduleDir, resolvedModule, resolvedOK, cfg)
}

func newPathClassifierWithModuleRoot(moduleDir, resolvedModule string, moduleResolvedOK bool, cfg testLogConfig) (pathClassifier, error) {
	// A module tree lying inside a declared ephemeral root does not
	// surrender its identities: module-relative reads are content-bearing
	// surface, never external temp machinery, so they keep their records
	// and the temp admissions never fire on them — declaring the system
	// temp directory stays sound for a repository checked out beneath it
	// (REQ-inputs-ephemeral-root).
	if resolvedModule == "" {
		resolvedModule, moduleResolvedOK = resolveModuleRootStatus(moduleDir)
	}
	ephemeralRoots, err := resolveEphemeralRoots(cfg.ephemeralRoots, moduleDir, resolvedModule)
	if err != nil {
		return pathClassifier{}, err
	}
	return pathClassifier{
		moduleDir:       moduleDir,
		resolvedModule:  resolvedModule,
		cfg:             cfg,
		guardRoots:      resolveGuardRoots(cfg.guardRoots),
		ephemeralRoots:  ephemeralRoots,
		ephemera:        cfg.bracket.ephemeraWithModuleRoot(cfg.scratchNamespaces, resolvedModule, moduleResolvedOK),
		guardMemo:       map[string]bool{},
		scratchMemo:     map[string]bool{},
		ephemeraMemo:    map[string]bool{},
		classifyMemo:    map[string]classifiedPath{},
		chdirTargetMemo: map[string]canonicalChdirTarget{},
	}, nil
}

func (c *pathClassifier) moduleInterior(p string) bool {
	return pathWithin(c.moduleDir, p) || pathWithin(c.resolvedModule, p)
}

func (c *pathClassifier) guardCovered(p string) bool {
	return guardCovered(p, c.guardRoots, c.guardMemo)
}

func (c *pathClassifier) ephemeralRoot(p string) bool {
	return !c.moduleInterior(p) && ephemeralRoot(p, c.ephemeralRoots)
}

func (c *pathClassifier) ephemeralScratch(p string) bool {
	return !c.moduleInterior(p) && ephemeralScratch(p, c.ephemeralRoots, c.resolvedModule, c.scratchMemo)
}

func (c *pathClassifier) elidesUnambiguous(p string) bool {
	return c.guardCovered(p) ||
		c.ephemeralRoot(p) ||
		c.ephemeralScratch(p) ||
		c.ephemera.admits(p, c.ephemeraMemo) ||
		nullSink(p)
}

func (c *pathClassifier) excludesRaw(p string) bool {
	return c.cfg.excludesRaw(c.moduleDir, p)
}

func (c *pathClassifier) classify(p string) (pathID, string) {
	if c.classifyMemo != nil {
		if cached, ok := c.classifyMemo[p]; ok {
			return cached.id, cached.reason
		}
	}
	id, reason := classifyPath(c.moduleDir, p)
	if c.classifyMemo != nil {
		c.classifyMemo[p] = classifiedPath{id: id, reason: reason}
	}
	return id, reason
}

// externalExistenceStat reports whether a clean unambiguous stat of p binds
// existence or absence alone (an external directory or absent external target;
// REQ-inputs-external-dir-existence, REQ-inputs-absent-stat).
func (c *pathClassifier) externalExistenceStat(p string) (pathID, bool) {
	if !filepath.IsAbs(p) || !utf8.ValidString(p) || strings.ContainsAny(p, "\x00\r\n") || volatileOSPath(p) {
		return pathID{}, false
	}
	if _, inModule := relUnder(c.moduleDir, p); inModule {
		return pathID{}, false
	}
	if info, statErr := classifyProbe(p); statErr == nil && info.IsDir() || os.IsNotExist(statErr) {
		return pathID{Kind: pathAbs, Path: filepath.Clean(p)}, true
	}
	return pathID{}, false
}

// canonicalizeTrackedChdirTarget validates and canonicalizes a clean absolute
// chdir target under tracked testing.Chdir excursion tracking.
//
// For targets under a declared ephemeral root whose lexical spelling aliases a
// resolved root (such as macOS /var/folders -> /private/var/folders), the
// root's lexical prefix is rewritten to its resolved prefix so os.Getwd()'s
// $PWD SameFile shortcut and syscall.Getwd() produce one canonical stack key;
// any surviving directory or nearest existing ancestor under the resolved root
// must traverse zero symlinks. Non-ephemeral targets must exist at ingest as
// real directories with zero symlink components along their full path.
func (c *pathClassifier) canonicalizeTrackedChdirTarget(p string) (string, bool) {
	if c.chdirTargetMemo != nil {
		if cached, ok := c.chdirTargetMemo[p]; ok {
			return cached.path, cached.ok
		}
	}
	canon, ok := c.canonicalizeTrackedChdirTargetUncached(p)
	if c.chdirTargetMemo != nil {
		c.chdirTargetMemo[p] = canonicalChdirTarget{path: canon, ok: ok}
	}
	return canon, ok
}

func (c *pathClassifier) canonicalizeTrackedChdirTargetUncached(p string) (string, bool) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || !utf8.ValidString(p) || strings.ContainsAny(p, "\x00\r\n") || volatileOSPath(p) {
		return "", false
	}
	if !c.moduleInterior(p) {
		for _, r := range c.ephemeralRoots {
			if canon, ok := c.canonicalizeUnderEphemeralRoot(r, p); ok {
				return canon, true
			}
		}
	}
	info, err := os.Lstat(p)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", false
	}
	resolved, _, ok := chainResolve(p)
	if !ok || resolved != p {
		return "", false
	}
	return p, true
}

func (c *pathClassifier) canonicalizeUnderEphemeralRoot(r [2]string, p string) (string, bool) {
	canon := p
	if pathWithin(r[0], p) && r[0] != r[1] {
		rel, ok := relUnder(r[0], p)
		if !ok {
			return "", false
		}
		if rel == "." {
			canon = r[1]
		} else {
			canon = filepath.Join(r[1], rel)
		}
	}
	if !pathWithin(r[1], canon) || c.moduleInterior(canon) {
		return "", false
	}
	info, err := os.Lstat(canon)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", false
		}
		resolved, _, ok := chainResolve(canon)
		if !ok || resolved != canon {
			return "", false
		}
		return canon, true
	}
	if !os.IsNotExist(err) {
		return "", false
	}
	for anc := filepath.Dir(canon); ; {
		ancInfo, ancErr := os.Lstat(anc)
		if os.IsNotExist(ancErr) {
			parent := filepath.Dir(anc)
			if parent == anc {
				return "", false
			}
			anc = parent
			continue
		}
		if ancErr != nil || ancInfo.Mode()&os.ModeSymlink != 0 || !ancInfo.IsDir() || !pathWithin(r[1], anc) {
			return "", false
		}
		resolved, _, ok := chainResolve(anc)
		if !ok || resolved != anc {
			return "", false
		}
		return canon, true
	}
}

// FileInputKind identifies how the producer treats an explicit file read.
// UnknownFileInput is the zero value and grants no eligibility.
type FileInputKind uint8

const (
	// UnknownFileInput grants no eligibility.
	UnknownFileInput FileInputKind = iota
	// RawFileInput can record the selected file's bytes when actually read.
	RawFileInput
	// ElidedFileInput records no file identity under the producer's policy.
	ElidedFileInput
	// ProjectedFileInput binds a derived value instead of the file's raw bytes.
	ProjectedFileInput
	// UnverifiableFileInput cannot satisfy this explicit-file preflight.
	UnverifiableFileInput
)

// FileEligibility is a classification, not observation or outcome evidence.
// Reason names every non-raw disposition; a raw result still needs a successful
// observed read and the ordinary bracket, closing and revalidation checks.
type FileEligibility struct {
	Kind   FileInputKind
	Reason string
}

// FileInputContext supplies the producing configuration for an eligibility
// query. Env is the actual non-nil complete process environment with a matching
// PWD, not the caller's ambient environment. Roots has the same one-judged-run
// lifetime as ProducerIngest.Roots. ScratchRoot is the producer's minted scratch
// root, and ExcludedPaths extends the facade's own exclusions, as in ProducerIngest.
// A selected file must remain present through capture and finalization: it cannot
// be newly minted scratch, so scratch-namespace declarations cannot exempt it.
type FileInputContext struct {
	Env           []string
	Runner        gotool.Runner
	Roots         *Roots
	ScratchRoot   string
	ExcludedPaths []string
}

// FileInputEligibility checks whether an explicit clean absolute regular-file
// path without symlink components is eligible for raw-byte observation under the
// producer facade's absolute evidence-root and process directories. It uses the
// facade's root resolution and predicates, preserving their exceptions.
// Eligibility does not read or hash the file as an observed input. Resolving roots
// can read configuration or toolchain inputs, including the selected file when
// it has both roles; those reads manufacture no consumer observation. No
// classification is overridden. The caller holds the file, environment and root
// topology stable from this query through capture, execution and finalization,
// and repeats the query when that context changes. Cancellation returns no result.
func FileInputEligibility(ctx context.Context, treeRoot, pkgDir, file string, in FileInputContext) (eligibility FileEligibility, err error) {
	if ctx == nil {
		return FileEligibility{}, fmt.Errorf("runtimeinputs: nil context")
	}
	defer func() {
		if ctxErr := ctx.Err(); ctxErr != nil {
			eligibility, err = FileEligibility{}, ctxErr
		}
	}()
	if err := ctx.Err(); err != nil {
		return FileEligibility{}, err
	}
	refuse := func(reason string) FileEligibility {
		return FileEligibility{Kind: UnverifiableFileInput, Reason: reason}
	}
	if in.Env == nil {
		return FileEligibility{}, fmt.Errorf("runtimeinputs: exact-input query needs the producing environment")
	}
	if !filepath.IsAbs(treeRoot) || !filepath.IsAbs(pkgDir) {
		return refuse("exact-input tree and package directories must be absolute"), nil
	}
	in.Env = slices.Clone(in.Env)
	in.ExcludedPaths = slices.Clone(in.ExcludedPaths)
	if !utf8.ValidString(file) || strings.ContainsAny(file, "\x00\r\n") || !filepath.IsAbs(file) || filepath.Clean(file) != file {
		return refuse("exact input needs a clean absolute representable file path"), nil
	}
	root, err := filepath.EvalSymlinks(treeRoot)
	if err != nil {
		return FileEligibility{}, fmt.Errorf("runtimeinputs: resolve exact-input tree: %w", err)
	}
	pkg, err := filepath.EvalSymlinks(pkgDir)
	if err != nil {
		return FileEligibility{}, fmt.Errorf("runtimeinputs: resolve exact-input package: %w", err)
	}
	if _, inside := relUnder(root, pkg); !inside {
		return refuse("exact-input package is outside the producing tree"), nil
	}
	env, err := normalizeEnvironment(in.Env)
	if err != nil {
		return FileEligibility{}, err
	}
	if reason := producerPWDProblem(pkg, env); reason != "" {
		return refuse(reason), nil
	}
	roots, err := resolveRoots(ctx, in.Roots, in.Runner, root, pkg, env)
	if err != nil {
		return FileEligibility{}, fmt.Errorf("runtimeinputs: exact-input classification roots: %w", err)
	}
	cfg, err := applyTestLogOptions(producerClassificationOptions(roots, root, in.ScratchRoot, in.ExcludedPaths, nil))
	if err != nil {
		return FileEligibility{}, err
	}
	classifier, err := newPathClassifierWithModuleRoot(root, root, true, cfg)
	if err != nil {
		return FileEligibility{}, err
	}
	// An exclusion outranks every per-path refusal, including volatile and
	// unavailable paths. These lexical decisions precede filesystem probes.
	if classifier.excludesRaw(file) {
		return FileEligibility{Kind: ElidedFileInput, Reason: "producer observation exclusion omits the file identity"}, nil
	}
	if volatileOSPath(file) {
		return refuse("volatile OS input: " + file), nil
	}
	if nullSink(file) {
		return FileEligibility{Kind: ElidedFileInput, Reason: "producer null-sink admission"}, nil
	}
	resolved, err := filepath.EvalSymlinks(file)
	if err != nil {
		return refuse("exact input does not resolve: " + err.Error()), nil
	}
	if resolved != file {
		return refuse("exact input traverses a symlink"), nil
	}
	info, err := os.Lstat(file)
	if err != nil {
		return refuse("exact input is unavailable: " + err.Error()), nil
	}
	if !info.Mode().IsRegular() {
		return refuse("exact input is not a regular file"), nil
	}
	if classifier.guardCovered(file) {
		return FileEligibility{Kind: ElidedFileInput, Reason: "producer guard-covered admission omits the file identity"}, nil
	}
	id, reason := classifier.classify(file)
	if reason != "" {
		return refuse(reason), nil
	}
	if machineProjected(id) {
		return FileEligibility{Kind: ProjectedFileInput, Reason: "producer stable-machine projection, not raw file bytes"}, nil
	}
	if classifier.ephemeralRoot(file) {
		return FileEligibility{Kind: ElidedFileInput, Reason: "producer ephemeral-root admission omits the file identity"}, nil
	}
	// A still-existing regular file cannot satisfy absent-at-ingest scratch
	// admission or a namespace's absent-at-both-endpoints condition.
	return FileEligibility{Kind: RawFileInput}, nil
}

// guardRootPair carries a declared guard-covered root in both its lexical and
// symlink-resolved forms: recorded paths may name either (a symlinked GOROOT
// appears both ways), while the soundness check always lands on the resolved
// form. excludeSub names the root's one uncovered direct subtree — the
// module cache's mutable `cache/` metadata, the build cache's discovered
// `fuzz/` corpus — which stays observed.
type guardRootPair struct {
	lexical, resolved string
	excludeSub        string
}

// admits reports whether path lies inside the root's covered region in either
// form — under the root and outside its excluded subtree, when one is named.
func (r guardRootPair) admits(path string) bool {
	for _, base := range [2]string{r.lexical, r.resolved} {
		if !pathWithin(base, path) {
			continue
		}
		if r.excludeSub != "" && pathWithin(filepath.Join(base, r.excludeSub), path) {
			return false
		}
		return true
	}
	return false
}

// bracketStatCover holds the declared bracket roots in identity form
// for the parse-time stat-metadata admission.
type bracketStatCover struct {
	roots      map[pathID]bool
	exclusions []pathID
}

// declaredBracketStatRoots lists the bracket's declared roots as
// identities the stat arm can admit against; a nil or unverifiable
// bracket declares nothing. Exclusions ride along: an excluded subtree
// is outside the fingerprint and outside this admission alike.
func declaredBracketStatRoots(b *Bracket) bracketStatCover {
	c := bracketStatCover{roots: map[pathID]bool{}}
	if b == nil || b.reason != "" {
		return c
	}
	for _, root := range b.roots {
		c.roots[root.id] = true
	}
	c.exclusions = b.exclusions
	return c
}

// covers reports whether id is a declared bracket root or lies under a
// declared directory root - the identities whose content and metadata
// the bracket fingerprint spans.
func (c bracketStatCover) covers(id pathID) bool {
	// An excluded subtree is removed from the fingerprint and from
	// coverage alike, so its metadata is NOT spanned and the seal
	// stands (REQ-inputs-bracket-coverage). The admission is lexical;
	// escaping symlinks are caught downstream by resolution-based
	// coverage and resolvedTarget, but exclusion must hold here.
	if excludesIdentity(c.exclusions, id) {
		return false
	}
	if c.roots[id] {
		return true
	}
	for root := range c.roots {
		if root.Kind != id.Kind {
			continue
		}
		// A module-root bracket root: cleaned rel identities never carry
		// a "./" prefix, so "." covers by kind alone - the fingerprint
		// spans the whole module, exactly as scratchNamespace.matches
		// reads the same root.
		if root.Kind == pathRel && root.Path == "." {
			return true
		}
		sep := "/"
		if id.Kind == pathAbs {
			sep = string(filepath.Separator)
		}
		if strings.HasPrefix(id.Path, root.Path+sep) {
			return true
		}
	}
	return false
}

// nullSink reports whether p is exactly the contentless sink device:
// every read sees immediate EOF and every write is discarded, so no
// state a subject observes flows through the identity. Lexical identity
// only — another name resolving to the same device stays observed. On
// windows os.DevNull is "NUL", never an absolute cleaned path, so the
// admission is inert there and sink reads stay observed, cost-only
// (REQ-inputs-null-sink).
func nullSink(p string) bool { return p == os.DevNull }

// resolveGuardRoots resolves each declared root once. A root that does not
// resolve declares nothing — nothing can be provably inside it.
func resolveGuardRoots(decls []guardRootDecl) []guardRootPair {
	out := make([]guardRootPair, 0, len(decls))
	for _, d := range decls {
		// A guard root under a volatile OS root would admit volatile
		// reads recordless and send the coverage walk probing kernel
		// objects; skipped exactly like an unresolvable declaration —
		// conservative, everything under it stays observed
		// (REQ-inputs-volatile-os-roots).
		if volatileOSPath(filepath.Clean(d.path)) {
			continue
		}
		resolved, err := filepath.EvalSymlinks(d.path)
		if err != nil {
			continue
		}
		out = append(out, guardRootPair{lexical: d.path, resolved: resolved, excludeSub: d.excludeSub})
	}
	return out
}

// guardCovered reports whether p is provably inside a guard-covered root's
// covered region (REQ-inputs-guard-covered): admitted in lexical form, the
// existing object it resolves to admitted, and every symlink the kernel walk
// traverses admitted — an out-and-back chain through anything outside the
// region is a mutable rebinding point and stays observed, exactly as
// value-binding coverage treats bracket roots. Missing or uninspectable
// objects stay observed. Results are memoized per construction: one testlog
// line's verdict cannot differ from the next's for the same path.
func guardCovered(p string, roots []guardRootPair, memo map[string]bool) bool {
	if v, ok := memo[p]; ok {
		return v
	}
	covered := guardCoveredUncached(p, roots)
	memo[p] = covered
	return covered
}

func guardCoveredUncached(p string, roots []guardRootPair) bool {
	// One admitting root's failed leg is that root's verdict, never the
	// walk's: a later overlapping root that admits the whole chain still
	// covers (a build cache configured inside a module cache's covered
	// region). Refusal stays the default when no root covers.
	// The chain resolves lazily and once: a function of the path alone,
	// probed only after some root admits it (non-admitted paths are
	// never probed), reused across overlapping roots.
	var resolved string
	var links []string
	resolvedOnce := false
	for _, r := range roots {
		if !r.admits(p) {
			continue
		}
		if !resolvedOnce {
			var ok bool
			resolved, links, ok = chainResolve(p)
			if !ok {
				// Unresolvable for every root alike: no later root can
				// admit a chain the kernel walk cannot produce.
				return false
			}
			if _, err := os.Lstat(resolved); err != nil {
				return false
			}
			resolvedOnce = true
		}
		if !r.admits(resolved) {
			continue
		}
		admitted := true
		for _, link := range links {
			if !r.admits(link) {
				admitted = false
				break
			}
		}
		if admitted {
			return true
		}
	}
	return false
}

func resolvePath(cwd, name string) string {
	if filepath.IsAbs(name) {
		return filepath.Clean(name)
	}
	return filepath.Clean(filepath.Join(cwd, name))
}

func hasParentTraversal(name string) bool {
	volume := filepath.VolumeName(name)
	for _, component := range pathComponents(strings.TrimPrefix(name, volume)) {
		if component == ".." {
			return true
		}
	}
	return false
}

// ambiguousTraversal reports whether name carries a ".." component whose
// kernel path-walk resolution cannot be proven to match lexical cleaning.
// Congruence is discharged exactly when every directory a ".." steps back
// across lstats as a real (non-symlink) directory at observation ingest —
// more than lexical normalization, as REQ-inputs-path-congruence demands.
// A mid-run change of a crossed component is the same
// one-process-run-wide residual the scratch admission accepts; a symlink
// the traversal does not itself step back across is an ordinary path
// identity, walked identically by the producer and by every later
// materialization of the recorded path. The ubiquitous test idiom this admits is a repo-root
// read from the package directory ("../../docs/..."), which previously
// sealed the whole observation.
func ambiguousTraversal(cwd, name string, memo map[string]bool) bool {
	if !hasParentTraversal(name) {
		return false
	}
	key := strconv.Itoa(len(cwd)) + ":" + cwd + name
	if ambiguous, ok := memo[key]; ok {
		return ambiguous
	}
	ambiguous := !congruentTraversal(cwd, name)
	memo[key] = ambiguous
	return ambiguous
}

// congruentTraversal walks name's components lexically from its resolution
// base, verifying at each ".." that the directory being stepped out of is
// an existing non-symlink directory. Any verification failure — a symlink,
// a non-directory, a vanished component, or an unusable base — refuses
// fail-closed, and a crossing under a volatile OS root refuses before any
// probe: those paths classify from the path alone
// (REQ-inputs-volatile-os-roots), so the verifier must not read them
// either.
func congruentTraversal(cwd, name string) bool {
	volume := filepath.VolumeName(name)
	rest := strings.TrimPrefix(name, volume)
	var cur string
	if filepath.IsAbs(name) {
		cur = volume + string(filepath.Separator)
	} else {
		if !filepath.IsAbs(cwd) {
			return false
		}
		cur = filepath.Clean(cwd)
	}
	for _, component := range pathComponents(rest) {
		switch component {
		case ".":
		case "..":
			parent := filepath.Dir(cur)
			if parent == cur {
				// The root's parent is the root under kernel path-walk
				// semantics too; nothing is crossed.
				continue
			}
			if volatileOSPath(cur) {
				return false
			}
			info, err := congruenceProbe(cur)
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return false
			}
			cur = parent
		default:
			cur = filepath.Join(cur, component)
		}
	}
	return true
}

// pathComponents splits a volume-stripped path into its components with the
// exact separator predicate the traversal gate uses — one splitter for the
// gate and the verifier, so the fast path can never disagree with the walk.
func pathComponents(name string) []string {
	return strings.FieldsFunc(name, func(r rune) bool {
		return r == '/' || filepath.Separator == '\\' && r == '\\'
	})
}

func classifyPath(moduleDir, p string) (pathID, string) {
	if !utf8.ValidString(p) {
		return pathID{}, "non-UTF-8 runtime input path"
	}
	if strings.ContainsAny(p, "\x00\r\n") {
		return pathID{}, "unrepresentable runtime input path"
	}
	id, _ := lexicalPathID(moduleDir, p)
	if id.Kind == pathRel {
		return id, ""
	}
	// A volatile-OS path classifies from the path alone — no probe:
	// the kernel fabricates these objects per read, so no binding over
	// them revalidates, and probing would make the classifier itself a
	// volatile read in any observing parent's evidence
	// (REQ-inputs-volatile-os-roots). Machine-fact identities keep
	// their projection digest.
	if volatileOSPath(p) {
		return pathID{}, "volatile OS input: " + p
	}
	info, err := classifyProbe(p)
	if err == nil && info.IsDir() {
		return pathID{}, "external directory input: " + p
	}
	if err != nil && !os.IsNotExist(err) {
		return pathID{}, "unhashable runtime input: " + p
	}
	return pathID{Kind: pathAbs, Path: filepath.Clean(p)}, ""
}

// volatileOSPath reports whether p lies under a kernel-synthesized
// volatile filesystem root without being an allowlisted machine-fact
// identity (REQ-inputs-volatile-os-roots). Purely lexical.
func volatileOSPath(p string) bool {
	if machineFactIdentities[filepath.Clean(p)] {
		return false
	}
	for _, root := range guard.VolatileOSRoots {
		if pathWithin(root, p) {
			return true
		}
	}
	return false
}

func relUnder(root, p string) (string, bool) {
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return rel, true
}

func materializePath(moduleDir string, id pathID) (string, error) {
	switch id.Kind {
	case pathRel:
		path := filepath.Clean(filepath.Join(moduleDir, filepath.FromSlash(id.Path)))
		if _, ok := relUnder(moduleDir, path); !ok {
			return "", fmt.Errorf("runtimeinputs: relative path escapes module: %q", id.Path)
		}
		return path, nil
	case pathAbs:
		if !filepath.IsAbs(id.Path) {
			return "", fmt.Errorf("runtimeinputs: absolute path input is relative: %q", id.Path)
		}
		return filepath.Clean(id.Path), nil
	default:
		return "", fmt.Errorf("runtimeinputs: unknown path kind %q", id.Kind)
	}
}
