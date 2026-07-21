package runtimeinput

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// Bracket is an observation bracket (REQ-inputs-value-binding): a fingerprint
// over a caller-declared set of candidate runtime-input roots, captured before
// the producing process starts and revalidated when its testlog becomes an
// observation, so a change to any bracketed object persisting across the
// run-to-observation span is detected. The fingerprint observes content and
// metadata together, so a restoration that does not reproduce the recorded
// metadata still moves the bracket — toward recomputation, never reuse. Only
// CaptureBracket constructs a usable value; a zero or copied-and-altered
// Bracket fails its seal and is refused rather than read as unchanged.
type Bracket struct {
	moduleDir   string
	roots       []bracketRoot
	exclusions  []pathID
	reason      string // non-empty: the bracket is unverifiable, attributably
	fingerprint string
	seal        string
}

// bracketRoot is one declared root with the digest of its captured stream. The
// per-root digest lets revalidation attribute a moved fingerprint to the root
// that moved.
type bracketRoot struct {
	id     pathID
	digest string
}

// BracketOption configures bracket capture.
type BracketOption func(*bracketConfig)

type bracketConfig struct {
	excluded []pathID
	err      error
}

// WithBracketExcludedPaths declares root exclusions with the semantics and
// responsibility of REQ-inputs-exclusions (REQ-inputs-bracket-coverage): each
// pattern is a non-empty identity-form path excluding the identical identity of
// its kind and every identity of that kind extending it past a separator. An
// excluded subtree is removed from the fingerprint and from coverage alike, so
// a volatile bookkeeping tree under a module-scale root does not make every
// bracket environmental noise; an excluded identity a run then observes is
// uncovered, never bound.
func WithBracketExcludedPaths(patterns ...string) BracketOption {
	return func(c *bracketConfig) {
		// Exclusion identities enter the fingerprint's newline-framed
		// preimage exactly as roots do, so they carry the same
		// representability bound: a pattern with framing bytes could alias
		// a different exclusion set.
		for _, q := range patterns {
			if !utf8.ValidString(q) || strings.ContainsAny(q, "\x00\r\n") {
				c.err = fmt.Errorf("runtimeinputs: unrepresentable bracket exclusion %q", q)
				return
			}
		}
		excluded, err := exclusionPatterns(patterns)
		if err != nil {
			c.err = err
			return
		}
		c.excluded = append(c.excluded, excluded...)
	}
}

// CaptureBracket fingerprints the declared roots under moduleDir, to be
// captured before the producing process starts (REQ-inputs-value-binding).
// Each root is a module-relative or clean absolute path whose object is a
// regular file, a directory tree, or absent; it is fingerprinted with the
// hashing semantics its materialized object would receive as an observed
// identity of its kind, and an absent root fingerprints as absent, so an input
// created, deleted, rewritten, or retyped under a root during the span moves
// the bracket (REQ-inputs-bracket-coverage). A root those semantics refuse to
// hash — an external directory, an unreadable object — makes the bracket
// unverifiable, carrying the refusing reason, rather than silently narrowing
// coverage. Declaring a root is the caller's assertion that the surface it
// names was mutation-free for the span, with the same soundness responsibility
// as an exclusion.
func CaptureBracket(moduleDir string, roots []string, opts ...BracketOption) (Bracket, error) {
	return CaptureBracketContext(context.Background(), moduleDir, roots, opts...)
}

// CaptureBracketContext is CaptureBracket observing ctx cancellation between
// and within root fingerprints.
func CaptureBracketContext(ctx context.Context, moduleDir string, roots []string, opts ...BracketOption) (Bracket, error) {
	if ctx == nil {
		return Bracket{}, errors.New("runtimeinputs: nil context")
	}
	var cfg bracketConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.err != nil {
		return Bracket{}, cfg.err
	}
	moduleDir, err := filepath.Abs(moduleDir)
	if err != nil {
		return Bracket{}, fmt.Errorf("runtimeinputs: module dir: %w", err)
	}
	ids := make([]pathID, 0, len(roots))
	for _, root := range roots {
		id, err := bracketRootID(root)
		if err != nil {
			return Bracket{}, err
		}
		ids = append(ids, id)
	}
	sortPathIDs(ids)
	ids = compact(ids)
	exclusions := append([]pathID(nil), cfg.excluded...)
	sortPathIDs(exclusions)
	exclusions = compact(exclusions)
	capture, err := fingerprintBracket(ctx, moduleDir, ids, exclusions)
	if err != nil {
		return Bracket{}, err
	}
	b := Bracket{
		moduleDir:   moduleDir,
		roots:       capture.roots,
		exclusions:  exclusions,
		reason:      capture.reason,
		fingerprint: capture.fingerprint,
	}
	b.seal = sealBracket(b)
	return b, nil
}

// checkSealed refuses a bracket that capture did not produce: a zero value or
// a copied-and-altered one fails its seal rather than reading as unchanged
// (REQ-inputs-value-binding).
func (b Bracket) checkSealed() error {
	if b.seal == "" || sealBracket(b) != b.seal {
		return errors.New("runtimeinputs: bracket seal is invalid")
	}
	return nil
}

// checkModuleView refuses a bracket interpreted under a different module view
// than its capture (REQ-inputs-value-binding). moduleDir must be absolute.
func (b Bracket) checkModuleView(moduleDir string) error {
	if moduleDir != b.moduleDir {
		return fmt.Errorf("runtimeinputs: bracket captured under module view %q interpreted under %q", b.moduleDir, moduleDir)
	}
	return nil
}

// revalidate re-fingerprints the bracket with the same hashing semantics as
// its capture; the caller runs it strictly after the manifest digest's last
// input read (REQ-inputs-value-binding). It reports unchanged, or an
// attributable unverifiable reason: the capture already carried one, the
// revalidation produced one, or the fingerprint moved — including a root whose
// object changed type, appeared, or disappeared. A bracket not produced by
// capture, or interpreted under a different module view than its capture, is
// refused rather than read as unchanged.
func (b Bracket) revalidate(ctx context.Context, moduleDir string) (bool, string, error) {
	if ctx == nil {
		return false, "", errors.New("runtimeinputs: nil context")
	}
	if err := b.checkSealed(); err != nil {
		return false, "", err
	}
	moduleDir, err := filepath.Abs(moduleDir)
	if err != nil {
		return false, "", fmt.Errorf("runtimeinputs: module dir: %w", err)
	}
	if err := b.checkModuleView(moduleDir); err != nil {
		return false, "", err
	}
	if b.reason != "" {
		return false, b.reason, nil
	}
	ids := make([]pathID, len(b.roots))
	for i, root := range b.roots {
		ids[i] = root.id
	}
	current, err := fingerprintBracket(ctx, b.moduleDir, ids, b.exclusions)
	if err != nil {
		return false, "", err
	}
	if current.reason != "" {
		return false, current.reason, nil
	}
	if current.fingerprint == b.fingerprint {
		return true, "", nil
	}
	for i, root := range b.roots {
		if current.roots[i].digest != root.digest {
			return false, "observation bracket moved: " + root.id.displayPath(), nil
		}
	}
	return false, "observation bracket moved", nil
}

// bracketRootID normalizes one declared root to identity form: a
// module-relative slash path or a clean absolute host path.
func bracketRootID(root string) (pathID, error) {
	if root == "" {
		return pathID{}, errors.New("runtimeinputs: empty bracket root")
	}
	if !utf8.ValidString(root) || strings.ContainsAny(root, "\x00\r\n") {
		return pathID{}, fmt.Errorf("runtimeinputs: unrepresentable bracket root %q", root)
	}
	if filepath.IsAbs(root) {
		// A volatile-OS root can only produce an always-moving
		// fingerprint — the kernel fabricates its objects per read — so
		// the declaration fails loud instead of silently staling every
		// check (REQ-inputs-volatile-os-roots).
		if volatileOSPath(filepath.Clean(root)) {
			return pathID{}, fmt.Errorf("runtimeinputs: bracket root %q lies under a volatile OS root; nothing over it revalidates", root)
		}
		return pathID{Kind: pathAbs, Path: filepath.Clean(root)}, nil
	}
	clean := path.Clean(filepath.ToSlash(root))
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return pathID{}, fmt.Errorf("runtimeinputs: bracket root escapes module: %q", root)
	}
	return pathID{Kind: pathRel, Path: clean}, nil
}

type bracketCapture struct {
	roots       []bracketRoot
	fingerprint string
	reason      string
}

// fingerprintBracket digests every declared root under one module view. The
// combined fingerprint pins the module view, the exclusion set, and every
// per-root digest, so any persisted change to a bracketed object moves it.
func fingerprintBracket(ctx context.Context, moduleDir string, ids, exclusions []pathID) (bracketCapture, error) {
	combined := sha256.New()
	fprintf(combined, "bracket %d\nmodule %s\n", manifestVersion, moduleDir)
	for _, q := range exclusions {
		fprintf(combined, "exclude %s %s\n", q.Kind, q.Path)
	}
	var capture bracketCapture
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return bracketCapture{}, err
		}
		digest, unverifiable, reason, err := fingerprintBracketRoot(ctx, moduleDir, id, exclusions)
		if err != nil {
			return bracketCapture{}, err
		}
		if unverifiable && capture.reason == "" {
			capture.reason = reason
		}
		fprintf(combined, "root %s %s %s\n", id.Kind, id.Path, digest)
		capture.roots = append(capture.roots, bracketRoot{id: id, digest: digest})
	}
	capture.fingerprint = hex.EncodeToString(combined.Sum(nil))
	return capture, nil
}

// fingerprintBracketRoot digests one root with the hashing semantics its
// materialized object would receive as an observed identity of its kind
// (REQ-inputs-bracket-coverage). A root that is itself excluded contributes a
// constant: its subtree is removed from the fingerprint entirely.
func fingerprintBracketRoot(ctx context.Context, moduleDir string, id pathID, exclusions []pathID) (string, bool, string, error) {
	if excludesIdentity(exclusions, id) {
		return "excluded", false, "", nil
	}
	p, err := materializePath(moduleDir, id)
	if err != nil {
		return "", false, "", err
	}
	h := sha256.New()
	unverifiable, reason, err := hashPath(ctx, h, id, p, moduleDir, bracketSkip(id, exclusions), false)
	if err != nil {
		return "", false, "", err
	}
	return hex.EncodeToString(h.Sum(nil)), unverifiable, reason, nil
}

// bracketSkip filters a root's directory walk by exclusion identity: an entry
// at slash-form rel within the walk carries the identity extending the root's,
// matched with REQ-inputs-exclusions semantics. Only module-relative roots
// walk directories, so absolute roots need no filter.
func bracketSkip(root pathID, exclusions []pathID) func(rel string) bool {
	if root.Kind != pathRel || len(exclusions) == 0 {
		return nil
	}
	return func(rel string) bool {
		return excludesIdentity(exclusions, pathID{Kind: pathRel, Path: path.Join(root.Path, rel)})
	}
}

// bracketCoverage is a bracket's per-identity coverage view: the module
// view's resolved root and every declared root's own resolved path, computed
// once so each recorded identity's resolution chain is compared against the
// same root positions (REQ-inputs-value-binding).
type bracketCoverage struct {
	bracket Bracket
	// moduleRoot is the module view's resolved root. Module-relative walks
	// start here: the module directory's own materialization is the caller's
	// fixed frame, shared by every root fingerprint, so its links are
	// content-pinned by construction and never part of an identity's chain.
	moduleRoot string
	// resolved holds each root's own resolved path, index-aligned with
	// bracket.roots; empty when the root does not resolve, in which case it
	// covers nothing.
	resolved []string
}

// coverage resolves the module view and every declared root's own path for
// per-identity coverage decisions. The caller must have checked the seal and
// module view first. A root's own resolution chain needs no residence check:
// the root fingerprint follows the same chain at hash time, so a retarget
// anywhere along it moves the digest of the content it reaches.
func (b Bracket) coverage() bracketCoverage {
	c := bracketCoverage{bracket: b, resolved: make([]string, len(b.roots))}
	if moduleRoot, _, ok := chainResolve(b.moduleDir); ok {
		c.moduleRoot = moduleRoot
	} else {
		c.moduleRoot = b.moduleDir
	}
	for i, root := range b.roots {
		start := root.id.Path
		if root.id.Kind == pathRel {
			start = filepath.Join(c.moduleRoot, filepath.FromSlash(root.id.Path))
		}
		if resolved, _, ok := chainResolve(start); ok {
			c.resolved[i] = resolved
		}
	}
	return c
}

// covers reports whether a recorded identity is bracket-covered
// (REQ-inputs-value-binding, REQ-inputs-bracket-coverage): the object it
// materializes to under kernel path-walk semantics resolves, after every
// symlink in the walk, to a path under a declared root's own resolved path,
// and every symlink the walk traverses — directory components included —
// itself lies under a declared root's resolved path. A within-root link's
// target string is recorded by the root's directory fingerprint (or its
// content is follow-hashed when the link is the root itself), so a retarget
// moves the bracket; a link outside every root is invisible to the
// fingerprint, so a mid-span retarget would silently rebind the identity —
// that identity is uncovered, never bound, and the offending link's path is
// returned for the attributable reason. An excluded identity, or one whose
// resolved object or traversed link sits in a root subtree the bracket's
// exclusions removed from the fingerprint, is uncovered however near a root
// it lies.
func (c bracketCoverage) covers(id pathID) (bool, string, error) {
	b := c.bracket
	if excludesIdentity(b.exclusions, id) {
		return false, "", nil
	}
	if _, err := materializePath(b.moduleDir, id); err != nil {
		return false, "", err
	}
	if id.Kind == pathAbs {
		covered, escaped := c.coversAbsolute(id)
		return covered, escaped, nil
	}
	start := filepath.Join(c.moduleRoot, filepath.FromSlash(id.Path))
	resolved, links, ok := chainResolve(start)
	if !ok {
		return false, "", nil
	}
	if !c.contains(resolved, false) {
		return false, "", nil
	}
	for _, link := range links {
		if !c.contains(link, false) {
			return false, link, nil
		}
	}
	return true, "", nil
}

// coversAbsolute is the absolute-identity leg of covers: only an absolute
// root can cover, and the walk is read from the covering root's own resolved
// position. An absolute root is follow-hashed through its full chain
// (hashPath resolves it with os.Stat), so a retarget of any link above the
// root already moves the root digest — the prefix needs no residence check,
// which keeps identities under symlinked host prefixes (macOS /var and /tmp,
// merged-usr Linux) coverable. Links at or below the root's position remain
// subject to the residence rule exactly as for relative identities. An
// identity lexically under no declared absolute root is uncovered: its own
// prefix chain is pinned by nothing.
func (c bracketCoverage) coversAbsolute(id pathID) (bool, string) {
	b := c.bracket
	escaped := ""
	for i, root := range b.roots {
		if root.id.Kind != pathAbs || c.resolved[i] == "" {
			continue
		}
		offset, under := pathOffset(root.id.Path, id.Path)
		if !under {
			continue
		}
		start := c.resolved[i]
		if offset != "." {
			start = filepath.Join(start, filepath.FromSlash(offset))
		}
		resolved, links, ok := chainResolve(start)
		if !ok {
			continue
		}
		if !c.contains(resolved, true) {
			continue
		}
		rootEscaped := ""
		for _, link := range links {
			if !c.contains(link, false) {
				rootEscaped = link
				break
			}
		}
		if rootEscaped == "" {
			return true, ""
		}
		if escaped == "" {
			escaped = rootEscaped
		}
	}
	return false, escaped
}

// contains reports whether target lies at or under a declared root's own
// resolved path, outside every excluded subtree; absOnly restricts the
// candidate roots to absolute ones.
func (c bracketCoverage) contains(target string, absOnly bool) bool {
	b := c.bracket
	for i, root := range b.roots {
		if c.resolved[i] == "" {
			continue
		}
		if absOnly && root.id.Kind != pathAbs {
			continue
		}
		offset, under := pathOffset(c.resolved[i], target)
		if !under {
			continue
		}
		if excludesIdentity(b.exclusions, walkIdentity(root.id, offset)) {
			continue
		}
		return true
	}
	return false
}

// chainResolve resolves the object p materializes to under kernel path-walk
// semantics, reporting the final resolved path and the path of every symlink
// the walk traverses — directory components included — in walk order. A
// missing suffix joins lexically: nothing at or beneath a missing component
// exists, so no remaining step can traverse a symlink, and the absent object
// stays coverable by the root whose fingerprint pins its absence. The lexical
// join also collapses a dot-dot past a missing component where the kernel
// would report the path nonexistent — a harmless divergence: either way the
// object hashes as missing and its appearance moves a covering root's
// fingerprint, so no value is ever falsely bound. A dot-dot step on the
// existing portion is taken on the resolved prefix, which contains no
// symlink, so its lexical parent is the object the kernel reaches. A walk
// that cannot be inspected or exceeds the link-hop budget reports no
// resolution, leaving the identity uncovered rather than guessed.
func chainResolve(p string) (string, []string, bool) {
	// maxLinkHops mirrors filepath.EvalSymlinks' link budget; the kernel's
	// own limit is lower (40 on Linux), so exhausting it here is only ever
	// more conservative.
	const maxLinkHops = 255
	sep := string(filepath.Separator)
	volume := filepath.VolumeName(p)
	resolved := volume + sep
	pending := strings.Split(p[len(volume):], sep)
	var links []string
	hops := 0
	for len(pending) > 0 {
		component := pending[0]
		pending = pending[1:]
		switch component {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, component)
		info, err := os.Lstat(next)
		if os.IsNotExist(err) {
			return filepath.Join(append([]string{next}, pending...)...), links, true
		}
		if err != nil {
			return "", nil, false
		}
		if info.Mode()&os.ModeSymlink == 0 {
			resolved = next
			continue
		}
		hops++
		if hops > maxLinkHops {
			return "", nil, false
		}
		links = append(links, next)
		target, err := os.Readlink(next)
		if err != nil {
			return "", nil, false
		}
		// An empty target — not creatable via os.Symlink, but representable
		// on disk — splits to one empty component and resolves to the link's
		// parent.
		if filepath.IsAbs(target) {
			volume = filepath.VolumeName(target)
			resolved = volume + sep
			pending = append(strings.Split(target[len(volume):], sep), pending...)
			continue
		}
		pending = append(strings.Split(target, sep), pending...)
	}
	return resolved, links, true
}

// pathOffset reports whether p is root itself or lies beneath it, returning
// the slash-form offset ("." for root itself).
func pathOffset(root, p string) (string, bool) {
	if p == root {
		return ".", true
	}
	sep := string(filepath.Separator)
	if strings.HasPrefix(p, root+sep) {
		return filepath.ToSlash(p[len(root)+len(sep):]), true
	}
	return "", false
}

// walkIdentity is the identity the bracket fingerprint walk assigns the
// object at offset beneath root — the position exclusion patterns are matched
// against.
func walkIdentity(root pathID, offset string) pathID {
	if offset == "." {
		return root
	}
	if root.Kind == pathRel {
		return pathID{Kind: pathRel, Path: path.Join(root.Path, offset)}
	}
	return pathID{Kind: pathAbs, Path: filepath.Join(root.Path, filepath.FromSlash(offset))}
}

// sealBracket pins every capture-derived field, so revalidation can refuse a
// bracket that capture did not produce.
func sealBracket(b Bracket) string {
	h := sha256.New()
	fprintf(h, "bracket-seal %d\nmodule %s\nfingerprint %s\nreason %s\n", manifestVersion, b.moduleDir, b.fingerprint, b.reason)
	for _, q := range b.exclusions {
		fprintf(h, "exclude %s %s\n", q.Kind, q.Path)
	}
	for _, root := range b.roots {
		fprintf(h, "root %s %s %s\n", root.id.Kind, root.id.Path, root.digest)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sortPathIDs(ids []pathID) {
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].Kind != ids[j].Kind {
			return ids[i].Kind < ids[j].Kind
		}
		return ids[i].Path < ids[j].Path
	})
}
