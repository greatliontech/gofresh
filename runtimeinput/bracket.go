package runtimeinput

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	if b.seal == "" || sealBracket(b) != b.seal {
		return false, "", errors.New("runtimeinputs: bracket seal is invalid")
	}
	moduleDir, err := filepath.Abs(moduleDir)
	if err != nil {
		return false, "", fmt.Errorf("runtimeinputs: module dir: %w", err)
	}
	if moduleDir != b.moduleDir {
		return false, "", fmt.Errorf("runtimeinputs: bracket captured under module view %q revalidated under %q", b.moduleDir, moduleDir)
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
	unverifiable, reason, err := hashPath(ctx, h, id, p, moduleDir, bracketSkip(id, exclusions))
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
