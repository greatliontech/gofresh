package runtimeinput

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// ScratchNamespace declares one in-module run-scratch namespace for the
// ingest (REQ-inputs-scratch-namespace): a module-relative directory and
// a single-component name pattern with os.MkdirTemp semantics.
type ScratchNamespace struct {
	Dir     string
	Pattern string
}

// scratchNamespace is one declared run-scratch namespace: the direct
// children of dir whose basename matches prefix*suffix — the shape
// os.MkdirTemp and os.CreateTemp mint — and everything beneath them.
type scratchNamespace struct {
	dir    pathID
	prefix string
	suffix string
}

// matches reports whether id lies strictly inside the namespace: a
// matching direct child of dir, or deeper.
func (n scratchNamespace) matches(id pathID) bool {
	if id.Kind != pathRel {
		return false
	}
	rel := ""
	if n.dir.Path == "." {
		rel = id.Path
	} else if strings.HasPrefix(id.Path, n.dir.Path+"/") {
		rel = id.Path[len(n.dir.Path)+1:]
	} else {
		return false
	}
	first, _, _ := strings.Cut(rel, "/")
	if len(first) < len(n.prefix)+len(n.suffix) {
		return false
	}
	return strings.HasPrefix(first, n.prefix) && strings.HasSuffix(first[len(n.prefix):], n.suffix)
}

// childOffset returns the walk offset, relative to the bracket root, of
// the namespace's matching child on id's path — the anchor of the
// freshness proof. id must satisfy matches. A child at or above the
// root itself maps to ".", which the capture listing always carries for
// a root that existed — a conservative veto.
func (n scratchNamespace) childOffset(root, id pathID) string {
	rel := id.Path
	if n.dir.Path != "." {
		rel = id.Path[len(n.dir.Path)+1:]
	}
	first, _, _ := strings.Cut(rel, "/")
	child := first
	if n.dir.Path != "." {
		child = n.dir.Path + "/" + first
	}
	if root.Path == "." {
		return child
	}
	if child == root.Path {
		return "."
	}
	if strings.HasPrefix(child, root.Path+"/") {
		return child[len(root.Path)+1:]
	}
	return "."
}

// withEphemeralTempRoot declares one of the producing environment's temp
// directories as an ephemeral root (REQ-inputs-ephemeral-root): the root's
// OWN identity — declared or resolved form — records nothing, because
// temp-tree creation machinery stats it to mint fresh per-run subtrees and
// no state a subject observes flows from its existing content. A deeper
// read whose object is absent at observation ingest likewise records
// nothing — per-run scratch by construction — while a deeper read still
// present at ingest stays observed, and an unresolvable root declares
// nothing.
func withEphemeralTempRoot(root string) TestLogOption {
	return func(c *testLogConfig) {
		if err := cleanAbsoluteRoot("ephemeral temp root", root); err != nil {
			c.err = err
			return
		}
		c.ephemeralRoots = append(c.ephemeralRoots, root)
	}
}

// WithScratchNamespace declares one in-module run-scratch namespace
// (REQ-inputs-scratch-namespace): the direct children of dir — a
// module-relative identity-form path, "." for the module root — whose
// basename matches pattern under os.MkdirTemp semantics (the random
// string replaces the last "*", or is appended when the pattern has
// none), and everything beneath them. A read inside the namespace is
// admitted recordless only when the engine proves the path absent at
// BOTH bracket endpoints — absent from the observation bracket's
// capture listing and absent again at observation ingest, under the
// bracket's fail-closed resolution rules — so a pre-existing object the
// pattern happens to match stays observed and a run-created object that
// outlives the run stays observed and moves the bracket. The declaration is
// the caller's assertion that an absence-probe of a name the pattern
// matches is not a meaningful input of the subject: that appearance-pin
// is the namespace's one forfeited protection, a blast radius one
// declared namespace wide. A namespace not covered by a declared
// observation-bracket root is inert: without the bracket's endpoint
// evidence nothing can be proven absent-before, so its reads stay
// observed.
func WithScratchNamespace(dir, pattern string) TestLogOption {
	return func(c *testLogConfig) {
		n, err := compileScratchNamespace(dir, pattern)
		if err != nil {
			c.err = err
			return
		}
		c.scratchNamespaces = append(c.scratchNamespaces, n)
	}
}

// MatchesPath reports syntactic coverage by the namespace using the same
// matcher as WithScratchNamespace. It performs no filesystem or environment
// reads and grants no observation admission: bracket coverage, matching-child
// absence at capture, and path absence at ingest remain separate obligations.
//
// Dir is normalized exactly as WithScratchNamespace normalizes it: host
// separators become slashes and lexical cleaning removes dot components.
// Pattern replaces its last "*" with any string (including empty), or accepts
// any suffix when it has no "*". Earlier stars are literal, prefix and suffix
// cannot overlap, and descendants of a matching child also match. The native
// matcher's conservative root behavior is retained: Dir "." with Pattern "*"
// also matches the module-root identity "."; this proves no root absence.
//
// identityPath must already be canonical identity form: a slash-separated
// module-relative path ("." for the module root), or a clean absolute host
// path. Absolute paths retain their absolute kind and never match; callers
// must express in-module paths relatively. No module root is inferred and
// identityPath is neither cleaned nor resolved. Invalid declarations or path
// identities return false and an error under the ingest declaration grammar
// and manifest path grammar, respectively.
func (n ScratchNamespace) MatchesPath(identityPath string) (bool, error) {
	compiled, err := compileScratchNamespace(n.Dir, n.Pattern)
	if err != nil {
		return false, err
	}
	id := pathID{Kind: pathRel, Path: identityPath}
	if filepath.IsAbs(identityPath) {
		id.Kind = pathAbs
	}
	if err := validatePathID(id); err != nil {
		return false, err
	}
	return compiled.matches(id), nil
}

func compileScratchNamespace(dir, pattern string) (scratchNamespace, error) {
	if err := ValidateScratchNamespace(dir, pattern); err != nil {
		return scratchNamespace{}, err
	}
	clean := path.Clean(filepath.ToSlash(dir))
	prefix, suffix := pattern, ""
	if i := strings.LastIndex(pattern, "*"); i >= 0 {
		prefix, suffix = pattern[:i], pattern[i+1:]
	}
	return scratchNamespace{dir: pathID{Kind: pathRel, Path: clean}, prefix: prefix, suffix: suffix}, nil
}

// ValidateScratchNamespace is the scratch-namespace grammar
// (REQ-inputs-scratch-namespace) as a standalone check, so a producer
// taking declarations at its own boundary can refuse a malformed one up
// front — before a measurement whose every observation would otherwise
// degrade at ingest.
func ValidateScratchNamespace(dir, pattern string) error {
	if pattern == "" || !utf8.ValidString(pattern) || strings.ContainsAny(pattern, "\x00\r\n") || strings.ContainsAny(pattern, `/\`) {
		return fmt.Errorf("runtimeinputs: scratch namespace pattern must be a non-empty single path component, got %q", pattern)
	}
	if dir == "" || filepath.IsAbs(dir) || !utf8.ValidString(dir) || strings.ContainsAny(dir, "\x00\r\n") {
		return fmt.Errorf("runtimeinputs: scratch namespace dir must be a module-relative path, got %q", dir)
	}
	clean := path.Clean(filepath.ToSlash(dir))
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("runtimeinputs: scratch namespace dir escapes module: %q", dir)
	}
	return nil
}

// bracketEphemera is the ingest-side scratch-namespace admission view: per
// declared module-relative root, its lexical and resolved absolute bases
// plus the capture membership, so the open/stat ladder can decide whether
// an observed path existed before the run without re-walking anything.
// Only reads inside a declared scratch namespace are candidates: the
// testlog carries no outcomes, so an endpoint-absent path is otherwise
// indistinguishable from an absence-probe whose appearance-pin must stay
// recorded (REQ-inputs-scratch-namespace).
type bracketEphemera struct {
	roots      []ephemeraRoot
	namespaces []scratchNamespace
	exclusions []pathID
}

type ephemeraRoot struct {
	id       pathID
	lexBase  string
	resolved string
	members  map[string]bool
}

// ephemera builds the scratch-namespace admission view. A nil or
// capture-unverifiable bracket admits nothing, exactly as it declares no
// stat roots, and no declared namespace admits nothing; absolute roots
// are outside the admission — a scratch namespace is declared
// module-relative (REQ-inputs-scratch-namespace), so nothing under an
// absolute root can match one, and its reads stay observed, the safe
// direction.
func (b *Bracket) ephemera(namespaces []scratchNamespace) bracketEphemera {
	e := bracketEphemera{}
	if b == nil || b.reason != "" || len(namespaces) == 0 {
		return e
	}
	e.namespaces = namespaces
	e.exclusions = b.exclusions
	for _, root := range b.roots {
		if root.id.Kind != pathRel || len(root.members) == 0 {
			continue
		}
		lexBase := filepath.Join(b.moduleDir, filepath.FromSlash(root.id.Path))
		resolved, err := filepath.EvalSymlinks(lexBase)
		if err != nil {
			// An unresolvable root (absent, or broken along its chain)
			// grants no admission: its reads stay observed.
			continue
		}
		e.roots = append(e.roots, ephemeraRoot{id: root.id, lexBase: lexBase, resolved: resolved, members: root.members})
	}
	return e
}

// admits reports whether p is declared run scratch under a declared
// bracket root: strictly inside a declared scratch namespace, absent from
// the covering root's capture membership, and absent again at observation
// ingest — with both endpoints proven, the declaration's only assertion is
// that an absence-probe of a namespace-matching name is not a meaningful
// input. Fail-closed on resolution exactly as the ephemeral-scratch
// admission: the nearest existing ancestor must resolve under the root's
// resolved base, so a traversal through an existing escaping link stays
// observed. A path in the capture membership is never admitted — and a
// pre-existing object the run consumed and removed also moves the root's
// digest at revalidation, so the masquerade direction seals the whole
// observation rather than binding. An identity under a bracket exclusion
// is refused: its subtree is outside the fingerprint, so pre-run absence
// is unknowable.
func (e bracketEphemera) admits(p string, memo map[string]bool) bool {
	if len(e.roots) == 0 {
		return false
	}
	if v, ok := memo[p]; ok {
		return v
	}
	res := func() bool {
		for _, root := range e.roots {
			offset, under := pathOffset(root.lexBase, p)
			if !under {
				offset, under = pathOffset(root.resolved, p)
			}
			if !under || offset == "." {
				continue
			}
			id := walkIdentity(root.id, offset)
			var matched scratchNamespace
			inNamespace := false
			for _, ns := range e.namespaces {
				if ns.matches(id) {
					matched, inNamespace = ns, true
					break
				}
			}
			if !inNamespace {
				continue
			}
			if excludesIdentity(e.exclusions, id) {
				continue
			}
			// The freshness proof anchors at the namespace's matching child:
			// a legitimate scratch mint is freshly created, so its child is
			// never in the capture listing. A pre-existing matching child —
			// a data directory the pattern happens to name, or a symlink
			// aliasing real state elsewhere (a bracket-excluded subtree
			// included, where the bracket digest could not backstop the
			// consumed-and-removed direction) — vetoes everything beneath
			// it, not just its own identity.
			if root.members[offset] || root.members[matched.childOffset(root.id, id)] {
				return false
			}
			targetP := filepath.Join(root.resolved, filepath.FromSlash(offset))
			if _, err := os.Lstat(targetP); !os.IsNotExist(err) {
				return false
			}
			anc, resolved, ok := nearestExistingAncestor(targetP)
			return ok && resolved == anc && pathWithin(root.resolved, resolved)
		}
		return false
	}()
	memo[p] = res
	return res
}

// resolveEphemeralRoots resolves each declared ephemeral root once into
// its identity pair; an unresolvable root declares nothing. A root
// equal to or inside the module tree — in either form — is refused
// loudly: swallowing a module-relative identity would silently vacate a
// content-bearing directory digest, the opposite of the class's
// one-external-identity blast radius (REQ-inputs-ephemeral-root).
func resolveEphemeralRoots(roots []string, moduleDir, resolvedModule string) ([][2]string, error) {
	if resolvedModule == "" {
		resolvedModule = resolveModuleRoot(moduleDir)
	}
	out := make([][2]string, 0, len(roots))
	for _, r := range roots {
		// The declared form's interiority is checkable without
		// resolution, so it refuses before the unresolvable skip — the
		// spec promises refusal in either form outright.
		if pathWithin(moduleDir, r) || pathWithin(resolvedModule, r) {
			return nil, fmt.Errorf("runtimeinputs: ephemeral temp root %q lies inside the module tree; it would vacate module-relative inputs", r)
		}
		// A volatile-OS root can never be per-run scratch, and admitting
		// it would vacate volatile reads recordless while the scratch
		// walk probed them (REQ-inputs-volatile-os-roots).
		if volatileOSPath(filepath.Clean(r)) {
			return nil, fmt.Errorf("runtimeinputs: ephemeral temp root %q lies under a volatile OS root", r)
		}
		resolved, err := filepath.EvalSymlinks(r)
		if err != nil {
			continue
		}
		if pathWithin(moduleDir, resolved) || pathWithin(resolvedModule, resolved) {
			return nil, fmt.Errorf("runtimeinputs: ephemeral temp root %q resolves inside the module tree; it would vacate module-relative inputs", r)
		}
		out = append(out, [2]string{r, resolved})
	}
	return out, nil
}

// ephemeralRoot reports whether p IS a declared ephemeral root — the one
// identity the class admits; depth is never covered
// (REQ-inputs-ephemeral-root).
func ephemeralRoot(p string, roots [][2]string) bool {
	for _, r := range roots {
		if p == r[0] || p == r[1] {
			return true
		}
	}
	return false
}

// ephemeralScratch reports whether p lies under a declared ephemeral
// root with its object absent at ingest: per-run scratch by
// construction — state that outlived the run would still be present and
// stay observed. (Callers test ephemeralRoot first, so the root's own
// identity never reaches here; pathWithin alone would also admit
// p == root.) Fail-closed on resolution: the nearest existing ancestor
// must resolve under a root's resolved form — an existing-but-dangling
// link ancestor refuses — so a traversal through an existing escaping
// link stays observed; a since-vanished redirecting link component is
// the class's accepted one-run residual (REQ-inputs-ephemeral-root).
// A module tree inside the root never surrenders its identities: the
// caller gates on lexical module interiority, and the ancestor's
// RESOLVED position is additionally refused under resolvedModule here,
// so an alias route into the module (outer/alias -> mod) cannot re-open
// what the lexical gate closed.
func ephemeralScratch(p string, roots [][2]string, resolvedModule string, memo map[string]bool) bool {
	if len(roots) == 0 {
		return false
	}
	if v, ok := memo[p]; ok {
		return v
	}
	res := func() bool {
		under := false
		for _, r := range roots {
			if pathWithin(r[0], p) || pathWithin(r[1], p) {
				under = true
				break
			}
		}
		if !under {
			return false
		}
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			return false
		}
		// The nearest existing ancestor must resolve inside a declared
		// root: an existing out-of-root link on the path means the
		// runtime read escaped and must stay observed.
		resolved, ok := nearestExistingAncestorResolved(p)
		if !ok {
			return false
		}
		if pathWithin(resolvedModule, resolved) {
			return false
		}
		for _, r := range roots {
			if pathWithin(r[1], resolved) {
				return true
			}
		}
		return false
	}()
	memo[p] = res
	return res
}

// nearestExistingAncestorResolved walks up from p's parent to the
// nearest existing ancestor and resolves it. An ancestor that EXISTS
// but does not resolve — a dangling link — is detectable evidence the
// runtime read escaped and refuses; only a truly absent ancestor
// ascends. Shared by the ephemeral-scratch and scratch-namespace
// admissions so both keep identical fail-closed resolution.
func nearestExistingAncestor(p string) (anc, resolved string, ok bool) {
	anc = filepath.Dir(p)
	for {
		resolved, err := filepath.EvalSymlinks(anc)
		if err == nil {
			return anc, resolved, true
		}
		if _, lerr := os.Lstat(anc); !os.IsNotExist(lerr) {
			return "", "", false
		}
		parent := filepath.Dir(anc)
		if parent == anc {
			return "", "", false
		}
		anc = parent
	}
}

func nearestExistingAncestorResolved(p string) (string, bool) {
	_, resolved, ok := nearestExistingAncestor(p)
	return resolved, ok
}
