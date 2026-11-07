package runtimeinput

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/guard"
	"github.com/greatliontech/gofresh/internal/outcome"
)

// TestLogOption configures observation construction from a testlog.
type TestLogOption func(*testLogConfig)

type testLogConfig struct {
	excluded   []pathID
	guardRoots []guardRootDecl
	// ephemeralRoots are declared temp roots whose own identity records
	// nothing (REQ-inputs-ephemeral-root).
	ephemeralRoots []string
	// scratchNamespaces are declared in-module run-scratch namespaces
	// whose endpoint-absent reads record nothing
	// (REQ-inputs-scratch-namespace).
	scratchNamespaces []scratchNamespace
	process           string
	// outcomeSubjects is set only by the facade after validating the separate
	// execution premises. Public identity-only options cannot construct it.
	outcomeSubjects []string
	bracket         *Bracket
	err             error
}

type guardRootDecl struct {
	path string
	// excludeSub names one direct subtree that stays observed — the
	// module cache's mutable "cache" metadata, the build cache's
	// discovered "fuzz" corpus; empty covers the whole root.
	excludeSub string
}

// WithCompletedProcess asserts that process terminated normally. It supplies
// identity evidence only, never independently established operation outcomes.
// Process must identify that contributing process uniquely and consistently across
// every observation in a merge. A caller lacking normal completion uses Incomplete.
func WithCompletedProcess(process string) TestLogOption {
	return func(c *testLogConfig) {
		if c.process != "" {
			c.err = errors.New("runtimeinputs: duplicate completed process assertion")
			return
		}
		if err := validateProcess(process); err != nil {
			c.err = err
			return
		}
		c.process = process
	}
}

// WithBracket supplies the observation bracket a completed observation is
// constructed against (REQ-inputs-value-binding): a fingerprint the caller
// captured with CaptureBracket before the producing process started, under
// the same module view the observation is constructed under. Construction
// revalidates the bracket strictly after the manifest digest's last input
// read: an unchanged bracket binds the digest of every covered recorded
// identity to the values read at any time in the capture-to-revalidation
// span, while a moved bracket records nonwaivable guard failure, an unknown
// bracket records attributable unverifiability, and an identity covered by no
// declared root seals per-identity unverifiable — in every case the
// observation still constructs, converts, merges, and checks, never as bound.
// A bracket captured under a different module view than the construction, or
// one CaptureBracket did not produce, is refused. Passing a bracket captured
// after the producing process started is the caller's violation of the
// capture-before-start obligation; it cannot be detected here.
func WithBracket(bracket Bracket) TestLogOption {
	return func(c *testLogConfig) {
		if c.bracket != nil {
			c.err = errors.New("runtimeinputs: duplicate observation bracket")
			return
		}
		c.bracket = &bracket
	}
}

// withToolchainRoot declares the producing toolchain's GOROOT as a
// guard-covered root (REQ-inputs-guard-covered): a clean absolute path
// resolved from the same environment the producing run used. Reads provably
// inside it record neither a path identity nor a per-path disposition — the
// toolchain guard already pins that content, the closure model's own stdlib
// collapse. The skip is fail-closed: symlink chains touching anything outside
// the root, ambiguous resolutions, and missing objects stay observed.
func withToolchainRoot(root string) TestLogOption {
	return guardRootOption(root, "")
}

// withModuleCacheRoot declares the producing environment's GOMODCACHE as a
// guard-covered root (REQ-inputs-guard-covered) for its version-addressed
// extracted module trees, which immutable version pinning already covers. The
// download cache subtree (`cache/`) holds mutable metadata no guard pins —
// version lists, lock files — and stays observed. The same fail-closed
// resolution rules as the toolchain root apply.
func withModuleCacheRoot(root string) TestLogOption {
	return guardRootOption(root, "cache")
}

// withBuildCacheRoot declares the producing environment's GOCACHE as a
// guard-covered root (REQ-inputs-guard-covered), its discovered `fuzz`
// corpus excepted. The admission is toolchain-mediated observational
// equivalence, not per-object immutability: everything else under the
// build cache — the mutable action index and its bookkeeping included —
// is machinery whose consumption through the go toolchain yields
// behavior determined by inputs the fingerprint already pins (sources
// through the closure, the toolchain through its guard, the build
// configuration), so any correct cache state is observationally
// equivalent and re-observing adds no protection while churn under
// concurrent builds forfeits reuse for free. The fuzz corpus is the
// counterexample that stays observed: discovered machine-local state a
// -fuzz run consumes semantically, derivable from nothing the
// fingerprint pins. The same fail-closed resolution rules as the
// toolchain root apply.
func withBuildCacheRoot(root string) TestLogOption {
	return guardRootOption(root, "fuzz")
}

// applyTestLogOptions applies the declaration options in order: the
// first malformed declaration refuses, so a caller sees one refusal
// naming the earliest fault.
func applyTestLogOptions(opts []TestLogOption) (testLogConfig, error) {
	var c testLogConfig
	for _, opt := range opts {
		opt(&c)
		if c.err != nil {
			return c, c.err
		}
	}
	return c, nil
}

// cleanAbsoluteRoot is the one admission of a declared absolute root: a
// non-empty, clean, absolute path.
func cleanAbsoluteRoot(kind, root string) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return fmt.Errorf("runtimeinputs: %s must be a clean absolute path, got %q", kind, root)
	}
	return nil
}

func guardRootOption(root, excludeSub string) TestLogOption {
	return func(c *testLogConfig) {
		if err := cleanAbsoluteRoot("guard-covered root", root); err != nil {
			c.err = err
			return
		}
		c.guardRoots = append(c.guardRoots, guardRootDecl{path: root, excludeSub: excludeSub})
	}
}

// WithExcludedPaths declares path exclusions (REQ-inputs-exclusions):
// each pattern is a non-empty identity-form path — module-relative, or
// clean absolute — excluding the identical identity of its kind and
// every identity of that kind extending it past a path separator; the
// root listings "." and "/" exclude only themselves. An excluded
// observation records neither a path identity nor a per-path
// disposition; the exclusion is the caller's assertion that those
// paths are not inputs of the subject, with the same soundness
// responsibility as attaching no manifest. Exclusion is per identity,
// never per content: a recorded directory identity still digests
// everything its hash walks, so silencing a volatile subtree means
// excluding both the subtree and every recorded ancestor listing whose
// digest observes it. Patterns that can name no identity — a relative
// path escaping the module, an absolute path inside it — exclude
// nothing. Environment identities are never excluded.
func WithExcludedPaths(patterns ...string) TestLogOption {
	return func(c *testLogConfig) {
		excluded, err := exclusionPatterns(patterns)
		if err != nil {
			c.err = err
			return
		}
		c.excluded = append(c.excluded, excluded...)
	}
}

// exclusionPatterns normalizes exclusion patterns to identity form: a non-empty
// module-relative or clean absolute path (REQ-inputs-exclusions). An empty
// pattern is refused rather than read as anything.
func exclusionPatterns(patterns []string) ([]pathID, error) {
	var excluded []pathID
	for _, q := range patterns {
		if q == "" {
			return nil, errors.New("runtimeinputs: empty exclusion pattern")
		}
		if filepath.IsAbs(q) {
			excluded = append(excluded, pathID{Kind: pathAbs, Path: filepath.Clean(q)})
			continue
		}
		excluded = append(excluded, pathID{Kind: pathRel, Path: path.Clean(filepath.ToSlash(q))})
	}
	return excluded, nil
}

// excludes reports whether id falls under any declared exclusion.
func (c *testLogConfig) excludes(id pathID) bool {
	return excludesIdentity(c.excluded, id)
}

// lexicalPathID returns the lexical pathID for p under moduleDir before any
// filesystem probe.
func lexicalPathID(moduleDir, p string) (pathID, bool) {
	if rel, ok := relUnder(moduleDir, p); ok {
		return pathID{Kind: pathRel, Path: filepath.ToSlash(rel)}, true
	}
	if filepath.IsAbs(p) {
		return pathID{Kind: pathAbs, Path: filepath.Clean(p)}, true
	}
	return pathID{}, false
}

// excludesRaw consults the exclusions for an observed path BEFORE
// classification: a classification refusal (an external directory, a
// volatile-OS object) must not outrank the caller's exclusion — the
// exclusion is precisely the assertion that the surface is no input,
// and a refusal-first ordering would make classifier-refused paths
// unexcludable, defeating the contract for exactly the surfaces it
// exists to cover (REQ-inputs-exclusions).
func (c *testLogConfig) excludesRaw(moduleDir, p string) bool {
	if len(c.excluded) == 0 {
		return false
	}
	id, ok := lexicalPathID(moduleDir, p)
	return ok && c.excludes(id)
}

// excludesIdentity reports whether id falls under any declared exclusion:
// equal, or extending it past a separator. Relative identities are
// slash-separated; absolute identities carry the host separator.
func excludesIdentity(excluded []pathID, id pathID) bool {
	for _, q := range excluded {
		if q.Kind != id.Kind {
			continue
		}
		sep := "/"
		if q.Kind == pathAbs {
			sep = string(filepath.Separator)
		}
		if id.Path == q.Path || strings.HasPrefix(id.Path, q.Path+sep) {
			return true
		}
	}
	return false
}

// FromTestLog builds a runtime-input manifest from a Go testlog stream and
// computes its digest against the current filesystem and env, the
// complete process environment the producing process ran under.
// The result is identity evidence only. No outcome support is inferred from the
// normal-process assertion or bracket; the producer facade supplies that separate
// premise from its execution-bound capability.
func FromTestLog(log []byte, moduleDir, packageDir string, env []string, opts ...TestLogOption) (Observation, error) {
	return fromTestLog(context.Background(), log, moduleDir, packageDir, env, opts...)
}

func fromTestLog(ctx context.Context, log []byte, moduleDir, packageDir string, env []string, opts ...TestLogOption) (Observation, error) {
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	cfg, err := applyTestLogOptions(opts)
	if err != nil {
		return Observation{}, err
	}
	if cfg.process == "" {
		return Observation{}, errors.New("runtimeinputs: completed observation needs a process assertion")
	}
	if cfg.bracket == nil {
		return Observation{}, errors.New("runtimeinputs: completed observation needs an observation bracket")
	}
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		return Observation{}, err
	}
	moduleDir, err = filepath.Abs(moduleDir)
	if err != nil {
		return Observation{}, err
	}
	packageDir, err = filepath.Abs(packageDir)
	if err != nil {
		return Observation{}, err
	}
	if err := cfg.bracket.checkSealed(); err != nil {
		return Observation{}, err
	}
	if err := cfg.bracket.checkModuleView(moduleDir); err != nil {
		return Observation{}, err
	}

	m := manifest{Version: manifestVersion}
	if len(cfg.outcomeSubjects) != 0 {
		m.Outcome, m.Subjects = outcome.Method, cfg.outcomeSubjects
	}
	envSeen := map[string]bool{}
	pathIndex := map[pathID]int{}
	unverifiableSeen := map[string]bool{}
	// Each clause's first attributed classification refusal, in log
	// order: construction-time diagnostic detail, never a manifest entry;
	// the observation carries the one attributing the reason the state
	// names (REQ-inputs-refusal-attribution).
	attributions := map[string]string{}
	classifier, err := newPathClassifier(moduleDir, cfg)
	if err != nil {
		return Observation{}, err
	}
	traversalMemo := map[string]bool{}
	existenceBound := map[pathID]bool{}
	nonExistenceBound := map[pathID]bool{}
	bracketStatRoots := declaredBracketStatRoots(cfg.bracket)
	cwd := packageDir
	cwdChanged := false
	// A truthful frozen PWD can be bound as an environment input. The frame
	// establishes this execution's directory, but is not a persisted runtime
	// dependency: a later session can run the same build in another directory.
	// Other postures retain the process-local refusal (REQ-inputs-unbounded).
	pwdValue, pwdPresent := gotool.LookupEnv(normalized, "PWD")
	pwdTruthful := pwdPresent && pwdValue == packageDir

	lines := bytes.Split(log, []byte{'\n'})
	if len(lines) != 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	for _, raw := range lines {
		if err := ctx.Err(); err != nil {
			return Observation{}, err
		}
		line := string(raw)
		if line == "# test log" {
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			addUnverifiable(&m, unverifiableSeen, "malformed testlog line")
			continue
		}
		op, name, ok := strings.Cut(line, " ")
		if !ok || name == "" {
			addUnverifiable(&m, unverifiableSeen, "malformed testlog line")
			continue
		}
		switch op {
		case "getenv":
			if !utf8.ValidString(name) {
				addUnverifiable(&m, unverifiableSeen, "non-UTF-8 environment name")
				continue
			}
			if strings.ContainsAny(name, "\x00\r\n") {
				addUnverifiable(&m, unverifiableSeen, "unrepresentable environment name")
				continue
			}
			if gotool.IsTraceEnvKey(name) {
				continue
			}
			if gotool.EqualEnvKey(name, "PWD") && !pwdTruthful {
				addUnverifiable(&m, unverifiableSeen, "process-local environment input: PWD")
				continue
			}
			if !envSeen[name] {
				envSeen[name] = true
				m.Env = append(m.Env, envInput{Name: name})
			}
		case "open":
			ambiguousParent := ambiguousTraversal(cwd, name, traversalMemo)
			relativeAfterChdir := cwdChanged && !filepath.IsAbs(name)
			p := resolvePath(cwd, name)
			// Guard coverage demands an unambiguous resolution: a traversal
			// whose lexical cleaning may not match the filesystem, or a
			// relative read after a directory change, is never provably
			// inside a root (REQ-inputs-guard-covered fail-closed).
			if !ambiguousParent && !relativeAfterChdir && classifier.elidesUnambiguous(p) {
				continue
			}
			if classifier.excludesRaw(p) {
				continue
			}
			id, reason := classifier.classify(p)
			if reason != "" {
				addUnverifiable(&m, unverifiableSeen, reason)
				noteAttribution(attributions, reason, operationAttribution(op, name, cwd))
				continue
			}
			m.Paths = upsertPath(m.Paths, pathIndex, pathInput{pathID: id})
			nonExistenceBound[id] = true
			delete(existenceBound, id)
			if ambiguousParent {
				addUnverifiable(&m, unverifiableSeen, "ambiguous parent traversal: "+id.displayPath())
			}
			if relativeAfterChdir {
				addUnverifiable(&m, unverifiableSeen, "relative runtime input after working-directory change: "+id.displayPath())
			}
		case "stat":
			ambiguousParent := ambiguousTraversal(cwd, name, traversalMemo)
			relativeAfterChdir := cwdChanged && !filepath.IsAbs(name)
			p := resolvePath(cwd, name)
			if !ambiguousParent && !relativeAfterChdir && classifier.elidesUnambiguous(p) {
				continue
			}
			// The exclusion consult precedes existence-binding as well as
			// classification: an excluded stat contributes nothing — not
			// even a revalidatable existence identity.
			if classifier.excludesRaw(p) {
				continue
			}
			// An external directory's stat binds existence alone — an
			// ancestor probe from path-creation machinery — recording a
			// revalidatable identity instead of sealing metadata
			// (REQ-inputs-external-dir-existence). A stat of an ABSENT
			// external identity likewise binds absence alone
			// (REQ-inputs-absent-stat).
			if !ambiguousParent && !relativeAfterChdir && filepath.IsAbs(p) && utf8.ValidString(p) && !strings.ContainsAny(p, "\x00\r\n") && !volatileOSPath(p) {
				if _, inModule := relUnder(moduleDir, p); !inModule {
					if info, statErr := classifyProbe(p); statErr == nil && info.IsDir() || os.IsNotExist(statErr) {
						id := pathID{Kind: pathAbs, Path: filepath.Clean(p)}
						m.Paths = upsertPath(m.Paths, pathIndex, pathInput{pathID: id})
						if !nonExistenceBound[id] {
							existenceBound[id] = true
						}
						continue
					}
				}
			}
			id, reason := classifier.classify(p)
			if reason != "" {
				addUnverifiable(&m, unverifiableSeen, reason)
				noteAttribution(attributions, reason, operationAttribution(op, name, cwd))
				continue
			}
			m.Paths = upsertPath(m.Paths, pathIndex, pathInput{pathID: id})
			nonExistenceBound[id] = true
			delete(existenceBound, id)
			// The stat observed the full object state, so this entry's
			// digest is metadata-bound from here on even if an earlier
			// open recorded it content-bound
			// (REQ-inputs-observation-class). An existence-bound entry
			// CAN be re-reached here (a post-chdir relative stat of an
			// absent external skips the existence block above) and then
			// carries the mark; that is harmless over-pinning — an
			// absent target digests as missing before any stat stream,
			// and the mark only binds the post-appearance state more
			// tightly.
			m.Paths[pathIndex[id]].Metadata = true
			// A stat under a DECLARED bracket root needs no metadata
			// seal: the bracket fingerprint spans content and metadata
			// over the whole run-to-ingest span — a directory object's
			// own size and mtime excepted, which nothing in the admitted
			// observation set can consume (metadata-returning methods
			// block) — and the entry digest binds the observed state for
			// later checks. A parse-time
			// admission - the seal is never added - so the bracket never
			// removes a reason (REQ-inputs-bracket-coverage's
			// never-weakens clause holds; REQ-inputs-unbounded).
			if !bracketStatRoots.covers(id) {
				addUnverifiable(&m, unverifiableSeen, "stat metadata input: "+id.displayPath())
			}
			if ambiguousParent {
				addUnverifiable(&m, unverifiableSeen, "ambiguous parent traversal: "+id.displayPath())
			}
			if relativeAfterChdir {
				addUnverifiable(&m, unverifiableSeen, "relative runtime input after working-directory change: "+id.displayPath())
			}
		// chdir is deliberately outside every root admission: each chdir
		// independently seals the observation unverifiable, so admitting
		// the identity could never clear anything.
		case "chdir":
			ambiguousParent := ambiguousTraversal(cwd, name, traversalMemo)
			p := resolvePath(cwd, name)
			// An excluded chdir target leaves no per-path disposition —
			// no identity, no classification refusal — but the
			// working-directory seal below and the cwd tracking are the
			// chdir's own observation, never the target path's, and stay.
			if classifier.excludesRaw(p) {
				addUnverifiable(&m, unverifiableSeen, "working-directory change")
			} else {
				id, reason := classifier.classify(p)
				if reason != "" {
					addUnverifiable(&m, unverifiableSeen, reason)
					noteAttribution(attributions, reason, operationAttribution(op, name, cwd))
				} else {
					m.Paths = upsertPath(m.Paths, pathIndex, pathInput{pathID: id})
				}
				addUnverifiable(&m, unverifiableSeen, "working-directory change")
				if reason == "" && ambiguousParent {
					addUnverifiable(&m, unverifiableSeen, "ambiguous parent traversal: "+id.displayPath())
				}
			}
			cwd = p
			cwdChanged = true
		default:
			if !utf8.ValidString(op) || strings.ContainsAny(op, "\x00\r\n") {
				addUnverifiable(&m, unverifiableSeen, "unrepresentable testlog operation")
			} else {
				addUnverifiable(&m, unverifiableSeen, "unrecognized testlog op: "+op)
			}
		}
	}
	if len(log) != 0 && log[len(log)-1] != '\n' {
		addUnverifiable(&m, unverifiableSeen, "malformed testlog line")
	}
	// Resolution-based per-identity coverage (REQ-inputs-value-binding,
	// REQ-inputs-bracket-coverage): a recorded identity is bracket-covered
	// only when the object it materializes to resolves, after every symlink
	// in the walk, under a declared root's own resolved path, and every
	// symlink the walk traverses itself lies under a declared root's resolved
	// path. An uncovered identity — excluded, resolving outside every root,
	// traversing an out-of-root link, or unresolvable — seals per-identity
	// unverifiable, never bound. The reasons enter the manifest before
	// encoding, so they persist and merge with the evidence.
	coverage := cfg.bracket.coverage()
	for _, entry := range m.Paths {
		id := entry.pathID
		// Machine-fact identities are exempt from bracket coverage: the
		// bracket binds values that could change across the run span, and
		// the stable projection these identities digest as (CPU model,
		// cores, memory, kernel) cannot hot-change under a running test
		// process — the projection equality at revalidation IS their
		// binding (REQ-inputs-machine-identity).
		if machineProjected(id) {
			continue
		}
		// Existence-bound identities - external directories and absent
		// stat targets: existence equality at revalidation is their
		// binding, exactly as the machine-fact projection is
		// (REQ-inputs-external-dir-existence, REQ-inputs-absent-stat).
		if existenceBound[id] {
			continue
		}
		covered, escapedLink, err := coverage.covers(id)
		if err != nil {
			return Observation{}, err
		}
		if !covered {
			reason := "runtime input not covered by observation bracket: " + id.displayPath()
			if escapedLink != "" && utf8.ValidString(escapedLink) && !strings.ContainsAny(escapedLink, "\x00\r\n") {
				// covers spells the escaping link as its identity is —
				// module-relative inside the module, so the clause is
				// the same from any checkout; absolute outside it.
				reason += " (symlink outside every bracket root: " + escapedLink + ")"
			}
			addUnverifiable(&m, unverifiableSeen, reason)
		}
	}
	pathUnverifiable, pathReason, err := populateManifestDigests(ctx, &m, moduleDir, normalized)
	if err != nil {
		return Observation{}, err
	}
	st, err := finalizeManifestState(m, pathUnverifiable, pathReason)
	if err != nil {
		return Observation{}, err
	}
	// The bracket is revalidated strictly after the manifest digest's last
	// input read (REQ-inputs-value-binding). Demonstrated movement is retained
	// separately from unknown binding, so purity cannot waive a failed guard.
	unchanged, moved, reason, err := cfg.bracket.revalidate(ctx, moduleDir)
	if err != nil {
		return Observation{}, err
	}
	if !unchanged {
		m.BracketMoved = moved
		if !strings.HasPrefix(reason, "observation bracket") {
			reason = "observation bracket unverifiable: " + reason
		}
		// The manifest carries the refusal's clause; a moved bracket's
		// member list — its attribution, timestamps included — rides the
		// observation's attribution field like a classification
		// refusal's, outside the identity (REQ-inputs-refusal-attribution).
		clause, attribution := splitAttribution(reason)
		if attribution != "" && strings.HasPrefix(reason, movedBracketClause) {
			noteAttribution(attributions, clause, attribution)
			reason = clause
		}
		addUnverifiable(&m, unverifiableSeen, reason)
		if st, err = finalizeManifestState(m, pathUnverifiable, pathReason); err != nil {
			return Observation{}, err
		}
	}
	origin := "identity-only"
	if m.Outcome != "" {
		origin = "outcome-supported"
	}
	observation := newObservation(st, cfg.process, origin)
	// The attribution is the one of the reason the state names — the
	// first clause of the sorted manifest; a reason the hashing pass
	// raised carries its own attribution, in the reason itself.
	observation.Attribution = attributions[st.Reason]
	return observation, nil
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
