// Package runtimeinput records and re-hashes non-source inputs observed by a
// measured process through Go's testlog channel (spec REQ-inputs-guard).
//
// Completed observations bind observed values through an observation bracket
// (REQ-inputs-value-binding): a fingerprint over caller-declared candidate
// roots, captured before the producing process starts and revalidated
// strictly after the manifest digest's last input read. Capture over declared
// roots is the only pre-run surface available — the observed path set exists
// only in the testlog the run produces, so hashing each observed path before
// the run is structurally unavailable, and digesting the recorded paths twice
// after the run observes only post-run values twice: neither digest connects
// to what the run read. Bracketing the whole span instead makes an unchanged
// fingerprint evidence that every covered value persisted from before the
// first read to after the last hash. Coverage is resolution-based and
// chain-complete: an identity is bound only when its kernel path walk — every
// traversed symlink included — stays under a declared root's resolved path,
// because a link outside every root is invisible to the fingerprint and could
// be retargeted between two in-root objects mid-span without moving it.
//
// A completed observation of newly read values exists only as a live sealed
// value from the bracket-gated constructor. Observation's provenance fields
// are unexported; the manifest string in State is the only wire form, and
// merge, absolute conversion, and dirty inspection each refuse a value whose
// seal construction did not produce. The one re-entry from the wire form is
// Adopt (REQ-inputs-adoption): it re-admits a persisted manifest as a sealed
// observation in the caller-trusted persistence class recorded fingerprints
// already occupy — provenance unauthenticatable, no bracket behind the
// re-admitted values, every recorded identity re-evaluated against the
// adoption-time view and refused on disagreement. Bracket-backed value
// binding therefore remains unrepresentable to fabricate for fresh
// observations, while adopted evidence is exactly as trustworthy as the
// caller's own store.
package runtimeinput

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/gofresh/internal/processenv"
)

const manifestVersion = 1

const (
	pathRel = "rel"
	pathAbs = "abs"
)

// State is the current digest of a recorded runtime-input manifest.
type State struct {
	Manifest     string
	Digest       string
	Unverifiable bool
	Reason       string
	OK           bool
}

// Observation is producer-constructed runtime-input evidence. Its private process
// provenance distinguishes completion-gated evidence from a State recomputed by a
// checker, while the embedded State remains the persisted manifest and digest.
type Observation struct {
	State
	processes []processObservation
	empty     bool
	seal      string
}

type processObservation struct {
	process string
	origin  string
	view    string
}

// CompletedState returns the persisted state from a sealed observation backed by
// at least one contributing process. Zero-process merge evidence is refused.
func CompletedState(observation Observation) (State, error) {
	if err := validateObservation(observation, false); err != nil {
		return State{}, err
	}
	if len(observation.processes) == 0 {
		return State{}, errors.New("runtimeinputs: completed observation has no contributing process")
	}
	return observation.State, nil
}

type manifest struct {
	Version      int         `json:"v"`
	Env          []envInput  `json:"env,omitempty"`
	Paths        []pathInput `json:"paths,omitempty"`
	Unverifiable []string    `json:"unverifiable,omitempty"`
}

// envInput is one observed environment identity with the digest of the value
// the producing run saw — names and digests only, values never in clear text.
type envInput struct {
	Name   string `json:"n"`
	Digest string `json:"d"`
}

type pathID struct {
	Kind string `json:"k"`
	Path string `json:"p"`
}

// pathInput is one observed path identity with the digest of the object state
// the producing run saw. The identity is the embedded pathID alone — the
// digest is evidence about it, never part of its key.
type pathInput struct {
	pathID
	Digest string `json:"d"`
}

// Incomplete constructs canonical evidence for a process whose runtime-input
// observation did not complete. Process must identify that contributing process
// uniquely and consistently across every observation in a merge.
func Incomplete(moduleDir, process, reason string) (Observation, error) {
	return IncompleteEnv(moduleDir, process, reason, os.Environ())
}

// IncompleteEnv is Incomplete with env as the complete process environment.
func IncompleteEnv(moduleDir, process, reason string, env []string) (Observation, error) {
	if err := validateProcess(process); err != nil {
		return Observation{}, err
	}
	if strings.TrimSpace(reason) == "" {
		return Observation{}, fmt.Errorf("runtimeinputs: incomplete observation needs a reason")
	}
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		return Observation{}, err
	}
	encoded, err := encode(manifest{Version: manifestVersion, Unverifiable: []string{reason}})
	if err != nil {
		return Observation{}, err
	}
	state, err := currentWithNormalizedEnv(encoded, moduleDir, normalized)
	if err != nil {
		return Observation{}, err
	}
	return newObservation(state, process, "incomplete"), nil
}

// Absolute revalidates state under moduleDir and returns equivalent evidence
// whose path identities are all absolute. This permits sound cross-module merge.
func Absolute(observation Observation, moduleDir string) (Observation, error) {
	return AbsoluteEnv(observation, moduleDir, os.Environ())
}

// AbsoluteEnv is Absolute with env as the complete process environment used to
// revalidate the input and compute the converted state.
func AbsoluteEnv(observation Observation, moduleDir string, env []string) (Observation, error) {
	if err := validateObservation(observation, false); err != nil {
		return Observation{}, err
	}
	state := observation.State
	if !state.OK || state.Manifest == "" || state.Digest == "" {
		return Observation{}, fmt.Errorf("runtimeinputs: incomplete state for absolute identities")
	}
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		return Observation{}, err
	}
	current, err := currentWithNormalizedEnv(state.Manifest, moduleDir, normalized)
	if err != nil {
		return Observation{}, err
	}
	if current != state {
		return Observation{}, fmt.Errorf("runtimeinputs: state moved before absolute identity conversion")
	}
	m, err := decode(state.Manifest)
	if err != nil {
		return Observation{}, err
	}
	if current.Unverifiable && current.Reason != "" {
		seen := make(map[string]bool, len(m.Unverifiable)+1)
		for _, reason := range m.Unverifiable {
			seen[reason] = true
		}
		addUnverifiable(&m, seen, current.Reason)
	}
	moduleDir, err = filepath.Abs(moduleDir)
	if err != nil {
		return Observation{}, fmt.Errorf("runtimeinputs: module dir: %w", err)
	}
	for i, entry := range m.Paths {
		path, err := materializePath(moduleDir, entry.pathID)
		if err != nil {
			return Observation{}, err
		}
		// The digest is recomputed by the converted state below: the framed
		// stream is identity-dependent, so a converted identity's digest is
		// never carried over.
		m.Paths[i] = pathInput{pathID: pathID{Kind: pathAbs, Path: path}}
	}
	sortManifest(&m)
	converted, err := stateFromManifest(context.Background(), m, moduleDir, normalized)
	if err != nil {
		return Observation{}, err
	}
	records := make([]processObservation, len(observation.processes))
	for i, record := range observation.processes {
		records[i] = processObservation{
			process: record.process,
			origin:  record.origin,
			view:    absoluteProcessView(record.origin),
		}
	}
	return sealObservation(converted, records, observation.empty), nil
}

// FromTestLog builds a runtime-input manifest from a Go testlog stream and
// computes its digest against the current filesystem and environment.
func FromTestLog(log []byte, moduleDir, packageDir string, opts ...TestLogOption) (Observation, error) {
	return FromTestLogEnv(log, moduleDir, packageDir, os.Environ(), opts...)
}

// TestLogOption configures observation construction from a testlog.
type TestLogOption func(*testLogConfig)

type testLogConfig struct {
	excluded   []pathID
	guardRoots []guardRootDecl
	// ephemeralRoots are declared temp roots whose own identity records
	// nothing (REQ-inputs-ephemeral-root).
	ephemeralRoots []string
	process        string
	bracket        *Bracket
	err            error
}

type guardRootDecl struct {
	path string
	// excludeSub names one direct subtree that stays observed — the
	// module cache's mutable "cache" metadata, the build cache's
	// discovered "fuzz" corpus; empty covers the whole root.
	excludeSub string
}

// WithCompletedProcess asserts that process terminated normally and every
// behavior-affecting observed-operation outcome agreed with its guarded value.
// Process must identify that contributing process uniquely and consistently across
// every observation in a merge. A caller lacking either fact must use Incomplete.
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
// span, while a moved or capture-unverifiable bracket seals the observation
// as attributable unverifiable evidence and a recorded identity covered by no
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

// WithToolchainRoot declares the producing toolchain's GOROOT as a
// guard-covered root (REQ-inputs-guard-covered): a clean absolute path
// resolved from the same environment the producing run used. Reads provably
// inside it record neither a path identity nor a per-path disposition — the
// toolchain guard already pins that content, the closure model's own stdlib
// collapse. The skip is fail-closed: symlink chains touching anything outside
// the root, ambiguous resolutions, and missing objects stay observed.
func WithToolchainRoot(root string) TestLogOption {
	return guardRootOption(root, "")
}

// WithModuleCacheRoot declares the producing environment's GOMODCACHE as a
// guard-covered root (REQ-inputs-guard-covered) for its version-addressed
// extracted module trees, which immutable version pinning already covers. The
// download cache subtree (`cache/`) holds mutable metadata no guard pins —
// version lists, lock files — and stays observed. The same fail-closed
// resolution rules as the toolchain root apply.
func WithModuleCacheRoot(root string) TestLogOption {
	return guardRootOption(root, "cache")
}

// WithBuildCacheRoot declares the producing environment's GOCACHE as a
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
func WithBuildCacheRoot(root string) TestLogOption {
	return guardRootOption(root, "fuzz")
}

// WithEphemeralTempRoot declares one of the producing environment's temp
// directories as an ephemeral root (REQ-inputs-ephemeral-root): the root's
// OWN identity — declared or resolved form — records nothing, because
// temp-tree creation machinery stats it to mint fresh per-run subtrees and
// no state a subject observes flows from its existing content. The
// admission is one identity wide: every deeper read stays observed.
func WithEphemeralTempRoot(root string) TestLogOption {
	return func(c *testLogConfig) {
		if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
			c.err = fmt.Errorf("runtimeinputs: ephemeral temp root must be a clean absolute path, got %q", root)
			return
		}
		c.ephemeralRoots = append(c.ephemeralRoots, root)
	}
}

func guardRootOption(root, excludeSub string) TestLogOption {
	return func(c *testLogConfig) {
		if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
			c.err = fmt.Errorf("runtimeinputs: guard-covered root must be a clean absolute path, got %q", root)
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

// FromTestLogEnv is FromTestLog with env as the complete process environment
// inherited by the observed test process.
func FromTestLogEnv(log []byte, moduleDir, packageDir string, env []string, opts ...TestLogOption) (Observation, error) {
	var cfg testLogConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.err != nil {
		return Observation{}, cfg.err
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
	envSeen := map[string]bool{}
	pathSeen := map[pathID]bool{}
	unverifiableSeen := map[string]bool{}
	guardRoots := resolveGuardRoots(cfg.guardRoots)
	ephemeralRoots, err := resolveEphemeralRoots(cfg.ephemeralRoots, moduleDir)
	if err != nil {
		return Observation{}, err
	}
	guardMemo := map[string]bool{}
	scratchMemo := map[string]bool{}
	cwd := packageDir
	cwdChanged := false

	lines := bytes.Split(log, []byte{'\n'})
	if len(lines) != 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	for _, raw := range lines {
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
			if processenv.EqualKey(name, "PWD") {
				addUnverifiable(&m, unverifiableSeen, "process-local environment input: PWD")
				continue
			}
			if !envSeen[name] {
				envSeen[name] = true
				m.Env = append(m.Env, envInput{Name: name})
			}
		case "open":
			ambiguousParent := hasParentTraversal(name)
			relativeAfterChdir := cwdChanged && !filepath.IsAbs(name)
			p := resolvePath(cwd, name)
			// Guard coverage demands an unambiguous resolution: a traversal
			// whose lexical cleaning may not match the filesystem, or a
			// relative read after a directory change, is never provably
			// inside a root (REQ-inputs-guard-covered fail-closed).
			if !ambiguousParent && !relativeAfterChdir && (guardCovered(p, guardRoots, guardMemo) || ephemeralRoot(p, ephemeralRoots) || ephemeralScratch(p, ephemeralRoots, scratchMemo) || nullSink(p)) {
				continue
			}
			id, reason := classifyPath(moduleDir, p)
			if reason != "" {
				addUnverifiable(&m, unverifiableSeen, reason)
				continue
			}
			if cfg.excludes(id) {
				continue
			}
			if !pathSeen[id] {
				pathSeen[id] = true
				m.Paths = append(m.Paths, pathInput{pathID: id})
			}
			if ambiguousParent {
				addUnverifiable(&m, unverifiableSeen, "ambiguous parent traversal: "+id.displayPath())
			}
			if relativeAfterChdir {
				addUnverifiable(&m, unverifiableSeen, "relative runtime input after working-directory change: "+id.displayPath())
			}
		case "stat":
			ambiguousParent := hasParentTraversal(name)
			relativeAfterChdir := cwdChanged && !filepath.IsAbs(name)
			p := resolvePath(cwd, name)
			if !ambiguousParent && !relativeAfterChdir && (guardCovered(p, guardRoots, guardMemo) || ephemeralRoot(p, ephemeralRoots) || ephemeralScratch(p, ephemeralRoots, scratchMemo) || nullSink(p)) {
				continue
			}
			id, reason := classifyPath(moduleDir, p)
			if reason != "" {
				addUnverifiable(&m, unverifiableSeen, reason)
				continue
			}
			if cfg.excludes(id) {
				continue
			}
			if !pathSeen[id] {
				pathSeen[id] = true
				m.Paths = append(m.Paths, pathInput{pathID: id})
			}
			addUnverifiable(&m, unverifiableSeen, "stat metadata input: "+id.displayPath())
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
			ambiguousParent := hasParentTraversal(name)
			p := resolvePath(cwd, name)
			id, reason := classifyPath(moduleDir, p)
			if reason != "" {
				addUnverifiable(&m, unverifiableSeen, reason)
			} else if !cfg.excludes(id) && !pathSeen[id] {
				pathSeen[id] = true
				m.Paths = append(m.Paths, pathInput{pathID: id})
			}
			addUnverifiable(&m, unverifiableSeen, "working-directory change")
			if reason == "" && !cfg.excludes(id) && ambiguousParent {
				addUnverifiable(&m, unverifiableSeen, "ambiguous parent traversal: "+id.displayPath())
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
		if id.Kind == pathAbs && machineFactIdentities[id.Path] {
			continue
		}
		covered, escapedLink, err := coverage.covers(id)
		if err != nil {
			return Observation{}, err
		}
		if !covered {
			reason := "runtime input not covered by observation bracket: " + id.displayPath()
			if escapedLink != "" && utf8.ValidString(escapedLink) && !strings.ContainsAny(escapedLink, "\x00\r\n") {
				reason += " (symlink outside every bracket root: " + escapedLink + ")"
			}
			addUnverifiable(&m, unverifiableSeen, reason)
		}
	}
	sortManifest(&m)
	st, err := stateFromManifest(context.Background(), m, moduleDir, normalized)
	if err != nil {
		return Observation{}, err
	}
	// The bracket is revalidated strictly after the manifest digest's last
	// input read (REQ-inputs-value-binding). A moved bracket — or one already
	// unverifiable at capture — seals the whole observation as attributable
	// unverifiable evidence: it still constructs, converts, merges, and
	// checks, never as bound, so the failure direction is recomputation. The
	// reason enters the persisted manifest, so the recomputed state is the
	// one every later revalidation reproduces; the bracket only ever adds
	// unverifiable reasons, never removes one.
	unchanged, reason, err := cfg.bracket.revalidate(context.Background(), moduleDir)
	if err != nil {
		return Observation{}, err
	}
	if !unchanged {
		if !strings.HasPrefix(reason, "observation bracket") {
			reason = "observation bracket unverifiable: " + reason
		}
		addUnverifiable(&m, unverifiableSeen, reason)
		sortManifest(&m)
		if st, err = stateFromManifest(context.Background(), m, moduleDir, normalized); err != nil {
			return Observation{}, err
		}
	}
	return newObservation(st, cfg.process, "complete"), nil
}

func validateProcess(process string) error {
	if process == "" || !utf8.ValidString(process) || strings.ContainsAny(process, "\x00\r\n") {
		return fmt.Errorf("runtimeinputs: invalid process identity %q", process)
	}
	return nil
}

func newObservation(state State, process, disposition string) Observation {
	origin := processOrigin(state, process, disposition)
	records := []processObservation{{process: process, origin: origin, view: origin}}
	return sealObservation(state, records, false)
}

func processOrigin(state State, process, disposition string) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%d:%s%d:%s%d:%s%d:%s", len(process), process, len(disposition), disposition, len(state.Manifest), state.Manifest, len(state.Digest), state.Digest))
	return hex.EncodeToString(sum[:])
}

func absoluteProcessView(origin string) string {
	sum := sha256.Sum256([]byte("absolute:" + origin))
	return hex.EncodeToString(sum[:])
}

func sealObservation(state State, processes []processObservation, empty bool) Observation {
	observation := Observation{State: state, processes: append([]processObservation(nil), processes...), empty: empty}
	h := sha256.New()
	fprintf(h, "manifest %s\ndigest %s\nunverifiable %t\nreason %s\nok %t\nempty %t\n", state.Manifest, state.Digest, state.Unverifiable, state.Reason, state.OK, empty)
	for _, record := range observation.processes {
		fprintf(h, "process %s %s %s\n", record.process, record.origin, record.view)
	}
	observation.seal = hex.EncodeToString(h.Sum(nil))
	return observation
}

func validateObservation(observation Observation, _ bool) error {
	if len(observation.processes) == 0 {
		if observation.empty && observation.State.OK && observation.State.Manifest != "" && observation.State.Digest != "" {
			if sealObservation(observation.State, nil, true).seal == observation.seal {
				return nil
			}
			return errors.New("runtimeinputs: observation seal is invalid")
		}
		return errors.New("runtimeinputs: observation has no process provenance")
	}
	if !observation.State.OK || observation.State.Manifest == "" || observation.State.Digest == "" {
		return errors.New("runtimeinputs: observation state is incomplete")
	}
	for _, record := range observation.processes {
		if err := validateProcess(record.process); err != nil || record.origin == "" || record.view == "" {
			return errors.New("runtimeinputs: observation process provenance is invalid")
		}
	}
	if sealObservation(observation.State, observation.processes, observation.empty).seal != observation.seal {
		return errors.New("runtimeinputs: observation seal is invalid")
	}
	return nil
}

// Adopt re-admits a persisted encoded manifest as a completed observation
// under process, an attributable identity of the caller's choosing
// (REQ-inputs-adoption). The manifest must be the canonical encoding; every
// recorded identity re-evaluates against the current module view, and any
// disagreement is refused naming the moved inputs. Adoption re-admits recorded
// evidence — it observes nothing new and confers no completeness beyond what
// the manifest recorded. The result participates in ordinary Merge.
func Adopt(encoded, moduleDir, process string) (Observation, error) {
	return AdoptEnv(encoded, moduleDir, process, os.Environ())
}

// AdoptEnv is Adopt with env as the complete process environment used to
// re-evaluate the persisted evidence. Canonical-encoding enforcement lives in
// decode — the one gate every manifest string passes.
func AdoptEnv(encoded, moduleDir, process string, env []string) (Observation, error) {
	if err := validateProcess(process); err != nil {
		return Observation{}, err
	}
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		return Observation{}, err
	}
	current, err := currentWithNormalizedEnv(encoded, moduleDir, normalized)
	if err != nil {
		return Observation{}, err
	}
	if current.Manifest != encoded {
		movers, moveErr := MovedInputs(encoded, moduleDir, env)
		switch {
		case moveErr != nil:
			return Observation{}, fmt.Errorf("runtimeinputs: adopted manifest moved; attribution unavailable: %w", moveErr)
		case len(movers) > 0:
			return Observation{}, fmt.Errorf("runtimeinputs: adopted manifest moved: %s", strings.Join(movers, ", "))
		default:
			return Observation{}, errors.New("runtimeinputs: adopted manifest moved")
		}
	}
	return newObservation(current, process, "adopted"), nil
}

// Merge revalidates independently completed runtime-input observations against one
// current module view, then returns their deterministic manifest union. Process
// identities must be unique and stable across the contributing process set. Passing no observations
// deliberately produces the encoded observation-free manifest; structurally
// unfinished, moved, or malformed states are rejected. A finalized state from
// Incomplete is accepted as explicit unverifiable evidence.
func Merge(moduleDir string, observations ...Observation) (Observation, error) {
	return MergeEnv(moduleDir, os.Environ(), observations...)
}

// MergeEnv is Merge with env as the complete process environment used to
// revalidate every input and compute the merged state.
func MergeEnv(moduleDir string, env []string, observations ...Observation) (Observation, error) {
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		return Observation{}, err
	}
	merged := manifest{Version: manifestVersion}
	envSeen := map[string]bool{}
	pathSeen := map[pathID]bool{}
	unverifiableSeen := map[string]bool{}
	processes := map[string]processObservation{}
	for i, observation := range observations {
		if err := validateObservation(observation, false); err != nil {
			return Observation{}, fmt.Errorf("runtimeinputs: merge input %d: %w", i, err)
		}
		for _, record := range observation.processes {
			if existing, ok := processes[record.process]; ok && existing != record {
				return Observation{}, fmt.Errorf("runtimeinputs: conflicting observations for process %q", record.process)
			}
			processes[record.process] = record
		}
		input := observation.State
		if !input.OK || input.Manifest == "" || input.Digest == "" {
			return Observation{}, fmt.Errorf("runtimeinputs: merge input %d is incomplete", i)
		}
		current, err := currentWithNormalizedEnv(input.Manifest, moduleDir, normalized)
		if err != nil {
			return Observation{}, fmt.Errorf("runtimeinputs: merge input %d: %w", i, err)
		}
		if current != input {
			return Observation{}, fmt.Errorf("runtimeinputs: merge input %d moved", i)
		}
		m, err := decode(input.Manifest)
		if err != nil {
			return Observation{}, fmt.Errorf("runtimeinputs: merge input %d: %w", i, err)
		}
		for _, entry := range m.Env {
			if !envSeen[entry.Name] {
				envSeen[entry.Name] = true
				merged.Env = append(merged.Env, entry)
			}
		}
		for _, entry := range m.Paths {
			if !pathSeen[entry.pathID] {
				pathSeen[entry.pathID] = true
				merged.Paths = append(merged.Paths, entry)
			}
		}
		for _, reason := range m.Unverifiable {
			addUnverifiable(&merged, unverifiableSeen, reason)
		}
	}
	result, err := encode(merged)
	if err != nil {
		return Observation{}, err
	}
	state, err := currentWithNormalizedEnv(result, moduleDir, normalized)
	if err != nil {
		return Observation{}, err
	}
	records := make([]processObservation, 0, len(processes))
	for _, record := range processes {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].process < records[j].process })
	return sealObservation(state, records, len(records) == 0), nil
}

// Current recomputes the runtime-input digest for an encoded manifest.
func Current(encoded, moduleDir string) (State, error) {
	return CurrentContext(context.Background(), encoded, moduleDir)
}

// CurrentContext recomputes the runtime-input digest under ctx.
func CurrentContext(ctx context.Context, encoded, moduleDir string) (State, error) {
	return CurrentEnvContext(ctx, encoded, moduleDir, os.Environ())
}

// CurrentEnv recomputes a manifest using env as the complete process environment.
func CurrentEnv(encoded, moduleDir string, env []string) (State, error) {
	return CurrentEnvContext(context.Background(), encoded, moduleDir, env)
}

// CurrentEnvContext is CurrentContext with env as the complete process environment.
func CurrentEnvContext(ctx context.Context, encoded, moduleDir string, env []string) (State, error) {
	if ctx == nil {
		return State{OK: false}, errors.New("runtimeinputs: nil context")
	}
	if err := ctx.Err(); err != nil {
		return State{OK: false}, err
	}
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		return State{OK: false}, err
	}
	return currentWithNormalizedEnvContext(ctx, encoded, moduleDir, normalized)
}

func normalizeEnvironment(env []string) ([]string, error) {
	normalized, err := processenv.Normalize(env)
	if err != nil {
		return nil, fmt.Errorf("runtimeinputs: %w", err)
	}
	return normalized, nil
}

func currentWithNormalizedEnv(encoded, moduleDir string, env []string) (State, error) {
	return currentWithNormalizedEnvContext(context.Background(), encoded, moduleDir, env)
}

func currentWithNormalizedEnvContext(ctx context.Context, encoded, moduleDir string, env []string) (State, error) {
	if err := ctx.Err(); err != nil {
		return State{OK: false}, err
	}
	m, err := decode(encoded)
	if err != nil {
		return State{OK: false}, err
	}
	return stateFromManifest(ctx, m, moduleDir, env)
}

// envEntryDigest digests one environment input: presence and value, names
// only ever disclosed.
func envEntryDigest(env []string, name string) string {
	value, ok := processenv.Lookup(env, name)
	valueHash := sha256.Sum256([]byte(value))
	sum := sha256.Sum256(fmt.Appendf(nil, "%t %x", ok, valueHash))
	return hex.EncodeToString(sum[:])[:32]
}

// pathEntryDigest digests one path input's observed object state through the
// same framed stream hashPath has always produced, into its own hasher.
func pathEntryDigest(ctx context.Context, id pathID, path, moduleDir string) (string, bool, string, error) {
	h := sha256.New()
	unverifiable, reason, err := hashPath(ctx, h, id, path, moduleDir, nil)
	if err != nil {
		return "", false, "", err
	}
	return hex.EncodeToString(h.Sum(nil))[:32], unverifiable, reason, nil
}

// stateFromManifest computes every input's current digest, writes it into the
// manifest's entries, folds the combined digest over identities and entry
// digests, and encodes — construction and check share it, so a recorded
// manifest whose inputs are unmoved re-encodes byte-identically
// (REQ-inputs-guard) and per-input attribution falls out of comparing a
// recorded entry's digest with the recomputed one.
func stateFromManifest(ctx context.Context, m manifest, moduleDir string, env []string) (State, error) {
	// The fold runs in canonical order regardless of the caller's collection
	// order — encode re-sorts anyway, and a fold that disagreed with the
	// encoded order would silently decouple digest from manifest.
	sortManifest(&m)
	moduleDir, err := filepath.Abs(moduleDir)
	if err != nil {
		return State{}, err
	}
	h := sha256.New()
	fprintf(h, "version %d\n", m.Version)
	for i, entry := range m.Env {
		if err := ctx.Err(); err != nil {
			return State{OK: false}, err
		}
		d := envEntryDigest(env, entry.Name)
		m.Env[i].Digest = d
		fprintf(h, "env %s %s\n", entry.Name, d)
	}
	unverifiable := len(m.Unverifiable) > 0
	reason := firstReason(m.Unverifiable)
	for i, entry := range m.Paths {
		if err := ctx.Err(); err != nil {
			return State{OK: false}, err
		}
		path, err := materializePath(moduleDir, entry.pathID)
		if err != nil {
			return State{}, err
		}
		// Manifest hashing never filters: exclusion is per identity, never per
		// content (REQ-inputs-exclusions), so a recorded directory identity
		// digests everything its hash walks.
		d, pathUnverifiable, pathReason, err := pathEntryDigest(ctx, entry.pathID, path, moduleDir)
		if err != nil {
			return State{}, err
		}
		m.Paths[i].Digest = d
		fprintf(h, "path %s %s %s\n", entry.Kind, entry.Path, d)
		if pathUnverifiable {
			unverifiable = true
			if reason == "" {
				reason = pathReason
			}
		}
	}
	for _, r := range m.Unverifiable {
		fprintf(h, "unverifiable %s\n", r)
	}
	if err := ctx.Err(); err != nil {
		return State{OK: false}, err
	}
	encoded, err := encode(m)
	if err != nil {
		return State{}, err
	}
	sum := h.Sum(nil)
	return State{
		Manifest:     encoded,
		Digest:       hex.EncodeToString(sum)[:32],
		Unverifiable: unverifiable,
		Reason:       reason,
		OK:           true,
	}, nil
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
		if !underPath(path, base) {
			continue
		}
		if r.excludeSub != "" && underPath(path, filepath.Join(base, r.excludeSub)) {
			return false
		}
		return true
	}
	return false
}

// resolveEphemeralRoots resolves each declared ephemeral root once into
// its identity pair; an unresolvable root declares nothing. A root
// equal to or inside the module tree — in either form — is refused
// loudly: swallowing a module-relative identity would silently vacate a
// content-bearing directory digest, the opposite of the class's
// one-external-identity blast radius (REQ-inputs-ephemeral-root).
func resolveEphemeralRoots(roots []string, moduleDir string) ([][2]string, error) {
	resolvedModule, err := filepath.EvalSymlinks(moduleDir)
	if err != nil {
		resolvedModule = moduleDir
	}
	out := make([][2]string, 0, len(roots))
	for _, r := range roots {
		// The declared form's interiority is checkable without
		// resolution, so it refuses before the unresolvable skip — the
		// spec promises refusal in either form outright.
		if underPath(r, moduleDir) || underPath(r, resolvedModule) {
			return nil, fmt.Errorf("runtimeinputs: ephemeral temp root %q lies inside the module tree; it would vacate module-relative inputs", r)
		}
		resolved, err := filepath.EvalSymlinks(r)
		if err != nil {
			continue
		}
		if underPath(resolved, moduleDir) || underPath(resolved, resolvedModule) {
			return nil, fmt.Errorf("runtimeinputs: ephemeral temp root %q resolves inside the module tree; it would vacate module-relative inputs", r)
		}
		out = append(out, [2]string{r, resolved})
	}
	return out, nil
}

// ephemeralScratch reports whether p lies under a declared ephemeral
// root with its object absent at ingest: per-run scratch by
// construction — state that outlived the run would still be present and
// stay observed. (Callers test ephemeralRoot first, so the root's own
// identity never reaches here; underPath alone would also admit
// p == root.) Fail-closed on resolution: the nearest existing ancestor
// must resolve under a root's resolved form — an existing-but-dangling
// link ancestor refuses — so a traversal through an existing escaping
// link stays observed; a since-vanished redirecting link component is
// the class's accepted one-run residual (REQ-inputs-ephemeral-root).
func ephemeralScratch(p string, roots [][2]string, memo map[string]bool) bool {
	if len(roots) == 0 {
		return false
	}
	if v, ok := memo[p]; ok {
		return v
	}
	res := func() bool {
		under := false
		for _, r := range roots {
			if underPath(p, r[0]) || underPath(p, r[1]) {
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
		// Walk to the nearest existing ancestor and demand it resolve
		// inside a declared root: an existing out-of-root link on the
		// path means the runtime read escaped and must stay observed.
		anc := filepath.Dir(p)
		for {
			resolved, err := filepath.EvalSymlinks(anc)
			if err == nil {
				for _, r := range roots {
					if underPath(resolved, r[1]) {
						return true
					}
				}
				return false
			}
			// An ancestor that EXISTS but does not resolve — a dangling
			// link — is detectable evidence the runtime read escaped the
			// root: refuse. Only a truly absent ancestor ascends.
			if _, lerr := os.Lstat(anc); !os.IsNotExist(lerr) {
				return false
			}
			parent := filepath.Dir(anc)
			if parent == anc {
				return false
			}
			anc = parent
		}
	}()
	memo[p] = res
	return res
}

// nullSink reports whether p is exactly the contentless sink device:
// every read sees immediate EOF and every write is discarded, so no
// state a subject observes flows through the identity. Lexical identity
// only — another name resolving to the same device stays observed. On
// windows os.DevNull is "NUL", never an absolute cleaned path, so the
// admission is inert there and sink reads stay observed, cost-only
// (REQ-inputs-null-sink).
func nullSink(p string) bool { return p == os.DevNull }

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

// resolveGuardRoots resolves each declared root once. A root that does not
// resolve declares nothing — nothing can be provably inside it.
func resolveGuardRoots(decls []guardRootDecl) []guardRootPair {
	out := make([]guardRootPair, 0, len(decls))
	for _, d := range decls {
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
	for _, r := range roots {
		if !r.admits(p) {
			continue
		}
		resolved, links, ok := chainResolve(p)
		if !ok {
			return false
		}
		if _, err := os.Lstat(resolved); err != nil {
			return false
		}
		if !r.admits(resolved) {
			return false
		}
		for _, link := range links {
			if !r.admits(link) {
				return false
			}
		}
		return true
	}
	return false
}

func underPath(p, root string) bool {
	return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
}

func resolvePath(cwd, name string) string {
	if filepath.IsAbs(name) {
		return filepath.Clean(name)
	}
	return filepath.Clean(filepath.Join(cwd, name))
}

func hasParentTraversal(name string) bool {
	volume := filepath.VolumeName(name)
	name = strings.TrimPrefix(name, volume)
	for _, component := range strings.FieldsFunc(name, func(r rune) bool {
		return r == '/' || filepath.Separator == '\\' && r == '\\'
	}) {
		if component == ".." {
			return true
		}
	}
	return false
}

func classifyPath(moduleDir, p string) (pathID, string) {
	if !utf8.ValidString(p) {
		return pathID{}, "non-UTF-8 runtime input path"
	}
	if strings.ContainsAny(p, "\x00\r\n") {
		return pathID{}, "unrepresentable runtime input path"
	}
	if rel, ok := relUnder(moduleDir, p); ok {
		return pathID{Kind: pathRel, Path: filepath.ToSlash(rel)}, ""
	}
	info, err := os.Stat(p)
	if err == nil && info.IsDir() {
		return pathID{}, "external directory input: " + p
	}
	if err != nil && !os.IsNotExist(err) {
		return pathID{}, "unhashable runtime input: " + p
	}
	return pathID{Kind: pathAbs, Path: filepath.Clean(p)}, ""
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

// hashPath writes the digest stream for one path identity. A non-nil skip
// filters directory-walk entries by their slash-form path relative to the walk
// root; identity-level hashing is unaffected by it.
// machineFactIdentities are the allowlisted stable-machine-fact files:
// their raw bytes and stat metadata are volatile on every read (cpu MHz
// lines, available-memory counters, proc mtimes stamped at stat time),
// while everything a subject could branch on is the stable projection
// REQ-guard-machine defines — so they digest as that projection's
// fingerprint, never as content, and revalidation recomputes the same
// projection: equal on the same machine, moved exactly when the
// hardware or kernel actually changed (REQ-inputs-machine-identity).
// The allowlist derives from the guard's own source list, so a fact
// source added to the gatherer is allowlisted by construction — the two
// sets cannot diverge.
var machineFactIdentities = func() map[string]bool {
	m := make(map[string]bool, len(guard.MachineFactSources))
	for _, p := range guard.MachineFactSources {
		m[p] = true
	}
	return m
}()

// currentMachineFacts is the projection source, a variable so the
// ungatherable arm is testable; production always points at the guard.
var currentMachineFacts = guard.CurrentMachineFacts

func hashPath(ctx context.Context, h hash.Hash, id pathID, p, moduleDir string, skip func(rel string) bool) (bool, string, error) {
	if err := ctx.Err(); err != nil {
		return false, "", err
	}
	if id.Kind == pathAbs && machineFactIdentities[id.Path] {
		facts, err := currentMachineFacts()
		if err != nil {
			fprintf(h, "path %s %s machine-unhashable\n", id.Kind, id.Path)
			return true, "unhashable runtime input: " + p, nil
		}
		fprintf(h, "path %s %s machine %s\n", id.Kind, id.Path, facts.Fingerprint())
		return false, "", nil
	}
	info, err := os.Stat(p)
	if os.IsNotExist(err) {
		fprintf(h, "path %s %s missing\n", id.Kind, id.Path)
		return false, "", nil
	}
	if err != nil {
		fprintf(h, "path %s %s unhashable\n", id.Kind, id.Path)
		return true, "unhashable runtime input: " + p, nil
	}
	target := p
	if id.Kind == pathRel {
		var external bool
		target, external, err = resolvedTarget(p, moduleDir)
		if err != nil {
			fprintf(h, "path %s %s unhashable-target\n", id.Kind, id.Path)
			return true, "unhashable runtime input: " + p, nil
		}
		if external {
			if info.IsDir() {
				fprintf(h, "path %s %s external-dir\n", id.Kind, id.Path)
				return true, "external directory input: " + p, nil
			}
			fprintf(h, "path %s %s external-target\n", id.Kind, id.Path)
			return true, "external runtime input target: " + p, nil
		}
	}
	mode := info.Mode()
	switch {
	case mode.IsRegular():
		writeStat(h, info)
		sum, err := fileHash(ctx, target)
		if err != nil {
			fprintf(h, "path %s %s unhashable\n", id.Kind, id.Path)
			return true, "unhashable runtime input: " + p, nil
		}
		fprintf(h, "path %s %s file %x\n", id.Kind, id.Path, sum)
		return false, "", nil
	case info.IsDir() && id.Kind == pathRel:
		sum, unv, reason, err := dirHashFiltered(ctx, target, skip)
		if err != nil {
			return false, "", err
		}
		fprintf(h, "path %s %s dir %x\n", id.Kind, id.Path, sum)
		return unv, reason, nil
	case info.IsDir():
		fprintf(h, "path %s %s external-dir\n", id.Kind, id.Path)
		return true, "external directory input: " + p, nil
	default:
		fprintf(h, "path %s %s unhashable-mode %s\n", id.Kind, id.Path, mode.String())
		return true, "unhashable runtime input: " + p, nil
	}
}

func (id pathID) displayPath() string {
	if id.Kind == pathRel {
		return id.Path
	}
	return filepath.Clean(id.Path)
}

func resolvedTarget(path, moduleDir string) (string, bool, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false, err
	}
	moduleRoot, err := filepath.EvalSymlinks(moduleDir)
	if err != nil {
		moduleRoot = moduleDir
	}
	if _, ok := relUnder(moduleRoot, resolved); !ok {
		return resolved, true, nil
	}
	return resolved, false, nil
}

func writeStat(h hash.Hash, info os.FileInfo) {
	fprintf(h, "stat %d %x %d %t\n", info.Size(), uint64(info.Mode()), info.ModTime().UnixNano(), info.IsDir())
}

func fileHash(ctx context.Context, path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()
	h := sha256.New()
	buffer := make([]byte, 32*1024)
	for {
		if err := ctx.Err(); err != nil {
			return [32]byte{}, err
		}
		n, readErr := f.Read(buffer)
		if n != 0 {
			_, _ = h.Write(buffer[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return [32]byte{}, readErr
		}
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

func dirHash(ctx context.Context, root string) ([32]byte, bool, string, error) {
	return dirHashFiltered(ctx, root, nil)
}

// dirHashFiltered is dirHash with a skip predicate over the slash-form path of
// each entry relative to root; a skipped directory's subtree contributes
// nothing to the digest. A nil skip digests the complete tree.
func dirHashFiltered(ctx context.Context, root string, skip func(rel string) bool) ([32]byte, bool, string, error) {
	h := sha256.New()
	unverifiable := false
	reason := ""
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		if skip != nil {
			if rel, relErr := filepath.Rel(root, path); relErr == nil {
				if s := filepath.ToSlash(rel); s != "." && skip(s) {
					if err == nil && d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
			}
		}
		if err != nil {
			unverifiable = true
			if reason == "" {
				reason = "unhashable runtime directory: " + path
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		info, err := d.Info()
		if err != nil {
			unverifiable = true
			if reason == "" {
				reason = "unhashable runtime directory: " + path
			}
			return nil
		}
		switch {
		case d.IsDir():
			fprintf(h, "dir %s/ ", rel)
			writeStat(h, info)
		case info.Mode().IsRegular():
			writeStat(h, info)
			sum, err := fileHash(ctx, path)
			if err != nil {
				unverifiable = true
				if reason == "" {
					reason = "unhashable runtime directory file: " + path
				}
				return nil
			}
			fprintf(h, "file %s %x\n", rel, sum)
		case info.Mode()&os.ModeSymlink != 0:
			writeStat(h, info)
			target, err := os.Readlink(path)
			if err != nil {
				unverifiable = true
				if reason == "" {
					reason = "unhashable runtime directory symlink: " + path
				}
				return nil
			}
			fprintf(h, "symlink %s %s\n", rel, target)
		default:
			unverifiable = true
			if reason == "" {
				reason = "unhashable runtime directory entry: " + path
			}
			fprintf(h, "unhashable %s %s\n", rel, info.Mode().String())
		}
		return nil
	})
	if err != nil {
		return [32]byte{}, false, "", err
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, unverifiable, reason, nil
}

func addUnverifiable(m *manifest, seen map[string]bool, reason string) {
	if !seen[reason] {
		seen[reason] = true
		m.Unverifiable = append(m.Unverifiable, reason)
	}
}

func firstReason(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	return reasons[0]
}

func sortManifest(m *manifest) {
	sort.Slice(m.Env, func(i, j int) bool { return m.Env[i].Name < m.Env[j].Name })
	m.Env = compact(m.Env)
	sort.Slice(m.Paths, func(i, j int) bool {
		if m.Paths[i].Kind != m.Paths[j].Kind {
			return m.Paths[i].Kind < m.Paths[j].Kind
		}
		return m.Paths[i].Path < m.Paths[j].Path
	})
	m.Paths = compact(m.Paths)
	sort.Strings(m.Unverifiable)
	m.Unverifiable = compact(m.Unverifiable)
}

func compact[T comparable](values []T) []T {
	if len(values) == 0 {
		return nil
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func encode(m manifest) (string, error) {
	sortManifest(&m)
	if err := validateManifest(m); err != nil {
		return "", err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ModuleRelPaths decodes an encoded manifest and returns the module-relative
// (slash-form) paths of its module-local file/directory inputs. These are the
// observed inputs whose Git-representable state at the recording's commit determines
// whether the recording is faithful to it (REQ-fresh-fingerprint-data,
// REQ-inputs-guard); external (absolute) inputs and environment
// variables are excluded (an external input is out of the module's git scope).
func ModuleRelPaths(encoded string) ([]string, error) {
	m, err := decode(encoded)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range m.Paths {
		if p.Kind == pathRel {
			out = append(out, p.Path)
		}
	}
	return out, nil
}

// Description is a validated manifest's observable identity set: what a run
// was recorded to observe, disclosed as identities only — environment values
// are never stored or reported in clear text (REQ-inputs-path-identities).
type Description struct {
	EnvNames     []string // observed environment-variable names, manifest order
	Paths        []string // materialized absolute path identities, manifest order
	Unverifiable []string // unverifiable observation dispositions, manifest order
}

// Describe decodes a canonical manifest into its identity set, materializing
// path identities under moduleDir exactly as Paths does. It names what a run
// was recorded to observe; MovedInputs names which of it moved.
func Describe(encoded, moduleDir string) (Description, error) {
	m, err := decode(encoded)
	if err != nil {
		return Description{}, err
	}
	abs, err := filepath.Abs(moduleDir)
	if err != nil {
		return Description{}, fmt.Errorf("runtimeinputs: module dir: %w", err)
	}
	d := Description{
		Unverifiable: append([]string(nil), m.Unverifiable...),
	}
	for _, entry := range m.Env {
		d.EnvNames = append(d.EnvNames, entry.Name)
	}
	for _, entry := range m.Paths {
		path, err := materializePath(abs, entry.pathID)
		if err != nil {
			return Description{}, err
		}
		d.Paths = append(d.Paths, path)
	}
	return d, nil
}

// MovedInputs names every input in a recorded manifest whose current digest
// differs from the recorded one — the attribution behind a runtime-input
// digest mismatch (REQ-inputs-guard): environment inputs as "env <name>"
// (values never disclosed), path inputs by their display identity. An empty
// result with a moved combined digest cannot occur: beyond the entries, the
// combined digest folds only recorded-verbatim data (the version and the
// unverifiable reasons), which cannot move at check time.
func MovedInputs(encoded, moduleDir string, env []string) ([]string, error) {
	return MovedInputsContext(context.Background(), encoded, moduleDir, env)
}

// MovedInputsContext is MovedInputs under caller-owned cancellation.
func MovedInputsContext(ctx context.Context, encoded, moduleDir string, env []string) ([]string, error) {
	if ctx == nil {
		return nil, errors.New("runtimeinputs: nil context")
	}
	m, err := decode(encoded)
	if err != nil {
		return nil, err
	}
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(moduleDir)
	if err != nil {
		return nil, fmt.Errorf("runtimeinputs: module dir: %w", err)
	}
	var moved []string
	for _, entry := range m.Env {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if envEntryDigest(normalized, entry.Name) != entry.Digest {
			moved = append(moved, "env "+entry.Name)
		}
	}
	for _, entry := range m.Paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path, err := materializePath(abs, entry.pathID)
		if err != nil {
			return nil, err
		}
		d, _, _, err := pathEntryDigest(ctx, entry.pathID, path, abs)
		if err != nil {
			return nil, err
		}
		if d != entry.Digest {
			moved = append(moved, "path "+entry.displayPath())
		}
	}
	return moved, nil
}

// Paths returns every path identity in a canonical manifest as an absolute path,
// preserving manifest order. Module-relative identities are rooted at moduleDir;
// external identities remain absolute.
func Paths(encoded, moduleDir string) ([]string, error) {
	m, err := decode(encoded)
	if err != nil {
		return nil, err
	}
	moduleDir, err = filepath.Abs(moduleDir)
	if err != nil {
		return nil, fmt.Errorf("runtimeinputs: module dir: %w", err)
	}
	out := make([]string, 0, len(m.Paths))
	for _, entry := range m.Paths {
		path, err := materializePath(moduleDir, entry.pathID)
		if err != nil {
			return nil, err
		}
		out = append(out, path)
	}
	return out, nil
}

func decode(s string) (manifest, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return manifest{}, fmt.Errorf("runtimeinputs: decode manifest: %w", err)
	}
	if base64.RawURLEncoding.EncodeToString(b) != s {
		return manifest{}, fmt.Errorf("runtimeinputs: non-canonical base64url manifest")
	}
	if !utf8.Valid(b) {
		return manifest{}, fmt.Errorf("runtimeinputs: manifest is not valid UTF-8")
	}
	var m manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return manifest{}, fmt.Errorf("runtimeinputs: parse manifest: %w", err)
	}
	if err := requireJSONEnd(dec); err != nil {
		return manifest{}, err
	}
	if m.Version != manifestVersion {
		return manifest{}, fmt.Errorf("runtimeinputs: unsupported manifest version %d", m.Version)
	}
	if err := validateManifest(m); err != nil {
		return manifest{}, err
	}
	sortManifest(&m)
	canonical, err := json.Marshal(m)
	if err != nil {
		return manifest{}, err
	}
	if !bytes.Equal(canonical, b) {
		return manifest{}, fmt.Errorf("runtimeinputs: non-canonical manifest encoding")
	}
	return m, nil
}

// validEntryDigest is the per-input digest shape: 32 lowercase hex characters
// (a truncated SHA-256), exactly as the combined digest renders.
func validEntryDigest(d string) bool {
	if len(d) != 32 {
		return false
	}
	for _, r := range d {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func validateManifest(m manifest) error {
	for i, entry := range m.Env {
		name := entry.Name
		if name == "" || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n") {
			return fmt.Errorf("runtimeinputs: invalid env name %q", name)
		}
		if !validEntryDigest(entry.Digest) {
			return fmt.Errorf("runtimeinputs: invalid env input digest for %q", name)
		}
		// Each array is a set once per IDENTITY: entries compact only when
		// byte-identical, so a duplicate identity with a differing digest
		// would otherwise survive into an accepted manifest.
		if i > 0 && m.Env[i-1].Name == name {
			return fmt.Errorf("runtimeinputs: duplicate env identity %q", name)
		}
	}
	for i, entry := range m.Paths {
		if !validEntryDigest(entry.Digest) {
			return fmt.Errorf("runtimeinputs: invalid path input digest for %q", entry.Path)
		}
		if i > 0 && m.Paths[i-1].pathID == entry.pathID {
			return fmt.Errorf("runtimeinputs: duplicate path identity %q", entry.Path)
		}
	}
	for _, entry := range m.Paths {
		id := entry.pathID
		if id.Path == "" || !utf8.ValidString(id.Path) || strings.ContainsAny(id.Path, "\x00\r\n") {
			return fmt.Errorf("runtimeinputs: invalid path %q", id.Path)
		}
		switch id.Kind {
		case pathRel:
			if filepath.IsAbs(id.Path) {
				return fmt.Errorf("runtimeinputs: relative path input is absolute: %q", id.Path)
			}
			clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(id.Path)))
			if clean == ".." || strings.HasPrefix(clean, "../") {
				return fmt.Errorf("runtimeinputs: relative path escapes module: %q", id.Path)
			}
			if clean != id.Path {
				return fmt.Errorf("runtimeinputs: relative path input is not canonical: %q", id.Path)
			}
		case pathAbs:
			if !filepath.IsAbs(id.Path) {
				return fmt.Errorf("runtimeinputs: absolute path input is relative: %q", id.Path)
			}
			if filepath.Clean(id.Path) != id.Path {
				return fmt.Errorf("runtimeinputs: absolute path input is not canonical: %q", id.Path)
			}
		default:
			return fmt.Errorf("runtimeinputs: unknown path kind %q", id.Kind)
		}
	}
	for _, reason := range m.Unverifiable {
		if reason == "" || !utf8.ValidString(reason) || strings.ContainsAny(reason, "\x00\r\n") {
			return fmt.Errorf("runtimeinputs: invalid unverifiable reason %q", reason)
		}
	}
	return nil
}

func requireJSONEnd(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("runtimeinputs: parse manifest: trailing JSON value")
		}
		return fmt.Errorf("runtimeinputs: parse manifest: %w", err)
	}
	return nil
}

func fprintf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}
