package runtimeinput

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/outcome"
	"github.com/greatliontech/gofresh/internal/trace"
)

// TestLogOption configures observation construction from a testlog.
type TestLogOption func(*testLogConfig)

type testLogConfig struct {
	excluded    []pathID
	excludedEnv []string
	guardRoots  []guardRootDecl
	// ephemeralRoots are declared temp roots whose own identity records
	// nothing (REQ-inputs-ephemeral-root).
	ephemeralRoots []string
	// scratchNamespaces are declared in-module run-scratch namespaces
	// whose endpoint-absent reads record nothing
	// (REQ-inputs-scratch-namespace).
	scratchNamespaces []scratchNamespace
	process           string
	// outcomeSubjects, trackedChdir, and requireEnvOnly are set only by the
	// facade after validating the separate execution premises. Public
	// identity-only options cannot construct them.
	outcomeSubjects []string
	trackedChdir    bool
	requireEnvOnly  bool
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
// nothing. Environment identities are excluded via WithExcludedEnv,
// not path patterns.
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

// ValidateExcludedEnv checks caller-declared environment-variable exclusions
// (REQ-inputs-exclusions): each entry must be a non-empty valid UTF-8 variable
// name containing no '=', NUL, CR, or LF, and PWD is never excludable.
func ValidateExcludedEnv(names []string) error {
	for _, name := range names {
		if name == "" {
			return errors.New("runtimeinputs: empty excluded environment variable name")
		}
		if !utf8.ValidString(name) || strings.ContainsAny(name, "=\x00\r\n") {
			return fmt.Errorf("runtimeinputs: invalid excluded environment variable name %q", name)
		}
		if gotool.EqualEnvKey(name, "PWD") {
			return errors.New("runtimeinputs: PWD cannot be excluded from runtime-input observation")
		}
	}
	return nil
}

// WithExcludedEnv declares environment-variable exclusions for testlog getenv
// observations (REQ-inputs-exclusions). PWD cannot be excluded.
func WithExcludedEnv(names ...string) TestLogOption {
	return func(c *testLogConfig) {
		if err := ValidateExcludedEnv(names); err != nil {
			c.err = err
			return
		}
		c.excludedEnv = append(c.excludedEnv, names...)
	}
}

func (c *testLogConfig) excludesEnv(name string) bool {
	for _, excl := range c.excludedEnv {
		if gotool.EqualEnvKey(excl, name) {
			return true
		}
	}
	return false
}

// exclusionPatterns normalizes exclusion patterns to identity form: a non-empty
// module-relative or clean absolute path (REQ-inputs-exclusions). An empty or
// unrepresentable pattern is refused rather than read as anything.
func exclusionPatterns(patterns []string) ([]pathID, error) {
	var excluded []pathID
	for _, q := range patterns {
		if q == "" {
			return nil, errors.New("runtimeinputs: empty exclusion pattern")
		}
		if !utf8.ValidString(q) || strings.ContainsAny(q, "\x00\r\n") {
			return nil, fmt.Errorf("runtimeinputs: unrepresentable exclusion pattern %q", q)
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

type captureReadError struct {
	err error
}

func (e captureReadError) Error() string { return e.err.Error() }
func (e captureReadError) Unwrap() error { return e.err }

var errUnsupportedOutcomeOp = errors.New("operation-outcome support does not cover the captured operations")

type cwdReadState struct {
	cwd       string
	relUnsafe bool
}

const (
	seenReadOpen uint8 = 1 << iota
	seenReadStat
)

// nextTestLogLineBytes reads the next '\n'-delimited line from br without
// stripping '\r' and without capping line length. The returned slice borrows
// from br or *scratch until the next call.
func nextTestLogLineBytes(br *bufio.Reader, scratch *[]byte) ([]byte, bool, bool, error) {
	frag, err := br.ReadSlice('\n')
	if err == nil {
		return frag[:len(frag)-1], true, false, nil
	}
	if err != bufio.ErrBufferFull {
		if err == io.EOF {
			if len(frag) == 0 {
				return nil, false, true, nil
			}
			return frag, false, false, nil
		}
		return nil, false, false, err
	}
	buf := (*scratch)[:0]
	buf = append(buf, frag...)
	for err == bufio.ErrBufferFull {
		frag, err = br.ReadSlice('\n')
		buf = append(buf, frag...)
	}
	*scratch = buf
	if err == nil {
		return buf[:len(buf)-1], true, false, nil
	}
	if err == io.EOF {
		return buf, false, false, nil
	}
	return nil, false, false, err
}

func drainCaptureForReadError(ctx context.Context, br *bufio.Reader) error {
	var scratch []byte
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, _, eof, err := nextTestLogLineBytes(br, &scratch)
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return captureReadError{err: err}
		}
		if eof {
			return nil
		}
	}
}

// FromTestLog builds a runtime-input manifest from a Go testlog byte slice and
// computes its digest against the current filesystem and env, the
// complete process environment the producing process ran under.
// The result is identity evidence only. No outcome support is inferred from the
// normal-process assertion or bracket; the producer facade supplies that separate
// premise from its execution-bound capability.
func FromTestLog(log []byte, moduleDir, packageDir string, env []string, opts ...TestLogOption) (Observation, error) {
	return fromTestLog(context.Background(), log, moduleDir, packageDir, env, opts...)
}

// FromTestLogFile streams a Go testlog file from disk into a runtime-input
// observation without buffering the entire capture file in memory.
func FromTestLogFile(ctx context.Context, path, moduleDir, packageDir string, env []string, opts ...TestLogOption) (Observation, error) {
	if ctx == nil {
		return Observation{}, errors.New("runtimeinputs: nil context")
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		return Observation{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Observation{}, ctxErr
		}
		return Observation{}, err
	}
	defer file.Close()
	br := bufio.NewReaderSize(captureReader{ctx: ctx, Reader: file}, producerCaptureBufSize)
	return fromTestLogStream(ctx, br, moduleDir, packageDir, normalized, opts...)
}

func fromTestLog(ctx context.Context, log []byte, moduleDir, packageDir string, env []string, opts ...TestLogOption) (Observation, error) {
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		return Observation{}, err
	}
	br := bufio.NewReader(captureReader{ctx: ctx, Reader: bytes.NewReader(log)})
	return fromTestLogStream(ctx, br, moduleDir, packageDir, normalized, opts...)
}

func fromTestLogStream(ctx context.Context, br *bufio.Reader, moduleDir, packageDir string, normalized []string, opts ...TestLogOption) (Observation, error) {
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	var start time.Time
	traced := trace.Enabled(ctx, trace.DomainRuntimeInput, "testlog.extract.done")
	if traced {
		start = time.Now()
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
	seenReads := map[cwdReadState]map[string]uint8{}
	bracketStatRoots := declaredBracketStatRoots(cfg.bracket)
	cwd := packageDir
	relUnsafe := false
	// A truthful frozen PWD can be bound as an environment input. The frame
	// establishes this execution's directory, but is not a persisted runtime
	// dependency: a later session can run the same build in another directory.
	// Other postures retain the process-local refusal (REQ-inputs-unbounded).
	pwdValue, pwdPresent := gotool.LookupEnv(normalized, "PWD")
	initialPWDTruthful := pwdPresent && pwdValue == packageDir
	pwdCurrentTruthful := initialPWDTruthful
	trackedChdirAllowed := false
	if cfg.trackedChdir && initialPWDTruthful {
		if resolvedPkg, pkgErr := filepath.EvalSymlinks(packageDir); pkgErr == nil && resolvedPkg == packageDir {
			trackedChdirAllowed = true
		}
	}
	var chdirStack []string
	cwdAmbiguous := false
	sawInExcursionPWD := false

	recordClassifiedPath := func(op, name, opCwd, p string, isStat, ambiguousParent, relativeAfterChdir bool) {
		id, reason := classifier.classify(p)
		if reason != "" {
			addUnverifiable(&m, unverifiableSeen, reason)
			noteAttribution(attributions, reason, operationAttribution(op, name, opCwd))
			return
		}
		m.Paths = upsertPath(m.Paths, pathIndex, pathInput{pathID: id})
		if isStat || op == "open" {
			nonExistenceBound[id] = true
			delete(existenceBound, id)
		}
		if isStat {
			// The stat observed the full object state, so this entry's
			// digest is metadata-bound from here on even if an earlier
			// open recorded it content-bound
			// (REQ-inputs-observation-class).
			m.Paths[pathIndex[id]].Metadata = true
			// A stat under a DECLARED bracket root needs no metadata
			// seal: the bracket fingerprint spans content and metadata
			// over the whole run-to-ingest span (REQ-inputs-unbounded).
			if !bracketStatRoots.covers(id) {
				addUnverifiable(&m, unverifiableSeen, "stat metadata input: "+id.displayPath())
			}
		}
		if ambiguousParent {
			addUnverifiable(&m, unverifiableSeen, "ambiguous parent traversal: "+id.displayPath())
		}
		if relativeAfterChdir {
			addUnverifiable(&m, unverifiableSeen, "relative runtime input after working-directory change: "+id.displayPath())
		}
	}

	processReadPathOp := func(op string, nameBytes []byte, isStat bool) {
		state := cwdReadState{cwd: cwd, relUnsafe: relUnsafe}
		mask := seenReadOpen
		if isStat {
			mask = seenReadStat
		}
		byName := seenReads[state]
		if byName != nil && byName[string(nameBytes)]&mask != 0 {
			return
		}
		name := string(nameBytes)
		if byName == nil {
			byName = map[string]uint8{}
			seenReads[state] = byName
		}
		byName[name] |= mask

		ambiguousParent := ambiguousTraversal(cwd, name, traversalMemo)
		relativeAfterChdir := relUnsafe && !filepath.IsAbs(name)
		p := resolvePath(cwd, name)
		// Guard coverage demands an unambiguous resolution: a traversal
		// whose lexical cleaning may not match the filesystem, or a
		// relative read after an untracked or ambiguous directory change,
		// is never provably inside a root (REQ-inputs-guard-covered fail-closed).
		if !ambiguousParent && !relativeAfterChdir && classifier.elidesUnambiguous(p) {
			return
		}
		// The exclusion consult precedes existence-binding as well as
		// classification: an excluded stat contributes nothing — not
		// even a revalidatable existence identity.
		if classifier.excludesRaw(p) {
			return
		}
		if isStat && !ambiguousParent && !relativeAfterChdir {
			if id, ok := classifier.externalExistenceStat(p); ok {
				m.Paths = upsertPath(m.Paths, pathIndex, pathInput{pathID: id})
				if !nonExistenceBound[id] {
					existenceBound[id] = true
				}
				return
			}
		}
		recordClassifiedPath(op, name, cwd, p, isStat, ambiguousParent, relativeAfterChdir)
	}

	var lineScratch []byte
	missingTrailingNewline := false
	for {
		if err := ctx.Err(); err != nil {
			return Observation{}, err
		}
		raw, hasNL, eof, readErr := nextTestLogLineBytes(br, &lineScratch)
		if err := ctx.Err(); err != nil {
			return Observation{}, err
		}
		if readErr != nil {
			return Observation{}, captureReadError{err: readErr}
		}
		if eof {
			break
		}
		if !hasNL {
			missingTrailingNewline = true
		}
		if bytes.Equal(raw, testlogHeaderLine) {
			continue
		}
		if cfg.requireEnvOnly && len(raw) != 0 && !bytes.HasPrefix(raw, getenvLinePrefix) {
			if drainErr := drainCaptureForReadError(ctx, br); drainErr != nil {
				return Observation{}, drainErr
			}
			return Observation{}, errUnsupportedOutcomeOp
		}
		if len(raw) == 0 || raw[0] == '#' {
			addUnverifiable(&m, unverifiableSeen, "malformed testlog line")
			continue
		}
		opBytes, nameBytes, ok := bytes.Cut(raw, []byte{' '})
		if !ok || len(nameBytes) == 0 {
			addUnverifiable(&m, unverifiableSeen, "malformed testlog line")
			continue
		}
		switch string(opBytes) {
		case "getenv":
			if !utf8.Valid(nameBytes) {
				addUnverifiable(&m, unverifiableSeen, "non-UTF-8 environment name")
				continue
			}
			if bytes.ContainsAny(nameBytes, "\x00\r\n") {
				addUnverifiable(&m, unverifiableSeen, "unrepresentable environment name")
				continue
			}
			nameCheck := string(nameBytes)
			if gotool.IsTraceEnvKey(nameCheck) || cfg.excludesEnv(nameCheck) {
				continue
			}
			if gotool.EqualEnvKey(nameCheck, "PWD") {
				if !pwdCurrentTruthful {
					addUnverifiable(&m, unverifiableSeen, "process-local environment input: PWD")
					continue
				}
				if trackedChdirAllowed && (len(chdirStack) != 0 || cwd != packageDir) {
					sawInExcursionPWD = true
				}
			}
			if !envSeen[nameCheck] {
				envSeen[nameCheck] = true
				m.Env = append(m.Env, envInput{Name: nameCheck})
			}
		case "open":
			processReadPathOp("open", nameBytes, false)
		case "stat":
			processReadPathOp("stat", nameBytes, true)
		case "chdir":
			name := string(nameBytes)
			ambiguousParent := ambiguousTraversal(cwd, name, traversalMemo)
			p := resolvePath(cwd, name)
			if !trackedChdirAllowed {
				// An excluded chdir target leaves no per-path disposition —
				// no identity, no classification refusal — but the
				// working-directory seal and cwd tracking stay.
				if !classifier.excludesRaw(p) {
					recordClassifiedPath("chdir", name, cwd, p, false, ambiguousParent, false)
				}
				addUnverifiable(&m, unverifiableSeen, "working-directory change")
				if trace.Enabled(ctx, trace.DomainRuntimeInput, packageDir) {
					trace.Emit(ctx, trace.DomainRuntimeInput, "runtimeinput.chdir.untracked", packageDir,
						trace.String("target", name),
					)
				}
				cwd = p
				relUnsafe = true
				pwdCurrentTruthful = false
				continue
			}
			var canonP string
			canonOK := false
			if !cwdAmbiguous && !ambiguousParent && utf8.ValidString(name) && !strings.ContainsAny(name, "\x00\r\n") && filepath.IsAbs(name) && p == name {
				canonP, canonOK = classifier.canonicalizeTrackedChdirTarget(p)
			}
			if !canonOK {
				cwdAmbiguous = true
				relUnsafe = true
				pwdCurrentTruthful = false
				if !classifier.excludesRaw(p) {
					recordClassifiedPath("chdir", name, cwd, p, false, ambiguousParent, false)
				}
				addUnverifiable(&m, unverifiableSeen, "working-directory change")
				if trace.Enabled(ctx, trace.DomainRuntimeInput, packageDir) {
					trace.Emit(ctx, trace.DomainRuntimeInput, "runtimeinput.chdir.ambiguous", packageDir,
						trace.String("target", name),
					)
				}
				cwd = p
				continue
			}
			if n := len(chdirStack); n > 0 && chdirStack[n-1] == canonP {
				chdirStack = chdirStack[:n-1]
			} else {
				chdirStack = append(chdirStack, cwd)
			}
			if !classifier.elidesUnambiguous(canonP) && !classifier.excludesRaw(canonP) {
				recordClassifiedPath("chdir", name, cwd, canonP, false, false, false)
			}
			cwd = canonP
		default:
			op := string(opBytes)
			if !utf8.ValidString(op) || strings.ContainsAny(op, "\x00\r\n") {
				addUnverifiable(&m, unverifiableSeen, "unrepresentable testlog operation")
			} else {
				addUnverifiable(&m, unverifiableSeen, "unrecognized testlog op: "+op)
			}
		}
	}
	if missingTrailingNewline {
		addUnverifiable(&m, unverifiableSeen, "malformed testlog line")
	}
	if trackedChdirAllowed && (cwdAmbiguous || len(chdirStack) != 0 || cwd != packageDir) {
		addUnverifiable(&m, unverifiableSeen, "working-directory change")
		if sawInExcursionPWD {
			addUnverifiable(&m, unverifiableSeen, "process-local environment input: PWD")
		}
		if trace.Enabled(ctx, trace.DomainRuntimeInput, packageDir) {
			trace.Emit(ctx, trace.DomainRuntimeInput, "runtimeinput.chdir.unbalanced", packageDir,
				trace.String("cwd", cwd),
				trace.Int("stack_depth", len(chdirStack)),
				trace.Bool("ambiguous", cwdAmbiguous),
			)
		}
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
	pathUnverifiable, pathReason, _, err := populateManifestDigestsWithModuleRoot(ctx, &m, moduleDir, classifier.resolvedModule, normalized, false, false)
	if err != nil {
		return Observation{}, err
	}
	// The bracket is revalidated strictly after the manifest digest's last
	// input read (REQ-inputs-value-binding). Demonstrated movement is retained
	// separately from unknown binding, so purity cannot waive a failed guard.
	unchanged, moved, bracketMovers, reason, err := cfg.bracket.revalidateWithMovers(ctx, moduleDir)
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
	}
	st, err := finalizeManifestState(m, pathUnverifiable, pathReason)
	if err != nil {
		return Observation{}, err
	}
	origin := "identity-only"
	if m.Outcome != "" {
		origin = "outcome-supported"
	}
	sealedPkgDir := ""
	if initialPWDTruthful {
		sealedPkgDir = packageDir
	}
	observation := newObservationWithPkgDir(st, cfg.process, origin, sealedPkgDir)
	// The attribution is the one of the reason the state names — the
	// first clause of the sorted manifest; a reason the hashing pass
	// raised carries its own attribution, in the reason itself.
	observation.Attribution = attributions[st.Reason]
	if moved {
		observation.MovedInputs = bracketMovers
	}
	if traced {
		trace.Emit(ctx, trace.DomainRuntimeInput, "testlog.extract.done", packageDir,
			trace.Bool("unverifiable", observation.State.Unverifiable),
			trace.Int("env_count", len(m.Env)),
			trace.Int("path_count", len(m.Paths)),
			trace.Int64("elapsed_ms", time.Since(start).Milliseconds()),
		)
	}
	return observation, nil
}
