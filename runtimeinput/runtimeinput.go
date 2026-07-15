// Package runtimeinputs records and re-hashes non-source inputs observed by a
// measured process through Go's testlog channel (spec REQ-inputs-guard).
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

type manifest struct {
	Version      int      `json:"v"`
	Env          []string `json:"env,omitempty"`
	Paths        []pathID `json:"paths,omitempty"`
	Unverifiable []string `json:"unverifiable,omitempty"`
}

type pathID struct {
	Kind string `json:"k"`
	Path string `json:"p"`
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
	for i, id := range m.Paths {
		path, err := materializePath(moduleDir, id)
		if err != nil {
			return Observation{}, err
		}
		m.Paths[i] = pathID{Kind: pathAbs, Path: path}
	}
	encoded, err := encode(m)
	if err != nil {
		return Observation{}, err
	}
	converted, err := currentWithNormalizedEnv(encoded, moduleDir, normalized)
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
	excluded []pathID
	process  string
	err      error
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
		for _, q := range patterns {
			if q == "" {
				c.err = errors.New("runtimeinputs: empty exclusion pattern")
				return
			}
			if filepath.IsAbs(q) {
				c.excluded = append(c.excluded, pathID{Kind: pathAbs, Path: filepath.Clean(q)})
				continue
			}
			c.excluded = append(c.excluded, pathID{Kind: pathRel, Path: path.Clean(filepath.ToSlash(q))})
		}
	}
}

// excludes reports whether id falls under any declared exclusion:
// equal, or extending it past a separator. Relative identities are
// slash-separated; absolute identities carry the host separator.
func (c *testLogConfig) excludes(id pathID) bool {
	for _, q := range c.excluded {
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

	m := manifest{Version: manifestVersion}
	envSeen := map[string]bool{}
	pathSeen := map[pathID]bool{}
	unverifiableSeen := map[string]bool{}
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
				m.Env = append(m.Env, name)
			}
		case "open":
			ambiguousParent := hasParentTraversal(name)
			relativeAfterChdir := cwdChanged && !filepath.IsAbs(name)
			p := resolvePath(cwd, name)
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
				m.Paths = append(m.Paths, id)
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
				m.Paths = append(m.Paths, id)
			}
			addUnverifiable(&m, unverifiableSeen, "stat metadata input: "+id.displayPath())
			if ambiguousParent {
				addUnverifiable(&m, unverifiableSeen, "ambiguous parent traversal: "+id.displayPath())
			}
			if relativeAfterChdir {
				addUnverifiable(&m, unverifiableSeen, "relative runtime input after working-directory change: "+id.displayPath())
			}
		case "chdir":
			ambiguousParent := hasParentTraversal(name)
			p := resolvePath(cwd, name)
			id, reason := classifyPath(moduleDir, p)
			if reason != "" {
				addUnverifiable(&m, unverifiableSeen, reason)
			} else if !cfg.excludes(id) && !pathSeen[id] {
				pathSeen[id] = true
				m.Paths = append(m.Paths, id)
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
	sortManifest(&m)
	encoded, err := encode(m)
	if err != nil {
		return Observation{}, err
	}
	st, err := currentWithNormalizedEnv(encoded, moduleDir, normalized)
	if err != nil {
		return Observation{}, err
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
		for _, name := range m.Env {
			if !envSeen[name] {
				envSeen[name] = true
				merged.Env = append(merged.Env, name)
			}
		}
		for _, id := range m.Paths {
			if !pathSeen[id] {
				pathSeen[id] = true
				merged.Paths = append(merged.Paths, id)
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
	moduleDir, err = filepath.Abs(moduleDir)
	if err != nil {
		return State{}, err
	}

	h := sha256.New()
	fprintf(h, "version %d\n", m.Version)
	for _, name := range m.Env {
		if err := ctx.Err(); err != nil {
			return State{OK: false}, err
		}
		value, ok := processenv.Lookup(env, name)
		valueHash := sha256.Sum256([]byte(value))
		fprintf(h, "env %s %t %x\n", name, ok, valueHash)
	}
	unverifiable := len(m.Unverifiable) > 0
	reason := firstReason(m.Unverifiable)
	for _, id := range m.Paths {
		if err := ctx.Err(); err != nil {
			return State{OK: false}, err
		}
		path, err := materializePath(moduleDir, id)
		if err != nil {
			return State{}, err
		}
		pathUnverifiable, pathReason, err := hashPath(ctx, h, id, path, moduleDir)
		if err != nil {
			return State{}, err
		}
		if pathUnverifiable {
			unverifiable = true
			if reason == "" {
				reason = pathReason
			}
		}
	}
	for _, reason := range m.Unverifiable {
		fprintf(h, "unverifiable %s\n", reason)
	}
	if err := ctx.Err(); err != nil {
		return State{OK: false}, err
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

func hashPath(ctx context.Context, h hash.Hash, id pathID, p, moduleDir string) (bool, string, error) {
	if err := ctx.Err(); err != nil {
		return false, "", err
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
		sum, unv, reason, err := dirHash(ctx, target)
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
	h := sha256.New()
	unverifiable := false
	reason := ""
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
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
	sort.Strings(m.Env)
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
	for _, id := range m.Paths {
		path, err := materializePath(moduleDir, id)
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

func validateManifest(m manifest) error {
	for _, name := range m.Env {
		if name == "" || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n") {
			return fmt.Errorf("runtimeinputs: invalid env name %q", name)
		}
	}
	for _, id := range m.Paths {
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
