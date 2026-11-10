// Package runtimeinput records and re-hashes non-source inputs observed by a
// measured process through Go's testlog channel (spec REQ-inputs-guard).
//
// Input-identity observations bind guarded values through an observation bracket
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
// A finalized observation of newly read identities exists only as a live sealed
// value from the bracket-gated constructor. Outcome support additionally requires
// the producer facade's independently bound premises. Observation's provenance fields
// are unexported; the manifest string in State is the only wire form, and
// merge and absolute conversion each refuse a value whose
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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/outcome"
)

// State is the current digest of a recorded runtime-input manifest:
// the inputs' state, which a derivation from the recorded manifest
// under the current tree reproduces, so a consumer compares it whole.
type State struct {
	Manifest string
	Digest   string
	// BracketMoved records demonstrated producing-span drift. Later agreement
	// cannot repair it, and assertions cannot waive this guard failure.
	BracketMoved bool
	Unverifiable bool
	Reason       string
	OK           bool
}

// Observation is producer-constructed runtime-input evidence. Its private process
// provenance distinguishes finalized producer evidence from a State recomputed by
// a checker. Finalization alone supplies no outcome support: the canonical
// manifest retains the supported method and subjects only after the producer
// facade checks the independent execution premises. The embedded State describes
// the input guard, not the entire observation-based reuse conjunction.
// Attribution is the observation that produced the classification
// refusal the state's reason names — the operation, its quoted name,
// and the producing process's own directory, the attribution alone
// without the clause or the separator (RefusalAttribution's form) —
// named at construction (the reason's first such refusal in log
// order), carried by a merge while the reason is theirs, and by an
// identity conversion with the directory converted as the identities
// are (module-relative in the portable form, a directory outside the
// module unchanged), and outside the state and its seal
// (REQ-inputs-refusal-attribution): diagnostic detail, fresh per
// measurement, never part of the inputs' identity a consumer
// compares; a reason the hashing pass raised (a resolved-target
// refusal carries its attribution in the reason itself, state that
// RefusalAttribution splits), or one with no attributed refusal (a
// working-directory change), carries none. The field is data —
// nothing re-derives it, so nothing checks it.
type Observation struct {
	State
	Attribution string
	processes   []processObservation
	empty       bool
	pkgDir      string
	seal        string
}

type processObservation struct {
	process string
	origin  string
	view    string
}

// CompletedState returns finalized input-guard state from a sealed observation
// backed by at least one contributing process. It accepts explicitly incomplete
// evidence too; callers judge outcome support separately. Zero-process merge
// evidence is refused.
func CompletedState(observation Observation) (State, error) {
	if err := validateObservation(observation, false); err != nil {
		return State{}, err
	}
	if len(observation.processes) == 0 {
		return State{}, errors.New("runtimeinputs: completed observation has no contributing process")
	}
	return observation.State, nil
}

// Incomplete constructs canonical evidence for a process whose runtime-input
// observation did not complete, under env as the complete process
// environment. Process must identify that contributing process uniquely
// and consistently across every observation in a merge.
func Incomplete(moduleDir, process, reason string, env []string) (Observation, error) {
	return incompleteContext(context.Background(), moduleDir, process, reason, env)
}

func incompleteContext(ctx context.Context, moduleDir, process, reason string, env []string) (Observation, error) {
	if ctx == nil {
		return Observation{}, errors.New("runtimeinputs: nil context")
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
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
	state, err := stateFromManifest(ctx, manifest{Version: manifestVersion, Unverifiable: []string{reason}}, moduleDir, normalized)
	if err != nil {
		return Observation{}, err
	}
	return newObservation(state, process, "incomplete"), nil
}

// Absolute revalidates state under moduleDir and env and returns equivalent
// evidence whose path identities are all absolute. This permits sound
// cross-module merge.
func Absolute(observation Observation, moduleDir string, env []string) (Observation, error) {
	return convertIdentityKinds(context.Background(), observation, moduleDir, env, identityConversion{
		name: "absolute",
		convert: func(moduleDir, path string) pathID {
			return pathID{Kind: pathAbs, Path: path}
		},
		attribution: func(moduleDir, attribution string) string {
			return convertAttributionDir(attribution, func(dir string) string {
				if filepath.IsAbs(dir) {
					return dir
				}
				return filepath.Clean(filepath.Join(moduleDir, filepath.FromSlash(dir)))
			})
		},
	})
}

// Relative revalidates state under moduleDir and env and returns equivalent
// evidence whose path identities lexically under the module are
// module-relative, external identities unchanged. This is the portable
// persisted form: the converted identities revalidate under any checkout
// of the same content, so evidence is keyed by what was measured, never by
// the checkout root that measured it (REQ-inputs-relative-identities).
func Relative(observation Observation, moduleDir string, env []string) (Observation, error) {
	return convertIdentityKinds(context.Background(), observation, moduleDir, env, identityConversion{
		name: "relative",
		convert: func(moduleDir, path string) pathID {
			if rel, ok := relativeSpelling(moduleDir, path); ok {
				return pathID{Kind: pathRel, Path: rel}
			}
			return pathID{Kind: pathAbs, Path: path}
		},
		attribution: func(moduleDir, attribution string) string {
			return convertAttributionDir(attribution, func(dir string) string {
				if rel, ok := relativeSpelling(moduleDir, dir); ok {
					return rel
				}
				return dir
			})
		},
	})
}

// upsertPath adds entry to paths under the one-identity-one-class rule:
// a new identity appends; a seen identity keeps its first entry and
// unions the class to the stronger, metadata-bound observation
// (REQ-inputs-observation-class). Every site that collapses identities
// — merge, and the identity-kind conversions when two kinds map onto
// one identity — goes through this one mechanism, so a collapse can
// never drop a class or duplicate an identity. Digests are evidence,
// not identity: the recomputed state rewrites them after any collapse.
func upsertPath(paths []pathInput, index map[pathID]int, entry pathInput) []pathInput {
	if at, ok := index[entry.pathID]; ok {
		if entry.Metadata {
			paths[at].Metadata = true
		}
		return paths
	}
	index[entry.pathID] = len(paths)
	return append(paths, entry)
}

// identityConversion parameterizes the one identity-kind conversion core:
// both directions share the revalidate/convert/recompute/reseal spine, and
// differ only in the per-identity target kind and the sealed view tag.
type identityConversion struct {
	name    string
	convert func(moduleDir, path string) pathID
	// attribution converts the directory an operation attribution
	// names, as convert converts the manifest's identities: the
	// producing process's directory is an in-tree identity like them.
	attribution func(moduleDir, attribution string) string
}

// convertAttributionDir rewrites the directory an operation attribution
// names through convert, the operation and the quoted name untouched;
// anything that is not exactly the operation form — a resolved-target
// attribution, or a string a caller assigned the field that the
// grammar does not parse — passes through unchanged, never rewritten
// into a form it was not.
func convertAttributionDir(attribution string, convert func(dir string) string) string {
	op, name, dir, ok := parseOperationAttribution(attribution)
	if !ok {
		return attribution
	}
	return op + " " + name + " in " + strconv.Quote(convert(dir))
}

// parseOperationAttribution is the one parse of the operation form —
// `<op> <quoted name> in <quoted directory>`, exactly to the end — the
// well-formedness check and the directory conversion both read: the
// operation, the name as quoted, the directory unquoted.
func parseOperationAttribution(s string) (op, quotedName, dir string, ok bool) {
	for _, candidate := range attributionOps {
		rest, found := strings.CutPrefix(s, candidate+" ")
		if !found {
			continue
		}
		name, rest, found := quotedPrefixThen(rest, " in ")
		if !found {
			return "", "", "", false
		}
		quoted, tail, found := quotedPrefixThen(rest, "")
		if !found || tail != "" {
			return "", "", "", false
		}
		unquoted, err := strconv.Unquote(quoted)
		if err != nil {
			return "", "", "", false
		}
		return candidate, name, unquoted, true
	}
	return "", "", "", false
}

// relativeSpelling is the portable spelling of a path under the module
// — slash-separated and module-relative — and false for a path outside
// it, which keeps its own spelling.
func relativeSpelling(moduleDir, p string) (string, bool) {
	rel, ok := relUnder(moduleDir, p)
	if !ok {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

func convertIdentityKinds(ctx context.Context, observation Observation, moduleDir string, env []string, conversion identityConversion) (Observation, error) {
	if ctx == nil {
		return Observation{}, errors.New("runtimeinputs: nil context")
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	if err := validateObservation(observation, false); err != nil {
		return Observation{}, err
	}
	state := observation.State
	if !state.OK || state.Manifest == "" || state.Digest == "" {
		return Observation{}, fmt.Errorf("runtimeinputs: incomplete state for %s identities", conversion.name)
	}
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		return Observation{}, err
	}
	absModuleDir, err := filepath.Abs(moduleDir)
	if err != nil {
		return Observation{}, fmt.Errorf("runtimeinputs: module dir: %w", err)
	}
	validationEnv := normalized
	outPkgDir := observation.pkgDir
	if observation.pkgDir != "" {
		if pwd, ok := gotool.LookupEnv(normalized, "PWD"); ok && sameDirectoryPath(pwd, absModuleDir) && pwd != observation.pkgDir {
			validationEnv, err = normalizeEnvironment(gotool.SetEnv(normalized, "PWD", observation.pkgDir))
			if err != nil {
				return Observation{}, err
			}
			outPkgDir = pwd
		}
	}
	current, m, err := currentAndManifestWithNormalizedEnv(ctx, state.Manifest, moduleDir, validationEnv)
	if err != nil {
		return Observation{}, err
	}
	if current != state {
		return Observation{}, fmt.Errorf("runtimeinputs: state moved before %s identity conversion", conversion.name)
	}
	if current.Unverifiable && current.Reason != "" {
		seen := make(map[string]bool, len(m.Unverifiable)+1)
		for _, reason := range m.Unverifiable {
			seen[reason] = true
		}
		addUnverifiable(&m, seen, current.Reason)
	}
	moduleDir = absModuleDir
	convertedPaths := make([]pathInput, 0, len(m.Paths))
	convertedIndex := map[pathID]int{}
	for _, entry := range m.Paths {
		path, err := materializePath(moduleDir, entry.pathID)
		if err != nil {
			return Observation{}, err
		}
		// The digest is recomputed by the converted state below: the framed
		// stream is identity-dependent, so a converted identity's digest is
		// never carried over. The observation class is identity-independent
		// and rides the conversion; a conversion that maps two kinds onto
		// one identity collapses them under the class-union rule.
		convertedPaths = upsertPath(convertedPaths, convertedIndex, pathInput{pathID: conversion.convert(moduleDir, path), Metadata: entry.Metadata})
	}
	m.Paths = convertedPaths
	sortManifest(&m)
	converted, err := stateFromManifest(ctx, m, moduleDir, normalized)
	if err != nil {
		return Observation{}, err
	}
	records := make([]processObservation, len(observation.processes))
	for i, record := range observation.processes {
		records[i] = processObservation{
			process: record.process,
			origin:  record.origin,
			view:    conversionProcessView(conversion.name, record.origin),
		}
	}
	sealed := sealObservationWithPkgDir(converted, records, observation.empty, outPkgDir)
	// The conversion is the same measurement's evidence: its attribution
	// rides along, the directory it names converted as the identities
	// are (module-relative under the module in the portable form, a
	// directory outside the module unchanged, absolute again in the
	// absolute form), so a persisted record names the producing
	// package the same in every checkout. It still attributes
	// the reason the converted state names: an attribution exists only
	// for a manifest clause, the state's reason is then the sorted
	// manifest's first clause, and the conversion keeps every clause
	// (promoting the reason itself above re-adds one of them), so the
	// converted state's reason is the same clause — no reason guard
	// stands here, unlike Merge's, whose union can name another
	// contributor's clause.
	sealed.Attribution = conversion.attribution(moduleDir, observation.Attribution)
	return sealed, nil
}

func sameDirectoryPath(a, b string) bool {
	if a == b {
		return true
	}
	if a == "" || b == "" {
		return false
	}
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && ra == rb
}

func validateProcess(process string) error {
	if process == "" || !utf8.ValidString(process) || strings.ContainsAny(process, "\x00\r\n") {
		return fmt.Errorf("runtimeinputs: invalid process identity %q", process)
	}
	return nil
}

func newObservation(state State, process, disposition string) Observation {
	return newObservationWithPkgDir(state, process, disposition, "")
}

func newObservationWithPkgDir(state State, process, disposition, pkgDir string) Observation {
	origin := processOrigin(state, process, disposition)
	records := []processObservation{{process: process, origin: origin, view: origin}}
	return sealObservationWithPkgDir(state, records, false, pkgDir)
}

func processOrigin(state State, process, disposition string) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%d:%s%d:%s%d:%s%d:%s", len(process), process, len(disposition), disposition, len(state.Manifest), state.Manifest, len(state.Digest), state.Digest))
	return hex.EncodeToString(sum[:])
}

func conversionProcessView(name, origin string) string {
	sum := sha256.Sum256([]byte(name + ":" + origin))
	return hex.EncodeToString(sum[:])
}

// sealObservation seals the state's identity — the attribution, a
// construction-time diagnostic, is outside the seal.
func sealObservation(state State, processes []processObservation, empty bool) Observation {
	return sealObservationWithPkgDir(state, processes, empty, "")
}

func sealObservationWithPkgDir(state State, processes []processObservation, empty bool, pkgDir string) Observation {
	observation := Observation{State: state, processes: append([]processObservation(nil), processes...), empty: empty, pkgDir: pkgDir}
	h := sha256.New()
	fprintf(h, "manifest %s\ndigest %s\nbracket-moved %t\nunverifiable %t\nreason %s\nok %t\nempty %t\npkg-dir %s\n", state.Manifest, state.Digest, state.BracketMoved, state.Unverifiable, state.Reason, state.OK, empty, pkgDir)
	for _, record := range observation.processes {
		fprintf(h, "process %s %s %s\n", record.process, record.origin, record.view)
	}
	observation.seal = hex.EncodeToString(h.Sum(nil))
	return observation
}

func validateObservation(observation Observation, _ bool) error {
	if len(observation.processes) == 0 {
		if observation.empty && observation.pkgDir == "" && observation.State.OK && observation.State.Manifest != "" && observation.State.Digest != "" {
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
	if sealObservationWithPkgDir(observation.State, observation.processes, observation.empty, observation.pkgDir).seal != observation.seal {
		return errors.New("runtimeinputs: observation seal is invalid")
	}
	return nil
}

// Adopt re-admits a persisted encoded manifest as a completed observation
// under process, an attributable identity of the caller's choosing, and
// env, the complete process environment (REQ-inputs-adoption). The
// manifest must be the canonical encoding; every recorded identity
// re-evaluates against the current module view, and any disagreement is
// refused naming the moved inputs. Adoption re-admits recorded evidence —
// it observes nothing new and confers no completeness beyond what the
// manifest recorded. The result participates in ordinary Merge.
func Adopt(encoded, moduleDir, process string, env []string) (Observation, error) {
	ctx := context.Background()
	if err := validateProcess(process); err != nil {
		return Observation{}, err
	}
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		return Observation{}, err
	}
	current, err := currentWithNormalizedEnvContext(ctx, encoded, moduleDir, normalized)
	if err != nil {
		return Observation{}, err
	}
	if current.Manifest != encoded {
		movers, moveErr := MovedInputs(ctx, encoded, moduleDir, env)
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

// Merge revalidates independently completed runtime-input observations
// against one current module view under env, then returns their
// deterministic manifest union. Process identities must be unique and
// stable across the contributing process set. Passing no observations
// deliberately produces the encoded observation-free manifest;
// structurally unfinished, moved, or malformed states are rejected. A
// finalized state from Incomplete is accepted as explicit unverifiable
// evidence.
func Merge(moduleDir string, env []string, observations ...Observation) (Observation, error) {
	ctx := context.Background()
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		return Observation{}, err
	}
	merged := manifest{Version: manifestVersion}
	supported := true
	envSeen := map[string]bool{}
	pathIndex := map[pathID]int{}
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
		current, m, err := currentAndManifestWithNormalizedEnv(ctx, input.Manifest, moduleDir, normalized)
		if err != nil {
			return Observation{}, fmt.Errorf("runtimeinputs: merge input %d: %w", i, err)
		}
		if current != input {
			return Observation{}, fmt.Errorf("runtimeinputs: merge input %d moved", i)
		}
		merged.BracketMoved = merged.BracketMoved || m.BracketMoved
		if len(observation.processes) > 0 {
			supported = supported && m.Outcome == outcome.Method
			merged.Subjects = append(merged.Subjects, m.Subjects...)
		}
		for _, entry := range m.Env {
			if !envSeen[entry.Name] {
				envSeen[entry.Name] = true
				merged.Env = append(merged.Env, entry)
			}
		}
		for _, entry := range m.Paths {
			merged.Paths = upsertPath(merged.Paths, pathIndex, entry)
		}
		for _, reason := range m.Unverifiable {
			addUnverifiable(&merged, unverifiableSeen, reason)
		}
	}
	if supported && len(merged.Subjects) > 0 {
		merged.Outcome = outcome.Method
	} else {
		merged.Subjects = nil
	}
	state, err := stateFromManifest(ctx, merged, moduleDir, normalized)
	if err != nil {
		return Observation{}, err
	}
	records := make([]processObservation, 0, len(processes))
	for _, record := range processes {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].process < records[j].process })
	sealed := sealObservation(state, records, len(records) == 0)
	// The merge's attribution is the first contributing observation's
	// that attributes the reason the merged state names, in the caller's
	// order — diagnostic detail, outside the seal.
	for _, observation := range observations {
		if observation.Attribution != "" && observation.Reason == state.Reason {
			sealed.Attribution = observation.Attribution
			break
		}
	}
	return sealed, nil
}
