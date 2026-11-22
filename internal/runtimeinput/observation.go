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
// A finalized observation of newly read identities exists only as a live
// process-bound value from the bracket-gated constructor or the explicit
// incomplete-observation constructor. Outcome support additionally requires
// independently bound execution premises (OutcomeBinding and OutcomeSupport).
package runtimeinput

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
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

// Observation is producer-constructed runtime-input evidence. Its unexported
// process and sealed-state provenance distinguishes finalized producer evidence
// from a State recomputed by a checker or mutated after finalization.
type Observation struct {
	State
	Attribution string
	MovedInputs []string
	process     string
	sealed      State
}

// CompletedState returns finalized input-guard state from a process-bound
// observation whose State has not been tampered with after finalization.
func CompletedState(observation Observation) (State, error) {
	if err := validateProcess(observation.process); err != nil {
		return State{}, errors.New("runtimeinputs: observation has no process provenance")
	}
	if !observation.State.OK || observation.State.Manifest == "" || observation.State.Digest == "" {
		return State{}, errors.New("runtimeinputs: observation state is incomplete")
	}
	if observation.State != observation.sealed {
		return State{}, errors.New("runtimeinputs: observation seal is invalid")
	}
	return observation.State, nil
}

// Incomplete constructs canonical evidence for a process whose runtime-input
// observation did not complete, under env as the complete process environment.
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
	return incompleteNormalizedContext(ctx, moduleDir, process, reason, normalized)
}

func incompleteNormalizedContext(ctx context.Context, moduleDir, process, reason string, normalized []string) (Observation, error) {
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
	state, err := stateFromManifest(ctx, manifest{Version: manifestVersion, Unverifiable: []string{reason}}, moduleDir, normalized)
	if err != nil {
		return Observation{}, err
	}
	return newObservation(state, process), nil
}

// upsertPath adds entry to paths under the one-identity-one-class rule:
// a new identity appends; a seen identity keeps its first entry and
// unions the class to the stronger, metadata-bound observation
// (REQ-inputs-observation-class).
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

// parseOperationAttribution parses `<op> <quoted name> in <quoted directory>`
// into the operation, the name as quoted, and the unquoted directory.
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

func validateProcess(process string) error {
	if process == "" || !utf8.ValidString(process) || strings.ContainsAny(process, "\x00\r\n") {
		return fmt.Errorf("runtimeinputs: invalid process identity %q", process)
	}
	return nil
}

func newObservation(state State, process string) Observation {
	return Observation{State: state, process: process, sealed: state}
}
