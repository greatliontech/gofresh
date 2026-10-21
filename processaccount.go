package gofresh

import "github.com/greatliontech/gofresh/runtimeinput"

// RuntimeInputSpanError refuses producing close after finalization established
// runtime-input movement. The unit's Account retains the observation and terminal
// facts, but no reusable evidence escapes. Purity cannot discharge this failure.
type RuntimeInputSpanError struct {
	Reason string
}

func (e *RuntimeInputSpanError) Error() string {
	return "gofresh: runtime-input producing span changed: " + e.Reason
}

// Cause identifies the demonstrated guard failure independently of diagnostics.
func (e *RuntimeInputSpanError) Cause() Cause {
	return Cause{Kind: RuntimeInputsCause, Condition: Changed}
}

// ProcessAccount reports declared execution facts and observations already
// finalized by a unit, including when closing refuses. It is not a reusable
// result, successful closing judgment or durable-publication receipt. It carries
// no transferable producing capability.
//
// Prepared reports successful registration; a reserved but failed or unfinished
// registration remains unprepared. Terminal.Kind is zero until submission.
// UnknownObservation and zero Inputs mean finalization has established no
// observation facts. Otherwise Inputs is the canonical CompletedState projection
// of the finalized observation, including explicitly incomplete evidence. Its OK
// describes only the input guard, never the success of unit closing. A supported
// observation describes the admitted capture method, not later validation.
type ProcessAccount struct {
	Process           string
	Artifact          string
	Prepared          bool
	Terminal          Terminal
	Observation       ObservationDisposition
	ObservationReason string
	OutcomeReason     string
	Attribution       string
	Inputs            runtimeinput.State
}

// Account returns an owned copy of the unit's process account. The boolean is
// false until an execution is reserved. Reading performs no I/O and continues no
// work, including after cancellation or abort. It is safe during registration,
// submission and closing; only facts established at the time of the read appear.
func (u *Unit) Account() (ProcessAccount, bool) {
	return u.transaction().account()
}

// Account returns an owned, non-authorizing account of this package process.
// The boolean is false until an execution is reserved. It reads only established
// facts, without I/O or further finalization, and is safe during other unit calls.
func (u *PackageUnit) Account() (ProcessAccount, bool) {
	return u.transaction().account()
}

// finalizedProcessObservation holds only the facts that cannot be recovered from
// registration and submission. It never retains a sealed producing observation.
type finalizedProcessObservation struct {
	inputs      runtimeinput.State
	reason      string
	attribution string
}

func (u *producingUnit) account() (ProcessAccount, bool) {
	if u == nil {
		return ProcessAccount{}, false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	x := u.execution
	if x == nil {
		return ProcessAccount{}, false
	}
	disposition := UnknownObservation
	// CompletedState always supplies a canonical manifest, including for
	// incomplete observations. Its absence means finalization established none.
	if x.observation.inputs.Manifest != "" {
		disposition = SupportedObservation
		if x.observation.reason != "" {
			disposition = IncompleteObservation
		} else {
			if len(x.observed) == 0 {
				disposition = IdentityObservation
			}
			for subject := range x.observed {
				// Attachment adds only runtime inputs and their digest; neither
				// is part of the prepared outcome-subject identity.
				if !runtimeinput.HasOutcomeSupport(x.observation.inputs.Manifest, outcomeSubject(x.fingerprints[subject], subject)) {
					disposition = IdentityObservation
					break
				}
			}
		}
	}
	return ProcessAccount{
		Process: x.process.Identity, Artifact: x.artifact, Prepared: x.ready,
		Terminal: x.terminal, Observation: disposition,
		ObservationReason: x.observation.reason, OutcomeReason: x.outcomeReason,
		Attribution: x.observation.attribution, Inputs: x.observation.inputs,
	}, true
}

// recordObservation retains finalized facts before attachment or closing checks
// can refuse. Abort may already have won: retaining observed facts gives no
// closing authority and does not continue observation work.
func (u *producingUnit) recordObservation(observation runtimeinput.Observation, reason string) error {
	state, err := runtimeinput.CompletedState(observation)
	if err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.execution.observation = finalizedProcessObservation{inputs: state, reason: reason, attribution: observation.Attribution}
	return nil
}
