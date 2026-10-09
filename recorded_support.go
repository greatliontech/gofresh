package gofresh

import "github.com/greatliontech/gofresh/runtimeinput"

// RecordedSupportStatus distinguishes native persisted support from its absence.
// Neither status is a current-tree freshness verdict.
type RecordedSupportStatus uint8

const (
	// RecordedSupportRefused includes missing, malformed and incompatible evidence.
	RecordedSupportRefused RecordedSupportStatus = iota
	// RecordedSupportNative means internally consistent native persisted support.
	RecordedSupportNative
)

// RecordedObservationSupport is a record-only judgment. Reason is diagnostic
// prose, not a stable grammar. Persistence provenance remains caller-trusted.
type RecordedObservationSupport struct {
	Status RecordedSupportStatus
	Reason string
}

// ValidateRecordedObservationSupport validates native support for the expected
// original producing subject. It reads no current files or environment, captures
// or upgrades nothing, and does not check or transform applicability. A retained
// applicability endpoint never replaces the original producing compartment in
// the support identity. Purity cannot supply native evidence. Success certifies
// internal consistency, not freshness, provenance authenticity or a mutant result.
func ValidateRecordedObservationSupport(recorded Fingerprint, subject Subject) RecordedObservationSupport {
	refuse := func(reason string) RecordedObservationSupport {
		return RecordedObservationSupport{Reason: reason}
	}
	if err := recorded.Validate(); err != nil {
		return refuse(err.Error())
	}
	if subject.Package == "" || subject.Symbol == "" {
		return refuse("missing expected subject")
	}
	if recorded.MaximalClosure == "" || recorded.TestVariantClosure == "" || recorded.Guards.Toolchain == "" || recorded.Guards.BuildConfig == "" {
		return refuse("missing producing code identity")
	}
	if recorded.ClosureStrategy != ClosureStrategy || recorded.DynamicStateStrategy != DynamicStateStrategy {
		return refuse("unrecognized producing analysis strategy")
	}
	if !recorded.ObservationProof.Observable || !compatibleObservationProof(recorded.ObservationProof, recorded.ObservationAssertion, subject, recorded.MaximalClosure) {
		return refuse("missing or incompatible native observation proof")
	}
	if err := runtimeinput.ValidateRecordedSupport(recorded.RuntimeInputs, recorded.RuntimeDigest, outcomeSubject(recorded, subject)); err != nil {
		return refuse(err.Error())
	}
	return RecordedObservationSupport{Status: RecordedSupportNative}
}
