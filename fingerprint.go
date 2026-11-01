package gofresh

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/greatliontech/gofresh/internal/guard"
	"github.com/greatliontech/gofresh/internal/jsonrecord"
)

// ObservationProof is versioned per-subject evidence that every reachable external
// effect is representable by the recognized completed observation stream.
type ObservationProof struct {
	Strategy   string
	Subject    Subject
	Observable bool
	Reason     string
	Evidence   string
}

// InertTestVariantExtension identifies the recognized applicability transform.
const InertTestVariantExtension = "gofresh/inert-test-variant-extension@1"

// InertTestVariantApplicability is a consumer-licensed effective compartment,
// distinct from the immutable producing fingerprint. Its zero value means no
// transform. Unknown strategies are readable persisted data but confer no reuse.
type InertTestVariantApplicability struct {
	Strategy           string
	TestVariantClosure string
}

// Fingerprint is the recorded evidence a verdict is computed from
// (REQ-fresh-fingerprint-data): the subject's maximal source-closure
// hash, its package's test-variant compartment hash, optional
// observability evidence, guard values, attributable observation and
// purity assertions, result kind, and the caller's runtime-input
// manifest and digest evidence. Its record form is its own JSON
// encoding (REQ-fresh-fingerprint-record) — the caller stores that
// beside its result and pins any further domain facts of its own
// (REQ-fresh-caller-pins). The type stays comparable: a view compares
// fingerprints by equality.
type Fingerprint struct {
	MaximalClosure string
	// ToolchainContent records the complete selected standard-library content.
	// AdmissionPolicy records the independent audit inventory used by dependent
	// derivations. Absence in historical records never acquires today's value.
	ToolchainContent string
	AdmissionPolicy  string
	// TestVariantClosure is the subject package's test-variant compartment:
	// 32 hex over the package's own test-only files, which the maximal
	// closure excludes. A sibling test edit moves only this compartment, so
	// a consumer validating test-binary evidence can tell "a sibling test
	// moved" (stale with reason ReasonTestVariants) from any other drift. A
	// package with no test files records the stable empty-set identity
	// (testvariant.EmptyTestVariantClosure); an empty value identifies a
	// recording that predates the partition and fails closed to stale
	// (REQ-closure-test-variant-hash).
	TestVariantClosure string
	// InertTestVariantApplicability is an explicitly licensed effective
	// endpoint. The producing fields, including TestVariantClosure, stay intact.
	InertTestVariantApplicability InertTestVariantApplicability
	ObservationAssertion          string
	ObservationProof              ObservationProof
	Guards                        Guards
	PurityAssertion               string // attributable assertion used to override unverifiability; empty means none
	// DynamicStateVouches names the caller vouches that discharged
	// shared-dynamic-state culprits reachable from this subject at capture:
	// sorted canonical "<import path>.<Variable>" identities, comma-joined.
	// Empty means no vouch was load-bearing. Recorded for audit — the
	// acceptance is visible in the evidence, never silent (REQ-vouch-recorded);
	// validity needs no comparison over it, because a withdrawn vouch
	// resurfaces the culprit in the current derivation and the verdict
	// refuses on its own.
	DynamicStateVouches string
	// SingleSubjectDischarges names the package-level variables whose
	// shared-dynamic-state discharge rested on the caller's
	// single-subject-process attestation (WithSingleSubjectExecution)
	// and is reachable from this subject at capture — the audited
	// pooling set's sync.Pool carriers and the single-subject
	// directive's variables alike: sorted canonical
	// "<import path>.<Variable>" identities, comma-joined. Empty means
	// the attestation was not load-bearing for this subject (or not
	// given). Recorded for audit exactly as a vouch discharge is — the
	// acceptance is visible in the evidence, never silent
	// (REQ-vouch-recorded); validity needs no comparison over it, because
	// a session without the attestation re-marks the variable in the
	// current derivation and the verdict refuses on its own.
	SingleSubjectDischarges string
	// PackageProcessDischarges names the package-level variables whose
	// shared-dynamic-state downgrade the package-process attestation's
	// binary-scoped reachability judgment discharged for this subject —
	// canonical (comma-joined, sorted), empty when none. Attestation-
	// borne acceptances exactly as SingleSubjectDischarges
	// (REQ-closure-shared-dynamic-state).
	PackageProcessDischarges string
	// DynamicStateStrategy records the shared-dynamic-state fact
	// derivation the evidence was computed under — the structural twin
	// of ObservationProof.Strategy: a strategy move re-measures rather
	// than serving verdicts under semantics the record was not computed
	// by, and an empty recorded value (a record predating the field)
	// fails closed exactly as the compartment's does
	// (REQ-closure-dynamic-state-memo's serving arm).
	DynamicStateStrategy string
	// ClosureStrategy records the closure identity derivation the
	// MaximalClosure and TestVariantClosure were folded under — the
	// identity's own version, so a consumer comparing two records'
	// closure identities compares them within one derivation and
	// bridges, rather than misreads, a derivation change: two hashes
	// folded by different strategies say nothing about each other's
	// source, and an empty recorded strategy is no derivation at all.
	ClosureStrategy string
	RuntimeInputs   string // encoded manifest; empty only when the caller supplies no observation manifest
	RuntimeDigest   string // digest of the manifest at capture
	ResultKind      Kind   // guard policy captured with this recording; zero is invalid
}

// EffectiveTestVariantClosure returns the applicability endpoint when present,
// otherwise the producing compartment. It does not recognize or validate a
// strategy; Check fails closed on an unknown one.
func (f Fingerprint) EffectiveTestVariantClosure() string {
	if f.InertTestVariantApplicability != (InertTestVariantApplicability{}) {
		return f.InertTestVariantApplicability.TestVariantClosure
	}
	return f.TestVariantClosure
}

func (f Fingerprint) recognizedApplicability() bool {
	a := f.InertTestVariantApplicability
	return a == (InertTestVariantApplicability{}) || (a.Strategy == InertTestVariantExtension && a.TestVariantClosure != "" && f.TestVariantClosure != "")
}

func validKind(kind Kind) bool { return kind == CodeResult || kind == Measurement }

func validateRecordedKind(recorded Fingerprint) error {
	if !validKind(recorded.ResultKind) {
		return fmt.Errorf("gofresh: invalid recorded result kind %d", recorded.ResultKind)
	}
	if recorded.ResultKind == CodeResult && (recorded.Guards.Machine != "" || recorded.Guards.RuntimeConfig != "") {
		return errors.New("gofresh: code-result fingerprint carries measurement guards")
	}
	return nil
}

// fingerprintRecord is the fingerprint's one record form
// (REQ-fresh-fingerprint-record): the guards flattened to their four
// keys, the observation proof a nested object present exactly when the
// proof is non-zero, every optional key omitted when empty, the closure
// hashes, the two code guards, and the result kind always present. The
// key set and its order are contract — a consumer derives record names
// from these bytes.
type fingerprintRecord struct {
	MaximalClosure                string                               `json:"maximalClosure"`
	TestVariantClosure            string                               `json:"testVariantClosure"`
	Toolchain                     string                               `json:"toolchain"`
	BuildConfig                   string                               `json:"buildConfig"`
	ToolchainContent              string                               `json:"toolchainContent,omitempty"`
	AdmissionPolicy               string                               `json:"admissionPolicy,omitempty"`
	Machine                       string                               `json:"machine,omitempty"`
	RuntimeConfig                 string                               `json:"runtimeConfig,omitempty"`
	ObservationAssertion          string                               `json:"observationAssertion,omitempty"`
	ObservationProof              *observationProofRecord              `json:"observationProof,omitempty"`
	PurityAssertion               string                               `json:"purityAssertion,omitempty"`
	DynamicStateVouches           string                               `json:"dynamicStateVouches,omitempty"`
	SingleSubjectDischarges       string                               `json:"singleSubjectDischarges,omitempty"`
	PackageProcessDischarges      string                               `json:"packageProcessDischarges,omitempty"`
	DynamicStateStrategy          string                               `json:"dynamicStateStrategy,omitempty"`
	ClosureStrategy               string                               `json:"closureStrategy,omitempty"`
	RuntimeInputs                 string                               `json:"runtimeInputs,omitempty"`
	RuntimeDigest                 string                               `json:"runtimeDigest,omitempty"`
	InertTestVariantApplicability *inertTestVariantApplicabilityRecord `json:"inertTestVariantApplicability,omitempty"`
	ResultKind                    Kind                                 `json:"resultKind"`
}

// observationProofRecord is the proof's record form: the subject
// flattened to its package and symbol, the reason omitted when empty.
type observationProofRecord struct {
	Strategy   string `json:"strategy"`
	Package    string `json:"package"`
	Symbol     string `json:"symbol"`
	Observable bool   `json:"observable"`
	Reason     string `json:"reason,omitempty"`
	Evidence   string `json:"evidence"`
}

// Validate is the record ladder every reader of a stored fingerprint
// applies before judging it — the engine at Check, the decoder on every
// record, the encoder before writing one: the result kind is one of the
// two kinds (zero is a recording written without one), and a code-result
// fingerprint carries no measurement guard (a machine or
// runtime-configuration value on a code-result recording is internally
// inconsistent, REQ-guard-selective-capture). A non-zero applicability endpoint
// carries both required values; unknown non-empty strategies remain readable.
// A refusal names the fault.
func (f Fingerprint) Validate() error {
	if a := f.InertTestVariantApplicability; a != (InertTestVariantApplicability{}) && (a.Strategy == "" || a.TestVariantClosure == "") {
		return errors.New("gofresh: inert test-variant applicability requires strategy and testVariantClosure")
	}
	return validateRecordedKind(f)
}

// MarshalJSON encodes the fingerprint in its one record form
// (REQ-fresh-fingerprint-record), refusing a fingerprint Validate
// refuses so an invalid record is never written.
func (f Fingerprint) MarshalJSON() ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	rec := fingerprintRecord{
		MaximalClosure:           f.MaximalClosure,
		TestVariantClosure:       f.TestVariantClosure,
		Toolchain:                f.Guards.Toolchain,
		BuildConfig:              f.Guards.BuildConfig,
		ToolchainContent:         f.ToolchainContent,
		AdmissionPolicy:          f.AdmissionPolicy,
		Machine:                  f.Guards.Machine,
		RuntimeConfig:            f.Guards.RuntimeConfig,
		ObservationAssertion:     f.ObservationAssertion,
		PurityAssertion:          f.PurityAssertion,
		DynamicStateVouches:      f.DynamicStateVouches,
		SingleSubjectDischarges:  f.SingleSubjectDischarges,
		PackageProcessDischarges: f.PackageProcessDischarges,
		DynamicStateStrategy:     f.DynamicStateStrategy,
		ClosureStrategy:          f.ClosureStrategy,
		RuntimeInputs:            f.RuntimeInputs,
		RuntimeDigest:            f.RuntimeDigest,
		ResultKind:               f.ResultKind,
	}
	if f.ObservationProof != (ObservationProof{}) {
		p := f.ObservationProof
		rec.ObservationProof = &observationProofRecord{
			Strategy:   p.Strategy,
			Package:    p.Subject.Package,
			Symbol:     p.Subject.Symbol,
			Observable: p.Observable,
			Reason:     p.Reason,
			Evidence:   p.Evidence,
		}
	}
	if a := f.InertTestVariantApplicability; a != (InertTestVariantApplicability{}) {
		rec.InertTestVariantApplicability = &inertTestVariantApplicabilityRecord{a.Strategy, a.TestVariantClosure}
	}
	return json.Marshal(rec)
}

// UnmarshalJSON decodes the one record form, refusing every shape the
// form does not produce — an unknown key, a duplicated key, an explicit
// null (judged before the key's name, so a null under an unknown key
// names the null), a proof without its observable, a positive proof
// carrying a reason, bytes the encoder would not have written up to
// insignificant whitespace (a reordered or empty-valued record; an
// indented one decodes, a parent document being free to indent) — and
// every fingerprint Validate refuses, so a stored record either
// decodes to the evidence it was written from, re-encoding to its
// compact bytes, or names its fault (REQ-fresh-fingerprint-record).
func (f *Fingerprint) UnmarshalJSON(data []byte) error {
	fields, err := jsonrecord.UniqueObjectFields("fingerprint record", data)
	if err != nil {
		return err
	}
	if err := jsonrecord.RejectNullFields("fingerprint record", fields); err != nil {
		return err
	}
	var rec fingerprintRecord
	if err := jsonrecord.DecodeObject("fingerprint record", data, &rec); err != nil {
		return err
	}
	decoded := Fingerprint{
		MaximalClosure:     rec.MaximalClosure,
		ToolchainContent:   rec.ToolchainContent,
		AdmissionPolicy:    rec.AdmissionPolicy,
		TestVariantClosure: rec.TestVariantClosure,
		Guards: guard.Guards{
			Toolchain:     rec.Toolchain,
			BuildConfig:   rec.BuildConfig,
			Machine:       rec.Machine,
			RuntimeConfig: rec.RuntimeConfig,
		},
		ObservationAssertion:     rec.ObservationAssertion,
		PurityAssertion:          rec.PurityAssertion,
		DynamicStateVouches:      rec.DynamicStateVouches,
		SingleSubjectDischarges:  rec.SingleSubjectDischarges,
		PackageProcessDischarges: rec.PackageProcessDischarges,
		DynamicStateStrategy:     rec.DynamicStateStrategy,
		ClosureStrategy:          rec.ClosureStrategy,
		RuntimeInputs:            rec.RuntimeInputs,
		RuntimeDigest:            rec.RuntimeDigest,
		ResultKind:               rec.ResultKind,
	}
	if p := rec.ObservationProof; p != nil {
		decoded.ObservationProof = ObservationProof{
			Strategy:   p.Strategy,
			Subject:    Subject{Package: p.Package, Symbol: p.Symbol},
			Observable: p.Observable,
			Reason:     p.Reason,
			Evidence:   p.Evidence,
		}
	}
	if a := rec.InertTestVariantApplicability; a != nil {
		decoded.InertTestVariantApplicability = InertTestVariantApplicability{a.Strategy, a.TestVariantClosure}
	}
	if err := decoded.Validate(); err != nil {
		return err
	}
	// The form's own encoding, up to insignificant whitespace: a parent
	// encoder re-indents a nested value (a consumer's pretty-printed
	// document), so the comparison is over the compacted bytes; a
	// reordered, empty-valued, or otherwise foreign record still differs.
	canonical, err := decoded.MarshalJSON()
	if err != nil {
		return err
	}
	if !jsonrecord.CanonicalEqual(canonical, data, true) {
		return errors.New("gofresh: fingerprint record is not the form's own encoding")
	}
	*f = decoded
	return nil
}

func (p *observationProofRecord) UnmarshalJSON(data []byte) error {
	type plain observationProofRecord
	fields, err := jsonrecord.UniqueObjectFields("observation proof", data)
	if err != nil {
		return err
	}
	if err := jsonrecord.RejectNullFields("observation proof", fields); err != nil {
		return err
	}
	if _, ok := fields["observable"]; !ok {
		return errors.New("gofresh: observation proof carries no observable")
	}
	var decoded plain
	if err := jsonrecord.DecodeObject("observation proof", data, &decoded); err != nil {
		return err
	}
	if _, hasReason := fields["reason"]; decoded.Observable && hasReason {
		return errors.New("gofresh: positive observation proof carries a reason")
	}
	*p = observationProofRecord(decoded)
	return nil
}

type inertTestVariantApplicabilityRecord struct {
	Strategy           string `json:"strategy"`
	TestVariantClosure string `json:"testVariantClosure"`
}

func (a *inertTestVariantApplicabilityRecord) UnmarshalJSON(data []byte) error {
	const object = "inert test-variant applicability"
	fields, err := jsonrecord.UniqueObjectFields(object, data)
	if err != nil {
		return err
	}
	if err := jsonrecord.RejectNullFields(object, fields); err != nil {
		return err
	}
	type plain inertTestVariantApplicabilityRecord
	var decoded plain
	if err := jsonrecord.DecodeObject(object, data, &decoded); err != nil {
		return err
	}
	if decoded.Strategy == "" || decoded.TestVariantClosure == "" {
		return fmt.Errorf("gofresh: %s requires strategy and testVariantClosure", object)
	}
	*a = inertTestVariantApplicabilityRecord(decoded)
	return nil
}
