package gofresh

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/gofresh/internal/jsonrecord"
)

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
