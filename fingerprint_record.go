package gofresh

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/greatliontech/gofresh/guard"
)

// fingerprintRecord is the fingerprint's one record form
// (REQ-fresh-fingerprint-record): the guards flattened to their four
// keys, the observation proof a nested object present exactly when the
// proof is non-zero, every optional key omitted when empty, the closure
// hashes, the two code guards, and the result kind always present. The
// key set and its order are contract — a consumer derives record names
// from these bytes.
type fingerprintRecord struct {
	MaximalClosure           string                  `json:"maximalClosure"`
	TestVariantClosure       string                  `json:"testVariantClosure"`
	Toolchain                string                  `json:"toolchain"`
	BuildConfig              string                  `json:"buildConfig"`
	Machine                  string                  `json:"machine,omitempty"`
	RuntimeConfig            string                  `json:"runtimeConfig,omitempty"`
	ObservationAssertion     string                  `json:"observationAssertion,omitempty"`
	ObservationProof         *observationProofRecord `json:"observationProof,omitempty"`
	PurityAssertion          string                  `json:"purityAssertion,omitempty"`
	DynamicStateVouches      string                  `json:"dynamicStateVouches,omitempty"`
	SingleSubjectDischarges  string                  `json:"singleSubjectDischarges,omitempty"`
	PackageProcessDischarges string                  `json:"packageProcessDischarges,omitempty"`
	DynamicStateStrategy     string                  `json:"dynamicStateStrategy,omitempty"`
	ClosureStrategy          string                  `json:"closureStrategy,omitempty"`
	RuntimeInputs            string                  `json:"runtimeInputs,omitempty"`
	RuntimeDigest            string                  `json:"runtimeDigest,omitempty"`
	ResultKind               Kind                    `json:"resultKind"`
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
// inconsistent, REQ-guard-selective-capture). A refusal names the fault.
func (f Fingerprint) Validate() error {
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
	fields, err := uniqueObjectFields("fingerprint record", data)
	if err != nil {
		return err
	}
	for name, value := range fields {
		if isJSONNull(value) {
			return fmt.Errorf("gofresh: fingerprint record field %q is null", name)
		}
	}
	var rec fingerprintRecord
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return recordFault("fingerprint record", err)
	}
	decoded := Fingerprint{
		MaximalClosure:     rec.MaximalClosure,
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
	// Compact cannot fail here — uniqueObjectFields walked the bytes as
	// one well-formed object and the decoder read them — so its error
	// is unreachable and discarded rather than guarded by a dead arm.
	var compact bytes.Buffer
	_ = json.Compact(&compact, data)
	if !bytes.Equal(canonical, compact.Bytes()) {
		return errors.New("gofresh: fingerprint record is not the form's own encoding")
	}
	*f = decoded
	return nil
}

// recordFault names a decoding fault in the record's own vocabulary:
// the package's own refusals pass through, a value of the wrong JSON
// kind names the field and the kind, anything else carries the object's
// noun — never the internal record type's name.
func recordFault(object string, err error) error {
	var typed *json.UnmarshalTypeError
	switch {
	case strings.HasPrefix(err.Error(), "gofresh: "):
		return err
	case errors.As(err, &typed):
		return fmt.Errorf("gofresh: %s field %q cannot hold a JSON %s", object, typed.Field, typed.Value)
	default:
		return fmt.Errorf("gofresh: %s: %w", object, err)
	}
}

func (p *observationProofRecord) UnmarshalJSON(data []byte) error {
	type plain observationProofRecord
	fields, err := uniqueObjectFields("observation proof", data)
	if err != nil {
		return err
	}
	for name, value := range fields {
		if isJSONNull(value) {
			return fmt.Errorf("gofresh: observation proof field %q is null", name)
		}
	}
	if _, ok := fields["observable"]; !ok {
		return errors.New("gofresh: observation proof carries no observable")
	}
	var decoded plain
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&decoded); err != nil {
		return recordFault("observation proof", err)
	}
	if _, hasReason := fields["reason"]; decoded.Observable && hasReason {
		return errors.New("gofresh: positive observation proof carries a reason")
	}
	*p = observationProofRecord(decoded)
	return nil
}

// uniqueObjectFields reads one JSON object's fields under the object's
// noun, refusing a duplicated key — encoding/json takes the last, which
// would let a record carry two values for one fact — and anything after
// the object.
func uniqueObjectFields(object string, data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return nil, fmt.Errorf("gofresh: %s is not a JSON object", object)
	}
	fields := make(map[string]json.RawMessage)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("gofresh: %s: %w", object, err)
		}
		name, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("gofresh: %s: expected an object field", object)
		}
		if _, exists := fields[name]; exists {
			return nil, fmt.Errorf("gofresh: %s field %q is duplicated", object, name)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, fmt.Errorf("gofresh: %s: %w", object, err)
		}
		fields[name] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("gofresh: %s: %w", object, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("gofresh: %s carries trailing data", object)
	}
	return fields, nil
}

func isJSONNull(value json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(value), []byte("null"))
}
