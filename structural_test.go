package gofresh

import (
	"testing"

	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/stipulator/stipulate/structural"
)

func TestFingerprintIsExportedData(t *testing.T) {
	structural.ExportedData[Fingerprint](t,
		structural.FieldOf[string]("MaximalClosure"),
		structural.FieldOf[Refinement]("Refinement"),
		structural.FieldOf[string]("ObservationAssertion"),
		structural.FieldOf[ObservationProof]("ObservationProof"),
		structural.FieldOf[guard.Guards]("Guards"),
		structural.FieldOf[string]("PurityAssertion"),
		structural.FieldOf[string]("RuntimeInputs"),
		structural.FieldOf[string]("RuntimeDigest"),
		structural.FieldOf[Kind]("ResultKind"),
	)
}

func TestPurityInputIsSubjectPredicate(t *testing.T) {
	structural.FunctionSignature[func(func(Subject) bool) Option](t, WithAssumePure)
}

func TestViewCheckUsesConstructionKind(t *testing.T) {
	structural.FunctionSignature[func(*View, Fingerprint, Subject) (Verdict, error)](t, (*View).Check)
}
