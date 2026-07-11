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
		structural.FieldOf[guard.Guards]("Guards"),
		structural.FieldOf[string]("PurityAssertion"),
		structural.FieldOf[string]("RuntimeInputs"),
		structural.FieldOf[string]("RuntimeDigest"),
	)
}

func TestPurityInputIsSubjectPredicate(t *testing.T) {
	structural.FunctionSignature[func(func(Subject) bool) Option](t, WithAssumePure)
}
