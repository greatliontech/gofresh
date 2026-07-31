package gofresh

import (
	"context"
	"reflect"
	"testing"

	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/stipulator/stipulate/structural"
)

func TestVariantLedgerTypesAreExportedData(t *testing.T) {
	// TestVariantLedger and TestVariantDelta carry deliberate methods (Clone;
	// Inert, the one Go-semantics judgment), so their field shapes are pinned
	// by reflection rather than the method-free ExportedData contract.
	for typeOf, want := range map[reflect.Type][]string{
		reflect.TypeFor[TestVariantLedger](): {"Declarations", "FileHeaders"},
		reflect.TypeFor[TestVariantDelta]():  {"Added", "Changed", "Removed", "HeaderChanges"},
	} {
		if typeOf.NumField() != len(want) {
			t.Fatalf("%s has %d fields, want %d", typeOf, typeOf.NumField(), len(want))
		}
		for i, name := range want {
			if typeOf.Field(i).Name != name {
				t.Fatalf("%s field %d = %s, want %s", typeOf, i, typeOf.Field(i).Name, name)
			}
		}
	}
	structural.ExportedData[TestVariantDeclaration](t,
		structural.FieldOf[string]("File"),
		structural.FieldOf[string]("Kind"),
		structural.FieldOf[string]("Name"),
		structural.FieldOf[string]("Receiver"),
		structural.FieldOf[string]("Hash"),
	)
	structural.ExportedData[TestVariantFileHeader](t,
		structural.FieldOf[string]("File"),
		structural.FieldOf[string]("Hash"),
		structural.FieldOf[bool]("Embedded"),
	)
	structural.ExportedData[TestVariantDeclarationChange](t,
		structural.FieldOf[TestVariantDeclaration]("Before"),
		structural.FieldOf[TestVariantDeclaration]("After"),
	)
	structural.ExportedData[TestVariantHeaderChange](t,
		structural.FieldOf[string]("File"),
		structural.FieldOf[string]("Before"),
		structural.FieldOf[string]("After"),
		structural.FieldOf[bool]("Embedded"),
	)
}

func TestFingerprintIsExportedData(t *testing.T) {
	structural.ExportedData[Fingerprint](t,
		structural.FieldOf[string]("MaximalClosure"),
		structural.FieldOf[string]("TestVariantClosure"),
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
	structural.FunctionSignature[func(*View, context.Context, Fingerprint, Subject) (Verdict, error)](t, (*View).Check)
}
