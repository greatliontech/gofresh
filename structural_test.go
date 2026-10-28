package gofresh

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/stipulator/stipulate/structural"
)

func TestVariantLedgerTypesAreExportedData(t *testing.T) {
	// TestVariantLedger and TestVariantDelta carry deliberate methods (Clone;
	// Inert, the one Go-semantics judgment), so their field shapes are pinned
	// by reflection rather than the method-free ExportedData contract.
	for typeOf, want := range map[reflect.Type][]string{
		reflect.TypeFor[TestVariantLedger](): {"BindingStrategy", "BaseFiles", "Declarations", "FileHeaders"},
		reflect.TypeFor[TestVariantDelta]():  {"BindingsPreserved", "Added", "Changed", "Removed", "HeaderChanges"},
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
		structural.FieldOf[string]("Package"),
		structural.FieldOf[[]string]("References"),
	)
	structural.ExportedData[TestVariantFileHeader](t,
		structural.FieldOf[string]("File"),
		structural.FieldOf[string]("Hash"),
		structural.FieldOf[bool]("Embedded"),
		structural.FieldOf[*TestVariantFileBindings]("Bindings"),
	)
	structural.ExportedData[TestVariantFileBindings](t,
		structural.FieldOf[string]("Package"),
		structural.FieldOf[[]string]("References"),
		structural.FieldOf[[]TestVariantImport]("Imports"),
	)
	structural.ExportedData[TestVariantImport](t,
		structural.FieldOf[string]("Name"),
		structural.FieldOf[string]("Path"),
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

func TestPurityInputIsSubjectPredicate(t *testing.T) {
	structural.ExportedData[SessionPolicy](t,
		structural.FieldOf[string]("EvidenceRoot"),
		structural.FieldOf[[]string]("Vouches"),
		structural.FieldOf[[]Subject]("PureSubjects"),
		structural.FieldOf[func(Subject) bool]("AssumePure"),
		structural.FieldOf[ExecutionModel]("Execution"),
		structural.FieldOf[time.Duration]("AnalysisBudget"),
		structural.FieldOf[gotool.Runner]("Runner"),
		structural.FieldOf[func(Progress)]("Progress"),
	)
}

func TestViewCheckUsesConstructionKind(t *testing.T) {
	structural.FunctionSignature[func(*Snapshot, context.Context, Fingerprint, Subject) (Verdict, error)](t, (*Snapshot).Check)
}

func TestVouchInputShapes(t *testing.T) {
	structural.FunctionSignature[func(string) (string, error)](t, ParseVouchEntry)
	structural.FunctionSignature[func([]string) ([]string, error)](t, ParseVouchEntries)
	structural.FunctionSignature[func(string) ([]string, error)](t, ReadVouchFile)
}

