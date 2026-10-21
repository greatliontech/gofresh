package gofresh

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/runtimeinput"
)

func TestMembershipRefusalsCollectOrderedSubjectsAndScope(t *testing.T) {
	known := Subject{Package: "p", Symbol: "Known"}
	a, b := Subject{Package: "p", Symbol: "A"}, Subject{Package: "p", Symbol: "B"}
	v := &View{subjects: []Subject{known}, facts: &observationFacts{maximal: map[Subject]subjectFacts{known: {}}}}
	for _, tc := range []struct{ request, want []Subject }{
		{[]Subject{b, known, a, b, a}, []Subject{b, a}},
		{[]Subject{a, a, known, b, known}, []Subject{a, b}},
	} {
		child, err := v.Sibling(tc.request)
		var unknown *UnknownSubjectsError
		if child != nil || !errors.As(err, &unknown) || unknown.Scope != ParentView || !slices.Equal(unknown.Subjects, tc.want) {
			t.Fatalf("sibling refusal = %+v %v, want %+v", child, err, tc.want)
		}
		if strings.Contains(err.Error(), "selected source") {
			t.Fatalf("selection refusal asserts declaration absence: %v", err)
		}
		err = requireSubjects(tc.request, func(s Subject) bool { return s == known }, SelectedSource)
		if !errors.As(err, &unknown) || unknown.Scope != SelectedSource || !slices.Equal(unknown.Subjects, tc.want) {
			t.Fatalf("source refusal = %v", err)
		}
	}
	child, err := v.Sibling([]Subject{known, known})
	if err != nil || !slices.Equal(child.subjects, []Subject{known}) {
		t.Fatalf("known duplicate selection = %+v %v", child, err)
	}
	if child, err := v.Sibling(nil); err == nil || child != nil {
		t.Fatal("empty sibling accepted")
	}
}

func TestRecordedBatchPreparationHasDeterministicCompleteTiers(t *testing.T) {
	known := Subject{Package: "p", Symbol: "Known"}
	// Package and symbol are separate sorting axes: concatenated names can
	// collide for dotted import paths and method symbols.
	a := Subject{Package: "a", Symbol: "z.F"}
	b := Subject{Package: "a.z", Symbol: "F"}
	c := Subject{Package: "z", Symbol: "F"}
	d := Subject{Package: "z", Symbol: "G"}
	good := Fingerprint{ResultKind: CodeResult}
	wrongKind := Fingerprint{ResultKind: Measurement}
	malformed := Fingerprint{ResultKind: Kind(99)}
	v := &View{engine: &Engine{}, kind: CodeResult, facts: &observationFacts{maximal: map[Subject]subjectFacts{known: {}}}}
	work := 0
	oldWindow := viewTestHooks.runtimeWindow
	viewTestHooks.runtimeWindow = func() { work++ }
	t.Cleanup(func() { viewTestHooks.runtimeWindow = oldWindow })
	v.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
		work++
		return runtimeinput.State{}, nil
	}
	v.beforePreciseAnalysis = func() { work++ }
	for _, check := range []struct {
		name string
		call func(context.Context, map[Subject]Fingerprint) (map[Subject]Verdict, error)
	}{{"ordinary", v.CheckBatch}, {"observed", v.CheckObservedBatch}} {
		for _, order := range [][]Subject{{known, a, b, c, d}, {d, c, b, a, known}, {b, known, d, a, c}} {
			for tier := 0; tier < 3; tier++ {
				t.Run(check.name+"/"+string(rune('0'+tier)), func(t *testing.T) {
					recorded := map[Subject]Fingerprint{}
					for _, subject := range order {
						recorded[subject] = good
						if tier <= 1 && (subject == a || subject == b) {
							recorded[subject] = wrongKind
						}
						if tier == 0 && (subject == c || subject == d) {
							recorded[subject] = malformed
						}
					}
					verdicts, err := check.call(t.Context(), recorded)
					if verdicts != nil || err == nil || work != 0 {
						t.Fatalf("preparation paid work/returned partials: %+v %v work=%d", verdicts, err, work)
					}
					if tier == 2 {
						var unknown *UnknownSubjectsError
						if !errors.As(err, &unknown) || unknown.Scope != SelectedView || !slices.Equal(unknown.Subjects, []Subject{a, b, c, d}) {
							t.Fatalf("membership = %v", err)
						}
						return
					}
					var batch *RecordedBatchError
					if !errors.As(err, &batch) {
						t.Fatalf("untyped record refusal: %v", err)
					}
					wantTier, wantSubjects := RecordShapeRefusal, []Subject{c, d}
					if tier == 1 {
						wantTier, wantSubjects = RecordKindRefusal, []Subject{a, b}
					}
					var subjects []Subject
					for _, failure := range batch.Failures {
						subjects = append(subjects, failure.Subject)
					}
					if batch.Tier != wantTier || !slices.Equal(subjects, wantSubjects) {
						t.Fatalf("tier/set = %+v, want %v %+v", batch, wantTier, wantSubjects)
					}
					if tier == 0 && len(batch.Unwrap()) != 2 {
						t.Fatal("lost original shape refusals")
					}
				})
			}
		}
	}
	// Empty maps retain the successful empty-batch behavior.
	prepared, err := v.CheckBatch(t.Context(), nil)
	if err != nil || !reflect.DeepEqual(prepared, map[Subject]Verdict{}) {
		t.Fatalf("empty preparation = %+v %v", prepared, err)
	}
}
