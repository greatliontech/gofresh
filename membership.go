package gofresh

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// SubjectScope states what a membership refusal tested. A declaration outside
// a selected view can still exist in source; these refusals do not conflate it
// with a missing declaration.
type SubjectScope uint8

const (
	SelectedSource SubjectScope = iota
	SelectedView
	ParentView
)

// UnknownSubjectsError names every missing member once, in request order (or
// package/symbol lexical order for map-backed requests). SelectedSource means
// declarations were absent from the source scan, including a formerly held
// subject disappearing during re-observation. Other scopes concern selection
// alone and make no assertion about source existence.
type UnknownSubjectsError struct {
	Subjects []Subject
	Scope    SubjectScope
}

func (e *UnknownSubjectsError) Error() string {
	noun := "subjects"
	if len(e.Subjects) == 1 {
		noun = "subject"
	}
	names := make([]string, 0, len(e.Subjects))
	for _, s := range e.Subjects {
		names = append(names, s.Package+"."+s.Symbol)
	}
	where := "not found in selected source"
	switch e.Scope {
	case SelectedView:
		where = "not in this analysis view"
	case ParentView:
		where = "not in the parent view"
	}
	return fmt.Sprintf("gofresh: %s %s %s", noun, strings.Join(names, ", "), where)
}

func requireSubjects(subjects []Subject, contains func(Subject) bool, scope SubjectScope) error {
	seen := make(map[Subject]bool, len(subjects))
	var unknown []Subject
	for _, subject := range subjects {
		if !seen[subject] && !contains(subject) {
			unknown = append(unknown, subject)
		}
		seen[subject] = true
	}
	if len(unknown) == 0 {
		return nil
	}
	return &UnknownSubjectsError{Subjects: unknown, Scope: scope}
}

// requireMembers judges selection, not whether today's source declares a name.
// The immutable closure inventory is the shared membership authority for every
// projection, attachment and check over a constructed view.
func (v *Snapshot) requireMembers(subjects []Subject) error {
	return requireSubjects(subjects, func(s Subject) bool {
		_, ok := v.facts.maximal[s]
		return ok
	}, SelectedView)
}

func orderedRecordedSubjects(recorded map[Subject]Fingerprint) []Subject {
	ordered := make([]Subject, 0, len(recorded))
	for subject := range recorded {
		ordered = append(ordered, subject)
	}
	slices.SortFunc(ordered, func(a, b Subject) int {
		if order := cmp.Compare(a.Package, b.Package); order != 0 {
			return order
		}
		return cmp.Compare(a.Symbol, b.Symbol)
	})
	return ordered
}

// RecordedRefusalKind identifies the preparation tier refusing a record batch.
type RecordedRefusalKind uint8

const (
	RecordShapeRefusal RecordedRefusalKind = iota + 1
	RecordKindRefusal
)

// RecordedFailure attributes one record's preparation failure. Shape refusals
// carry the fingerprint validator's error; kind refusals carry the recorded kind.
type RecordedFailure struct {
	Subject Subject
	Shape   error
	Kind    Kind
}

// RecordedBatchError reports every failure in the first refusing preparation
// tier, in request order (package/symbol order for map-backed APIs). All shape failures precede every view-kind
// mismatch; every kind mismatch precedes membership. No partial verdict exists.
type RecordedBatchError struct {
	Tier     RecordedRefusalKind
	ViewKind Kind
	Failures []RecordedFailure
}

func (e *RecordedBatchError) Error() string {
	parts := make([]string, 0, len(e.Failures))
	for _, failure := range e.Failures {
		if e.Tier == RecordShapeRefusal {
			parts = append(parts, fmt.Sprintf("%s.%s: %v", failure.Subject.Package, failure.Subject.Symbol, failure.Shape))
		} else {
			parts = append(parts, fmt.Sprintf("gofresh: recorded result kind %d for %s.%s does not match view kind %d", failure.Kind, failure.Subject.Package, failure.Subject.Symbol, e.ViewKind))
		}
	}
	return strings.Join(parts, "; ")
}

// Unwrap exposes the original fingerprint shape errors without making their
// diagnostic wording the batch's refusal classification.
func (e *RecordedBatchError) Unwrap() []error {
	var errors []error
	for _, failure := range e.Failures {
		if failure.Shape != nil {
			errors = append(errors, failure.Shape)
		}
	}
	return errors
}
