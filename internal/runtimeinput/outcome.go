package runtimeinput

import "slices"

// OutcomeMethod identifies the admitted immutable-environment derivation.
const OutcomeMethod = "gofresh/immutable-environment@1"

// StaticOutcomeMethod identifies the static effect-free reachability derivation.
const StaticOutcomeMethod = "gofresh/static-reachability@1"

// outcomeSpan identifies one pre-execution frame. The nonzero size gives
// distinct allocations distinct identities; copies of a frame retain the same
// span.
type outcomeSpan struct{ marker byte }

// OutcomeBinding joins the exact execution coordinates shared by independent
// completion and outcome premises. Only ProducerFrame.OutcomeBinding constructs
// a non-zero binding; it is never persisted.
type OutcomeBinding struct {
	span        *outcomeSpan
	process     string
	environment string
	root        string
	directory   string
}

func bindOutcome(span *outcomeSpan, process, environment, root, directory string) OutcomeBinding {
	return OutcomeBinding{
		span:        span,
		process:     process,
		environment: environment,
		root:        root,
		directory:   directory,
	}
}

// OutcomeSupport is an opaque outcome derivation bound to a contributing
// execution. Only the analysis view constructs support; its zero value supplies
// no evidence.
type OutcomeSupport struct {
	binding  OutcomeBinding
	subjects []string
	reason   string
}

// PrepareOutcomeSupport constructs outcome support after judging every
// contributing subject. A refusal retains its reason without inventing a
// supported subject.
func PrepareOutcomeSupport(binding OutcomeBinding, subjects []string, reason string) OutcomeSupport {
	if binding.span == nil || binding.process == "" || len(subjects) == 0 {
		return OutcomeSupport{}
	}
	keys := slices.Clone(subjects)
	slices.Sort(keys)
	return OutcomeSupport{binding: binding, subjects: slices.Compact(keys), reason: reason}
}

// Reason reports missing, unsupported or mismatched execution evidence.
func (s OutcomeSupport) Reason(binding OutcomeBinding) string {
	if s.reason != "" {
		return s.reason
	}
	if s.binding.span == nil {
		return "operation-outcome support unavailable"
	}
	if s.binding != binding {
		return "operation-outcome support belongs to a different execution or environment"
	}
	return ""
}

// Subjects returns an independent copy of this preparation's subject identities.
func (s OutcomeSupport) Subjects() []string { return slices.Clone(s.subjects) }

// TrackedChdirSupport is an opaque analysis-derived capability certifying that
// the producing test binary satisfies the toolchain and binary-graph premises
// for balanced LIFO testing.Chdir excursion tracking. The zero value grants none.
type TrackedChdirSupport struct {
	span      *outcomeSpan
	root      string
	directory string
}

func prepareTrackedChdir(span *outcomeSpan, root, directory string, safe bool) TrackedChdirSupport {
	if !safe || span == nil || root == "" || directory == "" {
		return TrackedChdirSupport{}
	}
	return TrackedChdirSupport{span: span, root: root, directory: directory}
}

func matchesTrackedChdir(s TrackedChdirSupport, span *outcomeSpan, root, directory string) bool {
	return s.span != nil && s.span == span && s.root == root && s.directory == directory
}
