package gofresh

import "github.com/greatliontech/gofresh/closure"

// subjectFacts separates immutable maximal inputs from consumer-tier obligations.
// The obligations are independent: selecting one diagnostic must not erase the
// others. They describe the construction's conservative analysis, never a later
// producing unit's or historical candidate's admission.
type subjectFacts struct {
	source      closure.MaximalFacts
	openWorld   *subjectRefusal
	sharedState *subjectRefusal
	ambiguous   *subjectRefusal
	external    bool
}

// Presence carries the obligation; even an empty diagnostic cannot remove it.
// A refusal is immutable after construction and may be shared with siblings.
type subjectRefusal struct{ reason string }

func sameRefusal(a, b *subjectRefusal) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// closure is the ordinary verdict ladder's projection. A caller may refine its
// local decision using separately admitted evidence, but cannot write it back to
// these facts. The source inventory and every consumer-tier obligation survive
// even when a higher-priority diagnostic is selected here.
func (f subjectFacts) closure() closure.Closure {
	c := f.source.Closure()
	if f.openWorld != nil {
		c.Unverifiable, c.Refusal, c.Reason = true, closure.OpenWorldRefusal, f.openWorld.reason
	}
	if f.sharedState != nil {
		c.Unverifiable, c.Refusal, c.Reason = true, closure.SharedDynamicStateRefusal, f.sharedState.reason
	}
	if f.ambiguous != nil {
		c.Unverifiable, c.Refusal, c.Reason = true, closure.AmbiguousSubjectRefusal, f.ambiguous.reason
	}
	if f.external {
		c.External, c.Unverifiable, c.Reason = true, true, "external directive"
	}
	return c
}

// equal compares base observations, not evidence-dependent decisions. A budget
// cut can change only the shared-state discharge; all other obligations must
// still agree, including ones hidden by the selected diagnostic.
func (f subjectFacts) equal(other subjectFacts, cut bool) bool {
	return f.source.Equal(other.source) && sameRefusal(f.openWorld, other.openWorld) &&
		(cut || sameRefusal(f.sharedState, other.sharedState)) &&
		sameRefusal(f.ambiguous, other.ambiguous) && f.external == other.external
}

func (f *observationFacts) closure(subject Subject) closure.Closure {
	return f.maximal[subject].closure()
}
