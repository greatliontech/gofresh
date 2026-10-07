// Package outcome carries the module-private capability issued by an analysis
// view. Public producers can hold a capability but cannot construct its proof.
package outcome

import "slices"

// Method identifies the admitted immutable-environment derivation.
const Method = "gofresh/immutable-environment@1"

// Span identifies one pre-execution frame. The nonzero size gives distinct
// allocations distinct identities; copies of a frame retain the same span.
type Span struct{ marker byte }

// Binding joins the exact execution coordinates shared by its independent
// completion and outcome premises. It is never persisted.
type Binding struct {
	Span        *Span
	Process     string
	Environment string
	Root        string
	Directory   string
}

// Support is an opaque outcome derivation bound to a contributing execution.
// Its zero value supplies no evidence.
type Support struct {
	binding  Binding
	subjects []string
	reason   string
}

// Prepare is used by the analysis view after judging every contributing
// subject. A refusal retains its reason without inventing a supported subject.
func Prepare(binding Binding, subjects []string, reason string) Support {
	if binding.Span == nil || binding.Process == "" || len(subjects) == 0 {
		return Support{}
	}
	keys := slices.Clone(subjects)
	slices.Sort(keys)
	return Support{binding: binding, subjects: slices.Compact(keys), reason: reason}
}

// Reason reports missing, unsupported or mismatched execution evidence.
func (s Support) Reason(binding Binding) string {
	if s.reason != "" {
		return s.reason
	}
	// Prepare is the only nonzero constructor and requires a nonempty set.
	if s.binding.Span == nil {
		return "operation-outcome support unavailable"
	}
	if s.binding != binding {
		return "operation-outcome support belongs to a different execution or environment"
	}
	return ""
}

// Subjects returns an independent copy of this preparation's subject identities.
func (s Support) Subjects() []string { return slices.Clone(s.subjects) }
