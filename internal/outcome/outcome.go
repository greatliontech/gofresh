// Package outcome carries the module-private capability issued by an analysis
// view. Public producers can hold a capability but cannot construct its proof.
//
// Environment reads and filesystem reads differ in how their operation outcomes
// are established:
//   - When an execution is attested to have an immutable process environment
//     (and static analysis proves no reachability to os.Setenv, os.Unsetenv, or
//     os.Clearenv), the outcome of every os.Getenv / os.LookupEnv consultation
//     is uniquely determined by the pre-execution environment snapshot bound in
//     Binding. The view derives those environment outcomes directly from the
//     bound snapshot without per-operation runtime logging.
//   - Filesystem consultations (os.Open, os.Stat, os.Chdir, etc.), by contrast,
//     depend on the mutable external filesystem and cannot be derived from a
//     static process snapshot alone; they require per-operation -test.testlogfile
//     records paired with a pre/post filesystem bracket.
//
// Span, Binding, and Support bind the pre-execution frame's coordinates
// (process, environment digest, module root, and working directory) to the
// static subject proofs prepared by the analysis view so that runtimeinput and
// Session verify the exact same execution frame.
package outcome

import "slices"

// Method identifies the admitted immutable-environment derivation.
const Method = "gofresh/immutable-environment@1"

// StaticMethod identifies the static effect-free reachability derivation.
const StaticMethod = "gofresh/static-reachability@1"

// Span identifies one pre-execution frame. The nonzero size gives distinct
// allocations distinct identities; copies of a frame retain the same span.
type Span struct{ marker byte }

// Binding joins the exact execution coordinates shared by its independent
// completion and outcome premises. It is never persisted.
type Binding struct {
	span        *Span
	process     string
	environment string
	root        string
	directory   string
}

// Bind constructs an execution binding from its coordinates.
func Bind(span *Span, process, environment, root, directory string) Binding {
	return Binding{
		span:        span,
		process:     process,
		environment: environment,
		root:        root,
		directory:   directory,
	}
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
	if binding.span == nil || binding.process == "" || len(subjects) == 0 {
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
	if s.binding.span == nil {
		return "operation-outcome support unavailable"
	}
	if s.binding != binding {
		return "operation-outcome support belongs to a different execution or environment"
	}
	return ""
}

// Subjects returns an independent copy of this preparation's subject identities.
func (s Support) Subjects() []string { return slices.Clone(s.subjects) }
