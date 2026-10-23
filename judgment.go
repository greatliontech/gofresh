package gofresh

import (
	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/gofresh/internal/outcome"
	"github.com/greatliontech/gofresh/runtimeinput"
)

// CauseKind identifies the native fact that decided a refusal. Diagnostic text
// is not part of this classification. NoCause accompanies a valid judgment.
type CauseKind uint8

const (
	NoCause CauseKind = iota
	ClosureCause
	TestVariantsCause
	ToolchainContentCause
	DynamicStateStrategyCause
	ClosureStrategyCause
	RuntimeInputsCause
	ToolchainCause
	BuildConfigCause
	MachineCause
	RuntimeConfigCause
	ResultKindCause
	ExternalDirectiveCause
	ClosureDependenceCause
	SharedDynamicStateCause
	OpenWorldCause
	AmbiguousSubjectCause
)

// CauseCondition distinguishes missing or unsupported evidence from observed
// disagreement. Unavailable means the comparison could not establish a value;
// Refused means a dependence or declaration prevents reuse despite agreement.
type CauseCondition uint8

const (
	NoCondition CauseCondition = iota
	Missing
	Changed
	Unsupported
	Unavailable
	Refused
)

// Cause is the first decisive native refusal, not an exhaustive inventory of
// facts an early-returning check did not evaluate.
type Cause struct {
	Kind      CauseKind
	Condition CauseCondition
}

// ExecutionAssertions names the checking session's caller-declared process model.
// These declarations alone grant neither a discharge nor observation support.
type ExecutionAssertions struct {
	SingleSubject  bool
	PackageProcess bool
}

// JudgmentScope identifies the subject, result policy and declared execution
// model under which the native judgment applies. Consumer outcome claims remain
// outside this scope.
type JudgmentScope struct {
	Subject        Subject
	ResultKind     Kind
	ExecutionModel ExecutionAssertions
}

// PurityAttribution names the responsibility accepted for a purity assertion.
type PurityAttribution uint8

const (
	NoPurity PurityAttribution = iota
	CallerPurity
	SourcePurity
	CallerAndSourcePurity
)

// PurityAuthority retains producing and currently admitted responsibility
// separately. They need not have identical attribution to authorize an override.
type PurityAuthority struct {
	Recorded PurityAttribution
	Current  PurityAttribution
}

func (p PurityAuthority) accepted() bool { return p.Recorded != NoPurity && p.Current != NoPurity }

// ObservationAuthority records the conjunction actually used to lift a closure
// refusal: caller-asserted completeness, compatible derived proof and exact
// subject outcome support, beside the separately checked runtime guard. A
// current applicability derivation never replaces the producing proof/support.
type ObservationAuthority struct {
	Assertion            string
	ProofStrategy        string
	OutcomeMethod        string
	CurrentApplicability bool
}

func (o ObservationAuthority) accepted() bool { return o != (ObservationAuthority{}) }

// AcceptedAuthority names the facts admitted by the deciding check. Zero fields
// grant no authority, including premises skipped by an early refusal. Agreement
// describes compared source and applicable guards, not an execution receipt.
// Discharge strings retain the native canonical variable identities; purity and
// discharges remain caller/source assertions, never observation support.
type AcceptedAuthority struct {
	// GuardAgreement covers source/effective-compartment identity, selected
	// toolchain content and every applicable ordinary guard together. It does
	// not assert absence of unguardable dependencies.
	GuardAgreement bool
	// RuntimeInputs means the recorded manifest's digest agreed. It does not
	// assert capture completeness or outcomes, including under a purity override.
	RuntimeInputs            bool
	Purity                   PurityAuthority
	DynamicStateVouches      string
	SingleSubjectDischarges  string
	PackageProcessDischarges string
	Observation              ObservationAuthority
	// Applicability is the separately licensed effective endpoint accepted by a
	// valid check. It never changes the original producing evidence.
	Applicability InertTestVariantApplicability
}

// JudgmentGround is the comparable semantic account of a verdict. It is derived
// at checking time, never inserted into historical fingerprint or seal bytes.
type JudgmentGround struct {
	Cause    Cause
	Scope    JudgmentScope
	Accepted AcceptedAuthority
}

func refusal(status Status, kind CauseKind, condition CauseCondition, reason string) Verdict {
	return Verdict{Status: status, Reason: reason, Ground: JudgmentGround{Cause: Cause{Kind: kind, Condition: condition}}}
}

func closureStrategyVerdict(rec Fingerprint) Verdict {
	condition := Unsupported
	if rec.ClosureStrategy == "" {
		condition = Missing
	}
	return refusal(Stale, ClosureStrategyCause, condition, "closure strategy")
}

func guardVerdict(mismatch guard.Mismatch) Verdict {
	kind := map[guard.Axis]CauseKind{
		guard.KindAxis: ResultKindCause, guard.ToolchainAxis: ToolchainCause,
		guard.BuildConfigAxis: BuildConfigCause, guard.MachineAxis: MachineCause,
		guard.RuntimeConfigAxis: RuntimeConfigCause,
	}[mismatch.Axis]
	condition := Changed
	if mismatch.Missing {
		condition = Missing
	} else if mismatch.Axis == guard.KindAxis {
		condition = Unsupported
	}
	return refusal(Stale, kind, condition, mismatch.Axis.String())
}

func purityAttribution(assertion string) PurityAttribution {
	switch assertion {
	case "caller assertion":
		return CallerPurity
	case "source directive":
		return SourcePurity
	case "caller assertion and source directive":
		return CallerAndSourcePurity
	default:
		return NoPurity
	}
}

func admittedObservation(rec Fingerprint, subject Subject, cl closure.Closure) ObservationAuthority {
	if !compatibleObservationProof(rec, subject) || rec.AdmissionPolicy != cl.AdmissionPolicy || !rec.ObservationProof.Observable || !runtimeinput.HasOutcomeSupport(rec.RuntimeInputs, outcomeSubject(rec, subject)) {
		return ObservationAuthority{}
	}
	return ObservationAuthority{Assertion: rec.ObservationAssertion, ProofStrategy: rec.ObservationProof.Strategy, OutcomeMethod: outcome.Method}
}

func (v *View) judgmentFor(subject Subject, verdict Verdict) Verdict {
	verdict.Ground.Scope = JudgmentScope{Subject: subject, ResultKind: v.kind}
	if v.engine != nil {
		verdict.Ground.Scope.ExecutionModel = v.engine.executionModel
	}
	// A cut is the immutable pass's unavailability, not proof that the
	// surviving culprit affects this subject. It still blocks observation lift.
	if verdict.Ground.Cause.Kind == SharedDynamicStateCause && v.facts.cut[subject] {
		verdict.Ground.Cause.Condition = Unavailable
	}
	if verdict.Ground.Accepted.GuardAgreement {
		d := v.facts.discharges[subject]
		verdict.Ground.Accepted.DynamicStateVouches = v.facts.vouchDischarges[subject]
		verdict.Ground.Accepted.SingleSubjectDischarges = d.singleSubject
		verdict.Ground.Accepted.PackageProcessDischarges = d.packageProcess
	}
	return verdict
}
