package gofresh

import (
	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/guard"
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
// facts an early-returning check did not evaluate. When Kind is
// SharedDynamicStateCause and Condition is Refused, Culprit names the package
// and variable that decided the shared-dynamic-state refusal.
type Cause struct {
	Kind      CauseKind
	Condition CauseCondition
	Culprit   Subject
}

// JudgmentScope identifies the subject, result policy and declared execution
// model under which the native judgment applies. Consumer outcome claims remain
// outside this scope.
type JudgmentScope struct {
	Subject        Subject
	ResultKind     Kind
	ExecutionModel ExecutionModel
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
	compatible, effectFree := compatibleObservationProofMode(rec, subject)
	if !compatible || rec.AdmissionPolicy != cl.AdmissionPolicy || !rec.ObservationProof.Observable {
		return ObservationAuthority{}
	}
	if runtimeinput.HasOutcomeSupport(rec.RuntimeInputs, outcomeSubject(rec, subject)) {
		return ObservationAuthority{Assertion: rec.ObservationAssertion, ProofStrategy: rec.ObservationProof.Strategy, OutcomeMethod: outcome.Method}
	}
	if effectFree {
		return ObservationAuthority{Assertion: rec.ObservationAssertion, ProofStrategy: rec.ObservationProof.Strategy, OutcomeMethod: outcome.StaticMethod}
	}
	return ObservationAuthority{}
}

func (v *Snapshot) judgmentFor(subject Subject, verdict Verdict) Verdict {
	verdict.Ground.Scope = JudgmentScope{Subject: subject, ResultKind: v.kind}
	if v.engine != nil {
		verdict.Ground.Scope.ExecutionModel = v.engine.executionModel
	}
	// A cut is the immutable pass's unavailability, not proof that the
	// surviving culprit affects this subject. It still blocks observation lift.
	if verdict.Ground.Cause.Kind == SharedDynamicStateCause && v.facts.cut[subject] {
		verdict.Ground.Cause.Condition = Unavailable
		verdict.Ground.Cause.Culprit = Subject{}
	}
	if verdict.Ground.Accepted.GuardAgreement {
		d := v.facts.discharges[subject]
		verdict.Ground.Accepted.DynamicStateVouches = v.facts.vouchDischarges[subject]
		verdict.Ground.Accepted.SingleSubjectDischarges = d.singleSubject
		verdict.Ground.Accepted.PackageProcessDischarges = d.packageProcess
	}
	return verdict
}

// Status is a verdict's outcome.
type Status string

const (
	Valid        Status = "valid"
	Stale        Status = "stale"
	Unverifiable Status = "unverifiable"
)

// ReasonTestVariants is the stale reason of a compartment-only move:
// the subject's own closure unchanged, its package's test variants
// moved. A consumer keying a rule on it reads the constant, never the
// spelling.
const ReasonTestVariants = "test variants"

// Verdict is the freshness answer for one subject's fingerprint. Reason names the
// first failing guard for Stale, or the unverifiable dependence for Unverifiable;
// its spellings are diagnostics, except ReasonTestVariants, the one a consumer
// keys a rule on. Ground carries the semantic cause, scope and accepted authority
// independently of that diagnostic projection. Verdict remains value-comparable.
type Verdict struct {
	Status Status
	Reason string
	Ground JudgmentGround
}

// decide is the pure verdict function (REQ-fresh-verdict, REQ-fresh-sound): stale on
// the first failing guard; unverifiable when the guards hold but the closure or
// runtime inputs reach an unhashable dependence and no purity override applies;
// valid otherwise. A missing required guard is a mismatch, never valid
// (REQ-guard-completeness). An absent runtime-input manifest supplies no
// observation or assertion; any validity rests on independent applicable
// evidence or purity (REQ-inputs-absent-asserted). commit/dirty are never consulted
// (REQ-fresh-commit-independent).
func decide(rec Fingerprint, cl closure.Closure, cur guard.Guards, rt runtimeinput.State, kind Kind, pure PurityAuthority) Verdict {
	if verdict, failed := recordedEvidenceVerdict(rec, cl); failed {
		return verdict
	}
	return decideAfterClosure(rec, cl, cur, rt, kind, pure)
}

// recordedEvidenceVerdict is the evidence-only verdict ladder shared by every
// check surface (decide, checkBatch, CheckObservedBatch), so the tier
// ordering is written once: an unevaluable recorded core is stale on the
// closure (REQ-fresh-sound); an unchanged core compares the test-variant
// compartment next, stale with the stable discriminating reason
// "test variants", never rescued by observation evidence, an
// empty recorded compartment failing closed
// (REQ-closure-test-variant-identity); a drifted core is stale on the
// closure (REQ-fresh-hierarchical-check). Records surviving the ladder
// proceed to the surface's own guard tiers.
func recordedEvidenceVerdict(rec Fingerprint, current closure.Closure) (Verdict, bool) {
	if rec.MaximalClosure == "" {
		return refusal(Stale, ClosureCause, Missing, "closure"), true
	}
	if rec.MaximalClosure == current.Hash && (!rec.recognizedApplicability() || compartmentStale(rec.EffectiveTestVariantClosure(), current.TestVariants)) {
		condition := Changed
		if !rec.recognizedApplicability() {
			condition = Unsupported
		} else if rec.EffectiveTestVariantClosure() == "" {
			condition = Missing
		} else if current.TestVariants == "" {
			condition = Unavailable
		}
		return refusal(Stale, TestVariantsCause, condition, ReasonTestVariants), true
	}
	if rec.MaximalClosure != current.Hash {
		if current.Hash == "" {
			return refusal(Stale, ClosureCause, Unavailable, "closure"), true
		}
		return refusal(Stale, ClosureCause, Changed, "closure"), true
	}
	if rec.ToolchainContent != "" && current.ToolchainContent != "" && rec.ToolchainContent != current.ToolchainContent {
		return refusal(Stale, ToolchainContentCause, Changed, "toolchain content"), true
	}
	if rec.DynamicStateStrategy != DynamicStateStrategy {
		// The dynamic-state derivation the record was computed under
		// moved (or predates the field): its verdict semantics are not
		// this engine's — re-measure, never serve. The structural twin
		// of the observation-strategy refusal.
		condition := Unsupported
		if rec.DynamicStateStrategy == "" {
			condition = Missing
		}
		return refusal(Stale, DynamicStateStrategyCause, condition, "dynamic-state strategy"), true
	}
	if rec.InertTestVariantApplicability != (InertTestVariantApplicability{}) && rec.ClosureStrategy != ClosureStrategy {
		return closureStrategyVerdict(rec), true
	}
	return Verdict{}, false
}

// compartmentStale reports whether a recorded test-variant compartment fails
// against the current one. An empty recorded value identifies a recording
// that predates the partition and fails closed; an empty current value is
// never a computed compartment, so it can only refuse
// (REQ-closure-test-variant-identity).
func compartmentStale(recorded, current string) bool {
	return recorded == "" || recorded != current
}

func decideAfterClosure(rec Fingerprint, cl closure.Closure, cur guard.Guards, rt runtimeinput.State, kind Kind, pure PurityAuthority) Verdict {
	return decideAfterClosureObserved(rec, cl, cur, rt, kind, pure, ObservationAuthority{})
}

func decideAfterClosureObserved(rec Fingerprint, cl closure.Closure, cur guard.Guards, rt runtimeinput.State, kind Kind, pure PurityAuthority, observed ObservationAuthority) Verdict {
	if verdict, failed := decideKnownGuards(rec, cur, rt, kind); failed {
		return verdict
	}
	if rec.ToolchainContent == "" || cl.ToolchainContent == "" {
		condition := Unavailable
		if rec.ToolchainContent == "" {
			condition = Missing
		}
		return refusal(Unverifiable, ToolchainContentCause, condition, "toolchain content evidence unavailable")
	}
	// An external-state declaration withholds reuse whenever the guards hold:
	// unverifiability by the author's word, immune to purity overrides and
	// observation evidence alike (REQ-external-directive,
	// REQ-external-precedence). A failing guard above still reported stale —
	// externality never masks guard information.
	if cl.External {
		return refusal(Unverifiable, ExternalDirectiveCause, Refused, "external directive")
	}
	accepted := AcceptedAuthority{GuardAgreement: true, RuntimeInputs: rec.RuntimeInputs != ""}
	answer := func(verdict Verdict) Verdict {
		if verdict.Status == Valid {
			accepted.Applicability = rec.InertTestVariantApplicability
		}
		verdict.Ground.Accepted = accepted
		return verdict
	}
	// Guards hold. Absent a purity override, an unhashable observed input or an
	// unverifiable closure dependence makes validity unprovable (REQ-fresh-sound).
	if !pure.accepted() {
		if rec.RuntimeInputs != "" && rt.Unverifiable {
			return answer(refusal(Unverifiable, RuntimeInputsCause, Refused, reasonOr(rt.Reason, "runtime inputs")))
		}
		if cl.Unverifiable {
			// Completed observation evidence substitutes for
			// unverifiable I/O dependence, never for the
			// shared-dynamic-state downgrade: process-shared state
			// sits outside every observation bracket — a prior
			// subject's in-process write is not an input the bracket
			// can see (REQ-purity-observation-separation,
			// REQ-closure-shared-dynamic-state).
			if observed.accepted() && rec.RuntimeInputs != "" && cl.Refusal != closure.SharedDynamicStateRefusal {
				accepted.Observation = observed
				return answer(Verdict{Status: Valid})
			}
			cause := ClosureDependenceCause
			switch cl.Refusal {
			case closure.OpenWorldRefusal:
				cause = OpenWorldCause
			case closure.SharedDynamicStateRefusal:
				cause = SharedDynamicStateCause
			case closure.AmbiguousSubjectRefusal:
				cause = AmbiguousSubjectCause
			}
			verdict := refusal(Unverifiable, cause, Refused, reasonOr(cl.Reason, "external dependence"))
			if cause == SharedDynamicStateCause {
				verdict.Ground.Cause.Culprit = Subject{
					Package: cl.Culprit.Package,
					Symbol:  cl.Culprit.Symbol,
				}
			}
			return answer(verdict)
		}
	} else if cl.Unverifiable || (rec.RuntimeInputs != "" && rt.Unverifiable) {
		accepted.Purity = pure
	}
	return answer(Verdict{Status: Valid})
}

func decideKnownGuards(rec Fingerprint, cur guard.Guards, rt runtimeinput.State, kind Kind) (Verdict, bool) {
	if verdict, failed := runtimeInputVerdict(rec, rt); failed {
		return verdict, true
	}
	// Environment guards under the kind policy.
	if mismatch := guard.CompareFacts(rec.Guards, cur, kind); mismatch.Axis != guard.NoAxis {
		return guardVerdict(mismatch), true
	}
	return Verdict{}, false
}

func runtimeInputVerdict(rec Fingerprint, rt runtimeinput.State) (Verdict, bool) {
	// A recorded runtime digest without its manifest is a corrupted recording, not
	// an absence assertion: the digest proves the guard applied, and the missing
	// manifest makes it unevaluable — Stale, never valid (REQ-guard-completeness).
	if rec.RuntimeInputs == "" && rec.RuntimeDigest != "" {
		return refusal(Stale, RuntimeInputsCause, Missing, "runtimeinputs"), true
	}
	// Runtime-input guard, when the recording carries a manifest.
	if rec.RuntimeInputs != "" {
		if rt.BracketMoved {
			return refusal(Stale, RuntimeInputsCause, Changed, reasonOr(rt.Reason, "runtimeinputs")), true
		}
		if !rt.OK {
			return refusal(Stale, RuntimeInputsCause, Unavailable, "runtimeinputs"), true
		}
		if rec.RuntimeDigest == "" {
			return refusal(Stale, RuntimeInputsCause, Missing, "runtimeinputs"), true
		}
		if rec.RuntimeDigest != rt.Digest {
			return refusal(Stale, RuntimeInputsCause, Changed, "runtimeinputs"), true
		}
	}
	return Verdict{}, false
}

func reasonOr(reason, fallback string) string {
	if reason == "" {
		return fallback
	}
	return reason
}
