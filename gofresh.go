// Package gofresh decides whether a cached result about a Go symbol is still
// trustworthy for the current source tree, or must be recomputed. It fingerprints
// the source a subject depends on and the environment that produced the result
// (closure, guard, runtimeinput), and reports a verdict by comparing a stored
// fingerprint against the current one (spec overview.md). It never runs the symbol
// and never owns the result store: it answers "is this still fresh?" and leaves
// measuring and storing to the caller. Operations use a shared maximal
// package closure so multi-subject checks avoid per-subject whole-program
// analysis; whole-program reachability runs only for the caller-selected
// observability proof.
package gofresh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/gofresh/internal/buildflags"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/processenv"
	"github.com/greatliontech/gofresh/runtimeinput"
)

// Kind classifies a cached result for guard selection (REQ-fresh-guard-set): a
// CodeResult (a test verdict, a mutation kill) is checked under the code guards
// only; a Measurement (a benchmark) also under the measurement guards.
type Kind = guard.Kind

const (
	CodeResult  = guard.CodeResult
	Measurement = guard.Measurement
)

// TestVariantLedger and its element types are the declaration-level read
// surface over a package's test-variant compartment, served by
// View.TestVariantLedger (REQ-closure-test-variant-compartment).
type (
	TestVariantLedger            = closure.TestVariantLedger
	TestVariantDeclaration       = closure.TestVariantDeclaration
	TestVariantFileHeader        = closure.TestVariantFileHeader
	TestVariantDelta             = closure.TestVariantDelta
	TestVariantDeclarationChange = closure.TestVariantDeclarationChange
	TestVariantHeaderChange      = closure.TestVariantHeaderChange
)

// DiffTestVariantLedgers classifies the delta between a recorded and a current
// compartment ledger; TestVariantDelta.Inert carries the one Go-semantics
// judgment gofresh renders over it (REQ-closure-test-variant-compartment).
func DiffTestVariantLedgers(before, after TestVariantLedger) TestVariantDelta {
	return closure.DiffTestVariantLedgers(before, after)
}

// Subject names the symbol whose freshness is tracked — a package import path and a
// symbol within it, either a function name or a "Type.Method" method reference.
type Subject struct {
	Package string
	Symbol  string
}

// SetMemoRoot redirects gofresh's persistent memo store - one knob
// covering every memo class (effect scans, observability proofs,
// dynamic-state facts). Empty restores the user-cache default and
// re-enables a disabled store. The store is a cache, never a record:
// no knob position changes a verdict, only what is recomputed. Set at
// process start, before any Engine runs.
func SetMemoRoot(dir string) { closure.SetMemoRoot(dir) }

// DisableMemos turns memo persistence off process-wide, for hermetic
// environments that forbid user-cache writes.
func DisableMemos() { closure.DisableMemos() }

// DynamicStateStrategy identifies the shared-dynamic-state fact derivation
// whose per-package facts the persistent memo serves for version-pinned
// packages (REQ-closure-dynamic-state-memo). Changing fact semantics bumps
// this version like any other strategy change. @26 adds the chained
// fmt.Errorf audited construction (conditional object-closed edges,
// break-propagated at composition), the constant-valued audited
// construction (a boxed basic-kind value carries no mutable reach; the
// syscall.Errno sentinel shape), and the attestation-gated audited
// mapping set discharge (golang.org/x/sys/unix.mapper). @27 makes the
// address of a composite literal capture the fresh object alone (its
// element references stay escapes), admits any static reflect.Type
// value as an audited construction (the interface is sealed by
// unexported methods, every referent runtime-canonical), and extends
// the object-closed reference chain across packages (the re-export
// idiom), an undeclared referent refusing fail-closed. @28 adds the
// //gofresh:single-subject variable directive (author-declared
// subject-own state, discharged only under the caller's attestation,
// mutable-local packages only — the vouch boundary's inverse) and the
// audited memoization set (gopkg.in/yaml.v3.structMap: content-
// invariant derivation, admitted without the attestation). @29 scopes
// the shared-dynamic-state judgment per subject under the attestation:
// a culprit none of whose marking sites the subject's rooted flow can
// execute (attributed-RTA-proven, fail-closed on open-world widening
// and on every unattributed mark) is init-determined state covered by
// the closure hash, and the downgrade lifts for that subject alone.
// @30 adds the generated-proto descriptor-cluster discharge
// (protoc-generated files' variables under the attestation, the
// directive's two-leg trust model) and, at the effect-scan floor, the
// audited linkname-target set (audited-only linkname files drop
// exactly the opaque-linkage effect). @31 adds the pooling set's
// content-proven discharge: an unexported package-level sync.Pool
// whose declaration alone could ever type its contents — a New
// function literal returning one identical concrete
// dynamic-carrier-free type, every other appearance exactly a Get or
// Put receiver, every admitted Put argument statically that type —
// is discharged in any execution model, the engine's own verdict
// (no attestation, no evidence record); every non-conforming shape
// keeps the attestation requirement. @32 retires the audited mapping
// set's attestation requirement on the deepened source audit (callable
// fields written only in the declarations, the raw *Ptr field reads
// included; last-byte-keyed data-only bookkeeping, cross-subject
// entries disjoint while their mappings live, the raw-pointer paths'
// stale-entry residue grounded on the syscalls' own observability
// refusal): the discharge is the engine's own verdict in any
// execution model — the memoization set's class, no evidence record —
// exactly for the audited x/sys versions (v0.8.0-v0.47.0 as
// enumerated at the discharge), an unaudited version refusing
// fail-closed. @33 extends the reachability scoping two ways: nested
// function literals' and go statements' marks attribute to their
// enclosing named declaration as literal-borne sites — never
// init-discharged, and foreclosed whenever init flow reaches the
// encloser ("prog" references failing closed), since executing a
// literal requires its encloser to have produced it — and the
// unattested execution model gains the BINARY-scoped judgment: a
// culprit no harness root (Test, Benchmark, Fuzz, Example of both
// test variants, each with its TestMain flow) can reach post-init is
// init-determined for every subject of that binary, sibling subjects
// being roots of the same binary; gated by the caller's
// package-process attestation (WithPackageProcessExecution — every
// measured process is the subject package's own test binary), its
// load-bearing discharges attestation-borne on the evidence
// (PackageProcessDischarges), fail-closed on ambiguous harness roots,
// open-world widenings, and unattributed marks.
const DynamicStateStrategy = "gofresh/dynamic-state@33"

// ObservationRTA identifies the caller-selected declaration-RTA observability
// proof. A standing coupling rides this surface: the audited mapping
// set's shared-dynamic-state discharge (closure.md) is grounded in the
// mapping syscalls keeping their fail-closed classification at the
// observability tiers — admitting mmap/munmap at the symbol tier
// (the way @25 admitted sync.Pool) voids that ground and must land
// with the mapping set re-derived.
// The version pins the engine's interpretation: any admission or
// classification change bumps it, so persistently memoized analyses and
// recorded proofs from the prior interpretation refuse instead of serving
// under semantics they were not computed by. Caller-vouched vocabulary is
// the one exception: a new opt-in declaration class (exclusions,
// static-input roots) leaves every undeclared run byte-identical and
// rides no bump — @7 admitted the testing
// harness's failure/logging channel as an audited harness fact instead
// of descending into harness internals; @8 extends the admission to
// harness-only interface dispatch — an invoke no longer widens the
// subject world when its RTA-enumerated target set is entirely audited
// harness methods AND its operand's provenance is closed under the
// subject's own flow (shared mutable state refuses) — and, for
// packages without a user TestMain, stops pre-blocking the whole
// package on the maximal scan's receiver-escape rejection, so
// testing.TB-taking helpers can earn proofs; @9 makes the refusal
// diagnostic causal-first — the proof names the highest-ranked
// blocking effect under the shared cause-preference order (structural
// findings and mutations before generic reads before ambient
// classifications) instead of the projection's first blocking entry;
// @10 widens user test-main flow on any dispatch whose operand is not
// locally closed (the one startup flow that can run a test-planted
// value; interface invokes and computed calls alike) and fully lifts
// the receiver-escape package backstop it replaces; @11 revises the
// runtime-observation interpretation: directory objects in path and
// bracket digests contribute membership and mode instead of full stat
// (their own size and mtime observe nothing in the admitted set and
// only count member churn), and reads inside a caller-declared
// scratch namespace proven absent at both bracket endpoints are
// admitted recordless — digests and recorded manifests from the prior
// interpretation compare unequal and re-measure rather than serve;
// @12 admits fmt's writer-first print family (Fprint, Fprintf,
// Fprintln) when the writer operand provably pins an audited in-memory
// sink — *bytes.Buffer or *strings.Builder — under the closed-value
// walk the dispatch admissions use (subject-attributed parameter
// crossing included; startup flow judges locally constructed writers
// only): a proven call is Sprint-equivalent value computation at every
// tier, and the maximal scan's package-level Fprint finding narrows to
// a diagnostic so the writer-sensitive tiers decide; an unproven
// writer keeps the formatted-output classification; @13 closes a
// non-generic dynamic-carrying subject by whole-view caller enumeration
// exactly as bounded generics close by instantiation: when every
// reference to the subject is a direct static call whose every
// dynamic-position argument closes in the calling function's own frame,
// the sites' closed function values and materialized concrete types
// seed the walk (dispatch candidates and runtime types under the
// subject's mask) and the subject analyzes closed — caller-passed
// closures become analyzed view content whose effects and edits are the
// subject's own; zero references, any non-call reference, any unclosed
// argument, or harness-dispatched reach keeps the open world; @14
// admits the audited synchronization set at the symbol tier - the
// mutex types (sync.Mutex, sync.RWMutex) and their lock operations no
// longer classify as unaudited standard operations, and lock state is
// receiver-neutral in the shared-dynamic-state judgment - lock state
// cannot change dispatch, and every other sync surface keeps its
// classification; @15 admits the audited runtime-type set - reflect.Type
// and reflect.TypeOf (and, at the SSA tiers, any reflect symbol the
// bare-name match reaches, notably the deterministic-pure
// (reflect.Value).Type) no longer classify as unaudited standard
// operations, while chained reflect results keep their own
// classifications; @16 widens the audited-pure set with math/big's
// value constructors (NewInt, NewFloat, NewRat - software arithmetic,
// no CPU dispatch), time.Date (calendar arithmetic; the ambient
// timezone channel stays flagged at the Location globals and
// constructors), reflect.DeepEqual (a structural comparator invoking
// nothing), and execution-free type and constant references
// (fmt.Stringer, time.Time, time.Month and its constants, math/big's
// Int, Float, and Rat - each declares or denotes and executes
// nothing, pure same-named value methods admitted with them); @17
// admits the harness subtest drivers (*testing.T).Run and
// (*testing.B).Run as admitted harness facts - receiver-discriminated,
// (*M).Run and (*F).Fuzz keep their classifications - with the driver
// bodies cut from the walk exactly as the logging channel's, and the
// package-scan testing.Fuzz finding narrowed to a diagnostic so one
// fuzz declaration no longer blocks every sibling subject; @18 moves
// user test-main flow into subject-time observation - the test log
// installs before the user test main runs, so its reads are bracketed
// observation inputs classified per effect with the subject tier's
// admissions, its unclosed dispatches still widen, and the canonical
// os.Exit epilogue is admitted as harness protocol; @19 audits
// standard flag REGISTRATION as a process-local registry mutation in
// startup and test-main flow, paired with a program-wide sink
// judgment: registered storage traces to package-level variables
// whose later references refuse in subject and test-main flow, an
// untraceable sink blocks the whole program, and the callback
// families keep the audited-pure exclusion outright; @20 audits the
// property-testing harness (pgregory.net/rapid, version-gated) as
// harness surface - bodies cut from the walks and the package scan
// with an admitted harness fact keeping the closure verdict
// unverifiable-by-hash, the property callback walked as subject flow,
// and every value crossing the harness boundary judged at a per-flow
// gate (subject-closed, handed-in handle, gated call result, or
// judged variadic); @21 names the call edge an open-world refusal
// widens on - the enclosing function and the interface method a
// unresolved invoke dispatches, or the value a computed call calls -
// so the reason points at the specific dispatch instead of the bare
// shape; @22 corrects the computed-call naming to the reachable
// identities - a parameter, or a load from a named package-level
// variable - where @21's arms matched SSA nodes that never reach the
// widen path and left the package-variable dispatch unnamed; @23
// generalizes the harness-dispatch admission to subject-determined
// dispatch - an unresolved invoke no longer widens when its operand's
// dynamic types derive wholly from subject-attributed flow and every
// enumerated target is an audited harness method or analyzed indexed
// content, whose effects then classify on their own terms; @24 narrows
// an enumeration-closed subject's walk to its pinned operand set - an
// init-parented anonymous closure of colliding signature outside the
// enumerated values no longer drags initializer content into the
// subject's scan (a subject-closed operand can hold an init-planted
// value only through a shared-state load the closed-value walk
// refuses); @25 admits the audited pooling set at the symbol tier -
// sync.Pool and its Get and Put operations no longer classify as
// unaudited standard operations (they touch only process memory fed by
// the analyzed program - no external input channel whatever the
// execution schedule), while in the shared-dynamic-state judgment a Get
// or Put call on a package-level pool carrier discharges only under the
// caller's single-subject-process attestation
// (WithSingleSubjectExecution) - there every in-process Put site lies
// in the subject's own rooted flow - the values passed and produced
// keeping their own pricing and every other pool use its
// classification.
const ObservationRTA = "gofresh/observation-rta@25"

// ObservationProof is versioned per-subject evidence that every reachable external
// effect is representable by the recognized completed observation stream.
type ObservationProof struct {
	Strategy   string
	Subject    Subject
	Observable bool
	Reason     string
	Evidence   string
}

// Fingerprint is the recorded evidence a verdict is computed from (data only, no
// wire format — REQ-fresh-fingerprint-data): the subject's maximal source-closure
// hash, its package's test-variant compartment hash, optional
// observability evidence, guard values, attributable
// observation and purity assertions, result kind, and the caller's runtime-input manifest and digest evidence.
// The caller serializes and stores it alongside its result, and pins any further
// domain facts of its own (REQ-fresh-caller-pins).
type Fingerprint struct {
	MaximalClosure string
	// TestVariantClosure is the subject package's test-variant compartment:
	// 32 hex over the package's own test-only files, which the maximal
	// closure excludes. A sibling test edit moves only this compartment, so
	// a consumer validating test-binary evidence can tell "a sibling test
	// moved" (stale with reason "test variants") from any other drift. A
	// package with no test files records the stable empty-set identity
	// (closure.EmptyTestVariantClosure); an empty value identifies a
	// recording that predates the partition and fails closed to stale
	// (REQ-closure-test-variant-compartment).
	TestVariantClosure   string
	ObservationAssertion string
	ObservationProof     ObservationProof
	Guards               guard.Guards
	PurityAssertion      string // attributable assertion used to override unverifiability; empty means none
	// DynamicStateVouches names the caller vouches that discharged
	// shared-dynamic-state culprits reachable from this subject at capture:
	// sorted canonical "<import path>.<Variable>" identities, comma-joined.
	// Empty means no vouch was load-bearing. Recorded for audit — the
	// acceptance is visible in the evidence, never silent (REQ-vouch-recorded);
	// validity needs no comparison over it, because a withdrawn vouch
	// resurfaces the culprit in the current derivation and the verdict
	// refuses on its own.
	DynamicStateVouches string
	// SingleSubjectDischarges names the package-level variables whose
	// shared-dynamic-state discharge rested on the caller's
	// single-subject-process attestation (WithSingleSubjectExecution)
	// and is reachable from this subject at capture — the audited
	// pooling set's sync.Pool carriers and the single-subject
	// directive's variables alike: sorted canonical
	// "<import path>.<Variable>" identities, comma-joined. Empty means
	// the attestation was not load-bearing for this subject (or not
	// given). Recorded for audit exactly as a vouch discharge is — the
	// acceptance is visible in the evidence, never silent
	// (REQ-vouch-recorded); validity needs no comparison over it, because
	// a session without the attestation re-marks the variable in the
	// current derivation and the verdict refuses on its own.
	SingleSubjectDischarges string
	// PackageProcessDischarges names the package-level variables whose
	// shared-dynamic-state downgrade the package-process attestation's
	// binary-scoped reachability judgment discharged for this subject —
	// canonical (comma-joined, sorted), empty when none. Attestation-
	// borne acceptances exactly as SingleSubjectDischarges
	// (REQ-closure-shared-dynamic-state).
	PackageProcessDischarges string
	RuntimeInputs            string // encoded manifest; empty only when the caller supplies no observation manifest
	RuntimeDigest            string // digest of the manifest at capture
	ResultKind               Kind   // guard policy captured with this recording; zero is invalid
}

// Status is a verdict's outcome.
type Status string

const (
	Valid        Status = "valid"
	Stale        Status = "stale"
	Unverifiable Status = "unverifiable"
)

// Verdict is the freshness answer for one subject's fingerprint. Reason names the
// first failing guard for Stale, or the unverifiable dependence for Unverifiable.
type Verdict struct {
	Status Status
	Reason string
}

// Engine is immutable analysis configuration. Source, guards, purity directives,
// and derived analysis state live in an explicit View and never cross view
// generations (REQ-fresh-coherent-view); within one generation, sibling views
// derived from a parent share its recorded facts by contract.
type Engine struct {
	assumePure  func(Subject) bool
	buildFlags  []string
	buildInputs []string
	dir         string
	env         []string
	envSet      bool
	// producerEnv, when declared, is the producer processes' environment:
	// runtime-input revalidation computes environment values from it
	// instead of env, so checks stay coherent with recorded evidence when
	// the two environments diverge (WithProducerEnv).
	producerEnv        []string
	producerEnvSet     bool
	analysisBudget     time.Duration
	progress           func(Progress)
	deferredCheckClose bool
	// dynamicStateVouches is the caller's vouch set: canonical
	// "<import path>.<Variable>" identities of version-pinned dependency
	// variables the caller accepts as stable after initialization
	// (REQ-vouch-input). Empty means no vouches.
	dynamicStateVouches map[string]bool
	// singleSubjectExecution is the caller's attestation that every
	// subject is measured in a process of its own
	// (WithSingleSubjectExecution); it arms the audited pooling set's
	// shared-dynamic-state discharge (REQ-closure-shared-dynamic-state).
	singleSubjectExecution  bool
	packageProcessExecution bool
}

// viewTestHooks is the package's one test-observation surface: each field
// observes an internal step tests prove taken, skipped, or counted; nil
// disables. Root tests run sequentially, so package scope suffices.
var viewTestHooks struct {
	// observe observes every source/guard/purity observation pass — tests
	// pin how many observations an operation performs.
	observe func()
	// snapshot observes the env snapshot each precise-analysis bracket
	// derives its configuration from — tests pin that the bracket reuses
	// the view's construction snapshot instead of re-reading go env.
	snapshot func(*gotool.EnvSnapshot)
	// dynamicStateMissLoad observes the batched typed load of
	// version-pinned packages whose dynamic-state facts missed the memo.
	dynamicStateMissLoad func(patterns []string)
	// factScope observes the derived dynamic-state fact scope — tests
	// pin the execution-model markers that keep option-on and
	// option-off sessions from serving each other's facts.
	factScope func(scope string)
}

// Option configures an Engine.
type Option func(*Engine)

// WithBuildFlags supplies complete go-command flags used by the producing build,
// such as -tags=integration, -race, or -pgo=profile. The flags select every source
// load and are folded into the build-configuration guard, so the closure and guard
// describe the same binary (REQ-guard-buildconfig).
func WithBuildFlags(flags ...string) Option {
	return func(e *Engine) { e.buildFlags = append([]string(nil), flags...) }
}

// WithBuildInputs supplies opaque build evidence that cannot itself configure a Go
// source load, such as a PGO profile's content digest. It is folded into the
// build-configuration guard (REQ-guard-buildconfig). Go-command flags belong in
// WithBuildFlags; presenting one here is refused when New applies the options.
func WithBuildInputs(inputs ...string) Option {
	return func(e *Engine) { e.buildInputs = append([]string(nil), inputs...) }
}

// Progress reports the start of one long-running analysis step: Phase is
// "observe" for a view observation pass, "runtime" for each runtime-input
// observation pass (a check's window performs two), "load" for a package
// program load, or "prove" for a package's observability
// batch; Package names the package for the per-package phases. Events are
// emitted before the step runs, carry no completion signal, and are
// diagnostic keep-alive data, not contract.
type Progress struct {
	Phase   string
	Package string
}

// WithProgress supplies a callback invoked synchronously at the start of each
// long-running analysis step. The callback must be fast, must not call back
// into the engine, and must be safe for concurrent invocation — one engine can
// serve concurrent operations. A panicking callback unwinds through the
// operation that emitted the event.
func WithProgress(f func(Progress)) Option {
	return func(e *Engine) { e.progress = f }
}

// WithAnalysisBudget bounds each precise-analysis phase — observability
// proving, whether selected at capture or re-established at
// validation — to d of wall clock. A
// batched operation's shared analysis draws on one budget; each operation
// derives a fresh one. An exhausted budget yields unavailable evidence for the
// affected subjects — captures record the unavailable proof, validation
// reports ErrAnalysisUnavailable — and it never cancels
// the operation itself, which remains governed solely by the caller's context
// (REQ-fresh-context). Zero means unbounded.
func WithAnalysisBudget(d time.Duration) Option {
	return func(e *Engine) { e.analysisBudget = d }
}

// WithAssumePure supplies the caller's purity predicate: a subject for which it
// returns true has all of its unverifiability suppressed (REQ-purity-input,
// REQ-purity-override). Source directives are discovered inside each View from the
// same selected source as closure analysis (REQ-purity-directive).
func WithAssumePure(pred func(Subject) bool) Option {
	return func(e *Engine) {
		if pred != nil {
			e.assumePure = pred
		}
	}
}

// WithDynamicStateVouches supplies the caller's dynamic-state vouch set:
// each identity is the canonical "<import path>.<Variable>" of a
// package-level variable in a version-pinned dependency that the caller
// accepts as stable after initialization, at the caller's responsibility
// (REQ-vouch-input). A vouched variable is exempt from the
// shared-dynamic-state downgrade (REQ-vouch-discharge); the vouches that
// actually discharged culprits reachable from a subject are recorded on
// its fingerprint (REQ-vouch-recorded). A vouch naming a variable in
// mutable-local source confers nothing — code the caller can edit is
// fixed, not vouched (REQ-vouch-dependency-boundary).
func WithDynamicStateVouches(identities ...string) Option {
	return func(e *Engine) {
		if len(identities) == 0 {
			return
		}
		if e.dynamicStateVouches == nil {
			e.dynamicStateVouches = make(map[string]bool, len(identities))
		}
		for _, identity := range identities {
			if identity != "" {
				e.dynamicStateVouches[identity] = true
			}
		}
	}
}

// WithSingleSubjectExecution attests the caller's execution model: every
// subject is measured in a process of its own, so no sibling subject's
// execution precedes a subject in the same process. The attestation arms
// the audited pooling set's shared-dynamic-state discharge — under it
// every in-process sync.Pool Put site lies in the subject's own rooted
// flow, so pool contents are a function of the analyzed source and the
// subject alone (REQ-closure-shared-dynamic-state). Without the
// attestation, sibling subjects sharing a process can communicate
// through pool contents (a prior subject's Put plants a value a later
// subject's Get dispatches on), so pool Get/Put on a package-level
// carrier keeps the fail-closed shared-dynamic-state judgment. (The
// audited mapping set — golang.org/x/sys/unix's mapper bookkeeping —
// discharges on its own deepened audit in any execution model and
// needs no attestation.) The
// attestation is the caller's responsibility; it changes what the
// derived dynamic-state facts record, so it is part of the persisted
// fact identity and option-on and option-off sessions never serve each
// other's facts.
func WithSingleSubjectExecution() Option {
	return func(e *Engine) { e.singleSubjectExecution = true }
}

// WithPackageProcessExecution attests the package-process execution
// model: every process that runs a measured subject is the subject
// package's OWN test binary — `go test` of that package, under any
// subject schedule. Under it the shared-dynamic-state judgment gains
// the binary-scoped reachability discharge: a sibling subject in the
// process is itself one of the binary's harness roots, so a culprit no
// harness root's post-initialization flow can reach is init-determined
// for every subject of the binary (REQ-closure-shared-dynamic-state).
// The attestation is weaker than the single-subject one — it bounds
// WHICH binary runs, not how many subjects share it — and the
// single-subject judgment takes precedence where both are set (each
// is sound under its own model; neither dominates the other's
// discharges). A package with no harness roots discharges vacuously —
// nothing executes past initialization in its own test binary — so
// setting the option for subjects actually measured through ANOTHER
// package's binary is the caller's soundness bug, and its cost is
// maximal. It is the
// caller's responsibility, it is part of the persisted fact identity
// (option-on and option-off sessions never serve each other's facts),
// and its load-bearing discharges ride the evidence
// (PackageProcessDischarges) exactly as the single-subject ones do. A
// consumer that runs subjects through any OTHER binary — another
// package's tests importing the subject's package — must not set it.
func WithPackageProcessExecution() Option {
	return func(e *Engine) { e.packageProcessExecution = true }
}

// WithDeferredCheckClose defers each check's closing base observation —
// the re-observation proving the tree stable across the check's
// runtime-input reads — to the view's validation: the validation's one
// comparison observation closes every deferred interval at once, and a
// change persisting to it refuses there. Verdicts return provisional
// under this option: the caller MUST consume them only under a later
// successful validation of the same view — any validation outcome short
// of success (refusal, a failed observation, unavailable analysis)
// discards every served verdict — the producer-view discipline
// (REQ-fresh-producer-view). The
// change-and-restore residual widens from each check's own close to the
// validation, carried by the caller's execution-span exclusion. For a
// pipeline running many checks against one quiescent view, the deferral
// collapses per-check base observations into validation's single
// comparison observation (REQ-fresh-coherent-view's deferred close).
func WithDeferredCheckClose() Option {
	return func(e *Engine) { e.deferredCheckClose = true }
}

// WithDir roots the engine at dir: every package load and go invocation
// resolves there, so a caller can fingerprint a tree it does not run inside.
// The default is the process working directory captured when New returns.
func WithDir(dir string) Option {
	return func(e *Engine) { e.dir = dir }
}

// WithEnv supplies the complete process environment used by every package load,
// Go command, source analysis, and guard observation. It has exec.Cmd.Env
// semantics rather than patch semantics. New rejects malformed or duplicate
// entries and owns a normalized copy; later caller mutation has no effect. A
// caller attaching runtime-input evidence under this option uses runtimeinput's
// Env-suffixed constructors with the same complete environment.
func WithEnv(env ...string) Option {
	owned := append([]string(nil), env...)
	return func(e *Engine) {
		e.env = append([]string(nil), owned...)
		e.envSet = true
	}
}

// WithProducerEnv supplies the complete process environment the
// engine's producer processes actually run under, when it differs from
// the analysis environment WithEnv configures — a consumer injecting
// resource bounds (a GOMAXPROCS cap, say) into the processes it spawns
// without throttling the engine's own loads. Revalidation of
// runtime-input evidence — the current checks a view performs against
// recorded observations, moved-input naming included — computes
// environment values from this environment, keeping checks coherent
// with what the producing processes recorded: the runtime-inputs
// contract requires every environment-aware current check to use the
// same complete process environment as the producing process, and an
// analysis-env stand-in silently violates it the moment the two
// diverge. Loads, Go commands, source analysis, and guard observation
// keep using WithEnv's environment. Unset, WithEnv governs both. The
// two environments may differ only in keys the closure, guard, and
// snapshot evidence does not consume — New refuses a producer env
// whose Go build identity (GOROOT, GOMODCACHE, GOCACHE, GOFLAGS,
// GOOS, GOARCH, GOEXPERIMENT, GOTOOLCHAIN, GOWORK, GOPATH,
// CGO_ENABLED) disagrees with the analysis env, because closure and
// guard digests would then describe artifacts the producer processes
// never ran against and stale evidence could serve silently. New also
// refuses a declared-but-empty producer env. WithEnv's normalization
// and ownership semantics apply.
func WithProducerEnv(env ...string) Option {
	owned := append([]string(nil), env...)
	return func(e *Engine) {
		e.producerEnv = append([]string(nil), owned...)
		e.producerEnvSet = true
	}
}

// evidenceEnv is the environment runtime-input revalidation computes
// values from: the producer processes' environment when the caller
// declared one, else the analysis environment — the runtime-inputs
// contract's same-environment-as-the-producing-process rule.
func (e *Engine) evidenceEnv() []string {
	if e.producerEnvSet {
		return e.producerEnv
	}
	return e.env
}

// buildIdentityDivergence reports the first Go build-identity key whose
// value differs between the analysis and producer environments, with
// both values; empty key means agreement. The closure, guard, and
// snapshot evidence consumes these keys from the analysis env, so a
// producer env disagreeing on one would let stale evidence serve
// silently against artifacts the producer never ran with.
func buildIdentityDivergence(analysis, producer []string) (key, analysisValue, producerValue string) {
	for _, k := range []string{"GOROOT", "GOMODCACHE", "GOCACHE", "GOFLAGS", "GOOS", "GOARCH", "GOEXPERIMENT", "GOTOOLCHAIN", "GOWORK", "GOPATH", "CGO_ENABLED"} {
		a, producerV := envValue(analysis, k), envValue(producer, k)
		if a != producerV {
			return k, a, producerV
		}
	}
	return "", "", ""
}

// envValue returns key's value in a normalized environment, empty when
// absent — absence and an explicitly empty value deliberately compare
// equal here: both make the go tool fall back to the same default.
func envValue(env []string, key string) string {
	prefix := key + "="
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return entry[len(prefix):]
		}
	}
	return ""
}

// New builds an Engine.
func New(opts ...Option) (*Engine, error) {
	e := &Engine{assumePure: func(Subject) bool { return false }}
	for _, o := range opts {
		o(e)
	}
	if !e.envSet {
		e.env = os.Environ()
	}
	normalized, err := processenv.Normalize(e.env)
	if err != nil {
		return nil, fmt.Errorf("gofresh: %w", err)
	}
	e.env = normalized
	if _, err := processenv.ForGoPackages(e.env); err != nil {
		return nil, fmt.Errorf("gofresh: %w", err)
	}
	if e.producerEnvSet {
		if len(e.producerEnv) == 0 {
			return nil, errors.New("gofresh: producer env declared empty; a producer process runs under a complete environment")
		}
		normalizedProducer, err := processenv.Normalize(e.producerEnv)
		if err != nil {
			return nil, fmt.Errorf("gofresh: producer env: %w", err)
		}
		e.producerEnv = normalizedProducer
		if key, analysis, producer := buildIdentityDivergence(e.env, e.producerEnv); key != "" {
			return nil, fmt.Errorf("gofresh: producer env %s=%q disagrees with the analysis env's %q: closure and guard evidence would describe artifacts the producer processes never ran against", key, producer, analysis)
		}
	}
	if e.dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("gofresh: resolve working directory: %w", err)
		}
		e.dir = cwd
	}
	root, err := canonicalDir(e.dir)
	if err != nil {
		return nil, fmt.Errorf("gofresh: resolve engine tree: %w", err)
	}
	e.dir = root
	for _, input := range e.buildInputs {
		if strings.HasPrefix(strings.TrimSpace(input), "-") {
			return nil, fmt.Errorf("gofresh: build flag %q passed as opaque input; use WithBuildFlags", input)
		}
	}
	// Engine construction is caller-side setup, not an operation phase; its
	// one-time flag validation runs to completion.
	if err := buildflags.ValidateEnv(context.Background(), e.dir, e.env, e.buildFlags); err != nil {
		return nil, err
	}
	return e, nil
}

func canonicalDir(dir string) (string, error) {
	raw := dir
	if !filepath.IsAbs(raw) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		raw = cwd + string(os.PathSeparator) + raw
	}
	resolved, err := filepath.EvalSymlinks(raw)
	if err != nil {
		return "", err
	}
	originalInfo, err := os.Stat(raw)
	if err != nil {
		return "", err
	}
	resolvedInfo, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if os.SameFile(originalInfo, resolvedInfo) {
		return resolved, nil
	}
	// Preserve kernel path-walk semantics when lexical cleaning across a symlink
	// would identify a different directory (for example, link/..).
	return raw, nil
}

// Capture records the closure hash and code-result guard values for subject, whose code lives
// under moduleDir (the dir `go` resolves the toolchain and build env in). Runtime
// inputs are added by the caller from the run's completion-asserted testlog
// (runtimeinput.FromTestLogEnv), from an incomplete process
// (runtimeinput.IncompleteEnv), by re-admitting a persisted manifest union
// (runtimeinput.AdoptEnv), or by combining several process observations
// (runtimeinput.MergeEnv) under the producer processes' environment —
// WithProducerEnv when declared, else the environment supplied to
// WithEnv; revalidation recomputes under that same environment, so
// ingesting under any other is the incoherent mixing the
// runtime-inputs contract forbids — into the returned Fingerprint's
// RuntimeInputs/RuntimeDigest fields. An observation-free run still attaches the
// non-empty manifest those functions return.
func (e *Engine) Capture(ctx context.Context, subject Subject, moduleDir string) (Fingerprint, error) {
	view, err := e.NewView(ctx, []Subject{subject}, moduleDir)
	if err != nil {
		return Fingerprint{}, err
	}
	return view.Capture(ctx, subject)
}

// CaptureFor records subject with the guards applicable to kind. Measurements must
// use this method so machine and runtime-configuration evidence is captured.
func (e *Engine) CaptureFor(ctx context.Context, subject Subject, moduleDir string, kind Kind) (Fingerprint, error) {
	view, err := e.NewViewFor(ctx, []Subject{subject}, moduleDir, kind)
	if err != nil {
		return Fingerprint{}, err
	}
	return view.Capture(ctx, subject)
}

// Check reports the freshness verdict for a recorded fingerprint against the current
// tree under its recorded result kind. It recomputes the current closure and guards
// (never reconstructing a historical build — REQ-guard-recompute) and, when the
// recording carries a runtime-input manifest, re-hashes it, then decides.
func (e *Engine) Check(ctx context.Context, recorded Fingerprint, subject Subject, moduleDir string) (Verdict, error) {
	if err := validateRecordedKind(recorded); err != nil {
		return Verdict{}, err
	}
	view, err := e.NewViewFor(ctx, []Subject{subject}, moduleDir, recorded.ResultKind)
	if err != nil {
		return Verdict{}, err
	}
	return view.Check(ctx, recorded, subject)
}

// CheckObserved checks a caller-selected observation proof under ctx. It never
// infers observation policy for ordinary Check calls.
func (e *Engine) CheckObserved(ctx context.Context, recorded Fingerprint, subject Subject, moduleDir string) (Verdict, error) {
	if err := validateRecordedKind(recorded); err != nil {
		return Verdict{}, err
	}
	view, err := e.NewViewFor(ctx, []Subject{subject}, moduleDir, recorded.ResultKind)
	if err != nil {
		return Verdict{}, err
	}
	return view.CheckObserved(ctx, recorded, subject)
}

func validKind(kind Kind) bool { return kind == CodeResult || kind == Measurement }

func validateRecordedKind(recorded Fingerprint) error {
	if !validKind(recorded.ResultKind) {
		return fmt.Errorf("gofresh: invalid recorded result kind %d", recorded.ResultKind)
	}
	if recorded.ResultKind == CodeResult && (recorded.Guards.Machine != "" || recorded.Guards.RuntimeConfig != "") {
		return errors.New("gofresh: code-result fingerprint carries measurement guards")
	}
	return nil
}

func (e *Engine) guardInputs() []string {
	inputs := make([]string, 0, len(e.buildFlags)+len(e.buildInputs))
	for _, flag := range e.buildFlags {
		inputs = append(inputs, "flag="+flag)
	}
	for _, input := range e.buildInputs {
		inputs = append(inputs, "input="+input)
	}
	return inputs
}

// decide is the pure verdict function (REQ-fresh-verdict, REQ-fresh-sound): stale on
// the first failing guard; unverifiable when the guards hold but the closure or
// runtime inputs reach an unhashable dependence and no purity override applies;
// valid otherwise. A missing recorded value is a mismatch, never valid
// (REQ-guard-completeness) — except an absent runtime-input manifest, which is the
// caller's assertion that the run observed no runtime inputs
// (REQ-inputs-absent-asserted). commit/dirty are never consulted
// (REQ-fresh-commit-independent).
func decide(rec Fingerprint, cl closure.Closure, cur guard.Guards, rt runtimeinput.State, kind Kind, pure bool) Verdict {
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
// (REQ-closure-test-variant-compartment); a drifted core is stale on the
// closure (REQ-fresh-hierarchical-check). Records surviving the ladder
// proceed to the surface's own guard tiers.
func recordedEvidenceVerdict(rec Fingerprint, current closure.Closure) (Verdict, bool) {
	if rec.MaximalClosure == "" {
		return Verdict{Stale, "closure"}, true
	}
	if rec.MaximalClosure == current.Hash && compartmentStale(rec.TestVariantClosure, current.TestVariants) {
		return Verdict{Stale, "test variants"}, true
	}
	if rec.MaximalClosure != current.Hash {
		return Verdict{Stale, "closure"}, true
	}
	return Verdict{}, false
}

// compartmentStale reports whether a recorded test-variant compartment fails
// against the current one. An empty recorded value identifies a recording
// that predates the partition and fails closed; an empty current value is
// never a computed compartment, so it can only refuse
// (REQ-closure-test-variant-compartment).
func compartmentStale(recorded, current string) bool {
	return recorded == "" || recorded != current
}

func decideAfterClosure(rec Fingerprint, cl closure.Closure, cur guard.Guards, rt runtimeinput.State, kind Kind, pure bool) Verdict {
	return decideAfterClosureObserved(rec, cl, cur, rt, kind, pure, false)
}

func decideAfterClosureObserved(rec Fingerprint, cl closure.Closure, cur guard.Guards, rt runtimeinput.State, kind Kind, pure, observed bool) Verdict {
	if verdict, failed := decideKnownGuards(rec, cur, rt, kind); failed {
		return verdict
	}
	// An external-state declaration withholds reuse whenever the guards hold:
	// unverifiability by the author's word, immune to purity overrides and
	// observation evidence alike (REQ-external-directive,
	// REQ-external-precedence). A failing guard above still reported stale —
	// externality never masks guard information.
	if cl.External {
		return Verdict{Unverifiable, "external directive"}
	}
	// Guards hold. Absent a purity override, an unhashable observed input or an
	// unverifiable closure dependence makes validity unprovable (REQ-fresh-sound).
	if !pure {
		if rec.RuntimeInputs != "" && rt.Unverifiable {
			return Verdict{Unverifiable, reasonOr(rt.Reason, "runtime inputs")}
		}
		if cl.Unverifiable {
			// Completed observation evidence substitutes for
			// unverifiable I/O dependence, never for the
			// shared-dynamic-state downgrade: process-shared state
			// sits outside every observation bracket — a prior
			// subject's in-process write is not an input the bracket
			// can see (REQ-purity-observation-separation,
			// REQ-closure-shared-dynamic-state).
			if observed && rec.RuntimeInputs != "" && !strings.HasPrefix(cl.Reason, sharedDynamicStatePrefix) {
				return Verdict{Valid, ""}
			}
			return Verdict{Unverifiable, reasonOr(cl.Reason, "external dependence")}
		}
	}
	return Verdict{Valid, ""}
}

func decideKnownGuards(rec Fingerprint, cur guard.Guards, rt runtimeinput.State, kind Kind) (Verdict, bool) {
	// A recorded runtime digest without its manifest is a corrupted recording, not
	// an absence assertion: the digest proves the guard applied, and the missing
	// manifest makes it unevaluable — Stale, never valid (REQ-guard-completeness).
	if rec.RuntimeInputs == "" && rec.RuntimeDigest != "" {
		return Verdict{Stale, "runtimeinputs"}, true
	}
	// Runtime-input guard, when the recording carries a manifest.
	if rec.RuntimeInputs != "" {
		if !rt.OK || rec.RuntimeDigest == "" || rec.RuntimeDigest != rt.Digest {
			return Verdict{Stale, "runtimeinputs"}, true
		}
	}
	// Environment guards under the kind policy.
	if mismatch := guard.Compare(rec.Guards, cur, kind); mismatch != "" {
		return Verdict{Stale, mismatch}, true
	}
	return Verdict{}, false
}

func reasonOr(reason, fallback string) string {
	if reason == "" {
		return fallback
	}
	return reason
}

// coherentDir refuses a guards dir that disagrees with the engine's tree
// root: the closure would come from one tree and the environment guards
// from another — an incoherent fingerprint that could serve or stale on the
// wrong tree's facts. Without WithDir, the source root is the process cwd.
func (e *Engine) coherentDir(moduleDir string) error {
	rootDir := e.dir
	if rootDir == "" {
		var err error
		rootDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("gofresh: resolve process tree: %w", err)
		}
	}
	root, err := os.Stat(rootDir)
	if err != nil {
		return fmt.Errorf("gofresh: resolve engine tree %s: %w", rootDir, err)
	}
	module, err := os.Stat(moduleDir)
	if err != nil {
		return fmt.Errorf("gofresh: resolve guards tree %s: %w", moduleDir, err)
	}
	if os.SameFile(root, module) {
		return nil
	}
	return fmt.Errorf("gofresh: engine rooted at %s asked to capture guards in %s; one tree per fingerprint", rootDir, moduleDir)
}
