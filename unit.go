package gofresh

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/greatliontech/gofresh/runtimeinput"
)

// ErrUnitClosed reports admission, submission or closing after the unit started
// its terminal closing transition. A retry needs another unit.
var ErrUnitClosed = errors.New("gofresh: unit is closing or ended")

// ErrUnitIncomplete reports a missing contributor or terminal disposition. A
// missing log never supplies that disposition on the executor's behalf.
var ErrUnitIncomplete = errors.New("gofresh: unit has incomplete contributing executions")

// ErrUnitAborted reports an abort that won before closing committed its final
// state. It grants no final evidence, even if some closing work completed.
var ErrUnitAborted = errors.New("gofresh: unit aborted before closing completed")

// ProcessDescription names the execution before it starts. Capture is the
// executor-owned test-log path; the executor keeps it exclusively assigned to
// this contribution through finalization. A relative path resolves against the
// binding's runtime directory at registration, and the same absolute coordinate
// is returned to the executor and read by closing. It is not supplied at Submit.
// Capture may be omitted when the selected source/assertion evidence needs no
// observation. A supplied capture still contributes ordinary input guards.
type ProcessDescription struct {
	Identity          string
	Capture           string
	BracketPaths      []string
	ExcludedPaths     []string
	ScratchRoot       string
	ScratchNamespaces []runtimeinput.ScratchNamespace
}

// TerminalKind is the executor's actual terminal harness disposition.
type TerminalKind uint8

const (
	// NormalCompletion asserts ordinary harness completion and flush of any capture,
	// including an ordinarily completed failing test, never merely exit code zero.
	NormalCompletion TerminalKind = iota + 1
	// AbnormalCompletion names an incomplete, crashed or killed execution.
	AbnormalCompletion
	// NeverStarted names a registered process which did not execute.
	NeverStarted
)

// Terminal carries a terminal fact, independently of the observation log and
// benchmark/sample success. Reason is required for abnormal and unstarted
// executions and absent for normal completion.
type Terminal struct {
	Kind   TerminalKind
	Reason string
}

// Contribution is a unit-owned execution binding. Its zero value and a handle
// from another unit cannot settle this unit's obligation.
type Contribution struct {
	unit      *producingUnit
	execution *unitExecution
}

// Subjects returns the complete declared subject set of the execution, in
// first-request order. The executor runs this set, not only its cacheable subset.
func (c Contribution) Subjects() []Subject {
	if c.unit == nil || c.execution == nil {
		return nil
	}
	return slices.Clone(c.unit.view.subjects)
}

// Environment returns the exact owned process environment as an independent copy.
func (c Contribution) Environment() []string {
	if c.execution == nil {
		return nil
	}
	return slices.Clone(c.execution.env)
}

// Directory returns the resolved working directory of the prepared execution.
func (c Contribution) Directory() string {
	if c.execution == nil {
		return ""
	}
	return c.unit.view.runtime.dir
}

// Capture returns the test-log path registered before execution.
func (c Contribution) Capture() string {
	if c.execution == nil {
		return ""
	}
	return c.execution.process.Capture
}

type unitPhase uint8

const (
	unitOpen unitPhase = iota
	unitClosing
	unitClosed
	unitFailed
	unitAborted
)

type unitExecution struct {
	process       ProcessDescription
	artifact      string
	inspected     *inspectedArtifact
	env           []string
	frame         runtimeinput.ProducerFrame
	support       runtimeinput.OutcomeSupport
	fingerprints  map[Subject]Fingerprint
	observed      map[Subject]bool
	outcomeReason string
	observation   finalizedProcessObservation
	terminal      Terminal
	ready         bool
	cancel        context.CancelFunc
}

// Unit owns one subject's single contributing package-test process and its
// producing/closing obligations. A second contributor is refused, not silently
// dropped. Independent units share only their snapshot's immutable source facts.
type Unit struct {
	producing *producingUnit
}

// PackageUnit owns one package-test process over its complete selected subject
// set. Its subjects share that process's observation, not another attempt's
// evidence. Isolation retries use separate units; publication grouping remains
// the result owner's responsibility.
type PackageUnit struct {
	producing *producingUnit
}

// producingUnit is the single lifecycle for singleton and package executions.
// The immutable subject set is also the complete roster for process-wide proofs.
type producingUnit struct {
	mu            sync.Mutex
	phase         unitPhase
	snapshot      *Snapshot
	view          *View
	execution     *unitExecution
	closingCancel context.CancelFunc
	identityOnly  bool
}

// Begin creates an independently closing unit under this runtime binding.
func (s *RuntimeBinding) Begin(subject Subject) (*Unit, error) {
	u, err := s.begin([]Subject{subject}, false)
	if err != nil {
		return nil, err
	}
	return &Unit{producing: u}, nil
}

// BeginIdentity selects identity-only input evidence for a diagnostic execution,
// such as an instrumented profile. It deliberately prepares no outcome support;
// ordinary completion cannot promote the resulting evidence to supported form.
func (s *RuntimeBinding) BeginIdentity(subject Subject) (*Unit, error) {
	u, err := s.begin([]Subject{subject}, true)
	if err != nil {
		return nil, err
	}
	return &Unit{producing: u}, nil
}

// BeginPackage creates an independently closing execution for a nonempty set
// of subjects from one package. Duplicates collapse in first-request order.
// Every executed subject, including subjects without a cacheable result, belongs
// in this set. A single-subject execution assertion refuses a larger set.
func (s *RuntimeBinding) BeginPackage(subjects []Subject) (*PackageUnit, error) {
	u, err := s.begin(subjects, false)
	if err != nil {
		return nil, err
	}
	return &PackageUnit{producing: u}, nil
}

func (s *RuntimeBinding) begin(subjects []Subject, identityOnly bool) (*producingUnit, error) {
	v, err := s.newView(subjects)
	if err != nil {
		return nil, err
	}
	if len(v.packages) != 1 {
		return nil, errors.New("gofresh: a producing execution must belong to one package")
	}
	if len(v.subjects) > 1 && v.engine.singleSubjectExecution {
		return nil, errors.New("gofresh: a multi-subject execution contradicts the single-subject assertion")
	}
	return &producingUnit{snapshot: s.snapshot, view: v, identityOnly: identityOnly}, nil
}

// Register prepares the complete producing obligation before execution. Build
// must belong to the same snapshot and package. Expensive preparation holds no
// unit mutex: concurrent close freezes the roster and cancels that preparation.
func (u *Unit) Register(ctx context.Context, build BuildBinding, process ProcessDescription) (Contribution, error) {
	return u.transaction().register(ctx, build, process)
}

// Register prepares all subject obligations before the package process starts.
// One process has one frame and one exclusive capture; a second registration is
// refused. The returned subject set is owned and cannot change preparation.
func (u *PackageUnit) Register(ctx context.Context, build BuildBinding, process ProcessDescription) (Contribution, error) {
	return u.transaction().register(ctx, build, process)
}

func (u *Unit) transaction() *producingUnit {
	if u == nil {
		return nil
	}
	return u.producing
}

func (u *PackageUnit) transaction() *producingUnit {
	if u == nil {
		return nil
	}
	return u.producing
}

func (u *producingUnit) register(ctx context.Context, build BuildBinding, process ProcessDescription) (Contribution, error) {
	if ctx == nil {
		return Contribution{}, errors.New("gofresh: nil registration context")
	}
	if err := ctx.Err(); err != nil {
		return Contribution{}, err
	}
	if u == nil || u.snapshot == nil {
		return Contribution{}, errors.New("gofresh: uninitialized unit")
	}
	if build.snapshot != u.snapshot || build.pkg != u.view.subjects[0].Package || build.identity == "" {
		return Contribution{}, errors.New("gofresh: built artifact belongs to another snapshot or package")
	}
	dir := u.view.runtime.dir
	if process.Capture != "" {
		var err error
		process.Capture, err = rebaseProcessPath(dir, process.Capture)
		if err != nil {
			return Contribution{}, fmt.Errorf("gofresh: capture: %w", err)
		}
	}
	process.BracketPaths, process.ExcludedPaths = slices.Clone(process.BracketPaths), slices.Clone(process.ExcludedPaths)
	process.ScratchNamespaces = slices.Clone(process.ScratchNamespaces)
	for _, namespace := range process.ScratchNamespaces {
		if err := runtimeinput.ValidateScratchNamespace(namespace.Dir, namespace.Pattern); err != nil {
			return Contribution{}, err
		}
	}
	e := u.snapshot.session.engine
	env := u.view.evidenceEnv()
	// The frame owns the process/environment grammar. A zero frame performs
	// that input validation without capturing anything or issuing support.
	if _, err := (runtimeinput.ProducerFrame{}).OutcomeBinding(process.Identity, env); err != nil {
		return Contribution{}, err
	}
	preparing, cancel := context.WithCancel(ctx)
	defer cancel()
	x := &unitExecution{process: process, artifact: build.identity, inspected: build.inspected, env: env, cancel: cancel}
	u.mu.Lock()
	if u.phase != unitOpen {
		u.mu.Unlock()
		return Contribution{}, ErrUnitClosed
	}
	if u.execution != nil {
		u.mu.Unlock()
		return Contribution{}, errors.New("gofresh: this unit already has its one contributor")
	}
	u.execution = x
	u.mu.Unlock()
	frame := runtimeinput.CaptureProducerFrame(preparing, e.evidenceRootFor(e.dir), dir, runtimeinput.FrameOptions{BracketPaths: process.BracketPaths, ExcludedPaths: process.ExcludedPaths})
	var support runtimeinput.OutcomeSupport
	fingerprints, err := u.view.CaptureBatch(preparing)
	observed := make(map[Subject]bool)
	if err == nil && !u.identityOnly {
		// Selection uses the ordinary evidence ladder over this immutable
		// snapshot, not a second set of purity or closure admission rules.
		for _, subject := range u.view.subjects {
			fp := fingerprints[subject]
			if decide(fp, u.view.facts.closure(subject), u.view.guards(), runtimeinput.State{}, u.view.kind, u.view.purityMatches(fp, subject)).Status != Valid {
				observed[subject] = true
			}
		}
	}
	if err == nil && len(observed) != 0 {
		// Even a source-supported or asserted-pure contributor can affect an
		// observing sibling's environment. Preserve the entire process roster
		// in outcome preparation and its closing proof obligations.
		support, err = u.view.PrepareOutcomeSupport(preparing, frame, process.Identity)
		if err == nil {
			var all map[Subject]Fingerprint
			all, err = u.view.CaptureObservedBatch(preparing)
			for subject := range observed {
				fingerprints[subject] = all[subject]
			}
		}
	}
	if err == nil {
		err = x.inspected.validate(preparing)
	}
	if preparing.Err() != nil {
		err = preparing.Err()
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	// Closing cancels the derived preparation context itself. Only cancellation
	// of the original caller context outranks the unit's terminal transition.
	if cause := ctx.Err(); cause != nil {
		if u.phase == unitOpen {
			u.phase = unitFailed
		}
		return Contribution{}, cause
	}
	if u.phase != unitOpen {
		return Contribution{}, ErrUnitClosed
	}
	if err != nil {
		u.phase = unitFailed
		return Contribution{}, err
	}
	binding, err := frame.OutcomeBinding(process.Identity, env)
	if err != nil {
		u.phase = unitFailed
		return Contribution{}, err
	}
	x.frame, x.support, x.fingerprints, x.outcomeReason = frame, support, fingerprints, support.Reason(binding)
	x.observed = observed
	if u.identityOnly {
		x.outcomeReason = "identity-only execution selected"
	} else if len(observed) == 0 {
		x.outcomeReason = "source/assertion evidence selected; observation support not required"
	}
	x.ready = true
	return Contribution{unit: u, execution: x}, nil
}

// Submit supplies the registered execution's one terminal disposition. No log,
// frame, environment or support can be substituted at this boundary.
func (u *Unit) Submit(c Contribution, terminal Terminal) error {
	return u.transaction().submit(c, terminal)
}

// Submit settles this package process with its actual harness disposition.
// An ordinary failing test can complete normally; result success remains the
// consumer's judgment. A handle from another attempt is always refused.
func (u *PackageUnit) Submit(c Contribution, terminal Terminal) error {
	return u.transaction().submit(c, terminal)
}

func (u *producingUnit) submit(c Contribution, terminal Terminal) error {
	if u == nil || u.snapshot == nil {
		return errors.New("gofresh: uninitialized unit")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.phase != unitOpen {
		return ErrUnitClosed
	}
	if c.unit != u || c.execution == nil || c.execution != u.execution || !c.execution.ready {
		return errors.New("gofresh: contribution belongs to another unit or is unprepared")
	}
	if terminal.Kind < NormalCompletion || terminal.Kind > NeverStarted || (terminal.Kind == NormalCompletion) != (terminal.Reason == "") {
		return errors.New("gofresh: invalid terminal execution disposition")
	}
	if c.execution.terminal.Kind != 0 {
		return errors.New("gofresh: execution already has a terminal disposition")
	}
	c.execution.terminal = terminal
	return nil
}

// Abort ends an unpublished unit and cancels its library-owned preparation or
// closing. An abort winning before closing commits its final state suppresses
// final evidence. The executor still owns stopping/reaping its process and
// disposing of its capture. Already closed evidence and other units are untouched.
func (u *Unit) Abort() {
	u.transaction().abort()
}

// Abort ends this unpublished package execution and cancels library-owned work.
// It does not stop the executor's process or alter an independently closed unit.
func (u *PackageUnit) Abort() {
	u.transaction().abort()
}

func (u *producingUnit) abort() {
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.phase == unitOpen || u.phase == unitClosing {
		u.phase = unitAborted
		if u.execution != nil {
			u.execution.cancel()
		}
		if u.closingCancel != nil {
			u.closingCancel()
		}
	}
}

// Finalized is the native evidence and judgment after successful unit closing.
// A successful close is not a claim of successful samples or durable publication.
// ObservationReason and OutcomeReason retain the distinct incomplete-capture
// and unsupported-outcome accounts; Attribution is diagnostic, never identity.
type Finalized struct {
	Fingerprint       Fingerprint
	Verdict           Verdict
	Terminal          Terminal
	Observation       ObservationDisposition
	ObservationReason string
	OutcomeReason     string
	Attribution       string
}

// FinalizedSubject is one subject's native evidence and closed judgment. It
// retains the process-wide observation because the test log does not attribute
// individual reads to subjects.
type FinalizedSubject struct {
	Subject     Subject
	Fingerprint Fingerprint
	Verdict     Verdict
}

// FinalizedProcess is a closed package execution, not a suite-health result or
// a durable publication. Process and Artifact retain executor-declared identity;
// Terminal is the executor's harness assertion. Subjects is in first-request
// order and owned by the caller. Observation describes the shared capture's
// authority, independently of each subject's verdict or purity assertion.
type FinalizedProcess struct {
	Process           string
	Artifact          string
	Subjects          []FinalizedSubject
	Terminal          Terminal
	Observation       ObservationDisposition
	ObservationReason string
	OutcomeReason     string
	Attribution       string
}

// ObservationDisposition states the native observation's support class without
// asking a consumer to interpret diagnostic text as authority.
type ObservationDisposition uint8

const (
	// UnknownObservation means finalization has not established observation facts.
	// It includes an unselected optional capture, work not attempted, or work
	// interrupted before finalization completed. Terminal completion is separate.
	UnknownObservation ObservationDisposition = iota
	// SupportedObservation carries process-wide outcome support for the subjects
	// selecting observation evidence.
	SupportedObservation
	// IdentityObservation carries finalized input guards, not outcome support.
	IdentityObservation
	// IncompleteObservation names missing or incomplete capture/completion.
	IncompleteObservation
)

// Close fixes the contributor roster immediately and returns evidence only after
// finalization and closing validation succeed. Cancellation or any failure ends
// the unit; retrying requires another unit. Publication belongs to the consumer,
// which keeps the source/runtime exclusion until that separate boundary ends.
func (u *Unit) Close(ctx context.Context) (Finalized, error) {
	result, err := u.transaction().close(ctx)
	if err != nil {
		return Finalized{}, err
	}
	subject := result.Subjects[0]
	return Finalized{Fingerprint: subject.Fingerprint, Verdict: subject.Verdict,
		Terminal: result.Terminal, Observation: result.Observation,
		ObservationReason: result.ObservationReason, OutcomeReason: result.OutcomeReason,
		Attribution: result.Attribution}, nil
}

// Close fixes this execution's roster and finalizes its one capture for all
// declared subjects. It exposes no subject result until the whole execution's
// closing validation succeeds. A failed or cancelled close is terminal; a
// separately prepared retry cannot repair this process's producing evidence.
func (u *PackageUnit) Close(ctx context.Context) (FinalizedProcess, error) {
	return u.transaction().close(ctx)
}

func (u *producingUnit) close(ctx context.Context) (result FinalizedProcess, err error) {
	if u == nil || u.snapshot == nil {
		return FinalizedProcess{}, errors.New("gofresh: uninitialized unit")
	}
	u.mu.Lock()
	if u.phase != unitOpen {
		u.mu.Unlock()
		return FinalizedProcess{}, ErrUnitClosed
	}
	u.phase = unitClosing
	parent := ctx
	if ctx != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		u.closingCancel = cancel
		defer cancel()
	}
	x := u.execution
	if x != nil {
		x.cancel()
	}
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		defer u.mu.Unlock()
		u.closingCancel = nil
		if parent != nil && parent.Err() != nil {
			err = parent.Err()
		} else if u.phase == unitAborted {
			err = ErrUnitAborted
		}
		if err != nil {
			result = FinalizedProcess{}
			if u.phase != unitAborted {
				u.phase = unitFailed
			}
		} else {
			u.phase = unitClosed
		}
	}()
	if ctx == nil {
		return FinalizedProcess{}, errors.New("gofresh: nil closing context")
	}
	if err := ctx.Err(); err != nil {
		return FinalizedProcess{}, err
	}
	if x == nil || !x.ready || x.terminal.Kind == 0 {
		return FinalizedProcess{}, ErrUnitIncomplete
	}
	if x.terminal.Kind == NeverStarted {
		return FinalizedProcess{}, fmt.Errorf("gofresh: execution %q never started: %s", x.process.Identity, x.terminal.Reason)
	}
	var observation runtimeinput.Observation
	var inputs *runtimeinput.State
	// An absent optional capture is not an incomplete observation. Diagnostic
	// identity units and abnormal executions retain their explicit finalization
	// semantics, as do ordinary units that selected observation obligations.
	if len(x.observed) != 0 || u.identityOnly || x.process.Capture != "" || x.terminal.Kind != NormalCompletion {
		receipt, err := x.frame.Completion(x.process.Identity, x.env, x.terminal.Reason)
		if err != nil {
			return FinalizedProcess{}, err
		}
		s := u.snapshot.session
		in := runtimeinput.ProducerIngest{Identity: x.process.Identity, Env: x.env, Runner: s.engine.runner, Roots: &s.roots, Completion: receipt, Outcome: x.support, ScratchRoot: x.process.ScratchRoot, ExcludedPaths: x.process.ExcludedPaths, ScratchNamespaces: x.process.ScratchNamespaces}
		var observationReason string
		if x.outcomeReason == "" {
			observation, observationReason, err = x.frame.Observe(ctx, x.process.Capture, in)
		} else {
			observation, observationReason, err = x.frame.ObserveInputs(ctx, x.process.Capture, in)
		}
		if err != nil {
			return FinalizedProcess{}, err
		}
		if err := u.recordObservation(observation, observationReason); err != nil {
			return FinalizedProcess{}, err
		}
		state, err := runtimeinput.CompletedState(observation)
		if err != nil {
			return FinalizedProcess{}, err
		}
		inputs = &state
	}
	fingerprints := make(map[Subject]Fingerprint, len(u.view.subjects))
	for _, subject := range u.view.subjects {
		fp, err := u.view.attachRuntimeState(subject, x.fingerprints[subject], inputs, x.observed[subject])
		if err != nil {
			return FinalizedProcess{}, err
		}
		fingerprints[subject] = fp
	}
	verdicts, err := u.view.CheckObservedBatch(ctx, fingerprints)
	if err != nil {
		return FinalizedProcess{}, err
	}
	validationErr := u.view.Validate(ctx)
	if validationErr != nil && !errors.Is(validationErr, ErrAnalysisUnavailable) {
		return FinalizedProcess{}, validationErr
	}
	// Source/view drift retains its established precedence. A missing optional
	// proof cannot obscure demonstrated runtime movement or authorize reuse.
	if observation.BracketMoved {
		return FinalizedProcess{}, &RuntimeInputSpanError{Reason: observation.Reason}
	}
	if validationErr != nil {
		return FinalizedProcess{}, validationErr
	}
	if err := x.inspected.validate(ctx); err != nil {
		return FinalizedProcess{}, err
	}
	account, _ := u.account()
	result = FinalizedProcess{Process: account.Process, Artifact: account.Artifact,
		Terminal: account.Terminal, Observation: account.Observation, ObservationReason: account.ObservationReason,
		OutcomeReason: account.OutcomeReason, Attribution: account.Attribution}
	for _, subject := range u.view.subjects {
		result.Subjects = append(result.Subjects, FinalizedSubject{Subject: subject, Fingerprint: fingerprints[subject], Verdict: verdicts[subject]})
	}
	return result, nil
}
