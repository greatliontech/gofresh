package gofresh

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/greatliontech/gofresh/gotool"
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
// session's runtime directory at registration, and the same absolute coordinate
// is returned to the executor and read by closing. It is not supplied at Submit.
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
	// NormalCompletion asserts ordinary harness completion and capture flush,
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
	unit      *Unit
	execution *unitExecution
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
	return c.unit.snapshot.session.runtimeDir
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
	env           []string
	frame         runtimeinput.ProducerFrame
	support       runtimeinput.OutcomeSupport
	fingerprint   Fingerprint
	outcomeReason string
	terminal      Terminal
	ready         bool
	cancel        context.CancelFunc
}

// Unit owns one subject's single contributing package-test process and its
// producing/closing obligations. A second contributor is refused, not silently
// dropped. Independent units share only their snapshot's immutable source facts.
type Unit struct {
	mu            sync.Mutex
	phase         unitPhase
	snapshot      *Snapshot
	subject       Subject
	view          *View
	execution     *unitExecution
	closingCancel context.CancelFunc
	identityOnly  bool
}

// Begin creates an independently closing unit for a subject in the snapshot.
func (s *Snapshot) Begin(subject Subject) (*Unit, error) {
	return s.begin(subject, false)
}

// BeginIdentity selects identity-only input evidence for a diagnostic execution,
// such as an instrumented profile. It deliberately prepares no outcome support;
// ordinary completion cannot promote the resulting evidence to supported form.
func (s *Snapshot) BeginIdentity(subject Subject) (*Unit, error) {
	return s.begin(subject, true)
}

func (s *Snapshot) begin(subject Subject, identityOnly bool) (*Unit, error) {
	if s == nil || s.view == nil {
		return nil, errors.New("gofresh: uninitialized snapshot")
	}
	v, err := s.view.Sibling([]Subject{subject})
	if err != nil {
		return nil, err
	}
	return &Unit{snapshot: s, subject: subject, view: v, identityOnly: identityOnly}, nil
}

// Register prepares the complete producing obligation before execution. Build
// must belong to the same snapshot and package. Expensive preparation holds no
// unit mutex: concurrent close freezes the roster and cancels that preparation.
func (u *Unit) Register(ctx context.Context, build BuildBinding, process ProcessDescription) (Contribution, error) {
	if ctx == nil {
		return Contribution{}, errors.New("gofresh: nil registration context")
	}
	if err := ctx.Err(); err != nil {
		return Contribution{}, err
	}
	if u == nil || u.snapshot == nil {
		return Contribution{}, errors.New("gofresh: uninitialized unit")
	}
	if build.snapshot != u.snapshot || build.pkg != u.subject.Package || build.identity == "" {
		return Contribution{}, errors.New("gofresh: built artifact belongs to another snapshot or package")
	}
	dir := u.snapshot.session.runtimeDir
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
	env, err := gotool.EnvForCommand(e.evidenceEnv(), dir)
	if err != nil {
		return Contribution{}, err
	}
	// The frame owns the process/environment grammar. A zero frame performs
	// that input validation without capturing anything or issuing support.
	if _, err := (runtimeinput.ProducerFrame{}).OutcomeBinding(process.Identity, env); err != nil {
		return Contribution{}, err
	}
	preparing, cancel := context.WithCancel(ctx)
	defer cancel()
	x := &unitExecution{process: process, env: env, cancel: cancel}
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
	var fp Fingerprint
	if u.identityOnly {
		fp, err = u.view.Capture(preparing, u.subject)
	} else {
		support, err = u.view.PrepareOutcomeSupport(preparing, frame, process.Identity)
		if err == nil {
			fp, err = u.view.CaptureObserved(preparing, u.subject)
		}
	}
	if preparing.Err() != nil {
		err = preparing.Err()
	}
	u.mu.Lock()
	defer u.mu.Unlock()
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
	x.frame, x.support, x.fingerprint, x.outcomeReason = frame, support, fp, support.Reason(binding)
	if u.identityOnly {
		x.outcomeReason = "identity-only execution selected"
	}
	x.ready = true
	return Contribution{unit: u, execution: x}, nil
}

// Submit supplies the registered execution's one terminal disposition. No log,
// frame, environment or support can be substituted at this boundary.
func (u *Unit) Submit(c Contribution, terminal Terminal) error {
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

// ObservationDisposition states the native observation's support class without
// asking a consumer to interpret diagnostic text as authority.
type ObservationDisposition uint8

const (
	// SupportedObservation carries the subject's admitted outcome support.
	SupportedObservation ObservationDisposition = iota + 1
	// IdentityObservation carries finalized input guards, not outcome support.
	IdentityObservation
	// IncompleteObservation names missing or incomplete capture/completion.
	IncompleteObservation
)

// Close fixes the contributor roster immediately and returns evidence only after
// finalization and closing validation succeed. Cancellation or any failure ends
// the unit; retrying requires another unit. Publication belongs to the consumer,
// which keeps the source/runtime exclusion until that separate boundary ends.
func (u *Unit) Close(ctx context.Context) (result Finalized, err error) {
	if u == nil || u.snapshot == nil {
		return Finalized{}, errors.New("gofresh: uninitialized unit")
	}
	u.mu.Lock()
	if u.phase != unitOpen {
		u.mu.Unlock()
		return Finalized{}, ErrUnitClosed
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
			result = Finalized{}
			if u.phase != unitAborted {
				u.phase = unitFailed
			}
		} else {
			u.phase = unitClosed
		}
	}()
	if ctx == nil {
		return Finalized{}, errors.New("gofresh: nil closing context")
	}
	if err := ctx.Err(); err != nil {
		return Finalized{}, err
	}
	if x == nil || !x.ready || x.terminal.Kind == 0 {
		return Finalized{}, ErrUnitIncomplete
	}
	if x.terminal.Kind == NeverStarted {
		return Finalized{}, fmt.Errorf("gofresh: execution %q never started: %s", x.process.Identity, x.terminal.Reason)
	}
	receipt, err := x.frame.Completion(x.process.Identity, x.env, x.terminal.Reason)
	if err != nil {
		return Finalized{}, err
	}
	s := u.snapshot.session
	in := runtimeinput.ProducerIngest{Identity: x.process.Identity, Env: x.env, Runner: s.engine.runner, Roots: &s.roots, Completion: receipt, Outcome: x.support, ScratchRoot: x.process.ScratchRoot, ExcludedPaths: x.process.ExcludedPaths, ScratchNamespaces: x.process.ScratchNamespaces}
	var observation runtimeinput.Observation
	var observationReason string
	if x.outcomeReason == "" {
		observation, observationReason, err = x.frame.Observe(ctx, x.process.Capture, in)
	} else {
		observation, observationReason, err = x.frame.ObserveInputs(ctx, x.process.Capture, in)
	}
	if err != nil {
		return Finalized{}, err
	}
	fp, err := u.view.attachObservation(u.subject, x.fingerprint, observation, !u.identityOnly)
	if err != nil {
		return Finalized{}, err
	}
	verdict, err := u.view.CheckObserved(ctx, fp, u.subject)
	if err != nil {
		return Finalized{}, err
	}
	if err := u.view.Validate(ctx); err != nil {
		return Finalized{}, err
	}
	disposition := IdentityObservation
	if observationReason != "" {
		disposition = IncompleteObservation
	} else if runtimeinput.HasOutcomeSupport(fp.RuntimeInputs, outcomeSubject(fp, u.subject)) {
		disposition = SupportedObservation
	}
	return Finalized{Fingerprint: fp, Verdict: verdict, Terminal: x.terminal, Observation: disposition, ObservationReason: observationReason, OutcomeReason: x.outcomeReason, Attribution: observation.Attribution}, nil
}
