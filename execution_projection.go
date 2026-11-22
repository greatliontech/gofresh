package gofresh

import (
	"context"
	"errors"
	"fmt"

	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/testvariant"
	"github.com/greatliontech/gofresh/internal/trace"
)

type projectedSubject struct {
	sharedState     *subjectRefusal
	vouchDischarges string
	discharges      attestationDischarges
	cut             bool
}

// executionModelProjection holds one execution model's per-subject dynamic-state
// refusals, vouch/attestation discharges, and pass-local reachability budget cuts
// over a single Snapshot observation.
type executionModelProjection struct {
	subjects map[Subject]projectedSubject
}

func (p executionModelProjection) restrict(subjects []Subject) executionModelProjection {
	out := executionModelProjection{
		subjects: make(map[Subject]projectedSubject, len(subjects)),
	}
	for _, s := range subjects {
		if entry, ok := p.subjects[s]; ok {
			out.subjects[s] = entry
		}
	}
	return out
}

func buildModelProjections(subjects []Subject, scan *subjectScan, attribution string, budgetText string) ([3]executionModelProjection, [3]bool) {
	var projs [3]executionModelProjection
	if scan == nil {
		return projs, [3]bool{}
	}
	for m := range scan.hasModel {
		if !scan.hasModel[m] || scan.byModel[m] == nil {
			continue
		}
		ms := scan.byModel[m]
		cutSet := scan.cutByModel[m]
		proj := executionModelProjection{
			subjects: make(map[Subject]projectedSubject, len(subjects)),
		}
		for _, subject := range subjects {
			if scan.staticDecl[subject] {
				continue
			}
			var ps projectedSubject
			if reason := ms.downgradeReason[subject]; reason != "" {
				var culprit Subject
				if !cutSet[subject] {
					culprit = ms.downgradeCulprit[subject]
				} else if budgetText != "" {
					reason += " (reachability unjudged: " + budgetText + ")"
				}
				ps.sharedState = &subjectRefusal{
					reason:  closure.AttributeSelection(reason, attribution),
					culprit: culprit,
				}
			}
			ps.vouchDischarges = ms.vouchDischarges[subject]
			ps.discharges = ms.discharges[subject]
			ps.cut = cutSet[subject]
			if ps.sharedState != nil || ps.vouchDischarges != "" || ps.discharges != (attestationDischarges{}) || ps.cut {
				proj.subjects[subject] = ps
			}
		}
		projs[m] = proj
	}
	return projs, scan.hasModel
}

func restrictModelProjections(projs [3]executionModelProjection, has [3]bool, subjects []Subject) [3]executionModelProjection {
	var out [3]executionModelProjection
	for m := range has {
		if has[m] {
			out[m] = projs[m].restrict(subjects)
		}
	}
	return out
}

func takeModelCutAt(f *observationFacts, other observationFacts, m int, subject Subject) {
	if !f.hasProjection[m] || !other.hasProjection[m] || !other.modelProjections[m].subjects[subject].cut {
		return
	}
	proj := f.modelProjections[m]
	if proj.subjects == nil {
		proj.subjects = map[Subject]projectedSubject{}
	}
	ps := proj.subjects[subject]
	otherPS := other.modelProjections[m].subjects[subject]
	ps.sharedState = otherPS.sharedState
	ps.discharges = otherPS.discharges
	ps.cut = true
	proj.subjects[subject] = ps
	f.modelProjections[m] = proj
}

func takeModelCut(f *observationFacts, other observationFacts, subject Subject) {
	for m := range f.hasProjection {
		takeModelCutAt(f, other, m, subject)
	}
}

func compareModelProjectionsDuringConstruction(ctx context.Context, base *observationFacts, current observationFacts, subject Subject) error {
	if base.hasProjection != current.hasProjection {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fmt.Errorf("%w: execution-model projections for %s.%s during construction", ErrViewChanged, subject.Package, subject.Symbol)
	}
	for m := range base.hasProjection {
		if !base.hasProjection[m] {
			continue
		}
		bp := base.modelProjections[m].subjects[subject]
		cp := current.modelProjections[m].subjects[subject]
		if bp.vouchDischarges != cp.vouchDischarges {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fmt.Errorf("%w: vouch discharges (%s) for %s.%s during construction", ErrViewChanged, ExecutionModel(m), subject.Package, subject.Symbol)
		}
		cutM := bp.cut || cp.cut
		if !cutM {
			if !sameRefusal(bp.sharedState, cp.sharedState) {
				if err := ctx.Err(); err != nil {
					return err
				}
				return fmt.Errorf("%w: closure (%s) for %s.%s during construction", ErrViewChanged, ExecutionModel(m), subject.Package, subject.Symbol)
			}
			if bp.discharges != cp.discharges {
				if err := ctx.Err(); err != nil {
					return err
				}
				return fmt.Errorf("%w: attestation discharges (%s) for %s.%s during construction", ErrViewChanged, ExecutionModel(m), subject.Package, subject.Symbol)
			}
		}
		if cp.cut && !bp.cut {
			takeModelCutAt(base, current, m, subject)
		}
	}
	return nil
}

func checkStaticDeclsForMeasurement(ctx context.Context, subjects []Subject, staticDecl map[Subject]bool, moduleDir string) error {
	var nonCallable []string
	for _, s := range subjects {
		if staticDecl[s] {
			nonCallable = append(nonCallable, s.Package+"."+s.Symbol)
		}
	}
	if len(nonCallable) == 0 {
		return nil
	}
	if trace.Enabled(ctx, trace.DomainView, moduleDir) {
		trace.Emit(ctx, trace.DomainView, "snapshot.static_decl.refused", moduleDir,
			trace.Int("count", len(nonCallable)),
			trace.String("first", nonCallable[0]),
			trace.String("reason", "measurement_requires_callable"),
		)
	}
	return fmt.Errorf("gofresh: non-callable declaration %s has no runtime execution to measure", nonCallable[0])
}

func (m ExecutionModel) String() string {
	switch m {
	case GeneralExecution:
		return "GeneralExecution"
	case PackageExecution:
		return "PackageExecution"
	case SingleSubjectExecution:
		return "SingleSubjectExecution"
	default:
		return fmt.Sprintf("ExecutionModel(%d)", m)
	}
}

func execModelFromBools(singleSubject, packageProcess bool) ExecutionModel {
	if singleSubject {
		return SingleSubjectExecution
	}
	if packageProcess {
		return PackageExecution
	}
	return GeneralExecution
}

func (v *Snapshot) effectiveExecutionModel() ExecutionModel {
	if v == nil {
		return GeneralExecution
	}
	if v.hasExecutionModel {
		return v.executionModel
	}
	if v.session != nil {
		return v.session.executionModel
	}
	return GeneralExecution
}

// ExecutionModel returns the execution-model attestation active on this snapshot.
func (v *Snapshot) ExecutionModel() ExecutionModel {
	return v.effectiveExecutionModel()
}

// WithExecution derives a sibling snapshot projecting model's dynamic-state
// discharges and execution-model obligations over this snapshot's single
// source/build observation without re-reading source, reloading packages, or
// spawning Go commands. A snapshot observed under PackageExecution or
// SingleSubjectExecution projects GeneralExecution, PackageExecution, and
// SingleSubjectExecution; a snapshot observed under GeneralExecution projects
// only GeneralExecution (unless its result kind is SourceResult, which carries
// no dynamic-state obligations). The derived snapshot owns fresh transactional
// state and re-observes under model at closing.
func (v *Snapshot) WithExecution(model ExecutionModel) (*Snapshot, error) {
	if v == nil || v.facts == nil {
		return nil, errors.New("gofresh: uninitialized snapshot")
	}
	if model > SingleSubjectExecution {
		return nil, fmt.Errorf("gofresh: invalid execution model %d", model)
	}
	v.mu.RLock()
	defer v.mu.RUnlock()

	curModel := v.effectiveExecutionModel()
	if v.kind != SourceResult && !v.facts.hasProjection[model] {
		if model != curModel {
			if trace.AnyEnabled() && v.session != nil {
				trace.Emit(nil, trace.DomainView, "snapshot.with_execution.refused", v.moduleDir,
					trace.String("from_model", curModel.String()),
					trace.String("to_model", model.String()),
					trace.String("reason", "unprojected_model"),
				)
			}
			return nil, fmt.Errorf("gofresh: snapshot observed under %s cannot project %s; configure SessionPolicy.Execution with PackageExecution or SingleSubjectExecution", curModel, model)
		}
	}

	rootParent := v
	if v.parent != nil {
		rootParent = v.parent
	}

	entries := make(map[Subject]subjectEntry, len(v.subjects))
	if v.kind == SourceResult || !v.facts.hasProjection[model] {
		for _, s := range v.subjects {
			entries[s] = v.facts.subjects[s]
		}
	} else {
		proj := v.facts.modelProjections[model]
		for _, s := range v.subjects {
			entry := v.facts.subjects[s]
			ps := proj.subjects[s]
			entry.maximal.sharedState = ps.sharedState
			entry.vouchDischarges = ps.vouchDischarges
			entry.discharges = ps.discharges
			entry.cut = ps.cut
			entries[s] = entry
		}
	}

	ledgers := make(map[string]testvariant.TestVariantLedger, len(v.packages))
	for _, pkg := range v.packages {
		if l, ok := v.facts.testVariantLedgers[pkg]; ok {
			ledgers[pkg] = l
		}
	}

	facts := &observationFacts{
		snapshot:           v.facts.snapshot,
		reader:             v.facts.reader,
		subjects:           entries,
		source:             v.facts.source,
		guards:             v.facts.guards,
		sourceFiles:        v.facts.sourceFiles,
		fileDigests:        v.facts.fileDigests,
		testVariantLedgers: ledgers,
		modelProjections:   v.facts.modelProjections,
		hasProjection:      v.facts.hasProjection,
	}

	shell := v.cloneShell(v.subjects, v.requests, v.packages, facts)
	shell.parent = rootParent
	shell.executionModel = model
	shell.hasExecutionModel = true
	if v.cutUnavailable == nil {
		for _, s := range v.subjects {
			if tx := v.txState[s]; tx.hasObservable {
				shell.txState[s] = subjectTxState{observable: tx.observable, hasObservable: true}
			}
		}
	}
	if trace.AnyEnabled() && v.session != nil {
		trace.Emit(nil, trace.DomainView, "snapshot.with_execution", v.moduleDir,
			trace.String("from_model", curModel.String()),
			trace.String("to_model", model.String()),
			trace.Int("subjects", len(v.subjects)),
		)
	}
	return shell, nil
}
