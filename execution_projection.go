package gofresh

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/observability"
	"github.com/greatliontech/gofresh/internal/testvariant"
	"github.com/greatliontech/gofresh/internal/trace"
)

// executionModelProjection holds one execution model's per-subject dynamic-state
// refusals, vouch/attestation discharges, and pass-local reachability budget cuts
// over a single Snapshot observation.
type executionModelProjection struct {
	sharedState     map[Subject]*subjectRefusal
	vouchDischarges map[Subject]string
	discharges      map[Subject]attestationDischarges
	cut             map[Subject]bool
}

func (p executionModelProjection) restrict(subjects []Subject) executionModelProjection {
	out := executionModelProjection{
		sharedState:     make(map[Subject]*subjectRefusal, len(subjects)),
		vouchDischarges: make(map[Subject]string, len(subjects)),
		discharges:      make(map[Subject]attestationDischarges, len(subjects)),
		cut:             make(map[Subject]bool),
	}
	for _, s := range subjects {
		if ref := p.sharedState[s]; ref != nil {
			out.sharedState[s] = ref
		}
		if v := p.vouchDischarges[s]; v != "" {
			out.vouchDischarges[s] = v
		}
		if d := p.discharges[s]; d != (attestationDischarges{}) {
			out.discharges[s] = d
		}
		if p.cut[s] {
			out.cut[s] = true
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
			sharedState:     make(map[Subject]*subjectRefusal, len(subjects)),
			vouchDischarges: make(map[Subject]string, len(subjects)),
			discharges:      make(map[Subject]attestationDischarges, len(subjects)),
			cut:             make(map[Subject]bool),
		}
		for _, subject := range subjects {
			if scan.staticDecl[subject] {
				continue
			}
			if reason := ms.downgradeReason[subject]; reason != "" {
				var culprit Subject
				if !cutSet[subject] {
					culprit = ms.downgradeCulprit[subject]
				} else if budgetText != "" {
					reason += " (reachability unjudged: " + budgetText + ")"
				}
				proj.sharedState[subject] = &subjectRefusal{
					reason:  closure.AttributeSelection(reason, attribution),
					culprit: culprit,
				}
			}
			if vd := ms.vouchDischarges[subject]; vd != "" {
				proj.vouchDischarges[subject] = vd
			}
			if d := ms.discharges[subject]; d != (attestationDischarges{}) {
				proj.discharges[subject] = d
			}
			if cutSet[subject] {
				proj.cut[subject] = true
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
	if !f.hasProjection[m] || !other.hasProjection[m] || !other.modelProjections[m].cut[subject] {
		return
	}
	proj := f.modelProjections[m]
	if proj.sharedState == nil {
		proj.sharedState = map[Subject]*subjectRefusal{}
	}
	if ref := other.modelProjections[m].sharedState[subject]; ref != nil {
		proj.sharedState[subject] = ref
	} else {
		delete(proj.sharedState, subject)
	}
	if d := other.modelProjections[m].discharges[subject]; d != (attestationDischarges{}) {
		if proj.discharges == nil {
			proj.discharges = map[Subject]attestationDischarges{}
		}
		proj.discharges[subject] = d
	} else {
		delete(proj.discharges, subject)
	}
	if proj.cut == nil {
		proj.cut = map[Subject]bool{}
	}
	proj.cut[subject] = true
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
		bp := base.modelProjections[m]
		cp := current.modelProjections[m]
		if bp.vouchDischarges[subject] != cp.vouchDischarges[subject] {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fmt.Errorf("%w: vouch discharges (%s) for %s.%s during construction", ErrViewChanged, ExecutionModel(m), subject.Package, subject.Symbol)
		}
		cutM := bp.cut[subject] || cp.cut[subject]
		if !cutM {
			if !sameRefusal(bp.sharedState[subject], cp.sharedState[subject]) {
				if err := ctx.Err(); err != nil {
					return err
				}
				return fmt.Errorf("%w: closure (%s) for %s.%s during construction", ErrViewChanged, ExecutionModel(m), subject.Package, subject.Symbol)
			}
			if bp.discharges[subject] != cp.discharges[subject] {
				if err := ctx.Err(); err != nil {
					return err
				}
				return fmt.Errorf("%w: attestation discharges (%s) for %s.%s during construction", ErrViewChanged, ExecutionModel(m), subject.Package, subject.Symbol)
			}
		}
		if cp.cut[subject] && !bp.cut[subject] {
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

	maximal := make(map[Subject]subjectFacts, len(v.subjects))
	vouchDischarges := make(map[Subject]string, len(v.subjects))
	discharges := make(map[Subject]attestationDischarges, len(v.subjects))
	cut := make(map[Subject]bool)

	if v.kind == SourceResult || !v.facts.hasProjection[model] {
		for _, s := range v.subjects {
			maximal[s] = v.facts.maximal[s]
			if vd := v.facts.vouchDischarges[s]; vd != "" {
				vouchDischarges[s] = vd
			}
			if d := v.facts.discharges[s]; d != (attestationDischarges{}) {
				discharges[s] = d
			}
			if v.facts.cut[s] {
				cut[s] = true
			}
		}
	} else {
		proj := v.facts.modelProjections[model]
		for _, s := range v.subjects {
			sf := v.facts.maximal[s]
			sf.sharedState = proj.sharedState[s]
			maximal[s] = sf
			if vd := proj.vouchDischarges[s]; vd != "" {
				vouchDischarges[s] = vd
			}
			if d := proj.discharges[s]; d != (attestationDischarges{}) {
				discharges[s] = d
			}
			if proj.cut[s] {
				cut[s] = true
			}
		}
	}

	purity := maps.Clone(v.facts.purity)
	sourceFilesBySubject := make(map[Subject][]string, len(v.subjects))
	for _, s := range v.subjects {
		sourceFilesBySubject[s] = v.facts.sourceFilesBySubject[s]
	}
	ledgers := make(map[string]testvariant.TestVariantLedger, len(v.packages))
	for _, pkg := range v.packages {
		if l, ok := v.facts.testVariantLedgers[pkg]; ok {
			ledgers[pkg] = l
		}
	}

	facts := &observationFacts{
		snapshot:             v.facts.snapshot,
		reader:               v.facts.reader,
		maximal:              maximal,
		source:               v.facts.source,
		guards:               v.facts.guards,
		purity:               purity,
		vouchDischarges:      vouchDischarges,
		discharges:           discharges,
		cut:                  cut,
		sourceFiles:          v.facts.sourceFiles,
		sourceFilesBySubject: sourceFilesBySubject,
		fileDigests:          v.facts.fileDigests,
		testVariantLedgers:   ledgers,
		modelProjections:     v.facts.modelProjections,
		hasProjection:        v.facts.hasProjection,
	}

	shell := v.cloneShell(v.subjects, v.requests, v.packages, facts)
	shell.parent = rootParent
	shell.executionModel = model
	shell.hasExecutionModel = true
	if v.cutUnavailable == nil && len(v.observable) > 0 {
		shell.observable = maps.Clone(v.observable)
	} else {
		shell.observable = make(map[Subject]observability.Observability, len(v.subjects))
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
