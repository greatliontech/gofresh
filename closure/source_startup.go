package closure

import (
	"context"
	"errors"
	"fmt"
	"go/types"
	"slices"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
)

type sourceInitializationModel uint8

const sourceStartupRules = "gofresh/source-startup@1"

const (
	sourceInitializationAbsent sourceInitializationModel = iota
	sourceLanguageInitialization
	sourceExternalInitialization
)

// This is an explicit SOURCE model selection, not evidence about a compiler
// image. Unknown or externally supplied initialization has no zero-storage rule.
// Linker options are retained separately; this grammar supports none (including
// -X). A source owner alone does not silently select the language-only model.
type sourceStartupInput struct {
	source         computationSource
	initialization sourceInitializationModel
	linkerFlags    []string
}

type sourceStartupPhase string

type sourceStartupOperation string

const (
	sourceStartupSelection      sourceStartupPhase = "selection"
	sourceStartupStorage        sourceStartupPhase = "storage"
	sourceStartupInitialization sourceStartupPhase = "initialization"
	sourceStartupEntry          sourceStartupPhase = "main-entry"
)

// The operation and dependency path remain machine-readable even when an inner
// checker has only diagnostic detail. Unwrap preserves cancellation identity.
type sourceStartupFailure struct {
	packageID      string
	phase          sourceStartupPhase
	operation      sourceStartupOperation
	dependencyPath []string
	operations     []ssa.Instruction
	cause          error
}

func (f *sourceStartupFailure) Error() string {
	return fmt.Sprintf("source startup %s %s %s: %v", f.packageID, f.phase, f.operation, f.cause)
}
func (f *sourceStartupFailure) Unwrap() error { return f.cause }

type sourceStartupPackage struct {
	selected       *packages.Package
	input          selectedSourcePackage
	initialization *sourceInitialization
	dependencies   []*packages.Package
	path           []string
	packets        []*checkedRegion
	calls          []sourceRegionCall
}

// Each heap is a whole alternative, never a fieldwise join or a selected-global
// projection. These facts describe the source language's initialization boundary
// only. They supply no native startup, lowering-origin or execution authority.
type sourceStartup struct {
	rules string
	owner computationSource
	model sourceInitializationModel
	order []*sourceStartupPackage
	heaps []regionState
}

type sourceEntry struct {
	startup *sourceStartup
	main    selectedSourceCallable
	regions []*sourceRegion
}

type sourceStartupChecker struct {
	*selectedSourceBinder
	meter     *regionMeter
	contexts  map[regionInvocation]regionContextFacts
	completed map[*ssa.Function]bool
	packages  map[*packages.Package]*sourceStartupPackage
}

func startupFailure(p *sourceStartupPackage, phase sourceStartupPhase, operation sourceStartupOperation, err error) error {
	f := &sourceStartupFailure{phase: phase, operation: operation, cause: err}
	if p != nil {
		f.packageID, f.dependencyPath = p.selected.ID, slices.Clone(p.path)
	}
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		if step, ok := cause.(*regionOperationFailure); ok {
			f.operations = append(f.operations, step.instruction)
		}
	}
	return f
}

func (c *sourceStartupChecker) failure(p *sourceStartupPackage, phase sourceStartupPhase, operation sourceStartupOperation, err error) error {
	f := startupFailure(p, phase, operation, err).(*sourceStartupFailure)
	if len(f.operations) != 0 {
		fn := f.operations[len(f.operations)-1].Parent()
		if fn != nil && fn.Pkg != nil {
			if owner := c.packages[c.pkgs[fn.Pkg.Pkg]]; owner != nil {
				f.packageID = owner.selected.ID
				f.dependencyPath = slices.Clone(owner.path)
			}
		}
	}
	return f
}

// prepareSourceEntry has deliberately no initial-state argument. It starts at
// ordinary source-language program initialization, derives the complete selected
// dependency graph's storage, and interprets the exact language main from entry
// to the actual use. The consuming operation itself remains outside that scope.
func prepareSourceEntry(ctx context.Context, input sourceStartupInput, main *ssa.Function, use regionUse, limits registrationLimits) (*sourceEntry, error) {
	if limits == (registrationLimits{}) {
		limits = defaultRegistrationLimits()
	}
	if ctx == nil || !limits.region.valid() || limits.source.work <= 0 || limits.source.bytes <= 0 || limits.source.depth <= 0 {
		return nil, startupFailure(nil, sourceStartupSelection, "context/budget", regionError("invalid startup context or budget"))
	}
	// Own selection containers before any user context callback. The typed owner
	// (including AST/SSA and loader package objects) stays immutable by contract.
	if len(input.linkerFlags) > limits.source.work || len(input.source.metas) > limits.source.work-len(input.linkerFlags) {
		return nil, startupFailure(nil, sourceStartupSelection, "capture", regionError("selection budget exhausted"))
	}
	input.linkerFlags = slices.Clone(input.linkerFlags)
	input.source.metas = slices.Clone(input.source.metas)
	remaining := limits.source.work - len(input.linkerFlags) - len(input.source.metas)
	for i := range input.source.metas {
		m := &input.source.metas[i]
		if m.Error != nil {
			copy := *m.Error
			m.Error = &copy
		}
		for _, field := range []*[]string{&m.GoFiles, &m.CgoFiles, &m.CgoCFLAGS, &m.CgoCPPFLAGS, &m.CgoCXXFLAGS, &m.CgoFFLAGS, &m.CgoPkgConfig, &m.CFiles, &m.CXXFiles, &m.MFiles, &m.HFiles, &m.FFiles, &m.SFiles, &m.SwigFiles, &m.SwigCXXFiles, &m.SysoFiles, &m.EmbedFiles, &m.EmbedPatterns, &m.TestEmbedPatterns, &m.XTestEmbedPatterns, &m.CgoLDFLAGS, &m.Imports, &m.Deps} {
			if len(*field) > remaining {
				return nil, startupFailure(nil, sourceStartupSelection, "capture", regionError("selection budget exhausted"))
			}
			remaining -= len(*field)
			*field = slices.Clone(*field)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, startupFailure(nil, sourceStartupSelection, "capture", err)
	}
	if input.initialization != sourceLanguageInitialization || len(input.linkerFlags) != 0 {
		return nil, startupFailure(nil, sourceStartupSelection, "external-initialization", regionError("ordinary language initialization and default linker inputs must be explicit"))
	}
	b, err := newSelectedSourceBinder(ctx, input.source, main, limits.source)
	if err != nil {
		return nil, startupFailure(nil, sourceStartupSelection, "owner", err)
	}
	captured := limits.source.work - remaining
	if captured > b.limits.work-b.work {
		return nil, startupFailure(nil, sourceStartupSelection, "capture", regionError("selection work budget exhausted"))
	}
	b.work += captured
	c := &sourceStartupChecker{selectedSourceBinder: b, meter: &regionMeter{ctx: ctx, limits: limits.region}, contexts: map[regionInvocation]regionContextFacts{}, completed: map[*ssa.Function]bool{}, packages: map[*packages.Package]*sourceStartupPackage{}}
	var root *sourceStartupPackage
	if main.Pkg != nil {
		if p := b.pkgs[main.Pkg.Pkg]; p != nil {
			root = &sourceStartupPackage{selected: p, path: []string{p.ID}}
		}
	}
	bound, err := b.bindCallable(main)
	if err != nil {
		return nil, startupFailure(root, sourceStartupEntry, "binding", err)
	}
	root = &sourceStartupPackage{selected: bound.pkg, path: []string{bound.pkg.ID}}
	if main.Parent() != nil || main.Pkg == nil || main.Pkg.Func("main") != main || main.Name() != "main" || bound.pkg.Name != "main" || bound.pkg.Types.Name() != "main" || main.Signature.Recv() != nil || main.Signature.Params().Len() != 0 || main.Signature.Results().Len() != 0 || len(main.Params) != 0 || len(main.FreeVars) != 0 {
		return nil, startupFailure(root, sourceStartupEntry, "language-entry", regionError("root is not the ordinary selected main entry"))
	}
	order, err := c.graph(root)
	if err != nil {
		return nil, err
	}
	initial := regionState{memory: map[regionObject]regionValue{}}
	zeroer := &regionKernel{meter: c.meter}
	for _, p := range order {
		for _, variable := range p.initialization.variables {
			value, err := zeroer.zero(variable.Type(), 0)
			if err != nil {
				return nil, startupFailure(p, sourceStartupStorage, "zero", err)
			}
			// zero refuses unsupported types rather than importing unknown storage.
			g := p.initialization.function.Pkg.Members[variable.Name()].(*ssa.Global)
			initial.memory[regionObject{kind: regionGlobal, site: g}] = value
		}
	}
	startup := &sourceStartup{rules: sourceStartupRules, owner: input.source, model: input.initialization, order: order, heaps: []regionState{initial}}
	for _, p := range order {
		init := p.initialization
		for _, dependency := range p.dependencies {
			if !c.completed[c.packages[dependency].initialization.function] {
				return nil, startupFailure(p, sourceStartupInitialization, "import-prefix", regionError("import has no completed initialization"))
			}
		}
		var next []regionState
		for _, heap := range startup.heaps {
			in := regionInput{owner: input.source.prog.Prog, root: init.function, entry: init.entry, use: init.end, initial: heap, premises: sourceStartupPremises()}
			packet, err := c.region(in)
			if err != nil {
				return nil, c.failure(p, sourceStartupInitialization, "interpret", err)
			}
			calls, err := c.calls(packet)
			if err != nil {
				return nil, startupFailure(p, sourceStartupInitialization, "call-binding", err)
			}
			p.packets, p.calls = append(p.packets, packet), append(p.calls, calls...)
			for _, observation := range packet.observations {
				if len(next) >= limits.region.alternatives {
					return nil, startupFailure(p, sourceStartupInitialization, "alternatives", regionError("whole heap alternative budget exhausted"))
				}
				next = append(next, regionState{memory: observation.state.memory})
			}
		}
		// The cut is licensed by the checked actual guard/import prefix and the
		// schedule's once-only execution. The suffix ran THROUGH its calls to the
		// actual void Return, not merely to the first explicit init's boundary.
		c.completed[init.function] = true
		startup.heaps = next
	}
	result := &sourceEntry{startup: startup, main: bound}
	for _, heap := range startup.heaps {
		in := regionInput{owner: input.source.prog.Prog, root: main, entry: regionPoint{main.Blocks[0], 0}, use: use, initial: heap, premises: sourceStartupPremises()}
		packet, err := c.region(in)
		if err != nil {
			return nil, c.failure(root, sourceStartupEntry, "interpret", err)
		}
		region, err := b.checkSourceRegion(packet)
		if err != nil {
			return nil, startupFailure(root, sourceStartupEntry, "binding", err)
		}
		if err := c.checkCallPackages(region.calls); err != nil {
			return nil, startupFailure(root, sourceStartupEntry, "call-binding", err)
		}
		result.regions = append(result.regions, region)
	}
	if err := c.tick(main, main.Pos()); err != nil {
		return nil, startupFailure(root, sourceStartupEntry, "completion", err)
	}
	return result, nil
}

func sourceStartupPremises() []string {
	return []string{"immutable complete selected source owner and faithful typed source-to-SSA language representation", "ordinary source-language program initialization; no external storage initialization or linker overrides", "source-language sequential startup and checked main prefix; no native/image/lowering-origin or runtime correspondence is established"}
}

func (c *sourceStartupChecker) calls(packet *checkedRegion) ([]sourceRegionCall, error) {
	calls, err := c.bindRegionCalls(packet)
	if err != nil {
		return nil, err
	}
	if err := c.checkCallPackages(calls); err != nil {
		return nil, err
	}
	return calls, nil
}

func (c *sourceStartupChecker) checkCallPackages(calls []sourceRegionCall) error {
	for _, call := range calls {
		if err := c.tick(call.bound.function, call.bound.function.Pos()); err != nil {
			return err
		}
		if c.packages[call.bound.pkg] == nil {
			return regionError("called source package is outside the eligible startup graph")
		}
	}
	return nil
}

// Each phase has its own root call-string namespace. Only checker-derived
// cardinality facts from earlier phases are inherited; proposals cannot supply
// them. Earlier storage survives wholesale, including escaped helper allocations.
func (c *sourceStartupChecker) region(input regionInput) (*checkedRegion, error) {
	newKernel := func(in regionInput) (*regionKernel, error) {
		s := newRegionCallSession(c.ctx, in, c.meter.limits)
		s.meter, s.completed = c.meter, c.completed
		for id, facts := range c.contexts {
			if err := c.meter.tick(); err != nil {
				return nil, err
			}
			s.contexts[id] = facts
		}
		return newRegionContextKernel(in, s, regionInvocation{root: in.root}, false)
	}
	in, _, err := regionCaptureMeter(input, nil, c.meter)
	if err != nil {
		return nil, err
	}
	proposer, err := newKernel(in)
	if err != nil {
		return nil, err
	}
	proposal, err := proposeRegionKernel(proposer)
	if err != nil {
		return nil, err
	}
	in, proposal, err = regionCaptureMeter(input, proposal, c.meter)
	if err != nil {
		return nil, err
	}
	checker, err := newKernel(in)
	if err != nil {
		return nil, err
	}
	packet, err := checkRegionKernel(checker, proposal)
	if err != nil {
		return nil, err
	}
	for id, facts := range checker.session.contexts {
		if err := c.meter.tick(); err != nil {
			return nil, err
		}
		c.contexts[id] = facts
	}
	return packet, nil
}

func (c *sourceStartupChecker) graph(root *sourceStartupPackage) ([]*sourceStartupPackage, error) {
	queue := []*sourceStartupPackage{root}
	paths := map[string]*packages.Package{}
	c.packages[root.selected] = root
	for len(queue) != 0 {
		p := queue[0]
		queue = queue[1:]
		selected := p.selected
		fail := func(op sourceStartupOperation, err error) ([]*sourceStartupPackage, error) {
			return nil, startupFailure(p, sourceStartupSelection, op, err)
		}
		if err := c.tick(nil, 0); err != nil {
			return fail("graph", err)
		}
		if selected.Types == nil || c.pkgs[selected.Types] != selected || selected.PkgPath != selected.Types.Path() || selected.ID == "" || selected.IllTyped || len(selected.Errors) != 0 {
			return fail("graph", regionError("missing or conflicting typed selection"))
		}
		if previous := paths[selected.Types.Path()]; previous != nil && previous != selected {
			return fail("graph", regionError("ambiguous selected import path"))
		}
		paths[selected.Types.Path()] = selected
		m, exists := c.metas[selected.ID]
		if !exists || m.Error != nil || m.Name != selected.Name || selected.Name != selected.Types.Name() || len(m.GoFiles) != len(selected.Syntax) {
			return fail("metadata", regionError("missing or failed selected listing"))
		}
		fn := c.source.prog.Prog.Package(selected.Types)
		if fn == nil || fn.Func("init") == nil {
			return fail("owner", regionError("missing selected SSA package"))
		}
		inventory, err := c.selectedPackage(fn.Func("init"), selected)
		if err != nil {
			return fail("inventory", err)
		}
		p.input = inventory
		if len(inventory.directives) != 0 || len(inventory.otherInputs) != 0 || len(m.CgoLDFLAGS)+len(m.CgoCFLAGS)+len(m.CgoCPPFLAGS)+len(m.CgoCXXFLAGS)+len(m.CgoFFLAGS)+len(m.CgoPkgConfig) != 0 {
			return fail("external-storage", regionError("selected directives or non-Go inputs have unsupported initialization"))
		}
		for _, decl := range inventory.declarations {
			if err := c.tick(nil, 0); err != nil {
				return fail("external-storage", err)
			}
			if decl.Body == nil {
				return fail("external-storage", regionError("selected package has a bodyless implementation boundary"))
			}
		}
		p.initialization, err = c.bindInitialization(selected)
		if err != nil {
			return fail("initialization-binding", err)
		}
		globals := map[types.Object]bool{}
		for _, v := range p.initialization.variables {
			globals[v] = true
		}
		for _, member := range fn.Members {
			if err := c.tick(nil, 0); err != nil {
				return fail("storage-inventory", err)
			}
			if g, ok := member.(*ssa.Global); ok && g != p.initialization.guard && !globals[g.Object()] {
				return fail("storage-inventory", regionError("global has no ordinary source declaration"))
			}
		}
		imports := map[*types.Package]bool{}
		listed := map[string]bool{}
		for _, name := range m.Imports {
			if err := c.tick(nil, 0); err != nil {
				return fail("imports", err)
			}
			if listed[name] {
				return fail("imports", regionError("duplicate listing import"))
			}
			listed[name] = true
		}
		for _, imported := range selected.Types.Imports() {
			if err := c.tick(nil, 0); err != nil {
				return fail("imports", err)
			}
			if imported == nil || imports[imported] {
				return fail("imports", regionError("absent or duplicate typed import"))
			}
			imports[imported] = true
			if imported == types.Unsafe {
				// This exact go/types object denotes language operations, not a
				// package implementation selected by the string "unsafe". Its SSA
				// import call was bound above; it contributes no language storage.
				pseudo := c.source.prog.Prog.Package(types.Unsafe)
				if pseudo == nil {
					return fail("imports", regionError("missing language pseudo-package owner"))
				}
				for name, member := range pseudo.Members {
					if err := c.tick(nil, 0); err != nil {
						return fail("imports", err)
					}
					if global, ok := member.(*ssa.Global); ok && (name != "init$guard" || global.Object() != nil || global.Pkg != pseudo || !types.Identical(global.Type(), types.NewPointer(types.Typ[types.Bool]))) {
						return fail("imports", regionError("language pseudo-package has arbitrary storage"))
					}
				}
				if !listed["unsafe"] {
					return fail("imports", regionError("missing language pseudo-package import"))
				}
				delete(listed, "unsafe")
				continue
			}
			dep := c.pkgs[imported]
			if dep == nil || !listed[dep.ID] {
				return fail("imports", regionError("missing selected dependency"))
			}
			delete(listed, dep.ID)
			p.dependencies = append(p.dependencies, dep)
			if c.packages[dep] == nil {
				child := &sourceStartupPackage{selected: dep, path: append(slices.Clone(p.path), dep.ID)}
				if len(child.path) > c.limits.depth {
					return fail("imports", regionError("dependency depth budget exhausted"))
				}
				c.packages[dep] = child
				queue = append(queue, child)
			}
		}
		if len(listed) != 0 || len(selected.Imports) != len(imports) {
			return fail("imports", regionError("selected dependency graph disagrees"))
		}
		for _, dep := range selected.Imports {
			if dep == nil || !imports[dep.Types] || dep.Types != types.Unsafe && c.pkgs[dep.Types] != dep {
				return fail("imports", regionError("loader import binding disagrees"))
			}
			delete(imports, dep.Types)
		}
		if len(imports) != 0 {
			return fail("imports", regionError("loader omitted a typed import"))
		}
	}
	var pending []*sourceStartupPackage
	for _, p := range c.packages {
		pending = append(pending, p)
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].selected.Types.Path() < pending[j].selected.Types.Path() })
	var order []*sourceStartupPackage
	done := map[*packages.Package]bool{}
	for len(pending) != 0 {
		chosen := -1
		for i, p := range pending {
			ready := true
			for _, dep := range p.dependencies {
				if err := c.tick(nil, 0); err != nil {
					return nil, startupFailure(p, sourceStartupSelection, "schedule", err)
				}
				ready = ready && done[dep]
			}
			if ready {
				chosen = i
				break
			}
		}
		if chosen < 0 {
			return nil, startupFailure(root, sourceStartupSelection, "schedule", regionError("cyclic dependency graph"))
		}
		p := pending[chosen]
		done[p.selected] = true
		order = append(order, p)
		pending = append(pending[:chosen], pending[chosen+1:]...)
	}
	return order, nil
}
