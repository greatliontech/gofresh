package closure

import (
	"context"
	"go/types"
	"sort"
	"strings"

	"github.com/greatliontech/gofresh/closure/internal/rta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type attributedReachability struct {
	functions        map[*ssa.Function]bool
	subjectFunctions map[*ssa.Function]bool
	startupFunctions map[*ssa.Function]bool
	// testMainFunctions is the user-TestMain-flow slice of the startup
	// provenance: the one startup flow that can dispatch a test-planted
	// value (after m.Run), so the one whose unattributed invokes widen.
	testMainFunctions map[*ssa.Function]bool
	resolved          map[ssa.CallInstruction]bool
	dynamicTargets    map[ssa.CallInstruction]map[*ssa.Function]bool
	// instantiatedOrigins marks parameterized origins whose materialized
	// instantiations were rooted for this subject: the origin's body
	// scan yields to theirs.
	instantiatedOrigins map[*ssa.Function]bool
	openWorld           bool
	// enumeratedRootSites is the subject root's whole-view caller
	// enumeration when its dynamic-carrying signature closed by it:
	// the sites the closed-value walk crosses to when judging the
	// root's own parameters. Nil for every other subject; subjectRoot
	// names the function the sites call.
	enumeratedRootSites []ssa.CallInstruction
	subjectRoot         *ssa.Function
	// propertyHarnessAudited carries the program-level audit verdict for
	// the property harness into the per-subject walks: the closed-value
	// arms consult it so no admission outlives the audit.
	propertyHarnessAudited bool
}

// attributedReachableSets runs package-local RTA once and projects its masks
// back into the reachable set expected by the existing per-subject analyzer.
func attributedReachableSets(ctx context.Context, prog *program, subjects []Subject) ([]attributedReachability, error) {
	roots := make(map[*ssa.Function]uint64)
	allMasks := ^uint64(0)
	if len(subjects) < 64 {
		allMasks = 1<<len(subjects) - 1
	}
	var testMasks uint64
	var allFunctions map[*ssa.Function]bool
	instantiated := map[uint64]map[*ssa.Function]bool{}
	for i, subject := range subjects {
		mask := uint64(1) << i
		root := prog.Roots[subject.Symbol]
		// A parameterized body is open over type parameters and cannot
		// enter the runtime-type walk (REQ-closure-analysis): it is never
		// a traversal root itself. A constraint-bounded generic instead
		// roots every materialized instantiation - each dispatches
		// concretely, so instantiation-reached content enters the
		// subject's reachable set (and through it the observability
		// effect walk). An unbounded generic roots
		// nothing: its signature reads open-world and
		// observability refuses; either way the origin fold below keeps
		// the declaration in the subject's content.
		switch {
		case !parameterizedBody(root):
			roots[root] |= mask
		case !rootMayReceiveUnknownDynamic(prog, root):
			if allFunctions == nil {
				allFunctions = ssautil.AllFunctions(prog.Prog)
			}
			for fn := range allFunctions {
				if fn != nil && fn != root && fn.Origin() == root {
					roots[fn] |= mask
					// The origin's own body scan yields to the rooted
					// instantiations': each dispatches concretely, so
					// scanning the open-over-T origin beside them would
					// re-widen exactly the sites the rooting resolves.
					if instantiated[mask] == nil {
						instantiated[mask] = map[*ssa.Function]bool{}
					}
					instantiated[mask][root] = true
				}
			}
		}
		if subjectRunsThroughHarness(prog, root) {
			testMasks |= mask
		}
	}
	if prog.TestMain != nil {
		roots[prog.TestMain] |= testMasks
	}
	// The init-root set is subject-independent; only the test-main prepend
	// varies by harness. One derivation serves the RTA roots and every
	// subject's startup provenance.
	initRoots := make([]*ssa.Function, 0, len(prog.Prog.AllPackages()))
	for _, p := range prog.Prog.AllPackages() {
		if isGeneratedTestMainPackage(prog, p) {
			continue
		}
		if init := p.Func("init"); init != nil {
			initRoots = append(initRoots, init)
		}
	}
	for _, init := range initRoots {
		roots[init] |= allMasks
	}
	// Whole-view caller enumeration for signature-open subjects
	// (REQ-closure-analysis): one deterministic pass collects every
	// candidate's references; a subject whose only references are direct
	// static calls with caller-frame-closed dynamic arguments analyzes
	// closed, its enumerated candidates seeded into the walk. Everything
	// else keeps the open world.
	enumClosed := map[int]enumerationClosure{}
	var seeds *rta.Seeds
	openCandidates := map[*ssa.Function]int{}
	for i, subject := range subjects {
		root := prog.Roots[subject.Symbol]
		if root == nil || parameterizedBody(root) || !rootMayReceiveUnknownDynamic(prog, root) {
			continue
		}
		openCandidates[root] = i
	}
	if len(openCandidates) > 0 {
		if allFunctions == nil {
			allFunctions = ssautil.AllFunctions(prog.Prog)
		}
		candidateSet := make(map[*ssa.Function]bool, len(openCandidates))
		for root := range openCandidates {
			candidateSet[root] = true
		}
		callerSites, valueRefs := enumerateCallerReferences(candidateSet, allFunctions)
		for root, i := range openCandidates {
			enc, ok := subjectEnumerationClosure(root, callerSites[root], valueRefs[root])
			if !ok {
				continue
			}
			mask := uint64(1) << i
			if seeds == nil {
				seeds = &rta.Seeds{AddrTaken: map[*ssa.Function]uint64{}}
			}
			for fn := range enc.addrTaken {
				seeds.AddrTaken[fn] |= mask
			}
			for _, t := range enc.types {
				seeds.RuntimeTypes = append(seeds.RuntimeTypes, rta.TypeSeed{Type: t, Masks: mask})
			}
			enumClosed[i] = enc
		}
	}
	res, err := rta.Analyze(ctx, roots, seeds)
	if err != nil {
		return nil, err
	}
	// Fold each parameterized origin into the result under its subject's
	// mask: its declaration is the subject's own source — the subject's
	// content must move when the generic body moves — while its body was
	// never traversed.
	for i, subject := range subjects {
		if origin := prog.Roots[subject.Symbol]; parameterizedBody(origin) {
			res.Reachable[origin] |= uint64(1) << i
		}
	}
	reachable := make([]attributedReachability, len(subjects))
	harnessAudited := propertyHarnessAuditedProg(prog)
	userPaths := userModulePaths(prog.Pkgs)
	for i := range reachable {
		enc, enumerated := enumClosed[i]
		reachable[i] = attributedReachability{
			functions:              make(map[*ssa.Function]bool, len(res.Reachable)),
			resolved:               make(map[ssa.CallInstruction]bool, len(res.Resolved)),
			dynamicTargets:         make(map[ssa.CallInstruction]map[*ssa.Function]bool),
			instantiatedOrigins:    instantiated[uint64(1)<<i],
			openWorld:              !enumerated && rootMayReceiveUnknownDynamic(prog, prog.Roots[subjects[i].Symbol]),
			enumeratedRootSites:    enc.sites,
			subjectRoot:            prog.Roots[subjects[i].Symbol],
			propertyHarnessAudited: harnessAudited,
		}
		mask := uint64(1) << i
		subjectRoot := prog.Roots[subjects[i].Symbol]
		// Startup provenance is package initializers alone: user
		// test-main flow classifies within subject-time observation -
		// the test log installs in the toolchain-generated test-main
		// package's initializer, after every dependency initializer and
		// before the user test main, so user test-main reads are
		// bracketed observation inputs while initializer reads stay
		// genuinely pre-bracket (REQ-closure-observability-analysis).
		// The flow keeps its own slice below for the dispatch widen.
		startupRoots := initRoots
		// The subject's provenance roots are exactly the roots its mask
		// was given: for a bounded generic those are its materialized
		// instantiations, so the effect walk sees every dispatch-reached
		// site the subject's reachable set carries — granting observability from
		// the origin alone would answer without ever seeing them
		// (REQ-closure-analysis's parameterized-subject arm,
		// REQ-closure-observability-analysis).
		subjectProvenance := []*ssa.Function{subjectRoot}
		if len(instantiated[mask]) > 0 {
			subjectProvenance = subjectProvenance[:0]
			for fn := range allFunctions {
				if fn != nil && fn != subjectRoot && fn.Origin() == subjectRoot {
					subjectProvenance = append(subjectProvenance, fn)
				}
			}
		}
		reachable[i].subjectFunctions, err = provenanceReachable(ctx, subjectProvenance, mask, res, harnessAudited, userPaths)
		if err != nil {
			return nil, err
		}
		reachable[i].startupFunctions, err = provenanceReachable(ctx, startupRoots, mask, res, harnessAudited, userPaths)
		if err != nil {
			return nil, err
		}
		if prog.TestMain != nil && subjectRunsThroughHarness(prog, subjectRoot) {
			reachable[i].testMainFunctions, err = provenanceReachable(ctx, []*ssa.Function{prog.TestMain}, mask, res, harnessAudited, userPaths)
			if err != nil {
				return nil, err
			}
		}
		for fn, masks := range res.Reachable {
			if masks&mask != 0 {
				reachable[i].functions[fn] = true
			}
		}
		for site, masks := range res.Resolved {
			if masks&mask != 0 {
				reachable[i].resolved[site] = true
			}
		}
		for site, targets := range res.Targets {
			callee := site.Common().StaticCallee()
			if !reachable[i].functions[site.Parent()] || callee != nil && funcPkgPath(callee) == "testing" {
				continue
			}
			for target, masks := range targets {
				if masks&mask != 0 && reachable[i].functions[target] {
					projected := reachable[i].dynamicTargets[site]
					if projected == nil {
						projected = make(map[*ssa.Function]bool)
						reachable[i].dynamicTargets[site] = projected
					}
					projected[target] = true
				}
			}
		}
	}
	return reachable, nil
}

func isTestingMRun(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	// The disjunction is order-free; the structural arm is checked first
	// because it needs no rendering, and only a non-testing-package name
	// pays the RelString render for the wrapper/thunk forms the string
	// arm exists to catch.
	if fn.Signature != nil && fn.Signature.Recv() != nil && funcPkgPath(fn) == "testing" && fn.Name() == "Run" &&
		strings.Contains(types.TypeString(fn.Signature.Recv().Type(), nil), "testing.M") {
		return true
	}
	// "testing.M).Run" in the rendered string always begins inside the
	// name portion (the receiver ends at ")."), so a name without "Run"
	// can never match — synthetic wrappers ("Run$bound", "Run$thunk")
	// keep it, and they may lack package identity, so the name is the
	// only allocation-free gate that loses nothing.
	if !strings.Contains(fn.Name(), "Run") {
		return false
	}
	return strings.Contains(fn.String(), "testing.M).Run")
}

// auditedHarnessSubtestDriver reports whether a function is the
// harness's subtest driver - exactly (*testing.T).Run and
// (*testing.B).Run, matched by receiver and name. The driver allocates
// a child harness handle, prints run-boundary bytes into the recorded
// output, keeps write-only harness bookkeeping no testing API hands
// back, consults run-filter state that shapes selection and
// recorded-output bytes only, and runs the caller-supplied callback -
// whose body is walked and classified at its own sites - on a
// harness-managed goroutine it waits for, returning only an outcome
// bit. Receiver discrimination is load-bearing: (*testing.M).Run is
// the test-main driver and (*testing.F).Fuzz dispatches its target
// reflectively over corpus files - both keep their classifications
// (REQ-closure-observability-analysis).
func auditedHarnessSubtestDriver(fn *ssa.Function) bool {
	if fn == nil || fn.Name() != "Run" || funcPkgPath(fn) != "testing" {
		return false
	}
	if fn.Signature == nil || fn.Signature.Recv() == nil {
		return false
	}
	recv := fn.Signature.Recv().Type()
	if ptr, ok := types.Unalias(recv).(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	named, ok := types.Unalias(recv).(*types.Named)
	return ok && named.Obj() != nil && (named.Obj().Name() == "T" || named.Obj().Name() == "B")
}

// harnessFuzzDriver reports (*testing.F).Fuzz - never admitted (its
// target dispatches reflectively over corpus files), but its
// harness-internal body is cut from the walk so the refusal names the
// driver itself rather than the harness's own formatting internals
// (REQ-closure-observability-analysis).
func harnessFuzzDriver(fn *ssa.Function) bool {
	if fn == nil || fn.Name() != "Fuzz" || funcPkgPath(fn) != "testing" {
		return false
	}
	if fn.Signature == nil || fn.Signature.Recv() == nil {
		return false
	}
	recv := fn.Signature.Recv().Type()
	if ptr, ok := types.Unalias(recv).(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	named, ok := types.Unalias(recv).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Name() == "F"
}

// enumerationClosure is one signature-open subject's whole-view caller
// closure (REQ-closure-analysis): the direct static call sites that are
// its only references, plus the dispatch candidates those sites pass —
// closed function values seeded address-taken, materialized concrete
// types seeded into the runtime-type walk — so everything an enumerable
// caller can hand the subject is analyzed view content.
type enumerationClosure struct {
	sites     []ssa.CallInstruction
	addrTaken map[*ssa.Function]bool
	types     []types.Type
}

// enumerateCallerReferences makes one deterministic pass over the whole
// analyzed program, collecting for each candidate root its direct static
// call sites and whether any other reference exists — an address
// capture, a stored value, a dynamic use, or a call held by a body the
// enumeration cannot judge as a caller. Function order is sorted so
// site order, and every judgment derived from it, is run-to-run stable.
func enumerateCallerReferences(candidates map[*ssa.Function]bool, all map[*ssa.Function]bool) (map[*ssa.Function][]ssa.CallInstruction, map[*ssa.Function]bool) {
	ordered := make([]*ssa.Function, 0, len(all))
	for fn := range all {
		if fn != nil {
			ordered = append(ordered, fn)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].String() < ordered[j].String() })
	sites := make(map[*ssa.Function][]ssa.CallInstruction)
	valueRef := make(map[*ssa.Function]bool)
	var space [16]*ssa.Value
	for _, fn := range ordered {
		// A body the enumeration cannot judge as a caller — a synthetic
		// function (wrapper re-dispatch, package initializer) or a
		// parameterized origin (open over type parameters) — makes any
		// call it holds a refusing reference, exactly like a value
		// capture: its arguments are never judged, so they must never
		// count as an enumerated site.
		judgeable := fn.Synthetic == "" && !parameterizedBody(fn)
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				rands := instr.Operands(space[:0])
				if site, ok := instr.(ssa.CallInstruction); ok && site.Common() != nil {
					if callee := site.Common().StaticCallee(); callee != nil && candidates[callee] {
						if judgeable {
							sites[callee] = append(sites[callee], site)
						} else {
							valueRef[callee] = true
						}
					}
					if !site.Common().IsInvoke() {
						// The callee operand is the call itself, not a
						// value reference.
						rands = rands[1:]
					}
				}
				for _, op := range rands {
					if g, ok := (*op).(*ssa.Function); ok && candidates[g] {
						valueRef[g] = true
					}
				}
			}
		}
	}
	return sites, valueRef
}

// subjectEnumerationClosure judges one open-signature root against its
// collected references: closed exactly when references are direct static
// calls only, at least one exists, and every dynamic-reaching argument
// position closes in the calling function's own frame (the caller-local
// walk — the caller's parameters, loads, and call results refuse).
func subjectEnumerationClosure(root *ssa.Function, sites []ssa.CallInstruction, valueRef bool) (enumerationClosure, bool) {
	// Functions only: a method's interface invocability leaves no
	// reference the scan can see (a pointer-receiver invoke synthesizes
	// no wrapper and takes no address), so a receiver-bearing subject
	// keeps its signature-shaped open world.
	if root.Signature != nil && root.Signature.Recv() != nil {
		return enumerationClosure{}, false
	}
	if valueRef || len(sites) == 0 {
		return enumerationClosure{}, false
	}
	enc := enumerationClosure{sites: sites, addrTaken: map[*ssa.Function]bool{}}
	for _, site := range sites {
		args := site.Common().Args
		if len(args) != len(root.Params) {
			return enumerationClosure{}, false
		}
		for i, param := range root.Params {
			if !typeMayCarryDynamic(param.Type(), make(map[types.Type]bool)) {
				continue
			}
			if !locallyClosedDynamicValue(args[i], make(map[ssa.Value]bool)) {
				return enumerationClosure{}, false
			}
			collectClosedDynamicSeeds(args[i], &enc, map[ssa.Value]bool{})
		}
	}
	return enc, true
}

// collectClosedDynamicSeeds walks an already-closed argument value and
// gathers what it can hand the subject: function values become dispatch
// candidates, materialized concrete types enter the runtime-type walk.
// The case set mirrors the closed-value walk that admitted the value;
// bindings of ordinary closures are not collected — a free-variable
// dispatch inside the body refuses per-site when the body is scanned.
func collectClosedDynamicSeeds(value ssa.Value, enc *enumerationClosure, seen map[ssa.Value]bool) {
	if value == nil || seen[value] {
		return
	}
	seen[value] = true
	switch v := value.(type) {
	case *ssa.Function:
		enc.addrTaken[v] = true
	case *ssa.MakeClosure:
		if fn, ok := v.Fn.(*ssa.Function); ok {
			enc.addrTaken[fn] = true
		}
	case *ssa.MakeInterface:
		enc.types = append(enc.types, v.X.Type())
		if _, isFunc := types.Unalias(v.X.Type()).Underlying().(*types.Signature); isFunc {
			collectClosedDynamicSeeds(v.X, enc, seen)
		}
	case *ssa.ChangeInterface:
		collectClosedDynamicSeeds(v.X, enc, seen)
	case *ssa.TypeAssert:
		collectClosedDynamicSeeds(v.X, enc, seen)
	case *ssa.ChangeType:
		collectClosedDynamicSeeds(v.X, enc, seen)
	case *ssa.Convert:
		collectClosedDynamicSeeds(v.X, enc, seen)
	case *ssa.Extract:
		collectClosedDynamicSeeds(v.Tuple, enc, seen)
	case *ssa.Phi:
		for _, edge := range v.Edges {
			collectClosedDynamicSeeds(edge, enc, seen)
		}
	}
}

func rootMayReceiveUnknownDynamic(prog *program, root *ssa.Function) bool {
	if root == nil || root.Signature == nil {
		return true
	}
	// A parameterized subject's openness is decided by its constraints,
	// consulted on the type-parameter list itself - a zero-parameter
	// generic (func Value[T any]() int) reads closed through Params
	// alone, so the params walk below can never be the whole answer. A
	// constraint that provably bounds its type set away from dynamic
	// carriers closes the caller's instantiation choice: every in-binary
	// instantiation then dispatches concretely and roots the walk.
	// Anything unbounded (any, comparable, a method-bearing constraint)
	// keeps the forced open world
	// (REQ-closure-analysis's parameterized-subject arm).
	if parameterizedBody(root) && !typeParamListsBoundAwayFromDynamic(root) {
		return true
	}
	if subjectRunsThroughHarness(prog, root) && isHarnessSubjectSignature(root.Signature) {
		return false
	}
	// One fresh map per parameter: sharing across parameters would let
	// one walk's marks short-circuit another's (a constraint interface
	// marked by a bounding evaluation reading clean as a later value
	// type); within one parameter's evaluation the map is shared - the
	// cycle guard for recursive constraints.
	if recv := root.Signature.Recv(); recv != nil && typeMayCarryDynamic(recv.Type(), make(map[types.Type]bool)) {
		return true
	}
	params := root.Signature.Params()
	for i := 0; params != nil && i < params.Len(); i++ {
		if typeMayCarryDynamic(params.At(i).Type(), make(map[types.Type]bool)) {
			return true
		}
	}
	return false
}

func isHarnessSubjectSignature(sig *types.Signature) bool {
	if sig == nil || sig.Recv() != nil || sig.Params().Len() != 1 {
		return false
	}
	pointer, ok := sig.Params().At(0).Type().(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := pointer.Elem().(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "testing" {
		return false
	}
	switch named.Obj().Name() {
	case "T", "B", "F", "M":
		return true
	default:
		return false
	}
}

func typeMayCarryDynamic(t types.Type, seen map[types.Type]bool) bool {
	if t == nil || seen[t] {
		return false
	}
	seen[t] = true
	switch t := types.Unalias(t).(type) {
	case *types.Basic:
		return t.Kind() == types.UnsafePointer
	case *types.Interface, *types.Signature:
		return true
	case *types.TypeParam:
		// The evaluation's own map is shared into the bounding walk: the
		// marks placed at each walk's entry are the cycle guards for
		// self- and mutually-referential constraints (~[]A on A is legal
		// Go). The interface-mark cut decides the recursive cases -
		// pessimistically, not-bounded, so a recursive constraint reads
		// open; the type-parameter mark's clean cut only governs term
		// structure inside one evaluation, where a carrier-free cycle
		// path adds no carrier. Cross-parameter decoupling lives at the
		// walk entries, which hand each parameter a fresh map.
		return !constraintBoundsAwayFromDynamic(t.Constraint(), seen)
	case *types.Named:
		return typeMayCarryDynamic(t.Underlying(), seen)
	case *types.Pointer:
		return typeMayCarryDynamic(t.Elem(), seen)
	case *types.Slice:
		return typeMayCarryDynamic(t.Elem(), seen)
	case *types.Array:
		return typeMayCarryDynamic(t.Elem(), seen)
	case *types.Map:
		return typeMayCarryDynamic(t.Key(), seen) || typeMayCarryDynamic(t.Elem(), seen)
	case *types.Chan:
		return typeMayCarryDynamic(t.Elem(), seen)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if typeMayCarryDynamic(t.Field(i).Type(), seen) {
				return true
			}
		}
	case *types.Tuple:
		for i := 0; i < t.Len(); i++ {
			if typeMayCarryDynamic(t.At(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

// TypeParamBoundsAwayFromDynamic reports whether one type parameter's
// constraint provably bounds its type set away from dynamic carriers -
// the openness question a parameterized subject asks per parameter,
// shared with the view tier so both tiers give one answer
// (REQ-closure-analysis's parameterized-subject arm).
func TypeParamBoundsAwayFromDynamic(tp *types.TypeParam) bool {
	if tp == nil {
		return false
	}
	return constraintBoundsAwayFromDynamic(tp.Constraint(), make(map[types.Type]bool))
}

// typeParamListsBoundAwayFromDynamic reports whether every type parameter
// of fn (function and receiver lists both) carries a constraint that
// provably bounds its type set away from dynamic carriers.
func typeParamListsBoundAwayFromDynamic(fn *ssa.Function) bool {
	for _, list := range []*types.TypeParamList{fn.TypeParams(), fn.Signature.RecvTypeParams()} {
		for i := 0; list != nil && i < list.Len(); i++ {
			if !constraintBoundsAwayFromDynamic(list.At(i).Constraint(), make(map[types.Type]bool)) {
				return false
			}
		}
	}
	return true
}

// constraintBoundsAwayFromDynamic reports whether a type parameter's
// constraint provably bounds its type set away from dynamic carriers: the
// complete interface is methodless (a constraint method is a dispatch
// surface this analysis does not narrow), and at least one embedded
// element bounds the set - a union or specific type whose every term is
// free of interface, function, channel, and unsafe reach, or an embedded
// interface that itself bounds. Intersection semantics make one clean
// bounded element sufficient: the type set is the intersection of every
// element's set, so a dirty sibling only shrinks a clean bound, never
// widens it. `any` and `comparable` embed nothing and bound nothing.
func constraintBoundsAwayFromDynamic(constraint types.Type, seen map[types.Type]bool) bool {
	iface, ok := types.Unalias(constraint).Underlying().(*types.Interface)
	if !ok {
		return false
	}
	return interfaceBoundsAwayFromDynamic(iface, seen)
}

func interfaceBoundsAwayFromDynamic(iface *types.Interface, seen map[types.Type]bool) bool {
	if iface == nil || iface.NumMethods() > 0 {
		return false
	}
	if seen[iface] {
		return false
	}
	seen[iface] = true
	bounded := false
	for i := 0; i < iface.NumEmbeddeds(); i++ {
		switch e := types.Unalias(iface.EmbeddedType(i)).(type) {
		case *types.Union:
			clean := true
			for j := 0; j < e.Len(); j++ {
				// A tilde term (~T) admits every type whose underlying
				// is T's underlying: structurally identical carriers, so
				// the structural walk of the term type answers for the
				// whole approximation set. Extra methods on a defined
				// type in that set are unreachable through a methodless
				// constraint.
				if typeMayCarryDynamic(e.Term(j).Type(), seen) {
					clean = false
					break
				}
			}
			if clean {
				bounded = true
			}
		default:
			if under, ok := types.Unalias(e).Underlying().(*types.Interface); ok {
				if interfaceBoundsAwayFromDynamic(under, seen) {
					bounded = true
				}
				continue
			}
			// A single specific-type element (interface{ int }).
			if !typeMayCarryDynamic(e, seen) {
				bounded = true
			}
		}
	}
	return bounded
}

func isGeneratedTestMainPackage(prog *program, pkg *ssa.Package) bool {
	return prog != nil && pkg != nil && pkg.Pkg != nil && pkg.Pkg.Name() == "main" && pkg.Pkg.Path() == prog.PkgPath+".test"
}

// tier2Reachable analyzes one attributed reachability set: effects,
// widen, and verdict, with the cross-boundary fresh-path analysis always
// in force (only the observability walk consults effect.observable).
func provenanceReachable(ctx context.Context, roots []*ssa.Function, mask uint64, result *rta.Result, harnessAudited bool, userPaths map[string]bool) (map[*ssa.Function]bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reachable := make(map[*ssa.Function]bool)
	scanned := make(map[*ssa.Function]bool)
	queue := append([]*ssa.Function(nil), roots...)
	for len(queue) != 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fn := queue[0]
		queue = queue[1:]
		if fn == nil || scanned[fn] || result.Reachable[fn]&mask == 0 {
			continue
		}
		scanned[fn] = true
		// A harness frame - the standard testing package or an audited
		// property harness - is never subject content; its dispatch
		// targets still traverse, so the caller-supplied callbacks it
		// runs stay subject flow (REQ-closure-observability-analysis).
		harnessFrame := funcPkgPath(fn) == "testing" || harnessAudited && propertyHarnessPath(funcPkgPath(fn))
		if !harnessFrame {
			reachable[fn] = true
		}
		for _, block := range fn.Blocks {
			for _, instruction := range block.Instrs {
				site, ok := instruction.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				callee := site.Common().StaticCallee()
				if isTestingMRun(callee) {
					continue
				}
				if callee != nil {
					calleePath := funcPkgPath(callee)
					calleeHarness := calleePath == "testing" || harnessAudited && propertyHarnessPath(calleePath)
					if !harnessFrame || calleeHarness {
						queue = append(queue, callee)
					}
					if calleeHarness && !harnessFrame {
						continue
					}
				}
				for target, targetMask := range result.Targets[site] {
					if targetMask&mask == 0 || isTestingMRun(target) {
						continue
					}
					targetPath := funcPkgPath(target)
					targetHarness := targetPath == "testing" || harnessAudited && propertyHarnessPath(targetPath)
					// User callbacks dispatched from harness frames stay
					// in the walk by the load's module facts, never by
					// path shape: a dotless user module's callback
					// classified standard here silently vanished from
					// the startup and test-main walks - the
					// dotless-module soundness family.
					if !harnessFrame || targetHarness || userPaths[targetPath] || !isStdImportPath(targetPath) {
						queue = append(queue, target)
					}
				}
			}
		}
	}
	return reachable, nil
}

// userModulePaths collects every loaded package path the module graph
// proves user code: both load configs request NeedModule, so in module
// mode a nil Module is exactly the standard library, and these paths
// are the code no path-shape heuristic may classify standard - a user
// module is legally named without a dot (the dotless-module soundness
// family).
func userModulePaths(pkgs []*packages.Package) map[string]bool {
	user := map[string]bool{}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.Module != nil {
			user[p.PkgPath] = true
		}
	})
	return user
}
