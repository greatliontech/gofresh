package closure

import (
	"go/types"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// The property-testing harness is audited surface exactly as the
// standard testing package is: its bodies are cut from every walk and
// from the package-scan backstop, because everything ambient in them
// is the harness's own protocol - the run configuration it reads
// surfaces in its harness-log summary line on every outcome, its
// clock reads pace the run and surface in the same line, its failure
// artifacts are output-only reproduction files, and its value
// generation is process-local PRNG state seeded by that same
// log-surfaced configuration. The audit is sound only paired with a
// boundary gate on every flow that can call into the harness: each
// dynamic-carrying argument must be judged closed - by the
// subject-closed value walk, as the harness's own handed-in handle, as
// a gate-passing harness call result, or as a locally built variadic
// of judged elements - so the only callables the harness's unscanned
// bodies can ever dispatch are structurally closed functions the
// reachability walk already scans. The gate-passing call-result arm
// carries a second audited property the subject-determined dispatch
// admission leans on: every value the audited releases return is a
// concrete generator, a plain value, or a wrapped callback - never an
// interface whose dynamic type escapes the caller's own flow - so a
// harness result feeding any dispatch operand pins no type outside
// the subject's mask. Audited surfaces: (*Generator[V]).Draw is
// interface-typed only under the caller's own instantiation, and the
// reflective Make[V] yields a nil interface for interface types,
// which panics on dispatch rather than pinning a foreign type. A harness function reached as a
// dynamic target keeps the conservative refusal: no gate can judge a
// dispatched-to boundary. The audit is version-gated: an unlisted
// harness release keeps the package's ordinary classification
// (REQ-closure-observability-analysis).

// propertyHarnessPath reports whether pkgPath is the property-testing
// harness package. Exactly pgregory.net/rapid.
func propertyHarnessPath(pkgPath string) bool {
	return pkgPath == "pgregory.net/rapid"
}

// auditedPropertyHarnessVersion reports whether a registry release of
// the property-harness package is one the audit covers. An unlisted
// release keeps the package's ordinary classification - fail-closed;
// local source is judged separately (main module or replace - a
// deliberate local choice, not a silent registry upgrade).
func auditedPropertyHarnessVersion(version string) bool {
	return version == "v1.3.0"
}

// auditedPropertyHarnessModule is the one module-level audit judgment
// every arm shares: an audited release, or deliberate local source.
// The analyzer's listing side and the attribution walk's program side
// both collapse to this - divergent verdicts would leave harness
// bodies both unattributed and unscanned, fail-open.
func auditedPropertyHarnessModule(version string, main, replaced bool) bool {
	return auditedPropertyHarnessVersion(version) || main || replaced
}

// propertyHarnessFact is the admitted harness fact the package-scan
// tier records for an audited harness dependency: the audit admits
// OBSERVATION, never purity - a property run's outcome depends on the
// harness's log-surfaced run configuration, so a package reaching the
// harness must stay unverifiable-by-hash and prove itself through the
// observation path, exactly as a package reaching the standard
// harness's classified surface does.
func propertyHarnessFact() externalEffect {
	effect := symbolExternalEffect(externalEffectTestRuntime, "pgregory.net/rapid", "Check", "reaches the audited property-testing harness pgregory.net/rapid")
	effect.observable = true
	return effect
}

// propertyHarnessAudited reports whether pkgPath is the property
// harness at an audited version or from deliberate local source,
// judged from the analyzer's package listing. The rule must stay
// byte-identical in judgment to propertyHarnessAuditedProg: the walk
// arms and the attribution arm consulting different verdicts for one
// package would leave bodies both unattributed and unscanned -
// fail-open.
func (a *tier2Analyzer) propertyHarnessAudited(pkgPath string) bool {
	if !propertyHarnessPath(pkgPath) {
		return false
	}
	meta := a.metaByPath[pkgPath]
	if meta == nil || meta.Module == nil {
		return false
	}
	// Only a DIRECTORY replace is local source: a version replace
	// (=> pgregory.net/rapid vX) is still a registry release and keeps
	// the version gate.
	return auditedPropertyHarnessModule(meta.Module.Version, meta.Module.Main,
		meta.Module.Replace != nil && meta.Module.Replace.Version == "")
}

// propertyHarnessHandleType reports the harness's handed-in handle
// types: the property harness's own T and the standard harness's
// T/B/TB. Handle values are constructed only by their harness
// (unexported field surfaces) and handed per-invocation into user
// code; the handle admission applies at PARAMETER position only - a
// handle loaded from shared state is a sibling invocation's value and
// refuses like any other load. Generator and other harness-owned
// value types are deliberately NOT handles: they are user-held values
// whose provenance must be judged wherever they cross
// (REQ-closure-observability-analysis).
func propertyHarnessHandleType(t types.Type) bool {
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	switch named.Obj().Pkg().Path() {
	case "pgregory.net/rapid":
		return named.Obj().Name() == "T"
	case "testing":
		name := named.Obj().Name()
		return name == "T" || name == "B" || name == "TB"
	}
	return false
}

// harnessHandleValue chases interface and representation hops to a
// parameter carrying a harness handle type.
func harnessHandleValue(v ssa.Value) bool {
	for {
		switch x := v.(type) {
		case *ssa.Parameter:
			return propertyHarnessHandleType(x.Type())
		case *ssa.MakeInterface:
			v = x.X
		case *ssa.ChangeInterface:
			v = x.X
		case *ssa.ChangeType:
			v = x.X
		case *ssa.Convert:
			v = x.X
		case *ssa.TypeAssert:
			v = x.X
		default:
			return false
		}
	}
}

// propertyHarnessClosedValue is the boundary gate's per-value
// judgment: the harness's own handed-in handle, a subject-closed
// value, or a locally built variadic slice of judged elements.
func propertyHarnessClosedValue(v ssa.Value, fp *freshParamAnalysis) bool {
	if harnessHandleValue(v) {
		return true
	}
	if subjectClosedDynamicValue(v, make(map[ssa.Value]bool), fp) {
		return true
	}
	return harnessVariadicClosed(v, fp)
}

// harnessVariadicClosed judges the SSA shape of a call-site-built
// variadic argument (rt.Logf("%v", n) and kin): a slice over a local
// alloc whose only uses are the element stores and this slice, every
// stored element judged by the gate's own per-value rule.
func harnessVariadicClosed(v ssa.Value, fp *freshParamAnalysis) bool {
	slice, ok := v.(*ssa.Slice)
	if !ok {
		return false
	}
	alloc, ok := slice.X.(*ssa.Alloc)
	if !ok {
		return false
	}
	refs := alloc.Referrers()
	if refs == nil {
		return false
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.Slice:
			if r != slice {
				return false
			}
		case *ssa.IndexAddr:
			irefs := r.Referrers()
			if irefs == nil {
				return false
			}
			for _, ir := range *irefs {
				store, ok := ir.(*ssa.Store)
				if !ok || store.Addr != r {
					return false
				}
				if !propertyHarnessClosedValue(store.Val, fp) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// propertyHarnessClosedArgs is the boundary gate: every
// dynamic-carrying argument of a static call into the harness must
// pass the per-value judgment. The harness's bodies are never
// scanned, so a callable crossing into them is judged here or not at
// all.
func propertyHarnessClosedArgs(c *ssa.CallCommon, fp *freshParamAnalysis) bool {
	if c == nil {
		return false
	}
	for _, arg := range c.Args {
		if arg == nil || !typeMayCarryDynamic(fp.selectionAudited, arg.Type(), map[types.Type]bool{}) {
			continue
		}
		if !propertyHarnessClosedValue(arg, fp) {
			return false
		}
	}
	return true
}

// localHarnessView carries only the program-level audit bit into the
// local closed-value walk: an empty analysis refuses every parameter
// crossing exactly as a nil one does, so local dispatch semantics stay
// intact while the harness call-result arm can still consult the
// audit.
func (a *tier2Analyzer) localHarnessView() *freshParamAnalysis {
	if a.fresh == nil || !a.fresh.propertyHarnessAudited {
		return nil
	}
	return &freshParamAnalysis{propertyHarnessAudited: true, selectionAudited: a.h.SelectionAudited()}
}

// propertyHarnessClosedResult reports whether a call value is a
// gate-passing static call into the property harness: its result is
// closed for dispatch judgment (rapid.MakeCheck's returned callback
// feeding (*testing.T).Run or a computed call is the driving shape,
// and generator constructors' results cross the gate at their own
// consuming call sites the same way).
func propertyHarnessClosedResult(call *ssa.Call, fp *freshParamAnalysis) bool {
	// Audit-gated like every other arm: without the audited bit carried
	// by the subject's own analysis, no third-party call result is ever
	// closed - an unlisted release's exported functions could return
	// callables from shared mutable state.
	if fp == nil || !fp.propertyHarnessAudited {
		return false
	}
	if call == nil || call.Common() == nil || call.Common().IsInvoke() {
		return false
	}
	callee := call.Common().StaticCallee()
	return callee != nil && propertyHarnessPath(funcPkgPath(callee)) &&
		propertyHarnessClosedArgs(call.Common(), fp)
}

// propertyHarnessAuditedProg reports whether the loaded program's
// property-harness module (if any) is at an audited version or from
// deliberate local source - the program-level twin of the analyzer's
// listing-based judgment, for the attribution walk. The judgment must
// stay byte-identical to propertyHarnessAudited's.
func propertyHarnessAuditedProg(p *program) bool {
	if p == nil {
		return false
	}
	audited := false
	// The harness is a dependency: the loaded roots are the subject
	// package's variants, so the judgment walks the whole import graph.
	packages.Visit(p.Pkgs, func(pkg *packages.Package) bool {
		if pkg == nil || !propertyHarnessPath(pkg.PkgPath) {
			return true
		}
		m := pkg.Module
		audited = m != nil && auditedPropertyHarnessModule(m.Version, m.Main,
			m.Replace != nil && m.Replace.Version == "")
		return false
	}, nil)
	return audited
}
