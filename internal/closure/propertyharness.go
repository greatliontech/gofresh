package closure

import (
	"context"
	"go/types"
	"strconv"
	"strings"
	"time"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"

	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/closure/internal/propharness"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/trace"
)

// The property-testing harness is summarized at walk and package-scan
// boundaries exactly when a mechanical source verification over its
// selected implementation proves its harness protocol: run
// configuration is read only during initialization from RAPID_-prefixed
// environment variables and rapid.-prefixed flags into unmutated
// package-private scalars and surfaced in its TB.Logf summary line,
// wall-clock reads pace execution without timer sleeps, failure
// artifacts are reproduction files, internal caches key only on
// carrier-free inputs without retaining caller callables, T exposes no
// exported fields, and every exported function or method result stays
// within the closed harness return grammar. The summary is sound only
// paired with the boundary gate on every static call into the harness:
// each dynamic-carrying argument must be judged closed - by the
// subject-closed value walk, as the harness's own handed-in handle, as
// a gate-passing harness call result, or as a locally built variadic of
// judged elements - so the only callables the harness's bodies can
// dispatch are structurally closed functions the reachability walk
// already scans. A named harness function reached via a computed
// function-value call keeps the conservative refusal, whereas in subject
// flow a named harness method reached via interface invoke is admitted
// only when the invoke arguments pass the boundary gate and every
// non-harness boxing of its receiver origin occurs in subject flow over
// a gate-passing value. Version pins and local-source checkouts carry no
// special trust; an implementation that violates any structural gate
// retains its ordinary classification
// (REQ-closure-observability-property-harness).

const propertyHarnessSummaryKeyPrefix = "gofresh/property-harness@6:"

var pinnedPropertyHarnessMemo cachefile.SyncMemo[bool]

func buildPinnedHarnessMemoKey(frontend, toolchainContent, admissionPolicy, pin string, packageEnv, buildFlags, goFiles []string) string {
	var b strings.Builder
	b.WriteString(propertyHarnessSummaryKeyPrefix)
	writeField := func(s string) {
		b.WriteString(strconv.Itoa(len(s)))
		b.WriteByte(':')
		b.WriteString(s)
	}
	writeSlice := func(items []string) {
		b.WriteString(strconv.Itoa(len(items)))
		b.WriteByte('#')
		for _, item := range items {
			writeField(item)
		}
	}
	writeField(frontend)
	writeField(toolchainContent)
	writeField(admissionPolicy)
	writeSlice(packageEnv)
	writeSlice(buildFlags)
	writeField(pin)
	writeSlice(goFiles)
	return b.String()
}

func verifyPropertyHarnessPackageTraced(ctx context.Context, audited bool, pkg *packages.Package) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	var start time.Time
	tracing := trace.Enabled(ctx, trace.DomainClosure, propharness.ModulePath)
	if tracing {
		start = time.Now()
	}
	ok, reason := propharness.VerifyPackageWithReason(audited, pkg)
	if tracing {
		trace.Emit(ctx, trace.DomainClosure, "propharness.verify.done", propharness.ModulePath,
			trace.Bool("ok", ok),
			trace.String("reason", reason),
			trace.Int64("duration_ns", time.Since(start).Nanoseconds()),
		)
	}
	return ok
}

// propertyHarnessFact is the admitted harness fact the package-scan
// tier records for a mechanically verified harness dependency: the
// verification admits OBSERVATION, never purity - a property run's
// outcome depends on the harness's log-surfaced run configuration, so a
// package reaching the harness must stay unverifiable-by-hash and prove
// itself through the observation path, exactly as a package reaching
// the standard harness's classified surface does.
func propertyHarnessFact() externalEffect {
	effect := symbolExternalEffect(externalEffectTestRuntime, propharness.ModulePath, "Check", "reaches the audited property-testing harness pgregory.net/rapid")
	effect.observable = true
	return effect
}

func listPkgHasNativeOrEmbed(pkg *listPkg) bool {
	if pkg == nil {
		return true
	}
	if hasExternalCgoMeta(pkg) || hasCgoCallbackBlindspot(pkg) {
		return true
	}
	return len(pkg.CgoFiles) > 0 ||
		len(pkg.CFiles) > 0 ||
		len(pkg.CXXFiles) > 0 ||
		len(pkg.MFiles) > 0 ||
		len(pkg.HFiles) > 0 ||
		len(pkg.FFiles) > 0 ||
		len(pkg.SFiles) > 0 ||
		len(pkg.SwigFiles) > 0 ||
		len(pkg.SwigCXXFiles) > 0 ||
		len(pkg.SysoFiles) > 0 ||
		len(pkg.EmbedFiles) > 0 ||
		len(pkg.EmbedPatterns) > 0 ||
		len(pkg.TestEmbedPatterns) > 0 ||
		len(pkg.XTestEmbedPatterns) > 0
}

// propertyHarnessAudited reports whether pkgPath is the mechanically
// verified property harness for the analyzer's loaded program. It
// delegates to propertyHarnessAuditedProg so the walk arms and the
// attribution arm consult the exact same verdict.
func (a *tier2Analyzer) propertyHarnessAudited(pkgPath string) bool {
	if a == nil || a.h == nil || !propharness.IsHarnessPath(pkgPath) {
		return false
	}
	meta := a.metaByPath[pkgPath]
	if meta == nil || meta.Module == nil || listPkgHasNativeOrEmbed(meta) {
		return false
	}
	return propertyHarnessAuditedProg(a.h.SelectionAudited(), a.prog)
}

// propertyHarnessAuditedListPkg evaluates the mechanical property-harness
// verification for a dependency node in the maximal package-scan tier.
func (h *Hasher) propertyHarnessAuditedListPkg(callerPkgPath string, pkg *listPkg) bool {
	if h == nil || !h.SelectionAudited() || pkg == nil || pkg.Module == nil || !propharness.IsHarnessPath(pkg.ImportPath) {
		return false
	}
	if listPkgHasNativeOrEmbed(pkg) {
		return false
	}
	cacheKey := pkg.Dir
	if cacheKey == "" {
		cacheKey = "\x00" + callerPkgPath + "\x00" + pkg.ImportPath
	}
	if v, ok := h.harnessVerdict[cacheKey]; ok {
		return v
	}
	recordVerdict := func(v bool) bool {
		if h.harnessVerdict == nil {
			h.harnessVerdict = make(map[string]bool, 1)
		}
		h.harnessVerdict[cacheKey] = v
		return v
	}

	isPinned := pkg.Module.Version != "" && h.pinnedPackage(pkg) && pkg.Module.Dir != ""
	var pinnedKey string
	if isPinned {
		pin := h.modulePin(pkg.Module)
		pinnedKey = buildPinnedHarnessMemoKey(
			AnalyzingFrontend(),
			h.ToolchainContent(),
			h.AdmissionPolicy(),
			pin,
			h.packageEnv,
			h.buildFlags,
			pkg.GoFiles,
		)
		if v, ok := pinnedPropertyHarnessMemo.Load(pinnedKey); ok {
			return recordVerdict(v)
		}
	}

	var candidates []*packages.Package
	seenPkg := map[*packages.Package]bool{}
	collectFromRoots := func(roots []*packages.Package) {
		if len(roots) == 0 {
			return
		}
		packages.Visit(roots, func(p *packages.Package) bool {
			if p == nil {
				return false
			}
			if propharness.IsHarnessPath(p.PkgPath) && p.ForTest == "" && len(p.Syntax) > 0 && p.Types != nil && p.TypesInfo != nil {
				if !seenPkg[p] {
					seenPkg[p] = true
					candidates = append(candidates, p)
				}
			}
			return true
		}, nil)
	}

	if h.viewLoad != nil {
		collectFromRoots(h.viewLoad.Packages())
	}
	if len(candidates) == 0 {
		if p := h.progs[callerPkgPath]; p != nil {
			collectFromRoots(p.Pkgs)
		}
	}
	if len(candidates) == 0 {
		if p := h.progs[propharness.ModulePath]; p != nil {
			collectFromRoots(p.Pkgs)
		}
	}
	if len(candidates) == 0 {
		for _, p := range h.progs {
			if p != nil {
				collectFromRoots(p.Pkgs)
			}
			if len(candidates) > 0 {
				break
			}
		}
	}
	if len(candidates) == 0 && h.testingPackagesOnMiss != nil {
		if p := h.testingPackagesOnMiss(h, callerPkgPath); p != nil {
			collectFromRoots(p.Pkgs)
		}
		if len(candidates) == 0 {
			if p := h.testingPackagesOnMiss(h, propharness.ModulePath); p != nil {
				collectFromRoots(p.Pkgs)
			}
		}
	}
	if len(candidates) == 0 {
		loadDir := h.dir
		pattern := propharness.ModulePath
		if isPinned && pkg.Dir != "" {
			loadDir = pkg.Dir
			pattern = "."
		}
		loaded, err := gotool.LoadPackages(
			h.ctx,
			packages.NeedName|packages.NeedFiles|packages.NeedCompiledGoFiles|packages.NeedEmbedFiles|packages.NeedEmbedPatterns|packages.NeedSyntax|packages.NeedTypes|packages.NeedTypesInfo|packages.NeedImports|packages.NeedModule,
			loadDir,
			h.packageEnv,
			h.buildFlags,
			pattern,
		)
		if err != nil {
			return recordVerdict(false)
		}
		collectFromRoots(loaded)
	}

	if len(candidates) == 0 {
		return recordVerdict(false)
	}
	for _, cand := range candidates {
		if !verifyPropertyHarnessPackageTraced(h.ctx, true, cand) {
			if isPinned && pinnedKey != "" {
				pinnedPropertyHarnessMemo.Store(pinnedKey, false)
			}
			return recordVerdict(false)
		}
	}
	if isPinned && pinnedKey != "" {
		pinnedPropertyHarnessMemo.Store(pinnedKey, true)
	}
	return recordVerdict(true)
}

// propertyHarnessHandleType reports the harness's handed-in handle
// types: the property harness's own T (requiring an unexported-fields
// struct) and the standard harness's T/B/TB. Handle values are
// constructed only by their harness and handed per-invocation into user
// code; the handle admission applies at PARAMETER position only - a
// handle loaded from shared state is a sibling invocation's value and
// refuses like any other load. Generator and other harness-owned value
// types are deliberately NOT handles: they are user-held values whose
// provenance must be judged wherever they cross
// (REQ-closure-observability-property-harness).
func propertyHarnessHandleType(t types.Type) bool {
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	switch named.Obj().Pkg().Path() {
	case propharness.ModulePath:
		if named.Obj().Name() != "T" {
			return false
		}
		st, ok := named.Underlying().(*types.Struct)
		return ok && propharness.StructHasNoExportedFields(st)
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
// value carrying no uncalled named/bound harness callable, or a
// locally built variadic slice of judged elements.
func propertyHarnessClosedValue(v ssa.Value, fp *freshParamAnalysis) bool {
	if harnessHandleValue(v) {
		return true
	}
	if subjectClosedDynamicValue(v, make(map[ssa.Value]bool), fp) {
		return !closedValueCarriesNamedHarnessCallable(v, fp)
	}
	return harnessVariadicClosed(v, fp)
}

func closedValueCarriesNamedHarnessCallable(v ssa.Value, fp *freshParamAnalysis) bool {
	if v == nil || v.Type() == nil || !typeMayCarryCallable(v.Type(), map[types.Type]bool{}) {
		return false
	}
	funcs := make(map[*ssa.Function]bool)
	walkDynamicValue(v, &dynamicValueCollector{
		types: map[types.Type]bool{},
		funcs: funcs,
		seeds: true,
	}, map[ssa.Value]bool{}, nil, resetWalkState(fp))
	for fn := range funcs {
		if fn != nil && fn.Parent() == nil && propharness.IsHarnessPath(funcPkgPath(fn)) {
			return true
		}
	}
	return false
}

func typeMayCarryCallable(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if seen[t] {
		return false
	}
	seen[t] = true
	if propertyHarnessHandleType(t) {
		var named *types.Named
		switch x := t.(type) {
		case *types.Named:
			named = x
		case *types.Pointer:
			named, _ = types.Unalias(x.Elem()).(*types.Named)
		}
		if named != nil {
			for i := 0; i < named.TypeArgs().Len(); i++ {
				if typeMayCarryCallable(named.TypeArgs().At(i), seen) {
					return true
				}
			}
		}
		return false
	}
	switch tt := t.(type) {
	case *types.Basic:
		return tt.Kind() == types.UnsafePointer
	case *types.Signature, *types.Interface, *types.TypeParam:
		return true
	case *types.Named:
		return typeMayCarryCallable(tt.Underlying(), seen)
	case *types.Pointer:
		return typeMayCarryCallable(tt.Elem(), seen)
	case *types.Slice:
		return typeMayCarryCallable(tt.Elem(), seen)
	case *types.Array:
		return typeMayCarryCallable(tt.Elem(), seen)
	case *types.Chan:
		return typeMayCarryCallable(tt.Elem(), seen)
	case *types.Map:
		return typeMayCarryCallable(tt.Key(), seen) || typeMayCarryCallable(tt.Elem(), seen)
	case *types.Struct:
		for i := 0; i < tt.NumFields(); i++ {
			if typeMayCarryCallable(tt.Field(i).Type(), seen) {
				return true
			}
		}
		return false
	case *types.Tuple:
		for i := 0; i < tt.Len(); i++ {
			if typeMayCarryCallable(tt.At(i).Type(), seen) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

// harnessVariadicClosed judges the SSA shape of a call-site-built
// variadic argument (rt.Logf("%v", n) and kin): a slice over a local
// alloc whose only uses are the element stores and this slice, every
// stored element judged by the gate's own per-value rule.
func harnessVariadicClosed(v ssa.Value, fp *freshParamAnalysis) bool {
	_, _, ok := forEachLocalSliceAllocStore(v, false, func(_ *ssa.IndexAddr, val ssa.Value) bool {
		return propertyHarnessClosedValue(val, fp)
	})
	return ok
}

// propertyHarnessClosedArgs is the boundary gate: every
// dynamic-carrying argument and bound-closure capture of a static call
// into the harness must pass the per-value judgment. The harness's
// bodies are never scanned, so a callable or bound receiver crossing
// into them is judged here or not at all.
func propertyHarnessClosedArgs(c *ssa.CallCommon, fp *freshParamAnalysis) bool {
	if c == nil || fp == nil || !fp.propertyHarnessAudited {
		return false
	}
	if mc, ok := c.Value.(*ssa.MakeClosure); ok {
		for _, b := range mc.Bindings {
			if b == nil || !typeMayCarryDynamic(fp.selectionAudited, b.Type(), map[types.Type]bool{}) {
				continue
			}
			if !propertyHarnessClosedValue(b, fp) {
				return false
			}
		}
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

func isPropertyHarnessExampleCallee(callee *ssa.Function) bool {
	return callee != nil && propharness.IsHarnessPath(funcPkgPath(callee)) && functionSymbolName(callee) == "Example"
}

func harnessExampleHasExplicitSeed(c *ssa.CallCommon) bool {
	if c == nil || c.IsInvoke() {
		return false
	}
	callee := c.StaticCallee()
	if callee == nil || callee.Signature == nil || !callee.Signature.Variadic() || len(c.Args) == 0 {
		return false
	}
	slice, arr, ok := forEachLocalSliceAllocStore(c.Args[len(c.Args)-1], false, nil)
	if !ok || arr == nil || arr.Len() < 1 {
		return false
	}
	low := int64(0)
	if slice.Low != nil {
		v, ok := constInt(slice.Low)
		if !ok || v < 0 {
			return false
		}
		low = v
	}
	high := arr.Len()
	if slice.High != nil {
		v, ok := constInt(slice.High)
		if !ok || v > arr.Len() {
			return false
		}
		high = v
	}
	return high-low >= 1
}

func propertyHarnessUnseededExampleEffect() externalEffect {
	return symbolExternalEffect(
		externalEffectNative,
		propharness.ModulePath,
		"Generator.Example",
		"reaches "+propharness.ModulePath+".Generator.Example without an explicit seed (entropy)",
	)
}

// propertyHarnessClosedResult reports whether a call value is a
// gate-passing static call into the property harness: its result is
// closed for dispatch judgment (rapid.MakeCheck's returned callback
// feeding (*testing.T).Run or a computed call is the driving shape,
// and generator constructors' results cross the gate at their own
// consuming call sites the same way). Unseeded (*Generator).Example
// calls are excluded because they draw live per-call entropy outside a
// TB-logged property run.
func propertyHarnessClosedResult(call *ssa.Call, fp *freshParamAnalysis) bool {
	if fp == nil || !fp.propertyHarnessAudited {
		return false
	}
	if call == nil || call.Common() == nil || call.Common().IsInvoke() {
		return false
	}
	callee := call.Common().StaticCallee()
	if callee == nil || !propharness.IsHarnessPath(funcPkgPath(callee)) {
		return false
	}
	if isPropertyHarnessExampleCallee(callee) && !harnessExampleHasExplicitSeed(call.Common()) {
		return false
	}
	return propertyHarnessClosedArgs(call.Common(), fp)
}

// propertyHarnessAuditedProg reports whether the loaded program's
// property-harness package (if any) passes mechanical structural
// verification across every visited variant, with no non-SSA global,
// assembly, native, or cross-package linkname hazards.
func propertyHarnessAuditedProg(audited bool, p *program) bool {
	if !audited || p == nil || len(p.Pkgs) == 0 {
		return false
	}
	cacheKey := propertyHarnessSummaryKeyPrefix + "audited"
	if p.Summaries != nil {
		if cached, ok := p.Summaries[cacheKey].(bool); ok {
			return cached
		}
	}
	store := func(v bool) bool {
		if p.Summaries == nil {
			p.Summaries = make(map[string]any, 4)
		}
		p.Summaries[cacheKey] = v
		return v
	}

	haz := nonSSAGlobalHazardsSummary(audited, p)
	if haz != nil {
		if haz.blockedPkgs[propharness.ModulePath] || haz.verifiedAsm[propharness.ModulePath] != nil {
			return store(false)
		}
		for k := range haz.linknamedVars {
			if k.pkgPath == propharness.ModulePath {
				return store(false)
			}
		}
	}

	found := false
	allValid := true
	packages.Visit(p.Pkgs, func(pkg *packages.Package) bool {
		if pkg == nil {
			return false
		}
		if !propharness.IsHarnessPath(pkg.PkgPath) {
			return true
		}
		found = true
		if !verifyPropertyHarnessPackageTraced(context.Background(), audited, pkg) {
			allValid = false
			return false
		}
		return true
	}, nil)

	return store(found && allValid)
}
