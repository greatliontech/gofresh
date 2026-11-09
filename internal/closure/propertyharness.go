package closure

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/dynstate"
	"github.com/greatliontech/gofresh/internal/gotool"
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

// propertyHarnessModulePath is the property-testing harness import path.
const propertyHarnessModulePath = "pgregory.net/rapid"

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

// propertyHarnessPath reports whether pkgPath is the property-testing
// harness package. Exactly pgregory.net/rapid.
func propertyHarnessPath(pkgPath string) bool {
	return pkgPath == propertyHarnessModulePath
}

// propertyHarnessFact is the admitted harness fact the package-scan
// tier records for a mechanically verified harness dependency: the
// verification admits OBSERVATION, never purity - a property run's
// outcome depends on the harness's log-surfaced run configuration, so a
// package reaching the harness must stay unverifiable-by-hash and prove
// itself through the observation path, exactly as a package reaching
// the standard harness's classified surface does.
func propertyHarnessFact() externalEffect {
	effect := symbolExternalEffect(externalEffectTestRuntime, propertyHarnessModulePath, "Check", "reaches the audited property-testing harness pgregory.net/rapid")
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
	if a == nil || a.h == nil || !propertyHarnessPath(pkgPath) {
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
	if h == nil || !h.SelectionAudited() || pkg == nil || pkg.Module == nil || !propertyHarnessPath(pkg.ImportPath) {
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
			if propertyHarnessPath(p.PkgPath) && p.ForTest == "" && len(p.Syntax) > 0 && p.Types != nil && p.TypesInfo != nil {
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
		if p := h.progs[propertyHarnessModulePath]; p != nil {
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
			if p := h.testingPackagesOnMiss(h, propertyHarnessModulePath); p != nil {
				collectFromRoots(p.Pkgs)
			}
		}
	}
	if len(candidates) == 0 {
		loadDir := h.dir
		pattern := propertyHarnessModulePath
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
		if !verifyPropertyHarnessPackage(true, cand) {
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
	case propertyHarnessModulePath:
		if named.Obj().Name() != "T" {
			return false
		}
		st, ok := named.Underlying().(*types.Struct)
		return ok && structHasNoExportedFields(st)
	case "testing":
		name := named.Obj().Name()
		return name == "T" || name == "B" || name == "TB"
	}
	return false
}

func structHasNoExportedFields(st *types.Struct) bool {
	if st == nil {
		return false
	}
	seen := map[*types.Struct]bool{}
	var walk func(*types.Struct) bool
	walk = func(cur *types.Struct) bool {
		if cur == nil {
			return false
		}
		if seen[cur] {
			return true
		}
		seen[cur] = true
		for i := 0; i < cur.NumFields(); i++ {
			f := cur.Field(i)
			if f.Exported() {
				return false
			}
			if f.Embedded() {
				ft := types.Unalias(f.Type())
				if ptr, ok := ft.(*types.Pointer); ok {
					ft = types.Unalias(ptr.Elem())
				}
				if embSt, ok := ft.Underlying().(*types.Struct); ok && !walk(embSt) {
					return false
				}
			}
		}
		return true
	}
	return walk(st)
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
		if fn != nil && fn.Parent() == nil && propertyHarnessPath(funcPkgPath(fn)) {
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
	return callee != nil && propertyHarnessPath(funcPkgPath(callee)) && functionSymbolName(callee) == "Example"
}

func harnessExampleHasExplicitSeed(c *ssa.CallCommon) bool {
	if c == nil || c.IsInvoke() {
		return false
	}
	callee := c.StaticCallee()
	if callee == nil || callee.Signature == nil || !callee.Signature.Variadic() || len(c.Args) == 0 {
		return false
	}
	seedArg := c.Args[len(c.Args)-1]
	slice, ok := seedArg.(*ssa.Slice)
	if !ok {
		return false
	}
	alloc, ok := slice.X.(*ssa.Alloc)
	if !ok {
		return false
	}
	ptr, ok := types.Unalias(alloc.Type()).Underlying().(*types.Pointer)
	if !ok {
		return false
	}
	arr, ok := types.Unalias(ptr.Elem()).Underlying().(*types.Array)
	if !ok || arr.Len() < 1 {
		return false
	}
	low := int64(0)
	if slice.Low != nil {
		cLow, isConst := slice.Low.(*ssa.Const)
		if !isConst || cLow.Value == nil || cLow.Value.Kind() != constant.Int {
			return false
		}
		v, exact := constant.Int64Val(cLow.Value)
		if !exact || v < 0 {
			return false
		}
		low = v
	}
	high := arr.Len()
	if slice.High != nil {
		cHigh, isConst := slice.High.(*ssa.Const)
		if !isConst || cHigh.Value == nil || cHigh.Value.Kind() != constant.Int {
			return false
		}
		v, exact := constant.Int64Val(cHigh.Value)
		if !exact || v > arr.Len() {
			return false
		}
		high = v
	}
	if high-low < 1 {
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
			}
		default:
			return false
		}
	}
	return true
}

func propertyHarnessUnseededExampleEffect() externalEffect {
	return symbolExternalEffect(
		externalEffectNative,
		propertyHarnessModulePath,
		"Generator.Example",
		"reaches "+propertyHarnessModulePath+".Generator.Example without an explicit seed (entropy)",
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
	if callee == nil || !propertyHarnessPath(funcPkgPath(callee)) {
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
		if haz.blockedPkgs[propertyHarnessModulePath] || haz.verifiedAsm[propertyHarnessModulePath] != nil {
			return store(false)
		}
		for k := range haz.linknamedVars {
			if k.pkgPath == propertyHarnessModulePath {
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
		if !propertyHarnessPath(pkg.PkgPath) {
			return true
		}
		found = true
		if !verifyPropertyHarnessPackage(audited, pkg) {
			allValid = false
			return false
		}
		return true
	}, nil)

	return store(found && allValid)
}

var harnessPureStdImports = map[string]bool{
	"bufio":           true,
	"bytes":           true,
	"cmp":             true,
	"context":         true,
	"encoding/base64": true,
	"encoding/binary": true,
	"errors":          true,
	"fmt":             true,
	"image":           true,
	"image/color":     true,
	"image/png":       true,
	"io":              true,
	"maps":            true,
	"math":            true,
	"math/bits":       true,
	"regexp":          true,
	"regexp/syntax":   true,
	"slices":          true,
	"sort":            true,
	"strconv":         true,
	"strings":         true,
	"sync":            true,
	"sync/atomic":     true,
	"unicode":         true,
	"unicode/utf8":    true,
}

var harnessProtocolStdImports = map[string]bool{
	"flag":             true,
	"hash/maphash":     true,
	"html/template":    true,
	"log":              true,
	"os":               true,
	"path/filepath":    true,
	"reflect":          true,
	"runtime":          true,
	"testing":          true,
	"testing/synctest": true,
	"time":             true,
}

var (
	harnessFlagFuncs = map[string]bool{
		"IntVar": true, "Int64Var": true, "UintVar": true, "Uint64Var": true,
		"StringVar": true, "BoolVar": true, "Float64Var": true, "DurationVar": true,
	}
	harnessTemplateTypes   = map[string]bool{"Template": true, "CSS": true}
	harnessTemplateFuncs   = map[string]bool{"New": true, "Must": true}
	harnessTemplateMethods = map[string]bool{"Parse": true, "Execute": true}
	harnessOSFuncs         = map[string]bool{
		"LookupEnv": true, "Getenv": true,
		"Open": true, "Create": true, "CreateTemp": true, "MkdirAll": true,
		"Rename": true, "Remove": true, "Getpid": true, "IsNotExist": true,
	}
	harnessOSTypes = map[string]bool{
		"File": true, "FileMode": true, "FileInfo": true, "PathError": true,
	}
	harnessOSMethods = map[string]bool{
		"Read": true, "Write": true, "WriteString": true,
		"Close": true, "Name": true, "Sync": true, "Stat": true,
	}
	harnessFilepathFuncs = map[string]bool{
		"Join": true, "Dir": true, "Base": true, "Clean": true,
		"Ext": true, "Split": true, "ToSlash": true, "FromSlash": true, "Glob": true,
	}
	harnessMaphashTypes   = map[string]bool{"Hash": true, "Seed": true}
	harnessMaphashFuncs   = map[string]bool{"MakeSeed": true, "Bytes": true, "String": true}
	harnessMaphashMethods = map[string]bool{
		"Write": true, "WriteByte": true, "WriteString": true,
		"Sum64": true, "Reset": true, "SetSeed": true, "Seed": true,
		"BlockSize": true, "Size": true, "Sum": true,
	}
	harnessTimeTypes = map[string]bool{"Time": true, "Duration": true, "Location": true}
	harnessTimeFuncs = map[string]bool{
		"ParseDuration": true, "Now": true, "Since": true, "Until": true,
		"Date": true, "Unix": true, "UnixMilli": true, "UnixMicro": true, "UnixNano": true,
	}
	harnessTimeMethods = map[string]bool{
		"Add": true, "Sub": true, "Before": true, "After": true, "Equal": true, "Compare": true,
		"IsZero": true, "Format": true, "String": true,
		"Nanoseconds": true, "Microseconds": true, "Milliseconds": true,
		"Seconds": true, "Minutes": true, "Hours": true, "Truncate": true, "Round": true,
		"UTC": true, "Unix": true, "UnixNano": true,
	}
	harnessRuntimeTypes   = map[string]bool{"Frame": true, "Frames": true}
	harnessRuntimeConsts  = map[string]bool{"GOOS": true, "GOARCH": true, "Compiler": true}
	harnessRuntimeFuncs   = map[string]bool{"Callers": true, "CallersFrames": true, "Goexit": true}
	harnessRuntimeMethods = map[string]bool{"Next": true}
	harnessLogTypes       = map[string]bool{"Logger": true}
	harnessLogFuncs       = map[string]bool{"New": true}
	harnessLogMethods     = map[string]bool{
		"Printf": true, "Print": true, "Println": true,
		"Writer": true, "Output": true, "Prefix": true, "Flags": true,
	}
	harnessTestingTypes   = map[string]bool{"T": true, "B": true, "F": true, "TB": true}
	harnessTestingFuncs   = map[string]bool{"Short": true, "Verbose": true}
	harnessTestingMethods = map[string]bool{
		"Helper": true, "Name": true, "Deadline": true,
		"Log": true, "Logf": true, "Error": true, "Errorf": true,
		"Fatal": true, "Fatalf": true, "Skip": true, "Skipf": true, "SkipNow": true, "Skipped": true,
		"Fail": true, "FailNow": true, "Failed": true,
		"Cleanup": true, "Context": true, "Output": true, "Run": true,
	}
	harnessSynctestFuncs = map[string]bool{"Test": true, "Wait": true}
	harnessReflectTypes  = map[string]bool{
		"Type": true, "Value": true, "Kind": true, "StructField": true, "StructTag": true, "Method": true,
	}
	harnessReflectKinds = map[string]bool{
		"Invalid": true, "Bool": true,
		"Int": true, "Int8": true, "Int16": true, "Int32": true, "Int64": true,
		"Uint": true, "Uint8": true, "Uint16": true, "Uint32": true, "Uint64": true, "Uintptr": true,
		"Float32": true, "Float64": true, "Complex64": true, "Complex128": true,
		"Array": true, "Map": true, "Pointer": true, "Ptr": true,
		"Slice": true, "String": true, "Struct": true,
	}
	harnessReflectFuncs = map[string]bool{
		"DeepEqual": true, "TypeOf": true, "ValueOf": true, "Zero": true,
		"New": true, "Indirect": true, "MakeSlice": true, "Append": true, "MakeMapWithSize": true,
	}
	harnessReflectTypeMethods = map[string]bool{
		"Kind": true, "Elem": true, "Key": true, "Len": true,
		"NumField": true, "Field": true, "NumMethod": true, "Method": true,
		"Name": true, "PkgPath": true, "String": true, "Size": true,
		"Comparable": true, "AssignableTo": true, "ConvertibleTo": true, "Implements": true, "Bits": true,
	}
	harnessReflectValueMethods = map[string]bool{
		"Type": true, "Kind": true, "Elem": true, "Field": true, "Index": true, "MapIndex": true,
		"Len": true, "Cap": true, "IsNil": true, "IsValid": true, "IsZero": true,
		"CanSet": true, "CanInterface": true, "Interface": true, "Convert": true,
		"Set": true, "SetMapIndex": true, "Method": true,
		"Bool": true, "Int": true, "Uint": true, "Float": true, "String": true, "Bytes": true,
	}
	harnessReflectTagMethods   = map[string]bool{"Get": true, "Lookup": true}
	harnessReflectFieldMethods = map[string]bool{"IsExported": true}
	harnessReflectKindMethods  = map[string]bool{"String": true}
)

// verifyPropertyHarnessPackage mechanically checks that pkg satisfies
// the closed property-harness protocol invariants over its selected Go
// syntax and type information (REQ-closure-observability-property-harness).
func verifyPropertyHarnessPackage(audited bool, pkg *packages.Package) bool {
	ok, _ := verifyPropertyHarnessPackageWithReason(audited, pkg)
	return ok
}

func verifyPropertyHarnessPackageWithReason(audited bool, pkg *packages.Package) (bool, string) {
	if !audited || pkg == nil || !propertyHarnessPath(pkg.PkgPath) {
		return false, "unaudited or non-harness pkg"
	}
	if len(pkg.Errors) > 0 || pkg.Types == nil || pkg.TypesInfo == nil || len(pkg.Syntax) == 0 {
		return false, "errors or missing syntax/types"
	}
	if len(pkg.OtherFiles) > 0 || len(pkg.EmbedFiles) > 0 || len(pkg.EmbedPatterns) > 0 {
		return false, "other/embed files present"
	}
	if len(pkg.CompiledGoFiles) > 0 && len(pkg.CompiledGoFiles) != len(pkg.GoFiles) {
		return false, "compiled go files mismatch"
	}
	if pkg.Imports["C"] != nil || pkg.Imports["runtime/cgo"] != nil || pkg.Imports["unsafe"] != nil {
		return false, "forbidden cgo/unsafe import"
	}
	for impPath := range pkg.Imports {
		if !harnessPureStdImports[impPath] && !harnessProtocolStdImports[impPath] {
			return false, "disallowed import: " + impPath
		}
	}

	declFuncs := map[*types.Func]*ast.FuncDecl{}
	var pkgVars []harnessVarSpecEntry
	pkgVarSet := map[*types.Var]harnessVarSpecEntry{}

	for _, af := range pkg.Syntax {
		if af == nil {
			return false, "nil ast.File"
		}
		for _, cg := range af.Comments {
			for _, c := range cg.List {
				if hasHarnessForbiddenDirective(c.Text) {
					return false, "forbidden directive: " + c.Text
				}
			}
		}
		for _, imp := range af.Imports {
			if imp == nil || imp.Path == nil {
				return false, "nil import spec"
			}
			impPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil || (!harnessPureStdImports[impPath] && !harnessProtocolStdImports[impPath]) {
				return false, "disallowed syntax import: " + imp.Path.Value
			}
			if imp.Name != nil && imp.Name.Name == "." {
				return false, "dot import: " + impPath
			}
		}
		for _, decl := range af.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body == nil || d.Name == nil {
					return false, "bodyless func decl"
				}
				if d.Recv == nil && d.Name.Name != "init" {
					fn, ok := pkg.TypesInfo.Defs[d.Name].(*types.Func)
					if !ok || fn == nil {
						return false, "unresolved func decl: " + d.Name.Name
					}
					declFuncs[fn] = d
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					continue
				}
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						return false, "non-ValueSpec var"
					}
					if len(vs.Values) > 0 && len(vs.Values) != len(vs.Names) {
						return false, "multi-value var spec"
					}
					for i, nameIdent := range vs.Names {
						if nameIdent == nil || nameIdent.Name == "_" {
							return false, "blank var decl"
						}
						v, ok := pkg.TypesInfo.Defs[nameIdent].(*types.Var)
						if !ok || v == nil || v.Exported() {
							return false, "exported or unresolved var: " + nameIdent.Name
						}
						var initVal ast.Expr
						if i < len(vs.Values) {
							initVal = vs.Values[i]
						}
						entry := harnessVarSpecEntry{v: v, spec: vs, val: initVal}
						pkgVars = append(pkgVars, entry)
						pkgVarSet[v] = entry
					}
				}
			}
		}
	}

	initOnly, funcValueTaken, callSitesByFunc := computeHarnessFunctionUsage(pkg, declFuncs)

	// Gate 2: Protocol stdlib symbol discipline across TypesInfo.Uses & Selections.
	for ident, obj := range pkg.TypesInfo.Uses {
		if ident == nil || obj == nil || obj.Pkg() == nil || obj.Pkg() == pkg.Types {
			continue
		}
		impPath := obj.Pkg().Path()
		if harnessPureStdImports[impPath] {
			if !checkHarnessPureStdObjectUse(impPath, obj) {
				return false, "disallowed pure std use: " + impPath + "." + obj.Name()
			}
			continue
		}
		if !harnessProtocolStdImports[impPath] {
			return false, "disallowed use pkg: " + impPath + "." + obj.Name()
		}
		if !checkHarnessProtocolObjectAllowed(impPath, obj) {
			return false, "disallowed protocol use: " + impPath + "." + obj.Name()
		}
	}
	for _, sel := range pkg.TypesInfo.Selections {
		if sel == nil || sel.Obj() == nil || sel.Obj().Pkg() == nil || sel.Obj().Pkg() == pkg.Types {
			continue
		}
		obj := sel.Obj()
		impPath := obj.Pkg().Path()
		if harnessPureStdImports[impPath] {
			if !checkHarnessPureStdObjectUse(impPath, obj) {
				return false, "disallowed pure std selection: " + impPath + "." + obj.Name()
			}
			continue
		}
		if !harnessProtocolStdImports[impPath] || !checkHarnessProtocolObjectAllowed(impPath, obj) {
			return false, "disallowed protocol selection: " + impPath + "." + obj.Name()
		}
	}

	// Gate 2: Closed package-scope variable categories (returning init-only Category 3A vars).
	categoryA, okVars := verifyHarnessPackageVars(audited, pkg, declFuncs, initOnly, funcValueTaken, callSitesByFunc, pkgVars, pkgVarSet)
	if !okVars {
		return false, "verifyHarnessPackageVars failed"
	}

	// Gate 3: Contextual AST protocol checks (flag.*Var, os.LookupEnv/Getenv, os.Stdout,
	// failfile/debugvis os & filepath.Glob provenance, joined synctest GoStmt,
	// non-value-taken reflect/protocol funcs, and TB.Logf witness).
	if okCtx, reasonCtx := verifyHarnessProtocolCallContexts(audited, pkg, declFuncs, initOnly, funcValueTaken, callSitesByFunc, pkgVarSet, categoryA); !okCtx {
		return false, "verifyHarnessProtocolCallContexts: " + reasonCtx
	}

	// Gate 4: Exported handle T, Check/MakeCheck entrypoints, and closed exported return types.
	if !verifyHarnessExportedSurface(audited, pkg) {
		return false, "verifyHarnessExportedSurface failed"
	}
	return true, ""
}

func hasHarnessForbiddenDirective(text string) bool {
	trimmed := strings.TrimSpace(strings.TrimPrefix(text, "//"))
	trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "/*"))
	trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, "*/"))
	for _, dir := range []string{"go:linkname", "go:linknamestd", "go:wasmimport", "go:cgo_"} {
		if strings.HasPrefix(trimmed, dir) {
			if dir == "go:cgo_" || trimmed == dir {
				return true
			}
			if _, ok := auditset.BoundedToken(trimmed, dir, " \t"); ok {
				return true
			}
		}
	}
	return false
}

func peelHarnessCallee(e ast.Expr) ast.Expr {
	for e != nil {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.IndexListExpr:
			e = x.X
		default:
			return e
		}
	}
	return nil
}

func resolveHarnessFuncExpr(info *types.Info, e ast.Expr) *types.Func {
	e = peelHarnessCallee(e)
	switch x := e.(type) {
	case *ast.Ident:
		fn, _ := info.Uses[x].(*types.Func)
		return fn
	case *ast.SelectorExpr:
		if sel := info.Selections[x]; sel != nil {
			fn, _ := sel.Obj().(*types.Func)
			return fn
		}
		if x.Sel != nil {
			fn, _ := info.Uses[x.Sel].(*types.Func)
			return fn
		}
	}
	return nil
}

func computeHarnessFunctionUsage(
	pkg *packages.Package,
	declFuncs map[*types.Func]*ast.FuncDecl,
) (map[*types.Func]bool, map[*types.Func]bool, map[*types.Func][]*ast.CallExpr) {
	calledFromInit := map[*types.Func]bool{}
	calledFromOther := map[*types.Func]bool{}
	callersOf := map[*types.Func]map[*types.Func]bool{}
	valueTaken := map[*types.Func]bool{}
	callSites := map[*types.Func][]*ast.CallExpr{}

	walkBody := func(root ast.Node, inInitRoot bool, callerFn *types.Func) {
		calleeIdents := map[*ast.Ident]bool{}
		var walk func(n ast.Node, inFuncLit bool)
		walk = func(n ast.Node, inFuncLit bool) {
			if n == nil {
				return
			}
			switch x := n.(type) {
			case *ast.FuncLit:
				if x.Type != nil {
					walk(x.Type, true)
				}
				if x.Body != nil {
					walk(x.Body, true)
				}
				return
			case *ast.GoStmt:
				walk(x.Call, true)
				return
			case *ast.CallExpr:
				baseFun := peelHarnessCallee(x.Fun)
				if id, ok := baseFun.(*ast.Ident); ok {
					if fn, ok := pkg.TypesInfo.Uses[id].(*types.Func); ok && declFuncs[fn] != nil {
						calleeIdents[id] = true
						callSites[fn] = append(callSites[fn], x)
						if inInitRoot && !inFuncLit {
							calledFromInit[fn] = true
						} else if callerFn != nil && !inFuncLit {
							if callersOf[fn] == nil {
								callersOf[fn] = map[*types.Func]bool{}
							}
							callersOf[fn][callerFn] = true
						} else {
							calledFromOther[fn] = true
						}
					}
				}
			case *ast.Ident:
				if !calleeIdents[x] {
					if fn, ok := pkg.TypesInfo.Uses[x].(*types.Func); ok && declFuncs[fn] != nil {
						valueTaken[fn] = true
					}
				}
			}
			ast.Inspect(n, func(child ast.Node) bool {
				if child == nil || child == n {
					return true
				}
				walk(child, inFuncLit)
				return false
			})
		}
		walk(root, false)
	}

	for _, af := range pkg.Syntax {
		for _, decl := range af.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.Name == "init" {
					walkBody(d.Body, true, nil)
				} else if d.Recv == nil {
					fn, _ := pkg.TypesInfo.Defs[d.Name].(*types.Func)
					if fn != nil && !fn.Exported() {
						walkBody(d.Body, false, fn)
					} else {
						walkBody(d.Body, false, nil)
					}
				} else {
					walkBody(d.Body, false, nil)
				}
			case *ast.GenDecl:
				walkBody(d, true, nil)
			}
		}
	}

	initOnly := map[*types.Func]bool{}
	for fn := range declFuncs {
		if !fn.Exported() && !valueTaken[fn] && !calledFromOther[fn] && (calledFromInit[fn] || len(callersOf[fn]) > 0) {
			initOnly[fn] = true
		}
	}
	changed := true
	for changed {
		changed = false
		for fn := range initOnly {
			hasInitCaller := calledFromInit[fn]
			for caller := range callersOf[fn] {
				if !initOnly[caller] {
					delete(initOnly, fn)
					changed = true
					hasInitCaller = false
					break
				}
				hasInitCaller = true
			}
			if initOnly[fn] && !hasInitCaller {
				delete(initOnly, fn)
				changed = true
			}
		}
	}

	return initOnly, valueTaken, callSites
}

func checkHarnessPureStdObjectUse(impPath string, obj types.Object) bool {
	// Disallow mutable package-level globals in stdlib packages (e.g. io.EOF
	// and io.Discard are immutable sentinels, whereas custom global registries are not).
	if v, ok := obj.(*types.Var); ok && !v.IsField() {
		switch impPath {
		case "io":
			return v.Name() == "Discard" || v.Name() == "EOF" || v.Name() == "ErrUnexpectedEOF"
		case "encoding/binary":
			return v.Name() == "LittleEndian" || v.Name() == "BigEndian" || v.Name() == "NativeEndian"
		case "encoding/base64":
			return v.Name() == "StdEncoding" || v.Name() == "RawStdEncoding" || v.Name() == "URLEncoding" || v.Name() == "RawURLEncoding"
		case "unicode":
			return true
		case "image/color":
			return v.Name() == "Black" || v.Name() == "White" || v.Name() == "Transparent" || v.Name() == "Opaque"
		default:
			return false
		}
	}
	return true
}

func recvNamedTypeName(sig *types.Signature) (pkgPath, typeName string) {
	if sig == nil || sig.Recv() == nil {
		return "", ""
	}
	rt := types.Unalias(sig.Recv().Type())
	if ptr, ok := rt.(*types.Pointer); ok {
		rt = types.Unalias(ptr.Elem())
	}
	named, ok := rt.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return "", ""
	}
	return named.Obj().Pkg().Path(), named.Obj().Name()
}

func checkHarnessProtocolObjectAllowed(impPath string, obj types.Object) bool {
	if v, ok := obj.(*types.Var); ok && v.IsField() {
		return true
	}
	switch impPath {
	case "flag":
		fn, ok := obj.(*types.Func)
		return ok && fn.Signature().Recv() == nil && harnessFlagFuncs[fn.Name()]
	case "html/template":
		switch o := obj.(type) {
		case *types.TypeName:
			return harnessTemplateTypes[o.Name()]
		case *types.Func:
			sig := o.Signature()
			if sig.Recv() == nil {
				return harnessTemplateFuncs[o.Name()]
			}
			_, typeName := recvNamedTypeName(sig)
			return typeName == "Template" && harnessTemplateMethods[o.Name()]
		}
		return false
	case "os":
		switch o := obj.(type) {
		case *types.TypeName:
			return harnessOSTypes[o.Name()]
		case *types.Const:
			return true
		case *types.Var:
			return o.Name() == "Stdout"
		case *types.Func:
			if o.Signature().Recv() == nil {
				return harnessOSFuncs[o.Name()]
			}
			return harnessOSMethods[o.Name()]
		}
		return false
	case "path/filepath":
		switch o := obj.(type) {
		case *types.Const:
			return o.Name() == "Separator" || o.Name() == "ListSeparator"
		case *types.Func:
			return o.Signature().Recv() == nil && harnessFilepathFuncs[o.Name()]
		}
		return false
	case "hash/maphash":
		switch o := obj.(type) {
		case *types.TypeName:
			return harnessMaphashTypes[o.Name()]
		case *types.Func:
			if o.Signature().Recv() == nil {
				return harnessMaphashFuncs[o.Name()]
			}
			return harnessMaphashMethods[o.Name()]
		}
		return false
	case "time":
		switch o := obj.(type) {
		case *types.TypeName:
			return harnessTimeTypes[o.Name()]
		case *types.Const:
			return true
		case *types.Func:
			if o.Signature().Recv() == nil {
				return harnessTimeFuncs[o.Name()]
			}
			return harnessTimeMethods[o.Name()]
		}
		return false
	case "runtime":
		switch o := obj.(type) {
		case *types.TypeName:
			return harnessRuntimeTypes[o.Name()]
		case *types.Const:
			return harnessRuntimeConsts[o.Name()]
		case *types.Func:
			if o.Signature().Recv() == nil {
				return harnessRuntimeFuncs[o.Name()]
			}
			return harnessRuntimeMethods[o.Name()]
		}
		return false
	case "log":
		switch o := obj.(type) {
		case *types.TypeName:
			return harnessLogTypes[o.Name()]
		case *types.Const:
			return true
		case *types.Func:
			if o.Signature().Recv() == nil {
				return harnessLogFuncs[o.Name()]
			}
			return harnessLogMethods[o.Name()]
		}
		return false
	case "testing":
		switch o := obj.(type) {
		case *types.TypeName:
			return harnessTestingTypes[o.Name()]
		case *types.Func:
			if o.Signature().Recv() == nil {
				return harnessTestingFuncs[o.Name()]
			}
			return harnessTestingMethods[o.Name()]
		}
		return false
	case "testing/synctest":
		fn, ok := obj.(*types.Func)
		return ok && fn.Signature().Recv() == nil && harnessSynctestFuncs[fn.Name()]
	case "reflect":
		switch o := obj.(type) {
		case *types.TypeName:
			return harnessReflectTypes[o.Name()]
		case *types.Const:
			named, ok := types.Unalias(o.Type()).(*types.Named)
			return ok && named.Obj() != nil && named.Obj().Name() == "Kind" && harnessReflectKinds[o.Name()]
		case *types.Func:
			sig := o.Signature()
			if sig.Recv() == nil {
				return harnessReflectFuncs[o.Name()]
			}
			_, typeName := recvNamedTypeName(sig)
			switch typeName {
			case "Type":
				return harnessReflectTypeMethods[o.Name()]
			case "Value":
				return harnessReflectValueMethods[o.Name()]
			case "StructTag":
				return harnessReflectTagMethods[o.Name()]
			case "StructField", "Method":
				return harnessReflectFieldMethods[o.Name()]
			case "Kind":
				return harnessReflectKindMethods[o.Name()]
			case "":
				if o.Pkg() != nil && o.Pkg().Scope() != nil {
					if typeObj := o.Pkg().Scope().Lookup("Type"); typeObj != nil {
						if mObj, _, _ := types.LookupFieldOrMethod(typeObj.Type(), false, o.Pkg(), o.Name()); mObj == o {
							return harnessReflectTypeMethods[o.Name()]
						}
					}
				}
			}
		}
		return false
	}
	return false
}

func constStringPrefix(info *types.Info, e ast.Expr, prefix string) bool {
	if info == nil || e == nil {
		return false
	}
	tv, ok := info.Types[e]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return false
	}
	return strings.HasPrefix(constant.StringVal(tv.Value), prefix)
}

type harnessVarSpecEntry struct {
	v    *types.Var
	spec *ast.ValueSpec
	val  ast.Expr
}

type harnessParamKey struct {
	fn  *types.Func
	idx int
}

func verifyHarnessProtocolCallContexts(
	audited bool,
	pkg *packages.Package,
	declFuncs map[*types.Func]*ast.FuncDecl,
	initOnly map[*types.Func]bool,
	funcValueTaken map[*types.Func]bool,
	callSites map[*types.Func][]*ast.CallExpr,
	pkgVarSet map[*types.Var]harnessVarSpecEntry,
	categoryA map[*types.Var]bool,
) (bool, string) {
	info := pkg.TypesInfo
	failfileVars, failfileParams, failfileResults := computeHarnessFailfileProvenance(pkg, declFuncs, initOnly, funcValueTaken, callSites, categoryA)

	var validRapidEnvStringParam func(fn *types.Func, idx int, seen map[harnessParamKey]bool) bool
	validRapidEnvStringParam = func(fn *types.Func, idx int, seen map[harnessParamKey]bool) bool {
		if fn == nil || !initOnly[fn] || fn.Signature().Variadic() {
			return false
		}
		params := fn.Signature().Params()
		if idx < 0 || idx >= params.Len() {
			return false
		}
		key := harnessParamKey{fn: fn, idx: idx}
		if seen[key] {
			return true
		}
		seen[key] = true
		sites := callSites[fn]
		if len(sites) == 0 {
			return false
		}
		for _, site := range sites {
			if site.Ellipsis.IsValid() || idx >= len(site.Args) {
				return false
			}
			arg := site.Args[idx]
			if constStringPrefix(info, arg, "RAPID_") {
				continue
			}
			argIdent, ok := ast.Unparen(arg).(*ast.Ident)
			if !ok {
				return false
			}
			paramObj, ok := info.Uses[argIdent].(*types.Var)
			if !ok || paramObj == nil {
				return false
			}
			callerFn, callerIdx := findFuncParamIndex(declFuncs, paramObj)
			if callerFn == nil || !validRapidEnvStringParam(callerFn, callerIdx, seen) {
				return false
			}
		}
		return true
	}

	var validInitLookupParam func(fn *types.Func, idx int, seen map[harnessParamKey]bool) bool
	validInitLookupParam = func(fn *types.Func, idx int, seen map[harnessParamKey]bool) bool {
		if fn == nil || !initOnly[fn] || fn.Signature().Variadic() {
			return false
		}
		params := fn.Signature().Params()
		if idx < 0 || idx >= params.Len() {
			return false
		}
		key := harnessParamKey{fn: fn, idx: idx}
		if seen[key] {
			return true
		}
		seen[key] = true
		paramVar := params.At(idx)
		fd := declFuncs[fn]
		if fd == nil || fd.Body == nil {
			return false
		}
		allowedIdents := map[*ast.Ident]bool{}
		okBody := true
		var inspectBody func(n ast.Node, inLit bool)
		inspectBody = func(n ast.Node, inLit bool) {
			if !okBody || n == nil {
				return
			}
			switch x := n.(type) {
			case *ast.FuncLit:
				inspectBody(x.Type, true)
				inspectBody(x.Body, true)
				return
			case *ast.GoStmt:
				inspectBody(x.Call, true)
				return
			case *ast.CallExpr:
				if funId, ok := peelHarnessCallee(x.Fun).(*ast.Ident); ok && info.Uses[funId] == paramVar {
					if inLit || x.Ellipsis.IsValid() || len(x.Args) != 1 {
						okBody = false
						return
					}
					allowedIdents[funId] = true
					keyArg := x.Args[0]
					if !constStringPrefix(info, keyArg, "RAPID_") {
						argId, ok := ast.Unparen(keyArg).(*ast.Ident)
						if !ok {
							okBody = false
							return
						}
						pObj, ok := info.Uses[argId].(*types.Var)
						if !ok || pObj == nil {
							okBody = false
							return
						}
						ownerFn, ownerIdx := findFuncParamIndex(declFuncs, pObj)
						if ownerFn != fn || !validRapidEnvStringParam(fn, ownerIdx, map[harnessParamKey]bool{}) {
							okBody = false
							return
						}
					}
				} else {
					callee := resolveHarnessFuncExpr(info, x.Fun)
					for argIdx, arg := range x.Args {
						if argId, ok := ast.Unparen(arg).(*ast.Ident); ok && info.Uses[argId] == paramVar {
							if inLit || x.Ellipsis.IsValid() || callee == nil || declFuncs[callee] == nil || !validInitLookupParam(callee, argIdx, seen) {
								okBody = false
								return
							}
							allowedIdents[argId] = true
						}
					}
				}
			}
			ast.Inspect(n, func(child ast.Node) bool {
				if !okBody || child == nil {
					return false
				}
				if child == n {
					return true
				}
				inspectBody(child, inLit)
				return false
			})
		}
		inspectBody(fd.Body, false)
		if !okBody {
			return false
		}
		// Reject any other reference (assignment, return, address-take, closure capture) to paramVar.
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if !okBody || n == nil {
				return false
			}
			if id, ok := n.(*ast.Ident); ok && info.Uses[id] == paramVar && !allowedIdents[id] {
				okBody = false
				return false
			}
			return true
		})
		return okBody
	}

	sawTBLogf := false
	okAll := true
	failReason := ""
	fail := func(msg string) {
		if okAll {
			okAll = false
			failReason = msg
		}
	}

	checkTree := func(root ast.Node, inInitRoot bool, enclosingFD *ast.FuncDecl, enclosingFn *types.Func) {
		approvedIdents := map[*ast.Ident]bool{}
		var tempFileVars map[*types.Var]bool
		if enclosingFD != nil && enclosingFD.Body != nil {
			tempFileVars = collectHarnessTempFileVars(info, pkg.Types, enclosingFD.Body, declFuncs, categoryA, failfileVars, failfileParams, failfileResults)
		}
		isFailfile := func(e ast.Expr) bool {
			return isHarnessFailfileExpr(info, e, declFuncs, categoryA, failfileVars, failfileParams, failfileResults)
		}

		var walk func(n ast.Node, inInitExec bool, inLit bool, inFlagBoolGuard bool)
		walk = func(n ast.Node, inInitExec bool, inLit bool, inFlagBoolGuard bool) {
			if !okAll || n == nil {
				return
			}
			switch x := n.(type) {
			case *ast.FuncLit:
				walk(x.Type, false, true, false)
				walk(x.Body, false, true, false)
				return
			case *ast.GoStmt:
				if inInitRoot || inLit || enclosingFD == nil || enclosingFD.Body == nil ||
					!verifyJoinedSynctestGoStmt(info, pkg.Types, enclosingFD.Body, x) {
					fail("unjoined go stmt")
					return
				}
				walk(x.Call, false, true, false)
				return
			case *ast.IfStmt:
				if x.Init != nil {
					walk(x.Init, inInitExec, inLit, inFlagBoolGuard)
				}
				walk(x.Cond, inInitExec, inLit, inFlagBoolGuard)
				condGuard := inFlagBoolGuard || (!inLit && isCategoryABoolFieldExpr(info, x.Cond, categoryA))
				walk(x.Body, inInitExec, inLit, condGuard)
				if x.Else != nil {
					walk(x.Else, inInitExec, inLit, inFlagBoolGuard)
				}
				return
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if rootImportedVar(info, lhs, pkg.Types) != nil {
						fail("assign imported var")
						return
					}
				}
			case *ast.IncDecStmt:
				if rootImportedVar(info, x.X, pkg.Types) != nil {
					fail("incdec imported var")
					return
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if (x.Key != nil && rootImportedVar(info, x.Key, pkg.Types) != nil) ||
						(x.Value != nil && rootImportedVar(info, x.Value, pkg.Types) != nil) {
						fail("range assign imported var")
						return
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND && rootImportedVar(info, x.X, pkg.Types) != nil {
					fail("addr imported var")
					return
				}
			case *ast.CallExpr:
				if id, ok := peelHarnessCallee(x.Fun).(*ast.Ident); ok {
					if b, isB := info.Uses[id].(*types.Builtin); isB && (b.Name() == "delete" || b.Name() == "clear" || b.Name() == "copy" || b.Name() == "append") && len(x.Args) > 0 {
						if rootImportedVar(info, x.Args[0], pkg.Types) != nil {
							fail("builtin mutate imported var")
							return
						}
					}
				}
				callee := resolveHarnessFuncExpr(info, x.Fun)
				if callee != nil {
					if callee.Name() == "Logf" && callee.Signature().Recv() != nil {
						sawTBLogf = true
					}
					if callee.Pkg() != nil && callee.Pkg() != pkg.Types {
						impPath := callee.Pkg().Path()
						switch {
						case impPath == "flag":
							if !inInitExec || x.Ellipsis.IsValid() || len(x.Args) != 4 {
								fail("flag call outside init or bad arity: " + callee.Name())
								return
							}
							if !isAddrOfCarrierFreeFlagField(audited, info, x.Args[0], pkgVarSet) || !constStringPrefix(info, x.Args[1], "rapid.") {
								fail("flag call bad target or prefix: " + callee.Name())
								return
							}
							markCalleeIdentApproved(x.Fun, approvedIdents)
						case impPath == "os" && (callee.Name() == "LookupEnv" || callee.Name() == "Getenv"):
							if !inInitExec || x.Ellipsis.IsValid() || len(x.Args) != 1 || !constStringPrefix(info, x.Args[0], "RAPID_") {
								fail("os env call bad context: " + callee.Name())
								return
							}
							markCalleeIdentApproved(x.Fun, approvedIdents)
						case impPath == "os" && callee.Signature().Recv() == nil:
							if !verifyHarnessOSFuncCall(info, enclosingFD, enclosingFn, inInitRoot, inLit, inFlagBoolGuard, callee.Name(), x, isFailfile, tempFileVars) {
								fail("os func call failed: os." + callee.Name())
								return
							}
							markCalleeIdentApproved(x.Fun, approvedIdents)
						case impPath == "path/filepath" && callee.Name() == "Glob":
							if inInitRoot || enclosingFn == nil || enclosingFn.Exported() || x.Ellipsis.IsValid() || len(x.Args) != 1 || !isFailfile(x.Args[0]) {
								fail("filepath.Glob failed")
								return
							}
							markCalleeIdentApproved(x.Fun, approvedIdents)
						case impPath == "log" && callee.Name() == "New":
							if !x.Ellipsis.IsValid() && len(x.Args) == 3 {
								if stdoutIdent := osStdoutIdent(info, x.Args[0]); stdoutIdent != nil {
									approvedIdents[stdoutIdent] = true
								}
							}
							markCalleeIdentApproved(x.Fun, approvedIdents)
						case impPath == "html/template":
							if !verifyHarnessTemplateCall(audited, info, pkg.Types, callee, x) {
								fail("html/template call failed: " + callee.Name())
								return
							}
							markCalleeIdentApproved(x.Fun, approvedIdents)
						case harnessProtocolStdImports[impPath]:
							markCalleeIdentApproved(x.Fun, approvedIdents)
						}
					} else if declFuncs[callee] != nil && initOnly[callee] && inInitExec && !x.Ellipsis.IsValid() {
						for argIdx, arg := range x.Args {
							if envIdent := osEnvLookupIdent(info, arg); envIdent != nil {
								if !validInitLookupParam(callee, argIdx, map[harnessParamKey]bool{}) {
									fail("invalid init lookup param: " + callee.Name())
									return
								}
								approvedIdents[envIdent] = true
							}
						}
					}
				}
			}
			ast.Inspect(n, func(child ast.Node) bool {
				if !okAll || child == nil {
					return false
				}
				if child == n {
					return true
				}
				walk(child, inInitExec, inLit, inFlagBoolGuard)
				return false
			})
		}
		walk(root, inInitRoot, false, false)
		if !okAll {
			return
		}
		// Reject any unapproved value-position reference to flag.*, os.* funcs, os.Stdout,
		// filepath.Glob, html/template.*, or any reflect function/method.
		ast.Inspect(root, func(n ast.Node) bool {
			if !okAll || n == nil {
				return false
			}
			id, ok := n.(*ast.Ident)
			if !ok || approvedIdents[id] {
				return true
			}
			obj := info.Uses[id]
			if obj == nil || obj.Pkg() == nil {
				return true
			}
			switch obj.Pkg().Path() {
			case "flag":
				if _, isFn := obj.(*types.Func); isFn {
					fail("unapproved flag ref: " + obj.Name())
					return false
				}
			case "html/template":
				if _, isFn := obj.(*types.Func); isFn {
					fail("unapproved html/template ref: " + obj.Name())
					return false
				}
			case "os":
				if _, isFn := obj.(*types.Func); isFn || obj.Name() == "Stdout" {
					fail("unapproved os ref: " + obj.Name())
					return false
				}
			case "path/filepath":
				if fn, isFn := obj.(*types.Func); isFn && fn.Name() == "Glob" {
					fail("unapproved filepath.Glob ref")
					return false
				}
			case "reflect":
				if _, isFn := obj.(*types.Func); isFn {
					fail("unapproved reflect ref: " + obj.Name())
					return false
				}
			}
			return true
		})
	}

	for _, af := range pkg.Syntax {
		for _, decl := range af.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				inInit := false
				var fn *types.Func
				if d.Recv == nil && d.Name.Name == "init" {
					inInit = true
				} else if d.Recv == nil {
					fn, _ = info.Defs[d.Name].(*types.Func)
					if fn != nil && initOnly[fn] {
						inInit = true
					}
				}
				checkTree(d.Body, inInit, d, fn)
			case *ast.GenDecl:
				checkTree(d, true, nil, nil)
			}
			if !okAll {
				return false, failReason
			}
		}
	}

	if !sawTBLogf {
		return false, "missing TB.Logf"
	}
	if !verifyHarnessMaphashCallerConfinement(pkg, funcValueTaken) {
		return false, "maphash caller confinement failed"
	}
	return true, ""
}

// verifyHarnessMaphashCallerConfinement verifies that every reference to "hash/maphash"
// inside pkg sits inside a non-init function/method whose transitive intra-package
// callers (attributing calls inside nested FuncLits to their enclosing FuncDecl and
// forbidding value-taken intermediate helpers) reach no exported symbol other than
// Check, MakeCheck, or (*Generator[V]).Example.
func verifyHarnessMaphashCallerConfinement(pkg *packages.Package, funcValueTaken map[*types.Func]bool) bool {
	info := pkg.TypesInfo
	allDecls := map[*types.Func]*ast.FuncDecl{}
	callersOf := map[*types.Func]map[*types.Func]bool{}
	anyValueTaken := map[*types.Func]bool{}
	for fn, v := range funcValueTaken {
		if v && fn != nil {
			anyValueTaken[fn.Origin()] = true
		}
	}

	for _, af := range pkg.Syntax {
		for _, decl := range af.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name == nil || (fd.Recv == nil && fd.Name.Name == "init") {
				continue
			}
			if fn, ok := info.Defs[fd.Name].(*types.Func); ok && fn != nil {
				allDecls[fn.Origin()] = fd
			}
		}
	}

	maphashSeeds := map[*types.Func]bool{}
	validContext := true
	scanRoot := func(root ast.Node, owner *types.Func) {
		calleeIdents := map[*ast.Ident]bool{}
		ast.Inspect(root, func(n ast.Node) bool {
			if !validContext || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.CallExpr:
				baseFun := peelHarnessCallee(x.Fun)
				switch bf := baseFun.(type) {
				case *ast.Ident:
					calleeIdents[bf] = true
				case *ast.SelectorExpr:
					if bf.Sel != nil {
						calleeIdents[bf.Sel] = true
					}
				}
				if callee := resolveHarnessFuncExpr(info, x.Fun); callee != nil {
					orig := callee.Origin()
					if allDecls[orig] != nil {
						if owner == nil {
							// Called from init or package-level var initializer.
							if callersOf[orig] == nil {
								callersOf[orig] = map[*types.Func]bool{}
							}
							callersOf[orig][nil] = true
						} else {
							if callersOf[orig] == nil {
								callersOf[orig] = map[*types.Func]bool{}
							}
							callersOf[orig][owner] = true
						}
					}
				}
			case *ast.Ident:
				if obj := info.Uses[x]; obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "hash/maphash" {
					if owner == nil {
						validContext = false
						return false
					}
					maphashSeeds[owner] = true
				}
			}
			return true
		})
		if !validContext {
			return
		}
		ast.Inspect(root, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || calleeIdents[id] {
				return true
			}
			if fn, ok := info.Uses[id].(*types.Func); ok && fn != nil && allDecls[fn.Origin()] != nil {
				anyValueTaken[fn.Origin()] = true
			}
			return true
		})
	}

	for _, af := range pkg.Syntax {
		for _, decl := range af.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.Name == "init" {
					scanRoot(d.Body, nil)
				} else if fn, ok := info.Defs[d.Name].(*types.Func); ok && fn != nil {
					scanRoot(d.Body, fn.Origin())
				} else {
					scanRoot(d.Body, nil)
				}
			case *ast.GenDecl:
				scanRoot(d, nil)
			}
			if !validContext {
				return false
			}
		}
	}

	if len(maphashSeeds) == 0 {
		return true
	}

	isAllowedExportedMaphashRoot := func(fn *types.Func) bool {
		sig := fn.Signature()
		if sig.Recv() == nil {
			return fn.Name() == "Check" || fn.Name() == "MakeCheck"
		}
		if fn.Name() != "Example" {
			return false
		}
		rt := types.Unalias(sig.Recv().Type())
		if ptr, ok := rt.(*types.Pointer); ok {
			rt = types.Unalias(ptr.Elem())
		}
		named, ok := rt.(*types.Named)
		return ok && named.Obj() != nil && named.Obj().Pkg() == pkg.Types && named.Obj().Name() == "Generator"
	}

	visited := map[*types.Func]bool{}
	var queue []*types.Func
	for fn := range maphashSeeds {
		visited[fn] = true
		queue = append(queue, fn)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur == nil {
			return false
		}
		if cur.Exported() {
			if !isAllowedExportedMaphashRoot(cur) {
				return false
			}
			continue
		}
		if anyValueTaken[cur] {
			return false
		}
		if cur.Signature().Recv() != nil {
			// Unexported method could satisfy an interface; disallow on maphash upward cone.
			return false
		}
		for caller := range callersOf[cur] {
			if caller == nil {
				return false
			}
			if !visited[caller] {
				visited[caller] = true
				queue = append(queue, caller)
			}
		}
	}
	return true
}

func findFuncParamIndex(declFuncs map[*types.Func]*ast.FuncDecl, paramObj *types.Var) (*types.Func, int) {
	for fn := range declFuncs {
		params := fn.Signature().Params()
		for i := 0; i < params.Len(); i++ {
			if params.At(i) == paramObj {
				return fn, i
			}
		}
	}
	return nil, -1
}

func markCalleeIdentApproved(fun ast.Expr, approved map[*ast.Ident]bool) {
	switch x := peelHarnessCallee(fun).(type) {
	case *ast.Ident:
		approved[x] = true
	case *ast.SelectorExpr:
		if x.Sel != nil {
			approved[x.Sel] = true
		}
	}
}

func osStdoutIdent(info *types.Info, e ast.Expr) *ast.Ident {
	switch x := ast.Unparen(e).(type) {
	case *ast.Ident:
		if v, ok := info.Uses[x].(*types.Var); ok && v.Pkg() != nil && v.Pkg().Path() == "os" && v.Name() == "Stdout" {
			return x
		}
	case *ast.SelectorExpr:
		if x.Sel != nil {
			if v, ok := info.Uses[x.Sel].(*types.Var); ok && v.Pkg() != nil && v.Pkg().Path() == "os" && v.Name() == "Stdout" {
				return x.Sel
			}
		}
	}
	return nil
}

func osEnvLookupIdent(info *types.Info, e ast.Expr) *ast.Ident {
	switch x := ast.Unparen(e).(type) {
	case *ast.Ident:
		if fn, ok := info.Uses[x].(*types.Func); ok && fn.Pkg() != nil && fn.Pkg().Path() == "os" && (fn.Name() == "LookupEnv" || fn.Name() == "Getenv") {
			return x
		}
	case *ast.SelectorExpr:
		if x.Sel != nil {
			if fn, ok := info.Uses[x.Sel].(*types.Func); ok && fn.Pkg() != nil && fn.Pkg().Path() == "os" && (fn.Name() == "LookupEnv" || fn.Name() == "Getenv") {
				return x.Sel
			}
		}
	}
	return nil
}

func isAddrOfCarrierFreeFlagField(
	audited bool,
	info *types.Info,
	e ast.Expr,
	pkgVarSet map[*types.Var]harnessVarSpecEntry,
) bool {
	un, ok := ast.Unparen(e).(*ast.UnaryExpr)
	if !ok || un.Op != token.AND {
		return false
	}
	sel, ok := ast.Unparen(un.X).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	baseId, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := info.Uses[baseId].(*types.Var)
	if !ok || v == nil {
		return false
	}
	if _, exists := pkgVarSet[v]; !exists {
		return false
	}
	if dynstate.TypeMayCarryUnknownDynamic(audited, v.Type()) {
		return false
	}
	_, isStruct := types.Unalias(v.Type()).Underlying().(*types.Struct)
	return isStruct
}

func isSyncMapType(t types.Type) bool {
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil &&
		named.Obj().Pkg().Path() == "sync" && named.Obj().Name() == "Map"
}

func isTemplatePtrType(t types.Type) bool {
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil &&
		named.Obj().Pkg().Path() == "html/template" && named.Obj().Name() == "Template"
}

func isCarrierFreeGeneratorPtrType(audited bool, pkgTypes *types.Package, t types.Type) (*types.Named, bool) {
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return nil, false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() != pkgTypes || named.Obj().Name() != "Generator" {
		return nil, false
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return nil, false
	}
	for i := 0; i < st.NumFields(); i++ {
		if st.Field(i).Exported() {
			return nil, false
		}
	}
	if targs := named.TypeArgs(); targs != nil {
		for i := 0; i < targs.Len(); i++ {
			if dynstate.TypeMayCarryUnknownDynamic(audited, targs.At(i)) {
				return nil, false
			}
		}
	}
	return named.Origin(), true
}

func verifyHarnessPackageVars(
	audited bool,
	pkg *packages.Package,
	declFuncs map[*types.Func]*ast.FuncDecl,
	initOnly map[*types.Func]bool,
	funcValueTaken map[*types.Func]bool,
	callSites map[*types.Func][]*ast.CallExpr,
	pkgVars []harnessVarSpecEntry,
	pkgVarSet map[*types.Var]harnessVarSpecEntry,
) (map[*types.Var]bool, bool) {
	if len(pkgVars) == 0 {
		return nil, true
	}
	info := pkg.TypesInfo

	categoryA := map[*types.Var]bool{}
	categorySyncMap := map[*types.Var]bool{}
	categoryImmutable := map[*types.Var]bool{}
	needsGeneratorImmutability := false

	for _, entry := range pkgVars {
		v := entry.v
		vt := v.Type()
		switch {
		case isSyncMapType(vt):
			if entry.val != nil {
				cl, ok := ast.Unparen(entry.val).(*ast.CompositeLit)
				if !ok || len(cl.Elts) != 0 {
					return nil, false
				}
			}
			categorySyncMap[v] = true
		case !dynstate.TypeMayCarryUnknownDynamic(audited, vt):
			// Disallow package-scope mutexes, atomics, or Once primitives.
			if containsSyncPrimitive(vt, map[types.Type]bool{}) {
				return nil, false
			}
			categoryA[v] = true
		default:
			// Category 3C: must have an explicit var-spec initializer and be one of:
			// (1) function signature bound to a package-local function or closed literal,
			// (2) *html/template.Template, or
			// (3) *Generator with carrier-free type args and unexported fields.
			if entry.val == nil {
				return nil, false
			}
			if _, isSig := types.Unalias(vt).Underlying().(*types.Signature); isSig {
				if !isClosedHarnessFuncInit(info, pkg.Types, entry.val) {
					return nil, false
				}
				categoryImmutable[v] = true
			} else if isTemplatePtrType(vt) {
				categoryImmutable[v] = true
			} else if _, ok := isCarrierFreeGeneratorPtrType(audited, pkg.Types, vt); ok {
				needsGeneratorImmutability = true
				categoryImmutable[v] = true
			} else {
				return nil, false
			}
		}
	}

	// Precompute carrier-free-at-all-callsites parameters for unexported non-value-taken functions.
	carrierFreeParam := map[*types.Var]bool{}
	for fn := range declFuncs {
		if fn.Exported() || funcValueTaken[fn] || fn.Signature().Variadic() {
			continue
		}
		sites := callSites[fn]
		if len(sites) == 0 {
			continue
		}
		params := fn.Signature().Params()
		for pIdx := 0; pIdx < params.Len(); pIdx++ {
			pv := params.At(pIdx)
			if !dynstate.TypeMayCarryUnknownDynamic(audited, pv.Type()) {
				carrierFreeParam[pv] = true
				continue
			}
			allCF := true
			for _, site := range sites {
				if site.Ellipsis.IsValid() || pIdx >= len(site.Args) {
					allCF = false
					break
				}
				argType := info.TypeOf(site.Args[pIdx])
				if argType == nil || dynstate.TypeMayCarryUnknownDynamic(audited, argType) {
					allCF = false
					break
				}
			}
			if allCF {
				carrierFreeParam[pv] = true
			}
		}
	}

	// Verify usage of every package-scope variable across all AST declarations.
	mutatedNamedStructs := collectMutatedHarnessNamedStructs(pkg)
	syncMapFuncs := map[*types.Func]bool{}
	syncMapRefFuncs := map[*types.Func]bool{}
	syncMapTypeAsserts := map[*ast.TypeAssertExpr]bool{}
	syncMapStoredVars := map[*types.Var]bool{}
	nonInitCategoryAUses := map[*ast.Ident]bool{}

	okVars := true
	checkVarUses := func(root ast.Node, inInitRoot bool, enclosingFn *types.Func) {
		approvedSyncMapIdents := map[*ast.Ident]bool{}
		approvedTemplateIdents := map[*ast.Ident]bool{}

		var walk func(n ast.Node, inInitExec bool, inLit bool)
		walk = func(n ast.Node, inInitExec bool, inLit bool) {
			if !okVars || n == nil {
				return
			}
			switch x := n.(type) {
			case *ast.FuncLit:
				walk(x.Type, false, true)
				walk(x.Body, false, true)
				return
			case *ast.GoStmt:
				walk(x.Call, false, true)
				return
			case *ast.Ident:
				if !inInitExec {
					if v, ok := info.Uses[x].(*types.Var); ok && categoryA[v] {
						nonInitCategoryAUses[x] = true
					}
				}
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if rootVar := rootPkgVar(info, lhs, pkgVarSet); rootVar != nil {
						if !categoryA[rootVar] || !inInitExec {
							okVars = false
							return
						}
					}
				}
			case *ast.IncDecStmt:
				if rootVar := rootPkgVar(info, x.X, pkgVarSet); rootVar != nil {
					if !categoryA[rootVar] || !inInitExec {
						okVars = false
						return
					}
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					for _, be := range []ast.Expr{x.Key, x.Value} {
						if be == nil {
							continue
						}
						if rootVar := rootPkgVar(info, be, pkgVarSet); rootVar != nil {
							if !categoryA[rootVar] || !inInitExec {
								okVars = false
								return
							}
						}
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if rootVar := rootPkgVar(info, x.X, pkgVarSet); rootVar != nil {
						if !categoryA[rootVar] || !inInitExec {
							okVars = false
							return
						}
					}
				}
			case *ast.CallExpr:
				// Builtin delete/clear/copy/append on package-scope slice/map globals.
				if id, ok := peelHarnessCallee(x.Fun).(*ast.Ident); ok {
					if b, isBuiltin := info.Uses[id].(*types.Builtin); isBuiltin && b != nil {
						if (b.Name() == "delete" || b.Name() == "clear" || b.Name() == "copy" || b.Name() == "append") && len(x.Args) > 0 {
							if rootVar := rootPkgVar(info, x.Args[0], pkgVarSet); rootVar != nil {
								if !categoryA[rootVar] || !inInitExec {
									okVars = false
									return
								}
							}
						}
					}
				}
				// sync.Map Load/Store and *template.Template Execute discipline.
				if sel, ok := peelHarnessCallee(x.Fun).(*ast.SelectorExpr); ok && sel.Sel != nil {
					if baseId, ok := ast.Unparen(sel.X).(*ast.Ident); ok {
						if v, ok := info.Uses[baseId].(*types.Var); ok && v != nil {
							if categorySyncMap[v] {
								mName := sel.Sel.Name
								if inLit || enclosingFn == nil || enclosingFn.Exported() || funcValueTaken[enclosingFn] {
									okVars = false
									return
								}
								if mName != "Load" && mName != "Store" {
									okVars = false
									return
								}
								wantArgs := 1
								if mName == "Store" {
									wantArgs = 2
								}
								if x.Ellipsis.IsValid() || len(x.Args) != wantArgs {
									okVars = false
									return
								}
								for pIdx := 0; pIdx < enclosingFn.Signature().Params().Len(); pIdx++ {
									if !carrierFreeParam[enclosingFn.Signature().Params().At(pIdx)] {
										okVars = false
										return
									}
								}
								if !isCarrierFreeSyncMapKey(audited, info, x.Args[0], carrierFreeParam) {
									okVars = false
									return
								}
								if mName == "Store" {
									sawMutableRef := false
									if !isImmutableHarnessCachedType(audited, pkg.Types, info.TypeOf(x.Args[1]), mutatedNamedStructs, &needsGeneratorImmutability, &sawMutableRef, map[types.Type]bool{}) {
										okVars = false
										return
									}
									if sawMutableRef {
										fd := declFuncs[enclosingFn]
										storedVars, okFresh := verifyFreshUnaliasedLocalAtStore(info, pkg.Types, fd, x.Args[1], x)
										if !okFresh {
											okVars = false
											return
										}
										syncMapRefFuncs[enclosingFn] = true
										for _, sv := range storedVars {
											if sv != nil && isRegexpOrSyntaxRegexpPtr(sv.Type()) {
												syncMapStoredVars[sv] = true
											}
										}
									}
								}
								syncMapFuncs[enclosingFn] = true
								approvedSyncMapIdents[baseId] = true
							} else if categoryImmutable[v] && isTemplatePtrType(v.Type()) {
								if sel.Sel.Name != "Execute" {
									okVars = false
									return
								}
								approvedTemplateIdents[baseId] = true
							}
						}
					}
				}
			}
			ast.Inspect(n, func(child ast.Node) bool {
				if !okVars || child == nil {
					return false
				}
				if child == n {
					return true
				}
				walk(child, inInitExec, inLit)
				return false
			})
		}
		walk(root, inInitRoot, false)
		if !okVars {
			return
		}
		// Ensure sync.Map and *template.Template vars do not escape via unapproved uses.
		ast.Inspect(root, func(n ast.Node) bool {
			if !okVars || n == nil {
				return false
			}
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			v, ok := info.Uses[id].(*types.Var)
			if !ok || v == nil {
				return true
			}
			if categorySyncMap[v] && !approvedSyncMapIdents[id] {
				okVars = false
				return false
			}
			if categoryImmutable[v] && isTemplatePtrType(v.Type()) && !approvedTemplateIdents[id] {
				okVars = false
				return false
			}
			return true
		})
	}

	for _, af := range pkg.Syntax {
		for _, decl := range af.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.Name == "init" {
					checkVarUses(d.Body, true, nil)
				} else if d.Recv == nil {
					fn, _ := info.Defs[d.Name].(*types.Func)
					checkVarUses(d.Body, fn != nil && initOnly[fn], fn)
				} else {
					checkVarUses(d.Body, false, nil)
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					checkVarUses(d, true, nil)
					break
				}
				for _, spec := range d.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok {
						for _, val := range vs.Values {
							checkVarUses(val, true, nil)
						}
					}
				}
			}
			if !okVars {
				return nil, false
			}
		}
	}

	for fn := range syncMapFuncs {
		fd := declFuncs[fn]
		if fd == nil || fd.Body == nil {
			return nil, false
		}
		res := fn.Signature().Results()
		for i := 0; i < res.Len(); i++ {
			rt := res.At(i).Type()
			if isErrorOrBoolType(rt) {
				continue
			}
			sawMutableRef := false
			if !isImmutableHarnessCachedType(audited, pkg.Types, rt, mutatedNamedStructs, &needsGeneratorImmutability, &sawMutableRef, map[types.Type]bool{}) {
				return nil, false
			}
			if sawMutableRef {
				syncMapRefFuncs[fn] = true
			}
		}
		okAssert := true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if !okAssert || n == nil {
				return false
			}
			ta, ok := n.(*ast.TypeAssertExpr)
			if !ok || ta.Type == nil {
				return true
			}
			sawMutableRef := false
			if !isImmutableHarnessCachedType(audited, pkg.Types, info.TypeOf(ta.Type), mutatedNamedStructs, &needsGeneratorImmutability, &sawMutableRef, map[types.Type]bool{}) {
				okAssert = false
				return false
			}
			if sawMutableRef {
				syncMapRefFuncs[fn] = true
				syncMapTypeAsserts[ta] = true
			}
			return true
		})
		if !okAssert {
			return nil, false
		}
	}

	var checkedGenStructs map[*types.Named]bool
	if needsGeneratorImmutability {
		if !verifyGeneratorFieldsWriteOnce(pkg) {
			return nil, false
		}
		var okGenImpl bool
		checkedGenStructs, okGenImpl = verifyCachedAndGlobalGeneratorImplsImmutable(audited, pkg, pkgVars, categoryImmutable, syncMapFuncs, mutatedNamedStructs)
		if !okGenImpl {
			return nil, false
		}
	}

	isGenPtr := func(t types.Type) bool {
		return isAnyGeneratorPtrType(pkg.Types, t)
	}
	if !dynstate.VerifyReadOnlyRefConfinement(pkg, dynstate.RefConfineConfig{
		IsImmutablePtr: isGenPtr,
		SeedStructOrigin: func(orig *types.Named) bool {
			return orig != nil && orig.Obj() != nil && !orig.Obj().Exported() && checkedGenStructs[orig]
		},
		CanBeSeedStructCapsule: func(orig *types.Named) bool {
			return orig != nil && !mutatedNamedStructs[orig]
		},
		AllowCompositeLitIntoSeedStruct: true,
		AllowReturnFromUnexportedFunc:   true,
		AllowIntraPkgInterfaceParam:     true,
		AllowScalarTypeParamProjection:  true,
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			switch e := ast.Unparen(expr).(type) {
			case *ast.Ident:
				if nonInitCategoryAUses[e] {
					vt := info.TypeOf(e)
					if dynstate.IsDirectMutableRefWith(vt, isGenPtr) {
						return true, true
					}
					if dynstate.TypeCarriesMutableRefWith(vt, isGenPtr) {
						return false, true
					}
					return false, false
				}
				if v, ok := info.Uses[e].(*types.Var); ok && syncMapStoredVars[v] {
					return true, true
				}
			case *ast.TypeAssertExpr:
				if syncMapTypeAsserts[e] && e.Type != nil {
					et := info.TypeOf(e.Type)
					if dynstate.TypeCarriesMutableRefWith(et, isGenPtr) {
						return dynstate.IsDirectMutableRefWith(et, isGenPtr), true
					}
				}
			case *ast.CallExpr:
				if callee := resolveHarnessFuncExpr(info, e.Fun); callee != nil && syncMapRefFuncs[callee.Origin()] {
					ct := info.TypeOf(e)
					if tup, isTup := ct.(*types.Tuple); isTup {
						for ti := 0; ti < tup.Len(); ti++ {
							if dynstate.TypeCarriesMutableRefWith(tup.At(ti).Type(), isGenPtr) {
								return false, true
							}
						}
						return false, false
					}
					if dynstate.TypeCarriesMutableRefWith(ct, isGenPtr) {
						return dynstate.IsDirectMutableRefWith(ct, isGenPtr), true
					}
				}
			}
			return false, false
		},
		AllowCallArg: func(call *ast.CallExpr, argIdx int, _ ast.Expr) bool {
			if call.Ellipsis.IsValid() {
				return false
			}
			sel, isSel := peelHarnessCallee(call.Fun).(*ast.SelectorExpr)
			if !isSel || sel.Sel == nil {
				return false
			}
			baseId, isID := ast.Unparen(sel.X).(*ast.Ident)
			if !isID {
				return false
			}
			v, isV := info.Uses[baseId].(*types.Var)
			if !isV || !categorySyncMap[v] {
				return false
			}
			switch sel.Sel.Name {
			case "Load":
				return len(call.Args) == 1 && argIdx == 0
			case "Store":
				return len(call.Args) == 2 && (argIdx == 0 || argIdx == 1)
			}
			return false
		},
		AllowMethodRecv: func(call *ast.CallExpr, callee *types.Func, _ ast.Expr) bool {
			if call.Ellipsis.IsValid() || callee == nil || callee.Pkg() == nil {
				return false
			}
			switch callee.Pkg().Path() {
			case "regexp":
				return callee.Name() == "Match" || callee.Name() == "MatchString" || callee.Name() == "String"
			case "regexp/syntax":
				return callee.Name() == "String"
			}
			return false
		},
	}) {
		return nil, false
	}

	return categoryA, true
}

func containsSyncPrimitive(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if seen[t] {
		return false
	}
	seen[t] = true
	if named, ok := t.(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() != nil {
		p := named.Obj().Pkg().Path()
		if p == "sync" || p == "sync/atomic" {
			return true
		}
	}
	switch u := t.Underlying().(type) {
	case *types.Chan:
		return true
	case *types.Pointer:
		return containsSyncPrimitive(u.Elem(), seen)
	case *types.Array:
		return containsSyncPrimitive(u.Elem(), seen)
	case *types.Slice:
		return containsSyncPrimitive(u.Elem(), seen)
	case *types.Map:
		return containsSyncPrimitive(u.Key(), seen) || containsSyncPrimitive(u.Elem(), seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if containsSyncPrimitive(u.Field(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func isAnyGeneratorPtrType(pkgTypes *types.Package, t types.Type) bool {
	if pkgTypes == nil || t == nil {
		return false
	}
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() == pkgTypes && named.Obj().Name() == "Generator"
}

func isRegexpOrSyntaxRegexpPtr(t types.Type) bool {
	if t == nil {
		return false
	}
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Name() != "Regexp" {
		return false
	}
	p := named.Obj().Pkg().Path()
	return p == "regexp" || p == "regexp/syntax"
}

func isClosedHarnessFuncInit(info *types.Info, pkgTypes *types.Package, e ast.Expr) bool {
	switch x := peelHarnessCallee(e).(type) {
	case *ast.Ident:
		fn, ok := info.Uses[x].(*types.Func)
		return ok && fn != nil && fn.Pkg() == pkgTypes
	case *ast.FuncLit:
		okLit := true
		ast.Inspect(x.Body, func(n ast.Node) bool {
			if !okLit || n == nil {
				return false
			}
			if id, ok := n.(*ast.Ident); ok {
				if v, ok := info.Uses[id].(*types.Var); ok && v != nil && !v.IsField() && v.Pkg() == pkgTypes && v.Parent() == pkgTypes.Scope() {
					okLit = false
					return false
				}
			}
			return true
		})
		return okLit
	}
	return false
}

func isCarrierFreeSyncMapKey(audited bool, info *types.Info, keyExpr ast.Expr, carrierFreeParam map[*types.Var]bool) bool {
	kt := info.TypeOf(keyExpr)
	if kt == nil {
		return false
	}
	if !dynstate.TypeMayCarryUnknownDynamic(audited, kt) {
		return true
	}
	if id, ok := ast.Unparen(keyExpr).(*ast.Ident); ok {
		if pv, ok := info.Uses[id].(*types.Var); ok && carrierFreeParam[pv] {
			return true
		}
	}
	return false
}

func rootImportedVar(info *types.Info, e ast.Expr, curPkg *types.Package) *types.Var {
	for e != nil {
		switch x := ast.Unparen(e).(type) {
		case *ast.Ident:
			if v, ok := info.Uses[x].(*types.Var); ok && !v.IsField() && v.Pkg() != nil && v.Pkg() != curPkg {
				return v
			}
			return nil
		case *ast.SelectorExpr:
			if x.Sel != nil {
				if v, ok := info.Uses[x.Sel].(*types.Var); ok && !v.IsField() && v.Pkg() != nil && v.Pkg() != curPkg {
					return v
				}
			}
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.SliceExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		default:
			return nil
		}
	}
	return nil
}

func rootPkgVar(
	info *types.Info,
	e ast.Expr,
	pkgVarSet map[*types.Var]harnessVarSpecEntry,
) *types.Var {
	for e != nil {
		switch x := ast.Unparen(e).(type) {
		case *ast.Ident:
			if v, ok := info.Uses[x].(*types.Var); ok {
				if _, exists := pkgVarSet[v]; exists {
					return v
				}
			}
			return nil
		case *ast.SelectorExpr:
			if x.Sel != nil {
				if v, ok := info.Uses[x.Sel].(*types.Var); ok && !v.IsField() {
					if _, exists := pkgVarSet[v]; exists {
						return v
					}
				}
			}
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.SliceExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		default:
			return nil
		}
	}
	return nil
}

func verifyGeneratorFieldsWriteOnce(pkg *packages.Package) bool {
	genObj, ok := pkg.Types.Scope().Lookup("Generator").(*types.TypeName)
	if !ok || genObj == nil {
		return false
	}
	genOrigin := genObj.Type().(*types.Named).Origin()
	info := pkg.TypesInfo

	isGenType := func(t types.Type) bool {
		if t == nil {
			return false
		}
		if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
			t = ptr.Elem()
		}
		named, ok := types.Unalias(t).(*types.Named)
		return ok && named.Origin() == genOrigin
	}

	exprChainHitsGen := func(e ast.Expr) (hit bool, directStringField bool) {
		if sel, isSel := ast.Unparen(e).(*ast.SelectorExpr); isSel && isGenType(info.TypeOf(sel.X)) {
			ft := info.TypeOf(sel)
			if ft != nil {
				if basic, isB := types.Unalias(ft).Underlying().(*types.Basic); isB && basic.Kind() == types.String {
					return true, true
				}
			}
			return true, false
		}
		for e != nil {
			switch x := ast.Unparen(e).(type) {
			case *ast.SelectorExpr:
				if isGenType(info.TypeOf(x.X)) {
					return true, false
				}
				if selInfo := info.Selections[x]; selInfo != nil && selInfo.Kind() == types.FieldVal {
					idx := selInfo.Index()
					cur := types.Unalias(selInfo.Recv())
					if ptr, isP := cur.(*types.Pointer); isP {
						cur = types.Unalias(ptr.Elem())
					}
					for step := 0; step < len(idx)-1; step++ {
						st, isSt := cur.Underlying().(*types.Struct)
						if !isSt || idx[step] >= st.NumFields() {
							break
						}
						cur = types.Unalias(st.Field(idx[step]).Type())
						if ptr, isP := cur.(*types.Pointer); isP {
							cur = types.Unalias(ptr.Elem())
						}
						if isGenType(cur) {
							return true, false
						}
					}
				}
				e = x.X
			case *ast.IndexExpr:
				e = x.X
			case *ast.SliceExpr:
				e = x.X
			case *ast.StarExpr:
				if isGenType(info.TypeOf(x.X)) {
					return true, false
				}
				e = x.X
			default:
				return false, false
			}
		}
		return false, false
	}

	okGen := true
	for _, af := range pkg.Syntax {
		var walk func(n ast.Node, inOnceDo bool)
		walk = func(n ast.Node, inOnceDo bool) {
			if !okGen || n == nil {
				return
			}
			if call, ok := n.(*ast.CallExpr); ok {
				if fn := resolveHarnessFuncExpr(info, call.Fun); fn != nil && fn.Name() == "Do" {
					if rPkg, rName := recvNamedTypeName(fn.Signature()); rPkg == "sync" && rName == "Once" && len(call.Args) == 1 {
						walk(call.Fun, inOnceDo)
						walk(call.Args[0], true)
						return
					}
				}
				if id, isID := peelHarnessCallee(call.Fun).(*ast.Ident); isID {
					if b, isB := info.Uses[id].(*types.Builtin); isB && (b.Name() == "delete" || b.Name() == "clear" || b.Name() == "copy" || b.Name() == "append") && len(call.Args) > 0 {
						if hit, _ := exprChainHitsGen(call.Args[0]); hit {
							okGen = false
							return
						}
					}
				}
			}
			switch x := n.(type) {
			case *ast.FuncLit:
				walk(x.Type, false)
				walk(x.Body, inOnceDo)
				return
			case *ast.GoStmt:
				walk(x.Call, false)
				return
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if hit, directStr := exprChainHitsGen(lhs); hit {
						if !inOnceDo || !directStr || x.Tok != token.ASSIGN {
							okGen = false
							return
						}
					}
				}
			case *ast.IncDecStmt:
				if hit, _ := exprChainHitsGen(x.X); hit {
					okGen = false
					return
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					for _, be := range []ast.Expr{x.Key, x.Value} {
						if be != nil {
							if hit, _ := exprChainHitsGen(be); hit {
								okGen = false
								return
							}
						}
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if hit, _ := exprChainHitsGen(x.X); hit {
						okGen = false
						return
					}
				}
			}
			ast.Inspect(n, func(child ast.Node) bool {
				if !okGen || child == nil {
					return false
				}
				if child == n {
					return true
				}
				walk(child, inOnceDo)
				return false
			})
		}
		walk(af, false)
		if !okGen {
			return false
		}
	}
	return true
}

func verifyCachedAndGlobalGeneratorImplsImmutable(
	audited bool,
	pkg *packages.Package,
	pkgVars []harnessVarSpecEntry,
	categoryImmutable map[*types.Var]bool,
	syncMapFuncs map[*types.Func]bool,
	mutatedNamedStructs map[*types.Named]bool,
) (map[*types.Named]bool, bool) {
	info := pkg.TypesInfo
	genObj, ok := pkg.Types.Scope().Lookup("Generator").(*types.TypeName)
	if !ok || genObj == nil {
		return nil, false
	}
	genOrigin := genObj.Type().(*types.Named).Origin()
	isGenPtr := func(t types.Type) bool {
		return isAnyGeneratorPtrType(pkg.Types, t)
	}

	allDecls := map[*types.Func]*ast.FuncDecl{}
	mutatedOrAddrLocals := map[*types.Var]bool{}
	markLocalChain := func(e ast.Expr, isDefStmt bool) {
		if id, isID := ast.Unparen(e).(*ast.Ident); isID {
			if v, isV := info.Uses[id].(*types.Var); isV && v != nil {
				mutatedOrAddrLocals[v] = true
			}
			return
		}
		if isDefStmt {
			return
		}
		for e != nil {
			switch x := ast.Unparen(e).(type) {
			case *ast.Ident:
				if v, isV := info.Uses[x].(*types.Var); isV && v != nil && !v.IsField() {
					mutatedOrAddrLocals[v] = true
				}
				return
			case *ast.SelectorExpr:
				e = x.X
			case *ast.IndexExpr:
				e = x.X
			case *ast.SliceExpr:
				e = x.X
			case *ast.StarExpr:
				e = x.X
			default:
				return
			}
		}
	}
	for _, af := range pkg.Syntax {
		for _, decl := range af.Decls {
			if fd, isFD := decl.(*ast.FuncDecl); isFD && fd.Name != nil && !(fd.Recv == nil && fd.Name.Name == "init") {
				if fn, isFn := info.Defs[fd.Name].(*types.Func); isFn && fn != nil {
					allDecls[fn.Origin()] = fd
				}
			}
		}
		ast.Inspect(af, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.AssignStmt:
				isDef := s.Tok == token.DEFINE
				for _, lhs := range s.Lhs {
					// Redeclared short-var in same block appears in Uses rather than Defs.
					markLocalChain(lhs, isDef)
				}
			case *ast.IncDecStmt:
				markLocalChain(s.X, false)
			case *ast.RangeStmt:
				if s.Tok == token.ASSIGN {
					for _, be := range []ast.Expr{s.Key, s.Value} {
						if be != nil {
							markLocalChain(be, false)
						}
					}
				}
			case *ast.UnaryExpr:
				if s.Op == token.AND {
					markLocalChain(s.X, false)
				}
			case *ast.CallExpr:
				if id, isID := peelHarnessCallee(s.Fun).(*ast.Ident); isID {
					if b, isB := info.Uses[id].(*types.Builtin); isB && (b.Name() == "delete" || b.Name() == "clear" || b.Name() == "copy" || b.Name() == "append") && len(s.Args) > 0 {
						markLocalChain(s.Args[0], false)
					}
				}
			}
			return true
		})
	}

	checkedStructs := map[*types.Named]bool{}
	var verifyConstructedStruct func(named *types.Named) bool
	var verifyFieldType func(ft types.Type, seen map[types.Type]bool) bool

	verifyFieldType = func(ft types.Type, seen map[types.Type]bool) bool {
		if ft == nil {
			return false
		}
		ft = types.Unalias(ft)
		if _, isTP := ft.(*types.TypeParam); isTP {
			return true
		}
		if isGenPtr(ft) {
			return true
		}
		if seen[ft] {
			return true
		}
		seen[ft] = true
		if fnamed, isN := ft.(*types.Named); isN && fnamed.Obj() != nil {
			if fnamed.Obj().Pkg() == pkg.Types {
				if fnamed.Origin() == genOrigin {
					return true
				}
				if _, isSubSt := fnamed.Underlying().(*types.Struct); isSubSt {
					return verifyConstructedStruct(fnamed)
				}
			} else if fnamed.Obj().Pkg() != nil {
				p := fnamed.Obj().Pkg().Path()
				if p == "sync" || p == "sync/atomic" {
					return false
				}
			}
		}
		switch u := ft.Underlying().(type) {
		case *types.Basic:
			return u.Kind() != types.UnsafePointer && u.Kind() != types.Invalid
		case *types.Pointer:
			elem := types.Unalias(u.Elem())
			enamed, isEN := elem.(*types.Named)
			if !isEN || enamed.Obj() == nil {
				return false
			}
			if enamed.Obj().Pkg() == pkg.Types {
				if enamed.Origin() == genOrigin {
					return true
				}
				if _, isSubSt := enamed.Underlying().(*types.Struct); isSubSt && !enamed.Obj().Exported() {
					return verifyConstructedStruct(enamed)
				}
				return false
			}
			if enamed.Obj().Pkg() != nil {
				p, n := enamed.Obj().Pkg().Path(), enamed.Obj().Name()
				if ((p == "regexp" && n == "Regexp") || (p == "regexp/syntax" && n == "Regexp") || (p == "unicode" && n == "RangeTable")) && !mutatedNamedStructs[enamed.Origin()] {
					return true
				}
			}
			return false
		case *types.Slice:
			return verifyFieldType(u.Elem(), seen)
		case *types.Array:
			return verifyFieldType(u.Elem(), seen)
		case *types.Map, *types.Chan, *types.Interface:
			return false
		case *types.Struct:
			if _, isN := ft.(*types.Named); !isN && u.NumFields() > 0 {
				return false
			}
			for i := 0; i < u.NumFields(); i++ {
				if !verifyFieldType(u.Field(i).Type(), seen) {
					return false
				}
			}
		}
		return true
	}

	verifyConstructedStruct = func(named *types.Named) bool {
		if named == nil || named.Obj() == nil || named.Obj().Pkg() != pkg.Types {
			return false
		}
		orig := named.Origin()
		if orig == genOrigin {
			return true
		}
		if orig.Obj().Exported() || mutatedNamedStructs[orig] {
			return false
		}
		if checkedStructs[orig] {
			return true
		}
		checkedStructs[orig] = true
		st, isSt := orig.Underlying().(*types.Struct)
		if !isSt {
			return false
		}
		for i := 0; i < st.NumFields(); i++ {
			if !verifyFieldType(st.Field(i).Type(), map[types.Type]bool{}) {
				return false
			}
		}
		return true
	}

	var roots []ast.Node
	visitedFuncs := map[*types.Func]bool{}
	var queue []*types.Func
	enqueueFn := func(fn *types.Func) {
		if fn == nil {
			return
		}
		orig := fn.Origin()
		if allDecls[orig] != nil && !visitedFuncs[orig] {
			visitedFuncs[orig] = true
			queue = append(queue, orig)
		}
	}

	for _, entry := range pkgVars {
		if categoryImmutable[entry.v] && entry.val != nil {
			if _, okGen := isCarrierFreeGeneratorPtrType(audited, pkg.Types, entry.v.Type()); okGen {
				roots = append(roots, entry.val)
			}
		}
	}
	for fn := range syncMapFuncs {
		enqueueFn(fn)
	}

	hasIfaceRecv := func(fn *types.Func) bool {
		sig := fn.Signature()
		if sig == nil || sig.Recv() == nil {
			return false
		}
		_, okIf := sig.Recv().Type().Underlying().(*types.Interface)
		return okIf
	}

	checkSubtree := func(root ast.Node) bool {
		okNode := true
		ast.Inspect(root, func(n ast.Node) bool {
			if !okNode || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.Ident:
				if inst, hasInst := info.Instances[x]; hasInst && inst.TypeArgs != nil {
					for ti := 0; ti < inst.TypeArgs.Len(); ti++ {
						targ := types.Unalias(inst.TypeArgs.At(ti))
						if _, isTP := targ.(*types.TypeParam); isTP {
							continue
						}
						if dynstate.TypeCarriesMutableRefWith(targ, isGenPtr) || types.IsInterface(targ) || !verifyFieldType(targ, map[types.Type]bool{}) {
							okNode = false
							return false
						}
					}
				}
				if fn, isFn := info.Uses[x].(*types.Func); isFn && fn != nil && fn.Pkg() == pkg.Types {
					if hasIfaceRecv(fn) {
						okNode = false
						return false
					}
					enqueueFn(fn)
				}
			case *ast.CompositeLit:
				lt := info.TypeOf(x)
				if lt != nil {
					lt = types.Unalias(lt)
					if ptr, isP := lt.(*types.Pointer); isP {
						lt = types.Unalias(ptr.Elem())
					}
					if named, isN := lt.(*types.Named); isN {
						if _, isSt := named.Underlying().(*types.Struct); isSt {
							if named.Obj() != nil && named.Obj().Pkg() != pkg.Types {
								p, nm := "", named.Obj().Name()
								if named.Obj().Pkg() != nil {
									p = named.Obj().Pkg().Path()
								}
								if !(p == "unicode" && (nm == "RangeTable" || nm == "Range16" || nm == "Range32")) {
									okNode = false
									return false
								}
							} else if !verifyConstructedStruct(named) {
								okNode = false
								return false
							}
						}
					} else if stUnder, isSt := lt.Underlying().(*types.Struct); isSt && stUnder.NumFields() > 0 {
						okNode = false
						return false
					}
				}
			case *ast.CallExpr:
				base := peelHarnessCallee(x.Fun)
				if info.Types[base].IsType() {
					return true
				}
				if id, isID := base.(*ast.Ident); isID {
					if b, isB := info.Uses[id].(*types.Builtin); isB {
						if b.Name() == "new" && len(x.Args) == 1 {
							nt := types.Unalias(info.TypeOf(x.Args[0]))
							named, isN := nt.(*types.Named)
							if !isN || !verifyConstructedStruct(named) {
								okNode = false
								return false
							}
						}
						return true
					}
				}
				callee := resolveHarnessFuncExpr(info, x.Fun)
				if callee == nil {
					okNode = false
					return false
				}
				if callee.Pkg() == pkg.Types {
					if hasIfaceRecv(callee) {
						okNode = false
						return false
					}
					enqueueFn(callee)
				}
			case *ast.FuncLit:
				// Any outer local variable captured by a closure constructed in this cone
				// must be immutable and carry zero mutable references.
				localDefs := map[*types.Var]bool{}
				ast.Inspect(x, func(cn ast.Node) bool {
					if id, isID := cn.(*ast.Ident); isID {
						if dv, isV := info.Defs[id].(*types.Var); isV && dv != nil {
							localDefs[dv] = true
						}
					}
					return true
				})
				ast.Inspect(x.Body, func(cn ast.Node) bool {
					if !okNode || cn == nil {
						return false
					}
					if id, isID := cn.(*ast.Ident); isID {
						if uv, isV := info.Uses[id].(*types.Var); isV && uv != nil && !uv.IsField() &&
							uv.Pkg() == pkg.Types && uv.Parent() != pkg.Types.Scope() && !localDefs[uv] {
							if mutatedOrAddrLocals[uv] || dynstate.TypeCarriesMutableRefWith(uv.Type(), isGenPtr) || !verifyFieldType(uv.Type(), map[types.Type]bool{}) {
								okNode = false
								return false
							}
						}
					}
					return true
				})
			}
			return true
		})
		return okNode
	}

	for _, r := range roots {
		if !checkSubtree(r) {
			return nil, false
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		fd := allDecls[cur]
		if fd == nil || fd.Body == nil || !checkSubtree(fd.Body) {
			return nil, false
		}
	}
	return checkedStructs, true
}

// verifyHarnessExportedSurface verifies the exported types, functions, and
// methods of pkg. Exported package-scope variables are rejected up front in
// verifyPropertyHarnessPackageWithReason as the single source of truth.
func verifyHarnessExportedSurface(audited bool, pkg *packages.Package) bool {
	scope := pkg.Types.Scope()
	if scope == nil {
		return false
	}

	// Exported type T must exist as a struct with zero exported fields.
	tObj, ok := scope.Lookup("T").(*types.TypeName)
	if !ok || tObj == nil || !tObj.Exported() || !propertyHarnessHandleType(tObj.Type()) {
		return false
	}

	// Exported Check and MakeCheck functions must exist.
	checkFn, ok := scope.Lookup("Check").(*types.Func)
	if !ok || checkFn == nil || !checkFn.Exported() {
		return false
	}
	makeCheckFn, ok := scope.Lookup("MakeCheck").(*types.Func)
	if !ok || makeCheckFn == nil || !makeCheckFn.Exported() {
		return false
	}

	allDecls := map[*types.Func]*ast.FuncDecl{}
	for _, af := range pkg.Syntax {
		for _, decl := range af.Decls {
			if fd, isFD := decl.(*ast.FuncDecl); isFD && fd.Name != nil && !(fd.Recv == nil && fd.Name.Name == "init") {
				if fn, isFn := pkg.TypesInfo.Defs[fd.Name].(*types.Func); isFn && fn != nil {
					allDecls[fn.Origin()] = fd
				}
			}
		}
	}

	tNamed := tObj.Type().(*types.Named)
	checkedNamed := map[*types.Named]bool{}
	var rule2Queue []*types.Named
	enqueueNamed := func(n *types.Named) {
		if n == nil {
			return
		}
		orig := n.Origin()
		if !checkedNamed[orig] {
			checkedNamed[orig] = true
			rule2Queue = append(rule2Queue, orig)
		}
	}

	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		if obj == nil || !obj.Exported() {
			continue
		}
		switch o := obj.(type) {
		case *types.Func:
			sig := o.Signature()
			if !checkHarnessResultTuple(audited, pkg.TypesInfo, allDecls, pkg.Types, tNamed, o, sig, nil, nil, enqueueNamed) {
				return false
			}
		case *types.TypeName:
			if _, isIface := o.Type().Underlying().(*types.Interface); isIface {
				continue
			}
			named, ok := types.Unalias(o.Type()).(*types.Named)
			if !ok {
				continue
			}
			enqueueNamed(named)
		}
	}

	for len(rule2Queue) > 0 {
		cur := rule2Queue[0]
		rule2Queue = rule2Queue[1:]
		if !checkAllExportedMethodsOfNamed(audited, pkg.TypesInfo, allDecls, pkg.Types, tNamed, cur, enqueueNamed) {
			return false
		}
	}

	return true
}

func checkAllExportedMethodsOfNamed(
	audited bool,
	info *types.Info,
	allDecls map[*types.Func]*ast.FuncDecl,
	pkgTypes *types.Package,
	tNamed *types.Named,
	owner *types.Named,
	enqueueNamed func(*types.Named),
) bool {
	if owner == nil {
		return false
	}
	ownerTPs := owner.TypeParams()
	visited := map[types.Type]bool{}
	var walk func(t types.Type) bool
	walk = func(t types.Type) bool {
		if t == nil {
			return true
		}
		t = types.Unalias(t)
		if ptr, ok := t.(*types.Pointer); ok {
			t = types.Unalias(ptr.Elem())
		}
		if visited[t] {
			return true
		}
		visited[t] = true
		if named, ok := t.(*types.Named); ok {
			for i := 0; i < named.NumMethods(); i++ {
				m := named.Method(i)
				if !m.Exported() {
					continue
				}
				if !checkHarnessResultTuple(audited, info, allDecls, pkgTypes, tNamed, m, m.Signature(), owner, ownerTPs, enqueueNamed) {
					return false
				}
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				f := u.Field(i)
				if f.Embedded() {
					if !walk(f.Type()) {
						return false
					}
				}
			}
		case *types.Interface:
			for i := 0; i < u.NumMethods(); i++ {
				m := u.Method(i)
				if !m.Exported() {
					continue
				}
				if !checkHarnessResultTuple(audited, info, allDecls, pkgTypes, tNamed, m, m.Signature(), owner, ownerTPs, enqueueNamed) {
					return false
				}
			}
		}
		return true
	}
	return walk(owner)
}

func checkHarnessResultTuple(
	audited bool,
	info *types.Info,
	allDecls map[*types.Func]*ast.FuncDecl,
	pkgTypes *types.Package,
	tNamed *types.Named,
	fnObj *types.Func,
	sig *types.Signature,
	recvNamed *types.Named,
	ownerTypeParams *types.TypeParamList,
	enqueueNamed func(*types.Named),
) bool {
	if sig == nil {
		return false
	}
	results := sig.Results()
	for i := 0; i < results.Len(); i++ {
		if !validHarnessExportedResultType(audited, info, allDecls, pkgTypes, tNamed, fnObj, sig, recvNamed, ownerTypeParams, results.At(i).Type(), enqueueNamed) {
			return false
		}
	}
	return true
}

func validHarnessExportedResultType(
	audited bool,
	info *types.Info,
	allDecls map[*types.Func]*ast.FuncDecl,
	pkgTypes *types.Package,
	tNamed *types.Named,
	fnObj *types.Func,
	sig *types.Signature,
	recvNamed *types.Named,
	ownerTypeParams *types.TypeParamList,
	ret types.Type,
	enqueueNamed func(*types.Named),
) bool {
	if ret == nil {
		return false
	}
	unaliased := types.Unalias(ret)

	// 1. Type parameter declared on the generic function or generic receiver itself,
	// provided the callable either requires *T/TB in its parameter list (e.g. Draw),
	// is a pure 1-parameter identity function (e.g. ID[V](v V) V), or is the
	// variadic (*Generator[V]).Example(seed ...int) V method verified to override
	// its PRNG seed from seed[0] when len(seed) > 0.
	if tp, ok := unaliased.(*types.TypeParam); ok {
		inScope := false
		if tps := sig.TypeParams(); tps != nil {
			for i := 0; i < tps.Len(); i++ {
				if tps.At(i) == tp {
					inScope = true
					break
				}
			}
		}
		if !inScope {
			if rtps := sig.RecvTypeParams(); rtps != nil {
				for i := 0; i < rtps.Len(); i++ {
					if rtps.At(i) == tp {
						inScope = true
						break
					}
				}
			}
		}
		if !inScope && ownerTypeParams != nil {
			for i := 0; i < ownerTypeParams.Len(); i++ {
				if ownerTypeParams.At(i) == tp {
					inScope = true
					break
				}
			}
		}
		if !inScope || fnObj == nil {
			return false
		}
		if sigRequiresHarnessHandleOrTB(pkgTypes, tNamed, sig) {
			return true
		}
		fd := allDecls[fnObj.Origin()]
		if sig.Recv() == nil && !sig.Variadic() && sig.Params().Len() == 1 && sig.Results().Len() == 1 &&
			types.Identical(types.Unalias(sig.Params().At(0).Type()), tp) &&
			isPureIdentityFuncDecl(info, fd, sig.Params().At(0)) {
			return true
		}
		if recvNamed != nil && recvNamed.Origin().Obj() != nil &&
			recvNamed.Origin().Obj().Pkg() == pkgTypes && recvNamed.Origin().Obj().Name() == "Generator" &&
			fnObj.Name() == "Example" && sig.Variadic() && sig.Params().Len() == 1 && sig.Results().Len() == 1 &&
			isTypesIntSlice(sig.Params().At(0).Type()) &&
			verifyGeneratorExampleSeedOverride(info, fd, sig.Params().At(0)) {
			return true
		}
		return false
	}

	// 0. Pure value results (scalars, strings, and value arrays/structs of them) that neither
	// carry dynamic dispatch nor hand out pointers, slices, maps, or channels. If a value
	// struct defined in pkgTypes is returned, enqueue it so any promoted exported methods are checked.
	if !dynstate.TypeMayCarryUnknownDynamic(audited, ret) && !typeHandsOutMutableAlias(ret, map[types.Type]bool{}) {
		if named, ok := unaliased.(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() == pkgTypes && enqueueNamed != nil {
			enqueueNamed(named)
		}
		return true
	}

	// 2. Pointer to a struct defined in pkgTypes with zero exported or promoted fields
	// (*T, *Generator, *Generator[V], etc.), provided all direct and promoted exported
	// methods on that struct also satisfy this grammar.
	if ptr, ok := unaliased.(*types.Pointer); ok {
		if named, ok := types.Unalias(ptr.Elem()).(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() == pkgTypes {
			if st, ok := named.Underlying().(*types.Struct); ok && structHasNoExportedFields(st) {
				if enqueueNamed != nil {
					enqueueNamed(named)
				}
				return true
			}
		}
	}

	// 3. Subtest/fuzz/action callback shapes: func(*testing.T), func(*testing.T, []byte), map[string]func(*T).
	if fnSig, ok := unaliased.Underlying().(*types.Signature); ok && fnSig.Recv() == nil && fnSig.Results().Len() == 0 && !fnSig.Variadic() {
		params := fnSig.Params()
		if params.Len() == 1 && isTestingTPtrType(params.At(0).Type()) {
			return true
		}
		if params.Len() == 2 && isTestingTPtrType(params.At(0).Type()) && isTypesByteSlice(params.At(1).Type()) {
			return true
		}
	}
	if mp, ok := unaliased.Underlying().(*types.Map); ok {
		if keyBasic, ok := types.Unalias(mp.Key()).Underlying().(*types.Basic); ok && keyBasic.Kind() == types.String {
			if valSig, ok := types.Unalias(mp.Elem()).Underlying().(*types.Signature); ok &&
				valSig.Recv() == nil && valSig.Results().Len() == 0 && !valSig.Variadic() && valSig.Params().Len() == 1 {
				if ptr, ok := types.Unalias(valSig.Params().At(0).Type()).(*types.Pointer); ok && types.Identical(types.Unalias(ptr.Elem()), tNamed) {
					return true
				}
			}
		}
	}

	// 4. (*T).Context() context.Context and (*T).Output() io.Writer.
	if recvNamed != nil && recvNamed.Origin() == tNamed.Origin() {
		if named, ok := unaliased.(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() != nil {
			p, n := named.Obj().Pkg().Path(), named.Obj().Name()
			if (p == "context" && n == "Context") || (p == "io" && n == "Writer") {
				return true
			}
		}
	}

	return false
}

func sigRequiresHarnessHandleOrTB(pkgTypes *types.Package, tNamed *types.Named, sig *types.Signature) bool {
	if sig == nil {
		return false
	}
	params := sig.Params()
	n := params.Len()
	if sig.Variadic() && n > 0 {
		n--
	}
	for i := 0; i < n; i++ {
		pt := types.Unalias(params.At(i).Type())
		if ptr, isP := pt.(*types.Pointer); isP {
			if named, isN := types.Unalias(ptr.Elem()).(*types.Named); isN && named.Origin() == tNamed.Origin() {
				return true
			}
		}
		if named, isN := pt.(*types.Named); isN && named.Obj() != nil {
			if named.Obj().Pkg() == pkgTypes && named.Obj().Name() == "TB" {
				return true
			}
			if named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "testing" && named.Obj().Name() == "TB" {
				return true
			}
		}
	}
	return false
}

func isPureIdentityFuncDecl(info *types.Info, fd *ast.FuncDecl, param *types.Var) bool {
	if info == nil || fd == nil || fd.Body == nil || param == nil || len(fd.Body.List) != 1 {
		return false
	}
	ret, ok := fd.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	id, ok := ast.Unparen(ret.Results[0]).(*ast.Ident)
	return ok && info.Uses[id] == param
}

func isTypesIntSlice(t types.Type) bool {
	sl, ok := types.Unalias(t).Underlying().(*types.Slice)
	if !ok {
		return false
	}
	b, ok := types.Unalias(sl.Elem()).Underlying().(*types.Basic)
	return ok && b.Kind() == types.Int
}

func verifyGeneratorExampleSeedOverride(info *types.Info, fd *ast.FuncDecl, seedParam *types.Var) bool {
	if info == nil || fd == nil || fd.Body == nil || seedParam == nil || len(fd.Body.List) < 2 {
		return false
	}
	isLenSeedPositive := func(cond ast.Expr) bool {
		bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
		if !ok {
			return false
		}
		isLenSeed := func(e ast.Expr) bool {
			call, isC := ast.Unparen(e).(*ast.CallExpr)
			if !isC || len(call.Args) != 1 {
				return false
			}
			id, isID := peelHarnessCallee(call.Fun).(*ast.Ident)
			if !isID {
				return false
			}
			b, isB := info.Uses[id].(*types.Builtin)
			if !isB || b.Name() != "len" {
				return false
			}
			argID, isArgID := ast.Unparen(call.Args[0]).(*ast.Ident)
			return isArgID && info.Uses[argID] == seedParam
		}
		isIntConst := func(e ast.Expr, want int64) bool {
			tv, okTV := info.Types[e]
			if !okTV || tv.Value == nil || tv.Value.Kind() != constant.Int {
				return false
			}
			v, exact := constant.Int64Val(tv.Value)
			return exact && v == want
		}
		return (isLenSeed(bin.X) && ((bin.Op == token.GTR && isIntConst(bin.Y, 0)) || (bin.Op == token.NEQ && isIntConst(bin.Y, 0)) || (bin.Op == token.GEQ && isIntConst(bin.Y, 1)))) ||
			(isLenSeed(bin.Y) && ((bin.Op == token.LSS && isIntConst(bin.X, 0)) || (bin.Op == token.NEQ && isIntConst(bin.X, 0)) || (bin.Op == token.LEQ && isIntConst(bin.X, 1))))
	}
	isSeedElem0Expr := func(e ast.Expr) bool {
		cur := ast.Unparen(e)
		if call, isC := cur.(*ast.CallExpr); isC && len(call.Args) == 1 && info.Types[peelHarnessCallee(call.Fun)].IsType() {
			cur = ast.Unparen(call.Args[0])
		}
		idx, isIdx := cur.(*ast.IndexExpr)
		if !isIdx {
			return false
		}
		baseID, isID := ast.Unparen(idx.X).(*ast.Ident)
		if !isID || info.Uses[baseID] != seedParam {
			return false
		}
		tv, okTV := info.Types[idx.Index]
		if !okTV || tv.Value == nil || tv.Value.Kind() != constant.Int {
			return false
		}
		v, exact := constant.Int64Val(tv.Value)
		return exact && v == 0
	}

	// Pattern 1 (rapid@v1.3.0): s := baseSeed(); if len(seed) > 0 { s = uint64(seed[0]) }
	if initAs, okAs := fd.Body.List[0].(*ast.AssignStmt); okAs && initAs.Tok == token.DEFINE && len(initAs.Lhs) == 1 && len(initAs.Rhs) == 1 {
		if sID, okID := ast.Unparen(initAs.Lhs[0]).(*ast.Ident); okID {
			if sVar, okV := info.Defs[sID].(*types.Var); okV && sVar != nil {
				if ifs, okIf := fd.Body.List[1].(*ast.IfStmt); okIf && ifs.Init == nil && ifs.Else == nil &&
					isLenSeedPositive(ifs.Cond) && ifs.Body != nil && len(ifs.Body.List) == 1 {
					if ovAs, okOv := ifs.Body.List[0].(*ast.AssignStmt); okOv && ovAs.Tok == token.ASSIGN && len(ovAs.Lhs) == 1 && len(ovAs.Rhs) == 1 {
						if lhsID, okLID := ast.Unparen(ovAs.Lhs[0]).(*ast.Ident); okLID && info.Uses[lhsID] == sVar && isSeedElem0Expr(ovAs.Rhs[0]) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func isTestingTPtrType(t types.Type) bool {
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil &&
		named.Obj().Pkg().Path() == "testing" && named.Obj().Name() == "T"
}

func isTypesByteSlice(t types.Type) bool {
	sl, ok := types.Unalias(t).Underlying().(*types.Slice)
	if !ok {
		return false
	}
	basic, ok := types.Unalias(sl.Elem()).Underlying().(*types.Basic)
	return ok && basic.Kind() == types.Byte
}

func typeHandsOutMutableAlias(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return true
	}
	t = types.Unalias(t)
	if seen[t] {
		return false
	}
	seen[t] = true
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Kind() == types.UnsafePointer || u.Kind() == types.Invalid
	case *types.Array:
		return typeHandsOutMutableAlias(u.Elem(), seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if typeHandsOutMutableAlias(u.Field(i).Type(), seen) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func verifyJoinedSynctestGoStmt(info *types.Info, pkgTypes *types.Package, body *ast.BlockStmt, goStmt *ast.GoStmt) bool {
	if body == nil || goStmt == nil || goStmt.Call == nil || goStmt.Call.Ellipsis.IsValid() || len(goStmt.Call.Args) != 0 {
		return false
	}
	lit, ok := ast.Unparen(goStmt.Call.Fun).(*ast.FuncLit)
	if !ok || lit.Body == nil || len(lit.Body.List) == 0 {
		return false
	}

	goIdx := -1
	for i, st := range body.List {
		if st == goStmt {
			goIdx = i
			break
		}
	}
	if goIdx <= 0 || goIdx+1 >= len(body.List) {
		return false
	}

	// Locate top-level synctest.Test(parent, func(st *testing.T) { ... }) inside lit.Body.List.
	syncIdx := -1
	var synctestCallback ast.Node
	for i, st := range lit.Body.List {
		es, isES := st.(*ast.ExprStmt)
		if !isES {
			continue
		}
		call, isC := ast.Unparen(es.X).(*ast.CallExpr)
		if !isC || len(call.Args) != 2 {
			continue
		}
		if callee := resolveHarnessFuncExpr(info, call.Fun); callee != nil && callee.Pkg() != nil &&
			callee.Pkg().Path() == "testing/synctest" && callee.Name() == "Test" {
			if syncIdx != -1 {
				return false
			}
			syncIdx = i
			synctestCallback = call.Args[1]
		}
	}
	if syncIdx == -1 {
		return false
	}

	// Disallow any extra GoStmt inside lit.Body outside synctest.Test's bubble callback.
	hasExtraGo := false
	var scanOutsideBubble func(n ast.Node)
	scanOutsideBubble = func(n ast.Node) {
		if n == nil || hasExtraGo || n == synctestCallback {
			return
		}
		if _, isGo := n.(*ast.GoStmt); isGo {
			hasExtraGo = true
			return
		}
		ast.Inspect(n, func(child ast.Node) bool {
			if child == nil || hasExtraGo {
				return false
			}
			if child == n {
				return true
			}
			scanOutsideBubble(child)
			return false
		})
	}
	scanOutsideBubble(lit.Body)
	if hasExtraGo {
		return false
	}

	// Identify the single channel variable sent as the final action of lit.Body:
	// either (A) the final statement of a single top-level defer func() { ... }() at deferIdx < syncIdx
	// with zero ReturnStmt/DeferStmt before deferIdx+1 and zero ReturnStmt/BranchStmt inside the defer,
	// or (B) the final top-level statement of lit.Body.List after syncIdx with zero top-level DeferStmt
	// and zero ReturnStmt before it.
	var chVar *types.Var
	if lastSt, isSend := lit.Body.List[len(lit.Body.List)-1].(*ast.SendStmt); isSend && syncIdx < len(lit.Body.List)-1 {
		if chID, isID := ast.Unparen(lastSt.Chan).(*ast.Ident); isID {
			if v, isV := info.Uses[chID].(*types.Var); isV && v != nil && v.Parent() != pkgTypes.Scope() {
				badBefore := false
				for i := 0; i < len(lit.Body.List)-1; i++ {
					ast.Inspect(lit.Body.List[i], func(n ast.Node) bool {
						if n == synctestCallback || badBefore || n == nil {
							return false
						}
						switch n.(type) {
						case *ast.DeferStmt, *ast.ReturnStmt:
							badBefore = true
							return false
						case *ast.FuncLit:
							return false
						}
						return true
					})
				}
				if !badBefore {
					chVar = v
				}
			}
		}
	} else {
		deferIdx := -1
		var deferLit *ast.FuncLit
		for i := 0; i < syncIdx; i++ {
			ds, isDS := lit.Body.List[i].(*ast.DeferStmt)
			if !isDS {
				continue
			}
			if deferIdx != -1 || ds.Call == nil || ds.Call.Ellipsis.IsValid() || len(ds.Call.Args) != 0 {
				return false
			}
			dl, isFL := ast.Unparen(ds.Call.Fun).(*ast.FuncLit)
			if !isFL || dl.Body == nil || len(dl.Body.List) == 0 {
				return false
			}
			deferIdx = i
			deferLit = dl
		}
		if deferIdx != -1 && deferLit != nil {
			if sendSt, isSend := deferLit.Body.List[len(deferLit.Body.List)-1].(*ast.SendStmt); isSend {
				if chID, isID := ast.Unparen(sendSt.Chan).(*ast.Ident); isID {
					if v, isV := info.Uses[chID].(*types.Var); isV && v != nil && v.Parent() != pkgTypes.Scope() {
						badDefer := false
						for i := 0; i <= deferIdx; i++ {
							if i == deferIdx {
								continue
							}
							ast.Inspect(lit.Body.List[i], func(n ast.Node) bool {
								if badDefer || n == nil {
									return false
								}
								switch n.(type) {
								case *ast.ReturnStmt, *ast.DeferStmt, *ast.BranchStmt:
									badDefer = true
									return false
								case *ast.FuncLit:
									return false
								}
								return true
							})
						}
						for i := 0; i < len(deferLit.Body.List)-1; i++ {
							ast.Inspect(deferLit.Body.List[i], func(n ast.Node) bool {
								if badDefer || n == nil {
									return false
								}
								switch n.(type) {
								case *ast.ReturnStmt, *ast.BranchStmt, *ast.GoStmt:
									badDefer = true
									return false
								case *ast.FuncLit:
									return false
								}
								return true
							})
						}
						if !badDefer {
							chVar = v
						}
					}
				}
			}
		}
	}
	if chVar == nil {
		return false
	}

	// Locate top-level ch := make(chan ...) at defIdx < goIdx in body.List.
	defIdx := -1
	for i := 0; i < goIdx; i++ {
		as, isAS := body.List[i].(*ast.AssignStmt)
		if !isAS || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			continue
		}
		id, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
		if !isID || info.Defs[id] != chVar {
			continue
		}
		if !isMakeChanCall(info, as.Rhs[0]) {
			return false
		}
		defIdx = i
		break
	}
	if defIdx == -1 {
		return false
	}

	isRecvOnCh := func(e ast.Expr) bool {
		un, isUn := ast.Unparen(e).(*ast.UnaryExpr)
		if !isUn || un.Op != token.ARROW {
			return false
		}
		id, isID := ast.Unparen(un.X).(*ast.Ident)
		return isID && info.Uses[id] == chVar
	}
	isTopLevelUnconditionalRecv := func(st ast.Stmt) bool {
		switch s := st.(type) {
		case *ast.ExprStmt:
			return isRecvOnCh(s.X)
		case *ast.AssignStmt:
			return len(s.Rhs) == 1 && (len(s.Lhs) == 1 || len(s.Lhs) == 2) && isRecvOnCh(s.Rhs[0])
		case *ast.IfStmt:
			if s.Init != nil {
				as, isAS := s.Init.(*ast.AssignStmt)
				return isAS && len(as.Rhs) == 1 && (len(as.Lhs) == 1 || len(as.Lhs) == 2) && isRecvOnCh(as.Rhs[0])
			}
			if isRecvOnCh(s.Cond) {
				return true
			}
			if bin, isBin := ast.Unparen(s.Cond).(*ast.BinaryExpr); isBin && (bin.Op == token.EQL || bin.Op == token.NEQ) {
				return isRecvOnCh(bin.X) || isRecvOnCh(bin.Y)
			}
		}
		return false
	}

	recvIdx := -1
	for i := goIdx + 1; i < len(body.List); i++ {
		if isTopLevelUnconditionalRecv(body.List[i]) {
			recvIdx = i
			break
		}
	}
	if recvIdx == -1 {
		return false
	}

	// Disallow ReturnStmt, BranchStmt, or GoStmt anywhere in body.List[goIdx+1 : recvIdx].
	badBetween := false
	for i := goIdx + 1; i < recvIdx; i++ {
		ast.Inspect(body.List[i], func(n ast.Node) bool {
			if badBetween || n == nil {
				return false
			}
			switch n.(type) {
			case *ast.ReturnStmt, *ast.BranchStmt, *ast.GoStmt:
				badBetween = true
				return false
			case *ast.FuncLit:
				return false
			}
			return true
		})
	}
	if badBetween {
		return false
	}

	// Ensure chVar has exactly 3 identifier occurrences across the entire enclosing body:
	// 1 definition at defIdx, 1 channel send inside lit.Body, and 1 unconditional receive at recvIdx.
	refCount := 0
	ast.Inspect(body, func(n ast.Node) bool {
		if id, isID := n.(*ast.Ident); isID {
			if info.Defs[id] == chVar || info.Uses[id] == chVar {
				refCount++
			}
		}
		return true
	})
	return refCount == 3
}

func isMakeChanCall(info *types.Info, e ast.Expr) bool {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || (len(call.Args) != 1 && len(call.Args) != 2) {
		return false
	}
	id, ok := peelHarnessCallee(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	b, ok := info.Uses[id].(*types.Builtin)
	if !ok || b.Name() != "make" {
		return false
	}
	if _, isCh := underlyingType(info.TypeOf(call.Args[0])).(*types.Chan); !isCh {
		return false
	}
	if len(call.Args) == 2 {
		tv, okTV := info.Types[call.Args[1]]
		if !okTV || tv.Value == nil || tv.Value.Kind() != constant.Int {
			return false
		}
		capVal, exact := constant.Int64Val(tv.Value)
		if !exact || (capVal != 0 && capVal != 1) {
			return false
		}
	}
	return true
}

func constStringEq(info *types.Info, e ast.Expr, want string) bool {
	if info == nil || e == nil {
		return false
	}
	tv, ok := info.Types[e]
	return ok && tv.Value != nil && tv.Value.Kind() == constant.String && constant.StringVal(tv.Value) == want
}

func isFailfileStringOrSliceType(t types.Type) bool {
	if t == nil {
		return false
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Basic:
		return u.Kind() == types.String
	case *types.Slice:
		b, ok := types.Unalias(u.Elem()).Underlying().(*types.Basic)
		return ok && b.Kind() == types.String
	}
	return false
}

func isEmptyFailfileReset(info *types.Info, e ast.Expr) bool {
	e = ast.Unparen(e)
	if constStringEq(info, e, "") {
		return true
	}
	if id, ok := e.(*ast.Ident); ok && info.Uses[id] == types.Universe.Lookup("nil") {
		return true
	}
	if cl, ok := e.(*ast.CompositeLit); ok && len(cl.Elts) == 0 && isFailfileStringOrSliceType(info.TypeOf(cl)) {
		return true
	}
	return false
}

func underlyingType(t types.Type) types.Type {
	if t = types.Unalias(t); t != nil {
		return t.Underlying()
	}
	return nil
}

func isCategoryABoolFieldExpr(info *types.Info, e ast.Expr, categoryA map[*types.Var]bool) bool {
	sel, ok := ast.Unparen(e).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	b, ok := underlyingType(info.TypeOf(sel)).(*types.Basic)
	if !ok || b.Kind() != types.Bool {
		return false
	}
	baseId, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := info.Uses[baseId].(*types.Var)
	return ok && categoryA[v]
}

func isHarnessFailfileExpr(
	info *types.Info,
	e ast.Expr,
	declFuncs map[*types.Func]*ast.FuncDecl,
	categoryA map[*types.Var]bool,
	failfileVars map[*types.Var]bool,
	failfileParams map[*types.Var]bool,
	failfileResults map[harnessParamKey]bool,
) bool {
	if e == nil {
		return false
	}
	e = ast.Unparen(e)
	if !isFailfileStringOrSliceType(info.TypeOf(e)) {
		return false
	}
	switch x := e.(type) {
	case *ast.Ident:
		v, ok := info.Uses[x].(*types.Var)
		return ok && (failfileVars[v] || failfileParams[v])
	case *ast.SelectorExpr:
		if baseId, ok := ast.Unparen(x.X).(*ast.Ident); ok {
			if v, ok := info.Uses[baseId].(*types.Var); ok && categoryA[v] {
				return true
			}
		}
	case *ast.CompositeLit:
		if len(x.Elts) == 0 {
			return false
		}
		saw := false
		for _, elt := range x.Elts {
			if isEmptyFailfileReset(info, elt) {
				continue
			}
			if isHarnessFailfileExpr(info, elt, declFuncs, categoryA, failfileVars, failfileParams, failfileResults) {
				saw = true
				continue
			}
			return false
		}
		return saw
	case *ast.CallExpr:
		if id, ok := peelHarnessCallee(x.Fun).(*ast.Ident); ok {
			if b, isB := info.Uses[id].(*types.Builtin); isB && b.Name() == "append" && len(x.Args) >= 2 {
				saw := false
				for _, arg := range x.Args {
					if isEmptyFailfileReset(info, arg) {
						continue
					}
					if isHarnessFailfileExpr(info, arg, declFuncs, categoryA, failfileVars, failfileParams, failfileResults) {
						saw = true
						continue
					}
					return false
				}
				return saw
			}
		}
		callee := resolveHarnessFuncExpr(info, x.Fun)
		if callee == nil || x.Ellipsis.IsValid() {
			return false
		}
		if callee.Pkg() != nil && callee.Pkg().Path() == "path/filepath" {
			switch callee.Name() {
			case "Join":
				if len(x.Args) < 2 {
					return false
				}
				for _, arg := range x.Args {
					if tv, ok := info.Types[arg]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
						if strings.Contains(constant.StringVal(tv.Value), "..") {
							return false
						}
					}
				}
				if constStringEq(info, x.Args[0], "testdata") && constStringEq(info, x.Args[1], "rapid") {
					return true
				}
				return isHarnessFailfileExpr(info, x.Args[0], declFuncs, categoryA, failfileVars, failfileParams, failfileResults)
			case "Dir", "Clean", "Glob":
				return len(x.Args) == 1 && isHarnessFailfileExpr(info, x.Args[0], declFuncs, categoryA, failfileVars, failfileParams, failfileResults)
			}
			return false
		}
		if declFuncs[callee] != nil && !callee.Exported() && callee.Signature().Results().Len() == 1 {
			return failfileResults[harnessParamKey{fn: callee, idx: 0}]
		}
	}
	return false
}

func computeHarnessFailfileProvenance(
	pkg *packages.Package,
	declFuncs map[*types.Func]*ast.FuncDecl,
	initOnly map[*types.Func]bool,
	funcValueTaken map[*types.Func]bool,
	callSites map[*types.Func][]*ast.CallExpr,
	categoryA map[*types.Var]bool,
) (map[*types.Var]bool, map[*types.Var]bool, map[harnessParamKey]bool) {
	info := pkg.TypesInfo
	failfileVars := map[*types.Var]bool{}
	failfileParams := map[*types.Var]bool{}
	failfileResults := map[harnessParamKey]bool{}

	isFF := func(e ast.Expr) bool {
		return isHarnessFailfileExpr(info, e, declFuncs, categoryA, failfileVars, failfileParams, failfileResults)
	}
	lookupLocalVar := func(e ast.Expr) *types.Var {
		id, ok := ast.Unparen(e).(*ast.Ident)
		if !ok {
			return nil
		}
		if v, ok := info.Defs[id].(*types.Var); ok && v != nil && v.Parent() != pkg.Types.Scope() {
			return v
		}
		if v, ok := info.Uses[id].(*types.Var); ok && v != nil && v.Parent() != pkg.Types.Scope() {
			return v
		}
		return nil
	}

	reassignedParams := map[*types.Var]bool{}
	for fn, fd := range declFuncs {
		if fd == nil || fd.Body == nil {
			continue
		}
		paramSet := map[*types.Var]bool{}
		for i := 0; i < fn.Signature().Params().Len(); i++ {
			paramSet[fn.Signature().Params().At(i)] = true
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range s.Lhs {
					if v := lookupLocalVar(lhs); v != nil && paramSet[v] {
						reassignedParams[v] = true
					}
				}
			case *ast.UnaryExpr:
				if s.Op == token.AND {
					if v := lookupLocalVar(s.X); v != nil && paramSet[v] {
						reassignedParams[v] = true
					}
				}
			}
			return true
		})
	}

	changed := true
	for changed {
		changed = false
		for fn, fd := range declFuncs {
			if fn.Exported() || fd == nil || fd.Body == nil {
				continue
			}
			paramSet := map[*types.Var]bool{}
			for i := 0; i < fn.Signature().Params().Len(); i++ {
				paramSet[fn.Signature().Params().At(i)] = true
			}
			totalWrites := map[*types.Var]int{}
			validWrites := map[*types.Var]int{}
			positiveWrites := map[*types.Var]int{}
			addrTaken := map[*types.Var]bool{}
			isSelfAppend := func(target *types.Var, rhs ast.Expr) (valid, positive bool) {
				call, ok := ast.Unparen(rhs).(*ast.CallExpr)
				if !ok || len(call.Args) < 2 {
					return false, false
				}
				id, ok := peelHarnessCallee(call.Fun).(*ast.Ident)
				if !ok {
					return false, false
				}
				b, ok := info.Uses[id].(*types.Builtin)
				if !ok || b.Name() != "append" {
					return false, false
				}
				if lookupLocalVar(call.Args[0]) != target {
					return false, false
				}
				sawPos := false
				for _, arg := range call.Args[1:] {
					if isEmptyFailfileReset(info, arg) {
						continue
					}
					if isFF(arg) {
						sawPos = true
						continue
					}
					return false, false
				}
				return true, sawPos
			}

			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch s := n.(type) {
				case *ast.ValueSpec:
					for i, nm := range s.Names {
						v, ok := info.Defs[nm].(*types.Var)
						if !ok || v == nil || v.Parent() == pkg.Types.Scope() || paramSet[v] || !isFailfileStringOrSliceType(v.Type()) {
							continue
						}
						if i < len(s.Values) {
							totalWrites[v]++
							if isEmptyFailfileReset(info, s.Values[i]) {
								validWrites[v]++
							} else if isFF(s.Values[i]) {
								validWrites[v]++
								positiveWrites[v]++
							}
						}
					}
				case *ast.AssignStmt:
					if len(s.Rhs) == 1 && len(s.Lhs) > 1 {
						call, isCall := ast.Unparen(s.Rhs[0]).(*ast.CallExpr)
						var callee *types.Func
						if isCall {
							callee = resolveHarnessFuncExpr(info, call.Fun)
						}
						for i, lhs := range s.Lhs {
							v := lookupLocalVar(lhs)
							if v == nil || paramSet[v] || !isFailfileStringOrSliceType(v.Type()) {
								continue
							}
							totalWrites[v]++
							if callee != nil && !call.Ellipsis.IsValid() {
								if callee.Pkg() != nil && callee.Pkg().Path() == "path/filepath" && callee.Name() == "Glob" && i == 0 && len(call.Args) == 1 && isFF(call.Args[0]) {
									validWrites[v]++
									positiveWrites[v]++
								} else if declFuncs[callee] != nil && !callee.Exported() && failfileResults[harnessParamKey{fn: callee, idx: i}] {
									validWrites[v]++
									positiveWrites[v]++
								}
							}
						}
					} else {
						for i, lhs := range s.Lhs {
							v := lookupLocalVar(lhs)
							if v == nil || paramSet[v] || !isFailfileStringOrSliceType(v.Type()) {
								continue
							}
							totalWrites[v]++
							if s.Tok == token.ASSIGN || s.Tok == token.DEFINE {
								if i < len(s.Rhs) {
									if isEmptyFailfileReset(info, s.Rhs[i]) {
										validWrites[v]++
									} else if isFF(s.Rhs[i]) {
										validWrites[v]++
										positiveWrites[v]++
									} else if s.Tok == token.ASSIGN {
										if okSA, posSA := isSelfAppend(v, s.Rhs[i]); okSA {
											validWrites[v]++
											if posSA {
												positiveWrites[v]++
											}
										}
									}
								}
							}
						}
					}
				case *ast.RangeStmt:
					if s.Key != nil {
						if kv := lookupLocalVar(s.Key); kv != nil && !paramSet[kv] && isFailfileStringOrSliceType(kv.Type()) {
							totalWrites[kv]++
						}
					}
					if s.Value != nil {
						if vv := lookupLocalVar(s.Value); vv != nil && !paramSet[vv] && isFailfileStringOrSliceType(vv.Type()) {
							totalWrites[vv]++
							if isFF(s.X) {
								validWrites[vv]++
								positiveWrites[vv]++
							}
						}
					}
				case *ast.UnaryExpr:
					if s.Op == token.AND {
						if v := lookupLocalVar(s.X); v != nil {
							addrTaken[v] = true
						}
					}
				}
				return true
			})

			for v, tot := range totalWrites {
				if tot > 0 && validWrites[v] == tot && positiveWrites[v] > 0 && !addrTaken[v] && !failfileVars[v] {
					failfileVars[v] = true
					changed = true
				}
			}

			if !initOnly[fn] {
				resTuple := fn.Signature().Results()
				for rIdx := 0; rIdx < resTuple.Len(); rIdx++ {
					key := harnessParamKey{fn: fn, idx: rIdx}
					if failfileResults[key] || !isFailfileStringOrSliceType(resTuple.At(rIdx).Type()) {
						continue
					}
					allValid := true
					sawPos := false
					ast.Inspect(fd.Body, func(n ast.Node) bool {
						if !allValid || n == nil {
							return false
						}
						if _, isLit := n.(*ast.FuncLit); isLit {
							return false
						}
						ret, ok := n.(*ast.ReturnStmt)
						if !ok {
							return true
						}
						if rIdx >= len(ret.Results) {
							allValid = false
							return false
						}
						rExpr := ret.Results[rIdx]
						if isEmptyFailfileReset(info, rExpr) {
							return true
						}
						if isFF(rExpr) {
							sawPos = true
							return true
						}
						allValid = false
						return false
					})
					if allValid && sawPos {
						failfileResults[key] = true
						changed = true
					}
				}
			}

			if !funcValueTaken[fn] && !fn.Signature().Variadic() && len(callSites[fn]) > 0 {
				params := fn.Signature().Params()
				for pIdx := 0; pIdx < params.Len(); pIdx++ {
					pv := params.At(pIdx)
					if failfileParams[pv] || reassignedParams[pv] || !isFailfileStringOrSliceType(pv.Type()) {
						continue
					}
					allSitesOK := true
					sawPos := false
					for _, site := range callSites[fn] {
						if site.Ellipsis.IsValid() || pIdx >= len(site.Args) {
							allSitesOK = false
							break
						}
						arg := site.Args[pIdx]
						if isEmptyFailfileReset(info, arg) {
							continue
						}
						if isFF(arg) {
							sawPos = true
							continue
						}
						allSitesOK = false
						break
					}
					if allSitesOK && sawPos {
						failfileParams[pv] = true
						changed = true
					}
				}
			}
		}
	}

	return failfileVars, failfileParams, failfileResults
}

func collectHarnessTempFileVars(
	info *types.Info,
	pkgTypes *types.Package,
	body *ast.BlockStmt,
	declFuncs map[*types.Func]*ast.FuncDecl,
	categoryA map[*types.Var]bool,
	failfileVars map[*types.Var]bool,
	failfileParams map[*types.Var]bool,
	failfileResults map[harnessParamKey]bool,
) map[*types.Var]bool {
	totalWrites := map[*types.Var]int{}
	createTempWrites := map[*types.Var]int{}
	addrTaken := map[*types.Var]bool{}
	lookupLocal := func(e ast.Expr) *types.Var {
		id, ok := ast.Unparen(e).(*ast.Ident)
		if !ok {
			return nil
		}
		if v, ok := info.Defs[id].(*types.Var); ok && v != nil && v.Parent() != pkgTypes.Scope() {
			return v
		}
		if v, ok := info.Uses[id].(*types.Var); ok && v != nil && v.Parent() != pkgTypes.Scope() {
			return v
		}
		return nil
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			isCT := false
			if len(s.Rhs) == 1 && len(s.Lhs) == 2 {
				if call, ok := ast.Unparen(s.Rhs[0]).(*ast.CallExpr); ok && !call.Ellipsis.IsValid() && len(call.Args) == 2 {
					if callee := resolveHarnessFuncExpr(info, call.Fun); callee != nil && callee.Pkg() != nil &&
						callee.Pkg().Path() == "os" && callee.Name() == "CreateTemp" &&
						isHarnessFailfileExpr(info, call.Args[0], declFuncs, categoryA, failfileVars, failfileParams, failfileResults) {
						isCT = true
					}
				}
			}
			for i, lhs := range s.Lhs {
				v := lookupLocal(lhs)
				if v == nil {
					continue
				}
				totalWrites[v]++
				if isCT && i == 0 && (s.Tok == token.DEFINE || s.Tok == token.ASSIGN) {
					createTempWrites[v]++
				}
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND {
				if v := lookupLocal(s.X); v != nil {
					addrTaken[v] = true
				}
			}
		}
		return true
	})
	out := map[*types.Var]bool{}
	for v, c := range createTempWrites {
		if c == 1 && totalWrites[v] == 1 && !addrTaken[v] {
			out[v] = true
		}
	}
	return out
}

func isTempFileNameCall(info *types.Info, e ast.Expr, tempFileVars map[*types.Var]bool) bool {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 0 {
		return false
	}
	sel, ok := peelHarnessCallee(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "Name" {
		return false
	}
	baseId, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := info.Uses[baseId].(*types.Var)
	return ok && tempFileVars[v]
}

func isDebugVisHTMLName(info *types.Info, body *ast.BlockStmt, e ast.Expr) bool {
	isSprintfHTML := func(expr ast.Expr) bool {
		call, ok := ast.Unparen(expr).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) < 1 {
			return false
		}
		callee := resolveHarnessFuncExpr(info, call.Fun)
		if callee == nil || callee.Pkg() == nil || callee.Pkg().Path() != "fmt" || callee.Name() != "Sprintf" {
			return false
		}
		tv, ok := info.Types[call.Args[0]]
		if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
			return false
		}
		fmtStr := constant.StringVal(tv.Value)
		return strings.HasSuffix(fmtStr, ".html") && !strings.ContainsAny(fmtStr, `/\`) && !strings.Contains(fmtStr, "..")
	}
	if isSprintfHTML(e) {
		return true
	}
	if body == nil {
		return false
	}
	id, ok := ast.Unparen(e).(*ast.Ident)
	if !ok {
		return false
	}
	targetVar, ok := info.Uses[id].(*types.Var)
	if !ok || targetVar == nil {
		return false
	}
	writes := 0
	valid := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range s.Lhs {
				if lId, ok := ast.Unparen(lhs).(*ast.Ident); ok && (info.Defs[lId] == targetVar || info.Uses[lId] == targetVar) {
					writes++
					if i < len(s.Rhs) && (s.Tok == token.DEFINE || s.Tok == token.ASSIGN) && isSprintfHTML(s.Rhs[i]) {
						valid = true
					}
				}
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND {
				if lId, ok := ast.Unparen(s.X).(*ast.Ident); ok && info.Uses[lId] == targetVar {
					writes += 2
				}
			}
		}
		return true
	})
	return writes == 1 && valid
}

func verifyHarnessOSFuncCall(
	info *types.Info,
	enclosingFD *ast.FuncDecl,
	enclosingFn *types.Func,
	inInitRoot bool,
	inLit bool,
	inFlagBoolGuard bool,
	fnName string,
	call *ast.CallExpr,
	isFailfile func(ast.Expr) bool,
	tempFileVars map[*types.Var]bool,
) bool {
	if call.Ellipsis.IsValid() {
		return false
	}
	switch fnName {
	case "Getpid":
		return len(call.Args) == 0
	case "IsNotExist":
		return len(call.Args) == 1
	case "Open":
		return !inInitRoot && enclosingFn != nil && !enclosingFn.Exported() && len(call.Args) == 1 && isFailfile(call.Args[0])
	case "MkdirAll", "CreateTemp":
		return !inInitRoot && enclosingFn != nil && !enclosingFn.Exported() && len(call.Args) == 2 && isFailfile(call.Args[0])
	case "Remove":
		return !inInitRoot && enclosingFn != nil && !enclosingFn.Exported() && len(call.Args) == 1 && isTempFileNameCall(info, call.Args[0], tempFileVars)
	case "Rename":
		return !inInitRoot && enclosingFn != nil && !enclosingFn.Exported() && len(call.Args) == 2 &&
			isTempFileNameCall(info, call.Args[0], tempFileVars) && isFailfile(call.Args[1])
	case "Create":
		var body *ast.BlockStmt
		if enclosingFD != nil {
			body = enclosingFD.Body
		}
		return !inInitRoot && !inLit && enclosingFn != nil && !enclosingFn.Exported() &&
			inFlagBoolGuard && len(call.Args) == 1 && isDebugVisHTMLName(info, body, call.Args[0])
	}
	return false
}

func collectMutatedHarnessNamedStructs(pkg *packages.Package) map[*types.Named]bool {
	mutated := map[*types.Named]bool{}
	info := pkg.TypesInfo
	markFieldOwner := func(e ast.Expr) {
		for e != nil {
			switch x := ast.Unparen(e).(type) {
			case *ast.SelectorExpr:
				if sel := info.Selections[x]; sel != nil && sel.Kind() == types.FieldVal {
					cur := types.Unalias(sel.Recv())
					if ptr, ok := cur.(*types.Pointer); ok {
						cur = types.Unalias(ptr.Elem())
					}
					if named, ok := cur.(*types.Named); ok {
						mutated[named.Origin()] = true
					}
					idx := sel.Index()
					for step := 0; step < len(idx)-1; step++ {
						st, ok := cur.Underlying().(*types.Struct)
						if !ok || idx[step] >= st.NumFields() {
							break
						}
						cur = types.Unalias(st.Field(idx[step]).Type())
						if ptr, ok := cur.(*types.Pointer); ok {
							cur = types.Unalias(ptr.Elem())
						}
						if named, ok := cur.(*types.Named); ok {
							mutated[named.Origin()] = true
						}
					}
				}
				e = x.X
			case *ast.IndexExpr:
				e = x.X
			case *ast.SliceExpr:
				e = x.X
			case *ast.StarExpr:
				rt := types.Unalias(info.TypeOf(x.X))
				if ptr, ok := rt.(*types.Pointer); ok {
					if named, ok := types.Unalias(ptr.Elem()).(*types.Named); ok {
						mutated[named.Origin()] = true
					}
				}
				e = x.X
			default:
				return
			}
		}
	}
	for _, af := range pkg.Syntax {
		ast.Inspect(af, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range s.Lhs {
					markFieldOwner(lhs)
				}
			case *ast.IncDecStmt:
				markFieldOwner(s.X)
			case *ast.RangeStmt:
				if s.Tok == token.ASSIGN {
					for _, be := range []ast.Expr{s.Key, s.Value} {
						if be != nil {
							markFieldOwner(be)
						}
					}
				}
			case *ast.UnaryExpr:
				if s.Op == token.AND {
					markFieldOwner(s.X)
				}
			case *ast.CallExpr:
				if id, ok := peelHarnessCallee(s.Fun).(*ast.Ident); ok {
					if b, isB := info.Uses[id].(*types.Builtin); isB && (b.Name() == "delete" || b.Name() == "clear" || b.Name() == "copy" || b.Name() == "append") && len(s.Args) > 0 {
						markFieldOwner(s.Args[0])
					}
				}
			}
			return true
		})
	}
	return mutated
}

func isErrorOrBoolType(t types.Type) bool {
	if t == nil {
		return false
	}
	if types.Identical(t, types.Universe.Lookup("error").Type()) {
		return true
	}
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	return ok && b.Kind() == types.Bool
}

func isImmutableHarnessCachedType(
	audited bool,
	pkgTypes *types.Package,
	t types.Type,
	mutatedStructs map[*types.Named]bool,
	needsGenImmut *bool,
	sawMutableRef *bool,
	seen map[types.Type]bool,
) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if seen[t] {
		return true
	}
	seen[t] = true

	if _, ok := isCarrierFreeGeneratorPtrType(audited, pkgTypes, t); ok {
		if needsGenImmut != nil {
			*needsGenImmut = true
		}
		return true
	}
	if ptr, ok := t.(*types.Pointer); ok {
		if named, ok := types.Unalias(ptr.Elem()).(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() != nil {
			p, n := named.Obj().Pkg().Path(), named.Obj().Name()
			if ((p == "regexp" && n == "Regexp") || (p == "regexp/syntax" && n == "Regexp")) && !mutatedStructs[named.Origin()] {
				if sawMutableRef != nil {
					*sawMutableRef = true
				}
				return true
			}
		}
		return false
	}
	if named, ok := t.(*types.Named); ok {
		if _, isSt := named.Underlying().(*types.Struct); isSt {
			if named.Obj() == nil || named.Obj().Pkg() != pkgTypes || named.Obj().Exported() || mutatedStructs[named.Origin()] {
				return false
			}
		}
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Kind() != types.UnsafePointer && u.Kind() != types.Invalid
	case *types.Array:
		return isImmutableHarnessCachedType(audited, pkgTypes, u.Elem(), mutatedStructs, needsGenImmut, sawMutableRef, seen)
	case *types.Slice:
		elemBasic, ok := types.Unalias(u.Elem()).Underlying().(*types.Basic)
		if !ok || elemBasic.Kind() == types.UnsafePointer || elemBasic.Kind() == types.Invalid {
			return false
		}
		if sawMutableRef != nil {
			*sawMutableRef = true
		}
		return true
	case *types.Struct:
		if _, isNamed := t.(*types.Named); !isNamed && u.NumFields() > 0 {
			return false
		}
		for i := 0; i < u.NumFields(); i++ {
			if !isImmutableHarnessCachedType(audited, pkgTypes, u.Field(i).Type(), mutatedStructs, needsGenImmut, sawMutableRef, seen) {
				return false
			}
		}
		return true
	}
	return false
}

// verifyFreshUnaliasedLocalAtStore verifies that a mutable-ref-carrying value
// stored into a Category 3B sync.Map (`storeCall.Args[1]`) originates from
// unaliased local construction inside fd.Body before storeCall.Pos(), never
// aliases a parameter or package global, is not declared outside any loop
// enclosing storeCall, and (for local slices) is never mutated or aliased at
// or after storeCall.Pos(). Any *regexp.Regexp / *regexp/syntax.Regexp local
// variables feeding storeArg are returned so VerifyReadOnlyRefConfinement seeds
// and confines them across the entire function and package.
func verifyFreshUnaliasedLocalAtStore(
	info *types.Info,
	pkgTypes *types.Package,
	fd *ast.FuncDecl,
	storeArg ast.Expr,
	storeCall *ast.CallExpr,
) ([]*types.Var, bool) {
	if info == nil || pkgTypes == nil || fd == nil || fd.Body == nil || storeArg == nil || storeCall == nil {
		return nil, false
	}
	body := fd.Body
	storePos := storeCall.Pos()
	hasGoto := false
	ast.Inspect(body, func(n ast.Node) bool {
		if hasGoto || n == nil {
			return false
		}
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		if br, isBr := n.(*ast.BranchStmt); isBr && br.Tok == token.GOTO {
			hasGoto = true
			return false
		}
		return true
	})
	if hasGoto {
		return nil, false
	}

	// Collect parameters/receivers/results so they are never accepted as fresh locals.
	sigVars := map[*types.Var]bool{}
	recordFL := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, nm := range f.Names {
				if v, ok := info.Defs[nm].(*types.Var); ok && v != nil {
					sigVars[v] = true
				}
			}
		}
	}
	recordFL(fd.Recv)
	if fd.Type != nil {
		recordFL(fd.Type.Params)
		recordFL(fd.Type.Results)
	}

	isDeclaredInBodyBefore := func(v *types.Var, limitPos token.Pos, forbidOuterLoopOf ast.Node) (token.Pos, bool) {
		if v == nil || sigVars[v] || v.IsField() || v.Pkg() != pkgTypes || v.Parent() == pkgTypes.Scope() {
			return token.NoPos, false
		}
		defCount := 0
		declPos := token.NoPos
		ast.Inspect(body, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && info.Defs[id] == v {
				defCount++
				declPos = id.Pos()
			}
			return true
		})
		if defCount != 1 || declPos == token.NoPos || declPos >= limitPos {
			return token.NoPos, false
		}
		// Reject variables declared outside any loop enclosing forbidOuterLoopOf.
		badLoop := false
		ast.Inspect(body, func(n ast.Node) bool {
			if badLoop || n == nil {
				return false
			}
			switch lp := n.(type) {
			case *ast.ForStmt:
				if lp.Pos() <= forbidOuterLoopOf.Pos() && forbidOuterLoopOf.End() <= lp.End() {
					if !(lp.Pos() <= declPos && declPos <= lp.End()) {
						badLoop = true
						return false
					}
				}
			case *ast.RangeStmt:
				if lp.Pos() <= forbidOuterLoopOf.Pos() && forbidOuterLoopOf.End() <= lp.End() {
					if !(lp.Pos() <= declPos && declPos <= lp.End()) {
						badLoop = true
						return false
					}
				}
			}
			return true
		})
		if badLoop {
			return token.NoPos, false
		}
		return declPos, true
	}

	isScalarType := func(t types.Type) bool {
		if t == nil {
			return false
		}
		b, ok := types.Unalias(t).Underlying().(*types.Basic)
		return ok && b.Kind() != types.UnsafePointer && b.Kind() != types.Invalid
	}

	verifyFreshSliceLocal := func(v *types.Var, freezeNode ast.Node, allowPostReturn bool) bool {
		freezePos := freezeNode.Pos()
		if _, ok := isDeclaredInBodyBefore(v, freezePos, freezeNode); !ok {
			return false
		}
		sl, ok := types.Unalias(v.Type()).Underlying().(*types.Slice)
		if !ok || !isScalarType(sl.Elem()) {
			return false
		}

		approvedUses := map[*ast.Ident]bool{}
		okSlice := true

		isFreshSliceInitRHS := func(rhs ast.Expr) bool {
			rhs = ast.Unparen(rhs)
			if id, isID := rhs.(*ast.Ident); isID {
				_, isNil := info.Uses[id].(*types.Nil)
				return isNil
			}
			switch r := rhs.(type) {
			case *ast.CompositeLit:
				if !types.Identical(types.Unalias(info.TypeOf(r)), types.Unalias(v.Type())) {
					return false
				}
				for _, elt := range r.Elts {
					val := elt
					if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
						val = kv.Value
					}
					if !isScalarType(info.TypeOf(val)) {
						return false
					}
				}
				return true
			case *ast.CallExpr:
				if bid, isID := peelHarnessCallee(r.Fun).(*ast.Ident); isID {
					if b, isB := info.Uses[bid].(*types.Builtin); isB {
						if b.Name() == "make" && len(r.Args) >= 2 && len(r.Args) <= 3 {
							return true
						}
						if b.Name() == "append" && !r.Ellipsis.IsValid() && len(r.Args) >= 2 {
							if aid, isAID := ast.Unparen(r.Args[0]).(*ast.Ident); isAID && info.Uses[aid] == v {
								approvedUses[aid] = true
								return true
							}
						}
					}
				}
			}
			return false
		}

		ast.Inspect(body, func(n ast.Node) bool {
			if !okSlice || n == nil {
				return false
			}
			switch s := n.(type) {
			case *ast.FuncLit, *ast.GoStmt:
				ast.Inspect(s, func(cn ast.Node) bool {
					if id, isID := cn.(*ast.Ident); isID && (info.Uses[id] == v || info.Defs[id] == v) {
						okSlice = false
						return false
					}
					return true
				})
				return false
			case *ast.ValueSpec:
				for i, nm := range s.Names {
					if info.Defs[nm] == v {
						if s.End() > freezePos {
							okSlice = false
							return false
						}
						if i < len(s.Values) && !isFreshSliceInitRHS(s.Values[i]) {
							okSlice = false
							return false
						}
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range s.Lhs {
					if lid, isID := ast.Unparen(lhs).(*ast.Ident); isID && (info.Defs[lid] == v || info.Uses[lid] == v) {
						if s.End() > freezePos || len(s.Lhs) != len(s.Rhs) || !isFreshSliceInitRHS(s.Rhs[i]) {
							okSlice = false
							return false
						}
						if info.Uses[lid] == v {
							approvedUses[lid] = true
						}
					} else if idx, isIX := ast.Unparen(lhs).(*ast.IndexExpr); isIX {
						if bid, isBID := ast.Unparen(idx.X).(*ast.Ident); isBID && info.Uses[bid] == v {
							if s.End() > freezePos || !isScalarType(info.TypeOf(idx)) {
								okSlice = false
								return false
							}
							approvedUses[bid] = true
						}
					}
				}
			case *ast.IncDecStmt:
				if idx, isIX := ast.Unparen(s.X).(*ast.IndexExpr); isIX {
					if bid, isBID := ast.Unparen(idx.X).(*ast.Ident); isBID && info.Uses[bid] == v {
						if s.End() > freezePos {
							okSlice = false
							return false
						}
						approvedUses[bid] = true
					}
				}
			case *ast.CallExpr:
				if s == storeCall && freezeNode == storeCall && len(s.Args) == 2 {
					if aid, isID := ast.Unparen(s.Args[1]).(*ast.Ident); isID && info.Uses[aid] == v {
						approvedUses[aid] = true
					}
				}
				if bid, isID := peelHarnessCallee(s.Fun).(*ast.Ident); isID {
					if b, isB := info.Uses[bid].(*types.Builtin); isB && (b.Name() == "len" || b.Name() == "cap") && len(s.Args) == 1 {
						if aid, isAID := ast.Unparen(s.Args[0]).(*ast.Ident); isAID && info.Uses[aid] == v {
							approvedUses[aid] = true
						}
					}
				}
			case *ast.ReturnStmt:
				if allowPostReturn && s.Pos() > freezePos {
					for _, res := range s.Results {
						if rid, isID := ast.Unparen(res).(*ast.Ident); isID && info.Uses[rid] == v {
							approvedUses[rid] = true
						}
					}
				}
			}
			return true
		})
		if !okSlice {
			return false
		}
		ast.Inspect(body, func(n ast.Node) bool {
			if !okSlice || n == nil {
				return false
			}
			if id, isID := n.(*ast.Ident); isID && info.Uses[id] == v && !approvedUses[id] {
				okSlice = false
				return false
			}
			return true
		})
		return okSlice
	}

	verifyFreshRegexpLocal := func(v *types.Var, limitNode ast.Node) bool {
		if _, ok := isDeclaredInBodyBefore(v, limitNode.Pos(), limitNode); !ok {
			return false
		}
		if !isRegexpOrSyntaxRegexpPtr(v.Type()) {
			return false
		}
		initCalls := 0
		reassignedOrAddr := false
		isStdRegexpConstructor := func(rhs ast.Expr) bool {
			call, ok := ast.Unparen(rhs).(*ast.CallExpr)
			if !ok {
				return false
			}
			callee := resolveHarnessFuncExpr(info, call.Fun)
			if callee == nil || callee.Pkg() == nil || callee.Signature().Recv() != nil {
				return false
			}
			p := callee.Pkg().Path()
			return p == "regexp" || p == "regexp/syntax"
		}
		ast.Inspect(body, func(n ast.Node) bool {
			if reassignedOrAddr || n == nil {
				return false
			}
			switch s := n.(type) {
			case *ast.FuncLit, *ast.GoStmt:
				ast.Inspect(s, func(cn ast.Node) bool {
					if id, isID := cn.(*ast.Ident); isID && (info.Uses[id] == v || info.Defs[id] == v) {
						reassignedOrAddr = true
						return false
					}
					return true
				})
				return false
			case *ast.ValueSpec:
				for i, nm := range s.Names {
					if info.Defs[nm] == v {
						if len(s.Values) == 1 && len(s.Names) >= 1 && isStdRegexpConstructor(s.Values[0]) {
							initCalls++
						} else if i < len(s.Values) && len(s.Names) == len(s.Values) && isStdRegexpConstructor(s.Values[i]) {
							initCalls++
						} else {
							reassignedOrAddr = true
							return false
						}
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range s.Lhs {
					lid, isID := ast.Unparen(lhs).(*ast.Ident)
					if !isID {
						continue
					}
					if info.Defs[lid] == v {
						if len(s.Rhs) == 1 && isStdRegexpConstructor(s.Rhs[0]) {
							initCalls++
						} else if i < len(s.Rhs) && len(s.Lhs) == len(s.Rhs) && isStdRegexpConstructor(s.Rhs[i]) {
							initCalls++
						} else {
							reassignedOrAddr = true
							return false
						}
					} else if info.Uses[lid] == v {
						reassignedOrAddr = true
						return false
					}
				}
			case *ast.UnaryExpr:
				if s.Op == token.AND {
					if id, isID := ast.Unparen(s.X).(*ast.Ident); isID && info.Uses[id] == v {
						reassignedOrAddr = true
						return false
					}
				}
			}
			return true
		})
		return !reassignedOrAddr && initCalls == 1
	}

	var regexpVars []*types.Var
	var verifyCompositeExpr func(expr ast.Expr, freezeNode ast.Node, isTopStoreArg bool) bool
	verifyCompositeExpr = func(expr ast.Expr, freezeNode ast.Node, isTopStoreArg bool) bool {
		if expr == nil {
			return false
		}
		expr = ast.Unparen(expr)
		et := info.TypeOf(expr)
		if et == nil {
			return false
		}
		if isScalarType(et) {
			return true
		}
		if _, ok := isCarrierFreeGeneratorPtrType(true, pkgTypes, et); ok {
			return true
		}
		if isRegexpOrSyntaxRegexpPtr(et) {
			id, ok := expr.(*ast.Ident)
			if !ok {
				return false
			}
			v, ok := info.Uses[id].(*types.Var)
			if !ok || !verifyFreshRegexpLocal(v, freezeNode) {
				return false
			}
			regexpVars = append(regexpVars, v)
			return true
		}
		if _, isSl := types.Unalias(et).Underlying().(*types.Slice); isSl {
			id, ok := expr.(*ast.Ident)
			if !ok {
				return false
			}
			v, ok := info.Uses[id].(*types.Var)
			if !ok {
				return false
			}
			return verifyFreshSliceLocal(v, freezeNode, isTopStoreArg)
		}

		// Struct or array value (either direct CompositeLit or single-assignment local var).
		if cl, isCL := expr.(*ast.CompositeLit); isCL {
			for _, elt := range cl.Elts {
				val := elt
				if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
					val = kv.Value
				}
				if !verifyCompositeExpr(val, cl, false) {
					return false
				}
			}
			return true
		}

		id, isID := expr.(*ast.Ident)
		if !isID {
			return false
		}
		v, isV := info.Uses[id].(*types.Var)
		if !isV || v == nil {
			return false
		}
		if _, ok := isDeclaredInBodyBefore(v, freezeNode.Pos(), freezeNode); !ok {
			return false
		}
		// Find single CompositeLit initializer for v and verify zero mutations/escapes of v.
		var initCL *ast.CompositeLit
		assigns := 0
		badUse := false
		approvedStructUses := map[*ast.Ident]bool{}
		if isTopStoreArg && len(storeCall.Args) == 2 {
			if aid, ok := ast.Unparen(storeCall.Args[1]).(*ast.Ident); ok && info.Uses[aid] == v {
				approvedStructUses[aid] = true
			}
		}
		ast.Inspect(body, func(n ast.Node) bool {
			if badUse || n == nil {
				return false
			}
			switch s := n.(type) {
			case *ast.FuncLit, *ast.GoStmt:
				ast.Inspect(s, func(cn ast.Node) bool {
					if cid, ok := cn.(*ast.Ident); ok && (info.Uses[cid] == v || info.Defs[cid] == v) {
						badUse = true
						return false
					}
					return true
				})
				return false
			case *ast.ValueSpec:
				for i, nm := range s.Names {
					if info.Defs[nm] == v {
						assigns++
						if i < len(s.Values) && len(s.Names) == len(s.Values) && s.End() <= freezeNode.Pos() {
							initCL, _ = ast.Unparen(s.Values[i]).(*ast.CompositeLit)
						}
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range s.Lhs {
					if lid, ok := ast.Unparen(lhs).(*ast.Ident); ok {
						if info.Defs[lid] == v {
							assigns++
							if i < len(s.Rhs) && len(s.Lhs) == len(s.Rhs) && s.End() <= freezeNode.Pos() {
								initCL, _ = ast.Unparen(s.Rhs[i]).(*ast.CompositeLit)
							}
						} else if info.Uses[lid] == v {
							badUse = true
							return false
						}
					}
				}
			case *ast.ReturnStmt:
				if isTopStoreArg && s.Pos() > storePos {
					for _, res := range s.Results {
						if rid, ok := ast.Unparen(res).(*ast.Ident); ok && info.Uses[rid] == v {
							approvedStructUses[rid] = true
						}
					}
				}
			}
			return true
		})
		if badUse || assigns != 1 || initCL == nil {
			return false
		}
		ast.Inspect(body, func(n ast.Node) bool {
			if badUse || n == nil {
				return false
			}
			if uid, ok := n.(*ast.Ident); ok && info.Uses[uid] == v && !approvedStructUses[uid] {
				badUse = true
				return false
			}
			return true
		})
		if badUse {
			return false
		}
		return verifyCompositeExpr(initCL, initCL, false)
	}

	if !verifyCompositeExpr(storeArg, storeCall, true) {
		return nil, false
	}
	return regexpVars, true
}

func verifyHarnessTemplateCall(
	audited bool,
	info *types.Info,
	pkgTypes *types.Package,
	callee *types.Func,
	call *ast.CallExpr,
) bool {
	if !audited || info == nil || pkgTypes == nil || callee == nil || call == nil || call.Ellipsis.IsValid() {
		return false
	}
	sig := callee.Signature()
	if sig.Recv() == nil {
		switch callee.Name() {
		case "New":
			return len(call.Args) == 1
		case "Must":
			return len(call.Args) == 1 || len(call.Args) == 2
		default:
			return false
		}
	}
	sel, ok := peelHarnessCallee(call.Fun).(*ast.SelectorExpr)
	if !ok || info.Selections[sel] == nil || info.Selections[sel].Kind() != types.MethodVal {
		return false
	}
	switch callee.Name() {
	case "Parse":
		return len(call.Args) == 1
	case "Execute":
		if len(call.Args) != 2 {
			return false
		}
		return isMethodlessCarrierFreeHarnessData(audited, pkgTypes, info.TypeOf(call.Args[1]))
	default:
		return false
	}
}

func isMethodlessCarrierFreeHarnessData(audited bool, pkgTypes *types.Package, t types.Type) bool {
	if !audited || pkgTypes == nil || t == nil || dynstate.TypeMayCarryUnknownDynamic(audited, t) {
		return false
	}
	top := types.Unalias(t)
	if ptr, ok := top.(*types.Pointer); ok {
		top = types.Unalias(ptr.Elem())
	}
	named, ok := top.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() != pkgTypes || named.Obj().Exported() {
		return false
	}
	if _, isStruct := named.Underlying().(*types.Struct); !isStruct {
		return false
	}
	return !typeTreeHasAnyMethods(t, map[types.Type]bool{})
}

func typeTreeHasAnyMethods(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if seen[t] {
		return false
	}
	seen[t] = true
	if types.NewMethodSet(t).Len() > 0 {
		return true
	}
	if _, isPtr := t.(*types.Pointer); !isPtr && !types.IsInterface(t) {
		if types.NewMethodSet(types.NewPointer(t)).Len() > 0 {
			return true
		}
	}
	switch x := t.Underlying().(type) {
	case *types.Pointer:
		return typeTreeHasAnyMethods(x.Elem(), seen)
	case *types.Slice:
		return typeTreeHasAnyMethods(x.Elem(), seen)
	case *types.Array:
		return typeTreeHasAnyMethods(x.Elem(), seen)
	case *types.Map:
		return typeTreeHasAnyMethods(x.Key(), seen) || typeTreeHasAnyMethods(x.Elem(), seen)
	case *types.Struct:
		for i := 0; i < x.NumFields(); i++ {
			if typeTreeHasAnyMethods(x.Field(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}
