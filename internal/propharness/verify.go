// Package propharness mechanically verifies from first principles that a
// candidate Go package satisfies the closed property-testing harness protocol
// over its AST, types, and intra-package dataflow
// (REQ-closure-observability-property-harness).
//
// Candidate screening and verification contain zero hardcoded third-party
// module paths, package names, environment/flag prefixes, or symbol names:
// Stage 0 (MayBeHarnessImports) screens import lists in O(len(imports)) with
// zero allocations, Stage 1 (ScreenPackage) derives the "<UPPER_PKG>_",
// "<pkg>.", and "testdata/<pkg>" namespaces from pkg.Types.Name() and discovers
// handle structs/interfaces, property drivers, subtest/fuzz wrapper factories,
// generic generator types, variadic-seed sample methods, and reflective value
// synthesizers structurally from exported signatures, and full verification
// proves variable/cache immutability, reference confinement, ambient-operation
// caller confinement, joined synctest bubbles, and closed return grammar.
package propharness

import (
	"context"
	"go/ast"
	"go/constant"
	"go/types"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/greatliontech/go-x-tools/go/packages"

	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
	"github.com/greatliontech/gofresh/internal/trace"
)

// PinnedMemoKeyPrefix versions the shared in-process memoization key for
// pinned property-testing harness packages.
const PinnedMemoKeyPrefix = "gofresh/property-harness@7:"

// MethodKey identifies a method on a named receiver type in a verified harness.
type MethodKey struct {
	Recv   string
	Method string
}

// VerifiedPackage records the structurally discovered protocol surface of a
// mechanically verified property-testing harness package.
type VerifiedPackage struct {
	PkgPath             string
	PkgName             string
	PrimaryDriver       string
	HandleStructs       map[string]bool
	HandleIfaces        map[string]bool
	DriverFuncs         map[string]bool
	WrapperFactoryFuncs map[string]bool
	GeneratorTypes      map[string]bool
	SeededSampleMethods map[MethodKey]bool
	ReflectSynthFuncs   map[string]bool
}

func (vp *VerifiedPackage) clone() *VerifiedPackage {
	if vp == nil {
		return nil
	}
	return &VerifiedPackage{
		PkgPath:             vp.PkgPath,
		PkgName:             vp.PkgName,
		PrimaryDriver:       vp.PrimaryDriver,
		HandleStructs:       maps.Clone(vp.HandleStructs),
		HandleIfaces:        maps.Clone(vp.HandleIfaces),
		DriverFuncs:         maps.Clone(vp.DriverFuncs),
		WrapperFactoryFuncs: maps.Clone(vp.WrapperFactoryFuncs),
		GeneratorTypes:      maps.Clone(vp.GeneratorTypes),
		SeededSampleMethods: maps.Clone(vp.SeededSampleMethods),
		ReflectSynthFuncs:   maps.Clone(vp.ReflectSynthFuncs),
	}
}

var pinnedHarnessMemo cachefile.SyncMemo[*VerifiedPackage]

// BuildPinnedMemoKey builds a length-prefixed collision-free cache key for a
// version-pinned candidate harness package.
func BuildPinnedMemoKey(frontend, toolchainContent, admissionPolicy, pin string, packageEnv, buildFlags, goFiles []string) string {
	var b strings.Builder
	b.WriteString(PinnedMemoKeyPrefix)
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

// VerifyPackagePinnedCached looks up memoKey in the shared pinned-harness memo
// table, loading and verifying the candidate package at most once on a miss.
// Both positive (*VerifiedPackage) and negative (nil) verdicts are cached when
// load succeeds without error.
func VerifyPackagePinnedCached(ctx context.Context, domain trace.Domain, audited bool, memoKey string, load func() ([]*packages.Package, error)) *VerifiedPackage {
	if !audited || memoKey == "" {
		return nil
	}
	if cached, ok := pinnedHarnessMemo.Load(memoKey); ok {
		return cached.clone()
	}
	cands, err := load()
	if err != nil || len(cands) == 0 {
		return nil
	}
	var verified *VerifiedPackage
	for _, cand := range cands {
		vp, _ := VerifyPackageWithIndex(ctx, domain, true, cand, nil)
		if vp == nil {
			pinnedHarnessMemo.Store(memoKey, nil)
			return nil
		}
		verified = vp
	}
	pinnedHarnessMemo.Store(memoKey, verified.clone())
	return verified.clone()
}

// ResetPinnedMemoForTest clears the in-process pinned harness memo table.
func ResetPinnedMemoForTest() {
	pinnedHarnessMemo.Reset()
}

// StructHasNoExportedFields reports whether st and all its embedded struct
// fields declare zero exported fields.
func StructHasNoExportedFields(st *types.Struct) bool {
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

// MayBeHarnessPkgPath reports whether pkgPath has a non-stdlib module-hosted
// import path shape eligible for property-harness screening.
func MayBeHarnessPkgPath(pkgPath string) bool {
	if pkgPath == "" || pkgPath == "main" || pkgPath == "testing" {
		return false
	}
	return !syntaxutil.IsStandardLibraryPkgPath(pkgPath)
}

// MayBeHarnessImports performs a fast zero-allocation Stage-0 screen over a
// package's import path and direct import list. A candidate property harness
// must be a non-stdlib package importing "testing", zero cgo/unsafe/embed
// pseudo-packages, and exclusively allowed standard-library packages.
func MayBeHarnessImports(pkgPath string, imports []string) bool {
	if !MayBeHarnessPkgPath(pkgPath) || len(imports) == 0 {
		return false
	}
	sawTesting := false
	for _, imp := range imports {
		if imp == "testing" {
			sawTesting = true
		}
		if !IsAllowedHarnessStdImport(imp) {
			return false
		}
	}
	return sawTesting
}

// MayBeHarnessPackage performs a fast zero-allocation Stage-0 screen over a
// loaded *packages.Package's import path and direct import set.
func MayBeHarnessPackage(pkg *packages.Package) bool {
	if pkg == nil || !MayBeHarnessPkgPath(pkg.PkgPath) {
		return false
	}
	if len(pkg.Imports) > 0 {
		sawTesting := false
		for imp := range pkg.Imports {
			if imp == "testing" {
				sawTesting = true
			}
			if !IsAllowedHarnessStdImport(imp) {
				return false
			}
		}
		return sawTesting
	}
	if pkg.Types != nil {
		tps := pkg.Types.Imports()
		if len(tps) == 0 {
			return false
		}
		sawTesting := false
		for _, tp := range tps {
			if tp == nil {
				continue
			}
			imp := tp.Path()
			if imp == "testing" {
				sawTesting = true
			}
			if !IsAllowedHarnessStdImport(imp) {
				return false
			}
		}
		return sawTesting
	}
	return false
}

// VerifyPackage mechanically checks that pkg satisfies the closed
// property-harness protocol invariants over its selected Go syntax and types.
func VerifyPackage(audited bool, pkg *packages.Package) bool {
	vp, _ := VerifyPackageWithIndex(context.Background(), "", audited, pkg, nil)
	return vp != nil
}

// VerifyPackageDetail mechanically checks pkg and returns its discovered
// VerifiedPackage descriptor, or nil if verification fails.
func VerifyPackageDetail(audited bool, pkg *packages.Package) *VerifiedPackage {
	vp, _ := VerifyPackageWithIndex(context.Background(), "", audited, pkg, nil)
	return vp
}

// VerifyPackageWithReason mechanically checks pkg and returns whether it
// passed alongside a diagnostic refusal reason when verification fails.
func VerifyPackageWithReason(audited bool, pkg *packages.Package) (bool, string) {
	vp, reason := VerifyPackageWithIndex(context.Background(), "", audited, pkg, nil)
	return vp != nil, reason
}

// VerifyPackageWithIndex runs full mechanical property-harness verification on
// pkg, reusing idx when non-nil so callers such as dynstate do not rebuild
// refconfine.PkgIndex, and emitting a zero-disabled-cost propharness.verify.done
// trace event when domain is non-empty and enabled.
func VerifyPackageWithIndex(
	ctx context.Context,
	domain trace.Domain,
	audited bool,
	pkg *packages.Package,
	idx *refconfine.PkgIndex,
) (*VerifiedPackage, string) {
	var pkgPath string
	if pkg != nil {
		pkgPath = pkg.PkgPath
	}
	var start time.Time
	tracing := domain != "" && pkgPath != "" && trace.Enabled(ctx, domain, pkgPath)
	if tracing {
		if ctx == nil {
			ctx = context.Background()
		}
		start = time.Now()
	}
	vp, reason := verifyPackageCore(ctx, domain, audited, pkg, idx)
	if tracing {
		trace.Emit(ctx, domain, "propharness.verify.done", pkgPath,
			trace.Bool("ok", vp != nil),
			trace.String("reason", reason),
			trace.Int64("duration_ns", time.Since(start).Nanoseconds()),
		)
	}
	return vp, reason
}

func verifyPackageCore(ctx context.Context, domain trace.Domain, audited bool, pkg *packages.Package, idx *refconfine.PkgIndex) (*VerifiedPackage, string) {
	screen, reason := screenPackageInternal(audited, pkg)
	if reason != "" {
		return nil, reason
	}
	g, graphReason := buildHarnessGraph(ctx, domain, pkg, idx, screen)
	if graphReason != "" {
		return nil, graphReason
	}
	if okStd, stdReason := verifyHarnessStdSymbolUses(g); !okStd {
		return nil, stdReason
	}
	categoryA, varsReason := verifyHarnessPackageVars(audited, g)
	if varsReason != "" {
		return nil, "verifyHarnessPackageVars failed: " + varsReason
	}
	envFlagVars, ctxReason := verifyHarnessProtocolCallContexts(audited, g, categoryA)
	if ctxReason != "" {
		return nil, "verifyHarnessProtocolCallContexts: " + ctxReason
	}
	if okSurf, surfReason := verifyHarnessExportedSurface(audited, g); !okSurf {
		return nil, "verifyHarnessExportedSurface: " + surfReason
	}
	if okAmb, ambReason := verifyHarnessAmbientConfinement(g, envFlagVars); !okAmb {
		return nil, "ambient confinement: " + ambReason
	}
	return g.screen.vp, ""
}

type harnessScreen struct {
	vp                    *VerifiedPackage
	envPrefix             string
	flagPrefix            string
	failfileSubdir        string
	handleStructs         map[*types.Named]bool
	handleIfaces          map[*types.Named]bool
	generatorOrigins      map[*types.Named]bool
	driverFuncs           map[*types.Func]bool
	wrapperFuncs          map[*types.Func]bool
	seededMethods         map[*types.Func]bool
	seededBaseSeedCalls   map[*ast.CallExpr]bool
	sealedHandleCallables map[*types.Func]bool
}

// ScreenPackage runs Stage-1 package metadata, import, namespace, and exported
// scope structural discovery without walking function bodies.
func ScreenPackage(audited bool, pkg *packages.Package) (*VerifiedPackage, string) {
	sc, reason := screenPackageInternal(audited, pkg)
	if sc == nil {
		return nil, reason
	}
	return sc.vp.clone(), ""
}

func isValidHarnessPkgIdent(name string) bool {
	if len(name) < 2 || name == "main" || name == "testing" ||
		strings.HasSuffix(name, "_test") || strings.HasPrefix(name, "internal") {
		return false
	}
	if name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

func screenPackageInternal(audited bool, pkg *packages.Package) (*harnessScreen, string) {
	if !audited || pkg == nil {
		return nil, "unaudited or nil pkg"
	}
	if syntaxutil.IsTrueStdlibInPkg(pkg, pkg.PkgPath) || (pkg.Module == nil && !MayBeHarnessPkgPath(pkg.PkgPath)) {
		return nil, "standard or non-module pkg"
	}
	if !MayBeHarnessPkgPath(pkg.PkgPath) {
		return nil, "disallowed pkg path"
	}
	if len(pkg.Errors) > 0 || pkg.Types == nil || pkg.TypesInfo == nil || len(pkg.Syntax) == 0 {
		return nil, "errors or missing syntax/types"
	}
	if len(pkg.OtherFiles) > 0 || len(pkg.EmbedFiles) > 0 || len(pkg.EmbedPatterns) > 0 {
		return nil, "other/embed files present"
	}
	for _, ig := range pkg.IgnoredFiles {
		if !strings.HasSuffix(ig, ".go") {
			return nil, "non-go ignored file: " + ig
		}
	}
	if len(pkg.CompiledGoFiles) > 0 && len(pkg.CompiledGoFiles) != len(pkg.GoFiles) {
		return nil, "compiled go files mismatch"
	}

	impSet := make(map[string]bool, len(pkg.Imports)+len(pkg.Types.Imports()))
	for impPath := range pkg.Imports {
		impSet[impPath] = true
	}
	var testingTypesPkg *types.Package
	for _, tp := range pkg.Types.Imports() {
		if tp != nil {
			impSet[tp.Path()] = true
			if tp.Path() == "testing" {
				testingTypesPkg = tp
			}
		}
	}
	if testingTypesPkg == nil && pkg.Imports != nil {
		if tPkg := pkg.Imports["testing"]; tPkg != nil {
			testingTypesPkg = tPkg.Types
		}
	}
	imps := make([]string, 0, len(impSet))
	for k := range impSet {
		imps = append(imps, k)
	}
	if !MayBeHarnessImports(pkg.PkgPath, imps) {
		for _, k := range slices.Sorted(maps.Keys(impSet)) {
			if !IsAllowedHarnessStdImport(k) {
				return nil, "disallowed import: " + k
			}
		}
		return nil, "missing testing import"
	}

	pkgName := pkg.Types.Name()
	if !isValidHarnessPkgIdent(pkgName) {
		return nil, "invalid harness package name: " + pkgName
	}

	scope := pkg.Types.Scope()
	if scope == nil {
		return nil, "missing package scope"
	}

	var testingTPtr types.Type
	if testingTypesPkg != nil && testingTypesPkg.Scope() != nil {
		if tObj, ok := testingTypesPkg.Scope().Lookup("T").(*types.TypeName); ok && tObj != nil {
			testingTPtr = types.NewPointer(tObj.Type())
		}
	}
	if testingTPtr == nil {
		return nil, "unresolved testing.T"
	}

	sc := &harnessScreen{
		vp: &VerifiedPackage{
			PkgPath:             pkg.PkgPath,
			PkgName:             pkgName,
			HandleStructs:       map[string]bool{},
			HandleIfaces:        map[string]bool{},
			DriverFuncs:         map[string]bool{},
			WrapperFactoryFuncs: map[string]bool{},
			GeneratorTypes:      map[string]bool{},
			SeededSampleMethods: map[MethodKey]bool{},
			ReflectSynthFuncs:   map[string]bool{},
		},
		envPrefix:             strings.ToUpper(pkgName) + "_",
		flagPrefix:            pkgName + ".",
		failfileSubdir:        pkgName,
		handleStructs:         map[*types.Named]bool{},
		handleIfaces:          map[*types.Named]bool{},
		generatorOrigins:      map[*types.Named]bool{},
		driverFuncs:           map[*types.Func]bool{},
		wrapperFuncs:          map[*types.Func]bool{},
		seededMethods:         map[*types.Func]bool{},
		seededBaseSeedCalls:   map[*ast.CallExpr]bool{},
		sealedHandleCallables: map[*types.Func]bool{},
	}

	names := scope.Names()
	var exportedFuncs []*types.Func
	var exportedNamed []*types.Named

	// Pass 1: reject exported vars and discover HandleIfaces.
	for _, name := range names {
		obj := scope.Lookup(name)
		if obj == nil {
			continue
		}
		if v, isVar := obj.(*types.Var); isVar {
			if v.Exported() {
				return nil, "exported var: " + v.Name()
			}
			continue
		}
		if !obj.Exported() {
			continue
		}
		switch o := obj.(type) {
		case *types.Func:
			exportedFuncs = append(exportedFuncs, o)
		case *types.TypeName:
			named, ok := types.Unalias(o.Type()).(*types.Named)
			if !ok {
				continue
			}
			exportedNamed = append(exportedNamed, named)
			if named.TypeParams() == nil {
				if iface, isIf := named.Underlying().(*types.Interface); isIf && isHarnessHandleIface(iface, testingTPtr) {
					sc.handleIfaces[named.Origin()] = true
					sc.vp.HandleIfaces[o.Name()] = true
				}
			}
		}
	}

	// Pass 2: discover DriverFuncs and HandleStructs.
	for _, fn := range exportedFuncs {
		sig := fn.Signature()
		if sig == nil || sig.Recv() != nil || sig.TypeParams() != nil || sig.Variadic() ||
			sig.Results().Len() != 0 || sig.Params().Len() != 2 {
			continue
		}
		p0 := sig.Params().At(0).Type()
		if !isTestingTPtrType(p0) && !isTestingTBType(p0) && !sc.isHandleIfaceType(p0) {
			continue
		}
		cbSig, ok := types.Unalias(sig.Params().At(1).Type()).Underlying().(*types.Signature)
		if !ok || cbSig.Recv() != nil || cbSig.TypeParams() != nil || cbSig.Variadic() ||
			cbSig.Results().Len() != 0 || cbSig.Params().Len() != 1 {
			continue
		}
		hNamed := derefExportedClosedStructInPkg(cbSig.Params().At(0).Type(), pkg.Types, false)
		if hNamed == nil {
			continue
		}
		sc.driverFuncs[fn.Origin()] = true
		sc.vp.DriverFuncs[fn.Name()] = true
		if sc.vp.PrimaryDriver == "" || fn.Name() < sc.vp.PrimaryDriver {
			sc.vp.PrimaryDriver = fn.Name()
		}
		sc.handleStructs[hNamed.Origin()] = true
		sc.vp.HandleStructs[hNamed.Obj().Name()] = true
	}
	if len(sc.driverFuncs) == 0 || len(sc.handleStructs) == 0 {
		return nil, "no property driver or handle struct discovered"
	}

	// Pass 3: discover WrapperFactoryFuncs.
	for _, fn := range exportedFuncs {
		sig := fn.Signature()
		if sig == nil || sig.Recv() != nil || sig.TypeParams() != nil || sig.Variadic() ||
			sig.Params().Len() != 1 || sig.Results().Len() != 1 {
			continue
		}
		cbSig, ok := types.Unalias(sig.Params().At(0).Type()).Underlying().(*types.Signature)
		if !ok || cbSig.Recv() != nil || cbSig.TypeParams() != nil || cbSig.Variadic() ||
			cbSig.Results().Len() != 0 || cbSig.Params().Len() != 1 {
			continue
		}
		if !sc.isHandleStructPtr(cbSig.Params().At(0).Type()) {
			continue
		}
		if isTestingWrapperReturnSig(sig.Results().At(0).Type()) {
			sc.wrapperFuncs[fn.Origin()] = true
			sc.vp.WrapperFactoryFuncs[fn.Name()] = true
		}
	}

	// Pass 4: discover GeneratorTypes and SeededSampleMethods.
	for _, named := range exportedNamed {
		if named.TypeParams() == nil || named.TypeParams().Len() != 1 {
			continue
		}
		st, ok := named.Underlying().(*types.Struct)
		if !ok || st.NumFields() == 0 || !StructHasNoExportedFields(st) {
			continue
		}
		tp := named.TypeParams().At(0)
		hasDraw := false
		for i := 0; i < named.NumMethods(); i++ {
			m := named.Method(i)
			if !m.Exported() {
				continue
			}
			msig := m.Signature()
			if msig == nil || msig.Recv() == nil {
				continue
			}
			if _, isPtr := types.Unalias(msig.Recv().Type()).(*types.Pointer); !isPtr {
				continue
			}
			if msig.Results().Len() == 1 && isMethodOwnFirstRecvTypeParam(msig, msig.Results().At(0).Type(), tp) &&
				sigHasHandleStructPtrParam(sc, msig) {
				hasDraw = true
				break
			}
		}
		if !hasDraw {
			continue
		}
		orig := named.Origin()
		sc.generatorOrigins[orig] = true
		sc.vp.GeneratorTypes[orig.Obj().Name()] = true
		for i := 0; i < named.NumMethods(); i++ {
			m := named.Method(i)
			if !m.Exported() {
				continue
			}
			msig := m.Signature()
			if msig != nil && msig.Variadic() && msig.Params().Len() == 1 && msig.Results().Len() == 1 &&
				isTypesIntSlice(msig.Params().At(0).Type()) &&
				isMethodOwnFirstRecvTypeParam(msig, msig.Results().At(0).Type(), tp) {
				sc.seededMethods[m.Origin()] = true
				sc.vp.SeededSampleMethods[MethodKey{Recv: orig.Obj().Name(), Method: m.Name()}] = true
			}
		}
	}
	if len(sc.generatorOrigins) == 0 {
		return nil, "no generic generator type discovered"
	}

	// Pass 5: record SealedHandleCallables across exported functions and methods.
	for _, fn := range exportedFuncs {
		if sigRequiresSealedHarnessHandle(sc, fn.Signature(), false) {
			sc.sealedHandleCallables[fn.Origin()] = true
		}
	}
	for _, name := range names {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok || tn == nil {
			continue
		}
		named, ok := types.Unalias(tn.Type()).(*types.Named)
		if !ok {
			continue
		}
		for i := 0; i < named.NumMethods(); i++ {
			m := named.Method(i)
			if m.Exported() && sigRequiresSealedHarnessHandle(sc, m.Signature(), true) {
				sc.sealedHandleCallables[m.Origin()] = true
			}
		}
	}

	return sc, ""
}

func (sc *harnessScreen) isHandleIfaceType(t types.Type) bool {
	named, ok := types.Unalias(t).(*types.Named)
	return ok && sc.handleIfaces[named.Origin()]
}

func (sc *harnessScreen) isHandleStructPtr(t types.Type) bool {
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	return ok && sc.handleStructs[named.Origin()]
}

func (sc *harnessScreen) isGeneratorType(t types.Type) bool {
	if t == nil {
		return false
	}
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && sc.generatorOrigins[named.Origin()]
}

func (sc *harnessScreen) isGeneratorPtrType(t types.Type) bool {
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	return ok && sc.generatorOrigins[named.Origin()]
}

func isHarnessHandleIface(iface *types.Interface, testingTPtr types.Type) bool {
	if iface == nil || !types.Implements(testingTPtr, iface) {
		return false
	}
	hasLogf := false
	hasFailOrHelper := false
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		sig := m.Signature()
		switch m.Name() {
		case "Logf":
			if sig != nil && sig.Variadic() && sig.Results().Len() == 0 && sig.Params().Len() == 2 {
				if b, ok := types.Unalias(sig.Params().At(0).Type()).Underlying().(*types.Basic); ok && b.Kind() == types.String &&
					syntaxutil.IsAnySliceType(sig.Params().At(1).Type()) {
					hasLogf = true
				}
			}
		case "Helper", "Errorf", "Fatalf", "Fail", "FailNow":
			hasFailOrHelper = true
		}
	}
	return hasLogf && hasFailOrHelper
}

func derefExportedClosedStructInPkg(t types.Type, pkgTypes *types.Package, allowGeneric bool) *types.Named {
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return nil
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() != pkgTypes || !named.Obj().Exported() {
		return nil
	}
	if !allowGeneric && named.TypeParams() != nil {
		return nil
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok || st.NumFields() == 0 || !StructHasNoExportedFields(st) {
		return nil
	}
	return named
}

func isTestingWrapperReturnSig(t types.Type) bool {
	sig, ok := types.Unalias(t).Underlying().(*types.Signature)
	if !ok || sig.Recv() != nil || sig.TypeParams() != nil || sig.Variadic() || sig.Results().Len() != 0 {
		return false
	}
	params := sig.Params()
	if params.Len() == 1 && isTestingTPtrType(params.At(0).Type()) {
		return true
	}
	return params.Len() == 2 && isTestingTPtrType(params.At(0).Type()) && syntaxutil.IsByteSliceType(params.At(1).Type())
}

func isMethodOwnFirstRecvTypeParam(sig *types.Signature, ret types.Type, ownerTP *types.TypeParam) bool {
	tp, ok := types.Unalias(ret).(*types.TypeParam)
	if !ok {
		return false
	}
	if tp == ownerTP {
		return true
	}
	if rtps := sig.RecvTypeParams(); rtps != nil && rtps.Len() == 1 && rtps.At(0) == tp {
		return true
	}
	return false
}

func sigHasHandleStructPtrParam(sc *harnessScreen, sig *types.Signature) bool {
	if sig == nil {
		return false
	}
	n := sig.Params().Len()
	if sig.Variadic() && n > 0 {
		n--
	}
	for i := 0; i < n; i++ {
		if sc.isHandleStructPtr(sig.Params().At(i).Type()) {
			return true
		}
	}
	return false
}

func constStringPrefix(info *types.Info, e ast.Expr, prefix string) bool {
	if info == nil || e == nil {
		return false
	}
	tv, ok := info.Types[e]
	return ok && tv.Value != nil && tv.Value.Kind() == constant.String && strings.HasPrefix(constant.StringVal(tv.Value), prefix)
}

func constStringEq(info *types.Info, e ast.Expr, want string) bool {
	if info == nil || e == nil {
		return false
	}
	tv, ok := info.Types[e]
	return ok && tv.Value != nil && tv.Value.Kind() == constant.String && constant.StringVal(tv.Value) == want
}
