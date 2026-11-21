package observability

import (
	"context"
	"errors"
	"go/ast"
	"go/types"
	"sync"
	"sync/atomic"
	"time"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/cprep"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/propharness"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
	"github.com/greatliontech/gofresh/internal/trace"
)

// Subject identifies a function or method whose observability or rooted flow is requested.
type Subject = closure.Subject

type (
	Hasher             = closure.Hasher
	program            = Program
	listPkg            = gotool.ListedPackage
	externalEffect     = closure.ExternalEffect
	externalEffectKind = closure.ExternalEffectKind
	maximalEffectScan  = closure.MaximalEffectScan
	funcDeclKey        = closure.FuncDeclKey
	pkgVarKey          = closure.PkgVarKey
)

const (
	externalEffectOpaque             = closure.ExternalEffectOpaque
	externalEffectStandardInput      = closure.ExternalEffectStandardInput
	externalEffectFormattedOutput    = closure.ExternalEffectFormattedOutput
	externalEffectEnvironment        = closure.ExternalEffectEnvironment
	externalEffectFileIO             = closure.ExternalEffectFileIO
	externalEffectFilesystemMutation = closure.ExternalEffectFilesystemMutation
	externalEffectPathMutation       = closure.ExternalEffectPathMutation
	externalEffectTestRuntime        = closure.ExternalEffectTestRuntime
	externalEffectNetwork            = closure.ExternalEffectNetwork
	externalEffectPlugin             = closure.ExternalEffectPlugin
	externalEffectNative             = closure.ExternalEffectNative
	externalEffectLinkage            = closure.ExternalEffectLinkage
	externalEffectUnauditedStandard  = closure.ExternalEffectUnauditedStandard
)

// Prover orchestrates Tier-2 whole-program SSA program loading, observability
// proofs, and post-initialization rooted-flow inventories over a Tier-1
// closure.Hasher.
type Prover struct {
	*closure.Hasher
	progs                 map[string]*Program
	progErrs              map[string]error
	packageMates          map[string][]Subject
	loadProgramOnMiss     func(ctx context.Context, p *Prover, pkgPath string) (*Program, bool, error)
	testingPackagesOnMiss func(p *Prover, pkgPath string) *Program
}

// NewProver wraps h with Tier-2 SSA program caching and hooks h's loaded-package
// lookup so Tier-1 typed scans reuse any loaded SSA programs.
func NewProver(h *closure.Hasher) *Prover {
	p := &Prover{
		Hasher:   h,
		progs:    map[string]*Program{},
		progErrs: map[string]error{},
	}
	if h != nil {
		h.SetLoadedPackagesLookup(p.loadedPackagesFor)
		h.SetHasStartedHook(func() bool {
			return len(p.progs) != 0 || len(p.progErrs) != 0
		})
		h.SetResetCallScopeHook(p.resetSummaries)
	}
	return p
}

// NewAt constructs a closure.Hasher and wraps it in a Prover.
func NewAt(ctx context.Context, reader *gotool.EnvReader, buildFlags ...string) (*Prover, error) {
	h, err := closure.NewAt(ctx, reader, buildFlags...)
	if err != nil {
		return nil, err
	}
	return NewProver(h), nil
}

// NewBracketAt constructs a live-GOFLAGS bracket Hasher and wraps it in a Prover.
func NewBracketAt(ctx context.Context, reader *gotool.EnvReader, buildFlags ...string) (*Prover, error) {
	h, err := closure.NewBracketAt(ctx, reader, buildFlags...)
	if err != nil {
		return nil, err
	}
	return NewProver(h), nil
}

// BaseHasher returns the underlying Tier-1 *closure.Hasher, or nil when p is nil.
func (p *Prover) BaseHasher() *closure.Hasher {
	if p == nil {
		return nil
	}
	return p.Hasher
}

// SetPackageMates supplies same-package sibling subjects that may opportunistically
// share unused bitmask slots (< 64) when an observability batch already loads and
// analyzes their package's test-binary SSA program.
func (p *Prover) SetPackageMates(subjects []Subject) {
	if p == nil {
		return
	}
	if len(subjects) == 0 {
		p.packageMates = nil
		return
	}
	byPkg := make(map[string][]Subject)
	for _, s := range subjects {
		byPkg[s.Package] = append(byPkg[s.Package], s)
	}
	p.packageMates = byPkg
}

// BoundAnalysis narrows the context governing subsequent analysis on p and its Hasher.
func (p *Prover) BoundAnalysis(bound context.Context) error {
	if bound == nil {
		return errors.New("closure: nil analysis bound")
	}
	if p == nil || p.Hasher == nil {
		return errors.New("closure: nil prover")
	}
	if len(p.progs) != 0 || len(p.progErrs) != 0 {
		return errors.New("closure: analysis already begun; bound the Hasher before its first compute")
	}
	return p.Hasher.BoundAnalysis(bound)
}

func (p *Prover) resetSummaries() {
	if p == nil {
		return
	}
	for _, prog := range p.progs {
		prog.resetSummaries()
	}
}

// ResetCallScope clears per-batch-call memo state on p's Hasher and drops any
// per-call summaries cached on retained SSA programs.
func (p *Prover) ResetCallScope() {
	p.resetCallScope()
}

func (p *Prover) resetCallScope() {
	if p == nil {
		return
	}
	if p.Hasher != nil {
		p.Hasher.ResetCallScope()
	} else {
		p.resetSummaries()
	}
}

func (p *Prover) loadedPackagesFor(pkgPath string) []*packages.Package {
	if p == nil {
		return nil
	}
	if pkgPath != "" {
		if prog := p.progs[pkgPath]; prog != nil && len(prog.Pkgs) > 0 {
			return prog.Pkgs
		}
		if p.testingPackagesOnMiss != nil {
			if prog := p.testingPackagesOnMiss(p, pkgPath); prog != nil && len(prog.Pkgs) > 0 {
				return prog.Pkgs
			}
		}
		return nil
	}
	for _, prog := range p.progs {
		if prog != nil && len(prog.Pkgs) > 0 {
			return prog.Pkgs
		}
	}
	return nil
}

type observabilityTestHookSet struct {
	analyzeBatch  func(ctx context.Context, audited bool, pureDelegates map[string]bool, prog *Program, subjects []Subject) ([]attributedReachability, error)
	probePkgScope func(ctx context.Context, prog *Program, subjects []Subject) error
}

var (
	observabilityTestHooksMu sync.Mutex
	observabilityTestHooks   atomic.Pointer[observabilityTestHookSet]
)

func withObservabilityTestHooks(hooks observabilityTestHookSet, fn func()) {
	observabilityTestHooksMu.Lock()
	defer observabilityTestHooksMu.Unlock()
	defer observabilityTestHooks.Store(nil)
	observabilityTestHooks.Store(&hooks)
	fn()
}

func runAnalyzeAttributedBatch(ctx context.Context, audited bool, pureDelegates map[string]bool, prog *Program, subjects []Subject) ([]attributedReachability, error) {
	if h := observabilityTestHooks.Load(); h != nil && h.analyzeBatch != nil {
		return h.analyzeBatch(ctx, audited, pureDelegates, prog, subjects)
	}
	return attributedReachableSetsOnce(ctx, audited, pureDelegates, prog, subjects)
}

func runProbePackageScope(ctx context.Context, prog *Program, subjects []Subject) error {
	if h := observabilityTestHooks.Load(); h != nil && h.probePkgScope != nil {
		return h.probePkgScope(ctx, prog, subjects)
	}
	return defaultProbePackageScope(ctx, prog, subjects)
}

// Package-private bridges to canonical Tier-1 / leaf helpers.
func opaqueExternalEffect(kind externalEffectKind, reason string) externalEffect {
	return closure.OpaqueExternalEffect(kind, reason)
}

func symbolExternalEffect(kind externalEffectKind, pkgPath, name, reason string) externalEffect {
	return closure.SymbolExternalEffect(kind, pkgPath, name, reason)
}

func unauditedStandardEffect(pkgPath, name string) externalEffect {
	return closure.UnauditedStandardEffect(pkgPath, name)
}

func appendExternalEffect(effects []externalEffect, effect externalEffect) []externalEffect {
	return closure.AppendExternalEffect(effects, effect)
}

func effectCauseRank(effect externalEffect) int {
	return closure.EffectCauseRank(effect)
}

func effectLess(a, b externalEffect) bool {
	return closure.EffectLess(a, b)
}

func preferEffectReason(candidate, current externalEffect) bool {
	return closure.PreferEffectReason(candidate, current)
}

func classBEffect(pkgPath, name string) (externalEffect, bool) {
	return closure.ClassBEffect(pkgPath, name)
}

func classBReason(pkgPath, name string) string {
	return closure.ClassBReason(pkgPath, name)
}

func classBPureStandard(audited bool, pkgPath, name string) bool {
	return closure.ClassBPureStandard(audited, pkgPath, name)
}

func auditedStandardSymbol(audited bool, pkgPath, name string) bool {
	return closure.AuditedStandardSymbol(audited, pkgPath, name)
}

func admittedPureStandardOrDelegateSymbol(audited bool, pureDelegates map[string]bool, pkgPath, name string) bool {
	return closure.AdmittedPureStandardOrDelegateSymbol(audited, pureDelegates, pkgPath, name)
}

func isSourceOnlyStandardPackage(audited bool, pkgPath string) bool {
	return closure.IsSourceOnlyStandardPackage(audited, pkgPath)
}

func isStandardFallbackExempt(audited bool, pkgPath string) bool {
	return closure.IsStandardFallbackExempt(audited, pkgPath)
}

func fmtFprintFamily(audited bool, pkgPath, name string) bool {
	return closure.FmtFprintFamily(audited, pkgPath, name)
}

func fmtFscanFamily(audited bool, pkgPath, name string) bool {
	return closure.FmtFscanFamily(audited, pkgPath, name)
}

func flagRegistrationSymbol(pkgPath, name string) bool {
	return closure.FlagRegistrationSymbol(pkgPath, name)
}

func isCompileTimeUnsafeIntrinsic(pkgPath, name string) bool {
	return closure.IsCompileTimeUnsafeIntrinsic(pkgPath, name)
}

func propertyHarnessFact(vp *propharness.VerifiedPackage) externalEffect {
	return closure.PropertyHarnessFact(vp)
}

func isPropertyHarnessFact(effect externalEffect) bool {
	return closure.IsPropertyHarnessFact(effect)
}

func maximalObservabilityBlocker(audited bool, effect externalEffect) bool {
	return closure.MaximalObservabilityBlocker(audited, effect)
}

func hasFilterableMaximalBlocker(audited bool, effects []externalEffect) bool {
	return closure.HasFilterableMaximalBlocker(audited, effects)
}

func hasAnyMaximalBlocker(audited bool, effects []externalEffect) bool {
	return closure.HasAnyMaximalBlocker(audited, effects)
}

func hasExternalCgo(flags []string) bool {
	return closure.HasExternalCgo(flags)
}

func hasExternalCgoMeta(p *listPkg) bool {
	return closure.HasExternalCgoMeta(p)
}

func listPkgHasNativeOrEmbed(p *listPkg) bool {
	return closure.ListPkgHasNativeOrEmbed(p)
}

func funcDeclKeyForAST(dir, pkgClause string, fn *ast.FuncDecl) (funcDeclKey, bool) {
	return closure.FuncDeclKeyForAST(dir, pkgClause, fn)
}

func ifCondRequiresNonZeroGlobalTyped(expr ast.Expr, info *types.Info, zeroGlobalDecls map[pkgVarKey]bool) bool {
	return closure.IfCondRequiresNonZeroGlobalTyped(expr, info, zeroGlobalDecls)
}

func isStdImportPath(pkgPath string) bool {
	return syntaxutil.IsStandardLibraryPkgPath(pkgPath)
}

func isInternalStdPackagePath(pkgPath string) bool {
	return syntaxutil.IsInternalStdPkgPath(pkgPath)
}

func forEachGoLinknameDirective(groups []*ast.CommentGroup, visit func(local, target string, valid bool)) {
	cprep.ForEachGoLinknameDirective(groups, visit)
}

func parseGoLinknameDirectiveComment(text string) (local, target string, matched, valid bool) {
	return cprep.ParseGoLinknameDirectiveComment(text)
}

func hasRawGoLinkname(text string) bool {
	return cprep.HasRawGoLinkname(text)
}

func isWasmImportComment(text string) bool {
	return cprep.IsWasmImportComment(text)
}

func isGeneratedTestMainLoadedPkg(p *packages.Package) bool {
	return gotool.IsGeneratedTestMainPackage(p)
}

func bindProgramHasher(h *closure.Hasher, p *Program) {
	if h == nil || p == nil {
		return
	}
	p.GOARCH = h.EffectiveGOARCH()
	p.Source = h
}

func pkgScopeShadowedUniverseZeroNames(base *tier2Base, pkgPath string) map[string]bool {
	if base == nil || pkgPath == "" {
		return nil
	}
	var out map[string]bool
	for tp, idx := range base.idxByTypes {
		if tp == nil || idx == nil || idx.path != pkgPath || tp.Scope() == nil {
			continue
		}
		for _, kw := range []string{"nil", "false"} {
			if tp.Scope().Lookup(kw) != nil {
				if out == nil {
					out = make(map[string]bool, 2)
				}
				out[kw] = true
			}
		}
	}
	return out
}

func subjectMaximalExternalEffectsWithZeroGlobals(
	h *closure.Hasher,
	base *tier2Base,
	pkgPath string,
	reachedDecls, startupOnlyDecls map[funcDeclKey]bool,
	startupZeroGlobalDecls, wholeZeroGlobalDecls map[pkgVarKey]bool,
) ([]externalEffect, error) {
	ctx := h.Context()
	tracing := trace.Enabled(ctx, trace.DomainClosure, pkgPath)
	var start time.Time
	if tracing {
		start = time.Now()
	}
	var loaded []*packages.Package
	var verifiedHarnesses map[string]*propharness.VerifiedPackage
	trackedChdirSafe := false
	if base != nil {
		if base.prog != nil {
			loaded = base.prog.Pkgs
			verifiedHarnesses = verifiedHarnessesProg(h.SelectionAudited(), base.prog)
		}
		trackedChdirSafe = base.binaryTrackedChdirSafe()
	}
	effects, _, err := h.WalkPackageGraphEffects(pkgPath, closure.PackageGraphWalkOptions{
		Filtered:               true,
		LoadedPackages:         loaded,
		VerifiedHarnesses:      verifiedHarnesses,
		TrackedChdirSafe:       trackedChdirSafe,
		ReachedDecls:           reachedDecls,
		StartupOnlyDecls:       startupOnlyDecls,
		StartupZeroGlobalDecls: startupZeroGlobalDecls,
		WholeZeroGlobalDecls:   wholeZeroGlobalDecls,
		AsmAdmitted: func(pkg *listPkg) bool {
			if base == nil {
				return false
			}
			_, ok := base.verifiedPackageAssembly(pkg)
			return ok
		},
		PkgScopeShadowed: func(srcPath string) map[string]bool {
			return pkgScopeShadowedUniverseZeroNames(base, srcPath)
		},
		VerifiedLinknameLocals: func(srcPath string) map[string]bool {
			if base == nil {
				return nil
			}
			return base.verifiedReadOnlyLinknameLocals(srcPath)
		},
		PkgConfinedUnsafe: func(importID, srcPath string) bool {
			return base != nil && base.pkgConfinedUnsafe(importID, srcPath)
		},
	})
	if err != nil {
		return nil, err
	}
	if tracing {
		trace.Emit(ctx, trace.DomainClosure, "maximal.subject.done", pkgPath,
			trace.Int("effects", len(effects)),
			trace.Bool("filtered", reachedDecls != nil),
			trace.Int64("elapsed_ns", time.Since(start).Nanoseconds()),
		)
	}
	return effects, nil
}
