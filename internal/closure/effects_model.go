package closure

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/propharness"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
	"github.com/greatliontech/gofresh/internal/toolchain"
	"github.com/greatliontech/gofresh/internal/trace"
)

// Subject identifies a function or method whose source closure is requested.
type Subject struct {
	Package string
	Symbol  string
}

// PkgVarKey identifies a package-level variable by its declaring package path
// and identifier name.
type PkgVarKey struct {
	PkgPath string
	Name    string
}

// FuncDeclKey uniquely identifies an ordinary top-level function or method
// declaration across type-checked package variants and syntactic file scans.
// Package-level init functions and user TestMain declarations are never
// filtered by FuncDeclKey.
type FuncDeclKey struct {
	Dir       string
	PkgClause string
	Recv      string
	Name      string
}

// FuncDeclKeyForAST computes the declaration key for fn, returning false for
// package-level init functions or malformed receiver signatures.
func FuncDeclKeyForAST(dir, pkgClause string, fn *ast.FuncDecl) (FuncDeclKey, bool) {
	if fn == nil || fn.Name == nil || fn.Name.Name == "" || fn.Name.Name == "init" {
		return FuncDeclKey{}, false
	}
	recv := ""
	if fn.Recv != nil {
		if len(fn.Recv.List) != 1 {
			return FuncDeclKey{}, false
		}
		recv = syntaxutil.RecvBaseTypeName(fn.Recv.List[0].Type)
		if recv == "" {
			return FuncDeclKey{}, false
		}
	}
	return FuncDeclKey{
		Dir:       filepath.Clean(dir),
		PkgClause: pkgClause,
		Recv:      recv,
		Name:      fn.Name.Name,
	}, true
}

// UnreachedASTDecls returns top-level function, type, and const AST nodes in
// file whose FuncDeclKey is absent from reachedDecls.
func UnreachedASTDecls(dir, pkgClause string, file *ast.File, testMainDecl *ast.FuncDecl, reachedDecls map[FuncDeclKey]bool) []ast.Node {
	if reachedDecls == nil || file == nil {
		return nil
	}
	dir = filepath.Clean(dir)
	var unreached []ast.Node
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d == testMainDecl || (d.Name != nil && d.Name.Name == "TestMain") {
				continue
			}
			if key, ok := FuncDeclKeyForAST(dir, pkgClause, d); ok && !reachedDecls[key] {
				unreached = append(unreached, d)
			}
		case *ast.GenDecl:
			switch d.Tok {
			case token.TYPE:
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok || ts.Name == nil || ts.Name.Name == "" || ts.Name.Name == "_" {
						continue
					}
					key := FuncDeclKey{Dir: dir, PkgClause: pkgClause, Name: ts.Name.Name}
					if !reachedDecls[key] {
						unreached = append(unreached, ts)
					}
				}
			case token.CONST:
				hasNamed := false
				anyReached := false
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, name := range vs.Names {
						if name == nil || name.Name == "" {
							continue
						}
						if name.Name == "_" {
							anyReached = true
							continue
						}
						hasNamed = true
						key := FuncDeclKey{Dir: dir, PkgClause: pkgClause, Name: name.Name}
						if reachedDecls[key] {
							anyReached = true
						}
					}
				}
				if hasNamed && !anyReached {
					unreached = append(unreached, d)
				}
			}
		}
	}
	return unreached
}

// ExternalEffectKind classifies an external dependence or runtime channel.
//
// The enum ORDER is the effect projection's primary sort key; the proof's
// refusal names the highest-ranked blocking effect under EffectCauseRank
// with this order as the tie-break — so inserting or reordering members,
// and any rank-table edit that can move a RECORDED reason text, owe an
// ObservationRTA bump (the recorded-evidence versioning clause) — and,
// because the persisted effect and testing scans store the kind as its
// number, an effectScanStrategy and a testingScanStrategy bump too; a
// re-stratification provably touching no recorded class states that
// exemption in its commit message instead.
type ExternalEffectKind uint8

const (
	ExternalEffectOpaque ExternalEffectKind = iota
	ExternalEffectStandardInput
	ExternalEffectFormattedOutput
	ExternalEffectEnvironment
	ExternalEffectFileIO
	ExternalEffectFilesystemMutation
	ExternalEffectPathMutation
	ExternalEffectTestRuntime
	ExternalEffectNetwork
	ExternalEffectPlugin
	ExternalEffectNative
	ExternalEffectLinkage
	ExternalEffectUnauditedStandard
)

// ExternalEffect retains the complete machine-readable fact independently of
// the single legacy diagnostic projected through Closure.Reason.
type ExternalEffect struct {
	Kind        ExternalEffectKind
	PackagePath string
	Symbol      string
	Detail      string
	Reason      string
	Unrefinable bool
	Observable  bool
}

// MaximalEffectScan collects verdict-bearing external effects and diagnostic
// import-only candidates for one file or package scan.
type MaximalEffectScan struct {
	Effects []ExternalEffect
	// ImportCandidates are diagnostic-only candidates: a plain
	// always-external import names its package as a preferred-reason
	// candidate at its rank without contributing a verdict-bearing
	// effect - an unused import blocks nothing
	// (REQ-closure-observability-cause-order).
	ImportCandidates []ExternalEffect
	Preferred        string
}

// Add appends effect to s.Effects when non-empty and not already present.
func (s *MaximalEffectScan) Add(effect ExternalEffect) {
	s.Effects = AppendExternalEffect(s.Effects, effect)
}

// Merge folds other's effects, import candidates, and fallback preferred reason
// into s.
func (s *MaximalEffectScan) Merge(other MaximalEffectScan) {
	for _, effect := range other.Effects {
		s.Add(effect)
	}
	for _, candidate := range other.ImportCandidates {
		s.ImportCandidates = AppendExternalEffect(s.ImportCandidates, candidate)
	}
	if len(other.Effects) == 0 && len(other.ImportCandidates) == 0 && other.Preferred != "" && (s.Preferred == "" || other.Preferred < s.Preferred) {
		s.Preferred = other.Preferred
	}
}

// PurityResponsibility is the one spelling of the subject-level purity
// channel every refusal that affords it names: the author's durable
// directive or the caller's recorded assertion (REQ-purity-directive,
// REQ-purity-responsibility; REQ-closure-refusal-channels).
const PurityResponsibility = "the //gofresh:pure directive on the subject's declaration or the caller's purity assertion"

func ambientDischargeChannel(kind ExternalEffectKind) string {
	switch kind {
	case ExternalEffectNetwork, ExternalEffectPlugin, ExternalEffectNative:
		return " (dischargeable by restructuring the subject away from the reach, or by " + PurityResponsibility + ")"
	default:
		return ""
	}
}

// OpaqueExternalEffect constructs an ExternalEffect without a symbol binding.
func OpaqueExternalEffect(kind ExternalEffectKind, reason string) ExternalEffect {
	return ExternalEffect{Kind: kind, Detail: reason, Reason: reason + ambientDischargeChannel(kind)}
}

// SymbolExternalEffect constructs a symbol-qualified ExternalEffect.
func SymbolExternalEffect(kind ExternalEffectKind, pkgPath, name, reason string) ExternalEffect {
	return ExternalEffect{Kind: kind, PackagePath: pkgPath, Symbol: name, Reason: reason + ambientDischargeChannel(kind)}
}

// UnauditedStandardEffect constructs the standard fallback effect for a symbol
// outside the audited sets.
func UnauditedStandardEffect(pkgPath, name string) ExternalEffect {
	return SymbolExternalEffect(ExternalEffectUnauditedStandard, pkgPath, name, "reaches unaudited standard operation "+pkgPath+"."+name)
}

// AppendExternalEffect appends effect to effects if its Reason is non-empty and
// it is not already present.
func AppendExternalEffect(effects []ExternalEffect, effect ExternalEffect) []ExternalEffect {
	if effect.Reason == "" {
		return effects
	}
	for _, existing := range effects {
		if existing == effect {
			return effects
		}
	}
	return append(effects, effect)
}

// EffectCauseRank returns the cause-preference rank of effect.
func EffectCauseRank(effect ExternalEffect) int {
	if effect.Kind == ExternalEffectTestRuntime && effect.Observable {
		return -1
	}
	if effect.PackagePath == "" && effect.Kind == ExternalEffectTestRuntime {
		return 4
	}
	switch effect.Kind {
	case ExternalEffectUnauditedStandard, ExternalEffectTestRuntime:
		return 0
	case ExternalEffectFormattedOutput, ExternalEffectEnvironment:
		return 1
	case ExternalEffectFileIO:
		return 3
	default:
		return 4
	}
}

// EffectLess imposes a deterministic total order over ExternalEffect values.
func EffectLess(a, b ExternalEffect) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.PackagePath != b.PackagePath {
		return a.PackagePath < b.PackagePath
	}
	if a.Symbol != b.Symbol {
		return a.Symbol < b.Symbol
	}
	if a.Detail != b.Detail {
		return a.Detail < b.Detail
	}
	if a.Reason != b.Reason {
		return a.Reason < b.Reason
	}
	if a.Unrefinable != b.Unrefinable {
		return !a.Unrefinable && b.Unrefinable
	}
	return !a.Observable && b.Observable
}

// PreferEffectReason reports whether candidate displaces current as the
// preferred diagnostic: higher cause rank first, lexicographic least within a rank.
func PreferEffectReason(candidate, current ExternalEffect) bool {
	candidateRank, currentRank := EffectCauseRank(candidate), EffectCauseRank(current)
	if candidateRank != currentRank {
		return candidateRank > currentRank
	}
	return candidate.Reason < current.Reason
}

// PreferredEffectReason selects the diagnostic over an effect set under PreferEffectReason.
func PreferredEffectReason(effects []ExternalEffect) string {
	var best ExternalEffect
	found := false
	for _, effect := range effects {
		if effect.Reason == "" {
			continue
		}
		if !found || PreferEffectReason(effect, best) {
			best, found = effect, true
		}
	}
	return best.Reason
}

type classBEntry struct {
	kind   ExternalEffectKind
	suffix string
}

// classBTable is the one declarative classification table for effect-bearing
// packages, and auditset.ClassBPackages matches its keys so the classifier
// and the maximal tier's dot-import backstop (packageHasClassifiedExternalAPI)
// can never disagree (REQ-closure-observability-audited-set).
var classBTable = func() map[string]map[string]classBEntry {
	arms := []struct {
		pkgs   []string
		kind   ExternalEffectKind
		suffix string
		names  []string
	}{
		{
			pkgs:   []string{"fmt"},
			kind:   ExternalEffectStandardInput,
			suffix: " (standard input)",
			names:  []string{"Scan", "Scanf", "Scanln", "Fscan", "Fscanf", "Fscanln"},
		},
		{
			pkgs:   []string{"fmt"},
			kind:   ExternalEffectFormattedOutput,
			suffix: " (formatted output)",
			names:  []string{"Print", "Printf", "Println", "Fprint", "Fprintf", "Fprintln"},
		},
		{
			pkgs:   []string{"os"},
			kind:   ExternalEffectEnvironment,
			suffix: " (environment input)",
			names:  []string{"Getenv", "LookupEnv", "Environ", "ExpandEnv"},
		},
		{
			pkgs:   []string{"os"},
			kind:   ExternalEffectFileIO,
			suffix: " (file I/O)",
			names:  []string{"Open", "OpenFile", "ReadFile", "ReadDir", "Stat", "Lstat"},
		},
		{
			pkgs:   []string{"os"},
			kind:   ExternalEffectFilesystemMutation,
			suffix: " (filesystem mutation)",
			names:  []string{"Create", "CreateTemp", "WriteFile"},
		},
		{
			pkgs:   []string{"os"},
			kind:   ExternalEffectPathMutation,
			suffix: " (path mutation)",
			names:  []string{"CopyFS", "Link", "Mkdir", "MkdirAll", "MkdirTemp", "Remove", "RemoveAll", "Rename", "Symlink"},
		},
		{
			pkgs:   []string{"syscall", "golang.org/x/sys/unix"},
			kind:   ExternalEffectFilesystemMutation,
			suffix: " (filesystem mutation)",
			names:  []string{"Creat"},
		},
		{
			pkgs:   []string{"syscall", "golang.org/x/sys/unix"},
			kind:   ExternalEffectPathMutation,
			suffix: " (path mutation)",
			names:  []string{"Link", "Linkat", "Mkdir", "Mkdirat", "Rename", "Renameat", "Renameat2", "Rmdir", "Symlink", "Symlinkat", "Unlink", "Unlinkat"},
		},
		{
			pkgs:   []string{"crypto/rand"},
			kind:   ExternalEffectNative,
			suffix: " (entropy)",
			names:  []string{"Read", "Text", "Int", "Prime"},
		},
		{
			pkgs:   []string{"testing"},
			kind:   ExternalEffectPathMutation,
			suffix: " (process or path mutation)",
			names:  []string{"TempDir", "Chdir", "Setenv"},
		},
		{
			pkgs:   []string{"testing"},
			kind:   ExternalEffectTestRuntime,
			suffix: " (test runtime configuration)",
			names:  []string{"Short", "Verbose", "Testing", "CoverMode", "Coverage", "Deadline", "Parallel", "ArtifactDir"},
		},
		{
			pkgs:   []string{"testing"},
			kind:   ExternalEffectTestRuntime,
			suffix: " (test runtime execution)",
			names:  []string{"Run", "Fuzz", "RunParallel", "Elapsed", "Result", "AllocsPerRun", "Benchmark", "RunBenchmarks", "RunExamples", "RunTests", "Main", "MainStart"},
		},
		{
			pkgs:   []string{"net"},
			kind:   ExternalEffectNetwork,
			suffix: " (network I/O)",
			names:  []string{"Dial", "DialContext", "DialTCP", "DialUDP", "DialIP", "Listen", "ListenTCP", "ListenUDP", "ListenIP", "ListenPacket"},
		},
		{
			pkgs:   []string{"net/http"},
			kind:   ExternalEffectNetwork,
			suffix: " (network I/O)",
			names:  []string{"Get", "Head", "Post", "PostForm", "Do", "ListenAndServe", "ListenAndServeTLS", "Serve", "ServeTLS"},
		},
		{
			pkgs:   []string{"html/template", "text/template"},
			kind:   ExternalEffectFileIO,
			suffix: " (file I/O)",
			names:  []string{"ParseFiles", "ParseGlob"},
		},
		{
			pkgs:   []string{"plugin"},
			kind:   ExternalEffectPlugin,
			suffix: "",
			names:  []string{"Open", "Lookup"},
		},
	}
	table := make(map[string]map[string]classBEntry)
	for _, arm := range arms {
		for _, pkg := range arm.pkgs {
			byName := table[pkg]
			if byName == nil {
				byName = make(map[string]classBEntry, len(arm.names))
				table[pkg] = byName
			}
			for _, name := range arm.names {
				byName[name] = classBEntry{kind: arm.kind, suffix: arm.suffix}
			}
		}
	}
	return table
}()

// ClassBEffect classifies an effect-bearing operation by package path and bare symbol name.
func ClassBEffect(pkgPath, name string) (ExternalEffect, bool) {
	entry, ok := classBTable[pkgPath][name]
	if !ok {
		return ExternalEffect{}, false
	}
	return SymbolExternalEffect(entry.kind, pkgPath, name, "reaches "+pkgPath+"."+name+entry.suffix), true
}

// ClassBReason returns the human-readable reason for a Class B symbol, or "".
func ClassBReason(pkgPath, name string) string {
	effect, ok := ClassBEffect(pkgPath, name)
	if !ok {
		return ""
	}
	return effect.Reason
}

// IsSourceOnlyStandardPackage reports whether pkgPath is in the verified
// source-only pure standard-library package set when audited.
func IsSourceOnlyStandardPackage(audited bool, pkgPath string) bool {
	return audited && auditset.PurePackage(pkgPath)
}

// ClassBPureStandard reports whether (pkgPath, name) is an audited pure symbol
// of an effect-bearing standard package.
func ClassBPureStandard(audited bool, pkgPath, name string) bool {
	return audited && auditset.Symbol(pkgPath, name)
}

// AuditedStandardSymbol is the shared bare-name standard-symbol admission ladder.
func AuditedStandardSymbol(audited bool, pkgPath, name string) bool {
	return ClassBPureStandard(audited, pkgPath, name) || (audited && pkgPath == "sync" && auditset.SyncSurfaceName(name))
}

// AdmittedPureStandardOrDelegateSymbol is the bare-name standard/delegate
// admission ladder consulted by syntactic selectors and symbol-level checks.
func AdmittedPureStandardOrDelegateSymbol(audited bool, pureDelegates map[string]bool, pkgPath, name string) bool {
	if !audited || pkgPath == "" {
		return false
	}
	return IsSourceOnlyStandardPackage(true, pkgPath) ||
		AuditedStandardSymbol(true, pkgPath, name) ||
		(pkgPath == "math" && pureDelegates["math:"+name])
}

// IsStandardFallbackExempt reports whether pkgPath is exempt from the
// unaudited-standard fallback.
func IsStandardFallbackExempt(audited bool, pkgPath string) bool {
	return pkgPath == "testing" || IsSourceOnlyStandardPackage(audited, pkgPath)
}

// FmtFprintFamily reports whether (pkgPath, name) is an audited fmt writer-first print function.
func FmtFprintFamily(audited bool, pkgPath, name string) bool {
	return audited && pkgPath == "fmt" && auditset.FmtWriterFunc(name)
}

// FmtFscanFamily reports whether (pkgPath, name) is an audited fmt reader-first scan function.
func FmtFscanFamily(audited bool, pkgPath, name string) bool {
	return audited && pkgPath == "fmt" && auditset.FmtReaderFunc(name)
}

// FlagRegistrationSymbol reports whether (pkgPath, name) is a flag registration operation.
func FlagRegistrationSymbol(pkgPath, name string) bool {
	return pkgPath == "flag" && auditset.FlagSurface(name).IsRegistration()
}

// IsCompileTimeUnsafeIntrinsic reports whether (pkgPath, name) is a Go
// compile-time unsafe layout intrinsic.
func IsCompileTimeUnsafeIntrinsic(pkgPath, name string) bool {
	return pkgPath == "unsafe" && refconfine.IsCompileTimeUnsafeBuiltinName(name)
}

// PropertyHarnessFact records the observable non-blocking package-scan fact for
// a mechanically verified property-testing harness dependency.
func PropertyHarnessFact(vp *propharness.VerifiedPackage) ExternalEffect {
	var pkgPath, sym string
	if vp != nil {
		pkgPath = vp.PkgPath
		sym = vp.PrimaryDriver
	}
	effect := SymbolExternalEffect(
		ExternalEffectTestRuntime,
		pkgPath,
		sym,
		"reaches the audited property-testing harness "+pkgPath,
	)
	effect.Observable = true
	return effect
}

// IsPropertyHarnessFact reports whether effect is a PropertyHarnessFact.
func IsPropertyHarnessFact(effect ExternalEffect) bool {
	return effect.Kind == ExternalEffectTestRuntime && effect.Observable &&
		effect.PackagePath != "" && effect.PackagePath != "testing"
}

func isOpenFlagSymbol(symbol string) bool {
	switch symbol {
	case "O_RDONLY", "O_WRONLY", "O_RDWR", "O_APPEND", "O_CREATE", "O_EXCL", "O_SYNC", "O_TRUNC":
		return true
	default:
		return false
	}
}

// MaximalObservabilityBlocker reports whether effect blocks Tier-2 observation
// when present in the package-level maximal scan.
func MaximalObservabilityBlocker(audited bool, effect ExternalEffect) bool {
	if effect.PackagePath == "testing" && (effect.Symbol == "Run" || effect.Symbol == "Fuzz") {
		return false
	}
	if IsPropertyHarnessFact(effect) {
		return false
	}
	if effect.Reason == "testing runtime value escapes analyzable receiver" {
		return false
	}
	if effect.PackagePath == "runtime" && effect.Symbol == "GOROOT" {
		return false
	}
	if audited && auditset.WriterFirstStdFunc(effect.PackagePath, effect.Symbol) {
		return false
	}
	if FmtFscanFamily(audited, effect.PackagePath, effect.Symbol) {
		return false
	}
	if audited && effect.PackagePath == "go/parser" && auditset.GoParserSourceFunc(effect.Symbol) {
		return false
	}
	if audited && effect.PackagePath == "runtime/debug" && effect.Symbol == "ReadBuildInfo" {
		return false
	}
	if effect.PackagePath == "testing" && effect.Symbol == "TempDir" {
		return false
	}
	if effect.PackagePath == "path/filepath" && effect.Symbol == "Join" {
		return false
	}
	if audited && effect.PackagePath == "math" {
		return false
	}
	if effect.PackagePath == "os" && isOpenFlagSymbol(effect.Symbol) {
		return false
	}
	if effect.PackagePath == "os" {
		switch effect.Symbol {
		case "Getenv", "LookupEnv", "Open", "OpenFile", "ReadFile", "ReadDir", "WriteFile", "Remove", "RemoveAll":
			return false
		}
	}
	if effect.PackagePath == "unsafe" && (effect.Symbol == "Pointer" || IsCompileTimeUnsafeIntrinsic(effect.PackagePath, effect.Symbol)) {
		return false
	}
	return true
}

// PackageWideMaximalHazard reports whether effect is a package-wide process or
// memory hazard that cannot be filtered out solely because its enclosing AST
// declaration is unreached.
func PackageWideMaximalHazard(effect ExternalEffect) bool {
	if effect.PackagePath == "unsafe" && effect.Symbol != "Pointer" && !IsCompileTimeUnsafeIntrinsic(effect.PackagePath, effect.Symbol) {
		return true
	}
	if effect.PackagePath == "os" && effect.Symbol == "Exit" {
		return true
	}
	if effect.PackagePath == "testing" && (effect.Symbol == "Setenv" || effect.Symbol == "Chdir") {
		return true
	}
	if effect.PackagePath == "os" || effect.PackagePath == "syscall" || strings.HasPrefix(effect.PackagePath, "golang.org/x/sys/") {
		switch effect.Symbol {
		case "Setenv", "Unsetenv", "Clearenv", "Chdir", "Fchdir":
			return true
		}
	}
	return false
}

// IsConditionallyConfinedUnsafeSymbol reports whether effect names an unsafe
// operation that can be confined at package scope.
func IsConditionallyConfinedUnsafeSymbol(effect ExternalEffect) bool {
	return effect.PackagePath == "unsafe" && (effect.Symbol == "StringData" || effect.Symbol == "Slice")
}

// IsConditionallyTrackedChdirSymbol reports whether effect names testing.Chdir
// under an audited toolchain.
func IsConditionallyTrackedChdirSymbol(audited bool, effect ExternalEffect) bool {
	return audited && effect.PackagePath == "testing" && effect.Symbol == "Chdir"
}

// PackageWideMaximalHazardForPkg evaluates PackageWideMaximalHazard with
// package-confined unsafe and binary-tracked chdir discharges applied.
func PackageWideMaximalHazardForPkg(audited bool, effect ExternalEffect, pkgConfinedUnsafe, trackedChdirSafe bool) bool {
	if pkgConfinedUnsafe && IsConditionallyConfinedUnsafeSymbol(effect) {
		return false
	}
	if trackedChdirSafe && IsConditionallyTrackedChdirSymbol(audited, effect) {
		return false
	}
	return PackageWideMaximalHazard(effect)
}

// HasFilterableMaximalBlocker reports whether effects contains a maximal
// observability blocker that declaration-level filtering can discharge.
func HasFilterableMaximalBlocker(audited bool, effects []ExternalEffect) bool {
	for _, effect := range effects {
		if MaximalObservabilityBlocker(audited, effect) && (!PackageWideMaximalHazard(effect) || IsConditionallyConfinedUnsafeSymbol(effect) || IsConditionallyTrackedChdirSymbol(audited, effect)) {
			return true
		}
	}
	return false
}

// HasAnyMaximalBlocker reports whether effects contains any MaximalObservabilityBlocker.
func HasAnyMaximalBlocker(audited bool, effects []ExternalEffect) bool {
	for _, effect := range effects {
		if MaximalObservabilityBlocker(audited, effect) {
			return true
		}
	}
	return false
}

// HasExternalCgo reports whether cgo LDFLAGS link an external library or object.
func HasExternalCgo(flags []string) bool {
	for _, f := range flags {
		for _, tok := range expandLinkerFlag(f) {
			if isExternalLinkToken(tok) {
				return true
			}
		}
	}
	return false
}

func expandLinkerFlag(f string) []string {
	if rest, ok := strings.CutPrefix(f, "-Wl,"); ok {
		return strings.Split(rest, ",")
	}
	return []string{f}
}

func isExternalLinkToken(f string) bool {
	return strings.HasPrefix(f, "-l") || f == "-framework" || strings.Contains(f, "-framework") ||
		strings.HasSuffix(f, ".a") || strings.HasSuffix(f, ".dylib") || strings.HasSuffix(f, ".so") ||
		strings.Contains(f, ".dylib.") || strings.Contains(f, ".so.")
}

// HasExternalCgoMeta reports whether p links external cgo libraries via LDFLAGS
// or pkg-config.
func HasExternalCgoMeta(p *gotool.ListedPackage) bool {
	return p != nil && (HasExternalCgo(p.CgoLDFLAGS) || len(p.CgoPkgConfig) > 0)
}

// ListPkgHasNativeOrEmbed reports whether pkg carries external cgo metadata,
// native sources, or //go:embed directives.
func ListPkgHasNativeOrEmbed(pkg *gotool.ListedPackage) bool {
	if pkg == nil {
		return true
	}
	return HasExternalCgoMeta(pkg) || pkg.HasNativeOrEmbed()
}

// AttributeSelection appends the selection's attribution to a tier refusal's reason.
func AttributeSelection(reason, axis string) string {
	return toolchain.AttributeSelection(reason, axis)
}

// propertyHarnessAuditedListPkg evaluates the two-stage property-harness
// screen and mechanical verification for a dependency node in the maximal
// package-scan tier.
func (h *Hasher) propertyHarnessAuditedListPkg(callerPkgPath string, pkg *listPkg) *propharness.VerifiedPackage {
	if h == nil || !h.SelectionAudited() || pkg == nil || pkg.Module == nil ||
		pkg.ImportPath == callerPkgPath || pkg.SourcePath() == callerPkgPath {
		return nil
	}
	if ListPkgHasNativeOrEmbed(pkg) || !propharness.MayBeHarnessImports(pkg.ImportPath, pkg.Imports) {
		return nil
	}
	cacheKey := pkg.Dir
	if cacheKey == "" {
		cacheKey = "\x00" + callerPkgPath + "\x00" + pkg.ImportPath
	}
	if v, ok := h.harnessVerdict[cacheKey]; ok {
		return v
	}
	recordVerdict := func(v *propharness.VerifiedPackage) *propharness.VerifiedPackage {
		if h.harnessVerdict == nil {
			h.harnessVerdict = make(map[string]*propharness.VerifiedPackage, 1)
		}
		h.harnessVerdict[cacheKey] = v
		return v
	}

	isPinned := pkg.Module.Version != "" && h.pinnedPackage(pkg) && pkg.Module.Dir != ""
	loadCandidates := func() ([]*packages.Package, error) {
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
				if p.PkgPath == pkg.ImportPath && p.ForTest == "" && len(p.Syntax) > 0 && p.Types != nil && p.TypesInfo != nil {
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
		if len(candidates) == 0 && h.loadedPackages != nil {
			for _, probePath := range []string{callerPkgPath, pkg.ImportPath, ""} {
				collectFromRoots(h.loadedPackages(probePath))
				if len(candidates) > 0 {
					break
				}
			}
		}
		if len(candidates) == 0 {
			loadDir := h.dir
			pattern := pkg.ImportPath
			if isPinned && pkg.Dir != "" {
				loadDir = pkg.Dir
				pattern = "."
			}
			loaded, err := gotool.LoadPackages(
				h.ctx,
				packages.NeedName|packages.NeedFiles|packages.NeedCompiledGoFiles|packages.NeedEmbedFiles|packages.NeedEmbedPatterns|packages.NeedSyntax|packages.NeedTypes|packages.NeedTypesInfo|packages.NeedImports|packages.NeedModule|packages.NeedForTest,
				loadDir,
				h.packageEnv,
				h.buildFlags,
				pattern,
			)
			if err != nil {
				return nil, err
			}
			collectFromRoots(loaded)
		}
		return candidates, nil
	}

	if isPinned {
		pinnedKey := propharness.BuildPinnedMemoKey(
			AnalyzingFrontend(),
			h.ToolchainContent(),
			h.AdmissionPolicy(),
			h.modulePin(pkg.Module)+"\x00"+pkg.ImportPath,
			h.packageEnv,
			h.buildFlags,
			pkg.GoFiles,
		)
		return recordVerdict(propharness.VerifyPackagePinnedCached(h.ctx, trace.DomainClosure, true, pinnedKey, loadCandidates))
	}

	cands, err := loadCandidates()
	if err != nil || len(cands) == 0 {
		return recordVerdict(nil)
	}
	var verified *propharness.VerifiedPackage
	for _, cand := range cands {
		vp, _ := propharness.VerifyPackageWithIndex(h.ctx, trace.DomainClosure, true, cand, nil)
		if vp == nil {
			return recordVerdict(nil)
		}
		verified = vp
	}
	return recordVerdict(verified)
}
