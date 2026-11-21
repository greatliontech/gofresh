package closure

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/types"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// MaximalIdentity is the comparable source and derivation dependency identity of a
// maximal closure. Its fields have the same meanings as the corresponding
// Closure fields. Identity agreement alone establishes no semantic authority.
type MaximalIdentity struct {
	Hash             string
	TestVariants     string
	ToolchainContent string
	AdmissionPolicy  string
}

// BlockerKind identifies a conservative external-effect classification. It is
// neither an approval of an implementation nor an occurrence identifier.
type BlockerKind uint8

// These kinds project the existing maximal scan's classifications.
const (
	BlockerOpaque             BlockerKind = BlockerKind(ExternalEffectOpaque)
	BlockerStandardInput      BlockerKind = BlockerKind(ExternalEffectStandardInput)
	BlockerFormattedOutput    BlockerKind = BlockerKind(ExternalEffectFormattedOutput)
	BlockerEnvironment        BlockerKind = BlockerKind(ExternalEffectEnvironment)
	BlockerFileIO             BlockerKind = BlockerKind(ExternalEffectFileIO)
	BlockerFilesystemMutation BlockerKind = BlockerKind(ExternalEffectFilesystemMutation)
	BlockerPathMutation       BlockerKind = BlockerKind(ExternalEffectPathMutation)
	BlockerTestRuntime        BlockerKind = BlockerKind(ExternalEffectTestRuntime)
	BlockerNetwork            BlockerKind = BlockerKind(ExternalEffectNetwork)
	BlockerPlugin             BlockerKind = BlockerKind(ExternalEffectPlugin)
	BlockerNative             BlockerKind = BlockerKind(ExternalEffectNative)
	BlockerLinkage            BlockerKind = BlockerKind(ExternalEffectLinkage)
	BlockerUnauditedStandard  BlockerKind = BlockerKind(ExternalEffectUnauditedStandard)
)

// Blocker is a caller-owned projection of a conservative classification, covering
// ALL matching origins and occurrences in the subject's selected test-binary
// source closure. Scans deduplicate classifications across files, declarations
// and package/test-variant nodes; this value is not an exact occurrence inventory.
// Discharging its obligation requires covering or excluding that whole scope.
// A package or symbol lookup alone cannot discharge it.
type Blocker struct {
	Kind BlockerKind
	// Package and Symbol locate referenced candidates where the scan knows them,
	// not originating nodes, call sites or proof coverage. Either may be empty.
	Package string
	Symbol  string
	// Detail retains the scan's classification-specific payload, when present.
	Detail string
	// Reason is diagnostic text, not a semantic discriminator or discharge key.
	Reason string
	// Observable and Unrefinable retain the scan's existing flags. They supply
	// neither observation completeness nor independent implementation authority.
	Observable  bool
	Unrefinable bool
}

// MaximalFacts contains a maximal identity, the complete maximal scan's blocker
// classifications and its preferred diagnostic. These are constructible base data,
// not checked proof authority, evidence-dependent refinement or consumer-tier
// refusals. ComputeMaximalFactsBatch returns caller-owned values. An immutable
// snapshot accepting a caller's value must Clone it at its ownership boundary.
// The zero value is unavailable and its Closure projection fails closed.
type MaximalFacts struct {
	Identity MaximalIdentity
	// Effects is the complete set of conservative classifications, with each
	// entry covering the whole scope documented by Blocker. It says nothing
	// about completeness of the separate precise observation analysis.
	Effects []Blocker
	// Diagnostic is the preferred human-readable reason, including a possible
	// import-only candidate when Effects is empty. It selects no authority.
	Diagnostic string
}

func newMaximalFacts(identity MaximalIdentity, effects []ExternalEffect, preferred string) MaximalFacts {
	owned := make([]Blocker, len(effects))
	for i, effect := range effects {
		owned[i] = Blocker{
			Kind: BlockerKind(effect.Kind), Package: effect.PackagePath,
			Symbol: effect.Symbol, Detail: effect.Detail, Reason: effect.Reason,
			Observable: effect.Observable, Unrefinable: effect.Unrefinable,
		}
	}
	// The scan's first-occurrence order is not semantic. Canonicalize all fields
	// so equivalent complete scans compare equally even if their traversal moves.
	slices.SortFunc(owned, func(a, b Blocker) int {
		if order := cmp.Or(cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(a.Package, b.Package), cmp.Compare(a.Symbol, b.Symbol),
			cmp.Compare(a.Detail, b.Detail), cmp.Compare(a.Reason, b.Reason)); order != 0 {
			return order
		}
		if a.Observable != b.Observable {
			if a.Observable {
				return 1
			}
			return -1
		}
		if a.Unrefinable != b.Unrefinable {
			if a.Unrefinable {
				return 1
			}
			return -1
		}
		return 0
	})
	return MaximalFacts{Identity: identity, Effects: owned, Diagnostic: preferred}
}

// Clone returns an independently owned copy, including the effect slice.
func (f MaximalFacts) Clone() MaximalFacts {
	f.Effects = slices.Clone(f.Effects)
	return f
}

// Closure projects the ordinary maximal-tier result, preserving the preferred
// diagnostic even when it came from an import candidate and no blocker exists.
// An unavailable value refuses rather than implying an empty, supported scan.
func (f MaximalFacts) Closure() Closure {
	result := Closure{
		Hash:             f.Identity.Hash,
		TestVariants:     f.Identity.TestVariants,
		ToolchainContent: f.Identity.ToolchainContent,
		AdmissionPolicy:  f.Identity.AdmissionPolicy,
		Unverifiable:     len(f.Effects) != 0 || f.Identity.Hash == "",
		Reason:           f.Diagnostic,
	}
	if f.Identity.Hash == "" {
		result.Reason = "maximal facts unavailable"
	}
	return result
}

// Equal compares identity, every blocker field in order and the preferred
// diagnostic. Batch results use canonical effect order. Agreement of just the
// Closure projection is insufficient.
func (f MaximalFacts) Equal(other MaximalFacts) bool {
	return f.Identity == other.Identity && f.Diagnostic == other.Diagnostic &&
		slices.Equal(f.Effects, other.Effects)
}

// InMemoryMaximalFacts computes the maximal closure facts for subject directly
// from pre-parsed and typechecked in-memory packages without invoking `go list`.
func InMemoryMaximalFacts(audited bool, pkgs []*packages.Package, subject Subject) (MaximalFacts, error) {
	pkgPath := subject.Package
	declaredNames := make(map[string]string, len(pkgs)*2)
	nonStdPaths := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		if p.PkgPath != "" && p.Name != "" {
			declaredNames[p.PkgPath] = p.Name
		}
		if p.Module != nil && p.PkgPath != "" {
			nonStdPaths[p.PkgPath] = true
		}
		for impPath, impPkg := range p.Imports {
			if impPkg != nil && impPkg.Name != "" {
				declaredNames[impPath] = impPkg.Name
			}
		}
	}
	var effects []ExternalEffect
	var candidates []ExternalEffect
	var fallback string
	record := func(scan MaximalEffectScan) {
		for _, effect := range scan.Effects {
			effects = AppendExternalEffect(effects, effect)
			candidates = AppendExternalEffect(candidates, effect)
		}
		for _, candidate := range scan.ImportCandidates {
			candidates = AppendExternalEffect(candidates, candidate)
		}
		if len(scan.Effects) == 0 && len(scan.ImportCandidates) == 0 && scan.Preferred != "" && (fallback == "" || scan.Preferred < fallback) {
			fallback = scan.Preferred
		}
	}
	var testingScan MaximalEffectScan
	for _, pkg := range pkgs {
		if pkg.PkgPath != pkgPath && pkg.ForTest != pkgPath {
			continue
		}
		for _, file := range pkg.Syntax {
			ast.Inspect(file, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				var object types.Object
				if selection := pkg.TypesInfo.Selections[selector]; selection != nil {
					object = selection.Obj()
				} else {
					object = pkg.TypesInfo.Uses[selector.Sel]
				}
				if object == nil || object.Pkg() == nil || object.Pkg().Path() != "testing" {
					return true
				}
				if effect, ok := ClassBEffect("testing", object.Name()); ok {
					testingScan.Add(effect)
				}
				return true
			})
		}
	}
	testingScan.Preferred = PreferredEffectReason(testingScan.Effects)
	record(testingScan)

	inCone := map[*packages.Package]bool{}
	var ordered []*packages.Package
	var visit func(p *packages.Package)
	visit = func(p *packages.Package) {
		if p == nil || p.Module == nil || inCone[p] {
			return
		}
		inCone[p] = true
		ordered = append(ordered, p)
		impPaths := make([]string, 0, len(p.Imports))
		for impPath := range p.Imports {
			impPaths = append(impPaths, impPath)
		}
		slices.Sort(impPaths)
		for _, impPath := range impPaths {
			visit(p.Imports[impPath])
		}
	}
	for _, p := range pkgs {
		if p.PkgPath == pkgPath || p.ForTest == pkgPath {
			visit(p)
		}
	}
	seenFiles := map[string]bool{}
	coreHasher := sha256.New()
	for _, p := range ordered {
		for _, fullPath := range p.CompiledGoFiles {
			if seenFiles[fullPath] {
				continue
			}
			seenFiles[fullPath] = true
			content, err := os.ReadFile(fullPath)
			if err != nil {
				return MaximalFacts{}, err
			}
			_, _ = coreHasher.Write(content)
			scan, err := maximalFileEffectsContentWithContextFiltered(audited, fullPath, content, declaredNames, nonStdPaths, nil)
			if err != nil {
				return MaximalFacts{}, err
			}
			record(scan)
		}
	}
	selected := PreferredEffectReason(candidates)
	if selected == "" {
		selected = fallback
	}
	coreDigest := hex.EncodeToString(coreHasher.Sum(nil)[:16])
	return newMaximalFacts(MaximalIdentity{
		Hash:             maximalSubjectHash(coreDigest, subject),
		ToolchainContent: "inmem-stdlib",
		AdmissionPolicy:  "inmem-audit",
	}, effects, selected), nil
}

func packageHasClassifiedExternalAPI(pkgPath string) bool {
	return auditset.ClassBPackage(pkgPath)
}

// ImplicitImportName returns the fallback identifier derived from an import
// path when no package listing supplies the declared package name.
func ImplicitImportName(pkgPath string) string {
	base := path.Base(pkgPath)
	if len(base) > 1 && base[0] == 'v' && strings.TrimLeft(base[1:], "0123456789") == "" {
		if dir := path.Dir(pkgPath); dir != "." && dir != "/" {
			return path.Base(dir)
		}
	}
	return base
}

func implicitImportName(pkgPath string) string {
	return ImplicitImportName(pkgPath)
}

func listedDeclaredNames(pkgs []listPkg) map[string]string {
	if len(pkgs) == 0 {
		return nil
	}
	names := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		if p.Name == "" || p.Name == "main" || strings.HasSuffix(p.Name, "_test") {
			continue
		}
		src := p.SourcePath()
		if existing, exists := names[src]; exists && existing != p.Name {
			names[src] = ""
		} else {
			names[src] = p.Name
		}
	}
	return names
}

func listedNonStandardPaths(pkgs []listPkg) map[string]bool {
	if len(pkgs) == 0 {
		return nil
	}
	var out map[string]bool
	for _, p := range pkgs {
		if p.Standard || p.Module == nil {
			continue
		}
		if src := p.SourcePath(); src != "" && syntaxutil.IsStandardLibraryPkgPath(src) {
			if out == nil {
				out = make(map[string]bool)
			}
			out[src] = true
		}
	}
	return out
}

func declaredOverridesKey(declaredNames map[string]string) string {
	return scanOverridesKey(declaredNames, nil)
}

func scanOverridesKey(declaredNames map[string]string, nonStdPaths map[string]bool) string {
	if len(declaredNames) == 0 && len(nonStdPaths) == 0 {
		return ""
	}
	var overrides []string
	for pkgPath, name := range declaredNames {
		if name == "" {
			continue
		}
		if name != path.Base(pkgPath) || implicitImportName(pkgPath) != path.Base(pkgPath) {
			overrides = append(overrides, pkgPath+"="+name)
		}
	}
	for pkgPath := range nonStdPaths {
		if syntaxutil.IsStandardLibraryPkgPath(pkgPath) {
			overrides = append(overrides, "nonstd:"+pkgPath)
		}
	}
	if len(overrides) == 0 {
		return ""
	}
	slices.Sort(overrides)
	sum := sha256.Sum256([]byte(strings.Join(overrides, "\x00")))
	return "\x00" + hex.EncodeToString(sum[:16])
}

func trueReason(pkgPath string) string {
	return trueExternalEffect(pkgPath).Reason
}

// trueExternalEffect names an always-external package's effect.
func trueExternalEffect(pkgPath string) ExternalEffect {
	switch {
	case pkgPath == "plugin":
		return SymbolExternalEffect(ExternalEffectPlugin, pkgPath, "", "reaches plugin")
	case auditset.NetworkPackage(pkgPath):
		return SymbolExternalEffect(ExternalEffectNetwork, pkgPath, "", "reaches "+pkgPath+" (network I/O)")
	default:
		return SymbolExternalEffect(ExternalEffectNative, pkgPath, "", "reaches "+pkgPath+" (external system call)")
	}
}
