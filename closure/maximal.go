package closure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
)

// ComputeMaximalBatch returns the maximal sound closure for every subject. All
// subjects in one package share the selected test binary's complete non-standard
// dependency closure; this deliberately trades declaration precision for bounded
// analysis cost while preserving the no-false-valid floor (REQ-closure-floor).
// The package's own test-variant source is partitioned out of the core hash
// into the Closure's TestVariants compartment
// (REQ-closure-test-variant-compartment).
func (h *Hasher) ComputeMaximalBatch(subjects []Subject) (map[Subject]Closure, error) {
	results, _, err := h.ComputeMaximalBatchWithSources(subjects)
	return results, err
}

// ComputeMaximalBatchWithSources also returns the exact mutable source paths
// whose bytes contribute to each subject's maximal closure. Cache-module and
// standard-library inputs remain represented by their existing guards.
func (h *Hasher) ComputeMaximalBatchWithSources(subjects []Subject) (map[Subject]Closure, map[Subject][]string, error) {
	if err := h.contextErr(); err != nil {
		return nil, nil, err
	}
	// One call observes one tree generation; a later call re-observes.
	h.resetCallScope()
	results := make(map[Subject]Closure, len(subjects))
	sources := make(map[Subject][]string, len(subjects))
	byPackage := make(map[string][]Subject)
	var packages []string
	seen := make(map[Subject]bool, len(subjects))
	for _, subject := range subjects {
		if seen[subject] {
			continue
		}
		seen[subject] = true
		if _, ok := byPackage[subject.Package]; !ok {
			packages = append(packages, subject.Package)
		}
		byPackage[subject.Package] = append(byPackage[subject.Package], subject)
	}
	for _, pkgPath := range packages {
		if err := h.contextErr(); err != nil {
			return nil, nil, err
		}
		contributions, files, err := h.maximalContributionsAndFiles(pkgPath)
		if err != nil {
			return nil, nil, err
		}
		hash, err := hashContributions(pkgPath, contributions)
		if err != nil {
			return nil, nil, err
		}
		unverifiable, reason, err := h.maximalUnverifiable(pkgPath)
		if err != nil {
			return nil, nil, err
		}
		for _, subject := range byPackage[pkgPath] {
			results[subject] = Closure{
				Hash:         maximalSubjectHash(hash, subject),
				TestVariants: h.testVariants[pkgPath].Hash,
				Unverifiable: unverifiable,
				Reason:       reason,
			}
			sources[subject] = append([]string(nil), files...)
		}
		if err := h.contextErr(); err != nil {
			return nil, nil, err
		}
		delete(h.lists, pkgPath)
	}
	return results, sources, nil
}

func maximalSubjectHash(packageHash string, subject Subject) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%d:%s%d:%s%d:%s", len(packageHash), packageHash, len(subject.Package), subject.Package, len(subject.Symbol), subject.Symbol))
	return hex.EncodeToString(sum[:])[:32]
}

// maximalUnverifiable conservatively scans every non-standard source file in
// the maximal closure for the high-confidence external-dependence classes. A
// package-wide hit applies to every subject sharing this maximal closure; the
// safe failure direction is a spurious unverifiable verdict.
func (h *Hasher) maximalUnverifiable(pkgPath string) (bool, string, error) {
	effects, selected, err := h.maximalExternalEffects(pkgPath)
	return len(effects) != 0, selected, err
}

// maximalEffectsResult memoizes one package's complete external-effect scan
// within a Hasher: the scan depends only on the package's listed sources, so
// every subject sharing the package shares one scan.
type maximalEffectsResult struct {
	effects  []externalEffect
	selected string
}

// maximalExternalEffects returns the package's complete external-effect scan.
// The returned effects slice aliases the Hasher's memo — callers must treat it
// as read-only.
func (h *Hasher) maximalExternalEffects(pkgPath string) ([]externalEffect, string, error) {
	if cached, ok := h.maximalEffects[pkgPath]; ok {
		return cached.effects, cached.selected, nil
	}
	pkgs, err := h.list(pkgPath)
	if err != nil {
		return nil, "", err
	}
	var effects []externalEffect
	// candidates pools the diagnostic candidates - the effect union
	// plus every scan's plain-import candidates; fallback carries the
	// lexicographically least preferred among candidate-less scans
	// (potential-external fallbacks), naming a dependence only when no
	// scan backed a real blocker or candidate.
	var candidates []externalEffect
	var fallback string
	record := func(scan maximalEffectScan) {
		for _, effect := range scan.effects {
			effects = appendExternalEffect(effects, effect)
			candidates = appendExternalEffect(candidates, effect)
		}
		for _, candidate := range scan.importCandidates {
			candidates = appendExternalEffect(candidates, candidate)
		}
		if len(scan.effects) == 0 && len(scan.importCandidates) == 0 && scan.preferred != "" && (fallback == "" || scan.preferred < fallback) {
			fallback = scan.preferred
		}
	}
	testingEffects, err := h.maximalTestingTypeEffects(pkgPath)
	if err != nil {
		return nil, "", err
	}
	record(testingEffects)
	for _, pkg := range pkgs {
		if err := h.contextErr(); err != nil {
			return nil, "", err
		}
		if pkg.Standard || pkg.Module == nil || pkg.IsGeneratedTestMainFor(pkgPath) {
			continue
		}
		if propertyHarnessPath(pkg.ImportPath) &&
			auditedPropertyHarnessModule(pkg.Module.Version, pkg.Module.Main,
				pkg.Module.Replace != nil && pkg.Module.Replace.Version == "") {
			// Audited property-harness surface: its files carry the
			// harness's own clock, filesystem, and flag protocol, all
			// covered by the package audit - the scan backstop exempts
			// them exactly as it exempts the standard library's. The
			// recorded fact keeps the package unverifiable-by-hash: the
			// audit admits observation, never purity - a property run's
			// outcome rides the harness's log-surfaced configuration,
			// not the sources alone (REQ-closure-observability-analysis).
			record(maximalEffectScan{effects: []externalEffect{propertyHarnessFact()}})
			continue
		}
		if scan, ok, err := h.pinnedEffectScan(pkg); err != nil {
			return nil, "", err
		} else if ok {
			record(scan)
			continue
		}
		record(maximalPackageExternalEffects(&pkg))
		files := append(append([]string(nil), pkg.GoFiles...), pkg.CgoFiles...)
		for _, name := range files {
			if err := h.contextErr(); err != nil {
				return nil, "", err
			}
			scan, err := h.maximalFileEffectsCached(filepath.Join(pkg.Dir, name))
			if err != nil {
				return nil, "", err
			}
			record(scan)
		}
	}
	// The maximal diagnostic owes the shared cause-preference order:
	// one selection over the whole candidate pool, rank strata with the
	// lexicographic tie-break; the import fallback
	// names a potential dependence only for a candidate-less closure.
	selected := preferredEffectReason(candidates)
	if selected == "" {
		selected = fallback
	}
	h.maximalEffects[pkgPath] = maximalEffectsResult{effects: effects, selected: selected}
	return effects, selected, nil
}

// maximalFileEffectsCached memoizes one file's effect scan within a Hasher: a
// file shared by several packages' closures is read and parsed once.
func (h *Hasher) maximalFileEffectsCached(path string) (maximalEffectScan, error) {
	if scan, ok := h.maximalFiles[path]; ok {
		return scan, nil
	}
	scan, err := maximalFileEffects(h.SelectionAudited(), path)
	if err != nil {
		return maximalEffectScan{}, err
	}
	h.maximalFiles[path] = scan
	return scan, nil
}

// preferEffectReason reports whether candidate displaces current as the
// preferred diagnostic: higher cause rank first, lexicographic least
// within a rank - exactly the shared cause-preference order with the
// legacy projection's tie-break, so the maximal instance and the
// legacy projection order every tie identically
// (REQ-closure-observability-analysis). The unrefinable bit takes no
// tie-break leg: no consumer reads the selected reason's refinability,
// so a privilege here would be an order this diagnostic alone obeys.
func preferEffectReason(candidate, current externalEffect) bool {
	candidateRank, currentRank := effectCauseRank(candidate), effectCauseRank(current)
	if candidateRank != currentRank {
		return candidateRank > currentRank
	}
	return candidate.reason < current.reason
}

// preferredEffectReason selects the diagnostic over an effect set under
// preferEffectReason; empty when no effect carries a reason. An
// effect-backed reason names a real blocker, so a caller with any
// backed reason never consults an import fallback
// (REQ-closure-observability-analysis's cause-preference order).
func preferredEffectReason(effects []externalEffect) string {
	var best externalEffect
	found := false
	for _, effect := range effects {
		if effect.reason == "" {
			continue
		}
		if !found || preferEffectReason(effect, best) {
			best, found = effect, true
		}
	}
	return best.reason
}

func (h *Hasher) maximalTestingTypeEffects(pkgPath string) (maximalEffectScan, error) {
	if scan, ok := h.maximalTesting[pkgPath]; ok {
		return scan, nil
	}
	// The persistent memo serves before any type-environment load: the
	// scan is a pure function of (scope, package test-binary closure), so
	// a hit under the complete key is byte-equivalent to recomputation
	// (REQ-closure-testing-scan-memo). A hash-derivation failure disables
	// the memo for the package — fail-open to recomputation.
	scope := h.testingScanScope()
	key := ""
	if scope != "" {
		if k, err := h.testBinaryClosureKey(pkgPath); err == nil {
			key = k
			if scan, ok := loadEffectScan(testingScanDirName, scope, key); ok {
				h.maximalTesting[pkgPath] = scan
				return scan, nil
			}
		}
	}
	loaded := h.viewLoadVariants(pkgPath)
	if loaded == nil {
		if analysisTestHooks.testingTypeOwnLoad != nil {
			analysisTestHooks.testingTypeOwnLoad(pkgPath)
		}
		var err error
		loaded, err = packages.Load(&packages.Config{
			Context:    h.ctx,
			Mode:       packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedForTest,
			Tests:      true,
			Dir:        h.dir,
			Env:        append([]string(nil), h.packageEnv...),
			BuildFlags: append([]string(nil), h.buildFlags...),
		}, pkgPath)
		if err != nil {
			return maximalEffectScan{}, err
		}
	}
	var scan maximalEffectScan
	for _, pkg := range loaded {
		if pkg.PkgPath != pkgPath && pkg.ForTest != pkgPath {
			continue
		}
		for _, packageErr := range pkg.Errors {
			return maximalEffectScan{}, fmt.Errorf("closure: load %s: %s", pkgPath, packageErr)
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
				effect, ok := classBEffect("testing", object.Name())
				if ok {
					scan.add(effect)
				}
				return true
			})
		}
	}
	scan.preferred = preferredEffectReason(scan.effects)
	if key != "" {
		storeEffectScan(testingScanDirName, scope, key, scan)
	}
	h.maximalTesting[pkgPath] = scan
	return scan, nil
}

// viewLoadVariants selects, from the shared view load, the packages a private
// load of pkgPath with Tests would return as pkgPath's own variants — nil when
// no shared load is set or it does not cover pkgPath, signalling fallback.
func (h *Hasher) viewLoadVariants(pkgPath string) []*packages.Package {
	if h.viewLoad == nil {
		return nil
	}
	var variants []*packages.Package
	for _, pkg := range h.viewLoad.Packages() {
		if pkg.PkgPath == pkgPath || pkg.ForTest == pkgPath {
			variants = append(variants, pkg)
		}
	}
	if len(variants) == 0 {
		return nil
	}
	return variants
}

func maximalPackageExternalEffects(pkg *listPkg) maximalEffectScan {
	var scan maximalEffectScan
	if hasExternalCgoMeta(pkg) {
		effect := opaqueExternalEffect(externalEffectNative, "reaches cgo external library")
		effect.unrefinable = true
		scan.add(effect)
	}
	if pkg != nil && len(pkg.SysoFiles) != 0 {
		effect := opaqueExternalEffect(externalEffectNative, "reaches non-standard system object")
		effect.unrefinable = true
		scan.add(effect)
	}
	if hasCgoCallbackBlindspot(pkg) {
		scan.add(opaqueExternalEffect(externalEffectNative, "reaches cgo or native source"))
	}
	if pkg != nil && len(pkg.SFiles) != 0 {
		scan.add(opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly"))
	}
	scan.preferred = preferredEffectReason(scan.effects)
	return scan
}

// importAlias is one import declaration's resolved alias and path, shared
// by the preferred-reason derivation and the effect collection so the scan
// unquotes each import once.
type importAlias struct {
	alias   string
	pkgPath string
}

// maximalFileEffects is the per-file external-effect scan: a pure function
// of the file's bytes. One read and one parse serve both the effect
// collection and the preferred-reason derivation
// (equivalence-pinned by TestFileEffectScanMatchesTwoPassReference).
func maximalFileEffects(audited bool, filename string) (maximalEffectScan, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return maximalEffectScan{}, err
	}
	text := string(content)
	hasWasmImport := strings.Contains(text, "//go:wasmimport")
	hasLinkname := strings.Contains(text, "//go:linkname") && !auditedLinknamesOnly(audited, text)
	// The walks read identifiers by name and imports from file.Imports;
	// object resolution is unused, so skipping it saves its allocations.
	file, err := parser.ParseFile(token.NewFileSet(), filename, content, parser.SkipObjectResolution)
	if err != nil {
		return maximalEffectScan{}, fmt.Errorf("closure: parse %s: %w", filename, err)
	}
	imports := make([]importAlias, 0, len(file.Imports))
	aliases := make(map[string]string, len(file.Imports))
	for _, spec := range file.Imports {
		pkgPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return maximalEffectScan{}, fmt.Errorf("closure: parse import in %s: %w", filename, err)
		}
		alias := path.Base(pkgPath)
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		aliases[alias] = pkgPath
		imports = append(imports, importAlias{alias: alias, pkgPath: pkgPath})
	}
	var scan maximalEffectScan
	// The preferred diagnostic derives from the same single walk's
	// effect set under the shared cause-preference order
	// (preferredEffectReason); the potential-external import fallback
	// names a dependence only for an effect-less file
	// (REQ-closure-observability-analysis).
	potentialExternal := ""
	if hasWasmImport {
		effect := opaqueExternalEffect(externalEffectLinkage, "reaches go:wasmimport")
		effect.unrefinable = true
		scan.add(effect)
	}
	if hasLinkname {
		scan.add(opaqueExternalEffect(externalEffectLinkage, "reaches go:linkname (opaque linkage)"))
	}
	for _, imp := range imports {
		if imp.pkgPath == "testing" {
			if imp.alias == "." {
				scan.add(opaqueExternalEffect(externalEffectUnauditedStandard, "reaches testing (potential external dependence)"))
				potentialExternal = imp.pkgPath
			}
			continue
		}
		if isAlwaysExternalPackage(imp.pkgPath) && imp.alias != "." && imp.alias != "_" {
			// A plain always-external import is a diagnostic candidate
			// only: the dot and blank spellings record the effect
			// itself below.
			scan.importCandidates = appendExternalEffect(scan.importCandidates, trueExternalEffect(imp.pkgPath))
		}
		if imp.alias == "." && packageHasClassifiedExternalAPI(imp.pkgPath) && potentialExternal == "" {
			potentialExternal = imp.pkgPath
		}
		if potentialExternal == "" && isStdImportPath(imp.pkgPath) && !isSourceOnlyStandardPackage(audited, imp.pkgPath) {
			potentialExternal = imp.pkgPath
		}
		if imp.alias == "." || imp.alias == "_" {
			if isAlwaysExternalPackage(imp.pkgPath) {
				scan.add(trueExternalEffect(imp.pkgPath))
			} else if packageHasClassifiedExternalAPI(imp.pkgPath) || isStdImportPath(imp.pkgPath) && !isSourceOnlyStandardPackage(audited, imp.pkgPath) {
				scan.add(opaqueExternalEffect(externalEffectUnauditedStandard, "reaches "+imp.pkgPath+" (potential external dependence)"))
			}
		}
	}
	// The canonical test-main epilogue is harness protocol, not an
	// unaudited operation: os.Exit inside the user TestMain(*testing.M)
	// declaration is admitted exactly as the observed test-main walk
	// admits it - it runs post-bracket and adds no input channel to any
	// subject's execution (REQ-closure-observability-analysis).
	testMainDecl := userTestMainDecl(file, aliases)
	inTestMain := func(node ast.Node) bool {
		return testMainDecl != nil && node.Pos() >= testMainDecl.Pos() && node.End() <= testMainDecl.End()
	}
	ast.Inspect(file, func(node ast.Node) bool {
		if sel, ok := node.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				pkgPath := aliases[ident.Name]
				if effect, ok := classBEffect(pkgPath, sel.Sel.Name); ok {
					scan.add(effect)
				} else if pkgPath == "os" && sel.Sel.Name == "Exit" && inTestMain(sel) {
					// admitted test-main epilogue
				} else if flagRegistrationSymbol(pkgPath, sel.Sel.Name) {
					// flag registration is a process-local registry
					// mutation; the name-based admission is sound
					// because the registration-facts sink judgment
					// guards every call site program-wide - traced
					// storage refuses on reference, an untraceable
					// sink poisons the package
					// (REQ-closure-observability-analysis).
				} else if pkgPath != "testing" && !classBPureStandard(audited, pkgPath, sel.Sel.Name) && !auditedSyncSymbol(audited, pkgPath, sel.Sel.Name) && !auditedPoolSymbol(audited, pkgPath, sel.Sel.Name) && !auditedRuntimeTypeSymbol(audited, pkgPath, sel.Sel.Name) && (isAlwaysExternalPackage(pkgPath) || isStdImportPath(pkgPath) && !isSourceOnlyStandardPackage(audited, pkgPath)) {
					scan.add(symbolExternalEffect(externalEffectUnauditedStandard, pkgPath, sel.Sel.Name, "reaches unaudited standard operation "+pkgPath+"."+sel.Sel.Name))
				}
			}
		}
		return true
	})
	testingEffects, _ := testingMethodEffects(file, aliases)
	for _, effect := range testingEffects {
		scan.add(effect)
	}
	scan.preferred = preferredEffectReason(append(append([]externalEffect(nil), scan.effects...), scan.importCandidates...))
	if scan.preferred == "" && potentialExternal != "" {
		scan.preferred = "reaches " + potentialExternal + " (potential external dependence)"
	}
	return scan, nil
}

// testingMethodEffects returns the file's testing-runtime effects and its
// testing reason: the first function with a non-empty final reason in
// declaration order,
// where a function's reason is the last assignment its walker makes (an
// escape, or a tracked receiver selector's classification — possibly
// empty). Both walker closures run over per-function receiver and parent
// state computed once; equivalence-pinned by
// TestFileEffectScanMatchesTwoPassReference.
func testingMethodEffects(file *ast.File, aliases map[string]string) ([]externalEffect, string) {
	if file == nil {
		return nil, ""
	}
	handleTypes := testingHandleTypeNames(file, aliases)
	reason := ""
	var effects []externalEffect
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Type.Params == nil || function.Body == nil {
			continue
		}
		receivers := map[string]bool{}
		for _, field := range function.Type.Params.List {
			if isTestingHandleType(field.Type, aliases, handleTypes) {
				for _, name := range field.Names {
					receivers[name.Name] = true
				}
			}
		}
		// One body walk collects the name-propagation edges; the fixed
		// point then iterates the small edge list instead of re-walking
		// the whole body per round. The fixed point is order-independent,
		// so the collection order only bounds round count
		// (equivalence-pinned by
		// TestFileEffectScanMatchesTwoPassReference's backward rows).
		type propagation struct{ from, to string }
		var edges []propagation
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if specification, ok := node.(*ast.ValueSpec); ok {
				for i, value := range specification.Values {
					if name, ok := identifierName(value); ok && i < len(specification.Names) {
						edges = append(edges, propagation{from: name, to: specification.Names[i].Name})
					}
				}
			}
			assignment, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, rhs := range assignment.Rhs {
				name, ok := identifierName(rhs)
				if !ok || i >= len(assignment.Lhs) {
					continue
				}
				if lhs, ok := assignment.Lhs[i].(*ast.Ident); ok {
					edges = append(edges, propagation{from: name, to: lhs.Name})
				}
			}
			return true
		})
		changed := true
		for changed {
			changed = false
			for _, edge := range edges {
				if receivers[edge.from] && !receivers[edge.to] {
					receivers[edge.to] = true
					changed = true
				}
			}
		}
		parents := make(map[ast.Node]ast.Node)
		var stack []ast.Node
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if node == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			if len(stack) != 0 {
				parents[node] = stack[len(stack)-1]
			}
			stack = append(stack, node)
			return true
		})
		escape := opaqueExternalEffect(externalEffectTestRuntime, "testing runtime value escapes analyzable receiver")
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.AssignStmt:
				for i, rhs := range node.Rhs {
					name, ok := identifierName(rhs)
					if ok && receivers[name] && i < len(node.Lhs) {
						if _, ok := node.Lhs[i].(*ast.Ident); !ok {
							effects = appendExternalEffect(effects, escape)
						}
					}
				}
			case *ast.CallExpr:
				for _, argument := range node.Args {
					if name, ok := identifierName(argument); ok && receivers[name] {
						effects = appendExternalEffect(effects, escape)
					}
				}
			case *ast.ReturnStmt:
				for _, result := range node.Results {
					if name, ok := identifierName(result); ok && receivers[name] {
						effects = appendExternalEffect(effects, escape)
					}
				}
			case *ast.Ident:
				if receivers[node.Name] && !testingIdentifierUseSupported(node, parents) {
					effects = appendExternalEffect(effects, escape)
				}
			}
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			receiver, ok := selector.X.(*ast.Ident)
			if !ok || !receivers[receiver.Name] {
				return true
			}
			if effect, ok := classBEffect("testing", selector.Sel.Name); ok {
				effects = appendExternalEffect(effects, effect)
			}
			return true
		})
		if reason == "" {
			var fnReason string
			ast.Inspect(function.Body, func(node ast.Node) bool {
				switch node := node.(type) {
				case *ast.AssignStmt:
					for i, rhs := range node.Rhs {
						name, ok := identifierName(rhs)
						if !ok || !receivers[name] || i >= len(node.Lhs) {
							continue
						}
						if _, ok := node.Lhs[i].(*ast.Ident); !ok {
							fnReason = "testing runtime value escapes analyzable receiver"
							return false
						}
					}
				case *ast.CallExpr:
					for _, argument := range node.Args {
						if name, ok := identifierName(argument); ok && receivers[name] {
							fnReason = "testing runtime value escapes analyzable receiver"
							return false
						}
					}
				case *ast.ReturnStmt:
					for _, result := range node.Results {
						if name, ok := identifierName(result); ok && receivers[name] {
							fnReason = "testing runtime value escapes analyzable receiver"
							return false
						}
					}
				case *ast.Ident:
					if receivers[node.Name] && !testingIdentifierUseSupported(node, parents) {
						fnReason = "testing runtime value escapes analyzable receiver"
						return false
					}
				}
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				receiver, ok := selector.X.(*ast.Ident)
				if !ok || !receivers[receiver.Name] {
					return true
				}
				fnReason = classBReason("testing", selector.Sel.Name)
				return fnReason == ""
			})
			if fnReason != "" {
				reason = fnReason
			}
		}
	}
	return effects, reason
}

func testingIdentifierUseSupported(identifier *ast.Ident, parents map[ast.Node]ast.Node) bool {
	var node ast.Node = identifier
	parent := parents[node]
	for {
		parenthesized, ok := parent.(*ast.ParenExpr)
		if !ok || parenthesized.X != node {
			break
		}
		node = parent
		parent = parents[node]
	}
	switch parent := parent.(type) {
	case *ast.Field:
		return true
	case *ast.SelectorExpr:
		return parent.X == node
	case *ast.AssignStmt:
		for i, lhs := range parent.Lhs {
			if lhs == node {
				return true
			}
			if i < len(parent.Rhs) && unwrapParen(parent.Rhs[i]) == identifier {
				_, ok := lhs.(*ast.Ident)
				return ok
			}
		}
	case *ast.ValueSpec:
		for _, name := range parent.Names {
			if name == identifier {
				return true
			}
		}
		for i, value := range parent.Values {
			if unwrapParen(value) == identifier {
				return i < len(parent.Names)
			}
		}
	}
	return false
}

func unwrapParen(expression ast.Expr) ast.Expr {
	for {
		parenthesized, ok := expression.(*ast.ParenExpr)
		if !ok {
			return expression
		}
		expression = parenthesized.X
	}
}

func identifierName(expression ast.Expr) (string, bool) {
	expression = unwrapParen(expression)
	identifier, ok := expression.(*ast.Ident)
	if !ok {
		return "", false
	}
	return identifier.Name, true
}

func testingHandleTypeNames(file *ast.File, aliases map[string]string) map[string]bool {
	handles := map[string]bool{}
	changed := true
	for changed {
		changed = extendTestingHandleTypeNames(file, aliases, handles)
	}
	return handles
}

func extendTestingHandleTypeNames(file *ast.File, aliases map[string]string, handles map[string]bool) bool {
	changed := false
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.TYPE {
			continue
		}
		for _, specification := range general.Specs {
			typeSpec, ok := specification.(*ast.TypeSpec)
			if ok && !handles[typeSpec.Name.Name] && isTestingHandleType(typeSpec.Type, aliases, handles) {
				handles[typeSpec.Name.Name] = true
				changed = true
			}
		}
	}
	return changed
}

func isTestingHandleType(expression ast.Expr, aliases map[string]string, handles map[string]bool) bool {
	switch expression := expression.(type) {
	case *ast.StarExpr:
		return isTestingHandleType(expression.X, aliases, handles)
	case *ast.Ident:
		return handles[expression.Name]
	case *ast.SelectorExpr:
		qualifier, ok := expression.X.(*ast.Ident)
		if !ok || aliases[qualifier.Name] != "testing" {
			return false
		}
		switch expression.Sel.Name {
		case "T", "B", "F", "M":
			return true
		}
	case *ast.StructType:
		for _, field := range expression.Fields.List {
			if isTestingHandleType(field.Type, aliases, handles) {
				return true
			}
		}
	}
	return false
}

func isAlwaysExternalPackage(pkgPath string) bool {
	return pkgPath == "plugin" || pkgPath == "syscall" ||
		strings.HasPrefix(pkgPath, "golang.org/x/sys/") ||
		pkgPath == "net" || strings.HasPrefix(pkgPath, "net/")
}

// isSourceOnlyStandardPackage is the deliberately small set whose public
// operations cannot directly acquire process-external state. Unknown standard
// packages fail closed to package-wide unverifiability; additions require a
// source audit, not an API-name heuristic — and the whole set is keyed to the
// audited toolchain releases (toolchainaudit.go): the audit is a property of
// specific standard-library source, so an unlisted release keeps every
// package's fail-closed classification until its delta is walked.
func isSourceOnlyStandardPackage(audited bool, pkgPath string) bool {
	if !audited {
		return false
	}
	// The audited-pure set: packages that are bit-deterministic pure
	// computation for every consumer of this audit - the observability
	// tier and the maximal unverifiable-dependence
	// marker share it, so membership demands the strongest reading:
	// every ambient effect must enter via a flagged constructor or
	// global of an effect-bearing package, no testlog-invisible input
	// channel, and no machine-variant results. Deliberately excluded:
	// reflect (defeats static reachability - auditing it would unsound
	// the proof itself); flag (registration returns pointers whose
	// values change at Parse, a testlog-invisible covert input channel);
	// encoding/gob (Register mutates a package-global registry - the
	// same registration-shaped covert channel: a subject's decode
	// outcome can depend on a sibling's prior Register call);
	// math and math/cmplx (CPU-dispatched implementations vary results
	// across machines); sync
	// and sync/atomic (sync.Pool is runtime-backed and GC-coupled);
	// time, math/rand, hash/maphash (ambient clock and entropy); and
	// every I/O-acquiring package
	// (REQ-closure-observability-analysis).
	switch pkgPath {
	case "bufio", "bytes", "cmp",
		"container/heap", "container/list", "container/ring",
		"crypto/hmac", "crypto/md5", "crypto/sha1", "crypto/sha256", "crypto/sha512", "crypto/subtle",
		"encoding", "encoding/asn1", "encoding/base32", "encoding/base64", "encoding/binary", "encoding/csv",
		"encoding/hex", "encoding/json", "encoding/pem", "encoding/xml",
		"errors", "hash", "hash/adler32", "hash/crc32", "hash/crc64", "hash/fnv",
		"io", "io/fs", "iter", "maps", "math/bits",
		"path", "regexp", "regexp/syntax",
		"slices", "sort", "strconv", "strings", "text/scanner",
		"unicode", "unicode/utf16", "unicode/utf8":
		return true
	default:
		return false
	}
}

// auditedRuntimeTypeSymbol reports whether a reflect-package symbol is
// in the audited reflect set: reflect.Type values are runtime-canonical
// and immutable, and reflect.TypeOf is bit-deterministic pure
// computation over its operand's static type. reflect.DeepEqual is a
// structural comparator that invokes nothing - no method call, no
// Call/MethodByName dispatch; function values compare by nil-ness only
// - so it reads its operands and defeats no reachability.
// At the SSA tiers the bare-name match also admits methods named Type
// - notably the deterministic-pure (reflect.Value).Type; no other
// reflect declaration is named DeepEqual. Chained
// selectors off admitted results are separate callees with their own
// classifications at the declaration-RTA tier; this per-file scan
// never sees them either way. reflect dispatch still defeats static
// reachability everywhere else. Grows only by source audit
// (REQ-closure-shared-dynamic-state).
func auditedRuntimeTypeSymbol(audited bool, pkgPath, name string) bool {
	if !audited || pkgPath != "reflect" {
		return false
	}
	switch name {
	case "Type", "TypeOf", "DeepEqual":
		return true
	default:
		return false
	}
}

// auditedLinknameTargets is the audited linkname-target set: standard
// symbols whose pull-style linkname is a read-only trampoline, each
// audited at the source of its version-pinned importer
// (golang.org/x/sys/unix on linux) — runtime.getAuxv (a read-only
// accessor of the runtime's startup-captured auxiliary vector),
// runtime.vgetrandom (the kernel entropy read the Getrandom surface
// already classifies), and syscall.prlimit (a standard syscall the
// calling surface's own syscall classifications already carry). The
// trampoline adds no effect its file's remaining classifications do
// not price, so an audited-only linkname file drops exactly the
// OPAQUE-linkage effect and keeps every other effect it carries —
// REQ-closure-blindspot's "resolved" disposition applied at the
// tier-1 floor, per target and by source audit only.
var auditedLinknameTargets = map[string]bool{
	"runtime.getAuxv":    true,
	"runtime.vgetrandom": true,
	"syscall.prlimit":    true,
}

// auditedLinknamesOnly reports whether every //go:linkname and
// //go:linknamestd directive in the file is the two-argument pull form
// naming an audited target: any one-argument form (an export marker
// whose counterpart lives in assembly or another package), any
// unparsable directive, and any unaudited target keeps the
// opaque-linkage floor, fail-closed. The two spellings share one
// grammar and one policy (go1.27's std-sanctioned variant changes who
// may declare the link, not what it links); the directive name is
// matched as a whole field, never as a prefix — a prefix match would
// read "//go:linknamestd target" as a two-argument "//go:linkname"
// pull with local name "std", letting a one-argument export marker
// whose bare name collides with an audited target impersonate an
// audited pull, the fail-open direction.
func auditedLinknamesOnly(audited bool, text string) bool {
	rest := text
	for {
		i := strings.Index(rest, "//go:linkname")
		if i < 0 {
			return true
		}
		if !audited {
			// The audited targets are claims about runtime/syscall
			// source; an unlisted release keeps the opaque-linkage
			// floor for every directive-bearing file
			// (REQ-closure-observability-analysis's exact-version
			// keying clause).
			return false
		}
		line := rest[i:]
		if j := strings.IndexByte(line, '\n'); j >= 0 {
			rest = line[j:]
			line = line[:j]
		} else {
			rest = ""
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "//go:linkname" && fields[0] != "//go:linknamestd" {
			return false
		}
		if len(fields) != 3 || !auditedLinknameTargets[fields[2]] {
			return false
		}
	}
}

// auditedSyncSymbol reports whether a sync-package symbol is in the
// audited synchronization set: the mutex types and their lock
// operations, whose state cannot change dispatch and which acquire no
// process-external state. sync exports no top-level functions by these
// names, so the method names are unambiguous. Grows only by source
// audit (REQ-closure-shared-dynamic-state).
func auditedSyncSymbol(audited bool, pkgPath, name string) bool {
	if !audited || pkgPath != "sync" {
		return false
	}
	switch name {
	case "Mutex", "RWMutex", "Lock", "Unlock", "RLock", "RUnlock", "TryLock", "TryRLock":
		return true
	default:
		return false
	}
}

// auditedPoolSymbol reports whether a sync-package symbol is in the
// audited pooling set: the pool type and its Get and Put operations.
// This admission is UNCONDITIONAL — it concerns runtime-input
// observability alone: Get and Put touch only process memory fed by the
// analyzed program, so they introduce no external input channel
// whatever the execution schedule. Cross-subject state through pool
// contents (sibling subjects sharing a process) is a different hazard,
// priced by the shared-dynamic-state judgment, whose pooling discharge
// is gated on the caller's single-subject-process attestation
// (WithSingleSubjectExecution) — not here. The values passed and
// produced keep their own classifications. sync exports no top-level
// functions by these names, so the method names are unambiguous. Grows
// only by source audit (REQ-closure-shared-dynamic-state).
func auditedPoolSymbol(audited bool, pkgPath, name string) bool {
	if !audited || pkgPath != "sync" {
		return false
	}
	switch name {
	case "Pool", "Get", "Put":
		return true
	default:
		return false
	}
}

func packageHasClassifiedExternalAPI(pkgPath string) bool {
	switch pkgPath {
	case "fmt", "os", "syscall", "golang.org/x/sys/unix", "testing", "net", "net/http", "html/template", "text/template", "plugin":
		return true
	default:
		return false
	}
}

func trueReason(pkgPath string) string {
	return trueExternalEffect(pkgPath).reason
}

func trueExternalEffect(pkgPath string) externalEffect {
	switch {
	case pkgPath == "plugin":
		return externalEffect{kind: externalEffectPlugin, packagePath: pkgPath, reason: "reaches plugin"}
	case pkgPath == "net" || strings.HasPrefix(pkgPath, "net/"):
		return externalEffect{kind: externalEffectNetwork, packagePath: pkgPath, reason: "reaches " + pkgPath + " (network I/O)"}
	default:
		return externalEffect{kind: externalEffectNative, packagePath: pkgPath, reason: "reaches " + pkgPath + " (external system call)"}
	}
}

// pinnedEffectScan serves a version-pinned package's per-file effect-scan
// fold from the persistent memo, deriving and storing it on a miss
// (REQ-closure-effect-scan-memo). Only the per-file fold persists — it is
// a pure syntactic function of the key's pinned inputs. The package-level
// facts (assembly, system objects, cgo linkage metadata) are functions of
// the live listing's build configuration, which the key does not carry, so
// every pass recomputes them from the listing in hand — zero file reads —
// and folds the served scans in. Both folds order and dedup exactly as the
// inline loop's global fold: effect dedup is first-occurrence-wins, and
// the preferred fold is a total order (opaqueness, then the
// lexicographically smaller reason), so per-package folding then
// cross-package folding equals the flat fold. A mutable-local package
// returns ok=false and takes the read path: the classification is
// directory-based — resolved source outside the module cache, the same
// rule the closure contribution pin applies — and the version leg
// additionally excludes modules reporting no version at all (the main
// and workspace modules, which pinnedPackage's Main leg also excludes),
// whose pin would carry no signal. The caller guarantees
// pkg.Module != nil.
func (h *Hasher) pinnedEffectScan(pkg listPkg) (maximalEffectScan, bool, error) {
	if pkg.Module.Version == "" || !h.pinnedPackage(&pkg) || pkg.Module.Dir == "" {
		return maximalEffectScan{}, false, nil
	}
	pin := h.modulePin(pkg.Module)
	key := effectScanKey(pin, pkg.ImportPath, pkg.GoFiles, pkg.CgoFiles)
	composite := maximalPackageExternalEffects(&pkg)
	// A backed scan's preferred is ignored by the package selection
	// (the union argmax re-derives it); only an effect-less scan's
	// import fallback folds, lexicographic least.
	fold := func(scan maximalEffectScan) {
		for _, effect := range scan.effects {
			composite.add(effect)
		}
		for _, candidate := range scan.importCandidates {
			composite.importCandidates = appendExternalEffect(composite.importCandidates, candidate)
		}
		if len(scan.effects) == 0 && len(scan.importCandidates) == 0 && scan.preferred != "" && (composite.preferred == "" || scan.preferred < composite.preferred) {
			composite.preferred = scan.preferred
		}
	}
	deriveComposite := func() {
		if selected := preferredEffectReason(append(append([]externalEffect(nil), composite.effects...), composite.importCandidates...)); selected != "" {
			composite.preferred = selected
		}
	}
	if stored, ok := loadEffectScan(effectScanDirName, h.effectScanScope(), key); ok {
		fold(stored)
		deriveComposite()
		return composite, true, nil
	}
	var fileFold maximalEffectScan
	files := append(append([]string(nil), pkg.GoFiles...), pkg.CgoFiles...)
	for _, name := range files {
		if err := h.contextErr(); err != nil {
			return maximalEffectScan{}, false, err
		}
		scan, err := h.maximalFileEffectsCached(filepath.Join(pkg.Dir, name))
		if err != nil {
			return maximalEffectScan{}, false, err
		}
		for _, effect := range scan.effects {
			fileFold.add(effect)
		}
		for _, candidate := range scan.importCandidates {
			fileFold.importCandidates = appendExternalEffect(fileFold.importCandidates, candidate)
		}
		if len(scan.effects) == 0 && len(scan.importCandidates) == 0 && scan.preferred != "" && (fileFold.preferred == "" || scan.preferred < fileFold.preferred) {
			fileFold.preferred = scan.preferred
		}
	}
	if selected := preferredEffectReason(append(append([]externalEffect(nil), fileFold.effects...), fileFold.importCandidates...)); selected != "" {
		fileFold.preferred = selected
	}
	storeEffectScan(effectScanDirName, h.effectScanScope(), key, fileFold)
	fold(fileFold)
	deriveComposite()
	return composite, true, nil
}

// userTestMainDecl returns the file's user TestMain declaration - a
// top-level func TestMain with exactly one parameter of syntactic type
// *testing.M under the file's own testing import alias - or nil. The
// syntactic shape is the harness contract: the toolchain only calls a
// TestMain matching it.
func userTestMainDecl(file *ast.File, aliases map[string]string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Name == nil || fd.Name.Name != "TestMain" || fd.Type == nil || fd.Type.Params == nil {
			continue
		}
		if len(fd.Type.Params.List) != 1 || len(fd.Type.Params.List[0].Names) > 1 {
			continue
		}
		star, ok := fd.Type.Params.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		// Both harness shapes: *testing.M under the file's own import
		// alias, and bare *M under a dot-imported testing.
		switch x := star.X.(type) {
		case *ast.SelectorExpr:
			pkgIdent, ok := x.X.(*ast.Ident)
			if !ok || x.Sel == nil || x.Sel.Name != "M" || aliases[pkgIdent.Name] != "testing" {
				continue
			}
		case *ast.Ident:
			if x.Name != "M" || aliases["."] != "testing" {
				continue
			}
		default:
			continue
		}
		return fd
	}
	return nil
}
