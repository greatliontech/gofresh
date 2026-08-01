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

func maximalReasonUnrefinable(reason string) bool {
	for _, marker := range []string{"external library", "system object", "go:wasmimport"} {
		if strings.Contains(reason, marker) {
			return true
		}
	}
	return false
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
	var selected string
	record := func(scan maximalEffectScan) {
		for _, effect := range scan.effects {
			effects = appendExternalEffect(effects, effect)
		}
		reason := scan.preferred
		if reason == "" {
			return
		}
		if selected == "" || preferMaximalReason(reason, selected) {
			selected = reason
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
	h.maximalEffects[pkgPath] = maximalEffectsResult{effects: effects, selected: selected}
	return effects, selected, nil
}

// maximalFileEffectsCached memoizes one file's effect scan within a Hasher: a
// file shared by several packages' closures is read and parsed once.
func (h *Hasher) maximalFileEffectsCached(path string) (maximalEffectScan, error) {
	if scan, ok := h.maximalFiles[path]; ok {
		return scan, nil
	}
	scan, err := maximalFileEffects(path)
	if err != nil {
		return maximalEffectScan{}, err
	}
	h.maximalFiles[path] = scan
	return scan, nil
}

func preferMaximalReason(candidate, current string) bool {
	candidateOpaque := maximalReasonUnrefinable(candidate)
	currentOpaque := maximalReasonUnrefinable(current)
	if candidateOpaque != currentOpaque {
		return candidateOpaque
	}
	return candidate < current
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
					if scan.preferred == "" || effect.reason < scan.preferred {
						scan.preferred = effect.reason
					}
				}
				return true
			})
		}
	}
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
		scan.preferred = effect.reason
	}
	if pkg != nil && len(pkg.SysoFiles) != 0 {
		effect := opaqueExternalEffect(externalEffectNative, "reaches non-standard system object")
		effect.unrefinable = true
		scan.add(effect)
		if scan.preferred == "" {
			scan.preferred = effect.reason
		}
	}
	if hasCgoCallbackBlindspot(pkg) {
		effect := opaqueExternalEffect(externalEffectNative, "reaches cgo or native source")
		scan.add(effect)
		if scan.preferred == "" {
			scan.preferred = effect.reason
		}
	}
	if pkg != nil && len(pkg.SFiles) != 0 {
		effect := opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly")
		scan.add(effect)
		if scan.preferred == "" {
			scan.preferred = effect.reason
		}
	}
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
func maximalFileEffects(filename string) (maximalEffectScan, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return maximalEffectScan{}, err
	}
	text := string(content)
	hasWasmImport := strings.Contains(text, "//go:wasmimport")
	hasLinkname := strings.Contains(text, "//go:linkname")
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
	// The preferred diagnostic's precedence over the same single walk:
	// directives, then the first always-external import, then the first
	// classified selector or call, then the testing-method scan, then the
	// potential-external import fallback.
	importReason := ""
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
		if isAlwaysExternalPackage(imp.pkgPath) && importReason == "" {
			importReason = trueReason(imp.pkgPath)
		}
		if imp.alias == "." && packageHasClassifiedExternalAPI(imp.pkgPath) && potentialExternal == "" {
			potentialExternal = imp.pkgPath
		}
		if potentialExternal == "" && isStdImportPath(imp.pkgPath) && !isSourceOnlyStandardPackage(imp.pkgPath) {
			potentialExternal = imp.pkgPath
		}
		if imp.alias == "." || imp.alias == "_" {
			if isAlwaysExternalPackage(imp.pkgPath) {
				scan.add(trueExternalEffect(imp.pkgPath))
			} else if packageHasClassifiedExternalAPI(imp.pkgPath) || isStdImportPath(imp.pkgPath) && !isSourceOnlyStandardPackage(imp.pkgPath) {
				scan.add(opaqueExternalEffect(externalEffectUnauditedStandard, "reaches "+imp.pkgPath+" (potential external dependence)"))
			}
		}
	}
	bodyReason := ""
	ast.Inspect(file, func(node ast.Node) bool {
		if sel, ok := node.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				pkgPath := aliases[ident.Name]
				if effect, ok := classBEffect(pkgPath, sel.Sel.Name); ok {
					scan.add(effect)
					if bodyReason == "" && pkgPath != "" {
						bodyReason = effect.reason
					}
				} else if pkgPath != "testing" && !classBPureStandard(pkgPath, sel.Sel.Name) && (isAlwaysExternalPackage(pkgPath) || isStdImportPath(pkgPath) && !isSourceOnlyStandardPackage(pkgPath)) {
					scan.add(symbolExternalEffect(externalEffectUnauditedStandard, pkgPath, sel.Sel.Name, "reaches unaudited standard operation "+pkgPath+"."+sel.Sel.Name))
				}
			}
		}
		return true
	})
	testingEffects, testingReason := testingMethodEffects(file, aliases)
	for _, effect := range testingEffects {
		scan.add(effect)
	}
	switch {
	case hasWasmImport:
		scan.preferred = "reaches go:wasmimport"
	case hasLinkname:
		scan.preferred = "reaches go:linkname (opaque linkage)"
	case importReason != "":
		scan.preferred = importReason
	case bodyReason != "":
		scan.preferred = bodyReason
	case testingReason != "":
		scan.preferred = testingReason
	case potentialExternal != "":
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
// source audit, not an API-name heuristic.
func isSourceOnlyStandardPackage(pkgPath string) bool {
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
		"encoding", "encoding/asn1", "encoding/base64", "encoding/binary", "encoding/csv",
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
	fold := func(scan maximalEffectScan) {
		for _, effect := range scan.effects {
			composite.add(effect)
		}
		if scan.preferred != "" && (composite.preferred == "" || preferMaximalReason(scan.preferred, composite.preferred)) {
			composite.preferred = scan.preferred
		}
	}
	if stored, ok := loadEffectScan(effectScanDirName, effectScanScope(), key); ok {
		fold(stored)
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
		if scan.preferred != "" && (fileFold.preferred == "" || preferMaximalReason(scan.preferred, fileFold.preferred)) {
			fileFold.preferred = scan.preferred
		}
	}
	storeEffectScan(effectScanDirName, effectScanScope(), key, fileFold)
	fold(fileFold)
	return composite, true, nil
}
