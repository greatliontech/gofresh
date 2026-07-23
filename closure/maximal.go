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
		unverifiable, reason, unrefinable, err := h.maximalUnverifiable(pkgPath)
		if err != nil {
			return nil, nil, err
		}
		for _, subject := range byPackage[pkgPath] {
			results[subject] = Closure{
				Hash:         maximalSubjectHash(hash, subject),
				Unverifiable: unverifiable,
				Reason:       reason,
				Unrefinable:  unrefinable,
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
func (h *Hasher) maximalUnverifiable(pkgPath string) (bool, string, bool, error) {
	effects, selected, unrefinable, err := h.maximalExternalEffects(pkgPath)
	return len(effects) != 0, selected, unrefinable, err
}

// maximalEffectsResult memoizes one package's complete external-effect scan
// within a Hasher: the scan depends only on the package's listed sources, so
// every subject sharing the package shares one scan.
type maximalEffectsResult struct {
	effects     []externalEffect
	selected    string
	unrefinable bool
}

// maximalExternalEffects returns the package's complete external-effect scan.
// The returned effects slice aliases the Hasher's memo — callers must treat it
// as read-only.
func (h *Hasher) maximalExternalEffects(pkgPath string) ([]externalEffect, string, bool, error) {
	if cached, ok := h.maximalEffects[pkgPath]; ok {
		return cached.effects, cached.selected, cached.unrefinable, nil
	}
	pkgs, err := h.list(pkgPath)
	if err != nil {
		return nil, "", false, err
	}
	var effects []externalEffect
	var selected string
	unrefinable := false
	record := func(scan maximalEffectScan) {
		for _, effect := range scan.effects {
			effects = appendExternalEffect(effects, effect)
		}
		reason := scan.preferred
		if reason == "" {
			return
		}
		unrefinable = unrefinable || maximalReasonUnrefinable(reason)
		if selected == "" || preferMaximalReason(reason, selected) {
			selected = reason
		}
	}
	testingEffects, err := h.maximalTestingTypeEffects(pkgPath)
	if err != nil {
		return nil, "", false, err
	}
	record(testingEffects)
	for _, pkg := range pkgs {
		if err := h.contextErr(); err != nil {
			return nil, "", false, err
		}
		if pkg.Standard || pkg.Module == nil || pkg.isGeneratedTestMainFor(pkgPath) {
			continue
		}
		record(maximalPackageExternalEffects(&pkg))
		files := append(append([]string(nil), pkg.GoFiles...), pkg.CgoFiles...)
		for _, name := range files {
			if err := h.contextErr(); err != nil {
				return nil, "", false, err
			}
			scan, err := h.maximalFileEffectsCached(filepath.Join(pkg.Dir, name))
			if err != nil {
				return nil, "", false, err
			}
			record(scan)
		}
	}
	h.maximalEffects[pkgPath] = maximalEffectsResult{effects: effects, selected: selected, unrefinable: unrefinable}
	return effects, selected, unrefinable, nil
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

func (h *Hasher) maximalTestingTypeReason(pkgPath string) (string, error) {
	scan, err := h.maximalTestingTypeEffects(pkgPath)
	return scan.preferred, err
}

// testingTypeOwnLoadHook observes the fallback private load for tests pinning
// that a shared view load is actually consumed instead.
var testingTypeOwnLoadHook func(pkgPath string)

func (h *Hasher) maximalTestingTypeEffects(pkgPath string) (maximalEffectScan, error) {
	if scan, ok := h.maximalTesting[pkgPath]; ok {
		return scan, nil
	}
	loaded := h.viewLoadVariants(pkgPath)
	if loaded == nil {
		if testingTypeOwnLoadHook != nil {
			testingTypeOwnLoadHook(pkgPath)
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

func maximalPackageExternalReason(pkg *listPkg) string {
	return maximalPackageExternalEffects(pkg).preferred
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

func maximalFileReason(filename string) (string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	if strings.Contains(string(content), "//go:wasmimport") {
		return "reaches go:wasmimport", nil
	}
	if strings.Contains(string(content), "//go:linkname") {
		return "reaches go:linkname (opaque linkage)", nil
	}
	file, err := parser.ParseFile(token.NewFileSet(), filename, content, parser.ImportsOnly)
	if err != nil {
		return "", fmt.Errorf("closure: parse %s: %w", filename, err)
	}
	aliases := make(map[string]string, len(file.Imports))
	potentialExternal := ""
	for _, spec := range file.Imports {
		pkgPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return "", fmt.Errorf("closure: parse import in %s: %w", filename, err)
		}
		alias := path.Base(pkgPath)
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		aliases[alias] = pkgPath
		if pkgPath == "testing" {
			if alias == "." {
				potentialExternal = pkgPath
			}
			continue
		}
		if isAlwaysExternalPackage(pkgPath) {
			return trueReason(pkgPath), nil
		}
		if alias == "." && packageHasClassifiedExternalAPI(pkgPath) && potentialExternal == "" {
			potentialExternal = pkgPath
		}
		if potentialExternal == "" && isStdImportPath(pkgPath) && !isSourceOnlyStandardPackage(pkgPath) {
			potentialExternal = pkgPath
		}
	}

	// Reparse with bodies only when imports include packages whose individual
	// calls distinguish external operations from ordinary deterministic APIs.
	file, err = parser.ParseFile(token.NewFileSet(), filename, content, 0)
	if err != nil {
		return "", fmt.Errorf("closure: parse %s: %w", filename, err)
	}
	var reason string
	ast.Inspect(file, func(node ast.Node) bool {
		if reason != "" {
			return false
		}
		if sel, ok := node.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if pkgPath := aliases[ident.Name]; pkgPath != "" {
					if classified := classBReason(pkgPath, sel.Sel.Name); classified != "" {
						reason = classified
						return false
					}
				}
			}
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if pkgPath := aliases[ident.Name]; pkgPath != "" {
			reason = classBReason(pkgPath, sel.Sel.Name)
		}
		return true
	})
	if reason == "" {
		reason = testingMethodReason(file, aliases)
	}
	if reason != "" {
		return reason, nil
	}
	if potentialExternal != "" {
		return "reaches " + potentialExternal + " (potential external dependence)", nil
	}
	return "", nil
}

func maximalFileEffects(filename string) (maximalEffectScan, error) {
	preferred, err := maximalFileReason(filename)
	if err != nil {
		return maximalEffectScan{}, err
	}
	scan := maximalEffectScan{preferred: preferred}
	content, err := os.ReadFile(filename)
	if err != nil {
		return maximalEffectScan{}, err
	}
	if strings.Contains(string(content), "//go:wasmimport") {
		effect := opaqueExternalEffect(externalEffectLinkage, "reaches go:wasmimport")
		effect.unrefinable = true
		scan.add(effect)
	}
	if strings.Contains(string(content), "//go:linkname") {
		scan.add(opaqueExternalEffect(externalEffectLinkage, "reaches go:linkname (opaque linkage)"))
	}
	file, err := parser.ParseFile(token.NewFileSet(), filename, content, 0)
	if err != nil {
		return maximalEffectScan{}, fmt.Errorf("closure: parse %s: %w", filename, err)
	}
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
		if pkgPath == "testing" {
			if alias == "." {
				scan.add(opaqueExternalEffect(externalEffectUnauditedStandard, "reaches testing (potential external dependence)"))
			}
			continue
		}
		if alias == "." || alias == "_" {
			if isAlwaysExternalPackage(pkgPath) {
				scan.add(trueExternalEffect(pkgPath))
			} else if packageHasClassifiedExternalAPI(pkgPath) || isStdImportPath(pkgPath) && !isSourceOnlyStandardPackage(pkgPath) {
				scan.add(opaqueExternalEffect(externalEffectUnauditedStandard, "reaches "+pkgPath+" (potential external dependence)"))
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		sel, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		pkgPath := aliases[ident.Name]
		if effect, ok := classBEffect(pkgPath, sel.Sel.Name); ok {
			scan.add(effect)
		} else if pkgPath != "testing" && !classBPureStandard(pkgPath, sel.Sel.Name) && (isAlwaysExternalPackage(pkgPath) || isStdImportPath(pkgPath) && !isSourceOnlyStandardPackage(pkgPath)) {
			scan.add(symbolExternalEffect(externalEffectUnauditedStandard, pkgPath, sel.Sel.Name, "reaches unaudited standard operation "+pkgPath+"."+sel.Sel.Name))
		}
		return true
	})
	for _, effect := range testingMethodEffects(file, aliases) {
		scan.add(effect)
	}
	return scan, nil
}

func testingMethodReason(file *ast.File, aliases map[string]string) string {
	return testingMethodReasonWithHandleTypes(file, aliases, testingHandleTypeNames(file, aliases))
}

func testingMethodReasonWithHandleTypes(file *ast.File, aliases map[string]string, handleTypes map[string]bool) string {
	if file == nil {
		return ""
	}
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
		changed := true
		for changed {
			changed = false
			ast.Inspect(function.Body, func(node ast.Node) bool {
				if specification, ok := node.(*ast.ValueSpec); ok {
					for i, value := range specification.Values {
						name, ok := identifierName(value)
						if ok && receivers[name] && i < len(specification.Names) && !receivers[specification.Names[i].Name] {
							receivers[specification.Names[i].Name] = true
							changed = true
						}
					}
				}
				assignment, ok := node.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for i, rhs := range assignment.Rhs {
					name, ok := identifierName(rhs)
					if !ok || !receivers[name] || i >= len(assignment.Lhs) {
						continue
					}
					if lhs, ok := assignment.Lhs[i].(*ast.Ident); ok && !receivers[lhs.Name] {
						receivers[lhs.Name] = true
						changed = true
					}
				}
				return true
			})
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
		var reason string
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.AssignStmt:
				for i, rhs := range node.Rhs {
					name, ok := identifierName(rhs)
					if !ok || !receivers[name] || i >= len(node.Lhs) {
						continue
					}
					if _, ok := node.Lhs[i].(*ast.Ident); !ok {
						reason = "testing runtime value escapes analyzable receiver"
						return false
					}
				}
			case *ast.CallExpr:
				for _, argument := range node.Args {
					if name, ok := identifierName(argument); ok && receivers[name] {
						reason = "testing runtime value escapes analyzable receiver"
						return false
					}
				}
			case *ast.ReturnStmt:
				for _, result := range node.Results {
					if name, ok := identifierName(result); ok && receivers[name] {
						reason = "testing runtime value escapes analyzable receiver"
						return false
					}
				}
			case *ast.Ident:
				if receivers[node.Name] && !testingIdentifierUseSupported(node, parents) {
					reason = "testing runtime value escapes analyzable receiver"
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
			reason = classBReason("testing", selector.Sel.Name)
			return reason == ""
		})
		if reason != "" {
			return reason
		}
	}
	return ""
}

func testingMethodEffects(file *ast.File, aliases map[string]string) []externalEffect {
	if file == nil {
		return nil
	}
	handleTypes := testingHandleTypeNames(file, aliases)
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
		changed := true
		for changed {
			changed = false
			ast.Inspect(function.Body, func(node ast.Node) bool {
				if specification, ok := node.(*ast.ValueSpec); ok {
					for i, value := range specification.Values {
						name, ok := identifierName(value)
						if ok && receivers[name] && i < len(specification.Names) && !receivers[specification.Names[i].Name] {
							receivers[specification.Names[i].Name] = true
							changed = true
						}
					}
				}
				assignment, ok := node.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for i, rhs := range assignment.Rhs {
					name, ok := identifierName(rhs)
					if !ok || !receivers[name] || i >= len(assignment.Lhs) {
						continue
					}
					if lhs, ok := assignment.Lhs[i].(*ast.Ident); ok && !receivers[lhs.Name] {
						receivers[lhs.Name] = true
						changed = true
					}
				}
				return true
			})
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
	}
	return effects
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
	// tier, the refinement tier, and the maximal unverifiable-dependence
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
	// across machines - the refinement tier pins the rejection); sync
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
