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
	pkgs, err := h.list(pkgPath)
	if err != nil {
		return false, "", false, err
	}
	var selected string
	unrefinable := false
	record := func(reason string) {
		if reason == "" {
			return
		}
		unrefinable = unrefinable || maximalReasonUnrefinable(reason)
		if selected == "" || preferMaximalReason(reason, selected) {
			selected = reason
		}
	}
	testingReason, err := h.maximalTestingTypeReason(pkgPath)
	if err != nil {
		return false, "", false, err
	}
	record(testingReason)
	for _, pkg := range pkgs {
		if err := h.contextErr(); err != nil {
			return false, "", false, err
		}
		if pkg.Standard || pkg.Module == nil || pkg.isGeneratedTestMainFor(pkgPath) {
			continue
		}
		if reason := maximalPackageExternalReason(&pkg); reason != "" {
			record(reason)
		}
		files := append(append([]string(nil), pkg.GoFiles...), pkg.CgoFiles...)
		for _, name := range files {
			if err := h.contextErr(); err != nil {
				return false, "", false, err
			}
			reason, err := maximalFileReason(filepath.Join(pkg.Dir, name))
			if err != nil {
				return false, "", false, err
			}
			if reason != "" {
				record(reason)
			}
		}
	}
	return selected != "", selected, unrefinable, nil
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
	if reason, ok := h.maximalTesting[pkgPath]; ok {
		return reason, nil
	}
	loaded, err := packages.Load(&packages.Config{
		Context:    h.ctx,
		Mode:       packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedForTest,
		Tests:      true,
		Dir:        h.dir,
		BuildFlags: append([]string(nil), h.buildFlags...),
	}, pkgPath)
	if err != nil {
		return "", err
	}
	selected := ""
	for _, pkg := range loaded {
		if pkg.PkgPath != pkgPath && pkg.ForTest != pkgPath {
			continue
		}
		for _, packageErr := range pkg.Errors {
			return "", fmt.Errorf("closure: load %s: %s", pkgPath, packageErr)
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
				reason := classBReason("testing", object.Name())
				if reason != "" && (selected == "" || reason < selected) {
					selected = reason
				}
				return true
			})
		}
	}
	h.maximalTesting[pkgPath] = selected
	return selected, nil
}

func maximalPackageExternalReason(pkg *listPkg) string {
	if hasExternalCgoMeta(pkg) {
		return "reaches cgo external library"
	}
	if pkg != nil && len(pkg.SysoFiles) != 0 {
		return "reaches non-standard system object"
	}
	if hasCgoCallbackBlindspot(pkg) {
		return "reaches cgo or native source"
	}
	if pkg != nil && len(pkg.SFiles) != 0 {
		return "reaches non-standard assembly"
	}
	return ""
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
	switch pkgPath {
	case "bytes", "cmp", "encoding", "encoding/base64", "encoding/binary", "encoding/hex",
		"errors", "hash", "hash/adler32", "hash/crc32", "hash/crc64", "hash/fnv",
		"math/bits", "regexp", "regexp/syntax",
		"slices", "sort", "strconv", "strings",
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
	switch {
	case pkgPath == "plugin":
		return "reaches plugin"
	case pkgPath == "net" || strings.HasPrefix(pkgPath, "net/"):
		return "reaches " + pkgPath + " (network I/O)"
	default:
		return "reaches " + pkgPath + " (external system call)"
	}
}
