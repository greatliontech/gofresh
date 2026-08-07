package closure

// Reference implementation of the per-file effect scan: the two-pass
// (read-twice, parse-three-times) shape the single-pass production scan
// replaced. The scan is a pure function of file bytes, so equality with
// this reference over any input is the refactor's correctness oracle
// (REQ-closure-blindspot's classification tables are shared, not copied).

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"strconv"
	"strings"
)

func referenceMaximalFileReason(filename string) (string, error) {
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
		reason = referenceTestingMethodReason(file, aliases)
	}
	if reason != "" {
		return reason, nil
	}
	if potentialExternal != "" {
		return "reaches " + potentialExternal + " (potential external dependence)", nil
	}
	return "", nil
}

func referenceMaximalFileEffects(filename string) (maximalEffectScan, error) {
	preferred, err := referenceMaximalFileReason(filename)
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
		} else if pkgPath != "testing" && !classBPureStandard(pkgPath, sel.Sel.Name) && !auditedSyncSymbol(pkgPath, sel.Sel.Name) && !auditedRuntimeTypeSymbol(pkgPath, sel.Sel.Name) && (isAlwaysExternalPackage(pkgPath) || isStdImportPath(pkgPath) && !isSourceOnlyStandardPackage(pkgPath)) {
			scan.add(symbolExternalEffect(externalEffectUnauditedStandard, pkgPath, sel.Sel.Name, "reaches unaudited standard operation "+pkgPath+"."+sel.Sel.Name))
		}
		return true
	})
	for _, effect := range referenceTestingMethodEffects(file, aliases) {
		scan.add(effect)
	}
	return scan, nil
}

// Frozen reason-walk twins the production scan collapsed onto the
// effects walk; the reference two-pass shape still consults them.
func referenceTestingMethodReason(file *ast.File, aliases map[string]string) string {
	return referenceTestingMethodReasonWithHandleTypes(file, aliases, testingHandleTypeNames(file, aliases))
}
func referenceTestingMethodReasonWithHandleTypes(file *ast.File, aliases map[string]string, handleTypes map[string]bool) string {
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

func referenceTestingMethodEffects(file *ast.File, aliases map[string]string) []externalEffect {
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
