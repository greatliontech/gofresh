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
