// Package seams analyzes bracketed test seams (t.Cleanup and defer global
// save-and-restore), parallel testing.T dataflow reachability, and sequential
// versus non-sequential call-graph uses across a package's syntax.
package seams

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// ExportedSeamMarkHook is an optional callback invoked when an exported
// function is marked as exposing a bracketed mutating seam.
type ExportedSeamMarkHook func(p *packages.Package, fn syntaxutil.FuncKey, key string, at token.Pos)

// Result holds the package-level bracketed seam analysis summary.
type Result struct {
	Exempt         map[ast.Node]bool
	ExportedSeams  []syntaxutil.ExportedSeam
	NonSeqFuncUses []syntaxutil.FuncKey
	SeqFuncEdges   []syntaxutil.FuncDepEdge
	ParallelFuncs  []syntaxutil.FuncKey
	ParallelEdges  []syntaxutil.FuncDepEdge
}

// CallGraph summarizes sequential vs. non-sequential/parallel reachability
// across plain functions and closures in a package.
type CallGraph struct {
	DeclPlainFuncs map[*types.Func]*ast.FuncDecl
	Blocked        map[*types.Func]bool
	NonSeqLits     map[*ast.FuncLit]bool
	IntraEdges     map[*types.Func]map[*types.Func]bool
	NonSeqFuncUses []syntaxutil.FuncKey
	SeqFuncEdges   []syntaxutil.FuncDepEdge
	ParallelFuncs  []syntaxutil.FuncKey
	ParallelEdges  []syntaxutil.FuncDepEdge
}

func isParallelSelector(info *types.Info, sel *ast.SelectorExpr) bool {
	if sel == nil || sel.Sel == nil || sel.Sel.Name != "Parallel" {
		return false
	}
	if info == nil {
		return true
	}
	obj := info.Uses[sel.Sel]
	if obj == nil {
		return true
	}
	switch obj := obj.(type) {
	case *types.Func:
		return true
	case *types.Const, *types.TypeName, *types.PkgName:
		return false
	case *types.Var:
		if obj.Type() == nil {
			return true
		}
		basic, isBasic := types.Unalias(obj.Type()).Underlying().(*types.Basic)
		if isBasic && basic.Kind() != types.Invalid {
			return false
		}
		return true
	default:
		return true
	}
}

func testingSyncMethodName(info *types.Info, call *ast.CallExpr) string {
	if info == nil || call == nil || call.Ellipsis.IsValid() {
		return ""
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if selInfo, ok := info.Selections[sel]; !ok || selInfo.Kind() != types.MethodVal {
		return ""
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok || fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "testing" {
		return ""
	}
	return fn.Name()
}

func bodyHasSyncHazard(info *types.Info, body *ast.BlockStmt, checkGo bool) bool {
	if body == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		switch n := n.(type) {
		case *ast.GoStmt:
			if checkGo {
				found = true
				return false
			}
		case *ast.SelectorExpr:
			if isParallelSelector(info, n) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func bodyHasParallelSelector(info *types.Info, body *ast.BlockStmt) bool {
	return bodyHasSyncHazard(info, body, false)
}

func bodyHasGoOrParallel(info *types.Info, body *ast.BlockStmt) bool {
	return bodyHasSyncHazard(info, body, true)
}

func extractTargetVar(info *types.Info, expr ast.Expr) *types.Var {
	if info == nil || expr == nil {
		return nil
	}
	for expr != nil {
		switch e := expr.(type) {
		case *ast.ParenExpr:
			expr = e.X
		case *ast.StarExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		case *ast.IndexListExpr:
			expr = e.X
		case *ast.SliceExpr:
			expr = e.X
		case *ast.TypeAssertExpr:
			expr = e.X
		case *ast.UnaryExpr:
			if e.Op == token.ARROW {
				expr = e.X
			} else {
				return nil
			}
		case *ast.SelectorExpr:
			if v, ok := info.Uses[e.Sel].(*types.Var); ok && v != nil && !v.IsField() {
				return v
			}
			expr = e.X
		case *ast.Ident:
			if v, ok := syntaxutil.IdentDefOrUse(info, e).(*types.Var); ok && v != nil && !v.IsField() {
				return v
			}
			return nil
		default:
			return nil
		}
	}
	return nil
}

func sigParamIndexForArg(sig *types.Signature, argIdx int, isEllipsis bool) (int, bool) {
	if sig == nil || sig.Params() == nil || argIdx < 0 {
		return 0, false
	}
	nParams := sig.Params().Len()
	if nParams == 0 {
		return 0, false
	}
	if sig.Variadic() {
		last := nParams - 1
		if isEllipsis {
			if argIdx > last {
				return 0, false
			}
			return argIdx, true
		}
		if argIdx >= last {
			return last, true
		}
		return argIdx, true
	}
	if isEllipsis || argIdx >= nParams {
		return 0, false
	}
	return argIdx, true
}

func concreteTestingHandleKind(t types.Type) string {
	if t == nil {
		return ""
	}
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok || ptr == nil {
		return ""
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || named == nil || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "testing" {
		return ""
	}
	switch named.Obj().Name() {
	case "T", "B", "F":
		return named.Obj().Name()
	default:
		return ""
	}
}

func isGoTestRunnerName(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	if len(name) == len(prefix) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(name[len(prefix):])
	return !unicode.IsLower(r)
}

func collectStdTestingFreePaths(p *packages.Package) map[string]bool {
	stdPaths := map[string]bool{}
	if p == nil || len(p.Imports) == 0 {
		return stdPaths
	}
	importsTestingMemo := map[*packages.Package]bool{}
	var pkgImportsTesting func(*packages.Package) bool
	pkgImportsTesting = func(imp *packages.Package) bool {
		if imp == nil {
			return false
		}
		if v, ok := importsTestingMemo[imp]; ok {
			return v
		}
		importsTestingMemo[imp] = false
		for _, dep := range imp.Imports {
			if dep == nil {
				continue
			}
			if dep.PkgPath == "testing" || pkgImportsTesting(dep) {
				importsTestingMemo[imp] = true
				return true
			}
		}
		return false
	}
	visitedImp := map[*packages.Package]bool{}
	var collectStd func(map[string]*packages.Package)
	collectStd = func(m map[string]*packages.Package) {
		for _, imp := range m {
			if imp == nil || visitedImp[imp] {
				continue
			}
			visitedImp[imp] = true
			if imp.Module == nil && imp.PkgPath != "" && !pkgImportsTesting(imp) {
				stdPaths[imp.PkgPath] = true
			}
			if len(imp.Imports) > 0 {
				collectStd(imp.Imports)
			}
		}
	}
	collectStd(p.Imports)
	return stdPaths
}
