package toolchain

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"slices"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/auditset"
)

var mathReservedIdents = map[string]bool{
	"nil": true, "true": true, "false": true,
	"bool": true, "float32": true, "float64": true,
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true, "uintptr": true,
	"len": true, "panic": true,
}

var mathScalarTypeNames = map[string]bool{
	"bool": true, "float32": true, "float64": true,
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true, "uintptr": true,
}

var mathNumericTypeNames = map[string]bool{
	"float32": true, "float64": true,
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true, "uintptr": true,
}

var mathForbiddenAsmOps = map[string]bool{
	"SYSCALL": true, "SYSENTER": true, "INT": true, "INTO": true,
	"SVC": true, "SWI": true, "HVC": true, "SMC": true,
	"ECALL": true, "EBREAK": true, "SC": true, "SCV": true,
	"RDTSC": true, "RDTSCP": true, "RDTIME": true, "RDTIMED": true, "RDTIMEW": true, "RDTIMEH": true,
	"RDRAND": true, "RDSEED": true,
	"STOSB": true, "STOSW": true, "STOSL": true, "STOSD": true, "STOSQ": true,
	"INB": true, "INW": true, "INL": true, "INSB": true, "INSW": true, "INSL": true,
	"OUTB": true, "OUTW": true, "OUTL": true, "OUTSB": true, "OUTSW": true, "OUTSL": true,
}

var mathCPUQueryAsmOps = map[string]bool{
	"CPUID": true, "XGETBV": true, "STFLE": true, "MRS": true, "CPUCFG": true,
	"BYTE": true, "WORD": true, "LONG": true, "QUAD": true,
}

// verifyMathPackage mechanically verifies the selected Go and assembly files of
// standard-library package math without GOARCH/GOOS allowlists:
//  1. Verifies whole-package directive, import, global-immutability, unsafe
//     scalar-bitcast, and assembly memory-safety invariants so Tier-1
//     auditset.MathPureFuncs() and auditset.MathConstants() are provably free
//     of runtime internal/cpu queries and mutable shared state.
//  2. Computes the transitive Go + Plan 9 .s call/symbol graph after pruning
//     compile-time boolean constant branches (such as `const haveArch* = ...`)
//     and returns the sorted exported math function names (excluding compiler-
//     intrinsic FMA) that are transitively free of internal/cpu features and
//     writable assembly globals on the selected target.
func verifyMathPackage(ctx context.Context, files []*ast.File, goSrcs []string, asmSources map[string]string, selectedHeaders map[string]bool) ([]string, error) {
	if len(files) == 0 || len(files) != len(goSrcs) {
		return nil, fmt.Errorf("math: invalid file/source slices (%d files, %d srcs)", len(files), len(goSrcs))
	}

	idx, err := indexPackageAST("math", files, mathReservedIdents, nil)
	if err != nil {
		return nil, err
	}
	if idx.hasInitFunc {
		return nil, fmt.Errorf("math: unexpected init function")
	}
	if idx.hasMethods {
		return nil, fmt.Errorf("math: unexpected method declarations")
	}
	if len(idx.dupTopFuncs) > 0 {
		return nil, fmt.Errorf("math: duplicate top-level function declarations")
	}
	if len(idx.typeSpecs) > 0 {
		return nil, fmt.Errorf("math: unexpected type declarations")
	}
	if err := idx.verifyBlankVarInitsPure("math"); err != nil {
		return nil, err
	}

	anyLinknameLocals := map[string]bool{}
	for _, src := range goSrcs {
		err := scanVerifiedLinknameDirectives(src, func(line string, fields []string) error {
			if len(fields) != 2 {
				return fmt.Errorf("math: unapproved two-argument linkname %q", line)
			}
			localSym := fields[1]
			fn := idx.topFuncs[localSym]
			if fn == nil || fn.Body == nil {
				return fmt.Errorf("math: single-argument linkname %q must target a body-bearing Go function", line)
			}
			anyLinknameLocals[localSym] = true
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	fileImports := make(map[*ast.File]map[string]string, len(files))
	declaredConsts := map[string]bool{}
	for _, f := range files {
		impMap := map[string]string{}
		for _, imp := range f.Imports {
			if imp.Path == nil {
				return nil, fmt.Errorf("math: empty import path")
			}
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return nil, err
			}
			if imp.Name != nil && (imp.Name.Name == "." || imp.Name.Name == "_" || imp.Name.Name == "") {
				return nil, fmt.Errorf("math: forbidden dot or blank import of %q", p)
			}
			if p != "unsafe" && p != "math/bits" && p != "internal/cpu" {
				return nil, fmt.Errorf("math: unapproved import %q", p)
			}
			alias := p
			if slash := strings.LastIndexByte(p, '/'); slash >= 0 {
				alias = p[slash+1:]
			}
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			if _, dup := impMap[alias]; dup {
				return nil, fmt.Errorf("math: duplicate import alias %q", alias)
			}
			impMap[alias] = p
		}
		fileImports[f] = impMap

		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, id := range vs.Names {
					if id.Name != "" && id.Name != "_" {
						declaredConsts[id.Name] = true
					}
				}
			}
		}
	}

	for _, reqConst := range auditset.MathConstants() {
		if !declaredConsts[reqConst] {
			return nil, fmt.Errorf("math: missing required exported constant %s", reqConst)
		}
	}

	pureGoTables := map[string]bool{}
	cpuGoVars := map[string]bool{}
	for vName, sp := range idx.pkgVarSpecs {
		if ast.IsExported(vName) || idx.pkgVarCounts[vName] != 1 || idx.pkgDeclCounts[vName] != 1 {
			return nil, fmt.Errorf("math: invalid or exported package-level var %s", vName)
		}
		initExpr, hasInit := idx.initPkgVars[vName]
		if !hasInit || initExpr == nil {
			return nil, fmt.Errorf("math: uninitialized package-level var %s", vName)
		}
		vFile := idx.initPkgVarFile[vName]
		if sp.Type != nil && !isMathFixedNumericArrayType(sp.Type, declaredConsts) {
			if _, isBool := isIdentNamed(sp.Type, "bool"); !isBool {
				return nil, fmt.Errorf("math: unsupported explicit type on var %s", vName)
			}
		}
		if isMathPureNumericArrayLit(initExpr, declaredConsts) {
			pureGoTables[vName] = true
			continue
		}
		if isMathCPUBoolExpr(initExpr, fileImports[vFile]) {
			cpuGoVars[vName] = true
			continue
		}
		return nil, fmt.Errorf("math: unsupported package-level var %s initializer", vName)
	}

	asmGraph, err := verifyAndIndexMathAssembly(ctx, asmSources, selectedHeaders, idx, pureGoTables, cpuGoVars, declaredConsts)
	if err != nil {
		return nil, err
	}

	kernel := newPackageInactiveKernel(idx, files, nil, anyLinknameLocals)

	edges := map[string]map[string]bool{}
	addEdge := func(from, to string) {
		if from == "" || to == "" || from == to {
			return
		}
		m := edges[from]
		if m == nil {
			m = map[string]bool{}
			edges[from] = m
		}
		m[to] = true
	}
	for from, tos := range asmGraph.edges {
		for to := range tos {
			addEdge(from, to)
		}
	}

	tainted := map[string]bool{}
	for sym := range asmGraph.tainted {
		tainted[sym] = true
	}
	for vName := range cpuGoVars {
		tainted["math."+vName] = true
	}

	for fnName, fn := range idx.topFuncs {
		symKey := "math." + fnName
		if err := verifyMathFuncSignature(fnName, fn.Type); err != nil {
			return nil, err
		}
		if fn.Body == nil {
			if !asmGraph.texts[symKey] {
				tainted[symKey] = true
			}
			continue
		}
		f := idx.funcFile[fn]
		fImps := fileImports[f]
		if err := verifyMathFuncBodySafety(fnName, fn, fImps, pureGoTables, cpuGoVars); err != nil {
			return nil, err
		}

		pureParams := map[string]bool{}
		for _, p := range paramNamesFlat(fn.Type.Params) {
			if p != "" && p != "_" {
				pureParams[p] = true
			}
		}
		prunedList, _ := kernel.pruneBlockStmts(fn.Body.List, fn, pureParams, nil, nil)
		prunedBody := &ast.BlockStmt{List: prunedList}

		scope := map[string]bool{}
		for _, fl := range []*ast.FieldList{fn.Type.Params, fn.Type.Results} {
			if fl == nil {
				continue
			}
			for _, fld := range fl.List {
				for _, id := range fld.Names {
					if id.Name != "" && id.Name != "_" {
						scope[id.Name] = true
					}
				}
			}
		}

		var bodyErr error
		walkLexicalAST(prunedBody, scope,
			func(ident string) {
				if bodyErr != nil {
					return
				}
				if mathReservedIdents[ident] || declaredConsts[ident] || pureGoTables[ident] {
					return
				}
				if cpuGoVars[ident] {
					addEdge(symKey, "math."+ident)
					return
				}
				if _, isFn := idx.topFuncs[ident]; isFn {
					addEdge(symKey, "math."+ident)
					return
				}
				bodyErr = fmt.Errorf("math: unresolved free identifier %q in %s", ident, fnName)
			},
			nil,
			func(base, sel string) {
				if bodyErr != nil {
					return
				}
				switch fImps[base] {
				case "math/bits":
					if !ast.IsExported(sel) || !auditset.PurePackage("math/bits") {
						bodyErr = fmt.Errorf("math: unapproved math/bits.%s in %s", sel, fnName)
					}
				case "internal/cpu":
					tainted[symKey] = true
				case "unsafe":
					if sel != "Pointer" {
						bodyErr = fmt.Errorf("math: unapproved unsafe.%s in %s", sel, fnName)
					}
				default:
					bodyErr = fmt.Errorf("math: unapproved qualified selector %s.%s in %s", base, sel, fnName)
				}
			},
		)
		if bodyErr != nil {
			return nil, bodyErr
		}
	}

	// Propagate taint backward across all Go and assembly dependency edges.
	for {
		changed := false
		for from, tos := range edges {
			if tainted[from] {
				continue
			}
			for to := range tos {
				if tainted[to] {
					tainted[from] = true
					changed = true
					break
				}
			}
		}
		if !changed {
			break
		}
	}

	// Every Tier-1 function in auditset.MathPureFuncs() must exist and be untainted.
	for _, reqFn := range auditset.MathPureFuncs() {
		fn := idx.topFuncs[reqFn]
		if fn == nil || !ast.IsExported(reqFn) {
			return nil, fmt.Errorf("math: missing required Tier-1 function %s", reqFn)
		}
		if tainted["math."+reqFn] {
			return nil, fmt.Errorf("math: Tier-1 function %s tainted by CPU feature or mutable global", reqFn)
		}
	}

	var pureFuncs []string
	for fnName := range idx.topFuncs {
		if !ast.IsExported(fnName) || fnName == "FMA" {
			continue
		}
		if !tainted["math."+fnName] {
			pureFuncs = append(pureFuncs, fnName)
		}
	}
	slices.Sort(pureFuncs)
	return pureFuncs, nil
}

func verifyMathFuncSignature(fnName string, ft *ast.FuncType) error {
	if ft == nil || ft.TypeParams != nil {
		return fmt.Errorf("math: %s missing or generic signature", fnName)
	}
	for _, fl := range []*ast.FieldList{ft.Params, ft.Results} {
		if fl == nil {
			continue
		}
		for _, fld := range fl.List {
			if fld.Type == nil {
				return fmt.Errorf("math: %s variadic or untyped parameter", fnName)
			}
			id, ok := unwrapParens(fld.Type).(*ast.Ident)
			if !ok || !mathScalarTypeNames[id.Name] {
				return fmt.Errorf("math: %s non-scalar parameter/result type", fnName)
			}
		}
	}
	return nil
}

func isMathFixedNumericArrayType(expr ast.Expr, consts map[string]bool) bool {
	at, ok := unwrapParens(expr).(*ast.ArrayType)
	if !ok || at.Len == nil {
		return false
	}
	if _, isEllip := unwrapParens(at.Len).(*ast.Ellipsis); !isEllip && !isMathPureConstNumericExpr(at.Len, consts) {
		return false
	}
	eltID, okElt := unwrapParens(at.Elt).(*ast.Ident)
	return okElt && mathNumericTypeNames[eltID.Name]
}

func isMathPureNumericArrayLit(expr ast.Expr, consts map[string]bool) bool {
	cl, ok := unwrapParens(expr).(*ast.CompositeLit)
	if !ok || cl.Type == nil || !isMathFixedNumericArrayType(cl.Type, consts) {
		return false
	}
	for _, elt := range cl.Elts {
		v := elt
		if kv, isKV := unwrapParens(elt).(*ast.KeyValueExpr); isKV {
			if !isMathPureConstNumericExpr(kv.Key, consts) {
				return false
			}
			v = kv.Value
		}
		if !isMathPureConstNumericExpr(v, consts) {
			return false
		}
	}
	return true
}

func isMathPureConstNumericExpr(expr ast.Expr, consts map[string]bool) bool {
	switch x := unwrapParens(expr).(type) {
	case *ast.BasicLit:
		return x.Kind == token.INT || x.Kind == token.FLOAT
	case *ast.Ident:
		return consts[x.Name]
	case *ast.UnaryExpr:
		return (x.Op == token.ADD || x.Op == token.SUB || x.Op == token.XOR) && isMathPureConstNumericExpr(x.X, consts)
	case *ast.BinaryExpr:
		switch x.Op {
		case token.ADD, token.SUB, token.MUL, token.QUO, token.REM, token.AND, token.OR, token.XOR, token.AND_NOT, token.SHL, token.SHR:
			return isMathPureConstNumericExpr(x.X, consts) && isMathPureConstNumericExpr(x.Y, consts)
		}
	case *ast.CallExpr:
		if !x.Ellipsis.IsValid() && len(x.Args) == 1 {
			if cID, ok := unwrapParens(x.Fun).(*ast.Ident); ok && mathNumericTypeNames[cID.Name] {
				return isMathPureConstNumericExpr(x.Args[0], consts)
			}
		}
	}
	return false
}

func isMathCPUBoolExpr(expr ast.Expr, fImps map[string]string) bool {
	switch x := unwrapParens(expr).(type) {
	case *ast.UnaryExpr:
		return x.Op == token.NOT && isMathCPUBoolExpr(x.X, fImps)
	case *ast.BinaryExpr:
		if x.Op == token.LAND || x.Op == token.LOR {
			return isMathCPUBoolExpr(x.X, fImps) && isMathCPUBoolExpr(x.Y, fImps)
		}
	case *ast.SelectorExpr:
		inner, okIn := unwrapParens(x.X).(*ast.SelectorExpr)
		if !okIn || x.Sel == nil || inner.Sel == nil {
			return false
		}
		pkgID, okPkg := unwrapParens(inner.X).(*ast.Ident)
		return okPkg && fImps[pkgID.Name] == "internal/cpu"
	}
	return false
}
