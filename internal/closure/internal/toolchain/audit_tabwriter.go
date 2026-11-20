package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/auditset"
)

var allowedTabwriterImports = map[string]bool{
	"fmt":          true,
	"io":           true,
	"unicode/utf8": true,
}

var tabwriterReservedIdents = map[string]bool{
	"nil": true, "true": true, "false": true,
	"byte": true, "int": true, "uint": true, "bool": true, "string": true, "error": true,
	"len": true, "cap": true, "make": true, "new": true, "append": true, "copy": true,
	"panic": true, "recover": true, "print": true, "println": true,
	"fmt": true, "io": true, "utf8": true,
}

var pureTabwriterScalarTypes = map[string]bool{
	"bool": true, "byte": true, "rune": true, "string": true,
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
}

// VerifyTabwriterPackageAST verifies the structural AST contract for
// standard-library package text/tabwriter.
func VerifyTabwriterPackageAST(files []*ast.File) error {
	if len(files) == 0 {
		return fmt.Errorf("text/tabwriter: no AST files")
	}
	if err := verifyClosedPackageImports("text/tabwriter", files, allowedTabwriterImports); err != nil {
		return err
	}
	idx, err := indexPackageAST("text/tabwriter", files, tabwriterReservedIdents, allowedTabwriterImports)
	if err != nil {
		return err
	}
	if idx.hasInitFunc {
		return fmt.Errorf("text/tabwriter: unexpected init function")
	}
	if len(idx.bodylessFuncs) > 0 {
		return fmt.Errorf("text/tabwriter: unexpected bodyless function declaration")
	}
	if len(idx.dupTopFuncs) > 0 || idx.anyDupTypeMethod {
		return fmt.Errorf("text/tabwriter: duplicate function or method declaration")
	}
	if err := idx.VerifyBlankVarInitsPure("text/tabwriter"); err != nil {
		return err
	}
	if err := verifyReadOnlyByteSlicePkgVars("text/tabwriter", idx, files); err != nil {
		return err
	}

	verifiedLocalStructs := map[string]bool{}
	var isPureTabwriterFieldType func(expr ast.Expr, depth int) bool
	isPureTabwriterFieldType = func(expr ast.Expr, depth int) bool {
		if depth > 4 || expr == nil {
			return false
		}
		switch t := unwrapParens(expr).(type) {
		case *ast.Ident:
			if pureTabwriterScalarTypes[t.Name] {
				return true
			}
			if t.Name == "Writer" || ast.IsExported(t.Name) {
				return false
			}
			if verifiedLocalStructs[t.Name] {
				return true
			}
			sp := idx.uniqueTypeSpec(t.Name)
			if sp == nil || sp.Assign.IsValid() || sp.TypeParams != nil {
				return false
			}
			st, ok := unwrapParens(sp.Type).(*ast.StructType)
			if !ok || st.Fields == nil {
				return false
			}
			verifiedLocalStructs[t.Name] = true
			for _, fld := range st.Fields.List {
				if len(fld.Names) == 0 || !isPureTabwriterFieldType(fld.Type, depth+1) {
					delete(verifiedLocalStructs, t.Name)
					return false
				}
			}
			return true
		case *ast.ArrayType:
			if t.Len != nil {
				lit, ok := unwrapParens(t.Len).(*ast.BasicLit)
				if !ok || lit.Kind != token.INT {
					return false
				}
			}
			return isPureTabwriterFieldType(t.Elt, depth+1)
		default:
			return false
		}
	}

	writerSpec := idx.uniqueTypeSpec("Writer")
	if writerSpec == nil || writerSpec.Assign.IsValid() || writerSpec.TypeParams != nil || idx.pkgDeclCounts["Writer"] != 1 {
		return fmt.Errorf("text/tabwriter: missing or invalid Writer struct declaration")
	}
	writerStruct, ok := unwrapParens(writerSpec.Type).(*ast.StructType)
	if !ok || writerStruct.Fields == nil {
		return fmt.Errorf("text/tabwriter: Writer is not a struct")
	}
	sawOutput := false
	seenFields := map[string]bool{}
	for _, fld := range writerStruct.Fields.List {
		if len(fld.Names) == 0 {
			return fmt.Errorf("text/tabwriter: embedded field on Writer forbidden")
		}
		for _, id := range fld.Names {
			if seenFields[id.Name] {
				return fmt.Errorf("text/tabwriter: duplicate field %s on Writer", id.Name)
			}
			seenFields[id.Name] = true
			if id.Name == "output" {
				if _, okIO := isSelectorBaseField(fld.Type, "io", "Writer"); !okIO {
					return fmt.Errorf("text/tabwriter: Writer.output must have type io.Writer")
				}
				sawOutput = true
				continue
			}
			if !isPureTabwriterFieldType(fld.Type, 0) {
				return fmt.Errorf("text/tabwriter: forbidden field %s type on Writer", id.Name)
			}
		}
	}
	if !sawOutput {
		return fmt.Errorf("text/tabwriter: Writer missing output io.Writer field")
	}

	nw, _, okNW := idx.VerifyFuncPreamble("", "NewWriter", false, tabwriterReservedIdents)
	initFn, _, okInit := idx.VerifyFuncPreamble("Writer", "Init", true, tabwriterReservedIdents)
	writeFn, _, okWrite := idx.VerifyFuncPreamble("Writer", "Write", true, tabwriterReservedIdents)
	flushFn, _, okFlush := idx.VerifyFuncPreamble("Writer", "Flush", true, tabwriterReservedIdents)
	if !okNW || !okInit || !okWrite || !okFlush {
		return fmt.Errorf("text/tabwriter: missing NewWriter, Init, Write, or Flush")
	}
	if !hasIOFirstParamAndWriterPtrResult(nw.Type, 6) || !hasIOFirstParamAndWriterPtrResult(initFn.Type, 6) {
		return fmt.Errorf("text/tabwriter: NewWriter or Init signature mismatch")
	}
	if writeFn.Type.Params == nil || writeFn.Type.Params.NumFields() != 1 || !isByteSliceType(writeFn.Type.Params.List[0].Type) ||
		writeFn.Type.Results == nil || writeFn.Type.Results.NumFields() != 2 || !firstResultIsInt(writeFn.Type.Results) || !funcReturnsErrorLast(writeFn.Type) {
		return fmt.Errorf("text/tabwriter: Write signature mismatch")
	}
	if (flushFn.Type.Params != nil && flushFn.Type.Params.NumFields() != 0) ||
		flushFn.Type.Results == nil || flushFn.Type.Results.NumFields() != 1 || !funcReturnsErrorLast(flushFn.Type) {
		return fmt.Errorf("text/tabwriter: Flush signature mismatch")
	}

	var dumpDeclIdent *ast.Ident
	if dumpFn := idx.typeMethods["Writer"]["dump"]; dumpFn != nil {
		dumpDeclIdent = dumpFn.Name
	}

	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			isDumpMethod := dumpDeclIdent != nil && fn.Name == dumpDeclIdent
			if err := verifyTabwriterFuncBody(fn, isDumpMethod, dumpDeclIdent); err != nil {
				return err
			}
		}
		var refErr error
		ast.Inspect(f, func(n ast.Node) bool {
			if refErr != nil || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.Ident:
				if x.Name == "dump" && x != dumpDeclIdent {
					refErr = fmt.Errorf("text/tabwriter: forbidden reference to dump")
					return false
				}
			case *ast.SelectorExpr:
				if x.Sel != nil && x.Sel.Name == "dump" {
					refErr = fmt.Errorf("text/tabwriter: forbidden selector reference .dump")
					return false
				}
			}
			return true
		})
		if refErr != nil {
			return refErr
		}
	}
	return nil
}

func hasIOFirstParamAndWriterPtrResult(ft *ast.FuncType, wantParams int) bool {
	if ft == nil || ft.Params == nil || ft.Params.NumFields() != wantParams || len(ft.Params.List) == 0 {
		return false
	}
	if _, okIO := isSelectorBaseField(ft.Params.List[0].Type, "io", "Writer"); !okIO {
		return false
	}
	if ft.Results == nil || ft.Results.NumFields() != 1 {
		return false
	}
	st, ok := unwrapParens(funcResultFieldTypeAt(ft.Results, 0)).(*ast.StarExpr)
	if !ok {
		return false
	}
	_, okW := isIdentNamed(st.X, "Writer")
	return okW
}

func verifyTabwriterFuncBody(fn *ast.FuncDecl, allowBuiltinPrint bool, _ *ast.Ident) error {
	if err := verifyNoConcurrency("text/tabwriter", fn); err != nil {
		return err
	}
	var bodyErr error
	WalkLexicalAST(fn.Body, funcInitialLexicalScope(fn),
		func(ident string) {
			if bodyErr == nil && (ident == "print" || ident == "println") && !allowBuiltinPrint {
				bodyErr = fmt.Errorf("text/tabwriter: forbidden builtin %s in %s", ident, fn.Name.Name)
			}
		},
		nil,
		func(base, sel string) {
			if bodyErr != nil {
				return
			}
			switch base {
			case "fmt":
				if !auditset.Symbol("fmt", sel) {
					bodyErr = fmt.Errorf("text/tabwriter: forbidden fmt.%s in %s", sel, fn.Name.Name)
				}
			case "io":
				if sel != "Writer" && sel != "ErrShortWrite" {
					bodyErr = fmt.Errorf("text/tabwriter: forbidden io.%s in %s", sel, fn.Name.Name)
				}
			case "utf8":
			default:
				bodyErr = fmt.Errorf("text/tabwriter: unapproved qualified reference %s.%s in %s", base, sel, fn.Name.Name)
			}
		},
	)
	return bodyErr
}

func reservedIdentsForImports(imports map[string]bool) map[string]bool {
	out := map[string]bool{
		"nil": true, "true": true, "false": true,
		"print": true, "println": true,
	}
	for imp := range imports {
		local := imp
		if slash := strings.LastIndexByte(imp, '/'); slash >= 0 {
			local = imp[slash+1:]
		}
		out[local] = true
	}
	return out
}

func verifyNoConcurrency(pkgPath string, fn *ast.FuncDecl) error {
	var bodyErr error
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if bodyErr != nil || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.GoStmt, *ast.SendStmt:
			bodyErr = fmt.Errorf("%s: forbidden concurrency in %s", pkgPath, fn.Name.Name)
			return false
		case *ast.UnaryExpr:
			if x.Op == token.ARROW {
				bodyErr = fmt.Errorf("%s: forbidden channel receive in %s", pkgPath, fn.Name.Name)
				return false
			}
		}
		return true
	})
	return bodyErr
}

func verifyNoConcurrencyOrBuiltinPrint(pkgPath string, fn *ast.FuncDecl) error {
	if err := verifyNoConcurrency(pkgPath, fn); err != nil {
		return err
	}
	var bodyErr error
	WalkLexicalAST(fn.Body, funcInitialLexicalScope(fn), func(ident string) {
		if bodyErr == nil && (ident == "print" || ident == "println") {
			bodyErr = fmt.Errorf("%s: forbidden builtin %s in %s", pkgPath, ident, fn.Name.Name)
		}
	}, nil, nil)
	return bodyErr
}

func paramIdentAt(fl *ast.FieldList, idx int) string {
	if fl == nil || idx < 0 {
		return ""
	}
	pos := 0
	for _, fld := range fl.List {
		if len(fld.Names) == 0 {
			if pos == idx {
				return ""
			}
			pos++
			continue
		}
		for _, id := range fld.Names {
			if pos == idx {
				if id.Name == "_" {
					return ""
				}
				return id.Name
			}
			pos++
		}
	}
	return ""
}

func isConstStringArrayOrSliceLit(expr ast.Expr) bool {
	cl, ok := unwrapParens(expr).(*ast.CompositeLit)
	if !ok {
		return false
	}
	at, ok := unwrapParens(cl.Type).(*ast.ArrayType)
	if !ok {
		return false
	}
	if _, okStr := isIdentNamed(at.Elt, "string"); !okStr {
		return false
	}
	if at.Len != nil {
		if _, okEll := unwrapParens(at.Len).(*ast.Ellipsis); !okEll {
			lit, okLit := unwrapParens(at.Len).(*ast.BasicLit)
			if !okLit || lit.Kind != token.INT {
				return false
			}
		}
	}
	for _, elt := range cl.Elts {
		val := elt
		if kv, okKV := unwrapParens(elt).(*ast.KeyValueExpr); okKV {
			if _, okID := unwrapParens(kv.Key).(*ast.Ident); !okID {
				litK, okLK := unwrapParens(kv.Key).(*ast.BasicLit)
				if !okLK || litK.Kind != token.INT {
					return false
				}
			}
			val = kv.Value
		}
		lit, okLit := unwrapParens(val).(*ast.BasicLit)
		if !okLit || lit.Kind != token.STRING {
			return false
		}
	}
	return true
}

func verifyClosedPackageImports(pkgPath string, files []*ast.File, allowed map[string]bool) error {
	for _, f := range files {
		if f == nil {
			return fmt.Errorf("%s: nil AST file", pkgPath)
		}
		for _, imp := range f.Imports {
			if imp.Path == nil {
				return fmt.Errorf("%s: empty import path", pkgPath)
			}
			importPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			if imp.Name != nil {
				return fmt.Errorf("%s: aliased import %q (%s) forbidden", pkgPath, importPath, imp.Name.Name)
			}
			if !allowed[importPath] {
				return fmt.Errorf("%s: unapproved import %q", pkgPath, importPath)
			}
		}
	}
	return nil
}

func funcInitialLexicalScope(fn *ast.FuncDecl) map[string]bool {
	scope := map[string]bool{}
	if fn == nil {
		return scope
	}
	if rName := recvVarName(fn); rName != "" {
		scope[rName] = true
	}
	if fn.Type != nil {
		for _, fl := range []*ast.FieldList{fn.Type.TypeParams, fn.Type.Params, fn.Type.Results} {
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
	}
	return scope
}

func isConstByteSliceInitExpr(expr ast.Expr) bool {
	switch e := unwrapParens(expr).(type) {
	case *ast.CompositeLit:
		if !isByteSliceType(e.Type) {
			return false
		}
		for _, elt := range e.Elts {
			lit, ok := unwrapParens(elt).(*ast.BasicLit)
			if !ok || (lit.Kind != token.CHAR && lit.Kind != token.INT) {
				return false
			}
		}
		return true
	case *ast.CallExpr:
		if e.Ellipsis.IsValid() || len(e.Args) != 1 || !isByteSliceType(e.Fun) {
			return false
		}
		lit, ok := unwrapParens(e.Args[0]).(*ast.BasicLit)
		return ok && lit.Kind == token.STRING
	default:
		return false
	}
}

func verifyReadOnlyByteSlicePkgVars(pkgPath string, idx *PackageASTIndex, files []*ast.File) error {
	if len(idx.pkgVarCounts) == 0 {
		return nil
	}
	varNames := map[string]bool{}
	for name, cnt := range idx.pkgVarCounts {
		if cnt != 1 || ast.IsExported(name) {
			return fmt.Errorf("%s: forbidden exported or duplicate package var %q", pkgPath, name)
		}
		initExpr, ok := idx.initPkgVars[name]
		if !ok || !isConstByteSliceInitExpr(initExpr) {
			return fmt.Errorf("%s: unapproved package var %q initializer", pkgPath, name)
		}
		varNames[name] = true
	}
	return verifyPkgVarsNeverMutatedOrAddressed(pkgPath, files, varNames, nil)
}

func verifyPkgVarsNeverMutatedOrAddressed(pkgPath string, files []*ast.File, varNames map[string]bool, allowInInit map[string]bool) error {
	if len(varNames) == 0 {
		return nil
	}
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			isInit := fn.Recv == nil && fn.Name.Name == "init"
			if err := checkFuncBodyDoesNotMutatePkgVars(pkgPath, fn, varNames, isInit, allowInInit); err != nil {
				return err
			}
		}
	}
	return nil
}

func baseUnshadowedVarIdent(expr ast.Expr, scope map[string]bool, varNames map[string]bool) string {
	cur := unwrapParens(expr)
	for {
		switch x := cur.(type) {
		case *ast.Ident:
			if !scope[x.Name] && varNames[x.Name] {
				return x.Name
			}
			return ""
		case *ast.IndexExpr:
			cur = unwrapParens(x.X)
		case *ast.SelectorExpr:
			cur = unwrapParens(x.X)
		case *ast.StarExpr:
			cur = unwrapParens(x.X)
		default:
			return ""
		}
	}
}

func checkFuncBodyDoesNotMutatePkgVars(pkgPath string, fn *ast.FuncDecl, varNames map[string]bool, isInit bool, allowInInit map[string]bool) error {
	var mutErr error
	checkMutTarget := func(target ast.Expr, scope map[string]bool, allowInitWrite bool) {
		if mutErr != nil || target == nil {
			return
		}
		if name := baseUnshadowedVarIdent(target, scope, varNames); name != "" {
			if allowInitWrite && isInit && allowInInit[name] {
				return
			}
			mutErr = fmt.Errorf("%s: forbidden mutation or address-of package var %s in %s", pkgPath, name, fn.Name.Name)
		}
	}

	var walkStmt func(n ast.Node, scope map[string]bool, inClosure bool)
	walkStmt = func(n ast.Node, scope map[string]bool, inClosure bool) {
		if mutErr != nil || n == nil {
			return
		}
		allowInitWrite := isInit && !inClosure
		switch x := n.(type) {
		case *ast.BlockStmt:
			sub := cloneBoolMap(scope)
			for _, st := range x.List {
				walkStmt(st, sub, inClosure)
			}
			return
		case *ast.IfStmt:
			sub := cloneBoolMap(scope)
			if x.Init != nil {
				walkStmt(x.Init, sub, inClosure)
			}
			walkStmt(x.Cond, sub, inClosure)
			walkStmt(x.Body, sub, inClosure)
			if x.Else != nil {
				walkStmt(x.Else, sub, inClosure)
			}
			return
		case *ast.ForStmt:
			sub := cloneBoolMap(scope)
			if x.Init != nil {
				walkStmt(x.Init, sub, inClosure)
			}
			if x.Cond != nil {
				walkStmt(x.Cond, sub, inClosure)
			}
			if x.Post != nil {
				walkStmt(x.Post, sub, inClosure)
			}
			walkStmt(x.Body, sub, inClosure)
			return
		case *ast.SwitchStmt:
			sub := cloneBoolMap(scope)
			if x.Init != nil {
				walkStmt(x.Init, sub, inClosure)
			}
			if x.Tag != nil {
				walkStmt(x.Tag, sub, inClosure)
			}
			if x.Body != nil {
				for _, st := range x.Body.List {
					walkStmt(st, cloneBoolMap(sub), inClosure)
				}
			}
			return
		case *ast.TypeSwitchStmt:
			sub := cloneBoolMap(scope)
			if x.Init != nil {
				walkStmt(x.Init, sub, inClosure)
			}
			if as, ok := x.Assign.(*ast.AssignStmt); ok && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
				walkStmt(as.Rhs[0], sub, inClosure)
				if id, okID := unwrapParens(as.Lhs[0]).(*ast.Ident); okID && id.Name != "_" && id.Name != "" {
					sub[id.Name] = true
				}
			} else if x.Assign != nil {
				walkStmt(x.Assign, sub, inClosure)
			}
			if x.Body != nil {
				for _, st := range x.Body.List {
					walkStmt(st, cloneBoolMap(sub), inClosure)
				}
			}
			return
		case *ast.CaseClause:
			for _, e := range x.List {
				walkStmt(e, scope, inClosure)
			}
			sub := cloneBoolMap(scope)
			for _, st := range x.Body {
				walkStmt(st, sub, inClosure)
			}
			return
		case *ast.CommClause:
			sub := cloneBoolMap(scope)
			if x.Comm != nil {
				walkStmt(x.Comm, sub, inClosure)
			}
			for _, st := range x.Body {
				walkStmt(st, sub, inClosure)
			}
			return
		case *ast.DeclStmt:
			if gd, ok := x.Decl.(*ast.GenDecl); ok {
				for _, sp := range gd.Specs {
					if vs, ok := sp.(*ast.ValueSpec); ok {
						if vs.Type != nil {
							walkStmt(vs.Type, scope, inClosure)
						}
						for _, val := range vs.Values {
							walkStmt(val, scope, inClosure)
						}
						for _, id := range vs.Names {
							if id.Name != "" && id.Name != "_" {
								scope[id.Name] = true
							}
						}
					}
				}
			}
			return
		case *ast.FuncLit:
			sub := expandScopeForFuncType(scope, x.Type)
			if x.Body != nil {
				walkStmt(x.Body, sub, true)
			}
			return
		case *ast.AssignStmt:
			for _, rhs := range x.Rhs {
				walkStmt(rhs, scope, inClosure)
			}
			for _, lhs := range x.Lhs {
				if x.Tok == token.DEFINE {
					if id, ok := unwrapParens(lhs).(*ast.Ident); ok {
						if id.Name != "_" && id.Name != "" {
							scope[id.Name] = true
						}
						continue
					}
				}
				checkMutTarget(lhs, scope, allowInitWrite)
				walkStmt(lhs, scope, inClosure)
			}
			return
		case *ast.IncDecStmt:
			checkMutTarget(x.X, scope, false)
		case *ast.RangeStmt:
			walkStmt(x.X, scope, inClosure)
			sub := cloneBoolMap(scope)
			if x.Tok == token.DEFINE {
				for _, e := range []ast.Expr{x.Key, x.Value} {
					if id, ok := unwrapParens(e).(*ast.Ident); ok && id.Name != "_" && id.Name != "" {
						sub[id.Name] = true
					}
				}
			} else {
				checkMutTarget(x.Key, sub, false)
				checkMutTarget(x.Value, sub, false)
			}
			walkStmt(x.Body, sub, inClosure)
			return
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				checkMutTarget(x.X, scope, false)
			}
		case *ast.CallExpr:
			if funID, ok := unwrapParens(x.Fun).(*ast.Ident); ok && !scope[funID.Name] && (funID.Name == "delete" || funID.Name == "clear") && len(x.Args) >= 1 {
				checkMutTarget(x.Args[0], scope, false)
			}
		}
		ast.Inspect(n, func(ch ast.Node) bool {
			if ch == nil || ch == n {
				return true
			}
			walkStmt(ch, scope, inClosure)
			return false
		})
	}
	walkStmt(fn.Body, funcInitialLexicalScope(fn), false)
	return mutErr
}

func cloneBoolMap(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		if v {
			out[k] = true
		}
	}
	return out
}

func expandScopeForFuncType(base map[string]bool, ft *ast.FuncType) map[string]bool {
	out := cloneBoolMap(base)
	if ft == nil {
		return out
	}
	for _, fl := range []*ast.FieldList{ft.TypeParams, ft.Params, ft.Results} {
		if fl == nil {
			continue
		}
		for _, fld := range fl.List {
			for _, id := range fld.Names {
				if id.Name != "" && id.Name != "_" {
					out[id.Name] = true
				}
			}
		}
	}
	return out
}
