package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"

	"github.com/greatliontech/gofresh/internal/auditset"
)

// VerifyNoForeignDirectives rejects block compiler directives, wasm/cgo
// directives, and any //go:linkname directive in text.
func VerifyNoForeignDirectives(pkgPath, text string) error {
	return scanVerifiedLinknameDirectives(text, func(line string, _ []string) error {
		return fmt.Errorf("%s: forbidden linkname directive %q", pkgPath, line)
	})
}

var (
	allowedGoTokenImports = map[string]bool{
		"cmp": true, "fmt": true, "iter": true, "slices": true,
		"strconv": true, "sync": true, "sync/atomic": true,
		"unicode": true, "unicode/utf8": true,
	}
	goTokenReservedIdents = reservedIdentsForImports(allowedGoTokenImports)

	allowedGoScannerImports = map[string]bool{
		"bytes": true, "fmt": true, "go/token": true, "io": true,
		"path/filepath": true, "sort": true, "strconv": true,
		"unicode": true, "unicode/utf8": true,
	}
	goScannerReservedIdents = reservedIdentsForImports(allowedGoScannerImports)

	allowedGoASTImports = map[string]bool{
		"bytes": true, "cmp": true, "fmt": true, "go/scanner": true, "go/token": true,
		"io": true, "iter": true, "os": true, "reflect": true, "slices": true,
		"strconv": true, "strings": true, "unicode": true, "unicode/utf8": true,
	}
	goASTReservedIdents = reservedIdentsForImports(allowedGoASTImports)

	allowedGoParserImports = map[string]bool{
		"bytes": true, "errors": true, "fmt": true, "go/ast": true,
		"go/build/constraint": true, "go/scanner": true, "go/token": true,
		"io": true, "io/fs": true, "os": true, "path/filepath": true, "strings": true,
	}
	goParserReservedIdents = reservedIdentsForImports(allowedGoParserImports)

	allowedAtomicTypes = map[string]bool{
		"Pointer": true, "Bool": true, "Int32": true, "Int64": true,
		"Uint32": true, "Uint64": true, "Uintptr": true,
	}
)

// VerifyGoTokenPackageAST verifies the structural AST contract for go/token.
func VerifyGoTokenPackageAST(files []*ast.File) error {
	if len(files) == 0 {
		return fmt.Errorf("go/token: no AST files")
	}
	if err := verifyClosedPackageImports("go/token", files, allowedGoTokenImports); err != nil {
		return err
	}
	idx, err := indexPackageAST("go/token", files, goTokenReservedIdents, allowedGoTokenImports)
	if err != nil {
		return err
	}
	if len(idx.bodylessFuncs) > 0 || len(idx.dupTopFuncs) > 0 || idx.anyDupTypeMethod {
		return fmt.Errorf("go/token: bodyless or duplicate function declaration")
	}

	varNames := map[string]bool{}
	allowInInit := map[string]bool{}
	for name, cnt := range idx.pkgVarCounts {
		if cnt != 1 || ast.IsExported(name) {
			return fmt.Errorf("go/token: forbidden exported or duplicate package var %q", name)
		}
		varNames[name] = true
		if name == "keywords" {
			vs, ok := idx.zeroInitPkgVars[name]
			if !ok || !isStringTokenMapType(vs.Type) {
				return fmt.Errorf("go/token: keywords must be zero-initialized map[string]Token")
			}
			allowInInit[name] = true
			continue
		}
		initExpr, ok := idx.initPkgVars[name]
		if !ok || !isConstStringArrayOrSliceLit(initExpr) {
			return fmt.Errorf("go/token: unapproved package var %q initializer", name)
		}
	}
	if err := verifyPkgVarsNeverMutatedOrAddressed("go/token", files, varNames, allowInInit); err != nil {
		return err
	}

	sawFileSet := false
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, sp := range gd.Specs {
				ts, ok := sp.(*ast.TypeSpec)
				if !ok || ts.Name == nil {
					continue
				}
				var tErr error
				WalkLexicalAST(ts.Type, map[string]bool{}, nil, nil, func(base, sel string) {
					if tErr != nil {
						return
					}
					switch base {
					case "sync":
						if sel != "Mutex" && sel != "RWMutex" {
							tErr = fmt.Errorf("go/token: forbidden sync.%s in type %s", sel, ts.Name.Name)
						}
					case "atomic":
						if !allowedAtomicTypes[sel] {
							tErr = fmt.Errorf("go/token: forbidden atomic.%s in type %s", sel, ts.Name.Name)
						}
					case "cmp", "fmt", "iter", "slices", "strconv", "unicode", "utf8":
					default:
						tErr = fmt.Errorf("go/token: unapproved qualified reference %s.%s in type %s", base, sel, ts.Name.Name)
					}
				})
				if tErr != nil {
					return tErr
				}
				if ts.Name.Name == "FileSet" {
					st, okST := ts.Type.(*ast.StructType)
					if !okST || ts.Assign.IsValid() || ts.TypeParams != nil || st.Fields == nil {
						return fmt.Errorf("go/token: FileSet must be a non-generic non-alias struct")
					}
					for _, fld := range st.Fields.List {
						if len(fld.Names) == 0 {
							return fmt.Errorf("go/token: FileSet must not embed fields")
						}
						for _, fn := range fld.Names {
							if ast.IsExported(fn.Name) {
								return fmt.Errorf("go/token: FileSet must not expose exported field %q", fn.Name)
							}
						}
					}
					sawFileSet = true
				}
			}
		}
	}
	if !sawFileSet {
		return fmt.Errorf("go/token: missing FileSet struct declaration")
	}

	initCount := 0
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			isInit := fn.Recv == nil && fn.Name.Name == "init"
			if isInit {
				initCount++
				if initCount > 1 {
					return fmt.Errorf("go/token: multiple init functions forbidden")
				}
			}
			if err := verifyNoConcurrencyOrBuiltinPrint("go/token", fn); err != nil {
				return err
			}
			var qErr error
			WalkLexicalAST(fn.Body, funcInitialLexicalScope(fn), nil, nil, func(base, sel string) {
				if qErr != nil {
					return
				}
				if isInit {
					qErr = fmt.Errorf("go/token: forbidden qualified reference %s.%s in init", base, sel)
					return
				}
				switch base {
				case "fmt":
					if !auditset.Symbol("fmt", sel) {
						qErr = fmt.Errorf("go/token: forbidden fmt.%s in %s", sel, fn.Name.Name)
					}
				case "sync":
					if sel != "Mutex" && sel != "RWMutex" {
						qErr = fmt.Errorf("go/token: forbidden sync.%s in %s", sel, fn.Name.Name)
					}
				case "atomic":
					if !allowedAtomicTypes[sel] {
						qErr = fmt.Errorf("go/token: forbidden atomic.%s in %s", sel, fn.Name.Name)
					}
				case "cmp", "iter", "slices", "strconv", "unicode", "utf8":
				default:
					qErr = fmt.Errorf("go/token: unapproved qualified reference %s.%s in %s", base, sel, fn.Name.Name)
				}
			})
			if qErr != nil {
				return qErr
			}
		}
	}
	return nil
}

// VerifyGoScannerPackageAST verifies the structural AST contract for go/scanner.
func VerifyGoScannerPackageAST(files []*ast.File) error {
	if len(files) == 0 {
		return fmt.Errorf("go/scanner: no AST files")
	}
	if err := verifyClosedPackageImports("go/scanner", files, allowedGoScannerImports); err != nil {
		return err
	}
	idx, err := indexPackageAST("go/scanner", files, goScannerReservedIdents, allowedGoScannerImports)
	if err != nil {
		return err
	}
	if idx.hasInitFunc || len(idx.bodylessFuncs) > 0 || len(idx.dupTopFuncs) > 0 || idx.anyDupTypeMethod {
		return fmt.Errorf("go/scanner: unexpected init, bodyless, or duplicate function declaration")
	}
	if err := verifyReadOnlyByteSlicePkgVars("go/scanner", idx, files); err != nil {
		return err
	}

	printErrFn, _, okPE := idx.VerifyFuncPreamble("", "PrintError", false, goScannerReservedIdents)
	if !okPE || printErrFn.Type.Params == nil || printErrFn.Type.Params.NumFields() != 2 || len(printErrFn.Type.Params.List) == 0 {
		return fmt.Errorf("go/scanner: missing or invalid PrintError signature")
	}
	if _, okIO := isSelectorBaseField(printErrFn.Type.Params.List[0].Type, "io", "Writer"); !okIO {
		return fmt.Errorf("go/scanner: PrintError first parameter must be io.Writer")
	}

	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if err := verifyNoConcurrencyOrBuiltinPrint("go/scanner", fn); err != nil {
				return err
			}
			isPrintError := fn == printErrFn
			var qErr error
			WalkLexicalAST(fn.Body, funcInitialLexicalScope(fn),
				func(ident string) {
					if qErr == nil && ident == "PrintError" {
						qErr = fmt.Errorf("go/scanner: forbidden internal call to PrintError in %s", fn.Name.Name)
					}
				},
				nil,
				func(base, sel string) {
					if qErr != nil {
						return
					}
					switch base {
					case "filepath":
						if !auditset.Symbol("path/filepath", sel) {
							qErr = fmt.Errorf("go/scanner: forbidden filepath.%s in %s", sel, fn.Name.Name)
						}
					case "fmt":
						if isPrintError && sel == "Fprintf" {
							return
						}
						if !auditset.Symbol("fmt", sel) {
							qErr = fmt.Errorf("go/scanner: forbidden fmt.%s in %s", sel, fn.Name.Name)
						}
					case "io":
						if !isPrintError || sel != "Writer" {
							qErr = fmt.Errorf("go/scanner: forbidden io.%s in %s", sel, fn.Name.Name)
						}
					case "token":
						if !auditset.Symbol("go/token", sel) {
							qErr = fmt.Errorf("go/scanner: forbidden token.%s in %s", sel, fn.Name.Name)
						}
					case "bytes", "sort", "strconv", "unicode", "utf8":
					default:
						qErr = fmt.Errorf("go/scanner: unapproved qualified reference %s.%s in %s", base, sel, fn.Name.Name)
					}
				},
			)
			if qErr != nil {
				return qErr
			}
		}
	}
	return nil
}

// VerifyGoASTPackageAST verifies the structural AST contract for go/ast.
func VerifyGoASTPackageAST(files []*ast.File) error {
	if len(files) == 0 {
		return fmt.Errorf("go/ast: no AST files")
	}
	if err := verifyClosedPackageImports("go/ast", files, allowedGoASTImports); err != nil {
		return err
	}
	idx, err := indexPackageAST("go/ast", files, goASTReservedIdents, allowedGoASTImports)
	if err != nil {
		return err
	}
	if idx.hasInitFunc || len(idx.bodylessFuncs) > 0 || len(idx.dupTopFuncs) > 0 || idx.anyDupTypeMethod {
		return fmt.Errorf("go/ast: unexpected init, bodyless, or duplicate function declaration")
	}

	varNames := map[string]bool{}
	for name, cnt := range idx.pkgVarCounts {
		if cnt != 1 || ast.IsExported(name) {
			return fmt.Errorf("go/ast: forbidden exported or duplicate package var %q", name)
		}
		initExpr, ok := idx.initPkgVars[name]
		if !ok || (!isConstByteSliceInitExpr(initExpr) && !isConstStringArrayOrSliceLit(initExpr) && !isReadOnlyCommentPtrLit(initExpr)) {
			return fmt.Errorf("go/ast: unapproved package var %q initializer", name)
		}
		varNames[name] = true
	}
	if err := verifyPkgVarsNeverMutatedOrAddressed("go/ast", files, varNames, nil); err != nil {
		return err
	}

	printFn, _, okPrint := idx.VerifyFuncPreamble("", "Print", false, goASTReservedIdents)
	fprintFn, _, okFprint := idx.VerifyFuncPreamble("", "Fprint", false, goASTReservedIdents)
	if !okPrint || !okFprint || fprintFn.Type.Params == nil || fprintFn.Type.Params.NumFields() != 4 || len(fprintFn.Type.Params.List) == 0 {
		return fmt.Errorf("go/ast: missing or invalid Print/Fprint declarations")
	}
	if _, okIO := isSelectorBaseField(fprintFn.Type.Params.List[0].Type, "io", "Writer"); !okIO {
		return fmt.Errorf("go/ast: Fprint first parameter must be io.Writer")
	}

	posEndCount := 0
	for _, f := range files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, sp := range d.Specs {
					ts, ok := sp.(*ast.TypeSpec)
					if !ok || ts.Name == nil {
						continue
					}
					var typeErr error
					WalkLexicalAST(ts.Type, nil, nil, nil, func(base, sel string) {
						if typeErr != nil {
							return
						}
						if base == "os" {
							typeErr = fmt.Errorf("go/ast: forbidden os.%s in type %s", sel, ts.Name.Name)
						}
						if base == "reflect" && ts.Name.Name != "FieldFilter" {
							typeErr = fmt.Errorf("go/ast: forbidden reflect.%s in type %s", sel, ts.Name.Name)
						}
						if base == "io" && ts.Name.Name != "printer" {
							typeErr = fmt.Errorf("go/ast: forbidden io.%s in type %s", sel, ts.Name.Name)
						}
					})
					if typeErr != nil {
						return typeErr
					}
				}
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				if err := verifyNoConcurrencyOrBuiltinPrint("go/ast", d); err != nil {
					return err
				}
				recvName := ""
				if d.Recv != nil && len(d.Recv.List) == 1 {
					recvName = recvTypeName(d.Recv.List[0].Type)
				}
				isPosOrEnd := recvName != "" && (d.Name.Name == "Pos" || d.Name.Name == "End")
				if isPosOrEnd {
					posEndCount++
					if (d.Type.Params != nil && d.Type.Params.NumFields() != 0) || d.Type.Results == nil || d.Type.Results.NumFields() != 1 {
						return fmt.Errorf("go/ast: invalid %s.%s signature", recvName, d.Name.Name)
					}
				}
				if err := verifyGoASTFuncBody(d, recvName, d == printFn, isPosOrEnd); err != nil {
					return err
				}
			}
		}
	}
	if posEndCount == 0 {
		return fmt.Errorf("go/ast: missing Pos/End node methods")
	}
	return nil
}

func verifyGoASTFuncBody(fn *ast.FuncDecl, recvName string, isTopPrint, isPosOrEnd bool) error {
	fnKey := fn.Name.Name
	if recvName != "" {
		fnKey = recvName + "." + fn.Name.Name
	}
	allowReflect := fnKey == "NotNilFilter" || fnKey == "Fprint" || fnKey == "fprint" || fnKey == "printer.print"
	allowIO := isTopPrint || fnKey == "Fprint" || fnKey == "fprint"
	allowFmtWriter := fnKey == "CommentMap.String" || fnKey == "Scope.String" ||
		fnKey == "printer.Write" || fnKey == "printer.printf" || fnKey == "Fprint" || fnKey == "fprint"

	var qErr error
	WalkLexicalAST(fn.Body, funcInitialLexicalScope(fn),
		func(ident string) {
			if qErr != nil {
				return
			}
			if ident == "Print" {
				qErr = fmt.Errorf("go/ast: forbidden internal reference to Print in %s", fnKey)
			}
			if isPosOrEnd && (ident == "Fprint" || ident == "fprint" || ident == "NotNilFilter") {
				qErr = fmt.Errorf("go/ast: forbidden printer reference %s in %s", ident, fnKey)
			}
		},
		nil,
		func(base, sel string) {
			if qErr != nil {
				return
			}
			if isPosOrEnd && (base == "os" || base == "fmt" || base == "io" || base == "reflect" || base == "scanner") {
				qErr = fmt.Errorf("go/ast: forbidden %s.%s in %s", base, sel, fnKey)
				return
			}
			switch base {
			case "os":
				if !isTopPrint || sel != "Stdout" {
					qErr = fmt.Errorf("go/ast: forbidden os.%s in %s", sel, fnKey)
				}
			case "reflect":
				if !allowReflect {
					qErr = fmt.Errorf("go/ast: forbidden reflect.%s in %s", sel, fnKey)
				}
			case "io":
				if !allowIO || sel != "Writer" {
					qErr = fmt.Errorf("go/ast: forbidden io.%s in %s", sel, fnKey)
				}
			case "fmt":
				if allowFmtWriter && (sel == "Fprintf" || sel == "Fprintln") {
					return
				}
				if !auditset.Symbol("fmt", sel) {
					qErr = fmt.Errorf("go/ast: forbidden fmt.%s in %s", sel, fnKey)
				}
			case "scanner":
				if !auditset.Symbol("go/scanner", sel) {
					qErr = fmt.Errorf("go/ast: forbidden scanner.%s in %s", sel, fnKey)
				}
			case "token":
				if !auditset.Symbol("go/token", sel) {
					qErr = fmt.Errorf("go/ast: forbidden token.%s in %s", sel, fnKey)
				}
			case "bytes", "cmp", "iter", "slices", "strconv", "strings", "unicode", "utf8":
			default:
				qErr = fmt.Errorf("go/ast: unapproved qualified reference %s.%s in %s", base, sel, fnKey)
			}
		},
	)
	return qErr
}


func isStringTokenMapType(expr ast.Expr) bool {
	mt, ok := unwrapParens(expr).(*ast.MapType)
	if !ok {
		return false
	}
	_, okK := isIdentNamed(mt.Key, "string")
	_, okV := isIdentNamed(mt.Value, "Token")
	return okK && okV
}

func isReadOnlyCommentPtrLit(expr ast.Expr) bool {
	ue, ok := unwrapParens(expr).(*ast.UnaryExpr)
	if !ok || ue.Op != token.AND {
		return false
	}
	cl, ok := unwrapParens(ue.X).(*ast.CompositeLit)
	if !ok || len(cl.Elts) != 2 {
		return false
	}
	if _, okC := isIdentNamed(cl.Type, "Comment"); !okC {
		return false
	}
	if _, okPos := isSelectorBaseField(cl.Elts[0], "token", "NoPos"); !okPos {
		return false
	}
	lit, okLit := unwrapParens(cl.Elts[1]).(*ast.BasicLit)
	return okLit && lit.Kind == token.STRING
}

