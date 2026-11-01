package closure

import (
	"fmt"
	"go/ast"
	"go/scanner"
	"go/token"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/auditset"
)

// parsedPkgIndex indexes package-level declarations, per-file imports, and
// method sets across a parsed standard-library package's AST files.
type parsedPkgIndex struct {
	fileImports      map[*ast.File]map[string]bool
	fileImportNames  map[*ast.File]map[string]bool
	funcFile         map[*ast.FuncDecl]*ast.File
	funcDeclsByName  map[string][]*ast.FuncDecl
	topFuncs         map[string]*ast.FuncDecl
	dupTopFuncs      map[string]bool
	typeMethods      map[string]map[string]*ast.FuncDecl
	dupTypeMethods   map[string]map[string]bool
	anyDupTypeMethod bool
	typeSpecs        map[string]*ast.TypeSpec
	typeSpecFile     map[*ast.TypeSpec]*ast.File
	typeSpecCounts   map[string]int
	pkgDeclCounts    map[string]int
	pkgValueCounts   map[string]int
	pkgVarSpecs      map[string]*ast.ValueSpec
	pkgVarFiles      map[string]*ast.File
	pkgVarCounts     map[string]int
	constPosInt      map[string]bool
	zeroInitPkgVars  map[string]*ast.ValueSpec
	zeroInitBoolVars map[string]bool
	initPkgVars      map[string]ast.Expr
	initPkgVarFile   map[string]*ast.File
	varDeclIdents    map[string]map[*ast.Ident]bool
	hasInitFunc      bool
	hasMethods       bool
	bodylessFuncs    []*ast.FuncDecl
}

func indexPackageAST(pkgName string, files []*ast.File, reserved map[string]bool, unaliasedImports map[string]bool) (*parsedPkgIndex, error) {
	idx := &parsedPkgIndex{
		fileImports:      make(map[*ast.File]map[string]bool, len(files)),
		fileImportNames:  make(map[*ast.File]map[string]bool, len(files)),
		funcFile:         map[*ast.FuncDecl]*ast.File{},
		funcDeclsByName:  map[string][]*ast.FuncDecl{},
		topFuncs:         map[string]*ast.FuncDecl{},
		dupTopFuncs:      map[string]bool{},
		typeMethods:      map[string]map[string]*ast.FuncDecl{},
		dupTypeMethods:   map[string]map[string]bool{},
		typeSpecs:        map[string]*ast.TypeSpec{},
		typeSpecFile:     map[*ast.TypeSpec]*ast.File{},
		typeSpecCounts:   map[string]int{},
		pkgDeclCounts:    map[string]int{},
		pkgValueCounts:   map[string]int{},
		pkgVarSpecs:      map[string]*ast.ValueSpec{},
		pkgVarFiles:      map[string]*ast.File{},
		pkgVarCounts:     map[string]int{},
		constPosInt:      map[string]bool{},
		zeroInitPkgVars:  map[string]*ast.ValueSpec{},
		zeroInitBoolVars: map[string]bool{},
		initPkgVars:      map[string]ast.Expr{},
		initPkgVarFile:   map[string]*ast.File{},
		varDeclIdents:    map[string]map[*ast.Ident]bool{},
	}
	for _, f := range files {
		idx.fileImports[f] = map[string]bool{}
		idx.fileImportNames[f] = map[string]bool{}
		for _, imp := range f.Imports {
			importPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return nil, err
			}
			if imp.Name != nil && (imp.Name.Name == "." || reserved[imp.Name.Name]) {
				return nil, fmt.Errorf("%s: forbidden or shadowing import alias %q", pkgName, imp.Name.Name)
			}
			if unaliasedImports[importPath] {
				if imp.Name != nil {
					return nil, fmt.Errorf("%s: aliased import of %s forbidden", pkgName, importPath)
				}
				idx.fileImports[f][importPath] = true
			}
			localName := importPath
			if slash := strings.LastIndexByte(importPath, '/'); slash >= 0 {
				localName = importPath[slash+1:]
			}
			if imp.Name != nil {
				localName = imp.Name.Name
			}
			if localName != "_" && localName != "." && localName != "" {
				idx.fileImportNames[f][localName] = true
			}
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.ValueSpec:
						for i, id := range sp.Names {
							if reserved[id.Name] {
								return nil, fmt.Errorf("%s: package-level declaration shadows %s", pkgName, id.Name)
							}
							if d.Tok == token.CONST && i < len(sp.Values) && isPositiveIntLit(sp.Values[i]) {
								idx.constPosInt[id.Name] = true
							}
							if id.Name == "_" {
								continue
							}
							idx.pkgDeclCounts[id.Name]++
							idx.pkgValueCounts[id.Name]++
							if d.Tok == token.VAR {
								idx.pkgVarCounts[id.Name]++
								idx.pkgVarSpecs[id.Name] = sp
								idx.pkgVarFiles[id.Name] = f
								if idx.varDeclIdents[id.Name] == nil {
									idx.varDeclIdents[id.Name] = map[*ast.Ident]bool{}
								}
								idx.varDeclIdents[id.Name][id] = true
								if len(sp.Values) == 0 {
									idx.zeroInitPkgVars[id.Name] = sp
									if tID, ok := unwrapParens(sp.Type).(*ast.Ident); ok && tID.Name == "bool" {
										idx.zeroInitBoolVars[id.Name] = true
									}
								} else if len(sp.Values) == len(sp.Names) {
									idx.initPkgVars[id.Name] = sp.Values[i]
									idx.initPkgVarFile[id.Name] = f
								}
							}
						}
					case *ast.TypeSpec:
						if sp.Name == nil {
							continue
						}
						if reserved[sp.Name.Name] {
							return nil, fmt.Errorf("%s: package-level type shadows %s", pkgName, sp.Name.Name)
						}
						if sp.Name.Name != "_" {
							idx.pkgDeclCounts[sp.Name.Name]++
							idx.typeSpecCounts[sp.Name.Name]++
							idx.typeSpecs[sp.Name.Name] = sp
							idx.typeSpecFile[sp] = f
						}
					}
				}
			case *ast.FuncDecl:
				idx.funcFile[d] = f
				idx.funcDeclsByName[d.Name.Name] = append(idx.funcDeclsByName[d.Name.Name], d)
				if d.Recv == nil && reserved[d.Name.Name] {
					return nil, fmt.Errorf("%s: package-level function shadows %s", pkgName, d.Name.Name)
				}
				if d.Recv == nil && d.Name.Name == "init" {
					idx.hasInitFunc = true
				}
				if d.Body == nil {
					idx.bodylessFuncs = append(idx.bodylessFuncs, d)
				}
				if d.Recv == nil {
					if d.Name.Name != "init" && d.Name.Name != "_" {
						idx.pkgDeclCounts[d.Name.Name]++
						if _, exists := idx.topFuncs[d.Name.Name]; exists {
							idx.dupTopFuncs[d.Name.Name] = true
						}
						idx.topFuncs[d.Name.Name] = d
					}
				} else {
					idx.hasMethods = true
					if len(d.Recv.List) == 1 {
						if rType := recvTypeName(d.Recv.List[0].Type); rType != "" {
							if idx.typeMethods[rType] == nil {
								idx.typeMethods[rType] = map[string]*ast.FuncDecl{}
								idx.dupTypeMethods[rType] = map[string]bool{}
							}
							if _, exists := idx.typeMethods[rType][d.Name.Name]; exists {
								idx.dupTypeMethods[rType][d.Name.Name] = true
								idx.anyDupTypeMethod = true
							}
							idx.typeMethods[rType][d.Name.Name] = d
						}
					}
				}
			}
		}
	}
	for dup := range idx.dupTopFuncs {
		delete(idx.topFuncs, dup)
	}
	return idx, nil
}

func (idx *parsedPkgIndex) hasFileImport(f *ast.File, importPath string) bool {
	return idx != nil && idx.fileImports[f][importPath]
}

func (idx *parsedPkgIndex) fileImportSet(importPath string) map[*ast.File]bool {
	out := map[*ast.File]bool{}
	if idx == nil {
		return out
	}
	for f, m := range idx.fileImports {
		if m[importPath] {
			out[f] = true
		}
	}
	return out
}

func (idx *parsedPkgIndex) hasAnyImport(importPath string) bool {
	if idx == nil {
		return false
	}
	for _, m := range idx.fileImports {
		if m[importPath] {
			return true
		}
	}
	return false
}

func (idx *parsedPkgIndex) uniqueTypeSpec(name string) *ast.TypeSpec {
	if idx == nil || idx.typeSpecCounts[name] != 1 {
		return nil
	}
	return idx.typeSpecs[name]
}

func scanGoDirectiveComments(src string, visit func(lit string) error) error {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var scanErr error
	var s scanner.Scanner
	s.Init(file, []byte(src), func(_ token.Position, msg string) {
		if scanErr == nil {
			scanErr = fmt.Errorf("scanner error: %s", msg)
		}
	}, scanner.ScanComments)
	for {
		_, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok != token.COMMENT {
			continue
		}
		if strings.HasPrefix(lit, "/*go:") {
			return fmt.Errorf("forbidden block compiler directive %q", lit)
		}
		if !strings.HasPrefix(lit, "//go:") {
			continue
		}
		line := strings.TrimSuffix(lit, "\r")
		if strings.ContainsRune(line, '\r') {
			return fmt.Errorf("malformed carriage return in compiler directive %q", line)
		}
		if err := visit(line); err != nil {
			return err
		}
	}
	return scanErr
}

func scanVerifiedLinknameDirectives(text string, check func(line string, fields []string) error) error {
	return scanGoDirectiveComments(text, func(line string) error {
		if strings.HasPrefix(line, "//go:wasmimport") {
			return fmt.Errorf("forbidden wasmimport directive %q", line)
		}
		if strings.HasPrefix(line, "//go:wasmexport") {
			return fmt.Errorf("forbidden wasmexport directive %q", line)
		}
		if strings.HasPrefix(line, "//go:cgo_") {
			return fmt.Errorf("forbidden cgo directive %q", line)
		}
		if !strings.HasPrefix(line, "//go:linkname") {
			return nil
		}
		_, plain := auditset.BoundedToken(line, "//go:linkname", " \t")
		_, std := auditset.BoundedToken(line, "//go:linknamestd", " \t")
		if !plain && !std {
			return fmt.Errorf("malformed linkname directive %q", line)
		}
		fields := strings.Fields(line)
		if len(fields) != 2 && len(fields) != 3 {
			return fmt.Errorf("invalid linkname directive arity %q", line)
		}
		return check(line, fields)
	})
}

var forbiddenOSLinknameLocals = map[string]bool{
	"Getenv": true, "LookupEnv": true, "Open": true, "Create": true,
	"OpenFile": true, "openDir": true, "ReadFile": true, "ReadDir": true,
	"Stat": true, "Lstat": true, "Chdir": true, "Getwd": true,
	"Write": true, "WriteString": true, "Close": true, "close": true,
	"write": true, "checkValid": true, "wrapErr": true, "fixCount": true,
	"writeLock": true, "writeUnlock": true, "decref": true, "destroy": true,
	"statNolog": true, "lstatNolog": true, "openFileNolog": true, "openDirNolog": true,
	"ErrInvalid": true, "ErrClosed": true, "Args": true, "Stdin": true, "Stdout": true, "Stderr": true,
	"Exit": true, "epipecheck": true, "sigpipe": true, "Fd": true, "fd": true,
	"NewFile": true, "newFile": true, "newFileFromNewFile": true, "open": true,
	"ignoringEINTR": true, "ignoringEINTR2": true, "fixLongPath": true,
	"statOrZero": true, "fstatNolog": true, "readFileContents": true, "NewSyscallError": true,
	"SameFile": true, "sameFile": true,
}

func verifyHarnessFileDirectives(pkgPath, text string, runtimePullLinknames, selfPushLinknames map[string]bool, osRuntimePullMap map[string]string, osAnyLinknameLocals map[string]bool) error {
	return scanVerifiedLinknameDirectives(text, func(line string, fields []string) error {
		switch pkgPath {
		case "testing/internal/testdeps":
			return fmt.Errorf("forbidden linkname directive %q in %s", line, pkgPath)
		case "internal/testlog":
			if len(fields) != 2 || fields[1] != "SetPanicOnExit0" {
				return fmt.Errorf("unapproved linkname directive %q in %s", line, pkgPath)
			}
		case "os":
			localSym := fields[1]
			if strings.Contains(localSym, ".") || forbiddenOSLinknameLocals[localSym] {
				return fmt.Errorf("forbidden linkname on os boundary/sink symbol %q", localSym)
			}
			if osAnyLinknameLocals != nil {
				osAnyLinknameLocals[localSym] = true
			}
			if len(fields) == 3 {
				target := fields[2]
				if target == "runtime.exit" || target == "syscall.Exit" || target == "syscall.ExitProcess" || strings.HasSuffix(target, ".Exit") || strings.HasSuffix(target, ".exit") {
					return fmt.Errorf("forbidden exit linkname target %q in os", target)
				}
				allowedTarget := target == "os."+localSym ||
					strings.HasPrefix(target, "os/") ||
					strings.HasPrefix(target, "runtime.") ||
					strings.HasPrefix(target, "syscall.") ||
					strings.HasPrefix(target, "net.") ||
					(strings.HasPrefix(target, "internal/") && !strings.HasPrefix(target, "internal/testlog."))
				if !allowedTarget {
					return fmt.Errorf("unapproved linkname target %q in os", target)
				}
				if strings.HasPrefix(target, "runtime.") {
					runtimePullLinknames[localSym] = true
					if osRuntimePullMap != nil {
						if prev, exists := osRuntimePullMap[localSym]; exists && prev != target {
							return fmt.Errorf("conflicting runtime linkname target for %s in os", localSym)
						}
						osRuntimePullMap[localSym] = target
					}
				}
			}
		case "testing":
			if len(fields) != 3 {
				return fmt.Errorf("unapproved single-argument linkname %q in %s", line, pkgPath)
			}
			localSym, target := fields[1], fields[2]
			switch localSym {
			case "MainStart", "Main", "Init", "tRunner", "runTests", "runBenchmarks", "runExamples", "runFuzzTests", "runFuzzing":
				return fmt.Errorf("forbidden linkname on harness symbol %s", localSym)
			}
			switch {
			case (target == "testing."+localSym || (strings.HasPrefix(target, "testing/") && !strings.HasPrefix(target, "testing/internal/"))) && strings.HasSuffix(target, "."+localSym):
				selfPushLinknames[localSym] = true
			case strings.HasPrefix(target, "runtime.") && target != "runtime.exit":
				runtimePullLinknames[localSym] = true
			default:
				return fmt.Errorf("unapproved linkname target %q in %s", target, pkgPath)
			}
		}
		return nil
	})
}

func verifyFileLinknameDirectives(pkgPath string, text string) error {
	return scanVerifiedLinknameDirectives(text, func(line string, fields []string) error {
		if len(fields) == 2 {
			if !allowedPureSingleArgLinknames[pkgPath+"."+fields[1]] {
				return fmt.Errorf("unapproved single-argument linkname %q in %s", line, pkgPath)
			}
			return nil
		}
		target := fields[2]
		if !strings.HasPrefix(target, pkgPath+".") && !allowedPureLinknameTargets[target] {
			return fmt.Errorf("unapproved pure-package linkname target %q", target)
		}
		return nil
	})
}

func splitLinknameTarget(target string) (pkgPath, sym string, ok bool) {
	slash := strings.LastIndexByte(target, '/')
	dotRel := strings.IndexByte(target[slash+1:], '.')
	if dotRel <= 0 {
		return "", "", false
	}
	dot := slash + 1 + dotRel
	pkgPath = target[:dot]
	sym = target[dot+1:]
	if sym == "" {
		return "", "", false
	}
	return pkgPath, sym, true
}

func scanOffSurfaceGoDirectives(src string, directRuntime map[string]bool, onTwoArgLink func(localSym, target string)) {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, []byte(src), func(_ token.Position, _ string) {}, scanner.ScanComments)
	for {
		_, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok != token.COMMENT {
			continue
		}
		if strings.HasPrefix(lit, "/*go:linkname") {
			if directRuntime != nil {
				directRuntime["runtime.*"] = true
			}
			continue
		}
		if strings.HasPrefix(lit, "//go:cgo_") && (strings.Contains(lit, "runtime.") || strings.Contains(lit, "runtime\xc2\xb7")) {
			if directRuntime != nil {
				directRuntime["runtime.*"] = true
			}
			continue
		}
		if !strings.HasPrefix(lit, "//go:linkname") {
			continue
		}
		line := strings.TrimSuffix(lit, "\r")
		if strings.ContainsRune(line, '\r') {
			if directRuntime != nil {
				directRuntime["runtime.*"] = true
			}
			continue
		}
		_, plain := auditset.BoundedToken(line, "//go:linkname", " \t")
		_, std := auditset.BoundedToken(line, "//go:linknamestd", " \t")
		fields := strings.Fields(line)
		if (!plain && !std) || (len(fields) != 2 && len(fields) != 3) {
			if directRuntime != nil {
				directRuntime["runtime.*"] = true
			}
			continue
		}
		if len(fields) == 3 && onTwoArgLink != nil {
			onTwoArgLink(fields[1], fields[2])
		}
	}
}

func collectGoRuntimeLinknameTargets(src string, out map[string]bool) {
	collectGoLinknameTargets("", src, out, nil)
}

func collectGoLinknameTargets(selfPkg, src string, runtimeOut, externalOut map[string]bool) {
	scanOffSurfaceGoDirectives(src, runtimeOut, func(_, target string) {
		if strings.HasPrefix(target, "runtime.") {
			if runtimeOut != nil {
				runtimeOut[target] = true
			}
		} else if externalOut != nil {
			if tPkg, _, ok := splitLinknameTarget(target); ok && tPkg != selfPkg {
				externalOut[target] = true
			}
		}
	})
}

func unwrapParens(expr ast.Expr) ast.Expr {
	for {
		p, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = p.X
	}
}

func recvTypeIdent(expr ast.Expr) *ast.Ident {
	expr = unwrapParens(expr)
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = unwrapParens(star.X)
	}
	id, _ := expr.(*ast.Ident)
	return id
}

func recvTypeName(expr ast.Expr) string {
	if id := recvTypeIdent(expr); id != nil {
		return id.Name
	}
	return ""
}

func baseTypeIdentName(expr ast.Expr) string {
	expr = unwrapParens(expr)
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		if id, ok := unwrapParens(t.X).(*ast.Ident); ok {
			return id.Name
		}
	case *ast.IndexListExpr:
		if id, ok := unwrapParens(t.X).(*ast.Ident); ok {
			return id.Name
		}
	}
	return ""
}

func recvBaseTypeName(expr ast.Expr) string {
	expr = unwrapParens(expr)
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = unwrapParens(star.X)
	}
	return baseTypeIdentName(expr)
}

func recvVarName(fn *ast.FuncDecl) string {
	if fn == nil || fn.Recv == nil || len(fn.Recv.List) != 1 {
		return ""
	}
	names := fn.Recv.List[0].Names
	if len(names) != 1 || names[0].Name == "_" {
		return ""
	}
	return names[0].Name
}

func funcResultFieldTypeAt(results *ast.FieldList, targetIdx int) ast.Expr {
	if results == nil || targetIdx < 0 {
		return nil
	}
	cur := 0
	for _, fld := range results.List {
		n := len(fld.Names)
		if n == 0 {
			n = 1
		}
		if targetIdx < cur+n {
			return fld.Type
		}
		cur += n
	}
	return nil
}

func isMethodCallNamed(expr ast.Expr, name string) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == name
}

func isIdentNamed(expr ast.Expr, name string) (*ast.Ident, bool) {
	id, ok := unwrapParens(expr).(*ast.Ident)
	return id, ok && id.Name == name
}

func isSelectorBaseField(expr ast.Expr, base, field string) (*ast.Ident, bool) {
	sel, ok := unwrapParens(expr).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != field {
		return nil, false
	}
	return isIdentNamed(sel.X, base)
}

func isZeroArgMethodCallOnSelector(expr ast.Expr, base, field, method string) (*ast.Ident, bool) {
	call, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 0 {
		return nil, false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != method {
		return nil, false
	}
	return isSelectorBaseField(sel.X, base, field)
}

func isZeroArgMethodCallOnIdent(expr ast.Expr, base, method string) (*ast.Ident, bool) {
	call, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 0 {
		return nil, false
	}
	return isSelectorBaseField(call.Fun, base, method)
}

func exprReferencesDiscard(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.Ident:
			if x.Name == "Discard" {
				found = true
				return false
			}
		case *ast.SelectorExpr:
			if x.Sel.Name == "Discard" {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func exprContainsAnyCall(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		if _, ok := n.(*ast.CallExpr); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

func exprHasCallOrFuncLit(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		switch n.(type) {
		case *ast.CallExpr, *ast.FuncLit:
			found = true
			return false
		}
		return true
	})
	return found
}

func compositeWriterLit(expr ast.Expr) (*ast.CompositeLit, string) {
	expr = unwrapParens(expr)
	if u, ok := expr.(*ast.UnaryExpr); ok && u.Op == token.AND {
		expr = unwrapParens(u.X)
	}
	lit, ok := expr.(*ast.CompositeLit)
	if !ok || lit.Type == nil {
		return nil, ""
	}
	id, ok := unwrapParens(lit.Type).(*ast.Ident)
	if !ok {
		return nil, ""
	}
	return lit, id.Name
}

func funcReturnsErrorLast(ft *ast.FuncType) bool {
	if ft == nil || ft.Results == nil || len(ft.Results.List) == 0 {
		return false
	}
	last := ft.Results.List[len(ft.Results.List)-1]
	id, ok := unwrapParens(last.Type).(*ast.Ident)
	return ok && id.Name == "error"
}

func lastNamedResultIdent(results *ast.FieldList) string {
	if results == nil || len(results.List) == 0 {
		return ""
	}
	last := results.List[len(results.List)-1]
	if len(last.Names) == 0 {
		return ""
	}
	name := last.Names[len(last.Names)-1].Name
	if name == "_" {
		return ""
	}
	return name
}

func paramNamesFlat(params *ast.FieldList) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, field := range params.List {
		if len(field.Names) == 0 {
			out = append(out, "")
			continue
		}
		for _, n := range field.Names {
			out = append(out, n.Name)
		}
	}
	return out
}

func isByteSliceType(expr ast.Expr) bool {
	arr, ok := unwrapParens(expr).(*ast.ArrayType)
	if !ok || arr.Len != nil {
		return false
	}
	elt, ok := unwrapParens(arr.Elt).(*ast.Ident)
	return ok && elt.Name == "byte"
}

func byteSliceParamIdents(params *ast.FieldList) map[string]bool {
	out := map[string]bool{}
	if params == nil {
		return out
	}
	for _, field := range params.List {
		if !isByteSliceType(field.Type) {
			continue
		}
		for _, n := range field.Names {
			if n.Name != "" && n.Name != "_" {
				out[n.Name] = true
			}
		}
	}
	return out
}

func singleByteSliceParamIdent(params *ast.FieldList) string {
	if params == nil || params.NumFields() != 1 || len(params.List) != 1 || len(params.List[0].Names) != 1 {
		return ""
	}
	if !isByteSliceType(params.List[0].Type) {
		return ""
	}
	name := params.List[0].Names[0].Name
	if name == "" || name == "_" {
		return ""
	}
	return name
}

func firstResultIsInt(results *ast.FieldList) bool {
	if results == nil || len(results.List) == 0 {
		return false
	}
	first := results.List[0]
	id, ok := unwrapParens(first.Type).(*ast.Ident)
	return ok && id.Name == "int"
}

func firstNamedIntResultIdent(results *ast.FieldList) string {
	if results == nil || results.NumFields() != 2 || !firstResultIsInt(results) {
		return ""
	}
	first := results.List[0]
	if len(first.Names) == 0 {
		return ""
	}
	name := first.Names[0].Name
	if name == "_" {
		return ""
	}
	return name
}

func isZeroIntLit(expr ast.Expr) bool {
	lit, ok := unwrapParens(expr).(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == "0"
}

func isPositiveIntLit(expr ast.Expr) bool {
	lit, ok := unwrapParens(expr).(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return false
	}
	v, err := strconv.ParseUint(lit.Value, 0, 64)
	return err == nil && v > 0
}

func isOneArgLenIdentCall(call *ast.CallExpr) bool {
	if call == nil || call.Ellipsis.IsValid() || len(call.Args) != 1 {
		return false
	}
	funID, ok := unwrapParens(call.Fun).(*ast.Ident)
	if !ok || funID.Name != "len" {
		return false
	}
	_, ok = unwrapParens(call.Args[0]).(*ast.Ident)
	return ok
}

func isLenOfIdentCall(expr ast.Expr, identName string) bool {
	if identName == "" {
		return false
	}
	call, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || call.Ellipsis.IsValid() {
		return false
	}
	funID, ok := unwrapParens(call.Fun).(*ast.Ident)
	if !ok || funID.Name != "len" {
		return false
	}
	argID, ok := unwrapParens(call.Args[0]).(*ast.Ident)
	return ok && argID.Name == identName
}

func isSliceLenZeroCond(cond ast.Expr, sliceName string) bool {
	if sliceName == "" {
		return false
	}
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return false
	}
	return (isLenOfIdentCall(bin.X, sliceName) && isZeroIntLit(bin.Y)) ||
		(isZeroIntLit(bin.X) && isLenOfIdentCall(bin.Y, sliceName))
}

func isConstantOrTrivialCond(cond ast.Expr) bool {
	cond = unwrapParens(cond)
	switch e := cond.(type) {
	case nil:
		return true
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return e.Name == "true" || e.Name == "false" || e.Name == "nil"
	case *ast.UnaryExpr:
		if e.Op == token.NOT {
			return isConstantOrTrivialCond(e.X)
		}
		return exprHasCallOrFuncLit(e.X)
	case *ast.BinaryExpr:
		if exprHasCallOrFuncLit(e.X) || exprHasCallOrFuncLit(e.Y) {
			return true
		}
		if e.Op == token.LAND || e.Op == token.LOR {
			return isConstantOrTrivialCond(e.X) || isConstantOrTrivialCond(e.Y)
		}
		if isConstantOrTrivialCond(e.X) && isConstantOrTrivialCond(e.Y) {
			return true
		}
		if xID, ok := unwrapParens(e.X).(*ast.Ident); ok {
			if yID, ok2 := unwrapParens(e.Y).(*ast.Ident); ok2 && xID.Name == yID.Name {
				return true
			}
		}
		return false
	default:
		return exprHasCallOrFuncLit(cond)
	}
}
