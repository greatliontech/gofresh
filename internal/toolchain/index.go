// Package toolchain provides the Go toolchain AST declaration/scope indexer,
// compiler-directive scanner, off-surface startup runtime-pull graph builder,
// and structural standard-library/runtime purity verifiers.
package toolchain

import (
	"fmt"
	"go/ast"
	"go/scanner"
	"go/token"
	"slices"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/cprep"
)

func sortedKeys(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	keys := make([]string, 0, len(set))
	for k, ok := range set {
		if ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}

// packageASTIndex indexes package-level declarations, per-file imports, and
// method sets across a parsed standard-library package's AST files.
type packageASTIndex struct {
	fileImports            map[*ast.File]map[string]bool
	fileImportNames        map[*ast.File]map[string]bool
	funcFile               map[*ast.FuncDecl]*ast.File
	funcDeclsByName        map[string][]*ast.FuncDecl
	topFuncs               map[string]*ast.FuncDecl
	dupTopFuncs            map[string]bool
	typeMethods            map[string]map[string]*ast.FuncDecl
	dupTypeMethods         map[string]map[string]bool
	anyDupTypeMethod       bool
	typeSpecs              map[string]*ast.TypeSpec
	typeSpecFile           map[*ast.TypeSpec]*ast.File
	typeSpecCounts         map[string]int
	nonAliasStructSpec     map[string]*ast.TypeSpec
	pkgDeclCounts          map[string]int
	pkgValueCounts         map[string]int
	pkgVarSpecs            map[string]*ast.ValueSpec
	pkgVarFiles            map[string]*ast.File
	pkgVarCounts           map[string]int
	constPosInt            map[string]bool
	zeroInitPkgVars        map[string]*ast.ValueSpec
	zeroInitBoolVars       map[string]bool
	initPkgVars            map[string]ast.Expr
	initPkgVarFile         map[string]*ast.File
	varDeclIdents          map[string]map[*ast.Ident]bool
	blankVarInits          []ast.Expr
	hasMultiReturnBlankVar bool
	hasInitFunc            bool
	hasMethods             bool
	bodylessFuncs          []*ast.FuncDecl
}

// indexPackageAST indexes package-level declarations, imports, and method sets
// across files.
func indexPackageAST(pkgName string, files []*ast.File, reserved map[string]bool, unaliasedImports map[string]bool) (*packageASTIndex, error) {
	idx := &packageASTIndex{
		fileImports:        make(map[*ast.File]map[string]bool, len(files)),
		fileImportNames:    make(map[*ast.File]map[string]bool, len(files)),
		funcFile:           map[*ast.FuncDecl]*ast.File{},
		funcDeclsByName:    map[string][]*ast.FuncDecl{},
		topFuncs:           map[string]*ast.FuncDecl{},
		dupTopFuncs:        map[string]bool{},
		typeMethods:        map[string]map[string]*ast.FuncDecl{},
		dupTypeMethods:     map[string]map[string]bool{},
		typeSpecs:          map[string]*ast.TypeSpec{},
		typeSpecFile:       map[*ast.TypeSpec]*ast.File{},
		typeSpecCounts:     map[string]int{},
		nonAliasStructSpec: map[string]*ast.TypeSpec{},
		pkgDeclCounts:      map[string]int{},
		pkgValueCounts:     map[string]int{},
		pkgVarSpecs:        map[string]*ast.ValueSpec{},
		pkgVarFiles:        map[string]*ast.File{},
		pkgVarCounts:       map[string]int{},
		constPosInt:        map[string]bool{},
		zeroInitPkgVars:    map[string]*ast.ValueSpec{},
		zeroInitBoolVars:   map[string]bool{},
		initPkgVars:        map[string]ast.Expr{},
		initPkgVarFile:     map[string]*ast.File{},
		varDeclIdents:      map[string]map[*ast.Ident]bool{},
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
								if d.Tok == token.VAR && len(sp.Values) > 0 {
									if len(sp.Values) == len(sp.Names) {
										idx.blankVarInits = append(idx.blankVarInits, sp.Values[i])
									} else {
										idx.hasMultiReturnBlankVar = true
									}
								}
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
							if !sp.Assign.IsValid() {
								if _, okST := unwrapParens(sp.Type).(*ast.StructType); okST {
									idx.nonAliasStructSpec[sp.Name.Name] = sp
								}
							}
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

func (idx *packageASTIndex) hasFileImport(f *ast.File, importPath string) bool {
	return idx != nil && idx.fileImports[f][importPath]
}

func (idx *packageASTIndex) fileImportSet(importPath string) map[*ast.File]bool {
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

func (idx *packageASTIndex) hasAnyImport(importPath string) bool {
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

func (idx *packageASTIndex) anyFileHasImportName(name string) bool {
	if idx == nil {
		return false
	}
	for _, m := range idx.fileImportNames {
		if m[name] {
			return true
		}
	}
	return false
}

func (idx *packageASTIndex) isUniqueLocalType(name string) bool {
	return idx != nil && name != "" && name != "_" &&
		idx.typeSpecCounts[name] == 1 && idx.pkgDeclCounts[name] == 1 &&
		idx.pkgValueCounts[name] == 0 && idx.topFuncs[name] == nil &&
		!idx.anyFileHasImportName(name)
}

// verifyBlankVarInitsPure checks that every package-level blank variable
// initializer (var _ = <expr>) in idx is a side-effect-free compile-time
// assertion literal or nil/zero local-type conversion.
func (idx *packageASTIndex) verifyBlankVarInitsPure(pkgName string) error {
	if idx == nil {
		return fmt.Errorf("%s: nil AST index", pkgName)
	}
	if idx.hasMultiReturnBlankVar {
		return fmt.Errorf("%s: multi-return blank package var initializer forbidden", pkgName)
	}
	for _, expr := range idx.blankVarInits {
		if !idx.isPureBlankVarInitExpr(expr) {
			return fmt.Errorf("%s: unapproved blank package var initializer", pkgName)
		}
	}
	return nil
}

func (idx *packageASTIndex) isPureBlankVarInitExpr(expr ast.Expr) bool {
	if expr == nil {
		return false
	}
	switch e := unwrapParens(expr).(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return (e.Name == "nil" || e.Name == "true" || e.Name == "false") &&
			idx.pkgDeclCounts[e.Name] == 0 && !idx.anyFileHasImportName(e.Name)
	case *ast.CallExpr:
		if e.Ellipsis.IsValid() || len(e.Args) != 1 {
			return false
		}
		argID, okArg := unwrapParens(e.Args[0]).(*ast.Ident)
		if !okArg || argID.Name != "nil" || idx.pkgDeclCounts["nil"] != 0 || idx.anyFileHasImportName("nil") {
			return false
		}
		fun := unwrapParens(e.Fun)
		if star, okStar := fun.(*ast.StarExpr); okStar {
			fun = unwrapParens(star.X)
		}
		tID, okT := fun.(*ast.Ident)
		return okT && idx.isUniqueLocalType(tID.Name)
	case *ast.CompositeLit:
		if len(e.Elts) != 0 {
			return false
		}
		tID, okT := unwrapParens(e.Type).(*ast.Ident)
		return okT && idx.isUniqueLocalType(tID.Name)
	case *ast.UnaryExpr:
		if e.Op != token.AND {
			return false
		}
		cl, okCL := unwrapParens(e.X).(*ast.CompositeLit)
		if !okCL || len(cl.Elts) != 0 {
			return false
		}
		tID, okT := unwrapParens(cl.Type).(*ast.Ident)
		return okT && idx.isUniqueLocalType(tID.Name)
	default:
		return false
	}
}

func (idx *packageASTIndex) uniqueTypeSpec(name string) *ast.TypeSpec {
	if idx == nil || idx.typeSpecCounts[name] != 1 {
		return nil
	}
	return idx.typeSpecs[name]
}

// verifyStructFields checks that name is a unique, non-alias, non-generic struct
// with no embedded or duplicate fields, and whose required fields match their
// type predicates (and has no extra fields when allowExtra is false).
func (idx *packageASTIndex) verifyStructFields(name string, required map[string]func(ast.Expr) bool, allowExtra bool) (*ast.StructType, *ast.File, bool) {
	if idx == nil || idx.pkgDeclCounts[name] != 1 {
		return nil, nil, false
	}
	sp := idx.uniqueTypeSpec(name)
	if sp == nil || sp.Assign.IsValid() || sp.TypeParams != nil {
		return nil, nil, false
	}
	st, ok := unwrapParens(sp.Type).(*ast.StructType)
	if !ok || st.Fields == nil {
		return nil, nil, false
	}
	seen := make(map[string]bool, len(required))
	allFields := map[string]bool{}
	for _, fld := range st.Fields.List {
		if len(fld.Names) == 0 {
			return nil, nil, false
		}
		for _, id := range fld.Names {
			if allFields[id.Name] {
				return nil, nil, false
			}
			allFields[id.Name] = true
			check, want := required[id.Name]
			if !want {
				if !allowExtra {
					return nil, nil, false
				}
				continue
			}
			if check != nil && !check(fld.Type) {
				return nil, nil, false
			}
			seen[id.Name] = true
		}
	}
	if len(seen) != len(required) {
		return nil, nil, false
	}
	return st, idx.typeSpecFile[sp], true
}

// verifyFuncPreamble looks up a unique concrete function or method, verifying
// that it has a body, no type parameters, no shadowing of reserved identifiers,
// and no control-flow/recover bypasses.
func (idx *packageASTIndex) verifyFuncPreamble(recvType, name string, wantPtrRecv bool, reserved map[string]bool) (*ast.FuncDecl, *ast.File, bool) {
	if idx == nil {
		return nil, nil, false
	}
	var fn *ast.FuncDecl
	if recvType == "" {
		if idx.pkgDeclCounts[name] != 1 || idx.dupTopFuncs[name] {
			return nil, nil, false
		}
		fn = idx.topFuncs[name]
	} else {
		if idx.dupTypeMethods[recvType][name] {
			return nil, nil, false
		}
		fn = idx.typeMethods[recvType][name]
		if fn == nil || fn.Recv == nil || len(fn.Recv.List) != 1 {
			return nil, nil, false
		}
		_, isPtr := unwrapParens(fn.Recv.List[0].Type).(*ast.StarExpr)
		if wantPtrRecv && !isPtr {
			return nil, nil, false
		}
	}
	if fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil {
		return nil, nil, false
	}
	if funcShadowsAnyIdent(fn, reserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
		return nil, nil, false
	}
	return fn, idx.funcFile[fn], true
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
		fields, ok := cprep.ParseGoLinknameLineFields(line)
		if !ok {
			return fmt.Errorf("malformed linkname directive %q", line)
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

var forbiddenTestdepsLinknameLocals = map[string]bool{
	"TestDeps": true, "StartTestLog": true, "StopTestLog": true,
	"ImportPath": true, "ModulePath": true, "SetPanicOnExit0": true, "MatchString": true,
	"StartCPUProfile": true, "StopCPUProfile": true, "WriteProfileTo": true,
	"CoordinateFuzzing": true, "RunFuzzWorker": true, "ReadCorpus": true,
	"CheckCorpus": true, "ResetCoverage": true, "SnapshotCoverage": true,
	"InitRuntimeCoverage": true, "testLog": true, "add": true, "log": true,
	"Getenv": true, "Open": true, "Stat": true, "Chdir": true,
}

func isForbiddenExitTarget(target string) bool {
	return target == "runtime.exit" || target == "syscall.Exit" || target == "syscall.ExitProcess" ||
		strings.HasSuffix(target, ".Exit") || strings.HasSuffix(target, ".exit")
}

// verifyHarnessFileDirectives verifies compiler directives in harness-premise
// packages (testing, internal/testlog, testing/internal/testdeps, os).
func verifyHarnessFileDirectives(pkgPath, text string, runtimePullLinknames, selfPushLinknames map[string]bool, runtimePullMap map[string]string, anyLinknameLocals map[string]bool) error {
	recordRuntimePull := func(localSym, target string) error {
		if runtimePullLinknames != nil {
			runtimePullLinknames[localSym] = true
		}
		if runtimePullMap != nil {
			if prev, exists := runtimePullMap[localSym]; exists && prev != target {
				return fmt.Errorf("conflicting runtime linkname target for %s in %s", localSym, pkgPath)
			}
			runtimePullMap[localSym] = target
		}
		return nil
	}
	return scanVerifiedLinknameDirectives(text, func(line string, fields []string) error {
		switch pkgPath {
		case "testing/internal/testdeps":
			if len(fields) != 3 {
				return fmt.Errorf("unapproved single-argument linkname %q in %s", line, pkgPath)
			}
			localSym, target := fields[1], fields[2]
			if strings.Contains(localSym, ".") || ast.IsExported(localSym) || forbiddenTestdepsLinknameLocals[localSym] {
				return fmt.Errorf("forbidden linkname on %s symbol %q", pkgPath, localSym)
			}
			if !strings.HasPrefix(target, "runtime.") || isForbiddenExitTarget(target) {
				return fmt.Errorf("unapproved linkname target %q in %s", target, pkgPath)
			}
			if anyLinknameLocals != nil {
				anyLinknameLocals[localSym] = true
			}
			return recordRuntimePull(localSym, target)
		case "internal/testlog":
			if len(fields) != 2 || fields[1] != "SetPanicOnExit0" {
				return fmt.Errorf("unapproved linkname directive %q in %s", line, pkgPath)
			}
		case "os":
			localSym := fields[1]
			if strings.Contains(localSym, ".") || forbiddenOSLinknameLocals[localSym] {
				return fmt.Errorf("forbidden linkname on os boundary/sink symbol %q", localSym)
			}
			if anyLinknameLocals != nil {
				anyLinknameLocals[localSym] = true
			}
			if len(fields) == 3 {
				target := fields[2]
				if isForbiddenExitTarget(target) {
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
					return recordRuntimePull(localSym, target)
				}
			}
		case "testing":
			if len(fields) != 3 {
				return fmt.Errorf("unapproved single-argument linkname %q in %s", line, pkgPath)
			}
			localSym, target := fields[1], fields[2]
			if strings.Contains(localSym, ".") {
				return fmt.Errorf("forbidden method linkname %s in testing", localSym)
			}
			switch localSym {
			case "MainStart", "Main", "Init", "tRunner", "runTests", "runBenchmarks", "runExamples", "runFuzzTests", "runFuzzing", "Chdir", "Setenv", "Cleanup", "runCleanup":
				return fmt.Errorf("forbidden linkname on harness symbol %s", localSym)
			}
			if anyLinknameLocals != nil {
				anyLinknameLocals[localSym] = true
			}
			switch {
			case (target == "testing."+localSym || (strings.HasPrefix(target, "testing/") && !strings.HasPrefix(target, "testing/internal/"))) && strings.HasSuffix(target, "."+localSym):
				if selfPushLinknames != nil {
					selfPushLinknames[localSym] = true
				}
			case localSym != "checkParallel" && strings.HasPrefix(target, "runtime.") && !isForbiddenExitTarget(target):
				return recordRuntimePull(localSym, target)
			default:
				return fmt.Errorf("unapproved linkname target %q in %s", target, pkgPath)
			}
		}
		return nil
	})
}

// verifyFileLinknameDirectives verifies //go:linkname directives in a pure-candidate
// standard-library source file.
func verifyFileLinknameDirectives(pkgPath string, text string) error {
	return scanVerifiedLinknameDirectives(text, func(line string, fields []string) error {
		if len(fields) == 2 {
			if !cprep.AllowedPureSingleArgLinknames[pkgPath+"."+fields[1]] {
				return fmt.Errorf("unapproved single-argument linkname %q in %s", line, pkgPath)
			}
			return nil
		}
		target := fields[2]
		if !strings.HasPrefix(target, pkgPath+".") && !cprep.AllowedPureLinknameTargets[target] {
			return fmt.Errorf("unapproved pure-package linkname target %q", target)
		}
		return nil
	})
}

// scanOffSurfaceGoDirectives scans Go source comments in an off-surface package
// for linkname and cgo directives.
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
		fields, ok := cprep.ParseGoLinknameLineFields(line)
		if !ok {
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

// directiveTouchesScannerHooks reports whether any Go compiler directive in src
// is malformed/unparseable or references go/internal/scannerhooks.
func directiveTouchesScannerHooks(src string) bool {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	scanErr := false
	var s scanner.Scanner
	s.Init(file, []byte(src), func(_ token.Position, _ string) {
		scanErr = true
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
			return true
		}
		if strings.HasPrefix(lit, "//go:cgo_") && strings.Contains(lit, "scannerhooks") {
			return true
		}
		if !strings.HasPrefix(lit, "//go:linkname") {
			continue
		}
		line := strings.TrimSuffix(lit, "\r")
		if strings.ContainsRune(line, '\r') {
			return true
		}
		fields, ok := cprep.ParseGoLinknameLineFields(line)
		if !ok {
			return true
		}
		if len(fields) == 3 {
			if tPkg, _, ok := cprep.SplitLinknameTarget(fields[2]); ok {
				if tPkg == "go/internal/scannerhooks" {
					return true
				}
			} else if strings.Contains(fields[2], "scannerhooks") {
				return true
			}
		}
	}
	return scanErr
}

// collectGoLinknameTargets records runtime.* and cross-package linkname targets in src.
func collectGoLinknameTargets(selfPkg, src string, runtimeOut, externalOut map[string]bool) {
	if externalOut != nil && selfPkg != "go/internal/scannerhooks" && directiveTouchesScannerHooks(src) {
		externalOut["go/internal/scannerhooks.*"] = true
	}
	scanOffSurfaceGoDirectives(src, runtimeOut, func(_, target string) {
		if strings.HasPrefix(target, "runtime.") {
			if runtimeOut != nil {
				runtimeOut[target] = true
			}
		} else if externalOut != nil {
			if tPkg, _, ok := cprep.SplitLinknameTarget(target); ok && tPkg != selfPkg {
				externalOut[target] = true
			}
		}
	})
}
