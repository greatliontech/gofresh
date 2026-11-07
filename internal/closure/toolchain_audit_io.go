package closure

import (
	"fmt"
	"go/ast"
	"go/token"
	"maps"
	"slices"
	"strconv"
	"strings"
)

func verifyOSPackageAST(files []*ast.File, osRuntimePullMap map[string]string, osAnyLinknameLocals map[string]bool) ([]string, error) {
	osReserved := map[string]bool{
		"testlog": true, "io": true, "syscall": true, "unsafe": true, "fs": true, "errors": true, "runtime": true,
		"nil": true, "true": true, "false": true, "len": true, "panic": true,
		"error": true, "int": true, "uintptr": true, "string": true, "byte": true, "bool": true,
		"File": true, "file": true, "ErrInvalid": true, "ErrClosed": true, "PathError": true,
	}
	osNoFileReserved := map[string]bool{
		"testlog": true, "io": true, "syscall": true, "unsafe": true, "fs": true, "errors": true, "runtime": true,
		"nil": true, "true": true, "false": true, "len": true, "panic": true,
		"error": true, "int": true, "uintptr": true, "string": true, "byte": true, "bool": true,
		"File": true, "ErrInvalid": true, "ErrClosed": true, "PathError": true,
	}
	osPkgScopeReserved := map[string]bool{
		"testlog": true, "io": true, "syscall": true, "unsafe": true, "fs": true, "errors": true, "runtime": true,
		"nil": true, "true": true, "false": true, "len": true, "panic": true,
		"error": true, "int": true, "uintptr": true, "string": true, "byte": true, "bool": true,
	}
	rawFileMethodShadowsReserved := func(fn *ast.FuncDecl) bool {
		if fn == nil {
			return true
		}
		if recv := recvVarName(fn); recv != "" && osNoFileReserved[recv] {
			return true
		}
		if fn.Type != nil {
			for _, flist := range []*ast.FieldList{fn.Type.Params, fn.Type.Results} {
				if flist == nil {
					continue
				}
				for _, f := range flist.List {
					for _, id := range f.Names {
						if osNoFileReserved[id.Name] {
							return true
						}
					}
				}
			}
		}
		return bodyDeclaresAnyIdent(fn.Body, osNoFileReserved)
	}
	requiredBoundaryFuncs := map[string]bool{
		"Getenv": true, "LookupEnv": true, "Open": true, "Create": true,
		"OpenFile": true, "openFileNolog": true, "openDir": true, "ReadFile": true, "ReadDir": true,
		"Stat": true, "Lstat": true, "Chdir": true, "Getwd": true, "Exit": true, "fixCount": true,
	}
	requiredFileSinkMethods := map[string]bool{
		"Write": true, "WriteString": true, "Close": true,
		"write": true, "checkValid": true, "wrapErr": true,
		"Fd": true, "fd": true,
	}
	requiredRawFileMethods := map[string]bool{
		"close": true, "decref": true, "destroy": true,
	}

	var importsTestlog bool
	fileImportsTestlog := map[*ast.File]bool{}
	fileImportsIO := map[*ast.File]bool{}
	fileImportsSyscall := map[*ast.File]bool{}
	fileImportsUnsafe := map[*ast.File]bool{}
	fileImportsIOFS := map[*ast.File]bool{}
	fileImportsErrors := map[*ast.File]bool{}
	fileImportsRuntime := map[*ast.File]bool{}
	funcFile := map[*ast.FuncDecl]*ast.File{}
	pkgDeclCounts := map[string]int{}
	hasErrInvalidInit := false
	hasErrClosedInit := false
	osErrConstCand := map[string]bool{}
	osErrVarCand := map[string]bool{}
	nonAliasStructSpecs := map[string]*ast.TypeSpec{}

	topFuncs := map[string]*ast.FuncDecl{}
	allTopFuncs := map[string]*ast.FuncDecl{}
	fileMethods := map[string]*ast.FuncDecl{}
	allFileMethods := map[string]*ast.FuncDecl{}
	fileMethodCounts := map[string]int{}
	rawFileMethods := map[string]*ast.FuncDecl{}
	allRawFileMethods := map[string]*ast.FuncDecl{}
	rawFileMethodCounts := map[string]int{}
	allFileStatMethods := map[string]*ast.FuncDecl{}
	fileStatMethodCounts := map[string]int{}
	var dirInfoCloseFn *ast.FuncDecl
	var fileTypeSpec, rawFileTypeSpec *ast.TypeSpec

	isNonEmptyStringLit := func(expr ast.Expr) bool {
		lit, ok := unwrapParens(expr).(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return false
		}
		unq, err := strconv.Unquote(lit.Value)
		return err == nil && unq != ""
	}

	isVerifiedOSSentinelInit := func(f *ast.File, name string, expr ast.Expr) bool {
		if expr == nil {
			return false
		}
		if fileImportsIOFS[f] {
			if _, ok := isSelectorBaseField(expr, "fs", name); ok {
				return true
			}
		}
		if fileImportsErrors[f] {
			if call, ok := unwrapParens(expr).(*ast.CallExpr); ok && !call.Ellipsis.IsValid() && len(call.Args) == 1 {
				if _, okSel := isSelectorBaseField(call.Fun, "errors", "New"); okSel {
					if isNonEmptyStringLit(call.Args[0]) {
						return true
					}
				}
			}
		}
		return false
	}

	isVerifiedNonNilOSErrVarInit := func(f *ast.File, expr ast.Expr) bool {
		if expr == nil {
			return false
		}
		if fileImportsIOFS[f] {
			if sel, okS := unwrapParens(expr).(*ast.SelectorExpr); okS {
				if _, okFS := isIdentNamed(sel.X, "fs"); okFS && strings.HasPrefix(sel.Sel.Name, "Err") {
					return true
				}
			}
		}
		if fileImportsErrors[f] {
			if call, ok := unwrapParens(expr).(*ast.CallExpr); ok && !call.Ellipsis.IsValid() && len(call.Args) == 1 {
				if _, okSel := isSelectorBaseField(call.Fun, "errors", "New"); okSel && isNonEmptyStringLit(call.Args[0]) {
					return true
				}
			}
		}
		if fileImportsSyscall[f] {
			if call, ok := unwrapParens(expr).(*ast.CallExpr); ok && !call.Ellipsis.IsValid() && len(call.Args) == 1 {
				if _, okSel := isSelectorBaseField(call.Fun, "syscall", "NewError"); okSel && isNonEmptyStringLit(call.Args[0]) {
					return true
				}
			}
		}
		return false
	}

	for _, f := range files {
		for _, imp := range f.Imports {
			importPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return nil, err
			}
			if imp.Name != nil && (imp.Name.Name == "." || osReserved[imp.Name.Name]) {
				return nil, fmt.Errorf("os: forbidden or shadowing import alias %q", imp.Name.Name)
			}
			switch importPath {
			case "internal/testlog":
				if imp.Name != nil {
					return nil, fmt.Errorf("os: aliased import of internal/testlog forbidden")
				}
				importsTestlog = true
				fileImportsTestlog[f] = true
			case "io":
				if imp.Name != nil {
					return nil, fmt.Errorf("os: aliased import of io forbidden")
				}
				fileImportsIO[f] = true
			case "syscall":
				if imp.Name != nil {
					return nil, fmt.Errorf("os: aliased import of syscall forbidden")
				}
				fileImportsSyscall[f] = true
			case "unsafe":
				if imp.Name != nil && imp.Name.Name != "_" {
					return nil, fmt.Errorf("os: aliased import of unsafe forbidden")
				}
				if imp.Name == nil {
					fileImportsUnsafe[f] = true
				}
			case "io/fs":
				if imp.Name != nil {
					return nil, fmt.Errorf("os: aliased import of io/fs forbidden")
				}
				fileImportsIOFS[f] = true
			case "errors":
				if imp.Name != nil {
					return nil, fmt.Errorf("os: aliased import of errors forbidden")
				}
				fileImportsErrors[f] = true
			case "runtime":
				if imp.Name != nil {
					return nil, fmt.Errorf("os: aliased import of runtime forbidden")
				}
				fileImportsRuntime[f] = true
			}
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.ValueSpec:
						for idx, id := range sp.Names {
							if osPkgScopeReserved[id.Name] {
								return nil, fmt.Errorf("os: package declaration shadows %s", id.Name)
							}
							if id.Name != "_" {
								pkgDeclCounts[id.Name]++
							}
							if d.Tok == token.CONST && id.Name != "_" && sp.Type == nil && len(sp.Values) == len(sp.Names) && fileImportsSyscall[f] {
								if sel, okS := unwrapParens(sp.Values[idx]).(*ast.SelectorExpr); okS {
									if _, okSys := isIdentNamed(sel.X, "syscall"); okSys && strings.HasPrefix(sel.Sel.Name, "E") {
										osErrConstCand[id.Name] = true
									}
								}
							}
							if d.Tok == token.VAR && id.Name != "_" && len(sp.Values) == len(sp.Names) && isVerifiedNonNilOSErrVarInit(f, sp.Values[idx]) {
								osErrVarCand[id.Name] = true
							}
							if d.Tok == token.VAR && (id.Name == "ErrInvalid" || id.Name == "ErrClosed") {
								if len(sp.Values) != len(sp.Names) || !isVerifiedOSSentinelInit(f, id.Name, sp.Values[idx]) {
									return nil, fmt.Errorf("os: %s must have non-nil initializer", id.Name)
								}
								if id.Name == "ErrInvalid" {
									hasErrInvalidInit = true
								} else {
									hasErrClosedInit = true
								}
							}
						}
					case *ast.TypeSpec:
						if sp.Name != nil {
							if osPkgScopeReserved[sp.Name.Name] {
								return nil, fmt.Errorf("os: type declaration shadows %s", sp.Name.Name)
							}
							if sp.Name.Name != "_" {
								pkgDeclCounts[sp.Name.Name]++
								if !sp.Assign.IsValid() {
									if _, okST := unwrapParens(sp.Type).(*ast.StructType); okST {
										nonAliasStructSpecs[sp.Name.Name] = sp
									}
								}
							}
							switch sp.Name.Name {
							case "File":
								fileTypeSpec = sp
							case "file":
								rawFileTypeSpec = sp
							}
						}
					}
				}
			case *ast.FuncDecl:
				funcFile[d] = f
				if d.Recv == nil {
					if osReserved[d.Name.Name] {
						return nil, fmt.Errorf("os: function declaration shadows %s", d.Name.Name)
					}
					if d.Name.Name != "init" && d.Name.Name != "_" {
						pkgDeclCounts[d.Name.Name]++
						allTopFuncs[d.Name.Name] = d
					}
					if requiredBoundaryFuncs[d.Name.Name] {
						if d.Body == nil {
							return nil, fmt.Errorf("os: boundary function %s cannot be bodyless", d.Name.Name)
						}
						if _, dup := topFuncs[d.Name.Name]; dup {
							return nil, fmt.Errorf("os: duplicate boundary function %s", d.Name.Name)
						}
						topFuncs[d.Name.Name] = d
					}
				} else if len(d.Recv.List) == 1 {
					rType := recvTypeName(d.Recv.List[0].Type)
					_, isPtrRecv := unwrapParens(d.Recv.List[0].Type).(*ast.StarExpr)
					switch rType {
					case "File":
						fileMethodCounts[d.Name.Name]++
						allFileMethods[d.Name.Name] = d
						if requiredFileSinkMethods[d.Name.Name] {
							if !isPtrRecv || d.Body == nil {
								return nil, fmt.Errorf("os: File.%s must be a concrete pointer-receiver method", d.Name.Name)
							}
							if _, dup := fileMethods[d.Name.Name]; dup {
								return nil, fmt.Errorf("os: duplicate (*File).%s method", d.Name.Name)
							}
							fileMethods[d.Name.Name] = d
						}
					case "file":
						rawFileMethodCounts[d.Name.Name]++
						allRawFileMethods[d.Name.Name] = d
						if requiredRawFileMethods[d.Name.Name] {
							if !isPtrRecv || d.Body == nil {
								return nil, fmt.Errorf("os: file.%s must be a concrete pointer-receiver method", d.Name.Name)
							}
							if _, dup := rawFileMethods[d.Name.Name]; dup {
								return nil, fmt.Errorf("os: duplicate (*file).%s method", d.Name.Name)
							}
							rawFileMethods[d.Name.Name] = d
						}
					case "fileStat":
						fileStatMethodCounts[d.Name.Name]++
						allFileStatMethods[d.Name.Name] = d
					case "dirInfo":
						if d.Name.Name == "close" {
							if !isPtrRecv || d.Body == nil || dirInfoCloseFn != nil {
								return nil, fmt.Errorf("os: invalid or duplicate (*dirInfo).close")
							}
							dirInfoCloseFn = d
						}
					}
				}
			}
		}
	}
	if !importsTestlog {
		return nil, fmt.Errorf("os: missing internal/testlog import")
	}
	if !hasErrInvalidInit || pkgDeclCounts["ErrInvalid"] != 1 || !hasErrClosedInit || pkgDeclCounts["ErrClosed"] != 1 {
		return nil, fmt.Errorf("os: missing unique non-nil ErrInvalid/ErrClosed sentinel declarations")
	}
	if err := verifyOSFileStructTypes(fileTypeSpec, rawFileTypeSpec, pkgDeclCounts); err != nil {
		return nil, err
	}
	if err := verifyOSExitIntegrity(files, topFuncs["Exit"], funcFile, fileImportsTestlog, fileImportsSyscall, osReserved); err != nil {
		return nil, err
	}

	// Ensure ErrInvalid and ErrClosed are never reassigned or address-taken anywhere in os,
	// and collect unmutated non-nil package error identifiers.
	mutatedErrVarCands := map[string]bool{}
	for _, f := range files {
		sentinelMutated := false
		ast.Inspect(f, func(n ast.Node) bool {
			if sentinelMutated || n == nil {
				return false
			}
			markMut := func(expr ast.Expr) {
				id, ok := unwrapParens(expr).(*ast.Ident)
				if !ok {
					return
				}
				if id.Name == "ErrInvalid" || id.Name == "ErrClosed" {
					sentinelMutated = true
				}
				if osErrVarCand[id.Name] {
					mutatedErrVarCands[id.Name] = true
				}
			}
			switch node := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					markMut(lhs)
				}
			case *ast.RangeStmt:
				if node.Key != nil {
					markMut(node.Key)
				}
				if node.Value != nil {
					markMut(node.Value)
				}
			case *ast.IncDecStmt:
				markMut(node.X)
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					markMut(node.X)
				}
			}
			return !sentinelMutated
		})
		if sentinelMutated {
			return nil, fmt.Errorf("os: ErrInvalid or ErrClosed mutated or address-taken")
		}
	}
	verifiedNonNilOSErrIdents := map[string]bool{
		"ErrInvalid": true,
		"ErrClosed":  true,
	}
	for name := range osErrConstCand {
		if pkgDeclCounts[name] == 1 && !osAnyLinknameLocals[name] {
			verifiedNonNilOSErrIdents[name] = true
		}
	}
	for name := range osErrVarCand {
		if pkgDeclCounts[name] == 1 && !osAnyLinknameLocals[name] && !mutatedErrVarCands[name] {
			verifiedNonNilOSErrIdents[name] = true
		}
	}

	osInactive := discoverOSInactiveState(files, osRuntimePullMap, osAnyLinknameLocals)
	usedRuntimeGates := map[string]bool{}
	skipInactiveHookIf := func(stmt ast.Stmt, fn *ast.FuncDecl) bool {
		gates, ok := osInactive.checkInactiveHookIf(stmt, fn)
		if !ok {
			return false
		}
		for _, g := range gates {
			if g != "" {
				usedRuntimeGates[g] = true
			}
		}
		return true
	}

	isDirectTestlogCall := func(stmt ast.Stmt, hookName, wantArg string) bool {
		es, ok := stmt.(*ast.ExprStmt)
		if !ok {
			return false
		}
		call, ok := unwrapParens(es.X).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) != 1 {
			return false
		}
		if _, okArg := isIdentNamed(call.Args[0], wantArg); !okArg {
			return false
		}
		_, okSel := isSelectorBaseField(call.Fun, "testlog", hookName)
		return okSel
	}

	firstParamChecked := func(fn *ast.FuncDecl, minParams int, needTestlogImport bool) (string, error) {
		if fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.Params == nil {
			return "", fmt.Errorf("missing function")
		}
		if needTestlogImport && !fileImportsTestlog[funcFile[fn]] {
			return "", fmt.Errorf("file defining %s missing internal/testlog import", fn.Name.Name)
		}
		if funcShadowsAnyIdent(fn, osReserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
			return "", fmt.Errorf("function %s shadows reserved identifier or has control-flow/recover bypass", fn.Name.Name)
		}
		pNames := paramNamesFlat(fn.Type.Params)
		if len(pNames) < minParams || pNames[0] == "" || pNames[0] == "_" {
			return "", fmt.Errorf("function %s invalid first parameter", fn.Name.Name)
		}
		return pNames[0], nil
	}

	// 1. Getenv(key) & LookupEnv(key): Body.List[0] must be testlog.Getenv(p0).
	for _, fnName := range []string{"Getenv", "LookupEnv"} {
		fn := topFuncs[fnName]
		p0, err := firstParamChecked(fn, 1, true)
		if err != nil {
			return nil, fmt.Errorf("os: %s: %w", fnName, err)
		}
		if len(fn.Body.List) < 2 || !isDirectTestlogCall(fn.Body.List[0], "Getenv", p0) {
			return nil, fmt.Errorf("os: %s must execute testlog.Getenv(%s) as its first statement", fnName, p0)
		}
	}

	// 2. Open(name) & Create(name): single return delegating to OpenFile(p0, ...).
	for _, fnName := range []string{"Open", "Create"} {
		fn := topFuncs[fnName]
		p0, err := firstParamChecked(fn, 1, false)
		if err != nil {
			return nil, fmt.Errorf("os: %s: %w", fnName, err)
		}
		if len(fn.Body.List) != 1 {
			return nil, fmt.Errorf("os: %s must be a single-statement delegation to OpenFile", fnName)
		}
		ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return nil, fmt.Errorf("os: %s must return OpenFile(%s, ...)", fnName, p0)
		}
		call, ok := unwrapParens(ret.Results[0]).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) != 3 {
			return nil, fmt.Errorf("os: %s invalid OpenFile call arity", fnName)
		}
		if _, okFun := isIdentNamed(call.Fun, "OpenFile"); !okFun {
			return nil, fmt.Errorf("os: %s does not call OpenFile", fnName)
		}
		if _, okArg := isIdentNamed(call.Args[0], p0); !okArg {
			return nil, fmt.Errorf("os: %s does not forward %s to OpenFile", fnName, p0)
		}
	}

	// 3. OpenFile(name, flag, perm), openFileNolog(name, flag, perm), & openDir(name).
	{
		ofFn := topFuncs["OpenFile"]
		p0, err := firstParamChecked(ofFn, 3, true)
		if err != nil {
			return nil, fmt.Errorf("os: OpenFile: %w", err)
		}
		ofParams := paramNamesFlat(ofFn.Type.Params)
		if len(ofParams) != 3 || ofParams[1] == "" || ofParams[1] == "_" || ofParams[2] == "" || ofParams[2] == "_" {
			return nil, fmt.Errorf("os: OpenFile invalid parameters")
		}
		if bodyMutatesOrTakesAddrOfAny(ofFn.Body, map[string]bool{p0: true, ofParams[1]: true, ofParams[2]: true}) || bodyDeclaresAnyIdent(ofFn.Body, map[string]bool{p0: true, ofParams[1]: true, ofParams[2]: true}) {
			return nil, fmt.Errorf("os: OpenFile mutates or shadows parameters")
		}
		if len(ofFn.Body.List) < 2 || !isDirectTestlogCall(ofFn.Body.List[0], "Open", p0) {
			return nil, fmt.Errorf("os: OpenFile must execute testlog.Open(%s) as its first statement", p0)
		}
		isOpenFileNologCall := func(expr ast.Expr) bool {
			c, okC := unwrapParens(expr).(*ast.CallExpr)
			if !okC || c.Ellipsis.IsValid() || len(c.Args) != 3 {
				return false
			}
			_, okF := isIdentNamed(c.Fun, "openFileNolog")
			_, ok0 := isIdentNamed(c.Args[0], p0)
			_, ok1 := isIdentNamed(c.Args[1], ofParams[1])
			_, ok2 := isIdentNamed(c.Args[2], ofParams[2])
			return okF && ok0 && ok1 && ok2
		}
		openFileOK := false
		if len(ofFn.Body.List) == 2 {
			if ret, okR := ofFn.Body.List[1].(*ast.ReturnStmt); okR && len(ret.Results) == 1 && isOpenFileNologCall(ret.Results[0]) {
				openFileOK = true
			}
		} else if len(ofFn.Body.List) >= 4 {
			as, okAs := ofFn.Body.List[1].(*ast.AssignStmt)
			ifs, okIf := ofFn.Body.List[2].(*ast.IfStmt)
			retLast, okRet := ofFn.Body.List[len(ofFn.Body.List)-1].(*ast.ReturnStmt)
			if okAs && as.Tok == token.DEFINE && len(as.Lhs) == 2 && len(as.Rhs) == 1 && isOpenFileNologCall(as.Rhs[0]) && okIf && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 && okRet && len(retLast.Results) == 2 {
				fID, okF := unwrapParens(as.Lhs[0]).(*ast.Ident)
				eID, okE := unwrapParens(as.Lhs[1]).(*ast.Ident)
				if okF && okE && fID.Name != "" && fID.Name != "_" && eID.Name != "" && eID.Name != "_" && fID.Name != eID.Name && condChecksNonZeroErr(ifs.Cond) == eID.Name {
					if errRet, okER := ifs.Body.List[0].(*ast.ReturnStmt); okER && len(errRet.Results) == 2 {
						_, okNil0 := isIdentNamed(errRet.Results[0], "nil")
						_, okErr1 := isIdentNamed(errRet.Results[1], eID.Name)
						_, okRetF := isIdentNamed(retLast.Results[0], fID.Name)
						_, okRetNil := isIdentNamed(retLast.Results[1], "nil")
						midOK := okNil0 && okErr1 && okRetF && okRetNil && !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: ofFn.Body.List[2:]}, map[string]bool{fID.Name: true})
						for _, mid := range ofFn.Body.List[3 : len(ofFn.Body.List)-1] {
							mAs, okM := mid.(*ast.AssignStmt)
							if !okM || mAs.Tok != token.ASSIGN || len(mAs.Lhs) != 1 || len(mAs.Rhs) != 1 {
								midOK = false
								break
							}
							sel, okS := unwrapParens(mAs.Lhs[0]).(*ast.SelectorExpr)
							if !okS {
								midOK = false
								break
							}
							_, okBase := isIdentNamed(sel.X, fID.Name)
							if !okBase || sel.Sel.Name == "file" || sel.Sel.Name == "pfd" || sel.Sel.Name == "sysfd" || sel.Sel.Name == "name" || exprContainsAnyCall(mAs.Rhs[0]) {
								midOK = false
								break
							}
						}
						openFileOK = midOK
					}
				}
			}
		}
		if !openFileOK {
			return nil, fmt.Errorf("os: OpenFile must delegate directly to openFileNolog")
		}
		if err := verifyOSOpenFileNolog(topFuncs["openFileNolog"], allTopFuncs, funcFile, fileImportsSyscall, osNoFileReserved, osAnyLinknameLocals, skipInactiveHookIf); err != nil {
			return nil, err
		}

		odFn := topFuncs["openDir"]
		odP0, err := firstParamChecked(odFn, 1, true)
		if err != nil {
			return nil, fmt.Errorf("os: openDir: %w", err)
		}
		if len(odFn.Body.List) < 2 || !isDirectTestlogCall(odFn.Body.List[0], "Open", odP0) {
			return nil, fmt.Errorf("os: openDir must execute testlog.Open(%s) as its first statement", odP0)
		}
	}

	// 4. ReadFile(name) & ReadDir(name).
	{
		rfFn := topFuncs["ReadFile"]
		rfP0, err := firstParamChecked(rfFn, 1, false)
		if err != nil {
			return nil, fmt.Errorf("os: ReadFile: %w", err)
		}
		if err := verifyOSReadFile(rfFn, rfP0, allTopFuncs, allFileMethods, allRawFileMethods, osNoFileReserved, osAnyLinknameLocals, skipInactiveHookIf); err != nil {
			return nil, err
		}

		rdFn := topFuncs["ReadDir"]
		rdP0, err := firstParamChecked(rdFn, 1, false)
		if err != nil {
			return nil, fmt.Errorf("os: ReadDir: %w", err)
		}
		if len(rdFn.Body.List) < 2 {
			return nil, fmt.Errorf("os: ReadDir missing body statements")
		}
		as, ok := rdFn.Body.List[0].(*ast.AssignStmt)
		if !ok || (as.Tok != token.DEFINE && as.Tok != token.ASSIGN) || len(as.Lhs) != 2 || len(as.Rhs) != 1 {
			return nil, fmt.Errorf("os: ReadDir first statement must bind logged open result")
		}
		call, ok := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) < 1 {
			return nil, fmt.Errorf("os: ReadDir invalid open call")
		}
		calleeID, ok := unwrapParens(call.Fun).(*ast.Ident)
		if !ok || (calleeID.Name != "openDir" && calleeID.Name != "Open" && calleeID.Name != "OpenFile") {
			return nil, fmt.Errorf("os: ReadDir first statement does not call logged open helper")
		}
		if _, okArg := isIdentNamed(call.Args[0], rdP0); !okArg {
			return nil, fmt.Errorf("os: ReadDir does not forward %s to %s", rdP0, calleeID.Name)
		}
	}

	// 5. Stat(name) & Lstat(name): optional verified inactive hook then testlog.Stat(p0).
	for _, fnName := range []string{"Stat", "Lstat"} {
		fn := topFuncs[fnName]
		p0, err := firstParamChecked(fn, 1, true)
		if err != nil {
			return nil, fmt.Errorf("os: %s: %w", fnName, err)
		}
		pos := 0
		for pos < len(fn.Body.List) && skipInactiveHookIf(fn.Body.List[pos], fn) {
			pos++
		}
		if len(fn.Body.List) < pos+2 || !isDirectTestlogCall(fn.Body.List[pos], "Stat", p0) {
			return nil, fmt.Errorf("os: %s must execute testlog.Stat(%s) before stat syscall", fnName, p0)
		}
	}

	// 6. Chdir(dir) & Getwd(): optional verified inactive hook, syscall.Chdir(p0) error-branch testlog.Open(p0),
	// verified mid-statements, testlog.Logger().Chdir(wd) on success, return nil; plus Getwd() integrity.
	{
		fn := topFuncs["Chdir"]
		p0, err := firstParamChecked(fn, 1, true)
		if err != nil {
			return nil, fmt.Errorf("os: Chdir: %w", err)
		}
		if !fileImportsSyscall[funcFile[fn]] {
			return nil, fmt.Errorf("os: file defining Chdir missing syscall import")
		}
		pos := 0
		for pos < len(fn.Body.List) && skipInactiveHookIf(fn.Body.List[pos], fn) {
			pos++
		}
		if len(fn.Body.List) < pos+3 {
			return nil, fmt.Errorf("os: Chdir body too short")
		}
		if bodyMutatesOrTakesAddrOfAny(fn.Body, map[string]bool{p0: true}) || bodyDeclaresAnyIdent(fn.Body, map[string]bool{p0: true}) {
			return nil, fmt.Errorf("os: Chdir mutates or shadows parameter %s", p0)
		}
		ifs0, ok := fn.Body.List[pos].(*ast.IfStmt)
		if !ok || ifs0.Init == nil || ifs0.Else != nil || len(ifs0.Body.List) != 2 {
			return nil, fmt.Errorf("os: Chdir missing syscall.Chdir error guard")
		}
		initAs, ok := ifs0.Init.(*ast.AssignStmt)
		if !ok || initAs.Tok != token.DEFINE || len(initAs.Lhs) != 1 || len(initAs.Rhs) != 1 {
			return nil, fmt.Errorf("os: Chdir invalid syscall.Chdir init assignment")
		}
		eID, ok := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
		sysCall, okC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
		if !ok || !okC || eID.Name == "" || eID.Name == "_" || condChecksNonZeroErr(ifs0.Cond) != eID.Name || sysCall.Ellipsis.IsValid() || len(sysCall.Args) != 1 {
			return nil, fmt.Errorf("os: Chdir invalid syscall.Chdir condition or call")
		}
		if _, okSel := isSelectorBaseField(sysCall.Fun, "syscall", "Chdir"); !okSel {
			return nil, fmt.Errorf("os: Chdir does not call syscall.Chdir")
		}
		if _, okArg := isIdentNamed(sysCall.Args[0], p0); !okArg {
			return nil, fmt.Errorf("os: Chdir does not pass %s to syscall.Chdir", p0)
		}
		if !isDirectTestlogCall(ifs0.Body.List[0], "Open", p0) {
			return nil, fmt.Errorf("os: Chdir failure branch missing testlog.Open(%s)", p0)
		}
		errRet, ok := ifs0.Body.List[1].(*ast.ReturnStmt)
		if !ok || len(errRet.Results) != 1 {
			return nil, fmt.Errorf("os: Chdir failure branch invalid return")
		}
		_, okDirectChdirErr := isIdentNamed(errRet.Results[0], eID.Name)
		uChdirErr, okUChdir := unwrapParens(errRet.Results[0]).(*ast.UnaryExpr)
		_, tChdirErr := compositeWriterLit(errRet.Results[0])
		if !okDirectChdirErr && (!okUChdir || uChdirErr.Op != token.AND || tChdirErr != "PathError") {
			return nil, fmt.Errorf("os: Chdir failure branch must return %s or &PathError", eID.Name)
		}
		for _, mid := range fn.Body.List[pos+1 : len(fn.Body.List)-2] {
			badMid := false
			ast.Inspect(mid, func(n ast.Node) bool {
				if badMid || n == nil {
					return false
				}
				switch call := n.(type) {
				case *ast.ReturnStmt, *ast.DeferStmt, *ast.GoStmt, *ast.FuncLit, *ast.BranchStmt, *ast.LabeledStmt:
					badMid = true
					return false
				case *ast.CallExpr:
					if call.Ellipsis.IsValid() {
						badMid = true
						return false
					}
					sel, okS := unwrapParens(call.Fun).(*ast.SelectorExpr)
					if !okS {
						badMid = true
						return false
					}
					if _, okBase := unwrapParens(sel.X).(*ast.Ident); !okBase {
						badMid = true
						return false
					}
					switch sel.Sel.Name {
					case "Lock", "Unlock":
						if len(call.Args) != 0 {
							badMid = true
							return false
						}
					case "IsAbs":
						if len(call.Args) != 1 {
							badMid = true
							return false
						}
						if _, okP0 := isIdentNamed(call.Args[0], p0); !okP0 {
							badMid = true
							return false
						}
					default:
						badMid = true
						return false
					}
				}
				return true
			})
			if badMid {
				return nil, fmt.Errorf("os: Chdir has forbidden control flow or call before testlog.Logger().Chdir")
			}
		}
		logIf, ok := fn.Body.List[len(fn.Body.List)-2].(*ast.IfStmt)
		if !ok || logIf.Init == nil || logIf.Else != nil || len(logIf.Body.List) != 2 {
			return nil, fmt.Errorf("os: Chdir missing testlog.Logger() block")
		}
		logInit, ok := logIf.Init.(*ast.AssignStmt)
		if !ok || logInit.Tok != token.DEFINE || len(logInit.Lhs) != 1 || len(logInit.Rhs) != 1 {
			return nil, fmt.Errorf("os: Chdir invalid testlog.Logger() assignment")
		}
		logID, ok1 := unwrapParens(logInit.Lhs[0]).(*ast.Ident)
		logCall, ok2 := unwrapParens(logInit.Rhs[0]).(*ast.CallExpr)
		if !ok1 || !ok2 || logID.Name == "" || logID.Name == "_" || condChecksNonZeroErr(logIf.Cond) != logID.Name || logCall.Ellipsis.IsValid() || len(logCall.Args) != 0 {
			return nil, fmt.Errorf("os: Chdir invalid testlog.Logger() guard")
		}
		if _, okSel := isSelectorBaseField(logCall.Fun, "testlog", "Logger"); !okSel {
			return nil, fmt.Errorf("os: Chdir does not call testlog.Logger()")
		}
		wdAs, ok := logIf.Body.List[0].(*ast.AssignStmt)
		if !ok || wdAs.Tok != token.DEFINE || len(wdAs.Lhs) != 2 || len(wdAs.Rhs) != 1 {
			return nil, fmt.Errorf("os: Chdir missing Getwd() assignment")
		}
		wdID, ok1 := unwrapParens(wdAs.Lhs[0]).(*ast.Ident)
		wdErrID, ok2 := unwrapParens(wdAs.Lhs[1]).(*ast.Ident)
		wdCall, ok3 := unwrapParens(wdAs.Rhs[0]).(*ast.CallExpr)
		if !ok1 || !ok2 || !ok3 || wdID.Name == "" || wdID.Name == "_" || wdErrID.Name == "" || wdErrID.Name == "_" || wdCall.Ellipsis.IsValid() || len(wdCall.Args) != 0 {
			return nil, fmt.Errorf("os: Chdir invalid Getwd() call")
		}
		if _, okFun := isIdentNamed(wdCall.Fun, "Getwd"); !okFun {
			return nil, fmt.Errorf("os: Chdir does not call Getwd()")
		}
		wdIf, ok := logIf.Body.List[1].(*ast.IfStmt)
		if !ok || wdIf.Init != nil || wdIf.Else != nil || !condChecksEqErr(wdIf.Cond, wdErrID.Name) || len(wdIf.Body.List) != 1 {
			return nil, fmt.Errorf("os: Chdir missing if err == nil guard around log.Chdir")
		}
		chES, ok := wdIf.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return nil, fmt.Errorf("os: Chdir log.Chdir not an expression statement")
		}
		chCall, ok := unwrapParens(chES.X).(*ast.CallExpr)
		if !ok || chCall.Ellipsis.IsValid() || len(chCall.Args) != 1 {
			return nil, fmt.Errorf("os: Chdir invalid log.Chdir call")
		}
		if _, okSel := isSelectorBaseField(chCall.Fun, logID.Name, "Chdir"); !okSel {
			return nil, fmt.Errorf("os: Chdir does not call %s.Chdir", logID.Name)
		}
		if _, okArg := isIdentNamed(chCall.Args[0], wdID.Name); !okArg {
			return nil, fmt.Errorf("os: Chdir does not pass %s to %s.Chdir", wdID.Name, logID.Name)
		}
		retNil, ok := fn.Body.List[len(fn.Body.List)-1].(*ast.ReturnStmt)
		if !ok || len(retNil.Results) != 1 {
			return nil, fmt.Errorf("os: Chdir missing trailing return nil")
		}
		if _, okNil := isIdentNamed(retNil.Results[0], "nil"); !okNil {
			return nil, fmt.Errorf("os: Chdir trailing return is not nil")
		}
		if err := verifyOSGetwd(files, topFuncs["Getwd"], allTopFuncs, allFileMethods, allRawFileMethods, allFileStatMethods, nonAliasStructSpecs, pkgDeclCounts, fileMethodCounts, rawFileMethodCounts, fileStatMethodCounts, funcFile, fileImportsSyscall, verifiedNonNilOSErrIdents, osReserved, osNoFileReserved, osAnyLinknameLocals, osInactive, skipInactiveHookIf); err != nil {
			return nil, err
		}
	}

	// 7. Verify (*os.File) write/close/fd sink delivery: checkValid, wrapErr, Write, WriteString, write, Fd, fd, Close, (*file).close.
	{
		cvFn := fileMethods["checkValid"]
		if cvFn == nil || len(cvFn.Body.List) < 2 || funcShadowsAnyIdent(cvFn, osReserved) || bodyHasControlFlowOrRecoverBypass(cvFn.Body) {
			return nil, fmt.Errorf("os: missing or invalid (*File).checkValid")
		}
		cvRecv := recvVarName(cvFn)
		if cvRecv == "" || cvFn.Type.Params == nil || cvFn.Type.Params.NumFields() != 1 || !funcReturnsErrorLast(cvFn.Type) || cvFn.Type.Results.NumFields() != 1 {
			return nil, fmt.Errorf("os: (*File).checkValid invalid signature")
		}
		ifs, ok := cvFn.Body.List[0].(*ast.IfStmt)
		if !ok || ifs.Init != nil || ifs.Else != nil || !condChecksEqErr(ifs.Cond, cvRecv) || len(ifs.Body.List) != 1 {
			return nil, fmt.Errorf("os: (*File).checkValid missing nil receiver guard")
		}
		ret, ok := ifs.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return nil, fmt.Errorf("os: (*File).checkValid invalid nil return")
		}
		if _, okErr := isIdentNamed(ret.Results[0], "ErrInvalid"); !okErr {
			return nil, fmt.Errorf("os: (*File).checkValid does not return ErrInvalid")
		}
	}

	{
		weFn := fileMethods["wrapErr"]
		if weFn == nil || len(weFn.Body.List) < 2 || funcShadowsAnyIdent(weFn, osReserved) || bodyHasControlFlowOrRecoverBypass(weFn.Body) || !blockAlwaysReturns(weFn.Body.List) {
			return nil, fmt.Errorf("os: missing or invalid (*File).wrapErr")
		}
		weParams := paramNamesFlat(weFn.Type.Params)
		if recvVarName(weFn) == "" || len(weParams) != 2 || weParams[1] == "" || weParams[1] == "_" || !funcReturnsErrorLast(weFn.Type) || weFn.Type.Results.NumFields() != 1 {
			return nil, fmt.Errorf("os: (*File).wrapErr invalid signature")
		}
		errParam := weParams[1]
		if bodyDeclaresAnyIdent(weFn.Body, map[string]bool{errParam: true}) {
			return nil, fmt.Errorf("os: (*File).wrapErr shadows error parameter")
		}
		badWrapErr := false
		ast.Inspect(weFn.Body, func(n ast.Node) bool {
			if badWrapErr || n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.DeferStmt, *ast.FuncLit:
				badWrapErr = true
				return false
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					if id, ok := unwrapParens(node.X).(*ast.Ident); ok && id.Name == errParam {
						badWrapErr = true
						return false
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range node.Lhs {
					if id, ok := unwrapParens(lhs).(*ast.Ident); ok && id.Name == errParam {
						if node.Tok != token.ASSIGN || i >= len(node.Rhs) {
							badWrapErr = true
							return false
						}
						if _, okEC := isIdentNamed(node.Rhs[i], "ErrClosed"); !okEC {
							badWrapErr = true
							return false
						}
					}
				}
			case *ast.ReturnStmt:
				if len(node.Results) != 1 {
					badWrapErr = true
					return false
				}
				if _, okID := isIdentNamed(node.Results[0], errParam); okID {
					return false
				}
				u, okU := unwrapParens(node.Results[0]).(*ast.UnaryExpr)
				_, tName := compositeWriterLit(node.Results[0])
				if !okU || u.Op != token.AND || tName != "PathError" {
					badWrapErr = true
					return false
				}
			}
			return true
		})
		if badWrapErr {
			return nil, fmt.Errorf("os: (*File).wrapErr may swallow non-nil error")
		}
	}

	{
		wFn := fileMethods["Write"]
		if wFn == nil || len(wFn.Body.List) < 5 || !fileImportsIO[funcFile[wFn]] || funcShadowsAnyIdent(wFn, osReserved) || bodyHasControlFlowOrRecoverBypass(wFn.Body) {
			return nil, fmt.Errorf("os: missing or invalid (*File).Write")
		}
		wRecv := recvVarName(wFn)
		wParams := paramNamesFlat(wFn.Type.Params)
		if wRecv == "" || len(wParams) != 1 || wParams[0] == "" || wParams[0] == "_" || wFn.Type.Results == nil || wFn.Type.Results.NumFields() != 2 || !firstResultIsInt(wFn.Type.Results) || !funcReturnsErrorLast(wFn.Type) {
			return nil, fmt.Errorf("os: (*File).Write invalid signature")
		}
		bParam := wParams[0]
		if bodyMutatesOrTakesAddrOfAny(wFn.Body, map[string]bool{wRecv: true, bParam: true}) || bodyDeclaresAnyIdent(wFn.Body, map[string]bool{wRecv: true, bParam: true}) {
			return nil, fmt.Errorf("os: (*File).Write mutates receiver or slice parameter")
		}
		// List[0]: if err := f.checkValid("write"); err != nil { return 0, err }
		s0, ok := wFn.Body.List[0].(*ast.IfStmt)
		if !ok || s0.Init == nil || s0.Else != nil || len(s0.Body.List) != 1 {
			return nil, fmt.Errorf("os: (*File).Write missing checkValid guard")
		}
		cvAs, ok := s0.Init.(*ast.AssignStmt)
		if !ok || (cvAs.Tok != token.DEFINE && cvAs.Tok != token.ASSIGN) || len(cvAs.Lhs) != 1 || len(cvAs.Rhs) != 1 {
			return nil, fmt.Errorf("os: (*File).Write invalid checkValid assignment")
		}
		cvErrID, ok1 := unwrapParens(cvAs.Lhs[0]).(*ast.Ident)
		cvCall, ok2 := unwrapParens(cvAs.Rhs[0]).(*ast.CallExpr)
		if !ok1 || !ok2 || cvErrID.Name == "" || cvErrID.Name == "_" || condChecksNonZeroErr(s0.Cond) != cvErrID.Name || cvCall.Ellipsis.IsValid() || len(cvCall.Args) != 1 {
			return nil, fmt.Errorf("os: (*File).Write invalid checkValid call")
		}
		if _, okSel := isSelectorBaseField(cvCall.Fun, wRecv, "checkValid"); !okSel {
			return nil, fmt.Errorf("os: (*File).Write does not call %s.checkValid", wRecv)
		}
		cvRet, ok := s0.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(cvRet.Results) != 2 || !isZeroIntLit(cvRet.Results[0]) {
			return nil, fmt.Errorf("os: (*File).Write invalid checkValid return")
		}
		if _, okErr := isIdentNamed(cvRet.Results[1], cvErrID.Name); !okErr {
			return nil, fmt.Errorf("os: (*File).Write checkValid does not propagate error")
		}

		// List[1]: n, e := f.write(b)
		s1, ok := wFn.Body.List[1].(*ast.AssignStmt)
		if !ok || (s1.Tok != token.DEFINE && s1.Tok != token.ASSIGN) || len(s1.Lhs) != 2 || len(s1.Rhs) != 1 {
			return nil, fmt.Errorf("os: (*File).Write missing %s.write(%s) assignment", wRecv, bParam)
		}
		nID, ok1 := unwrapParens(s1.Lhs[0]).(*ast.Ident)
		eID, ok2 := unwrapParens(s1.Lhs[1]).(*ast.Ident)
		wrCall, ok3 := unwrapParens(s1.Rhs[0]).(*ast.CallExpr)
		if !ok1 || !ok2 || !ok3 || nID.Name == "" || nID.Name == "_" || eID.Name == "" || eID.Name == "_" || nID.Name == eID.Name || wrCall.Ellipsis.IsValid() || len(wrCall.Args) != 1 {
			return nil, fmt.Errorf("os: (*File).Write invalid %s.write call", wRecv)
		}
		if _, okSel := isSelectorBaseField(wrCall.Fun, wRecv, "write"); !okSel {
			return nil, fmt.Errorf("os: (*File).Write does not call %s.write", wRecv)
		}
		if _, okArg := isIdentNamed(wrCall.Args[0], bParam); !okArg {
			return nil, fmt.Errorf("os: (*File).Write does not forward %s to %s.write", bParam, wRecv)
		}

		resNames := paramNamesFlat(wFn.Type.Results)
		var errVar string
		if len(resNames) == 2 && resNames[1] != "" && resNames[1] != "_" {
			errVar = resNames[1]
		}
		if errVar == eID.Name {
			return nil, fmt.Errorf("os: (*File).Write aliases raw error and returned error")
		}
		var sawShortWrite, sawWrapErr bool
		for idx := 2; idx < len(wFn.Body.List)-1; idx++ {
			st := wFn.Body.List[idx]
			if ifs, isIf := st.(*ast.IfStmt); isIf && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
				if bin, okB := unwrapParens(ifs.Cond).(*ast.BinaryExpr); okB {
					// Optional: if n < 0 { n = 0 }
					if bin.Op == token.LSS && isZeroIntLit(bin.Y) {
						if _, okN := isIdentNamed(bin.X, nID.Name); okN && !sawShortWrite {
							if as, okA := ifs.Body.List[0].(*ast.AssignStmt); okA && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 && isZeroIntLit(as.Rhs[0]) {
								if _, okNL := isIdentNamed(as.Lhs[0], nID.Name); okNL {
									continue
								}
							}
						}
					}
					// Required: if n != len(b) { err = io.ErrShortWrite }
					if bin.Op == token.NEQ && isLenOfIdentCall(bin.Y, bParam) {
						if _, okN := isIdentNamed(bin.X, nID.Name); okN && !sawShortWrite && !sawWrapErr {
							if as, okA := ifs.Body.List[0].(*ast.AssignStmt); okA && (as.Tok == token.ASSIGN || as.Tok == token.DEFINE) && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
								lhsErr, okL := unwrapParens(as.Lhs[0]).(*ast.Ident)
								_, okSW := isSelectorBaseField(as.Rhs[0], "io", "ErrShortWrite")
								if okL && okSW && lhsErr.Name != "" && lhsErr.Name != "_" && lhsErr.Name != nID.Name && lhsErr.Name != eID.Name && (errVar == "" || errVar == lhsErr.Name) {
									errVar = lhsErr.Name
									sawShortWrite = true
									continue
								}
							}
						}
					}
				}
				// Required: if e != nil { err = f.wrapErr("write", e) }
				if condChecksNonZeroErr(ifs.Cond) == eID.Name && sawShortWrite && !sawWrapErr && errVar != "" {
					if as, okA := ifs.Body.List[0].(*ast.AssignStmt); okA && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
						_, okL := isIdentNamed(as.Lhs[0], errVar)
						weCall, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
						if okL && okC && !weCall.Ellipsis.IsValid() && len(weCall.Args) == 2 {
							_, okSel := isSelectorBaseField(weCall.Fun, wRecv, "wrapErr")
							_, okArg := isIdentNamed(weCall.Args[1], eID.Name)
							if okSel && okArg {
								sawWrapErr = true
								continue
							}
						}
					}
				}
			}
			// Optional: epipecheck(f, e)
			if es, isES := st.(*ast.ExprStmt); isES {
				if c, okC := unwrapParens(es.X).(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) == 2 {
					_, ok0 := isIdentNamed(c.Args[0], wRecv)
					_, ok1 := isIdentNamed(c.Args[1], eID.Name)
					if cFun, okFun := unwrapParens(c.Fun).(*ast.Ident); okFun && cFun.Name == "epipecheck" && ok0 && ok1 {
						if err := verifyOSEpipecheck(allTopFuncs["epipecheck"], funcFile, fileImportsSyscall, osNoFileReserved, osAnyLinknameLocals); err != nil {
							return nil, err
						}
						continue
					}
				}
			}
			return nil, fmt.Errorf("os: (*File).Write unexpected statement at index %d", idx)
		}
		if !sawShortWrite || !sawWrapErr || errVar == "" {
			return nil, fmt.Errorf("os: (*File).Write missing ErrShortWrite or wrapErr propagation")
		}
		lastRet, ok := wFn.Body.List[len(wFn.Body.List)-1].(*ast.ReturnStmt)
		if !ok || len(lastRet.Results) != 2 {
			return nil, fmt.Errorf("os: (*File).Write invalid final return")
		}
		_, okRN := isIdentNamed(lastRet.Results[0], nID.Name)
		_, okRE := isIdentNamed(lastRet.Results[1], errVar)
		if !okRN || !okRE {
			return nil, fmt.Errorf("os: (*File).Write final return does not return (%s, %s)", nID.Name, errVar)
		}
	}

	{
		wsFn := fileMethods["WriteString"]
		if wsFn == nil || (len(wsFn.Body.List) != 1 && len(wsFn.Body.List) != 2) || funcShadowsAnyIdent(wsFn, osReserved) || bodyHasControlFlowOrRecoverBypass(wsFn.Body) {
			return nil, fmt.Errorf("os: missing or invalid (*File).WriteString")
		}
		wsRecv := recvVarName(wsFn)
		wsParams := paramNamesFlat(wsFn.Type.Params)
		if wsRecv == "" || len(wsParams) != 1 || wsParams[0] == "" || wsParams[0] == "_" || wsFn.Type.Results == nil || wsFn.Type.Results.NumFields() != 2 || !firstResultIsInt(wsFn.Type.Results) || !funcReturnsErrorLast(wsFn.Type) {
			return nil, fmt.Errorf("os: (*File).WriteString invalid signature")
		}
		sParam := wsParams[0]
		if len(wsFn.Body.List) == 1 {
			ret, ok := wsFn.Body.List[0].(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				return nil, fmt.Errorf("os: (*File).WriteString invalid 1-stmt return")
			}
			wCall, ok := unwrapParens(ret.Results[0]).(*ast.CallExpr)
			if !ok || wCall.Ellipsis.IsValid() || len(wCall.Args) != 1 {
				return nil, fmt.Errorf("os: (*File).WriteString invalid Write delegation")
			}
			if _, okSel := isSelectorBaseField(wCall.Fun, wsRecv, "Write"); !okSel {
				return nil, fmt.Errorf("os: (*File).WriteString does not call %s.Write", wsRecv)
			}
			conv, ok := unwrapParens(wCall.Args[0]).(*ast.CallExpr)
			if !ok || conv.Ellipsis.IsValid() || len(conv.Args) != 1 {
				return nil, fmt.Errorf("os: (*File).WriteString invalid []byte conversion")
			}
			at, okAT := unwrapParens(conv.Fun).(*ast.ArrayType)
			_, okByte := isIdentNamed(at.Elt, "byte")
			_, okS := isIdentNamed(conv.Args[0], sParam)
			if !okAT || at.Len != nil || !okByte || !okS {
				return nil, fmt.Errorf("os: (*File).WriteString does not convert %s to []byte", sParam)
			}
		} else {
			if !fileImportsUnsafe[funcFile[wsFn]] {
				return nil, fmt.Errorf("os: (*File).WriteString unsafe.Slice form missing unsafe import")
			}
			as, ok := wsFn.Body.List[0].(*ast.AssignStmt)
			if !ok || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return nil, fmt.Errorf("os: (*File).WriteString invalid unsafe.Slice assignment")
			}
			bID, ok1 := unwrapParens(as.Lhs[0]).(*ast.Ident)
			slCall, ok2 := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
			if !ok1 || !ok2 || bID.Name == "" || bID.Name == "_" || slCall.Ellipsis.IsValid() || len(slCall.Args) != 2 || !isLenOfIdentCall(slCall.Args[1], sParam) {
				return nil, fmt.Errorf("os: (*File).WriteString invalid unsafe.Slice call")
			}
			if _, okSel := isSelectorBaseField(slCall.Fun, "unsafe", "Slice"); !okSel {
				return nil, fmt.Errorf("os: (*File).WriteString does not call unsafe.Slice")
			}
			sdCall, ok := unwrapParens(slCall.Args[0]).(*ast.CallExpr)
			if !ok || sdCall.Ellipsis.IsValid() || len(sdCall.Args) != 1 {
				return nil, fmt.Errorf("os: (*File).WriteString invalid unsafe.StringData call")
			}
			_, okSDSel := isSelectorBaseField(sdCall.Fun, "unsafe", "StringData")
			_, okSArg := isIdentNamed(sdCall.Args[0], sParam)
			if !okSDSel || !okSArg {
				return nil, fmt.Errorf("os: (*File).WriteString does not pass %s to unsafe.StringData", sParam)
			}
			ret, ok := wsFn.Body.List[1].(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				return nil, fmt.Errorf("os: (*File).WriteString invalid return")
			}
			wCall, ok := unwrapParens(ret.Results[0]).(*ast.CallExpr)
			if !ok || wCall.Ellipsis.IsValid() || len(wCall.Args) != 1 {
				return nil, fmt.Errorf("os: (*File).WriteString invalid Write call")
			}
			_, okWSel := isSelectorBaseField(wCall.Fun, wsRecv, "Write")
			_, okBArg := isIdentNamed(wCall.Args[0], bID.Name)
			if !okWSel || !okBArg {
				return nil, fmt.Errorf("os: (*File).WriteString does not return %s.Write(%s)", wsRecv, bID.Name)
			}
		}
	}

	{
		wrFn := fileMethods["write"]
		if wrFn == nil || len(wrFn.Body.List) < 2 || funcShadowsAnyIdent(wrFn, osReserved) || bodyHasControlFlowOrRecoverBypass(wrFn.Body) {
			return nil, fmt.Errorf("os: missing or invalid (*File).write")
		}
		wrRecv := recvVarName(wrFn)
		wrParams := paramNamesFlat(wrFn.Type.Params)
		if wrRecv == "" || len(wrParams) != 1 || wrParams[0] == "" || wrParams[0] == "_" || wrFn.Type.Results == nil || wrFn.Type.Results.NumFields() != 2 || !firstResultIsInt(wrFn.Type.Results) || !funcReturnsErrorLast(wrFn.Type) {
			return nil, fmt.Errorf("os: (*File).write invalid signature")
		}
		bParam := wrParams[0]
		if bodyMutatesOrTakesAddrOfAny(wrFn.Body, map[string]bool{wrRecv: true, bParam: true}) || bodyDeclaresAnyIdent(wrFn.Body, map[string]bool{wrRecv: true, bParam: true}) {
			return nil, fmt.Errorf("os: (*File).write mutates receiver or slice parameter")
		}
		pos := 0
		for pos < len(wrFn.Body.List) && skipInactiveHookIf(wrFn.Body.List[pos], wrFn) {
			pos++
		}
		validPosixWrite := false
		if pos+1 < len(wrFn.Body.List) {
			if as, ok := wrFn.Body.List[pos].(*ast.AssignStmt); ok && (as.Tok == token.ASSIGN || as.Tok == token.DEFINE) && len(as.Lhs) == 2 && len(as.Rhs) == 1 {
				nID, ok1 := unwrapParens(as.Lhs[0]).(*ast.Ident)
				eID, ok2 := unwrapParens(as.Lhs[1]).(*ast.Ident)
				pfdCall, ok3 := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
				if ok1 && ok2 && ok3 && nID.Name != "" && nID.Name != "_" && eID.Name != "" && eID.Name != "_" && nID.Name != eID.Name && !pfdCall.Ellipsis.IsValid() && len(pfdCall.Args) == 1 {
					if _, okArg := isIdentNamed(pfdCall.Args[0], bParam); okArg {
						if wSel, okS := unwrapParens(pfdCall.Fun).(*ast.SelectorExpr); okS && wSel.Sel.Name == "Write" {
							if _, okPFD := isSelectorBaseField(wSel.X, wrRecv, "pfd"); okPFD {
								midOK := true
								for _, mid := range wrFn.Body.List[pos+1 : len(wrFn.Body.List)-1] {
									es, okES := mid.(*ast.ExprStmt)
									if !okES {
										midOK = false
										break
									}
									kc, okKC := unwrapParens(es.X).(*ast.CallExpr)
									if !okKC || kc.Ellipsis.IsValid() || len(kc.Args) != 1 {
										midOK = false
										break
									}
									_, okKA := isSelectorBaseField(kc.Fun, "runtime", "KeepAlive")
									_, okKArg := isIdentNamed(kc.Args[0], wrRecv)
									if !okKA || !okKArg {
										midOK = false
										break
									}
								}
								if ret, okR := wrFn.Body.List[len(wrFn.Body.List)-1].(*ast.ReturnStmt); midOK && okR && len(ret.Results) == 2 {
									_, okRN := isIdentNamed(ret.Results[0], nID.Name)
									_, okRE := isIdentNamed(ret.Results[1], eID.Name)
									if okRN && okRE {
										validPosixWrite = true
									}
								}
							}
						}
					}
				}
			}
		}
		validPlan9Write := false
		if !validPosixWrite && pos == 0 && len(wrFn.Body.List) == 4 && fileImportsSyscall[funcFile[wrFn]] {
			// Plan 9: writeLock guard, defer writeUnlock, len(b) == 0 guard, return fixCount(syscall.Write(f.sysfd, b)).
			s0, ok0 := wrFn.Body.List[0].(*ast.IfStmt)
			s1, ok1 := wrFn.Body.List[1].(*ast.DeferStmt)
			s2, ok2 := wrFn.Body.List[2].(*ast.IfStmt)
			s3, ok3 := wrFn.Body.List[3].(*ast.ReturnStmt)
			fcFn := topFuncs["fixCount"]
			if ok0 && ok1 && ok2 && ok3 && s0.Else == nil && s2.Init == nil && s2.Else == nil && len(s3.Results) == 1 && fcFn != nil && len(fcFn.Body.List) == 2 && !funcShadowsAnyIdent(fcFn, osReserved) && !bodyHasControlFlowOrRecoverBypass(fcFn.Body) {
				if _, okUnlock := isZeroArgMethodCallOnIdent(s1.Call, wrRecv, "writeUnlock"); okUnlock {
					if bin, okB := unwrapParens(s2.Cond).(*ast.BinaryExpr); okB && bin.Op == token.EQL && isLenOfIdentCall(bin.X, bParam) && isZeroIntLit(bin.Y) && len(s2.Body.List) == 1 {
						if zRet, okZR := s2.Body.List[0].(*ast.ReturnStmt); okZR && len(zRet.Results) == 2 && isZeroIntLit(zRet.Results[0]) {
							if _, okNil := isIdentNamed(zRet.Results[1], "nil"); okNil {
								if fcCall, okFC := unwrapParens(s3.Results[0]).(*ast.CallExpr); okFC && !fcCall.Ellipsis.IsValid() && len(fcCall.Args) == 1 {
									if _, okFCID := isIdentNamed(fcCall.Fun, "fixCount"); okFCID {
										if sc, okSC := unwrapParens(fcCall.Args[0]).(*ast.CallExpr); okSC && !sc.Ellipsis.IsValid() && len(sc.Args) == 2 {
											_, okSCSel := isSelectorBaseField(sc.Fun, "syscall", "Write")
											_, okSysfd := isSelectorBaseField(sc.Args[0], wrRecv, "sysfd")
											_, okBArg := isIdentNamed(sc.Args[1], bParam)
											fcParams := paramNamesFlat(fcFn.Type.Params)
											if okSCSel && okSysfd && okBArg && len(fcParams) == 2 {
												if fcRet, okFCR := fcFn.Body.List[1].(*ast.ReturnStmt); okFCR && len(fcRet.Results) == 2 {
													_, okFN := isIdentNamed(fcRet.Results[0], fcParams[0])
													_, okFE := isIdentNamed(fcRet.Results[1], fcParams[1])
													if okFN && okFE && !bodyMutatesOrTakesAddrOfAny(fcFn.Body, map[string]bool{fcParams[1]: true}) {
														validPlan9Write = true
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		if !validPosixWrite && !validPlan9Write {
			return nil, fmt.Errorf("os: (*File).write has unverified implementation")
		}
	}

	if err := verifyOSFileFdMethods(fileMethods["Fd"], fileMethods["fd"], osNoFileReserved, skipInactiveHookIf); err != nil {
		return nil, err
	}

	{
		clFn := fileMethods["Close"]
		if clFn == nil || len(clFn.Body.List) < 2 || funcShadowsAnyIdent(clFn, osReserved) || bodyHasControlFlowOrRecoverBypass(clFn.Body) {
			return nil, fmt.Errorf("os: missing or invalid (*File).Close")
		}
		clRecv := recvVarName(clFn)
		if clRecv == "" || (clFn.Type.Params != nil && clFn.Type.Params.NumFields() != 0) || !funcReturnsErrorLast(clFn.Type) || clFn.Type.Results.NumFields() != 1 {
			return nil, fmt.Errorf("os: (*File).Close invalid signature")
		}
		ifs0, ok := clFn.Body.List[0].(*ast.IfStmt)
		if !ok || ifs0.Init != nil || ifs0.Else != nil || !condChecksEqErr(ifs0.Cond, clRecv) || len(ifs0.Body.List) != 1 {
			return nil, fmt.Errorf("os: (*File).Close missing nil receiver guard")
		}
		if ret0, okR := ifs0.Body.List[0].(*ast.ReturnStmt); !okR || len(ret0.Results) != 1 {
			return nil, fmt.Errorf("os: (*File).Close invalid nil receiver return")
		} else if _, okEI := isIdentNamed(ret0.Results[0], "ErrInvalid"); !okEI {
			return nil, fmt.Errorf("os: (*File).Close nil receiver guard does not return ErrInvalid")
		}
		pos := 1
		for pos < len(clFn.Body.List) && skipInactiveHookIf(clFn.Body.List[pos], clFn) {
			pos++
		}
		if len(clFn.Body.List) != pos+1 {
			return nil, fmt.Errorf("os: (*File).Close unexpected statements before f.file.close()")
		}
		retClose, ok := clFn.Body.List[pos].(*ast.ReturnStmt)
		if !ok || len(retClose.Results) != 1 {
			return nil, fmt.Errorf("os: (*File).Close invalid final return")
		}
		cCall, ok := unwrapParens(retClose.Results[0]).(*ast.CallExpr)
		if !ok || cCall.Ellipsis.IsValid() || len(cCall.Args) != 0 {
			return nil, fmt.Errorf("os: (*File).Close invalid close() call")
		}
		cSel, ok := unwrapParens(cCall.Fun).(*ast.SelectorExpr)
		if !ok || cSel.Sel.Name != "close" {
			return nil, fmt.Errorf("os: (*File).Close does not call f.file.close()")
		}
		if _, okFile := isSelectorBaseField(cSel.X, clRecv, "file"); !okFile {
			return nil, fmt.Errorf("os: (*File).Close receiver is not %s.file", clRecv)
		}
	}

	{
		rcFn := rawFileMethods["close"]
		if rcFn == nil || len(rcFn.Body.List) < 3 || rawFileMethodShadowsReserved(rcFn) || bodyHasControlFlowOrRecoverBypass(rcFn.Body) {
			return nil, fmt.Errorf("os: missing or invalid (*file).close")
		}
		rcRecv := recvVarName(rcFn)
		if rcRecv == "" || (rcFn.Type.Params != nil && rcFn.Type.Params.NumFields() != 0) || !funcReturnsErrorLast(rcFn.Type) || rcFn.Type.Results.NumFields() != 1 {
			return nil, fmt.Errorf("os: (*file).close invalid signature")
		}
		if bodyMutatesOrTakesAddrOfAny(rcFn.Body, map[string]bool{rcRecv: true}) || bodyDeclaresAnyIdent(rcFn.Body, map[string]bool{rcRecv: true}) {
			return nil, fmt.Errorf("os: (*file).close mutates or shadows receiver")
		}
		isSetFinalizerNilStmt := func(st ast.Stmt) bool {
			if !fileImportsRuntime[funcFile[rcFn]] {
				return false
			}
			es, okES := st.(*ast.ExprStmt)
			if !okES {
				return false
			}
			c, okC := unwrapParens(es.X).(*ast.CallExpr)
			if !okC || c.Ellipsis.IsValid() || len(c.Args) != 2 {
				return false
			}
			_, okSF := isSelectorBaseField(c.Fun, "runtime", "SetFinalizer")
			_, okR := isIdentNamed(c.Args[0], rcRecv)
			_, okN := isIdentNamed(c.Args[1], "nil")
			return okSF && okR && okN
		}
		validPFDClose := false
		if ifs0, ok0 := rcFn.Body.List[0].(*ast.IfStmt); ok0 && ifs0.Init == nil && ifs0.Else == nil && condChecksEqErr(ifs0.Cond, rcRecv) && len(ifs0.Body.List) == 1 {
			if ret0, okR0 := ifs0.Body.List[0].(*ast.ReturnStmt); okR0 && len(ret0.Results) == 1 {
				_, okNilEI := isIdentNamed(ret0.Results[0], "ErrInvalid")
				_, okNilEINVAL := isSelectorBaseField(ret0.Results[0], "syscall", "EINVAL")
				if okNilEI || (fileImportsSyscall[funcFile[rcFn]] && okNilEINVAL) {
					var errVar string
					pfdCloseIdx := -1
					directReturnOnErr := false
					preOK := true
					for idx := 1; idx < len(rcFn.Body.List)-1; idx++ {
						st := rcFn.Body.List[idx]
						if pfdCloseIdx < 0 && skipInactiveHookIf(st, rcFn) {
							continue
						}
						if isDirinfoSwapCloseIf(st, rcRecv, dirInfoCloseFn, osNoFileReserved, osAnyLinknameLocals) {
							continue
						}
						if ds, isDS := st.(*ast.DeclStmt); isDS {
							if gd, okGD := ds.Decl.(*ast.GenDecl); okGD && gd.Tok == token.VAR && len(gd.Specs) == 1 {
								if vs, okVS := gd.Specs[0].(*ast.ValueSpec); okVS && len(vs.Names) == 1 && len(vs.Values) == 0 {
									if _, okErrT := isIdentNamed(vs.Type, "error"); okErrT && errVar == "" {
										errVar = vs.Names[0].Name
										continue
									}
								}
							}
						}
						if ifs, isIf := st.(*ast.IfStmt); isIf && ifs.Init != nil && ifs.Else == nil {
							if initAs, okA := ifs.Init.(*ast.AssignStmt); okA && initAs.Tok == token.DEFINE && len(initAs.Lhs) == 1 && len(initAs.Rhs) == 1 {
								eID, okE := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
								pcCall, okC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
								if okE && okC && eID.Name != "" && eID.Name != "_" && condChecksNonZeroErr(ifs.Cond) == eID.Name && !pcCall.Ellipsis.IsValid() && len(pcCall.Args) == 0 {
									if pcSel, okS := unwrapParens(pcCall.Fun).(*ast.SelectorExpr); okS && pcSel.Sel.Name == "Close" {
										if _, okPFD := isSelectorBaseField(pcSel.X, rcRecv, "pfd"); okPFD {
											if len(ifs.Body.List) == 1 {
												if rStmt, okRS := ifs.Body.List[0].(*ast.ReturnStmt); okRS && len(rStmt.Results) == 1 {
													_, okRetE := isIdentNamed(rStmt.Results[0], eID.Name)
													u, okU := unwrapParens(rStmt.Results[0]).(*ast.UnaryExpr)
													_, tName := compositeWriterLit(rStmt.Results[0])
													if okRetE || (okU && u.Op == token.AND && tName == "PathError") {
														pfdCloseIdx = idx
														directReturnOnErr = true
														break
													}
												}
											}
											if errVar != "" && len(ifs.Body.List) >= 1 {
												lastAssign, okLA := ifs.Body.List[len(ifs.Body.List)-1].(*ast.AssignStmt)
												if okLA && lastAssign.Tok == token.ASSIGN && len(lastAssign.Lhs) == 1 && len(lastAssign.Rhs) == 1 {
													_, okL := isIdentNamed(lastAssign.Lhs[0], errVar)
													u, okU := unwrapParens(lastAssign.Rhs[0]).(*ast.UnaryExpr)
													_, tName := compositeWriterLit(lastAssign.Rhs[0])
													preErrOK := true
													for _, preS := range ifs.Body.List[:len(ifs.Body.List)-1] {
														preIf, okPI := preS.(*ast.IfStmt)
														if !okPI || preIf.Init != nil || preIf.Else != nil || len(preIf.Body.List) != 1 || exprContainsAnyCall(preIf.Cond) {
															preErrOK = false
															break
														}
														preAs, okPA := preIf.Body.List[0].(*ast.AssignStmt)
														if !okPA || preAs.Tok != token.ASSIGN || len(preAs.Lhs) != 1 || len(preAs.Rhs) != 1 {
															preErrOK = false
															break
														}
														_, okPL := isIdentNamed(preAs.Lhs[0], eID.Name)
														_, okPR := isIdentNamed(preAs.Rhs[0], "ErrClosed")
														if !okPL || !okPR {
															preErrOK = false
															break
														}
													}
													if okL && okU && u.Op == token.AND && tName == "PathError" && preErrOK {
														pfdCloseIdx = idx
														break
													}
												}
											}
										}
									}
								}
							}
						}
						preOK = false
						break
					}
					if preOK && pfdCloseIdx >= 1 {
						postOK := true
						for _, postSt := range rcFn.Body.List[pfdCloseIdx+1 : len(rcFn.Body.List)-1] {
							if !isSetFinalizerNilStmt(postSt) {
								postOK = false
								break
							}
						}
						if lastRet, okLR := rcFn.Body.List[len(rcFn.Body.List)-1].(*ast.ReturnStmt); postOK && okLR && len(lastRet.Results) == 1 {
							if directReturnOnErr {
								if _, okNil := isIdentNamed(lastRet.Results[0], "nil"); okNil {
									validPFDClose = true
								}
							} else if errVar != "" {
								if _, okEV := isIdentNamed(lastRet.Results[0], errVar); okEV {
									validPFDClose = true
								}
							}
						}
					}
				}
			}
		}
		validPlan9Close := false
		if !validPFDClose && len(rcFn.Body.List) >= 3 {
			decFn := rawFileMethods["decref"]
			desFn := rawFileMethods["destroy"]
			if decFn != nil && desFn != nil && len(decFn.Body.List) == 2 && len(desFn.Body.List) == 3 &&
				fileImportsSyscall[funcFile[desFn]] &&
				!rawFileMethodShadowsReserved(decFn) && !bodyHasControlFlowOrRecoverBypass(decFn.Body) &&
				!rawFileMethodShadowsReserved(desFn) && !bodyHasControlFlowOrRecoverBypass(desFn.Body) {
				decRecv := recvVarName(decFn)
				desRecv := recvVarName(desFn)
				// 1. (*file).close List[0]: if !file.fdmu.IncrefAndClose() { return &PathError{...} }
				ifs0, okI0 := rcFn.Body.List[0].(*ast.IfStmt)
				var closeGuardOK bool
				if okI0 && ifs0.Init == nil && ifs0.Else == nil && len(ifs0.Body.List) == 1 {
					if u0, okU0 := unwrapParens(ifs0.Cond).(*ast.UnaryExpr); okU0 && u0.Op == token.NOT {
						if icCall, okIC := unwrapParens(u0.X).(*ast.CallExpr); okIC && !icCall.Ellipsis.IsValid() && len(icCall.Args) == 0 {
							if icSel, okS := unwrapParens(icCall.Fun).(*ast.SelectorExpr); okS && icSel.Sel.Name == "IncrefAndClose" {
								if _, okFDMU := isSelectorBaseField(icSel.X, rcRecv, "fdmu"); okFDMU {
									if r0, okR0 := ifs0.Body.List[0].(*ast.ReturnStmt); okR0 && len(r0.Results) == 1 {
										_, okEC := isIdentNamed(r0.Results[0], "ErrClosed")
										uPE, okUPE := unwrapParens(r0.Results[0]).(*ast.UnaryExpr)
										_, tPE := compositeWriterLit(r0.Results[0])
										closeGuardOK = okEC || (okUPE && uPE.Op == token.AND && tPE == "PathError")
									}
								}
							}
						}
					}
				}
				// 2. (*file).decref: if file.fdmu.Decref() { return file.destroy() }; return nil
				var decOK bool
				if decRecv != "" && (decFn.Type.Params == nil || decFn.Type.Params.NumFields() == 0) && funcReturnsErrorLast(decFn.Type) && decFn.Type.Results.NumFields() == 1 {
					if dIf, okDI := decFn.Body.List[0].(*ast.IfStmt); okDI && dIf.Init == nil && dIf.Else == nil && len(dIf.Body.List) == 1 {
						if dCall, okDC := unwrapParens(dIf.Cond).(*ast.CallExpr); okDC && !dCall.Ellipsis.IsValid() && len(dCall.Args) == 0 {
							if dSel, okDS := unwrapParens(dCall.Fun).(*ast.SelectorExpr); okDS && dSel.Sel.Name == "Decref" {
								if _, okFDMU := isSelectorBaseField(dSel.X, decRecv, "fdmu"); okFDMU {
									if dRet, okDR := dIf.Body.List[0].(*ast.ReturnStmt); okDR && len(dRet.Results) == 1 {
										if _, okDest := isZeroArgMethodCallOnIdent(dRet.Results[0], decRecv, "destroy"); okDest {
											if dNil, okDN := decFn.Body.List[1].(*ast.ReturnStmt); okDN && len(dNil.Results) == 1 {
												_, decOK = isIdentNamed(dNil.Results[0], "nil")
											}
										}
									}
								}
							}
						}
					}
				}
				// 3. (*file).destroy: var err error; if e := syscall.Close(file.sysfd); e != nil { err = &PathError{...} }; return err
				var desOK bool
				if desRecv != "" && (desFn.Type.Params == nil || desFn.Type.Params.NumFields() == 0) && funcReturnsErrorLast(desFn.Type) && desFn.Type.Results.NumFields() == 1 && !bodyMutatesOrTakesAddrOfAny(desFn.Body, map[string]bool{desRecv: true}) {
					var desErrVar string
					if ds, okDS := desFn.Body.List[0].(*ast.DeclStmt); okDS {
						if gd, okGD := ds.Decl.(*ast.GenDecl); okGD && gd.Tok == token.VAR && len(gd.Specs) == 1 {
							if vs, okVS := gd.Specs[0].(*ast.ValueSpec); okVS && len(vs.Names) == 1 && len(vs.Values) == 0 {
								if _, okET := isIdentNamed(vs.Type, "error"); okET {
									desErrVar = vs.Names[0].Name
								}
							}
						}
					}
					if desErrVar != "" {
						if sIf, okSI := desFn.Body.List[1].(*ast.IfStmt); okSI && sIf.Init != nil && sIf.Else == nil && len(sIf.Body.List) == 1 {
							if sInit, okSIn := sIf.Init.(*ast.AssignStmt); okSIn && sInit.Tok == token.DEFINE && len(sInit.Lhs) == 1 && len(sInit.Rhs) == 1 {
								seID, okSE := unwrapParens(sInit.Lhs[0]).(*ast.Ident)
								scCall, okSC := unwrapParens(sInit.Rhs[0]).(*ast.CallExpr)
								if okSE && okSC && seID.Name != "" && seID.Name != "_" && condChecksNonZeroErr(sIf.Cond) == seID.Name && !scCall.Ellipsis.IsValid() && len(scCall.Args) == 1 {
									_, okSCSel := isSelectorBaseField(scCall.Fun, "syscall", "Close")
									_, okSysfd := isSelectorBaseField(scCall.Args[0], desRecv, "sysfd")
									if okSCSel && okSysfd {
										if eAs, okEA := sIf.Body.List[0].(*ast.AssignStmt); okEA && eAs.Tok == token.ASSIGN && len(eAs.Lhs) == 1 && len(eAs.Rhs) == 1 {
											_, okEL := isIdentNamed(eAs.Lhs[0], desErrVar)
											_, okER := isIdentNamed(eAs.Rhs[0], seID.Name)
											uPE, okUPE := unwrapParens(eAs.Rhs[0]).(*ast.UnaryExpr)
											_, tPE := compositeWriterLit(eAs.Rhs[0])
											if okEL && (okER || (okUPE && uPE.Op == token.AND && tPE == "PathError")) {
												if dLast, okDL := desFn.Body.List[2].(*ast.ReturnStmt); okDL && len(dLast.Results) == 1 {
													_, desOK = isIdentNamed(dLast.Results[0], desErrVar)
												}
											}
										}
									}
								}
							}
						}
					}
				}
				if closeGuardOK && decOK && desOK {
					if as, okA := rcFn.Body.List[1].(*ast.AssignStmt); okA && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
						eID, okE := unwrapParens(as.Lhs[0]).(*ast.Ident)
						midClean := true
						for _, mid := range rcFn.Body.List[2 : len(rcFn.Body.List)-1] {
							if !isSetFinalizerNilStmt(mid) {
								midClean = false
								break
							}
						}
						_, okDecref := isZeroArgMethodCallOnIdent(as.Rhs[0], rcRecv, "decref")
						if okE && eID.Name != "" && eID.Name != "_" && midClean && okDecref && !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: rcFn.Body.List[2:]}, map[string]bool{eID.Name: true}) {
							if lr, okLR := rcFn.Body.List[len(rcFn.Body.List)-1].(*ast.ReturnStmt); okLR && len(lr.Results) == 1 {
								if _, okRE := isIdentNamed(lr.Results[0], eID.Name); okRE {
									validPlan9Close = true
								}
							}
						}
					}
				}
			}
		}
		if !validPFDClose && !validPlan9Close {
			return nil, fmt.Errorf("os: (*file).close has unverified implementation")
		}
	}

	return sortedKeys(usedRuntimeGates), nil
}


func verifyOSFileStructTypes(fileTypeSpec, rawFileTypeSpec *ast.TypeSpec, pkgDeclCounts map[string]int) error {
	if pkgDeclCounts["File"] != 1 || pkgDeclCounts["file"] != 1 || fileTypeSpec == nil || rawFileTypeSpec == nil {
		return fmt.Errorf("os: missing or duplicate File/file type declarations")
	}
	if fileTypeSpec.Assign.IsValid() || fileTypeSpec.TypeParams != nil || rawFileTypeSpec.Assign.IsValid() || rawFileTypeSpec.TypeParams != nil {
		return fmt.Errorf("os: File/file cannot be type aliases or generic")
	}
	fst, ok := unwrapParens(fileTypeSpec.Type).(*ast.StructType)
	if !ok || fst.Fields == nil || len(fst.Fields.List) != 1 || len(fst.Fields.List[0].Names) != 0 {
		return fmt.Errorf("os: File must be a struct with a single embedded *file field")
	}
	star, ok := unwrapParens(fst.Fields.List[0].Type).(*ast.StarExpr)
	if !ok {
		return fmt.Errorf("os: File embedded field is not a pointer")
	}
	if _, ok := isIdentNamed(star.X, "file"); !ok {
		return fmt.Errorf("os: File embedded field is not *file")
	}
	rst, ok := unwrapParens(rawFileTypeSpec.Type).(*ast.StructType)
	if !ok || rst.Fields == nil {
		return fmt.Errorf("os: file is not a struct")
	}
	seenFields := map[string]bool{}
	var sawName, sawFD bool
	for _, fld := range rst.Fields.List {
		if len(fld.Names) == 0 {
			return fmt.Errorf("os: embedded field on internal file struct forbidden")
		}
		for _, id := range fld.Names {
			if seenFields[id.Name] {
				return fmt.Errorf("os: duplicate field %s on file struct", id.Name)
			}
			seenFields[id.Name] = true
			switch id.Name {
			case "name":
				if _, okStr := isIdentNamed(fld.Type, "string"); !okStr {
					return fmt.Errorf("os: file.name must have type string")
				}
				sawName = true
			case "pfd", "sysfd":
				sawFD = true
			}
		}
	}
	if !sawName || !sawFD {
		return fmt.Errorf("os: file struct missing name or pfd/sysfd field")
	}
	return nil
}

func verifyOSExitIntegrity(files []*ast.File, exitFn *ast.FuncDecl, funcFile map[*ast.FuncDecl]*ast.File, fileImportsTestlog, fileImportsSyscall map[*ast.File]bool, osReserved map[string]bool) error {
	if exitFn == nil || exitFn.Body == nil || exitFn.Type == nil || exitFn.Type.TypeParams != nil {
		return fmt.Errorf("os: missing Exit function")
	}
	if !fileImportsTestlog[funcFile[exitFn]] || !fileImportsSyscall[funcFile[exitFn]] {
		return fmt.Errorf("os: file defining Exit missing internal/testlog or syscall import")
	}
	if funcShadowsAnyIdent(exitFn, osReserved) || bodyHasControlFlowOrRecoverBypass(exitFn.Body) {
		return fmt.Errorf("os: Exit shadows reserved identifier or has control-flow/recover bypass")
	}
	pNames := paramNamesFlat(exitFn.Type.Params)
	if len(pNames) != 1 || pNames[0] == "" || pNames[0] == "_" || len(exitFn.Type.Params.List) != 1 || (exitFn.Type.Results != nil && exitFn.Type.Results.NumFields() != 0) {
		return fmt.Errorf("os: Exit invalid signature")
	}
	if _, okInt := isIdentNamed(exitFn.Type.Params.List[0].Type, "int"); !okInt {
		return fmt.Errorf("os: Exit parameter is not int")
	}
	codeParam := pNames[0]
	if bodyMutatesOrTakesAddrOfAny(exitFn.Body, map[string]bool{codeParam: true}) || bodyDeclaresAnyIdent(exitFn.Body, map[string]bool{codeParam: true}) {
		return fmt.Errorf("os: Exit mutates or shadows %s", codeParam)
	}
	if len(exitFn.Body.List) != 2 && len(exitFn.Body.List) != 3 {
		return fmt.Errorf("os: Exit unexpected statement count %d", len(exitFn.Body.List))
	}
	s0, ok := exitFn.Body.List[0].(*ast.IfStmt)
	if !ok || s0.Init != nil || s0.Else != nil || len(s0.Body.List) != 1 {
		return fmt.Errorf("os: Exit missing PanicOnExit0 guard")
	}
	andBin, ok := unwrapParens(s0.Cond).(*ast.BinaryExpr)
	if !ok || andBin.Op != token.LAND {
		return fmt.Errorf("os: Exit guard condition is not &&")
	}
	eqBin, ok := unwrapParens(andBin.X).(*ast.BinaryExpr)
	if !ok || eqBin.Op != token.EQL {
		return fmt.Errorf("os: Exit guard LHS is not == 0")
	}
	_, okCodeL := isIdentNamed(eqBin.X, codeParam)
	_, okCodeR := isIdentNamed(eqBin.Y, codeParam)
	if !((okCodeL && isZeroIntLit(eqBin.Y)) || (isZeroIntLit(eqBin.X) && okCodeR)) {
		return fmt.Errorf("os: Exit guard does not compare %s == 0", codeParam)
	}
	if _, okPOE := isZeroArgMethodCallOnIdent(andBin.Y, "testlog", "PanicOnExit0"); !okPOE {
		return fmt.Errorf("os: Exit guard does not call testlog.PanicOnExit0()")
	}
	pES, ok := s0.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return fmt.Errorf("os: Exit guard body is not panic statement")
	}
	pCall, ok := unwrapParens(pES.X).(*ast.CallExpr)
	if !ok || pCall.Ellipsis.IsValid() || len(pCall.Args) != 1 {
		return fmt.Errorf("os: Exit guard invalid panic call")
	}
	if _, okP := isIdentNamed(pCall.Fun, "panic"); !okP {
		return fmt.Errorf("os: Exit guard does not call panic")
	}
	if lit, okLit := unwrapParens(pCall.Args[0]).(*ast.BasicLit); !okLit || lit.Kind != token.STRING {
		return fmt.Errorf("os: Exit panic argument must be string literal")
	}

	allowedBeforeExit := map[*ast.Ident]bool{}
	beforeExitDecls := 0
	for _, f := range files {
		for _, decl := range f.Decls {
			if fn, okF := decl.(*ast.FuncDecl); okF && fn.Recv == nil && fn.Name != nil && fn.Name.Name == "runtime_beforeExit" {
				beforeExitDecls++
				if fn.Body != nil || beforeExitDecls > 1 {
					return fmt.Errorf("os: invalid or duplicate runtime_beforeExit declaration")
				}
				allowedBeforeExit[fn.Name] = true
			}
		}
	}
	if len(exitFn.Body.List) == 3 {
		s1, okES := exitFn.Body.List[1].(*ast.ExprStmt)
		if !okES {
			return fmt.Errorf("os: Exit middle statement is not runtime_beforeExit call")
		}
		beCall, okC := unwrapParens(s1.X).(*ast.CallExpr)
		if !okC || beCall.Ellipsis.IsValid() || len(beCall.Args) != 1 {
			return fmt.Errorf("os: Exit invalid runtime_beforeExit call")
		}
		beID, okID := isIdentNamed(beCall.Fun, "runtime_beforeExit")
		_, okArg := isIdentNamed(beCall.Args[0], codeParam)
		if !okID || !okArg {
			return fmt.Errorf("os: Exit middle statement does not call runtime_beforeExit(%s)", codeParam)
		}
		allowedBeforeExit[beID] = true
	}

	lastES, ok := exitFn.Body.List[len(exitFn.Body.List)-1].(*ast.ExprStmt)
	if !ok {
		return fmt.Errorf("os: Exit final statement is not syscall.Exit call")
	}
	sysCall, ok := unwrapParens(lastES.X).(*ast.CallExpr)
	if !ok || sysCall.Ellipsis.IsValid() || len(sysCall.Args) != 1 {
		return fmt.Errorf("os: Exit invalid syscall.Exit call")
	}
	sysSel, ok := unwrapParens(sysCall.Fun).(*ast.SelectorExpr)
	if !ok || sysSel.Sel.Name != "Exit" {
		return fmt.Errorf("os: Exit does not call syscall.Exit")
	}
	if _, okSys := isIdentNamed(sysSel.X, "syscall"); !okSys {
		return fmt.Errorf("os: Exit final call receiver is not syscall")
	}
	if _, okArg := isIdentNamed(sysCall.Args[0], codeParam); !okArg {
		return fmt.Errorf("os: Exit does not forward %s to syscall.Exit", codeParam)
	}

	var exitLeak bool
	for _, f := range files {
		walkNonSelectorPropIdents(f, func(id *ast.Ident) {
			if id.Name == "Exit" && id != exitFn.Name {
				exitLeak = true
			}
			if id.Name == "runtime_beforeExit" && !allowedBeforeExit[id] {
				exitLeak = true
			}
		})
		ast.Inspect(f, func(n ast.Node) bool {
			if exitLeak || n == nil {
				return false
			}
			if sel, okS := n.(*ast.SelectorExpr); okS && sel != sysSel && (sel.Sel.Name == "Exit" || sel.Sel.Name == "ExitProcess") {
				if _, okSys := isIdentNamed(sel.X, "syscall"); okSys {
					exitLeak = true
					return false
				}
			}
			return true
		})
		if exitLeak {
			return fmt.Errorf("os: forbidden process-termination reference outside Exit")
		}
	}
	return nil
}

func verifyOSEpipecheck(fn *ast.FuncDecl, funcFile map[*ast.FuncDecl]*ast.File, fileImportsSyscall map[*ast.File]bool, osNoFileReserved, osAnyLinknameLocals map[string]bool) error {
	if fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || osAnyLinknameLocals["epipecheck"] {
		return fmt.Errorf("os: missing or invalid epipecheck")
	}
	if funcShadowsAnyIdent(fn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
		return fmt.Errorf("os: epipecheck shadows reserved identifier or has control-flow bypass")
	}
	pNames := paramNamesFlat(fn.Type.Params)
	if len(pNames) != 2 || pNames[0] == "" || pNames[0] == "_" || pNames[1] == "" || pNames[1] == "_" || (fn.Type.Results != nil && fn.Type.Results.NumFields() != 0) {
		return fmt.Errorf("os: epipecheck invalid signature")
	}
	if len(fn.Body.List) == 0 {
		return nil
	}
	if len(fn.Body.List) != 1 || !fileImportsSyscall[funcFile[fn]] {
		return fmt.Errorf("os: epipecheck unexpected body")
	}
	ifs, ok := fn.Body.List[0].(*ast.IfStmt)
	if !ok || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
		return fmt.Errorf("os: epipecheck body is not single EPIPE guard")
	}
	isEpipeCmp := func(expr ast.Expr) bool {
		bin, okB := unwrapParens(expr).(*ast.BinaryExpr)
		if !okB || bin.Op != token.EQL {
			return false
		}
		_, okE := isIdentNamed(bin.X, pNames[1])
		_, okSys := isSelectorBaseField(bin.Y, "syscall", "EPIPE")
		return okE && okSys
	}
	condOK := isEpipeCmp(ifs.Cond)
	if !condOK {
		if andBin, okA := unwrapParens(ifs.Cond).(*ast.BinaryExpr); okA && andBin.Op == token.LAND {
			_, okStd := isSelectorBaseField(andBin.Y, pNames[0], "stdoutOrErr")
			condOK = isEpipeCmp(andBin.X) && okStd
		}
	}
	es, okES := ifs.Body.List[0].(*ast.ExprStmt)
	if !condOK || !okES {
		return fmt.Errorf("os: epipecheck invalid condition or call")
	}
	sc, okC := unwrapParens(es.X).(*ast.CallExpr)
	if !okC || sc.Ellipsis.IsValid() || len(sc.Args) != 0 {
		return fmt.Errorf("os: epipecheck invalid sigpipe call")
	}
	if _, okSig := isIdentNamed(sc.Fun, "sigpipe"); !okSig {
		return fmt.Errorf("os: epipecheck does not call sigpipe()")
	}
	return nil
}

func verifyOSFileFdMethods(fdExported, fdLower *ast.FuncDecl, osNoFileReserved map[string]bool, skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool) error {
	if fdExported == nil || fdExported.Body == nil || len(fdExported.Body.List) != 1 || funcShadowsAnyIdent(fdExported, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(fdExported.Body) {
		return fmt.Errorf("os: missing or invalid (*File).Fd")
	}
	expRecv := recvVarName(fdExported)
	if expRecv == "" || (fdExported.Type.Params != nil && fdExported.Type.Params.NumFields() != 0) || fdExported.Type.Results == nil || fdExported.Type.Results.NumFields() != 1 || len(fdExported.Type.Results.List) != 1 {
		return fmt.Errorf("os: (*File).Fd invalid signature")
	}
	if _, okU := isIdentNamed(fdExported.Type.Results.List[0].Type, "uintptr"); !okU {
		return fmt.Errorf("os: (*File).Fd result is not uintptr")
	}
	expRet, ok := fdExported.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(expRet.Results) != 1 {
		return fmt.Errorf("os: (*File).Fd does not return single expression")
	}
	if _, okCall := isZeroArgMethodCallOnIdent(expRet.Results[0], expRecv, "fd"); !okCall {
		return fmt.Errorf("os: (*File).Fd does not delegate to %s.fd()", expRecv)
	}

	if fdLower == nil || fdLower.Body == nil || len(fdLower.Body.List) < 2 || funcShadowsAnyIdent(fdLower, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(fdLower.Body) {
		return fmt.Errorf("os: missing or invalid (*File).fd")
	}
	lowRecv := recvVarName(fdLower)
	if lowRecv == "" || (fdLower.Type.Params != nil && fdLower.Type.Params.NumFields() != 0) || fdLower.Type.Results == nil || fdLower.Type.Results.NumFields() != 1 || len(fdLower.Type.Results.List) != 1 {
		return fmt.Errorf("os: (*File).fd invalid signature")
	}
	if _, okU := isIdentNamed(fdLower.Type.Results.List[0].Type, "uintptr"); !okU {
		return fmt.Errorf("os: (*File).fd result is not uintptr")
	}
	if bodyMutatesOrTakesAddrOfAny(fdLower.Body, map[string]bool{lowRecv: true}) || bodyDeclaresAnyIdent(fdLower.Body, map[string]bool{lowRecv: true}) {
		return fmt.Errorf("os: (*File).fd mutates or shadows receiver")
	}
	ifs0, ok := fdLower.Body.List[0].(*ast.IfStmt)
	if !ok || ifs0.Init != nil || ifs0.Else != nil || !condChecksEqErr(ifs0.Cond, lowRecv) || len(ifs0.Body.List) != 1 {
		return fmt.Errorf("os: (*File).fd missing nil receiver guard")
	}
	ret0, ok := ifs0.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret0.Results) != 1 {
		return fmt.Errorf("os: (*File).fd invalid nil receiver return")
	}
	badNilRet := false
	ast.Inspect(ret0.Results[0], func(n ast.Node) bool {
		if badNilRet || n == nil {
			return false
		}
		if c, okC := n.(*ast.CallExpr); okC {
			if _, okConv := isIdentNamed(c.Fun, "uintptr"); !okConv || c.Ellipsis.IsValid() || len(c.Args) != 1 {
				badNilRet = true
				return false
			}
		}
		return true
	})
	if badNilRet {
		return fmt.Errorf("os: (*File).fd nil guard contains forbidden call")
	}
	pos := 1
	for pos < len(fdLower.Body.List)-1 && skipInactiveHookIf(fdLower.Body.List[pos], fdLower) {
		pos++
	}
	for _, mid := range fdLower.Body.List[pos : len(fdLower.Body.List)-1] {
		if ifs, okI := mid.(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
			if _, okNB := isSelectorBaseField(ifs.Cond, lowRecv, "nonblock"); okNB {
				if es, okES := ifs.Body.List[0].(*ast.ExprStmt); okES {
					if _, okSB := isZeroArgMethodCallOnSelector(es.X, lowRecv, "pfd", "SetBlocking"); okSB {
						continue
					}
				}
			}
		}
		if as, okA := mid.(*ast.AssignStmt); okA && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			if _, okBlank := isIdentNamed(as.Lhs[0], "_"); okBlank {
				if _, okDis := isZeroArgMethodCallOnSelector(as.Rhs[0], lowRecv, "pfd", "DisassociateIOCP"); okDis {
					continue
				}
			}
		}
		return fmt.Errorf("os: (*File).fd unexpected statement before final return")
	}
	lastRet, ok := fdLower.Body.List[len(fdLower.Body.List)-1].(*ast.ReturnStmt)
	if !ok || len(lastRet.Results) != 1 {
		return fmt.Errorf("os: (*File).fd invalid final return")
	}
	convCall, ok := unwrapParens(lastRet.Results[0]).(*ast.CallExpr)
	if !ok || convCall.Ellipsis.IsValid() || len(convCall.Args) != 1 {
		return fmt.Errorf("os: (*File).fd final return is not uintptr(...) conversion")
	}
	if _, okU := isIdentNamed(convCall.Fun, "uintptr"); !okU {
		return fmt.Errorf("os: (*File).fd final return is not uintptr(...)")
	}
	_, okSysfdDirect := isSelectorBaseField(convCall.Args[0], lowRecv, "sysfd")
	var okPFDSysfd bool
	if sel, okS := unwrapParens(convCall.Args[0]).(*ast.SelectorExpr); okS && sel.Sel.Name == "Sysfd" {
		_, okPFDSysfd = isSelectorBaseField(sel.X, lowRecv, "pfd")
	}
	if !okSysfdDirect && !okPFDSysfd {
		return fmt.Errorf("os: (*File).fd does not return uintptr(%s.pfd.Sysfd) or uintptr(%s.sysfd)", lowRecv, lowRecv)
	}
	return nil
}

func isDirinfoSwapCloseIf(st ast.Stmt, rcRecv string, dirInfoCloseFn *ast.FuncDecl, osNoFileReserved, osAnyLinknameLocals map[string]bool) bool {
	ifs, ok := st.(*ast.IfStmt)
	if !ok || ifs.Init == nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
		return false
	}
	initAs, ok := ifs.Init.(*ast.AssignStmt)
	if !ok || initAs.Tok != token.DEFINE || len(initAs.Lhs) != 1 || len(initAs.Rhs) != 1 {
		return false
	}
	infoID, ok := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
	if !ok || infoID.Name == "" || infoID.Name == "_" || condChecksNonZeroErr(ifs.Cond) != infoID.Name {
		return false
	}
	swapCall, ok := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
	if !ok || swapCall.Ellipsis.IsValid() || len(swapCall.Args) != 1 {
		return false
	}
	if _, okNil := isIdentNamed(swapCall.Args[0], "nil"); !okNil {
		return false
	}
	swapSel, ok := unwrapParens(swapCall.Fun).(*ast.SelectorExpr)
	if !ok || swapSel.Sel.Name != "Swap" {
		return false
	}
	if _, okDI := isSelectorBaseField(swapSel.X, rcRecv, "dirinfo"); !okDI {
		return false
	}
	es, ok := ifs.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	if _, okCl := isZeroArgMethodCallOnIdent(es.X, infoID.Name, "close"); !okCl {
		return false
	}
	if dirInfoCloseFn == nil || dirInfoCloseFn.Body == nil || osAnyLinknameLocals["close"] || funcShadowsAnyIdent(dirInfoCloseFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(dirInfoCloseFn.Body) {
		return false
	}
	badDirClose := false
	ast.Inspect(dirInfoCloseFn.Body, func(n ast.Node) bool {
		if badDirClose || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.DeferStmt, *ast.GoStmt, *ast.FuncLit:
			badDirClose = true
			return false
		case *ast.Ident:
			if x.Name == "testlog" {
				badDirClose = true
				return false
			}
		case *ast.ReturnStmt:
			if len(x.Results) != 0 {
				badDirClose = true
				return false
			}
		}
		return true
	})
	return !badDirClose
}

func verifyOSOpenFileNolog(fn *ast.FuncDecl, allTopFuncs map[string]*ast.FuncDecl, funcFile map[*ast.FuncDecl]*ast.File, fileImportsSyscall map[*ast.File]bool, osNoFileReserved, osAnyLinknameLocals map[string]bool, skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool) error {
	if fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || osAnyLinknameLocals["openFileNolog"] {
		return fmt.Errorf("os: missing or invalid openFileNolog")
	}
	if funcShadowsAnyIdent(fn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
		return fmt.Errorf("os: openFileNolog shadows reserved identifier or has control-flow/recover bypass")
	}
	pNames := paramNamesFlat(fn.Type.Params)
	if len(pNames) != 3 || pNames[0] == "" || pNames[0] == "_" || pNames[1] == "" || pNames[1] == "_" || pNames[2] == "" || pNames[2] == "_" {
		return fmt.Errorf("os: openFileNolog invalid parameters")
	}
	if fn.Type.Results == nil || fn.Type.Results.NumFields() != 2 || !funcReturnsErrorLast(fn.Type) {
		return fmt.Errorf("os: openFileNolog invalid results")
	}
	if starF, okS := unwrapParens(fn.Type.Results.List[0].Type).(*ast.StarExpr); !okS {
		return fmt.Errorf("os: openFileNolog first result is not *File")
	} else if _, okF := isIdentNamed(starF.X, "File"); !okF {
		return fmt.Errorf("os: openFileNolog first result is not *File")
	}
	p0 := pNames[0]
	if bodyMutatesOrTakesAddrOfAny(fn.Body, map[string]bool{p0: true}) || bodyDeclaresAnyIdent(fn.Body, map[string]bool{p0: true}) {
		return fmt.Errorf("os: openFileNolog mutates or shadows %s", p0)
	}
	pos := 0
	for pos < len(fn.Body.List) && skipInactiveHookIf(fn.Body.List[pos], fn) {
		pos++
	}
	if len(fn.Body.List) < pos+3 {
		return fmt.Errorf("os: openFileNolog body too short")
	}

	isVerifiedFileLit := func(expr ast.Expr, fdNames map[string]bool, wantName string) bool {
		outerLit, outerType := compositeWriterLit(expr)
		if outerLit == nil || outerType != "File" || len(outerLit.Elts) != 1 {
			return false
		}
		innerExpr := outerLit.Elts[0]
		if kv, okKV := innerExpr.(*ast.KeyValueExpr); okKV {
			if _, okKey := isIdentNamed(kv.Key, "file"); !okKey {
				return false
			}
			innerExpr = kv.Value
		}
		innerLit, innerType := compositeWriterLit(innerExpr)
		if innerLit == nil || innerType != "file" {
			return false
		}
		var sawName, sawFD bool
		for _, elt := range innerLit.Elts {
			kv, okKV := elt.(*ast.KeyValueExpr)
			if !okKV {
				return false
			}
			kID, okK := unwrapParens(kv.Key).(*ast.Ident)
			if !okK {
				return false
			}
			switch kID.Name {
			case "name":
				if _, okN := isIdentNamed(kv.Value, wantName); !okN {
					return false
				}
				sawName = true
			case "sysfd":
				if vID, okV := unwrapParens(kv.Value).(*ast.Ident); !okV || !fdNames[vID.Name] {
					return false
				}
				sawFD = true
			case "pfd":
				pfdLit, okCL := unwrapParens(kv.Value).(*ast.CompositeLit)
				if !okCL {
					return false
				}
				for _, pElt := range pfdLit.Elts {
					pkv, okPKV := pElt.(*ast.KeyValueExpr)
					if !okPKV {
						return false
					}
					if _, okSys := isIdentNamed(pkv.Key, "Sysfd"); okSys {
						vID, okV := unwrapParens(pkv.Value).(*ast.Ident)
						if !okV || !fdNames[vID.Name] {
							return false
						}
						sawFD = true
					}
				}
			}
		}
		return sawName && sawFD
	}

	verifyNewFileHelper := func(nfFn *ast.FuncDecl) bool {
		if nfFn == nil || nfFn.Body == nil || osAnyLinknameLocals[nfFn.Name.Name] || funcShadowsAnyIdent(nfFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(nfFn.Body) {
			return false
		}
		nfParams := paramNamesFlat(nfFn.Type.Params)
		if len(nfParams) < 2 || nfParams[0] == "" || nfParams[0] == "_" || nfParams[1] == "" || nfParams[1] == "_" {
			return false
		}
		fdP, nameP := nfParams[0], nfParams[1]
		if bodyMutatesOrTakesAddrOfAny(nfFn.Body, map[string]bool{fdP: true, nameP: true}) || bodyDeclaresAnyIdent(nfFn.Body, map[string]bool{fdP: true, nameP: true}) {
			return false
		}
		hasTestlog := false
		ast.Inspect(nfFn.Body, func(n ast.Node) bool {
			if id, okID := n.(*ast.Ident); okID && id.Name == "testlog" {
				hasTestlog = true
				return false
			}
			return !hasTestlog
		})
		if hasTestlog || len(nfFn.Body.List) == 0 {
			return false
		}
		fdAliases := map[string]bool{fdP: true}
		scanIdx := 0
		if as0, okA := nfFn.Body.List[0].(*ast.AssignStmt); okA && as0.Tok == token.DEFINE && len(as0.Lhs) == 1 && len(as0.Rhs) == 1 {
			if aID, okID := unwrapParens(as0.Lhs[0]).(*ast.Ident); okID && aID.Name != "" && aID.Name != "_" {
				if conv, okC := unwrapParens(as0.Rhs[0]).(*ast.CallExpr); okC && !conv.Ellipsis.IsValid() && len(conv.Args) == 1 {
					if _, okArg := isIdentNamed(conv.Args[0], fdP); okArg {
						_, okInt := isIdentNamed(conv.Fun, "int")
						_, okH := isSelectorBaseField(conv.Fun, "syscall", "Handle")
						if (okInt || okH) && !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: nfFn.Body.List[1:]}, map[string]bool{aID.Name: true}) {
							fdAliases[aID.Name] = true
							scanIdx = 1
						}
					}
				}
			}
		}
		if scanIdx < len(nfFn.Body.List) {
			if ifs, okI := nfFn.Body.List[scanIdx].(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
				if rNil, okR := ifs.Body.List[0].(*ast.ReturnStmt); okR && len(rNil.Results) == 1 {
					if _, okN := isIdentNamed(rNil.Results[0], "nil"); okN && !exprContainsAnyCall(ifs.Cond) {
						scanIdx++
					}
				}
			}
		}
		if scanIdx == len(nfFn.Body.List)-1 {
			if ret, okR := nfFn.Body.List[scanIdx].(*ast.ReturnStmt); okR && len(ret.Results) == 1 {
				if isVerifiedFileLit(ret.Results[0], fdAliases, nameP) {
					return true
				}
				if c, okC := unwrapParens(ret.Results[0]).(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) >= 2 {
					if cFun, okF := unwrapParens(c.Fun).(*ast.Ident); okF && cFun.Name == "newFile" {
						if a0, ok0 := unwrapParens(c.Args[0]).(*ast.Ident); ok0 && fdAliases[a0.Name] {
							if _, ok1 := isIdentNamed(c.Args[1], nameP); ok1 && nfFn.Name.Name != "newFile" {
								return allTopFuncs["newFile"] != nil
							}
						}
					}
				}
			}
		}
		fDeclIdx := -1
		var nfVar string
		for idx := scanIdx; idx < len(nfFn.Body.List); idx++ {
			if as, okA := nfFn.Body.List[idx].(*ast.AssignStmt); okA && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
				if vID, okID := unwrapParens(as.Lhs[0]).(*ast.Ident); okID && vID.Name != "" && vID.Name != "_" && isVerifiedFileLit(as.Rhs[0], fdAliases, nameP) {
					fDeclIdx = idx
					nfVar = vID.Name
					break
				}
			}
		}
		if fDeclIdx < 0 || nfVar == "" {
			return false
		}
		if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: nfFn.Body.List[fDeclIdx+1:]}, map[string]bool{nfVar: true}) || bodyDeclaresAnyIdent(&ast.BlockStmt{List: nfFn.Body.List[fDeclIdx+1:]}, map[string]bool{nfVar: true}) {
			return false
		}
		badPost := false
		for _, st := range nfFn.Body.List[:fDeclIdx] {
			ast.Inspect(st, func(n ast.Node) bool {
				if _, isFL := n.(*ast.FuncLit); isFL {
					return false
				}
				if _, okR := n.(*ast.ReturnStmt); okR && st != nfFn.Body.List[scanIdx-1] {
					badPost = true
					return false
				}
				return !badPost
			})
		}
		for _, st := range nfFn.Body.List[fDeclIdx+1:] {
			ast.Inspect(st, func(n ast.Node) bool {
				if badPost || n == nil {
					return false
				}
				if as, okA := n.(*ast.AssignStmt); okA {
					for _, lhs := range as.Lhs {
						if sel, okS := unwrapParens(lhs).(*ast.SelectorExpr); okS {
							if _, okB := isIdentNamed(sel.X, nfVar); okB && (sel.Sel.Name == "file" || sel.Sel.Name == "pfd" || sel.Sel.Name == "sysfd" || sel.Sel.Name == "name") {
								badPost = true
								return false
							}
							if sel.Sel.Name == "Sysfd" {
								if _, okPFD := isSelectorBaseField(sel.X, nfVar, "pfd"); okPFD {
									badPost = true
									return false
								}
							}
						}
					}
				}
				return true
			})
			ast.Inspect(st, func(n ast.Node) bool {
				if badPost || n == nil {
					return false
				}
				if _, isFL := n.(*ast.FuncLit); isFL {
					return false
				}
				if r, okR := n.(*ast.ReturnStmt); okR {
					if len(r.Results) != 1 {
						badPost = true
						return false
					}
					if _, okV := isIdentNamed(r.Results[0], nfVar); !okV {
						badPost = true
						return false
					}
				}
				return true
			})
		}
		lastRet, okLR := nfFn.Body.List[len(nfFn.Body.List)-1].(*ast.ReturnStmt)
		if badPost || !okLR || len(lastRet.Results) != 1 {
			return false
		}
		_, okFinal := isIdentNamed(lastRet.Results[0], nfVar)
		return okFinal
	}

	matchNewFileCall := func(expr ast.Expr) (string, bool) {
		c, okC := unwrapParens(expr).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) < 2 {
			return "", false
		}
		fnID, okF := unwrapParens(c.Fun).(*ast.Ident)
		if !okF {
			return "", false
		}
		if _, okName := isIdentNamed(c.Args[1], p0); !okName {
			return "", false
		}
		switch fnID.Name {
		case "newFile":
			fdID, okFD := unwrapParens(c.Args[0]).(*ast.Ident)
			if !okFD || fdID.Name == "" || fdID.Name == "_" || !verifyNewFileHelper(allTopFuncs["newFile"]) {
				return "", false
			}
			return fdID.Name, true
		case "NewFile":
			if len(c.Args) != 2 {
				return "", false
			}
			uConv, okConv := unwrapParens(c.Args[0]).(*ast.CallExpr)
			if !okConv || uConv.Ellipsis.IsValid() || len(uConv.Args) != 1 {
				return "", false
			}
			if _, okU := isIdentNamed(uConv.Fun, "uintptr"); !okU {
				return "", false
			}
			fdID, okFD := unwrapParens(uConv.Args[0]).(*ast.Ident)
			nfExported := allTopFuncs["NewFile"]
			if !okFD || fdID.Name == "" || fdID.Name == "_" || nfExported == nil || nfExported.Body == nil || osAnyLinknameLocals["NewFile"] || len(nfExported.Body.List) == 0 {
				return "", false
			}
			nfExpParams := paramNamesFlat(nfExported.Type.Params)
			if len(nfExpParams) != 2 {
				return "", false
			}
			lastExp, okLE := nfExported.Body.List[len(nfExported.Body.List)-1].(*ast.ReturnStmt)
			if !okLE || len(lastExp.Results) != 1 {
				return "", false
			}
			delCall, okDC := unwrapParens(lastExp.Results[0]).(*ast.CallExpr)
			if !okDC || delCall.Ellipsis.IsValid() || len(delCall.Args) != 2 {
				return "", false
			}
			_, okDelFun := isIdentNamed(delCall.Fun, "newFileFromNewFile")
			_, okD0 := isIdentNamed(delCall.Args[0], nfExpParams[0])
			_, okD1 := isIdentNamed(delCall.Args[1], nfExpParams[1])
			if !okDelFun || !okD0 || !okD1 || !verifyNewFileHelper(allTopFuncs["newFileFromNewFile"]) {
				return "", false
			}
			if allTopFuncs["newFile"] != nil && !verifyNewFileHelper(allTopFuncs["newFile"]) {
				return "", false
			}
			return fdID.Name, true
		default:
			return "", false
		}
	}

	lastRet, ok := fn.Body.List[len(fn.Body.List)-1].(*ast.ReturnStmt)
	if !ok || len(lastRet.Results) != 2 {
		return fmt.Errorf("os: openFileNolog missing trailing 2-value return")
	}
	if _, okNil := isIdentNamed(lastRet.Results[1], "nil"); !okNil {
		return fmt.Errorf("os: openFileNolog final return error is not nil")
	}

	var wantFDVar string
	fConstructIdx := -1
	if fdV, okInline := matchNewFileCall(lastRet.Results[0]); okInline {
		wantFDVar = fdV
		fConstructIdx = len(fn.Body.List) - 1
	} else if fVarID, okFV := unwrapParens(lastRet.Results[0]).(*ast.Ident); okFV && fVarID.Name != "" && fVarID.Name != "_" {
		for candIdx := len(fn.Body.List) - 2; candIdx >= pos && candIdx >= len(fn.Body.List)-3; candIdx-- {
			as, okA := fn.Body.List[candIdx].(*ast.AssignStmt)
			if !okA || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				continue
			}
			if _, okLHS := isIdentNamed(as.Lhs[0], fVarID.Name); !okLHS {
				continue
			}
			fdV, okNF := matchNewFileCall(as.Rhs[0])
			if !okNF {
				continue
			}
			tailOK := !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: fn.Body.List[candIdx+1:]}, map[string]bool{fVarID.Name: true})
			for _, tailSt := range fn.Body.List[candIdx+1 : len(fn.Body.List)-1] {
				tAs, okTA := tailSt.(*ast.AssignStmt)
				if !okTA || tAs.Tok != token.ASSIGN || len(tAs.Lhs) != 1 || len(tAs.Rhs) != 1 || exprContainsAnyCall(tAs.Rhs[0]) {
					tailOK = false
					break
				}
				sel, okS := unwrapParens(tAs.Lhs[0]).(*ast.SelectorExpr)
				if !okS || sel.Sel.Name != "SysFile" {
					tailOK = false
					break
				}
				if _, okPFD := isSelectorBaseField(sel.X, fVarID.Name, "pfd"); !okPFD {
					tailOK = false
					break
				}
			}
			if tailOK {
				wantFDVar = fdV
				fConstructIdx = candIdx
				break
			}
		}
	}
	if fConstructIdx < pos+2 || wantFDVar == "" {
		return fmt.Errorf("os: openFileNolog missing verified newFile construction")
	}

	isPathErrorReturn := func(ret *ast.ReturnStmt) bool {
		if ret == nil || len(ret.Results) != 2 {
			return false
		}
		if _, okNil := isIdentNamed(ret.Results[0], "nil"); !okNil {
			return false
		}
		u, okU := unwrapParens(ret.Results[1]).(*ast.UnaryExpr)
		lit, tName := compositeWriterLit(ret.Results[1])
		if !okU || u.Op != token.AND || lit == nil || tName != "PathError" {
			return false
		}
		for _, elt := range lit.Elts {
			if kv, okKV := elt.(*ast.KeyValueExpr); okKV {
				if _, okE := isIdentNamed(kv.Key, "Err"); okE {
					_, isNilErr := isIdentNamed(kv.Value, "nil")
					return !isNilErr
				}
			}
		}
		return false
	}

	badMidReturn := false
	for _, st := range fn.Body.List[pos:fConstructIdx] {
		if _, isBareRet := st.(*ast.ReturnStmt); isBareRet {
			return fmt.Errorf("os: openFileNolog unexpected unconditional return before newFile")
		}
		ast.Inspect(st, func(n ast.Node) bool {
			if badMidReturn || n == nil {
				return false
			}
			if _, isFL := n.(*ast.FuncLit); isFL {
				return false
			}
			if ret, okR := n.(*ast.ReturnStmt); okR && !isPathErrorReturn(ret) {
				badMidReturn = true
				return false
			}
			return true
		})
		if badMidReturn {
			return fmt.Errorf("os: openFileNolog early return does not return (nil, &PathError)")
		}
	}

	verifyIgnoringEINTR := func(igFn *ast.FuncDecl) bool {
		return verifyOSIgnoringEINTR(igFn, funcFile, fileImportsSyscall, osNoFileReserved, osAnyLinknameLocals)
	}

	verifyJoinPathHelper := func(jpFn *ast.FuncDecl) bool {
		if jpFn == nil || jpFn.Body == nil || osAnyLinknameLocals["joinPath"] || funcShadowsAnyIdent(jpFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(jpFn.Body) {
			return false
		}
		hasTestlog := false
		ast.Inspect(jpFn.Body, func(n ast.Node) bool {
			if id, okID := n.(*ast.Ident); okID && id.Name == "testlog" {
				hasTestlog = true
				return false
			}
			return !hasTestlog
		})
		return !hasTestlog
	}

	isMinusOneLit := func(expr ast.Expr) bool {
		u, okU := unwrapParens(expr).(*ast.UnaryExpr)
		if !okU || u.Op != token.SUB {
			return false
		}
		lit, okL := unwrapParens(u.X).(*ast.BasicLit)
		return okL && lit.Kind == token.INT && lit.Value == "1"
	}

	verifyOpenHelper := func(opFn *ast.FuncDecl) bool {
		if opFn == nil || opFn.Body == nil || osAnyLinknameLocals["open"] || !fileImportsSyscall[funcFile[opFn]] || funcShadowsAnyIdent(opFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(opFn.Body) {
			return false
		}
		opParams := paramNamesFlat(opFn.Type.Params)
		if len(opParams) != 3 || opParams[0] == "" || opParams[0] == "_" || len(opFn.Body.List) < 2 {
			return false
		}
		if bodyMutatesOrTakesAddrOfAny(opFn.Body, map[string]bool{opParams[0]: true}) || bodyDeclaresAnyIdent(opFn.Body, map[string]bool{opParams[0]: true}) {
			return false
		}
		hasTestlog := false
		ast.Inspect(opFn.Body, func(n ast.Node) bool {
			if id, okID := n.(*ast.Ident); okID && id.Name == "testlog" {
				hasTestlog = true
				return false
			}
			return !hasTestlog
		})
		if hasTestlog {
			return false
		}
		lastRet, okLR := opFn.Body.List[len(opFn.Body.List)-1].(*ast.ReturnStmt)
		if !okLR || len(lastRet.Results) != 3 {
			return false
		}
		fdRetID, okFD := unwrapParens(lastRet.Results[0]).(*ast.Ident)
		errRetID, okER := unwrapParens(lastRet.Results[2]).(*ast.Ident)
		if !okFD || !okER || fdRetID.Name == "" || errRetID.Name == "" {
			return false
		}
		checkedErrIfRets := map[*ast.ReturnStmt]bool{}
		ast.Inspect(&ast.BlockStmt{List: opFn.Body.List[:len(opFn.Body.List)-1]}, func(n ast.Node) bool {
			if ifs, okI := n.(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
				if eName := condChecksNonZeroErr(ifs.Cond); eName != "" {
					if r, okR := ifs.Body.List[0].(*ast.ReturnStmt); okR && len(r.Results) == 3 && isMinusOneLit(r.Results[0]) {
						if _, okE := isIdentNamed(r.Results[2], eName); okE {
							checkedErrIfRets[r] = true
						}
					}
				}
			}
			return true
		})
		badEarlyRet := false
		ast.Inspect(&ast.BlockStmt{List: opFn.Body.List[:len(opFn.Body.List)-1]}, func(n ast.Node) bool {
			if badEarlyRet || n == nil {
				return false
			}
			if r, okR := n.(*ast.ReturnStmt); okR {
				if checkedErrIfRets[r] {
					return false
				}
				if len(r.Results) != 3 || !isMinusOneLit(r.Results[0]) {
					badEarlyRet = true
					return false
				}
				sel, okS := unwrapParens(r.Results[2]).(*ast.SelectorExpr)
				if !okS || sel.Sel.Name == "" {
					badEarlyRet = true
					return false
				}
				if _, okSys := isIdentNamed(sel.X, "syscall"); !okSys {
					badEarlyRet = true
					return false
				}
			}
			return true
		})
		if badEarlyRet {
			return false
		}
		opPathAliases := map[string]bool{opParams[0]: true}
		sawSyscallOpen := false
		for idx := 0; idx < len(opFn.Body.List)-1; idx++ {
			st := opFn.Body.List[idx]
			if as, okA := st.(*ast.AssignStmt); okA && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
				if aID, okID := unwrapParens(as.Lhs[0]).(*ast.Ident); okID && aID.Name != "" && aID.Name != "_" {
					if _, okSrc := isIdentNamed(as.Rhs[0], opParams[0]); okSrc {
						afterIdx := idx + 1
						if afterIdx < len(opFn.Body.List)-1 {
							if ifs, okI := opFn.Body.List[afterIdx].(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 3 {
								s0, ok0 := ifs.Body.List[0].(*ast.AssignStmt)
								s1, ok1 := ifs.Body.List[1].(*ast.IfStmt)
								s2, ok2 := ifs.Body.List[2].(*ast.AssignStmt)
								if ok0 && ok1 && ok2 && s0.Tok == token.DEFINE && len(s0.Lhs) == 2 && len(s0.Rhs) == 1 && s2.Tok == token.ASSIGN && len(s2.Lhs) == 1 && len(s2.Rhs) == 1 {
									wdID, okWD := unwrapParens(s0.Lhs[0]).(*ast.Ident)
									wdErrID, okWE := unwrapParens(s0.Lhs[1]).(*ast.Ident)
									wdCall, okWC := unwrapParens(s0.Rhs[0]).(*ast.CallExpr)
									_, okAliasLHS := isIdentNamed(s2.Lhs[0], aID.Name)
									jpCall, okJC := unwrapParens(s2.Rhs[0]).(*ast.CallExpr)
									if okWD && okWE && okWC && okAliasLHS && okJC && wdID.Name != "" && wdID.Name != "_" && wdErrID.Name != "" && !wdCall.Ellipsis.IsValid() && len(wdCall.Args) == 0 && !jpCall.Ellipsis.IsValid() && len(jpCall.Args) == 2 && condChecksNonZeroErr(s1.Cond) == wdErrID.Name && len(s1.Body.List) == 1 {
										_, okGetwd := isSelectorBaseField(wdCall.Fun, "syscall", "Getwd")
										_, okJP := isIdentNamed(jpCall.Fun, "joinPath")
										_, okJA0 := isIdentNamed(jpCall.Args[0], wdID.Name)
										_, okJA1 := isIdentNamed(jpCall.Args[1], opParams[0])
										_, okRet := s1.Body.List[0].(*ast.ReturnStmt)
										if okGetwd && okJP && okJA0 && okJA1 && okRet && verifyJoinPathHelper(allTopFuncs["joinPath"]) {
											afterIdx++
										}
									}
								}
							}
						}
						if !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: opFn.Body.List[afterIdx:]}, map[string]bool{aID.Name: true}) && !bodyDeclaresAnyIdent(&ast.BlockStmt{List: opFn.Body.List[idx+1:]}, map[string]bool{aID.Name: true}) {
							opPathAliases[aID.Name] = true
							continue
						}
					}
				}
			}
			as, okA := st.(*ast.AssignStmt)
			if !okA || len(as.Lhs) != 2 || len(as.Rhs) != 1 {
				continue
			}
			if _, okL0 := isIdentNamed(as.Lhs[0], fdRetID.Name); !okL0 {
				continue
			}
			if _, okL1 := isIdentNamed(as.Lhs[1], errRetID.Name); !okL1 {
				continue
			}
			sc, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
			if !okC || sc.Ellipsis.IsValid() || len(sc.Args) < 1 {
				continue
			}
			if _, okSel := isSelectorBaseField(sc.Fun, "syscall", "Open"); okSel {
				if pID, okP := unwrapParens(sc.Args[0]).(*ast.Ident); okP && opPathAliases[pID.Name] && !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: opFn.Body.List[idx+1:]}, map[string]bool{fdRetID.Name: true, errRetID.Name: true}) {
					sawSyscallOpen = true
					break
				}
			}
		}
		return sawSyscallOpen
	}

	pathAliases := map[string]bool{p0: true}
	openIdx := -1
	var openErrVar string
	for idx := pos; idx < fConstructIdx-1; idx++ {
		st := fn.Body.List[idx]
		if as, okA := st.(*ast.AssignStmt); okA && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			if pID, okP := unwrapParens(as.Lhs[0]).(*ast.Ident); okP && pID.Name != "" && pID.Name != "_" {
				if flCall, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr); okC && !flCall.Ellipsis.IsValid() && len(flCall.Args) == 1 {
					_, okFL := isIdentNamed(flCall.Fun, "fixLongPath")
					_, okArg := isIdentNamed(flCall.Args[0], p0)
					flFn := allTopFuncs["fixLongPath"]
					if okFL && okArg && flFn != nil && flFn.Body != nil && !osAnyLinknameLocals["fixLongPath"] && !funcShadowsAnyIdent(flFn, osNoFileReserved) && !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: fn.Body.List[idx+1:]}, map[string]bool{pID.Name: true}) {
						pathAliases[pID.Name] = true
						continue
					}
				}
			}
		}
		// Form 1: ignoringEINTR(func() error { <wantFDVar>, ..., <eVar> = open(<p0>, ...); return <eVar> })
		if es, okES := st.(*ast.ExprStmt); okES {
			if igCall, okC := unwrapParens(es.X).(*ast.CallExpr); okC && !igCall.Ellipsis.IsValid() && len(igCall.Args) == 1 {
				if _, okIG := isIdentNamed(igCall.Fun, "ignoringEINTR"); okIG && verifyIgnoringEINTR(allTopFuncs["ignoringEINTR"]) && verifyOpenHelper(allTopFuncs["open"]) {
					if fl, okFL := unwrapParens(igCall.Args[0]).(*ast.FuncLit); okFL && fl.Body != nil && len(fl.Body.List) == 2 {
						inAs, okIA := fl.Body.List[0].(*ast.AssignStmt)
						inRet, okIR := fl.Body.List[1].(*ast.ReturnStmt)
						if okIA && okIR && inAs.Tok == token.ASSIGN && len(inAs.Lhs) == 3 && len(inAs.Rhs) == 1 && len(inRet.Results) == 1 {
							_, okFD := isIdentNamed(inAs.Lhs[0], wantFDVar)
							eID, okE := unwrapParens(inAs.Lhs[2]).(*ast.Ident)
							opCall, okOC := unwrapParens(inAs.Rhs[0]).(*ast.CallExpr)
							if okFD && okE && okOC && eID.Name != "" && eID.Name != "_" && eID.Name != wantFDVar && !opCall.Ellipsis.IsValid() && len(opCall.Args) == 3 {
								_, okOpFun := isIdentNamed(opCall.Fun, "open")
								_, okOpArg := isIdentNamed(opCall.Args[0], p0)
								_, okRetE := isIdentNamed(inRet.Results[0], eID.Name)
								if okOpFun && okOpArg && okRetE {
									openIdx = idx
									openErrVar = eID.Name
									break
								}
							}
						}
					}
				}
			}
		}
		// Form 2: <wantFDVar>, <eVar> := syscall.Open(<path>, ...)
		if as, okA := st.(*ast.AssignStmt); okA && (as.Tok == token.DEFINE || as.Tok == token.ASSIGN) && len(as.Lhs) == 2 && len(as.Rhs) == 1 && fileImportsSyscall[funcFile[fn]] {
			_, okFD := isIdentNamed(as.Lhs[0], wantFDVar)
			eID, okE := unwrapParens(as.Lhs[1]).(*ast.Ident)
			sc, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
			if okFD && okE && okC && eID.Name != "" && eID.Name != "_" && eID.Name != wantFDVar && !sc.Ellipsis.IsValid() && len(sc.Args) >= 2 {
				if _, okSel := isSelectorBaseField(sc.Fun, "syscall", "Open"); okSel {
					if pArg, okPA := unwrapParens(sc.Args[0]).(*ast.Ident); okPA && pathAliases[pArg.Name] {
						openIdx = idx
						openErrVar = eID.Name
						break
					}
				}
			}
		}
		// Form 3 (Plan 9): if ... { <wantFDVar>, <eVar> = syscall.Create(<p0>, ...) } else { <wantFDVar>, <eVar> = syscall.Open(<p0>, ...); [if IsNotExist(<eVar>) && ... { <wantFDVar>, <eVar> = syscall.Create(<p0>, ...); if <eVar> != nil { return nil, &PathError{...} } }] }
		if ifs, okI := st.(*ast.IfStmt); okI && ifs.Else != nil && fileImportsSyscall[funcFile[fn]] {
			elseBlk, okEB := ifs.Else.(*ast.BlockStmt)
			if okEB && len(ifs.Body.List) == 1 && (len(elseBlk.List) == 1 || len(elseBlk.List) == 2) {
				as1, okA1 := ifs.Body.List[0].(*ast.AssignStmt)
				as2, okA2 := elseBlk.List[0].(*ast.AssignStmt)
				if okA1 && okA2 && as1.Tok == token.ASSIGN && as2.Tok == token.ASSIGN && len(as1.Lhs) == 2 && len(as1.Rhs) == 1 && len(as2.Lhs) == 2 && len(as2.Rhs) == 1 {
					_, okFD1 := isIdentNamed(as1.Lhs[0], wantFDVar)
					_, okFD2 := isIdentNamed(as2.Lhs[0], wantFDVar)
					e1, okE1 := unwrapParens(as1.Lhs[1]).(*ast.Ident)
					e2, okE2 := unwrapParens(as2.Lhs[1]).(*ast.Ident)
					c1, okC1 := unwrapParens(as1.Rhs[0]).(*ast.CallExpr)
					c2, okC2 := unwrapParens(as2.Rhs[0]).(*ast.CallExpr)
					if okFD1 && okFD2 && okE1 && okE2 && okC1 && okC2 && e1.Name != "" && e1.Name != "_" && e1.Name != wantFDVar && e1.Name == e2.Name && !c1.Ellipsis.IsValid() && !c2.Ellipsis.IsValid() && len(c1.Args) >= 1 && len(c2.Args) >= 1 {
						_, okCr := isSelectorBaseField(c1.Fun, "syscall", "Create")
						_, okOp := isSelectorBaseField(c2.Fun, "syscall", "Open")
						_, okP1 := isIdentNamed(c1.Args[0], p0)
						_, okP2 := isIdentNamed(c2.Args[0], p0)
						elseTailOK := len(elseBlk.List) == 1
						if len(elseBlk.List) == 2 {
							subIf, okSI := elseBlk.List[1].(*ast.IfStmt)
							if okSI && subIf.Init == nil && subIf.Else == nil && len(subIf.Body.List) == 2 {
								as3, okA3 := subIf.Body.List[0].(*ast.AssignStmt)
								errSubIf, okEI := subIf.Body.List[1].(*ast.IfStmt)
								if okA3 && okEI && as3.Tok == token.ASSIGN && len(as3.Lhs) == 2 && len(as3.Rhs) == 1 && errSubIf.Init == nil && errSubIf.Else == nil && condChecksNonZeroErr(errSubIf.Cond) == e1.Name && len(errSubIf.Body.List) == 1 {
									_, okFD3 := isIdentNamed(as3.Lhs[0], wantFDVar)
									_, okE3 := isIdentNamed(as3.Lhs[1], e1.Name)
									c3, okC3 := unwrapParens(as3.Rhs[0]).(*ast.CallExpr)
									subRet, okSR := errSubIf.Body.List[0].(*ast.ReturnStmt)
									if okFD3 && okE3 && okC3 && okSR && !c3.Ellipsis.IsValid() && len(c3.Args) >= 1 && isPathErrorReturn(subRet) {
										_, okCr3 := isSelectorBaseField(c3.Fun, "syscall", "Create")
										_, okP3 := isIdentNamed(c3.Args[0], p0)
										elseTailOK = okCr3 && okP3
									}
								}
							}
						}
						if okCr && okOp && okP1 && okP2 && elseTailOK {
							openIdx = idx
							openErrVar = e1.Name
							break
						}
					}
				}
			}
		}
	}
	if openIdx < 0 || openErrVar == "" {
		return fmt.Errorf("os: openFileNolog missing verified syscall.Open acquisition")
	}
	errIf, ok := fn.Body.List[openIdx+1].(*ast.IfStmt)
	if !ok || errIf.Init != nil || errIf.Else != nil || condChecksNonZeroErr(errIf.Cond) != openErrVar || len(errIf.Body.List) != 1 {
		return fmt.Errorf("os: openFileNolog missing error check immediately after open")
	}
	errRet, ok := errIf.Body.List[0].(*ast.ReturnStmt)
	if !ok || !isPathErrorReturn(errRet) {
		return fmt.Errorf("os: openFileNolog error check does not return &PathError")
	}
	if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: fn.Body.List[openIdx+1 : fConstructIdx]}, map[string]bool{wantFDVar: true}) || bodyDeclaresAnyIdent(&ast.BlockStmt{List: fn.Body.List[openIdx+1:]}, map[string]bool{wantFDVar: true}) {
		return fmt.Errorf("os: openFileNolog mutates or shadows descriptor %s before newFile", wantFDVar)
	}
	return nil
}

func verifyOSReadFile(rfFn *ast.FuncDecl, rfP0 string, allTopFuncs, allFileMethods, allRawFileMethods map[string]*ast.FuncDecl, osNoFileReserved, osAnyLinknameLocals map[string]bool, skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool) error {
	if len(rfFn.Body.List) != 4 {
		return fmt.Errorf("os: ReadFile must have canonical 4-statement Open/Close/readFileContents body")
	}
	s0, ok0 := rfFn.Body.List[0].(*ast.AssignStmt)
	s1, ok1 := rfFn.Body.List[1].(*ast.IfStmt)
	s2, ok2 := rfFn.Body.List[2].(*ast.DeferStmt)
	s3, ok3 := rfFn.Body.List[3].(*ast.ReturnStmt)
	if !ok0 || (s0.Tok != token.DEFINE && s0.Tok != token.ASSIGN) || len(s0.Lhs) != 2 || len(s0.Rhs) != 1 || !ok1 || s1.Init != nil || s1.Else != nil || len(s1.Body.List) != 1 || !ok2 || !ok3 || len(s3.Results) != 1 {
		return fmt.Errorf("os: ReadFile invalid canonical body shape")
	}
	fID, okF := unwrapParens(s0.Lhs[0]).(*ast.Ident)
	eID, okE := unwrapParens(s0.Lhs[1]).(*ast.Ident)
	openCall, okOC := unwrapParens(s0.Rhs[0]).(*ast.CallExpr)
	if !okF || !okE || !okOC || fID.Name == "" || fID.Name == "_" || eID.Name == "" || eID.Name == "_" || fID.Name == eID.Name || openCall.Ellipsis.IsValid() || len(openCall.Args) != 1 {
		return fmt.Errorf("os: ReadFile first statement must be f, err := Open(%s)", rfP0)
	}
	_, okOpenFun := isIdentNamed(openCall.Fun, "Open")
	_, okOpenArg := isIdentNamed(openCall.Args[0], rfP0)
	if !okOpenFun || !okOpenArg || condChecksNonZeroErr(s1.Cond) != eID.Name {
		return fmt.Errorf("os: ReadFile Open call or error guard invalid")
	}
	errRet, okER := s1.Body.List[0].(*ast.ReturnStmt)
	if !okER || len(errRet.Results) != 2 {
		return fmt.Errorf("os: ReadFile error guard invalid return")
	}
	_, okNil0 := isIdentNamed(errRet.Results[0], "nil")
	_, okErr1 := isIdentNamed(errRet.Results[1], eID.Name)
	if !okNil0 || !okErr1 {
		return fmt.Errorf("os: ReadFile error guard does not return nil, %s", eID.Name)
	}
	if _, okClose := isZeroArgMethodCallOnIdent(s2.Call, fID.Name, "Close"); !okClose {
		return fmt.Errorf("os: ReadFile missing defer %s.Close()", fID.Name)
	}
	rfcCall, okRFC := unwrapParens(s3.Results[0]).(*ast.CallExpr)
	if !okRFC || rfcCall.Ellipsis.IsValid() || len(rfcCall.Args) != 2 {
		return fmt.Errorf("os: ReadFile final return is not readFileContents(statOrZero(f), f.Read)")
	}
	if _, okRFCFun := isIdentNamed(rfcCall.Fun, "readFileContents"); !okRFCFun {
		return fmt.Errorf("os: ReadFile does not call readFileContents")
	}
	sozCall, okSOZ := unwrapParens(rfcCall.Args[0]).(*ast.CallExpr)
	if !okSOZ || sozCall.Ellipsis.IsValid() || len(sozCall.Args) != 1 {
		return fmt.Errorf("os: ReadFile first arg to readFileContents is not statOrZero(%s)", fID.Name)
	}
	_, okSOZFun := isIdentNamed(sozCall.Fun, "statOrZero")
	_, okSOZArg := isIdentNamed(sozCall.Args[0], fID.Name)
	_, okReadSel := isSelectorBaseField(rfcCall.Args[1], fID.Name, "Read")
	if !okSOZFun || !okSOZArg || !okReadSel {
		return fmt.Errorf("os: ReadFile arguments to readFileContents are not (statOrZero(%s), %s.Read)", fID.Name, fID.Name)
	}

	type workItem struct {
		kind       string // "top", "file", "raw"
		name       string
		arg0IsFile bool
	}
	queue := []workItem{
		{kind: "top", name: "readFileContents"},
		{kind: "top", name: "statOrZero", arg0IsFile: true},
		{kind: "file", name: "Read"},
	}
	seen := map[workItem]bool{}
	enqueue := func(it workItem) {
		if !seen[it] {
			seen[it] = true
			queue = append(queue, it)
		}
	}
	for _, it := range queue {
		seen[it] = true
	}

	forbiddenTopCalls := map[string]bool{
		"Open": true, "OpenFile": true, "Create": true, "Stat": true, "Lstat": true,
		"Getenv": true, "LookupEnv": true, "Chdir": true, "ReadDir": true, "openDir": true,
		"Exit": true, "NewFile": true, "newFile": true,
	}
	forbiddenSyscallSels := map[string]bool{
		"Open": true, "Creat": true, "Stat": true, "Lstat": true,
		"Chdir": true, "Fchdir": true, "Getenv": true, "Exit": true, "ExitProcess": true,
	}
	collectPtrTypeIdents := func(fl *ast.FieldList, targetType string, dst map[string]bool) {
		if fl == nil {
			return
		}
		for _, fld := range fl.List {
			star, okS := unwrapParens(fld.Type).(*ast.StarExpr)
			if !okS {
				continue
			}
			if _, okT := isIdentNamed(star.X, targetType); !okT {
				continue
			}
			for _, id := range fld.Names {
				if id.Name != "" && id.Name != "_" {
					dst[id.Name] = true
				}
			}
		}
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		var hFn *ast.FuncDecl
		switch cur.kind {
		case "top":
			hFn = allTopFuncs[cur.name]
		case "file":
			hFn = allFileMethods[cur.name]
		case "raw":
			hFn = allRawFileMethods[cur.name]
		}
		if hFn == nil || hFn.Body == nil || osAnyLinknameLocals[cur.name] || funcShadowsAnyIdent(hFn, map[string]bool{"testlog": true, "syscall": true}) {
			return fmt.Errorf("os: ReadFile helper %s:%s missing, bodyless, linknamed, or shadowing reserved identifier", cur.kind, cur.name)
		}
		fileVars := map[string]bool{}
		rawFileVars := map[string]bool{}
		collectPtrTypeIdents(hFn.Recv, "File", fileVars)
		collectPtrTypeIdents(hFn.Type.Params, "File", fileVars)
		collectPtrTypeIdents(hFn.Recv, "file", rawFileVars)
		collectPtrTypeIdents(hFn.Type.Params, "file", rawFileVars)
		if cur.arg0IsFile && cur.kind == "top" {
			hParams := paramNamesFlat(hFn.Type.Params)
			if len(hParams) >= 1 && hParams[0] != "" && hParams[0] != "_" && !bodyMutatesOrTakesAddrOfAny(hFn.Body, map[string]bool{hParams[0]: true}) && !bodyDeclaresAnyIdent(hFn.Body, map[string]bool{hParams[0]: true}) {
				fileVars[hParams[0]] = true
			}
		}

		pos := 0
		for pos < len(hFn.Body.List) && skipInactiveHookIf(hFn.Body.List[pos], hFn) {
			pos++
		}
		var helperErr error
		var inspectHelperNode func(n ast.Node, curFileVars map[string]bool)
		inspectHelperNode = func(n ast.Node, curFileVars map[string]bool) {
			if helperErr != nil || n == nil {
				return
			}
			if ifs, okI := n.(*ast.IfStmt); okI && skipInactiveHookIf(ifs, hFn) {
				return
			}
			if ts, okTS := n.(*ast.TypeSwitchStmt); okTS {
				var switchTarget string
				var boundName string
				switch as := ts.Assign.(type) {
				case *ast.ExprStmt:
					if ta, okTA := unwrapParens(as.X).(*ast.TypeAssertExpr); okTA && ta.Type == nil {
						if id, okID := unwrapParens(ta.X).(*ast.Ident); okID {
							switchTarget = id.Name
						}
					}
				case *ast.AssignStmt:
					if as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
						if lhsID, okL := unwrapParens(as.Lhs[0]).(*ast.Ident); okL {
							if ta, okTA := unwrapParens(as.Rhs[0]).(*ast.TypeAssertExpr); okTA && ta.Type == nil {
								if id, okID := unwrapParens(ta.X).(*ast.Ident); okID {
									switchTarget = id.Name
									boundName = lhsID.Name
								}
							}
						}
					}
				}
				if switchTarget != "" && curFileVars[switchTarget] && ts.Init == nil && ts.Body != nil {
					for _, rawClause := range ts.Body.List {
						cc, okCC := rawClause.(*ast.CaseClause)
						if !okCC {
							continue
						}
						if len(cc.List) == 1 {
							star, okS := unwrapParens(cc.List[0]).(*ast.StarExpr)
							if okS {
								if _, okF := isIdentNamed(star.X, "File"); okF {
									nextFV := maps.Clone(curFileVars)
									if boundName != "" && boundName != "_" {
										nextFV[boundName] = true
									}
									for _, bs := range cc.Body {
										inspectHelperNode(bs, nextFV)
									}
									continue
								}
							}
							if cID, okID := unwrapParens(cc.List[0]).(*ast.Ident); okID && (cID.Name == "string" || cID.Name == "int" || cID.Name == "uintptr") {
								continue
							}
						}
						for _, bs := range cc.Body {
							inspectHelperNode(bs, curFileVars)
						}
					}
					return
				}
			}
			switch x := n.(type) {
			case *ast.Ident:
				if x.Name == "testlog" {
					helperErr = fmt.Errorf("os: ReadFile helper %s:%s references testlog", cur.kind, cur.name)
					return
				}
			case *ast.SelectorExpr:
				if baseID, okB := unwrapParens(x.X).(*ast.Ident); okB {
					if baseID.Name == "syscall" && forbiddenSyscallSels[x.Sel.Name] {
						helperErr = fmt.Errorf("os: ReadFile helper %s:%s references syscall.%s", cur.kind, cur.name, x.Sel.Name)
						return
					}
					if curFileVars[baseID.Name] && x.Sel.Name != "Close" {
						if allFileMethods[x.Sel.Name] != nil {
							enqueue(workItem{kind: "file", name: x.Sel.Name})
						} else if allRawFileMethods[x.Sel.Name] != nil {
							enqueue(workItem{kind: "raw", name: x.Sel.Name})
						}
					}
					if rawFileVars[baseID.Name] && x.Sel.Name != "close" && allRawFileMethods[x.Sel.Name] != nil {
						enqueue(workItem{kind: "raw", name: x.Sel.Name})
					}
				} else if innerSel, okIS := unwrapParens(x.X).(*ast.SelectorExpr); okIS && innerSel.Sel.Name == "file" {
					if baseID, okB := unwrapParens(innerSel.X).(*ast.Ident); okB && curFileVars[baseID.Name] && x.Sel.Name != "close" && allRawFileMethods[x.Sel.Name] != nil {
						enqueue(workItem{kind: "raw", name: x.Sel.Name})
					}
				}
			case *ast.CallExpr:
				if cID, okID := unwrapParens(x.Fun).(*ast.Ident); okID {
					if forbiddenTopCalls[cID.Name] {
						helperErr = fmt.Errorf("os: ReadFile helper %s:%s calls forbidden %s", cur.kind, cur.name, cID.Name)
						return
					}
					if osAnyLinknameLocals[cID.Name] {
						helperErr = fmt.Errorf("os: ReadFile helper %s:%s calls linknamed %s", cur.kind, cur.name, cID.Name)
						return
					}
					if allTopFuncs[cID.Name] != nil {
						a0File := false
						if !x.Ellipsis.IsValid() && len(x.Args) >= 1 {
							if aID, okA := unwrapParens(x.Args[0]).(*ast.Ident); okA && curFileVars[aID.Name] {
								a0File = true
							}
						}
						enqueue(workItem{kind: "top", name: cID.Name, arg0IsFile: a0File})
					}
				} else if cSel, okS := unwrapParens(x.Fun).(*ast.SelectorExpr); okS {
					if baseID, okB := unwrapParens(cSel.X).(*ast.Ident); okB {
						if curFileVars[baseID.Name] && cSel.Sel.Name != "Close" {
							if allFileMethods[cSel.Sel.Name] != nil {
								enqueue(workItem{kind: "file", name: cSel.Sel.Name})
							} else if allRawFileMethods[cSel.Sel.Name] != nil {
								enqueue(workItem{kind: "raw", name: cSel.Sel.Name})
							} else {
								helperErr = fmt.Errorf("os: ReadFile helper %s:%s calls unknown *File method %s", cur.kind, cur.name, cSel.Sel.Name)
								return
							}
						}
						if rawFileVars[baseID.Name] && cSel.Sel.Name != "close" {
							if allRawFileMethods[cSel.Sel.Name] == nil {
								helperErr = fmt.Errorf("os: ReadFile helper %s:%s calls unknown *file method %s", cur.kind, cur.name, cSel.Sel.Name)
								return
							}
							enqueue(workItem{kind: "raw", name: cSel.Sel.Name})
						}
					}
				}
			}
			ast.Inspect(n, func(ch ast.Node) bool {
				if ch == n {
					return true
				}
				inspectHelperNode(ch, curFileVars)
				return false
			})
		}
		for _, st := range hFn.Body.List[pos:] {
			inspectHelperNode(st, fileVars)
			if helperErr != nil {
				return helperErr
			}
		}
	}
	return nil
}

func funcHasUnnamedResults(ft *ast.FuncType, count int) bool {
	if ft == nil || ft.Results == nil || ft.Results.NumFields() != count || len(ft.Results.List) != count {
		return false
	}
	for _, fld := range ft.Results.List {
		if len(fld.Names) != 0 {
			return false
		}
	}
	return true
}

func verifyOSIgnoringEINTR(igFn *ast.FuncDecl, funcFile map[*ast.FuncDecl]*ast.File, fileImportsSyscall map[*ast.File]bool, osNoFileReserved, osAnyLinknameLocals map[string]bool) bool {
	if igFn == nil || igFn.Body == nil || igFn.Type == nil || igFn.Type.TypeParams != nil || !funcHasUnnamedResults(igFn.Type, 1) || osAnyLinknameLocals["ignoringEINTR"] || funcShadowsAnyIdent(igFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(igFn.Body) {
		return false
	}
	igParams := paramNamesFlat(igFn.Type.Params)
	if len(igParams) != 1 || igParams[0] == "" || igParams[0] == "_" || len(igFn.Body.List) != 1 {
		return false
	}
	if ret, okRet := igFn.Body.List[0].(*ast.ReturnStmt); okRet && len(ret.Results) == 1 {
		c, okC := unwrapParens(ret.Results[0]).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 0 {
			return false
		}
		_, okFn := isIdentNamed(c.Fun, igParams[0])
		return okFn
	}
	fs, okFor := igFn.Body.List[0].(*ast.ForStmt)
	if !okFor || !fileImportsSyscall[funcFile[igFn]] || fs.Init != nil || fs.Cond != nil || fs.Post != nil || len(fs.Body.List) != 2 {
		return false
	}
	as, okA := fs.Body.List[0].(*ast.AssignStmt)
	if !okA || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
		return false
	}
	errID, okE := unwrapParens(as.Lhs[0]).(*ast.Ident)
	if !okE || errID.Name == "" || errID.Name == "_" {
		return false
	}
	c, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
	if !okC || c.Ellipsis.IsValid() || len(c.Args) != 0 {
		return false
	}
	if _, okFn := isIdentNamed(c.Fun, igParams[0]); !okFn {
		return false
	}
	ifs, okI := fs.Body.List[1].(*ast.IfStmt)
	if !okI || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
		return false
	}
	condBin, okCB := unwrapParens(ifs.Cond).(*ast.BinaryExpr)
	if !okCB || condBin.Op != token.NEQ {
		return false
	}
	_, okEL := isIdentNamed(condBin.X, errID.Name)
	_, okSysR := isSelectorBaseField(condBin.Y, "syscall", "EINTR")
	_, okSysL := isSelectorBaseField(condBin.X, "syscall", "EINTR")
	_, okER := isIdentNamed(condBin.Y, errID.Name)
	if !((okEL && okSysR) || (okSysL && okER)) {
		return false
	}
	ret, okR := ifs.Body.List[0].(*ast.ReturnStmt)
	if !okR || len(ret.Results) != 1 {
		return false
	}
	_, okRetErr := isIdentNamed(ret.Results[0], errID.Name)
	return okRetErr
}

func verifyOSGetwd(
	files []*ast.File,
	gwFn *ast.FuncDecl,
	allTopFuncs, allFileMethods, allRawFileMethods, allFileStatMethods map[string]*ast.FuncDecl,
	nonAliasStructSpecs map[string]*ast.TypeSpec,
	pkgDeclCounts, fileMethodCounts, rawFileMethodCounts, fileStatMethodCounts map[string]int,
	funcFile map[*ast.FuncDecl]*ast.File,
	fileImportsSyscall map[*ast.File]bool,
	verifiedNonNilOSErrIdents, osReserved, osNoFileReserved, osAnyLinknameLocals map[string]bool,
	osInactive *osInactiveState,
	skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool,
) error {
	if gwFn == nil || gwFn.Body == nil || gwFn.Type == nil || gwFn.Type.TypeParams != nil || osAnyLinknameLocals["Getwd"] {
		return fmt.Errorf("os: missing or invalid Getwd")
	}
	if !fileImportsSyscall[funcFile[gwFn]] || funcShadowsAnyIdent(gwFn, osReserved) {
		return fmt.Errorf("os: Getwd missing syscall import or shadows reserved identifier")
	}
	if (gwFn.Type.Params != nil && gwFn.Type.Params.NumFields() != 0) || gwFn.Type.Results == nil || gwFn.Type.Results.NumFields() != 2 || len(gwFn.Type.Results.List) != 2 || !funcReturnsErrorLast(gwFn.Type) {
		return fmt.Errorf("os: Getwd invalid signature")
	}
	if _, okStr := isIdentNamed(gwFn.Type.Results.List[0].Type, "string"); !okStr {
		return fmt.Errorf("os: Getwd first result is not string")
	}
	pos := 0
	for pos < len(gwFn.Body.List) && skipInactiveHookIf(gwFn.Body.List[pos], gwFn) {
		pos++
	}
	gwStmts := gwFn.Body.List[pos:]
	if len(gwStmts) == 0 {
		return fmt.Errorf("os: Getwd empty body")
	}
	for _, topSt := range gwStmts[:len(gwStmts)-1] {
		if _, isBareRet := topSt.(*ast.ReturnStmt); isBareRet {
			return fmt.Errorf("os: Getwd has unconditional early return")
		}
	}

	stmtUnwrapLabel := func(st ast.Stmt) ast.Stmt {
		for {
			ls, ok := st.(*ast.LabeledStmt)
			if !ok {
				return st
			}
			st = ls.Stmt
		}
	}
	isNonEmptyStrLit := func(expr ast.Expr) bool {
		lit, ok := unwrapParens(expr).(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return false
		}
		unq, err := strconv.Unquote(lit.Value)
		return err == nil && unq != ""
	}
	isSameFileCallPair := func(expr ast.Expr) (string, string, bool) {
		c, okC := unwrapParens(expr).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 2 {
			return "", "", false
		}
		if _, okSF := isIdentNamed(c.Fun, "SameFile"); !okSF {
			return "", "", false
		}
		a0, ok0 := unwrapParens(c.Args[0]).(*ast.Ident)
		a1, ok1 := unwrapParens(c.Args[1]).(*ast.Ident)
		if !ok0 || !ok1 || a0.Name == "" || a0.Name == "_" || a1.Name == "" || a1.Name == "_" {
			return "", "", false
		}
		return a0.Name, a1.Name, true
	}
	isDirectOrWrappedErrExpr := func(expr ast.Expr, wantErr string) bool {
		if _, okDirect := isIdentNamed(expr, wantErr); okDirect {
			return true
		}
		c, okC := unwrapParens(expr).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 2 {
			return false
		}
		_, okNSE := isIdentNamed(c.Fun, "NewSyscallError")
		_, okErr := isIdentNamed(c.Args[1], wantErr)
		return okNSE && isNonEmptyStrLit(c.Args[0]) && okErr
	}
	isVerifiedConstErrArg := func(expr ast.Expr) bool {
		if sel, okS := unwrapParens(expr).(*ast.SelectorExpr); okS {
			_, okSys := isIdentNamed(sel.X, "syscall")
			return okSys && strings.HasPrefix(sel.Sel.Name, "E") && len(sel.Sel.Name) > 1
		}
		if id, okID := unwrapParens(expr).(*ast.Ident); okID {
			return verifiedNonNilOSErrIdents[id.Name] && !funcShadowsAnyIdent(gwFn, map[string]bool{id.Name: true})
		}
		return false
	}
	isVerifiedConstGetwdErr := func(expr ast.Expr) bool {
		if isVerifiedConstErrArg(expr) {
			return true
		}
		c, okC := unwrapParens(expr).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 2 {
			return false
		}
		_, okNSE := isIdentNamed(c.Fun, "NewSyscallError")
		return okNSE && isNonEmptyStrLit(c.Args[0]) && isVerifiedConstErrArg(c.Args[1])
	}
	condChecksAbsSlashPrefix := func(cond ast.Expr, dirVar string) bool {
		found := false
		var check func(e ast.Expr)
		check = func(e ast.Expr) {
			if found || e == nil {
				return
			}
			bin, okB := unwrapParens(e).(*ast.BinaryExpr)
			if !okB {
				return
			}
			if bin.Op == token.LAND {
				check(bin.X)
				check(bin.Y)
				return
			}
			if bin.Op != token.EQL {
				return
			}
			matchIdxSlash := func(idxSide, charSide ast.Expr) bool {
				ix, okIX := unwrapParens(idxSide).(*ast.IndexExpr)
				lit, okL := unwrapParens(charSide).(*ast.BasicLit)
				if !okIX || !okL || !isZeroIntLit(ix.Index) {
					return false
				}
				if _, okD := isIdentNamed(ix.X, dirVar); !okD {
					return false
				}
				return lit.Kind == token.CHAR && lit.Value == `'/'`
			}
			if matchIdxSlash(bin.X, bin.Y) || matchIdxSlash(bin.Y, bin.X) {
				found = true
			}
		}
		check(cond)
		return found
	}
	isParentLenBoundCond := func(cond ast.Expr, parentLoopVars map[string]bool) bool {
		bin, okB := unwrapParens(cond).(*ast.BinaryExpr)
		if !okB {
			return false
		}
		checkLenLit := func(lenSide, litSide ast.Expr) bool {
			c, okC := unwrapParens(lenSide).(*ast.CallExpr)
			lit, okL := unwrapParens(litSide).(*ast.BasicLit)
			if !okC || !okL || c.Ellipsis.IsValid() || len(c.Args) != 1 || lit.Kind != token.INT {
				return false
			}
			if _, okLen := isIdentNamed(c.Fun, "len"); !okLen {
				return false
			}
			pID, okP := unwrapParens(c.Args[0]).(*ast.Ident)
			if !okP || !parentLoopVars[pID.Name] {
				return false
			}
			n, err := strconv.ParseInt(lit.Value, 0, 64)
			return err == nil && n >= 64
		}
		switch bin.Op {
		case token.GEQ, token.GTR:
			return checkLenLit(bin.X, bin.Y)
		case token.LEQ, token.LSS:
			return checkLenLit(bin.Y, bin.X)
		default:
			return false
		}
	}
	condChecksNonEmptyStr := func(cond ast.Expr, dirVar string) bool {
		found := false
		var check func(e ast.Expr)
		check = func(e ast.Expr) {
			if found || e == nil {
				return
			}
			bin, okB := unwrapParens(e).(*ast.BinaryExpr)
			if !okB {
				return
			}
			if bin.Op == token.LAND {
				check(bin.X)
				check(bin.Y)
				return
			}
			matchLenCall := func(side ast.Expr) bool {
				c, okC := unwrapParens(side).(*ast.CallExpr)
				if !okC || c.Ellipsis.IsValid() || len(c.Args) != 1 {
					return false
				}
				_, okLen := isIdentNamed(c.Fun, "len")
				_, okD := isIdentNamed(c.Args[0], dirVar)
				return okLen && okD
			}
			parseIntSide := func(side ast.Expr) (int64, bool) {
				lit, okL := unwrapParens(side).(*ast.BasicLit)
				if !okL || lit.Kind != token.INT {
					return 0, false
				}
				n, err := strconv.ParseInt(lit.Value, 0, 64)
				return n, err == nil
			}
			switch bin.Op {
			case token.GTR:
				if matchLenCall(bin.X) {
					if n, ok := parseIntSide(bin.Y); ok && n >= 0 {
						found = true
					}
				}
			case token.LSS:
				if matchLenCall(bin.Y) {
					if n, ok := parseIntSide(bin.X); ok && n >= 0 {
						found = true
					}
				}
			case token.GEQ:
				if matchLenCall(bin.X) {
					if n, ok := parseIntSide(bin.Y); ok && n >= 1 {
						found = true
					}
				}
			case token.LEQ:
				if matchLenCall(bin.Y) {
					if n, ok := parseIntSide(bin.X); ok && n >= 1 {
						found = true
					}
				}
			case token.NEQ:
				isEmpty := func(side ast.Expr) bool {
					lit, okL := unwrapParens(side).(*ast.BasicLit)
					return okL && lit.Kind == token.STRING && lit.Value == `""`
				}
				_, okLX := isIdentNamed(bin.X, dirVar)
				_, okLY := isIdentNamed(bin.Y, dirVar)
				if (okLX && isEmpty(bin.Y)) || (okLY && isEmpty(bin.X)) {
					found = true
				}
			}
		}
		check(cond)
		return found
	}
	isGetenvPWDCall := func(expr ast.Expr) bool {
		c, okC := unwrapParens(expr).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 1 {
			return false
		}
		_, okGE := isIdentNamed(c.Fun, "Getenv")
		lit, okLit := unwrapParens(c.Args[0]).(*ast.BasicLit)
		return okGE && okLit && lit.Kind == token.STRING && lit.Value == `"PWD"`
	}
	collectCompoundStmtMutations := func(node ast.Node, mutated, assignedPWD map[string]bool) {
		ast.Inspect(node, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range x.Lhs {
					if id, okID := unwrapParens(lhs).(*ast.Ident); okID && id.Name != "" && id.Name != "_" {
						mutated[id.Name] = true
						if len(x.Lhs) == len(x.Rhs) && i < len(x.Rhs) && isGetenvPWDCall(x.Rhs[i]) {
							assignedPWD[id.Name] = true
						}
					}
				}
			case *ast.ValueSpec:
				for i, id := range x.Names {
					if id.Name != "" && id.Name != "_" {
						mutated[id.Name] = true
						if i < len(x.Values) && isGetenvPWDCall(x.Values[i]) {
							assignedPWD[id.Name] = true
						}
					}
				}
			case *ast.RangeStmt:
				if x.Key != nil {
					if id, okK := unwrapParens(x.Key).(*ast.Ident); okK && id.Name != "" && id.Name != "_" {
						mutated[id.Name] = true
					}
				}
				if x.Value != nil {
					if id, okV := unwrapParens(x.Value).(*ast.Ident); okV && id.Name != "" && id.Name != "_" {
						mutated[id.Name] = true
					}
				}
			case *ast.IncDecStmt:
				if id, okID := unwrapParens(x.X).(*ast.Ident); okID && id.Name != "" && id.Name != "_" {
					mutated[id.Name] = true
				}
			}
			return true
		})
	}
	stmtsMutateIdentBefore := func(list []ast.Stmt, stopAt ast.Node, target string) bool {
		mutated := false
		stopped := false
		for _, s := range list {
			ast.Inspect(s, func(n ast.Node) bool {
				if mutated || stopped || n == nil {
					return false
				}
				if stopAt != nil && n == stopAt {
					stopped = true
					return false
				}
				switch x := n.(type) {
				case *ast.AssignStmt:
					for _, lhs := range x.Lhs {
						if _, okID := isIdentNamed(lhs, target); okID {
							mutated = true
							return false
						}
					}
				case *ast.ValueSpec:
					for _, id := range x.Names {
						if id.Name == target {
							mutated = true
							return false
						}
					}
				case *ast.RangeStmt:
					if x.Key != nil {
						if _, okK := isIdentNamed(x.Key, target); okK {
							mutated = true
							return false
						}
					}
					if x.Value != nil {
						if _, okV := isIdentNamed(x.Value, target); okV {
							mutated = true
							return false
						}
					}
				case *ast.IncDecStmt:
					if _, okID := isIdentNamed(x.X, target); okID {
						mutated = true
						return false
					}
				}
				return true
			})
			if mutated || stopped {
				break
			}
		}
		return mutated
	}
	isCheckedErrGuardIf := func(st ast.Stmt, wantErr string) (*ast.ReturnStmt, bool) {
		ifs, okI := st.(*ast.IfStmt)
		if !okI || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 || condChecksNonZeroErr(ifs.Cond) != wantErr {
			return nil, false
		}
		ret, okR := ifs.Body.List[0].(*ast.ReturnStmt)
		if !okR || len(ret.Results) != 2 {
			return nil, false
		}
		r0Lit, ok0 := unwrapParens(ret.Results[0]).(*ast.BasicLit)
		_, ok1 := isIdentNamed(ret.Results[1], wantErr)
		if !ok0 || r0Lit.Kind != token.STRING || r0Lit.Value != `""` || !ok1 {
			return nil, false
		}
		return ret, true
	}
	isCloseCallOn := func(st ast.Stmt, fdVar string) bool {
		es, okE := st.(*ast.ExprStmt)
		if !okE {
			return false
		}
		c, okC := unwrapParens(es.X).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 0 {
			return false
		}
		_, okSel := isSelectorBaseField(c.Fun, fdVar, "Close")
		return okSel
	}

	var sawSyscallGetwd, usedIgnoringEINTR2, usedNewSyscallError, usedSameFile, usedStatHelpers, usedOpenDirNolog, usedFstatNolog, usedFileStatInGetwd, usedGetwdCache bool
	allowedSyscallGetwdSels := map[*ast.SelectorExpr]bool{}
	allowedReturns := map[*ast.ReturnStmt]bool{}
	validErrIfs := map[*ast.IfStmt]string{}
	dotSeedAssigns := map[*ast.AssignStmt]bool{}
	rootSeedAssigns := map[*ast.AssignStmt]bool{}
	fdSeedAssigns := map[*ast.AssignStmt]bool{}
	pdSeedAssigns := map[*ast.AssignStmt]bool{}
	shape1Assigns := map[*ast.AssignStmt]bool{}
	parentInitAssigns := map[*ast.AssignStmt]bool{}
	parentStepAssigns := map[*ast.AssignStmt]bool{}
	dotVars := map[string]bool{}
	rootVars := map[string]bool{}
	fdVarsInLoop := map[string]bool{}
	pdVarsInLoop := map[string]bool{}
	shape2ReturnedDirVars := map[string]bool{}
	parentLoopVars := map[string]bool{}
	var topParentLoop *ast.ForStmt
	topParentLoopIdx := -1
	sawLoopInGetwd := false

	var verifyBlock func(stmts []ast.Stmt, enclosingIfs []*ast.IfStmt, inLoop bool, pwdUncheckedVars, validErrVars map[string]bool) error
	verifyBlock = func(stmts []ast.Stmt, enclosingIfs []*ast.IfStmt, inLoop bool, pwdUncheckedVars, validErrVars map[string]bool) error {
		curPWD := maps.Clone(pwdUncheckedVars)
		curValidErr := maps.Clone(validErrVars)
		for idx := 0; idx < len(stmts); idx++ {
			raw := stmts[idx]
			if _, isLbl := raw.(*ast.LabeledStmt); isLbl {
				clear(curValidErr)
			}
			st := stmtUnwrapLabel(raw)

			if ds, okDS := st.(*ast.DeclStmt); okDS {
				if gd, okGD := ds.Decl.(*ast.GenDecl); okGD {
					for _, spec := range gd.Specs {
						if vs, okVS := spec.(*ast.ValueSpec); okVS {
							for i, id := range vs.Names {
								if id.Name != "" && id.Name != "_" {
									delete(curValidErr, id.Name)
									if i < len(vs.Values) && isGetenvPWDCall(vs.Values[i]) {
										curPWD[id.Name] = true
									} else if len(vs.Values) == 0 {
										delete(curPWD, id.Name)
									} else if i < len(vs.Values) {
										if lit, okLit := unwrapParens(vs.Values[i]).(*ast.BasicLit); okLit && lit.Kind == token.STRING && lit.Value == `""` {
											delete(curPWD, id.Name)
										}
									}
								}
							}
						}
					}
				}
			}

			if as, okA := st.(*ast.AssignStmt); okA {
				// Track PWD vs getwdCache.dir hint state on 1-LHS assignments.
				if len(as.Lhs) == 1 && len(as.Rhs) == 1 {
					if lID, okL := unwrapParens(as.Lhs[0]).(*ast.Ident); okL && lID.Name != "" && lID.Name != "_" {
						if isGetenvPWDCall(as.Rhs[0]) {
							curPWD[lID.Name] = true
						} else if _, okCache := isSelectorBaseField(as.Rhs[0], "getwdCache", "dir"); okCache {
							usedGetwdCache = true
							delete(curPWD, lID.Name)
						} else if lit, okLit := unwrapParens(as.Rhs[0]).(*ast.BasicLit); okLit && lit.Kind == token.STRING && lit.Value == `""` {
							delete(curPWD, lID.Name)
						}
					}
				}

				producesValidErr := false
				var validErrName string
				if (as.Tok == token.DEFINE || as.Tok == token.ASSIGN) && len(as.Lhs) == 2 && len(as.Rhs) == 1 {
					l0, ok0 := unwrapParens(as.Lhs[0]).(*ast.Ident)
					l1, ok1 := unwrapParens(as.Lhs[1]).(*ast.Ident)
					c, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
					if ok0 && ok1 && okC && !c.Ellipsis.IsValid() && l0.Name != "" && l0.Name != "_" && l1.Name != "_" && l0.Name != l1.Name {
						if l1.Name != "" {
							if _, okLS := isIdentNamed(c.Fun, "lstatNolog"); okLS && len(c.Args) == 1 {
								usedStatHelpers = true
								producesValidErr = true
								validErrName = l1.Name
							}
						}
					}
					if ok0 && ok1 && okC && !c.Ellipsis.IsValid() && l0.Name != "" && l0.Name != "_" && l1.Name != "" && l1.Name != "_" && l0.Name != l1.Name {
						// Shape 1: <dVar>, <eVar> =|:= syscall.Getwd() | ignoringEINTR2(syscall.Getwd).
						var sgSel *ast.SelectorExpr
						if _, okSG := isSelectorBaseField(c.Fun, "syscall", "Getwd"); okSG && len(c.Args) == 0 {
							sgSel = unwrapParens(c.Fun).(*ast.SelectorExpr)
						} else if _, okIG := isIdentNamed(c.Fun, "ignoringEINTR2"); okIG && len(c.Args) == 1 {
							if _, okSG := isSelectorBaseField(c.Args[0], "syscall", "Getwd"); okSG {
								sgSel = unwrapParens(c.Args[0]).(*ast.SelectorExpr)
							}
						}
						if sgSel != nil {
							producesValidErr = true
							validErrName = l1.Name
							if idx+1 >= len(stmts) {
								return fmt.Errorf("os: Getwd syscall.Getwd call missing immediate return")
							}
							nextSt := stmts[idx+1]
							var matchedRet *ast.ReturnStmt
							if ret, okR := nextSt.(*ast.ReturnStmt); okR && len(ret.Results) == 2 {
								if _, okD := isIdentNamed(ret.Results[0], l0.Name); okD && isDirectOrWrappedErrExpr(ret.Results[1], l1.Name) {
									matchedRet = ret
								}
							} else if ifs, okI := nextSt.(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
								if ret, okR := ifs.Body.List[0].(*ast.ReturnStmt); okR && len(ret.Results) == 2 {
									if _, okD := isIdentNamed(ret.Results[0], l0.Name); okD && isDirectOrWrappedErrExpr(ret.Results[1], l1.Name) {
										matchedRet = ret
									}
								}
							}
							if matchedRet == nil {
								return fmt.Errorf("os: Getwd syscall.Getwd result (%s, %s) not immediately returned with its error", l0.Name, l1.Name)
							}
							allowedSyscallGetwdSels[sgSel] = true
							allowedReturns[matchedRet] = true
							shape1Assigns[as] = true
							delete(curPWD, l0.Name)
							sawSyscallGetwd = true
						}

						// Seed dot/root/Shape 2 via statNolog(...).
						if _, okSN := isIdentNamed(c.Fun, "statNolog"); okSN && len(c.Args) == 1 {
							usedStatHelpers = true
							producesValidErr = true
							validErrName = l1.Name
							if lit, okLit := unwrapParens(c.Args[0]).(*ast.BasicLit); okLit && lit.Kind == token.STRING {
								if (lit.Value == `"."` || lit.Value == `"/"`) && idx+1 < len(stmts) {
									if errRet, okG := isCheckedErrGuardIf(stmts[idx+1], l1.Name); okG {
										allowedReturns[errRet] = true
										if lit.Value == `"."` {
											dotSeedAssigns[as] = true
											dotVars[l0.Name] = true
										} else {
											rootSeedAssigns[as] = true
											rootVars[l0.Name] = true
										}
									}
								}
							} else if dirArgID, okDA := unwrapParens(c.Args[0]).(*ast.Ident); okDA && !inLoop && !sawLoopInGetwd && dirArgID.Name != "" && dirArgID.Name != "_" && dirArgID.Name != l0.Name && dirArgID.Name != l1.Name && idx+1 < len(stmts) {
								if ifs, okI := stmts[idx+1].(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
									if bin, okB := unwrapParens(ifs.Cond).(*ast.BinaryExpr); okB && bin.Op == token.LAND && condChecksEqErr(bin.X, l1.Name) {
										if a0, a1, okSF := isSameFileCallPair(bin.Y); okSF {
											dotCand := ""
											if a0 == l0.Name && dotVars[a1] {
												dotCand = a1
											} else if a1 == l0.Name && dotVars[a0] {
												dotCand = a0
											}
											if dotCand != "" {
												if ret, okR := ifs.Body.List[0].(*ast.ReturnStmt); okR && len(ret.Results) == 2 {
													_, okRD := isIdentNamed(ret.Results[0], dirArgID.Name)
													_, okRN := isIdentNamed(ret.Results[1], "nil")
													if okRD && okRN {
														hasNonEmptyGuard := false
														for _, enc := range enclosingIfs {
															if condChecksNonEmptyStr(enc.Cond, dirArgID.Name) {
																hasNonEmptyGuard = true
																break
															}
														}
														if !hasNonEmptyGuard {
															return fmt.Errorf("os: Getwd hint %s returned without non-empty guard", dirArgID.Name)
														}
														if curPWD[dirArgID.Name] {
															hasSlashGuard := false
															for _, enc := range enclosingIfs {
																if condChecksAbsSlashPrefix(enc.Cond, dirArgID.Name) {
																	hasSlashGuard = true
																	break
																}
															}
															if !hasSlashGuard {
																return fmt.Errorf("os: Getwd PWD hint %s returned without leading '/' guard", dirArgID.Name)
															}
														}
														allowedReturns[ret] = true
														shape2ReturnedDirVars[dirArgID.Name] = true
														usedSameFile = true
													}
												}
											}
										}
									}
								}
							}
						}

						// Loop parent openDirNolog(parent), Readdirnames, and fstatNolog(fd)/fd.Stat() seeds.
						if inLoop {
							if _, okOD := isIdentNamed(c.Fun, "openDirNolog"); okOD && len(c.Args) == 1 {
								if pID, okP := unwrapParens(c.Args[0]).(*ast.Ident); okP && parentLoopVars[pID.Name] {
									producesValidErr = true
									validErrName = l1.Name
									if idx+1 < len(stmts) {
										if errRet, okG := isCheckedErrGuardIf(stmts[idx+1], l1.Name); okG {
											allowedReturns[errRet] = true
											fdSeedAssigns[as] = true
											fdVarsInLoop[l0.Name] = true
											usedOpenDirNolog = true
										}
									}
								}
							}
							if sel, okS := unwrapParens(c.Fun).(*ast.SelectorExpr); okS && sel.Sel.Name == "Readdirnames" {
								if fdID, okFD := unwrapParens(sel.X).(*ast.Ident); okFD && fdVarsInLoop[fdID.Name] {
									producesValidErr = true
									validErrName = l1.Name
								}
							}
							var fdStatTarget string
							var isFstatCall, isFileStatCall bool
							if _, okFN := isIdentNamed(c.Fun, "fstatNolog"); okFN && len(c.Args) == 1 {
								if fdID, okFD := unwrapParens(c.Args[0]).(*ast.Ident); okFD && fdVarsInLoop[fdID.Name] {
									fdStatTarget = fdID.Name
									isFstatCall = true
								}
							} else if sel, okS := unwrapParens(c.Fun).(*ast.SelectorExpr); okS && sel.Sel.Name == "Stat" && len(c.Args) == 0 {
								if fdID, okFD := unwrapParens(sel.X).(*ast.Ident); okFD && fdVarsInLoop[fdID.Name] {
									fdStatTarget = fdID.Name
									isFileStatCall = true
								}
							}
							if fdStatTarget != "" {
								usedStatHelpers = true
								producesValidErr = true
								validErrName = l1.Name
								if isFstatCall {
									usedFstatNolog = true
								}
								if isFileStatCall {
									usedFileStatInGetwd = true
								}
								guardIdx := idx + 1
								if guardIdx < len(stmts) && isCloseCallOn(stmts[guardIdx], fdStatTarget) {
									guardIdx++
								}
								if guardIdx < len(stmts) {
									if errRet, okG := isCheckedErrGuardIf(stmts[guardIdx], l1.Name); okG {
										allowedReturns[errRet] = true
										pdSeedAssigns[as] = true
										pdVarsInLoop[l0.Name] = true
									}
								}
							}
						}
					}
				}
				for _, lhs := range as.Lhs {
					if id, okID := unwrapParens(lhs).(*ast.Ident); okID {
						delete(curValidErr, id.Name)
					}
				}
				if producesValidErr && validErrName != "" && validErrName != "_" {
					curValidErr[validErrName] = true
				}
			}

			switch x := st.(type) {
			case *ast.ReturnStmt:
				if len(x.Results) != 2 {
					return fmt.Errorf("os: Getwd return must have 2 explicit results")
				}
				if !allowedReturns[x] {
					if lit, okL := unwrapParens(x.Results[0]).(*ast.BasicLit); okL && lit.Kind == token.STRING {
						if lit.Value == `"/"` {
							_, okNil := isIdentNamed(x.Results[1], "nil")
							hasRootSameFile := false
							for _, enc := range enclosingIfs {
								if enc.Init == nil {
									if a0, a1, okSF := isSameFileCallPair(enc.Cond); okSF {
										if (rootVars[a0] && dotVars[a1]) || (rootVars[a1] && dotVars[a0]) {
											hasRootSameFile = true
											break
										}
									}
								}
							}
							if okNil && hasRootSameFile {
								allowedReturns[x] = true
								usedSameFile = true
								usedStatHelpers = true
							}
						} else if lit.Value == `""` && len(enclosingIfs) > 0 {
							if eID, okE := unwrapParens(x.Results[1]).(*ast.Ident); okE && eID.Name != "" && eID.Name != "_" && eID.Name != "nil" {
								for _, enc := range enclosingIfs {
									if validErrIfs[enc] == eID.Name && !stmtsMutateIdentBefore(enc.Body.List, x, eID.Name) {
										allowedReturns[x] = true
										break
									}
								}
							}
							if !allowedReturns[x] && isVerifiedConstGetwdErr(x.Results[1]) {
								for _, enc := range enclosingIfs {
									if (validErrIfs[enc] != "" && !stmtsMutateIdentBefore(enc.Body.List, x, validErrIfs[enc])) || isParentLenBoundCond(enc.Cond, parentLoopVars) {
										allowedReturns[x] = true
										break
									}
								}
							}
						}
					}
				}
			case *ast.IfStmt:
				if x.Init != nil {
					return fmt.Errorf("os: Getwd contains unexpected if init statement")
				}
				if checkedErr := condChecksNonZeroErr(x.Cond); checkedErr != "" && curValidErr[checkedErr] {
					validErrIfs[x] = checkedErr
				}
				nextIfs := append(slices.Clone(enclosingIfs), x)
				if err := verifyBlock(x.Body.List, nextIfs, inLoop, curPWD, curValidErr); err != nil {
					return err
				}
				if x.Else != nil {
					switch eb := x.Else.(type) {
					case *ast.BlockStmt:
						if err := verifyBlock(eb.List, enclosingIfs, inLoop, curPWD, curValidErr); err != nil {
							return err
						}
					case *ast.IfStmt:
						if err := verifyBlock([]ast.Stmt{eb}, enclosingIfs, inLoop, curPWD, curValidErr); err != nil {
							return err
						}
					default:
						return fmt.Errorf("os: Getwd unexpected else clause")
					}
				}
				mut, pwd := map[string]bool{}, map[string]bool{}
				collectCompoundStmtMutations(x, mut, pwd)
				for m := range mut {
					delete(curValidErr, m)
				}
				for p := range pwd {
					curPWD[p] = true
				}
			case *ast.ForStmt:
				sawLoopInGetwd = true
				if !inLoop && x.Cond == nil && topParentLoop == nil {
					topParentLoop = x
					topParentLoopIdx = idx
					initAs, okIA := x.Init.(*ast.AssignStmt)
					postAs, okPA := x.Post.(*ast.AssignStmt)
					if okIA && initAs.Tok == token.DEFINE && len(initAs.Lhs) == 1 && len(initAs.Rhs) == 1 && okPA && postAs.Tok == token.ASSIGN && len(postAs.Lhs) == 1 && len(postAs.Rhs) == 1 {
						if pID, okP := unwrapParens(initAs.Lhs[0]).(*ast.Ident); okP && pID.Name != "" && pID.Name != "_" {
							lit, okL := unwrapParens(initAs.Rhs[0]).(*ast.BasicLit)
							_, okPostLHS := isIdentNamed(postAs.Lhs[0], pID.Name)
							postBin, okPB := unwrapParens(postAs.Rhs[0]).(*ast.BinaryExpr)
							if okL && lit.Kind == token.STRING && lit.Value == `".."` && okPostLHS && okPB && postBin.Op == token.ADD {
								stepLit, okSL := unwrapParens(postBin.X).(*ast.BasicLit)
								_, okStepVar := isIdentNamed(postBin.Y, pID.Name)
								if okSL && stepLit.Kind == token.STRING && stepLit.Value == `"../"` && okStepVar {
									parentLoopVars[pID.Name] = true
									parentInitAssigns[initAs] = true
									parentStepAssigns[postAs] = true
								}
							}
						}
					}
				}
				if err := verifyBlock(x.Body.List, enclosingIfs, true, curPWD, curValidErr); err != nil {
					return err
				}
				mut, pwd := map[string]bool{}, map[string]bool{}
				collectCompoundStmtMutations(x, mut, pwd)
				for m := range mut {
					delete(curValidErr, m)
				}
				for p := range pwd {
					curPWD[p] = true
				}
			case *ast.RangeStmt:
				sawLoopInGetwd = true
				if err := verifyBlock(x.Body.List, enclosingIfs, true, curPWD, curValidErr); err != nil {
					return err
				}
				mut, pwd := map[string]bool{}, map[string]bool{}
				collectCompoundStmtMutations(x, mut, pwd)
				for m := range mut {
					delete(curValidErr, m)
				}
				for p := range pwd {
					curPWD[p] = true
				}
			case *ast.BlockStmt:
				if err := verifyBlock(x.List, enclosingIfs, inLoop, curPWD, curValidErr); err != nil {
					return err
				}
				mut, pwd := map[string]bool{}, map[string]bool{}
				collectCompoundStmtMutations(x, mut, pwd)
				for m := range mut {
					delete(curValidErr, m)
				}
				for p := range pwd {
					curPWD[p] = true
				}
			case *ast.AssignStmt, *ast.DeclStmt, *ast.ExprStmt, *ast.BranchStmt, *ast.EmptyStmt:
			default:
				return fmt.Errorf("os: Getwd contains unexpected statement %T", st)
			}
		}
		return nil
	}

	if err := verifyBlock(gwStmts, nil, false, map[string]bool{}, map[string]bool{}); err != nil {
		return err
	}

	// Verify Shape 5 if the trailing statement of Getwd is `return <dirVar>, nil`.
	shape5Verified := false
	shape5DirVar := ""
	if lastRet, okLR := stmtUnwrapLabel(gwStmts[len(gwStmts)-1]).(*ast.ReturnStmt); okLR && !allowedReturns[lastRet] {
		if len(lastRet.Results) == 2 {
			dirID, okD := unwrapParens(lastRet.Results[0]).(*ast.Ident)
			_, okNil := isIdentNamed(lastRet.Results[1], "nil")
			if okD && okNil && dirID.Name != "" && dirID.Name != "_" && topParentLoop != nil && topParentLoopIdx >= 1 {
				resetAs, okRA := stmtUnwrapLabel(gwStmts[topParentLoopIdx-1]).(*ast.AssignStmt)
				resetOK := false
				if okRA && (resetAs.Tok == token.ASSIGN || resetAs.Tok == token.DEFINE) && len(resetAs.Lhs) == 1 && len(resetAs.Rhs) == 1 {
					_, okLHS := isIdentNamed(resetAs.Lhs[0], dirID.Name)
					lit, okLit := unwrapParens(resetAs.Rhs[0]).(*ast.BasicLit)
					resetOK = okLHS && okLit && lit.Kind == token.STRING && lit.Value == `""`
				}
				afterUnmutated := !stmtsMutateIdentBefore(gwStmts[topParentLoopIdx+1:], lastRet, dirID.Name)
				if resetOK && afterUnmutated {
					// Verify outer loop break guards and all assignments to dirID inside topParentLoop.
					loopOK := len(dotVars) > 0 && len(rootVars) > 0
					sawClimbAssign := false
					var checkOuterLoop func(stmts []ast.Stmt, encIfs []*ast.IfStmt, nestedLoop bool, validNamesVars, lstatVars, rangeElemVars map[string]bool)
					checkOuterLoop = func(stmts []ast.Stmt, encIfs []*ast.IfStmt, nestedLoop bool, validNamesVars, lstatVars, rangeElemVars map[string]bool) {
						if !loopOK {
							return
						}
						curNames := maps.Clone(validNamesVars)
						curLstat := maps.Clone(lstatVars)
						for i, raw := range stmts {
							if _, isLbl := raw.(*ast.LabeledStmt); isLbl {
								clear(curNames)
								clear(curLstat)
							}
							s := stmtUnwrapLabel(raw)
							if ds, okDS := s.(*ast.DeclStmt); okDS {
								if gd, okGD := ds.Decl.(*ast.GenDecl); okGD {
									for _, spec := range gd.Specs {
										if vs, okVS := spec.(*ast.ValueSpec); okVS {
											for _, id := range vs.Names {
												delete(curNames, id.Name)
												delete(curLstat, id.Name)
												if rangeElemVars[id.Name] || id.Name == dirID.Name {
													loopOK = false
													return
												}
											}
										}
									}
								}
							}
							if as, okA := s.(*ast.AssignStmt); okA {
								for _, lhs := range as.Lhs {
									if id, okID := unwrapParens(lhs).(*ast.Ident); okID {
										delete(curNames, id.Name)
										delete(curLstat, id.Name)
										if rangeElemVars[id.Name] {
											loopOK = false
											return
										}
									}
								}
								// Track `names, err := fd.Readdirnames(...)` guarded by `if err != nil { ... return ... }`.
								if (as.Tok == token.DEFINE || as.Tok == token.ASSIGN) && len(as.Lhs) == 2 && len(as.Rhs) == 1 {
									nID, okN := unwrapParens(as.Lhs[0]).(*ast.Ident)
									eID, okE := unwrapParens(as.Lhs[1]).(*ast.Ident)
									rc, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
									if okN && okE && okC && !rc.Ellipsis.IsValid() && nID.Name != "" && nID.Name != "_" && nID.Name != eID.Name {
										if sel, okS := unwrapParens(rc.Fun).(*ast.SelectorExpr); okS && sel.Sel.Name == "Readdirnames" && eID.Name != "" && eID.Name != "_" && i+1 < len(stmts) {
											if fdID, okFD := unwrapParens(sel.X).(*ast.Ident); okFD && fdVarsInLoop[fdID.Name] {
												if gIf, okGI := stmts[i+1].(*ast.IfStmt); okGI && gIf.Init == nil && gIf.Else == nil && condChecksNonZeroErr(gIf.Cond) == eID.Name && len(gIf.Body.List) > 0 {
													if _, okLastRet := gIf.Body.List[len(gIf.Body.List)-1].(*ast.ReturnStmt); okLastRet {
														curNames[nID.Name] = true
													}
												}
											}
										}
										if _, okLS := isIdentNamed(rc.Fun, "lstatNolog"); okLS && len(rc.Args) == 1 {
											usedStatHelpers = true
											curLstat[nID.Name] = true
										}
									}
								}
								for idxLHS, lhs := range as.Lhs {
									if _, okT := isIdentNamed(lhs, dirID.Name); okT {
										if as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || idxLHS != 0 {
											loopOK = false
											return
										}
										// Must be `"/" + <rangeElem> + <dirVar>` inside `if SameFile(<lstatVar>, <dotVar>)`.
										addOuter, okAO := unwrapParens(as.Rhs[0]).(*ast.BinaryExpr)
										if !okAO || addOuter.Op != token.ADD {
											loopOK = false
											return
										}
										addInner, okAI := unwrapParens(addOuter.X).(*ast.BinaryExpr)
										_, okTail := isIdentNamed(addOuter.Y, dirID.Name)
										if !okAI || addInner.Op != token.ADD || !okTail {
											loopOK = false
											return
										}
										slashLit, okSL := unwrapParens(addInner.X).(*ast.BasicLit)
										elemID, okEL := unwrapParens(addInner.Y).(*ast.Ident)
										if !okSL || slashLit.Kind != token.STRING || slashLit.Value != `"/"` || !okEL || !rangeElemVars[elemID.Name] {
											loopOK = false
											return
										}
										guardedByLstatSameFile := false
										for _, enc := range encIfs {
											if enc.Init == nil {
												if a0, a1, okSF := isSameFileCallPair(enc.Cond); okSF {
													if (curLstat[a0] && dotVars[a1]) || (curLstat[a1] && dotVars[a0]) {
														guardedByLstatSameFile = true
														break
													}
												}
											}
										}
										if !guardedByLstatSameFile {
											loopOK = false
											return
										}
										sawClimbAssign = true
										usedSameFile = true
									}
								}
							}
							switch x := s.(type) {
							case *ast.BranchStmt:
								if x.Tok == token.BREAK && !nestedLoop {
									if x.Label != nil || len(encIfs) == 0 {
										loopOK = false
										return
									}
									innerEnc := encIfs[len(encIfs)-1]
									a0, a1, okSF := isSameFileCallPair(innerEnc.Cond)
									if !okSF || !((pdVarsInLoop[a0] && rootVars[a1]) || (pdVarsInLoop[a1] && rootVars[a0])) {
										loopOK = false
										return
									}
									usedSameFile = true
								}
							case *ast.IfStmt:
								if x.Init != nil {
									loopOK = false
									return
								}
								nextIfs := append(slices.Clone(encIfs), x)
								checkOuterLoop(x.Body.List, nextIfs, nestedLoop, curNames, curLstat, rangeElemVars)
								if x.Else != nil {
									if eb, okEB := x.Else.(*ast.BlockStmt); okEB {
										checkOuterLoop(eb.List, encIfs, nestedLoop, curNames, curLstat, rangeElemVars)
									} else if ei, okEI := x.Else.(*ast.IfStmt); okEI {
										checkOuterLoop([]ast.Stmt{ei}, encIfs, nestedLoop, curNames, curLstat, rangeElemVars)
									} else {
										loopOK = false
										return
									}
								}
								mut, pwd := map[string]bool{}, map[string]bool{}
								collectCompoundStmtMutations(x, mut, pwd)
								for m := range mut {
									delete(curNames, m)
									delete(curLstat, m)
								}
							case *ast.ForStmt:
								checkOuterLoop(x.Body.List, encIfs, true, curNames, curLstat, rangeElemVars)
								mut, pwd := map[string]bool{}, map[string]bool{}
								collectCompoundStmtMutations(x, mut, pwd)
								for m := range mut {
									delete(curNames, m)
									delete(curLstat, m)
								}
							case *ast.RangeStmt:
								if x.Key != nil {
									if kID, okK := unwrapParens(x.Key).(*ast.Ident); okK && (kID.Name == dirID.Name || rangeElemVars[kID.Name]) {
										loopOK = false
										return
									}
								}
								if x.Value != nil {
									if vID, okV := unwrapParens(x.Value).(*ast.Ident); okV && (vID.Name == dirID.Name || rangeElemVars[vID.Name]) {
										loopOK = false
										return
									}
								}
								nextElem := maps.Clone(rangeElemVars)
								if rX, okRX := unwrapParens(x.X).(*ast.Ident); okRX && curNames[rX.Name] && x.Value != nil {
									if vID, okV := unwrapParens(x.Value).(*ast.Ident); okV && vID.Name != "" && vID.Name != "_" {
										nextElem[vID.Name] = true
									}
								}
								checkOuterLoop(x.Body.List, encIfs, true, curNames, curLstat, nextElem)
								mut, pwd := map[string]bool{}, map[string]bool{}
								collectCompoundStmtMutations(x, mut, pwd)
								for m := range mut {
									delete(curNames, m)
									delete(curLstat, m)
								}
							case *ast.BlockStmt:
								checkOuterLoop(x.List, encIfs, nestedLoop, curNames, curLstat, rangeElemVars)
								mut, pwd := map[string]bool{}, map[string]bool{}
								collectCompoundStmtMutations(x, mut, pwd)
								for m := range mut {
									delete(curNames, m)
									delete(curLstat, m)
								}
							case *ast.AssignStmt, *ast.DeclStmt, *ast.ExprStmt, *ast.ReturnStmt, *ast.EmptyStmt:
							default:
								loopOK = false
								return
							}
						}
					}
					checkOuterLoop(topParentLoop.Body.List, nil, false, map[string]bool{}, map[string]bool{}, map[string]bool{})
					if loopOK && sawClimbAssign {
						allowedReturns[lastRet] = true
						shape5Verified = true
						shape5DirVar = dirID.Name
					}
				}
			}
		}
	}

	// Whole-body structural audit: enforce loop label bounds, ban defer/go/closures/address-taking,
	// ensure every syscall.Getwd reference is Shape 1, ensure every ReturnStmt is in allowedReturns,
	// and verify dot/root/Shape-2 variable assignment discipline.
	var walkErr error
	var walkStmt func(n ast.Node, loopLabels map[string]bool, insideParentLoop bool)
	walkStmt = func(n ast.Node, loopLabels map[string]bool, insideParentLoop bool) {
		if walkErr != nil || n == nil {
			return
		}
		switch x := n.(type) {
		case *ast.DeferStmt, *ast.GoStmt, *ast.FuncLit, *ast.SendStmt, *ast.IncDecStmt:
			walkErr = fmt.Errorf("os: Getwd contains forbidden defer/go/closure/send/incdec")
			return
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				walkErr = fmt.Errorf("os: Getwd contains forbidden address-taking expression")
				return
			}
		case *ast.LabeledStmt:
			if len(loopLabels) == 0 || !loopLabels[x.Label.Name] {
				walkErr = fmt.Errorf("os: Getwd contains label outside loop")
				return
			}
			walkStmt(x.Stmt, loopLabels, insideParentLoop)
			return
		case *ast.BranchStmt:
			switch x.Tok {
			case token.FALLTHROUGH:
				walkErr = fmt.Errorf("os: Getwd contains fallthrough")
				return
			case token.BREAK, token.CONTINUE:
				if x.Label != nil {
					walkErr = fmt.Errorf("os: Getwd contains labeled break/continue")
					return
				}
			case token.GOTO:
				if x.Label == nil || !loopLabels[x.Label.Name] {
					walkErr = fmt.Errorf("os: Getwd contains goto outside enclosing loop")
					return
				}
			}
			return
		case *ast.ForStmt:
			nextLabels := maps.Clone(loopLabels)
			if nextLabels == nil {
				nextLabels = map[string]bool{}
			}
			for _, st := range x.Body.List {
				if ls, okLS := st.(*ast.LabeledStmt); okLS && ls.Label != nil {
					nextLabels[ls.Label.Name] = true
				}
			}
			nextInParent := insideParentLoop || x == topParentLoop
			if x.Init != nil {
				walkStmt(x.Init, nextLabels, nextInParent)
			}
			if x.Cond != nil {
				walkStmt(x.Cond, nextLabels, nextInParent)
			}
			if x.Post != nil {
				walkStmt(x.Post, nextLabels, nextInParent)
			}
			for _, st := range x.Body.List {
				walkStmt(st, nextLabels, nextInParent)
			}
			return
		case *ast.RangeStmt:
			for _, expr := range []ast.Expr{x.Key, x.Value} {
				if expr == nil {
					continue
				}
				if rID, okID := unwrapParens(expr).(*ast.Ident); okID {
					if dotVars[rID.Name] || rootVars[rID.Name] || fdVarsInLoop[rID.Name] || pdVarsInLoop[rID.Name] || parentLoopVars[rID.Name] || shape2ReturnedDirVars[rID.Name] {
						walkErr = fmt.Errorf("os: Getwd tracked variable %s overwritten by range clause", rID.Name)
						return
					}
				}
			}
		case *ast.ValueSpec:
			for idx, id := range x.Names {
				if dotVars[id.Name] && len(x.Values) != 0 {
					walkErr = fmt.Errorf("os: Getwd dot variable %s initialized outside statNolog(\".\")", id.Name)
					return
				}
				if rootVars[id.Name] && len(x.Values) != 0 {
					walkErr = fmt.Errorf("os: Getwd root variable %s initialized outside statNolog(\"/\")", id.Name)
					return
				}
				if fdVarsInLoop[id.Name] && len(x.Values) != 0 {
					walkErr = fmt.Errorf("os: Getwd fd variable %s initialized outside openDirNolog", id.Name)
					return
				}
				if pdVarsInLoop[id.Name] && len(x.Values) != 0 {
					walkErr = fmt.Errorf("os: Getwd pd variable %s initialized outside verified fd stat", id.Name)
					return
				}
				if parentLoopVars[id.Name] {
					walkErr = fmt.Errorf("os: Getwd parent variable %s redeclared", id.Name)
					return
				}
				if shape2ReturnedDirVars[id.Name] && idx < len(x.Values) {
					walkErr = fmt.Errorf("os: Getwd hint variable %s has unexpected ValueSpec initializer", id.Name)
					return
				}
			}
		case *ast.AssignStmt:
			for idxLHS, lhs := range x.Lhs {
				lID, okID := unwrapParens(lhs).(*ast.Ident)
				if !okID {
					continue
				}
				if dotVars[lID.Name] && !dotSeedAssigns[x] {
					stepOK := insideParentLoop && x.Tok == token.ASSIGN && len(x.Lhs) == 1 && len(x.Rhs) == 1
					if stepOK {
						if rhsID, okR := unwrapParens(x.Rhs[0]).(*ast.Ident); !okR || !pdVarsInLoop[rhsID.Name] {
							stepOK = false
						}
					}
					if !stepOK {
						walkErr = fmt.Errorf("os: Getwd dot variable %s assigned from unverified source", lID.Name)
						return
					}
				}
				if rootVars[lID.Name] && !rootSeedAssigns[x] {
					walkErr = fmt.Errorf("os: Getwd root variable %s reassigned", lID.Name)
					return
				}
				if fdVarsInLoop[lID.Name] && !fdSeedAssigns[x] {
					walkErr = fmt.Errorf("os: Getwd fd variable %s reassigned", lID.Name)
					return
				}
				if pdVarsInLoop[lID.Name] && !pdSeedAssigns[x] {
					walkErr = fmt.Errorf("os: Getwd pd variable %s reassigned", lID.Name)
					return
				}
				if parentLoopVars[lID.Name] && !parentInitAssigns[x] && !parentStepAssigns[x] {
					walkErr = fmt.Errorf("os: Getwd parent variable %s reassigned", lID.Name)
					return
				}
				if shape2ReturnedDirVars[lID.Name] && !shape1Assigns[x] {
					if insideParentLoop && shape5Verified && lID.Name == shape5DirVar {
						// Verified by checkOuterLoop to be "/" + name + dir.
						continue
					}
					hintOK := !insideParentLoop && (x.Tok == token.ASSIGN || x.Tok == token.DEFINE) && len(x.Lhs) == 1 && len(x.Rhs) == 1 && idxLHS == 0
					if hintOK {
						rhs := unwrapParens(x.Rhs[0])
						if lit, okLit := rhs.(*ast.BasicLit); okLit && lit.Kind == token.STRING && lit.Value == `""` {
							// allowed reset
						} else if _, okCache := isSelectorBaseField(rhs, "getwdCache", "dir"); okCache {
							usedGetwdCache = true
						} else if c, okC := rhs.(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) == 1 {
							_, okGE := isIdentNamed(c.Fun, "Getenv")
							aLit, okAL := unwrapParens(c.Args[0]).(*ast.BasicLit)
							hintOK = okGE && okAL && aLit.Kind == token.STRING && aLit.Value == `"PWD"`
						} else {
							hintOK = false
						}
					}
					if !hintOK {
						walkErr = fmt.Errorf("os: Getwd hint variable %s assigned from unverified source", lID.Name)
						return
					}
				}
			}
		case *ast.Ident:
			if x.Name == "testlog" {
				walkErr = fmt.Errorf("os: Getwd references testlog")
				return
			}
		case *ast.SelectorExpr:
			if _, okSG := isSelectorBaseField(x, "syscall", "Getwd"); okSG && !allowedSyscallGetwdSels[x] {
				walkErr = fmt.Errorf("os: Getwd references syscall.Getwd outside verified return pair")
				return
			}
			if _, okSys := isIdentNamed(x.X, "syscall"); okSys && (x.Sel.Name == "Chdir" || x.Sel.Name == "Fchdir") {
				walkErr = fmt.Errorf("os: Getwd calls syscall.%s", x.Sel.Name)
				return
			}
		case *ast.CallExpr:
			if cID, okID := unwrapParens(x.Fun).(*ast.Ident); okID {
				switch cID.Name {
				case "recover", "Chdir", "Fchdir":
					walkErr = fmt.Errorf("os: Getwd calls forbidden %s", cID.Name)
					return
				case "ignoringEINTR2":
					usedIgnoringEINTR2 = true
				case "NewSyscallError":
					usedNewSyscallError = true
				case "SameFile":
					usedSameFile = true
				case "openDirNolog":
					usedOpenDirNolog = true
				case "statNolog", "lstatNolog":
					usedStatHelpers = true
				case "fstatNolog":
					usedStatHelpers = true
					usedFstatNolog = true
				}
			} else if sel, okS := unwrapParens(x.Fun).(*ast.SelectorExpr); okS && sel.Sel.Name == "Stat" && len(x.Args) == 0 {
				usedStatHelpers = true
				usedFileStatInGetwd = true
			}
		case *ast.ReturnStmt:
			if !allowedReturns[x] {
				walkErr = fmt.Errorf("os: Getwd contains unverified return statement")
				return
			}
		}
		ast.Inspect(n, func(ch ast.Node) bool {
			if ch == n {
				return true
			}
			walkStmt(ch, loopLabels, insideParentLoop)
			return false
		})
	}
	for _, st := range gwStmts {
		walkStmt(st, nil, false)
		if walkErr != nil {
			return walkErr
		}
	}
	if !sawSyscallGetwd {
		return fmt.Errorf("os: Getwd does not invoke syscall.Getwd")
	}

	if usedGetwdCache {
		if pkgDeclCounts["getwdCache"] != 1 {
			return fmt.Errorf("os: invalid getwdCache declaration count")
		}
		var cacheDeclIdent *ast.Ident
		for _, f := range files {
			for _, decl := range f.Decls {
				gd, okGD := decl.(*ast.GenDecl)
				if !okGD || gd.Tok != token.VAR {
					continue
				}
				for _, spec := range gd.Specs {
					vs, okVS := spec.(*ast.ValueSpec)
					if !okVS || len(vs.Names) != 1 || vs.Names[0].Name != "getwdCache" {
						continue
					}
					if len(vs.Values) != 0 {
						return fmt.Errorf("os: getwdCache must be zero-initialized")
					}
					if _, okST := unwrapParens(vs.Type).(*ast.StructType); !okST {
						return fmt.Errorf("os: getwdCache must be an unexported anonymous struct")
					}
					cacheDeclIdent = vs.Names[0]
				}
			}
		}
		if cacheDeclIdent == nil {
			return fmt.Errorf("os: missing getwdCache var declaration")
		}
		postLoopAssigns := map[*ast.AssignStmt]bool{}
		if shape5Verified && topParentLoopIdx >= 0 && topParentLoopIdx+1 < len(gwStmts) {
			for _, st := range gwStmts[topParentLoopIdx+1:] {
				ast.Inspect(st, func(n ast.Node) bool {
					if as, okA := n.(*ast.AssignStmt); okA {
						postLoopAssigns[as] = true
					}
					return true
				})
			}
		}
		fileHasUnaliasedImport := func(f *ast.File, want string) bool {
			if f == nil {
				return false
			}
			for _, imp := range f.Imports {
				if imp.Name != nil {
					continue
				}
				if p, err := strconv.Unquote(imp.Path.Value); err == nil && p == want {
					return true
				}
			}
			return false
		}
		chdirFn := allTopFuncs["Chdir"]
		chdirParam0 := ""
		chdirAbsIfs := map[*ast.IfStmt]bool{}
		if chdirFn != nil && chdirFn.Body != nil && chdirFn.Type != nil && fileHasUnaliasedImport(funcFile[chdirFn], "internal/filepathlite") && !funcShadowsAnyIdent(chdirFn, map[string]bool{"filepathlite": true, "getwdCache": true}) {
			if pNames := paramNamesFlat(chdirFn.Type.Params); len(pNames) == 1 && pNames[0] != "" && pNames[0] != "_" && !stmtsMutateIdentBefore(chdirFn.Body.List, nil, pNames[0]) {
				chdirParam0 = pNames[0]
				absAssignCounts := map[string]int{}
				absVerifiedVars := map[string]bool{}
				ast.Inspect(chdirFn.Body, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.AssignStmt:
						for i, lhs := range x.Lhs {
							if id, okID := unwrapParens(lhs).(*ast.Ident); okID && id.Name != "" && id.Name != "_" {
								absAssignCounts[id.Name]++
								if len(x.Lhs) == 1 && len(x.Rhs) == 1 && i == 0 && (x.Tok == token.DEFINE || x.Tok == token.ASSIGN) {
									if c, okC := unwrapParens(x.Rhs[0]).(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) == 1 {
										_, okFP := isSelectorBaseField(c.Fun, "filepathlite", "IsAbs")
										_, okP0 := isIdentNamed(c.Args[0], chdirParam0)
										if okFP && okP0 {
											absVerifiedVars[id.Name] = true
										}
									}
								}
							}
						}
					case *ast.ValueSpec:
						for _, id := range x.Names {
							if id.Name != "" && id.Name != "_" {
								absAssignCounts[id.Name]++
							}
						}
					}
					return true
				})
				ast.Inspect(chdirFn.Body, func(n ast.Node) bool {
					if ifs, okI := n.(*ast.IfStmt); okI && ifs.Init == nil {
						if cID, okID := unwrapParens(ifs.Cond).(*ast.Ident); okID && absVerifiedVars[cID.Name] && absAssignCounts[cID.Name] == 1 {
							chdirAbsIfs[ifs] = true
						}
					}
					return true
				})
			}
		}
		for _, f := range files {
			for _, decl := range f.Decls {
				switch d := decl.(type) {
				case *ast.GenDecl:
					var gdErr error
					ast.Inspect(d, func(n ast.Node) bool {
						if gdErr != nil || n == nil {
							return false
						}
						if id, okID := n.(*ast.Ident); okID && id.Name == "getwdCache" && id != cacheDeclIdent {
							gdErr = fmt.Errorf("os: unexpected package-level reference to getwdCache")
							return false
						}
						return true
					})
					if gdErr != nil {
						return gdErr
					}
				case *ast.FuncDecl:
					if d.Body == nil {
						continue
					}
					mentionsCache := false
					ast.Inspect(d.Body, func(n ast.Node) bool {
						if id, okID := n.(*ast.Ident); okID && id.Name == "getwdCache" {
							mentionsCache = true
							return false
						}
						return true
					})
					if !mentionsCache {
						continue
					}
					if funcShadowsAnyIdent(d, map[string]bool{"getwdCache": true}) {
						return fmt.Errorf("os: function %s shadows getwdCache", d.Name.Name)
					}
					validBaseIdents := map[*ast.Ident]bool{}
					ast.Inspect(d.Body, func(n ast.Node) bool {
						if sel, okS := n.(*ast.SelectorExpr); okS {
							if bID, okB := unwrapParens(sel.X).(*ast.Ident); okB && bID.Name == "getwdCache" && (sel.Sel.Name == "Lock" || sel.Sel.Name == "Unlock" || sel.Sel.Name == "dir") {
								validBaseIdents[bID] = true
							}
						}
						return true
					})
					var cacheErr error
					var auditCache func(n ast.Node, inAbsBody bool)
					auditCache = func(n ast.Node, inAbsBody bool) {
						if cacheErr != nil || n == nil {
							return
						}
						if ifs, okI := n.(*ast.IfStmt); okI {
							if skipInactiveHookIf(ifs, d) {
								return
							}
							if ifs.Init != nil {
								auditCache(ifs.Init, inAbsBody)
							}
							auditCache(ifs.Cond, inAbsBody)
							auditCache(ifs.Body, inAbsBody || chdirAbsIfs[ifs])
							if ifs.Else != nil {
								auditCache(ifs.Else, inAbsBody)
							}
							return
						}
						switch x := n.(type) {
						case *ast.Ident:
							if x.Name == "getwdCache" && !validBaseIdents[x] {
								cacheErr = fmt.Errorf("os: unsupported getwdCache reference in %s", d.Name.Name)
								return
							}
						case *ast.UnaryExpr:
							if x.Op == token.AND {
								if _, okCD := isSelectorBaseField(x.X, "getwdCache", "dir"); okCD {
									cacheErr = fmt.Errorf("os: address taken of getwdCache.dir in %s", d.Name.Name)
									return
								}
							}
						case *ast.IncDecStmt:
							if _, okCD := isSelectorBaseField(x.X, "getwdCache", "dir"); okCD {
								cacheErr = fmt.Errorf("os: inc/dec on getwdCache.dir in %s", d.Name.Name)
								return
							}
						case *ast.RangeStmt:
							for _, expr := range []ast.Expr{x.Key, x.Value} {
								if expr != nil {
									if _, okCD := isSelectorBaseField(expr, "getwdCache", "dir"); okCD {
										cacheErr = fmt.Errorf("os: range write to getwdCache.dir in %s", d.Name.Name)
										return
									}
								}
							}
						case *ast.AssignStmt:
							for idxLHS, lhs := range x.Lhs {
								if _, okCD := isSelectorBaseField(lhs, "getwdCache", "dir"); okCD {
									writeOK := false
									if x.Tok == token.ASSIGN {
										if len(x.Lhs) == 1 && len(x.Rhs) == 1 {
											rhs := unwrapParens(x.Rhs[0])
											if lit, okL := rhs.(*ast.BasicLit); okL && lit.Kind == token.STRING && lit.Value == `""` {
												writeOK = true
											} else if d == gwFn && shape5Verified && postLoopAssigns[x] {
												_, writeOK = isIdentNamed(rhs, shape5DirVar)
											} else if d == chdirFn && inAbsBody && chdirParam0 != "" {
												_, writeOK = isIdentNamed(rhs, chdirParam0)
											}
										} else if len(x.Lhs) == 2 && len(x.Rhs) == 1 && idxLHS == 0 && fileImportsSyscall[f] && !funcShadowsAnyIdent(d, map[string]bool{"syscall": true}) {
											_, okBlank := isIdentNamed(x.Lhs[1], "_")
											if c, okC := unwrapParens(x.Rhs[0]).(*ast.CallExpr); okBlank && okC && !c.Ellipsis.IsValid() && len(c.Args) == 0 {
												_, writeOK = isSelectorBaseField(c.Fun, "syscall", "Getwd")
											}
										}
									}
									if !writeOK {
										cacheErr = fmt.Errorf("os: unverified write to getwdCache.dir in %s", d.Name.Name)
										return
									}
								}
							}
						}
						ast.Inspect(n, func(ch ast.Node) bool {
							if ch == n {
								return true
							}
							auditCache(ch, inAbsBody)
							return false
						})
					}
					auditCache(d.Body, false)
					if cacheErr != nil {
						return cacheErr
					}
				}
			}
		}
	}

	if usedIgnoringEINTR2 {
		ig2 := allTopFuncs["ignoringEINTR2"]
		if ig2 == nil || ig2.Body == nil || ig2.Type == nil || (ig2.Type.TypeParams != nil && ig2.Type.TypeParams.NumFields() > 1) || !funcHasUnnamedResults(ig2.Type, 2) || pkgDeclCounts["ignoringEINTR2"] != 1 || osAnyLinknameLocals["ignoringEINTR2"] || funcShadowsAnyIdent(ig2, osReserved) || bodyHasControlFlowOrRecoverBypass(ig2.Body) || len(ig2.Body.List) != 1 {
			return fmt.Errorf("os: invalid ignoringEINTR2 helper")
		}
		igParams := paramNamesFlat(ig2.Type.Params)
		if len(igParams) != 1 || igParams[0] == "" || igParams[0] == "_" {
			return fmt.Errorf("os: ignoringEINTR2 invalid parameters")
		}
		if ret, okRet := ig2.Body.List[0].(*ast.ReturnStmt); okRet && len(ret.Results) == 1 {
			c, okC := unwrapParens(ret.Results[0]).(*ast.CallExpr)
			if !okC || c.Ellipsis.IsValid() || len(c.Args) != 0 {
				return fmt.Errorf("os: ignoringEINTR2 invalid fn() return")
			}
			if _, okFn := isIdentNamed(c.Fun, igParams[0]); !okFn {
				return fmt.Errorf("os: ignoringEINTR2 does not call %s()", igParams[0])
			}
		} else {
			fs, okFor := ig2.Body.List[0].(*ast.ForStmt)
			if !okFor || !fileImportsSyscall[funcFile[ig2]] || fs.Init != nil || fs.Cond != nil || fs.Post != nil || len(fs.Body.List) != 2 {
				return fmt.Errorf("os: ignoringEINTR2 unexpected body")
			}
			as, okA := fs.Body.List[0].(*ast.AssignStmt)
			if !okA || as.Tok != token.DEFINE || len(as.Lhs) != 2 || len(as.Rhs) != 1 {
				return fmt.Errorf("os: ignoringEINTR2 missing fn() call")
			}
			vID, okV := unwrapParens(as.Lhs[0]).(*ast.Ident)
			errID, okE := unwrapParens(as.Lhs[1]).(*ast.Ident)
			if !okV || !okE || vID.Name == "" || vID.Name == "_" || errID.Name == "" || errID.Name == "_" || vID.Name == errID.Name {
				return fmt.Errorf("os: ignoringEINTR2 invalid result bindings")
			}
			c, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
			if !okC || c.Ellipsis.IsValid() || len(c.Args) != 0 {
				return fmt.Errorf("os: ignoringEINTR2 invalid fn() call")
			}
			if _, okFn := isIdentNamed(c.Fun, igParams[0]); !okFn {
				return fmt.Errorf("os: ignoringEINTR2 does not call %s()", igParams[0])
			}
			ifs, okI := fs.Body.List[1].(*ast.IfStmt)
			if !okI || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
				return fmt.Errorf("os: ignoringEINTR2 unexpected loop guard")
			}
			condBin, okCB := unwrapParens(ifs.Cond).(*ast.BinaryExpr)
			if !okCB || condBin.Op != token.NEQ {
				return fmt.Errorf("os: ignoringEINTR2 loop guard is not != syscall.EINTR")
			}
			_, okEL := isIdentNamed(condBin.X, errID.Name)
			_, okSysR := isSelectorBaseField(condBin.Y, "syscall", "EINTR")
			_, okSysL := isSelectorBaseField(condBin.X, "syscall", "EINTR")
			_, okER := isIdentNamed(condBin.Y, errID.Name)
			if !((okEL && okSysR) || (okSysL && okER)) {
				return fmt.Errorf("os: ignoringEINTR2 loop guard does not check %s != syscall.EINTR", errID.Name)
			}
			ret2, okR2 := ifs.Body.List[0].(*ast.ReturnStmt)
			if !okR2 || len(ret2.Results) != 2 {
				return fmt.Errorf("os: ignoringEINTR2 unexpected return")
			}
			_, okRV := isIdentNamed(ret2.Results[0], vID.Name)
			_, okRE := isIdentNamed(ret2.Results[1], errID.Name)
			if !okRV || !okRE {
				return fmt.Errorf("os: ignoringEINTR2 does not return (%s, %s)", vID.Name, errID.Name)
			}
		}
	}
	if usedNewSyscallError {
		nse := allTopFuncs["NewSyscallError"]
		if nse == nil || nse.Body == nil || nse.Type == nil || nse.Type.TypeParams != nil || !funcHasUnnamedResults(nse.Type, 1) || pkgDeclCounts["NewSyscallError"] != 1 || osAnyLinknameLocals["NewSyscallError"] || nonAliasStructSpecs["SyscallError"] == nil || pkgDeclCounts["SyscallError"] != 1 || funcShadowsAnyIdent(nse, map[string]bool{"nil": true, "error": true, "SyscallError": true}) || bodyHasControlFlowOrRecoverBypass(nse.Body) || len(nse.Body.List) != 2 {
			return fmt.Errorf("os: invalid NewSyscallError helper")
		}
		nseParams := paramNamesFlat(nse.Type.Params)
		if len(nseParams) != 2 || nseParams[0] == "" || nseParams[0] == "_" || nseParams[1] == "" || nseParams[1] == "_" || nseParams[0] == nseParams[1] || bodyMutatesOrTakesAddrOfAny(nse.Body, map[string]bool{nseParams[1]: true}) {
			return fmt.Errorf("os: NewSyscallError invalid parameters")
		}
		ifs, okI := nse.Body.List[0].(*ast.IfStmt)
		ret1, okR1 := nse.Body.List[1].(*ast.ReturnStmt)
		if !okI || ifs.Init != nil || ifs.Else != nil || !condChecksEqErr(ifs.Cond, nseParams[1]) || len(ifs.Body.List) != 1 || !okR1 || len(ret1.Results) != 1 {
			return fmt.Errorf("os: NewSyscallError unexpected body")
		}
		ret0, okR0 := ifs.Body.List[0].(*ast.ReturnStmt)
		if !okR0 || len(ret0.Results) != 1 {
			return fmt.Errorf("os: NewSyscallError nil branch does not return single value")
		}
		if _, okNil := isIdentNamed(ret0.Results[0], "nil"); !okNil {
			return fmt.Errorf("os: NewSyscallError nil branch does not return nil")
		}
		u, okU := unwrapParens(ret1.Results[0]).(*ast.UnaryExpr)
		cl, tName := compositeWriterLit(ret1.Results[0])
		if !okU || u.Op != token.AND || cl == nil || tName != "SyscallError" {
			return fmt.Errorf("os: NewSyscallError does not return &SyscallError")
		}
		bindsErrField := false
		if len(cl.Elts) == 2 {
			_, kv0 := cl.Elts[0].(*ast.KeyValueExpr)
			_, kv1 := cl.Elts[1].(*ast.KeyValueExpr)
			if !kv0 && !kv1 {
				_, bindsErrField = isIdentNamed(cl.Elts[1], nseParams[1])
			}
		}
		if !bindsErrField {
			for _, elt := range cl.Elts {
				kv, okKV := elt.(*ast.KeyValueExpr)
				if !okKV {
					bindsErrField = false
					break
				}
				if kID, okK := kv.Key.(*ast.Ident); okK && kID.Name == "Err" {
					_, bindsErrField = isIdentNamed(kv.Value, nseParams[1])
				}
			}
		}
		if !bindsErrField {
			return fmt.Errorf("os: NewSyscallError does not bind error parameter in SyscallError")
		}
	}
	if usedOpenDirNolog {
		odFn := allTopFuncs["openDirNolog"]
		if odFn == nil || odFn.Body == nil || odFn.Type == nil || odFn.Type.TypeParams != nil || pkgDeclCounts["openDirNolog"] != 1 || osAnyLinknameLocals["openDirNolog"] || funcShadowsAnyIdent(odFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(odFn.Body) {
			return fmt.Errorf("os: invalid openDirNolog helper")
		}
		odParams := paramNamesFlat(odFn.Type.Params)
		if len(odParams) != 1 || odParams[0] == "" || odParams[0] == "_" || odFn.Type.Results == nil || odFn.Type.Results.NumFields() != 2 || !funcReturnsErrorLast(odFn.Type) {
			return fmt.Errorf("os: openDirNolog invalid signature")
		}
		if starF, okS := unwrapParens(odFn.Type.Results.List[0].Type).(*ast.StarExpr); !okS {
			return fmt.Errorf("os: openDirNolog first result is not *File")
		} else if _, okF := isIdentNamed(starF.X, "File"); !okF {
			return fmt.Errorf("os: openDirNolog first result is not *File")
		}
		odPos := 0
		for odPos < len(odFn.Body.List) && skipInactiveHookIf(odFn.Body.List[odPos], odFn) {
			odPos++
		}
		if odPos >= len(odFn.Body.List) {
			return fmt.Errorf("os: openDirNolog empty body")
		}
		var odErr error
		for _, st := range odFn.Body.List[odPos:] {
			ast.Inspect(st, func(n ast.Node) bool {
				if odErr != nil || n == nil {
					return false
				}
				if ifs, okI := n.(*ast.IfStmt); okI && skipInactiveHookIf(ifs, odFn) {
					return false
				}
				switch x := n.(type) {
				case *ast.Ident:
					if x.Name == "testlog" {
						odErr = fmt.Errorf("os: openDirNolog references testlog")
						return false
					}
				case *ast.SelectorExpr:
					if _, okSys := isIdentNamed(x.X, "syscall"); okSys {
						switch x.Sel.Name {
						case "Chdir", "Fchdir", "Unlink", "Rmdir", "Rename":
							odErr = fmt.Errorf("os: openDirNolog calls syscall.%s", x.Sel.Name)
							return false
						}
					}
				case *ast.CallExpr:
					if cID, okID := unwrapParens(x.Fun).(*ast.Ident); okID {
						if osAnyLinknameLocals[cID.Name] {
							odErr = fmt.Errorf("os: openDirNolog calls linknamed %s", cID.Name)
							return false
						}
						switch cID.Name {
						case "Open", "OpenFile", "Create", "Stat", "Lstat", "Chdir", "Fchdir", "Remove", "Rename", "Truncate", "openDir":
							odErr = fmt.Errorf("os: openDirNolog calls forbidden %s", cID.Name)
							return false
						case "fstatNolog":
							usedStatHelpers = true
							usedFstatNolog = true
						case "statNolog", "lstatNolog":
							usedStatHelpers = true
						}
					} else if sel, okS := unwrapParens(x.Fun).(*ast.SelectorExpr); okS && sel.Sel.Name == "Stat" && len(x.Args) == 0 {
						usedStatHelpers = true
						usedFileStatInGetwd = true
					}
				}
				return true
			})
			if odErr != nil {
				return odErr
			}
		}
	}
	var disjointAltStruct string
	if usedSameFile {
		var err error
		disjointAltStruct, err = verifyOSSameFile(allTopFuncs, nonAliasStructSpecs, pkgDeclCounts, osReserved, osNoFileReserved, osAnyLinknameLocals, osInactive, skipInactiveHookIf)
		if err != nil {
			return err
		}
	}
	if usedStatHelpers || usedSameFile {
		if err := verifyOSNologStatHelpers(allTopFuncs, allFileMethods, allRawFileMethods, allFileStatMethods, pkgDeclCounts, fileMethodCounts, rawFileMethodCounts, fileStatMethodCounts, funcFile, fileImportsSyscall, osInactive, osNoFileReserved, osAnyLinknameLocals, disjointAltStruct, usedSameFile, usedFstatNolog, usedFileStatInGetwd, skipInactiveHookIf); err != nil {
			return err
		}
	}
	return nil
}

func verifyOSSameFile(
	allTopFuncs map[string]*ast.FuncDecl,
	nonAliasStructSpecs map[string]*ast.TypeSpec,
	pkgDeclCounts map[string]int,
	osReserved, osNoFileReserved, osAnyLinknameLocals map[string]bool,
	osInactive *osInactiveState,
	skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool,
) (string, error) {
	sf := allTopFuncs["SameFile"]
	if sf == nil || sf.Body == nil || sf.Type == nil || sf.Type.TypeParams != nil || !funcHasUnnamedResults(sf.Type, 1) || pkgDeclCounts["SameFile"] != 1 || osAnyLinknameLocals["SameFile"] || funcShadowsAnyIdent(sf, osReserved) || bodyHasControlFlowOrRecoverBypass(sf.Body) {
		return "", fmt.Errorf("os: invalid SameFile helper")
	}
	if _, okBool := isIdentNamed(sf.Type.Results.List[0].Type, "bool"); !okBool {
		return "", fmt.Errorf("os: SameFile does not return bool")
	}
	sfParams := paramNamesFlat(sf.Type.Params)
	if len(sfParams) != 2 || sfParams[0] == "" || sfParams[0] == "_" || sfParams[1] == "" || sfParams[1] == "_" || sfParams[0] == sfParams[1] || bodyMutatesOrTakesAddrOfAny(sf.Body, map[string]bool{sfParams[0]: true, sfParams[1]: true}) {
		return "", fmt.Errorf("os: SameFile invalid parameters")
	}
	if nonAliasStructSpecs["fileStat"] == nil || pkgDeclCounts["fileStat"] != 1 {
		return "", fmt.Errorf("os: missing unique fileStat struct definition")
	}

	matchPtrStructTypeAssert := func(st ast.Stmt, wantParam string) (string, string, string, bool) {
		as, okA := st.(*ast.AssignStmt)
		if !okA || as.Tok != token.DEFINE || len(as.Lhs) != 2 || len(as.Rhs) != 1 {
			return "", "", "", false
		}
		vID, okV := unwrapParens(as.Lhs[0]).(*ast.Ident)
		okID, okO := unwrapParens(as.Lhs[1]).(*ast.Ident)
		ta, okTA := unwrapParens(as.Rhs[0]).(*ast.TypeAssertExpr)
		if !okV || !okO || !okTA || ta.Type == nil || vID.Name == "" || vID.Name == "_" || okID.Name == "" || okID.Name == "_" || vID.Name == okID.Name {
			return "", "", "", false
		}
		if _, okX := isIdentNamed(ta.X, wantParam); !okX {
			return "", "", "", false
		}
		star, okS := unwrapParens(ta.Type).(*ast.StarExpr)
		if !okS {
			return "", "", "", false
		}
		tID, okT := unwrapParens(star.X).(*ast.Ident)
		if !okT || tID.Name == "" {
			return "", "", "", false
		}
		return vID.Name, okID.Name, tID.Name, true
	}

	pos := 0
	for pos < len(sf.Body.List) && skipInactiveHookIf(sf.Body.List[pos], sf) {
		pos++
	}

	var disjointAltStruct string
	if pos < len(sf.Body.List) {
		var candInner *ast.IfStmt
		if outerIf, okOut := sf.Body.List[pos].(*ast.IfStmt); okOut && outerIf.Else == nil {
			if outerIf.Init != nil {
				candInner = outerIf
			} else if cID, okC := unwrapParens(outerIf.Cond).(*ast.Ident); okC && (cID.Name == "true" || (osInactive != nil && osInactive.trueConsts[cID.Name])) && !funcShadowsAnyIdent(sf, map[string]bool{cID.Name: true}) && len(outerIf.Body.List) == 1 {
				if inIf, okIn := outerIf.Body.List[0].(*ast.IfStmt); okIn && inIf.Else == nil {
					candInner = inIf
				}
			}
		}
		if candInner != nil && candInner.Init != nil && len(candInner.Body.List) == 1 {
			initAs, okIA := candInner.Init.(*ast.AssignStmt)
			retSt, okRS := candInner.Body.List[0].(*ast.ReturnStmt)
			if okIA && initAs.Tok == token.DEFINE && len(initAs.Lhs) == 2 && len(initAs.Rhs) == 1 && okRS && len(retSt.Results) == 1 {
				sID, okS := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
				hID, okH := unwrapParens(initAs.Lhs[1]).(*ast.Ident)
				hc, okHC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
				if okS && okH && okHC && !hc.Ellipsis.IsValid() && len(hc.Args) == 2 && sID.Name != "" && sID.Name != "_" && hID.Name != "" && hID.Name != "_" && sID.Name != hID.Name {
					_, okCond := isIdentNamed(candInner.Cond, hID.Name)
					_, okRet := isIdentNamed(retSt.Results[0], sID.Name)
					_, okA0 := isIdentNamed(hc.Args[0], sfParams[0])
					_, okA1 := isIdentNamed(hc.Args[1], sfParams[1])
					calleeID, okCallee := unwrapParens(hc.Fun).(*ast.Ident)
					if okCond && okRet && okA0 && okA1 && okCallee && !ast.IsExported(calleeID.Name) && pkgDeclCounts[calleeID.Name] == 1 && !osAnyLinknameLocals[calleeID.Name] && !funcShadowsAnyIdent(sf, map[string]bool{calleeID.Name: true}) {
						hFn := allTopFuncs[calleeID.Name]
						if hFn != nil && hFn.Body != nil && hFn.Type != nil && hFn.Type.TypeParams == nil && hFn.Type.Results != nil && hFn.Type.Results.NumFields() == 2 && !funcShadowsAnyIdent(hFn, map[string]bool{"false": true, "bool": true}) && !bodyHasControlFlowOrRecoverBypass(hFn.Body) {
							resAllBool := true
							hResNames := map[string]bool{}
							for _, fld := range hFn.Type.Results.List {
								if _, okB := isIdentNamed(fld.Type, "bool"); !okB {
									resAllBool = false
									break
								}
								for _, id := range fld.Names {
									hResNames[id.Name] = true
								}
							}
							qParams := paramNamesFlat(hFn.Type.Params)
							if resAllBool && len(qParams) == 2 && qParams[0] != "" && qParams[0] != "_" && qParams[1] != "" && qParams[1] != "_" && qParams[0] != qParams[1] && !bodyMutatesOrTakesAddrOfAny(hFn.Body, map[string]bool{qParams[0]: true, qParams[1]: true}) {
								hPos := 0
								for hPos < len(hFn.Body.List) && skipInactiveHookIf(hFn.Body.List[hPos], hFn) {
									hPos++
								}
								if hPos+3 <= len(hFn.Body.List) {
									d1, ok1, st1, m1 := matchPtrStructTypeAssert(hFn.Body.List[hPos], qParams[0])
									d2, ok2, st2, m2 := matchPtrStructTypeAssert(hFn.Body.List[hPos+1], qParams[1])
									gIf, okGI := hFn.Body.List[hPos+2].(*ast.IfStmt)
									distinctLocals := d1 != d2 && d1 != ok2 && ok1 != d2 && ok1 != ok2 && !hResNames[d1] && !hResNames[ok1] && !hResNames[d2] && !hResNames[ok2] && d1 != qParams[0] && d1 != qParams[1] && ok1 != qParams[0] && ok1 != qParams[1] && d2 != qParams[0] && d2 != qParams[1] && ok2 != qParams[0] && ok2 != qParams[1]
									if m1 && m2 && distinctLocals && st1 == st2 && !ast.IsExported(st1) && st1 != "fileStat" && nonAliasStructSpecs[st1] != nil && pkgDeclCounts[st1] == 1 && okGI && gIf.Init == nil && gIf.Else == nil && len(gIf.Body.List) == 1 {
										binAnd, okBA := unwrapParens(gIf.Cond).(*ast.BinaryExpr)
										gRet, okGR := gIf.Body.List[0].(*ast.ReturnStmt)
										if okBA && binAnd.Op == token.LAND && okGR && len(gRet.Results) == 2 {
											uL, okUL := unwrapParens(binAnd.X).(*ast.UnaryExpr)
											uR, okUR := unwrapParens(binAnd.Y).(*ast.UnaryExpr)
											_, okF0 := isIdentNamed(gRet.Results[0], "false")
											_, okF1 := isIdentNamed(gRet.Results[1], "false")
											if okUL && okUR && uL.Op == token.NOT && uR.Op == token.NOT && okF0 && okF1 {
												_, l1 := isIdentNamed(uL.X, ok1)
												_, r2 := isIdentNamed(uR.X, ok2)
												_, l2 := isIdentNamed(uL.X, ok2)
												_, r1 := isIdentNamed(uR.X, ok1)
												if (l1 && r2) || (l2 && r1) {
													disjointAltStruct = st1
													pos++
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	rem := sf.Body.List[pos:]
	if len(rem) != 4 {
		return "", fmt.Errorf("os: SameFile unexpected statement count %d", len(rem))
	}
	fs1, ok1, st1, m1 := matchPtrStructTypeAssert(rem[0], sfParams[0])
	fs2, ok2, st2, m2 := matchPtrStructTypeAssert(rem[1], sfParams[1])
	if !m1 || !m2 || st1 != "fileStat" || st2 != "fileStat" || fs1 == fs2 || fs1 == ok2 || ok1 == fs2 || ok1 == ok2 {
		return "", fmt.Errorf("os: SameFile missing (*fileStat) type assertions")
	}
	gIf, okGI := rem[2].(*ast.IfStmt)
	if !okGI || gIf.Init != nil || gIf.Else != nil || len(gIf.Body.List) != 1 {
		return "", fmt.Errorf("os: SameFile missing (!ok1 || !ok2) guard")
	}
	binOr, okBO := unwrapParens(gIf.Cond).(*ast.BinaryExpr)
	gRet, okGR := gIf.Body.List[0].(*ast.ReturnStmt)
	if !okBO || binOr.Op != token.LOR || !okGR || len(gRet.Results) != 1 {
		return "", fmt.Errorf("os: SameFile invalid (!ok1 || !ok2) guard")
	}
	uL, okUL := unwrapParens(binOr.X).(*ast.UnaryExpr)
	uR, okUR := unwrapParens(binOr.Y).(*ast.UnaryExpr)
	_, okFalse := isIdentNamed(gRet.Results[0], "false")
	if !okUL || !okUR || uL.Op != token.NOT || uR.Op != token.NOT || !okFalse {
		return "", fmt.Errorf("os: SameFile guard does not return false on !ok1 || !ok2")
	}
	_, l1 := isIdentNamed(uL.X, ok1)
	_, r2 := isIdentNamed(uR.X, ok2)
	_, l2 := isIdentNamed(uL.X, ok2)
	_, r1 := isIdentNamed(uR.X, ok1)
	if !((l1 && r2) || (l2 && r1)) {
		return "", fmt.Errorf("os: SameFile guard does not check (!%s || !%s)", ok1, ok2)
	}
	lastRet, okLR := rem[3].(*ast.ReturnStmt)
	if !okLR || len(lastRet.Results) != 1 {
		return "", fmt.Errorf("os: SameFile missing final return")
	}
	smCall, okSMC := unwrapParens(lastRet.Results[0]).(*ast.CallExpr)
	if !okSMC || smCall.Ellipsis.IsValid() || len(smCall.Args) != 2 {
		return "", fmt.Errorf("os: SameFile final return does not call sameFile")
	}
	_, okSMFun := isIdentNamed(smCall.Fun, "sameFile")
	_, c01 := isIdentNamed(smCall.Args[0], fs1)
	_, c12 := isIdentNamed(smCall.Args[1], fs2)
	_, c02 := isIdentNamed(smCall.Args[0], fs2)
	_, c11 := isIdentNamed(smCall.Args[1], fs1)
	if !okSMFun || !((c01 && c12) || (c02 && c11)) {
		return "", fmt.Errorf("os: SameFile does not delegate to sameFile(%s, %s)", fs1, fs2)
	}

	// Verify platform sameFile(fs1, fs2 *fileStat) bool compares corresponding fields across both arguments.
	sm := allTopFuncs["sameFile"]
	if sm == nil || sm.Body == nil || sm.Type == nil || sm.Type.TypeParams != nil || !funcHasUnnamedResults(sm.Type, 1) || pkgDeclCounts["sameFile"] != 1 || osAnyLinknameLocals["sameFile"] || funcShadowsAnyIdent(sm, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(sm.Body) || len(sm.Body.List) == 0 {
		return "", fmt.Errorf("os: invalid sameFile implementation")
	}
	if _, okBool := isIdentNamed(sm.Type.Results.List[0].Type, "bool"); !okBool {
		return "", fmt.Errorf("os: sameFile does not return bool")
	}
	smParams := paramNamesFlat(sm.Type.Params)
	if len(smParams) != 2 || smParams[0] == "" || smParams[0] == "_" || smParams[1] == "" || smParams[1] == "_" || smParams[0] == smParams[1] || bodyMutatesOrTakesAddrOfAny(sm.Body, map[string]bool{smParams[0]: true, smParams[1]: true}) {
		return "", fmt.Errorf("os: sameFile invalid parameters")
	}
	for _, fld := range sm.Type.Params.List {
		star, okS := unwrapParens(fld.Type).(*ast.StarExpr)
		if !okS {
			return "", fmt.Errorf("os: sameFile parameter is not *fileStat")
		}
		if _, okFS := isIdentNamed(star.X, "fileStat"); !okFS {
			return "", fmt.Errorf("os: sameFile parameter is not *fileStat")
		}
	}

	side0 := map[string]bool{smParams[0]: true}
	side1 := map[string]bool{smParams[1]: true}
	errVars := map[string]bool{}
	for _, st := range sm.Body.List[:len(sm.Body.List)-1] {
		switch s := st.(type) {
		case *ast.AssignStmt:
			if len(s.Lhs) != 1 || len(s.Rhs) != 1 {
				return "", fmt.Errorf("os: sameFile unexpected assignment")
			}
			lhsID, okL := unwrapParens(s.Lhs[0]).(*ast.Ident)
			if !okL || lhsID.Name == "" || lhsID.Name == "_" || side0[lhsID.Name] || side1[lhsID.Name] {
				return "", fmt.Errorf("os: sameFile invalid local assignment")
			}
			if ta, okTA := unwrapParens(s.Rhs[0]).(*ast.TypeAssertExpr); okTA && s.Tok == token.DEFINE && ta.Type != nil {
				sel, okSel := unwrapParens(ta.X).(*ast.SelectorExpr)
				if !okSel {
					return "", fmt.Errorf("os: sameFile invalid type assertion target")
				}
				bID, okB := unwrapParens(sel.X).(*ast.Ident)
				if !okB || (!side0[bID.Name] && !side1[bID.Name]) {
					return "", fmt.Errorf("os: sameFile type assertion not rooted on parameter")
				}
				if side0[bID.Name] {
					side0[lhsID.Name] = true
				} else {
					side1[lhsID.Name] = true
				}
				continue
			}
			if c, okC := unwrapParens(s.Rhs[0]).(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) == 0 {
				if sel, okSel := unwrapParens(c.Fun).(*ast.SelectorExpr); okSel && sel.Sel.Name == "loadFileId" {
					if bID, okB := unwrapParens(sel.X).(*ast.Ident); okB && (bID.Name == smParams[0] || bID.Name == smParams[1]) {
						errVars[lhsID.Name] = true
						continue
					}
				}
			}
			return "", fmt.Errorf("os: sameFile unexpected helper statement")
		case *ast.IfStmt:
			eVar := condChecksNonZeroErr(s.Cond)
			if s.Init != nil || s.Else != nil || !errVars[eVar] || len(s.Body.List) != 1 {
				return "", fmt.Errorf("os: sameFile unexpected guard statement")
			}
			r, okR := s.Body.List[0].(*ast.ReturnStmt)
			if !okR || len(r.Results) != 1 {
				return "", fmt.Errorf("os: sameFile guard does not return false")
			}
			if _, okF := isIdentNamed(r.Results[0], "false"); !okF {
				return "", fmt.Errorf("os: sameFile guard does not return false")
			}
		default:
			return "", fmt.Errorf("os: sameFile unexpected statement before return")
		}
	}

	extractSideFieldChain := func(expr ast.Expr) (int, []string, bool) {
		var fields []string
		cur := unwrapParens(expr)
		for {
			sel, okS := cur.(*ast.SelectorExpr)
			if !okS {
				break
			}
			fields = append(fields, sel.Sel.Name)
			cur = unwrapParens(sel.X)
		}
		if len(fields) == 0 {
			return -1, nil, false
		}
		id, okID := cur.(*ast.Ident)
		if !okID {
			return -1, nil, false
		}
		slices.Reverse(fields)
		if side0[id.Name] {
			return 0, fields, true
		}
		if side1[id.Name] {
			return 1, fields, true
		}
		return -1, nil, false
	}
	var verifyEqConj func(expr ast.Expr) bool
	verifyEqConj = func(expr ast.Expr) bool {
		bin, okB := unwrapParens(expr).(*ast.BinaryExpr)
		if !okB {
			return false
		}
		if bin.Op == token.LAND {
			return verifyEqConj(bin.X) && verifyEqConj(bin.Y)
		}
		if bin.Op != token.EQL {
			return false
		}
		sL, fL, okL := extractSideFieldChain(bin.X)
		sR, fR, okR := extractSideFieldChain(bin.Y)
		return okL && okR && sL != sR && slices.Equal(fL, fR)
	}

	smRet, okSMR := sm.Body.List[len(sm.Body.List)-1].(*ast.ReturnStmt)
	if !okSMR || len(smRet.Results) != 1 || !verifyEqConj(smRet.Results[0]) {
		return "", fmt.Errorf("os: sameFile return does not compare corresponding fields of both fileStat values")
	}
	return disjointAltStruct, nil
}

func verifyOSNologStatHelpers(
	allTopFuncs, allFileMethods, allRawFileMethods, allFileStatMethods map[string]*ast.FuncDecl,
	pkgDeclCounts, fileMethodCounts, rawFileMethodCounts, fileStatMethodCounts map[string]int,
	funcFile map[*ast.FuncDecl]*ast.File,
	fileImportsSyscall map[*ast.File]bool,
	osInactive *osInactiveState,
	osNoFileReserved, osAnyLinknameLocals map[string]bool,
	disjointAltStruct string,
	usedSameFile, usedFstatNolog, usedFileStatInGetwd bool,
	skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool,
) error {
	returnsFileInfoOrStat := func(fn *ast.FuncDecl) bool {
		if fn == nil || fn.Type == nil || fn.Type.Results == nil || len(fn.Type.Results.List) == 0 {
			return false
		}
		t0 := unwrapParens(fn.Type.Results.List[0].Type)
		if _, okFI := isIdentNamed(t0, "FileInfo"); okFI {
			return true
		}
		if star, okS := t0.(*ast.StarExpr); okS {
			if _, okFS := isIdentNamed(star.X, "fileStat"); okFS {
				return true
			}
		}
		return false
	}

	type statWorkItem struct {
		kind string // "top", "file", "raw", "filestat"
		name string
	}
	type statRootSpec struct {
		item       statWorkItem
		needKernel bool
		isFdStat   bool
	}
	roots := []statRootSpec{
		{item: statWorkItem{kind: "top", name: "statNolog"}, needKernel: true},
		{item: statWorkItem{kind: "top", name: "lstatNolog"}, needKernel: true},
	}
	if usedFstatNolog {
		roots = append(roots, statRootSpec{item: statWorkItem{kind: "top", name: "fstatNolog"}, needKernel: true, isFdStat: true})
	}
	if usedFileStatInGetwd {
		roots = append(roots, statRootSpec{item: statWorkItem{kind: "file", name: "Stat"}, needKernel: true, isFdStat: true})
	}
	if usedSameFile && allFileStatMethods["loadFileId"] != nil {
		roots = append(roots, statRootSpec{item: statWorkItem{kind: "filestat", name: "loadFileId"}, needKernel: false})
	}

	lookupStatCallable := func(it statWorkItem) (*ast.FuncDecl, bool) {
		switch it.kind {
		case "top":
			fn := allTopFuncs[it.name]
			if fn == nil || fn.Body == nil || fn.Type == nil || pkgDeclCounts[it.name] != 1 || osAnyLinknameLocals[it.name] {
				return nil, false
			}
			return fn, true
		case "file":
			fn := allFileMethods[it.name]
			if fn == nil || fn.Body == nil || fn.Type == nil || fn.Recv == nil || len(fn.Recv.List) != 1 || fileMethodCounts[it.name] != 1 || osAnyLinknameLocals[it.name] {
				return nil, false
			}
			if _, isPtr := unwrapParens(fn.Recv.List[0].Type).(*ast.StarExpr); !isPtr {
				return nil, false
			}
			return fn, true
		case "raw":
			fn := allRawFileMethods[it.name]
			if fn == nil || fn.Body == nil || fn.Type == nil || fn.Recv == nil || len(fn.Recv.List) != 1 || rawFileMethodCounts[it.name] != 1 || osAnyLinknameLocals[it.name] {
				return nil, false
			}
			if _, isPtr := unwrapParens(fn.Recv.List[0].Type).(*ast.StarExpr); !isPtr {
				return nil, false
			}
			return fn, true
		case "filestat":
			fn := allFileStatMethods[it.name]
			if fn == nil || fn.Body == nil || fn.Type == nil || fn.Recv == nil || len(fn.Recv.List) != 1 || fileStatMethodCounts[it.name] != 1 || osAnyLinknameLocals[it.name] {
				return nil, false
			}
			if _, isPtr := unwrapParens(fn.Recv.List[0].Type).(*ast.StarExpr); !isPtr {
				return nil, false
			}
			return fn, true
		default:
			return nil, false
		}
	}

	usedIgnoringEINTR := false
	for _, rootSpec := range roots {
		rootLabel := rootSpec.item.name
		if rootSpec.item.kind != "top" {
			rootLabel = rootSpec.item.kind + ":" + rootSpec.item.name
		}
		if _, okRoot := lookupStatCallable(rootSpec.item); !okRoot {
			return fmt.Errorf("os: missing or invalid %s helper", rootLabel)
		}
		visited := map[statWorkItem]bool{}
		queue := []statWorkItem{rootSpec.item}
		sawKernelStat := false

		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if visited[cur] {
				continue
			}
			visited[cur] = true
			curLabel := cur.name
			if cur.kind != "top" {
				curLabel = cur.kind + ":" + cur.name
			}
			fn, okFn := lookupStatCallable(cur)
			if !okFn || funcShadowsAnyIdent(fn, map[string]bool{"testlog": true, "syscall": true, "nil": true, "fileStat": true}) {
				return fmt.Errorf("os: invalid %s stat helper %s", rootLabel, curLabel)
			}
			hPos := 0
			for hPos < len(fn.Body.List) && skipInactiveHookIf(fn.Body.List[hPos], fn) {
				hPos++
			}
			stmts := fn.Body.List[hPos:]
			if len(stmts) == 0 {
				return fmt.Errorf("os: %s helper %s has empty body", rootLabel, curLabel)
			}

			type statLocalBinding struct {
				isZeroFileStat bool
				sawFresh       bool
				bad            bool
			}
			identBinding := map[*ast.Ident]*statLocalBinding{}
			topScope := map[string]*statLocalBinding{}
			topSame := map[string]*statLocalBinding{}
			if r := recvVarName(fn); r != "" && r != "_" {
				b := &statLocalBinding{bad: true}
				topScope[r] = b
				topSame[r] = b
			}
			for _, p := range paramNamesFlat(fn.Type.Params) {
				if p != "" && p != "_" {
					b := &statLocalBinding{bad: true}
					topScope[p] = b
					topSame[p] = b
				}
			}
			if fn.Type.Results != nil {
				for _, fld := range fn.Type.Results.List {
					for _, id := range fld.Names {
						if id.Name != "" && id.Name != "_" {
							b := &statLocalBinding{sawFresh: true}
							topScope[id.Name] = b
							topSame[id.Name] = b
							identBinding[id] = b
						}
					}
				}
			}

			fileImports := map[string]bool(nil)
			if osInactive != nil {
				fileImports = osInactive.fileImportNames[funcFile[fn]]
			}

			var helperErr error
			var bindStatExpr func(e ast.Expr, scope map[string]*statLocalBinding)
			var bindStatStmt func(s ast.Stmt, scope, sameBlock map[string]*statLocalBinding)

			bindStatExpr = func(e ast.Expr, scope map[string]*statLocalBinding) {
				if helperErr != nil || e == nil {
					return
				}
				switch x := e.(type) {
				case *ast.Ident:
					if b := scope[x.Name]; b != nil {
						identBinding[x] = b
					}
					return
				case *ast.SelectorExpr:
					bindStatExpr(x.X, scope)
					return
				case *ast.UnaryExpr:
					bindStatExpr(x.X, scope)
					if helperErr == nil && x.Op == token.AND {
						curExpr := unwrapParens(x.X)
						for {
							sel, okS := curExpr.(*ast.SelectorExpr)
							if !okS {
								break
							}
							curExpr = unwrapParens(sel.X)
						}
						if bID, okB := curExpr.(*ast.Ident); okB && identBinding[bID] == nil && pkgDeclCounts[bID.Name] > 0 {
							helperErr = fmt.Errorf("os: %s helper %s takes address of package declaration %s", rootLabel, curLabel, bID.Name)
						}
					}
					return
				case *ast.FuncLit:
					litScope := maps.Clone(scope)
					litSame := map[string]*statLocalBinding{}
					if x.Type != nil {
						if x.Type.Params != nil {
							for _, fld := range x.Type.Params.List {
								bindStatExpr(fld.Type, scope)
							}
						}
						if x.Type.Results != nil {
							for _, fld := range x.Type.Results.List {
								bindStatExpr(fld.Type, scope)
							}
						}
						for _, p := range paramNamesFlat(x.Type.Params) {
							if p != "" && p != "_" {
								b := &statLocalBinding{bad: true}
								litScope[p] = b
								litSame[p] = b
							}
						}
						if x.Type.Results != nil {
							for _, fld := range x.Type.Results.List {
								for _, id := range fld.Names {
									if id.Name != "" && id.Name != "_" {
										b := &statLocalBinding{bad: true}
										litScope[id.Name] = b
										litSame[id.Name] = b
										identBinding[id] = b
									}
								}
							}
						}
					}
					if x.Body != nil {
						for _, st := range x.Body.List {
							bindStatStmt(st, litScope, litSame)
						}
					}
					return
				}
				ast.Inspect(e, func(ch ast.Node) bool {
					if helperErr != nil || ch == nil {
						return false
					}
					if ch == e {
						return true
					}
					if subE, okE := ch.(ast.Expr); okE {
						bindStatExpr(subE, scope)
						return false
					}
					if subS, okS := ch.(ast.Stmt); okS {
						bindStatStmt(subS, scope, map[string]*statLocalBinding{})
						return false
					}
					return true
				})
			}

			bindStatStmt = func(s ast.Stmt, scope, sameBlock map[string]*statLocalBinding) {
				if helperErr != nil || s == nil {
					return
				}
				switch x := s.(type) {
				case *ast.BlockStmt:
					blkScope := maps.Clone(scope)
					blkSame := map[string]*statLocalBinding{}
					for _, st := range x.List {
						bindStatStmt(st, blkScope, blkSame)
					}
				case *ast.LabeledStmt:
					bindStatStmt(x.Stmt, scope, sameBlock)
				case *ast.BranchStmt, *ast.EmptyStmt:
				case *ast.DeclStmt:
					gd, okGD := x.Decl.(*ast.GenDecl)
					if !okGD {
						helperErr = fmt.Errorf("os: %s helper %s has unexpected declaration %T", rootLabel, curLabel, x.Decl)
						return
					}
					for _, spec := range gd.Specs {
						switch sp := spec.(type) {
						case *ast.TypeSpec:
							helperErr = fmt.Errorf("os: %s helper %s declares local type", rootLabel, curLabel)
							return
						case *ast.ValueSpec:
							if sp.Type != nil {
								bindStatExpr(sp.Type, scope)
							}
							for _, val := range sp.Values {
								bindStatExpr(val, scope)
							}
							isFSVal := gd.Tok == token.VAR && sp.Type != nil && len(sp.Values) == 0 && !fileImports["fileStat"]
							if isFSVal {
								_, isFSVal = isIdentNamed(sp.Type, "fileStat")
							}
							for _, id := range sp.Names {
								if id.Name == "" || id.Name == "_" {
									continue
								}
								b := &statLocalBinding{isZeroFileStat: isFSVal}
								identBinding[id] = b
								scope[id.Name] = b
								sameBlock[id.Name] = b
							}
						}
					}
				case *ast.AssignStmt:
					if x.Tok == token.DEFINE {
						for _, rhs := range x.Rhs {
							bindStatExpr(rhs, scope)
						}
						for _, lhs := range x.Lhs {
							if id, okID := unwrapParens(lhs).(*ast.Ident); okID {
								if id.Name == "" || id.Name == "_" {
									continue
								}
								if existing := sameBlock[id.Name]; existing != nil {
									identBinding[id] = existing
								} else {
									b := &statLocalBinding{}
									scope[id.Name] = b
									sameBlock[id.Name] = b
									identBinding[id] = b
								}
							} else {
								bindStatExpr(lhs, scope)
							}
						}
					} else {
						for _, lhs := range x.Lhs {
							bindStatExpr(lhs, scope)
						}
						for _, rhs := range x.Rhs {
							bindStatExpr(rhs, scope)
						}
					}
				case *ast.IfStmt:
					if skipInactiveHookIf(x, fn) {
						return
					}
					ifScope := maps.Clone(scope)
					ifSame := map[string]*statLocalBinding{}
					if x.Init != nil {
						bindStatStmt(x.Init, ifScope, ifSame)
					}
					bindStatExpr(x.Cond, ifScope)
					if x.Body != nil {
						bindStatStmt(x.Body, ifScope, ifSame)
					}
					if x.Else != nil {
						bindStatStmt(x.Else, maps.Clone(ifScope), map[string]*statLocalBinding{})
					}
				case *ast.ForStmt:
					forScope := maps.Clone(scope)
					forSame := map[string]*statLocalBinding{}
					if x.Init != nil {
						bindStatStmt(x.Init, forScope, forSame)
					}
					if x.Cond != nil {
						bindStatExpr(x.Cond, forScope)
					}
					if x.Post != nil {
						bindStatStmt(x.Post, forScope, forSame)
					}
					if x.Body != nil {
						bindStatStmt(x.Body, forScope, forSame)
					}
				case *ast.RangeStmt:
					bindStatExpr(x.X, scope)
					rngScope := maps.Clone(scope)
					rngSame := map[string]*statLocalBinding{}
					if x.Tok == token.DEFINE {
						for _, expr := range []ast.Expr{x.Key, x.Value} {
							if expr == nil {
								continue
							}
							if id, okID := unwrapParens(expr).(*ast.Ident); okID {
								if id.Name != "" && id.Name != "_" {
									b := &statLocalBinding{bad: true}
									rngScope[id.Name] = b
									rngSame[id.Name] = b
									identBinding[id] = b
								}
							} else {
								bindStatExpr(expr, rngScope)
							}
						}
					} else {
						if x.Key != nil {
							bindStatExpr(x.Key, rngScope)
						}
						if x.Value != nil {
							bindStatExpr(x.Value, rngScope)
						}
					}
					if x.Body != nil {
						bindStatStmt(x.Body, rngScope, rngSame)
					}
				case *ast.SwitchStmt:
					swScope := maps.Clone(scope)
					swSame := map[string]*statLocalBinding{}
					if x.Init != nil {
						bindStatStmt(x.Init, swScope, swSame)
					}
					if x.Tag != nil {
						bindStatExpr(x.Tag, swScope)
					}
					if x.Body != nil {
						for _, cs := range x.Body.List {
							if cc, okCC := cs.(*ast.CaseClause); okCC {
								for _, ce := range cc.List {
									bindStatExpr(ce, swScope)
								}
								ccScope := maps.Clone(swScope)
								ccSame := map[string]*statLocalBinding{}
								for _, bodySt := range cc.Body {
									bindStatStmt(bodySt, ccScope, ccSame)
								}
							}
						}
					}
				case *ast.TypeSwitchStmt:
					tsScope := maps.Clone(scope)
					tsSame := map[string]*statLocalBinding{}
					if x.Init != nil {
						bindStatStmt(x.Init, tsScope, tsSame)
					}
					var boundID *ast.Ident
					if as, okA := x.Assign.(*ast.AssignStmt); okA && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
						bindStatExpr(as.Rhs[0], tsScope)
						if id, okID := unwrapParens(as.Lhs[0]).(*ast.Ident); okID && id.Name != "" && id.Name != "_" {
							boundID = id
							identBinding[id] = &statLocalBinding{bad: true}
						}
					} else if x.Assign != nil {
						bindStatStmt(x.Assign, tsScope, tsSame)
					}
					if x.Body != nil {
						for _, cs := range x.Body.List {
							if cc, okCC := cs.(*ast.CaseClause); okCC {
								for _, ce := range cc.List {
									bindStatExpr(ce, tsScope)
								}
								ccScope := maps.Clone(tsScope)
								ccSame := map[string]*statLocalBinding{}
								if boundID != nil {
									b := &statLocalBinding{bad: true}
									ccScope[boundID.Name] = b
									ccSame[boundID.Name] = b
								}
								for _, bodySt := range cc.Body {
									bindStatStmt(bodySt, ccScope, ccSame)
								}
							}
						}
					}
				case *ast.SelectStmt:
					if x.Body != nil {
						for _, cs := range x.Body.List {
							if cm, okCM := cs.(*ast.CommClause); okCM {
								cmScope := maps.Clone(scope)
								cmSame := map[string]*statLocalBinding{}
								if cm.Comm != nil {
									bindStatStmt(cm.Comm, cmScope, cmSame)
								}
								for _, bodySt := range cm.Body {
									bindStatStmt(bodySt, cmScope, cmSame)
								}
							}
						}
					}
				case *ast.ReturnStmt:
					for _, r := range x.Results {
						bindStatExpr(r, scope)
					}
				case *ast.ExprStmt:
					bindStatExpr(x.X, scope)
				case *ast.SendStmt:
					bindStatExpr(x.Chan, scope)
					bindStatExpr(x.Value, scope)
				case *ast.IncDecStmt:
					bindStatExpr(x.X, scope)
				case *ast.GoStmt:
					bindStatExpr(x.Call, scope)
				case *ast.DeferStmt:
					bindStatExpr(x.Call, scope)
				default:
					helperErr = fmt.Errorf("os: %s helper %s has unsupported statement %T", rootLabel, curLabel, s)
				}
			}

			for _, st := range stmts {
				bindStatStmt(st, topScope, topSame)
				if helperErr != nil {
					return helperErr
				}
			}

			// Pass 2a: mark any address-taken non-fileStat local, any whole-value mutation of a zero-init
			// fileStat local, and any inc/dec/range/type-switch assignment target on its lexical binding
			// before evaluating isFreshStatExpr.
			for _, st := range stmts {
				ast.Inspect(st, func(n ast.Node) bool {
					if helperErr != nil || n == nil {
						return false
					}
					if ifs, okI := n.(*ast.IfStmt); okI && skipInactiveHookIf(ifs, fn) {
						return false
					}
					switch x := n.(type) {
					case *ast.UnaryExpr:
						if x.Op == token.AND {
							if directID, okD := unwrapParens(x.X).(*ast.Ident); okD {
								if b := identBinding[directID]; b != nil && !b.isZeroFileStat {
									b.bad = true
								}
							}
						}
					case *ast.AssignStmt:
						for _, lhs := range x.Lhs {
							if _, okStar := unwrapParens(lhs).(*ast.StarExpr); okStar {
								helperErr = fmt.Errorf("os: %s helper %s dereference-assigns pointer target", rootLabel, curLabel)
								return false
							}
							if lID, okID := unwrapParens(lhs).(*ast.Ident); okID {
								if b := identBinding[lID]; b != nil && b.isZeroFileStat {
									b.bad = true
								}
							}
						}
					case *ast.IncDecStmt:
						if _, okStar := unwrapParens(x.X).(*ast.StarExpr); okStar {
							helperErr = fmt.Errorf("os: %s helper %s dereference-mutates pointer target", rootLabel, curLabel)
							return false
						}
						if lID, okID := unwrapParens(x.X).(*ast.Ident); okID {
							if b := identBinding[lID]; b != nil {
								b.bad = true
							}
						}
					case *ast.RangeStmt:
						for _, expr := range []ast.Expr{x.Key, x.Value} {
							if expr != nil {
								if _, okStar := unwrapParens(expr).(*ast.StarExpr); okStar {
									helperErr = fmt.Errorf("os: %s helper %s dereference-assigns pointer target in range", rootLabel, curLabel)
									return false
								}
								if id, okID := unwrapParens(expr).(*ast.Ident); okID {
									if b := identBinding[id]; b != nil {
										b.bad = true
									}
								}
							}
						}
					case *ast.TypeSwitchStmt:
						if as, okA := x.Assign.(*ast.AssignStmt); okA {
							for _, lhs := range as.Lhs {
								if id, okID := unwrapParens(lhs).(*ast.Ident); okID {
									if b := identBinding[id]; b != nil {
										b.bad = true
									}
								}
							}
						}
					}
					return true
				})
				if helperErr != nil {
					return helperErr
				}
			}

			isFreshStatExpr := func(expr ast.Expr) bool {
				expr = unwrapParens(expr)
				if _, okNil := isIdentNamed(expr, "nil"); okNil && !fileImports["nil"] {
					return true
				}
				if u, okU := expr.(*ast.UnaryExpr); okU && u.Op == token.AND {
					if _, tName := compositeWriterLit(expr); tName == "fileStat" && !fileImports["fileStat"] {
						return true
					}
					if vID, okV := unwrapParens(u.X).(*ast.Ident); okV {
						b := identBinding[vID]
						return b != nil && b.isZeroFileStat && !b.bad
					}
					return false
				}
				if c, okC := expr.(*ast.CallExpr); okC && !c.Ellipsis.IsValid() {
					if cID, okID := unwrapParens(c.Fun).(*ast.Ident); okID && !fileImports[cID.Name] && allTopFuncs[cID.Name] != nil && pkgDeclCounts[cID.Name] == 1 && !osAnyLinknameLocals[cID.Name] && returnsFileInfoOrStat(allTopFuncs[cID.Name]) {
						return true
					}
				}
				return false
			}

			enqueueIfNew := func(it statWorkItem) {
				if !visited[it] {
					queue = append(queue, it)
				}
			}

			recordBindFreshness := func(id *ast.Ident, fresh bool) {
				if id == nil || id.Name == "" || id.Name == "_" {
					return
				}
				if b := identBinding[id]; b != nil {
					if fresh {
						b.sawFresh = true
					} else {
						b.bad = true
					}
				}
			}

			// Pass 2b: evaluate all variable initializers/assignments against finalized zero-fileStat
			// bindings, and audit calls and identifier references.
			checkReturns := returnsFileInfoOrStat(fn)
			for _, st := range stmts {
				ast.Inspect(st, func(n ast.Node) bool {
					if helperErr != nil || n == nil {
						return false
					}
					if ifs, okI := n.(*ast.IfStmt); okI && skipInactiveHookIf(ifs, fn) {
						return false
					}
					switch x := n.(type) {
					case *ast.GenDecl:
						for _, spec := range x.Specs {
							vs, okVS := spec.(*ast.ValueSpec)
							if !okVS {
								continue
							}
							if len(vs.Names) == 1 {
								if b := identBinding[vs.Names[0]]; b != nil && b.isZeroFileStat {
									continue
								}
							}
							allZeroFS := len(vs.Names) > 0
							for _, id := range vs.Names {
								if id.Name == "" || id.Name == "_" {
									continue
								}
								if b := identBinding[id]; b == nil || !b.isZeroFileStat {
									allZeroFS = false
									break
								}
							}
							if allZeroFS {
								continue
							}
							if len(vs.Values) == 0 {
								for _, id := range vs.Names {
									recordBindFreshness(id, x.Tok == token.VAR)
								}
							} else if len(vs.Values) == len(vs.Names) {
								for i, id := range vs.Names {
									recordBindFreshness(id, isFreshStatExpr(vs.Values[i]))
								}
							} else if len(vs.Values) == 1 && len(vs.Names) == 2 {
								recordBindFreshness(vs.Names[0], isFreshStatExpr(vs.Values[0]))
								recordBindFreshness(vs.Names[1], false)
							} else {
								for _, id := range vs.Names {
									recordBindFreshness(id, false)
								}
							}
						}
					case *ast.AssignStmt:
						if x.Tok != token.ASSIGN && x.Tok != token.DEFINE {
							for _, lhs := range x.Lhs {
								if lID, okID := unwrapParens(lhs).(*ast.Ident); okID {
									recordBindFreshness(lID, false)
								}
							}
						} else if len(x.Rhs) == 1 && len(x.Lhs) == 2 {
							if l0, ok0 := unwrapParens(x.Lhs[0]).(*ast.Ident); ok0 {
								recordBindFreshness(l0, isFreshStatExpr(x.Rhs[0]))
							}
							if l1, ok1 := unwrapParens(x.Lhs[1]).(*ast.Ident); ok1 {
								recordBindFreshness(l1, false)
							}
						} else if len(x.Lhs) == len(x.Rhs) {
							for i, lhs := range x.Lhs {
								if lID, okID := unwrapParens(lhs).(*ast.Ident); okID {
									recordBindFreshness(lID, isFreshStatExpr(x.Rhs[i]))
								}
							}
						} else {
							for _, lhs := range x.Lhs {
								if lID, okID := unwrapParens(lhs).(*ast.Ident); okID {
									recordBindFreshness(lID, false)
								}
							}
						}
					case *ast.Ident:
						if x.Name == "testlog" {
							helperErr = fmt.Errorf("os: %s helper %s references testlog", rootLabel, curLabel)
							return false
						}
						if disjointAltStruct != "" && x.Name == disjointAltStruct {
							helperErr = fmt.Errorf("os: %s helper %s references alternate FileInfo struct %s", rootLabel, curLabel, disjointAltStruct)
							return false
						}
					case *ast.CallExpr:
						if cID, okID := unwrapParens(x.Fun).(*ast.Ident); okID {
							if identBinding[cID] != nil {
								helperErr = fmt.Errorf("os: %s helper %s calls local variable %s", rootLabel, curLabel, cID.Name)
								return false
							}
							if osAnyLinknameLocals[cID.Name] {
								helperErr = fmt.Errorf("os: %s helper %s calls linknamed %s", rootLabel, curLabel, cID.Name)
								return false
							}
							if cID.Name == "ignoringEINTR" {
								usedIgnoringEINTR = true
							} else if allTopFuncs[cID.Name] != nil {
								enqueueIfNew(statWorkItem{kind: "top", name: cID.Name})
							}
						} else if sel, okS := unwrapParens(x.Fun).(*ast.SelectorExpr); okS {
							if _, okSys := isIdentNamed(sel.X, "syscall"); okSys {
								if rootSpec.isFdStat {
									if sel.Sel.Name == "Fstat" || sel.Sel.Name == "GetFileInformationByHandle" {
										sawKernelStat = true
									}
								} else {
									if sel.Sel.Name == "Stat" || sel.Sel.Name == "Lstat" || sel.Sel.Name == "GetFileAttributesEx" || sel.Sel.Name == "CreateFile" || sel.Sel.Name == "GetFileInformationByHandle" {
										sawKernelStat = true
									}
								}
							} else if rootSpec.isFdStat && sel.Sel.Name == "Fstat" {
								sawKernelStat = true
							}
							isNonImportRecv := false
							if bID, okB := unwrapParens(sel.X).(*ast.Ident); okB && !fileImports[bID.Name] {
								isNonImportRecv = true
							} else if _, okTA := unwrapParens(sel.X).(*ast.TypeAssertExpr); okTA {
								isNonImportRecv = true
							}
							if isNonImportRecv {
								if allFileStatMethods[sel.Sel.Name] != nil {
									enqueueIfNew(statWorkItem{kind: "filestat", name: sel.Sel.Name})
								} else if sel.Sel.Name != "Close" && allFileMethods[sel.Sel.Name] != nil {
									enqueueIfNew(statWorkItem{kind: "file", name: sel.Sel.Name})
								} else if sel.Sel.Name != "close" && allRawFileMethods[sel.Sel.Name] != nil {
									enqueueIfNew(statWorkItem{kind: "raw", name: sel.Sel.Name})
								}
							}
						}
					case *ast.FuncLit:
						// Only permitted as the callback argument of ignoringEINTR(...).
					}
					return true
				})
				if helperErr != nil {
					return helperErr
				}
			}

			if checkReturns {
				for _, st := range stmts {
					ast.Inspect(st, func(n ast.Node) bool {
						if helperErr != nil || n == nil {
							return false
						}
						if _, okFL := n.(*ast.FuncLit); okFL {
							return false
						}
						if ifs, okI := n.(*ast.IfStmt); okI && skipInactiveHookIf(ifs, fn) {
							return false
						}
						ret, okR := n.(*ast.ReturnStmt)
						if !okR {
							return true
						}
						if len(ret.Results) == 0 {
							helperErr = fmt.Errorf("os: %s helper %s has bare return", rootLabel, curLabel)
							return false
						}
						r0 := unwrapParens(ret.Results[0])
						if isFreshStatExpr(r0) {
							return true
						}
						if vID, okV := r0.(*ast.Ident); okV {
							if b := identBinding[vID]; b != nil && b.sawFresh && !b.bad {
								return true
							}
						}
						helperErr = fmt.Errorf("os: %s helper %s returns unverified FileInfo expression", rootLabel, curLabel)
						return false
					})
					if helperErr != nil {
						return helperErr
					}
				}
			}
		}

		if rootSpec.needKernel && !sawKernelStat {
			return fmt.Errorf("os: %s does not reach kernel stat operation", rootLabel)
		}
	}
	if usedIgnoringEINTR && !verifyOSIgnoringEINTR(allTopFuncs["ignoringEINTR"], funcFile, fileImportsSyscall, osNoFileReserved, osAnyLinknameLocals) {
		return fmt.Errorf("os: invalid ignoringEINTR helper used by statNolog")
	}
	return nil
}

type osFalseHelperKey struct {
	name    string
	arity   int
	boolIdx int
}

var osAllowedPureIntConversions = map[string]bool{
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true, "uintptr": true,
}

type osInactiveState struct {
	pkgDeclCounts       map[string]int
	funcFile            map[*ast.FuncDecl]*ast.File
	fileImportNames     map[*ast.File]map[string]bool
	falseConsts         map[string]bool
	trueConsts          map[string]bool
	osGateFuncs         map[string]string
	nilAccessors        map[string][]string
	falsePreds          map[string][]string
	falseHandledHelpers map[osFalseHelperKey][]string
}

func (s *osInactiveState) identShadowedInFunc(fn *ast.FuncDecl, name string) bool {
	if s == nil {
		return true
	}
	if funcShadowsAnyIdent(fn, map[string]bool{name: true}) {
		return true
	}
	if fn != nil && s.fileImportNames[s.funcFile[fn]][name] {
		return true
	}
	return false
}

type osFalseEvalEnv[D any] struct {
	st          *osInactiveState
	zeroDep     func() D
	gateDep     func(rtGate string) D
	falsePred   func(name string) (D, bool)
	nilAccessor func(name string) (D, bool)
	merge       func(a, b D) D
}

func evalOSFalseExpr[D any](env osFalseEvalEnv[D], expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) (D, bool) {
	var zero D
	if env.st == nil {
		return zero, false
	}
	expr = unwrapParens(expr)
	if id, okID := expr.(*ast.Ident); okID {
		if id.Name == "false" && env.st.pkgDeclCounts["false"] == 0 && !env.st.identShadowedInFunc(fn, "false") {
			return env.zeroDep(), true
		}
		if env.st.falseConsts[id.Name] && !env.st.identShadowedInFunc(fn, id.Name) {
			return env.zeroDep(), true
		}
		return zero, false
	}
	if call, okC := expr.(*ast.CallExpr); okC && !call.Ellipsis.IsValid() {
		if cID, okID := unwrapParens(call.Fun).(*ast.Ident); okID && !env.st.identShadowedInFunc(fn, cID.Name) {
			if len(call.Args) == 0 {
				if rtGate, okG := env.st.osGateFuncs[cID.Name]; okG {
					return env.gateDep(rtGate), true
				}
			}
			if len(call.Args) == 1 && env.st.isPureChain(call.Args[0], fn, params) {
				if d, okFP := env.falsePred(cID.Name); okFP {
					return d, true
				}
			}
		}
	}
	if bin, okB := expr.(*ast.BinaryExpr); okB {
		switch bin.Op {
		case token.NEQ:
			checkNilAccCall := func(callSide, nilSide ast.Expr) (D, bool) {
				if _, okNil := isIdentNamed(nilSide, "nil"); !okNil || env.st.pkgDeclCounts["nil"] != 0 || env.st.identShadowedInFunc(fn, "nil") {
					return zero, false
				}
				c, okC := unwrapParens(callSide).(*ast.CallExpr)
				if !okC || c.Ellipsis.IsValid() || len(c.Args) != 1 || !env.st.isPureChain(c.Args[0], fn, params) {
					return zero, false
				}
				cID, okID := unwrapParens(c.Fun).(*ast.Ident)
				if !okID || env.st.identShadowedInFunc(fn, cID.Name) {
					return zero, false
				}
				return env.nilAccessor(cID.Name)
			}
			if d, okL := checkNilAccCall(bin.X, bin.Y); okL {
				return d, true
			}
			if d, okR := checkNilAccCall(bin.Y, bin.X); okR {
				return d, true
			}
		case token.LAND:
			if dL, okL := evalOSFalseExpr(env, bin.X, fn, params); okL {
				return dL, true
			}
			if env.st.isPureGuardExpr(bin.X, fn, params) {
				return evalOSFalseExpr(env, bin.Y, fn, params)
			}
		case token.LOR:
			dL, okL := evalOSFalseExpr(env, bin.X, fn, params)
			if !okL {
				return zero, false
			}
			dR, okR := evalOSFalseExpr(env, bin.Y, fn, params)
			if !okR {
				return zero, false
			}
			return env.merge(dL, dR), true
		}
	}
	return zero, false
}

func discoverOSInactiveState(files []*ast.File, osRuntimePullMap map[string]string, osAnyLinknameLocals map[string]bool) *osInactiveState {
	pkgDeclCounts := map[string]int{}
	funcFile := map[*ast.FuncDecl]*ast.File{}
	fileImportNames := map[*ast.File]map[string]bool{}
	st := &osInactiveState{
		pkgDeclCounts:       pkgDeclCounts,
		funcFile:            funcFile,
		fileImportNames:     fileImportNames,
		falseConsts:         map[string]bool{},
		trueConsts:          map[string]bool{},
		osGateFuncs:         map[string]string{},
		nilAccessors:        map[string][]string{},
		falsePreds:          map[string][]string{},
		falseHandledHelpers: map[osFalseHelperKey][]string{},
	}

	constDeclNames := map[string]bool{}
	falseConstCand := map[string]bool{}
	trueConstCand := map[string]bool{}
	badBoolConst := map[string]bool{}
	topFuncs := map[string]*ast.FuncDecl{}
	fileImportsAtomic := map[*ast.File]bool{}
	fileImportsSync := map[*ast.File]bool{}
	fileImportsRuntime := map[*ast.File]bool{}
	fileImportsUnsafe := map[*ast.File]bool{}
	badSpecialImport := map[*ast.File]map[string]bool{}

	type tableStructCand struct {
		name           string
		spineField     string
		nonSpineFields map[string]bool
		methods        map[string]*ast.FuncDecl
		readNilMethods map[string]bool
		mutatorMethods map[string]bool
		valid          bool
	}
	structSpecs := map[string]*ast.TypeSpec{}
	structFiles := map[string]*ast.File{}

	type tableVarCand struct {
		name       string
		structName string
		declIdent  *ast.Ident
	}
	varCands := map[string]tableVarCand{}

	for _, f := range files {
		fileImportNames[f] = map[string]bool{}
		badSpecialImport[f] = map[string]bool{}
		for _, imp := range f.Imports {
			if imp.Name != nil && imp.Name.Name == "." {
				return st
			}
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return st
			}
			if imp.Name != nil {
				if imp.Name.Name != "_" {
					fileImportNames[f][imp.Name.Name] = true
					badSpecialImport[f][imp.Name.Name] = true
				}
				continue
			}
			base := p
			if slash := strings.LastIndexByte(p, '/'); slash >= 0 {
				base = p[slash+1:]
			}
			fileImportNames[f][base] = true
			switch p {
			case "sync/atomic":
				fileImportsAtomic[f] = true
			case "sync":
				fileImportsSync[f] = true
			case "runtime":
				fileImportsRuntime[f] = true
			case "unsafe":
				fileImportsUnsafe[f] = true
			default:
				if base == "atomic" || base == "sync" || base == "runtime" || base == "unsafe" {
					badSpecialImport[f][base] = true
				}
			}
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.ValueSpec:
						for idx, id := range sp.Names {
							if id.Name == "_" {
								continue
							}
							pkgDeclCounts[id.Name]++
							if d.Tok == token.CONST {
								constDeclNames[id.Name] = true
								if sp.Type == nil && idx < len(sp.Values) {
									if vID, okID := unwrapParens(sp.Values[idx]).(*ast.Ident); okID {
										switch vID.Name {
										case "false":
											if !fileImportNames[f]["false"] {
												falseConstCand[id.Name] = true
											} else {
												badBoolConst[id.Name] = true
											}
										case "true":
											if !fileImportNames[f]["true"] {
												trueConstCand[id.Name] = true
											} else {
												badBoolConst[id.Name] = true
											}
										default:
											badBoolConst[id.Name] = true
										}
									} else {
										badBoolConst[id.Name] = true
									}
								} else {
									badBoolConst[id.Name] = true
								}
							}
							if d.Tok == token.VAR && !ast.IsExported(id.Name) && len(sp.Names) == 1 && len(sp.Values) == 0 && sp.Type != nil {
								if sName := baseTypeIdentName(sp.Type); sName != "" && !ast.IsExported(sName) && !fileImportNames[f][sName] {
									varCands[id.Name] = tableVarCand{name: id.Name, structName: sName, declIdent: id}
								}
							}
						}
					case *ast.TypeSpec:
						if sp.Name != nil && sp.Name.Name != "_" {
							pkgDeclCounts[sp.Name.Name]++
							if !ast.IsExported(sp.Name.Name) && !sp.Assign.IsValid() {
								if _, okST := unwrapParens(sp.Type).(*ast.StructType); okST {
									structSpecs[sp.Name.Name] = sp
									structFiles[sp.Name.Name] = f
								}
							}
						}
					}
				}
			case *ast.FuncDecl:
				funcFile[d] = f
				if d.Recv == nil && d.Name != nil && d.Name.Name != "init" && d.Name.Name != "_" {
					pkgDeclCounts[d.Name.Name]++
					topFuncs[d.Name.Name] = d
				}
			}
		}
	}

	if pkgDeclCounts["false"] == 0 && pkgDeclCounts["true"] == 0 && pkgDeclCounts["bool"] == 0 {
		for name := range falseConstCand {
			if !badBoolConst[name] && !trueConstCand[name] && pkgDeclCounts[name] == 1 && !osAnyLinknameLocals[name] {
				st.falseConsts[name] = true
			}
		}
		for name := range trueConstCand {
			if !badBoolConst[name] && !falseConstCand[name] && pkgDeclCounts[name] == 1 && !osAnyLinknameLocals[name] {
				st.trueConsts[name] = true
			}
		}
	}

	for gName, fn := range topFuncs {
		if ast.IsExported(gName) || pkgDeclCounts[gName] != 1 || fn.Type == nil || fn.Type.TypeParams != nil {
			continue
		}
		if fn.Type.Params != nil && fn.Type.Params.NumFields() != 0 {
			continue
		}
		if !funcHasUnnamedResults(fn.Type, 1) || len(fn.Type.Results.List) != 1 {
			continue
		}
		if _, okBool := isIdentNamed(fn.Type.Results.List[0].Type, "bool"); !okBool || pkgDeclCounts["bool"] != 0 || st.identShadowedInFunc(fn, "bool") {
			continue
		}
		if fn.Body == nil {
			if rtTarget := osRuntimePullMap[gName]; strings.HasPrefix(rtTarget, "runtime.") {
				st.osGateFuncs[gName] = rtTarget
			}
			continue
		}
		if osAnyLinknameLocals[gName] || st.identShadowedInFunc(fn, "false") || bodyHasControlFlowOrRecoverBypass(fn.Body) || len(fn.Body.List) != 1 {
			continue
		}
		if ret, okR := fn.Body.List[0].(*ast.ReturnStmt); okR && len(ret.Results) == 1 {
			if rID, okID := unwrapParens(ret.Results[0]).(*ast.Ident); okID {
				if (rID.Name == "false" && pkgDeclCounts["false"] == 0) || (st.falseConsts[rID.Name] && !st.identShadowedInFunc(fn, rID.Name)) {
					st.osGateFuncs[gName] = ""
				}
			}
		}
	}

	// Discover generic/concrete atomic-spine state tables (e.g. struct holding an unexported atomic.Pointer[...] spine).
	allowedBasicFieldTypes := map[string]bool{
		"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
		"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true, "uintptr": true,
		"bool": true, "string": true, "byte": true,
	}
	isSafeNonSpineFieldType := func(sFile *ast.File, expr ast.Expr) bool {
		switch t := unwrapParens(expr).(type) {
		case *ast.ArrayType, *ast.MapType:
			return true
		case *ast.Ident:
			return allowedBasicFieldTypes[t.Name] && pkgDeclCounts[t.Name] == 0 && !fileImportNames[sFile][t.Name]
		case *ast.SelectorExpr:
			if t.Sel.Name != "Mutex" && t.Sel.Name != "RWMutex" {
				return false
			}
			_, okSync := isIdentNamed(t.X, "sync")
			return okSync && fileImportsSync[sFile] && !badSpecialImport[sFile]["sync"] && pkgDeclCounts["sync"] == 0
		default:
			return false
		}
	}
	tableStructs := map[string]*tableStructCand{}
	for sName, sp := range structSpecs {
		sFile := structFiles[sName]
		if pkgDeclCounts[sName] != 1 || pkgDeclCounts["atomic"] != 0 || !fileImportsAtomic[sFile] || badSpecialImport[sFile]["atomic"] {
			continue
		}
		stType, okST := unwrapParens(sp.Type).(*ast.StructType)
		if !okST || stType.Fields == nil {
			continue
		}
		var spineField string
		nonSpineFields := map[string]bool{}
		badStructField := false
		for _, fld := range stType.Fields.List {
			if len(fld.Names) == 0 {
				badStructField = true
				break
			}
			for _, id := range fld.Names {
				if id.Name == "" || id.Name == "_" || ast.IsExported(id.Name) {
					badStructField = true
					break
				}
			}
			if badStructField {
				break
			}
			isSpineType := false
			if idxExpr, okIdx := unwrapParens(fld.Type).(*ast.IndexExpr); okIdx {
				_, isSpineType = isSelectorBaseField(idxExpr.X, "atomic", "Pointer")
			}
			if isSpineType {
				if len(fld.Names) != 1 || spineField != "" {
					badStructField = true
					break
				}
				spineField = fld.Names[0].Name
			} else {
				if !isSafeNonSpineFieldType(sFile, fld.Type) {
					badStructField = true
					break
				}
				for _, id := range fld.Names {
					nonSpineFields[id.Name] = true
				}
			}
		}
		if badStructField || spineField == "" {
			continue
		}
		cand := &tableStructCand{
			name:           sName,
			spineField:     spineField,
			nonSpineFields: nonSpineFields,
			methods:        map[string]*ast.FuncDecl{},
			readNilMethods: map[string]bool{},
			mutatorMethods: map[string]bool{},
			valid:          true,
		}
		for _, f := range files {
			for _, decl := range f.Decls {
				fn, okF := decl.(*ast.FuncDecl)
				if !okF || fn.Recv == nil || len(fn.Recv.List) != 1 {
					continue
				}
				if recvBaseTypeName(fn.Recv.List[0].Type) != sName {
					continue
				}
				if fileImportNames[f][sName] {
					cand.valid = false
					break
				}
				_, isPtr := unwrapParens(fn.Recv.List[0].Type).(*ast.StarExpr)
				if !isPtr || fn.Body == nil || fn.Name == nil || osAnyLinknameLocals[fn.Name.Name] || cand.nonSpineFields[fn.Name.Name] || fn.Name.Name == spineField {
					cand.valid = false
					break
				}
				if _, dup := cand.methods[fn.Name.Name]; dup {
					cand.valid = false
					break
				}
				cand.methods[fn.Name.Name] = fn
			}
			if !cand.valid {
				break
			}
		}
		if !cand.valid || len(cand.methods) == 0 {
			continue
		}
		// Ensure spineField is accessed exclusively via pointer-receiver methods on sName using atomic Pointer methods,
		// and receiver pointers never escape or take field addresses.
		allowedSpineSels := map[*ast.SelectorExpr]bool{}
		methodCalleeMap := map[string]map[string]bool{}
		for mName, mFn := range cand.methods {
			mRecv := recvVarName(mFn)
			if mRecv == "" || pkgDeclCounts["nil"] != 0 || st.identShadowedInFunc(mFn, "nil") || bodyDeclaresAnyIdent(mFn.Body, map[string]bool{mRecv: true}) {
				cand.valid = false
				break
			}
			if mFn.Type != nil {
				for _, fl := range []*ast.FieldList{mFn.Type.TypeParams, mFn.Type.Params, mFn.Type.Results} {
					if fl == nil {
						continue
					}
					for _, fld := range fl.List {
						for _, id := range fld.Names {
							if id.Name == mRecv {
								cand.valid = false
							}
						}
					}
				}
			}
			if !cand.valid {
				break
			}
			allowedRecvIdents := map[*ast.Ident]bool{}
			methodCalleeMap[mName] = map[string]bool{}
			var mutatesSpine, badSpineUse bool
			ast.Inspect(mFn.Body, func(n ast.Node) bool {
				if badSpineUse || n == nil {
					return false
				}
				if u, okU := n.(*ast.UnaryExpr); okU && u.Op == token.AND {
					ast.Inspect(u.X, func(un ast.Node) bool {
						if id, okID := un.(*ast.Ident); okID && id.Name == mRecv {
							badSpineUse = true
							return false
						}
						return !badSpineUse
					})
					if badSpineUse {
						return false
					}
				}
				if sel, okS := n.(*ast.SelectorExpr); okS && cand.nonSpineFields[sel.Sel.Name] {
					if rID, okR := isIdentNamed(sel.X, mRecv); okR {
						allowedRecvIdents[rID] = true
					}
				}
				call, okC := n.(*ast.CallExpr)
				if !okC || call.Ellipsis.IsValid() {
					return true
				}
				opSel, okOS := unwrapParens(call.Fun).(*ast.SelectorExpr)
				if !okOS {
					return true
				}
				if rID, okRM := isIdentNamed(opSel.X, mRecv); okRM && cand.methods[opSel.Sel.Name] != nil {
					allowedRecvIdents[rID] = true
					methodCalleeMap[mName][opSel.Sel.Name] = true
					return true
				}
				spSel, okSS := unwrapParens(opSel.X).(*ast.SelectorExpr)
				if !okSS || spSel.Sel.Name != spineField {
					return true
				}
				rID, okR := isIdentNamed(spSel.X, mRecv)
				if !okR {
					badSpineUse = true
					return false
				}
				switch opSel.Sel.Name {
				case "Load":
					if len(call.Args) != 0 {
						badSpineUse = true
						return false
					}
					allowedSpineSels[spSel] = true
					allowedRecvIdents[rID] = true
				case "Store", "Swap":
					if len(call.Args) != 1 {
						badSpineUse = true
						return false
					}
					allowedSpineSels[spSel] = true
					allowedRecvIdents[rID] = true
					mutatesSpine = true
				case "CompareAndSwap":
					if len(call.Args) != 2 {
						badSpineUse = true
						return false
					}
					allowedSpineSels[spSel] = true
					allowedRecvIdents[rID] = true
					mutatesSpine = true
				default:
					badSpineUse = true
					return false
				}
				return true
			})
			if !badSpineUse {
				walkNonSelectorPropIdents(mFn.Body, func(id *ast.Ident) {
					if id.Name == mRecv && !allowedRecvIdents[id] {
						badSpineUse = true
					}
				})
			}
			if badSpineUse {
				cand.valid = false
				break
			}
			if mutatesSpine {
				cand.mutatorMethods[mName] = true
				continue
			}
			// Check whether read-only method returns nil immediately when spine.Load() == nil.
			if funcHasUnnamedResults(mFn.Type, 1) && !bodyHasControlFlowOrRecoverBypass(mFn.Body) && len(mFn.Body.List) >= 2 {
				as0, okA := mFn.Body.List[0].(*ast.AssignStmt)
				ifs1, okI := mFn.Body.List[1].(*ast.IfStmt)
				if okA && as0.Tok == token.DEFINE && len(as0.Lhs) == 1 && len(as0.Rhs) == 1 && okI && ifs1.Init == nil && ifs1.Else == nil && len(ifs1.Body.List) == 1 {
					vID, okV := unwrapParens(as0.Lhs[0]).(*ast.Ident)
					if okV && vID.Name != "" && vID.Name != "_" {
						if lCall, okLC := unwrapParens(as0.Rhs[0]).(*ast.CallExpr); okLC && !lCall.Ellipsis.IsValid() && len(lCall.Args) == 0 {
							if lSel, okLS := unwrapParens(lCall.Fun).(*ast.SelectorExpr); okLS && lSel.Sel.Name == "Load" {
								if _, okSP := isSelectorBaseField(lSel.X, mRecv, spineField); okSP {
									leftCond := ifs1.Cond
									for {
										orBin, okOr := unwrapParens(leftCond).(*ast.BinaryExpr)
										if !okOr || orBin.Op != token.LOR {
											break
										}
										leftCond = orBin.X
									}
									if condChecksEqErr(leftCond, vID.Name) {
										if rNil, okRN := ifs1.Body.List[0].(*ast.ReturnStmt); okRN && len(rNil.Results) == 1 {
											if _, okNil := isIdentNamed(rNil.Results[0], "nil"); okNil {
												cand.readNilMethods[mName] = true
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		if !cand.valid {
			continue
		}
		for {
			mProp := false
			for mName, callees := range methodCalleeMap {
				if cand.mutatorMethods[mName] {
					continue
				}
				for callee := range callees {
					if cand.mutatorMethods[callee] {
						cand.mutatorMethods[mName] = true
						delete(cand.readNilMethods, mName)
						mProp = true
						break
					}
				}
			}
			if !mProp {
				break
			}
		}
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				if !cand.valid || n == nil {
					return false
				}
				if sel, okS := n.(*ast.SelectorExpr); okS && sel.Sel.Name == spineField && !allowedSpineSels[sel] {
					cand.valid = false
					return false
				}
				return true
			})
		}
		if cand.valid {
			tableStructs[sName] = cand
		}
	}

	type mutCallSite struct {
		fn   *ast.FuncDecl
		call *ast.CallExpr
	}
	activeTables := map[string]tableVarCand{}
	mutSitesByTable := map[string][]mutCallSite{}
	candAllowedByName := map[string]map[*ast.Ident]bool{}
	candSitesByTable := map[string][]mutCallSite{}
	for vName, vc := range varCands {
		ts := tableStructs[vc.structName]
		if ts == nil || pkgDeclCounts[vName] != 1 || osAnyLinknameLocals[vName] {
			continue
		}
		allowedIdents := map[*ast.Ident]bool{vc.declIdent: true}
		var sites []mutCallSite
		badUse := false
		for _, f := range files {
			if fileImportNames[f][vName] {
				badUse = true
				break
			}
			for _, decl := range f.Decls {
				fn, okF := decl.(*ast.FuncDecl)
				if !okF || fn.Body == nil {
					continue
				}
				if funcShadowsAnyIdent(fn, map[string]bool{vName: true}) {
					badUse = true
					break
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if badUse || n == nil {
						return false
					}
					if u, okU := n.(*ast.UnaryExpr); okU && u.Op == token.AND {
						ast.Inspect(u.X, func(un ast.Node) bool {
							if id, okID := un.(*ast.Ident); okID && id.Name == vName {
								badUse = true
								return false
							}
							return !badUse
						})
						if badUse {
							return false
						}
					}
					if sel, okS := n.(*ast.SelectorExpr); okS && ts.nonSpineFields[sel.Sel.Name] {
						if bID, okID := unwrapParens(sel.X).(*ast.Ident); okID && bID.Name == vName {
							allowedIdents[bID] = true
						}
					}
					call, okC := n.(*ast.CallExpr)
					if !okC || call.Ellipsis.IsValid() {
						return true
					}
					sel, okS := unwrapParens(call.Fun).(*ast.SelectorExpr)
					if !okS {
						return true
					}
					bID, okID := unwrapParens(sel.X).(*ast.Ident)
					if !okID || bID.Name != vName {
						return true
					}
					if ts.methods[sel.Sel.Name] == nil {
						badUse = true
						return false
					}
					if ts.mutatorMethods[sel.Sel.Name] {
						if fn.Recv == nil && fn.Name != nil && fn.Name.Name == "init" {
							badUse = true
							return false
						}
						sites = append(sites, mutCallSite{fn: fn, call: call})
					}
					allowedIdents[bID] = true
					return true
				})
				if badUse {
					break
				}
			}
			if badUse {
				break
			}
		}
		if !badUse {
			candAllowedByName[vName] = allowedIdents
			candSitesByTable[vName] = sites
		}
	}
	leakedTableNames := filterNonSelPropIdentsInSet(files, candAllowedByName)
	for vName := range candAllowedByName {
		if !leakedTableNames[vName] {
			activeTables[vName] = varCands[vName]
			mutSitesByTable[vName] = candSitesByTable[vName]
		}
	}

	pureIndexHelpers := map[string]bool{}
	for hName, fn := range topFuncs {
		if ast.IsExported(hName) || pkgDeclCounts[hName] != 1 || osAnyLinknameLocals[hName] || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || bodyHasControlFlowOrRecoverBypass(fn.Body) {
			continue
		}
		if !funcHasUnnamedResults(fn.Type, 2) || len(fn.Type.Results.List) != 2 {
			continue
		}
		r0ID, okR0 := unwrapParens(fn.Type.Results.List[0].Type).(*ast.Ident)
		_, okR1 := isIdentNamed(fn.Type.Results.List[1].Type, "bool")
		if !okR0 || !okR1 || !osAllowedPureIntConversions[r0ID.Name] || pkgDeclCounts[r0ID.Name] != 0 || st.identShadowedInFunc(fn, r0ID.Name) || pkgDeclCounts["bool"] != 0 || st.identShadowedInFunc(fn, "bool") {
			continue
		}
		hParams := paramNamesFlat(fn.Type.Params)
		if len(hParams) != 1 || hParams[0] == "" || hParams[0] == "_" {
			continue
		}
		hFile := funcFile[fn]

		var isParamFieldChain func(expr ast.Expr) bool
		isParamFieldChain = func(expr ast.Expr) bool {
			switch e := unwrapParens(expr).(type) {
			case *ast.Ident:
				return e.Name == hParams[0]
			case *ast.SelectorExpr:
				return isParamFieldChain(e.X)
			default:
				return false
			}
		}

		var isPureIdxExpr func(expr ast.Expr, scope map[string]bool) bool
		isPureIdxExpr = func(expr ast.Expr, scope map[string]bool) bool {
			if expr == nil {
				return false
			}
			switch x := unwrapParens(expr).(type) {
			case *ast.BasicLit:
				return true
			case *ast.Ident:
				if x.Name == hParams[0] || scope[x.Name] {
					return true
				}
				if x.Name == "true" || x.Name == "false" || x.Name == "nil" {
					return pkgDeclCounts[x.Name] == 0 && !st.identShadowedInFunc(fn, x.Name)
				}
				if constDeclNames[x.Name] && pkgDeclCounts[x.Name] == 1 && !osAnyLinknameLocals[x.Name] && !st.identShadowedInFunc(fn, x.Name) {
					return true
				}
				return false
			case *ast.SelectorExpr:
				return isParamFieldChain(x)
			case *ast.UnaryExpr:
				switch x.Op {
				case token.ADD, token.SUB, token.NOT, token.XOR:
					return isPureIdxExpr(x.X, scope)
				default:
					return false
				}
			case *ast.BinaryExpr:
				switch x.Op {
				case token.ADD, token.SUB, token.MUL, token.QUO, token.REM,
					token.AND, token.OR, token.XOR, token.AND_NOT, token.SHL, token.SHR,
					token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ,
					token.LAND, token.LOR:
					return isPureIdxExpr(x.X, scope) && isPureIdxExpr(x.Y, scope)
				default:
					return false
				}
			case *ast.CallExpr:
				if x.Ellipsis.IsValid() || len(x.Args) != 1 || !isPureIdxExpr(x.Args[0], scope) {
					return false
				}
				if cID, okID := unwrapParens(x.Fun).(*ast.Ident); okID {
					return osAllowedPureIntConversions[cID.Name] && pkgDeclCounts[cID.Name] == 0 && !st.identShadowedInFunc(fn, cID.Name) && !scope[cID.Name] && cID.Name != hParams[0]
				}
				if cSel, okS := unwrapParens(x.Fun).(*ast.SelectorExpr); okS {
					_, okU := isIdentNamed(cSel.X, "unsafe")
					if !okU || (cSel.Sel.Name != "Pointer" && cSel.Sel.Name != "Sizeof" && cSel.Sel.Name != "Alignof") {
						return false
					}
					return fileImportsUnsafe[hFile] && !badSpecialImport[hFile]["unsafe"] && pkgDeclCounts["unsafe"] == 0 && !funcShadowsAnyIdent(fn, map[string]bool{"unsafe": true}) && !scope["unsafe"] && hParams[0] != "unsafe"
				}
				return false
			default:
				return false
			}
		}

		isPureIdxAssign := func(as *ast.AssignStmt, scope map[string]bool) bool {
			if as == nil || len(as.Lhs) == 0 || len(as.Lhs) != len(as.Rhs) {
				return false
			}
			for _, rhs := range as.Rhs {
				if !isPureIdxExpr(rhs, scope) {
					return false
				}
			}
			switch as.Tok {
			case token.DEFINE:
				added := map[string]bool{}
				for _, lhs := range as.Lhs {
					id, okID := unwrapParens(lhs).(*ast.Ident)
					if !okID || id.Name == "" || id.Name == hParams[0] {
						return false
					}
					if id.Name == "_" {
						continue
					}
					if scope[id.Name] || added[id.Name] {
						return false
					}
					added[id.Name] = true
				}
				for name := range added {
					scope[name] = true
				}
				return true
			case token.ASSIGN, token.ADD_ASSIGN, token.SUB_ASSIGN, token.MUL_ASSIGN, token.QUO_ASSIGN, token.REM_ASSIGN,
				token.AND_ASSIGN, token.OR_ASSIGN, token.XOR_ASSIGN, token.SHL_ASSIGN, token.SHR_ASSIGN, token.AND_NOT_ASSIGN:
				for _, lhs := range as.Lhs {
					id, okID := unwrapParens(lhs).(*ast.Ident)
					if !okID || id.Name == "" || id.Name == hParams[0] {
						return false
					}
					if id.Name != "_" && !scope[id.Name] {
						return false
					}
				}
				return true
			default:
				return false
			}
		}

		var isPureIdxBlock func(stmts []ast.Stmt, parentScope map[string]bool) bool
		isPureIdxBlock = func(stmts []ast.Stmt, parentScope map[string]bool) bool {
			scope := maps.Clone(parentScope)
			for _, stmt := range stmts {
				switch s := stmt.(type) {
				case *ast.BlockStmt:
					if !isPureIdxBlock(s.List, scope) {
						return false
					}
				case *ast.ReturnStmt:
					if len(s.Results) != 2 || !isPureIdxExpr(s.Results[0], scope) || !isPureIdxExpr(s.Results[1], scope) {
						return false
					}
				case *ast.IfStmt:
					ifScope := maps.Clone(scope)
					if s.Init != nil {
						initAs, okA := s.Init.(*ast.AssignStmt)
						if !okA || initAs.Tok != token.DEFINE || !isPureIdxAssign(initAs, ifScope) {
							return false
						}
					}
					if !isPureIdxExpr(s.Cond, ifScope) || !isPureIdxBlock(s.Body.List, ifScope) {
						return false
					}
					if s.Else != nil {
						switch el := s.Else.(type) {
						case *ast.BlockStmt:
							if !isPureIdxBlock(el.List, ifScope) {
								return false
							}
						case *ast.IfStmt:
							if !isPureIdxBlock([]ast.Stmt{el}, ifScope) {
								return false
							}
						default:
							return false
						}
					}
				case *ast.DeclStmt:
					gd, okG := s.Decl.(*ast.GenDecl)
					if !okG || (gd.Tok != token.VAR && gd.Tok != token.CONST) {
						return false
					}
					for _, spec := range gd.Specs {
						vs, okV := spec.(*ast.ValueSpec)
						if !okV || len(vs.Names) == 0 || (len(vs.Values) != 0 && len(vs.Values) != len(vs.Names)) {
							return false
						}
						if gd.Tok == token.CONST && len(vs.Values) != len(vs.Names) {
							return false
						}
						if vs.Type != nil {
							tID, okT := unwrapParens(vs.Type).(*ast.Ident)
							if !okT || (!osAllowedPureIntConversions[tID.Name] && tID.Name != "bool") || pkgDeclCounts[tID.Name] != 0 || st.identShadowedInFunc(fn, tID.Name) || scope[tID.Name] || tID.Name == hParams[0] {
								return false
							}
						}
						for _, val := range vs.Values {
							if !isPureIdxExpr(val, scope) {
								return false
							}
						}
						added := map[string]bool{}
						for _, id := range vs.Names {
							if id.Name == "" || id.Name == hParams[0] {
								return false
							}
							if id.Name == "_" {
								continue
							}
							if scope[id.Name] || added[id.Name] {
								return false
							}
							added[id.Name] = true
						}
						for name := range added {
							scope[name] = true
						}
					}
				case *ast.AssignStmt:
					if !isPureIdxAssign(s, scope) {
						return false
					}
				default:
					return false
				}
			}
			return true
		}

		if isPureIdxBlock(fn.Body.List, map[string]bool{}) {
			pureIndexHelpers[hName] = true
		}
	}

	type depPair struct {
		gates map[string]bool
		tabs  map[string]bool
	}
	cloneDep := func(d depPair) depPair {
		out := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
		for g := range d.gates {
			if g != "" {
				out.gates[g] = true
			}
		}
		for t := range d.tabs {
			out.tabs[t] = true
		}
		return out
	}
	mergeDep := func(dst *depPair, src depPair) bool {
		changed := false
		for g := range src.gates {
			if g != "" && !dst.gates[g] {
				dst.gates[g] = true
				changed = true
			}
		}
		for t := range src.tabs {
			if !dst.tabs[t] {
				dst.tabs[t] = true
				changed = true
			}
		}
		return changed
	}

	funcParamSet := func(fn *ast.FuncDecl) map[string]bool {
		out := map[string]bool{}
		if fn == nil {
			return out
		}
		if r := recvVarName(fn); r != "" {
			out[r] = true
		}
		for _, p := range paramNamesFlat(fn.Type.Params) {
			if p != "" && p != "_" {
				out[p] = true
			}
		}
		return out
	}

	type rule3CallSite struct {
		caller *ast.FuncDecl
		call   *ast.CallExpr
	}
	rule3CandFuncs := map[string]*ast.FuncDecl{}
	for fnName, fn := range topFuncs {
		if ast.IsExported(fnName) || pkgDeclCounts[fnName] != 1 || osAnyLinknameLocals[fnName] || fn.Body == nil {
			continue
		}
		shadowedByImport := false
		for _, f := range files {
			if fileImportNames[f][fnName] {
				shadowedByImport = true
				break
			}
		}
		if !shadowedByImport {
			rule3CandFuncs[fnName] = fn
		}
	}
	rule3CallSites := map[string][]rule3CallSite{}
	rule3AllowedIdents := map[string]map[*ast.Ident]bool{}
	for fnName, fn := range rule3CandFuncs {
		rule3AllowedIdents[fnName] = map[*ast.Ident]bool{fn.Name: true}
	}
	if len(rule3CandFuncs) > 0 {
		for _, f := range files {
			for _, decl := range f.Decls {
				caller, okF := decl.(*ast.FuncDecl)
				if !okF || caller.Body == nil {
					continue
				}
				ast.Inspect(caller.Body, func(n ast.Node) bool {
					call, okC := n.(*ast.CallExpr)
					if !okC {
						return true
					}
					cID, okID := unwrapParens(call.Fun).(*ast.Ident)
					if !okID || rule3CandFuncs[cID.Name] == nil {
						return true
					}
					rule3CallSites[cID.Name] = append(rule3CallSites[cID.Name], rule3CallSite{caller: caller, call: call})
					rule3AllowedIdents[cID.Name][cID] = true
					return true
				})
			}
		}
		leakedRule3 := filterNonSelPropIdentsInSet(files, rule3AllowedIdents)
		for fnName := range leakedRule3 {
			delete(rule3CandFuncs, fnName)
			delete(rule3CallSites, fnName)
		}
	}

	// Greatest fixpoint over activeTables: keep only tables whose mutator call sites are all gated/unreachable.
	var finalNilAcc, finalFalsePreds map[string]depPair
	var finalTableGates map[string]map[string]bool
	for {
		nilAcc := map[string]depPair{}
		falsePreds := map[string]depPair{}

		evalEnv := osFalseEvalEnv[depPair]{
			st: st,
			zeroDep: func() depPair {
				return depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
			},
			gateDep: func(rtGate string) depPair {
				d := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
				if rtGate != "" {
					d.gates[rtGate] = true
				}
				return d
			},
			falsePred: func(name string) (depPair, bool) {
				fp, okFP := falsePreds[name]
				if !okFP {
					return depPair{}, false
				}
				return cloneDep(fp), true
			},
			nilAccessor: func(name string) (depPair, bool) {
				na, okNA := nilAcc[name]
				if !okNA {
					return depPair{}, false
				}
				return cloneDep(na), true
			},
			merge: func(a, b depPair) depPair {
				out := cloneDep(a)
				mergeDep(&out, b)
				return out
			},
		}
		evalFalse := func(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) (depPair, bool) {
			return evalOSFalseExpr(evalEnv, expr, fn, params)
		}

		// Inner least fixpoint for nilAcc & falsePreds under current activeTables.
		for {
			innerChanged := false
			for fnName, fn := range topFuncs {
				if ast.IsExported(fnName) || pkgDeclCounts[fnName] != 1 || osAnyLinknameLocals[fnName] || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || bodyHasControlFlowOrRecoverBypass(fn.Body) {
					continue
				}
				pNames := paramNamesFlat(fn.Type.Params)
				if len(pNames) != 1 || pNames[0] == "" || pNames[0] == "_" || !funcHasUnnamedResults(fn.Type, 1) || len(fn.Type.Results.List) != 1 {
					continue
				}
				pSet := map[string]bool{pNames[0]: true}
				if _, isBoolRes := isIdentNamed(fn.Type.Results.List[0].Type, "bool"); isBoolRes {
					if pkgDeclCounts["bool"] != 0 || st.identShadowedInFunc(fn, "bool") {
						continue
					}
					if _, already := falsePreds[fnName]; already || len(fn.Body.List) != 1 || st.identShadowedInFunc(fn, "nil") || st.identShadowedInFunc(fn, "false") || st.identShadowedInFunc(fn, "true") {
						continue
					}
					if ret, okR := fn.Body.List[0].(*ast.ReturnStmt); okR && len(ret.Results) == 1 {
						if d, okF := evalFalse(ret.Results[0], fn, pSet); okF {
							falsePreds[fnName] = d
							innerChanged = true
						}
					}
					continue
				}
				if _, already := nilAcc[fnName]; already || pkgDeclCounts["nil"] != 0 || st.identShadowedInFunc(fn, "nil") || st.identShadowedInFunc(fn, "false") || st.identShadowedInFunc(fn, "true") {
					continue
				}
				fnFile := funcFile[fn]
				var proveBlockReturnsNil func(stmts []ast.Stmt, knownNil map[string]bool, declaredLocals map[string]bool, acc *depPair) bool
				proveBlockReturnsNil = func(stmts []ast.Stmt, knownNil map[string]bool, declaredLocals map[string]bool, acc *depPair) bool {
					for i := 0; i < len(stmts); i++ {
						switch s := stmts[i].(type) {
						case *ast.ReturnStmt:
							if len(s.Results) != 1 {
								return false
							}
							rID, okID := unwrapParens(s.Results[0]).(*ast.Ident)
							return okID && (rID.Name == "nil" || knownNil[rID.Name])
						case *ast.ExprStmt:
							kc, okKC := unwrapParens(s.X).(*ast.CallExpr)
							if !okKC || kc.Ellipsis.IsValid() || len(kc.Args) != 1 || !st.isPureChain(kc.Args[0], fn, pSet) {
								return false
							}
							if _, okKA := isSelectorBaseField(kc.Fun, "runtime", "KeepAlive"); !okKA {
								return false
							}
							if !fileImportsRuntime[fnFile] || badSpecialImport[fnFile]["runtime"] || pkgDeclCounts["runtime"] != 0 || funcShadowsAnyIdent(fn, map[string]bool{"runtime": true}) || declaredLocals["runtime"] {
								return false
							}
						case *ast.AssignStmt:
							if s.Tok == token.DEFINE && len(s.Lhs) == 1 && len(s.Rhs) == 1 {
								vID, okV := unwrapParens(s.Lhs[0]).(*ast.Ident)
								c, okC := unwrapParens(s.Rhs[0]).(*ast.CallExpr)
								if !okV || !okC || vID.Name == "" || vID.Name == "_" || declaredLocals[vID.Name] || c.Ellipsis.IsValid() || len(c.Args) != 1 {
									return false
								}
								if cID, okCID := unwrapParens(c.Fun).(*ast.Ident); okCID && !st.identShadowedInFunc(fn, cID.Name) && !declaredLocals[cID.Name] && st.isPureChain(c.Args[0], fn, pSet) {
									na, okNA := nilAcc[cID.Name]
									if !okNA {
										return false
									}
									mergeDep(acc, na)
									declaredLocals[vID.Name] = true
									knownNil[vID.Name] = true
									continue
								}
							}
							if s.Tok == token.DEFINE && len(s.Lhs) == 2 && len(s.Rhs) == 1 && i+2 < len(stmts) {
								idxID, okI0 := unwrapParens(s.Lhs[0]).(*ast.Ident)
								okVarID, okI1 := unwrapParens(s.Lhs[1]).(*ast.Ident)
								ic, okIC := unwrapParens(s.Rhs[0]).(*ast.CallExpr)
								if !okI0 || !okI1 || !okIC || idxID.Name == "" || idxID.Name == "_" || okVarID.Name == "" || okVarID.Name == "_" || idxID.Name == okVarID.Name || declaredLocals[idxID.Name] || declaredLocals[okVarID.Name] || ic.Ellipsis.IsValid() || len(ic.Args) != 1 || !st.isPureChain(ic.Args[0], fn, pSet) {
									return false
								}
								ihID, okIH := unwrapParens(ic.Fun).(*ast.Ident)
								if !okIH || !pureIndexHelpers[ihID.Name] || st.identShadowedInFunc(fn, ihID.Name) || declaredLocals[ihID.Name] {
									return false
								}
								guardIf, okGI := stmts[i+1].(*ast.IfStmt)
								getAs, okGA := stmts[i+2].(*ast.AssignStmt)
								if !okGI || guardIf.Init != nil || guardIf.Else != nil || len(guardIf.Body.List) != 1 || !okGA || getAs.Tok != token.DEFINE || len(getAs.Lhs) != 1 || len(getAs.Rhs) != 1 {
									return false
								}
								uNot, okUN := unwrapParens(guardIf.Cond).(*ast.UnaryExpr)
								gRet, okGR := guardIf.Body.List[0].(*ast.ReturnStmt)
								if !okUN || uNot.Op != token.NOT || !okGR || len(gRet.Results) != 1 {
									return false
								}
								_, okVarMatch := isIdentNamed(uNot.X, okVarID.Name)
								_, okRetNil := isIdentNamed(gRet.Results[0], "nil")
								if !okVarMatch || !okRetNil {
									return false
								}
								declaredLocals[idxID.Name] = true
								declaredLocals[okVarID.Name] = true
								sVarID, okSV := unwrapParens(getAs.Lhs[0]).(*ast.Ident)
								getCall, okGC := unwrapParens(getAs.Rhs[0]).(*ast.CallExpr)
								if !okSV || sVarID.Name == "" || sVarID.Name == "_" || declaredLocals[sVarID.Name] || !okGC || getCall.Ellipsis.IsValid() || len(getCall.Args) != 1 {
									return false
								}
								_, okIdxArg := isIdentNamed(getCall.Args[0], idxID.Name)
								getSel, okGS := unwrapParens(getCall.Fun).(*ast.SelectorExpr)
								if !okIdxArg || !okGS {
									return false
								}
								tabID, okTID := unwrapParens(getSel.X).(*ast.Ident)
								if !okTID || st.identShadowedInFunc(fn, tabID.Name) || declaredLocals[tabID.Name] {
									return false
								}
								vc, okTab := activeTables[tabID.Name]
								if !okTab || !tableStructs[vc.structName].readNilMethods[getSel.Sel.Name] {
									return false
								}
								acc.tabs[tabID.Name] = true
								declaredLocals[sVarID.Name] = true
								knownNil[sVarID.Name] = true
								i += 2
								continue
							}
							return false
						case *ast.IfStmt:
							if s.Else != nil {
								return false
							}
							if s.Init == nil {
								if d, okF := evalFalse(s.Cond, fn, pSet); okF {
									mergeDep(acc, d)
									continue
								}
								if nzVar := condChecksNonZeroErr(s.Cond); nzVar != "" && knownNil[nzVar] {
									continue
								}
								if condChecksEqErr(s.Cond, pNames[0]) && len(s.Body.List) == 1 {
									if r0, okR0 := s.Body.List[0].(*ast.ReturnStmt); okR0 && len(r0.Results) == 1 {
										if _, okN := isIdentNamed(r0.Results[0], "nil"); okN {
											continue
										}
									}
								}
								for kn := range knownNil {
									if condChecksEqErr(s.Cond, kn) {
										if proveBlockReturnsNil(s.Body.List, maps.Clone(knownNil), maps.Clone(declaredLocals), acc) {
											return true
										}
									}
								}
								return false
							}
							if initAs, okA := s.Init.(*ast.AssignStmt); okA && initAs.Tok == token.DEFINE && len(initAs.Lhs) == 1 && len(initAs.Rhs) == 1 {
								vID, okV := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
								c, okC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
								if okV && okC && vID.Name != "" && vID.Name != "_" && vID.Name != "nil" && condChecksNonZeroErr(s.Cond) == vID.Name && !c.Ellipsis.IsValid() && len(c.Args) == 1 && st.isPureChain(c.Args[0], fn, pSet) {
									if cID, okCID := unwrapParens(c.Fun).(*ast.Ident); okCID && !st.identShadowedInFunc(fn, cID.Name) && !declaredLocals[cID.Name] {
										if na, okNA := nilAcc[cID.Name]; okNA {
											mergeDep(acc, na)
											continue
										}
									}
								}
							}
							return false
						default:
							return false
						}
					}
					return false
				}
				acc := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
				if proveBlockReturnsNil(fn.Body.List, map[string]bool{}, map[string]bool{pNames[0]: true}, &acc) {
					nilAcc[fnName] = acc
					innerChanged = true
				}
			}
			if !innerChanged {
				break
			}
		}

		// Compute dead IfStmt branches & unreachableFuncs across files under (nilAcc, falsePreds).
		deadIfDeps := map[*ast.IfStmt]depPair{}
		for _, f := range files {
			for _, decl := range f.Decls {
				fn, okF := decl.(*ast.FuncDecl)
				if !okF || fn.Body == nil {
					continue
				}
				pSet := funcParamSet(fn)
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					ifs, okI := n.(*ast.IfStmt)
					if !okI {
						return true
					}
					if ifs.Init == nil && ifs.Else == nil && !bodyHasControlFlowOrRecoverBypass(ifs.Body) {
						if d, okF := evalFalse(ifs.Cond, fn, pSet); okF {
							deadIfDeps[ifs] = d
							return false
						}
					}
					return true
				})
			}
		}

		nodeDeadDep := func(fn *ast.FuncDecl, target ast.Node) (depPair, bool) {
			var found bool
			var out depPair
			var walk func(n ast.Node, cur *depPair)
			walk = func(n ast.Node, cur *depPair) {
				if found || n == nil {
					return
				}
				if n == target {
					if cur != nil {
						out = cloneDep(*cur)
						found = true
					}
					return
				}
				if ifs, okI := n.(*ast.IfStmt); okI {
					if d, okD := deadIfDeps[ifs]; okD {
						next := cloneDep(d)
						if cur != nil {
							mergeDep(&next, *cur)
						}
						for _, bs := range ifs.Body.List {
							walk(bs, &next)
						}
						return
					}
				}
				ast.Inspect(n, func(ch ast.Node) bool {
					if ch == n {
						return true
					}
					walk(ch, cur)
					return false
				})
			}
			walk(fn.Body, nil)
			return out, found
		}

		nodeContainsCall := func(root *ast.IfStmt, target *ast.CallExpr) bool {
			if root == nil || target == nil {
				return false
			}
			hit := false
			ast.Inspect(root, func(n ast.Node) bool {
				if n == target {
					hit = true
					return false
				}
				return !hit
			})
			return hit
		}

		unreachableFuncs := map[string]depPair{}
		seedRule1Head := map[string]*ast.IfStmt{}
		// Seed Rule 1: top-level concrete funcs whose first statement is `if !<falseCond> [|| ...] { return ... }`.
		for fnName, fn := range topFuncs {
			if pkgDeclCounts[fnName] != 1 || fn.Body == nil || len(fn.Body.List) == 0 {
				continue
			}
			ifs, okI := fn.Body.List[0].(*ast.IfStmt)
			if !okI || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 || bodyHasControlFlowOrRecoverBypass(ifs.Body) {
				continue
			}
			if _, okRet := ifs.Body.List[0].(*ast.ReturnStmt); !okRet {
				continue
			}
			negTarget := ifs.Cond
			for {
				orBin, okOr := unwrapParens(negTarget).(*ast.BinaryExpr)
				if !okOr || orBin.Op != token.LOR {
					break
				}
				negTarget = orBin.X
			}
			if uNot, okU := unwrapParens(negTarget).(*ast.UnaryExpr); okU && uNot.Op == token.NOT {
				if d, okF := evalFalse(uNot.X, fn, nil); okF {
					unreachableFuncs[fnName] = d
					seedRule1Head[fnName] = ifs
				}
			}
		}

		// Seed/iterate Rule 3: unexported non-linknamed top-level funcs called exclusively from deadIfDeps or unreachableFuncs.
		for {
			uChanged := false
			for fnName := range rule3CandFuncs {
				if _, already := unreachableFuncs[fnName]; already {
					continue
				}
				agg := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
				allCovered := true
				for _, site := range rule3CallSites[fnName] {
					caller := site.caller
					if caller.Recv == nil {
						if callerUnreach, isCallerUnreach := unreachableFuncs[caller.Name.Name]; isCallerUnreach && !nodeContainsCall(seedRule1Head[caller.Name.Name], site.call) {
							mergeDep(&agg, callerUnreach)
							continue
						}
					}
					if dDead, okD := nodeDeadDep(caller, site.call); okD {
						mergeDep(&agg, dDead)
						continue
					}
					allCovered = false
					break
				}
				if allCovered {
					unreachableFuncs[fnName] = agg
					uChanged = true
				}
			}
			if !uChanged {
				break
			}
		}

		evicted := false
		curTableDeps := map[string]depPair{}
		for vName := range activeTables {
			agg := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
			covered := true
			for _, site := range mutSitesByTable[vName] {
				if site.fn.Recv == nil {
					if uDep, okU := unreachableFuncs[site.fn.Name.Name]; okU && !nodeContainsCall(seedRule1Head[site.fn.Name.Name], site.call) {
						mergeDep(&agg, uDep)
						continue
					}
				}
				if dDead, okD := nodeDeadDep(site.fn, site.call); okD {
					mergeDep(&agg, dDead)
					continue
				}
				covered = false
				break
			}
			if !covered {
				delete(activeTables, vName)
				evicted = true
				continue
			}
			curTableDeps[vName] = agg
		}
		if evicted {
			continue
		}

		// Propagate table-to-table dependencies to fixpoint and finalize gate sets.
		for {
			tChanged := false
			for vName, dp := range curTableDeps {
				for depTab := range dp.tabs {
					if other, okO := curTableDeps[depTab]; okO {
						for g := range other.gates {
							if !dp.gates[g] {
								dp.gates[g] = true
								tChanged = true
							}
						}
					}
				}
				curTableDeps[vName] = dp
			}
			if !tChanged {
				break
			}
		}
		finalTableGates = map[string]map[string]bool{}
		for vName, dp := range curTableDeps {
			finalTableGates[vName] = dp.gates
		}
		finalNilAcc = nilAcc
		finalFalsePreds = falsePreds
		break
	}

	resolveDepGates := func(dp depPair) []string {
		merged := map[string]bool{}
		for g := range dp.gates {
			if g != "" {
				merged[g] = true
			}
		}
		for t := range dp.tabs {
			for g := range finalTableGates[t] {
				if g != "" {
					merged[g] = true
				}
			}
		}
		out := sortedKeys(merged)
		if out == nil {
			out = make([]string, 0)
		}
		return out
	}

	for name, dp := range finalNilAcc {
		st.nilAccessors[name] = resolveDepGates(dp)
	}
	for name, dp := range finalFalsePreds {
		st.falsePreds[name] = resolveDepGates(dp)
	}

	// Discover unexported false-handled tuple helpers (e.g. `if ..., handled, ... := h(...); handled`).
	paramsOrResultsShadow := func(fn *ast.FuncDecl, names map[string]bool) bool {
		if fn == nil || fn.Type == nil {
			return false
		}
		for _, fl := range []*ast.FieldList{fn.Recv, fn.Type.TypeParams, fn.Type.Params, fn.Type.Results} {
			if fl == nil {
				continue
			}
			for _, fld := range fl.List {
				for _, id := range fld.Names {
					if names[id.Name] {
						return true
					}
				}
			}
		}
		return false
	}
	identShadowedAtHead := func(fn *ast.FuncDecl, name string) bool {
		return paramsOrResultsShadow(fn, map[string]bool{name: true}) || fileImportNames[funcFile[fn]][name]
	}
	isPureZeroResult := func(fn *ast.FuncDecl, expr ast.Expr) bool {
		expr = unwrapParens(expr)
		if id, okID := expr.(*ast.Ident); okID {
			if (id.Name == "nil" || id.Name == "false") && pkgDeclCounts[id.Name] == 0 && !identShadowedAtHead(fn, id.Name) {
				return true
			}
			if st.falseConsts[id.Name] && !identShadowedAtHead(fn, id.Name) {
				return true
			}
			return false
		}
		if isZeroIntLit(expr) {
			return true
		}
		if lit, okL := expr.(*ast.BasicLit); okL && lit.Kind == token.STRING && lit.Value == `""` {
			return true
		}
		return false
	}
	for hName, fn := range topFuncs {
		if ast.IsExported(hName) || pkgDeclCounts[hName] != 1 || osAnyLinknameLocals[hName] || fn.Body == nil || len(fn.Body.List) == 0 || fn.Type == nil || fn.Type.TypeParams != nil || fn.Type.Results == nil {
			continue
		}
		numRes := fn.Type.Results.NumFields()
		if numRes < 2 || pkgDeclCounts["false"] != 0 || pkgDeclCounts["bool"] != 0 || identShadowedAtHead(fn, "false") || identShadowedAtHead(fn, "nil") || identShadowedAtHead(fn, "bool") {
			continue
		}
		checkRetTuple := func(ret *ast.ReturnStmt, gates []string) {
			if len(ret.Results) != numRes {
				return
			}
			for idx, r := range ret.Results {
				rID, okID := unwrapParens(r).(*ast.Ident)
				if !okID || (rID.Name != "false" && (!st.falseConsts[rID.Name] || identShadowedAtHead(fn, rID.Name))) {
					continue
				}
				if _, okBool := isIdentNamed(funcResultFieldTypeAt(fn.Type.Results, idx), "bool"); !okBool {
					continue
				}
				othersZero := true
				for j, other := range ret.Results {
					if j != idx && !isPureZeroResult(fn, other) {
						othersZero = false
						break
					}
				}
				if othersZero {
					st.falseHandledHelpers[osFalseHelperKey{name: hName, arity: len(ret.Results), boolIdx: idx}] = gates
				}
			}
		}
		switch s0 := fn.Body.List[0].(type) {
		case *ast.ReturnStmt:
			checkRetTuple(s0, make([]string, 0))
		case *ast.IfStmt:
			if s0.Init == nil && s0.Else == nil && len(s0.Body.List) == 1 && !bodyHasControlFlowOrRecoverBypass(s0.Body) {
				if ret, okR := s0.Body.List[0].(*ast.ReturnStmt); okR {
					if uNot, okU := unwrapParens(s0.Cond).(*ast.UnaryExpr); okU && uNot.Op == token.NOT {
						if gates, okG := st.evalFalseCond(uNot.X, fn, nil); okG {
							checkRetTuple(ret, gates)
						}
					}
				}
			}
		}
	}

	return st
}

func (s *osInactiveState) isPureChain(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) bool {
	if s == nil {
		return false
	}
	switch x := unwrapParens(expr).(type) {
	case *ast.Ident:
		return params[x.Name]
	case *ast.SelectorExpr:
		return s.isPureChain(x.X, fn, params)
	case *ast.UnaryExpr:
		return x.Op == token.AND && s.isPureChain(x.X, fn, params)
	case *ast.CallExpr:
		if x.Ellipsis.IsValid() || len(x.Args) != 1 {
			return false
		}
		cID, okID := unwrapParens(x.Fun).(*ast.Ident)
		if !okID || !osAllowedPureIntConversions[cID.Name] {
			return false
		}
		if s.pkgDeclCounts[cID.Name] != 0 || s.identShadowedInFunc(fn, cID.Name) {
			return false
		}
		return s.isPureChain(x.Args[0], fn, params)
	default:
		return false
	}
}

func (s *osInactiveState) isPureArg(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) bool {
	if s == nil {
		return false
	}
	if s.isPureChain(expr, fn, params) {
		return true
	}
	switch x := unwrapParens(expr).(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		if x.Name == "true" || x.Name == "false" || x.Name == "nil" {
			return s.pkgDeclCounts[x.Name] == 0 && !s.identShadowedInFunc(fn, x.Name)
		}
		if s.trueConsts[x.Name] || s.falseConsts[x.Name] {
			return !s.identShadowedInFunc(fn, x.Name)
		}
	}
	return false
}

func (s *osInactiveState) isPureGuardExpr(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) bool {
	if s == nil {
		return false
	}
	if s.isPureChain(expr, fn, params) {
		return true
	}
	switch x := unwrapParens(expr).(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		if x.Name == "nil" || x.Name == "true" || x.Name == "false" {
			return s.pkgDeclCounts[x.Name] == 0 && !s.identShadowedInFunc(fn, x.Name)
		}
		if s.trueConsts[x.Name] || s.falseConsts[x.Name] {
			return !s.identShadowedInFunc(fn, x.Name)
		}
	case *ast.UnaryExpr:
		return x.Op == token.NOT && s.isPureGuardExpr(x.X, fn, params)
	case *ast.BinaryExpr:
		switch x.Op {
		case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ, token.LAND, token.LOR:
			return s.isPureGuardExpr(x.X, fn, params) && s.isPureGuardExpr(x.Y, fn, params)
		}
	}
	return false
}

func (s *osInactiveState) evalFalseCond(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) ([]string, bool) {
	if s == nil {
		return nil, false
	}
	env := osFalseEvalEnv[[]string]{
		st: s,
		zeroDep: func() []string {
			return make([]string, 0)
		},
		gateDep: func(rtGate string) []string {
			if rtGate == "" {
				return make([]string, 0)
			}
			return []string{rtGate}
		},
		falsePred: func(name string) ([]string, bool) {
			gates, okFP := s.falsePreds[name]
			if !okFP {
				return nil, false
			}
			return slices.Clone(gates), true
		},
		nilAccessor: func(name string) ([]string, bool) {
			gates, okNA := s.nilAccessors[name]
			if !okNA {
				return nil, false
			}
			return slices.Clone(gates), true
		},
		merge: func(gL, gR []string) []string {
			merged := map[string]bool{}
			for _, g := range gL {
				merged[g] = true
			}
			for _, g := range gR {
				merged[g] = true
			}
			out := sortedKeys(merged)
			if out == nil {
				out = make([]string, 0)
			}
			return out
		},
	}
	return evalOSFalseExpr(env, expr, fn, params)
}

func (s *osInactiveState) checkInactiveHookIf(stmt ast.Stmt, fn *ast.FuncDecl) ([]string, bool) {
	if s == nil || fn == nil {
		return nil, false
	}
	ifs, ok := stmt.(*ast.IfStmt)
	if !ok || ifs.Else != nil {
		return nil, false
	}
	params := map[string]bool{}
	if r := recvVarName(fn); r != "" {
		params[r] = true
	}
	for _, p := range paramNamesFlat(fn.Type.Params) {
		if p != "" && p != "_" {
			params[p] = true
		}
	}
	checkInitHook := func(inner *ast.IfStmt) ([]string, bool) {
		initAs, okA := inner.Init.(*ast.AssignStmt)
		if !okA || initAs.Tok != token.DEFINE || len(initAs.Rhs) != 1 {
			return nil, false
		}
		call, okC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
		if !okC || call.Ellipsis.IsValid() {
			return nil, false
		}
		calleeID, okFun := unwrapParens(call.Fun).(*ast.Ident)
		if !okFun || s.identShadowedInFunc(fn, calleeID.Name) {
			return nil, false
		}
		for _, arg := range call.Args {
			if !s.isPureArg(arg, fn, params) {
				return nil, false
			}
		}
		if len(initAs.Lhs) == 1 && len(call.Args) == 1 {
			vID, okV := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
			if !okV || vID.Name == "" || vID.Name == "_" || vID.Name == "nil" || s.pkgDeclCounts["nil"] != 0 || s.identShadowedInFunc(fn, "nil") || condChecksNonZeroErr(inner.Cond) != vID.Name {
				return nil, false
			}
			if gates, okNA := s.nilAccessors[calleeID.Name]; okNA {
				return slices.Clone(gates), true
			}
			return nil, false
		}
		if len(initAs.Lhs) >= 2 {
			cID, okCond := unwrapParens(inner.Cond).(*ast.Ident)
			if !okCond || cID.Name == "" || cID.Name == "_" {
				return nil, false
			}
			boolIdx := -1
			for idx, lhs := range initAs.Lhs {
				lID, okL := unwrapParens(lhs).(*ast.Ident)
				if !okL || lID.Name == "" {
					return nil, false
				}
				if lID.Name == cID.Name {
					if boolIdx >= 0 {
						return nil, false
					}
					boolIdx = idx
				}
			}
			if boolIdx >= 0 {
				if gates, okH := s.falseHandledHelpers[osFalseHelperKey{name: calleeID.Name, arity: len(initAs.Lhs), boolIdx: boolIdx}]; okH {
					return slices.Clone(gates), true
				}
			}
		}
		return nil, false
	}
	if ifs.Init != nil {
		return checkInitHook(ifs)
	}
	if gates, okF := s.evalFalseCond(ifs.Cond, fn, params); okF {
		return gates, true
	}
	condID, okCID := unwrapParens(ifs.Cond).(*ast.Ident)
	if !okCID || (!s.trueConsts[condID.Name] && !(condID.Name == "true" && s.pkgDeclCounts["true"] == 0)) || s.identShadowedInFunc(fn, condID.Name) || len(ifs.Body.List) != 1 {
		return nil, false
	}
	inner, okIn := ifs.Body.List[0].(*ast.IfStmt)
	if !okIn || inner.Else != nil {
		return nil, false
	}
	if inner.Init == nil {
		return s.evalFalseCond(inner.Cond, fn, params)
	}
	return checkInitHook(inner)
}


func verifyBufioWriterAST(files []*ast.File) error {
	reserved := map[string]bool{
		"io": true, "copy": true, "len": true, "make": true,
		"byte": true, "int": true, "string": true, "error": true,
		"nil": true, "true": true, "false": true,
	}
	idx, err := indexPackageAST("bufio", files, reserved, map[string]bool{"io": true})
	if err != nil {
		return err
	}
	ws := idx.uniqueTypeSpec("Writer")
	if ws == nil || len(idx.dupTypeMethods["Writer"]) > 0 || len(idx.dupTopFuncs) > 0 {
		return fmt.Errorf("bufio: missing or duplicate Writer type/methods")
	}
	constPosInt := idx.constPosInt
	topFuncs := idx.topFuncs
	writerMethods := idx.typeMethods["Writer"]
	if writerMethods == nil {
		writerMethods = map[string]*ast.FuncDecl{}
	}
	if ws.Assign.IsValid() || ws.TypeParams != nil {
		return fmt.Errorf("bufio: invalid Writer type declaration")
	}
	wst, ok := unwrapParens(ws.Type).(*ast.StructType)
	if !ok || wst.Fields == nil {
		return fmt.Errorf("bufio: Writer is not a struct")
	}
	fieldTypes := map[string]ast.Expr{}
	for _, fld := range wst.Fields.List {
		if len(fld.Names) == 0 {
			return fmt.Errorf("bufio: embedded field on Writer")
		}
		for _, id := range fld.Names {
			fieldTypes[id.Name] = fld.Type
		}
	}
	if len(fieldTypes) != 4 {
		return fmt.Errorf("bufio: unexpected Writer field set")
	}
	if _, ok := isIdentNamed(fieldTypes["err"], "error"); !ok {
		return fmt.Errorf("bufio: Writer.err is not error")
	}
	if !isByteSliceType(fieldTypes["buf"]) {
		return fmt.Errorf("bufio: Writer.buf is not []byte")
	}
	if _, ok := isIdentNamed(fieldTypes["n"], "int"); !ok {
		return fmt.Errorf("bufio: Writer.n is not int")
	}
	if _, ok := isSelectorBaseField(fieldTypes["wr"], "io", "Writer"); !ok {
		return fmt.Errorf("bufio: Writer.wr is not io.Writer")
	}

	// Verify NewWriter and NewWriterSize construct a Writer bound to w with positive buffer capacity.
	nw := topFuncs["NewWriter"]
	nws := topFuncs["NewWriterSize"]
	if nw == nil || nw.Body == nil || nws == nil || nws.Body == nil || funcShadowsAnyIdent(nw, reserved) || funcShadowsAnyIdent(nws, reserved) {
		return fmt.Errorf("bufio: missing NewWriter or NewWriterSize")
	}
	nwParams := paramNamesFlat(nw.Type.Params)
	if len(nwParams) != 1 || nwParams[0] == "" || nwParams[0] == "_" || len(nw.Body.List) != 1 {
		return fmt.Errorf("bufio: unexpected NewWriter shape")
	}
	nwRet, ok := nw.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(nwRet.Results) != 1 {
		return fmt.Errorf("bufio: unexpected NewWriter return")
	}
	nwCall, ok := unwrapParens(nwRet.Results[0]).(*ast.CallExpr)
	if !ok || nwCall.Ellipsis.IsValid() || len(nwCall.Args) != 2 {
		return fmt.Errorf("bufio: unexpected NewWriter delegation")
	}
	if _, ok := isIdentNamed(nwCall.Fun, "NewWriterSize"); !ok {
		return fmt.Errorf("bufio: NewWriter does not call NewWriterSize")
	}
	if _, ok := isIdentNamed(nwCall.Args[0], nwParams[0]); !ok {
		return fmt.Errorf("bufio: NewWriter does not forward w")
	}
	if !isPositiveIntLit(nwCall.Args[1]) {
		if cID, ok := unwrapParens(nwCall.Args[1]).(*ast.Ident); !ok || !constPosInt[cID.Name] {
			return fmt.Errorf("bufio: NewWriter size argument is not a positive constant")
		}
	}

	nwsParams := paramNamesFlat(nws.Type.Params)
	if len(nwsParams) != 2 || nwsParams[0] == "" || nwsParams[0] == "_" || nwsParams[1] == "" || nwsParams[1] == "_" || len(nws.Body.List) < 2 {
		return fmt.Errorf("bufio: unexpected NewWriterSize shape")
	}
	wParam, sizeParam := nwsParams[0], nwsParams[1]
	if bodyMutatesOrTakesAddrOfAny(nws.Body, map[string]bool{wParam: true}) {
		return fmt.Errorf("bufio: NewWriterSize mutates w")
	}
	nwsPos := 0
	if len(nws.Body.List) == 4 {
		// Optional pass-through: b, ok := w.(*Writer); if ok && len(b.buf) >= size { return b }
		taAssign, ok1 := nws.Body.List[0].(*ast.AssignStmt)
		taIf, ok2 := nws.Body.List[1].(*ast.IfStmt)
		if !ok1 || !ok2 || taAssign.Tok != token.DEFINE || len(taAssign.Lhs) != 2 || len(taAssign.Rhs) != 1 || taIf.Init != nil || taIf.Else != nil || len(taIf.Body.List) != 1 {
			return fmt.Errorf("bufio: NewWriterSize invalid Writer pass-through")
		}
		bID, okB := unwrapParens(taAssign.Lhs[0]).(*ast.Ident)
		okID, okOK := unwrapParens(taAssign.Lhs[1]).(*ast.Ident)
		ta, okTA := unwrapParens(taAssign.Rhs[0]).(*ast.TypeAssertExpr)
		if !okB || !okOK || !okTA || bID.Name == "" || bID.Name == "_" || okID.Name == "" || okID.Name == "_" || ta.Type == nil {
			return fmt.Errorf("bufio: NewWriterSize invalid Writer type assertion")
		}
		if _, ok := isIdentNamed(ta.X, wParam); !ok {
			return fmt.Errorf("bufio: NewWriterSize type assertion not on w")
		}
		starW, ok := unwrapParens(ta.Type).(*ast.StarExpr)
		if !ok {
			return fmt.Errorf("bufio: NewWriterSize type assertion not *Writer")
		}
		if _, ok := isIdentNamed(starW.X, "Writer"); !ok {
			return fmt.Errorf("bufio: NewWriterSize type assertion target not Writer")
		}
		andCond, ok := unwrapParens(taIf.Cond).(*ast.BinaryExpr)
		if !ok || andCond.Op != token.LAND {
			return fmt.Errorf("bufio: NewWriterSize pass-through condition not &&")
		}
		if _, ok := isIdentNamed(andCond.X, okID.Name); !ok {
			return fmt.Errorf("bufio: NewWriterSize pass-through LHS not ok")
		}
		geqCond, ok := unwrapParens(andCond.Y).(*ast.BinaryExpr)
		if !ok || geqCond.Op != token.GEQ {
			return fmt.Errorf("bufio: NewWriterSize pass-through capacity check not >=")
		}
		lenCall, ok := unwrapParens(geqCond.X).(*ast.CallExpr)
		if !ok || lenCall.Ellipsis.IsValid() || len(lenCall.Args) != 1 {
			return fmt.Errorf("bufio: NewWriterSize pass-through missing len(b.buf)")
		}
		if _, ok := isIdentNamed(lenCall.Fun, "len"); !ok {
			return fmt.Errorf("bufio: NewWriterSize pass-through not calling len")
		}
		if _, ok := isSelectorBaseField(lenCall.Args[0], bID.Name, "buf"); !ok {
			return fmt.Errorf("bufio: NewWriterSize pass-through len arg not b.buf")
		}
		if _, ok := isIdentNamed(geqCond.Y, sizeParam); !ok {
			return fmt.Errorf("bufio: NewWriterSize pass-through RHS not size")
		}
		ptRet, ok := taIf.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ptRet.Results) != 1 {
			return fmt.Errorf("bufio: NewWriterSize pass-through invalid return")
		}
		if _, ok := isIdentNamed(ptRet.Results[0], bID.Name); !ok {
			return fmt.Errorf("bufio: NewWriterSize pass-through does not return b")
		}
		nwsPos = 2
	} else if len(nws.Body.List) != 2 {
		return fmt.Errorf("bufio: NewWriterSize unexpected statement count")
	}
	// Mandatory size clamp: if size <= 0 { size = <posConstOrLit> }
	if sizeIf, ok := nws.Body.List[nwsPos].(*ast.IfStmt); !ok || sizeIf.Init != nil || sizeIf.Else != nil || len(sizeIf.Body.List) != 1 {
		return fmt.Errorf("bufio: NewWriterSize missing size <= 0 clamp")
	} else {
		leCond, ok := unwrapParens(sizeIf.Cond).(*ast.BinaryExpr)
		if !ok || leCond.Op != token.LEQ || !isZeroIntLit(leCond.Y) {
			return fmt.Errorf("bufio: NewWriterSize size clamp condition invalid")
		}
		if _, ok := isIdentNamed(leCond.X, sizeParam); !ok {
			return fmt.Errorf("bufio: NewWriterSize size clamp LHS not size")
		}
		clampAs, ok := sizeIf.Body.List[0].(*ast.AssignStmt)
		if !ok || clampAs.Tok != token.ASSIGN || len(clampAs.Lhs) != 1 || len(clampAs.Rhs) != 1 {
			return fmt.Errorf("bufio: NewWriterSize size clamp assignment invalid")
		}
		if _, ok := isIdentNamed(clampAs.Lhs[0], sizeParam); !ok {
			return fmt.Errorf("bufio: NewWriterSize size clamp target not size")
		}
		if !isPositiveIntLit(clampAs.Rhs[0]) {
			if cID, ok := unwrapParens(clampAs.Rhs[0]).(*ast.Ident); !ok || !constPosInt[cID.Name] {
				return fmt.Errorf("bufio: NewWriterSize default size is not positive")
			}
		}
	}
	nwsRet, ok := nws.Body.List[nwsPos+1].(*ast.ReturnStmt)
	if !ok || len(nwsRet.Results) != 1 {
		return fmt.Errorf("bufio: NewWriterSize missing final return")
	}
	lit, litName := compositeWriterLit(nwsRet.Results[0])
	if lit == nil || litName != "Writer" || len(lit.Elts) != 2 {
		return fmt.Errorf("bufio: NewWriterSize final return is not &Writer{buf, wr}")
	}
	var sawBufMake, sawWrBind bool
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return fmt.Errorf("bufio: NewWriterSize unkeyed Writer literal")
		}
		kID, ok := unwrapParens(kv.Key).(*ast.Ident)
		if !ok {
			return fmt.Errorf("bufio: NewWriterSize invalid key")
		}
		switch kID.Name {
		case "wr":
			if _, ok := isIdentNamed(kv.Value, wParam); !ok {
				return fmt.Errorf("bufio: NewWriterSize wr does not bind w")
			}
			sawWrBind = true
		case "buf":
			mc, ok := unwrapParens(kv.Value).(*ast.CallExpr)
			if !ok || mc.Ellipsis.IsValid() || len(mc.Args) != 2 || !isByteSliceType(mc.Args[0]) {
				return fmt.Errorf("bufio: NewWriterSize buf is not make([]byte, size)")
			}
			if _, ok := isIdentNamed(mc.Fun, "make"); !ok {
				return fmt.Errorf("bufio: NewWriterSize buf is not make")
			}
			if _, ok := isIdentNamed(mc.Args[1], sizeParam); !ok {
				return fmt.Errorf("bufio: NewWriterSize buf size mismatch")
			}
			sawBufMake = true
		}
	}
	if !sawBufMake || !sawWrBind {
		return fmt.Errorf("bufio: NewWriterSize incomplete Writer initialization")
	}

	// Verify Available() and Buffered().
	availFn := writerMethods["Available"]
	bufdFn := writerMethods["Buffered"]
	if availFn == nil || availFn.Body == nil || len(availFn.Body.List) != 1 || bufdFn == nil || bufdFn.Body == nil || len(bufdFn.Body.List) != 1 {
		return fmt.Errorf("bufio: missing Available or Buffered")
	}
	if avRecv := recvVarName(availFn); avRecv == "" {
		return fmt.Errorf("bufio: unnamed Available receiver")
	} else {
		ret, ok := availFn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return fmt.Errorf("bufio: invalid Available return")
		}
		bin, ok := unwrapParens(ret.Results[0]).(*ast.BinaryExpr)
		if !ok || bin.Op != token.SUB {
			return fmt.Errorf("bufio: Available does not compute len(buf) - n")
		}
		lc, ok := unwrapParens(bin.X).(*ast.CallExpr)
		if !ok || len(lc.Args) != 1 || lc.Ellipsis.IsValid() {
			return fmt.Errorf("bufio: Available invalid len call")
		}
		if _, ok := isIdentNamed(lc.Fun, "len"); !ok {
			return fmt.Errorf("bufio: Available not calling len")
		}
		if _, ok := isSelectorBaseField(lc.Args[0], avRecv, "buf"); !ok {
			return fmt.Errorf("bufio: Available len target not b.buf")
		}
		if _, ok := isSelectorBaseField(bin.Y, avRecv, "n"); !ok {
			return fmt.Errorf("bufio: Available subtrahend not b.n")
		}
	}
	if bfRecv := recvVarName(bufdFn); bfRecv == "" {
		return fmt.Errorf("bufio: unnamed Buffered receiver")
	} else {
		ret, ok := bufdFn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return fmt.Errorf("bufio: invalid Buffered return")
		}
		if _, ok := isSelectorBaseField(ret.Results[0], bfRecv, "n"); !ok {
			return fmt.Errorf("bufio: Buffered does not return b.n")
		}
	}

	// Verify (*Writer).Flush() dereferences receiver without nil guard, writes b.buf[0:b.n] to b.wr,
	// checks short writes, and latches + returns any error.
	flushFn := writerMethods["Flush"]
	if flushFn == nil || flushFn.Body == nil || funcShadowsAnyIdent(flushFn, reserved) || !funcReturnsErrorLast(flushFn.Type) {
		return fmt.Errorf("bufio: missing or invalid (*Writer).Flush")
	}
	fRecv := recvVarName(flushFn)
	if fRecv == "" || len(flushFn.Body.List) != 7 {
		return fmt.Errorf("bufio: (*Writer).Flush has unexpected statement structure")
	}
	// Stmt 0: if b.err != nil { return b.err }
	if s0, ok := flushFn.Body.List[0].(*ast.IfStmt); !ok || s0.Init != nil || s0.Else != nil || len(s0.Body.List) != 1 {
		return fmt.Errorf("bufio: Flush missing sticky error guard")
	} else {
		cond, ok := unwrapParens(s0.Cond).(*ast.BinaryExpr)
		if !ok || cond.Op != token.NEQ {
			return fmt.Errorf("bufio: Flush sticky error guard condition invalid")
		}
		if _, ok1 := isSelectorBaseField(cond.X, fRecv, "err"); !ok1 {
			return fmt.Errorf("bufio: Flush sticky error guard LHS not b.err")
		}
		if _, ok2 := isIdentNamed(cond.Y, "nil"); !ok2 {
			return fmt.Errorf("bufio: Flush sticky error guard RHS not nil")
		}
		ret, ok := s0.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return fmt.Errorf("bufio: Flush sticky error return invalid")
		}
		if _, ok := isSelectorBaseField(ret.Results[0], fRecv, "err"); !ok {
			return fmt.Errorf("bufio: Flush does not return b.err")
		}
	}
	// Stmt 1: if b.n == 0 { return nil }
	if s1, ok := flushFn.Body.List[1].(*ast.IfStmt); !ok || s1.Init != nil || s1.Else != nil || len(s1.Body.List) != 1 {
		return fmt.Errorf("bufio: Flush missing empty-buffer check")
	} else {
		cond, ok := unwrapParens(s1.Cond).(*ast.BinaryExpr)
		if !ok || cond.Op != token.EQL || !isZeroIntLit(cond.Y) {
			return fmt.Errorf("bufio: Flush empty-buffer condition invalid")
		}
		if _, ok := isSelectorBaseField(cond.X, fRecv, "n"); !ok {
			return fmt.Errorf("bufio: Flush empty-buffer LHS not b.n")
		}
		ret, ok := s1.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return fmt.Errorf("bufio: Flush empty-buffer return invalid")
		}
		if _, ok := isIdentNamed(ret.Results[0], "nil"); !ok {
			return fmt.Errorf("bufio: Flush empty-buffer check does not return nil")
		}
	}
	// Stmt 2: n, err := b.wr.Write(b.buf[0:b.n])
	var flushNVar, flushErrVar string
	if s2, ok := flushFn.Body.List[2].(*ast.AssignStmt); !ok || s2.Tok != token.DEFINE || len(s2.Lhs) != 2 || len(s2.Rhs) != 1 {
		return fmt.Errorf("bufio: Flush missing b.wr.Write assignment")
	} else {
		nID, ok1 := unwrapParens(s2.Lhs[0]).(*ast.Ident)
		eID, ok2 := unwrapParens(s2.Lhs[1]).(*ast.Ident)
		wCall, ok3 := unwrapParens(s2.Rhs[0]).(*ast.CallExpr)
		if !ok1 || !ok2 || !ok3 || nID.Name == "" || nID.Name == "_" || eID.Name == "" || eID.Name == "_" || wCall.Ellipsis.IsValid() || len(wCall.Args) != 1 {
			return fmt.Errorf("bufio: Flush invalid b.wr.Write call")
		}
		flushNVar, flushErrVar = nID.Name, eID.Name
		wSel, ok := unwrapParens(wCall.Fun).(*ast.SelectorExpr)
		if !ok || wSel.Sel.Name != "Write" {
			return fmt.Errorf("bufio: Flush does not call Write")
		}
		if _, ok := isSelectorBaseField(wSel.X, fRecv, "wr"); !ok {
			return fmt.Errorf("bufio: Flush Write receiver not b.wr")
		}
		sl, ok := unwrapParens(wCall.Args[0]).(*ast.SliceExpr)
		if !ok || sl.Slice3 || sl.High == nil || (sl.Low != nil && !isZeroIntLit(sl.Low)) {
			return fmt.Errorf("bufio: Flush slice arg not b.buf[0:b.n]")
		}
		if _, ok := isSelectorBaseField(sl.X, fRecv, "buf"); !ok {
			return fmt.Errorf("bufio: Flush slice base not b.buf")
		}
		if _, ok := isSelectorBaseField(sl.High, fRecv, "n"); !ok {
			return fmt.Errorf("bufio: Flush slice high not b.n")
		}
	}
	// Stmt 3: if n < b.n && err == nil { err = io.ErrShortWrite }
	if s3, ok := flushFn.Body.List[3].(*ast.IfStmt); !ok || s3.Init != nil || s3.Else != nil || len(s3.Body.List) != 1 {
		return fmt.Errorf("bufio: Flush missing short-write check")
	} else {
		andExpr, ok := unwrapParens(s3.Cond).(*ast.BinaryExpr)
		if !ok || andExpr.Op != token.LAND || !condChecksEqErr(andExpr.Y, flushErrVar) {
			return fmt.Errorf("bufio: Flush short-write condition invalid")
		}
		ltExpr, ok := unwrapParens(andExpr.X).(*ast.BinaryExpr)
		if !ok || ltExpr.Op != token.LSS {
			return fmt.Errorf("bufio: Flush short-write comparison invalid")
		}
		if _, ok1 := isIdentNamed(ltExpr.X, flushNVar); !ok1 {
			return fmt.Errorf("bufio: Flush short-write LHS not n")
		}
		if _, ok2 := isSelectorBaseField(ltExpr.Y, fRecv, "n"); !ok2 {
			return fmt.Errorf("bufio: Flush short-write RHS not b.n")
		}
		as, ok := s3.Body.List[0].(*ast.AssignStmt)
		if !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return fmt.Errorf("bufio: Flush short-write assignment invalid")
		}
		if _, ok1 := isIdentNamed(as.Lhs[0], flushErrVar); !ok1 {
			return fmt.Errorf("bufio: Flush short-write LHS not err")
		}
		if _, ok2 := isSelectorBaseField(as.Rhs[0], "io", "ErrShortWrite"); !ok2 {
			return fmt.Errorf("bufio: Flush short-write RHS not io.ErrShortWrite")
		}
	}
	// Stmt 4: if err != nil { ...; b.err = err; return err }
	if s4, ok := flushFn.Body.List[4].(*ast.IfStmt); !ok || s4.Init != nil || s4.Else != nil || condChecksNonZeroErr(s4.Cond) != flushErrVar || len(s4.Body.List) < 2 {
		return fmt.Errorf("bufio: Flush missing error return branch")
	} else {
		if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: s4.Body.List[:len(s4.Body.List)-1]}, map[string]bool{flushErrVar: true}) {
			return fmt.Errorf("bufio: Flush mutates err before returning")
		}
		latchStmt, ok1 := s4.Body.List[len(s4.Body.List)-2].(*ast.AssignStmt)
		retStmt, ok2 := s4.Body.List[len(s4.Body.List)-1].(*ast.ReturnStmt)
		if !ok1 || !ok2 || latchStmt.Tok != token.ASSIGN || len(latchStmt.Lhs) != 1 || len(latchStmt.Rhs) != 1 || len(retStmt.Results) != 1 {
			return fmt.Errorf("bufio: Flush error branch missing b.err = err; return err")
		}
		if _, ok := isSelectorBaseField(latchStmt.Lhs[0], fRecv, "err"); !ok {
			return fmt.Errorf("bufio: Flush does not latch b.err")
		}
		if _, ok := isIdentNamed(latchStmt.Rhs[0], flushErrVar); !ok {
			return fmt.Errorf("bufio: Flush latches wrong error")
		}
		if _, ok := isIdentNamed(retStmt.Results[0], flushErrVar); !ok {
			return fmt.Errorf("bufio: Flush returns wrong error")
		}
	}
	// Stmt 5 & 6: b.n = 0; return nil
	if s5, ok := flushFn.Body.List[5].(*ast.AssignStmt); !ok || s5.Tok != token.ASSIGN || len(s5.Lhs) != 1 || len(s5.Rhs) != 1 || !isZeroIntLit(s5.Rhs[0]) {
		return fmt.Errorf("bufio: Flush missing b.n = 0")
	} else if _, ok := isSelectorBaseField(s5.Lhs[0], fRecv, "n"); !ok {
		return fmt.Errorf("bufio: Flush reset target not b.n")
	}
	if s6, ok := flushFn.Body.List[6].(*ast.ReturnStmt); !ok || len(s6.Results) != 1 {
		return fmt.Errorf("bufio: Flush missing final return nil")
	} else if _, ok := isIdentNamed(s6.Results[0], "nil"); !ok {
		return fmt.Errorf("bufio: Flush final return not nil")
	}

	// Verify (*Writer).WriteByte and (*Writer).WriteString preserve bytes and sticky b.err.
	wbFn := writerMethods["WriteByte"]
	wsFn := writerMethods["WriteString"]
	if wbFn == nil || wbFn.Body == nil || funcShadowsAnyIdent(wbFn, reserved) || wsFn == nil || wsFn.Body == nil || funcShadowsAnyIdent(wsFn, reserved) {
		return fmt.Errorf("bufio: missing WriteByte or WriteString")
	}
	wbRecv := recvVarName(wbFn)
	wbParams := paramNamesFlat(wbFn.Type.Params)
	if wbRecv == "" || len(wbParams) != 1 || wbParams[0] == "" || wbParams[0] == "_" || len(wbFn.Body.List) != 5 {
		return fmt.Errorf("bufio: unexpected WriteByte shape")
	}
	// WriteByte[0]: if b.err != nil { return b.err }
	if wb0, ok := wbFn.Body.List[0].(*ast.IfStmt); !ok || wb0.Init != nil || wb0.Else != nil || len(wb0.Body.List) != 1 {
		return fmt.Errorf("bufio: WriteByte missing sticky b.err guard")
	} else {
		cond, ok := unwrapParens(wb0.Cond).(*ast.BinaryExpr)
		if !ok || cond.Op != token.NEQ {
			return fmt.Errorf("bufio: WriteByte sticky b.err condition invalid")
		}
		if _, ok1 := isSelectorBaseField(cond.X, wbRecv, "err"); !ok1 {
			return fmt.Errorf("bufio: WriteByte sticky guard LHS not b.err")
		}
		if _, ok2 := isIdentNamed(cond.Y, "nil"); !ok2 {
			return fmt.Errorf("bufio: WriteByte sticky guard RHS not nil")
		}
		ret, ok := wb0.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return fmt.Errorf("bufio: WriteByte sticky guard return invalid")
		}
		if _, ok := isSelectorBaseField(ret.Results[0], wbRecv, "err"); !ok {
			return fmt.Errorf("bufio: WriteByte sticky guard does not return b.err")
		}
	}
	// WriteByte[1]: if b.Available() <= 0 && b.Flush() != nil { return b.err }
	if wb1, ok := wbFn.Body.List[1].(*ast.IfStmt); !ok || wb1.Init != nil || wb1.Else != nil || len(wb1.Body.List) != 1 {
		return fmt.Errorf("bufio: WriteByte missing Available/Flush guard")
	} else {
		andC, ok := unwrapParens(wb1.Cond).(*ast.BinaryExpr)
		if !ok || andC.Op != token.LAND {
			return fmt.Errorf("bufio: WriteByte Available/Flush guard not &&")
		}
		leC, ok1 := unwrapParens(andC.X).(*ast.BinaryExpr)
		neqC, ok2 := unwrapParens(andC.Y).(*ast.BinaryExpr)
		if !ok1 || !ok2 || leC.Op != token.LEQ || !isZeroIntLit(leC.Y) || neqC.Op != token.NEQ {
			return fmt.Errorf("bufio: WriteByte Available/Flush comparisons invalid")
		}
		if _, ok := isZeroArgMethodCallOnIdent(leC.X, wbRecv, "Available"); !ok {
			return fmt.Errorf("bufio: WriteByte does not check b.Available() <= 0")
		}
		if _, ok := isZeroArgMethodCallOnIdent(neqC.X, wbRecv, "Flush"); !ok {
			return fmt.Errorf("bufio: WriteByte does not call b.Flush()")
		}
		if _, ok := isIdentNamed(neqC.Y, "nil"); !ok {
			return fmt.Errorf("bufio: WriteByte Flush comparison RHS not nil")
		}
		ret, ok := wb1.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return fmt.Errorf("bufio: WriteByte Flush guard return invalid")
		}
		if _, ok := isSelectorBaseField(ret.Results[0], wbRecv, "err"); !ok {
			return fmt.Errorf("bufio: WriteByte Flush guard does not return b.err")
		}
	}
	if as, ok := wbFn.Body.List[2].(*ast.AssignStmt); !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
		return fmt.Errorf("bufio: WriteByte missing b.buf[b.n] = c")
	} else {
		idx, ok1 := unwrapParens(as.Lhs[0]).(*ast.IndexExpr)
		_, ok2 := isIdentNamed(as.Rhs[0], wbParams[0])
		if !ok1 || !ok2 {
			return fmt.Errorf("bufio: WriteByte assignment mismatch")
		}
		if _, ok := isSelectorBaseField(idx.X, wbRecv, "buf"); !ok {
			return fmt.Errorf("bufio: WriteByte target not b.buf")
		}
		if _, ok := isSelectorBaseField(idx.Index, wbRecv, "n"); !ok {
			return fmt.Errorf("bufio: WriteByte index not b.n")
		}
	}
	if inc, ok := wbFn.Body.List[3].(*ast.IncDecStmt); !ok || inc.Tok != token.INC {
		return fmt.Errorf("bufio: WriteByte missing b.n++")
	} else if _, ok := isSelectorBaseField(inc.X, wbRecv, "n"); !ok {
		return fmt.Errorf("bufio: WriteByte increment target not b.n")
	}
	if wb4, ok := wbFn.Body.List[4].(*ast.ReturnStmt); !ok || len(wb4.Results) != 1 {
		return fmt.Errorf("bufio: WriteByte missing final return nil")
	} else if _, ok := isIdentNamed(wb4.Results[0], "nil"); !ok {
		return fmt.Errorf("bufio: WriteByte final return not nil")
	}

	wsRecv := recvVarName(wsFn)
	wsParams := paramNamesFlat(wsFn.Type.Params)
	if wsRecv == "" || len(wsParams) != 1 || wsParams[0] == "" || wsParams[0] == "_" || len(wsFn.Body.List) != 9 {
		return fmt.Errorf("bufio: unexpected WriteString shape")
	}
	sParam := wsParams[0]
	if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: wsFn.Body.List[4:]}, map[string]bool{sParam: true}) {
		return fmt.Errorf("bufio: WriteString mutates s after loop")
	}
	// Stmt 0: var sw io.StringWriter; Stmt 1: tryStringWriter := true; Stmt 2: nn := 0
	var swVar, trySWVar, nnVar string
	if ds0, ok := wsFn.Body.List[0].(*ast.DeclStmt); !ok {
		return fmt.Errorf("bufio: WriteString missing var sw io.StringWriter")
	} else {
		gd, ok := ds0.Decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR || len(gd.Specs) != 1 {
			return fmt.Errorf("bufio: WriteString invalid sw declaration")
		}
		vs, ok := gd.Specs[0].(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || len(vs.Values) != 0 || vs.Names[0].Name == "" || vs.Names[0].Name == "_" {
			return fmt.Errorf("bufio: WriteString invalid sw ValueSpec")
		}
		if _, ok := isSelectorBaseField(vs.Type, "io", "StringWriter"); !ok {
			return fmt.Errorf("bufio: WriteString sw type not io.StringWriter")
		}
		swVar = vs.Names[0].Name
	}
	if as1, ok := wsFn.Body.List[1].(*ast.AssignStmt); !ok || as1.Tok != token.DEFINE || len(as1.Lhs) != 1 || len(as1.Rhs) != 1 {
		return fmt.Errorf("bufio: WriteString missing tryStringWriter := true")
	} else {
		id, ok1 := unwrapParens(as1.Lhs[0]).(*ast.Ident)
		_, ok2 := isIdentNamed(as1.Rhs[0], "true")
		if !ok1 || !ok2 || id.Name == "" || id.Name == "_" {
			return fmt.Errorf("bufio: WriteString invalid tryStringWriter init")
		}
		trySWVar = id.Name
	}
	if as2, ok := wsFn.Body.List[2].(*ast.AssignStmt); !ok || as2.Tok != token.DEFINE || len(as2.Lhs) != 1 || len(as2.Rhs) != 1 || !isZeroIntLit(as2.Rhs[0]) {
		return fmt.Errorf("bufio: WriteString missing nn := 0")
	} else {
		id, ok := unwrapParens(as2.Lhs[0]).(*ast.Ident)
		if !ok || id.Name == "" || id.Name == "_" {
			return fmt.Errorf("bufio: WriteString invalid nn init")
		}
		nnVar = id.Name
	}
	// Stmt 3: for len(s) > b.Available() && b.err == nil { ... }
	if fs3, ok := wsFn.Body.List[3].(*ast.ForStmt); !ok || fs3.Init != nil || fs3.Post != nil || len(fs3.Body.List) != 5 {
		return fmt.Errorf("bufio: WriteString missing overflow loop")
	} else {
		andC, ok := unwrapParens(fs3.Cond).(*ast.BinaryExpr)
		if !ok || andC.Op != token.LAND {
			return fmt.Errorf("bufio: WriteString loop condition not &&")
		}
		gtC, ok1 := unwrapParens(andC.X).(*ast.BinaryExpr)
		eqC, ok2 := unwrapParens(andC.Y).(*ast.BinaryExpr)
		if !ok1 || !ok2 || gtC.Op != token.GTR || !isLenOfIdentCall(gtC.X, sParam) || eqC.Op != token.EQL {
			return fmt.Errorf("bufio: WriteString loop comparisons invalid")
		}
		if _, ok := isZeroArgMethodCallOnIdent(gtC.Y, wsRecv, "Available"); !ok {
			return fmt.Errorf("bufio: WriteString loop RHS not b.Available()")
		}
		if _, ok := isSelectorBaseField(eqC.X, wsRecv, "err"); !ok {
			return fmt.Errorf("bufio: WriteString loop err check LHS not b.err")
		}
		if _, ok := isIdentNamed(eqC.Y, "nil"); !ok {
			return fmt.Errorf("bufio: WriteString loop err check RHS not nil")
		}
		// Loop[0]: var n int
		var loopNVar string
		if lds0, ok := fs3.Body.List[0].(*ast.DeclStmt); !ok {
			return fmt.Errorf("bufio: WriteString loop missing var n int")
		} else {
			gd, ok := lds0.Decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR || len(gd.Specs) != 1 {
				return fmt.Errorf("bufio: WriteString loop invalid var n int")
			}
			vs, ok := gd.Specs[0].(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 0 || vs.Names[0].Name == "" || vs.Names[0].Name == "_" {
				return fmt.Errorf("bufio: WriteString loop invalid n spec")
			}
			if _, ok := isIdentNamed(vs.Type, "int"); !ok {
				return fmt.Errorf("bufio: WriteString loop n not int")
			}
			loopNVar = vs.Names[0].Name
		}
		// Loop[1]: if b.Buffered() == 0 && sw == nil && tryStringWriter { sw, tryStringWriter = b.wr.(io.StringWriter) }
		if lif1, ok := fs3.Body.List[1].(*ast.IfStmt); !ok || lif1.Init != nil || lif1.Else != nil || len(lif1.Body.List) != 1 {
			return fmt.Errorf("bufio: WriteString loop missing StringWriter probe")
		} else {
			outerAnd, okAnd := unwrapParens(lif1.Cond).(*ast.BinaryExpr)
			if !okAnd || outerAnd.Op != token.LAND {
				return fmt.Errorf("bufio: WriteString StringWriter probe outer condition invalid")
			}
			if _, okTry := isIdentNamed(outerAnd.Y, trySWVar); !okTry {
				return fmt.Errorf("bufio: WriteString StringWriter probe missing tryStringWriter guard")
			}
			innerAnd, okIn := unwrapParens(outerAnd.X).(*ast.BinaryExpr)
			if !okIn || innerAnd.Op != token.LAND {
				return fmt.Errorf("bufio: WriteString StringWriter probe inner condition invalid")
			}
			bufEq, okBE := unwrapParens(innerAnd.X).(*ast.BinaryExpr)
			var okBufCall bool
			if okBE {
				_, okBufCall = isZeroArgMethodCallOnIdent(bufEq.X, wsRecv, "Buffered")
			}
			if !okBE || bufEq.Op != token.EQL || !okBufCall || !isZeroIntLit(bufEq.Y) {
				return fmt.Errorf("bufio: WriteString StringWriter probe missing b.Buffered() == 0 guard")
			}
			swEq, okSE := unwrapParens(innerAnd.Y).(*ast.BinaryExpr)
			if !okSE || swEq.Op != token.EQL {
				return fmt.Errorf("bufio: WriteString StringWriter probe missing sw == nil guard")
			}
			_, okSW := isIdentNamed(swEq.X, swVar)
			_, okNil := isIdentNamed(swEq.Y, "nil")
			if !okSW || !okNil {
				return fmt.Errorf("bufio: WriteString StringWriter probe sw == nil operands invalid")
			}
			as, ok := lif1.Body.List[0].(*ast.AssignStmt)
			if !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 2 || len(as.Rhs) != 1 {
				return fmt.Errorf("bufio: WriteString StringWriter probe assign invalid")
			}
			_, ok1 := isIdentNamed(as.Lhs[0], swVar)
			_, ok2 := isIdentNamed(as.Lhs[1], trySWVar)
			ta, ok3 := unwrapParens(as.Rhs[0]).(*ast.TypeAssertExpr)
			if !ok1 || !ok2 || !ok3 || ta.Type == nil {
				return fmt.Errorf("bufio: WriteString StringWriter type assertion invalid")
			}
			if _, ok := isSelectorBaseField(ta.X, wsRecv, "wr"); !ok {
				return fmt.Errorf("bufio: WriteString StringWriter assertion not on b.wr")
			}
			if _, ok := isSelectorBaseField(ta.Type, "io", "StringWriter"); !ok {
				return fmt.Errorf("bufio: WriteString assertion type not io.StringWriter")
			}
		}
		// Loop[2]: if b.Buffered() == 0 && tryStringWriter { n, b.err = sw.WriteString(s) } else { n = copy(b.buf[b.n:], s); b.n += n; b.Flush() }
		if lif2, ok := fs3.Body.List[2].(*ast.IfStmt); !ok || lif2.Init != nil || lif2.Else == nil || len(lif2.Body.List) != 1 {
			return fmt.Errorf("bufio: WriteString loop missing StringWriter/copy dispatch")
		} else {
			and2, ok := unwrapParens(lif2.Cond).(*ast.BinaryExpr)
			if !ok || and2.Op != token.LAND {
				return fmt.Errorf("bufio: WriteString dispatch cond not &&")
			}
			bufEq, ok1 := unwrapParens(and2.X).(*ast.BinaryExpr)
			_, ok2 := isIdentNamed(and2.Y, trySWVar)
			if !ok1 || !ok2 || bufEq.Op != token.EQL || !isZeroIntLit(bufEq.Y) {
				return fmt.Errorf("bufio: WriteString dispatch Buffered() == 0 cond invalid")
			}
			if _, ok := isZeroArgMethodCallOnIdent(bufEq.X, wsRecv, "Buffered"); !ok {
				return fmt.Errorf("bufio: WriteString dispatch does not check b.Buffered()")
			}
			swAs, ok := lif2.Body.List[0].(*ast.AssignStmt)
			if !ok || swAs.Tok != token.ASSIGN || len(swAs.Lhs) != 2 || len(swAs.Rhs) != 1 {
				return fmt.Errorf("bufio: WriteString sw.WriteString assign invalid")
			}
			_, okN := isIdentNamed(swAs.Lhs[0], loopNVar)
			_, okErr := isSelectorBaseField(swAs.Lhs[1], wsRecv, "err")
			swCall, okC := unwrapParens(swAs.Rhs[0]).(*ast.CallExpr)
			if !okN || !okErr || !okC || swCall.Ellipsis.IsValid() || len(swCall.Args) != 1 {
				return fmt.Errorf("bufio: WriteString sw.WriteString call invalid")
			}
			if _, ok := isSelectorBaseField(swCall.Fun, swVar, "WriteString"); !ok {
				return fmt.Errorf("bufio: WriteString does not call sw.WriteString")
			}
			if _, ok := isIdentNamed(swCall.Args[0], sParam); !ok {
				return fmt.Errorf("bufio: WriteString sw.WriteString arg not s")
			}
			elseBlk, ok := lif2.Else.(*ast.BlockStmt)
			if !ok || len(elseBlk.List) != 3 {
				return fmt.Errorf("bufio: WriteString else branch unexpected shape")
			}
			cpAs, ok1 := elseBlk.List[0].(*ast.AssignStmt)
			addAs, ok2 := elseBlk.List[1].(*ast.AssignStmt)
			flES, ok3 := elseBlk.List[2].(*ast.ExprStmt)
			if !ok1 || !ok2 || !ok3 || cpAs.Tok != token.ASSIGN || len(cpAs.Lhs) != 1 || len(cpAs.Rhs) != 1 || addAs.Tok != token.ADD_ASSIGN || len(addAs.Lhs) != 1 || len(addAs.Rhs) != 1 {
				return fmt.Errorf("bufio: WriteString else copy/add/Flush invalid")
			}
			if _, ok := isIdentNamed(cpAs.Lhs[0], loopNVar); !ok {
				return fmt.Errorf("bufio: WriteString else copy LHS not n")
			}
			cpCall, ok := unwrapParens(cpAs.Rhs[0]).(*ast.CallExpr)
			if !ok || cpCall.Ellipsis.IsValid() || len(cpCall.Args) != 2 {
				return fmt.Errorf("bufio: WriteString else copy call invalid")
			}
			if _, ok := isIdentNamed(cpCall.Fun, "copy"); !ok {
				return fmt.Errorf("bufio: WriteString else call not copy")
			}
			sl, ok := unwrapParens(cpCall.Args[0]).(*ast.SliceExpr)
			if !ok || sl.Slice3 || sl.High != nil || sl.Low == nil {
				return fmt.Errorf("bufio: WriteString else copy dst slice invalid")
			}
			if _, ok1 := isSelectorBaseField(sl.X, wsRecv, "buf"); !ok1 {
				return fmt.Errorf("bufio: WriteString else copy dst not b.buf")
			}
			if _, ok2 := isSelectorBaseField(sl.Low, wsRecv, "n"); !ok2 {
				return fmt.Errorf("bufio: WriteString else copy low not b.n")
			}
			if _, ok := isIdentNamed(cpCall.Args[1], sParam); !ok {
				return fmt.Errorf("bufio: WriteString else copy src not s")
			}
			if _, ok1 := isSelectorBaseField(addAs.Lhs[0], wsRecv, "n"); !ok1 {
				return fmt.Errorf("bufio: WriteString else add LHS not b.n")
			}
			if _, ok2 := isIdentNamed(addAs.Rhs[0], loopNVar); !ok2 {
				return fmt.Errorf("bufio: WriteString else add RHS not n")
			}
			if _, ok := isZeroArgMethodCallOnIdent(flES.X, wsRecv, "Flush"); !ok {
				return fmt.Errorf("bufio: WriteString else missing b.Flush()")
			}
		}
		// Loop[3]: nn += n; Loop[4]: s = s[n:]
		if las3, ok := fs3.Body.List[3].(*ast.AssignStmt); !ok || las3.Tok != token.ADD_ASSIGN || len(las3.Lhs) != 1 || len(las3.Rhs) != 1 {
			return fmt.Errorf("bufio: WriteString loop missing nn += n")
		} else {
			_, ok1 := isIdentNamed(las3.Lhs[0], nnVar)
			_, ok2 := isIdentNamed(las3.Rhs[0], loopNVar)
			if !ok1 || !ok2 {
				return fmt.Errorf("bufio: WriteString loop nn += n mismatch")
			}
		}
		if las4, ok := fs3.Body.List[4].(*ast.AssignStmt); !ok || !isCountAdvanceSliceAssign(las4, sParam, map[string]bool{loopNVar: true}) {
			return fmt.Errorf("bufio: WriteString loop missing s = s[n:]")
		}
	}
	// Stmt 4: if b.err != nil { return nn, b.err }
	if s4, ok := wsFn.Body.List[4].(*ast.IfStmt); !ok || s4.Init != nil || s4.Else != nil || len(s4.Body.List) != 1 {
		return fmt.Errorf("bufio: WriteString missing post-loop b.err check")
	} else {
		cond, ok := unwrapParens(s4.Cond).(*ast.BinaryExpr)
		if !ok || cond.Op != token.NEQ {
			return fmt.Errorf("bufio: WriteString post-loop condition invalid")
		}
		if _, ok := isSelectorBaseField(cond.X, wsRecv, "err"); !ok {
			return fmt.Errorf("bufio: WriteString post-loop LHS not b.err")
		}
		if _, ok := isIdentNamed(cond.Y, "nil"); !ok {
			return fmt.Errorf("bufio: WriteString post-loop RHS not nil")
		}
		ret4, ok := s4.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret4.Results) != 2 {
			return fmt.Errorf("bufio: WriteString post-loop return invalid")
		}
		_, ok1 := isIdentNamed(ret4.Results[0], nnVar)
		_, ok2 := isSelectorBaseField(ret4.Results[1], wsRecv, "err")
		if !ok1 || !ok2 {
			return fmt.Errorf("bufio: WriteString post-loop return not nn, b.err")
		}
	}
	// Stmt 5: n := copy(b.buf[b.n:], s); Stmt 6: b.n += n; Stmt 7: nn += n; Stmt 8: return nn, nil
	var tailNVar string
	if s5, ok := wsFn.Body.List[5].(*ast.AssignStmt); !ok || s5.Tok != token.DEFINE || len(s5.Lhs) != 1 || len(s5.Rhs) != 1 {
		return fmt.Errorf("bufio: WriteString missing tail copy")
	} else {
		nID, ok1 := unwrapParens(s5.Lhs[0]).(*ast.Ident)
		cpCall, ok2 := unwrapParens(s5.Rhs[0]).(*ast.CallExpr)
		if !ok1 || !ok2 || nID.Name == "" || nID.Name == "_" || cpCall.Ellipsis.IsValid() || len(cpCall.Args) != 2 {
			return fmt.Errorf("bufio: WriteString invalid tail copy")
		}
		tailNVar = nID.Name
		if _, ok := isIdentNamed(cpCall.Fun, "copy"); !ok {
			return fmt.Errorf("bufio: WriteString tail call not copy")
		}
		sl, ok := unwrapParens(cpCall.Args[0]).(*ast.SliceExpr)
		if !ok || sl.Slice3 || sl.High != nil || sl.Low == nil {
			return fmt.Errorf("bufio: WriteString tail copy dst slice invalid")
		}
		if _, ok := isSelectorBaseField(sl.X, wsRecv, "buf"); !ok {
			return fmt.Errorf("bufio: WriteString tail copy dst not b.buf")
		}
		if _, ok := isSelectorBaseField(sl.Low, wsRecv, "n"); !ok {
			return fmt.Errorf("bufio: WriteString tail copy low not b.n")
		}
		if _, ok := isIdentNamed(cpCall.Args[1], sParam); !ok {
			return fmt.Errorf("bufio: WriteString tail copy src not s")
		}
		s6, ok := wsFn.Body.List[6].(*ast.AssignStmt)
		if !ok || s6.Tok != token.ADD_ASSIGN || len(s6.Lhs) != 1 || len(s6.Rhs) != 1 {
			return fmt.Errorf("bufio: WriteString missing b.n += n")
		}
		if _, ok := isSelectorBaseField(s6.Lhs[0], wsRecv, "n"); !ok {
			return fmt.Errorf("bufio: WriteString tail add target not b.n")
		}
		if _, ok := isIdentNamed(s6.Rhs[0], tailNVar); !ok {
			return fmt.Errorf("bufio: WriteString tail add RHS not n")
		}
	}
	if s7, ok := wsFn.Body.List[7].(*ast.AssignStmt); !ok || s7.Tok != token.ADD_ASSIGN || len(s7.Lhs) != 1 || len(s7.Rhs) != 1 {
		return fmt.Errorf("bufio: WriteString missing tail nn += n")
	} else {
		_, ok1 := isIdentNamed(s7.Lhs[0], nnVar)
		_, ok2 := isIdentNamed(s7.Rhs[0], tailNVar)
		if !ok1 || !ok2 {
			return fmt.Errorf("bufio: WriteString tail nn += n mismatch")
		}
	}
	if s8, ok := wsFn.Body.List[8].(*ast.ReturnStmt); !ok || len(s8.Results) != 2 {
		return fmt.Errorf("bufio: WriteString missing final return")
	} else {
		_, ok1 := isIdentNamed(s8.Results[0], nnVar)
		_, ok2 := isIdentNamed(s8.Results[1], "nil")
		if !ok1 || !ok2 {
			return fmt.Errorf("bufio: WriteString final return not nn, nil")
		}
	}
	return nil
}
