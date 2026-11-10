package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
	"strings"
)

// VerifyOSPackageAST verifies that package os satisfies the pure harness contract
// and returns the sorted list of runtime inactive gate names used by os.
func VerifyOSPackageAST(files []*ast.File, osRuntimePullMap map[string]string, osAnyLinknameLocals map[string]bool) ([]string, error) {
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

	idx, err := indexPackageAST("os", files, osPkgScopeReserved, map[string]bool{
		"internal/testlog": true, "io": true, "syscall": true,
		"io/fs": true, "errors": true, "runtime": true,
	})
	if err != nil {
		return nil, err
	}
	fileImportsTestlog := idx.fileImportSet("internal/testlog")
	importsTestlog := len(fileImportsTestlog) > 0
	fileImportsIO := idx.fileImportSet("io")
	fileImportsSyscall := idx.fileImportSet("syscall")
	fileImportsUnsafe := map[*ast.File]bool{}
	fileImportsIOFS := idx.fileImportSet("io/fs")
	fileImportsErrors := idx.fileImportSet("errors")
	fileImportsRuntime := idx.fileImportSet("runtime")
	funcFile := idx.funcFile
	pkgDeclCounts := idx.pkgDeclCounts
	hasErrInvalidInit := false
	hasErrClosedInit := false
	osErrConstCand := map[string]bool{}
	osErrVarCand := map[string]bool{}
	nonAliasStructSpecs := idx.nonAliasStructSpec

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
			importPath, _ := strconv.Unquote(imp.Path.Value)
			if imp.Name != nil && osReserved[imp.Name.Name] {
				return nil, fmt.Errorf("os: forbidden or shadowing import alias %q", imp.Name.Name)
			}
			if importPath == "unsafe" {
				if imp.Name != nil && imp.Name.Name != "_" {
					return nil, fmt.Errorf("os: aliased import of unsafe forbidden")
				}
				if imp.Name == nil {
					fileImportsUnsafe[f] = true
				}
			}
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					sp, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for idxSpec, id := range sp.Names {
						if d.Tok == token.CONST && id.Name != "_" && sp.Type == nil && len(sp.Values) == len(sp.Names) && fileImportsSyscall[f] {
							if sel, okS := unwrapParens(sp.Values[idxSpec]).(*ast.SelectorExpr); okS {
								if _, okSys := isIdentNamed(sel.X, "syscall"); okSys && strings.HasPrefix(sel.Sel.Name, "E") {
									osErrConstCand[id.Name] = true
								}
							}
						}
						if d.Tok == token.VAR && id.Name != "_" && len(sp.Values) == len(sp.Names) && isVerifiedNonNilOSErrVarInit(f, sp.Values[idxSpec]) {
							osErrVarCand[id.Name] = true
						}
						if d.Tok == token.VAR && (id.Name == "ErrInvalid" || id.Name == "ErrClosed") {
							if len(sp.Values) != len(sp.Names) || !isVerifiedOSSentinelInit(f, id.Name, sp.Values[idxSpec]) {
								return nil, fmt.Errorf("os: %s must have non-nil initializer", id.Name)
							}
							if id.Name == "ErrInvalid" {
								hasErrInvalidInit = true
							} else {
								hasErrClosedInit = true
							}
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil {
					if osReserved[d.Name.Name] {
						return nil, fmt.Errorf("os: function declaration shadows %s", d.Name.Name)
					}
					if d.Name.Name != "init" && d.Name.Name != "_" {
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
	if err := verifyOSFileStructTypes(idx); err != nil {
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

	osInactive := discoverOSInactiveState(idx, files, osRuntimePullMap, osAnyLinknameLocals)
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
		if rcFn == nil || len(rcFn.Body.List) < 3 || funcShadowsAnyIdent(rcFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(rcFn.Body) {
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
				!funcShadowsAnyIdent(decFn, osNoFileReserved) && !bodyHasControlFlowOrRecoverBypass(decFn.Body) &&
				!funcShadowsAnyIdent(desFn, osNoFileReserved) && !bodyHasControlFlowOrRecoverBypass(desFn.Body) {
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

func verifyOSFileStructTypes(idx *PackageASTIndex) error {
	fileTypeSpec := idx.uniqueTypeSpec("File")
	if idx.pkgDeclCounts["File"] != 1 || fileTypeSpec == nil || fileTypeSpec.Assign.IsValid() || fileTypeSpec.TypeParams != nil {
		return fmt.Errorf("os: missing or invalid File type declaration")
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
	rst, _, ok := idx.VerifyStructFields("file", map[string]func(ast.Expr) bool{
		"name": func(e ast.Expr) bool { _, ok := isIdentNamed(e, "string"); return ok },
	}, true)
	if !ok {
		return fmt.Errorf("os: invalid file struct declaration")
	}
	var sawFD bool
	for _, fld := range rst.Fields.List {
		for _, id := range fld.Names {
			if id.Name == "pfd" || id.Name == "sysfd" {
				sawFD = true
			}
		}
	}
	if !sawFD {
		return fmt.Errorf("os: file struct missing pfd/sysfd field")
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
