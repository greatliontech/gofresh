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
		"Fd": true, "fd": true, "Chdir": true, "incref": true,
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
		if err := verifyOSTestlogChdirTail("Chdir", fn.Body.List[len(fn.Body.List)-2:]); err != nil {
			return nil, err
		}
		if err := verifyOSGetwd(files, topFuncs["Getwd"], allTopFuncs, allFileMethods, allRawFileMethods, allFileStatMethods, nonAliasStructSpecs, pkgDeclCounts, fileMethodCounts, rawFileMethodCounts, fileStatMethodCounts, funcFile, fileImportsSyscall, verifiedNonNilOSErrIdents, osReserved, osNoFileReserved, osAnyLinknameLocals, osInactive, skipInactiveHookIf); err != nil {
			return nil, err
		}
	}

	if err := verifyOSFileMethods(
		topFuncs, allTopFuncs, fileMethods, rawFileMethods,
		dirInfoCloseFn, funcFile,
		fileImportsTestlog, fileImportsIO, fileImportsSyscall, fileImportsUnsafe, fileImportsRuntime,
		osReserved, osNoFileReserved, osAnyLinknameLocals,
		skipInactiveHookIf,
	); err != nil {
		return nil, err
	}

	return sortedKeys(usedRuntimeGates), nil
}
