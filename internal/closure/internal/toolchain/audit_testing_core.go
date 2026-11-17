package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
	"slices"
	"strconv"
)

// VerifyTestingPackageAST verifies that package testing satisfies the pure harness contract
// without external runtime inactive gate dependencies.
func VerifyTestingPackageAST(files []*ast.File, runtimePullLinknames, selfPushLinknames map[string]bool) error {
	reqGates, err := VerifyTestingPackageASTWithPulls(files, runtimePullLinknames, selfPushLinknames, nil, nil)
	if err != nil {
		return err
	}
	if len(reqGates) > 0 {
		return fmt.Errorf("testing: requires cross-package runtime gate verification %v", reqGates)
	}
	return nil
}

// VerifyTestingPackageASTWithPulls verifies package testing and returns any
// runtime.* inactive gates required by its proof.
func VerifyTestingPackageASTWithPulls(files []*ast.File, runtimePullLinknames, selfPushLinknames map[string]bool, runtimePullMap map[string]string, anyLinknameLocals map[string]bool) ([]string, error) {
	pkgReserved := map[string]bool{
		"os":      true,
		"fmt":     true,
		"io":      true,
		"flag":    true,
		"sync":    true,
		"syscall": true,
		"panic":   true,
		"recover": true,
		"new":     true,
		"len":     true,
		"append":  true,
		"make":    true,
		"copy":    true,
		"clear":   true,
		"uintptr": true,
		"int":     true,
		"byte":    true,
		"string":  true,
		"bool":    true,
		"nil":     true,
		"error":   true,
		"true":    true,
		"false":   true,
	}
	idx, err := indexPackageAST("testing", files, pkgReserved, map[string]bool{
		"os": true, "fmt": true, "io": true, "flag": true, "sync": true, "syscall": true,
	})
	if err != nil {
		return nil, err
	}
	k := NewPackageInactiveKernel(idx, files, runtimePullMap, anyLinknameLocals)
	reqGates := map[string]bool{}
	if idx.anyDupTypeMethod || len(idx.dupTopFuncs) > 0 {
		return nil, fmt.Errorf("testing: duplicate method or function declarations")
	}
	for _, d := range idx.bodylessFuncs {
		if d.Recv != nil || !runtimePullLinknames[d.Name.Name] {
			return nil, fmt.Errorf("testing: unexpected bodyless function %s", d.Name.Name)
		}
	}
	var hasValidContextMethod, hasInvalidContextMethod bool
	for _, d := range idx.funcDeclsByName["Context"] {
		if verifyTestingContextDecl(d) {
			hasValidContextMethod = true
		} else {
			hasInvalidContextMethod = true
		}
	}
	fileImportsOS := idx.fileImportSet("os")
	fileImportsFmt := idx.fileImportSet("fmt")
	fileImportsIO := idx.fileImportSet("io")
	fileImportsFlag := idx.fileImportSet("flag")
	fileImportsSync := idx.fileImportSet("sync")
	fileImportsSyscall := idx.fileImportSet("syscall")
	funcFile := idx.funcFile
	topFuncs := idx.topFuncs
	dupTopFuncs := idx.dupTopFuncs
	typeMethods := idx.typeMethods
	pkgVarCounts := idx.pkgValueCounts
	zeroInitPkgVars := idx.zeroInitPkgVars
	zeroInitBoolVars := idx.zeroInitBoolVars
	initPkgVars := idx.initPkgVars
	initPkgVarFile := idx.initPkgVarFile
	flagAllowedDeclIdents := idx.varDeclIdents
	recordAllowedFlagIdent := func(name string, id *ast.Ident) {
		if name == "" || name == "_" || id == nil {
			return
		}
		if flagAllowedDeclIdents[name] == nil {
			flagAllowedDeclIdents[name] = map[*ast.Ident]bool{}
		}
		flagAllowedDeclIdents[name][id] = true
	}
	for sym := range runtimePullLinknames {
		if fn := topFuncs[sym]; fn == nil || fn.Body != nil {
			return nil, fmt.Errorf("testing: runtime pull linkname %s missing bodyless declaration", sym)
		}
	}
	for sym := range selfPushLinknames {
		if fn := topFuncs[sym]; fn == nil || fn.Body == nil {
			return nil, fmt.Errorf("testing: push linkname %s missing concrete top-level function", sym)
		}
	}

	// Count all occurrences of "Main" across files to verify legacy func Main is unreferenced.
	mainIdentCount := 0
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "Main" {
				mainIdentCount++
			}
			return true
		})
	}

	// Package-wide Exit / flag / raw-syscall audit: prevent exit-0 and flag-mutation bypasses anywhere in testing.
	var mRunExitCalls []*ast.CallExpr
	var osExitSites []testingExitSite
	flagRegCounts := map[string]int{}
	for _, f := range files {
		directCalls := map[*ast.SelectorExpr]*ast.CallExpr{}
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && !call.Ellipsis.IsValid() {
				if sel, ok2 := unwrapParens(call.Fun).(*ast.SelectorExpr); ok2 {
					directCalls[sel] = call
				}
			}
			return true
		})
		var exitErr error
		ast.Inspect(f, func(n ast.Node) bool {
			if exitErr != nil || n == nil {
				return false
			}
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "Set" {
				if innerSel, okS := unwrapParens(sel.X).(*ast.SelectorExpr); okS && innerSel.Sel.Name == "CommandLine" {
					exitErr = fmt.Errorf("testing: forbidden CommandLine.Set reference")
					return false
				}
			}
			pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
			if !ok {
				return true
			}
			switch pkgID.Name {
			case "CommandLine":
				if sel.Sel.Name == "Set" {
					exitErr = fmt.Errorf("testing: forbidden CommandLine.Set reference")
					return false
				}
			case "flag":
				if !fileImportsFlag[f] {
					exitErr = fmt.Errorf("testing: flag selector without unaliased flag import")
					return false
				}
				call := directCalls[sel]
				switch sel.Sel.Name {
				case "Parsed", "Parse", "Usage":
					if call == nil || len(call.Args) != 0 {
						exitErr = fmt.Errorf("testing: flag.%s must be a direct 0-argument call", sel.Sel.Name)
						return false
					}
				case "Bool", "Int", "Int64", "Uint", "Uint64", "String", "Float64", "Duration", "Var":
					if call == nil || len(call.Args) != 3 {
						exitErr = fmt.Errorf("testing: flag.%s must be a direct 3-argument call", sel.Sel.Name)
						return false
					}
					nameIdx := 0
					if sel.Sel.Name == "Var" {
						nameIdx = 1
					}
					nameLit, okL := unwrapParens(call.Args[nameIdx]).(*ast.BasicLit)
					if !okL || nameLit.Kind != token.STRING {
						exitErr = fmt.Errorf("testing: flag.%s requires literal flag name", sel.Sel.Name)
						return false
					}
					parsedName, uErr := strconv.Unquote(nameLit.Value)
					if uErr != nil || parsedName == "" {
						exitErr = fmt.Errorf("testing: invalid flag.%s name literal", sel.Sel.Name)
						return false
					}
					flagRegCounts[parsedName]++
				default:
					exitErr = fmt.Errorf("testing: forbidden flag.%s reference", sel.Sel.Name)
					return false
				}
			case "syscall":
				switch sel.Sel.Name {
				case "Exit", "Syscall", "Syscall6", "RawSyscall6":
					exitErr = fmt.Errorf("testing: forbidden syscall.%s reference", sel.Sel.Name)
					return false
				case "RawSyscall":
					call := directCalls[sel]
					if call == nil || len(call.Args) != 4 || !fileImportsSyscall[f] {
						exitErr = fmt.Errorf("testing: forbidden or non-SYS_WRITE syscall.RawSyscall")
						return false
					}
					sysSel, ok := unwrapParens(call.Args[0]).(*ast.SelectorExpr)
					if !ok || sysSel.Sel.Name != "SYS_WRITE" {
						exitErr = fmt.Errorf("testing: syscall.RawSyscall allowed only for SYS_WRITE")
						return false
					}
					sysPkg, ok := unwrapParens(sysSel.X).(*ast.Ident)
					if !ok || sysPkg.Name != "syscall" {
						exitErr = fmt.Errorf("testing: syscall.RawSyscall requires syscall.SYS_WRITE")
						return false
					}
				}
			case "os":
				if sel.Sel.Name != "Exit" {
					return true
				}
				call := directCalls[sel]
				if call == nil || len(call.Args) != 1 || !fileImportsOS[f] {
					exitErr = fmt.Errorf("testing: os.Exit must be a direct 1-argument call")
					return false
				}
				encFn, encAncestors := findEnclosingFuncAndAncestors(f, call)
				if encFn == nil || funcShadowsAnyIdent(encFn, map[string]bool{"os": true}) {
					exitErr = fmt.Errorf("testing: os.Exit outside verified function declaration")
					return false
				}
				isMRun := encFn.Recv != nil && len(encFn.Recv.List) == 1 && recvTypeName(encFn.Recv.List[0].Type) == "M" && encFn.Name.Name == "Run"
				if !exprHasCallOrFuncLit(call.Args[0]) && isPositiveIntLit(call.Args[0]) {
					if isMRun {
						mRunExitCalls = append(mRunExitCalls, call)
					}
					osExitSites = append(osExitSites, testingExitSite{
						file:      f,
						call:      call,
						encFn:     encFn,
						ancestors: encAncestors,
					})
					return true
				}
				if encFn.Recv == nil && encFn.Name.Name == "Main" && !dupTopFuncs["Main"] && !selfPushLinknames["Main"] && mainIdentCount == 1 && len(encAncestors) == 3 && len(encFn.Body.List) == 1 {
					return true
				}
				exitErr = fmt.Errorf("testing: non-positive or unverified os.Exit in %s", encFn.Name.Name)
				return false
			}
			return true
		})
		if exitErr != nil {
			return nil, exitErr
		}
	}
	if flagRegCounts["test.testlogfile"] != 1 || flagRegCounts["test.list"] > 1 {
		return nil, fmt.Errorf("testing: duplicate or missing test.testlogfile/test.list flag registration")
	}

	// Discover unexported package-level string-pointer flags registered for
	// "test.testlogfile" and "test.list" with empty default "", via either Form A
	// (package-level var initializer) or Form B (once-guarded Init() called by MainStart),
	// and verify neither the pointer nor *pointer is mutated or address-taken elsewhere.
	varWriteCount := map[string]int{}
	flagAddrTaken := map[string]bool{}
	flagDerefMutated := map[string]bool{}
	recordLHSWrite := func(lhs ast.Expr) {
		switch x := unwrapParens(lhs).(type) {
		case *ast.Ident:
			if x.Name != "" && x.Name != "_" {
				varWriteCount[x.Name]++
			}
		case *ast.StarExpr:
			if id, ok := unwrapParens(x.X).(*ast.Ident); ok && id.Name != "" && id.Name != "_" {
				flagDerefMutated[id.Name] = true
			}
		}
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					recordLHSWrite(lhs)
				}
			case *ast.RangeStmt:
				if node.Key != nil {
					recordLHSWrite(node.Key)
				}
				if node.Value != nil {
					recordLHSWrite(node.Value)
				}
			case *ast.IncDecStmt:
				recordLHSWrite(node.X)
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					switch x := unwrapParens(node.X).(type) {
					case *ast.Ident:
						flagAddrTaken[x.Name] = true
					case *ast.StarExpr:
						if id, ok := unwrapParens(x.X).(*ast.Ident); ok {
							flagAddrTaken[id.Name] = true
						}
					}
				}
			}
			return true
		})
	}

	testlogfileFlagVars := map[string]bool{}
	listFlagVars := map[string]bool{}
	emptyDefaultStringFlags := map[string]bool{}
	flagInitFunc := map[string]*ast.FuncDecl{}

	// Form A: var fv = flag.String("...", "", ...)
	for fv, initExpr := range initPkgVars {
		f := initPkgVarFile[fv]
		if ast.IsExported(fv) || pkgVarCounts[fv] != 1 || varWriteCount[fv] != 0 || flagAddrTaken[fv] || flagDerefMutated[fv] || !fileImportsFlag[f] {
			continue
		}
		call, ok := unwrapParens(initExpr).(*ast.CallExpr)
		if !ok {
			continue
		}
		if flagName, ok := flagStringEmptyDefaultName(call); ok {
			switch flagName {
			case "test.testlogfile":
				testlogfileFlagVars[fv] = true
			case "test.list":
				listFlagVars[fv] = true
			default:
				emptyDefaultStringFlags[fv] = true
			}
		}
	}

	// Form B: zero-init var fv assigned once at top level of a 0-arg/0-result Init-style function.
	for name, fn := range topFuncs {
		f := funcFile[fn]
		if fn == nil || fn.Body == nil || !fileImportsFlag[f] || name == "MainStart" || name == "Main" {
			continue
		}
		if (fn.Type.Params != nil && fn.Type.Params.NumFields() != 0) || (fn.Type.Results != nil && fn.Type.Results.NumFields() != 0) {
			continue
		}
		if funcShadowsAnyIdent(fn, pkgReserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
			continue
		}
		startCheckIdx := 0
		if len(fn.Body.List) >= 2 {
			if ifs, ok := fn.Body.List[0].(*ast.IfStmt); ok && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
				if ret, ok2 := ifs.Body.List[0].(*ast.ReturnStmt); ok2 && len(ret.Results) == 0 {
					if onceID, ok3 := unwrapParens(ifs.Cond).(*ast.Ident); ok3 && !ast.IsExported(onceID.Name) && zeroInitBoolVars[onceID.Name] && pkgVarCounts[onceID.Name] == 1 && varWriteCount[onceID.Name] == 1 && !flagAddrTaken[onceID.Name] && !funcShadowsAnyIdent(fn, map[string]bool{onceID.Name: true}) {
						if as1, ok4 := fn.Body.List[1].(*ast.AssignStmt); ok4 && as1.Tok == token.ASSIGN && len(as1.Lhs) == 1 && len(as1.Rhs) == 1 {
							_, okL := isIdentNamed(as1.Lhs[0], onceID.Name)
							_, okR := isIdentNamed(as1.Rhs[0], "true")
							if okL && okR {
								startCheckIdx = 2
							}
						}
					}
				}
			}
		}
		seenFlags := map[string]bool{}
		for idx := startCheckIdx; idx < len(fn.Body.List); idx++ {
			stmt := fn.Body.List[idx]
			if as, ok := stmt.(*ast.AssignStmt); ok && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
				if lhsID, ok2 := unwrapParens(as.Lhs[0]).(*ast.Ident); ok2 && !ast.IsExported(lhsID.Name) && zeroInitPkgVars[lhsID.Name] != nil && pkgVarCounts[lhsID.Name] == 1 && varWriteCount[lhsID.Name] == 1 && !flagAddrTaken[lhsID.Name] && !flagDerefMutated[lhsID.Name] && !funcShadowsAnyIdent(fn, map[string]bool{lhsID.Name: true}) {
					if call, ok3 := unwrapParens(as.Rhs[0]).(*ast.CallExpr); ok3 {
						if flagName, okName := flagStringEmptyDefaultName(call); okName && !seenFlags[flagName] {
							recordAllowedFlagIdent(lhsID.Name, lhsID)
							switch flagName {
							case "test.testlogfile":
								testlogfileFlagVars[lhsID.Name] = true
								flagInitFunc[lhsID.Name] = fn
							case "test.list":
								listFlagVars[lhsID.Name] = true
								flagInitFunc[lhsID.Name] = fn
							default:
								emptyDefaultStringFlags[lhsID.Name] = true
								flagInitFunc[lhsID.Name] = fn
							}
						}
					}
				}
			}
			if !isBenignFlagInitRegStmt(stmt, seenFlags) {
				break
			}
		}
	}
	if len(testlogfileFlagVars) == 0 {
		return nil, fmt.Errorf("testing: missing verified test.testlogfile flag registration")
	}

	stopLogAssign := func(stmt ast.Stmt) (string, *ast.CallExpr) {
		as, ok := stmt.(*ast.AssignStmt)
		if !ok || (as.Tok != token.DEFINE && as.Tok != token.ASSIGN) || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return "", nil
		}
		id, ok := unwrapParens(as.Lhs[0]).(*ast.Ident)
		if !ok || id.Name == "" || id.Name == "_" || id.Name == "nil" {
			return "", nil
		}
		call, ok := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) != 0 || !isMethodCallNamed(call, "StopTestLog") {
			return "", nil
		}
		return id.Name, call
	}

	validateCallAncestors := func(fn *ast.FuncDecl, ancestors []ast.Node, stmtIdx int) (flagGuard string, topStmt ast.Stmt, ok bool) {
		if fn == nil || stmtIdx < 1 || stmtIdx >= len(ancestors) {
			return "", nil, false
		}
		ts, isStmt := ancestors[1].(ast.Stmt)
		if !isStmt {
			return "", nil, false
		}
		for i := 0; i < stmtIdx; i++ {
			switch node := ancestors[i].(type) {
			case *ast.BlockStmt:
				childStmt, isStmt := ancestors[i+1].(ast.Stmt)
				if !isStmt {
					return "", nil, false
				}
				foundIdx := -1
				for j, bs := range node.List {
					if bs == childStmt {
						foundIdx = j
						break
					}
				}
				if foundIdx < 0 {
					return "", nil, false
				}
				for _, prior := range node.List[:foundIdx] {
					if stmtAlwaysTerminates(prior) {
						return "", nil, false
					}
				}
			case *ast.IfStmt:
				if node.Init != nil || node.Else != nil || ancestors[i+1] != node.Body || flagGuard != "" {
					return "", nil, false
				}
				fg, ok := derefFlagNonEmptyCondIdent(node.Cond)
				if !ok || !testlogfileFlagVars[fg] || funcShadowsAnyIdent(fn, map[string]bool{fg: true}) {
					return "", nil, false
				}
				flagGuard = fg
			default:
				return "", nil, false
			}
		}
		if flagGuard == "" {
			return "", nil, false
		}
		return flagGuard, ts, true
	}

	blockDeclaresVarBefore := func(blk *ast.BlockStmt, limit int, varName string) bool {
		for _, raw := range blk.List[:limit] {
			switch s := raw.(type) {
			case *ast.DeclStmt:
				if gd, ok := s.Decl.(*ast.GenDecl); ok && gd.Tok == token.VAR {
					for _, spec := range gd.Specs {
						if vs, ok2 := spec.(*ast.ValueSpec); ok2 {
							for _, id := range vs.Names {
								if id.Name == varName {
									return true
								}
							}
						}
					}
				}
			case *ast.AssignStmt:
				if s.Tok == token.DEFINE {
					for _, lhs := range s.Lhs {
						if id, ok := unwrapParens(lhs).(*ast.Ident); ok && id.Name == varName {
							return true
						}
					}
				}
			}
		}
		return false
	}

	var hasInvalidStartCall bool
	var verifiedStarts []verifiedStartInfo

	for _, f := range files {
		var startCalls []*ast.CallExpr
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && isMethodCallNamed(call, "StartTestLog") {
				startCalls = append(startCalls, call)
			}
			return true
		})
		for _, call := range startCalls {
			if len(call.Args) != 1 || call.Ellipsis.IsValid() || !fileImportsOS[f] {
				hasInvalidStartCall = true
				continue
			}
			fileVar, wrapName, ok := verifyTestingStartLogArg(call.Args[0], files, topFuncs, typeMethods, k, reqGates)
			if !ok || fileVar == "" {
				hasInvalidStartCall = true
				continue
			}
			fn, ancestors := findEnclosingFuncAndAncestors(f, call)
			if fn == nil || len(ancestors) < 2 {
				hasInvalidStartCall = true
				continue
			}
			reserved := map[string]bool{}
			for k := range pkgReserved {
				reserved[k] = true
			}
			if wrapName != "" {
				reserved[wrapName] = true
			}
			if funcShadowsAnyIdent(fn, reserved) || funcDeclaresParamOrResult(fn, fileVar) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
				hasInvalidStartCall = true
				continue
			}
			es, ok := ancestors[len(ancestors)-2].(*ast.ExprStmt)
			if !ok || unwrapParens(es.X) != call {
				hasInvalidStartCall = true
				continue
			}
			flagGuard, topStmt, ok := validateCallAncestors(fn, ancestors, len(ancestors)-2)
			if !ok {
				hasInvalidStartCall = true
				continue
			}
			recvKey := canonicalDepsReceiverKey(fn, call)
			if recvKey == "" {
				hasInvalidStartCall = true
				continue
			}
			var declBlock *ast.BlockStmt
			declTargetIdx := -1
			for i := len(ancestors) - 3; i >= 0; i-- {
				blk, isBlk := ancestors[i].(*ast.BlockStmt)
				if !isBlk {
					continue
				}
				childStmt := ancestors[i+1].(ast.Stmt)
				idx := slices.Index(blk.List, childStmt)
				if idx < 0 {
					break
				}
				if blockDeclaresVarBefore(blk, idx, fileVar) {
					declBlock = blk
					declTargetIdx = idx
					break
				}
			}
			if declBlock == nil || declTargetIdx <= 0 || declBlock.List[declTargetIdx] != es {
				hasInvalidStartCall = true
				continue
			}
			openExits := map[*ast.CallExpr]bool{}
			if !verifyLogFileOpenPrefix(declBlock.List[:declTargetIdx], fileVar, flagGuard, fileImportsOS[f], fileImportsFmt[f], openExits) {
				hasInvalidStartCall = true
				continue
			}
			verifiedStarts = append(verifiedStarts, verifiedStartInfo{
				file:          f,
				fn:            fn,
				topStmt:       topStmt,
				declBlock:     declBlock,
				declTargetIdx: declTargetIdx,
				fileVar:       fileVar,
				recvKey:       recvKey,
				flagGuard:     flagGuard,
				openExits:     openExits,
			})
		}
	}

	verifiedStopCalls := map[*ast.CallExpr]verifiedStopInfo{}
	recordCandidateStop := func(f *ast.File, parentBlk *ast.BlockStmt, stmtPos, afterStopPos int, errVar string, call *ast.CallExpr, handler *ast.IfStmt) {
		if !isFailureForcingErrHandler(handler, errVar, fileImportsOS[f], fileImportsFmt[f]) {
			return
		}
		fn, ancestors := findEnclosingFuncAndAncestors(f, parentBlk.List[stmtPos])
		if fn == nil || len(ancestors) < 2 {
			return
		}
		if funcShadowsAnyIdent(fn, pkgReserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
			return
		}
		flagGuard, topStmt, ok := validateCallAncestors(fn, ancestors, len(ancestors)-1)
		if !ok {
			return
		}
		recvKey := canonicalDepsReceiverKey(fn, call)
		if recvKey == "" {
			return
		}
		matchedStart := false
		for _, st := range verifiedStarts {
			if st.recvKey == recvKey && flagGuard == st.flagGuard {
				matchedStart = true
				break
			}
		}
		if !matchedStart {
			return
		}
		verifiedStopCalls[call] = verifiedStopInfo{
			file:         f,
			fn:           fn,
			topStmt:      topStmt,
			parentBlk:    parentBlk,
			stmtPos:      stmtPos,
			afterStopPos: afterStopPos,
			recvKey:      recvKey,
			flagGuard:    flagGuard,
			stopExit:     errHandlerTerminalCall(handler),
		}
	}

	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			blk, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for i, s := range blk.List {
				if ifs, isIf := s.(*ast.IfStmt); isIf {
					if errVar, call := stopLogAssign(ifs.Init); call != nil {
						recordCandidateStop(f, blk, i, i+1, errVar, call, ifs)
					}
				}
				if i+1 < len(blk.List) {
					if errVar, call := stopLogAssign(s); call != nil {
						if ifs, isIf := blk.List[i+1].(*ast.IfStmt); isIf && ifs.Init == nil {
							recordCandidateStop(f, blk, i, i+2, errVar, call, ifs)
						}
					}
				}
			}
			return true
		})
	}

	var hasCheckedStopCall, hasDiscardedStopCall bool
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if isMethodCallNamed(call, "StopTestLog") {
				if _, ok := verifiedStopCalls[call]; ok {
					hasCheckedStopCall = true
				} else {
					hasDiscardedStopCall = true
				}
			}
			return true
		})
	}
	if len(verifiedStarts) != 1 || hasInvalidStartCall || len(verifiedStopCalls) != 1 || !hasCheckedStopCall || hasDiscardedStopCall {
		return nil, fmt.Errorf("testing: missing, duplicate, unchecked, or error-dropping StartTestLog/StopTestLog calls")
	}

	st := verifiedStarts[0]
	var sp verifiedStopInfo
	for _, info := range verifiedStopCalls {
		sp = info
	}
	if st.recvKey != sp.recvKey || st.flagGuard == "" || st.flagGuard != sp.flagGuard {
		return nil, fmt.Errorf("testing: StartTestLog and StopTestLog receiver or flag guard mismatch")
	}

	stmtMutatesOrClosesVar := func(stmt ast.Stmt, varName string, allowClose bool) bool {
		bad := false
		ast.Inspect(stmt, func(n ast.Node) bool {
			if bad || n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					if id, ok := unwrapParens(lhs).(*ast.Ident); ok && id.Name == varName {
						bad = true
						return false
					}
				}
			case *ast.RangeStmt:
				for _, lhs := range []ast.Expr{node.Key, node.Value} {
					if lhs != nil {
						if id, ok := unwrapParens(lhs).(*ast.Ident); ok && id.Name == varName {
							bad = true
							return false
						}
					}
				}
			case *ast.IncDecStmt:
				if id, ok := unwrapParens(node.X).(*ast.Ident); ok && id.Name == varName {
					bad = true
					return false
				}
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					if id, ok := unwrapParens(node.X).(*ast.Ident); ok && id.Name == varName {
						bad = true
						return false
					}
				}
			case *ast.CallExpr:
				if !allowClose {
					if sel, ok := unwrapParens(node.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Close" {
						if id, ok2 := unwrapParens(sel.X).(*ast.Ident); ok2 && id.Name == varName {
							bad = true
							return false
						}
					}
				}
			}
			return true
		})
		return bad
	}

	closeExits := map[*ast.CallExpr]bool{}
	if st.fn == sp.fn && st.declBlock == sp.parentBlk {
		if sp.stmtPos <= st.declTargetIdx {
			return nil, fmt.Errorf("testing: StopTestLog must follow StartTestLog")
		}
		for _, midStmt := range st.declBlock.List[st.declTargetIdx+1 : sp.stmtPos] {
			if stmtAlwaysTerminates(midStmt) || stmtMutatesOrClosesVar(midStmt, st.fileVar, false) {
				return nil, fmt.Errorf("testing: unsafe statement between StartTestLog and StopTestLog")
			}
		}
		for _, afterStmt := range sp.parentBlk.List[sp.afterStopPos:] {
			if stmtMutatesOrClosesVar(afterStmt, st.fileVar, true) {
				return nil, fmt.Errorf("testing: unsafe mutation of testlog file after StopTestLog")
			}
		}
		_, closeExit, ok := blockHasFailureForcingClose(sp.parentBlk.List[sp.afterStopPos:], st.fileVar, fileImportsOS[sp.file], fileImportsFmt[sp.file])
		if !ok {
			return nil, fmt.Errorf("testing: missing failure-forcing Close on testlog file after StopTestLog")
		}
		if closeExit != nil {
			closeExits[closeExit] = true
		}
		for _, exitCall := range mRunExitCalls {
			if !st.openExits[exitCall] && exitCall != sp.stopExit && !closeExits[exitCall] {
				return nil, fmt.Errorf("testing: non-positive or unverified os.Exit in Run")
			}
		}
	} else {
		if len(mRunExitCalls) > 0 {
			return nil, fmt.Errorf("testing: non-positive or unverified os.Exit in Run")
		}
		logFileAliases := map[string]*ast.AssignStmt{}
		for _, tailStmt := range st.declBlock.List[st.declTargetIdx+1:] {
			if stmtAlwaysTerminates(tailStmt) {
				return nil, fmt.Errorf("testing: terminating statement after StartTestLog in start block")
			}
			if as, isAs := tailStmt.(*ast.AssignStmt); isAs && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
				if rhsID, ok := unwrapParens(as.Rhs[0]).(*ast.Ident); ok && rhsID.Name == st.fileVar {
					if lhsID, ok2 := unwrapParens(as.Lhs[0]).(*ast.Ident); ok2 && lhsID.Name != "" && lhsID.Name != "_" && lhsID.Name != st.fileVar {
						if _, dup := logFileAliases[lhsID.Name]; dup {
							return nil, fmt.Errorf("testing: duplicate assignment to testlog file alias %s", lhsID.Name)
						}
						logFileAliases[lhsID.Name] = as
						continue
					}
				}
			}
			if stmtMutatesOrClosesVar(tailStmt, st.fileVar, false) {
				return nil, fmt.Errorf("testing: unsafe mutation or premature Close on testlog file")
			}
		}
		if len(logFileAliases) == 0 {
			return nil, fmt.Errorf("testing: split StartTestLog/StopTestLog missing saved testlog file variable")
		}
		allowedAliasIdents := map[*ast.Ident]bool{}
		for alias, bindAssign := range logFileAliases {
			if ast.IsExported(alias) || zeroInitPkgVars[alias] == nil || pkgVarCounts[alias] != 1 {
				return nil, fmt.Errorf("testing: testlog file alias %s must be a unique unexported zero-initialized package var", alias)
			}
			if funcShadowsAnyIdent(st.fn, map[string]bool{alias: true}) || funcShadowsAnyIdent(sp.fn, map[string]bool{alias: true}) {
				return nil, fmt.Errorf("testing: testlog file alias %s shadowed in lifecycle function", alias)
			}
			if lhsID, ok := unwrapParens(bindAssign.Lhs[0]).(*ast.Ident); ok {
				allowedAliasIdents[lhsID] = true
			}
			for _, f := range files {
				for _, decl := range f.Decls {
					if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.VAR {
						for _, spec := range gd.Specs {
							if vs, ok2 := spec.(*ast.ValueSpec); ok2 && len(vs.Values) == 0 {
								for _, id := range vs.Names {
									if id.Name == alias {
										allowedAliasIdents[id] = true
									}
								}
							}
						}
					}
				}
			}
			closeRecvID, closeExit, ok := blockHasFailureForcingClose(sp.parentBlk.List[sp.afterStopPos:], alias, fileImportsOS[sp.file], fileImportsFmt[sp.file])
			if !ok || closeRecvID == nil {
				return nil, fmt.Errorf("testing: missing failure-forcing %s.Close() after StopTestLog", alias)
			}
			if closeExit != nil {
				closeExits[closeExit] = true
			}
			allowedAliasIdents[closeRecvID] = true
		}
		if !allNonSelPropIdentsInSet(files, logFileAliases, allowedAliasIdents) {
			return nil, fmt.Errorf("testing: unsafe mutation or unchecked Close on saved testlog file")
		}
	}

	if hasInvalidContextMethod {
		return nil, fmt.Errorf("testing: (*common).Context has unexpected shape")
	}
	if !hasValidContextMethod {
		return nil, fmt.Errorf("testing: missing (*common).Context")
	}
	if err := verifyTestingChdirSetenvCleanup(idx, files, k, reqGates); err != nil {
		return nil, err
	}
	if !verifyTestingMRunTestlogWiring(files, funcFile, topFuncs, typeMethods, st, sp, flagInitFunc, flagAllowedDeclIdents, listFlagVars, emptyDefaultStringFlags, osExitSites, closeExits, fileImportsOS, fileImportsFmt, fileImportsIO, fileImportsFlag, fileImportsSync, pkgReserved) {
		return nil, fmt.Errorf("testing: (*M).Run does not wire MainStart deps through verified StartTestLog/StopTestLog")
	}
	return sortedKeys(reqGates), nil
}

