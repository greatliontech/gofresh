package toolchain

import (
	"go/ast"
	"go/token"
	"slices"
)

func verifyTestingMRunTestlogWiring(
	files []*ast.File,
	funcFile map[*ast.FuncDecl]*ast.File,
	topFuncs map[string]*ast.FuncDecl,
	typeMethods map[string]map[string]*ast.FuncDecl,
	st verifiedStartInfo,
	sp verifiedStopInfo,
	flagInitFunc map[string]*ast.FuncDecl,
	flagAllowedDeclIdents map[string]map[*ast.Ident]bool,
	listFlagVars map[string]bool,
	emptyDefaultStringFlags map[string]bool,
	osExitSites []testingExitSite,
	closeExits map[*ast.CallExpr]bool,
	fileImportsOS map[*ast.File]bool,
	fileImportsFmt map[*ast.File]bool,
	fileImportsIO map[*ast.File]bool,
	fileImportsFlag map[*ast.File]bool,
	fileImportsSync map[*ast.File]bool,
	pkgReserved map[string]bool,
) bool {
	mainStart := topFuncs["MainStart"]
	mMethods := typeMethods["M"]
	runFn := mMethods["Run"]
	if mainStart == nil || mainStart.Body == nil || mainStart.Type == nil || mainStart.Type.Params == nil || mainStart.Type.Results == nil || mainStart.Type.Results.NumFields() != 1 || runFn == nil || runFn.Body == nil || runFn.Type == nil {
		return false
	}
	if (runFn.Type.Params != nil && runFn.Type.Params.NumFields() != 0) || runFn.Type.Results == nil || runFn.Type.Results.NumFields() != 1 {
		return false
	}
	if funcShadowsAnyIdent(mainStart, pkgReserved) || bodyHasControlFlowOrRecoverBypass(mainStart.Body) || !blockAlwaysReturns(mainStart.Body.List) {
		return false
	}
	if funcShadowsAnyIdent(runFn, pkgReserved) || bodyHasControlFlowOrRecoverBypass(runFn.Body) {
		return false
	}
	runRecv := recvVarName(runFn)
	if runRecv == "" {
		return false
	}

	// Verify unique type M struct declaration, collect its fields, and track all allowed M idents.
	allowedMIdents := map[*ast.Ident]bool{}
	var mStruct *ast.StructType
	var mStructFile *ast.File
	mTypeSpecs := 0
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || ts.Name == nil || ts.Name.Name != "M" {
					continue
				}
				mTypeSpecs++
				if stType, ok := ts.Type.(*ast.StructType); ok && !ts.Assign.IsValid() {
					mStruct = stType
					mStructFile = f
					allowedMIdents[ts.Name] = true
				}
			}
		}
	}
	if mTypeSpecs != 1 || mStruct == nil || mStruct.Fields == nil {
		return false
	}
	if len(mainStart.Type.Results.List) != 1 || len(mainStart.Type.Results.List[0].Names) != 0 {
		return false
	}
	msResStar, okMSStar := unwrapParens(mainStart.Type.Results.List[0].Type).(*ast.StarExpr)
	if !okMSStar {
		return false
	}
	msResID, okMSID := unwrapParens(msResStar.X).(*ast.Ident)
	if !okMSID || msResID.Name != "M" {
		return false
	}
	allowedMIdents[msResID] = true

	mFields := map[string]ast.Expr{}
	mFieldIdents := map[string]*ast.Ident{}
	for _, fld := range mStruct.Fields.List {
		if len(fld.Names) == 0 {
			return false
		}
		for _, id := range fld.Names {
			if _, dup := mFields[id.Name]; dup {
				return false
			}
			mFields[id.Name] = fld.Type
			mFieldIdents[id.Name] = id
		}
	}

	pNames := paramNamesFlat(mainStart.Type.Params)
	if len(pNames) == 0 || pNames[0] == "" || pNames[0] == "_" {
		return false
	}
	depsParam := pNames[0]
	if bodyMutatesOrTakesAddrOfAny(mainStart.Body, map[string]bool{depsParam: true}) || bodyDeclaresAnyIdent(mainStart.Body, map[string]bool{depsParam: true}) {
		return false
	}
	var depsField string
	mainStartValid := true
	sawMainStartReturn := false
	ast.Inspect(mainStart.Body, func(n ast.Node) bool {
		if !mainStartValid || n == nil {
			return false
		}
		if _, isFL := n.(*ast.FuncLit); isFL {
			mainStartValid = false
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		sawMainStartReturn = true
		if len(ret.Results) != 1 {
			mainStartValid = false
			return false
		}
		u, ok := unwrapParens(ret.Results[0]).(*ast.UnaryExpr)
		if !ok || u.Op != token.AND {
			mainStartValid = false
			return false
		}
		lit, tName := compositeWriterLit(ret.Results[0])
		if lit == nil || tName != "M" {
			mainStartValid = false
			return false
		}
		litTypeID, okLT := unwrapParens(lit.Type).(*ast.Ident)
		if !okLT || litTypeID.Name != "M" {
			mainStartValid = false
			return false
		}
		allowedMIdents[litTypeID] = true
		var retDepsField string
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				mainStartValid = false
				return false
			}
			kID, ok1 := unwrapParens(kv.Key).(*ast.Ident)
			if !ok1 || kID.Name == "" {
				mainStartValid = false
				return false
			}
			if vID, ok2 := unwrapParens(kv.Value).(*ast.Ident); ok2 && vID.Name == depsParam {
				if retDepsField != "" {
					mainStartValid = false
					return false
				}
				retDepsField = kID.Name
			}
		}
		if retDepsField == "" || (depsField != "" && depsField != retDepsField) {
			mainStartValid = false
			return false
		}
		depsField = retDepsField
		return false
	})
	if !mainStartValid || !sawMainStartReturn || depsField == "" || ast.IsExported(depsField) || mFields[depsField] == nil {
		return false
	}

	// Verify every method on M has a pointer receiver *M whose receiver variable is only field/method-selected,
	// never mutated, address-taken, or used to invoke (*M).Run recursively, and verify no other M ident exists in testing.
	for _, mFn := range mMethods {
		if mFn == nil || mFn.Body == nil || mFn.Recv == nil || len(mFn.Recv.List) != 1 || len(mFn.Recv.List[0].Names) > 1 {
			return false
		}
		rStar, okRS := unwrapParens(mFn.Recv.List[0].Type).(*ast.StarExpr)
		if !okRS {
			return false
		}
		rID, okRID := unwrapParens(rStar.X).(*ast.Ident)
		if !okRID || rID.Name != "M" {
			return false
		}
		allowedMIdents[rID] = true
		if rv := recvVarName(mFn); rv != "" {
			if bodyMutatesOrTakesAddrOfAny(mFn.Body, map[string]bool{rv: true}) || !blockOnlySelectsOnIdent(mFn.Body, rv) {
				return false
			}
			callsSelfRun := false
			ast.Inspect(mFn.Body, func(n ast.Node) bool {
				if callsSelfRun || n == nil {
					return false
				}
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Run" {
					if xID, okX := unwrapParens(sel.X).(*ast.Ident); okX && xID.Name == rv {
						callsSelfRun = true
						return false
					}
				}
				return true
			})
			if callsSelfRun {
				return false
			}
		}
	}
	if !allNonSelPropIdentsIn(files, "M", allowedMIdents) {
		return false
	}

	// Ensure M.<depsField> is never reassigned, incremented, or address-taken anywhere in testing.
	for _, f := range files {
		if nodeMutatesOrTakesAddrOfSelector(f, "", map[string]bool{depsField: true}) {
			return false
		}
	}
	wantRecvKey := "<M>." + depsField
	if st.recvKey != wantRecvKey || sp.recvKey != wantRecvKey {
		return false
	}

	// Helper verifying that any flag pointer var used by the lifecycle appears ONLY at its
	// allowed declaration/Init sites or as the direct operand of a *<fv> dereference.
	verifyFlagPtrIdentOnlyDereferenced := func(fv string) bool {
		allowed := flagAllowedDeclIdents[fv]
		if fv == "" || len(allowed) == 0 {
			return false
		}
		ok := true
		for _, f := range files {
			var stack []ast.Node
			var walk func(n ast.Node)
			walk = func(n ast.Node) {
				if !ok || n == nil {
					return
				}
				switch node := n.(type) {
				case *ast.SelectorExpr:
					stack = append(stack, node)
					walk(node.X)
					stack = stack[:len(stack)-1]
					return
				case *ast.Ident:
					if node.Name == fv && !allowed[node] {
						starOK := false
						for idx := len(stack) - 1; idx >= 0; idx-- {
							if _, isParen := stack[idx].(*ast.ParenExpr); isParen {
								continue
							}
							if star, isStar := stack[idx].(*ast.StarExpr); isStar && unwrapParens(star.X) == node {
								starOK = true
							}
							break
						}
						if !starOK {
							ok = false
						}
					}
					return
				}
				stack = append(stack, n)
				ast.Inspect(n, func(ch ast.Node) bool {
					if ch == n {
						return true
					}
					walk(ch)
					return false
				})
				stack = stack[:len(stack)-1]
			}
			walk(f)
			if !ok {
				return false
			}
		}
		return true
	}

	// Helper verifying that any Form B flag var used by the lifecycle has its Init-style
	// function called unconditionally at top level of MainStart before return &M{...}.
	verifyFlagInitCalledInMainStart := func(fv string) bool {
		initFn := flagInitFunc[fv]
		if initFn == nil {
			return true
		}
		if funcShadowsAnyIdent(mainStart, map[string]bool{initFn.Name.Name: true}) {
			return false
		}
		for _, stmt := range mainStart.Body.List {
			if stmtAlwaysTerminates(stmt) {
				return false
			}
			switch s := stmt.(type) {
			case *ast.EmptyStmt, *ast.DeclStmt, *ast.AssignStmt:
			case *ast.ExprStmt:
				if call, ok := unwrapParens(s.X).(*ast.CallExpr); ok && !call.Ellipsis.IsValid() && len(call.Args) == 0 {
					if id, ok2 := unwrapParens(call.Fun).(*ast.Ident); ok2 && id.Name == initFn.Name.Name {
						return true
					}
				}
			default:
				return false
			}
		}
		return false
	}
	if !verifyFlagInitCalledInMainStart(st.flagGuard) || !verifyFlagPtrIdentOnlyDereferenced(st.flagGuard) {
		return false
	}

	// Check optional named-result exitCode defer at runFn.Body.List[0]:
	// defer func() { <code> = m.<exitCodeField> }()
	var exitCodeField string
	var exitCodeDefer *ast.DeferStmt
	if len(runFn.Type.Results.List) == 1 && len(runFn.Type.Results.List[0].Names) == 1 && len(runFn.Body.List) > 0 {
		codeName := runFn.Type.Results.List[0].Names[0].Name
		if ds, ok := runFn.Body.List[0].(*ast.DeferStmt); ok && codeName != "" && codeName != "_" {
			if fl, ok2 := unwrapParens(ds.Call.Fun).(*ast.FuncLit); ok2 && !ds.Call.Ellipsis.IsValid() && len(ds.Call.Args) == 0 && (fl.Type.Params == nil || fl.Type.Params.NumFields() == 0) && (fl.Type.Results == nil || fl.Type.Results.NumFields() == 0) && fl.Body != nil && len(fl.Body.List) == 1 {
				if as, ok3 := fl.Body.List[0].(*ast.AssignStmt); ok3 && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
					_, okL := isIdentNamed(as.Lhs[0], codeName)
					if sel, okR := unwrapParens(as.Rhs[0]).(*ast.SelectorExpr); okL && okR {
						if rID, okRecv := unwrapParens(sel.X).(*ast.Ident); okRecv && rID.Name == runRecv && sel.Sel.Name != "" && sel.Sel.Name != depsField && !ast.IsExported(sel.Sel.Name) {
							if fType, okFld := unwrapParens(mFields[sel.Sel.Name]).(*ast.Ident); okFld && fType.Name == "int" {
								exitCodeField = sel.Sel.Name
								exitCodeDefer = ds
							}
						}
					}
				}
			}
		}
	}
	if exitCodeField != "" {
		// Ensure exitCodeField is never written or address-taken outside runFn, and never address-taken inside runFn.
		badExitCode := false
		for _, f := range files {
			for _, decl := range f.Decls {
				ast.Inspect(decl, func(n ast.Node) bool {
					if badExitCode || n == nil {
						return false
					}
					switch node := n.(type) {
					case *ast.UnaryExpr:
						if node.Op == token.AND {
							if sel, ok := unwrapParens(node.X).(*ast.SelectorExpr); ok && sel.Sel.Name == exitCodeField {
								badExitCode = true
								return false
							}
						}
					case *ast.FuncLit:
						if decl == runFn {
							ast.Inspect(node.Body, func(fnN ast.Node) bool {
								if badExitCode || fnN == nil {
									return false
								}
								switch inner := fnN.(type) {
								case *ast.AssignStmt:
									for _, lhs := range inner.Lhs {
										if sel, ok := unwrapParens(lhs).(*ast.SelectorExpr); ok && sel.Sel.Name == exitCodeField {
											badExitCode = true
											return false
										}
									}
								case *ast.RangeStmt:
									for _, lhs := range []ast.Expr{inner.Key, inner.Value} {
										if lhs != nil {
											if sel, ok := unwrapParens(lhs).(*ast.SelectorExpr); ok && sel.Sel.Name == exitCodeField {
												badExitCode = true
												return false
											}
										}
									}
								}
								return true
							})
						}
					case *ast.AssignStmt:
						if decl != runFn {
							for _, lhs := range node.Lhs {
								if sel, ok := unwrapParens(lhs).(*ast.SelectorExpr); ok && sel.Sel.Name == exitCodeField {
									badExitCode = true
									return false
								}
							}
						}
					case *ast.RangeStmt:
						for _, lhs := range []ast.Expr{node.Key, node.Value} {
							if lhs != nil {
								if sel, ok := unwrapParens(lhs).(*ast.SelectorExpr); ok && sel.Sel.Name == exitCodeField {
									badExitCode = true
									return false
								}
							}
						}
					case *ast.IncDecStmt:
						if sel, ok := unwrapParens(node.X).(*ast.SelectorExpr); ok && sel.Sel.Name == exitCodeField {
							badExitCode = true
							return false
						}
					case *ast.KeyValueExpr:
						if kID, ok := unwrapParens(node.Key).(*ast.Ident); ok && kID.Name == exitCodeField {
							badExitCode = true
							return false
						}
					}
					return true
				})
			}
		}
		if badExitCode {
			return false
		}
	}

	// Build function/method graph over testing declarations:
	// - runnerDecl: seeded by .F / .Fn callback selectors and canonical runner names, closed backwards over callers.
	// - forward closures for os.Exit reachability auditing across per-case runners, core test/bench/fuzz runners,
	//   example runners, and active testlog lifecycle helpers.
	allDecls := []*ast.FuncDecl{}
	declByName := map[string][]*ast.FuncDecl{}
	for _, f := range files {
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				allDecls = append(allDecls, fn)
				declByName[fn.Name.Name] = append(declByName[fn.Name.Name], fn)
			}
		}
	}
	collectDirectCallees := func(nodes []ast.Node, excludeSels map[*ast.SelectorExpr]bool) []*ast.FuncDecl {
		seen := map[*ast.FuncDecl]bool{}
		var out []*ast.FuncDecl
		var walk func(n ast.Node)
		walk = func(n ast.Node) {
			if n == nil {
				return
			}
			switch node := n.(type) {
			case *ast.ValueSpec:
				if node.Type != nil {
					walk(node.Type)
				}
				for _, v := range node.Values {
					walk(v)
				}
			case *ast.KeyValueExpr:
				walk(node.Value)
			case *ast.SelectorExpr:
				if !excludeSels[node] {
					for _, target := range declByName[node.Sel.Name] {
						if target.Recv != nil && target != runFn && !seen[target] {
							seen[target] = true
							out = append(out, target)
						}
					}
				}
				walk(node.X)
			case *ast.Ident:
				for _, target := range declByName[node.Name] {
					if target.Recv == nil && target != mainStart && !seen[target] {
						seen[target] = true
						out = append(out, target)
					}
				}
			default:
				ast.Inspect(node, func(ch ast.Node) bool {
					if ch == node {
						return true
					}
					walk(ch)
					return false
				})
			}
		}
		for _, root := range nodes {
			walk(root)
		}
		return out
	}
	forwardClosure := func(seeds map[*ast.FuncDecl]bool, excludeSels map[*ast.SelectorExpr]bool) map[*ast.FuncDecl]bool {
		reached := map[*ast.FuncDecl]bool{}
		var queue []*ast.FuncDecl
		for fn := range seeds {
			if fn != nil && fn.Body != nil && !reached[fn] {
				reached[fn] = true
				queue = append(queue, fn)
			}
		}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, callee := range collectDirectCallees([]ast.Node{cur.Body}, excludeSels) {
				if !reached[callee] {
					reached[callee] = true
					queue = append(queue, callee)
				}
			}
		}
		return reached
	}

	seedRunnerNames := map[string]bool{
		"tRunner": true, "fRunner": true, "run1": true, "runN": true,
		"runTests": true, "runBenchmarks": true, "runExamples": true,
		"runFuzzTests": true, "runFuzzing": true,
		"RunTests": true, "RunBenchmarks": true, "RunExamples": true, "Benchmark": true,
	}
	perCaseExecSeedNames := map[string]bool{
		"tRunner": true, "fRunner": true, "run1": true, "runN": true,
		"Loop": true, "loopSlow": true, "ResetTimer": true, "StartTimer": true, "StopTimer": true,
	}
	coreTestBenchFuzzSeedNames := map[string]bool{
		"tRunner": true, "fRunner": true, "run1": true, "runN": true,
		"Loop": true, "loopSlow": true, "ResetTimer": true, "StartTimer": true, "StopTimer": true,
		"runTests": true, "runBenchmarks": true, "runFuzzTests": true, "runFuzzing": true,
		"RunTests": true, "RunBenchmarks": true, "Benchmark": true,
	}
	paramsMentionIdent := func(fl *ast.FieldList, target string) bool {
		if fl == nil {
			return false
		}
		hit := false
		for _, fld := range fl.List {
			ast.Inspect(fld.Type, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && id.Name == target {
					hit = true
					return false
				}
				return true
			})
		}
		return hit
	}

	runnerDecl := map[*ast.FuncDecl]bool{}
	perCaseExecSeeds := map[*ast.FuncDecl]bool{}
	coreTestBenchFuzzSeeds := map[*ast.FuncDecl]bool{}
	declCallees := map[*ast.FuncDecl][]*ast.FuncDecl{}
	for _, fn := range allDecls {
		if fn != runFn {
			if seedRunnerNames[fn.Name.Name] {
				runnerDecl[fn] = true
			}
			if perCaseExecSeedNames[fn.Name.Name] {
				perCaseExecSeeds[fn] = true
			}
			if coreTestBenchFuzzSeedNames[fn.Name.Name] {
				coreTestBenchFuzzSeeds[fn] = true
			}
		}
		hasFFnSel := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && (sel.Sel.Name == "F" || sel.Sel.Name == "Fn") {
				hasFFnSel = true
				return false
			}
			return true
		})
		if hasFFnSel && fn != runFn {
			runnerDecl[fn] = true
			if !paramsMentionIdent(fn.Type.Params, "InternalExample") {
				coreTestBenchFuzzSeeds[fn] = true
			}
		}
		declCallees[fn] = collectDirectCallees([]ast.Node{fn.Body}, nil)
	}
	for changed := true; changed; {
		changed = false
		for _, fn := range allDecls {
			if runnerDecl[fn] || fn == runFn {
				continue
			}
			for _, target := range declCallees[fn] {
				if runnerDecl[target] {
					runnerDecl[fn] = true
					changed = true
					break
				}
			}
		}
	}
	stmtCallsRunner := func(stmt ast.Stmt) bool {
		for _, target := range collectDirectCallees([]ast.Node{stmt}, nil) {
			if seedRunnerNames[target.Name.Name] || runnerDecl[target] {
				return true
			}
		}
		return false
	}

	exitSitesByFunc := map[*ast.FuncDecl][]testingExitSite{}
	for _, site := range osExitSites {
		if site.encFn == nil || site.encFn.Name.Name == "init" {
			return false
		}
		exitSitesByFunc[site.encFn] = append(exitSitesByFunc[site.encFn], site)
	}
	perCaseExecReachable := forwardClosure(perCaseExecSeeds, nil)
	for fn := range perCaseExecReachable {
		if len(exitSitesByFunc[fn]) > 0 {
			return false
		}
	}
	coreTestBenchFuzzReachable := forwardClosure(coreTestBenchFuzzSeeds, nil)
	allRunnerForwardReachable := forwardClosure(runnerDecl, nil)

	isBenignRunnerReachableExitSite := func(site testingExitSite) bool {
		idx := len(site.ancestors) - 1
		if idx < 4 || site.ancestors[idx] != site.call {
			return false
		}
		idx--
		for idx >= 0 {
			if _, isParen := site.ancestors[idx].(*ast.ParenExpr); !isParen {
				break
			}
			idx--
		}
		if idx < 3 {
			return false
		}
		es, okES := site.ancestors[idx].(*ast.ExprStmt)
		ifBlk, okIB := site.ancestors[idx-1].(*ast.BlockStmt)
		ifs, okIF := site.ancestors[idx-2].(*ast.IfStmt)
		parentBlk, okPB := site.ancestors[idx-3].(*ast.BlockStmt)
		if !okES || !okIB || !okIF || !okPB || unwrapParens(es.X) != site.call || ifs.Body != ifBlk || ifs.Else != nil || len(ifBlk.List) == 0 || ifBlk.List[len(ifBlk.List)-1] != es {
			return false
		}
		errVar := condChecksNonZeroErr(ifs.Cond)
		if errVar == "" {
			return false
		}
		hasOS := fileImportsOS[site.file]
		hasFmt := fileImportsFmt[site.file]
		for _, pre := range ifBlk.List[:len(ifBlk.List)-1] {
			if isBenignStderrDiagStmt(pre, hasOS, hasFmt) {
				continue
			}
			// Allow `if os.IsExist(errVar) { continue }` in temp-file open loop.
			if innerIf, okIn := pre.(*ast.IfStmt); okIn && innerIf.Init == nil && innerIf.Else == nil && hasOS && len(innerIf.Body.List) == 1 {
				if br, okBr := innerIf.Body.List[0].(*ast.BranchStmt); okBr && br.Tok == token.CONTINUE && br.Label == nil {
					if ieCall, okIEC := unwrapParens(innerIf.Cond).(*ast.CallExpr); okIEC && !ieCall.Ellipsis.IsValid() && len(ieCall.Args) == 1 {
						_, okSel := isSelectorBaseField(ieCall.Fun, "os", "IsExist")
						_, okArg := isIdentNamed(ieCall.Args[0], errVar)
						if okSel && okArg {
							continue
						}
					}
				}
			}
			return false
		}
		// Form 1: Pre-case filter/skip regex validation in unexported matcher constructor (`newMatcher`):
		// `if err := <ident>.verify(<arg0>, <p0>); err != nil { ... os.Exit(1) }`
		if ifs.Init != nil {
			if runnerDecl[site.encFn] || site.encFn.Recv != nil || ast.IsExported(site.encFn.Name.Name) || site.encFn.Type.Params == nil || site.encFn.Type.Results == nil || site.encFn.Type.Results.NumFields() != 1 {
				return false
			}
			fnParams := paramNamesFlat(site.encFn.Type.Params)
			if len(fnParams) != 4 || fnParams[0] == "" || fnParams[0] == "_" {
				return false
			}
			if _, isFT := unwrapParens(site.encFn.Type.Params.List[0].Type).(*ast.FuncType); !isFT {
				return false
			}
			initAs, okA := ifs.Init.(*ast.AssignStmt)
			if !okA || initAs.Tok != token.DEFINE || len(initAs.Lhs) != 1 || len(initAs.Rhs) != 1 {
				return false
			}
			if _, okLHS := isIdentNamed(initAs.Lhs[0], errVar); !okLHS {
				return false
			}
			vCall, okVC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
			if !okVC || vCall.Ellipsis.IsValid() || len(vCall.Args) != 2 || exprHasCallOrFuncLit(vCall.Args[0]) {
				return false
			}
			if _, okP0 := isIdentNamed(vCall.Args[1], fnParams[0]); !okP0 {
				return false
			}
			vSel, okVS := unwrapParens(vCall.Fun).(*ast.SelectorExpr)
			if !okVS || vSel.Sel.Name != "verify" {
				return false
			}
			if _, okBase := unwrapParens(vSel.X).(*ast.Ident); !okBase {
				return false
			}
			verifyDecls := declByName["verify"]
			if len(verifyDecls) == 0 {
				return false
			}
			for _, vd := range verifyDecls {
				if runnerDecl[vd] || len(exitSitesByFunc[vd]) > 0 {
					return false
				}
			}
			return true
		}
		// Form 2: Example stdout-capture OS failure (`os.Pipe`, `os.OpenFile`, `io.Copy`, `<file>.Seek`),
		// prohibited anywhere reachable from core Test/Benchmark/Fuzz runners.
		if coreTestBenchFuzzReachable[site.encFn] {
			return false
		}
		ifIdx := slices.Index(parentBlk.List, ast.Stmt(ifs))
		if ifIdx <= 0 {
			return false
		}
		for pos := ifIdx - 1; pos >= 0; pos-- {
			stPrev := parentBlk.List[pos]
			if as, okA := stPrev.(*ast.AssignStmt); okA && (as.Tok == token.DEFINE || as.Tok == token.ASSIGN) && len(as.Lhs) >= 2 && len(as.Rhs) == 1 {
				if _, okLast := isIdentNamed(as.Lhs[len(as.Lhs)-1], errVar); okLast {
					if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: parentBlk.List[pos+1 : ifIdx]}, map[string]bool{errVar: true}) {
						return false
					}
					opCall, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
					if !okC || opCall.Ellipsis.IsValid() {
						return false
					}
					if _, okPipe := isSelectorBaseField(opCall.Fun, "os", "Pipe"); okPipe && hasOS && len(opCall.Args) == 0 {
						return true
					}
					if _, okOF := isSelectorBaseField(opCall.Fun, "os", "OpenFile"); okOF && hasOS && len(opCall.Args) == 3 {
						return true
					}
					if _, okCopy := isSelectorBaseField(opCall.Fun, "io", "Copy"); okCopy && fileImportsIO[site.file] && len(opCall.Args) == 2 {
						return true
					}
					if sSel, okSeek := unwrapParens(opCall.Fun).(*ast.SelectorExpr); okSeek && sSel.Sel.Name == "Seek" && len(opCall.Args) == 2 && !exprHasCallOrFuncLit(opCall.Args[0]) && !exprHasCallOrFuncLit(opCall.Args[1]) {
						if _, okRecv := unwrapParens(sSel.X).(*ast.Ident); okRecv {
							return true
						}
					}
					return false
				}
			}
			if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: []ast.Stmt{stPrev}}, map[string]bool{errVar: true}) {
				return false
			}
		}
		return false
	}

	for fn := range allRunnerForwardReachable {
		for _, site := range exitSitesByFunc[fn] {
			if !isBenignRunnerReachableExitSite(site) {
				return false
			}
		}
	}

	stmtsHaveNoNonRunnerHelperExit := func(stmts []ast.Stmt, excludeSels map[*ast.SelectorExpr]bool) bool {
		seeds := map[*ast.FuncDecl]bool{}
		nodes := make([]ast.Node, 0, len(stmts))
		for _, s := range stmts {
			if s != nil {
				nodes = append(nodes, s)
			}
		}
		for _, callee := range collectDirectCallees(nodes, excludeSels) {
			if !runnerDecl[callee] {
				seeds[callee] = true
			}
		}
		for fn := range forwardClosure(seeds, excludeSels) {
			if !runnerDecl[fn] && len(exitSitesByFunc[fn]) > 0 {
				return false
			}
		}
		return true
	}

	bodyHasGoexit := func(body *ast.BlockStmt) bool {
		hit := false
		ast.Inspect(body, func(n ast.Node) bool {
			if hit || n == nil {
				return false
			}
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Goexit" {
				hit = true
				return false
			}
			return true
		})
		return hit
	}
	if bodyHasGoexit(runFn.Body) {
		return false
	}

	// Find flag.Parse() or if !flag.Parsed() { flag.Parse() } at top level of (*M).Run.
	runFile := funcFile[runFn]
	if !fileImportsFlag[runFile] {
		return false
	}
	isFlagCall0 := func(expr ast.Expr, fnName string) bool {
		call, ok := unwrapParens(expr).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) != 0 {
			return false
		}
		sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != fnName {
			return false
		}
		pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
		return ok && pkgID.Name == "flag"
	}
	parseIdx := -1
	for i, stmt := range runFn.Body.List {
		if es, ok := stmt.(*ast.ExprStmt); ok && isFlagCall0(es.X, "Parse") {
			parseIdx = i
			break
		}
		if ifs, ok := stmt.(*ast.IfStmt); ok && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
			if u, okU := unwrapParens(ifs.Cond).(*ast.UnaryExpr); okU && u.Op == token.NOT && isFlagCall0(u.X, "Parsed") {
				if es, okE := ifs.Body.List[0].(*ast.ExprStmt); okE && isFlagCall0(es.X, "Parse") {
					parseIdx = i
					break
				}
			}
		}
	}
	if parseIdx < 0 {
		return false
	}

	// Validate pre-StartTestLog statements in (*M).Run:
	// - No runner calls and no unconditional top-level termination.
	// - Every ReturnStmt either returns a positive exit code (directly when exitCodeField == "",
	//   or preceded immediately by m.<exitCodeField> = <posIntLit> when exitCodeField != "")
	//   OR sits inside a post-Parse `if *<listFlag> != ""` block for a verified test.list flag.
	verifyRunPreStartSlice := func(limit int) bool {
		for idx, top := range runFn.Body.List[:limit] {
			if stmtAlwaysTerminates(top) || stmtCallsRunner(top) {
				return false
			}
			allowedZeroReturn := false
			if idx > parseIdx {
				if ifs, ok := top.(*ast.IfStmt); ok && ifs.Init == nil && ifs.Else == nil {
					if lf, ok2 := derefFlagNonEmptyCondIdent(ifs.Cond); ok2 && listFlagVars[lf] && !funcShadowsAnyIdent(runFn, map[string]bool{lf: true}) && verifyFlagInitCalledInMainStart(lf) && verifyFlagPtrIdentOnlyDereferenced(lf) {
						allowedZeroReturn = true
					}
				}
			}
			var checkPreBlock func(blk *ast.BlockStmt) bool
			checkPreBlock = func(blk *ast.BlockStmt) bool {
				if blk == nil {
					return true
				}
				for j, s := range blk.List {
					switch node := s.(type) {
					case *ast.ReturnStmt:
						if allowedZeroReturn {
							if exitCodeField != "" && len(node.Results) != 0 {
								return false
							}
							continue
						}
						if exitCodeField == "" {
							if len(node.Results) != 1 || exprHasCallOrFuncLit(node.Results[0]) || !isPositiveIntLit(node.Results[0]) {
								return false
							}
						} else {
							if len(node.Results) != 0 || j == 0 {
								return false
							}
							prevAs, ok := blk.List[j-1].(*ast.AssignStmt)
							if !ok || prevAs.Tok != token.ASSIGN || len(prevAs.Lhs) != 1 || len(prevAs.Rhs) != 1 || exprHasCallOrFuncLit(prevAs.Rhs[0]) || !isPositiveIntLit(prevAs.Rhs[0]) {
								return false
							}
							sel, ok := unwrapParens(prevAs.Lhs[0]).(*ast.SelectorExpr)
							if !ok || sel.Sel.Name != exitCodeField {
								return false
							}
							if rID, ok2 := unwrapParens(sel.X).(*ast.Ident); !ok2 || rID.Name != runRecv {
								return false
							}
						}
					case *ast.IfStmt:
						if !checkPreBlock(node.Body) {
							return false
						}
						switch el := node.Else.(type) {
						case nil:
						case *ast.BlockStmt:
							if !checkPreBlock(el) {
								return false
							}
						case *ast.IfStmt:
							if !checkPreBlock(&ast.BlockStmt{List: []ast.Stmt{el}}) {
								return false
							}
						default:
							return false
						}
					case *ast.BlockStmt:
						if !checkPreBlock(node) {
							return false
						}
					case *ast.GoStmt:
						return false
					case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
						hasRetOrGo := false
						ast.Inspect(node, func(n ast.Node) bool {
							if _, isFL := n.(*ast.FuncLit); isFL {
								return false
							}
							switch n.(type) {
							case *ast.ReturnStmt, *ast.GoStmt:
								hasRetOrGo = true
								return false
							}
							return true
						})
						if hasRetOrGo {
							return false
						}
					}
				}
				return true
			}
			if topIf, ok := top.(*ast.IfStmt); ok {
				if !checkPreBlock(topIf.Body) {
					return false
				}
				if topIf.Else != nil {
					if !checkPreBlock(&ast.BlockStmt{List: []ast.Stmt{topIf.Else}}) {
						return false
					}
				}
			} else {
				hasRetOrGo := false
				ast.Inspect(top, func(n ast.Node) bool {
					if _, isFL := n.(*ast.FuncLit); isFL {
						return false
					}
					switch n.(type) {
					case *ast.ReturnStmt, *ast.GoStmt:
						hasRetOrGo = true
						return false
					}
					return true
				})
				if hasRetOrGo {
					return false
				}
			}
		}
		return true
	}

	verifyOnlyAllowedDefersInRun := func(allowedAfterDefer *ast.DeferStmt) bool {
		badDeferOrGo := false
		ast.Inspect(runFn.Body, func(n ast.Node) bool {
			if badDeferOrGo || n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.DeferStmt:
				if node != exitCodeDefer && node != allowedAfterDefer {
					badDeferOrGo = true
					return false
				}
			case *ast.GoStmt:
				badDeferOrGo = true
				return false
			}
			return true
		})
		return !badDeferOrGo
	}

	// Mode 1: Inline StartTestLog and StopTestLog directly in (*M).Run.
	if st.fn == runFn && sp.fn == runFn {
		if !verifyOnlyAllowedDefersInRun(nil) {
			return false
		}
		startTopIdx := slices.Index(runFn.Body.List, st.topStmt)
		stopTopIdx := slices.Index(runFn.Body.List, sp.topStmt)
		if startTopIdx < 0 || stopTopIdx < startTopIdx || parseIdx >= startTopIdx {
			return false
		}
		if !verifyRunPreStartSlice(startTopIdx) {
			return false
		}
		checkNoRetOrGo := func(stmts []ast.Stmt) bool {
			for _, mid := range stmts {
				if stmtAlwaysTerminates(mid) {
					return false
				}
				hasRetOrGo := false
				ast.Inspect(mid, func(n ast.Node) bool {
					switch n.(type) {
					case *ast.ReturnStmt, *ast.GoStmt:
						hasRetOrGo = true
						return false
					}
					return true
				})
				if hasRetOrGo {
					return false
				}
			}
			return true
		}
		if st.topStmt == sp.topStmt {
			if st.declBlock != sp.parentBlk {
				return false
			}
			for _, pre := range st.declBlock.List[:st.declTargetIdx] {
				if stmtCallsRunner(pre) {
					return false
				}
			}
			if !checkNoRetOrGo(st.declBlock.List[st.declTargetIdx+1 : sp.stmtPos]) {
				return false
			}
			if !stmtsHaveNoNonRunnerHelperExit(st.declBlock.List[st.declTargetIdx+1:], nil) {
				return false
			}
			for _, post := range sp.parentBlk.List[sp.stmtPos:] {
				if stmtCallsRunner(post) {
					return false
				}
			}
			if !slices.ContainsFunc(sp.parentBlk.List[sp.afterStopPos:], stmtAlwaysTerminates) {
				for _, post := range runFn.Body.List[stopTopIdx+1:] {
					if stmtCallsRunner(post) {
						return false
					}
				}
			}
		} else {
			if stmtCallsRunner(st.topStmt) || stmtCallsRunner(sp.topStmt) {
				return false
			}
			if !checkNoRetOrGo(runFn.Body.List[startTopIdx+1 : stopTopIdx]) {
				return false
			}
			if !stmtsHaveNoNonRunnerHelperExit(st.declBlock.List[st.declTargetIdx+1:], nil) || !stmtsHaveNoNonRunnerHelperExit(runFn.Body.List[startTopIdx+1:stopTopIdx+1], nil) {
				return false
			}
			for _, post := range runFn.Body.List[stopTopIdx+1:] {
				if stmtCallsRunner(post) {
					return false
				}
			}
		}
		return true
	}

	// Mode 2: Split lifecycle via unexported *M methods: m.<before>() + defer m.<after>() in (*M).Run.
	if st.fn == runFn || sp.fn == runFn || st.fn == sp.fn {
		return false
	}
	beforeName := st.fn.Name.Name
	stopMethodName := sp.fn.Name.Name
	if ast.IsExported(beforeName) || ast.IsExported(stopMethodName) || mMethods[beforeName] != st.fn || mMethods[stopMethodName] != sp.fn {
		return false
	}
	isZeroArgVoidMMethod := func(fn *ast.FuncDecl) bool {
		return fn != nil && fn.Body != nil && recvVarName(fn) != "" &&
			(fn.Type.Params == nil || fn.Type.Params.NumFields() == 0) &&
			(fn.Type.Results == nil || fn.Type.Results.NumFields() == 0)
	}
	if !isZeroArgVoidMMethod(st.fn) || !isZeroArgVoidMMethod(sp.fn) {
		return false
	}

	beforeIdx := -1
	var afterName string
	var afterDeferStmt *ast.DeferStmt
	var beforeCallSel, afterDeferSel *ast.SelectorExpr
	for i := 0; i+1 < len(runFn.Body.List); i++ {
		es, ok1 := runFn.Body.List[i].(*ast.ExprStmt)
		ds, ok2 := runFn.Body.List[i+1].(*ast.DeferStmt)
		if !ok1 || !ok2 {
			continue
		}
		bCall, okB := unwrapParens(es.X).(*ast.CallExpr)
		if !okB || bCall.Ellipsis.IsValid() || len(bCall.Args) != 0 || ds.Call.Ellipsis.IsValid() || len(ds.Call.Args) != 0 {
			continue
		}
		bSel, okBS := unwrapParens(bCall.Fun).(*ast.SelectorExpr)
		aSel, okAS := unwrapParens(ds.Call.Fun).(*ast.SelectorExpr)
		if !okBS || !okAS || bSel.Sel.Name != beforeName {
			continue
		}
		bRecv, okBR := unwrapParens(bSel.X).(*ast.Ident)
		aRecv, okAR := unwrapParens(aSel.X).(*ast.Ident)
		if okBR && okAR && bRecv.Name == runRecv && aRecv.Name == runRecv {
			beforeIdx = i
			afterName = aSel.Sel.Name
			afterDeferStmt = ds
			beforeCallSel = bSel
			afterDeferSel = aSel
			break
		}
	}
	if beforeIdx < 0 || parseIdx >= beforeIdx || ast.IsExported(afterName) {
		return false
	}
	afterFn := mMethods[afterName]
	if !isZeroArgVoidMMethod(afterFn) || afterFn == runFn || afterFn == st.fn {
		return false
	}
	if funcShadowsAnyIdent(afterFn, pkgReserved) || bodyHasControlFlowOrRecoverBypass(afterFn.Body) {
		return false
	}
	if bodyHasGoexit(st.fn.Body) || bodyHasGoexit(afterFn.Body) || bodyHasGoexit(sp.fn.Body) {
		return false
	}
	if !verifyOnlyAllowedDefersInRun(afterDeferStmt) || !verifyRunPreStartSlice(beforeIdx) {
		return false
	}

	// Verify st.fn (before): no runners, no Defer/Go, no top-level termination before StartTestLog,
	// pre-StartTestLog returns only inside `if ... err != nil`, and no returns at/after StartTestLog.
	startInBeforeIdx := slices.Index(st.fn.Body.List, st.topStmt)
	if startInBeforeIdx < 0 || stmtCallsRunner(&ast.BlockStmt{List: st.fn.Body.List}) {
		return false
	}
	hasDeferOrGo := func(body *ast.BlockStmt) bool {
		hit := false
		ast.Inspect(body, func(n ast.Node) bool {
			if hit || n == nil {
				return false
			}
			switch n.(type) {
			case *ast.DeferStmt, *ast.GoStmt:
				hit = true
				return false
			}
			return true
		})
		return hit
	}
	if hasDeferOrGo(st.fn.Body) || hasDeferOrGo(afterFn.Body) || hasDeferOrGo(sp.fn.Body) {
		return false
	}
	for _, pre := range st.fn.Body.List[:startInBeforeIdx] {
		if stmtAlwaysTerminates(pre) {
			return false
		}
		var outerOptFlagOK bool
		if topIf, ok := pre.(*ast.IfStmt); ok && topIf.Init == nil && topIf.Else == nil {
			if fg, ok2 := derefFlagNonEmptyCondIdent(topIf.Cond); ok2 && emptyDefaultStringFlags[fg] && !funcShadowsAnyIdent(st.fn, map[string]bool{fg: true}) && verifyFlagInitCalledInMainStart(fg) && verifyFlagPtrIdentOnlyDereferenced(fg) {
				outerOptFlagOK = true
			}
		}
		var checkBeforeStmt func(s ast.Stmt, underErrIf bool) bool
		checkBeforeStmt = func(s ast.Stmt, underErrIf bool) bool {
			switch node := s.(type) {
			case nil, *ast.EmptyStmt, *ast.DeclStmt, *ast.AssignStmt, *ast.ExprStmt, *ast.IncDecStmt:
				hasLit := false
				ast.Inspect(s, func(n ast.Node) bool {
					if _, ok := n.(*ast.FuncLit); ok {
						hasLit = true
						return false
					}
					return true
				})
				return !hasLit
			case *ast.ReturnStmt:
				return outerOptFlagOK && underErrIf && len(node.Results) == 0
			case *ast.BlockStmt:
				for _, child := range node.List {
					if !checkBeforeStmt(child, underErrIf) {
						return false
					}
				}
				return true
			case *ast.IfStmt:
				isErrIf := underErrIf || (node.Else == nil && condChecksNonZeroErr(node.Cond) != "")
				if !checkBeforeStmt(node.Body, isErrIf) {
					return false
				}
				if node.Else != nil && !checkBeforeStmt(node.Else, false) {
					return false
				}
				return true
			default:
				return false
			}
		}
		if !checkBeforeStmt(pre, false) {
			return false
		}
	}
	for _, post := range st.fn.Body.List[startInBeforeIdx:] {
		hasRet := false
		ast.Inspect(post, func(n ast.Node) bool {
			if _, ok := n.(*ast.ReturnStmt); ok {
				hasRet = true
				return false
			}
			return true
		})
		if hasRet {
			return false
		}
	}

	// Verify afterFn -> sp.fn wiring and sp.fn head position.
	if stmtCallsRunner(&ast.BlockStmt{List: afterFn.Body.List}) || stmtCallsRunner(&ast.BlockStmt{List: sp.fn.Body.List}) {
		return false
	}
	if len(sp.fn.Body.List) == 0 || sp.fn.Body.List[0] != sp.topStmt || sp.stmtPos != 0 {
		return false
	}
	var spCallSel *ast.SelectorExpr
	var onceField string
	var onceSelIdent *ast.Ident
	if afterFn != sp.fn {
		if len(afterFn.Body.List) == 0 {
			return false
		}
		afterRecv := recvVarName(afterFn)
		s0, ok := afterFn.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return false
		}
		c0, ok := unwrapParens(s0.X).(*ast.CallExpr)
		if !ok || c0.Ellipsis.IsValid() {
			return false
		}
		sel0, ok := unwrapParens(c0.Fun).(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if rID, okR := unwrapParens(sel0.X).(*ast.Ident); okR && rID.Name == afterRecv && sel0.Sel.Name == stopMethodName && len(c0.Args) == 0 {
			spCallSel = sel0
		} else if sel0.Sel.Name == "Do" && len(c0.Args) == 1 {
			fSel, okFS := unwrapParens(sel0.X).(*ast.SelectorExpr)
			if !okFS {
				return false
			}
			rID, okR := unwrapParens(fSel.X).(*ast.Ident)
			fl, okFL := unwrapParens(c0.Args[0]).(*ast.FuncLit)
			if !okR || !okFL || rID.Name != afterRecv || ast.IsExported(fSel.Sel.Name) || (fl.Type.Params != nil && fl.Type.Params.NumFields() != 0) || (fl.Type.Results != nil && fl.Type.Results.NumFields() != 0) || fl.Body == nil || len(fl.Body.List) != 1 {
				return false
			}
			innerES, okIE := fl.Body.List[0].(*ast.ExprStmt)
			if !okIE {
				return false
			}
			innerCall, okIC := unwrapParens(innerES.X).(*ast.CallExpr)
			if !okIC || innerCall.Ellipsis.IsValid() || len(innerCall.Args) != 0 {
				return false
			}
			innerSel, okIS := unwrapParens(innerCall.Fun).(*ast.SelectorExpr)
			if !okIS || innerSel.Sel.Name != stopMethodName {
				return false
			}
			if innerRecv, okIR := unwrapParens(innerSel.X).(*ast.Ident); !okIR || innerRecv.Name != afterRecv {
				return false
			}
			// Verify onceField has type sync.Once on M.
			onceTypeSel, okOT := unwrapParens(mFields[fSel.Sel.Name]).(*ast.SelectorExpr)
			if !okOT || onceTypeSel.Sel.Name != "Once" || !fileImportsSync[mStructFile] {
				return false
			}
			if syncID, okSID := unwrapParens(onceTypeSel.X).(*ast.Ident); !okSID || syncID.Name != "sync" {
				return false
			}
			onceField = fSel.Sel.Name
			onceSelIdent = fSel.Sel
			spCallSel = innerSel
		} else {
			return false
		}
	}

	// Verify call-site and field-reference isolation across the entire testing package for:
	// - onceField (only M struct field decl and afterFn's single m.<onceField>.Do)
	// - beforeName (only m.<before>() at runFn.Body.List[beforeIdx])
	// - stopMethodName when afterFn != sp.fn (only m.<sp>() at stmt 0 of afterFn)
	// - afterName (only defer m.<after>() in runFn, plus optional panic-terminating alarm FuncLit
	//   inside an unexported *M method called exclusively in runFn.Body.List[beforeIdx+2:])
	var extraAfterHelperNames = map[string]bool{}
	alarmAfterSels := map[*ast.SelectorExpr]bool{}
	isolatedOK := true
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if !isolatedOK || n == nil {
				return false
			}
			if id, isID := n.(*ast.Ident); isID && onceField != "" && id.Name == onceField {
				if id != mFieldIdents[onceField] && id != onceSelIdent {
					isolatedOK = false
					return false
				}
			}
			sel, isSel := n.(*ast.SelectorExpr)
			if !isSel {
				return true
			}
			switch sel.Sel.Name {
			case beforeName:
				if sel != beforeCallSel {
					isolatedOK = false
					return false
				}
			case stopMethodName:
				if afterFn != sp.fn && sel != spCallSel {
					isolatedOK = false
					return false
				}
			case afterName:
				if sel == afterDeferSel {
					return true
				}
				// Secondary call allowed only as stmt 0 of a panic-terminating FuncLit inside an unexported *M method.
				encFn, anc := findEnclosingFuncAndAncestors(f, sel)
				if encFn == nil || encFn == runFn || encFn == st.fn || encFn == afterFn || encFn == sp.fn || ast.IsExported(encFn.Name.Name) || mMethods[encFn.Name.Name] != encFn || funcShadowsAnyIdent(encFn, pkgReserved) {
					isolatedOK = false
					return false
				}
				hRecv := recvVarName(encFn)
				if hRecv == "" {
					isolatedOK = false
					return false
				}
				rID, okR := unwrapParens(sel.X).(*ast.Ident)
				if !okR || rID.Name != hRecv {
					isolatedOK = false
					return false
				}
				// Locate enclosing FuncLit in anc: ... -> FuncLit -> BlockStmt -> ExprStmt -> CallExpr -> sel
				if len(anc) < 5 {
					isolatedOK = false
					return false
				}
				callNode, ok1 := anc[len(anc)-2].(*ast.CallExpr)
				esNode, ok2 := anc[len(anc)-3].(*ast.ExprStmt)
				blkNode, ok3 := anc[len(anc)-4].(*ast.BlockStmt)
				flNode, ok4 := anc[len(anc)-5].(*ast.FuncLit)
				if !ok1 || !ok2 || !ok3 || !ok4 || callNode.Ellipsis.IsValid() || len(callNode.Args) != 0 || unwrapParens(callNode.Fun) != sel || unwrapParens(esNode.X) != callNode || flNode.Body != blkNode || len(blkNode.List) < 2 || blkNode.List[0] != esNode {
					isolatedOK = false
					return false
				}
				// Verify FuncLit body has no ReturnStmt, LabeledStmt, BranchStmt, DeferStmt, ForStmt, or recover,
				// and ends with unconditional panic(...).
				badFL := false
				ast.Inspect(blkNode, func(fnNode ast.Node) bool {
					if badFL || fnNode == nil {
						return false
					}
					if innerFL, isFL := fnNode.(*ast.FuncLit); isFL {
						badFL = innerFL != flNode
						return false
					}
					switch x := fnNode.(type) {
					case *ast.ReturnStmt, *ast.LabeledStmt, *ast.BranchStmt, *ast.DeferStmt, *ast.ForStmt, *ast.SelectStmt:
						badFL = true
						return false
					case *ast.CallExpr:
						if cid, ok := unwrapParens(x.Fun).(*ast.Ident); ok && cid.Name == "recover" {
							badFL = true
							return false
						}
					}
					return true
				})
				if badFL || funcLitShadowsAnyIdent(flNode, map[string]bool{"panic": true}) {
					isolatedOK = false
					return false
				}
				lastES, okLast := blkNode.List[len(blkNode.List)-1].(*ast.ExprStmt)
				if !okLast {
					isolatedOK = false
					return false
				}
				pCall, okPC := unwrapParens(lastES.X).(*ast.CallExpr)
				if !okPC || pCall.Ellipsis.IsValid() || len(pCall.Args) != 1 {
					isolatedOK = false
					return false
				}
				if pID, okPID := unwrapParens(pCall.Fun).(*ast.Ident); !okPID || pID.Name != "panic" {
					isolatedOK = false
					return false
				}
				extraAfterHelperNames[encFn.Name.Name] = true
				alarmAfterSels[sel] = true
			}
			return true
		})
		if !isolatedOK {
			return false
		}
	}

	// Any helper method containing a secondary m.<after>() panic FuncLit (e.g. startAlarm)
	// may only be referenced inside runFn.Body.List[beforeIdx+2:].
	if len(extraAfterHelperNames) > 0 {
		allowedHelperSels := map[*ast.SelectorExpr]bool{}
		for _, postStmt := range runFn.Body.List[beforeIdx+2:] {
			ast.Inspect(postStmt, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok && !call.Ellipsis.IsValid() && len(call.Args) == 0 {
					if sel, ok2 := unwrapParens(call.Fun).(*ast.SelectorExpr); ok2 && extraAfterHelperNames[sel.Sel.Name] {
						if rID, ok3 := unwrapParens(sel.X).(*ast.Ident); ok3 && rID.Name == runRecv {
							allowedHelperSels[sel] = true
						}
					}
				}
				return true
			})
		}
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				if !isolatedOK || n == nil {
					return false
				}
				if sel, ok := n.(*ast.SelectorExpr); ok && extraAfterHelperNames[sel.Sel.Name] && !allowedHelperSels[sel] {
					isolatedOK = false
					return false
				}
				return true
			})
		}
		if !isolatedOK {
			return false
		}
	}

	// Verify Mode 2 os.Exit containment across active testlog lifecycle:
	// - Direct os.Exit in st.fn (`before`) allowed ONLY in st.openExits or before startInBeforeIdx.
	// - Zero direct os.Exit in afterFn (when afterFn != sp.fn) and extraAfterHelperNames.
	// - Direct os.Exit inside sp.fn.Body.List[0] (`if *testlog != ""`) allowed ONLY in sp.stopExit or closeExits.
	// - Zero os.Exit in any non-runner helper reachable from active lifecycle statement slices.
	ancestorsTouchSlice := func(ancestors []ast.Node, slice []ast.Stmt) bool {
		for _, anc := range ancestors {
			if s, ok := anc.(ast.Stmt); ok && slices.Contains(slice, s) {
				return true
			}
		}
		return false
	}
	for _, site := range exitSitesByFunc[st.fn] {
		if !st.openExits[site.call] && !ancestorsTouchSlice(site.ancestors, st.fn.Body.List[:startInBeforeIdx]) {
			return false
		}
	}
	if afterFn != sp.fn && len(exitSitesByFunc[afterFn]) > 0 {
		return false
	}
	for helperName := range extraAfterHelperNames {
		if len(exitSitesByFunc[mMethods[helperName]]) > 0 {
			return false
		}
	}
	for _, site := range exitSitesByFunc[sp.fn] {
		if ancestorsTouchSlice(site.ancestors, sp.fn.Body.List[:1]) && site.call != sp.stopExit && !closeExits[site.call] {
			return false
		}
	}
	excludeActiveSels := map[*ast.SelectorExpr]bool{}
	if afterDeferSel != nil {
		excludeActiveSels[afterDeferSel] = true
	}
	if spCallSel != nil {
		excludeActiveSels[spCallSel] = true
	}
	for sel := range alarmAfterSels {
		excludeActiveSels[sel] = true
	}
	if !stmtsHaveNoNonRunnerHelperExit(st.declBlock.List[st.declTargetIdx+1:], excludeActiveSels) ||
		!stmtsHaveNoNonRunnerHelperExit(st.fn.Body.List[startInBeforeIdx+1:], excludeActiveSels) ||
		!stmtsHaveNoNonRunnerHelperExit(runFn.Body.List[beforeIdx+1:], excludeActiveSels) ||
		!stmtsHaveNoNonRunnerHelperExit(sp.fn.Body.List[:1], excludeActiveSels) {
		return false
	}
	if afterFn != sp.fn && !stmtsHaveNoNonRunnerHelperExit(afterFn.Body.List, excludeActiveSels) {
		return false
	}

	return true
}
