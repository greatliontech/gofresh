package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
	"maps"
	"slices"
)

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
