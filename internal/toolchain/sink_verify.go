package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
	"maps"
)

func verifyTestingWriterFunc(recvType string, fn *ast.FuncDecl, binding testingWriterBinding, topFuncs map[string]*ast.FuncDecl, typeMethods map[string]map[string]*ast.FuncDecl, k *packageInactiveKernel, reqGates map[string]bool, visiting map[string]bool) bool {
	if fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.Results == nil || binding.sliceVar == "" {
		return false
	}
	writerReserved := map[string]bool{
		"len": true, "append": true, "make": true, "copy": true, "clear": true,
		"uintptr": true, "int": true, "byte": true, "nil": true, "error": true,
		"unsafe": true, "syscall": true, "os": true,
	}
	if funcShadowsAnyIdent(fn, writerReserved) {
		return false
	}
	numResults := fn.Type.Results.NumFields()
	if (numResults != 1 && (numResults != 2 || !firstResultIsInt(fn.Type.Results))) || !funcReturnsErrorLast(fn.Type) {
		return false
	}
	prunedStmts := fn.Body.List
	var prunedDeadNodes []ast.Node
	if k != nil {
		prunedStmts, _ = k.pruneBlockStmts(fn.Body.List, fn, nil, reqGates, &prunedDeadNodes)
	}
	cfg, okCFG := buildStmtCFG(prunedStmts)
	if !okCFG || !cfg.everyPathReturns() {
		return false
	}
	visitKey := recvType + "." + fn.Name.Name + fmt.Sprintf("|%s|%v|%v|%v|%v|%v", binding.sliceVar, sortedKeys(binding.fileFields), sortedKeys(binding.fdFields), sortedKeys(binding.fileVars), sortedKeys(binding.fdVars), sortedKeys(binding.emptyVars))
	if visiting[visitKey] {
		return false
	}
	visiting[visitKey] = true
	defer delete(visiting, visitKey)

	prunedBody := &ast.BlockStmt{List: prunedStmts}
	protectedSinks := map[string]bool{}
	maps.Copy(protectedSinks, binding.fileVars)
	maps.Copy(protectedSinks, binding.fdVars)
	maps.Copy(protectedSinks, binding.emptyVars)
	if recv := recvVarName(fn); recv != "" {
		protectedSinks[recv] = true
		if !blockOnlySelectsOnIdent(prunedBody, recv) {
			return false
		}
	}
	if bodyMutatesOrTakesAddrOfAny(prunedBody, protectedSinks) {
		return false
	}

	sliceParam := binding.sliceVar
	namedErrResult := lastNamedResultIdent(fn.Type.Results)
	namedCountResult := firstNamedIntResultIdent(fn.Type.Results)

	localClosures := map[string]*ast.FuncType{}
	verifiedClosureLits := map[*ast.FuncLit]bool{}
	allowedSliceZeroAmps := map[*ast.UnaryExpr]bool{}
	allowedPayloadCalls := map[*ast.CallExpr]bool{}
	allowedPayloadAssigns := map[*ast.AssignStmt]bool{}
	allowedPayloadValueSpecs := map[*ast.ValueSpec]bool{}
	allErrNames, allCountNames, allLoopCountNames := map[string]bool{}, map[string]bool{}, map[string]bool{}
	allChunkNames, allBufNames := map[string]bool{}, map[string]bool{}
	currentPayloadProtected := func() map[string]bool {
		m := map[string]bool{sliceParam: true}
		maps.Copy(m, allChunkNames)
		maps.Copy(m, allBufNames)
		maps.Copy(m, binding.emptyVars)
		return m
	}
	var namedErrBoundDirectly, everLatched bool
	outerVarDecls := map[string]bool{}
	if namedErrResult != "" {
		allErrNames[namedErrResult] = true
		outerVarDecls[namedErrResult] = true
	}
	if namedCountResult != "" {
		allCountNames[namedCountResult] = true
		outerVarDecls[namedCountResult] = true
	}

	var loopCountAliases, chunkVars, freshBufVars map[string]bool
	var bufChunkSource map[string]string
	var sawLenZeroExitReturn bool

	isProtectedIdent := func(name string) bool {
		return localClosures[name] != nil || allErrNames[name] || allCountNames[name] || allLoopCountNames[name] || allChunkNames[name] || allBufNames[name] || protectedSinks[name]
	}

	bindFreshErrIdent := func(expr ast.Expr) (string, bool) {
		id, ok := unwrapParens(expr).(*ast.Ident)
		if !ok || id.Name == "" || id.Name == "_" || id.Name == sliceParam || localClosures[id.Name] != nil || allCountNames[id.Name] || allLoopCountNames[id.Name] || allChunkNames[id.Name] || allBufNames[id.Name] || protectedSinks[id.Name] {
			return "", false
		}
		if id.Name == namedErrResult {
			if namedErrBoundDirectly || everLatched {
				return "", false
			}
			namedErrBoundDirectly = true
			return id.Name, true
		}
		if allErrNames[id.Name] {
			return "", false
		}
		allErrNames[id.Name] = true
		return id.Name, true
	}

	sinkSliceSource := func(expr ast.Expr, st writerPathState, mode writerBlockMode) (string, bool) {
		id, ok := unwrapParens(expr).(*ast.Ident)
		if !ok || id.Name == "" {
			return "", false
		}
		switch mode {
		case writerBlockPlain:
			if id.Name == sliceParam && !st.sliceParamMutated {
				return sliceParam, true
			}
		case writerBlockSliceLoop:
			if id.Name == sliceParam && !st.sliceAdvancedInLoop {
				return sliceParam, true
			}
		case writerBlockChunkLoop:
			if st.chunkAdvancedInLoop {
				return "", false
			}
			if id.Name == sliceParam || chunkVars[id.Name] {
				return id.Name, true
			}
			if srcChunk := bufChunkSource[id.Name]; srcChunk != "" {
				return srcChunk, true
			}
		}
		return "", false
	}

	isValidTailSinkCall := func(call *ast.CallExpr, wantResults int, st writerPathState, mode writerBlockMode) bool {
		if mode != writerBlockPlain || call.Ellipsis.IsValid() {
			return false
		}
		if id, isID := unwrapParens(call.Fun).(*ast.Ident); isID {
			if cType := localClosures[id.Name]; cType != nil && cType.Results.NumFields() == wantResults && len(call.Args) == 1 {
				if _, ok := sinkSliceSource(call.Args[0], st, mode); ok {
					allowedPayloadCalls[call] = true
					return true
				}
				return false
			}
		}
		if wantResults == 2 && isUnderlyingBoundWriteCall(fn, call, binding) {
			if _, ok := sinkSliceSource(call.Args[0], st, mode); ok {
				allowedPayloadCalls[call] = true
				return true
			}
			return false
		}
		helperRecv, helperDecl, isLocal := resolveLocalHelper(recvType, fn, call, topFuncs, typeMethods)
		if !isLocal || helperDecl.Type == nil || helperDecl.Type.Results == nil || helperDecl.Type.Results.NumFields() != wantResults || !funcReturnsErrorLast(helperDecl.Type) || (wantResults == 2 && !firstResultIsInt(helperDecl.Type.Results)) {
			return false
		}
		calleeBinding, _, boundOK := deriveCalleeBinding(fn, recvType, binding, currentPayloadProtected(), call, helperRecv, helperDecl, func(arg ast.Expr) (string, bool) {
			return sinkSliceSource(arg, st, mode)
		})
		if boundOK && verifyTestingWriterFunc(helperRecv, helperDecl, calleeBinding, topFuncs, typeMethods, k, reqGates, visiting) {
			allowedPayloadCalls[call] = true
			return true
		}
		return false
	}

	classifySinkAssignCall := func(lhsLen int, call *ast.CallExpr, st writerPathState, mode writerBlockMode) (isSink bool, chunkUsed string, ok bool) {
		if id, isID := unwrapParens(call.Fun).(*ast.Ident); isID {
			if cType, isClosure := localClosures[id.Name]; isClosure {
				if call.Ellipsis.IsValid() || len(call.Args) != 1 || lhsLen != cType.Results.NumFields() {
					return true, "", false
				}
				srcChunk, argOK := sinkSliceSource(call.Args[0], st, mode)
				if argOK {
					allowedPayloadCalls[call] = true
				}
				return true, srcChunk, argOK
			}
		}
		if helperRecv, helperDecl, isLocal := resolveLocalHelper(recvType, fn, call, topFuncs, typeMethods); isLocal {
			if helperDecl.Type == nil || helperDecl.Type.Results == nil || helperDecl.Type.Results.NumFields() == 0 {
				return false, "", false
			}
			if !funcReturnsErrorLast(helperDecl.Type) {
				return false, "", true
			}
			if lhsLen != helperDecl.Type.Results.NumFields() || (lhsLen == 2 && !firstResultIsInt(helperDecl.Type.Results)) {
				return true, "", false
			}
			calleeBinding, srcChunk, boundOK := deriveCalleeBinding(fn, recvType, binding, currentPayloadProtected(), call, helperRecv, helperDecl, func(arg ast.Expr) (string, bool) {
				return sinkSliceSource(arg, st, mode)
			})
			if !boundOK || !verifyTestingWriterFunc(helperRecv, helperDecl, calleeBinding, topFuncs, typeMethods, k, reqGates, visiting) {
				return true, "", false
			}
			allowedPayloadCalls[call] = true
			return true, srcChunk, true
		}
		switch isBoundSyscallWriteCall(fn, call, binding) {
		case "write2":
			if mode != writerBlockSliceLoop || lhsLen != 2 {
				return true, "", false
			}
			srcChunk, argOK := sinkSliceSource(call.Args[1], st, mode)
			if !argOK || srcChunk != sliceParam {
				return true, "", false
			}
			allowedPayloadCalls[call] = true
			return true, srcChunk, true
		case "raw3":
			if mode != writerBlockSliceLoop || lhsLen != 3 || st.sliceAdvancedInLoop {
				return true, "", false
			}
			amp, innerCalls, ptrOK := isSliceZeroElemUintptrExpr(call.Args[2], sliceParam)
			if !ptrOK || !isSliceLenUintptrExpr(call.Args[3], sliceParam) {
				return true, "", false
			}
			if amp != nil {
				allowedSliceZeroAmps[amp] = true
			}
			allowedPayloadCalls[call] = true
			for _, ic := range innerCalls {
				allowedPayloadCalls[ic] = true
			}
			return true, sliceParam, true
		}
		if syscallWriteSinkKind(call) != "" {
			return true, "", false
		}
		if isUnderlyingBoundWriteCall(fn, call, binding) {
			if lhsLen != 2 {
				return true, "", false
			}
			srcChunk, argOK := sinkSliceSource(call.Args[0], st, mode)
			if argOK {
				allowedPayloadCalls[call] = true
			}
			return true, srcChunk, argOK
		}
		if sel, isSel := unwrapParens(call.Fun).(*ast.SelectorExpr); isSel && sel.Sel.Name == "Write" {
			return true, "", false
		}
		return false, "", true
	}

	verifySinkClosureLit := func(name string, lit *ast.FuncLit, mode writerBlockMode, inBranch bool) bool {
		if mode != writerBlockPlain || inBranch || lit == nil || lit.Type == nil || lit.Type.Results == nil || !funcReturnsErrorLast(lit.Type) {
			return false
		}
		cRes := lit.Type.Results.NumFields()
		if cRes != 1 && (cRes != 2 || !firstResultIsInt(lit.Type.Results)) {
			return false
		}
		cSlice := singleByteSliceParamIdent(lit.Type.Params)
		if cSlice == "" || name == "" || name == "_" || isProtectedIdent(name) || name == sliceParam {
			return false
		}
		closureEmpty := map[string]bool{}
		for eVar := range binding.emptyVars {
			if eVar != cSlice && !bodyDeclaresAnyIdent(lit.Body, map[string]bool{eVar: true}) && !bodyMutatesOrTakesAddrOfAny(lit.Body, map[string]bool{eVar: true}) {
				closureEmpty[eVar] = true
			}
		}
		closureBinding := testingWriterBinding{
			fileFields: binding.fileFields, fdFields: binding.fdFields,
			fileVars: binding.fileVars, fdVars: binding.fdVars,
			emptyVars: closureEmpty, sliceVar: cSlice,
		}
		synth := &ast.FuncDecl{Name: &ast.Ident{Name: name}, Type: lit.Type, Body: lit.Body}
		if !verifyTestingWriterFunc(recvType, synth, closureBinding, topFuncs, typeMethods, k, reqGates, visiting) {
			return false
		}
		verifiedClosureLits[lit] = true
		localClosures[name] = lit.Type
		return true
	}

	recordSinkCountLHS := func(lhsExprs []ast.Expr, st *writerPathState, mode writerBlockMode, chunkUsed string) bool {
		switch len(lhsExprs) {
		case 1:
			if mode == writerBlockSliceLoop {
				return false
			}
			st.liveCountVar = ""
			return true
		case 2, 3:
			countID, ok := unwrapParens(lhsExprs[0]).(*ast.Ident)
			if !ok || countID.Name == "" || countID.Name == sliceParam || localClosures[countID.Name] != nil || allErrNames[countID.Name] || allChunkNames[countID.Name] || allBufNames[countID.Name] || protectedSinks[countID.Name] {
				return false
			}
			if countID.Name == "_" {
				if !(mode == writerBlockPlain && numResults == 1 && len(lhsExprs) == 2) {
					return false
				}
				st.liveCountVar = ""
				return true
			}
			if len(lhsExprs) == 3 {
				r2ID, ok := unwrapParens(lhsExprs[1]).(*ast.Ident)
				if !ok || r2ID.Name == countID.Name || r2ID.Name == sliceParam || isProtectedIdent(r2ID.Name) {
					return false
				}
			}
			switch mode {
			case writerBlockSliceLoop:
				allLoopCountNames[countID.Name] = true
				loopCountAliases[countID.Name] = true
			case writerBlockPlain:
				if chunkUsed != sliceParam || (allCountNames[countID.Name] && countID.Name != namedCountResult) {
					return false
				}
				allCountNames[countID.Name] = true
				st.liveCountVar = countID.Name
			case writerBlockChunkLoop:
				if countID.Name == namedCountResult {
					return false
				}
				allCountNames[countID.Name] = true
			}
			return true
		default:
			return false
		}
	}

	checkValidCountReturnExpr := func(expr ast.Expr, st writerPathState) bool {
		expr = unwrapParens(expr)
		if st.liveErr != "" && isZeroIntLit(expr) {
			return true
		}
		if id, ok := expr.(*ast.Ident); ok {
			if st.liveCountVar != "" && id.Name == st.liveCountVar && (st.liveErr != "" || st.discharged2ResultSink) {
				return true
			}
			if namedCountResult != "" && id.Name == namedCountResult && st.latchedCount {
				return true
			}
		}
		return st.liveErr == "" && st.dischargedFullSlice1ResultSink && !st.sliceParamMutated && isLenOfIdentCall(expr, sliceParam)
	}

	checkReturn := func(ret *ast.ReturnStmt, st writerPathState, allowNilFromLoop bool, mode writerBlockMode) bool {
		switch len(ret.Results) {
		case 0:
			if namedErrResult == "" {
				return false
			}
			if numResults == 2 {
				return namedCountResult != "" && ((st.liveErr != "" && st.liveErr == namedErrResult && st.liveCountVar == namedCountResult) || (st.liveErr == "" && st.latchedSink && st.latchedCount))
			}
			return (st.liveErr != "" && st.liveErr == namedErrResult) || (st.liveErr == "" && st.latchedSink)
		case 1:
			if numResults > 1 {
				if st.liveErr != "" {
					return false
				}
				call, ok := unwrapParens(ret.Results[0]).(*ast.CallExpr)
				return ok && isValidTailSinkCall(call, numResults, st, mode)
			}
			fallthrough
		default:
			if len(ret.Results) != numResults {
				return false
			}
			last := unwrapParens(ret.Results[numResults-1])
			if numResults == 1 && st.liveErr == "" {
				if call, ok := last.(*ast.CallExpr); ok && isValidTailSinkCall(call, 1, st, mode) {
					return true
				}
			}
			if numResults == 2 && !checkValidCountReturnExpr(ret.Results[0], st) {
				return false
			}
			if st.liveErr != "" && exprIsUntaintedErrResult(last, st.liveErr) {
				return true
			}
			if st.liveErr == "" {
				if id, ok := last.(*ast.Ident); ok && namedErrResult != "" && id.Name == namedErrResult && st.latchedSink {
					return true
				}
				if id, ok := last.(*ast.Ident); ok && id.Name == "nil" && (allowNilFromLoop || (numResults == 2 && (st.dischargedFullSlice1ResultSink || st.discharged2ResultSink))) {
					return true
				}
			}
			return false
		}
	}

	applySinkAssign := func(lhsExprs []ast.Expr, srcChunk string, st writerPathState, mode writerBlockMode, isNewDecl bool, blockDepth int) (writerPathState, bool) {
		for _, lhs := range lhsExprs {
			id, ok := unwrapParens(lhs).(*ast.Ident)
			if !ok || id.Name == "" {
				return st, false
			}
			if id.Name == "_" {
				continue
			}
			if isNewDecl {
				if blockDepth > 0 && outerVarDecls[id.Name] {
					return st, false
				}
			} else if !outerVarDecls[id.Name] {
				return st, false
			}
		}
		if st.liveErr != "" || !recordSinkCountLHS(lhsExprs, &st, mode, srcChunk) {
			return st, false
		}
		errName, bound := bindFreshErrIdent(lhsExprs[len(lhsExprs)-1])
		if !bound {
			return st, false
		}
		if isNewDecl && blockDepth == 0 {
			outerVarDecls[errName] = true
			if st.liveCountVar != "" {
				outerVarDecls[st.liveCountVar] = true
			}
		}
		st.liveErr, st.lastChunk, st.lastSinkResultArity = errName, srcChunk, len(lhsExprs)
		if mode == writerBlockChunkLoop {
			st.activeChunk = srcChunk
		}
		if mode == writerBlockSliceLoop {
			st.sawSinkInLoop = true
		}
		st.dischargedLoop, st.dischargedFullSlice1ResultSink, st.discharged2ResultSink = false, false, false
		return st, true
	}

	hasScopedOutLiveVars := func(st writerPathState) bool {
		return (st.liveErr != "" && !outerVarDecls[st.liveErr]) || (st.liveCountVar != "" && !outerVarDecls[st.liveCountVar])
	}

	var walkBlock func(stmts []ast.Stmt, st writerPathState, inErrCheckFor string, mode writerBlockMode, inBranch bool, blockDepth int) (writerPathState, bool)
	walkBlock = func(stmts []ast.Stmt, st writerPathState, inErrCheckFor string, mode writerBlockMode, inBranch bool, blockDepth int) (writerPathState, bool) {
		for idx, stmt := range stmts {
			if idx != len(stmts)-1 && blockAlwaysReturns([]ast.Stmt{stmt}) {
				return st, false
			}
			switch s := stmt.(type) {
			case *ast.EmptyStmt:
				continue
			case *ast.ExprStmt:
				if call, isCall := unwrapParens(s.X).(*ast.CallExpr); isCall {
					if id, isID := unwrapParens(call.Fun).(*ast.Ident); isID && localClosures[id.Name] != nil {
						return st, false
					}
					if _, helperDecl, isLocal := resolveLocalHelper(recvType, fn, call, topFuncs, typeMethods); isLocal && funcReturnsErrorLast(helperDecl.Type) {
						return st, false
					}
					if syscallWriteSinkKind(call) != "" {
						return st, false
					}
					if sel, isSel := unwrapParens(call.Fun).(*ast.SelectorExpr); isSel && sel.Sel.Name == "Write" {
						return st, false
					}
				}
			case *ast.DeferStmt:
				if _, isLit := unwrapParens(s.Call.Fun).(*ast.FuncLit); isLit {
					return st, false
				}
				if _, helperDecl, isLocal := resolveLocalHelper(recvType, fn, s.Call, topFuncs, typeMethods); isLocal && funcReturnsErrorLast(helperDecl.Type) {
					return st, false
				}
			case *ast.DeclStmt:
				gd, isGen := s.Decl.(*ast.GenDecl)
				if !isGen {
					continue
				}
				for _, spec := range gd.Specs {
					vs, isVal := spec.(*ast.ValueSpec)
					if !isVal {
						continue
					}
					if len(vs.Values) == 0 {
						_, isErrType := isIdentNamed(vs.Type, "error")
						for _, n := range vs.Names {
							if (isErrType && (n.Name == "" || n.Name == "_")) || n.Name == sliceParam || isProtectedIdent(n.Name) || (blockDepth > 0 && outerVarDecls[n.Name]) {
								return st, false
							}
							if blockDepth == 0 && n.Name != "" && n.Name != "_" {
								outerVarDecls[n.Name] = true
							}
						}
						continue
					}
					if len(vs.Names) == 1 && len(vs.Values) == 1 {
						if lit, isLit := unwrapParens(vs.Values[0]).(*ast.FuncLit); isLit {
							if !verifySinkClosureLit(vs.Names[0].Name, lit, mode, inBranch) {
								return st, false
							}
							continue
						}
					}
					if len(vs.Values) == 1 {
						if call, isCall := unwrapParens(vs.Values[0]).(*ast.CallExpr); isCall {
							isSink, srcChunk, callOK := classifySinkAssignCall(len(vs.Names), call, st, mode)
							if !callOK {
								return st, false
							}
							if isSink {
								lhsExprs := make([]ast.Expr, len(vs.Names))
								for i, n := range vs.Names {
									lhsExprs[i] = n
								}
								var sinkOK bool
								if st, sinkOK = applySinkAssign(lhsExprs, srcChunk, st, mode, true, blockDepth); !sinkOK {
									return st, false
								}
								allowedPayloadValueSpecs[vs] = true
								continue
							}
						}
					}
					for _, n := range vs.Names {
						if n.Name == sliceParam || isProtectedIdent(n.Name) || (blockDepth > 0 && outerVarDecls[n.Name]) {
							return st, false
						}
						if blockDepth == 0 && n.Name != "" && n.Name != "_" {
							outerVarDecls[n.Name] = true
						}
					}
				}
			case *ast.AssignStmt:
				if len(s.Lhs) == 1 && len(s.Rhs) == 1 {
					if lit, isLit := unwrapParens(s.Rhs[0]).(*ast.FuncLit); isLit {
						id, isID := unwrapParens(s.Lhs[0]).(*ast.Ident)
						if !isID || !verifySinkClosureLit(id.Name, lit, mode, inBranch) {
							return st, false
						}
						continue
					}
				}
				if len(s.Rhs) == 1 {
					if call, isCall := unwrapParens(s.Rhs[0]).(*ast.CallExpr); isCall {
						isSink, srcChunk, callOK := classifySinkAssignCall(len(s.Lhs), call, st, mode)
						if !callOK {
							return st, false
						}
						if isSink {
							if s.Tok != token.DEFINE && s.Tok != token.ASSIGN {
								return st, false
							}
							var sinkOK bool
							if st, sinkOK = applySinkAssign(s.Lhs, srcChunk, st, mode, s.Tok == token.DEFINE, blockDepth); !sinkOK {
								return st, false
							}
							allowedPayloadAssigns[s] = true
							continue
						}
					}
				}
				if s.Tok == token.ASSIGN && len(s.Lhs) == 1 && len(s.Rhs) == 1 && st.liveErr != "" && inErrCheckFor == st.liveErr {
					if _, ok := isIdentNamed(s.Lhs[0], st.liveErr); ok && isWrappedErrStructPtr(s.Rhs[0], st.liveErr) {
						continue
					}
				}
				if mode == writerBlockSliceLoop && len(s.Lhs) == 1 && len(s.Rhs) == 1 {
					if s.Tok == token.DEFINE {
						if lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident); ok && lhsID.Name != "" && lhsID.Name != "_" && lhsID.Name != sliceParam && !isProtectedIdent(lhsID.Name) {
							rhs := unwrapParens(s.Rhs[0])
							if conv, isCall := rhs.(*ast.CallExpr); isCall && len(conv.Args) == 1 && !conv.Ellipsis.IsValid() {
								if cid, ok := unwrapParens(conv.Fun).(*ast.Ident); ok && (cid.Name == "int" || cid.Name == "uintptr") {
									rhs = unwrapParens(conv.Args[0])
								}
							}
							if srcID, ok := rhs.(*ast.Ident); ok && loopCountAliases[srcID.Name] {
								allLoopCountNames[lhsID.Name] = true
								loopCountAliases[lhsID.Name] = true
								continue
							}
						}
					}
					if s.Tok == token.ASSIGN && st.liveErr != "" && inErrCheckFor == st.liveErr {
						if lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident); ok && loopCountAliases[lhsID.Name] && isZeroIntLit(s.Rhs[0]) {
							continue
						}
					}
					if isCountAdvanceSliceAssign(s, sliceParam, loopCountAliases) {
						if st.sliceAdvancedInLoop {
							return st, false
						}
						st.sliceAdvancedInLoop = true
						allowedPayloadAssigns[s] = true
						continue
					}
				}
				if mode == writerBlockChunkLoop && len(s.Lhs) == 1 && len(s.Rhs) == 1 {
					if s.Tok == token.DEFINE && !st.chunkAdvancedInLoop && st.activeChunk == "" {
						if lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident); ok && lhsID.Name != "" && lhsID.Name != "_" && lhsID.Name != sliceParam && !isProtectedIdent(lhsID.Name) {
							if _, okR := isIdentNamed(s.Rhs[0], sliceParam); okR {
								chunkVars[lhsID.Name], allChunkNames[lhsID.Name], allowedPayloadAssigns[s] = true, true, true
								continue
							}
							if makeCall, ok := unwrapParens(s.Rhs[0]).(*ast.CallExpr); ok && !makeCall.Ellipsis.IsValid() && len(makeCall.Args) >= 2 && len(makeCall.Args) <= 3 {
								if _, okM := isIdentNamed(makeCall.Fun, "make"); okM && isByteSliceType(makeCall.Args[0]) && isZeroIntLit(makeCall.Args[1]) {
									if len(makeCall.Args) == 3 && exprRefsIdentOutsideLen(makeCall.Args[2], currentPayloadProtected()) {
										return st, false
									}
									freshBufVars[lhsID.Name], allBufNames[lhsID.Name], allowedPayloadCalls[makeCall], allowedPayloadAssigns[s] = true, true, true, true
									continue
								}
							}
						}
					}
					if s.Tok == token.ASSIGN && !st.chunkAdvancedInLoop && st.activeChunk == "" {
						if lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident); ok && chunkVars[lhsID.Name] {
							sl, ok := unwrapParens(s.Rhs[0]).(*ast.SliceExpr)
							if !ok || sl.Slice3 || sl.Low != nil || sl.High == nil || isZeroIntLit(sl.High) || exprRefsIdentOutsideLen(sl.High, currentPayloadProtected()) {
								return st, false
							}
							if _, okB := isIdentNamed(sl.X, lhsID.Name); !okB {
								return st, false
							}
							allowedPayloadAssigns[s] = true
							continue
						}
						if lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident); ok && freshBufVars[lhsID.Name] {
							appCall, ok := unwrapParens(s.Rhs[0]).(*ast.CallExpr)
							if !ok || !appCall.Ellipsis.IsValid() || len(appCall.Args) != 2 {
								return st, false
							}
							_, okApp := isIdentNamed(appCall.Fun, "append")
							_, okDst := isIdentNamed(appCall.Args[0], lhsID.Name)
							if !okApp || !okDst {
								return st, false
							}
							if srcID, ok := unwrapParens(appCall.Args[1]).(*ast.Ident); ok && (srcID.Name == sliceParam || chunkVars[srcID.Name]) {
								if bufChunkSource[lhsID.Name] != "" {
									return st, false
								}
								bufChunkSource[lhsID.Name], allowedPayloadCalls[appCall], allowedPayloadAssigns[s] = srcID.Name, true, true
								continue
							}
							if bufChunkSource[lhsID.Name] == "" && isProvablyEmptyByteSliceArg(appCall.Args[1], binding) {
								allowedPayloadCalls[appCall], allowedPayloadAssigns[s] = true, true
								continue
							}
							return st, false
						}
					}
					if isChunkAdvanceSliceAssign(s, sliceParam, st.activeChunk) {
						if st.chunkAdvancedInLoop || st.liveErr != "" {
							return st, false
						}
						st.chunkAdvancedInLoop, allowedPayloadAssigns[s] = true, true
						continue
					}
				}
				payloadProtectedNow := currentPayloadProtected()
				for _, lhs := range s.Lhs {
					if isProtectedPayloadWriteLHS(lhs, sliceParam, isProtectedIdent, payloadProtectedNow) {
						return st, false
					}
				}
				for _, rhs := range s.Rhs {
					var hasFuncLit bool
					ast.Inspect(rhs, func(n ast.Node) bool {
						if _, ok := n.(*ast.FuncLit); ok {
							hasFuncLit = true
							return false
						}
						return true
					})
					if hasFuncLit {
						return st, false
					}
				}
			case *ast.IfStmt:
				if s.Init != nil {
					return st, false
				}
				if mode == writerBlockChunkLoop && !inBranch && st.liveErr != "" && namedErrResult != "" && !namedErrBoundDirectly {
					if updatedCount, latchOK := isMonotonicLatchIf(s, st.liveErr, namedErrResult, namedCountResult, st.activeChunk, numResults == 2); latchOK {
						everLatched, st.latchedSink, st.liveErr = true, true, ""
						if updatedCount && namedCountResult != "" {
							st.latchedCount = true
						}
						continue
					}
				}
				if mode == writerBlockSliceLoop && !inBranch && st.liveErr != "" && isTransientErrnoRetryIf(s, st.liveErr) {
					continue
				}
				if mode == writerBlockSliceLoop && !inBranch && s.Else == nil && len(s.Body.List) == 1 && isCountPositiveCond(s.Cond, loopCountAliases) {
					if as, ok := s.Body.List[0].(*ast.AssignStmt); ok && isCountAdvanceSliceAssign(as, sliceParam, loopCountAliases) {
						if st.sliceAdvancedInLoop {
							return st, false
						}
						st.sliceAdvancedInLoop, allowedPayloadAssigns[as] = true, true
						continue
					}
				}
				if mode == writerBlockChunkLoop && !inBranch && st.liveErr == "" && st.chunkAdvancedInLoop && s.Else == nil && len(s.Body.List) == 1 && isSliceLenZeroCond(s.Cond, sliceParam) {
					if ret, isRet := s.Body.List[0].(*ast.ReturnStmt); isRet {
						if !checkReturn(ret, st, false, mode) {
							return st, false
						}
						sawLenZeroExitReturn = true
						continue
					}
				}
				entrySt := st
				checkedErr := condChecksNonZeroErr(s.Cond)
				savedAllErrs := maps.Clone(allErrNames)
				savedAllCounts := maps.Clone(allCountNames)
				thenSt, thenOK := walkBlock(s.Body.List, entrySt, checkedErr, mode, true, blockDepth+1)
				if !thenOK {
					return st, false
				}
				thenRet := blockAlwaysReturns(s.Body.List)
				dischargeCheckedErr := func(base writerPathState) writerPathState {
					next := base
					if mode == writerBlockPlain && base.lastChunk == sliceParam {
						if base.lastSinkResultArity == 1 {
							next.dischargedFullSlice1ResultSink = true
						} else if base.lastSinkResultArity == 2 {
							next.discharged2ResultSink = true
						}
					}
					next.liveErr = ""
					return next
				}
				if s.Else == nil {
					if thenRet {
						if entrySt.liveErr != "" && checkedErr == entrySt.liveErr {
							st = dischargeCheckedErr(entrySt)
						} else if mode == writerBlockChunkLoop && entrySt.liveErr == "" {
							return st, false
						} else {
							st = entrySt
						}
					} else if thenSt != entrySt {
						return st, false
					} else {
						st = entrySt
					}
					continue
				}
				var elseStmts []ast.Stmt
				switch el := s.Else.(type) {
				case *ast.BlockStmt:
					elseStmts = el.List
				case *ast.IfStmt:
					elseStmts = []ast.Stmt{el}
				default:
					return st, false
				}
				if entrySt.liveErr == "" {
					if thenSt.liveErr != "" && !savedAllErrs[thenSt.liveErr] {
						delete(allErrNames, thenSt.liveErr)
					}
					if thenSt.liveCountVar != "" && !savedAllCounts[thenSt.liveCountVar] {
						delete(allCountNames, thenSt.liveCountVar)
					}
				}
				elseEntry := entrySt
				if thenRet && entrySt.liveErr != "" && checkedErr == entrySt.liveErr {
					elseEntry = dischargeCheckedErr(entrySt)
				}
				elseSt, elseOK := walkBlock(elseStmts, elseEntry, "", mode, true, blockDepth+1)
				if thenSt.liveErr != "" {
					allErrNames[thenSt.liveErr] = true
				}
				if thenSt.liveCountVar != "" {
					allCountNames[thenSt.liveCountVar] = true
				}
				if !elseOK {
					return st, false
				}
				elseRet := blockAlwaysReturns(elseStmts)
				switch {
				case thenRet && elseRet:
					st = writerPathState{}
				case thenRet && !elseRet:
					if hasScopedOutLiveVars(elseSt) {
						return st, false
					}
					st = elseSt
				case !thenRet && elseRet:
					if hasScopedOutLiveVars(thenSt) {
						return st, false
					}
					st = thenSt
				default:
					if thenSt != elseSt || hasScopedOutLiveVars(thenSt) {
						return st, false
					}
					st = thenSt
				}
			case *ast.ForStmt:
				if s.Init != nil || s.Post != nil {
					if !isPureNonSinkLoop(s, sliceParam, isProtectedIdent, currentPayloadProtected(), localClosures, topFuncs) {
						return st, false
					}
					continue
				}
				if s.Cond != nil {
					if mode == writerBlockPlain && !inBranch && isLenSlicePositiveCond(s.Cond, sliceParam) && !st.sliceParamMutated && st.liveErr == "" {
						if sinkSliceLoopBodyHasBadBranch(s.Body) {
							return st, false
						}
						loopCountAliases = map[string]bool{}
						loopSt, loopOK := walkBlock(s.Body.List, writerPathState{}, "", writerBlockSliceLoop, false, blockDepth+1)
						if !loopOK || loopSt.liveErr != "" || !loopSt.sawSinkInLoop || !loopSt.sliceAdvancedInLoop {
							return st, false
						}
						st.sliceParamMutated, st.dischargedLoop = true, true
						st.dischargedFullSlice1ResultSink, st.discharged2ResultSink = false, false
						continue
					}
					if !isPureNonSinkLoop(s, sliceParam, isProtectedIdent, currentPayloadProtected(), localClosures, topFuncs) {
						return st, false
					}
					continue
				}
				if mode != writerBlockPlain || inBranch || st.liveErr != "" || st.sliceParamMutated || sinkChunkLoopBodyHasOuterBranch(s.Body) {
					return st, false
				}
				sawLenZeroExitReturn = false
				chunkVars, freshBufVars, bufChunkSource = map[string]bool{}, map[string]bool{}, map[string]string{}
				loopSt, loopOK := walkBlock(s.Body.List, writerPathState{}, "", writerBlockChunkLoop, false, blockDepth+1)
				if !loopOK || loopSt.liveErr != "" || !loopSt.chunkAdvancedInLoop || !sawLenZeroExitReturn {
					return st, false
				}
				st.sliceParamMutated = true
			case *ast.ReturnStmt:
				if (mode == writerBlockChunkLoop && st.liveErr == "") || !checkReturn(s, st, st.dischargedLoop && inErrCheckFor == "", mode) {
					return st, false
				}
				st.liveErr = ""
			case *ast.IncDecStmt:
				if id, ok := unwrapParens(s.X).(*ast.Ident); !ok || id.Name == sliceParam || isProtectedIdent(id.Name) {
					return st, false
				}
			case *ast.BlockStmt:
				subSt, blkOK := walkBlock(s.List, st, inErrCheckFor, mode, inBranch, blockDepth+1)
				if !blkOK {
					return st, false
				}
				if !blockAlwaysReturns(s.List) && hasScopedOutLiveVars(subSt) {
					return st, false
				}
				st = subSt
			default:
				return st, false
			}
		}
		return st, true
	}

	endSt, ok := walkBlock(prunedStmts, writerPathState{}, "", writerBlockPlain, false, 0)
	if !ok || endSt.liveErr != "" {
		return false
	}

	payloadProtected := currentPayloadProtected()
	protectedAll := map[string]bool{sliceParam: true}
	for k := range localClosures {
		protectedAll[k] = true
	}
	maps.Copy(protectedAll, allErrNames)
	maps.Copy(protectedAll, allCountNames)
	maps.Copy(protectedAll, allLoopCountNames)
	maps.Copy(protectedAll, allChunkNames)
	maps.Copy(protectedAll, allBufNames)
	maps.Copy(protectedAll, protectedSinks)

	return verifySinkPostConfinement(
		prunedBody,
		sliceParam,
		allChunkNames, allBufNames, protectedAll, payloadProtected,
		verifiedClosureLits,
		allowedSliceZeroAmps,
		allowedPayloadValueSpecs,
		allowedPayloadAssigns,
		allowedPayloadCalls,
	)
}
