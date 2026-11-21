package toolchain

import (
	"go/ast"
	"go/token"
	"maps"
)

func syscallWriteSinkKind(call *ast.CallExpr) string {
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if _, ok := isIdentNamed(sel.X, "syscall"); !ok {
		return ""
	}
	switch sel.Sel.Name {
	case "Write":
		return "write2"
	case "Syscall", "RawSyscall", "Syscall6":
		return "raw3"
	default:
		return ""
	}
}

func isSysWriteConstExpr(expr ast.Expr) bool {
	_, ok := isSelectorBaseField(expr, "syscall", "SYS_WRITE")
	return ok
}

type testingWriterBinding struct {
	fileFields map[string]bool
	fdFields   map[string]bool
	fileVars   map[string]bool
	fdVars     map[string]bool
	emptyVars  map[string]bool
	sliceVar   string
}

func isProvablyEmptyByteSliceArg(expr ast.Expr, binding testingWriterBinding) bool {
	switch e := unwrapParens(expr).(type) {
	case *ast.Ident:
		return e.Name == "nil" || binding.emptyVars[e.Name]
	case *ast.BasicLit:
		return e.Kind == token.STRING && (e.Value == `""` || e.Value == "``")
	case *ast.CompositeLit:
		return len(e.Elts) == 0 && e.Type != nil && isByteSliceType(e.Type)
	case *ast.CallExpr:
		if e.Ellipsis.IsValid() || len(e.Args) != 1 || !isByteSliceType(e.Fun) {
			return false
		}
		if id, ok := unwrapParens(e.Args[0]).(*ast.Ident); ok && id.Name == "nil" {
			return true
		}
		lit, ok := unwrapParens(e.Args[0]).(*ast.BasicLit)
		return ok && lit.Kind == token.STRING && (lit.Value == `""` || lit.Value == "``")
	}
	return false
}

func isSliceZeroElemUintptrExpr(expr ast.Expr, sliceName string) (*ast.UnaryExpr, []*ast.CallExpr, bool) {
	if sliceName == "" {
		return nil, nil, false
	}
	uptrCall, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || len(uptrCall.Args) != 1 || uptrCall.Ellipsis.IsValid() {
		return nil, nil, false
	}
	if _, ok := isIdentNamed(uptrCall.Fun, "uintptr"); !ok {
		return nil, nil, false
	}
	ptrCall, ok := unwrapParens(uptrCall.Args[0]).(*ast.CallExpr)
	if !ok || len(ptrCall.Args) != 1 || ptrCall.Ellipsis.IsValid() {
		return nil, nil, false
	}
	if _, ok := isSelectorBaseField(ptrCall.Fun, "unsafe", "Pointer"); !ok {
		return nil, nil, false
	}
	inner := unwrapParens(ptrCall.Args[0])
	if amp, ok := inner.(*ast.UnaryExpr); ok && amp.Op == token.AND {
		idx, ok := unwrapParens(amp.X).(*ast.IndexExpr)
		if !ok || !isZeroIntLit(idx.Index) {
			return nil, nil, false
		}
		if _, ok := isIdentNamed(idx.X, sliceName); !ok {
			return nil, nil, false
		}
		return amp, []*ast.CallExpr{uptrCall, ptrCall}, true
	}
	if sdCall, ok := inner.(*ast.CallExpr); ok && len(sdCall.Args) == 1 && !sdCall.Ellipsis.IsValid() {
		if _, ok := isSelectorBaseField(sdCall.Fun, "unsafe", "SliceData"); !ok {
			return nil, nil, false
		}
		if _, ok := isIdentNamed(sdCall.Args[0], sliceName); !ok {
			return nil, nil, false
		}
		return nil, []*ast.CallExpr{uptrCall, ptrCall, sdCall}, true
	}
	return nil, nil, false
}

func isSliceLenUintptrExpr(expr ast.Expr, sliceName string) bool {
	uptrCall, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || len(uptrCall.Args) != 1 || uptrCall.Ellipsis.IsValid() {
		return false
	}
	_, okU := isIdentNamed(uptrCall.Fun, "uintptr")
	return okU && isLenOfIdentCall(uptrCall.Args[0], sliceName)
}

func isFdMethodCallOnSource(expr ast.Expr, isFileSource func(ast.Expr) bool) bool {
	expr = unwrapParens(expr)
	if conv, ok := expr.(*ast.CallExpr); ok && len(conv.Args) == 1 {
		if cid, ok := unwrapParens(conv.Fun).(*ast.Ident); ok && (cid.Name == "int" || cid.Name == "uintptr") {
			expr = unwrapParens(conv.Args[0])
		}
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Fd" && isFileSource(sel.X)
}

func extractCompositeWriterBinding(lit *ast.CompositeLit, isFileSource func(ast.Expr) bool) (testingWriterBinding, bool) {
	if lit == nil || len(lit.Elts) == 0 {
		return testingWriterBinding{}, false
	}
	b := testingWriterBinding{fileFields: map[string]bool{}, fdFields: map[string]bool{}}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return testingWriterBinding{}, false
		}
		keyID, ok := unwrapParens(kv.Key).(*ast.Ident)
		if !ok || keyID.Name == "" {
			return testingWriterBinding{}, false
		}
		val := unwrapParens(kv.Value)
		if isFileSource(val) {
			b.fileFields[keyID.Name] = true
		} else if isFdMethodCallOnSource(val, isFileSource) {
			b.fdFields[keyID.Name] = true
		}
	}
	if len(b.fileFields) == 0 && len(b.fdFields) == 0 {
		return testingWriterBinding{}, false
	}
	return b, true
}

func isBoundFileTargetExpr(fn *ast.FuncDecl, expr ast.Expr, binding testingWriterBinding) bool {
	switch e := unwrapParens(expr).(type) {
	case *ast.Ident:
		return binding.fileVars[e.Name]
	case *ast.SelectorExpr:
		if recv := recvVarName(fn); recv != "" {
			if _, ok := isIdentNamed(e.X, recv); ok {
				return binding.fileFields[e.Sel.Name]
			}
		}
	}
	return false
}

func isBoundFdTargetExpr(fn *ast.FuncDecl, expr ast.Expr, binding testingWriterBinding) bool {
	expr = unwrapParens(expr)
	if conv, ok := expr.(*ast.CallExpr); ok && len(conv.Args) == 1 {
		if cid, ok := unwrapParens(conv.Fun).(*ast.Ident); ok && (cid.Name == "int" || cid.Name == "uintptr") {
			expr = unwrapParens(conv.Args[0])
		}
	}
	switch e := expr.(type) {
	case *ast.Ident:
		return binding.fdVars[e.Name]
	case *ast.SelectorExpr:
		if recv := recvVarName(fn); recv != "" {
			if _, ok := isIdentNamed(e.X, recv); ok {
				return binding.fdFields[e.Sel.Name]
			}
		}
	case *ast.CallExpr:
		return isFdMethodCallOnSource(e, func(src ast.Expr) bool { return isBoundFileTargetExpr(fn, src, binding) })
	}
	return false
}

func isUnderlyingBoundWriteCall(fn *ast.FuncDecl, call *ast.CallExpr, binding testingWriterBinding) bool {
	if call.Ellipsis.IsValid() || len(call.Args) != 1 {
		return false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Write" && isBoundFileTargetExpr(fn, sel.X, binding)
}

func isBoundSyscallWriteCall(fn *ast.FuncDecl, call *ast.CallExpr, binding testingWriterBinding) string {
	if call.Ellipsis.IsValid() {
		return ""
	}
	switch syscallWriteSinkKind(call) {
	case "write2":
		if len(call.Args) == 2 && isBoundFdTargetExpr(fn, call.Args[0], binding) {
			return "write2"
		}
	case "raw3":
		sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		validArity := (sel.Sel.Name == "Syscall" || sel.Sel.Name == "RawSyscall") && len(call.Args) == 4
		if sel.Sel.Name == "Syscall6" && len(call.Args) == 6 && isZeroIntLit(call.Args[4]) && isZeroIntLit(call.Args[5]) {
			validArity = true
		}
		if validArity && isSysWriteConstExpr(call.Args[0]) && isBoundFdTargetExpr(fn, call.Args[1], binding) {
			return "raw3"
		}
	}
	return ""
}

func deriveCalleeBinding(callerFn *ast.FuncDecl, callerRecv string, callerBinding testingWriterBinding, callerPayloadProtected map[string]bool, call *ast.CallExpr, helperRecv string, helperDecl *ast.FuncDecl, sinkArgSource func(ast.Expr) (string, bool)) (testingWriterBinding, string, bool) {
	if call.Ellipsis.IsValid() {
		return testingWriterBinding{}, "", false
	}
	callee := testingWriterBinding{fileVars: map[string]bool{}, fdVars: map[string]bool{}, emptyVars: map[string]bool{}}
	if helperRecv != "" && helperRecv == callerRecv {
		callee.fileFields = callerBinding.fileFields
		callee.fdFields = callerBinding.fdFields
	}
	pNames := paramNamesFlat(helperDecl.Type.Params)
	if len(call.Args) != len(pNames) {
		return testingWriterBinding{}, "", false
	}
	byteSliceParams := byteSliceParamIdents(helperDecl.Type.Params)
	var matchedChunk string
	for i, arg := range call.Args {
		pName := pNames[i]
		if pName != "" && pName != "_" {
			if isBoundFileTargetExpr(callerFn, arg, callerBinding) && !exprRefsIdentOutsideLen(arg, callerPayloadProtected) {
				callee.fileVars[pName] = true
				continue
			}
			if isBoundFdTargetExpr(callerFn, arg, callerBinding) && !exprRefsIdentOutsideLen(arg, callerPayloadProtected) {
				callee.fdVars[pName] = true
				continue
			}
			if byteSliceParams[pName] {
				if srcChunk, ok := sinkArgSource(arg); ok {
					if callee.sliceVar != "" {
						return testingWriterBinding{}, "", false
					}
					callee.sliceVar = pName
					matchedChunk = srcChunk
					continue
				}
				if isProvablyEmptyByteSliceArg(arg, callerBinding) && !bodyDeclaresAnyIdent(helperDecl.Body, map[string]bool{pName: true}) && !bodyMutatesOrTakesAddrOfAny(helperDecl.Body, map[string]bool{pName: true}) {
					callee.emptyVars[pName] = true
					continue
				}
			}
		}
		if exprHasCallOrFuncLit(arg) || exprRefsIdentOutsideLen(arg, callerPayloadProtected) {
			return testingWriterBinding{}, "", false
		}
	}
	if callee.sliceVar == "" {
		return testingWriterBinding{}, "", false
	}
	return callee, matchedChunk, true
}

func resolveLocalHelper(recvType string, fn *ast.FuncDecl, call *ast.CallExpr, topFuncs map[string]*ast.FuncDecl, typeMethods map[string]map[string]*ast.FuncDecl) (string, *ast.FuncDecl, bool) {
	switch fun := unwrapParens(call.Fun).(type) {
	case *ast.Ident:
		if decl, ok := topFuncs[fun.Name]; ok {
			return "", decl, true
		}
	case *ast.SelectorExpr:
		if recv := recvVarName(fn); recv != "" && recvType != "" {
			if _, ok := isIdentNamed(fun.X, recv); ok {
				if decl, ok := typeMethods[recvType][fun.Sel.Name]; ok {
					return recvType, decl, true
				}
			}
		}
	}
	return "", nil, false
}

func isWrappedErrStructPtr(expr ast.Expr, errName string) bool {
	u, ok := unwrapParens(expr).(*ast.UnaryExpr)
	if !ok || u.Op != token.AND {
		return false
	}
	lit, ok := unwrapParens(u.X).(*ast.CompositeLit)
	if !ok || lit.Type == nil {
		return false
	}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if _, ok := isIdentNamed(kv.Value, errName); ok {
				return true
			}
		}
	}
	return false
}

func exprIsUntaintedErrResult(expr ast.Expr, errName string) bool {
	if _, ok := isIdentNamed(expr, errName); ok {
		return true
	}
	return isWrappedErrStructPtr(expr, errName)
}

func isTransientErrnoEq(expr ast.Expr, errName string) bool {
	bin, ok := unwrapParens(expr).(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return false
	}
	if _, ok := isIdentNamed(bin.X, errName); !ok {
		return false
	}
	sel, ok := unwrapParens(bin.Y).(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "EINTR" && sel.Sel.Name != "EAGAIN") {
		return false
	}
	_, okPkg := isIdentNamed(sel.X, "syscall")
	return okPkg
}

func isTransientErrnoRetryIf(s *ast.IfStmt, errName string) bool {
	if s.Init != nil || s.Else != nil || len(s.Body.List) != 1 {
		return false
	}
	br, ok := s.Body.List[0].(*ast.BranchStmt)
	if !ok || br.Tok != token.CONTINUE {
		return false
	}
	cond := unwrapParens(s.Cond)
	if isTransientErrnoEq(cond, errName) {
		return true
	}
	bin, ok := cond.(*ast.BinaryExpr)
	return ok && bin.Op == token.LOR && isTransientErrnoEq(bin.X, errName) && isTransientErrnoEq(bin.Y, errName)
}

func isLenSlicePositiveCond(cond ast.Expr, sliceName string) bool {
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	return sliceName != "" && ok && (bin.Op == token.GTR || bin.Op == token.NEQ) && isLenOfIdentCall(bin.X, sliceName) && isZeroIntLit(bin.Y)
}

func isCountPositiveCond(cond ast.Expr, countAliases map[string]bool) bool {
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.GTR || !isZeroIntLit(bin.Y) {
		return false
	}
	id, ok := unwrapParens(bin.X).(*ast.Ident)
	return ok && countAliases[id.Name]
}

func isChunkAdvanceSliceAssign(s *ast.AssignStmt, sliceName, activeChunk string) bool {
	if activeChunk == "" || s.Tok != token.ASSIGN || len(s.Lhs) != 1 || len(s.Rhs) != 1 {
		return false
	}
	if _, ok := isIdentNamed(s.Lhs[0], sliceName); !ok {
		return false
	}
	sl, ok := unwrapParens(s.Rhs[0]).(*ast.SliceExpr)
	if !ok || sl.Slice3 || sl.High != nil || sl.Low == nil {
		return false
	}
	_, okB := isIdentNamed(sl.X, sliceName)
	return okB && isLenOfIdentCall(sl.Low, activeChunk)
}

func isMonotonicLatchIf(s *ast.IfStmt, chunkErrVar, accumErrVar, namedCountResult, activeChunk string, requireCountUpdate bool) (updatedCount bool, ok bool) {
	checkArm := func(arm *ast.IfStmt) bool {
		if arm == nil || arm.Init != nil || arm.Else != nil || len(arm.Body.List) != 1 {
			return false
		}
		bin, ok := unwrapParens(arm.Cond).(*ast.BinaryExpr)
		if !ok || bin.Op != token.LAND || condChecksNonZeroErr(bin.X) != chunkErrVar || !condChecksEqErr(bin.Y, accumErrVar) {
			return false
		}
		as, ok := arm.Body.List[0].(*ast.AssignStmt)
		if !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return false
		}
		_, okL := isIdentNamed(as.Lhs[0], accumErrVar)
		_, okR := isIdentNamed(as.Rhs[0], chunkErrVar)
		return okL && okR
	}
	if checkArm(s) {
		return false, !requireCountUpdate
	}
	if s.Init != nil || s.Else == nil {
		return false, false
	}
	bin, ok := unwrapParens(s.Cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.LAND {
		return false, false
	}
	if !((condChecksEqErr(bin.X, chunkErrVar) && condChecksEqErr(bin.Y, accumErrVar)) || (condChecksEqErr(bin.Y, chunkErrVar) && condChecksEqErr(bin.X, accumErrVar))) {
		return false, false
	}
	elseIf, ok := s.Else.(*ast.IfStmt)
	if !ok || !checkArm(elseIf) {
		return false, false
	}
	if requireCountUpdate {
		if namedCountResult == "" || activeChunk == "" || len(s.Body.List) != 1 {
			return false, false
		}
		addStmt, ok := s.Body.List[0].(*ast.AssignStmt)
		if !ok || addStmt.Tok != token.ADD_ASSIGN || len(addStmt.Lhs) != 1 || len(addStmt.Rhs) != 1 {
			return false, false
		}
		_, okL := isIdentNamed(addStmt.Lhs[0], namedCountResult)
		return true, okL && isLenOfIdentCall(addStmt.Rhs[0], activeChunk)
	}
	return false, len(s.Body.List) == 0
}

type writerBlockMode int

const (
	writerBlockPlain writerBlockMode = iota
	writerBlockSliceLoop
	writerBlockChunkLoop
)

type writerPathState struct {
	liveErr                        string
	lastChunk                      string
	lastSinkResultArity            int
	activeChunk                    string
	liveCountVar                   string
	sliceParamMutated              bool
	sliceAdvancedInLoop            bool
	chunkAdvancedInLoop            bool
	sawSinkInLoop                  bool
	dischargedLoop                 bool
	dischargedFullSlice1ResultSink bool
	discharged2ResultSink          bool
	latchedSink                    bool
	latchedCount                   bool
}

func isPureNonSinkLoop(loop *ast.ForStmt, sliceParam string, isProt func(string) bool, loopPayloadProtected map[string]bool, localClosures map[string]*ast.FuncType, topFuncs map[string]*ast.FuncDecl) bool {
	if loop.Cond == nil {
		return false
	}
	var bad bool
	ast.Inspect(loop, func(n ast.Node) bool {
		if bad || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.ReturnStmt, *ast.FuncLit, *ast.DeferStmt, *ast.GoStmt, *ast.LabeledStmt, *ast.SendStmt:
			bad = true
			return false
		case *ast.BranchStmt:
			if node.Tok == token.GOTO || node.Label != nil {
				bad = true
				return false
			}
		case *ast.CallExpr:
			if syscallWriteSinkKind(node) != "" {
				bad = true
				return false
			}
			if sel, ok := unwrapParens(node.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Write" {
				bad = true
				return false
			}
			if id, ok := unwrapParens(node.Fun).(*ast.Ident); ok && (localClosures[id.Name] != nil || topFuncs[id.Name] != nil) {
				bad = true
				return false
			}
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if isProtectedPayloadWriteLHS(lhs, sliceParam, isProt, loopPayloadProtected) {
					bad = true
					return false
				}
			}
		case *ast.IncDecStmt:
			id, ok := unwrapParens(node.X).(*ast.Ident)
			if !ok || id.Name == sliceParam || isProt(id.Name) || loopPayloadProtected[id.Name] {
				bad = true
				return false
			}
		}
		return true
	})
	return !bad
}

func isProtectedPayloadWriteLHS(lhs ast.Expr, sliceParam string, isProt func(string) bool, payloadProtected map[string]bool) bool {
	switch target := unwrapParens(lhs).(type) {
	case *ast.Ident:
		return target.Name == sliceParam || isProt(target.Name)
	case *ast.IndexExpr:
		return exprReferencesAnyIdent(target.X, payloadProtected)
	case *ast.StarExpr:
		return exprReferencesAnyIdent(target.X, payloadProtected)
	}
	return false
}

func verifySinkPostConfinement(
	prunedBody *ast.BlockStmt,
	sliceParam string,
	allChunkNames, allBufNames, protectedAll, payloadProtected map[string]bool,
	verifiedClosureLits map[*ast.FuncLit]bool,
	allowedSliceZeroAmps map[*ast.UnaryExpr]bool,
	allowedPayloadValueSpecs map[*ast.ValueSpec]bool,
	allowedPayloadAssigns map[*ast.AssignStmt]bool,
	allowedPayloadCalls map[*ast.CallExpr]bool,
) bool {
	var postCheckBad bool
	var inspectNoNestedClosures func(node ast.Node)
	inspectNoNestedClosures = func(node ast.Node) {
		if postCheckBad || node == nil {
			return
		}
		switch x := node.(type) {
		case *ast.FuncLit:
			if !verifiedClosureLits[x] {
				postCheckBad = true
				return
			}
			outerProtected := maps.Clone(protectedAll)
			outerPayload := map[string]bool{sliceParam: true}
			maps.Copy(outerPayload, allChunkNames)
			maps.Copy(outerPayload, allBufNames)
			for _, p := range paramNamesFlat(x.Type.Params) {
				delete(outerProtected, p)
				delete(outerPayload, p)
			}
			if bodyMutatesOrTakesAddrOfAny(x.Body, outerProtected) || exprReferencesAnyIdent(x.Body, outerPayload) {
				postCheckBad = true
			}
			return
		case *ast.UnaryExpr:
			if x.Op == token.AND && !allowedSliceZeroAmps[x] {
				if id, ok := unwrapParens(x.X).(*ast.Ident); (ok && protectedAll[id.Name]) || exprReferencesAnyIdent(x.X, payloadProtected) {
					postCheckBad = true
					return
				}
			}
		case *ast.IncDecStmt:
			if id, ok := unwrapParens(x.X).(*ast.Ident); !ok || protectedAll[id.Name] || payloadProtected[id.Name] {
				postCheckBad = true
				return
			}
		case *ast.DeferStmt:
			if _, isLit := unwrapParens(x.Call.Fun).(*ast.FuncLit); isLit || exprReferencesAnyIdent(x.Call, protectedAll) || exprReferencesAnyIdent(x.Call, payloadProtected) {
				postCheckBad = true
				return
			}
		case *ast.ValueSpec:
			if !allowedPayloadValueSpecs[x] {
				for _, v := range x.Values {
					if lit, isLit := unwrapParens(v).(*ast.FuncLit); isLit && verifiedClosureLits[lit] {
						continue
					}
					if exprRefsIdentOutsideLen(v, payloadProtected) {
						postCheckBad = true
						return
					}
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if idx, ok := unwrapParens(lhs).(*ast.IndexExpr); ok && exprReferencesAnyIdent(idx.X, payloadProtected) {
					postCheckBad = true
					return
				}
				if star, ok := unwrapParens(lhs).(*ast.StarExpr); ok && exprReferencesAnyIdent(star.X, payloadProtected) {
					postCheckBad = true
					return
				}
			}
			if !allowedPayloadAssigns[x] {
				for _, rhs := range x.Rhs {
					if lit, isLit := unwrapParens(rhs).(*ast.FuncLit); isLit && verifiedClosureLits[lit] {
						continue
					}
					if exprRefsIdentOutsideLen(rhs, payloadProtected) {
						postCheckBad = true
						return
					}
				}
			}
		case *ast.ReturnStmt:
			for _, res := range x.Results {
				if call, ok := unwrapParens(res).(*ast.CallExpr); ok && (allowedPayloadCalls[call] || isOneArgLenIdentCall(call)) {
					continue
				}
				if exprRefsIdentOutsideLen(res, payloadProtected) {
					postCheckBad = true
					return
				}
			}
		case *ast.CallExpr:
			if !allowedPayloadCalls[x] && !isOneArgLenIdentCall(x) {
				if exprRefsIdentOutsideLen(x.Fun, payloadProtected) {
					postCheckBad = true
					return
				}
				for _, arg := range x.Args {
					if exprRefsIdentOutsideLen(arg, payloadProtected) {
						postCheckBad = true
						return
					}
				}
			}
		}
		ast.Inspect(node, func(ch ast.Node) bool {
			if ch == node {
				return true
			}
			inspectNoNestedClosures(ch)
			return false
		})
	}
	inspectNoNestedClosures(prunedBody)
	return !postCheckBad
}

func verifyTestingCustomWriter(typeName string, allowedLit *ast.CompositeLit, binding testingWriterBinding, files []*ast.File, topFuncs map[string]*ast.FuncDecl, typeMethods map[string]map[string]*ast.FuncDecl, k *packageInactiveKernel, reqGates map[string]bool) bool {
	if typeName == "" || ast.IsExported(typeName) || allowedLit == nil || (len(binding.fileFields) == 0 && len(binding.fdFields) == 0) {
		return false
	}
	allBoundFields := maps.Clone(binding.fileFields)
	if allBoundFields == nil {
		allBoundFields = map[string]bool{}
	}
	maps.Copy(allBoundFields, binding.fdFields)

	allowedTypeIdents := map[*ast.Ident]bool{}
	litTypeID, ok := unwrapParens(allowedLit.Type).(*ast.Ident)
	if !ok || litTypeID.Name != typeName {
		return false
	}
	allowedTypeIdents[litTypeID] = true

	var matchedSpecs []*ast.TypeSpec
	var methodDecls []*ast.FuncDecl
	for _, f := range files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				if d.Tok == token.TYPE {
					for _, spec := range d.Specs {
						if ts, ok := spec.(*ast.TypeSpec); ok && ts.Name.Name == typeName {
							matchedSpecs = append(matchedSpecs, ts)
							allowedTypeIdents[ts.Name] = true
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv != nil && len(d.Recv.List) == 1 {
					if rID := recvTypeIdent(d.Recv.List[0].Type); rID != nil && rID.Name == typeName {
						allowedTypeIdents[rID] = true
						methodDecls = append(methodDecls, d)
					}
				}
			}
		}
	}
	if len(matchedSpecs) != 1 || matchedSpecs[0].Assign.IsValid() || matchedSpecs[0].TypeParams != nil {
		return false
	}
	st, ok := unwrapParens(matchedSpecs[0].Type).(*ast.StructType)
	if !ok || st.Fields == nil {
		return false
	}
	declaredFields := map[string]bool{}
	for _, field := range st.Fields.List {
		if len(field.Names) == 0 {
			return false
		}
		for _, fn := range field.Names {
			declaredFields[fn.Name] = true
		}
	}
	for bf := range allBoundFields {
		if !declaredFields[bf] {
			return false
		}
	}
	if !allNonSelPropIdentsIn(files, typeName, allowedTypeIdents) {
		return false
	}
	for _, m := range methodDecls {
		if m.Body == nil {
			return false
		}
		if recv := recvVarName(m); recv != "" {
			if bodyMutatesOrTakesAddrOfAny(m.Body, map[string]bool{recv: true}) || !blockOnlySelectsOnIdent(m.Body, recv) || nodeMutatesOrTakesAddrOfSelector(m.Body, recv, allBoundFields) {
				return false
			}
		}
	}
	methods := typeMethods[typeName]
	if methods == nil || len(methods) != len(methodDecls) || methods["ReadFrom"] != nil {
		return false
	}
	if wsFn := methods["WriteString"]; wsFn != nil {
		wsRecv := recvVarName(wsFn)
		if wsRecv == "" || wsFn.Body == nil || len(wsFn.Body.List) != 1 || wsFn.Type == nil || wsFn.Type.Params == nil || wsFn.Type.Results == nil || wsFn.Type.Params.NumFields() != 1 || len(wsFn.Type.Params.List) != 1 || len(wsFn.Type.Params.List[0].Names) != 1 || wsFn.Type.Results.NumFields() != 2 || !firstResultIsInt(wsFn.Type.Results) || !funcReturnsErrorLast(wsFn.Type) {
			return false
		}
		if _, ok := isIdentNamed(wsFn.Type.Params.List[0].Type, "string"); !ok {
			return false
		}
		sParam := wsFn.Type.Params.List[0].Names[0].Name
		if sParam == "" || sParam == "_" || sParam == wsRecv || funcShadowsAnyIdent(wsFn, map[string]bool{"byte": true, "string": true, "int": true, "error": true}) {
			return false
		}
		ret, ok := wsFn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return false
		}
		wCall, ok := unwrapParens(ret.Results[0]).(*ast.CallExpr)
		if !ok || wCall.Ellipsis.IsValid() || len(wCall.Args) != 1 {
			return false
		}
		if _, ok := isSelectorBaseField(wCall.Fun, wsRecv, "Write"); !ok {
			return false
		}
		conv, ok := unwrapParens(wCall.Args[0]).(*ast.CallExpr)
		if !ok || conv.Ellipsis.IsValid() || len(conv.Args) != 1 || !isByteSliceType(conv.Fun) {
			return false
		}
		if _, ok := isIdentNamed(conv.Args[0], sParam); !ok {
			return false
		}
	}
	writeFn := methods["Write"]
	if writeFn == nil || writeFn.Body == nil || writeFn.Type == nil || writeFn.Type.Params == nil || writeFn.Type.Results == nil || writeFn.Type.Results.NumFields() != 2 || !firstResultIsInt(writeFn.Type.Results) || !funcReturnsErrorLast(writeFn.Type) {
		return false
	}
	binding.sliceVar = singleByteSliceParamIdent(writeFn.Type.Params)
	if binding.sliceVar == "" {
		return false
	}
	return verifyTestingWriterFunc(typeName, writeFn, binding, topFuncs, typeMethods, k, reqGates, map[string]bool{})
}

func sinkSliceLoopBodyHasBadBranch(body *ast.BlockStmt) bool {
	if body == nil {
		return true
	}
	var bad bool
	for _, ls := range body.List {
		if _, isBr := ls.(*ast.BranchStmt); isBr {
			return true
		}
		if ifs, isIf := ls.(*ast.IfStmt); isIf {
			ast.Inspect(ifs, func(n ast.Node) bool {
				if bad || n == nil {
					return false
				}
				switch bn := n.(type) {
				case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
					return false
				case *ast.BranchStmt:
					if bn.Tok == token.BREAK || bn.Tok == token.GOTO || bn.Label != nil || (bn.Tok == token.CONTINUE && (n != ifs.Body.List[0] || len(ifs.Body.List) != 1 || ifs.Else != nil)) {
						bad = true
						return false
					}
				}
				return true
			})
		}
	}
	return bad
}

func sinkChunkLoopBodyHasOuterBranch(body *ast.BlockStmt) bool {
	if body == nil {
		return true
	}
	var hasOuterBranch bool
	ast.Inspect(body, func(n ast.Node) bool {
		if hasOuterBranch || n == nil {
			return false
		}
		switch n.(type) {
		case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.FuncLit:
			return false
		case *ast.BranchStmt:
			hasOuterBranch = true
			return false
		}
		return true
	})
	return hasOuterBranch
}
