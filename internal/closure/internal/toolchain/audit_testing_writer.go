package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
)

func syscallWriteSinkKind(call *ast.CallExpr) string {
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	id, ok := unwrapParens(sel.X).(*ast.Ident)
	if !ok || id.Name != "syscall" {
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
	sel, ok := unwrapParens(expr).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "SYS_WRITE" {
		return false
	}
	id, ok := unwrapParens(sel.X).(*ast.Ident)
	return ok && id.Name == "syscall"
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
		switch a := unwrapParens(e.Args[0]).(type) {
		case *ast.Ident:
			return a.Name == "nil"
		case *ast.BasicLit:
			return a.Kind == token.STRING && (a.Value == `""` || a.Value == "``")
		default:
			return false
		}
	default:
		return false
	}
}

func isSliceZeroElemUintptrExpr(expr ast.Expr, sliceName string) (*ast.UnaryExpr, []*ast.CallExpr, bool) {
	if sliceName == "" {
		return nil, nil, false
	}
	uptrCall, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || len(uptrCall.Args) != 1 || uptrCall.Ellipsis.IsValid() {
		return nil, nil, false
	}
	uptrID, ok := unwrapParens(uptrCall.Fun).(*ast.Ident)
	if !ok || uptrID.Name != "uintptr" {
		return nil, nil, false
	}
	ptrCall, ok := unwrapParens(uptrCall.Args[0]).(*ast.CallExpr)
	if !ok || len(ptrCall.Args) != 1 || ptrCall.Ellipsis.IsValid() {
		return nil, nil, false
	}
	ptrSel, ok := unwrapParens(ptrCall.Fun).(*ast.SelectorExpr)
	if !ok || ptrSel.Sel.Name != "Pointer" {
		return nil, nil, false
	}
	unsafeID, ok := unwrapParens(ptrSel.X).(*ast.Ident)
	if !ok || unsafeID.Name != "unsafe" {
		return nil, nil, false
	}
	inner := unwrapParens(ptrCall.Args[0])
	if amp, ok := inner.(*ast.UnaryExpr); ok && amp.Op == token.AND {
		idx, ok := unwrapParens(amp.X).(*ast.IndexExpr)
		if !ok || !isZeroIntLit(idx.Index) {
			return nil, nil, false
		}
		sID, ok := unwrapParens(idx.X).(*ast.Ident)
		if !ok || sID.Name != sliceName {
			return nil, nil, false
		}
		return amp, []*ast.CallExpr{uptrCall, ptrCall}, true
	}
	if sdCall, ok := inner.(*ast.CallExpr); ok && len(sdCall.Args) == 1 && !sdCall.Ellipsis.IsValid() {
		sdSel, ok := unwrapParens(sdCall.Fun).(*ast.SelectorExpr)
		if !ok || sdSel.Sel.Name != "SliceData" {
			return nil, nil, false
		}
		uID, ok := unwrapParens(sdSel.X).(*ast.Ident)
		if !ok || uID.Name != "unsafe" {
			return nil, nil, false
		}
		sID, ok := unwrapParens(sdCall.Args[0]).(*ast.Ident)
		if !ok || sID.Name != sliceName {
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
	uptrID, ok := unwrapParens(uptrCall.Fun).(*ast.Ident)
	if !ok || uptrID.Name != "uintptr" {
		return false
	}
	return isLenOfIdentCall(uptrCall.Args[0], sliceName)
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
	b := testingWriterBinding{
		fileFields: map[string]bool{},
		fdFields:   map[string]bool{},
	}
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
	expr = unwrapParens(expr)
	switch e := expr.(type) {
	case *ast.Ident:
		return binding.fileVars[e.Name]
	case *ast.SelectorExpr:
		recv := recvVarName(fn)
		if recv != "" {
			if id, ok := unwrapParens(e.X).(*ast.Ident); ok && id.Name == recv {
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
		recv := recvVarName(fn)
		if recv != "" {
			if id, ok := unwrapParens(e.X).(*ast.Ident); ok && id.Name == recv {
				return binding.fdFields[e.Sel.Name]
			}
		}
	case *ast.CallExpr:
		return isFdMethodCallOnSource(e, func(src ast.Expr) bool {
			return isBoundFileTargetExpr(fn, src, binding)
		})
	}
	return false
}

func isUnderlyingBoundWriteCall(fn *ast.FuncDecl, call *ast.CallExpr, binding testingWriterBinding) bool {
	if call.Ellipsis.IsValid() {
		return false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Write" || len(call.Args) != 1 {
		return false
	}
	return isBoundFileTargetExpr(fn, sel.X, binding)
}

func isBoundSyscallWriteCall(fn *ast.FuncDecl, call *ast.CallExpr, binding testingWriterBinding) string {
	if call.Ellipsis.IsValid() {
		return ""
	}
	kind := syscallWriteSinkKind(call)
	switch kind {
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
	callee := testingWriterBinding{
		fileVars:  map[string]bool{},
		fdVars:    map[string]bool{},
		emptyVars: map[string]bool{},
	}
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
		recv := recvVarName(fn)
		if recv != "" && recvType != "" {
			if id, ok := unwrapParens(fun.X).(*ast.Ident); ok && id.Name == recv {
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
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := unwrapParens(kv.Value).(*ast.Ident); ok && id.Name == errName {
			return true
		}
	}
	return false
}

func exprIsUntaintedErrResult(expr ast.Expr, errName string) bool {
	expr = unwrapParens(expr)
	if id, ok := expr.(*ast.Ident); ok && id.Name == errName {
		return true
	}
	return isWrappedErrStructPtr(expr, errName)
}

func isTransientErrnoEq(expr ast.Expr, errName string) bool {
	bin, ok := unwrapParens(expr).(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return false
	}
	id, ok := unwrapParens(bin.X).(*ast.Ident)
	if !ok || id.Name != errName {
		return false
	}
	sel, ok := unwrapParens(bin.Y).(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "EINTR" && sel.Sel.Name != "EAGAIN") {
		return false
	}
	pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
	return ok && pkgID.Name == "syscall"
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
	if sliceName == "" {
		return false
	}
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	if !ok || (bin.Op != token.GTR && bin.Op != token.NEQ) {
		return false
	}
	return isLenOfIdentCall(bin.X, sliceName) && isZeroIntLit(bin.Y)
}

func isCountPositiveCond(cond ast.Expr, countAliases map[string]bool) bool {
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.GTR {
		return false
	}
	id, ok := unwrapParens(bin.X).(*ast.Ident)
	return ok && countAliases[id.Name] && isZeroIntLit(bin.Y)
}

func isChunkAdvanceSliceAssign(s *ast.AssignStmt, sliceName, activeChunk string) bool {
	if activeChunk == "" || s.Tok != token.ASSIGN || len(s.Lhs) != 1 || len(s.Rhs) != 1 {
		return false
	}
	lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident)
	if !ok || lhsID.Name != sliceName {
		return false
	}
	sl, ok := unwrapParens(s.Rhs[0]).(*ast.SliceExpr)
	if !ok || sl.Slice3 || sl.High != nil || sl.Low == nil {
		return false
	}
	baseID, ok := unwrapParens(sl.X).(*ast.Ident)
	return ok && baseID.Name == sliceName && isLenOfIdentCall(sl.Low, activeChunk)
}

func isMonotonicLatchIf(s *ast.IfStmt, chunkErrVar, accumErrVar, namedCountResult, activeChunk string, requireCountUpdate bool) (updatedCount bool, ok bool) {
	checkArm := func(arm *ast.IfStmt) bool {
		if arm == nil || arm.Init != nil || arm.Else != nil || len(arm.Body.List) != 1 {
			return false
		}
		bin, ok := unwrapParens(arm.Cond).(*ast.BinaryExpr)
		if !ok || bin.Op != token.LAND {
			return false
		}
		if condChecksNonZeroErr(bin.X) != chunkErrVar || !condChecksEqErr(bin.Y, accumErrVar) {
			return false
		}
		assign, ok := arm.Body.List[0].(*ast.AssignStmt)
		if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return false
		}
		lhsID, ok := unwrapParens(assign.Lhs[0]).(*ast.Ident)
		rhsID, ok2 := unwrapParens(assign.Rhs[0]).(*ast.Ident)
		return ok && ok2 && lhsID.Name == accumErrVar && rhsID.Name == chunkErrVar
	}
	if checkArm(s) {
		if requireCountUpdate {
			return false, false
		}
		return false, true
	}
	if s.Init != nil || s.Else == nil {
		return false, false
	}
	condRequiresNilBoth := false
	if bin, ok := unwrapParens(s.Cond).(*ast.BinaryExpr); ok && bin.Op == token.LAND {
		condRequiresNilBoth = (condChecksEqErr(bin.X, chunkErrVar) && condChecksEqErr(bin.Y, accumErrVar)) ||
			(condChecksEqErr(bin.Y, chunkErrVar) && condChecksEqErr(bin.X, accumErrVar))
	}
	if !condRequiresNilBoth {
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
		lhsID, ok := unwrapParens(addStmt.Lhs[0]).(*ast.Ident)
		if !ok || lhsID.Name != namedCountResult || !isLenOfIdentCall(addStmt.Rhs[0], activeChunk) {
			return false, false
		}
		return true, true
	}
	if len(s.Body.List) != 0 {
		return false, false
	}
	return false, true
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

func verifyTestingWriterFunc(recvType string, fn *ast.FuncDecl, binding testingWriterBinding, topFuncs map[string]*ast.FuncDecl, typeMethods map[string]map[string]*ast.FuncDecl, visiting map[string]bool) bool {
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
	if !blockAlwaysReturns(fn.Body.List) {
		return false
	}
	visitKey := recvType + "." + fn.Name.Name + fmt.Sprintf("|%s|%v|%v|%v|%v|%v", binding.sliceVar, sortedKeys(binding.fileFields), sortedKeys(binding.fdFields), sortedKeys(binding.fileVars), sortedKeys(binding.fdVars), sortedKeys(binding.emptyVars))
	if visiting[visitKey] {
		return false
	}
	visiting[visitKey] = true
	defer delete(visiting, visitKey)

	protectedSinks := map[string]bool{}
	for k := range binding.fileVars {
		protectedSinks[k] = true
	}
	for k := range binding.fdVars {
		protectedSinks[k] = true
	}
	for k := range binding.emptyVars {
		protectedSinks[k] = true
	}
	if recv := recvVarName(fn); recv != "" {
		protectedSinks[recv] = true
		if !blockOnlySelectsOnIdent(fn.Body, recv) {
			return false
		}
	}
	if bodyMutatesOrTakesAddrOfAny(fn.Body, protectedSinks) {
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
	allErrNames := map[string]bool{}
	allCountNames := map[string]bool{}
	allLoopCountNames := map[string]bool{}
	allChunkNames := map[string]bool{}
	allBufNames := map[string]bool{}
	currentPayloadProtected := func() map[string]bool {
		m := map[string]bool{sliceParam: true}
		for k := range allChunkNames {
			m[k] = true
		}
		for k := range allBufNames {
			m[k] = true
		}
		for k := range binding.emptyVars {
			m[k] = true
		}
		return m
	}
	var namedErrBoundDirectly, everLatched bool
	if namedErrResult != "" {
		allErrNames[namedErrResult] = true
	}
	if namedCountResult != "" {
		allCountNames[namedCountResult] = true
	}

	// Per-loop auxiliary name tables, active only inside their respective loop walks.
	var loopCountAliases map[string]bool
	var sawLenZeroExitReturn bool
	var chunkVars map[string]bool
	var freshBufVars map[string]bool
	var bufChunkSource map[string]string

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
			if id.Name == sliceParam {
				return sliceParam, true
			}
			if chunkVars[id.Name] {
				return id.Name, true
			}
			if srcChunk, ok := bufChunkSource[id.Name]; ok && srcChunk != "" {
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
		if !isLocal || helperDecl.Type == nil || helperDecl.Type.Results == nil || helperDecl.Type.Results.NumFields() != wantResults || !funcReturnsErrorLast(helperDecl.Type) {
			return false
		}
		if wantResults == 2 && !firstResultIsInt(helperDecl.Type.Results) {
			return false
		}
		calleeBinding, _, boundOK := deriveCalleeBinding(fn, recvType, binding, currentPayloadProtected(), call, helperRecv, helperDecl, func(arg ast.Expr) (string, bool) {
			return sinkSliceSource(arg, st, mode)
		})
		if boundOK && verifyTestingWriterFunc(helperRecv, helperDecl, calleeBinding, topFuncs, typeMethods, visiting) {
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
			if !boundOK {
				return true, "", false
			}
			if !verifyTestingWriterFunc(helperRecv, helperDecl, calleeBinding, topFuncs, typeMethods, visiting) {
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
		for k := range binding.emptyVars {
			if k != cSlice && !bodyDeclaresAnyIdent(lit.Body, map[string]bool{k: true}) && !bodyMutatesOrTakesAddrOfAny(lit.Body, map[string]bool{k: true}) {
				closureEmpty[k] = true
			}
		}
		closureBinding := testingWriterBinding{
			fileFields: binding.fileFields,
			fdFields:   binding.fdFields,
			fileVars:   binding.fileVars,
			fdVars:     binding.fdVars,
			emptyVars:  closureEmpty,
			sliceVar:   cSlice,
		}
		synth := &ast.FuncDecl{Name: &ast.Ident{Name: name}, Type: lit.Type, Body: lit.Body}
		if !verifyTestingWriterFunc(recvType, synth, closureBinding, topFuncs, typeMethods, visiting) {
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
				if chunkUsed != sliceParam {
					return false
				}
				if allCountNames[countID.Name] && countID.Name != namedCountResult {
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
		if st.liveErr == "" && st.dischargedFullSlice1ResultSink && !st.sliceParamMutated && isLenOfIdentCall(expr, sliceParam) {
			return true
		}
		return false
	}

	checkReturn := func(ret *ast.ReturnStmt, st writerPathState, allowNilFromLoop bool, mode writerBlockMode) bool {
		switch len(ret.Results) {
		case 0:
			if namedErrResult == "" {
				return false
			}
			if numResults == 2 {
				if namedCountResult == "" {
					return false
				}
				if st.liveErr != "" && st.liveErr == namedErrResult && st.liveCountVar == namedCountResult {
					return true
				}
				if st.liveErr == "" && st.latchedSink && st.latchedCount {
					return true
				}
				return false
			}
			if st.liveErr != "" && st.liveErr == namedErrResult {
				return true
			}
			if st.liveErr == "" && st.latchedSink {
				return true
			}
			return false
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

	applySinkAssign := func(lhsExprs []ast.Expr, srcChunk string, st writerPathState, mode writerBlockMode) (writerPathState, bool) {
		if st.liveErr != "" {
			return st, false
		}
		if !recordSinkCountLHS(lhsExprs, &st, mode, srcChunk) {
			return st, false
		}
		errName, bound := bindFreshErrIdent(lhsExprs[len(lhsExprs)-1])
		if !bound {
			return st, false
		}
		st.liveErr = errName
		st.lastChunk = srcChunk
		st.lastSinkResultArity = len(lhsExprs)
		if mode == writerBlockChunkLoop {
			st.activeChunk = srcChunk
		}
		if mode == writerBlockSliceLoop {
			st.sawSinkInLoop = true
		}
		st.dischargedLoop = false
		st.dischargedFullSlice1ResultSink = false
		st.discharged2ResultSink = false
		return st, true
	}

	var walkBlock func(stmts []ast.Stmt, st writerPathState, inErrCheckFor string, mode writerBlockMode, inBranch bool) (writerPathState, bool)
	walkBlock = func(stmts []ast.Stmt, st writerPathState, inErrCheckFor string, mode writerBlockMode, inBranch bool) (writerPathState, bool) {
		for idx, stmt := range stmts {
			if idx != len(stmts)-1 && blockAlwaysReturns([]ast.Stmt{stmt}) {
				return st, false
			}
			switch s := stmt.(type) {
			case *ast.EmptyStmt:
				continue
			case *ast.ExprStmt:
				call, isCall := unwrapParens(s.X).(*ast.CallExpr)
				if isCall {
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
						if idType, isID := unwrapParens(vs.Type).(*ast.Ident); isID && idType.Name == "error" {
							for _, n := range vs.Names {
								if n.Name == "" || n.Name == "_" || n.Name == sliceParam || isProtectedIdent(n.Name) {
									return st, false
								}
							}
						} else {
							for _, n := range vs.Names {
								if n.Name == sliceParam || isProtectedIdent(n.Name) {
									return st, false
								}
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
								st, sinkOK = applySinkAssign(lhsExprs, srcChunk, st, mode)
								if !sinkOK {
									return st, false
								}
								allowedPayloadValueSpecs[vs] = true
								continue
							}
						}
					}
					for _, n := range vs.Names {
						if n.Name == sliceParam || isProtectedIdent(n.Name) {
							return st, false
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
							var sinkOK bool
							st, sinkOK = applySinkAssign(s.Lhs, srcChunk, st, mode)
							if !sinkOK {
								return st, false
							}
							allowedPayloadAssigns[s] = true
							continue
						}
					}
				}
				// Wrapping `err = &os.PathError{..., Err: err}` inside `if err != nil`.
				if s.Tok == token.ASSIGN && len(s.Lhs) == 1 && len(s.Rhs) == 1 && st.liveErr != "" && inErrCheckFor == st.liveErr {
					if id, isID := unwrapParens(s.Lhs[0]).(*ast.Ident); isID && id.Name == st.liveErr && isWrappedErrStructPtr(s.Rhs[0], st.liveErr) {
						continue
					}
				}
				// Slice-draining write loop helpers: `n := int(r1)`, `if errno != 0 { n = 0 }`, and `b = b[n:]` / `b = b[int(r1):]`.
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
				// Chunking loop helpers: `chunk := payload`, `chunk = chunk[:cut]`, `buf := make([]byte, 0, ...)`, `buf = append(buf, ...)`, and `payload = payload[len(chunk):]`.
				if mode == writerBlockChunkLoop && len(s.Lhs) == 1 && len(s.Rhs) == 1 {
					if s.Tok == token.DEFINE && !st.chunkAdvancedInLoop && st.activeChunk == "" {
						if lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident); ok && lhsID.Name != "" && lhsID.Name != "_" && lhsID.Name != sliceParam && !isProtectedIdent(lhsID.Name) {
							if rhsID, ok := unwrapParens(s.Rhs[0]).(*ast.Ident); ok && rhsID.Name == sliceParam {
								chunkVars[lhsID.Name] = true
								allChunkNames[lhsID.Name] = true
								allowedPayloadAssigns[s] = true
								continue
							}
							if makeCall, ok := unwrapParens(s.Rhs[0]).(*ast.CallExpr); ok && !makeCall.Ellipsis.IsValid() && len(makeCall.Args) >= 2 && len(makeCall.Args) <= 3 {
								if makeID, ok := unwrapParens(makeCall.Fun).(*ast.Ident); ok && makeID.Name == "make" && isByteSliceType(makeCall.Args[0]) && isZeroIntLit(makeCall.Args[1]) {
									if len(makeCall.Args) == 3 && exprRefsIdentOutsideLen(makeCall.Args[2], currentPayloadProtected()) {
										return st, false
									}
									freshBufVars[lhsID.Name] = true
									allBufNames[lhsID.Name] = true
									allowedPayloadCalls[makeCall] = true
									allowedPayloadAssigns[s] = true
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
							baseID, ok := unwrapParens(sl.X).(*ast.Ident)
							if !ok || baseID.Name != lhsID.Name {
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
							appID, ok := unwrapParens(appCall.Fun).(*ast.Ident)
							if !ok || appID.Name != "append" {
								return st, false
							}
							dstID, ok := unwrapParens(appCall.Args[0]).(*ast.Ident)
							if !ok || dstID.Name != lhsID.Name {
								return st, false
							}
							if srcID, ok := unwrapParens(appCall.Args[1]).(*ast.Ident); ok && (srcID.Name == sliceParam || chunkVars[srcID.Name]) {
								if bufChunkSource[lhsID.Name] != "" {
									return st, false
								}
								bufChunkSource[lhsID.Name] = srcID.Name
								allowedPayloadCalls[appCall] = true
								allowedPayloadAssigns[s] = true
								continue
							}
							if bufChunkSource[lhsID.Name] == "" && isProvablyEmptyByteSliceArg(appCall.Args[1], binding) {
								allowedPayloadCalls[appCall] = true
								allowedPayloadAssigns[s] = true
								continue
							}
							return st, false
						}
					}
					if isChunkAdvanceSliceAssign(s, sliceParam, st.activeChunk) {
						if st.chunkAdvancedInLoop || st.liveErr != "" {
							return st, false
						}
						st.chunkAdvancedInLoop = true
						allowedPayloadAssigns[s] = true
						continue
					}
				}
				payloadProtectedNow := currentPayloadProtected()
				for _, lhs := range s.Lhs {
					switch target := unwrapParens(lhs).(type) {
					case *ast.Ident:
						if target.Name == sliceParam || isProtectedIdent(target.Name) {
							return st, false
						}
					case *ast.IndexExpr:
						if exprReferencesAnyIdent(target.X, payloadProtectedNow) {
							return st, false
						}
					case *ast.StarExpr:
						if exprReferencesAnyIdent(target.X, payloadProtectedNow) {
							return st, false
						}
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
				// Monotonic latch in chunking loops: `if chunkErr == nil && err == nil { written += len(chunk) } else if chunkErr != nil && err == nil { err = chunkErr }`
				if mode == writerBlockChunkLoop && !inBranch && st.liveErr != "" && namedErrResult != "" && !namedErrBoundDirectly {
					if updatedCount, latchOK := isMonotonicLatchIf(s, st.liveErr, namedErrResult, namedCountResult, st.activeChunk, numResults == 2); latchOK {
						everLatched = true
						st.latchedSink = true
						if updatedCount && namedCountResult != "" {
							st.latchedCount = true
						}
						st.liveErr = ""
						continue
					}
				}
				// Transient EINTR/EAGAIN retry inside a slice-draining write loop.
				if mode == writerBlockSliceLoop && !inBranch && st.liveErr != "" && isTransientErrnoRetryIf(s, st.liveErr) {
					continue
				}
				// Guarded slice advance `if n > 0 { b = b[n:] }` inside a slice-draining write loop.
				if mode == writerBlockSliceLoop && !inBranch && s.Else == nil && len(s.Body.List) == 1 && isCountPositiveCond(s.Cond, loopCountAliases) {
					if as, ok := s.Body.List[0].(*ast.AssignStmt); ok && isCountAdvanceSliceAssign(as, sliceParam, loopCountAliases) {
						if st.sliceAdvancedInLoop {
							return st, false
						}
						st.sliceAdvancedInLoop = true
						allowedPayloadAssigns[as] = true
						continue
					}
				}
				// Chunking loop exit `if len(payload) == 0 { return written, err }` after advancing payload.
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
				savedAllErrs := make(map[string]bool, len(allErrNames))
				for k, v := range allErrNames {
					savedAllErrs[k] = v
				}
				savedAllCounts := make(map[string]bool, len(allCountNames))
				for k, v := range allCountNames {
					savedAllCounts[k] = v
				}
				thenSt, thenOK := walkBlock(s.Body.List, entrySt, checkedErr, mode, true)
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
							// Forbid arbitrary early returns from a chunking loop before draining sliceParam.
							return st, false
						} else {
							st = entrySt
						}
					} else {
						if thenSt != entrySt {
							return st, false
						}
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
				elseSt, elseOK := walkBlock(elseStmts, elseEntry, "", mode, true)
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
					st = elseSt
				case !thenRet && elseRet:
					st = thenSt
				default:
					if thenSt != elseSt {
						return st, false
					}
					st = thenSt
				}
			case *ast.ForStmt:
				isPureNonSinkLoop := func(loop *ast.ForStmt) bool {
					if loop.Cond == nil {
						return false
					}
					loopPayloadProtected := currentPayloadProtected()
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
								switch target := unwrapParens(lhs).(type) {
								case *ast.Ident:
									if target.Name == sliceParam || isProtectedIdent(target.Name) {
										bad = true
										return false
									}
								case *ast.IndexExpr:
									if exprReferencesAnyIdent(target.X, loopPayloadProtected) {
										bad = true
										return false
									}
								case *ast.StarExpr:
									if exprReferencesAnyIdent(target.X, loopPayloadProtected) {
										bad = true
										return false
									}
								}
							}
						case *ast.IncDecStmt:
							id, ok := unwrapParens(node.X).(*ast.Ident)
							if !ok || id.Name == sliceParam || isProtectedIdent(id.Name) || loopPayloadProtected[id.Name] {
								bad = true
								return false
							}
						}
						return true
					})
					return !bad
				}
				if s.Init != nil || s.Post != nil {
					if !isPureNonSinkLoop(s) {
						return st, false
					}
					continue
				}
				if s.Cond != nil {
					if mode == writerBlockPlain && !inBranch && isLenSlicePositiveCond(s.Cond, sliceParam) && !st.sliceParamMutated && st.liveErr == "" {
						var badLoopBranch bool
						for _, ls := range s.Body.List {
							if _, isBr := ls.(*ast.BranchStmt); isBr {
								badLoopBranch = true
								break
							}
							if ifs, isIf := ls.(*ast.IfStmt); isIf {
								ast.Inspect(ifs, func(n ast.Node) bool {
									if badLoopBranch || n == nil {
										return false
									}
									switch bn := n.(type) {
									case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
										return false
									case *ast.BranchStmt:
										if bn.Tok == token.BREAK || bn.Tok == token.GOTO || bn.Label != nil {
											badLoopBranch = true
											return false
										}
										if bn.Tok == token.CONTINUE {
											if n != ifs.Body.List[0] || len(ifs.Body.List) != 1 || ifs.Else != nil {
												badLoopBranch = true
												return false
											}
										}
									}
									return true
								})
							}
						}
						if badLoopBranch {
							return st, false
						}
						loopCountAliases = map[string]bool{}
						loopSt, loopOK := walkBlock(s.Body.List, writerPathState{}, "", writerBlockSliceLoop, false)
						if !loopOK || loopSt.liveErr != "" || !loopSt.sawSinkInLoop || !loopSt.sliceAdvancedInLoop {
							return st, false
						}
						st.sliceParamMutated = true
						st.dischargedLoop = true
						st.dischargedFullSlice1ResultSink = false
						st.discharged2ResultSink = false
						continue
					}
					if !isPureNonSinkLoop(s) {
						return st, false
					}
					continue
				}
				// Unconditional `for { ... }` chunking loop.
				if mode != writerBlockPlain || inBranch || st.liveErr != "" || st.sliceParamMutated {
					return st, false
				}
				var hasOuterBranch bool
				ast.Inspect(s.Body, func(n ast.Node) bool {
					if hasOuterBranch || n == nil {
						return false
					}
					switch bn := n.(type) {
					case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.FuncLit:
						return false
					case *ast.BranchStmt:
						if bn.Tok == token.BREAK || bn.Tok == token.CONTINUE || bn.Tok == token.GOTO || bn.Label != nil {
							hasOuterBranch = true
							return false
						}
					}
					return true
				})
				if hasOuterBranch {
					return st, false
				}
				sawLenZeroExitReturn = false
				chunkVars = map[string]bool{}
				freshBufVars = map[string]bool{}
				bufChunkSource = map[string]string{}
				loopSt, loopOK := walkBlock(s.Body.List, writerPathState{}, "", writerBlockChunkLoop, false)
				if !loopOK || loopSt.liveErr != "" || !loopSt.chunkAdvancedInLoop || !sawLenZeroExitReturn {
					return st, false
				}
				st.sliceParamMutated = true
			case *ast.ReturnStmt:
				if mode == writerBlockChunkLoop && st.liveErr == "" {
					// Chunking loop exits when liveErr == "" must go through `if len(sliceParam) == 0 { return ... }` after advancing.
					return st, false
				}
				if !checkReturn(s, st, st.dischargedLoop && inErrCheckFor == "", mode) {
					return st, false
				}
				st.liveErr = ""
			case *ast.IncDecStmt:
				id, ok := unwrapParens(s.X).(*ast.Ident)
				if !ok || id.Name == sliceParam || isProtectedIdent(id.Name) {
					return st, false
				}
			case *ast.BlockStmt:
				var blkOK bool
				st, blkOK = walkBlock(s.List, st, inErrCheckFor, mode, inBranch)
				if !blkOK {
					return st, false
				}
			default:
				return st, false
			}
		}
		return st, true
	}

	endSt, ok := walkBlock(fn.Body.List, writerPathState{}, "", writerBlockPlain, false)
	if !ok || endSt.liveErr != "" {
		return false
	}

	// Whole-body post-check: forbid labels/goto/labeled-branches, taking addresses of
	// protected/slice variables (other than validated `&b[0]` inside `RawSyscall`),
	// unverified closures, closure mutation/aliasing of outer protected variables, ++/-- on
	// protected vars or indexed/dereferenced operands, defers referencing protected vars,
	// and any unapproved payload/chunk/buf/empty-var aliasing, mutation, or call escape.
	payloadProtected := currentPayloadProtected()
	protectedAll := map[string]bool{sliceParam: true}
	for k := range localClosures {
		protectedAll[k] = true
	}
	for k := range allErrNames {
		protectedAll[k] = true
	}
	for k := range allCountNames {
		protectedAll[k] = true
	}
	for k := range allLoopCountNames {
		protectedAll[k] = true
	}
	for k := range allChunkNames {
		protectedAll[k] = true
	}
	for k := range allBufNames {
		protectedAll[k] = true
	}
	for k := range protectedSinks {
		protectedAll[k] = true
	}

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
			// Do not descend into verified sink closures with the outer variable names
			// (the inner closure has already passed its own whole-body post-check);
			// verify the inner closure does not mutate outer protected variables or
			// reference outer non-empty payload/chunk/buf variables.
			outerProtected := map[string]bool{}
			for k := range protectedAll {
				outerProtected[k] = true
			}
			outerPayload := map[string]bool{sliceParam: true}
			for k := range allChunkNames {
				outerPayload[k] = true
			}
			for k := range allBufNames {
				outerPayload[k] = true
			}
			for _, p := range paramNamesFlat(x.Type.Params) {
				delete(outerProtected, p)
				delete(outerPayload, p)
			}
			if bodyMutatesOrTakesAddrOfAny(x.Body, outerProtected) || exprReferencesAnyIdent(x.Body, outerPayload) {
				postCheckBad = true
			}
			return
		case *ast.GoStmt, *ast.LabeledStmt, *ast.SendStmt:
			postCheckBad = true
			return
		case *ast.BranchStmt:
			if x.Tok == token.GOTO || x.Label != nil {
				postCheckBad = true
				return
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND && !allowedSliceZeroAmps[x] {
				if id, ok := unwrapParens(x.X).(*ast.Ident); ok && protectedAll[id.Name] {
					postCheckBad = true
					return
				}
				if exprReferencesAnyIdent(x.X, payloadProtected) {
					postCheckBad = true
					return
				}
			}
		case *ast.IncDecStmt:
			id, ok := unwrapParens(x.X).(*ast.Ident)
			if !ok || protectedAll[id.Name] || payloadProtected[id.Name] {
				postCheckBad = true
				return
			}
		case *ast.DeferStmt:
			if _, isLit := unwrapParens(x.Call.Fun).(*ast.FuncLit); isLit {
				postCheckBad = true
				return
			}
			if exprReferencesAnyIdent(x.Call, protectedAll) || exprReferencesAnyIdent(x.Call, payloadProtected) {
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
				switch target := unwrapParens(lhs).(type) {
				case *ast.IndexExpr:
					if exprReferencesAnyIdent(target.X, payloadProtected) {
						postCheckBad = true
						return
					}
				case *ast.StarExpr:
					if exprReferencesAnyIdent(target.X, payloadProtected) {
						postCheckBad = true
						return
					}
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
	inspectNoNestedClosures(fn.Body)
	return !postCheckBad
}

func verifyTestingCustomWriter(typeName string, allowedLit *ast.CompositeLit, binding testingWriterBinding, files []*ast.File, topFuncs map[string]*ast.FuncDecl, typeMethods map[string]map[string]*ast.FuncDecl) bool {
	if typeName == "" || ast.IsExported(typeName) || allowedLit == nil || (len(binding.fileFields) == 0 && len(binding.fdFields) == 0) {
		return false
	}
	allBoundFields := map[string]bool{}
	for k := range binding.fileFields {
		allBoundFields[k] = true
	}
	for k := range binding.fdFields {
		allBoundFields[k] = true
	}

	var matchedSpecs []*ast.TypeSpec
	allowedTypeIdents := map[*ast.Ident]bool{}
	if litTypeID, ok := unwrapParens(allowedLit.Type).(*ast.Ident); ok && litTypeID.Name == typeName {
		allowedTypeIdents[litTypeID] = true
	} else {
		return false
	}

	var methodDecls []*ast.FuncDecl
	for _, f := range files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				if d.Tok != token.TYPE {
					continue
				}
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if ok && ts.Name.Name == typeName {
						matchedSpecs = append(matchedSpecs, ts)
						allowedTypeIdents[ts.Name] = true
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
	if len(matchedSpecs) != 1 {
		return false
	}
	ts := matchedSpecs[0]
	if ts.Assign.IsValid() || ts.TypeParams != nil {
		return false
	}
	st, ok := unwrapParens(ts.Type).(*ast.StructType)
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

	// Verify typeName is referenced nowhere else in package testing (no other
	// composite literals, zero-value vars, new(...), fields, params, or type assertions).
	if !allNonSelPropIdentsIn(files, typeName, allowedTypeIdents) {
		return false
	}

	// Verify every method on typeName keeps the receiver unescaped and never
	// mutates or takes the address of any bound field.
	for _, m := range methodDecls {
		if m.Body == nil {
			return false
		}
		recv := recvVarName(m)
		if recv == "" {
			continue
		}
		if bodyMutatesOrTakesAddrOfAny(m.Body, map[string]bool{recv: true}) || !blockOnlySelectsOnIdent(m.Body, recv) || nodeMutatesOrTakesAddrOfSelector(m.Body, recv, allBoundFields) {
			return false
		}
	}

	methods := typeMethods[typeName]
	if methods == nil || len(methods) != len(methodDecls) {
		return false
	}
	if methods["ReadFrom"] != nil {
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
	return verifyTestingWriterFunc(typeName, writeFn, binding, topFuncs, typeMethods, map[string]bool{})
}
