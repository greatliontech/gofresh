package toolchain

import (
	"go/ast"
	"go/token"
	"strings"
)

func verifyTestdepsDirectFdState(
	idx *PackageASTIndex,
	files []*ast.File,
	k *PackageInactiveKernel,
	loggerType, boundField string,
	startHelper, stopHelper, hostAddHelper string,
	runtimePullMap map[string]string,
	allowedLoggerTypeIdents map[*ast.Ident]bool,
	reqGates map[string]bool,
) ([]string, bool) {
	if idx == nil || k == nil || startHelper == "" || stopHelper == "" || hostAddHelper == "" ||
		startHelper == stopHelper || startHelper == hostAddHelper || stopHelper == hostAddHelper {
		return nil, false
	}
	for _, h := range []string{startHelper, stopHelper, hostAddHelper} {
		if ast.IsExported(h) || idx.pkgDeclCounts[h] != 1 || k.anyLinknameLocals[h] {
			return nil, false
		}
	}
	reserved := map[string]bool{
		"os": true, "io": true, "syscall": true, "atomic": true,
		"int": true, "uint32": true, "uintptr": true, "string": true, "bool": true, "error": true,
		"nil": true, "true": true, "false": true, "panic": true, "recover": true,
	}
	startFn, startFile, okStart := idx.VerifyFuncPreamble("", startHelper, false, reserved)
	stopFn, stopFile, okStop := idx.VerifyFuncPreamble("", stopHelper, false, reserved)
	hostFn, _, okHost := idx.VerifyFuncPreamble("", hostAddHelper, false, reserved)
	if !okStart || !okStop || !okHost {
		return nil, false
	}
	if k.FileImportPath(startFile, "io") != "io" || k.FileImportPath(startFile, "os") != "os" ||
		k.FileImportPath(stopFile, "os") != "os" || k.FileImportPath(stopFile, "syscall") != "syscall" {
		return nil, false
	}

	checkPtrLoggerParam := func(tExpr ast.Expr) bool {
		star, ok := unwrapParens(tExpr).(*ast.StarExpr)
		if !ok {
			return false
		}
		id, ok := isIdentNamed(star.X, loggerType)
		if ok {
			allowedLoggerTypeIdents[id] = true
		}
		return ok
	}

	// 1. Verify startFn `(l *<loggerType>, w io.Writer)`
	if startFn.Type.Params == nil || startFn.Type.Params.NumFields() != 2 || len(startFn.Type.Params.List) != 2 || (startFn.Type.Results != nil && startFn.Type.Results.NumFields() != 0) {
		return nil, false
	}
	sParams := paramNamesFlat(startFn.Type.Params)
	if len(sParams) != 2 || sParams[0] == "" || sParams[0] == "_" || sParams[1] == "" || sParams[1] == "_" || sParams[0] == sParams[1] {
		return nil, false
	}
	if !checkPtrLoggerParam(startFn.Type.Params.List[0].Type) {
		return nil, false
	}
	if _, okW := isSelectorBaseField(startFn.Type.Params.List[1].Type, "io", "Writer"); !okW {
		return nil, false
	}
	lParam, wParam := sParams[0], sParams[1]
	startStmts, _ := k.PruneBlockStmts(startFn.Body.List, startFn, nil, reqGates, nil)
	if len(startStmts) != 4 {
		return nil, false
	}
	flAs, okFA := startStmts[0].(*ast.AssignStmt)
	if !okFA || flAs.Tok != token.DEFINE || len(flAs.Lhs) != 1 || len(flAs.Rhs) != 1 {
		return nil, false
	}
	flErrID, okFE := unwrapParens(flAs.Lhs[0]).(*ast.Ident)
	if !okFE || flErrID.Name == "" || flErrID.Name == "_" {
		return nil, false
	}
	if _, okFl := isZeroArgMethodCallOnSelector(flAs.Rhs[0], lParam, boundField, "Flush"); !okFl {
		return nil, false
	}
	stAs, okSA := startStmts[1].(*ast.AssignStmt)
	if !okSA || stAs.Tok != token.DEFINE || len(stAs.Lhs) != 1 || len(stAs.Rhs) != 1 {
		return nil, false
	}
	stVarID, okSVID := unwrapParens(stAs.Lhs[0]).(*ast.Ident)
	stLit, stateStruct := compositeWriterLit(stAs.Rhs[0])
	uAmp, isAmp := unwrapParens(stAs.Rhs[0]).(*ast.UnaryExpr)
	if !okSVID || stVarID.Name == "" || stVarID.Name == "_" || !isAmp || uAmp.Op != token.AND || stLit == nil || stateStruct == "" || ast.IsExported(stateStruct) || len(stLit.Elts) != 3 {
		return nil, false
	}
	allowedStateTypeIdents := map[*ast.Ident]bool{unwrapParens(stLit.Type).(*ast.Ident): true}
	var targetField, fdField, flushErrField, nameField, errErrnoField string
	for _, elt := range stLit.Elts {
		kv, okKV := elt.(*ast.KeyValueExpr)
		if !okKV {
			return nil, false
		}
		kID, okK := unwrapParens(kv.Key).(*ast.Ident)
		if !okK || kID.Name == "" {
			return nil, false
		}
		val := unwrapParens(kv.Value)
		switch {
		case targetField == "":
			if _, okL := isIdentNamed(val, lParam); okL {
				targetField = kID.Name
				continue
			}
			fallthrough
		default:
			if flushErrField == "" {
				if _, okFE2 := isIdentNamed(val, flErrID.Name); okFE2 {
					flushErrField = kID.Name
					continue
				}
			}
			if fdField == "" {
				if neg, okU := val.(*ast.UnaryExpr); okU && neg.Op == token.SUB {
					if lit1, okL1 := unwrapParens(neg.X).(*ast.BasicLit); okL1 && lit1.Kind == token.INT && lit1.Value == "1" {
						fdField = kID.Name
						continue
					}
				}
			}
			return nil, false
		}
	}
	if targetField == "" || fdField == "" || flushErrField == "" {
		return nil, false
	}
	taIf, okTI := startStmts[2].(*ast.IfStmt)
	if !okTI || taIf.Init == nil || taIf.Else != nil || len(taIf.Body.List) != 1 {
		return nil, false
	}
	taAs, okTAA := taIf.Init.(*ast.AssignStmt)
	if !okTAA || taAs.Tok != token.DEFINE || len(taAs.Lhs) != 2 || len(taAs.Rhs) != 1 {
		return nil, false
	}
	fVarID, okF1 := unwrapParens(taAs.Lhs[0]).(*ast.Ident)
	okVarID, okF2 := unwrapParens(taAs.Lhs[1]).(*ast.Ident)
	taExpr, okTA := unwrapParens(taAs.Rhs[0]).(*ast.TypeAssertExpr)
	if !okF1 || !okF2 || !okTA || taExpr.Type == nil {
		return nil, false
	}
	_, okW2 := isIdentNamed(taExpr.X, wParam)
	_, okCond := isIdentNamed(taIf.Cond, okVarID.Name)
	starOSFile, okStar := unwrapParens(taExpr.Type).(*ast.StarExpr)
	if !okW2 || !okCond || !okStar {
		return nil, false
	}
	if _, okOSF := isSelectorBaseField(starOSFile.X, "os", "File"); !okOSF {
		return nil, false
	}
	fdIf, okFDI := taIf.Body.List[0].(*ast.IfStmt)
	if !okFDI || fdIf.Init == nil || fdIf.Else != nil || len(fdIf.Body.List) < 1 || len(fdIf.Body.List) > 2 {
		return nil, false
	}
	fdAs, okFDA := fdIf.Init.(*ast.AssignStmt)
	fdCond, okFDC := unwrapParens(fdIf.Cond).(*ast.BinaryExpr)
	if !okFDA || fdAs.Tok != token.DEFINE || len(fdAs.Lhs) != 1 || len(fdAs.Rhs) != 1 || !okFDC || fdCond.Op != token.GEQ || !isZeroIntLit(fdCond.Y) {
		return nil, false
	}
	fdLocID, okFDL := unwrapParens(fdAs.Lhs[0]).(*ast.Ident)
	if !okFDL || !isFdMethodCallOnSource(fdAs.Rhs[0], func(src ast.Expr) bool {
		_, ok := isIdentNamed(src, fVarID.Name)
		return ok
	}) {
		return nil, false
	}
	if _, ok := isIdentNamed(fdCond.X, fdLocID.Name); !ok {
		return nil, false
	}
	setFDAs, okSFD := fdIf.Body.List[0].(*ast.AssignStmt)
	if !okSFD || setFDAs.Tok != token.ASSIGN || len(setFDAs.Lhs) != 1 || len(setFDAs.Rhs) != 1 {
		return nil, false
	}
	_, okSetLHS := isSelectorBaseField(setFDAs.Lhs[0], stVarID.Name, fdField)
	_, okSetRHS := isIdentNamed(setFDAs.Rhs[0], fdLocID.Name)
	if !okSetLHS || !okSetRHS {
		return nil, false
	}
	if len(fdIf.Body.List) == 2 {
		setNameAs, okSN := fdIf.Body.List[1].(*ast.AssignStmt)
		if !okSN || setNameAs.Tok != token.ASSIGN || len(setNameAs.Lhs) != 1 || len(setNameAs.Rhs) != 1 {
			return nil, false
		}
		nSel, okNS := unwrapParens(setNameAs.Lhs[0]).(*ast.SelectorExpr)
		if !okNS || nSel.Sel.Name == "" || nSel.Sel.Name == targetField || nSel.Sel.Name == fdField || nSel.Sel.Name == flushErrField {
			return nil, false
		}
		_, okBase := isIdentNamed(nSel.X, stVarID.Name)
		_, okNameCall := isZeroArgMethodCallOnIdent(setNameAs.Rhs[0], fVarID.Name, "Name")
		if !okBase || !okNameCall {
			return nil, false
		}
		nameField = nSel.Sel.Name
	}
	storeES, okSES := startStmts[3].(*ast.ExprStmt)
	if !okSES {
		return nil, false
	}
	storeCall, okSC := unwrapParens(storeES.X).(*ast.CallExpr)
	if !okSC || storeCall.Ellipsis.IsValid() || len(storeCall.Args) != 1 {
		return nil, false
	}
	storeSel, okSS := unwrapParens(storeCall.Fun).(*ast.SelectorExpr)
	if !okSS || storeSel.Sel.Name != "Store" {
		return nil, false
	}
	actID, okAID := unwrapParens(storeSel.X).(*ast.Ident)
	_, okStArg := isIdentNamed(storeCall.Args[0], stVarID.Name)
	if !okAID || actID.Name == "" || ast.IsExported(actID.Name) || !okStArg {
		return nil, false
	}
	activeVar := actID.Name
	allowedActiveIdents := map[*ast.Ident]bool{actID: true}

	// 2. Verify <stateStruct> and <activeVar> declarations.
	stSpec := idx.uniqueTypeSpec(stateStruct)
	if stSpec == nil || idx.pkgDeclCounts[stateStruct] != 1 {
		return nil, false
	}
	stFile := idx.typeSpecFile[stSpec]
	if k.FileImportPath(stFile, "sync/atomic") == "" && k.FileImportPath(stFile, "atomic") != "sync/atomic" {
		return nil, false
	}
	allowedStateTypeIdents[stSpec.Name] = true
	stStruct, okST := unwrapParens(stSpec.Type).(*ast.StructType)
	if !okST || stStruct.Fields == nil {
		return nil, false
	}
	seenFields := map[string]bool{}
	for _, fld := range stStruct.Fields.List {
		if len(fld.Names) == 0 {
			return nil, false
		}
		for _, id := range fld.Names {
			if seenFields[id.Name] || ast.IsExported(id.Name) {
				return nil, false
			}
			seenFields[id.Name] = true
			switch id.Name {
			case targetField:
				if !checkPtrLoggerParam(fld.Type) {
					return nil, false
				}
			case fdField:
				if _, ok := isIdentNamed(fld.Type, "int"); !ok {
					return nil, false
				}
			case flushErrField:
				if _, ok := isIdentNamed(fld.Type, "error"); !ok {
					return nil, false
				}
			case nameField:
				if nameField == "" {
					return nil, false
				}
				if _, ok := isIdentNamed(fld.Type, "string"); !ok {
					return nil, false
				}
			default:
				if errErrnoField != "" {
					return nil, false
				}
				sel, okS := unwrapParens(fld.Type).(*ast.SelectorExpr)
				if !okS || (sel.Sel.Name != "Uint32" && sel.Sel.Name != "Int32") {
					return nil, false
				}
				if _, okA := isIdentNamed(sel.X, "atomic"); !okA || k.FileImportPath(stFile, "atomic") != "sync/atomic" {
					return nil, false
				}
				errErrnoField = id.Name
			}
		}
	}
	if !seenFields[targetField] || !seenFields[fdField] || !seenFields[flushErrField] || errErrnoField == "" {
		return nil, false
	}
	actVS := idx.zeroInitPkgVars[activeVar]
	actFile := idx.pkgVarFiles[activeVar]
	if actVS == nil || idx.pkgVarCounts[activeVar] != 1 || idx.pkgDeclCounts[activeVar] != 1 || k.anyLinknameLocals[activeVar] || k.FileImportPath(actFile, "atomic") != "sync/atomic" {
		return nil, false
	}
	for id := range idx.varDeclIdents[activeVar] {
		allowedActiveIdents[id] = true
	}
	actIdx, okAI := unwrapParens(actVS.Type).(*ast.IndexExpr)
	if !okAI {
		return nil, false
	}
	_, okAPtr := isSelectorBaseField(actIdx.X, "atomic", "Pointer")
	stTypeArgID, okSTArg := isIdentNamed(actIdx.Index, stateStruct)
	if !okAPtr || !okSTArg {
		return nil, false
	}
	allowedStateTypeIdents[stTypeArgID] = true

	// 3. Verify stopFn `(l *<loggerType>) error`
	if stopFn.Type.Params == nil || stopFn.Type.Params.NumFields() != 1 || len(stopFn.Type.Params.List) != 1 || !funcHasUnnamedResults(stopFn.Type, 1) || !funcReturnsErrorLast(stopFn.Type) {
		return nil, false
	}
	stopParams := paramNamesFlat(stopFn.Type.Params)
	if len(stopParams) != 1 || stopParams[0] == "" || stopParams[0] == "_" || !checkPtrLoggerParam(stopFn.Type.Params.List[0].Type) {
		return nil, false
	}
	stopL := stopParams[0]
	stopStmts, _ := k.PruneBlockStmts(stopFn.Body.List, stopFn, nil, reqGates, nil)
	if len(stopStmts) != 6 {
		return nil, false
	}
	loadAs0, okL0 := stopStmts[0].(*ast.AssignStmt)
	if !okL0 || loadAs0.Tok != token.DEFINE || len(loadAs0.Lhs) != 1 || len(loadAs0.Rhs) != 1 {
		return nil, false
	}
	stopStVar, okSSV := unwrapParens(loadAs0.Lhs[0]).(*ast.Ident)
	actLoadID0, okAL0 := isZeroArgMethodCallOnIdent(loadAs0.Rhs[0], activeVar, "Load")
	if !okSSV || stopStVar.Name == "" || stopStVar.Name == "_" || !okAL0 {
		return nil, false
	}
	allowedActiveIdents[actLoadID0] = true

	nilTgtIf, okNTI := stopStmts[1].(*ast.IfStmt)
	if !okNTI || nilTgtIf.Init != nil || nilTgtIf.Else != nil || len(nilTgtIf.Body.List) != 1 {
		return nil, false
	}
	orStop, okOS := unwrapParens(nilTgtIf.Cond).(*ast.BinaryExpr)
	retNil1, okRN1 := nilTgtIf.Body.List[0].(*ast.ReturnStmt)
	if !okOS || orStop.Op != token.LOR || !condChecksEqErr(orStop.X, stopStVar.Name) || !okRN1 || len(retNil1.Results) != 1 {
		return nil, false
	}
	if _, ok := isIdentNamed(retNil1.Results[0], "nil"); !ok {
		return nil, false
	}
	tgtNeq, okTN := unwrapParens(orStop.Y).(*ast.BinaryExpr)
	if !okTN || tgtNeq.Op != token.NEQ {
		return nil, false
	}
	_, okTL := isSelectorBaseField(tgtNeq.X, stopStVar.Name, targetField)
	_, okTR := isIdentNamed(tgtNeq.Y, stopL)
	if !okTL || !okTR {
		return nil, false
	}
	casES, okCES := stopStmts[2].(*ast.ExprStmt)
	if !okCES {
		return nil, false
	}
	casCall, okCC := unwrapParens(casES.X).(*ast.CallExpr)
	if !okCC || casCall.Ellipsis.IsValid() || len(casCall.Args) != 2 {
		return nil, false
	}
	actCASID, okACAS := isSelectorBaseField(casCall.Fun, activeVar, "CompareAndSwap")
	_, okC0 := isIdentNamed(casCall.Args[0], stopStVar.Name)
	_, okC1 := isIdentNamed(casCall.Args[1], "nil")
	if !okACAS || !okC0 || !okC1 {
		return nil, false
	}
	allowedActiveIdents[actCASID] = true
	if !isStickyFieldErrorGuardIf(stopStmts[3], stopStVar.Name, flushErrField) {
		return nil, false
	}
	errnoIf, okEI := stopStmts[4].(*ast.IfStmt)
	if !okEI || errnoIf.Init == nil || errnoIf.Else != nil || len(errnoIf.Body.List) != 1 {
		return nil, false
	}
	eInit, okEIn := errnoIf.Init.(*ast.AssignStmt)
	eRet, okER := errnoIf.Body.List[0].(*ast.ReturnStmt)
	if !okEIn || eInit.Tok != token.DEFINE || len(eInit.Lhs) != 1 || len(eInit.Rhs) != 1 || !okER || len(eRet.Results) != 1 {
		return nil, false
	}
	eVarID, okEV := unwrapParens(eInit.Lhs[0]).(*ast.Ident)
	_, okELoad := isZeroArgMethodCallOnSelector(eInit.Rhs[0], stopStVar.Name, errErrnoField, "Load")
	if !okEV || !okELoad || condChecksNonZeroErr(errnoIf.Cond) != eVarID.Name {
		return nil, false
	}
	peAmp, okPEA := unwrapParens(eRet.Results[0]).(*ast.UnaryExpr)
	if !okPEA || peAmp.Op != token.AND {
		return nil, false
	}
	peLit, okPEL := unwrapParens(peAmp.X).(*ast.CompositeLit)
	if !okPEL || peLit.Type == nil {
		return nil, false
	}
	if _, okPET := isSelectorBaseField(peLit.Type, "os", "PathError"); !okPET {
		return nil, false
	}
	sawWrappedErrno := false
	for _, elt := range peLit.Elts {
		kv, okKV := elt.(*ast.KeyValueExpr)
		if !okKV {
			return nil, false
		}
		kID, okK := unwrapParens(kv.Key).(*ast.Ident)
		if okK && kID.Name == "Err" {
			scConv, okSC := unwrapParens(kv.Value).(*ast.CallExpr)
			if !okSC || scConv.Ellipsis.IsValid() || len(scConv.Args) != 1 {
				return nil, false
			}
			_, okSE := isSelectorBaseField(scConv.Fun, "syscall", "Errno")
			_, okEA := isIdentNamed(scConv.Args[0], eVarID.Name)
			if okSE && okEA {
				sawWrappedErrno = true
			}
		}
	}
	if !sawWrappedErrno {
		return nil, false
	}
	retNil5, okRN5 := stopStmts[5].(*ast.ReturnStmt)
	if !okRN5 || len(retNil5.Results) != 1 {
		return nil, false
	}
	if _, ok := isIdentNamed(retNil5.Results[0], "nil"); !ok {
		return nil, false
	}

	// 4. Verify hostFn `(l *<loggerType>, op, name string) bool`
	if hostFn.Type.Params == nil || hostFn.Type.Params.NumFields() != 3 || !funcHasUnnamedResults(hostFn.Type, 1) {
		return nil, false
	}
	if _, okB := isIdentNamed(hostFn.Type.Results.List[0].Type, "bool"); !okB {
		return nil, false
	}
	hParams := paramNamesFlat(hostFn.Type.Params)
	if len(hParams) != 3 || hParams[0] == "" || hParams[0] == "_" || hParams[1] == "" || hParams[1] == "_" || hParams[2] == "" || hParams[2] == "_" {
		return nil, false
	}
	var hTypes []ast.Expr
	for _, fld := range hostFn.Type.Params.List {
		for range max(1, len(fld.Names)) {
			hTypes = append(hTypes, fld.Type)
		}
	}
	if len(hTypes) != 3 || !checkPtrLoggerParam(hTypes[0]) {
		return nil, false
	}
	_, okS1 := isIdentNamed(hTypes[1], "string")
	_, okS2 := isIdentNamed(hTypes[2], "string")
	if !okS1 || !okS2 {
		return nil, false
	}
	hL, hOp, hName := hParams[0], hParams[1], hParams[2]
	hostStmts, _ := k.PruneBlockStmts(hostFn.Body.List, hostFn, nil, reqGates, nil)
	if len(hostStmts) != 5 {
		return nil, false
	}
	hLoadAs, okHL := hostStmts[0].(*ast.AssignStmt)
	if !okHL || hLoadAs.Tok != token.DEFINE || len(hLoadAs.Lhs) != 1 || len(hLoadAs.Rhs) != 1 {
		return nil, false
	}
	hStVar, okHSV := unwrapParens(hLoadAs.Lhs[0]).(*ast.Ident)
	hActID, okHA := isZeroArgMethodCallOnIdent(hLoadAs.Rhs[0], activeVar, "Load")
	if !okHSV || hStVar.Name == "" || hStVar.Name == "_" || !okHA {
		return nil, false
	}
	allowedActiveIdents[hActID] = true

	hGuardIf, okHGI := hostStmts[1].(*ast.IfStmt)
	if !okHGI || hGuardIf.Init != nil || hGuardIf.Else != nil || len(hGuardIf.Body.List) != 1 {
		return nil, false
	}
	hRetF, okHRF := hGuardIf.Body.List[0].(*ast.ReturnStmt)
	if !okHRF || len(hRetF.Results) != 1 {
		return nil, false
	}
	if _, ok := isIdentNamed(hRetF.Results[0], "false"); !ok {
		return nil, false
	}
	orOuter, okOO := unwrapParens(hGuardIf.Cond).(*ast.BinaryExpr)
	if !okOO || orOuter.Op != token.LOR {
		return nil, false
	}
	orInner, okOI := unwrapParens(orOuter.X).(*ast.BinaryExpr)
	fdLt0, okFLT := unwrapParens(orOuter.Y).(*ast.BinaryExpr)
	if !okOI || orInner.Op != token.LOR || !condChecksEqErr(orInner.X, hStVar.Name) || !okFLT || fdLt0.Op != token.LSS || !isZeroIntLit(fdLt0.Y) {
		return nil, false
	}
	hTgtNeq, okHTN := unwrapParens(orInner.Y).(*ast.BinaryExpr)
	if !okHTN || hTgtNeq.Op != token.NEQ {
		return nil, false
	}
	_, okHT1 := isSelectorBaseField(hTgtNeq.X, hStVar.Name, targetField)
	_, okHT2 := isIdentNamed(hTgtNeq.Y, hL)
	_, okHFD := isSelectorBaseField(fdLt0.X, hStVar.Name, fdField)
	if !okHT1 || !okHT2 || !okHFD {
		return nil, false
	}
	hStickyIf, okHSI := hostStmts[2].(*ast.IfStmt)
	if !okHSI || hStickyIf.Init != nil || hStickyIf.Else != nil || len(hStickyIf.Body.List) != 1 {
		return nil, false
	}
	hRetT2, okHRT2 := hStickyIf.Body.List[0].(*ast.ReturnStmt)
	if !okHRT2 || len(hRetT2.Results) != 1 {
		return nil, false
	}
	if _, ok := isIdentNamed(hRetT2.Results[0], "true"); !ok {
		return nil, false
	}
	stOr, okSO := unwrapParens(hStickyIf.Cond).(*ast.BinaryExpr)
	if !okSO || stOr.Op != token.LOR {
		return nil, false
	}
	flNeq, okFN := unwrapParens(stOr.X).(*ast.BinaryExpr)
	erNeq, okEN := unwrapParens(stOr.Y).(*ast.BinaryExpr)
	if !okFN || flNeq.Op != token.NEQ || !okEN || erNeq.Op != token.NEQ || !isZeroIntLit(erNeq.Y) {
		return nil, false
	}
	_, okFL1 := isSelectorBaseField(flNeq.X, hStVar.Name, flushErrField)
	_, okFL2 := isIdentNamed(flNeq.Y, "nil")
	_, okERL := isZeroArgMethodCallOnSelector(erNeq.X, hStVar.Name, errErrnoField, "Load")
	if !okFL1 || !okFL2 || !okERL {
		return nil, false
	}
	wIf, okWI := hostStmts[3].(*ast.IfStmt)
	if !okWI || wIf.Init == nil || wIf.Else != nil || len(wIf.Body.List) != 1 {
		return nil, false
	}
	wInit, okWIn := wIf.Init.(*ast.AssignStmt)
	wCASStmt, okWCS := wIf.Body.List[0].(*ast.ExprStmt)
	if !okWIn || wInit.Tok != token.DEFINE || len(wInit.Lhs) != 1 || len(wInit.Rhs) != 1 || !okWCS {
		return nil, false
	}
	wErrID, okWE := unwrapParens(wInit.Lhs[0]).(*ast.Ident)
	wCall, okWC := unwrapParens(wInit.Rhs[0]).(*ast.CallExpr)
	if !okWE || !okWC || wCall.Ellipsis.IsValid() || len(wCall.Args) != 3 || condChecksNonZeroErr(wIf.Cond) != wErrID.Name {
		return nil, false
	}
	lwID, okLW := unwrapParens(wCall.Fun).(*ast.Ident)
	if !okLW || k.IdentShadowedInFunc(hostFn, lwID.Name) {
		return nil, false
	}
	rtWriterTarget := runtimePullMap[lwID.Name]
	if !strings.HasPrefix(rtWriterTarget, "runtime.") {
		return nil, false
	}
	_, okWA0 := isSelectorBaseField(wCall.Args[0], hStVar.Name, fdField)
	_, okWA1 := isIdentNamed(wCall.Args[1], hOp)
	_, okWA2 := isIdentNamed(wCall.Args[2], hName)
	if !okWA0 || !okWA1 || !okWA2 {
		return nil, false
	}
	eCASCall, okECC := unwrapParens(wCASStmt.X).(*ast.CallExpr)
	if !okECC || eCASCall.Ellipsis.IsValid() || len(eCASCall.Args) != 2 || !isZeroIntLit(eCASCall.Args[0]) {
		return nil, false
	}
	if _, ok := isSelectorBaseField(eCASCall.Fun, hStVar.Name, errErrnoField); ok {
		return nil, false
	}
	eCASSel, okECS := unwrapParens(eCASCall.Fun).(*ast.SelectorExpr)
	if !okECS || eCASSel.Sel.Name != "CompareAndSwap" {
		return nil, false
	}
	if _, ok := isSelectorBaseField(eCASSel.X, hStVar.Name, errErrnoField); !ok {
		return nil, false
	}
	casVal := unwrapParens(eCASCall.Args[1])
	if u32C, okU32 := casVal.(*ast.CallExpr); okU32 && !u32C.Ellipsis.IsValid() && len(u32C.Args) == 1 {
		if _, okID := isIdentNamed(u32C.Fun, "uint32"); okID {
			casVal = unwrapParens(u32C.Args[0])
		}
	}
	if _, ok := isIdentNamed(casVal, wErrID.Name); !ok {
		return nil, false
	}
	hRet4, okHR4 := hostStmts[4].(*ast.ReturnStmt)
	if !okHR4 || len(hRet4.Results) != 1 {
		return nil, false
	}
	if _, ok := isIdentNamed(hRet4.Results[0], "true"); !ok {
		return nil, false
	}

	for efName := range k.EarlyFalseFuncs {
		efFn := idx.topFuncs[efName]
		if efFn == nil || efFn.Body == nil {
			continue
		}
		ast.Inspect(efFn.Body, func(n ast.Node) bool {
			call, okC := n.(*ast.CallExpr)
			if !okC || call.Ellipsis.IsValid() || len(call.Args) != 0 {
				return true
			}
			if aID, okA := isSelectorBaseField(call.Fun, activeVar, "Load"); okA && !k.IdentShadowedInFunc(efFn, activeVar) {
				allowedActiveIdents[aID] = true
			}
			return true
		})
	}
	badFieldUse := false
	for _, f := range files {
		if nodeMutatesOrTakesAddrOfSelector(f, "", map[string]bool{targetField: true, flushErrField: true, errErrnoField: true}) {
			return nil, false
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if badFieldUse || n == nil {
				return false
			}
			call, okC := n.(*ast.CallExpr)
			if !okC {
				return true
			}
			sel, okS := unwrapParens(call.Fun).(*ast.SelectorExpr)
			if !okS {
				return true
			}
			fSel, okFS := unwrapParens(sel.X).(*ast.SelectorExpr)
			if !okFS || fSel.Sel.Name != errErrnoField {
				return true
			}
			switch sel.Sel.Name {
			case "Load":
				if call.Ellipsis.IsValid() || len(call.Args) != 0 {
					badFieldUse = true
				}
			case "CompareAndSwap":
				if call.Ellipsis.IsValid() || len(call.Args) != 2 || !isZeroIntLit(call.Args[0]) || isZeroIntLit(call.Args[1]) {
					badFieldUse = true
				}
			default:
				badFieldUse = true
			}
			return !badFieldUse
		})
	}
	if badFieldUse {
		return nil, false
	}
	if !allNonSelectorPropIdentsIn(files, map[string]map[*ast.Ident]bool{
		activeVar:   allowedActiveIdents,
		stateStruct: allowedStateTypeIdents,
	}) {
		return nil, false
	}
	return []string{rtWriterTarget}, true
}
