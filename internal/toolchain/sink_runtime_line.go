package toolchain

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/cprep"
)

// discoverVerifiedRuntimeLineWriters returns sorted `"runtime.<fn>"` symbols in
// package runtime that are exposed via //go:linkname and mechanically verified
// to format `"<op> <name>\n"` and write the complete byte sequence to `fd` via
// `write1` (retrying only `_EINTR`/`_EAGAIN` and returning `0` iff all bytes
// were written, else a positive non-zero errno).
func discoverVerifiedRuntimeLineWriters(files []*ast.File, goSrcs []string) []string {
	linknamed := map[string]bool{}
	badLinkname := map[string]bool{}
	for _, src := range goSrcs {
		err := scanGoDirectiveComments(src, func(line string) error {
			if !strings.HasPrefix(line, "//go:linkname") {
				return nil
			}
			fields, ok := cprep.ParseGoLinknameLineFields(line)
			if !ok {
				return nil
			}
			localSym := fields[1]
			if len(fields) == 2 || fields[2] == "runtime."+localSym {
				linknamed[localSym] = true
			} else {
				badLinkname[localSym] = true
			}
			return nil
		})
		if err != nil || len(linknamed) == 0 {
			continue
		}
	}
	if len(linknamed) == 0 {
		return nil
	}

	idx, err := indexPackageAST("runtime", files, nil, nil)
	if err != nil {
		return nil
	}
	fileImportsUnsafe := map[*ast.File]bool{}
	for _, f := range files {
		for _, imp := range f.Imports {
			if imp.Path == nil {
				continue
			}
			p, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil || p != "unsafe" {
				continue
			}
			if imp.Name != nil && imp.Name.Name != "_" {
				return nil
			}
			if imp.Name == nil {
				fileImportsUnsafe[f] = true
			}
		}
	}
	reserved := map[string]bool{
		"uintptr": true, "int": true, "int32": true, "byte": true, "string": true,
		"len": true, "copy": true, "unsafe": true, "nil": true,
		"write1": true, "add": true, "_EINTR": true, "_EAGAIN": true,
	}
	for r := range reserved {
		if r != "write1" && r != "add" && r != "_EINTR" && r != "_EAGAIN" && r != "unsafe" && idx.pkgDeclCounts[r] > 0 {
			return nil
		}
	}

	verifiedWriteAll := map[string]string{}
	for name, fn := range idx.topFuncs {
		if ast.IsExported(name) || idx.pkgDeclCounts[name] != 1 || badLinkname[name] || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil {
			continue
		}
		if resType, ok := verifyRuntimeWrite1RetryHelper(fn, fileImportsUnsafe[idx.funcFile[fn]], reserved); ok {
			verifiedWriteAll[name] = resType
		}
	}
	if len(verifiedWriteAll) == 0 {
		return nil
	}

	verified := map[string]bool{}
	for name, fn := range idx.topFuncs {
		if !linknamed[name] || badLinkname[name] || ast.IsExported(name) || idx.pkgDeclCounts[name] != 1 || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil {
			continue
		}
		if verifyRuntimeFormattedLineWriter(fn, fileImportsUnsafe[idx.funcFile[fn]], verifiedWriteAll, reserved) {
			verified["runtime."+name] = true
		}
	}
	return sortedKeys(verified)
}

func verifyRuntimeWrite1RetryHelper(fn *ast.FuncDecl, hasUnsafe bool, reserved map[string]bool) (string, bool) {
	if !hasUnsafe || fn.Type.Params == nil || fn.Type.Params.NumFields() != 3 || !funcHasUnnamedResults(fn.Type, 1) || funcShadowsAnyIdent(fn, reserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
		return "", false
	}
	resID, okRes := unwrapParens(fn.Type.Results.List[0].Type).(*ast.Ident)
	if !okRes || (resID.Name != "int32" && resID.Name != "int") {
		return "", false
	}
	pNames := paramNamesFlat(fn.Type.Params)
	if len(pNames) != 3 || pNames[0] == "" || pNames[0] == "_" || pNames[1] == "" || pNames[1] == "_" || pNames[2] == "" || pNames[2] == "_" {
		return "", false
	}
	var pTypes []ast.Expr
	for _, fld := range fn.Type.Params.List {
		for range max(1, len(fld.Names)) {
			pTypes = append(pTypes, fld.Type)
		}
	}
	if len(pTypes) != 3 {
		return "", false
	}
	_, okT0 := isIdentNamed(pTypes[0], "uintptr")
	_, okT1 := isSelectorBaseField(pTypes[1], "unsafe", "Pointer")
	_, okT2 := isIdentNamed(pTypes[2], "int")
	if !okT0 || !okT1 || !okT2 {
		return "", false
	}
	fdParam, ptrParam, remParam := pNames[0], pNames[1], pNames[2]
	if bodyMutatesOrTakesAddrOfAny(fn.Body, map[string]bool{fdParam: true}) {
		return "", false
	}

	posConsts := map[string]bool{}
	stmts := fn.Body.List
	pos := 0
	for pos < len(stmts) {
		ds, ok := stmts[pos].(*ast.DeclStmt)
		if !ok {
			break
		}
		gd, ok := ds.Decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			return "", false
		}
		for _, sp := range gd.Specs {
			vs, ok := sp.(*ast.ValueSpec)
			if !ok || len(vs.Names) != len(vs.Values) {
				return "", false
			}
			for i, id := range vs.Names {
				if !isPositiveIntLit(vs.Values[i]) {
					return "", false
				}
				posConsts[id.Name] = true
			}
		}
		pos++
	}
	if len(stmts)-pos != 2 {
		return "", false
	}
	loop, okL := stmts[pos].(*ast.ForStmt)
	ret0, okR := stmts[pos+1].(*ast.ReturnStmt)
	if !okL || !okR || loop.Init != nil || loop.Post != nil || len(ret0.Results) != 1 || !isZeroIntLit(ret0.Results[0]) {
		return "", false
	}
	condBin, okCB := unwrapParens(loop.Cond).(*ast.BinaryExpr)
	if !okCB || condBin.Op != token.GTR || !isZeroIntLit(condBin.Y) {
		return "", false
	}
	if _, ok := isIdentNamed(condBin.X, remParam); !ok {
		return "", false
	}

	bs := loop.Body.List
	bPos := 0
	chunkVar := remParam
	if bPos+1 < len(bs) {
		if as, okA := bs[bPos].(*ast.AssignStmt); okA && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			if cID, okID := unwrapParens(as.Lhs[0]).(*ast.Ident); okID {
				if _, okRem := isIdentNamed(as.Rhs[0], remParam); okRem {
					if clampIf, okIf := bs[bPos+1].(*ast.IfStmt); okIf && clampIf.Init == nil && clampIf.Else == nil && len(clampIf.Body.List) == 1 {
						gt, okGT := unwrapParens(clampIf.Cond).(*ast.BinaryExpr)
						cAs, okCA := clampIf.Body.List[0].(*ast.AssignStmt)
						if okGT && gt.Op == token.GTR && isPositiveIntLit(gt.Y) && okCA && cAs.Tok == token.ASSIGN && len(cAs.Lhs) == 1 && len(cAs.Rhs) == 1 && isPositiveIntLit(cAs.Rhs[0]) {
							_, ok1 := isIdentNamed(gt.X, cID.Name)
							_, ok2 := isIdentNamed(cAs.Lhs[0], cID.Name)
							if ok1 && ok2 {
								chunkVar = cID.Name
								bPos += 2
							}
						}
					}
				}
			}
		}
	}
	if len(bs)-bPos < 4 {
		return "", false
	}
	wAs, okW := bs[bPos].(*ast.AssignStmt)
	if !okW || wAs.Tok != token.DEFINE || len(wAs.Lhs) != 1 || len(wAs.Rhs) != 1 {
		return "", false
	}
	rID, okRID := unwrapParens(wAs.Lhs[0]).(*ast.Ident)
	wCall, okWC := unwrapParens(wAs.Rhs[0]).(*ast.CallExpr)
	if !okRID || rID.Name == "" || rID.Name == "_" || !okWC || wCall.Ellipsis.IsValid() || len(wCall.Args) != 3 {
		return "", false
	}
	_, okFun := isIdentNamed(wCall.Fun, "write1")
	_, okA0 := isIdentNamed(wCall.Args[0], fdParam)
	_, okA1 := isIdentNamed(wCall.Args[1], ptrParam)
	if !okFun || !okA0 || !okA1 {
		return "", false
	}
	nArg := unwrapParens(wCall.Args[2])
	if conv, okC := nArg.(*ast.CallExpr); okC && !conv.Ellipsis.IsValid() && len(conv.Args) == 1 {
		if _, okI32 := isIdentNamed(conv.Fun, "int32"); okI32 {
			nArg = unwrapParens(conv.Args[0])
		}
	}
	if _, okChunk := isIdentNamed(nArg, chunkVar); !okChunk {
		return "", false
	}
	bPos++

	advIf, okAdv := bs[bPos].(*ast.IfStmt)
	if !okAdv || advIf.Init != nil || advIf.Else != nil || len(advIf.Body.List) != 3 {
		return "", false
	}
	rPosCond, okRP := unwrapParens(advIf.Cond).(*ast.BinaryExpr)
	if !okRP || rPosCond.Op != token.GTR || !isZeroIntLit(rPosCond.Y) {
		return "", false
	}
	if _, ok := isIdentNamed(rPosCond.X, rID.Name); !ok {
		return "", false
	}
	pAdv, okPA := advIf.Body.List[0].(*ast.AssignStmt)
	remSub, okRS := advIf.Body.List[1].(*ast.AssignStmt)
	contBr, okCB2 := advIf.Body.List[2].(*ast.BranchStmt)
	if !okPA || pAdv.Tok != token.ASSIGN || len(pAdv.Lhs) != 1 || len(pAdv.Rhs) != 1 || !okRS || remSub.Tok != token.SUB_ASSIGN || len(remSub.Lhs) != 1 || len(remSub.Rhs) != 1 || !okCB2 || contBr.Tok != token.CONTINUE {
		return "", false
	}
	if _, ok := isIdentNamed(pAdv.Lhs[0], ptrParam); !ok {
		return "", false
	}
	addCall, okAC := unwrapParens(pAdv.Rhs[0]).(*ast.CallExpr)
	if !okAC || addCall.Ellipsis.IsValid() || len(addCall.Args) != 2 {
		return "", false
	}
	_, okAddFn := isIdentNamed(addCall.Fun, "add")
	_, okAddP := isIdentNamed(addCall.Args[0], ptrParam)
	uConv, okUC := unwrapParens(addCall.Args[1]).(*ast.CallExpr)
	if !okAddFn || !okAddP || !okUC || uConv.Ellipsis.IsValid() || len(uConv.Args) != 1 {
		return "", false
	}
	_, okUP := isIdentNamed(uConv.Fun, "uintptr")
	_, okUR := isIdentNamed(uConv.Args[0], rID.Name)
	if !okUP || !okUR {
		return "", false
	}
	if _, ok := isIdentNamed(remSub.Lhs[0], remParam); !ok {
		return "", false
	}
	subRHS := unwrapParens(remSub.Rhs[0])
	if ic, okIC := subRHS.(*ast.CallExpr); okIC && !ic.Ellipsis.IsValid() && len(ic.Args) == 1 {
		if _, okInt := isIdentNamed(ic.Fun, "int"); okInt {
			subRHS = unwrapParens(ic.Args[0])
		}
	}
	if _, ok := isIdentNamed(subRHS, rID.Name); !ok {
		return "", false
	}
	bPos++

	eAs, okEA := bs[bPos].(*ast.AssignStmt)
	if !okEA || eAs.Tok != token.DEFINE || len(eAs.Lhs) != 1 || len(eAs.Rhs) != 1 {
		return "", false
	}
	eID, okEID := unwrapParens(eAs.Lhs[0]).(*ast.Ident)
	negU, okNeg := unwrapParens(eAs.Rhs[0]).(*ast.UnaryExpr)
	if !okEID || eID.Name == "" || eID.Name == "_" || !okNeg || negU.Op != token.SUB {
		return "", false
	}
	if _, ok := isIdentNamed(negU.X, rID.Name); !ok {
		return "", false
	}
	bPos++

	retryIf, okRI := bs[bPos].(*ast.IfStmt)
	if !okRI || retryIf.Init != nil || retryIf.Else != nil || len(retryIf.Body.List) != 1 {
		return "", false
	}
	rBr, okRBr := retryIf.Body.List[0].(*ast.BranchStmt)
	if !okRBr || rBr.Tok != token.CONTINUE {
		return "", false
	}
	isRtErrno := func(e ast.Expr) bool {
		b, okB := unwrapParens(e).(*ast.BinaryExpr)
		if !okB || b.Op != token.EQL {
			return false
		}
		_, okL := isIdentNamed(b.X, eID.Name)
		cID, okR := unwrapParens(b.Y).(*ast.Ident)
		return okL && okR && (cID.Name == "_EINTR" || cID.Name == "_EAGAIN")
	}
	rCond := unwrapParens(retryIf.Cond)
	if !isRtErrno(rCond) {
		orBin, okOr := rCond.(*ast.BinaryExpr)
		if !okOr || orBin.Op != token.LOR || !isRtErrno(orBin.X) || !isRtErrno(orBin.Y) {
			return "", false
		}
	}
	bPos++

	if len(bs)-bPos != 2 {
		return "", false
	}
	leIf, okLE := bs[bPos].(*ast.IfStmt)
	endRet, okER := bs[bPos+1].(*ast.ReturnStmt)
	if !okLE || leIf.Init != nil || leIf.Else != nil || len(leIf.Body.List) != 1 || !okER || len(endRet.Results) != 1 {
		return "", false
	}
	leBin, okLB := unwrapParens(leIf.Cond).(*ast.BinaryExpr)
	leRet, okLR := leIf.Body.List[0].(*ast.ReturnStmt)
	if !okLB || leBin.Op != token.LEQ || !isZeroIntLit(leBin.Y) || !okLR || len(leRet.Results) != 1 {
		return "", false
	}
	if _, ok := isIdentNamed(leBin.X, eID.Name); !ok {
		return "", false
	}
	isPosErrnoExpr := isPositiveIntLit(leRet.Results[0])
	if !isPosErrnoExpr {
		if cID, okC := unwrapParens(leRet.Results[0]).(*ast.Ident); okC && posConsts[cID.Name] {
			isPosErrnoExpr = true
		}
	}
	if !isPosErrnoExpr {
		return "", false
	}
	if _, ok := isIdentNamed(endRet.Results[0], eID.Name); !ok {
		return "", false
	}
	return resID.Name, true
}

func isLenOpPlusNamePlusTwo(expr ast.Expr, opParam, nameParam string) bool {
	var sawOp, sawName bool
	constSum := 0
	var walk func(e ast.Expr) bool
	walk = func(e ast.Expr) bool {
		e = unwrapParens(e)
		if bin, ok := e.(*ast.BinaryExpr); ok && bin.Op == token.ADD {
			return walk(bin.X) && walk(bin.Y)
		}
		if isLenOfIdentCall(e, opParam) && !sawOp {
			sawOp = true
			return true
		}
		if isLenOfIdentCall(e, nameParam) && !sawName {
			sawName = true
			return true
		}
		if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.INT {
			v, err := strconv.Atoi(lit.Value)
			if err == nil && v >= 0 {
				constSum += v
				return true
			}
		}
		return false
	}
	return walk(expr) && sawOp && sawName && constSum == 2
}

func verifyLineBufFormatStmts(stmts []ast.Stmt, bufName, opParam, nameParam string) (nVar string, consumed int, fullCount bool, ok bool) {
	if len(stmts) < 4 {
		return "", 0, false, false
	}
	s0, ok0 := stmts[0].(*ast.AssignStmt)
	if !ok0 || s0.Tok != token.DEFINE || len(s0.Lhs) != 1 || len(s0.Rhs) != 1 {
		return "", 0, false, false
	}
	nID, okNID := unwrapParens(s0.Lhs[0]).(*ast.Ident)
	cp0, okCP0 := unwrapParens(s0.Rhs[0]).(*ast.CallExpr)
	if !okNID || nID.Name == "" || nID.Name == "_" || !okCP0 || cp0.Ellipsis.IsValid() || len(cp0.Args) != 2 {
		return "", 0, false, false
	}
	if _, ok := isIdentNamed(cp0.Fun, "copy"); !ok {
		return "", 0, false, false
	}
	if _, ok := isIdentNamed(cp0.Args[1], opParam); !ok {
		return "", 0, false, false
	}
	dst0 := unwrapParens(cp0.Args[0])
	if sl0, okS := dst0.(*ast.SliceExpr); okS && !sl0.Slice3 && sl0.Low == nil && sl0.High == nil {
		dst0 = unwrapParens(sl0.X)
	}
	if _, ok := isIdentNamed(dst0, bufName); !ok {
		return "", 0, false, false
	}
	nVar = nID.Name

	checkByteAtN := func(st ast.Stmt, want byte) bool {
		as, okA := st.(*ast.AssignStmt)
		if !okA || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return false
		}
		ix, okIX := unwrapParens(as.Lhs[0]).(*ast.IndexExpr)
		lit, okL := unwrapParens(as.Rhs[0]).(*ast.BasicLit)
		if !okIX || !okL || lit.Kind != token.CHAR {
			return false
		}
		_, okB := isIdentNamed(ix.X, bufName)
		_, okI := isIdentNamed(ix.Index, nVar)
		ch, _, tail, err := strconv.UnquoteChar(strings.Trim(lit.Value, "'"), '\'')
		return okB && okI && err == nil && tail == "" && ch == rune(want)
	}
	checkIncN := func(st ast.Stmt) bool {
		inc, okI := st.(*ast.IncDecStmt)
		if !okI || inc.Tok != token.INC {
			return false
		}
		_, okN := isIdentNamed(inc.X, nVar)
		return okN
	}
	if !checkByteAtN(stmts[1], ' ') || !checkIncN(stmts[2]) || len(stmts) < 5 {
		return "", 0, false, false
	}
	s3, ok3 := stmts[3].(*ast.AssignStmt)
	if !ok3 || s3.Tok != token.ADD_ASSIGN || len(s3.Lhs) != 1 || len(s3.Rhs) != 1 {
		return "", 0, false, false
	}
	if _, ok := isIdentNamed(s3.Lhs[0], nVar); !ok {
		return "", 0, false, false
	}
	cp1, okCP1 := unwrapParens(s3.Rhs[0]).(*ast.CallExpr)
	if !okCP1 || cp1.Ellipsis.IsValid() || len(cp1.Args) != 2 {
		return "", 0, false, false
	}
	_, okCopy := isIdentNamed(cp1.Fun, "copy")
	_, okName := isIdentNamed(cp1.Args[1], nameParam)
	sl1, okSL1 := unwrapParens(cp1.Args[0]).(*ast.SliceExpr)
	if !okCopy || !okName || !okSL1 || sl1.Slice3 || sl1.High != nil || sl1.Low == nil {
		return "", 0, false, false
	}
	_, okBuf := isIdentNamed(sl1.X, bufName)
	_, okLow := isIdentNamed(sl1.Low, nVar)
	if !okBuf || !okLow || !checkByteAtN(stmts[4], '\n') {
		return "", 0, false, false
	}
	if len(stmts) > 5 && checkIncN(stmts[5]) {
		return nVar, 6, true, true
	}
	return nVar, 5, false, true
}

func verifyRuntimeFormattedLineWriter(fn *ast.FuncDecl, hasUnsafe bool, verifiedWriteAll map[string]string, reserved map[string]bool) bool {
	if !hasUnsafe || fn.Type.Params == nil || fn.Type.Params.NumFields() != 3 || !funcHasUnnamedResults(fn.Type, 1) || funcShadowsAnyIdent(fn, reserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
		return false
	}
	resID, okRes := unwrapParens(fn.Type.Results.List[0].Type).(*ast.Ident)
	if !okRes || (resID.Name != "int32" && resID.Name != "int") {
		return false
	}
	pNames := paramNamesFlat(fn.Type.Params)
	if len(pNames) != 3 || pNames[0] == "" || pNames[0] == "_" || pNames[1] == "" || pNames[1] == "_" || pNames[2] == "" || pNames[2] == "_" {
		return false
	}
	var pTypes []ast.Expr
	for _, fld := range fn.Type.Params.List {
		for range max(1, len(fld.Names)) {
			pTypes = append(pTypes, fld.Type)
		}
	}
	if len(pTypes) != 3 {
		return false
	}
	_, okP0 := isIdentNamed(pTypes[0], "int")
	_, okP1 := isIdentNamed(pTypes[1], "string")
	_, okP2 := isIdentNamed(pTypes[2], "string")
	if !okP0 || !okP1 || !okP2 {
		return false
	}
	fdParam, opParam, nameParam := pNames[0], pNames[1], pNames[2]
	if bodyMutatesOrTakesAddrOfAny(fn.Body, map[string]bool{fdParam: true, opParam: true, nameParam: true}) {
		return false
	}

	stmts := fn.Body.List
	if len(stmts) < 2 {
		return false
	}
	s0, ok0 := stmts[0].(*ast.AssignStmt)
	if !ok0 || s0.Tok != token.DEFINE || len(s0.Lhs) != 1 || len(s0.Rhs) != 1 {
		return false
	}
	totID, okTID := unwrapParens(s0.Lhs[0]).(*ast.Ident)
	if !okTID || totID.Name == "" || totID.Name == "_" || !isLenOpPlusNamePlusTwo(s0.Rhs[0], opParam, nameParam) {
		return false
	}
	totalVar := totID.Name

	checkWriteAllCall := func(expr ast.Expr, checkPtr func(ast.Expr) bool, allowedLenVars map[string]bool) bool {
		c, okC := unwrapParens(expr).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 3 {
			return false
		}
		hID, okH := unwrapParens(c.Fun).(*ast.Ident)
		if !okH || verifiedWriteAll[hID.Name] != resID.Name {
			return false
		}
		fdConv, okFC := unwrapParens(c.Args[0]).(*ast.CallExpr)
		if !okFC || fdConv.Ellipsis.IsValid() || len(fdConv.Args) != 1 {
			return false
		}
		_, okU := isIdentNamed(fdConv.Fun, "uintptr")
		_, okFD := isIdentNamed(fdConv.Args[0], fdParam)
		if !okU || !okFD || !checkPtr(c.Args[1]) {
			return false
		}
		lID, okL := unwrapParens(c.Args[2]).(*ast.Ident)
		return okL && allowedLenVars[lID.Name]
	}

	pos := 1
	if fastIf, okIf := stmts[pos].(*ast.IfStmt); okIf && fastIf.Init == nil && fastIf.Else == nil {
		leBin, okLE := unwrapParens(fastIf.Cond).(*ast.BinaryExpr)
		if !okLE || leBin.Op != token.LEQ || !isPositiveIntLit(leBin.Y) || len(fastIf.Body.List) < 7 {
			return false
		}
		if _, ok := isIdentNamed(leBin.X, totalVar); !ok {
			return false
		}
		capLit := unwrapParens(leBin.Y).(*ast.BasicLit).Value
		ds, okDS := fastIf.Body.List[0].(*ast.DeclStmt)
		if !okDS {
			return false
		}
		gd, okGD := ds.Decl.(*ast.GenDecl)
		if !okGD || gd.Tok != token.VAR || len(gd.Specs) != 1 {
			return false
		}
		vs, okVS := gd.Specs[0].(*ast.ValueSpec)
		if !okVS || len(vs.Names) != 1 || len(vs.Values) != 0 {
			return false
		}
		arrT, okAT := unwrapParens(vs.Type).(*ast.ArrayType)
		if !okAT || arrT.Len == nil {
			return false
		}
		arrLenLit, okAL := unwrapParens(arrT.Len).(*ast.BasicLit)
		_, okByte := isIdentNamed(arrT.Elt, "byte")
		if !okAL || arrLenLit.Kind != token.INT || arrLenLit.Value != capLit || !okByte {
			return false
		}
		bufName := vs.Names[0].Name
		reservedOuter := map[string]bool{totalVar: true, fdParam: true, opParam: true, nameParam: true}
		if bodyDeclaresAnyIdent(fastIf.Body, reservedOuter) {
			return false
		}
		nVar, used, fullN, okFmt := verifyLineBufFormatStmts(fastIf.Body.List[1:], bufName, opParam, nameParam)
		if !okFmt || 1+used+1 != len(fastIf.Body.List) {
			return false
		}
		retS, okRS := fastIf.Body.List[1+used].(*ast.ReturnStmt)
		if !okRS || len(retS.Results) != 1 {
			return false
		}
		lenVars := map[string]bool{totalVar: true}
		if fullN {
			lenVars[nVar] = true
		}
		okFastCall := checkWriteAllCall(retS.Results[0], func(ptrArg ast.Expr) bool {
			ptrArg = unwrapParens(ptrArg)
			if neCall, okNE := ptrArg.(*ast.CallExpr); okNE && !neCall.Ellipsis.IsValid() && len(neCall.Args) == 1 {
				if _, okID := isIdentNamed(neCall.Fun, "noescape"); okID {
					ptrArg = unwrapParens(neCall.Args[0])
				}
			}
			upCall, okUP := ptrArg.(*ast.CallExpr)
			if !okUP || upCall.Ellipsis.IsValid() || len(upCall.Args) != 1 {
				return false
			}
			if _, ok := isSelectorBaseField(upCall.Fun, "unsafe", "Pointer"); !ok {
				return false
			}
			amp, okAmp := unwrapParens(upCall.Args[0]).(*ast.UnaryExpr)
			if !okAmp || amp.Op != token.AND {
				return false
			}
			ix, okIX := unwrapParens(amp.X).(*ast.IndexExpr)
			if !okIX || !isZeroIntLit(ix.Index) {
				return false
			}
			_, okB := isIdentNamed(ix.X, bufName)
			return okB
		}, lenVars)
		if !okFastCall {
			return false
		}
		pos++
	}

	rem := stmts[pos:]
	reservedSlowOuter := map[string]bool{totalVar: true, fdParam: true, opParam: true, nameParam: true}
	if len(rem) < 9 || bodyDeclaresAnyIdent(&ast.BlockStmt{List: rem}, reservedSlowOuter) {
		return false
	}
	isNonZeroErrRetIf := func(st ast.Stmt) bool {
		ifs, okI := st.(*ast.IfStmt)
		if !okI || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
			return false
		}
		ret, okR := ifs.Body.List[0].(*ast.ReturnStmt)
		if !okR || len(ret.Results) != 1 {
			return false
		}
		if isPositiveIntLit(ret.Results[0]) {
			return true
		}
		cID, okC := unwrapParens(ret.Results[0]).(*ast.Ident)
		return okC && cID.Name == "_ENOMEM"
	}
	allocAs, okAA := rem[0].(*ast.AssignStmt)
	pAs, okPA := rem[2].(*ast.AssignStmt)
	bufAs, okBA := rem[4].(*ast.AssignStmt)
	if !okAA || allocAs.Tok != token.DEFINE || len(allocAs.Lhs) != 1 || !isNonZeroErrRetIf(rem[1]) ||
		!okPA || pAs.Tok != token.DEFINE || len(pAs.Lhs) != 1 || len(pAs.Rhs) != 1 || !isNonZeroErrRetIf(rem[3]) ||
		!okBA || bufAs.Tok != token.DEFINE || len(bufAs.Lhs) != 1 || len(bufAs.Rhs) != 1 {
		return false
	}
	allocID, okAl := unwrapParens(allocAs.Lhs[0]).(*ast.Ident)
	pID, okPID := unwrapParens(pAs.Lhs[0]).(*ast.Ident)
	bufID, okBID := unwrapParens(bufAs.Lhs[0]).(*ast.Ident)
	if !okAl || !okPID || !okBID || !condChecksEqErr(rem[3].(*ast.IfStmt).Cond, pID.Name) {
		return false
	}
	pAllocCall, okPAC := unwrapParens(pAs.Rhs[0]).(*ast.CallExpr)
	if !okPAC || pAllocCall.Ellipsis.IsValid() || len(pAllocCall.Args) != 2 {
		return false
	}
	_, okSysAlloc := isIdentNamed(pAllocCall.Fun, "sysAllocOS")
	_, okAllocArg := isIdentNamed(pAllocCall.Args[0], allocID.Name)
	if !okSysAlloc || !okAllocArg {
		return false
	}
	slCall, okSLC := unwrapParens(bufAs.Rhs[0]).(*ast.CallExpr)
	if !okSLC || slCall.Ellipsis.IsValid() || len(slCall.Args) != 2 {
		return false
	}
	_, okUSlice := isSelectorBaseField(slCall.Fun, "unsafe", "Slice")
	_, okTotArg := isIdentNamed(slCall.Args[1], totalVar)
	bytePtrCast, okBPC := unwrapParens(slCall.Args[0]).(*ast.CallExpr)
	if !okUSlice || !okTotArg || !okBPC || bytePtrCast.Ellipsis.IsValid() || len(bytePtrCast.Args) != 1 {
		return false
	}
	starByte, okSB := unwrapParens(bytePtrCast.Fun).(*ast.StarExpr)
	if !okSB {
		return false
	}
	_, okByteID := isIdentNamed(starByte.X, "byte")
	_, okCastP := isIdentNamed(bytePtrCast.Args[0], pID.Name)
	if !okByteID || !okCastP {
		return false
	}
	nVar, used, fullN, okFmt := verifyLineBufFormatStmts(rem[5:], bufID.Name, opParam, nameParam)
	if !okFmt || 5+used+3 != len(rem) {
		return false
	}
	errAs, okEA := rem[5+used].(*ast.AssignStmt)
	freeES, okFE := rem[5+used+1].(*ast.ExprStmt)
	finalRet, okFR := rem[5+used+2].(*ast.ReturnStmt)
	if !okEA || errAs.Tok != token.DEFINE || len(errAs.Lhs) != 1 || len(errAs.Rhs) != 1 || !okFE || !okFR || len(finalRet.Results) != 1 {
		return false
	}
	errID, okEID := unwrapParens(errAs.Lhs[0]).(*ast.Ident)
	if !okEID {
		return false
	}
	lenVars := map[string]bool{totalVar: true}
	if fullN {
		lenVars[nVar] = true
	}
	if !checkWriteAllCall(errAs.Rhs[0], func(ptrArg ast.Expr) bool {
		_, ok := isIdentNamed(ptrArg, pID.Name)
		return ok
	}, lenVars) {
		return false
	}
	freeCall, okFC := unwrapParens(freeES.X).(*ast.CallExpr)
	if !okFC || freeCall.Ellipsis.IsValid() || len(freeCall.Args) != 2 {
		return false
	}
	_, okSysFree := isIdentNamed(freeCall.Fun, "sysFreeOS")
	_, okFP := isIdentNamed(freeCall.Args[0], pID.Name)
	_, okFA := isIdentNamed(freeCall.Args[1], allocID.Name)
	_, okRetErr := isIdentNamed(finalRet.Results[0], errID.Name)
	return okSysFree && okFP && okFA && okRetErr
}
