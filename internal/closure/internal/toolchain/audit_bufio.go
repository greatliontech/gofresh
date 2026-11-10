package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
)

// VerifyBufioWriterAST verifies the structural contract for package bufio's Writer.
func VerifyBufioWriterAST(files []*ast.File) error {
	reserved := map[string]bool{
		"io": true, "copy": true, "len": true, "make": true,
		"byte": true, "int": true, "string": true, "error": true,
		"nil": true, "true": true, "false": true,
	}
	idx, err := indexPackageAST("bufio", files, reserved, map[string]bool{"io": true})
	if err != nil {
		return err
	}
	if len(idx.dupTypeMethods["Writer"]) > 0 || len(idx.dupTopFuncs) > 0 {
		return fmt.Errorf("bufio: missing or duplicate Writer type/methods")
	}
	_, _, ok := idx.VerifyStructFields("Writer", map[string]func(ast.Expr) bool{
		"err": func(e ast.Expr) bool { _, ok := isIdentNamed(e, "error"); return ok },
		"buf": isByteSliceType,
		"n":   func(e ast.Expr) bool { _, ok := isIdentNamed(e, "int"); return ok },
		"wr":  func(e ast.Expr) bool { _, ok := isSelectorBaseField(e, "io", "Writer"); return ok },
	}, false)
	if !ok {
		return fmt.Errorf("bufio: invalid Writer struct declaration")
	}
	constPosInt := idx.constPosInt
	writerMethods := idx.typeMethods["Writer"]
	if writerMethods == nil {
		writerMethods = map[string]*ast.FuncDecl{}
	}

	// Verify NewWriter and NewWriterSize construct a Writer bound to w with positive buffer capacity.
	nw, _, okNW := idx.VerifyFuncPreamble("", "NewWriter", false, reserved)
	nws, _, okNWS := idx.VerifyFuncPreamble("", "NewWriterSize", false, reserved)
	if !okNW || !okNWS {
		return fmt.Errorf("bufio: missing NewWriter or NewWriterSize")
	}
	nwParams := paramNamesFlat(nw.Type.Params)
	if len(nwParams) != 1 || nwParams[0] == "" || nwParams[0] == "_" || len(nw.Body.List) != 1 {
		return fmt.Errorf("bufio: unexpected NewWriter shape")
	}
	nwRet, ok := nw.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(nwRet.Results) != 1 {
		return fmt.Errorf("bufio: unexpected NewWriter return")
	}
	nwCall, ok := unwrapParens(nwRet.Results[0]).(*ast.CallExpr)
	if !ok || nwCall.Ellipsis.IsValid() || len(nwCall.Args) != 2 {
		return fmt.Errorf("bufio: unexpected NewWriter delegation")
	}
	if _, ok := isIdentNamed(nwCall.Fun, "NewWriterSize"); !ok {
		return fmt.Errorf("bufio: NewWriter does not call NewWriterSize")
	}
	if _, ok := isIdentNamed(nwCall.Args[0], nwParams[0]); !ok {
		return fmt.Errorf("bufio: NewWriter does not forward w")
	}
	if !isPositiveIntLit(nwCall.Args[1]) {
		if cID, ok := unwrapParens(nwCall.Args[1]).(*ast.Ident); !ok || !constPosInt[cID.Name] {
			return fmt.Errorf("bufio: NewWriter size argument is not a positive constant")
		}
	}

	nwsParams := paramNamesFlat(nws.Type.Params)
	if len(nwsParams) != 2 || nwsParams[0] == "" || nwsParams[0] == "_" || nwsParams[1] == "" || nwsParams[1] == "_" || len(nws.Body.List) < 2 {
		return fmt.Errorf("bufio: unexpected NewWriterSize shape")
	}
	wParam, sizeParam := nwsParams[0], nwsParams[1]
	if bodyMutatesOrTakesAddrOfAny(nws.Body, map[string]bool{wParam: true}) {
		return fmt.Errorf("bufio: NewWriterSize mutates w")
	}
	nwsPos := 0
	if len(nws.Body.List) == 4 {
		// Optional pass-through: b, ok := w.(*Writer); if ok && len(b.buf) >= size { return b }
		taAssign, ok1 := nws.Body.List[0].(*ast.AssignStmt)
		taIf, ok2 := nws.Body.List[1].(*ast.IfStmt)
		if !ok1 || !ok2 || taAssign.Tok != token.DEFINE || len(taAssign.Lhs) != 2 || len(taAssign.Rhs) != 1 || taIf.Init != nil || taIf.Else != nil || len(taIf.Body.List) != 1 {
			return fmt.Errorf("bufio: NewWriterSize invalid Writer pass-through")
		}
		bID, okB := unwrapParens(taAssign.Lhs[0]).(*ast.Ident)
		okID, okOK := unwrapParens(taAssign.Lhs[1]).(*ast.Ident)
		ta, okTA := unwrapParens(taAssign.Rhs[0]).(*ast.TypeAssertExpr)
		if !okB || !okOK || !okTA || bID.Name == "" || bID.Name == "_" || okID.Name == "" || okID.Name == "_" || ta.Type == nil {
			return fmt.Errorf("bufio: NewWriterSize invalid Writer type assertion")
		}
		if _, ok := isIdentNamed(ta.X, wParam); !ok {
			return fmt.Errorf("bufio: NewWriterSize type assertion not on w")
		}
		starW, ok := unwrapParens(ta.Type).(*ast.StarExpr)
		if !ok {
			return fmt.Errorf("bufio: NewWriterSize type assertion not *Writer")
		}
		if _, ok := isIdentNamed(starW.X, "Writer"); !ok {
			return fmt.Errorf("bufio: NewWriterSize type assertion target not Writer")
		}
		andCond, ok := unwrapParens(taIf.Cond).(*ast.BinaryExpr)
		if !ok || andCond.Op != token.LAND {
			return fmt.Errorf("bufio: NewWriterSize pass-through condition not &&")
		}
		if _, ok := isIdentNamed(andCond.X, okID.Name); !ok {
			return fmt.Errorf("bufio: NewWriterSize pass-through LHS not ok")
		}
		geqCond, ok := unwrapParens(andCond.Y).(*ast.BinaryExpr)
		if !ok || geqCond.Op != token.GEQ {
			return fmt.Errorf("bufio: NewWriterSize pass-through capacity check not >=")
		}
		lenCall, ok := unwrapParens(geqCond.X).(*ast.CallExpr)
		if !ok || lenCall.Ellipsis.IsValid() || len(lenCall.Args) != 1 {
			return fmt.Errorf("bufio: NewWriterSize pass-through missing len(b.buf)")
		}
		if _, ok := isIdentNamed(lenCall.Fun, "len"); !ok {
			return fmt.Errorf("bufio: NewWriterSize pass-through not calling len")
		}
		if _, ok := isSelectorBaseField(lenCall.Args[0], bID.Name, "buf"); !ok {
			return fmt.Errorf("bufio: NewWriterSize pass-through len arg not b.buf")
		}
		if _, ok := isIdentNamed(geqCond.Y, sizeParam); !ok {
			return fmt.Errorf("bufio: NewWriterSize pass-through RHS not size")
		}
		ptRet, ok := taIf.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ptRet.Results) != 1 {
			return fmt.Errorf("bufio: NewWriterSize pass-through invalid return")
		}
		if _, ok := isIdentNamed(ptRet.Results[0], bID.Name); !ok {
			return fmt.Errorf("bufio: NewWriterSize pass-through does not return b")
		}
		nwsPos = 2
	} else if len(nws.Body.List) != 2 {
		return fmt.Errorf("bufio: NewWriterSize unexpected statement count")
	}
	// Mandatory size clamp: if size <= 0 { size = <posConstOrLit> }
	if sizeIf, ok := nws.Body.List[nwsPos].(*ast.IfStmt); !ok || sizeIf.Init != nil || sizeIf.Else != nil || len(sizeIf.Body.List) != 1 {
		return fmt.Errorf("bufio: NewWriterSize missing size <= 0 clamp")
	} else {
		leCond, ok := unwrapParens(sizeIf.Cond).(*ast.BinaryExpr)
		if !ok || leCond.Op != token.LEQ || !isZeroIntLit(leCond.Y) {
			return fmt.Errorf("bufio: NewWriterSize size clamp condition invalid")
		}
		if _, ok := isIdentNamed(leCond.X, sizeParam); !ok {
			return fmt.Errorf("bufio: NewWriterSize size clamp LHS not size")
		}
		clampAs, ok := sizeIf.Body.List[0].(*ast.AssignStmt)
		if !ok || clampAs.Tok != token.ASSIGN || len(clampAs.Lhs) != 1 || len(clampAs.Rhs) != 1 {
			return fmt.Errorf("bufio: NewWriterSize size clamp assignment invalid")
		}
		if _, ok := isIdentNamed(clampAs.Lhs[0], sizeParam); !ok {
			return fmt.Errorf("bufio: NewWriterSize size clamp target not size")
		}
		if !isPositiveIntLit(clampAs.Rhs[0]) {
			if cID, ok := unwrapParens(clampAs.Rhs[0]).(*ast.Ident); !ok || !constPosInt[cID.Name] {
				return fmt.Errorf("bufio: NewWriterSize default size is not positive")
			}
		}
	}
	nwsRet, ok := nws.Body.List[nwsPos+1].(*ast.ReturnStmt)
	if !ok || len(nwsRet.Results) != 1 {
		return fmt.Errorf("bufio: NewWriterSize missing final return")
	}
	lit, litName := compositeWriterLit(nwsRet.Results[0])
	if lit == nil || litName != "Writer" || len(lit.Elts) != 2 {
		return fmt.Errorf("bufio: NewWriterSize final return is not &Writer{buf, wr}")
	}
	var sawBufMake, sawWrBind bool
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return fmt.Errorf("bufio: NewWriterSize unkeyed Writer literal")
		}
		kID, ok := unwrapParens(kv.Key).(*ast.Ident)
		if !ok {
			return fmt.Errorf("bufio: NewWriterSize invalid key")
		}
		switch kID.Name {
		case "wr":
			if _, ok := isIdentNamed(kv.Value, wParam); !ok {
				return fmt.Errorf("bufio: NewWriterSize wr does not bind w")
			}
			sawWrBind = true
		case "buf":
			mc, ok := unwrapParens(kv.Value).(*ast.CallExpr)
			if !ok || mc.Ellipsis.IsValid() || len(mc.Args) != 2 || !isByteSliceType(mc.Args[0]) {
				return fmt.Errorf("bufio: NewWriterSize buf is not make([]byte, size)")
			}
			if _, ok := isIdentNamed(mc.Fun, "make"); !ok {
				return fmt.Errorf("bufio: NewWriterSize buf is not make")
			}
			if _, ok := isIdentNamed(mc.Args[1], sizeParam); !ok {
				return fmt.Errorf("bufio: NewWriterSize buf size mismatch")
			}
			sawBufMake = true
		}
	}
	if !sawBufMake || !sawWrBind {
		return fmt.Errorf("bufio: NewWriterSize incomplete Writer initialization")
	}

	// Verify Available() and Buffered().
	availFn := writerMethods["Available"]
	bufdFn := writerMethods["Buffered"]
	if availFn == nil || availFn.Body == nil || len(availFn.Body.List) != 1 || bufdFn == nil || bufdFn.Body == nil || len(bufdFn.Body.List) != 1 {
		return fmt.Errorf("bufio: missing Available or Buffered")
	}
	if avRecv := recvVarName(availFn); avRecv == "" {
		return fmt.Errorf("bufio: unnamed Available receiver")
	} else {
		ret, ok := availFn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return fmt.Errorf("bufio: invalid Available return")
		}
		bin, ok := unwrapParens(ret.Results[0]).(*ast.BinaryExpr)
		if !ok || bin.Op != token.SUB {
			return fmt.Errorf("bufio: Available does not compute len(buf) - n")
		}
		lc, ok := unwrapParens(bin.X).(*ast.CallExpr)
		if !ok || len(lc.Args) != 1 || lc.Ellipsis.IsValid() {
			return fmt.Errorf("bufio: Available invalid len call")
		}
		if _, ok := isIdentNamed(lc.Fun, "len"); !ok {
			return fmt.Errorf("bufio: Available not calling len")
		}
		if _, ok := isSelectorBaseField(lc.Args[0], avRecv, "buf"); !ok {
			return fmt.Errorf("bufio: Available len target not b.buf")
		}
		if _, ok := isSelectorBaseField(bin.Y, avRecv, "n"); !ok {
			return fmt.Errorf("bufio: Available subtrahend not b.n")
		}
	}
	if bfRecv := recvVarName(bufdFn); bfRecv == "" {
		return fmt.Errorf("bufio: unnamed Buffered receiver")
	} else {
		ret, ok := bufdFn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return fmt.Errorf("bufio: invalid Buffered return")
		}
		if _, ok := isSelectorBaseField(ret.Results[0], bfRecv, "n"); !ok {
			return fmt.Errorf("bufio: Buffered does not return b.n")
		}
	}

	// Verify (*Writer).Flush() dereferences receiver without nil guard, writes b.buf[0:b.n] to b.wr,
	// checks short writes, and latches + returns any error.
	flushFn, _, okFl := idx.VerifyFuncPreamble("Writer", "Flush", true, reserved)
	if !okFl || !funcReturnsErrorLast(flushFn.Type) {
		return fmt.Errorf("bufio: missing or invalid (*Writer).Flush")
	}
	fRecv := recvVarName(flushFn)
	if fRecv == "" || len(flushFn.Body.List) != 7 {
		return fmt.Errorf("bufio: (*Writer).Flush has unexpected statement structure")
	}
	// Stmt 0: if b.err != nil { return b.err }
	if !isStickyFieldErrorGuardIf(flushFn.Body.List[0], fRecv, "err") {
		return fmt.Errorf("bufio: Flush missing sticky error guard")
	}
	// Stmt 1: if b.n == 0 { return nil }
	if s1, ok := flushFn.Body.List[1].(*ast.IfStmt); !ok || s1.Init != nil || s1.Else != nil || len(s1.Body.List) != 1 {
		return fmt.Errorf("bufio: Flush missing empty-buffer check")
	} else {
		cond, ok := unwrapParens(s1.Cond).(*ast.BinaryExpr)
		if !ok || cond.Op != token.EQL || !isZeroIntLit(cond.Y) {
			return fmt.Errorf("bufio: Flush empty-buffer condition invalid")
		}
		if _, ok := isSelectorBaseField(cond.X, fRecv, "n"); !ok {
			return fmt.Errorf("bufio: Flush empty-buffer LHS not b.n")
		}
		ret, ok := s1.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return fmt.Errorf("bufio: Flush empty-buffer return invalid")
		}
		if _, ok := isIdentNamed(ret.Results[0], "nil"); !ok {
			return fmt.Errorf("bufio: Flush empty-buffer check does not return nil")
		}
	}
	// Stmt 2: n, err := b.wr.Write(b.buf[0:b.n])
	var flushNVar, flushErrVar string
	if s2, ok := flushFn.Body.List[2].(*ast.AssignStmt); !ok || s2.Tok != token.DEFINE || len(s2.Lhs) != 2 || len(s2.Rhs) != 1 {
		return fmt.Errorf("bufio: Flush missing b.wr.Write assignment")
	} else {
		nID, ok1 := unwrapParens(s2.Lhs[0]).(*ast.Ident)
		eID, ok2 := unwrapParens(s2.Lhs[1]).(*ast.Ident)
		wCall, ok3 := unwrapParens(s2.Rhs[0]).(*ast.CallExpr)
		if !ok1 || !ok2 || !ok3 || nID.Name == "" || nID.Name == "_" || eID.Name == "" || eID.Name == "_" || wCall.Ellipsis.IsValid() || len(wCall.Args) != 1 {
			return fmt.Errorf("bufio: Flush invalid b.wr.Write call")
		}
		flushNVar, flushErrVar = nID.Name, eID.Name
		wSel, ok := unwrapParens(wCall.Fun).(*ast.SelectorExpr)
		if !ok || wSel.Sel.Name != "Write" {
			return fmt.Errorf("bufio: Flush does not call Write")
		}
		if _, ok := isSelectorBaseField(wSel.X, fRecv, "wr"); !ok {
			return fmt.Errorf("bufio: Flush Write receiver not b.wr")
		}
		sl, ok := unwrapParens(wCall.Args[0]).(*ast.SliceExpr)
		if !ok || sl.Slice3 || sl.High == nil || (sl.Low != nil && !isZeroIntLit(sl.Low)) {
			return fmt.Errorf("bufio: Flush slice arg not b.buf[0:b.n]")
		}
		if _, ok := isSelectorBaseField(sl.X, fRecv, "buf"); !ok {
			return fmt.Errorf("bufio: Flush slice base not b.buf")
		}
		if _, ok := isSelectorBaseField(sl.High, fRecv, "n"); !ok {
			return fmt.Errorf("bufio: Flush slice high not b.n")
		}
	}
	// Stmt 3: if n < b.n && err == nil { err = io.ErrShortWrite }
	if s3, ok := flushFn.Body.List[3].(*ast.IfStmt); !ok || s3.Init != nil || s3.Else != nil || len(s3.Body.List) != 1 {
		return fmt.Errorf("bufio: Flush missing short-write check")
	} else {
		andExpr, ok := unwrapParens(s3.Cond).(*ast.BinaryExpr)
		if !ok || andExpr.Op != token.LAND || !condChecksEqErr(andExpr.Y, flushErrVar) {
			return fmt.Errorf("bufio: Flush short-write condition invalid")
		}
		ltExpr, ok := unwrapParens(andExpr.X).(*ast.BinaryExpr)
		if !ok || ltExpr.Op != token.LSS {
			return fmt.Errorf("bufio: Flush short-write comparison invalid")
		}
		if _, ok1 := isIdentNamed(ltExpr.X, flushNVar); !ok1 {
			return fmt.Errorf("bufio: Flush short-write LHS not n")
		}
		if _, ok2 := isSelectorBaseField(ltExpr.Y, fRecv, "n"); !ok2 {
			return fmt.Errorf("bufio: Flush short-write RHS not b.n")
		}
		as, ok := s3.Body.List[0].(*ast.AssignStmt)
		if !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return fmt.Errorf("bufio: Flush short-write assignment invalid")
		}
		if _, ok1 := isIdentNamed(as.Lhs[0], flushErrVar); !ok1 {
			return fmt.Errorf("bufio: Flush short-write LHS not err")
		}
		if _, ok2 := isSelectorBaseField(as.Rhs[0], "io", "ErrShortWrite"); !ok2 {
			return fmt.Errorf("bufio: Flush short-write RHS not io.ErrShortWrite")
		}
	}
	// Stmt 4: if err != nil { ...; b.err = err; return err }
	if s4, ok := flushFn.Body.List[4].(*ast.IfStmt); !ok || s4.Init != nil || s4.Else != nil || condChecksNonZeroErr(s4.Cond) != flushErrVar || len(s4.Body.List) < 2 {
		return fmt.Errorf("bufio: Flush missing error return branch")
	} else {
		if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: s4.Body.List[:len(s4.Body.List)-1]}, map[string]bool{flushErrVar: true}) {
			return fmt.Errorf("bufio: Flush mutates err before returning")
		}
		latchStmt, ok1 := s4.Body.List[len(s4.Body.List)-2].(*ast.AssignStmt)
		retStmt, ok2 := s4.Body.List[len(s4.Body.List)-1].(*ast.ReturnStmt)
		if !ok1 || !ok2 || latchStmt.Tok != token.ASSIGN || len(latchStmt.Lhs) != 1 || len(latchStmt.Rhs) != 1 || len(retStmt.Results) != 1 {
			return fmt.Errorf("bufio: Flush error branch missing b.err = err; return err")
		}
		if _, ok := isSelectorBaseField(latchStmt.Lhs[0], fRecv, "err"); !ok {
			return fmt.Errorf("bufio: Flush does not latch b.err")
		}
		if _, ok := isIdentNamed(latchStmt.Rhs[0], flushErrVar); !ok {
			return fmt.Errorf("bufio: Flush latches wrong error")
		}
		if _, ok := isIdentNamed(retStmt.Results[0], flushErrVar); !ok {
			return fmt.Errorf("bufio: Flush returns wrong error")
		}
	}
	// Stmt 5 & 6: b.n = 0; return nil
	if s5, ok := flushFn.Body.List[5].(*ast.AssignStmt); !ok || s5.Tok != token.ASSIGN || len(s5.Lhs) != 1 || len(s5.Rhs) != 1 || !isZeroIntLit(s5.Rhs[0]) {
		return fmt.Errorf("bufio: Flush missing b.n = 0")
	} else if _, ok := isSelectorBaseField(s5.Lhs[0], fRecv, "n"); !ok {
		return fmt.Errorf("bufio: Flush reset target not b.n")
	}
	if s6, ok := flushFn.Body.List[6].(*ast.ReturnStmt); !ok || len(s6.Results) != 1 {
		return fmt.Errorf("bufio: Flush missing final return nil")
	} else if _, ok := isIdentNamed(s6.Results[0], "nil"); !ok {
		return fmt.Errorf("bufio: Flush final return not nil")
	}

	// Verify (*Writer).WriteByte and (*Writer).WriteString preserve bytes and sticky b.err.
	wbFn, _, okWB := idx.VerifyFuncPreamble("Writer", "WriteByte", true, reserved)
	wsFn, _, okWS := idx.VerifyFuncPreamble("Writer", "WriteString", true, reserved)
	if !okWB || !okWS {
		return fmt.Errorf("bufio: missing WriteByte or WriteString")
	}
	wbRecv := recvVarName(wbFn)
	wbParams := paramNamesFlat(wbFn.Type.Params)
	if wbRecv == "" || len(wbParams) != 1 || wbParams[0] == "" || wbParams[0] == "_" || len(wbFn.Body.List) != 5 {
		return fmt.Errorf("bufio: unexpected WriteByte shape")
	}
	// WriteByte[0]: if b.err != nil { return b.err }
	if !isStickyFieldErrorGuardIf(wbFn.Body.List[0], wbRecv, "err") {
		return fmt.Errorf("bufio: WriteByte missing sticky b.err guard")
	}
	// WriteByte[1]: if b.Available() <= 0 && b.Flush() != nil { return b.err }
	if wb1, ok := wbFn.Body.List[1].(*ast.IfStmt); !ok || wb1.Init != nil || wb1.Else != nil || len(wb1.Body.List) != 1 {
		return fmt.Errorf("bufio: WriteByte missing Available/Flush guard")
	} else {
		andC, ok := unwrapParens(wb1.Cond).(*ast.BinaryExpr)
		if !ok || andC.Op != token.LAND {
			return fmt.Errorf("bufio: WriteByte Available/Flush guard not &&")
		}
		leC, ok1 := unwrapParens(andC.X).(*ast.BinaryExpr)
		neqC, ok2 := unwrapParens(andC.Y).(*ast.BinaryExpr)
		if !ok1 || !ok2 || leC.Op != token.LEQ || !isZeroIntLit(leC.Y) || neqC.Op != token.NEQ {
			return fmt.Errorf("bufio: WriteByte Available/Flush comparisons invalid")
		}
		if _, ok := isZeroArgMethodCallOnIdent(leC.X, wbRecv, "Available"); !ok {
			return fmt.Errorf("bufio: WriteByte does not check b.Available() <= 0")
		}
		if _, ok := isZeroArgMethodCallOnIdent(neqC.X, wbRecv, "Flush"); !ok {
			return fmt.Errorf("bufio: WriteByte does not call b.Flush()")
		}
		if _, ok := isIdentNamed(neqC.Y, "nil"); !ok {
			return fmt.Errorf("bufio: WriteByte Flush comparison RHS not nil")
		}
		ret, ok := wb1.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return fmt.Errorf("bufio: WriteByte Flush guard return invalid")
		}
		if _, ok := isSelectorBaseField(ret.Results[0], wbRecv, "err"); !ok {
			return fmt.Errorf("bufio: WriteByte Flush guard does not return b.err")
		}
	}
	if as, ok := wbFn.Body.List[2].(*ast.AssignStmt); !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
		return fmt.Errorf("bufio: WriteByte missing b.buf[b.n] = c")
	} else {
		idx, ok1 := unwrapParens(as.Lhs[0]).(*ast.IndexExpr)
		_, ok2 := isIdentNamed(as.Rhs[0], wbParams[0])
		if !ok1 || !ok2 {
			return fmt.Errorf("bufio: WriteByte assignment mismatch")
		}
		if _, ok := isSelectorBaseField(idx.X, wbRecv, "buf"); !ok {
			return fmt.Errorf("bufio: WriteByte target not b.buf")
		}
		if _, ok := isSelectorBaseField(idx.Index, wbRecv, "n"); !ok {
			return fmt.Errorf("bufio: WriteByte index not b.n")
		}
	}
	if inc, ok := wbFn.Body.List[3].(*ast.IncDecStmt); !ok || inc.Tok != token.INC {
		return fmt.Errorf("bufio: WriteByte missing b.n++")
	} else if _, ok := isSelectorBaseField(inc.X, wbRecv, "n"); !ok {
		return fmt.Errorf("bufio: WriteByte increment target not b.n")
	}
	if wb4, ok := wbFn.Body.List[4].(*ast.ReturnStmt); !ok || len(wb4.Results) != 1 {
		return fmt.Errorf("bufio: WriteByte missing final return nil")
	} else if _, ok := isIdentNamed(wb4.Results[0], "nil"); !ok {
		return fmt.Errorf("bufio: WriteByte final return not nil")
	}

	wsRecv := recvVarName(wsFn)
	wsParams := paramNamesFlat(wsFn.Type.Params)
	if wsRecv == "" || len(wsParams) != 1 || wsParams[0] == "" || wsParams[0] == "_" || len(wsFn.Body.List) != 9 {
		return fmt.Errorf("bufio: unexpected WriteString shape")
	}
	sParam := wsParams[0]
	if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: wsFn.Body.List[4:]}, map[string]bool{sParam: true}) {
		return fmt.Errorf("bufio: WriteString mutates s after loop")
	}
	// Stmt 0: var sw io.StringWriter; Stmt 1: tryStringWriter := true; Stmt 2: nn := 0
	var swVar, trySWVar, nnVar string
	if ds0, ok := wsFn.Body.List[0].(*ast.DeclStmt); !ok {
		return fmt.Errorf("bufio: WriteString missing var sw io.StringWriter")
	} else {
		gd, ok := ds0.Decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR || len(gd.Specs) != 1 {
			return fmt.Errorf("bufio: WriteString invalid sw declaration")
		}
		vs, ok := gd.Specs[0].(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || len(vs.Values) != 0 || vs.Names[0].Name == "" || vs.Names[0].Name == "_" {
			return fmt.Errorf("bufio: WriteString invalid sw ValueSpec")
		}
		if _, ok := isSelectorBaseField(vs.Type, "io", "StringWriter"); !ok {
			return fmt.Errorf("bufio: WriteString sw type not io.StringWriter")
		}
		swVar = vs.Names[0].Name
	}
	if as1, ok := wsFn.Body.List[1].(*ast.AssignStmt); !ok || as1.Tok != token.DEFINE || len(as1.Lhs) != 1 || len(as1.Rhs) != 1 {
		return fmt.Errorf("bufio: WriteString missing tryStringWriter := true")
	} else {
		id, ok1 := unwrapParens(as1.Lhs[0]).(*ast.Ident)
		_, ok2 := isIdentNamed(as1.Rhs[0], "true")
		if !ok1 || !ok2 || id.Name == "" || id.Name == "_" {
			return fmt.Errorf("bufio: WriteString invalid tryStringWriter init")
		}
		trySWVar = id.Name
	}
	if as2, ok := wsFn.Body.List[2].(*ast.AssignStmt); !ok || as2.Tok != token.DEFINE || len(as2.Lhs) != 1 || len(as2.Rhs) != 1 || !isZeroIntLit(as2.Rhs[0]) {
		return fmt.Errorf("bufio: WriteString missing nn := 0")
	} else {
		id, ok := unwrapParens(as2.Lhs[0]).(*ast.Ident)
		if !ok || id.Name == "" || id.Name == "_" {
			return fmt.Errorf("bufio: WriteString invalid nn init")
		}
		nnVar = id.Name
	}
	// Stmt 3: for len(s) > b.Available() && b.err == nil { ... }
	if fs3, ok := wsFn.Body.List[3].(*ast.ForStmt); !ok || fs3.Init != nil || fs3.Post != nil || len(fs3.Body.List) != 5 {
		return fmt.Errorf("bufio: WriteString missing overflow loop")
	} else {
		andC, ok := unwrapParens(fs3.Cond).(*ast.BinaryExpr)
		if !ok || andC.Op != token.LAND {
			return fmt.Errorf("bufio: WriteString loop condition not &&")
		}
		gtC, ok1 := unwrapParens(andC.X).(*ast.BinaryExpr)
		eqC, ok2 := unwrapParens(andC.Y).(*ast.BinaryExpr)
		if !ok1 || !ok2 || gtC.Op != token.GTR || !isLenOfIdentCall(gtC.X, sParam) || eqC.Op != token.EQL {
			return fmt.Errorf("bufio: WriteString loop comparisons invalid")
		}
		if _, ok := isZeroArgMethodCallOnIdent(gtC.Y, wsRecv, "Available"); !ok {
			return fmt.Errorf("bufio: WriteString loop RHS not b.Available()")
		}
		if _, ok := isSelectorBaseField(eqC.X, wsRecv, "err"); !ok {
			return fmt.Errorf("bufio: WriteString loop err check LHS not b.err")
		}
		if _, ok := isIdentNamed(eqC.Y, "nil"); !ok {
			return fmt.Errorf("bufio: WriteString loop err check RHS not nil")
		}
		// Loop[0]: var n int
		var loopNVar string
		if lds0, ok := fs3.Body.List[0].(*ast.DeclStmt); !ok {
			return fmt.Errorf("bufio: WriteString loop missing var n int")
		} else {
			gd, ok := lds0.Decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR || len(gd.Specs) != 1 {
				return fmt.Errorf("bufio: WriteString loop invalid var n int")
			}
			vs, ok := gd.Specs[0].(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 0 || vs.Names[0].Name == "" || vs.Names[0].Name == "_" {
				return fmt.Errorf("bufio: WriteString loop invalid n spec")
			}
			if _, ok := isIdentNamed(vs.Type, "int"); !ok {
				return fmt.Errorf("bufio: WriteString loop n not int")
			}
			loopNVar = vs.Names[0].Name
		}
		// Loop[1]: if b.Buffered() == 0 && sw == nil && tryStringWriter { sw, tryStringWriter = b.wr.(io.StringWriter) }
		if lif1, ok := fs3.Body.List[1].(*ast.IfStmt); !ok || lif1.Init != nil || lif1.Else != nil || len(lif1.Body.List) != 1 {
			return fmt.Errorf("bufio: WriteString loop missing StringWriter probe")
		} else {
			outerAnd, okAnd := unwrapParens(lif1.Cond).(*ast.BinaryExpr)
			if !okAnd || outerAnd.Op != token.LAND {
				return fmt.Errorf("bufio: WriteString StringWriter probe outer condition invalid")
			}
			if _, okTry := isIdentNamed(outerAnd.Y, trySWVar); !okTry {
				return fmt.Errorf("bufio: WriteString StringWriter probe missing tryStringWriter guard")
			}
			innerAnd, okIn := unwrapParens(outerAnd.X).(*ast.BinaryExpr)
			if !okIn || innerAnd.Op != token.LAND {
				return fmt.Errorf("bufio: WriteString StringWriter probe inner condition invalid")
			}
			bufEq, okBE := unwrapParens(innerAnd.X).(*ast.BinaryExpr)
			var okBufCall bool
			if okBE {
				_, okBufCall = isZeroArgMethodCallOnIdent(bufEq.X, wsRecv, "Buffered")
			}
			if !okBE || bufEq.Op != token.EQL || !okBufCall || !isZeroIntLit(bufEq.Y) {
				return fmt.Errorf("bufio: WriteString StringWriter probe missing b.Buffered() == 0 guard")
			}
			swEq, okSE := unwrapParens(innerAnd.Y).(*ast.BinaryExpr)
			if !okSE || swEq.Op != token.EQL {
				return fmt.Errorf("bufio: WriteString StringWriter probe missing sw == nil guard")
			}
			_, okSW := isIdentNamed(swEq.X, swVar)
			_, okNil := isIdentNamed(swEq.Y, "nil")
			if !okSW || !okNil {
				return fmt.Errorf("bufio: WriteString StringWriter probe sw == nil operands invalid")
			}
			as, ok := lif1.Body.List[0].(*ast.AssignStmt)
			if !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 2 || len(as.Rhs) != 1 {
				return fmt.Errorf("bufio: WriteString StringWriter probe assign invalid")
			}
			_, ok1 := isIdentNamed(as.Lhs[0], swVar)
			_, ok2 := isIdentNamed(as.Lhs[1], trySWVar)
			ta, ok3 := unwrapParens(as.Rhs[0]).(*ast.TypeAssertExpr)
			if !ok1 || !ok2 || !ok3 || ta.Type == nil {
				return fmt.Errorf("bufio: WriteString StringWriter type assertion invalid")
			}
			if _, ok := isSelectorBaseField(ta.X, wsRecv, "wr"); !ok {
				return fmt.Errorf("bufio: WriteString StringWriter assertion not on b.wr")
			}
			if _, ok := isSelectorBaseField(ta.Type, "io", "StringWriter"); !ok {
				return fmt.Errorf("bufio: WriteString assertion type not io.StringWriter")
			}
		}
		// Loop[2]: if b.Buffered() == 0 && tryStringWriter { n, b.err = sw.WriteString(s) } else { n = copy(b.buf[b.n:], s); b.n += n; b.Flush() }
		if lif2, ok := fs3.Body.List[2].(*ast.IfStmt); !ok || lif2.Init != nil || lif2.Else == nil || len(lif2.Body.List) != 1 {
			return fmt.Errorf("bufio: WriteString loop missing StringWriter/copy dispatch")
		} else {
			and2, ok := unwrapParens(lif2.Cond).(*ast.BinaryExpr)
			if !ok || and2.Op != token.LAND {
				return fmt.Errorf("bufio: WriteString dispatch cond not &&")
			}
			bufEq, ok1 := unwrapParens(and2.X).(*ast.BinaryExpr)
			_, ok2 := isIdentNamed(and2.Y, trySWVar)
			if !ok1 || !ok2 || bufEq.Op != token.EQL || !isZeroIntLit(bufEq.Y) {
				return fmt.Errorf("bufio: WriteString dispatch Buffered() == 0 cond invalid")
			}
			if _, ok := isZeroArgMethodCallOnIdent(bufEq.X, wsRecv, "Buffered"); !ok {
				return fmt.Errorf("bufio: WriteString dispatch does not check b.Buffered()")
			}
			swAs, ok := lif2.Body.List[0].(*ast.AssignStmt)
			if !ok || swAs.Tok != token.ASSIGN || len(swAs.Lhs) != 2 || len(swAs.Rhs) != 1 {
				return fmt.Errorf("bufio: WriteString sw.WriteString assign invalid")
			}
			_, okN := isIdentNamed(swAs.Lhs[0], loopNVar)
			_, okErr := isSelectorBaseField(swAs.Lhs[1], wsRecv, "err")
			swCall, okC := unwrapParens(swAs.Rhs[0]).(*ast.CallExpr)
			if !okN || !okErr || !okC || swCall.Ellipsis.IsValid() || len(swCall.Args) != 1 {
				return fmt.Errorf("bufio: WriteString sw.WriteString call invalid")
			}
			if _, ok := isSelectorBaseField(swCall.Fun, swVar, "WriteString"); !ok {
				return fmt.Errorf("bufio: WriteString does not call sw.WriteString")
			}
			if _, ok := isIdentNamed(swCall.Args[0], sParam); !ok {
				return fmt.Errorf("bufio: WriteString sw.WriteString arg not s")
			}
			elseBlk, ok := lif2.Else.(*ast.BlockStmt)
			if !ok || len(elseBlk.List) != 3 {
				return fmt.Errorf("bufio: WriteString else branch unexpected shape")
			}
			cpAs, ok1 := elseBlk.List[0].(*ast.AssignStmt)
			addAs, ok2 := elseBlk.List[1].(*ast.AssignStmt)
			flES, ok3 := elseBlk.List[2].(*ast.ExprStmt)
			if !ok1 || !ok2 || !ok3 || cpAs.Tok != token.ASSIGN || len(cpAs.Lhs) != 1 || len(cpAs.Rhs) != 1 || addAs.Tok != token.ADD_ASSIGN || len(addAs.Lhs) != 1 || len(addAs.Rhs) != 1 {
				return fmt.Errorf("bufio: WriteString else copy/add/Flush invalid")
			}
			if _, ok := isIdentNamed(cpAs.Lhs[0], loopNVar); !ok {
				return fmt.Errorf("bufio: WriteString else copy LHS not n")
			}
			cpCall, ok := unwrapParens(cpAs.Rhs[0]).(*ast.CallExpr)
			if !ok || cpCall.Ellipsis.IsValid() || len(cpCall.Args) != 2 {
				return fmt.Errorf("bufio: WriteString else copy call invalid")
			}
			if _, ok := isIdentNamed(cpCall.Fun, "copy"); !ok {
				return fmt.Errorf("bufio: WriteString else call not copy")
			}
			sl, ok := unwrapParens(cpCall.Args[0]).(*ast.SliceExpr)
			if !ok || sl.Slice3 || sl.High != nil || sl.Low == nil {
				return fmt.Errorf("bufio: WriteString else copy dst slice invalid")
			}
			if _, ok1 := isSelectorBaseField(sl.X, wsRecv, "buf"); !ok1 {
				return fmt.Errorf("bufio: WriteString else copy dst not b.buf")
			}
			if _, ok2 := isSelectorBaseField(sl.Low, wsRecv, "n"); !ok2 {
				return fmt.Errorf("bufio: WriteString else copy low not b.n")
			}
			if _, ok := isIdentNamed(cpCall.Args[1], sParam); !ok {
				return fmt.Errorf("bufio: WriteString else copy src not s")
			}
			if _, ok1 := isSelectorBaseField(addAs.Lhs[0], wsRecv, "n"); !ok1 {
				return fmt.Errorf("bufio: WriteString else add LHS not b.n")
			}
			if _, ok2 := isIdentNamed(addAs.Rhs[0], loopNVar); !ok2 {
				return fmt.Errorf("bufio: WriteString else add RHS not n")
			}
			if _, ok := isZeroArgMethodCallOnIdent(flES.X, wsRecv, "Flush"); !ok {
				return fmt.Errorf("bufio: WriteString else missing b.Flush()")
			}
		}
		// Loop[3]: nn += n; Loop[4]: s = s[n:]
		if las3, ok := fs3.Body.List[3].(*ast.AssignStmt); !ok || las3.Tok != token.ADD_ASSIGN || len(las3.Lhs) != 1 || len(las3.Rhs) != 1 {
			return fmt.Errorf("bufio: WriteString loop missing nn += n")
		} else {
			_, ok1 := isIdentNamed(las3.Lhs[0], nnVar)
			_, ok2 := isIdentNamed(las3.Rhs[0], loopNVar)
			if !ok1 || !ok2 {
				return fmt.Errorf("bufio: WriteString loop nn += n mismatch")
			}
		}
		if las4, ok := fs3.Body.List[4].(*ast.AssignStmt); !ok || !isCountAdvanceSliceAssign(las4, sParam, map[string]bool{loopNVar: true}) {
			return fmt.Errorf("bufio: WriteString loop missing s = s[n:]")
		}
	}
	// Stmt 4: if b.err != nil { return nn, b.err }
	if s4, ok := wsFn.Body.List[4].(*ast.IfStmt); !ok || s4.Init != nil || s4.Else != nil || len(s4.Body.List) != 1 {
		return fmt.Errorf("bufio: WriteString missing post-loop b.err check")
	} else {
		cond, ok := unwrapParens(s4.Cond).(*ast.BinaryExpr)
		if !ok || cond.Op != token.NEQ {
			return fmt.Errorf("bufio: WriteString post-loop condition invalid")
		}
		if _, ok := isSelectorBaseField(cond.X, wsRecv, "err"); !ok {
			return fmt.Errorf("bufio: WriteString post-loop LHS not b.err")
		}
		if _, ok := isIdentNamed(cond.Y, "nil"); !ok {
			return fmt.Errorf("bufio: WriteString post-loop RHS not nil")
		}
		ret4, ok := s4.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret4.Results) != 2 {
			return fmt.Errorf("bufio: WriteString post-loop return invalid")
		}
		_, ok1 := isIdentNamed(ret4.Results[0], nnVar)
		_, ok2 := isSelectorBaseField(ret4.Results[1], wsRecv, "err")
		if !ok1 || !ok2 {
			return fmt.Errorf("bufio: WriteString post-loop return not nn, b.err")
		}
	}
	// Stmt 5: n := copy(b.buf[b.n:], s); Stmt 6: b.n += n; Stmt 7: nn += n; Stmt 8: return nn, nil
	var tailNVar string
	if s5, ok := wsFn.Body.List[5].(*ast.AssignStmt); !ok || s5.Tok != token.DEFINE || len(s5.Lhs) != 1 || len(s5.Rhs) != 1 {
		return fmt.Errorf("bufio: WriteString missing tail copy")
	} else {
		nID, ok1 := unwrapParens(s5.Lhs[0]).(*ast.Ident)
		cpCall, ok2 := unwrapParens(s5.Rhs[0]).(*ast.CallExpr)
		if !ok1 || !ok2 || nID.Name == "" || nID.Name == "_" || cpCall.Ellipsis.IsValid() || len(cpCall.Args) != 2 {
			return fmt.Errorf("bufio: WriteString invalid tail copy")
		}
		tailNVar = nID.Name
		if _, ok := isIdentNamed(cpCall.Fun, "copy"); !ok {
			return fmt.Errorf("bufio: WriteString tail call not copy")
		}
		sl, ok := unwrapParens(cpCall.Args[0]).(*ast.SliceExpr)
		if !ok || sl.Slice3 || sl.High != nil || sl.Low == nil {
			return fmt.Errorf("bufio: WriteString tail copy dst slice invalid")
		}
		if _, ok := isSelectorBaseField(sl.X, wsRecv, "buf"); !ok {
			return fmt.Errorf("bufio: WriteString tail copy dst not b.buf")
		}
		if _, ok := isSelectorBaseField(sl.Low, wsRecv, "n"); !ok {
			return fmt.Errorf("bufio: WriteString tail copy low not b.n")
		}
		if _, ok := isIdentNamed(cpCall.Args[1], sParam); !ok {
			return fmt.Errorf("bufio: WriteString tail copy src not s")
		}
		s6, ok := wsFn.Body.List[6].(*ast.AssignStmt)
		if !ok || s6.Tok != token.ADD_ASSIGN || len(s6.Lhs) != 1 || len(s6.Rhs) != 1 {
			return fmt.Errorf("bufio: WriteString missing b.n += n")
		}
		if _, ok := isSelectorBaseField(s6.Lhs[0], wsRecv, "n"); !ok {
			return fmt.Errorf("bufio: WriteString tail add target not b.n")
		}
		if _, ok := isIdentNamed(s6.Rhs[0], tailNVar); !ok {
			return fmt.Errorf("bufio: WriteString tail add RHS not n")
		}
	}
	if s7, ok := wsFn.Body.List[7].(*ast.AssignStmt); !ok || s7.Tok != token.ADD_ASSIGN || len(s7.Lhs) != 1 || len(s7.Rhs) != 1 {
		return fmt.Errorf("bufio: WriteString missing tail nn += n")
	} else {
		_, ok1 := isIdentNamed(s7.Lhs[0], nnVar)
		_, ok2 := isIdentNamed(s7.Rhs[0], tailNVar)
		if !ok1 || !ok2 {
			return fmt.Errorf("bufio: WriteString tail nn += n mismatch")
		}
	}
	if s8, ok := wsFn.Body.List[8].(*ast.ReturnStmt); !ok || len(s8.Results) != 2 {
		return fmt.Errorf("bufio: WriteString missing final return")
	} else {
		_, ok1 := isIdentNamed(s8.Results[0], nnVar)
		_, ok2 := isIdentNamed(s8.Results[1], "nil")
		if !ok1 || !ok2 {
			return fmt.Errorf("bufio: WriteString final return not nn, nil")
		}
	}
	return nil
}

func isStickyFieldErrorGuardIf(stmt ast.Stmt, recvName, errField string) bool {
	ifs, ok := stmt.(*ast.IfStmt)
	if !ok || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
		return false
	}
	cond, ok := unwrapParens(ifs.Cond).(*ast.BinaryExpr)
	if !ok || cond.Op != token.NEQ {
		return false
	}
	if _, ok := isSelectorBaseField(cond.X, recvName, errField); !ok {
		return false
	}
	if _, ok := isIdentNamed(cond.Y, "nil"); !ok {
		return false
	}
	ret, ok := ifs.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	_, ok = isSelectorBaseField(ret.Results[0], recvName, errField)
	return ok
}
