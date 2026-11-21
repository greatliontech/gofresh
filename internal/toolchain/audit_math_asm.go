package toolchain

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/greatliontech/gofresh/internal/cprep"
)

func verifyMathFuncBodySafety(fnName string, fn *ast.FuncDecl, fImps map[string]string, pureGoTables, cpuGoVars map[string]bool) error {
	paramTypes := map[string]string{}
	if fn.Type.Params != nil {
		for _, fld := range fn.Type.Params.List {
			tID, ok := unwrapParens(fld.Type).(*ast.Ident)
			if !ok {
				continue
			}
			for _, id := range fld.Names {
				if id.Name != "" && id.Name != "_" {
					paramTypes[id.Name] = tID.Name
				}
			}
		}
	}

	var unsafeAlias string
	for alias, pkg := range fImps {
		if pkg == "unsafe" {
			unsafeAlias = alias
			break
		}
	}

	// Collect local fixed-array pointer variables (`var p *[N]float64`) eligible
	// to hold `&pureGoTable` for strictly read-only indexing (as in j0.go / j1.go).
	localTablePtrVars := map[string]bool{}
	localDeclCounts := map[string]int{}
	mutatedVars := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.DeclStmt:
			if gd, ok := x.Decl.(*ast.GenDecl); ok {
				for _, spec := range gd.Specs {
					switch sp := spec.(type) {
					case *ast.ValueSpec:
						for _, id := range sp.Names {
							if id.Name != "" && id.Name != "_" {
								localDeclCounts[id.Name]++
							}
						}
						if gd.Tok == token.VAR && sp.Type != nil && len(sp.Values) == 0 {
							if st, okS := unwrapParens(sp.Type).(*ast.StarExpr); okS {
								if at, okA := unwrapParens(st.X).(*ast.ArrayType); okA && at.Len != nil {
									if eltID, okE := unwrapParens(at.Elt).(*ast.Ident); okE && mathNumericTypeNames[eltID.Name] {
										for _, id := range sp.Names {
											if id.Name != "" && id.Name != "_" {
												localTablePtrVars[id.Name] = true
											}
										}
									}
								}
							}
						}
					case *ast.TypeSpec:
						if sp.Name != nil && sp.Name.Name != "_" {
							localDeclCounts[sp.Name.Name]++
						}
					}
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if id, ok := baseAssignedIdent(lhs); ok {
					mutatedVars[id] = true
					if x.Tok == token.DEFINE {
						localDeclCounts[id]++
					}
				}
			}
		case *ast.IncDecStmt:
			if id, ok := baseAssignedIdent(x.X); ok {
				mutatedVars[id] = true
			}
		case *ast.RangeStmt:
			for _, e := range []ast.Expr{x.Key, x.Value} {
				if id, ok := baseAssignedIdent(e); ok {
					mutatedVars[id] = true
					if x.Tok == token.DEFINE {
						localDeclCounts[id]++
					}
				}
			}
		}
		return true
	})
	for pName := range localTablePtrVars {
		if localDeclCounts[pName] > 1 || paramTypes[pName] != "" {
			delete(localTablePtrVars, pName)
		}
	}

	allowedAmpExprs := map[*ast.UnaryExpr]bool{}
	allowedTablePtrIdents := map[*ast.Ident]bool{}
	allowedUnsafeCalls := map[*ast.CallExpr]bool{}

	// Pre-authorize valid `loc = &pureGoTable` bindings and `loc[idx]` reads,
	// plus valid `*(*dst)(unsafe.Pointer(&param))` scalar bitcasts.
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ValueSpec:
			for _, id := range x.Names {
				if localTablePtrVars[id.Name] {
					allowedTablePtrIdents[id] = true
				}
			}
		case *ast.AssignStmt:
			if x.Tok == token.ASSIGN && len(x.Lhs) == 1 && len(x.Rhs) == 1 {
				if lhsID, okL := unwrapParens(x.Lhs[0]).(*ast.Ident); okL && localTablePtrVars[lhsID.Name] {
					if amp, okA := unwrapParens(x.Rhs[0]).(*ast.UnaryExpr); okA && amp.Op == token.AND {
						if tblID, okT := unwrapParens(amp.X).(*ast.Ident); okT && pureGoTables[tblID.Name] {
							allowedTablePtrIdents[lhsID] = true
							allowedAmpExprs[amp] = true
						}
					}
				}
			}
		case *ast.IndexExpr:
			if xID, okX := unwrapParens(x.X).(*ast.Ident); okX && localTablePtrVars[xID.Name] {
				allowedTablePtrIdents[xID] = true
			}
		case *ast.StarExpr:
			if unsafeAlias != "" && localDeclCounts[unsafeAlias] == 0 && paramTypes[unsafeAlias] == "" {
				if uCall, amp, ok := matchMathScalarBitcast(x, unsafeAlias, paramTypes, mutatedVars, localDeclCounts); ok {
					allowedUnsafeCalls[uCall] = true
					allowedAmpExprs[amp] = true
				}
			}
		}
		return true
	})

	// Disqualify any localTablePtrVar that appears on a mutating LHS (`p[i] = ...` or `*p = ...`).
	var safetyErr error
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if safetyErr != nil || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.GoStmt, *ast.DeferStmt, *ast.SendStmt, *ast.FuncLit:
			safetyErr = fmt.Errorf("math: forbidden statement construct in %s", fnName)
			return false
		case *ast.UnaryExpr:
			if x.Op == token.ARROW {
				safetyErr = fmt.Errorf("math: forbidden channel receive in %s", fnName)
				return false
			}
			if x.Op == token.AND && !allowedAmpExprs[x] {
				if id, ok := baseAssignedIdent(x.X); ok && (pureGoTables[id] || cpuGoVars[id] || localTablePtrVars[id]) {
					safetyErr = fmt.Errorf("math: forbidden address-of %s in %s", id, fnName)
					return false
				}
			}
		case *ast.SliceExpr:
			if id, ok := baseAssignedIdent(x.X); ok && (pureGoTables[id] || localTablePtrVars[id]) {
				safetyErr = fmt.Errorf("math: forbidden slice expression on %s in %s", id, fnName)
				return false
			}
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if id, ok := baseAssignedIdent(lhs); ok {
					if pureGoTables[id] || cpuGoVars[id] {
						safetyErr = fmt.Errorf("math: forbidden mutation of package var %s in %s", id, fnName)
						return false
					}
					if localTablePtrVars[id] {
						if lhsID, isPlain := unwrapParens(lhs).(*ast.Ident); !isPlain || !allowedTablePtrIdents[lhsID] {
							safetyErr = fmt.Errorf("math: forbidden mutation via local table pointer %s in %s", id, fnName)
							return false
						}
					}
				}
			}
		case *ast.IncDecStmt:
			if id, ok := baseAssignedIdent(x.X); ok && (pureGoTables[id] || cpuGoVars[id] || localTablePtrVars[id]) {
				safetyErr = fmt.Errorf("math: forbidden inc/dec on %s in %s", id, fnName)
				return false
			}
		case *ast.RangeStmt:
			for _, e := range []ast.Expr{x.Key, x.Value} {
				if id, ok := baseAssignedIdent(e); ok && (pureGoTables[id] || cpuGoVars[id] || localTablePtrVars[id]) {
					safetyErr = fmt.Errorf("math: forbidden range assignment on %s in %s", id, fnName)
					return false
				}
			}
		case *ast.Ident:
			if localTablePtrVars[x.Name] && !allowedTablePtrIdents[x] {
				safetyErr = fmt.Errorf("math: unapproved escape or use of local table pointer %s in %s", x.Name, fnName)
				return false
			}
		case *ast.CallExpr:
			if cID, okID := unwrapParens(x.Fun).(*ast.Ident); okID {
				switch cID.Name {
				case "recover", "print", "println", "make", "new", "append", "copy", "clear", "delete", "close":
					safetyErr = fmt.Errorf("math: forbidden builtin %s in %s", cID.Name, fnName)
					return false
				}
			}
			if unsafeAlias != "" {
				if sel, okS := unwrapParens(x.Fun).(*ast.SelectorExpr); okS {
					if pID, okP := unwrapParens(sel.X).(*ast.Ident); okP && pID.Name == unsafeAlias {
						if !allowedUnsafeCalls[x] {
							safetyErr = fmt.Errorf("math: unapproved unsafe.%s call in %s", sel.Sel.Name, fnName)
							return false
						}
					}
				}
			}
		}
		return true
	})
	return safetyErr
}

func baseAssignedIdent(expr ast.Expr) (string, bool) {
	switch x := unwrapParens(expr).(type) {
	case *ast.Ident:
		return x.Name, x.Name != "" && x.Name != "_"
	case *ast.IndexExpr:
		return baseAssignedIdent(x.X)
	case *ast.StarExpr:
		return baseAssignedIdent(x.X)
	case *ast.SelectorExpr:
		return baseAssignedIdent(x.X)
	}
	return "", false
}

func matchMathScalarBitcast(deref *ast.StarExpr, unsafeAlias string, paramTypes map[string]string, mutatedVars map[string]bool, localDeclCounts map[string]int) (*ast.CallExpr, *ast.UnaryExpr, bool) {
	castCall, okC := unwrapParens(deref.X).(*ast.CallExpr)
	if !okC || castCall.Ellipsis.IsValid() || len(castCall.Args) != 1 {
		return nil, nil, false
	}
	ptrType, okPT := unwrapParens(castCall.Fun).(*ast.StarExpr)
	if !okPT {
		return nil, nil, false
	}
	dstID, okDst := unwrapParens(ptrType.X).(*ast.Ident)
	if !okDst {
		return nil, nil, false
	}
	uCall, okUC := unwrapParens(castCall.Args[0]).(*ast.CallExpr)
	if !okUC || uCall.Ellipsis.IsValid() || len(uCall.Args) != 1 {
		return nil, nil, false
	}
	uSel, okUS := unwrapParens(uCall.Fun).(*ast.SelectorExpr)
	if !okUS || uSel.Sel.Name != "Pointer" {
		return nil, nil, false
	}
	if uPkg, okUP := unwrapParens(uSel.X).(*ast.Ident); !okUP || uPkg.Name != unsafeAlias {
		return nil, nil, false
	}
	amp, okAmp := unwrapParens(uCall.Args[0]).(*ast.UnaryExpr)
	if !okAmp || amp.Op != token.AND {
		return nil, nil, false
	}
	srcID, okSrc := unwrapParens(amp.X).(*ast.Ident)
	if !okSrc || mutatedVars[srcID.Name] || localDeclCounts[srcID.Name] > 0 {
		return nil, nil, false
	}
	srcType := paramTypes[srcID.Name]
	if (srcType == "float32" && dstID.Name == "uint32") ||
		(srcType == "uint32" && dstID.Name == "float32") ||
		(srcType == "float64" && dstID.Name == "uint64") ||
		(srcType == "uint64" && dstID.Name == "float64") {
		return uCall, amp, true
	}
	return nil, nil, false
}

type mathAsmGraph struct {
	texts   map[string]bool
	tainted map[string]bool
	edges   map[string]map[string]bool
}

func verifyAndIndexMathAssembly(ctx context.Context, asmSources map[string]string, selectedHeaders map[string]bool, idx *packageASTIndex, pureGoTables, cpuGoVars, declaredConsts map[string]bool) (*mathAsmGraph, error) {
	out := &mathAsmGraph{
		texts:   map[string]bool{},
		tainted: map[string]bool{},
		edges:   map[string]map[string]bool{},
	}
	if len(asmSources) == 0 {
		return out, nil
	}
	addEdge := func(from, to string) {
		if from == "" || to == "" || from == to {
			return
		}
		m := out.edges[from]
		if m == nil {
			m = map[string]bool{}
			out.edges[from] = m
		}
		m[to] = true
	}

	names := make([]string, 0, len(asmSources))
	for name := range asmSources {
		names = append(names, name)
	}
	slices.Sort(names)

	expandedByFile := make(map[string][]string, len(names))
	rodataSyms := map[string]bool{}
	taintedGloblSyms := map[string]bool{}
	type pendingData struct {
		file string
		rest string
	}
	var dataItems []pendingData

	for _, name := range names {
		src := asmSources[name]
		if err := verifyToolchainAssemblyFile(ctx, "math", name, src, selectedHeaders); err != nil {
			return nil, fmt.Errorf("math: assembly %s: %w", name, err)
		}
		stmts, err := expandMathAsmStatements(name, src)
		if err != nil {
			return nil, err
		}
		expandedByFile[name] = stmts

		for _, stmt := range stmts {
			op, rest := splitMathAsmOp(stmt)
			switch strings.ToUpper(op) {
			case "GLOBL":
				symKey, goName, isRodata, ok := parseMathAsmGlobl(name, rest)
				if !ok {
					return nil, fmt.Errorf("math: malformed GLOBL in %s: %q", name, stmt)
				}
				if goName != "" && (pureGoTables[goName] || cpuGoVars[goName] || declaredConsts[goName] || idx.topFuncs[goName] != nil) {
					return nil, fmt.Errorf("math: assembly GLOBL %s collides with Go declaration", goName)
				}
				if isRodata {
					rodataSyms[symKey] = true
				} else {
					taintedGloblSyms[symKey] = true
					out.tainted[symKey] = true
				}
			case "DATA":
				dataItems = append(dataItems, pendingData{file: name, rest: rest})
			case "TEXT":
				textKey, ok := parseMathAsmTextSym(name, rest)
				if !ok {
					return nil, fmt.Errorf("math: malformed TEXT header in %s: %q", name, stmt)
				}
				if textKey == "math.init" {
					return nil, fmt.Errorf("math: forbidden assembly init TEXT in %s", name)
				}
				out.texts[textKey] = true
			}
		}
	}

	resolveSym := func(file, rawSym string) (symKey string, kind string, ok bool) {
		rawSym = strings.TrimSpace(rawSym)
		if rawSym == "" {
			return "", "", false
		}
		if strings.HasSuffix(rawSym, "<>") {
			base := strings.TrimPrefix(strings.TrimSuffix(rawSym, "<>"), "·")
			if base == "" {
				return "", "", false
			}
			k := file + ":<>" + base
			if rodataSyms[k] {
				return k, "rodata", true
			}
			if taintedGloblSyms[k] {
				return k, "tainted_globl", true
			}
			if out.texts[k] {
				return k, "text", true
			}
			return "", "", false
		}
		if strings.HasPrefix(rawSym, "·") {
			goName := strings.TrimPrefix(rawSym, "·")
			if goName == "" {
				return "", "", false
			}
			k := "math." + goName
			if rodataSyms[k] {
				return k, "rodata", true
			}
			if taintedGloblSyms[k] {
				return k, "tainted_globl", true
			}
			if out.texts[k] {
				return k, "text", true
			}
			if pureGoTables[goName] {
				return k, "go_table", true
			}
			if cpuGoVars[goName] {
				return k, "cpu_var", true
			}
			if idx.topFuncs[goName] != nil {
				return k, "go_func", true
			}
			return "", "", false
		}
		// Cross-package symbol (e.g. runtime·memmove or internal/cpu·X86).
		norm := strings.ReplaceAll(rawSym, "·", ".")
		if cprep.AllowedPureAsmCrossPkgSymbols[norm] {
			return norm, "pure_ext", true
		}
		if strings.HasPrefix(norm, "internal/cpu.") {
			return norm, "cpu_ext", true
		}
		return "", "", false
	}

	for _, di := range dataItems {
		comma := strings.IndexByte(di.rest, ',')
		if comma < 0 {
			return nil, fmt.Errorf("math: malformed DATA in %s: %q", di.file, di.rest)
		}
		lhs, rhs := di.rest[:comma], di.rest[comma+1:]
		lhsRefs := extractMathSBRefs(lhs)
		if len(lhsRefs) != 1 {
			return nil, fmt.Errorf("math: invalid DATA target in %s: %q", di.file, di.rest)
		}
		dstKey, dstKind, okDst := resolveSym(di.file, lhsRefs[0].sym)
		if !okDst || (dstKind != "rodata" && dstKind != "tainted_globl") {
			return nil, fmt.Errorf("math: DATA target %q not declared GLOBL in %s", lhsRefs[0].sym, di.file)
		}
		for _, r := range extractMathSBRefs(rhs) {
			valKey, valKind, okVal := resolveSym(di.file, r.sym)
			if !okVal {
				return nil, fmt.Errorf("math: unresolved DATA symbol %q in %s", r.sym, di.file)
			}
			if dstKind == "rodata" && (valKind == "tainted_globl" || valKind == "cpu_var" || valKind == "cpu_ext") {
				return nil, fmt.Errorf("math: RODATA %s references mutable/CPU symbol %s", dstKey, valKey)
			}
			addEdge(dstKey, valKey)
		}
	}

	for _, name := range names {
		curText := ""
		tookReadOnlyAddr := false
		sawNonStackMemWrite := false
		flushText := func() error {
			if curText != "" && tookReadOnlyAddr && sawNonStackMemWrite {
				return fmt.Errorf("math: indirect memory store in TEXT %s after read-only table address load in %s", curText, name)
			}
			curText = ""
			tookReadOnlyAddr = false
			sawNonStackMemWrite = false
			return nil
		}
		for _, stmt := range expandedByFile[name] {
			op, rest := splitMathAsmOp(stmt)
			uop := strings.ToUpper(op)
			baseOp := uop
			if dot := strings.IndexByte(baseOp, '.'); dot >= 0 {
				baseOp = baseOp[:dot]
			}
			switch baseOp {
			case "GLOBL", "DATA":
				if err := flushText(); err != nil {
					return nil, err
				}
				continue
			case "TEXT":
				if err := flushText(); err != nil {
					return nil, err
				}
				tk, _ := parseMathAsmTextSym(name, rest)
				curText = tk
				continue
			case "FUNCDATA", "PCDATA", "PCALIGN", "PCALIGNMAX", "NOP", "RET", "UNDEF":
				continue
			}
			if curText == "" {
				return nil, fmt.Errorf("math: stray assembly instruction outside TEXT in %s: %q", name, stmt)
			}
			if mathForbiddenAsmOps[baseOp] {
				return nil, fmt.Errorf("math: forbidden instruction %s in %s (%s)", uop, name, curText)
			}
			if mathCPUQueryAsmOps[baseOp] {
				out.tainted[curText] = true
			}

			operands := splitMathAsmOperands(rest)
			if len(operands) == 0 {
				if mathAllowedZeroOperandAsmOps[baseOp] {
					continue
				}
				return nil, fmt.Errorf("math: unsupported zero-operand instruction %s in %s (%s)", uop, name, curText)
			}
			for opIdx, operand := range operands {
				mayWriteMem := mathAsmOperandMayWriteMemory(baseOp, operand, opIdx, len(operands))
				refs := extractMathSBRefs(operand)
				if mayWriteMem && len(refs) > 0 {
					return nil, fmt.Errorf("math: forbidden direct store/RMW to (SB) in %s (%s): %q", name, curText, stmt)
				}
				for _, r := range refs {
					rk, rKind, okR := resolveSym(name, r.sym)
					if !okR {
						return nil, fmt.Errorf("math: unresolved (SB) symbol %q in %s (%s)", r.sym, name, curText)
					}
					if rKind == "cpu_ext" || rKind == "cpu_var" || rKind == "tainted_globl" {
						out.tainted[curText] = true
					}
					isAddrLoadOp := strings.HasPrefix(baseOp, "LEA") || baseOp == "LA" || baseOp == "LAY" || baseOp == "LARL"
					if (r.addrTaken || isAddrLoadOp) && (rKind == "rodata" || rKind == "go_table" || rKind == "cpu_var") {
						tookReadOnlyAddr = true
					}
					addEdge(curText, rk)
				}
				if mayWriteMem && strings.ContainsRune(operand, '(') &&
					!strings.Contains(operand, "(FP)") && !strings.Contains(operand, "(SP)") &&
					!strings.Contains(operand, "(RSP)") && !strings.Contains(operand, "(PC)") {
					sawNonStackMemWrite = true
					out.tainted[curText] = true
				}
			}
		}
		if err := flushText(); err != nil {
			return nil, err
		}
	}

	return out, nil
}

var mathAllowedZeroOperandAsmOps = map[string]bool{
	"FRNDINT": true, "FABS": true, "FTST": true, "FXAM": true, "FCHS": true, "FSQRT": true,
	"FLD1": true, "FLDZ": true, "FLDPI": true, "FLDL2E": true, "FLDL2T": true, "FLDLG2": true, "FLDLN2": true,
	"FPREM": true, "FPREM1": true, "F2XM1": true, "FYL2X": true, "FPTAN": true, "FPATAN": true, "FSCALE": true,
	"FSIN": true, "FCOS": true, "FSINCOS": true, "WAIT": true, "FWAIT": true,
	"SAHF": true, "CDQ": true, "CQO": true, "CWDE": true, "CDQE": true,
	"F64FLOOR": true, "F64CEIL": true, "F64TRUNC": true, "F64ABS": true, "F64NEG": true, "F64SQRT": true, "F64NEAREST": true,
	"F32FLOOR": true, "F32CEIL": true, "F32TRUNC": true, "F32ABS": true, "F32NEG": true, "F32SQRT": true, "F32NEAREST": true,
}

var mathAsmReadOnlyBranchOrCompareOps = map[string]bool{
	"CALL": true, "JAL": true, "JALR": true,
	"BR": true, "BL": true, "BLR": true,
	"BEQ": true, "BNE": true, "BGT": true, "BGE": true, "BLT": true, "BLE": true,
	"BHI": true, "BHS": true, "BLO": true, "BLS": true, "BMI": true, "BPL": true,
	"BVS": true, "BVC": true, "BCC": true, "BCS": true,
	"BEQZ": true, "BNEZ": true, "BLEZ": true, "BGTZ": true, "BLTZ": true, "BGEZ": true,
	"BGTU": true, "BGEU": true, "BLTU": true, "BLEU": true,
	"BC": true, "BCT": true, "BCTG": true, "CBZ": true, "CBNZ": true, "TBZ": true, "TBNZ": true,
	"CMP": true, "CMPB": true, "CMPW": true, "CMPL": true, "CMPQ": true, "CMPD": true,
	"CMPU": true, "CMPUB": true, "CMPUW": true, "CMPUL": true, "CMPUD": true,
	"CMPUBEQ": true, "CMPUBNE": true, "CMPUBLT": true, "CMPUBLE": true, "CMPUBGT": true, "CMPUBGE": true,
	"CMPBEQ": true, "CMPBNE": true, "CMPBLT": true, "CMPBLE": true, "CMPBGT": true, "CMPBGE": true,
	"CMPEQ": true, "CMPNE": true, "CMPLT": true, "CMPLE": true, "CMPGT": true, "CMPGE": true,
	"CMPPS": true, "CMPPD": true, "CMPSS": true, "CMPSD": true,
	"FCMP": true, "FCMPD": true, "FCMPS": true, "FCMPU": true, "FCMPO": true,
	"UCOMISS": true, "UCOMISD": true, "COMISS": true, "COMISD": true,
	"VUCOMISS": true, "VUCOMISD": true, "VCOMISS": true, "VCOMISD": true,
	"TEST": true, "TESTB": true, "TESTW": true, "TESTL": true, "TESTQ": true,
	"TST": true, "TSTW": true,
	"BT": true, "BTW": true, "BTL": true, "BTQ": true,
	"PTEST": true, "VPTEST": true,
}

func isMathAsmReadOnlyBranchOrCompare(baseOp string) bool {
	return strings.HasPrefix(baseOp, "J") || mathAsmReadOnlyBranchOrCompareOps[baseOp]
}

func isMathAsmAnyOperandMemWriteOp(baseOp string) bool {
	for _, pfx := range []string{
		"XCHG", "CMPXCHG", "CAS", "SWP",
		"STXR", "STLXR", "STXP", "STLXP",
		"VST", "ST1", "ST2", "ST3", "ST4", "STP", "STL", "STUR", "STR", "STM",
		"LDADD", "LDCLR", "LDEOR", "LDSET", "LDOR",
		"LDSMAX", "LDSMIN", "LDUMAX", "LDUMIN",
		"AMO", "SC", "LOCK",
	} {
		if strings.HasPrefix(baseOp, pfx) {
			return true
		}
	}
	return false
}

func mathAsmOperandMayWriteMemory(baseOp, operand string, opIdx, nOps int) bool {
	trimmed := strings.TrimSpace(operand)
	if trimmed == "" || strings.HasPrefix(trimmed, "$") {
		return false
	}
	if isMathAsmReadOnlyBranchOrCompare(baseOp) {
		return false
	}
	if nOps == 1 || isMathAsmAnyOperandMemWriteOp(baseOp) {
		return true
	}
	return opIdx == nOps-1
}

func expandMathAsmStatements(name, src string) ([]string, error) {
	cleaned := cprep.StripAssemblyComments(src, true, true)
	activeDefs := map[string][]cprep.MacroDef{}
	condDepth := 0
	var stmts []string

	for _, rawLine := range strings.Split(cleaned, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			kw, rest, _ := cprep.CutDirectiveKeyword(line)
			switch kw {
			case "include":
				hdr, err := strconv.Unquote(strings.TrimSpace(rest))
				if err != nil || !cprep.AllowedPureAsmStandardHeaders[hdr] {
					return nil, fmt.Errorf("math: unapproved #include %q in %s", rest, name)
				}
			case "define":
				mName, def, _, ok := cprep.ParseDefineRest(rest)
				if !ok || mName == "" {
					return nil, fmt.Errorf("math: malformed #define in %s: %q", name, line)
				}
				wasEmpty := len(activeDefs[mName]) == 0
				cprep.AppendMacroDefUnique(activeDefs, mName, def)
				if wasEmpty && condDepth > 0 {
					cprep.EnsureMacroIdentityChoice(activeDefs, mName)
				}
			case "undef":
				mName := cprep.LeadingASCIIIdent(strings.TrimSpace(rest))
				if condDepth == 0 {
					delete(activeDefs, mName)
				} else if len(activeDefs[mName]) > 0 {
					cprep.EnsureMacroIdentityChoice(activeDefs, mName)
				}
			case "if", "ifdef", "ifndef":
				condDepth++
			case "elif", "else":
				if condDepth <= 0 {
					return nil, fmt.Errorf("math: unmatched #%s in %s", kw, name)
				}
			case "endif":
				if condDepth <= 0 {
					return nil, fmt.Errorf("math: unmatched #endif in %s", name)
				}
				condDepth--
			default:
				return nil, fmt.Errorf("math: unsupported directive #%s in %s", kw, name)
			}
			continue
		}

		choices := []string{line}
		if len(activeDefs) > 0 {
			budget := &cprep.ExpandBudget{StatesLeft: cprep.MaxCPPExpandedStatesPerLine}
			_, expanded := cprep.ExpandAsmCPPStatesWithBudget(line, activeDefs, "", "", 0, budget)
			if budget.Overflow || len(expanded) == 0 {
				return nil, fmt.Errorf("math: macro expansion overflow in %s", name)
			}
			choices = expanded
		}
		for _, expLine := range choices {
			for _, part := range strings.Split(expLine, ";") {
				s := strings.TrimSpace(part)
				for {
					lbl, after, ok := cutMathAsmLabel(s)
					if !ok || lbl == "" {
						break
					}
					s = strings.TrimSpace(after)
				}
				if s != "" {
					stmts = append(stmts, s)
				}
			}
		}
	}
	if condDepth != 0 {
		return nil, fmt.Errorf("math: unterminated preprocessor conditional in %s", name)
	}
	return stmts, nil
}

func cutMathAsmLabel(s string) (string, string, bool) {
	colon := strings.IndexByte(s, ':')
	if colon <= 0 {
		return "", s, false
	}
	prefix := strings.TrimSpace(s[:colon])
	for i, r := range prefix {
		if !(unicode.IsLetter(r) || r == '_' || (i > 0 && unicode.IsDigit(r))) {
			return "", s, false
		}
	}
	return prefix, s[colon+1:], true
}

func splitMathAsmOp(stmt string) (string, string) {
	i := 0
	for i < len(stmt) && stmt[i] != ' ' && stmt[i] != '\t' {
		i++
	}
	return stmt[:i], strings.TrimSpace(stmt[i:])
}

func splitMathAsmOperands(rest string) []string {
	if rest == "" {
		return nil
	}
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(rest[start:i]))
				start = i + 1
			}
		}
	}
	out = append(out, strings.TrimSpace(rest[start:]))
	return out
}

type mathSBRef struct {
	sym       string
	addrTaken bool
}

func extractMathSBRefs(s string) []mathSBRef {
	var out []mathSBRef
	rem := s
	for {
		idx := strings.Index(rem, "(SB)")
		if idx < 0 {
			break
		}
		prefix := rem[:idx]
		rem = rem[idx+4:]

		// Strip optional `[ \t]*[+-][ \t]*[0-9xXa-fA-F]+` offset before `(SB)`.
		p := strings.TrimRight(prefix, " \t")
		for {
			k := len(p)
			for k > 0 && (unicode.IsDigit(rune(p[k-1])) || (p[k-1] >= 'a' && p[k-1] <= 'f') || (p[k-1] >= 'A' && p[k-1] <= 'F') || p[k-1] == 'x' || p[k-1] == 'X') {
				k--
			}
			if k < len(p) {
				beforeNum := strings.TrimRight(p[:k], " \t")
				if strings.HasSuffix(beforeNum, "+") || strings.HasSuffix(beforeNum, "-") {
					p = strings.TrimRight(beforeNum[:len(beforeNum)-1], " \t")
					continue
				}
			}
			break
		}

		end := len(p)
		start := end
		if strings.HasSuffix(p[:start], "<>") {
			start -= 2
		}
		for start > 0 {
			ch := p[start-1]
			if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '/' || ch == '.' {
				start--
				continue
			}
			if start >= 2 && p[start-2] == 0xc2 && p[start-1] == 0xb7 { // UTF-8 '·'
				start -= 2
				continue
			}
			break
		}
		sym := p[start:end]
		if sym == "" {
			continue
		}
		beforeSym := strings.TrimRight(p[:start], " \t")
		addrTaken := strings.HasSuffix(beforeSym, "$")
		out = append(out, mathSBRef{sym: sym, addrTaken: addrTaken})
	}
	return out
}

func parseMathAsmGlobl(file, rest string) (symKey, goName string, isRodata, ok bool) {
	parts := splitMathAsmOperands(rest)
	if len(parts) != 2 && len(parts) != 3 {
		return "", "", false, false
	}
	refs := extractMathSBRefs(parts[0])
	if len(refs) != 1 || refs[0].addrTaken {
		return "", "", false, false
	}
	raw := refs[0].sym
	if len(parts) == 3 {
		for _, tok := range strings.FieldsFunc(parts[1], func(r rune) bool {
			return r == '|' || r == '+' || unicode.IsSpace(r)
		}) {
			if tok == "RODATA" {
				isRodata = true
			}
		}
	}
	if strings.HasSuffix(raw, "<>") {
		base := strings.TrimPrefix(strings.TrimSuffix(raw, "<>"), "·")
		if base == "" {
			return "", "", false, false
		}
		return file + ":<>" + base, "", isRodata, true
	}
	if strings.HasPrefix(raw, "·") {
		gn := strings.TrimPrefix(raw, "·")
		if gn == "" {
			return "", "", false, false
		}
		return "math." + gn, gn, isRodata, true
	}
	return "", "", false, false
}

func parseMathAsmTextSym(file, rest string) (string, bool) {
	parts := splitMathAsmOperands(rest)
	if len(parts) < 2 {
		return "", false
	}
	refs := extractMathSBRefs(parts[0])
	if len(refs) != 1 || refs[0].addrTaken {
		return "", false
	}
	raw := refs[0].sym
	if strings.HasSuffix(raw, "<>") {
		base := strings.TrimPrefix(strings.TrimSuffix(raw, "<>"), "·")
		if base == "" {
			return "", false
		}
		return file + ":<>" + base, true
	}
	if strings.HasPrefix(raw, "·") {
		gn := strings.TrimPrefix(raw, "·")
		if gn == "" {
			return "", false
		}
		return "math." + gn, true
	}
	return "", false
}
