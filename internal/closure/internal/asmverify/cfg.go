package asmverify

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/closure/internal/cprep"
)

type asmCFGNode struct {
	stmt          string
	uop           string
	baseOp        string
	hasDot        bool
	rest          string
	operands      []string
	succs         []int
	callTargetKey string
	isTailCall    bool
	isRet         bool
}

type asmBlockCFG struct {
	entry       int
	falloffExit int
	nodes       []asmCFGNode
	callees     []string
}

func appendUniqueCFGNodes(dst []int, more ...int) []int {
	for _, v := range more {
		if !slices.Contains(dst, v) {
			dst = append(dst, v)
		}
	}
	return dst
}

// buildAsmBlockCFG builds a preprocessor- and macro-choice-aware statement
// control-flow graph for blk, rejecting unbalanced conditionals, unresolved
// branches, out-of-bounds PC-relative branches, and any control-flow path from
// entry that can fall off the end of TEXT without RET or an intra-package
// tail-jump.
func buildAsmBlockCFG(goarch, pkgPath string, fileIdx int, blk asmTextBlock, definedTexts map[string]bool) (*asmBlockCFG, bool) {
	type pendingBranch struct {
		from   int
		seqIdx int
		target string
	}
	type condFrame struct {
		entryFrontier []int
		exitFrontiers []int
		hasElse       bool
	}

	var nodes []asmCFGNode
	addNode := func(nd asmCFGNode) int {
		nodes = append(nodes, nd)
		return len(nodes) - 1
	}
	wireFrontier := func(frontier []int, to int) {
		for _, u := range frontier {
			if !slices.Contains(nodes[u].succs, to) {
				nodes[u].succs = append(nodes[u].succs, to)
			}
		}
	}

	entry := addNode(asmCFGNode{})
	frontier := []int{entry}
	labelNodes := map[string][]int{}
	var branches []pendingBranch
	var condStack []condFrame
	var callees []string
	var seqInstrNodes []int
	hasPreprocOrMacroChoice := false
	hasPCDirective := false

	addCallee := func(k string) {
		if !slices.Contains(callees, k) {
			callees = append(callees, k)
		}
	}

	for _, line := range blk.lines {
		if line.condOp != asmCondNone {
			hasPreprocOrMacroChoice = true
			switch line.condOp {
			case asmCondIf:
				if line.condDepth > blk.openCondDepth {
					condStack = append(condStack, condFrame{
						entryFrontier: slices.Clone(frontier),
					})
				}
			case asmCondElif:
				if len(condStack) == 0 || condStack[len(condStack)-1].hasElse {
					return nil, false
				}
				top := &condStack[len(condStack)-1]
				top.exitFrontiers = appendUniqueCFGNodes(top.exitFrontiers, frontier...)
				frontier = slices.Clone(top.entryFrontier)
			case asmCondElse:
				if len(condStack) == 0 || condStack[len(condStack)-1].hasElse {
					return nil, false
				}
				top := &condStack[len(condStack)-1]
				top.hasElse = true
				top.exitFrontiers = appendUniqueCFGNodes(top.exitFrontiers, frontier...)
				frontier = slices.Clone(top.entryFrontier)
			case asmCondEndif:
				if len(condStack) == 0 {
					return nil, false
				}
				top := condStack[len(condStack)-1]
				condStack = condStack[:len(condStack)-1]
				merged := appendUniqueCFGNodes(top.exitFrontiers, frontier...)
				if !top.hasElse {
					merged = appendUniqueCFGNodes(merged, top.entryFrontier...)
				}
				frontier = merged
			}
			continue
		}

		if len(line.choices) > 1 {
			hasPreprocOrMacroChoice = true
		}
		var nextFrontier []int
		for _, ch := range line.choices {
			chFrontier := slices.Clone(frontier)
			for _, rawStmt := range splitAsmStatements(ch) {
				stmt := strings.TrimSpace(rawStmt)
				if stmt == "" {
					continue
				}
				for {
					lbl, rest, ok := cutAsmLabel(stmt)
					if !ok {
						break
					}
					lblNode := addNode(asmCFGNode{})
					wireFrontier(chFrontier, lblNode)
					labelNodes[lbl] = append(labelNodes[lbl], lblNode)
					chFrontier = []int{lblNode}
					stmt = strings.TrimSpace(rest)
				}
				if stmt == "" {
					continue
				}
				op, rest := splitAsmOp(stmt)
				uop := strings.ToUpper(op)
				baseOp, _, hasDot := strings.Cut(uop, ".")
				if !hasDot {
					if uop == "TEXT" {
						continue
					}
					if uop == "FUNCDATA" || uop == "PCDATA" || uop == "PCALIGN" || uop == "PCALIGNMAX" {
						hasPCDirective = true
						continue
					}
				}
				operands := splitAsmOperands(rest)
				nd := asmCFGNode{
					stmt:     stmt,
					uop:      uop,
					baseOp:   baseOp,
					hasDot:   hasDot,
					rest:     rest,
					operands: operands,
				}
				if strings.HasPrefix(baseOp, "RET") {
					if uop != "RET" || rest != "" {
						return nil, false
					}
					nd.isRet = true
					n := addNode(nd)
					seqInstrNodes = append(seqInstrNodes, n)
					wireFrontier(chFrontier, n)
					chFrontier = nil
					continue
				}
				if isIntraPkgDirectCallOp(goarch, uop, hasDot) {
					if len(operands) != 1 {
						return nil, false
					}
					targetKey, okTarget := parseAsmCallTargetSBRef(pkgPath, fileIdx, operands[0])
					if !okTarget || !definedTexts[targetKey] {
						return nil, false
					}
					nd.callTargetKey = targetKey
					addCallee(targetKey)
					n := addNode(nd)
					seqInstrNodes = append(seqInstrNodes, n)
					wireFrontier(chFrontier, n)
					chFrontier = []int{n}
					continue
				}
				if isAsmBranchMnemonic(uop) || isAsmBranchMnemonic(baseOp) {
					if len(operands) == 0 {
						return nil, false
					}
					isUncondJmp := !hasDot && ((goarch == "amd64" && uop == "JMP") || (goarch == "arm64" && uop == "B"))
					if isUncondJmp && len(operands) == 1 && strings.Contains(operands[0], "(SB)") {
						targetKey, okTarget := parseAsmCallTargetSBRef(pkgPath, fileIdx, operands[0])
						if !okTarget || !definedTexts[targetKey] {
							return nil, false
						}
						nd.callTargetKey = targetKey
						nd.isTailCall = true
						addCallee(targetKey)
						n := addNode(nd)
						seqInstrNodes = append(seqInstrNodes, n)
						wireFrontier(chFrontier, n)
						chFrontier = nil
						continue
					}
					n := addNode(nd)
					seqIdx := len(seqInstrNodes)
					seqInstrNodes = append(seqInstrNodes, n)
					wireFrontier(chFrontier, n)
					target := strings.TrimSpace(operands[len(operands)-1])
					branches = append(branches, pendingBranch{from: n, seqIdx: seqIdx, target: target})
					if isUncondJmp {
						chFrontier = nil
					} else {
						chFrontier = []int{n}
					}
					continue
				}
				n := addNode(nd)
				seqInstrNodes = append(seqInstrNodes, n)
				wireFrontier(chFrontier, n)
				chFrontier = []int{n}
			}
			nextFrontier = appendUniqueCFGNodes(nextFrontier, chFrontier...)
		}
		frontier = nextFrontier
	}
	if len(condStack) != 0 {
		return nil, false
	}

	falloffExit := addNode(asmCFGNode{})
	wireFrontier(frontier, falloffExit)

	for _, br := range branches {
		if strings.HasSuffix(br.target, "(PC)") {
			if hasPreprocOrMacroChoice || hasPCDirective {
				return nil, false
			}
			offStr := strings.TrimSpace(strings.TrimSuffix(br.target, "(PC)"))
			off, err := strconv.ParseInt(offStr, 0, 64)
			if err != nil {
				return nil, false
			}
			for _, nd := range nodes {
				if nd.baseOp == "BYTE" || nd.baseOp == "WORD" || nd.baseOp == "DWORD" || nd.baseOp == "LONG" || nd.baseOp == "QUAD" {
					return nil, false
				}
			}
			dstSeq := int64(br.seqIdx) + off
			if dstSeq < 0 || dstSeq >= int64(len(seqInstrNodes)) {
				return nil, false
			}
			dstNode := seqInstrNodes[int(dstSeq)]
			if !slices.Contains(nodes[br.from].succs, dstNode) {
				nodes[br.from].succs = append(nodes[br.from].succs, dstNode)
			}
			continue
		}
		targets := labelNodes[br.target]
		if len(targets) == 0 {
			return nil, false
		}
		for _, t := range targets {
			if !slices.Contains(nodes[br.from].succs, t) {
				nodes[br.from].succs = append(nodes[br.from].succs, t)
			}
		}
	}

	// Reject any control-flow path from entry that can reach falloffExit.
	seen := make([]bool, len(nodes))
	seen[entry] = true
	stack := []int{entry}
	for len(stack) > 0 {
		u := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if u == falloffExit {
			return nil, false
		}
		for _, v := range nodes[u].succs {
			if !seen[v] {
				seen[v] = true
				stack = append(stack, v)
			}
		}
	}

	slices.Sort(callees)
	return &asmBlockCFG{
		entry:       entry,
		falloffExit: falloffExit,
		nodes:       nodes,
		callees:     callees,
	}, true
}

func isIntraPkgDirectCallOp(goarch, uop string, hasDot bool) bool {
	if hasDot {
		return false
	}
	if goarch == "amd64" {
		return uop == "CALL"
	}
	if goarch == "arm64" {
		return uop == "BL"
	}
	return false
}

const asmTaintFlagsBit uint32 = 1 << 31

func amd64GPRIndex(tok string) (idx int, fullWidth bool, ok bool) {
	switch strings.ToUpper(strings.TrimSpace(tok)) {
	case "AX":
		return 0, true, true
	case "AL", "AH":
		return 0, false, true
	case "CX":
		return 1, true, true
	case "CL", "CH":
		return 1, false, true
	case "DX":
		return 2, true, true
	case "DL", "DH":
		return 2, false, true
	case "BX":
		return 3, true, true
	case "BL", "BH":
		return 3, false, true
	case "SP":
		return 4, true, true
	case "SPL", "SPB":
		return 4, false, true
	case "BP":
		return 5, true, true
	case "BPL", "BPB":
		return 5, false, true
	case "SI":
		return 6, true, true
	case "SIL", "SIB":
		return 6, false, true
	case "DI":
		return 7, true, true
	case "DIL", "DIB":
		return 7, false, true
	}
	u := strings.ToUpper(strings.TrimSpace(tok))
	if len(u) >= 2 && u[0] == 'R' {
		tail := u[1:]
		full := true
		if last := tail[len(tail)-1]; last == 'B' || last == 'W' {
			full = false
			tail = tail[:len(tail)-1]
		} else if last == 'L' || last == 'D' {
			tail = tail[:len(tail)-1]
		}
		if n, okN := parseOneOrTwoAsciiDigits(tail); okN && n >= 8 && n <= 15 {
			return n, full, true
		}
	}
	return 0, false, false
}

func arm64GPRIndex(tok string) (idx int, ok bool) {
	u := strings.ToUpper(strings.TrimSpace(tok))
	if u == "LR" {
		return 30, true
	}
	if len(u) >= 2 && len(u) <= 3 && u[0] == 'R' && !(len(u) == 3 && u[1] == '0') {
		if n, okN := parseOneOrTwoAsciiDigits(u[1:]); okN && n >= 0 && n <= 30 && n != 18 && n != 28 {
			return n, true
		}
	}
	return 0, false
}

func scanOperandGPRMask(goarch, s string) uint32 {
	var mask uint32
	unq := stripAsmQuotedLiterals(s)
	for i := 0; i < len(unq); {
		if unq[i] == '"' || unq[i] == '\'' {
			i = cprep.SkipQuotedLiteral(unq, i)
			continue
		}
		isIdent := func(b byte) bool {
			return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b > 0x7f
		}
		if isIdent(unq[i]) {
			start := i
			for i < len(unq) && isIdent(unq[i]) {
				i++
			}
			tok := unq[start:i]
			if isAsciiLowerIdent(tok) && isFrameSlotIdentBeforePlusFP(unq, start, i) {
				continue
			}
			if strings.ContainsRune(tok, '·') || (start > 0 && unq[start-1] == '·') {
				continue
			}
			if goarch == "amd64" {
				if idx, _, ok := amd64GPRIndex(tok); ok {
					mask |= 1 << uint(idx)
				}
			} else if goarch == "arm64" {
				if idx, ok := arm64GPRIndex(tok); ok {
					mask |= 1 << uint(idx)
				}
			}
			continue
		}
		i++
	}
	return mask
}

func operandProducesSBAddress(uop, opnd string, opIdx int) bool {
	unq := stripAsmQuotedLiterals(opnd)
	if !strings.Contains(unq, "(SB)") {
		return false
	}
	if strings.HasPrefix(strings.TrimSpace(opnd), "$") {
		return true
	}
	return opIdx == 0 && strings.HasPrefix(uop, "LEA")
}

func isConditionalFlagConsumerOp(goarch, uop, baseOp string, hasDot bool) bool {
	if goarch == "amd64" {
		if uop != "JMP" && isAsmBranchMnemonic(uop) {
			return true
		}
		return baseOp == "LAHF" ||
			strings.HasPrefix(baseOp, "CMOV") || strings.HasPrefix(baseOp, "FCMOV") ||
			strings.HasPrefix(baseOp, "SET") || strings.HasPrefix(baseOp, "ADOX") ||
			strings.HasPrefix(baseOp, "ADC") || strings.HasPrefix(baseOp, "SBB") ||
			strings.HasPrefix(baseOp, "RCL") || strings.HasPrefix(baseOp, "RCR")
	}
	if goarch == "arm64" {
		if hasDot && baseOp == "B" {
			return true
		}
		switch baseOp {
		case "BEQ", "BNE", "BCS", "BHS", "BCC", "BLO", "BMI", "BPL", "BVS", "BVC",
			"BHI", "BLS", "BGE", "BLT", "BGT", "BLE",
			"CSEL", "CSINC", "CSINV", "CSNEG", "CSET", "CSETM", "CINC", "CINV", "CNEG",
			"CCMP", "CCMN", "FCCMP", "FCCMPE", "ADC", "ADCS", "SBC", "SBCS", "NGC", "NGCS":
			return true
		}
	}
	return false
}

func isUntaintedFlagOverwriteOp(goarch, baseOp string) bool {
	if goarch == "amd64" {
		switch baseOp {
		case "CMPB", "CMPW", "CMPL", "CMPQ",
			"TESTB", "TESTW", "TESTL", "TESTQ",
			"XORB", "XORW", "XORL", "XORQ",
			"SUBB", "SUBW", "SUBL", "SUBQ",
			"ADDB", "ADDW", "ADDL", "ADDQ",
			"ANDB", "ANDW", "ANDL", "ANDQ",
			"ORB", "ORW", "ORL", "ORQ":
			return true
		}
		return false
	}
	if goarch == "arm64" {
		switch baseOp {
		case "CMP", "CMPW", "CMN", "CMNW", "TST", "TSTW", "ADDS", "ADDSW", "SUBS", "SUBSW", "ANDS", "ANDSW":
			return true
		}
	}
	return false
}

// amd64ImplicitGPRMask returns the bitmask of amd64 GPRs implicitly read or
// written by nd without appearing in nd.operands.
func amd64ImplicitGPRMask(nd asmCFGNode) uint32 {
	const (
		regAX uint32 = 1 << 0
		regCX uint32 = 1 << 1
		regDX uint32 = 1 << 2
		regBX uint32 = 1 << 3
		regSP uint32 = 1 << 4
		regBP uint32 = 1 << 5
		regSI uint32 = 1 << 6
		regDI uint32 = 1 << 7
	)
	op := nd.baseOp
	switch {
	case strings.HasPrefix(op, "MOVS") || strings.HasPrefix(op, "STOS") ||
		strings.HasPrefix(op, "LODS") || strings.HasPrefix(op, "SCAS") || strings.HasPrefix(op, "CMPS"):
		return regAX | regCX | regSI | regDI
	case strings.HasPrefix(op, "MASKMOV") || strings.HasPrefix(op, "VMASKMOV"):
		return regDI
	case strings.HasPrefix(op, "XLAT"):
		return regAX | regBX
	case strings.HasPrefix(op, "MULX"):
		return regDX
	case strings.HasPrefix(op, "LEAVE") || strings.HasPrefix(op, "ENTER"):
		return regBP | regSP
	case op == "CMPXCHG8B" || op == "CMPXCHG16B":
		return regAX | regBX | regCX | regDX
	case strings.HasPrefix(op, "CMPXCHG"):
		return regAX
	case strings.HasPrefix(op, "JCXZ") || op == "JECXZ" || op == "JRCXZ" || strings.HasPrefix(op, "LOOP"):
		return regCX
	case (strings.HasPrefix(op, "MUL") || strings.HasPrefix(op, "IMUL") ||
		strings.HasPrefix(op, "DIV") || strings.HasPrefix(op, "IDIV")) && len(nd.operands) == 1:
		return regAX | regDX
	case op == "CWD" || op == "CDQ" || op == "CDL" || op == "CQO":
		return regAX | regDX
	case op == "CBW" || op == "CWDE" || op == "CDQE" || op == "CWL" || op == "CLQ" || op == "SAHF" || op == "LAHF":
		return regAX
	case strings.HasPrefix(op, "PCMPESTRI") || strings.HasPrefix(op, "PCMPESTRM") ||
		strings.HasPrefix(op, "PCMPISTRI") || strings.HasPrefix(op, "PCMPISTRM") ||
		strings.HasPrefix(op, "VPCMPESTRI") || strings.HasPrefix(op, "VPCMPESTRM") ||
		strings.HasPrefix(op, "VPCMPISTRI") || strings.HasPrefix(op, "VPCMPISTRM"):
		return regAX | regCX | regDX
	case op == "CPUID":
		return regAX | regBX | regCX | regDX
	case op == "BYTE" || op == "RDTSC" || op == "RDTSCP" || op == "RDPMC":
		return regAX | regCX | regDX
	}
	return 0
}

// verifyAsmBlockSBAddrTaint proves via forward monotone dataflow over cfg that
// any GPR loaded with an (SB) symbol address ($sym(SB) or LEA* sym(SB)) is used
// strictly for in-register offset arithmetic or read-only memory loads, never
// written through, never spilled/returned to memory or stack or vector
// registers, and never tested/branched on to leak ASLR address bits.
func verifyAsmBlockSBAddrTaint(goarch string, cfg *asmBlockCFG, entryMask uint32, calleeRetTaint map[string]uint32) (uint32, map[string]uint32, bool) {
	if cfg == nil {
		return 0, nil, false
	}
	taintIn := make([]uint32, len(cfg.nodes))
	visited := make([]bool, len(cfg.nodes))
	taintIn[cfg.entry] = entryMask
	visited[cfg.entry] = true
	worklist := []int{cfg.entry}
	var retMask uint32
	var calleeDemand map[string]uint32

	stepNode := func(nd asmCFGNode, cur uint32) (uint32, bool) {
		if nd.stmt == "" {
			return cur, true
		}
		if nd.isRet {
			retMask |= cur
			return 0, true
		}
		if nd.callTargetKey != "" {
			if cur != 0 {
				if calleeDemand == nil {
					calleeDemand = make(map[string]uint32, 2)
				}
				calleeDemand[nd.callTargetKey] |= cur
			}
			if nd.isTailCall {
				retMask |= calleeRetTaint[nd.callTargetKey]
				return 0, true
			}
			return calleeRetTaint[nd.callTargetKey], true
		}
		if (cur&asmTaintFlagsBit) != 0 && isConditionalFlagConsumerOp(goarch, nd.uop, nd.baseOp, nd.hasDot) {
			return 0, false
		}
		// Implicit-register instructions on amd64 must never execute while any implicit GPR is tainted.
		if goarch == "amd64" {
			if ((cur &^ asmTaintFlagsBit) & amd64ImplicitGPRMask(nd)) != 0 {
				return 0, false
			}
		}
		// Decoded arm64 raw WORD opcodes encode register numbers in binary rather than text operands.
		if goarch == "arm64" && nd.uop == "WORD" {
			w, okW := parseAsmImmUint32(nd.rest)
			if !okW || !isAuditedARM64WordOpcode(w) {
				if (cur &^ asmTaintFlagsBit) != 0 {
					return 0, false
				}
				return cur, true
			}
			rd := int(w & 0x1f)
			rdBit := uint32(1) << uint(rd)
			// MOVZ or MRS: overwrites Rd with an untainted constant or static ID register.
			if (w&0x7f800000) == 0x52800000 || (w&0xfff00000) == 0xd5300000 {
				return cur &^ rdBit, true
			}
			// UBFM / LSL / LSR: reject bit-extraction on a tainted pointer (ASLR bit leak); otherwise Rd is untainted.
			if (w & 0x7f800000) == 0x53000000 {
				rn := int((w >> 5) & 0x1f)
				if rn < 31 && (cur&(1<<uint(rn))) != 0 {
					return 0, false
				}
				return cur &^ rdBit, true
			}
			// SVE ADDVL / ADDPL Xd, Xn, #imm6: pointer offset if Xn is tainted, otherwise untainted vector-length multiple.
			if (w & 0xffa0f800) == 0x04205000 {
				rn := int((w >> 5) & 0x1f)
				if rn < 31 && (cur&(1<<uint(rn))) != 0 {
					return cur | rdBit, true
				}
				return cur &^ rdBit, true
			}
			return cur, true
		}

		createsAddr := false
		var stmtRegs uint32
		for idx, opnd := range nd.operands {
			if operandProducesSBAddress(nd.uop, opnd, idx) {
				createsAddr = true
			}
			stmtRegs |= scanOperandGPRMask(goarch, opnd)
		}

		// Fast path: instruction neither creates an (SB) address nor mentions any currently tainted GPR.
		if !createsAddr && (stmtRegs&(cur&^asmTaintFlagsBit)) == 0 {
			next := cur
			if goarch == "amd64" {
				if killedIdx, full, okK := stmtUnconditionallyKillsAMD64GPR(nd.stmt); okK && full {
					next &^= 1 << uint(killedIdx)
				}
			} else if goarch == "arm64" {
				if killedIdx, okK := stmtUnconditionallyKillsARM64GPR(nd); okK {
					next &^= 1 << uint(killedIdx)
				}
			}
			if (next&asmTaintFlagsBit) != 0 && isUntaintedFlagOverwriteOp(goarch, nd.baseOp) {
				next &^= asmTaintFlagsBit
			}
			return next, true
		}

		// Case 1: Creating taint from $sym(SB) or LEAQ sym(SB).
		if createsAddr {
			if len(nd.operands) != 2 || nd.hasDot {
				return 0, false
			}
			// Source operand may optionally index by an untainted GPR in LEAQ sym(SB)(AX*8), Rd,
			// but must not combine two (SB) addresses or write to memory/SP.
			srcMask := scanOperandGPRMask(goarch, nd.operands[0])
			if (srcMask & cur) != 0 {
				return 0, false
			}
			if goarch == "amd64" {
				if nd.uop != "MOVQ" && nd.uop != "LEAQ" {
					return 0, false
				}
				if strings.HasPrefix(strings.TrimSpace(nd.operands[0]), "$") && nd.uop != "MOVQ" {
					return 0, false
				}
				dstIdx, full, okGPR := amd64GPRIndex(nd.operands[1])
				if !okGPR || !full || dstIdx == 4 { // reject SP and sub-64-bit destinations
					return 0, false
				}
				return cur | (1 << uint(dstIdx)), true
			}
			if goarch == "arm64" {
				if nd.uop != "MOVD" || !strings.HasPrefix(strings.TrimSpace(nd.operands[0]), "$") {
					return 0, false
				}
				dstIdx, okGPR := arm64GPRIndex(nd.operands[1])
				if !okGPR {
					return 0, false
				}
				return cur | (1 << uint(dstIdx)), true
			}
			return 0, false
		}

		// Instruction mentions at least one tainted GPR without creating a new (SB) address.
		// Case 2: Self-zeroing idiom on amd64 (`XORL R8, R8` / `XORQ R8, R8` / `SUBL R8, R8` / `SUBQ R8, R8`).
		if goarch == "amd64" && !nd.hasDot && len(nd.operands) == 2 &&
			(nd.uop == "XORL" || nd.uop == "XORQ" || nd.uop == "SUBL" || nd.uop == "SUBQ") {
			r0, full0, ok0 := amd64GPRIndex(nd.operands[0])
			r1, full1, ok1 := amd64GPRIndex(nd.operands[1])
			if ok0 && ok1 && full0 && full1 && r0 == r1 && strings.EqualFold(strings.TrimSpace(nd.operands[0]), strings.TrimSpace(nd.operands[1])) {
				return (cur &^ (1 << uint(r0))) &^ asmTaintFlagsBit, true
			}
		}

		// Case 3: GPR-to-GPR copy or pointer-offset addition (`MOVQ`/`LEAQ`/`ADDQ` on amd64; `MOVD`/`ADD` on arm64).
		if goarch == "amd64" && !nd.hasDot && len(nd.operands) == 2 {
			dstIdx, fullDst, okDst := amd64GPRIndex(nd.operands[1])
			if okDst && fullDst && dstIdx != 4 {
				srcOp := strings.TrimSpace(nd.operands[0])
				if nd.uop == "MOVQ" && !strings.ContainsRune(srcOp, '(') {
					if _, fullSrc, okSrc := amd64GPRIndex(srcOp); okSrc && fullSrc {
						return cur | (1 << uint(dstIdx)), true
					}
				}
				if nd.uop == "LEAQ" && strings.ContainsRune(srcOp, '(') && !strings.Contains(srcOp, "(SB)") {
					return cur | (1 << uint(dstIdx)), true
				}
				if nd.uop == "ADDQ" && !strings.ContainsRune(srcOp, '(') {
					return cur | (1 << uint(dstIdx)) | asmTaintFlagsBit, true
				}
			}
		}
		if goarch == "arm64" && !nd.hasDot {
			if nd.uop == "MOVD" && len(nd.operands) == 2 && !strings.ContainsRune(nd.operands[0], '(') {
				_, okSrc := arm64GPRIndex(nd.operands[0])
				dstIdx, okDst := arm64GPRIndex(nd.operands[1])
				if okSrc && okDst {
					return cur | (1 << uint(dstIdx)), true
				}
			}
			if nd.uop == "ADD" && (len(nd.operands) == 2 || len(nd.operands) == 3) {
				dstOp := nd.operands[len(nd.operands)-1]
				dstIdx, okDst := arm64GPRIndex(dstOp)
				noMem := true
				for _, o := range nd.operands {
					if strings.ContainsRune(o, '(') || strings.ContainsRune(o, '[') {
						noMem = false
					}
				}
				if okDst && noMem {
					return cur | (1 << uint(dstIdx)), true
				}
			}
		}

		// Case 4: Pure memory dereference load `off(Rt)...` in a strictly read-only source operand.
		if strings.HasPrefix(nd.baseOp, "LEA") || isAsmReadModifyWriteMnemonic(nd.baseOp) ||
			isARM64MemoryStoreMnemonic(nd.baseOp) || nd.hasDot || isAsmBranchMnemonic(nd.uop) || isAsmBranchMnemonic(nd.baseOp) {
			return 0, false
		}
		if len(nd.operands) < 2 {
			return 0, false
		}
		isROCompare := isAsmReadOnlyCompareMnemonic(nd.baseOp)
		for idx, opnd := range nd.operands {
			opMask := scanOperandGPRMask(goarch, opnd)
			taintedHere := opMask & (cur &^ asmTaintFlagsBit)
			if taintedHere == 0 {
				continue
			}
			if idx == len(nd.operands)-1 {
				if isROCompare {
					// Compare against memory loaded from table (`CMPB $1, 0(R8)` or `BTQ AX, 0(R8)`).
					if !operandDereferencesAllMaskRegs(goarch, opnd, taintedHere) {
						return 0, false
					}
					continue
				}
				// Tainted destination GPR is allowed ONLY when this instruction unconditionally
				// overwrites the full destination GPR from a memory load (`MOVQ (R8), R8`), handled below.
				if !strings.ContainsRune(opnd, '(') && !strings.ContainsRune(opnd, '[') {
					continue
				}
				return 0, false
			}
			// Source operand mentioning tainted GPR(s): every tainted GPR in this operand MUST
			// sit inside `(...)` memory addressing (never a bare register value!).
			if !operandDereferencesAllMaskRegs(goarch, opnd, taintedHere) {
				return 0, false
			}
		}

		dstOp := strings.TrimSpace(nd.operands[len(nd.operands)-1])
		if isROCompare {
			// Full-flag scalar integer compares/tests overwrite all condition flags from
			// untainted table data; partial-flag instructions such as BT* (which leave ZF
			// unaffected) preserve any prior flag taint.
			if isUntaintedFlagOverwriteOp(goarch, nd.baseOp) {
				return cur &^ asmTaintFlagsBit, true
			}
			return cur, true
		}
		// Destination of a memory load MUST be a register (never memory!).
		if strings.ContainsRune(dstOp, '(') || strings.ContainsRune(dstOp, '[') {
			return 0, false
		}
		dstMask := scanOperandGPRMask(goarch, dstOp)
		if (dstMask & (cur &^ asmTaintFlagsBit)) != 0 {
			// Destination GPR itself was previously tainted: permitted ONLY if this memory load
			// is a pure unconditional full-width load into dstOp (`MOVQ (R8), R8` / `MOVBLZX (R8), R8` / `MOVD (R8), R8`),
			// which replaces the pointer in dstOp with untainted table data.
			if goarch == "amd64" {
				if dstIdx, full, okK := amd64LoadFullWidthDestGPR(nd.uop, dstOp); okK && full {
					return cur &^ (1 << uint(dstIdx)), true
				}
			} else if goarch == "arm64" {
				if dstIdx, okK := arm64LoadFullWidthDestGPR(nd.uop, dstOp); okK {
					return cur &^ (1 << uint(dstIdx)), true
				}
			}
			return 0, false
		}
		return cur, true
	}

	for len(worklist) > 0 {
		u := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		outMask, ok := stepNode(cfg.nodes[u], taintIn[u])
		if !ok {
			return 0, nil, false
		}
		if cfg.nodes[u].isRet || cfg.nodes[u].isTailCall {
			continue
		}
		for _, v := range cfg.nodes[u].succs {
			merged := taintIn[v] | outMask
			if !visited[v] || merged != taintIn[v] {
				visited[v] = true
				taintIn[v] = merged
				worklist = append(worklist, v)
			}
		}
	}
	return retMask, calleeDemand, true
}

// operandDereferencesAllMaskRegs verifies that opnd is a memory dereference
// operand (containing `(...)` without `!` writeback) and that every register in
// requiredMask occurs strictly inside parentheses (never outside as a bare register).
func operandDereferencesAllMaskRegs(goarch, opnd string, requiredMask uint32) bool {
	unq := stripAsmQuotedLiterals(opnd)
	if strings.HasPrefix(strings.TrimSpace(unq), "$") || strings.ContainsRune(unq, '!') || strings.ContainsRune(unq, ',') || !strings.ContainsRune(unq, '(') {
		return false
	}
	depth := 0
	var insideMask, outsideMask uint32
	isIdent := func(b byte) bool {
		return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b > 0x7f
	}
	for i := 0; i < len(unq); {
		if unq[i] == '"' || unq[i] == '\'' {
			i = cprep.SkipQuotedLiteral(unq, i)
			continue
		}
		switch unq[i] {
		case '(':
			depth++
			i++
			continue
		case ')':
			if depth <= 0 {
				return false
			}
			depth--
			i++
			continue
		}
		if isIdent(unq[i]) {
			start := i
			for i < len(unq) && isIdent(unq[i]) {
				i++
			}
			tok := unq[start:i]
			var bit uint32
			if goarch == "amd64" {
				if idx, _, ok := amd64GPRIndex(tok); ok {
					bit = 1 << uint(idx)
				}
			} else if goarch == "arm64" {
				if idx, ok := arm64GPRIndex(tok); ok {
					bit = 1 << uint(idx)
				}
			}
			if bit != 0 {
				if depth > 0 {
					insideMask |= bit
				} else {
					outsideMask |= bit
				}
			}
			continue
		}
		i++
	}
	return depth == 0 && (outsideMask&requiredMask) == 0 && (insideMask&requiredMask) == requiredMask
}

func amd64LoadFullWidthDestGPR(uop, dstOp string) (int, bool, bool) {
	switch uop {
	case "MOVQ", "MOVL",
		"MOVBLZX", "MOVWLZX", "MOVBQZX", "MOVWQZX", "MOVLQZX",
		"MOVBLSX", "MOVWLSX", "MOVBQSX", "MOVWQSX", "MOVLQSX":
		idx, full, ok := amd64GPRIndex(dstOp)
		if ok && full && idx != 4 {
			return idx, true, true
		}
	}
	return 0, false, false
}

func arm64LoadFullWidthDestGPR(uop, dstOp string) (int, bool) {
	switch uop {
	case "MOVD", "MOVW", "MOVWU", "MOVH", "MOVHU", "MOVB", "MOVBU":
		return arm64GPRIndex(dstOp)
	}
	return 0, false
}

func stmtUnconditionallyKillsARM64GPR(nd asmCFGNode) (int, bool) {
	if nd.hasDot || len(nd.operands) != 2 {
		return 0, false
	}
	switch nd.uop {
	case "MOVD", "MOVW", "MOVWU", "MOVH", "MOVHU", "MOVB", "MOVBU", "MOVZ":
		dstIdx, okDst := arm64GPRIndex(nd.operands[1])
		if !okDst {
			return 0, false
		}
		if (scanOperandGPRMask("arm64", nd.operands[0]) & (1 << uint(dstIdx))) != 0 {
			return 0, false
		}
		return dstIdx, true
	}
	return 0, false
}

func scopedAsmTextKey(fileIdx int, blkName string) string {
	if strings.HasPrefix(blkName, "<>") {
		return fmt.Sprintf("file#%d:%s", fileIdx, blkName)
	}
	return blkName
}
