package asmverify

import "strings"

func isAMD64R14AliasUpper(u string) bool {
	switch u {
	case "R14", "R14L", "R14D", "R14W", "R14B":
		return true
	}
	return false
}

func stmtMentionsAMD64R14(s string) bool {
	return (scanAsmTokens(s) & asmTokAMD64R14) != 0
}

func stmtUnconditionallyKillsAMD64GPR(stmt string) (int, bool, bool) {
	if HasUnquotedColon(stmt) {
		return 0, false, false
	}
	op, rest := splitAsmOp(stmt)
	uop := strings.ToUpper(op)
	if strings.ContainsRune(uop, '.') {
		return 0, false, false
	}
	operands := splitAsmOperands(rest)
	switch uop {
	case "XORL", "XORQ", "SUBL", "SUBQ":
		if len(operands) != 2 {
			return 0, false, false
		}
		r0, full0, ok0 := amd64GPRIndex(operands[0])
		r1, full1, ok1 := amd64GPRIndex(operands[1])
		if ok0 && ok1 && full0 && full1 && r0 == r1 && r0 != 4 &&
			strings.EqualFold(strings.TrimSpace(operands[0]), strings.TrimSpace(operands[1])) {
			return r0, true, true
		}
	case "POPQ":
		if len(operands) == 1 {
			if idx, full, ok := amd64GPRIndex(operands[0]); ok && full && idx != 4 && strings.EqualFold(strings.TrimSpace(operands[0]), operands[0]) {
				u := strings.ToUpper(strings.TrimSpace(operands[0]))
				if !strings.HasSuffix(u, "L") && !strings.HasSuffix(u, "D") {
					return idx, true, true
				}
			}
		}
	case "MOVQ", "MOVL", "MOVABS",
		"MOVBLZX", "MOVWLZX", "MOVBQZX", "MOVWQZX", "MOVLQZX",
		"MOVBLSX", "MOVWLSX", "MOVBQSX", "MOVWQSX", "MOVLQSX",
		"LEAQ", "LEAL",
		"MOVD", "VMOVD", "VMOVQ",
		"MOVMSKPS", "MOVMSKPD", "VMOVMSKPS", "VMOVMSKPD", "PMOVMSKB", "VPMOVMSKB",
		"KMOVB", "KMOVW", "KMOVD", "KMOVQ",
		"LZCNTQ", "LZCNTL", "TZCNTQ", "TZCNTL", "POPCNTQ", "POPCNTL":
		if len(operands) == 2 {
			dstIdx, full, ok := amd64GPRIndex(operands[1])
			if ok && full && dstIdx != 4 && (scanOperandGPRMask("amd64", operands[0])&(1<<uint(dstIdx))) == 0 {
				return dstIdx, true, true
			}
		}
	case "PEXTRD", "PEXTRQ", "VPEXTRD", "VPEXTRQ",
		"BEXTRQ", "BEXTRL", "BZHIQ", "BZHIL", "PDEPQ", "PDEPL", "PEXTQ", "PEXTL",
		"SARXQ", "SARXL", "SHLXQ", "SHLXL", "SHRXQ", "SHRXL", "RORXQ", "RORXL",
		"ANDNQ", "ANDNL":
		if len(operands) == 3 {
			dstIdx, full, ok := amd64GPRIndex(operands[2])
			bit := uint32(1) << uint(dstIdx)
			if ok && full && dstIdx != 4 &&
				(scanOperandGPRMask("amd64", operands[0])&bit) == 0 &&
				(scanOperandGPRMask("amd64", operands[1])&bit) == 0 {
				return dstIdx, true, true
			}
		}
	case "MULXQ", "MULXL":
		if len(operands) == 3 {
			srcMask := scanOperandGPRMask("amd64", operands[0]) | (1 << 2) // implicit RDX read
			if d2, f2, ok2 := amd64GPRIndex(operands[2]); ok2 && f2 && d2 != 4 && (srcMask&(1<<uint(d2))) == 0 {
				return d2, true, true
			}
			if d1, f1, ok1 := amd64GPRIndex(operands[1]); ok1 && f1 && d1 != 4 && (srcMask&(1<<uint(d1))) == 0 {
				return d1, true, true
			}
		}
	}
	return 0, false, false
}

func stmtUnconditionallyKillsAMD64R14(stmt string) bool {
	if HasUnquotedColon(stmt) {
		return false
	}
	op, rest := splitAsmOp(stmt)
	uop := strings.ToUpper(op)
	if strings.ContainsRune(uop, '.') {
		return false
	}
	operands := splitAsmOperands(rest)
	if uop == "MULXQ" || uop == "MULXL" {
		if len(operands) != 3 || stmtMentionsAMD64R14(operands[0]) {
			return false
		}
		_, f1, ok1 := amd64GPRIndex(operands[1])
		d1, _, _ := amd64GPRIndex(operands[1])
		_, f2, ok2 := amd64GPRIndex(operands[2])
		d2, _, _ := amd64GPRIndex(operands[2])
		return (ok1 && f1 && d1 == 14) || (ok2 && f2 && d2 == 14)
	}
	idx, full, ok := stmtUnconditionallyKillsAMD64GPR(stmt)
	return ok && full && idx == 14
}

// verifyAMD64EntryR14NotRead proves via forward CFG reachability over cfg that
// no path from an amd64 ABI0 TEXT entry can read or partially clobber R14
// (which holds the caller's Go goroutine pointer g on entry under the register
// ABI) before an instruction unconditionally overwrites all 64 bits of R14.
func verifyAMD64EntryR14NotRead(cfg *asmBlockCFG) bool {
	if cfg == nil {
		return false
	}
	mentionsR14 := false
	for _, nd := range cfg.nodes {
		if nd.stmt != "" && (strings.Contains(nd.stmt, "R14") || strings.Contains(nd.stmt, "r14")) {
			mentionsR14 = true
			break
		}
	}
	if !mentionsR14 {
		return true
	}

	liveIn := make([]bool, len(cfg.nodes))
	liveIn[cfg.entry] = true
	worklist := []int{cfg.entry}
	for len(worklist) > 0 {
		u := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		if cfg.nodes[u].stmt != "" && stmtMentionsAMD64R14(cfg.nodes[u].stmt) {
			if !stmtUnconditionallyKillsAMD64R14(cfg.nodes[u].stmt) {
				return false
			}
			continue
		}
		for _, v := range cfg.nodes[u].succs {
			if !liveIn[v] {
				liveIn[v] = true
				worklist = append(worklist, v)
			}
		}
	}
	return true
}
