package asmverify

import (
	"slices"
	"strings"
)

func isAMD64R14AliasUpper(u string) bool {
	switch u {
	case "R14", "R14L", "R14D", "R14W", "R14B":
		return true
	}
	return false
}

func isAMD64FullWidthR14Reg(opnd string) bool {
	switch strings.ToUpper(strings.TrimSpace(opnd)) {
	case "R14", "R14L", "R14D":
		return true
	}
	return false
}

func stmtMentionsAMD64R14(s string) bool {
	return (scanAsmTokens(s) & asmTokAMD64R14) != 0
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
	switch uop {
	case "XORL", "XORQ", "SUBL", "SUBQ":
		return len(operands) == 2 && isAMD64FullWidthR14Reg(operands[0]) &&
			strings.EqualFold(strings.TrimSpace(operands[0]), strings.TrimSpace(operands[1]))
	case "POPQ":
		return len(operands) == 1 && strings.EqualFold(strings.TrimSpace(operands[0]), "R14")
	case "MOVQ", "MOVL", "MOVABS",
		"MOVBLZX", "MOVWLZX", "MOVBQZX", "MOVWQZX", "MOVLQZX",
		"MOVBLSX", "MOVWLSX", "MOVBQSX", "MOVWQSX", "MOVLQSX",
		"LEAQ", "LEAL",
		"MOVD", "VMOVD", "VMOVQ",
		"MOVMSKPS", "MOVMSKPD", "VMOVMSKPS", "VMOVMSKPD", "PMOVMSKB", "VPMOVMSKB",
		"KMOVB", "KMOVW", "KMOVD", "KMOVQ",
		"LZCNTQ", "LZCNTL", "TZCNTQ", "TZCNTL", "POPCNTQ", "POPCNTL":
		return len(operands) == 2 && !stmtMentionsAMD64R14(operands[0]) && isAMD64FullWidthR14Reg(operands[1])
	case "PEXTRD", "PEXTRQ", "VPEXTRD", "VPEXTRQ",
		"BEXTRQ", "BEXTRL", "BZHIQ", "BZHIL", "PDEPQ", "PDEPL", "PEXTQ", "PEXTL",
		"SARXQ", "SARXL", "SHLXQ", "SHLXL", "SHRXQ", "SHRXL", "RORXQ", "RORXL",
		"ANDNQ", "ANDNL":
		return len(operands) == 3 && !stmtMentionsAMD64R14(operands[0]) && !stmtMentionsAMD64R14(operands[1]) && isAMD64FullWidthR14Reg(operands[2])
	case "MULXQ", "MULXL":
		if len(operands) != 3 || stmtMentionsAMD64R14(operands[0]) {
			return false
		}
		return isAMD64FullWidthR14Reg(operands[1]) || isAMD64FullWidthR14Reg(operands[2])
	}
	return false
}

func appendUniqueR14Nodes(dst []int, more ...int) []int {
	for _, v := range more {
		if !slices.Contains(dst, v) {
			dst = append(dst, v)
		}
	}
	return dst
}

// verifyAMD64EntryR14NotRead proves via forward CFG reachability that no path
// from an amd64 ABI0 TEXT entry can read or partially clobber R14 (which holds
// the caller's Go goroutine pointer g on entry under the register ABI) before
// an instruction unconditionally overwrites all 64 bits of R14.
func verifyAMD64EntryR14NotRead(blk asmTextBlock) bool {
	mentionsR14 := false
	for _, line := range blk.lines {
		for _, ch := range line.choices {
			if strings.Contains(ch, "R14") || strings.Contains(ch, "r14") {
				mentionsR14 = true
				break
			}
		}
		if mentionsR14 {
			break
		}
	}
	if !mentionsR14 {
		return true
	}

	type r14Node struct {
		stmt  string
		succs []int
	}
	type r14Branch struct {
		from   int
		target string
	}
	type r14CondFrame struct {
		entryFrontier []int
		exitFrontiers []int
		hasElse       bool
	}

	var nodes []r14Node
	addNode := func(stmt string) int {
		nodes = append(nodes, r14Node{stmt: stmt})
		return len(nodes) - 1
	}
	wireFrontier := func(frontier []int, to int) {
		for _, u := range frontier {
			if !slices.Contains(nodes[u].succs, to) {
				nodes[u].succs = append(nodes[u].succs, to)
			}
		}
	}

	entry := addNode("")
	frontier := []int{entry}
	labelNodes := map[string][]int{}
	var branches []r14Branch
	var condStack []r14CondFrame

	for _, line := range blk.lines {
		if line.condOp != asmCondNone {
			switch line.condOp {
			case asmCondIf:
				if line.condDepth > blk.openCondDepth {
					condStack = append(condStack, r14CondFrame{
						entryFrontier: slices.Clone(frontier),
					})
				}
			case asmCondElif:
				if len(condStack) == 0 || condStack[len(condStack)-1].hasElse {
					return false
				}
				top := &condStack[len(condStack)-1]
				top.exitFrontiers = appendUniqueR14Nodes(top.exitFrontiers, frontier...)
				frontier = slices.Clone(top.entryFrontier)
			case asmCondElse:
				if len(condStack) == 0 || condStack[len(condStack)-1].hasElse {
					return false
				}
				top := &condStack[len(condStack)-1]
				top.hasElse = true
				top.exitFrontiers = appendUniqueR14Nodes(top.exitFrontiers, frontier...)
				frontier = slices.Clone(top.entryFrontier)
			case asmCondEndif:
				if len(condStack) == 0 {
					return false
				}
				top := condStack[len(condStack)-1]
				condStack = condStack[:len(condStack)-1]
				merged := appendUniqueR14Nodes(top.exitFrontiers, frontier...)
				if !top.hasElse {
					merged = appendUniqueR14Nodes(merged, top.entryFrontier...)
				}
				frontier = merged
			}
			continue
		}

		var nextFrontier []int
		for _, ch := range line.choices {
			chFrontier := slices.Clone(frontier)
			for _, stmt := range splitAsmStatements(ch) {
				stmt = strings.TrimSpace(stmt)
				if stmt == "" {
					continue
				}
				for {
					lbl, rest, ok := cutAsmLabel(stmt)
					if !ok {
						break
					}
					lblNode := addNode("")
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
				if !hasDot && (uop == "TEXT" || uop == "FUNCDATA" || uop == "PCDATA" || uop == "PCALIGN" || uop == "PCALIGNMAX") {
					continue
				}
				n := addNode(stmt)
				wireFrontier(chFrontier, n)
				if strings.HasPrefix(baseOp, "RET") {
					if uop != "RET" || rest != "" {
						return false
					}
					chFrontier = nil
					continue
				}
				if isAsmBranchMnemonic(uop) || isAsmBranchMnemonic(baseOp) {
					operands := splitAsmOperands(rest)
					if len(operands) == 0 {
						return false
					}
					target := strings.TrimSpace(operands[len(operands)-1])
					branches = append(branches, r14Branch{from: n, target: target})
					if !hasDot && (uop == "JMP" || uop == "B") {
						chFrontier = nil
					} else {
						chFrontier = []int{n}
					}
					continue
				}
				chFrontier = []int{n}
			}
			nextFrontier = appendUniqueR14Nodes(nextFrontier, chFrontier...)
		}
		frontier = nextFrontier
	}
	if len(condStack) != 0 {
		return false
	}

	for _, br := range branches {
		if strings.HasSuffix(br.target, "(PC)") {
			for idx := range nodes {
				if idx != br.from && !slices.Contains(nodes[br.from].succs, idx) {
					nodes[br.from].succs = append(nodes[br.from].succs, idx)
				}
			}
			continue
		}
		targets := labelNodes[br.target]
		if len(targets) == 0 {
			return false
		}
		for _, t := range targets {
			if !slices.Contains(nodes[br.from].succs, t) {
				nodes[br.from].succs = append(nodes[br.from].succs, t)
			}
		}
	}

	liveIn := make([]bool, len(nodes))
	liveIn[entry] = true
	worklist := []int{entry}
	for len(worklist) > 0 {
		u := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		if nodes[u].stmt != "" && stmtMentionsAMD64R14(nodes[u].stmt) {
			if !stmtUnconditionallyKillsAMD64R14(nodes[u].stmt) {
				return false
			}
			continue
		}
		for _, v := range nodes[u].succs {
			if !liveIn[v] {
				liveIn[v] = true
				worklist = append(worklist, v)
			}
		}
	}
	return true
}
