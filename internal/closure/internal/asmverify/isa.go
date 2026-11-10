package asmverify

import (
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/closure/internal/cprep"
)

func parseOneOrTwoAsciiDigits(s string) (int, bool) {
	switch len(s) {
	case 1:
		if s[0] < '0' || s[0] > '9' {
			return 0, false
		}
		return int(s[0] - '0'), true
	case 2:
		if s[0] < '0' || s[0] > '9' || s[1] < '0' || s[1] > '9' {
			return 0, false
		}
		return int(s[0]-'0')*10 + int(s[1]-'0'), true
	default:
		return 0, false
	}
}

func isForbiddenX86ControlOrDebugReg(u string) bool {
	for _, pfx := range []string{"CR", "DR", "TR"} {
		if rest, ok := strings.CutPrefix(u, pfx); ok {
			if n, ok := parseOneOrTwoAsciiDigits(rest); ok && ((pfx != "TR" && n <= 15) || (pfx == "TR" && n <= 7)) {
				return true
			}
		}
	}
	return false
}

func isARM64TLSSysReg(u string) bool {
	return strings.HasPrefix(u, "TPIDR") || strings.HasPrefix(u, "SCXTNUM")
}

func hasARM64ELRegSuffix(u string) bool {
	return strings.Contains(u, "_EL0") || strings.Contains(u, "_EL1") ||
		strings.Contains(u, "_EL2") || strings.Contains(u, "_EL3")
}

// isARM64SystemOrPStateReg reports whether u (uppercased) names an ARM64
// system register or PSTATE field recognized by cmd/asm (including all
// arm64.SystemReg entries in cmd/internal/obj/arm64/sysRegEnc.go and PSTATE
// special operands). On arm64, cmd/asm accepts MOVD <SysReg>, Rd and
// MOVD Rs/$imm, <SysReg> as aliases for MRS and MSR.
func isARM64SystemOrPStateReg(u string) bool {
	if hasARM64ELRegSuffix(u) {
		return true
	}
	switch u {
	case "CURRENTEL", "DAIF", "DAIFSET", "DAIFCLR", "DIT", "FPCR", "FPSR",
		"NZCV", "PAN", "RNDR", "RNDRRS", "SPSEL",
		"SPSR_ABT", "SPSR_FIQ", "SPSR_IRQ", "SPSR_UND",
		"SSBS", "TCO", "UAO",
		"ALLINT", "SVCR", "SVCRSM", "SVCRZA", "SVCRSMZA":
		return true
	}
	return false
}

func hasImpureAsmMnemonicPrefix(u string) bool {
	return strings.HasPrefix(u, "RDRAND") ||
		strings.HasPrefix(u, "RDSEED") ||
		strings.HasPrefix(u, "RDFSBASE") ||
		strings.HasPrefix(u, "RDGSBASE") ||
		strings.HasPrefix(u, "WRFSBASE") ||
		strings.HasPrefix(u, "WRGSBASE") ||
		strings.HasPrefix(u, "FXRSTOR") ||
		strings.HasPrefix(u, "XRSTOR") ||
		strings.HasPrefix(u, "POPF") ||
		strings.HasPrefix(u, "PUSHF")
}

func isForbiddenCallOrJumpMnemonic(u string) bool {
	switch u {
	case "BL", "BLR", "BLRAA", "BLRAAZ", "BLRAB", "BLRABZ",
		"JAL", "JALR", "CALLF", "BSR", "BCTRL", "BLRL",
		"BR", "BRAA", "BRAAZ", "BRAB", "BRABZ", "JMPF",
		"ADR", "ADRP":
		return true
	}
	return false
}

func isCommonImpureOrSystemAsmMnemonic(u string) bool {
	switch u {
	case "GETCALLERPC", "UNDEF",
		"SYSCALL", "SYSENTER", "SYSENTER64", "SYSEXIT", "SYSEXIT64", "SYSRET", "SYSRET64",
		"SVC", "ECALL", "SCALL", "SWI", "INT", "INT1", "INT3", "INTO", "ICEBP", "TA",
		"RDTSC", "RDTSCP", "RDPMC", "RDTIME", "RDCYCLE", "RDINSTRET",
		"MSR", "LDMXCSR", "VLDMXCSR", "FLDCW", "FLDENV", "FRSTOR", "FINIT", "FNINIT", "XSETBV", "STD",
		"WRPKRU", "RDPKRU", "WRMSR", "RDMSR", "RDPID",
		"SGDT", "SIDT", "LGDT", "LIDT", "LLDT", "LTR", "LMSW", "CLTS", "INVD", "WBINVD", "INVLPG", "INVPCID", "SWAPGS",
		"XBEGIN", "XEND", "XABORT", "XTEST",
		"TPAUSE", "UMWAIT", "MWAIT", "MONITOR", "MWAITX", "MONITORX",
		"UD0", "UD1", "UD2", "BRK", "HVC", "SMC", "HLT",
		"INB", "INW", "INL", "OUTB", "OUTW", "OUTL",
		"INSB", "INSW", "INSL", "OUTSB", "OUTSW", "OUTSL":
		return true
	}
	return false
}

func isARM64ImpureAsmMnemonic(u string) bool {
	switch u {
	case "SYS", "SYSL", "DC", "IC", "AT", "TLBI", "HINT", "SEV", "SEVL",
		"DCPS1", "DCPS2", "DCPS3", "DRPS", "ERET", "WFI", "WFE":
		return true
	}
	return false
}

func isAMD64SegmentLoadMnemonic(u string) bool {
	switch u {
	case "LFS", "LFSW", "LFSL", "LFSQ", "LGS", "LGSW", "LGSL", "LGSQ",
		"LSS", "LSSW", "LSSL", "LSSQ", "LDS", "LDSW", "LDSL", "LDSQ", "LES", "LESW", "LESL", "LESQ":
		return true
	}
	return false
}

func isForbiddenAsmRegisterName(u string) bool {
	switch u {
	case "R28", "R18", "R18_PLATFORM", "IP", "MAXREG",
		"FS", "GS", "CS", "SS", "DS", "ES",
		"GDTR", "IDTR", "LDTR", "MSW", "TASK":
		return true
	}
	return isForbiddenX86ControlOrDebugReg(u) || isARM64TLSSysReg(u)
}

func isReservedNonStdAsmMacroName(name string) bool {
	if name == "g" || name == "init" {
		return true
	}
	u := strings.ToUpper(name)
	if isForbiddenAsmRegisterName(u) || isARM64SystemOrPStateReg(u) ||
		hasImpureAsmMnemonicPrefix(u) || isCommonImpureOrSystemAsmMnemonic(u) ||
		isARM64ImpureAsmMnemonic(u) || isAMD64SegmentLoadMnemonic(u) || isForbiddenCallOrJumpMnemonic(u) {
		return true
	}
	switch u {
	case "TEXT", "GLOBL", "DATA", "FUNCDATA", "PCDATA", "PCALIGN", "PCALIGNMAX",
		"DUFFCOPY", "DUFFZERO", "END", "XXX",
		"BYTE", "WORD", "DWORD", "LONG", "QUAD",
		"CALL", "JMP",
		"RET", "RETF", "RETFW", "RETFL", "RETFQ", "RETAA", "RETAB",
		"CPUID", "MRS",
		"SPR", "SREG",
		"RODATA", "NOPTR", "DUPOK", "NOPROF", "TLSBSS", "NOSPLIT",
		"SB", "FP", "SP", "PC", "TLS":
		return true
	}
	return false
}

func verifyParsedNonStdAsmFile(goarch, pkgPath string, parsed *parsedNonStdAsmFile, pkgRodataSyms map[string]bool, funcs map[string]TextSummary) bool {
	if parsed == nil || (goarch != "amd64" && goarch != "arm64") {
		return false
	}
	rodataSyms := make(map[string]bool, len(pkgRodataSyms)+len(parsed.fileRodataSyms))
	for k := range pkgRodataSyms {
		rodataSyms[k] = true
	}
	for k := range parsed.fileRodataSyms {
		rodataSyms[k] = true
	}

	// Validate all top-level DATA directives collected in Pass 1 against rodataSyms.
	for _, dataRest := range parsed.dataDirectives {
		if !validateAsmDataDirective(pkgPath, dataRest, rodataSyms) {
			return false
		}
	}

	// Pass 2: verify every TEXT block's control flow, (SB) references, and instructions.
	for _, blk := range parsed.blocks {
		if rodataSyms["·"+blk.name] || rodataSyms[blk.name] {
			return false
		}
		if goarch == "amd64" && !verifyAMD64EntryR14NotRead(blk) {
			return false
		}
		sum := funcs[blk.name]
		sawCPUID := false
		var pendingBytes []byte
		lastByteEpoch := -1
		flushBytes := func() {
			if len(pendingBytes) == 0 {
				return
			}
			if !(goarch == "amd64" && len(pendingBytes) == 3 && pendingBytes[0] == 0x0f && pendingBytes[1] == 0x01 && pendingBytes[2] == 0xd0) {
				if sum.ImpureKind == "" {
					sum.ImpureKind = "unverified raw opcode in assembly"
				}
			}
			pendingBytes = pendingBytes[:0]
			lastByteEpoch = -1
		}
		for _, line := range blk.lines {
			if line.condOp != asmCondNone {
				flushBytes()
				continue
			}
			if len(pendingBytes) > 0 && line.condEpoch != lastByteEpoch {
				flushBytes()
			}
			for _, expanded := range line.choices {
				for _, stmt := range splitAsmStatements(expanded) {
					stmt = strings.TrimSpace(stmt)
					if stmt == "" {
						continue
					}
					for {
						_, rest, ok := cutAsmLabel(stmt)
						if !ok {
							break
						}
						flushBytes()
						stmt = strings.TrimSpace(rest)
					}
					if stmt == "" {
						continue
					}
					op, rest := splitAsmOp(stmt)
					uop := strings.ToUpper(op)
					if uop == "TEXT" {
						flushBytes()
						continue
					}
					if uop == "BYTE" {
						if goarch != "amd64" || line.condDepth != blk.openCondDepth || len(line.choices) != 1 {
							flushBytes()
							if sum.ImpureKind == "" {
								sum.ImpureKind = "unverified raw opcode in assembly"
							}
							continue
						}
						b, ok := parseAsmImmByte(rest)
						if !ok {
							if sum.ImpureKind == "" {
								sum.ImpureKind = "unverified raw opcode in assembly"
							}
							pendingBytes = pendingBytes[:0]
							lastByteEpoch = -1
						} else {
							pendingBytes = append(pendingBytes, b)
							lastByteEpoch = line.condEpoch
						}
						continue
					}
					flushBytes()
					ok, cpuid, impure := verifyAsmTextInstruction(goarch, pkgPath, uop, rest, blk.labels, rodataSyms)
					if !ok {
						return false
					}
					if cpuid {
						sawCPUID = true
					}
					if impure != "" && sum.ImpureKind == "" {
						sum.ImpureKind = impure
					}
				}
			}
		}
		flushBytes()
		if sum.ImpureKind != "" {
			sum.CPUIDArgs = 0
		} else if sawCPUID {
			argCount, okCanonical := verifyCanonicalCPUIDTextBlock(blk)
			if !okCanonical || (sum.CPUIDArgs != 0 && sum.CPUIDArgs != argCount) {
				sum.CPUIDArgs = 0
				sum.ImpureKind = "per-core CPUID register"
			} else {
				sum.CPUIDArgs = argCount
			}
		}
		funcs[blk.name] = sum
	}
	return true
}

func isValidAsmMnemonic(uop string) bool {
	if uop == "" || uop[0] < 'A' || uop[0] > 'Z' {
		return false
	}
	for i := 1; i < len(uop); i++ {
		c := uop[i]
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func isFrameSlotIdentBeforePlusFP(s string, start, end int) bool {
	if start > 0 && s[start-1] != ' ' && s[start-1] != '\t' && s[start-1] != ',' && s[start-1] != '$' {
		return false
	}
	if end >= len(s) || s[end] != '+' {
		return false
	}
	p := end + 1
	digits := 0
	for p < len(s) && s[p] >= '0' && s[p] <= '9' {
		p++
		digits++
	}
	return digits > 0 && strings.HasPrefix(s[p:], "(FP)")
}

type asmTokenFlags uint8

const (
	asmTokUnquotedColon asmTokenFlags = 1 << iota
	asmTokForbidden
	asmTokPC
	asmTokARM64SysReg
	asmTokAMD64R14
)

func isAsciiLowerIdent(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return false
		}
	}
	return true
}

func scanAsmTokens(s string) asmTokenFlags {
	var flags asmTokenFlags
	for i := 0; i < len(s); {
		if s[i] == '"' || s[i] == '\'' {
			next, closed := cprep.SkipQuotedLiteralChecked(s, i)
			if !closed {
				return asmTokUnquotedColon | asmTokForbidden | asmTokPC | asmTokARM64SysReg | asmTokAMD64R14
			}
			i = next
			continue
		}
		if s[i] == ':' {
			flags |= asmTokUnquotedColon
			i++
			continue
		}
		end, okIdent := cprep.ScanIdentToken(s, i, true)
		if okIdent && end > i {
			start := i
			i = end
			tok := s[start:end]
			u := strings.ToUpper(tok)
			isLowerFrameSlot := isAsciiLowerIdent(tok) && isFrameSlotIdentBeforePlusFP(s, start, end)
			if u == "PC" && !(tok == "pc" && isLowerFrameSlot) {
				flags |= asmTokPC
			}
			if !strings.ContainsRune(tok, '·') && !isLowerFrameSlot && isARM64SystemOrPStateReg(u) {
				flags |= asmTokARM64SysReg
			}
			if isAMD64R14AliasUpper(u) && !isLowerFrameSlot {
				flags |= asmTokAMD64R14
			}
			if u == "TLS" {
				flags |= asmTokForbidden
				continue
			}
			if u == "SB" {
				if tok != "SB" || start < 2 || s[start-1] != '(' || s[start-2] == ' ' || s[start-2] == '\t' || end >= len(s) || s[end] != ')' {
					flags |= asmTokForbidden
				}
				continue
			}
			switch u {
			case "R", "F", "V", "Z", "P", "M", "SPR", "SREG", "PN":
				p := end
				for p < len(s) && (s[p] == ' ' || s[p] == '\t') {
					p++
				}
				if p < len(s) && s[p] == '(' {
					flags |= asmTokForbidden
				}
			}
			if tok == "g" && !isLowerFrameSlot {
				flags |= asmTokForbidden
			}
			if !isLowerFrameSlot && isForbiddenAsmRegisterName(u) {
				flags |= asmTokForbidden
			}
			continue
		}
		i++
	}
	return flags
}

// HasUnquotedColon reports whether s contains any ':' character outside single
// or double quotes. In Plan 9 cmd/asm (parse.go:operand), an unquoted 'X:Y'
// operand pair at nesting depth 0 splits into two reversed operands '[Y, X]'
// (e.g. 'MOVD R0:CNTVCT_EL0' assembles as 'MOVD CNTVCT_EL0, R0').
func HasUnquotedColon(s string) bool {
	for i := 0; i < len(s); {
		if s[i] == '"' || s[i] == '\'' {
			next, closed := cprep.SkipQuotedLiteralChecked(s, i)
			if !closed {
				return true
			}
			i = next
			continue
		}
		if s[i] == ':' {
			return true
		}
		i++
	}
	return false
}

// hasAsmPCToken reports whether s contains the PC pseudo-register token
// (excluding a lowercase stack-slot label `pc+<digits>(FP)` or middle-dot
// RODATA symbol `·pc(SB)`).
func hasAsmPCToken(s string) bool {
	return (scanAsmTokens(s) & asmTokPC) != 0
}

// stmtContainsARM64SysReg reports whether s references any ARM64 system
// register or PSTATE field token (excluding lowercase `<ident>+<digits>(FP)`
// frame-slot labels and middle-dot `(SB)` symbols).
func stmtContainsARM64SysReg(s string) bool {
	return (scanAsmTokens(s) & asmTokARM64SysReg) != 0
}

func isCleanARM64SysRegDestGPR(opnd string) bool {
	s := strings.TrimSpace(opnd)
	if s == "LR" {
		return true
	}
	if len(s) < 2 || len(s) > 3 || s[0] != 'R' || (len(s) == 3 && s[1] == '0') {
		return false
	}
	n, ok := parseOneOrTwoAsciiDigits(s[1:])
	return ok && n >= 0 && n <= 30 && n != 18 && n != 28
}

// hasForbiddenAsmToken rejects TLS references, non-canonical SB spellings,
// parameterized register forms, x86 segment/control/debug/descriptor registers,
// ARM64 platform/goroutine registers, IP, and bare g.
func hasForbiddenAsmToken(s string) bool {
	return (scanAsmTokens(s) & asmTokForbidden) != 0
}

func isImpureOrSystemAsmMnemonic(goarch, baseOp string) bool {
	if hasImpureAsmMnemonicPrefix(baseOp) || isCommonImpureOrSystemAsmMnemonic(baseOp) {
		return true
	}
	if goarch == "amd64" {
		if strings.HasPrefix(baseOp, "SMSW") ||
			strings.HasPrefix(baseOp, "SLDT") ||
			strings.HasPrefix(baseOp, "LAR") ||
			strings.HasPrefix(baseOp, "LSL") ||
			isAMD64SegmentLoadMnemonic(baseOp) {
			return true
		}
		switch baseOp {
		case "STR", "STRW", "STRL", "STRQ", "VERR", "VERW":
			return true
		}
	}
	if goarch == "arm64" && isARM64ImpureAsmMnemonic(baseOp) {
		return true
	}
	return false
}

func verifyAsmTextInstruction(goarch, pkgPath, uop, rest string, localLabels, rodataSyms map[string]bool) (ok bool, cpuid bool, impure string) {
	if (goarch != "amd64" && goarch != "arm64") || !isValidAsmMnemonic(uop) || hasForbiddenAsmToken(uop) {
		return false, false, ""
	}
	restFlags := scanAsmTokens(rest)
	if (restFlags & (asmTokUnquotedColon | asmTokForbidden)) != 0 {
		return false, false, ""
	}
	unquotedRest := stripAsmQuotedLiterals(rest)
	if strings.Contains(unquotedRest, "(TLS)") || strings.Contains(uop, "(TLS)") {
		return false, false, ""
	}
	baseOp, _, hasDot := strings.Cut(uop, ".")
	if baseOp == "" || baseOp == "TEXT" || baseOp == "GLOBL" || baseOp == "DATA" ||
		baseOp == "DUFFCOPY" || baseOp == "DUFFZERO" || baseOp == "END" || baseOp == "XXX" {
		return false, false, ""
	}
	if hasDot {
		switch baseOp {
		case "BYTE", "WORD", "DWORD", "LONG", "QUAD",
			"RET", "CPUID", "MRS", "FUNCDATA", "PCDATA", "PCALIGN", "PCALIGNMAX":
			return false, false, ""
		}
	}
	if strings.HasPrefix(baseOp, "RET") {
		if uop != "RET" || rest != "" {
			return false, false, ""
		}
		return true, false, ""
	}
	if strings.HasPrefix(baseOp, "CALL") || strings.HasPrefix(baseOp, "IRET") || isForbiddenCallOrJumpMnemonic(baseOp) {
		return false, false, ""
	}

	operands := splitAsmOperands(rest)

	if isAsmBranchMnemonic(uop) || isAsmBranchMnemonic(baseOp) {
		if len(operands) == 0 {
			return false, false, ""
		}
		if (restFlags & asmTokPC) != 0 {
			for _, nonTarget := range operands[:len(operands)-1] {
				if hasAsmPCToken(nonTarget) {
					return false, false, ""
				}
			}
		}
		target := strings.TrimSpace(operands[len(operands)-1])
		if !isLocalAsmBranchTarget(goarch, target, localLabels) {
			return false, false, ""
		}
	} else if (restFlags & asmTokPC) != 0 {
		return false, false, ""
	}

	for idx, opnd := range operands {
		unquotedOpnd := stripAsmQuotedLiterals(opnd)
		if strings.Contains(unquotedOpnd, "(SB)") {
			if strings.ContainsAny(opnd, `"'`) || isAsmReadModifyWriteMnemonic(baseOp) {
				return false, false, ""
			}
			if len(operands) == 1 && !strings.HasPrefix(baseOp, "PUSH") && !strings.HasPrefix(baseOp, "PREFETCH") {
				return false, false, ""
			}
			if len(operands) >= 2 && idx == len(operands)-1 && !isAsmReadOnlyCompareMnemonic(baseOp) {
				return false, false, ""
			}
			sbIdx := strings.Index(unquotedOpnd, "(SB)")
			if sbIdx <= 0 {
				return false, false, ""
			}
			tail := strings.TrimSpace(unquotedOpnd[sbIdx+4:])
			if tail != "" {
				if !strings.HasPrefix(tail, "(") || !strings.HasSuffix(tail, ")") || strings.Contains(tail, "(SB)") || strings.ContainsRune(tail, '·') {
					return false, false, ""
				}
			}
			normSym, _, _, symOK := parseAsmLocalSBRef(pkgPath, unquotedOpnd[:sbIdx])
			if !symOK || !rodataSyms[normSym] {
				return false, false, ""
			}
		} else if strings.ContainsRune(unquotedOpnd, '·') {
			return false, false, ""
		}
	}

	if uop == "CPUID" {
		if goarch != "amd64" || rest != "" {
			return false, false, ""
		}
		return true, true, ""
	}
	if uop == "MRS" {
		if goarch != "arm64" {
			return false, false, ""
		}
		if len(operands) == 2 && isAuditedARM64IDRegName(operands[0]) && isCleanARM64SysRegDestGPR(operands[1]) {
			return true, false, ""
		}
		return true, false, "hardware counter, entropy, or system assembly instruction"
	}
	if uop == "WORD" {
		if goarch != "arm64" {
			return true, false, "unverified raw opcode in assembly"
		}
		w, wordOK := parseAsmImmUint32(rest)
		if !wordOK || !isAuditedARM64WordOpcode(w) {
			return true, false, "unverified raw opcode in assembly"
		}
		return true, false, ""
	}
	if baseOp == "DWORD" || baseOp == "LONG" || baseOp == "QUAD" {
		return true, false, "unverified raw opcode in assembly"
	}
	if isImpureOrSystemAsmMnemonic(goarch, baseOp) {
		return true, false, "hardware counter, entropy, or system assembly instruction"
	}
	if (restFlags & asmTokARM64SysReg) != 0 {
		if goarch == "arm64" && uop == "MOVD" && len(operands) == 2 &&
			isAuditedARM64IDRegName(operands[0]) && isCleanARM64SysRegDestGPR(operands[1]) {
			return true, false, ""
		}
		return true, false, "hardware counter, entropy, or system assembly instruction"
	}
	return true, false, ""
}

func isAsmReadOnlyCompareMnemonic(uop string) bool {
	return strings.HasPrefix(uop, "CMP") && !strings.HasPrefix(uop, "CMPXCHG") ||
		strings.HasPrefix(uop, "TEST") || strings.HasPrefix(uop, "UCOMI") || strings.HasPrefix(uop, "VCOMI")
}

func isAsmReadModifyWriteMnemonic(uop string) bool {
	return uop == "LOCK" ||
		strings.HasPrefix(uop, "XCHG") ||
		strings.HasPrefix(uop, "XADD") ||
		strings.HasPrefix(uop, "CMPXCHG") ||
		strings.HasPrefix(uop, "BTS") ||
		strings.HasPrefix(uop, "BTR") ||
		strings.HasPrefix(uop, "BTC") ||
		strings.HasPrefix(uop, "VSCATTER") ||
		strings.HasPrefix(uop, "VPSCATTER") ||
		strings.HasPrefix(uop, "STXR") ||
		strings.HasPrefix(uop, "STLXR") ||
		strings.HasPrefix(uop, "STXP") ||
		strings.HasPrefix(uop, "STLXP") ||
		strings.HasPrefix(uop, "CAS") ||
		strings.HasPrefix(uop, "SWP") ||
		strings.HasPrefix(uop, "LDADD") ||
		strings.HasPrefix(uop, "LDCLR") ||
		strings.HasPrefix(uop, "LDEOR") ||
		strings.HasPrefix(uop, "LDOR") ||
		strings.HasPrefix(uop, "LDSET") ||
		strings.HasPrefix(uop, "LDSMAX") ||
		strings.HasPrefix(uop, "LDSMIN") ||
		strings.HasPrefix(uop, "LDUMAX") ||
		strings.HasPrefix(uop, "LDUMIN") ||
		strings.HasPrefix(uop, "STADD") ||
		strings.HasPrefix(uop, "STCLR") ||
		strings.HasPrefix(uop, "STEOR") ||
		strings.HasPrefix(uop, "STOR") ||
		strings.HasPrefix(uop, "STSET") ||
		strings.HasPrefix(uop, "STSMAX") ||
		strings.HasPrefix(uop, "STSMIN") ||
		strings.HasPrefix(uop, "STUMAX") ||
		strings.HasPrefix(uop, "STUMIN")
}

func isAsmBranchMnemonic(uop string) bool {
	if uop == "B" || strings.HasPrefix(uop, "B.") {
		return true
	}
	switch uop {
	case "JMP", "JA", "JAE", "JB", "JBE", "JC", "JCC", "JCS", "JE", "JEQ", "JG", "JGE", "JGT",
		"JHI", "JHS", "JL", "JLE", "JLO", "JLS", "JLT", "JMI",
		"JNA", "JNAE", "JNB", "JNBE", "JNC", "JNE", "JNG", "JNGE", "JNL", "JNLE",
		"JNO", "JNP", "JNS", "JNZ", "JO", "JOC", "JOS", "JP", "JPC", "JPE", "JPL", "JPO", "JPS", "JS", "JZ",
		"JCXZ", "JCXZW", "JCXZL", "JCXZQ", "JECXZ", "JRCXZ",
		"LOOP", "LOOPE", "LOOPEQ", "LOOPNE", "LOOPNZ", "LOOPZ",
		"BEQ", "BNE", "BCS", "BHS", "BCC", "BLO", "BMI", "BPL", "BVS", "BVC",
		"BHI", "BLS", "BGE", "BLT", "BGT", "BLE",
		"CBZ", "CBZW", "CBNZ", "CBNZW", "TBZ", "TBZW", "TBNZ", "TBNZW":
		return true
	}
	return false
}

func isArchRegisterIdent(goarch, s string) bool {
	switch s {
	case "FP", "SP", "SB", "PC", "TLS", "g", "IP", "MAXREG":
		return true
	}
	if goarch == "amd64" {
		switch s {
		case "AX", "BX", "CX", "DX", "SI", "DI", "BP",
			"AL", "AH", "BL", "BH", "CL", "CH", "DL", "DH",
			"SIL", "DIL", "BPL", "SPL", "SPB", "BPB", "SIB", "DIB":
			return true
		}
		if len(s) >= 2 && (s[0] == 'R' || s[0] == 'X' || s[0] == 'Y' || s[0] == 'Z' || s[0] == 'K' || s[0] == 'M' || s[0] == 'F') {
			tail := s[1:]
			if s[0] == 'R' {
				if last := tail[len(tail)-1]; last == 'B' || last == 'W' || last == 'D' || last == 'L' {
					tail = tail[:len(tail)-1]
				}
			}
			if _, ok := parseOneOrTwoAsciiDigits(tail); ok {
				return true
			}
		}
	}
	if goarch == "arm64" {
		switch s {
		case "ZR", "LR", "RSP":
			return true
		}
		u := strings.ToUpper(s)
		if isARM64TLSSysReg(u) || isARM64SystemOrPStateReg(u) {
			return true
		}
		if strings.HasPrefix(s, "PN") {
			if _, ok := parseOneOrTwoAsciiDigits(s[2:]); ok {
				return true
			}
		}
		if len(s) >= 2 && (s[0] == 'R' || s[0] == 'F' || s[0] == 'V' || s[0] == 'Z' || s[0] == 'P') {
			if _, ok := parseOneOrTwoAsciiDigits(s[1:]); ok {
				return true
			}
		}
	}
	return false
}

func isLocalAsmBranchTarget(goarch, target string, localLabels map[string]bool) bool {
	if target == "" || strings.Contains(target, "(SB)") || strings.ContainsAny(target, "[]") {
		return false
	}
	if isArchRegisterIdent(goarch, target) {
		return false
	}
	if localLabels[target] {
		return true
	}
	if strings.HasSuffix(target, "(PC)") {
		off := strings.TrimSpace(strings.TrimSuffix(target, "(PC)"))
		_, err := strconv.ParseInt(off, 0, 64)
		return err == nil
	}
	return false
}

func parseAsmImmByte(rest string) (byte, bool) {
	s := strings.TrimSpace(rest)
	if !strings.HasPrefix(s, "$") {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(s[1:]), 0, 8)
	if err != nil {
		return 0, false
	}
	return byte(v), true
}

func parseAsmImmUint32(rest string) (uint32, bool) {
	s := strings.TrimSpace(rest)
	if !strings.HasPrefix(s, "$") {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(s[1:]), 0, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

func isAuditedARM64IDRegName(opnd string) bool {
	u := strings.ToUpper(strings.TrimSpace(opnd))
	if u == "MIDR_EL1" || u == "REVIDR_EL1" {
		return true
	}
	return strings.HasPrefix(u, "ID_AA64") && strings.HasSuffix(u, "_EL1")
}

func isAuditedARM64WordOpcode(w uint32) bool {
	// Reject writes targeting R18 (platform register), R28 (g), or SP/XZR (31).
	rd := w & 0x1f
	if rd == 18 || rd == 28 || rd == 31 {
		return false
	}
	// MOVZ Wd/Xd, #imm16, LSL #(hw*16)
	if (w & 0x7f800000) == 0x52800000 {
		return true
	}
	// UBFM / LSL / LSR Wd/Xd, Wn/Xn, #immr, #imms
	if (w & 0x7f800000) == 0x53000000 {
		rn := (w >> 5) & 0x1f
		return rn != 18 && rn != 28 && rn != 31
	}
	// SVE ADDVL / ADDPL Xd, Xn, #imm6
	if (w & 0xffa0f800) == 0x04205000 {
		rn := (w >> 5) & 0x1f
		return rn != 18 && rn != 28 && rn != 31
	}
	// MRS Xt, <sysreg>: 1101_0101_0011_op1_CRn_CRm_op2_Rt
	if (w & 0xfff00000) == 0xd5300000 {
		op0 := ((w >> 19) & 1) + 2
		op1 := (w >> 16) & 7
		crn := (w >> 12) & 0xf
		crm := (w >> 8) & 0xf
		op2 := (w >> 5) & 7
		if op0 != 3 || op1 != 0 || crn != 0 {
			return false
		}
		if crm == 0 {
			// MIDR_EL1 (op2=0) and REVIDR_EL1 (op2=6) are static chip IDs;
			// MPIDR_EL1 (op2=5) is per-core affinity and MUST be rejected.
			return op2 == 0 || op2 == 6
		}
		// ID_AA64PFR*, ID_AA64DFR*, ID_AA64AFR*, ID_AA64ISAR*, ID_AA64MMFR*, ID_AA64ZFR*, ID_AA64SMFR*
		return crm >= 1 && crm <= 7
	}
	return false
}
