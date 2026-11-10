package asmverify

import (
	"go/types"
	"strconv"
	"strings"
	"unicode"

	"github.com/greatliontech/gofresh/internal/closure/internal/cprep"
)

type asmCondKind uint8

const (
	asmCondNone asmCondKind = iota
	asmCondIf
	asmCondElif
	asmCondElse
	asmCondEndif
)

type asmLogicalLine struct {
	choices   []string
	condDepth int
	condEpoch int
	condOp    asmCondKind
}

type asmTextBlock struct {
	name          string
	openCondDepth int
	labels        map[string]bool
	lines         []asmLogicalLine
}

type parsedNonStdAsmFile struct {
	lines          []asmLogicalLine
	dataDirectives []string
	fileRodataSyms map[string]bool
	rodataGoNames  []string
	blocks         []asmTextBlock
}

func parseSingleNonStdAsmFile(pkgPath, folded string, localHeaders map[string]string, typeScopes []*types.Package, pkgRodataSyms map[string]bool) (*parsedNonStdAsmFile, bool) {
	activeDefs := map[string][]cprep.MacroDef{}
	includeStack := map[string]bool{}
	condDepth := 0
	condEpoch := 0
	var logicalLines []asmLogicalLine

	emitLogicalLine := func(line string) bool {
		if len(activeDefs) == 0 {
			logicalLines = append(logicalLines, asmLogicalLine{
				choices:   []string{line},
				condDepth: condDepth,
				condEpoch: condEpoch,
			})
			return true
		}
		budget := &cprep.ExpandBudget{StatesLeft: cprep.MaxCPPExpandedStatesPerLine}
		_, terminals := cprep.ExpandAsmCPPStatesWithBudget(line, activeDefs, "", "", 0, budget)
		if budget.Overflow || len(terminals) == 0 {
			return false
		}
		logicalLines = append(logicalLines, asmLogicalLine{
			choices:   terminals,
			condDepth: condDepth,
			condEpoch: condEpoch,
		})
		return true
	}

	var walkUnit func(unitFolded string) bool
	walkUnit = func(unitFolded string) bool {
		rawLines := strings.Split(unitFolded, "\n")
		var pending string
		flushPending := func() bool {
			if pending == "" {
				return true
			}
			line := pending
			pending = ""
			return emitLogicalLine(line)
		}
		for idx := 0; idx < len(rawLines); idx++ {
			line := strings.TrimSpace(rawLines[idx])
			if line == "" {
				continue
			}
			if len(line) > cprep.MaxNonGoLogicalLineBytes {
				return false
			}
			if strings.HasPrefix(line, "#") {
				if !flushPending() {
					return false
				}
				kw, rest, _ := cprep.CutDirectiveKeyword(line)
				switch kw {
				case "if", "ifdef", "ifndef":
					condDepth++
					condEpoch++
					logicalLines = append(logicalLines, asmLogicalLine{condDepth: condDepth, condEpoch: condEpoch, condOp: asmCondIf})
				case "elif":
					if condDepth <= 0 {
						return false
					}
					condEpoch++
					logicalLines = append(logicalLines, asmLogicalLine{condDepth: condDepth, condEpoch: condEpoch, condOp: asmCondElif})
				case "else":
					if condDepth <= 0 {
						return false
					}
					condEpoch++
					logicalLines = append(logicalLines, asmLogicalLine{condDepth: condDepth, condEpoch: condEpoch, condOp: asmCondElse})
				case "endif":
					if condDepth <= 0 {
						return false
					}
					condDepth--
					condEpoch++
					logicalLines = append(logicalLines, asmLogicalLine{condDepth: condDepth, condEpoch: condEpoch, condOp: asmCondEndif})
				case "include":
					hdr, err := strconv.Unquote(strings.TrimSpace(rest))
					if err != nil || hdr == "" {
						return false
					}
					if cprep.AllowedPureAsmStandardHeaders[hdr] {
						continue
					}
					hdrFolded, ok := localHeaders[hdr]
					if !ok || includeStack[hdr] || len(includeStack) >= 16 {
						return false
					}
					includeStack[hdr] = true
					savedDepth := condDepth
					okHdr := walkUnit(hdrFolded)
					delete(includeStack, hdr)
					if !okHdr || condDepth != savedDepth {
						return false
					}
				case "define":
					mName, def, _, ok := cprep.ParseDefineRest(rest)
					if !ok || mName == "" {
						return false
					}
					if condDepth == 0 {
						activeDefs[mName] = []cprep.MacroDef{def}
					} else if len(activeDefs[mName]) == 0 {
						activeDefs[mName] = []cprep.MacroDef{def}
						cprep.EnsureMacroIdentityChoice(activeDefs, mName)
					} else {
						cprep.AppendMacroDefUnique(activeDefs, mName, def)
					}
				case "undef":
					uRest := strings.TrimSpace(rest)
					mName := cprep.LeadingASCIIIdent(uRest)
					if mName == "" || strings.TrimSpace(uRest[len(mName):]) != "" {
						return false
					}
					if condDepth == 0 {
						delete(activeDefs, mName)
					} else if len(activeDefs[mName]) > 0 {
						cprep.EnsureMacroIdentityChoice(activeDefs, mName)
					}
				default:
					return false
				}
				continue
			}
			if pending == "" {
				pending = line
			} else if len(pending)+1+len(line) <= cprep.MaxNonGoLogicalLineBytes {
				pending = pending + " " + line
			} else {
				return false
			}
			if cprep.UnquotedParenBalance(pending) > 0 {
				continue
			}
			if cprep.TrailingFuncMacroIdentMode(pending, activeDefs, true) {
				peek := idx + 1
				for peek < len(rawLines) && strings.TrimSpace(rawLines[peek]) == "" {
					peek++
				}
				if peek < len(rawLines) && strings.HasPrefix(strings.TrimSpace(rawLines[peek]), "(") {
					continue
				}
			}
			if !flushPending() {
				return false
			}
		}
		return flushPending()
	}

	if !walkUnit(folded) || condDepth != 0 {
		return nil, false
	}

	// Pass 1: collect and validate RODATA GLOBL symbols, top-level DATA directives, and per-TEXT local labels.
	fileRodataSyms := map[string]bool{}
	var rodataGoNames []string
	var dataDirectives []string
	var blocks []asmTextBlock
	curBlock := -1

	for _, line := range logicalLines {
		if line.condOp != asmCondNone {
			if curBlock >= 0 {
				openDepth := blocks[curBlock].openCondDepth
				if (line.condOp == asmCondEndif && line.condDepth < openDepth) ||
					((line.condOp == asmCondElif || line.condOp == asmCondElse) && line.condDepth == openDepth) {
					curBlock = -1
				} else {
					blocks[curBlock].lines = append(blocks[curBlock].lines, line)
				}
			}
			continue
		}
		nextBlock := curBlock
		for choiceIdx, expanded := range line.choices {
			choiceCur := curBlock
			stmts := splitAsmStatements(expanded)
			for _, stmt := range stmts {
				stmt = strings.TrimSpace(stmt)
				if stmt == "" {
					continue
				}
				for {
					lbl, rest, ok := cutAsmLabel(stmt)
					if !ok {
						break
					}
					if choiceCur < 0 {
						return nil, false
					}
					blocks[choiceCur].labels[lbl] = true
					stmt = strings.TrimSpace(rest)
				}
				if stmt == "" {
					continue
				}
				op, rest := splitAsmOp(stmt)
				switch strings.ToUpper(op) {
				case "GLOBL":
					if choiceCur >= 0 && line.condDepth > blocks[choiceCur].openCondDepth {
						return nil, false
					}
					choiceCur = -1
					sym, goName, ok := parseAsmGloblRODATA(pkgPath, rest, typeScopes)
					if !ok {
						return nil, false
					}
					if goName != "" {
						rodataGoNames = append(rodataGoNames, goName)
					}
					if strings.HasPrefix(sym, "<>") {
						fileRodataSyms[sym] = true
					} else {
						pkgRodataSyms[sym] = true
					}
				case "DATA":
					if choiceCur >= 0 && line.condDepth > blocks[choiceCur].openCondDepth {
						return nil, false
					}
					choiceCur = -1
					dataDirectives = append(dataDirectives, rest)
				case "TEXT":
					if choiceCur >= 0 && line.condDepth > blocks[choiceCur].openCondDepth {
						return nil, false
					}
					fnName, ok := parseAsmTextHeader(pkgPath, rest)
					if !ok {
						return nil, false
					}
					if choiceIdx == 0 {
						blocks = append(blocks, asmTextBlock{
							name:          fnName,
							openCondDepth: line.condDepth,
							labels:        map[string]bool{},
						})
						choiceCur = len(blocks) - 1
					} else if nextBlock < 0 || blocks[nextBlock].name != fnName {
						return nil, false
					} else {
						choiceCur = nextBlock
					}
				default:
					if choiceCur < 0 {
						uop := strings.ToUpper(op)
						if (uop != "FUNCDATA" && uop != "PCDATA" && uop != "PCALIGN" && uop != "PCALIGNMAX") ||
							(scanAsmTokens(rest)&(asmTokUnquotedColon|asmTokForbidden|asmTokPC)) != 0 {
							return nil, false
						}
					}
				}
			}
			if choiceIdx == 0 {
				nextBlock = choiceCur
			} else if choiceCur != nextBlock {
				return nil, false
			}
		}
		curBlock = nextBlock
		if curBlock >= 0 {
			blocks[curBlock].lines = append(blocks[curBlock].lines, line)
		}
	}

	return &parsedNonStdAsmFile{
		lines:          logicalLines,
		dataDirectives: dataDirectives,
		fileRodataSyms: fileRodataSyms,
		rodataGoNames:  rodataGoNames,
		blocks:         blocks,
	}, true
}

func splitAsmStatements(line string) []string {
	if !strings.ContainsRune(line, ';') {
		return []string{line}
	}
	if !strings.ContainsAny(line, `"'`) {
		return strings.Split(line, ";")
	}
	var out []string
	start := 0
	for i := 0; i < len(line); {
		if line[i] == '"' || line[i] == '\'' {
			i = cprep.SkipQuotedLiteral(line, i)
			continue
		}
		if line[i] == ';' {
			out = append(out, line[start:i])
			start = i + 1
		}
		i++
	}
	out = append(out, line[start:])
	return out
}

func cutAsmLabel(stmt string) (string, string, bool) {
	lbl := cprep.LeadingASCIIIdent(stmt)
	if lbl == "" || len(lbl) >= len(stmt) || stmt[len(lbl)] != ':' {
		return "", "", false
	}
	return lbl, stmt[len(lbl)+1:], true
}

func splitAsmOp(stmt string) (string, string) {
	i := 0
	for i < len(stmt) && stmt[i] != ' ' && stmt[i] != '\t' && stmt[i] != ',' {
		i++
	}
	return stmt[:i], strings.TrimSpace(stmt[i:])
}

const maxConstAsmUintOffset = uint64(0x3fffffff)

// evalConstAsmUintExpr evaluates a pure non-negative constant integer arithmetic
// expression using '+', '*', '|', '<<', '>>', and parentheses without overflow
// above maxConstAsmUintOffset. Identifiers, registers, '-', '/', '^', and
// symbol references are rejected.
func evalConstAsmUintExpr(expr string) (uint64, bool) {
	s := strings.TrimSpace(expr)
	if s == "" {
		return 0, false
	}
	pos := 0
	var parseExpr func() (uint64, bool)
	parseAtom := func() (uint64, bool) {
		for pos < len(s) && (s[pos] == ' ' || s[pos] == '\t') {
			pos++
		}
		if pos >= len(s) {
			return 0, false
		}
		if s[pos] == '(' {
			pos++
			v, ok := parseExpr()
			if !ok {
				return 0, false
			}
			for pos < len(s) && (s[pos] == ' ' || s[pos] == '\t') {
				pos++
			}
			if pos >= len(s) || s[pos] != ')' {
				return 0, false
			}
			pos++
			return v, true
		}
		if s[pos] < '0' || s[pos] > '9' {
			return 0, false
		}
		start := pos
		for pos < len(s) && cprep.IsASCIIIdentByte(s[pos]) {
			pos++
		}
		v, err := strconv.ParseUint(s[start:pos], 0, 64)
		if err != nil || v > maxConstAsmUintOffset {
			return 0, false
		}
		return v, true
	}
	parseExpr = func() (uint64, bool) {
		acc, ok := parseAtom()
		if !ok {
			return 0, false
		}
		for {
			for pos < len(s) && (s[pos] == ' ' || s[pos] == '\t') {
				pos++
			}
			if pos >= len(s) || s[pos] == ')' {
				return acc, true
			}
			op := ""
			switch {
			case strings.HasPrefix(s[pos:], "<<"):
				op = "<<"
				pos += 2
			case strings.HasPrefix(s[pos:], ">>"):
				op = ">>"
				pos += 2
			case s[pos] == '+' || s[pos] == '*' || s[pos] == '|':
				op = s[pos : pos+1]
				pos++
			default:
				return 0, false
			}
			rhs, rok := parseAtom()
			if !rok {
				return 0, false
			}
			switch op {
			case "+":
				if acc+rhs < acc || acc+rhs > maxConstAsmUintOffset {
					return 0, false
				}
				acc += rhs
			case "*":
				if rhs != 0 && acc > maxConstAsmUintOffset/rhs {
					return 0, false
				}
				acc *= rhs
			case "|":
				acc |= rhs
				if acc > maxConstAsmUintOffset {
					return 0, false
				}
			case "<<":
				if rhs >= 30 || (acc<<rhs) > maxConstAsmUintOffset {
					return 0, false
				}
				acc <<= rhs
			case ">>":
				if rhs >= 64 {
					acc = 0
				} else {
					acc >>= rhs
				}
			}
		}
	}
	val, ok := parseExpr()
	if !ok || pos != len(s) || val > maxConstAsmUintOffset {
		return 0, false
	}
	return val, true
}

func isValidAsmGoSymbolIdent(s string) bool {
	if s == "" {
		return false
	}
	for idx, r := range s {
		if r == '_' || unicode.IsLetter(r) || (idx > 0 && unicode.IsDigit(r)) {
			continue
		}
		return false
	}
	return true
}

func parseAsmLocalSBRef(pkgPath, rawSym string) (normSym string, hasOffset bool, goName string, ok bool) {
	rawSym = strings.TrimSpace(rawSym)
	rawSym = strings.TrimSpace(strings.TrimPrefix(rawSym, "$"))
	if rawSym == "" {
		return "", false, "", false
	}
	if pkgPrefix, symAndOff, hasDot := strings.Cut(rawSym, "·"); hasDot {
		if strings.ContainsAny(pkgPrefix, " \t+<>()*") {
			return "", false, "", false
		}
		pkgPrefix = strings.ReplaceAll(pkgPrefix, "∕", "/")
		if pkgPrefix != "" && pkgPrefix != pkgPath {
			return "", false, "", false
		}
		if strings.ContainsRune(symAndOff, '-') {
			return "", false, "", false
		}
		symPart, offExpr, hasPlus := strings.Cut(symAndOff, "+")
		if hasPlus {
			if _, offOK := evalConstAsmUintExpr(offExpr); !offOK {
				return "", false, "", false
			}
		}
		symPart = strings.TrimSpace(symPart)
		baseSym, abiPart, hasABI := strings.Cut(symPart, "<")
		if hasABI && abiPart != "ABI0>" {
			return "", false, "", false
		}
		if !isValidAsmGoSymbolIdent(baseSym) {
			return "", false, "", false
		}
		return "·" + baseSym, hasPlus, baseSym, true
	}
	if strings.ContainsRune(rawSym, '-') {
		return "", false, "", false
	}
	symPart, offExpr, hasPlus := strings.Cut(rawSym, "+")
	if hasPlus {
		if _, offOK := evalConstAsmUintExpr(offExpr); !offOK {
			return "", false, "", false
		}
	}
	symPart = strings.TrimSpace(symPart)
	base, isStatic := strings.CutSuffix(symPart, "<>")
	if !isStatic || !isValidAsmGoSymbolIdent(base) {
		return "", false, "", false
	}
	return "<>" + base, hasPlus, "", true
}

func parseAsmGloblRODATA(pkgPath, rest string, typeScopes []*types.Package) (string, string, bool) {
	if (scanAsmTokens(rest) & (asmTokUnquotedColon | asmTokForbidden | asmTokPC)) != 0 {
		return "", "", false
	}
	operands := splitAsmOperands(rest)
	if len(operands) != 3 {
		return "", "", false
	}
	symOp := strings.TrimSpace(operands[0])
	if strings.HasPrefix(symOp, "$") || !strings.HasSuffix(symOp, "(SB)") {
		return "", "", false
	}
	normSym, hasOffset, goName, ok := parseAsmLocalSBRef(pkgPath, strings.TrimSuffix(symOp, "(SB)"))
	if !ok || hasOffset {
		return "", "", false
	}
	if goName == "init" || strings.HasPrefix(goName, "init·") || strings.HasPrefix(goName, "init.") ||
		strings.ContainsRune(goName, '·') || strings.ContainsAny(goName, "()*") {
		return "", "", false
	}
	if goName != "" {
		for _, tp := range typeScopes {
			if tp == nil || tp.Scope() == nil || tp.Scope().Lookup(goName) != nil {
				return "", "", false
			}
		}
	}
	flagsExpr := strings.TrimSpace(operands[1])
	if !asmFlagsIncludeRODATA(flagsExpr) {
		return "", "", false
	}
	sizeOp := strings.TrimSpace(operands[2])
	if !strings.HasPrefix(sizeOp, "$") || strings.Contains(sizeOp, "(SB)") || strings.Contains(sizeOp, "(TLS)") || strings.ContainsRune(sizeOp, '·') {
		return "", "", false
	}
	sizeVal, sizeOK := evalConstAsmUintExpr(strings.TrimSpace(sizeOp[1:]))
	if !sizeOK || sizeVal == 0 {
		return "", "", false
	}
	return normSym, goName, true
}

func asmFlagsIncludeRODATA(expr string) bool {
	s := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(expr), "$"))
	if s == "" {
		return false
	}
	const allowedBits = uint64(1 | 2 | 8 | 16) // NOPROF | DUPOK | RODATA | NOPTR
	pos := 0
	var parseExpr func() (uint64, bool)
	parseAtom := func() (uint64, bool) {
		for pos < len(s) && (s[pos] == ' ' || s[pos] == '\t') {
			pos++
		}
		if pos >= len(s) {
			return 0, false
		}
		if s[pos] == '$' {
			pos++
			for pos < len(s) && (s[pos] == ' ' || s[pos] == '\t') {
				pos++
			}
		}
		if pos < len(s) && s[pos] == '(' {
			pos++
			v, ok := parseExpr()
			if !ok {
				return 0, false
			}
			for pos < len(s) && (s[pos] == ' ' || s[pos] == '\t') {
				pos++
			}
			if pos >= len(s) || s[pos] != ')' {
				return 0, false
			}
			pos++
			return v, true
		}
		start := pos
		for pos < len(s) && cprep.IsASCIIIdentByte(s[pos]) {
			pos++
		}
		tok := s[start:pos]
		if tok == "" {
			return 0, false
		}
		switch tok {
		case "RODATA":
			return 8, true
		case "NOPTR":
			return 16, true
		case "DUPOK":
			return 2, true
		case "NOPROF":
			return 1, true
		}
		v, err := strconv.ParseUint(tok, 0, 64)
		if err != nil || v&^allowedBits != 0 {
			return 0, false
		}
		return v, true
	}
	parseExpr = func() (uint64, bool) {
		acc, ok := parseAtom()
		if !ok {
			return 0, false
		}
		for {
			for pos < len(s) && (s[pos] == ' ' || s[pos] == '\t') {
				pos++
			}
			if pos >= len(s) || s[pos] == ')' {
				return acc, true
			}
			op := s[pos]
			if op != '|' && op != '+' {
				return 0, false
			}
			pos++
			rhs, rok := parseAtom()
			if !rok {
				return 0, false
			}
			if op == '+' && (acc&rhs) != 0 {
				return 0, false
			}
			acc |= rhs
		}
	}
	mask, ok := parseExpr()
	if !ok || pos != len(s) {
		return false
	}
	return (mask&8) != 0 && (mask&^allowedBits) == 0
}

func validateAsmDataDirective(pkgPath, rest string, rodataSyms map[string]bool) bool {
	if (scanAsmTokens(rest) & (asmTokUnquotedColon | asmTokForbidden | asmTokPC)) != 0 {
		return false
	}
	operands := splitAsmOperands(rest)
	if len(operands) != 2 {
		return false
	}
	lhs := strings.TrimSpace(operands[0])
	rhs := strings.TrimSpace(operands[1])
	slashIdx := strings.LastIndexByte(lhs, '/')
	if slashIdx <= 0 {
		return false
	}
	target := strings.TrimSpace(lhs[:slashIdx])
	widthStr := strings.TrimSpace(lhs[slashIdx+1:])
	width, wErr := strconv.ParseUint(widthStr, 0, 64)
	if wErr != nil || (width != 1 && width != 2 && width != 4 && width != 8) {
		return false
	}
	if strings.HasPrefix(target, "$") || !strings.HasSuffix(target, "(SB)") {
		return false
	}
	normSym, _, _, ok := parseAsmLocalSBRef(pkgPath, strings.TrimSuffix(target, "(SB)"))
	if !ok || !rodataSyms[normSym] {
		return false
	}
	unquotedRHS := stripAsmQuotedLiterals(rhs)
	if !strings.HasPrefix(rhs, "$") || strings.TrimSpace(rhs[1:]) == "" ||
		strings.Contains(unquotedRHS, "(SB)") || strings.Contains(unquotedRHS, "(TLS)") || strings.ContainsRune(unquotedRHS, '·') {
		return false
	}
	return true
}

func stripAsmQuotedLiterals(s string) string {
	if !strings.ContainsAny(s, `"'`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '"' || s[i] == '\'' {
			q := s[i]
			b.WriteByte(q)
			next, closed := cprep.SkipQuotedLiteralChecked(s, i)
			if closed {
				b.WriteByte(q)
			}
			i = next
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func parseAsmTextHeader(pkgPath, rest string) (string, bool) {
	if (scanAsmTokens(rest) & (asmTokUnquotedColon | asmTokForbidden | asmTokPC)) != 0 {
		return "", false
	}
	operands := splitAsmOperands(rest)
	if len(operands) < 2 || len(operands) > 3 {
		return "", false
	}
	symOp := strings.TrimSpace(operands[0])
	if strings.HasPrefix(symOp, "$") || !strings.HasSuffix(symOp, "(SB)") {
		return "", false
	}
	normSym, hasOffset, goName, ok := parseAsmLocalSBRef(pkgPath, strings.TrimSuffix(symOp, "(SB)"))
	if !ok || hasOffset {
		return "", false
	}
	if goName == "init" || strings.HasPrefix(goName, "init·") || strings.HasPrefix(goName, "init.") ||
		strings.ContainsRune(goName, '·') || strings.ContainsAny(goName, "()*") {
		return "", false
	}
	if goName != "" {
		return goName, true
	}
	return normSym, true
}

func splitAsmOperands(rest string) []string {
	if rest == "" {
		return nil
	}
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(rest); {
		if rest[i] == '"' || rest[i] == '\'' {
			i = cprep.SkipQuotedLiteral(rest, i)
			continue
		}
		switch rest[i] {
		case '(', '[':
			depth++
		case ')', ']':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(rest[start:i]))
				start = i + 1
			}
		}
		i++
	}
	out = append(out, strings.TrimSpace(rest[start:]))
	return out
}
