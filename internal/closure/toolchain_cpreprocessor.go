package closure

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

func isASCIIIdentByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

// scanIdentToken scans an identifier starting at s[pos]. When asmIdentMode is
// false, standard C/ASCII identifier rules apply ([A-Za-z_][A-Za-z0-9_]*).
// When asmIdentMode is true, cmd/asm's tokenizer rules apply
// (cmd/asm/internal/lex/tokenizer.go:isIdentRune), treating UTF-8 middle-dot
// '·' (U+00B7), division-slash '∕' (U+2215), and Unicode letters/digits as
// part of a single identifier token so #define Evil Safe never rewrites ·Evil.
func scanIdentToken(s string, pos int, asmIdentMode bool) (int, bool) {
	if pos >= len(s) {
		return pos, false
	}
	if !asmIdentMode {
		if !isASCIIIdentByte(s[pos]) || (s[pos] >= '0' && s[pos] <= '9') {
			return pos, false
		}
		end := pos + 1
		for end < len(s) && isASCIIIdentByte(s[end]) {
			end++
		}
		return end, true
	}
	w, ok := nextAsmIdentRune(s, pos, true)
	if !ok {
		return pos, false
	}
	end := pos + w
	for end < len(s) {
		nw, nok := nextAsmIdentRune(s, end, false)
		if !nok {
			break
		}
		end += nw
	}
	return end, true
}

func nextAsmIdentRune(s string, pos int, first bool) (int, bool) {
	if pos >= len(s) {
		return 0, false
	}
	b := s[pos]
	if b < 0x80 {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_' || (!first && b >= '0' && b <= '9') {
			return 1, true
		}
		return 0, false
	}
	r, width := utf8.DecodeRuneInString(s[pos:])
	if r == utf8.RuneError && width == 1 {
		return 0, false
	}
	if r == '\u00B7' || r == '\u2215' || unicode.IsLetter(r) || (!first && unicode.IsDigit(r)) {
		return width, true
	}
	return 0, false
}

func collectAllASCIIIdents(raw []byte, out map[string]bool) {
	i := 0
	for i < len(raw) {
		if !isASCIIIdentByte(raw[i]) {
			i++
			continue
		}
		start := i
		for i < len(raw) && isASCIIIdentByte(raw[i]) {
			i++
		}
		out[string(raw[start:i])] = true
	}
}

func collectRawBytesRuntimeSymbolRefs(raw []byte, out map[string]bool) {
	for _, prefix := range []string{"runtime.", "runtime\xc2\xb7"} {
		pb := []byte(prefix)
		idx := 0
		for idx < len(raw) {
			pos := strings.Index(string(raw[idx:]), prefix)
			if pos < 0 {
				break
			}
			start := idx + pos + len(pb)
			end := start
			for end < len(raw) && isASCIIIdentByte(raw[end]) {
				end++
			}
			if end > start {
				out["runtime."+string(raw[start:end])] = true
			}
			idx = max(start, idx+pos+1)
		}
	}
}

func collectTextRuntimeSymbolRefs(text string, out map[string]bool) {
	collectRawBytesRuntimeSymbolRefs([]byte(text), out)
}

func extractCgoPreamble(doc *ast.CommentGroup) string {
	if doc == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range doc.List {
		if strings.HasPrefix(c.Text, "//") {
			b.WriteString(c.Text[2:])
			b.WriteByte('\n')
		} else if strings.HasPrefix(c.Text, "/*") && strings.HasSuffix(c.Text, "*/") && len(c.Text) >= 4 {
			b.WriteString(c.Text[2 : len(c.Text)-2])
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func extractFileCgoPreambles(file *ast.File) []string {
	if file == nil {
		return nil
	}
	var out []string
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.IMPORT {
			continue
		}
		for _, spec := range gd.Specs {
			imp, ok := spec.(*ast.ImportSpec)
			if !ok || imp.Path == nil || imp.Path.Value != `"C"` {
				continue
			}
			cg := imp.Doc
			if cg == nil && len(gd.Specs) == 1 {
				cg = gd.Doc
			}
			if cg != nil {
				if p := extractCgoPreamble(cg); p != "" {
					out = append(out, p)
				}
			}
		}
	}
	return out
}

type cppMacroDef struct {
	hasParams     bool
	params        []string
	variadic      bool
	namedVarParam string
	body          string
}

func collectCPPMacrosFromText(cleaned string, defs map[string][]cppMacroDef) {
	for _, rawLine := range strings.Split(cleaned, "\n") {
		trimmed := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(trimmed, "#") {
			continue
		}
		dRest := strings.TrimSpace(trimmed[1:])
		if !strings.HasPrefix(dRest, "define") || (len(dRest) > 6 && dRest[6] != ' ' && dRest[6] != '\t') {
			continue
		}
		afterDef := strings.TrimSpace(dRest[6:])
		mEnd := 0
		for mEnd < len(afterDef) && (isASCIIIdentByte(afterDef[mEnd]) && (mEnd > 0 || (afterDef[mEnd] < '0' || afterDef[mEnd] > '9'))) {
			mEnd++
		}
		if mEnd == 0 {
			continue
		}
		name := afterDef[:mEnd]
		afterName := afterDef[mEnd:]
		var def cppMacroDef
		if strings.HasPrefix(afterName, "(") {
			closeIdx := strings.IndexByte(afterName, ')')
			if closeIdx < 0 {
				continue
			}
			def.hasParams = true
			paramList := strings.TrimSpace(afterName[1:closeIdx])
			if paramList != "" {
				for _, p := range strings.Split(paramList, ",") {
					p = strings.TrimSpace(p)
					if p == "..." {
						def.variadic = true
						continue
					}
					if strings.HasSuffix(p, "...") {
						p = strings.TrimSpace(strings.TrimSuffix(p, "..."))
						def.variadic = true
						def.namedVarParam = p
						continue
					}
					if p != "" {
						def.params = append(def.params, p)
					}
				}
			}
			def.body = strings.TrimSpace(afterName[closeIdx+1:])
		} else {
			def.body = strings.TrimSpace(afterName)
		}
		dup := false
		for _, prev := range defs[name] {
			if prev.hasParams == def.hasParams && prev.variadic == def.variadic && prev.namedVarParam == def.namedVarParam && prev.body == def.body && slices.Equal(prev.params, def.params) {
				dup = true
				break
			}
		}
		if !dup {
			defs[name] = append(defs[name], def)
		}
	}
}

func collapseTokenPasteOps(s string) string {
	for {
		idx := strings.Index(s, "##")
		if idx < 0 {
			return s
		}
		left := idx
		for left > 0 && (s[left-1] == ' ' || s[left-1] == '\t') {
			left--
		}
		right := idx + 2
		for right < len(s) && (s[right] == ' ' || s[right] == '\t') {
			right++
		}
		s = s[:left] + s[right:]
	}
}

func parseCPPMacroCallArgs(s string, openParenIdx int) (args []string, nextIdx int, ok bool) {
	if openParenIdx >= len(s) || s[openParenIdx] != '(' {
		return nil, 0, false
	}
	depth := 1
	curStart := openParenIdx + 1
	for i := openParenIdx + 1; i < len(s); i++ {
		switch s[i] {
		case '"', '\'':
			q := s[i]
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				i++
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				tail := strings.TrimSpace(s[curStart:i])
				if len(args) > 0 || tail != "" {
					args = append(args, tail)
				}
				return args, i + 1, true
			}
		case ',':
			if depth == 1 {
				args = append(args, strings.TrimSpace(s[curStart:i]))
				curStart = i + 1
			}
		}
	}
	return nil, 0, false
}

func cppStringizeArg(arg string) string {
	trimmed := strings.TrimSpace(arg)
	var b strings.Builder
	b.WriteByte('"')
	inSpace := false
	for i := 0; i < len(trimmed); i++ {
		ch := trimmed[i]
		if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
			inSpace = true
			continue
		}
		if inSpace {
			b.WriteByte(' ')
			inSpace = false
		}
		if ch == '\\' || ch == '"' {
			b.WriteByte('\\')
		}
		b.WriteByte(ch)
	}
	b.WriteByte('"')
	return b.String()
}

func isHexDigitByte(c byte) (uint32, bool) {
	switch {
	case c >= '0' && c <= '9':
		return uint32(c - '0'), true
	case c >= 'a' && c <= 'f':
		return uint32(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return uint32(c-'A') + 10, true
	default:
		return 0, false
	}
}

func matchCStringPrefixAt(s string, idx int) (quoteIdx int, ok bool) {
	if idx >= len(s) {
		return 0, false
	}
	if s[idx] == '"' {
		return idx, true
	}
	if idx > 0 && isASCIIIdentByte(s[idx-1]) {
		return 0, false
	}
	if idx+1 < len(s) && (s[idx] == 'L' || s[idx] == 'u' || s[idx] == 'U') && s[idx+1] == '"' {
		return idx + 1, true
	}
	if idx+2 < len(s) && s[idx] == 'u' && s[idx+1] == '8' && s[idx+2] == '"' {
		return idx + 2, true
	}
	return 0, false
}

func writeNormalizedCStringByte(b *strings.Builder, ch byte) {
	switch ch {
	case '"':
		b.WriteString(`\"`)
	case '\\':
		b.WriteString(`\\`)
	default:
		b.WriteByte(ch)
	}
}

func normalizeCStringLiterals(s string, allowNewlineConcat bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '\'' {
			b.WriteByte(s[i])
			i++
			for i < len(s) {
				b.WriteByte(s[i])
				if s[i] == '\\' && i+1 < len(s) {
					i++
					b.WriteByte(s[i])
					i++
					continue
				}
				if s[i] == '\'' {
					i++
					break
				}
				i++
			}
			continue
		}
		if qIdx, ok := matchCStringPrefixAt(s, i); ok {
			b.WriteByte('"')
			i = qIdx + 1
			for {
				for i < len(s) && s[i] != '"' {
					if s[i] != '\\' || i+1 >= len(s) {
						b.WriteByte(s[i])
						i++
						continue
					}
					esc := s[i+1]
					switch {
					case esc == 'x':
						j := i + 2
						var val uint32
						digits := 0
						for j < len(s) {
							d, okD := isHexDigitByte(s[j])
							if !okD {
								break
							}
							val = (val << 4) | d
							digits++
							j++
						}
						if digits > 0 {
							writeNormalizedCStringByte(&b, byte(val))
							i = j
							continue
						}
					case esc >= '0' && esc <= '7':
						j := i + 1
						var val uint32
						for k := 0; k < 3 && j < len(s) && s[j] >= '0' && s[j] <= '7'; k++ {
							val = (val << 3) | uint32(s[j]-'0')
							j++
						}
						writeNormalizedCStringByte(&b, byte(val))
						i = j
						continue
					case esc == 'u' || esc == 'U':
						want := 4
						if esc == 'U' {
							want = 8
						}
						if i+2+want <= len(s) {
							var val uint32
							okU := true
							for k := 0; k < want; k++ {
								d, okD := isHexDigitByte(s[i+2+k])
								if !okD {
									okU = false
									break
								}
								val = (val << 4) | d
							}
							if okU && utf8.ValidRune(rune(val)) {
								r := rune(val)
								if r == '"' {
									b.WriteString(`\"`)
								} else if r == '\\' {
									b.WriteString(`\\`)
								} else {
									b.WriteRune(r)
								}
								i += 2 + want
								continue
							}
						}
					}
					switch esc {
					case '"':
						b.WriteString(`\"`)
					case '\\':
						b.WriteString(`\\`)
					case '\'':
						b.WriteByte('\'')
					case '?':
						b.WriteByte('?')
					case 'n':
						b.WriteByte('\n')
					case 'r':
						b.WriteByte('\r')
					case 't':
						b.WriteByte('\t')
					case 'v':
						b.WriteByte('\v')
					case 'b':
						b.WriteByte('\b')
					case 'f':
						b.WriteByte('\f')
					case 'a':
						b.WriteByte('\a')
					default:
						b.WriteByte(esc)
					}
					i += 2
				}
				if i < len(s) && s[i] == '"' {
					i++
				}
				k := i
				for k < len(s) {
					if s[k] == ' ' || s[k] == '\t' {
						k++
						continue
					}
					if allowNewlineConcat && (s[k] == '\r' || s[k] == '\n') {
						k++
						continue
					}
					break
				}
				if nextQ, okNext := matchCStringPrefixAt(s, k); okNext {
					i = nextQ + 1
					continue
				}
				b.WriteByte('"')
				break
			}
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

const (
	maxNonGoLogicalLineBytes    = 1 << 20
	maxCPPExpandedStatesPerLine = 256
	maxCPPExpansionDepth        = 32
)

type cppExpandBudget struct {
	statesLeft int
	overflow   bool
}

type cppStateKey struct {
	text    string
	blocked string
	chosen  string
}

type cppWorkItem struct {
	text    string
	blocked string
	chosen  string
	depth   int
}

func lookupChosenMacro(chosen, name string) (int, bool) {
	if chosen == "" {
		return 0, false
	}
	needle := "|" + name + "="
	idx := strings.Index(chosen, needle)
	if idx < 0 {
		return 0, false
	}
	rest := chosen[idx+len(needle):]
	end := strings.IndexByte(rest, '|')
	if end < 0 {
		return 0, false
	}
	val, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0, false
	}
	return val, true
}

func addChosenMacro(chosen, name string, defIdx int) string {
	if _, ok := lookupChosenMacro(chosen, name); ok {
		return chosen
	}
	entry := name + "=" + strconv.Itoa(defIdx) + "|"
	if chosen == "" {
		return "|" + entry
	}
	return chosen + entry
}

func isBlockedMacro(blocked, name string) bool {
	return blocked != "" && strings.Contains(blocked, "|"+name+"|")
}

func addBlockedMacro(blocked, name string) string {
	if isBlockedMacro(blocked, name) {
		return blocked
	}
	if blocked == "" {
		return "|" + name + "|"
	}
	return blocked + name + "|"
}

func mergeBlockedMacros(a, b string) string {
	if b == "" {
		return a
	}
	if a == "" {
		return b
	}
	out := a
	for _, part := range strings.Split(b, "|") {
		if part != "" {
			out = addBlockedMacro(out, part)
		}
	}
	return out
}

func isPasteAdjacentInBody(body string, start, end int) bool {
	l := start
	for l > 0 && (body[l-1] == ' ' || body[l-1] == '\t') {
		l--
	}
	if l >= 2 && body[l-1] == '#' && body[l-2] == '#' {
		return true
	}
	r := end
	for r < len(body) && (body[r] == ' ' || body[r] == '\t') {
		r++
	}
	return r+1 < len(body) && body[r] == '#' && body[r+1] == '#'
}

func macroNormalParams(def cppMacroDef) map[string]bool {
	return macroNormalParamsMode(def, false)
}

func macroNormalParamsMode(def cppMacroDef, asmIdentMode bool) map[string]bool {
	normal := map[string]bool{}
	body := def.body
	for i := 0; i < len(body); {
		if body[i] == '"' || body[i] == '\'' {
			q := body[i]
			i++
			for i < len(body) {
				if body[i] == '\\' && i+1 < len(body) {
					i += 2
					continue
				}
				if body[i] == q {
					i++
					break
				}
				i++
			}
			continue
		}
		if body[i] == '#' && (i+1 >= len(body) || body[i+1] != '#') && (i == 0 || body[i-1] != '#') {
			k := i + 1
			for k < len(body) && (body[k] == ' ' || body[k] == '\t') {
				k++
			}
			if end, ok := scanIdentToken(body, k, asmIdentMode); ok {
				i = end
				continue
			}
		}
		if end, ok := scanIdentToken(body, i, asmIdentMode); ok {
			start := i
			i = end
			if !isPasteAdjacentInBody(body, start, i) {
				normal[body[start:i]] = true
			}
			continue
		}
		i++
	}
	return normal
}

func bodyMacroRefs(def cppMacroDef, defs map[string][]cppMacroDef) []string {
	return bodyMacroRefsMode(def, defs, false)
}

func bodyMacroRefsMode(def cppMacroDef, defs map[string][]cppMacroDef, asmIdentMode bool) []string {
	paramSet := make(map[string]bool, len(def.params)+2)
	for _, p := range def.params {
		paramSet[p] = true
	}
	if def.variadic {
		paramSet["__VA_ARGS__"] = true
		if def.namedVarParam != "" {
			paramSet[def.namedVarParam] = true
		}
	}
	var refs []string
	for _, scanBody := range []string{def.body, collapseTokenPasteOps(def.body)} {
		for i := 0; i < len(scanBody); {
			if scanBody[i] == '"' || scanBody[i] == '\'' {
				q := scanBody[i]
				i++
				for i < len(scanBody) {
					if scanBody[i] == '\\' && i+1 < len(scanBody) {
						i += 2
						continue
					}
					if scanBody[i] == q {
						i++
						break
					}
					i++
				}
				continue
			}
			if end, ok := scanIdentToken(scanBody, i, asmIdentMode); ok {
				tok := scanBody[i:end]
				i = end
				if !paramSet[tok] && len(defs[tok]) > 0 && !slices.Contains(refs, tok) {
					refs = append(refs, tok)
				}
				continue
			}
			i++
		}
	}
	return refs
}

func defReachesMacro(target string, startDef cppMacroDef, defs map[string][]cppMacroDef) bool {
	return defReachesMacroMode(target, startDef, defs, false)
}

func defReachesMacroMode(target string, startDef cppMacroDef, defs map[string][]cppMacroDef, asmIdentMode bool) bool {
	queue := bodyMacroRefsMode(startDef, defs, asmIdentMode)
	visited := map[string]bool{}
	for len(queue) > 0 {
		m := queue[0]
		queue = queue[1:]
		if m == target {
			return true
		}
		if visited[m] {
			continue
		}
		visited[m] = true
		for _, d := range defs[m] {
			for _, next := range bodyMacroRefsMode(d, defs, asmIdentMode) {
				if next == target {
					return true
				}
				if !visited[next] {
					queue = append(queue, next)
				}
			}
		}
	}
	return false
}

func substituteCPPMacroBody(def cppMacroDef, rawArgs, expArgs []string) string {
	return substituteCPPMacroBodyMode(def, rawArgs, expArgs, false)
}

func substituteCPPMacroBodyMode(def cppMacroDef, rawArgs, expArgs []string, asmIdentMode bool) string {
	if !def.hasParams {
		return collapseTokenPasteOps(def.body)
	}
	rawMap := make(map[string]string, len(def.params)+2)
	expMap := make(map[string]string, len(def.params)+2)
	for idx, p := range def.params {
		if idx < len(rawArgs) {
			rawMap[p] = rawArgs[idx]
		} else {
			rawMap[p] = ""
		}
		if idx < len(expArgs) {
			expMap[p] = expArgs[idx]
		} else {
			expMap[p] = ""
		}
	}
	if def.variadic {
		varKey := "__VA_ARGS__"
		if def.namedVarParam != "" {
			varKey = def.namedVarParam
		}
		if len(rawArgs) > len(def.params) {
			rawMap[varKey] = strings.Join(rawArgs[len(def.params):], ", ")
		} else {
			rawMap[varKey] = ""
		}
		if len(expArgs) > len(def.params) {
			expMap[varKey] = strings.Join(expArgs[len(def.params):], ", ")
		} else {
			expMap[varKey] = ""
		}
	}
	var b strings.Builder
	body := def.body
	for i := 0; i < len(body); {
		if body[i] == '"' || body[i] == '\'' {
			q := body[i]
			b.WriteByte(body[i])
			i++
			for i < len(body) {
				b.WriteByte(body[i])
				if body[i] == '\\' && i+1 < len(body) {
					i++
					b.WriteByte(body[i])
					i++
					continue
				}
				if body[i] == q {
					i++
					break
				}
				i++
			}
			continue
		}
		if body[i] == '#' && (i+1 >= len(body) || body[i+1] != '#') && (i == 0 || body[i-1] != '#') {
			k := i + 1
			for k < len(body) && (body[k] == ' ' || body[k] == '\t') {
				k++
			}
			if mEnd, ok := scanIdentToken(body, k, asmIdentMode); ok {
				if rep, ok := rawMap[body[k:mEnd]]; ok {
					b.WriteString(cppStringizeArg(rep))
					i = mEnd
					continue
				}
			}
		}
		if end, ok := scanIdentToken(body, i, asmIdentMode); ok {
			start := i
			i = end
			tok := body[start:i]
			if rawRep, ok := rawMap[tok]; ok {
				if isPasteAdjacentInBody(body, start, i) {
					b.WriteString(rawRep)
				} else {
					b.WriteString(expMap[tok])
				}
			} else {
				b.WriteString(tok)
			}
			continue
		}
		b.WriteByte(body[i])
		i++
	}
	return collapseTokenPasteOps(b.String())
}

func stepCPPPass(cur cppWorkItem, defs map[string][]cppMacroDef, budget *cppExpandBudget) ([]cppWorkItem, bool) {
	return stepCPPPassMode(cur, defs, budget, false)
}

func stepCPPPassMode(cur cppWorkItem, defs map[string][]cppMacroDef, budget *cppExpandBudget, asmIdentMode bool) ([]cppWorkItem, bool) {
	s := cur.text
	var prefix strings.Builder
	expandedAny := false
	passAddedBlocks := ""
	type candChoice struct {
		rep        string
		nextEnd    int
		addBlock   bool
		bindChoice bool
		choiceIdx  int
	}

	for i := 0; i < len(s); {
		if budget.overflow {
			return nil, false
		}
		if s[i] == '"' || s[i] == '\'' {
			q := s[i]
			prefix.WriteByte(s[i])
			i++
			for i < len(s) {
				prefix.WriteByte(s[i])
				if s[i] == '\\' && i+1 < len(s) {
					i++
					prefix.WriteByte(s[i])
					i++
					continue
				}
				if s[i] == q {
					i++
					break
				}
				i++
			}
			continue
		}
		if end, ok := scanIdentToken(s, i, asmIdentMode); ok {
			start := i
			i = end
			tok := s[start:i]
			dList := defs[tok]
			hasMultiDefs := len(dList) > 1
			if hasMultiDefs {
				if cIdx, okC := lookupChosenMacro(cur.chosen, tok); okC {
					if cIdx < 0 || cIdx >= len(dList) {
						dList = nil
					} else {
						dList = dList[cIdx : cIdx+1]
						hasMultiDefs = false
					}
				}
			}
			if len(dList) == 0 || isBlockedMacro(cur.blocked, tok) || (len(dList) == 1 && !dList[0].hasParams && dList[0].body == tok) {
				prefix.WriteString(tok)
				continue
			}
			j := i
			for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r' || s[j] == '\n') {
				j++
			}
			rawArgs, afterClose, hasCall := parseCPPMacroCallArgs(s, j)

			var choices []candChoice
			hasNonApplicableFuncDef := false
			for dIdx, d := range dList {
				if !d.hasParams {
					choices = append(choices, candChoice{
						rep:        collapseTokenPasteOps(d.body),
						nextEnd:    i,
						addBlock:   defReachesMacroMode(tok, d, defs, asmIdentMode),
						bindChoice: hasMultiDefs,
						choiceIdx:  dIdx,
					})
					continue
				}
				if !hasCall {
					hasNonApplicableFuncDef = true
					continue
				}
				normal := macroNormalParamsMode(d, asmIdentMode)
				argChoices := make([][]string, len(rawArgs))
				for k, rawArg := range rawArgs {
					isNormal := false
					if k < len(d.params) {
						isNormal = normal[d.params[k]]
					} else if d.variadic {
						isNormal = normal["__VA_ARGS__"] || (d.namedVarParam != "" && normal[d.namedVarParam])
					}
					if isNormal && rawArg != "" {
						if cur.depth+1 > maxCPPExpansionDepth {
							budget.overflow = true
							return nil, false
						}
						_, terms := expandCPPStatesWithBudgetMode(rawArg, defs, cur.blocked, cur.chosen, cur.depth+1, budget, asmIdentMode)
						if budget.overflow {
							return nil, false
						}
						argChoices[k] = terms
					} else {
						argChoices[k] = []string{rawArg}
					}
				}
				tuples := [][]string{{}}
				for _, ac := range argChoices {
					if len(tuples)*max(len(ac), 1) > maxCPPExpandedStatesPerLine {
						budget.overflow = true
						return nil, false
					}
					nextTuples := make([][]string, 0, len(tuples)*max(len(ac), 1))
					for _, prev := range tuples {
						for _, val := range ac {
							cp := make([]string, len(prev)+1)
							copy(cp, prev)
							cp[len(prev)] = val
							nextTuples = append(nextTuples, cp)
						}
					}
					tuples = nextTuples
				}
				addBlk := defReachesMacroMode(tok, d, defs, asmIdentMode)
				for _, expArgs := range tuples {
					choices = append(choices, candChoice{
						rep:        substituteCPPMacroBodyMode(d, rawArgs, expArgs, asmIdentMode),
						nextEnd:    afterClose,
						addBlock:   addBlk,
						bindChoice: hasMultiDefs,
						choiceIdx:  dIdx,
					})
				}
			}
			if len(choices) == 0 {
				prefix.WriteString(tok)
				continue
			}
			if hasNonApplicableFuncDef {
				choices = append(choices, candChoice{
					rep:        tok,
					nextEnd:    i,
					addBlock:   true,
					bindChoice: hasMultiDefs,
					choiceIdx:  -1,
				})
			}
			if cur.depth+1 > maxCPPExpansionDepth {
				budget.overflow = true
				return nil, false
			}
			if len(choices) == 1 {
				expandedAny = true
				prefix.WriteString(choices[0].rep)
				if choices[0].addBlock {
					passAddedBlocks = addBlockedMacro(passAddedBlocks, tok)
				}
				i = choices[0].nextEnd
				if prefix.Len() > maxNonGoLogicalLineBytes {
					budget.overflow = true
					return nil, false
				}
				continue
			}
			pfx := prefix.String()
			baseBlk := mergeBlockedMacros(cur.blocked, passAddedBlocks)
			children := make([]cppWorkItem, 0, len(choices))
			for _, ch := range choices {
				if len(pfx)+len(ch.rep)+len(s[ch.nextEnd:]) > maxNonGoLogicalLineBytes {
					budget.overflow = true
					return nil, false
				}
				nextText := collapseTokenPasteOps(pfx + ch.rep + s[ch.nextEnd:])
				if len(nextText) > maxNonGoLogicalLineBytes {
					budget.overflow = true
					return nil, false
				}
				nextBlk := baseBlk
				if ch.addBlock {
					nextBlk = addBlockedMacro(nextBlk, tok)
				}
				nextChosen := cur.chosen
				if ch.bindChoice {
					nextChosen = addChosenMacro(nextChosen, tok, ch.choiceIdx)
				}
				children = append(children, cppWorkItem{
					text:    nextText,
					blocked: nextBlk,
					chosen:  nextChosen,
					depth:   cur.depth + 1,
				})
			}
			return children, true
		}
		prefix.WriteByte(s[i])
		i++
	}
	if !expandedAny {
		return nil, false
	}
	nextText := collapseTokenPasteOps(prefix.String())
	if len(nextText) > maxNonGoLogicalLineBytes {
		budget.overflow = true
		return nil, false
	}
	nextBlk := mergeBlockedMacros(cur.blocked, passAddedBlocks)
	if nextText == cur.text && nextBlk == cur.blocked {
		return nil, false
	}
	return []cppWorkItem{{
		text:    nextText,
		blocked: nextBlk,
		chosen:  cur.chosen,
		depth:   cur.depth + 1,
	}}, true
}

func expandCPPStatesWithBudget(line string, defs map[string][]cppMacroDef, blocked, chosen string, startDepth int, budget *cppExpandBudget) (allStates []string, terminals []string) {
	return expandCPPStatesWithBudgetMode(line, defs, blocked, chosen, startDepth, budget, false)
}

func expandAsmCPPStatesWithBudget(line string, defs map[string][]cppMacroDef, blocked, chosen string, startDepth int, budget *cppExpandBudget) (allStates []string, terminals []string) {
	return expandCPPStatesWithBudgetMode(line, defs, blocked, chosen, startDepth, budget, true)
}

func expandCPPStatesWithBudgetMode(line string, defs map[string][]cppMacroDef, blocked, chosen string, startDepth int, budget *cppExpandBudget, asmIdentMode bool) (allStates []string, terminals []string) {
	if len(line) > maxNonGoLogicalLineBytes {
		budget.overflow = true
		return nil, nil
	}
	initKey := cppStateKey{text: line, blocked: blocked, chosen: chosen}
	seen := map[cppStateKey]bool{initKey: true}
	queue := []cppWorkItem{{text: line, blocked: blocked, chosen: chosen, depth: startDepth}}
	allSet := map[string]bool{}
	termSet := map[string]bool{}

	for len(queue) > 0 && !budget.overflow {
		cur := queue[0]
		queue = queue[1:]
		if !allSet[cur.text] {
			allSet[cur.text] = true
			allStates = append(allStates, cur.text)
		}
		children, expanded := stepCPPPassMode(cur, defs, budget, asmIdentMode)
		if budget.overflow {
			return nil, nil
		}
		if !expanded {
			if !termSet[cur.text] {
				termSet[cur.text] = true
				terminals = append(terminals, cur.text)
			}
			continue
		}
		for _, ch := range children {
			key := cppStateKey{text: ch.text, blocked: ch.blocked, chosen: ch.chosen}
			if seen[key] {
				continue
			}
			budget.statesLeft--
			if budget.statesLeft < 0 {
				budget.overflow = true
				return nil, nil
			}
			seen[key] = true
			queue = append(queue, ch)
		}
	}
	if len(terminals) == 0 && !budget.overflow {
		terminals = []string{line}
	}
	return allStates, terminals
}

func expandCPPLineAllChoices(line string, defs map[string][]cppMacroDef) (allStates []string, primary string, overflow bool) {
	budget := &cppExpandBudget{statesLeft: maxCPPExpandedStatesPerLine}
	all, terms := expandCPPStatesWithBudget(line, defs, "", "", 0, budget)
	if budget.overflow {
		return nil, "", true
	}
	prim := line
	if len(terms) > 0 {
		prim = terms[0]
	}
	return all, prim, false
}

func collapseAsmMiddleDotAndSlashSpaces(s string) string {
	s = strings.ReplaceAll(s, "∕", "/")
	for _, sep := range []string{"·", "/"} {
		for {
			prev := s
			s = strings.ReplaceAll(s, " "+sep, sep)
			s = strings.ReplaceAll(s, "\t"+sep, sep)
			s = strings.ReplaceAll(s, sep+" ", sep)
			s = strings.ReplaceAll(s, sep+"\t", sep)
			if s == prev {
				break
			}
		}
	}
	searchFrom := 0
	for searchFrom < len(s) {
		rel := strings.Index(s[searchFrom:], "·(*")
		if rel < 0 {
			break
		}
		idx := searchFrom + rel
		rest := s[idx+len("·(*"):]
		end := 0
		for end < len(rest) && isASCIIIdentByte(rest[end]) {
			end++
		}
		if end == 0 || !strings.HasPrefix(rest[end:], ")·") {
			searchFrom = idx + len("·(*")
			continue
		}
		s = s[:idx] + "·" + rest[:end] + "·" + rest[end+len(")·"):]
		searchFrom = idx + len("·")
	}
	return s
}

func leadingASCIIIdent(s string) string {
	end := 0
	for end < len(s) && isASCIIIdentByte(s[end]) {
		end++
	}
	if end == 0 || (s[0] >= '0' && s[0] <= '9') {
		return ""
	}
	return s[:end]
}

func unescapeObjabiToken(s string) string {
	if strings.IndexByte(s, '%') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) {
			hi, okHi := isHexDigitByte(s[i+1])
			lo, okLo := isHexDigitByte(s[i+2])
			if okHi && okLo {
				b.WriteByte(byte((hi << 4) | lo))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func collectRuntimeIdentsAndMachO(data []byte, identOut map[string]bool) {
	if identOut == nil || len(data) == 0 {
		return
	}
	tmp := map[string]bool{}
	collectAllASCIIIdents(data, tmp)
	for id := range tmp {
		identOut[id] = true
		if trimmed := strings.TrimLeft(id, "_"); trimmed != "" && (trimmed[0] < '0' || trimmed[0] > '9') {
			identOut[trimmed] = true
		}
	}
}

func collectCStringSymbolRefs(s, selfPkg string, runtimeOut, externalOut, identOut map[string]bool) {
	if runtimeOut == nil && externalOut == nil && identOut == nil {
		return
	}
	recordTarget := func(pkgPrefix, sym string) {
		if pkgPrefix == "" || sym == "" {
			return
		}
		if pkgPrefix == "runtime" {
			base := leadingASCIIIdent(sym)
			if base != "" && runtimeOut != nil {
				runtimeOut["runtime."+base] = true
			}
		} else if externalOut != nil && pkgPrefix != selfPkg {
			externalOut[pkgPrefix+"."+sym] = true
		}
	}
	isSymRunByte := func(c byte) bool {
		return isASCIIIdentByte(c) || c == '/' || c == '.' || c == '-' || c == '%'
	}
	for i := 0; i < len(s); {
		if s[i] == '\'' {
			i++
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				if s[i] == '\'' {
					i++
					break
				}
				i++
			}
			continue
		}
		if s[i] != '"' {
			i++
			continue
		}
		i++
		var lit strings.Builder
		for i < len(s) && s[i] != '"' {
			if s[i] == '\\' && i+1 < len(s) {
				lit.WriteByte(s[i+1])
				i += 2
				continue
			}
			lit.WriteByte(s[i])
			i++
		}
		if i < len(s) && s[i] == '"' {
			i++
		}
		body := lit.String()
		if identOut != nil {
			collectRuntimeIdentsAndMachO([]byte(body), identOut)
			if unescBody := unescapeObjabiToken(body); unescBody != body {
				collectRuntimeIdentsAndMachO([]byte(unescBody), identOut)
			}
		}
		for j := 0; j < len(body); {
			if !isSymRunByte(body[j]) {
				j++
				continue
			}
			start := j
			for j < len(body) {
				if isSymRunByte(body[j]) {
					j++
					continue
				}
				if j > start && body[j-1] == '.' && strings.HasPrefix(body[j:], "(*") {
					tIdent := leadingASCIIIdent(body[j+2:])
					afterType := j + 2 + len(tIdent)
					if tIdent != "" && strings.HasPrefix(body[afterType:], ").") {
						j = afterType + 2
						continue
					}
				}
				break
			}
			rawTok := body[start:j]
			tokCands := []string{rawTok}
			if unesc := unescapeObjabiToken(rawTok); unesc != rawTok {
				tokCands = append(tokCands, unesc)
			}
			for _, tok := range tokCands {
				pkgPrefix, symPart, ok := splitLinknameTarget(tok)
				if !ok {
					continue
				}
				pkgPrefix = unescapeObjabiToken(strings.TrimLeft(pkgPrefix, "./"))
				symPart = unescapeObjabiToken(symPart)
				var syms []string
				if strings.HasPrefix(symPart, "(*") {
					tIdent := leadingASCIIIdent(symPart[2:])
					afterType := 2 + len(tIdent)
					if tIdent != "" && strings.HasPrefix(symPart[afterType:], ").") {
						mIdent := leadingASCIIIdent(symPart[afterType+2:])
						if mIdent != "" {
							syms = append(syms, tIdent, tIdent+"."+mIdent)
						}
					}
				} else if first := leadingASCIIIdent(symPart); first != "" {
					syms = append(syms, first)
					if len(symPart) > len(first) && symPart[len(first)] == '.' {
						if second := leadingASCIIIdent(symPart[len(first)+1:]); second != "" {
							syms = append(syms, first+"."+second)
						}
					}
				}
				for _, sym := range syms {
					recordTarget(pkgPrefix, sym)
					if machOPrefix := strings.TrimPrefix(pkgPrefix, "_"); machOPrefix != pkgPrefix {
						recordTarget(machOPrefix, sym)
					}
				}
			}
		}
	}
}

func extractExpandedLineSymbols(text, selfPkg string, runtimeOut, externalOut, identOut map[string]bool) {
	candidates := []string{text}
	if cNorm := normalizeCStringLiterals(text, true); cNorm != text {
		candidates = append(candidates, cNorm)
	}
	for _, cand := range candidates {
		if identOut != nil {
			collectRuntimeIdentsAndMachO([]byte(cand), identOut)
		}
		if runtimeOut != nil {
			collectRawBytesRuntimeSymbolRefs([]byte(cand), runtimeOut)
		}
		collectCStringSymbolRefs(cand, selfPkg, runtimeOut, externalOut, identOut)
		norm := collapseAsmMiddleDotAndSlashSpaces(cand)
		if identOut != nil {
			collectRuntimeIdentsAndMachO([]byte(norm), identOut)
		}
		if runtimeOut != nil {
			collectRawBytesRuntimeSymbolRefs([]byte(norm), runtimeOut)
		}
		collectCStringSymbolRefs(norm, selfPkg, runtimeOut, externalOut, identOut)
		runes := []rune(norm)
		for i := 0; i < len(runes); {
			if !isAsmWordRune(runes[i]) {
				i++
				continue
			}
			start := i
			for i < len(runes) && isAsmWordRune(runes[i]) {
				i++
			}
			tok := string(runes[start:i])
			if !strings.ContainsRune(tok, '·') {
				continue
			}
			pkgPrefix, symPart, _ := strings.Cut(tok, "·")
			pkgPrefix = strings.TrimLeft(pkgPrefix, "./")
			basePart, _, _ := strings.Cut(symPart, "<")
			baseSym := leadingASCIIIdent(basePart)
			if pkgPrefix == "" || baseSym == "" {
				continue
			}
			if pkgPrefix == "runtime" {
				if runtimeOut != nil {
					runtimeOut["runtime."+baseSym] = true
				}
			} else if externalOut != nil && pkgPrefix != selfPkg {
				externalOut[pkgPrefix+"."+baseSym] = true
				if afterDot, okSecond := strings.CutPrefix(basePart[len(baseSym):], "·"); okSecond {
					if secondSym := leadingASCIIIdent(afterDot); secondSym != "" {
						externalOut[pkgPrefix+"."+baseSym+"."+secondSym] = true
					}
				}
			}
		}
	}
}

func unquotedParenBalance(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"', '\'':
			q := s[i]
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				i++
			}
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		}
	}
	return depth
}

func trailingFuncMacroIdent(s string, defs map[string][]cppMacroDef) bool {
	return trailingFuncMacroIdentMode(s, defs, false)
}

func trailingAsmFuncMacroIdent(s string, defs map[string][]cppMacroDef) bool {
	return trailingFuncMacroIdentMode(s, defs, true)
}

func trailingFuncMacroIdentMode(s string, defs map[string][]cppMacroDef, asmIdentMode bool) bool {
	if len(defs) == 0 {
		return false
	}
	end := len(s)
	for end > 0 && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	start := end
	for start > 0 && isASCIIIdentByte(s[start-1]) {
		start--
	}
	if start == end || (s[start] >= '0' && s[start] <= '9') {
		return false
	}
	if asmIdentMode && start > 0 {
		r, _ := utf8.DecodeLastRuneInString(s[:start])
		if r == '\u00B7' || r == '\u2215' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			return false
		}
	}
	for _, d := range defs[s[start:end]] {
		if d.hasParams {
			return true
		}
	}
	return false
}

func buildLogicalNonGoScanLines(cleaned string, defs map[string][]cppMacroDef) ([]string, string, bool) {
	rawLines := strings.Split(cleaned, "\n")
	out := make([]string, 0, len(rawLines))
	var nonDirective strings.Builder
	var pending string
	for idx := 0; idx < len(rawLines); idx++ {
		line := strings.TrimSpace(rawLines[idx])
		if line == "" {
			continue
		}
		if len(line) > maxNonGoLogicalLineBytes {
			return nil, "", true
		}
		if strings.HasPrefix(line, "#") {
			if pending != "" {
				out = append(out, pending)
				pending = ""
			}
			dRest := strings.TrimSpace(line[1:])
			if strings.HasPrefix(dRest, "define") && (len(dRest) == 6 || dRest[6] == ' ' || dRest[6] == '\t') {
				afterDef := strings.TrimSpace(dRest[6:])
				mEnd := 0
				for mEnd < len(afterDef) && isASCIIIdentByte(afterDef[mEnd]) {
					mEnd++
				}
				afterName := afterDef[mEnd:]
				var body string
				if strings.HasPrefix(afterName, "(") {
					if closeIdx := strings.IndexByte(afterName, ')'); closeIdx >= 0 {
						body = strings.TrimSpace(afterName[closeIdx+1:])
					}
				} else {
					body = strings.TrimSpace(afterName)
				}
				if body != "" {
					out = append(out, body)
				}
			}
			continue
		}
		nonDirective.WriteString(line)
		nonDirective.WriteByte('\n')
		if pending == "" {
			pending = line
		} else if len(pending)+1+len(line) <= maxNonGoLogicalLineBytes {
			pending = pending + " " + line
		} else {
			return nil, "", true
		}
		if unquotedParenBalance(pending) > 0 {
			continue
		}
		if trailingFuncMacroIdent(pending, defs) {
			peek := idx + 1
			for peek < len(rawLines) && strings.TrimSpace(rawLines[peek]) == "" {
				peek++
			}
			if peek < len(rawLines) && strings.HasPrefix(strings.TrimSpace(rawLines[peek]), "(") {
				continue
			}
		}
		out = append(out, pending)
		pending = ""
	}
	if pending != "" {
		out = append(out, pending)
	}
	return out, nonDirective.String(), false
}

func scanPreprocessedNonGoSymbolRefs(selfPkg string, includeHeaders, pkgTexts []string, runtimeOut, externalOut, identOut map[string]bool) bool {
	for _, joinSpace := range []bool{false, true} {
		defs := map[string][]cppMacroDef{}
		for _, hdr := range includeHeaders {
			collectCPPMacrosFromText(stripAssemblyComments(hdr, true, joinSpace), defs)
		}
		cleanedTexts := make([]string, len(pkgTexts))
		for idx, txt := range pkgTexts {
			cleaned := stripAssemblyComments(txt, true, joinSpace)
			cleanedTexts[idx] = cleaned
			collectCPPMacrosFromText(cleaned, defs)
		}
		for _, cleaned := range cleanedTexts {
			logicalLines, nonDirText, overflow := buildLogicalNonGoScanLines(cleaned, defs)
			if overflow {
				return true
			}
			if nonDirText != "" {
				extractExpandedLineSymbols(nonDirText, selfPkg, runtimeOut, externalOut, identOut)
			}
			expandedLines := make([]string, 0, len(logicalLines))
			for _, line := range logicalLines {
				if line == "" {
					continue
				}
				extractExpandedLineSymbols(line, selfPkg, runtimeOut, externalOut, identOut)
				if len(defs) == 0 {
					expandedLines = append(expandedLines, line)
					continue
				}
				states, primary, expOverflow := expandCPPLineAllChoices(line, defs)
				if expOverflow {
					return true
				}
				expandedLines = append(expandedLines, primary)
				for _, st := range states {
					if st != line {
						extractExpandedLineSymbols(st, selfPkg, runtimeOut, externalOut, identOut)
					}
				}
			}
			if len(expandedLines) > 1 {
				extractExpandedLineSymbols(strings.Join(expandedLines, "\n"), selfPkg, runtimeOut, externalOut, identOut)
			}
		}
	}
	return false
}

func matchLineContinuation(src string, idx int) (int, bool) {
	if idx >= len(src) || src[idx] != '\\' {
		return 0, false
	}
	j := idx + 1
	for j < len(src) && (src[j] == ' ' || src[j] == '\t' || src[j] == '\r') {
		j++
	}
	if j < len(src) && src[j] == '\n' {
		return j, true
	}
	return 0, false
}

func stripAssemblyComments(src string, keepLiterals, joinContinuationWithSpace bool) string {
	var b strings.Builder
	b.Grow(len(src))
	const (
		stateNormal = iota
		stateLineComment
		stateBlockComment
		stateString
		stateChar
	)
	state := stateNormal
	for i := 0; i < len(src); i++ {
		ch := src[i]
		switch state {
		case stateNormal:
			if nlIdx, ok := matchLineContinuation(src, i); ok {
				if joinContinuationWithSpace {
					b.WriteByte(' ')
				}
				i = nlIdx
				continue
			}
			if ch == '/' && i+1 < len(src) && src[i+1] == '/' {
				state = stateLineComment
				i++
				continue
			}
			if ch == '/' && i+1 < len(src) && src[i+1] == '*' {
				state = stateBlockComment
				b.WriteByte(' ')
				i++
				continue
			}
			if ch == '"' {
				state = stateString
				if keepLiterals {
					b.WriteByte(ch)
				} else {
					b.WriteByte(' ')
				}
				continue
			}
			if ch == '\'' {
				state = stateChar
				if keepLiterals {
					b.WriteByte(ch)
				} else {
					b.WriteByte(' ')
				}
				continue
			}
			b.WriteByte(ch)
		case stateLineComment:
			if ch == '\n' {
				state = stateNormal
				b.WriteByte('\n')
			}
		case stateBlockComment:
			if ch == '*' && i+1 < len(src) && src[i+1] == '/' {
				state = stateNormal
				i++
				continue
			}
		case stateString:
			if nlIdx, ok := matchLineContinuation(src, i); ok {
				i = nlIdx
				continue
			}
			if ch == '\\' && i+1 < len(src) {
				if keepLiterals {
					b.WriteByte(ch)
					b.WriteByte(src[i+1])
				}
				i++
				continue
			}
			if keepLiterals {
				b.WriteByte(ch)
			}
			if ch == '"' {
				state = stateNormal
			} else if ch == '\n' {
				state = stateNormal
				if !keepLiterals {
					b.WriteByte('\n')
				}
			}
		case stateChar:
			if nlIdx, ok := matchLineContinuation(src, i); ok {
				i = nlIdx
				continue
			}
			if ch == '\\' && i+1 < len(src) {
				if keepLiterals {
					b.WriteByte(ch)
					b.WriteByte(src[i+1])
				}
				i++
				continue
			}
			if keepLiterals {
				b.WriteByte(ch)
			}
			if ch == '\'' {
				state = stateNormal
			} else if ch == '\n' {
				state = stateNormal
				if !keepLiterals {
					b.WriteByte('\n')
				}
			}
		}
	}
	return foldAssemblyCommentContinuations(b.String(), joinContinuationWithSpace)
}

func foldAssemblyCommentContinuations(s string, joinWithSpace bool) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	lines := strings.Split(s, "\n")
	var out strings.Builder
	out.Grow(len(s))
	for idx, line := range lines {
		trimmedRight := strings.TrimRight(line, " \t\r")
		bs := 0
		for bs < len(trimmedRight) && trimmedRight[len(trimmedRight)-1-bs] == '\\' {
			bs++
		}
		if bs%2 == 1 && idx+1 < len(lines) {
			out.WriteString(trimmedRight[:len(trimmedRight)-1])
			if joinWithSpace {
				out.WriteByte(' ')
			}
			continue
		}
		out.WriteString(line)
		if idx+1 < len(lines) {
			out.WriteByte('\n')
		}
	}
	return out.String()
}

func isAsmWordRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
		r == '_' || r == '.' || r == '·' || r == '/' || r == '∕' || r == '<' || r == '>'
}

func verifyAssemblyNoSyscall(pkgPath, name, src string) error {
	return verifyAssemblyFile(pkgPath, name, src, nil)
}

var allowedAsmDirectiveKeywords = map[string]bool{
	"define":  true,
	"elif":    true,
	"else":    true,
	"endif":   true,
	"error":   true,
	"if":      true,
	"ifdef":   true,
	"ifndef":  true,
	"include": true,
	"line":    true,
	"pragma":  true,
	"undef":   true,
}

func verifyAssemblyFile(pkgPath, name, src string, selectedHeaders map[string]bool) error {
	if err := verifyAssemblyFileSinglePass(pkgPath, name, src, selectedHeaders, true); err != nil {
		return err
	}
	return verifyAssemblyFileSinglePass(pkgPath, name, src, selectedHeaders, false)
}

func verifyAssemblyFileSinglePass(pkgPath, name, src string, selectedHeaders map[string]bool, joinContinuationWithSpace bool) error {
	isHeader := pkgPath == "" || strings.EqualFold(filepath.Ext(name), ".h")
	noComments := stripAssemblyComments(src, true, joinContinuationWithSpace)
	definedMacros := map[string]bool{}
	for _, rawLine := range strings.Split(noComments, "\n") {
		trimmed := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(trimmed, "#") {
			continue
		}
		directive := strings.TrimSpace(trimmed[1:])
		kwEnd := 0
		for kwEnd < len(directive) && ((directive[kwEnd] >= 'a' && directive[kwEnd] <= 'z') || (directive[kwEnd] >= 'A' && directive[kwEnd] <= 'Z') || directive[kwEnd] == '_') {
			kwEnd++
		}
		kw := directive[:kwEnd]
		if !allowedAsmDirectiveKeywords[kw] {
			return fmt.Errorf("%s/%s: unsupported preprocessor directive in assembly", pkgPath, name)
		}
		if kw == "define" {
			defRest := strings.TrimSpace(directive[kwEnd:])
			mEnd := 0
			for mEnd < len(defRest) && ((defRest[mEnd] >= 'a' && defRest[mEnd] <= 'z') || (defRest[mEnd] >= 'A' && defRest[mEnd] <= 'Z') || (mEnd > 0 && defRest[mEnd] >= '0' && defRest[mEnd] <= '9') || defRest[mEnd] == '_') {
				mEnd++
			}
			macroName := defRest[:mEnd]
			if macroName == "" {
				return fmt.Errorf("%s/%s: malformed #define in assembly", pkgPath, name)
			}
			afterMacroName := defRest[mEnd:]
			hasMacroParams := strings.HasPrefix(afterMacroName, "(")
			macroBody := afterMacroName
			if hasMacroParams {
				if closeIdx := strings.IndexByte(afterMacroName, ')'); closeIdx >= 0 {
					macroBody = afterMacroName[closeIdx+1:]
				}
			}
			if pkgPath != "" && (macroName == pkgPath || slices.Contains(strings.Split(pkgPath, "/"), macroName)) {
				return fmt.Errorf("%s/%s: #define %s shadows package path", pkgPath, name, macroName)
			}
			if isHeader && !hasMacroParams && strings.TrimSpace(macroBody) != "" && macroName[0] >= 'a' && macroName[0] <= 'z' {
				return fmt.Errorf("%s/%s: header #define %s shadows lowercase package identifier", pkgPath, name, macroName)
			}
			definedMacros[macroName] = true
			continue
		}
		if kw != "include" {
			continue
		}
		incArg := strings.TrimSpace(directive[kwEnd:])
		if len(incArg) < 2 || incArg[0] != '"' {
			return fmt.Errorf("%s/%s: unapproved #include %s in assembly", pkgPath, name, incArg)
		}
		hdr, err := strconv.Unquote(incArg)
		if err != nil {
			return fmt.Errorf("%s/%s: unapproved #include %s in assembly", pkgPath, name, incArg)
		}
		if hdr == "" || strings.ContainsAny(hdr, `/\`) || strings.Contains(hdr, "..") {
			return fmt.Errorf("%s/%s: forbidden path in #include %q", pkgPath, name, hdr)
		}
		if !allowedPureAsmStandardHeaders[hdr] && !selectedHeaders[hdr] {
			return fmt.Errorf("%s/%s: unapproved #include %q in assembly", pkgPath, name, hdr)
		}
	}

	cleaned := stripAssemblyComments(src, false, joinContinuationWithSpace)
	for _, line := range strings.Split(cleaned, "\n") {
		trimmedClean := strings.TrimSpace(line)
		isDirectiveLine := strings.HasPrefix(trimmedClean, "#")
		if strings.Contains(trimmedClean, "#") && (!isDirectiveLine || strings.Contains(trimmedClean[1:], "#")) {
			return fmt.Errorf("%s/%s: unexpected '#' in assembly", pkgPath, name)
		}
		scanLine := line
		var macroParams map[string]bool
		isObjectDefine := false
		if isDirectiveLine {
			dRest := strings.TrimSpace(trimmedClean[1:])
			if strings.HasPrefix(dRest, "define") && (len(dRest) == 6 || dRest[6] == ' ' || dRest[6] == '\t') {
				afterDef := strings.TrimSpace(dRest[6:])
				mEnd := 0
				for mEnd < len(afterDef) && ((afterDef[mEnd] >= 'a' && afterDef[mEnd] <= 'z') || (afterDef[mEnd] >= 'A' && afterDef[mEnd] <= 'Z') || (mEnd > 0 && afterDef[mEnd] >= '0' && afterDef[mEnd] <= '9') || afterDef[mEnd] == '_') {
					mEnd++
				}
				afterName := afterDef[mEnd:]
				if strings.HasPrefix(afterName, "(") {
					closeIdx := strings.IndexByte(afterName, ')')
					if closeIdx < 0 {
						return fmt.Errorf("%s/%s: malformed function-like #define in assembly", pkgPath, name)
					}
					macroParams = map[string]bool{}
					for _, p := range strings.Split(afterName[1:closeIdx], ",") {
						p = strings.TrimSpace(p)
						if p != "" {
							macroParams[p] = true
						}
					}
					scanLine = afterName[closeIdx+1:]
				} else {
					isObjectDefine = true
					scanLine = afterName
				}
			}
		}
		if isObjectDefine {
			trimmedBody := strings.TrimSpace(scanLine)
			lastSpace := strings.LastIndexAny(trimmedBody, " \t")
			if lastSpace > 0 {
				beforeLast := strings.TrimRight(trimmedBody[:lastSpace], " \t")
				lastTok := trimmedBody[lastSpace+1:]
				if len(beforeLast) > 0 && isAsmWordRune(rune(beforeLast[len(beforeLast)-1])) &&
					len(lastTok) > 0 && lastTok[0] >= 'a' && lastTok[0] <= 'z' {
					allPkgChars := true
					for _, r := range lastTok {
						if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '/' || r == '∕') {
							allPkgChars = false
							break
						}
					}
					if allPkgChars {
						return fmt.Errorf("%s/%s: forbidden trailing package token %s in #define", pkgPath, name, lastTok)
					}
				}
			}
		}
		runes := []rune(scanLine)
		stmtWordIdx := 0
		prevWord := ""
		for i := 0; i < len(runes); {
			if runes[i] == ';' {
				stmtWordIdx = 0
				prevWord = ""
				i++
				continue
			}
			if !isAsmWordRune(runes[i]) {
				i++
				continue
			}
			start := i
			for i < len(runes) && isAsmWordRune(runes[i]) {
				i++
			}
			rawTok := string(runes[start:i])
			prevNonSpace := rune(0)
			for back := start - 1; back >= 0; back-- {
				if runes[back] != ' ' && runes[back] != '\t' && runes[back] != '\r' {
					prevNonSpace = runes[back]
					break
				}
			}
			if strings.ContainsRune(rawTok, '·') {
				if strings.HasSuffix(rawTok, "·") || strings.HasPrefix(rawTok, "/") || strings.HasPrefix(rawTok, "∕") ||
					prevNonSpace == '/' || prevNonSpace == '∕' || prevNonSpace == ')' ||
					strings.HasSuffix(prevWord, "/") || strings.HasSuffix(prevWord, "∕") {
					return fmt.Errorf("%s/%s: split middle-dot symbol %s in assembly", pkgPath, name, rawTok)
				}
				if (isObjectDefine || macroParams != nil) && strings.HasPrefix(rawTok, "·") && prevNonSpace == 0 {
					return fmt.Errorf("%s/%s: macro body starts with middle-dot symbol %s in assembly", pkgPath, name, rawTok)
				}
				if strings.HasPrefix(rawTok, "·") && isAsmWordRune(prevNonSpace) {
					prevHasLowerOrSlash := strings.ContainsAny(prevWord, "abcdefghijklmnopqrstuvwxyz/∕·")
					if stmtWordIdx != 1 || prevHasLowerOrSlash || definedMacros[prevWord] || macroParams[prevWord] {
						return fmt.Errorf("%s/%s: split package-qualified symbol %s %s in assembly", pkgPath, name, prevWord, rawTok)
					}
				}
				pkgPrefix, symPart, _ := strings.Cut(rawTok, "·")
				pkgPrefix = strings.ReplaceAll(pkgPrefix, "∕", "/")
				if pkgPrefix != "" {
					baseSym, _, _ := strings.Cut(symPart, "<")
					hasMacroSeg := definedMacros[pkgPrefix] || macroParams[pkgPrefix] || definedMacros[baseSym] || macroParams[baseSym] ||
						slices.ContainsFunc(strings.Split(pkgPrefix, "/"), func(seg string) bool {
							return definedMacros[seg] || macroParams[seg]
						})
					if hasMacroSeg {
						return fmt.Errorf("%s/%s: macro-qualified assembly symbol %s", pkgPath, name, rawTok)
					}
					if pkgPrefix != pkgPath {
						target := pkgPrefix + "." + baseSym
						if !allowedPureAsmCrossPkgSymbols[target] && !allowedPureSingleArgLinknames[target] {
							return fmt.Errorf("%s/%s: unapproved cross-package assembly symbol %s", pkgPath, name, rawTok)
						}
					}
				}
				stmtWordIdx++
				prevWord = rawTok
				continue
			}
			if isObjectDefine || macroParams != nil {
				switch rawTok {
				case "runtime", "syscall", "os", "internal":
					if !macroParams[rawTok] {
						return fmt.Errorf("%s/%s: forbidden package token %s in #define", pkgPath, name, rawTok)
					}
				}
			}
			tok := strings.ToUpper(rawTok)
			switch tok {
			case "SYSCALL", "SYSENTER", "SVC", "ECALL", "SCALL", "SWI",
				"RDTSC", "RDTSCP", "RDRAND", "RDSEED", "RDTIME", "RDCYCLE", "RDINSTRET",
				"CNTVCT_EL0", "CNTPCT_EL0", "CNTVCTSS_EL0", "CNTPCTSS_EL0", "RNDR", "RNDRRS":
				return fmt.Errorf("%s/%s: assembly file contains forbidden instruction %s", pkgPath, name, tok)
			case "TA":
				if prevNonSpace != ',' {
					return fmt.Errorf("%s/%s: assembly file contains raw trap instruction TA", pkgPath, name)
				}
			case "INT":
				rest := strings.TrimSpace(string(runes[i:]))
				if rawTok == "INT" || strings.HasPrefix(rest, "$") {
					return fmt.Errorf("%s/%s: assembly file contains software interrupt instruction", pkgPath, name)
				}
			}
			stmtWordIdx++
			prevWord = rawTok
		}
	}
	return nil
}
