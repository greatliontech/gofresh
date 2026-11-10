package cprep

import (
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MacroDef represents a parsed C or assembly #define macro definition.
type MacroDef struct {
	HasParams     bool
	Params        []string
	Variadic      bool
	NamedVarParam string
	Body          string
}

// ParseDefineRest parses the remainder of a #define directive immediately
// following the "define" keyword. It returns the macro name, the parsed
// MacroDef, the unparsed slice immediately following the macro name, and
// whether the #define syntax is well-formed.
func ParseDefineRest(rest string) (name string, def MacroDef, rawAfterName string, ok bool) {
	if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
		return "", MacroDef{}, "", false
	}
	afterDef := strings.TrimSpace(rest)
	name = LeadingASCIIIdent(afterDef)
	if name == "" {
		return "", MacroDef{}, "", false
	}
	rawAfterName = afterDef[len(name):]
	if strings.HasPrefix(rawAfterName, "(") {
		def.HasParams = true
		closeIdx := strings.IndexByte(rawAfterName, ')')
		if closeIdx < 0 {
			return name, def, rawAfterName, false
		}
		paramList := strings.TrimSpace(rawAfterName[1:closeIdx])
		if paramList != "" {
			for _, p := range strings.Split(paramList, ",") {
				p = strings.TrimSpace(p)
				if p == "..." {
					def.Variadic = true
					continue
				}
				if strings.HasSuffix(p, "...") {
					p = strings.TrimSpace(strings.TrimSuffix(p, "..."))
					def.Variadic = true
					def.NamedVarParam = p
					continue
				}
				if p != "" {
					def.Params = append(def.Params, p)
				}
			}
		}
		def.Body = strings.TrimSpace(rawAfterName[closeIdx+1:])
		return name, def, rawAfterName, true
	}
	def.Body = strings.TrimSpace(rawAfterName)
	return name, def, rawAfterName, true
}

// ParseDefineDirective parses a single-line #define directive.
func ParseDefineDirective(line string) (name string, def MacroDef, rawAfterName string, ok bool) {
	kw, rest, isDir := CutDirectiveKeyword(line)
	if !isDir || kw != "define" {
		return "", MacroDef{}, "", false
	}
	return ParseDefineRest(rest)
}

// CollectCPPMacrosFromText parses #define directives in cleaned text into defs.
func CollectCPPMacrosFromText(cleaned string, defs map[string][]MacroDef) {
	for _, rawLine := range strings.Split(cleaned, "\n") {
		if name, def, _, ok := ParseDefineDirective(rawLine); ok {
			AppendMacroDefUnique(defs, name, def)
		}
	}
}

// AppendMacroDefUnique appends def to defs[name] if not already present.
func AppendMacroDefUnique(defs map[string][]MacroDef, name string, def MacroDef) {
	for _, prev := range defs[name] {
		if prev.HasParams == def.HasParams && prev.Variadic == def.Variadic && prev.NamedVarParam == def.NamedVarParam && prev.Body == def.Body && slices.Equal(prev.Params, def.Params) {
			return
		}
	}
	defs[name] = append(defs[name], def)
}

// EnsureMacroIdentityChoice ensures defs[name] includes an identity expansion choice.
func EnsureMacroIdentityChoice(defs map[string][]MacroDef, name string) {
	dList := defs[name]
	if len(dList) == 0 {
		return
	}
	for _, d := range dList {
		if !d.HasParams && d.Body == name {
			return
		}
	}
	defs[name] = append(dList, MacroDef{Body: name})
}

// CollapseTokenPasteOps collapses C preprocessor ## token-pasting operators.
func CollapseTokenPasteOps(s string) string {
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

// ParseCPPMacroCallArgs parses a parenthesized macro invocation argument list.
func ParseCPPMacroCallArgs(s string, openParenIdx int) (args []string, nextIdx int, ok bool) {
	if openParenIdx >= len(s) || s[openParenIdx] != '(' {
		return nil, 0, false
	}
	depth := 1
	curStart := openParenIdx + 1
	for i := openParenIdx + 1; i < len(s); i++ {
		switch s[i] {
		case '"', '\'':
			i = SkipQuotedLiteral(s, i) - 1
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

// Preprocessor expansion limits.
const (
	MaxNonGoLogicalLineBytes    = 1 << 20
	MaxCPPExpandedStatesPerLine = 256
	MaxCPPExpansionDepth        = 32
)

// ExpandBudget tracks the remaining state budget during bounded macro expansion.
type ExpandBudget struct {
	StatesLeft int
	Overflow   bool
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
	if b == "" || a == b {
		return a
	}
	if a == "" {
		return b
	}
	out := a
	rest := b
	for len(rest) > 0 {
		sep := strings.IndexByte(rest, '|')
		var part string
		if sep < 0 {
			part = rest
			rest = ""
		} else {
			part = rest[:sep]
			rest = rest[sep+1:]
		}
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

func macroNormalParamsMode(def MacroDef, asmIdentMode bool) map[string]bool {
	normal := map[string]bool{}
	body := def.Body
	for i := 0; i < len(body); {
		if body[i] == '"' || body[i] == '\'' {
			i = SkipQuotedLiteral(body, i)
			continue
		}
		if body[i] == '#' && (i+1 >= len(body) || body[i+1] != '#') && (i == 0 || body[i-1] != '#') {
			k := i + 1
			for k < len(body) && (body[k] == ' ' || body[k] == '\t') {
				k++
			}
			if end, ok := ScanIdentToken(body, k, asmIdentMode); ok {
				i = end
				continue
			}
		}
		if end, ok := ScanIdentToken(body, i, asmIdentMode); ok {
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

func bodyMacroRefsMode(def MacroDef, defs map[string][]MacroDef, asmIdentMode bool) []string {
	paramSet := make(map[string]bool, len(def.Params)+2)
	for _, p := range def.Params {
		paramSet[p] = true
	}
	if def.Variadic {
		paramSet["__VA_ARGS__"] = true
		if def.NamedVarParam != "" {
			paramSet[def.NamedVarParam] = true
		}
	}
	scanBodies := [2]string{def.Body}
	numBodies := 1
	if collapsed := CollapseTokenPasteOps(def.Body); collapsed != def.Body {
		scanBodies[1] = collapsed
		numBodies = 2
	}
	var refs []string
	for bIdx := 0; bIdx < numBodies; bIdx++ {
		scanBody := scanBodies[bIdx]
		for i := 0; i < len(scanBody); {
			if scanBody[i] == '"' || scanBody[i] == '\'' {
				i = SkipQuotedLiteral(scanBody, i)
				continue
			}
			if end, ok := ScanIdentToken(scanBody, i, asmIdentMode); ok {
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

func defReachesMacroMode(target string, startDef MacroDef, defs map[string][]MacroDef, asmIdentMode bool) bool {
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

func substituteCPPMacroBodyMode(def MacroDef, rawArgs, expArgs []string, asmIdentMode bool) string {
	if !def.HasParams {
		return CollapseTokenPasteOps(def.Body)
	}
	rawMap := make(map[string]string, len(def.Params)+2)
	expMap := make(map[string]string, len(def.Params)+2)
	for idx, p := range def.Params {
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
	if def.Variadic {
		varKey := "__VA_ARGS__"
		if def.NamedVarParam != "" {
			varKey = def.NamedVarParam
		}
		if len(rawArgs) > len(def.Params) {
			rawMap[varKey] = strings.Join(rawArgs[len(def.Params):], ", ")
		} else {
			rawMap[varKey] = ""
		}
		if len(expArgs) > len(def.Params) {
			expMap[varKey] = strings.Join(expArgs[len(def.Params):], ", ")
		} else {
			expMap[varKey] = ""
		}
	}
	var b strings.Builder
	body := def.Body
	for i := 0; i < len(body); {
		if body[i] == '"' || body[i] == '\'' {
			end := SkipQuotedLiteral(body, i)
			b.WriteString(body[i:end])
			i = end
			continue
		}
		if body[i] == '#' && (i+1 >= len(body) || body[i+1] != '#') && (i == 0 || body[i-1] != '#') {
			k := i + 1
			for k < len(body) && (body[k] == ' ' || body[k] == '\t') {
				k++
			}
			if mEnd, ok := ScanIdentToken(body, k, asmIdentMode); ok {
				if rep, ok := rawMap[body[k:mEnd]]; ok {
					b.WriteString(cppStringizeArg(rep))
					i = mEnd
					continue
				}
			}
		}
		if end, ok := ScanIdentToken(body, i, asmIdentMode); ok {
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
	return CollapseTokenPasteOps(b.String())
}

func stepCPPPassMode(cur cppWorkItem, defs map[string][]MacroDef, budget *ExpandBudget, asmIdentMode bool) ([]cppWorkItem, bool) {
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
		if budget.Overflow {
			return nil, false
		}
		if s[i] == '"' || s[i] == '\'' {
			end := SkipQuotedLiteral(s, i)
			prefix.WriteString(s[i:end])
			i = end
			continue
		}
		if end, ok := ScanIdentToken(s, i, asmIdentMode); ok {
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
			if len(dList) == 0 || isBlockedMacro(cur.blocked, tok) || (len(dList) == 1 && !dList[0].HasParams && dList[0].Body == tok) {
				prefix.WriteString(tok)
				continue
			}
			j := i
			for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r' || s[j] == '\n') {
				j++
			}
			rawArgs, afterClose, hasCall := ParseCPPMacroCallArgs(s, j)

			var choices []candChoice
			hasNonApplicableFuncDef := false
			for dIdx, d := range dList {
				if !d.HasParams {
					choices = append(choices, candChoice{
						rep:        CollapseTokenPasteOps(d.Body),
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
					if k < len(d.Params) {
						isNormal = normal[d.Params[k]]
					} else if d.Variadic {
						isNormal = normal["__VA_ARGS__"] || (d.NamedVarParam != "" && normal[d.NamedVarParam])
					}
					if isNormal && rawArg != "" {
						if cur.depth+1 > MaxCPPExpansionDepth {
							budget.Overflow = true
							return nil, false
						}
						_, terms := ExpandCPPStatesWithBudgetMode(rawArg, defs, cur.blocked, cur.chosen, cur.depth+1, budget, asmIdentMode)
						if budget.Overflow {
							return nil, false
						}
						argChoices[k] = terms
					} else {
						argChoices[k] = []string{rawArg}
					}
				}
				tuples := [][]string{{}}
				for _, ac := range argChoices {
					if len(tuples)*max(len(ac), 1) > MaxCPPExpandedStatesPerLine {
						budget.Overflow = true
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
			if cur.depth+1 > MaxCPPExpansionDepth {
				budget.Overflow = true
				return nil, false
			}
			if len(choices) == 1 {
				expandedAny = true
				prefix.WriteString(choices[0].rep)
				if choices[0].addBlock {
					passAddedBlocks = addBlockedMacro(passAddedBlocks, tok)
				}
				i = choices[0].nextEnd
				if prefix.Len() > MaxNonGoLogicalLineBytes {
					budget.Overflow = true
					return nil, false
				}
				continue
			}
			pfx := prefix.String()
			baseBlk := mergeBlockedMacros(cur.blocked, passAddedBlocks)
			children := make([]cppWorkItem, 0, len(choices))
			for _, ch := range choices {
				if len(pfx)+len(ch.rep)+len(s[ch.nextEnd:]) > MaxNonGoLogicalLineBytes {
					budget.Overflow = true
					return nil, false
				}
				nextText := CollapseTokenPasteOps(pfx + ch.rep + s[ch.nextEnd:])
				if len(nextText) > MaxNonGoLogicalLineBytes {
					budget.Overflow = true
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
	nextText := CollapseTokenPasteOps(prefix.String())
	if len(nextText) > MaxNonGoLogicalLineBytes {
		budget.Overflow = true
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

// ExpandCPPStatesWithBudget expands C preprocessor macros on line under budget.
func ExpandCPPStatesWithBudget(line string, defs map[string][]MacroDef, blocked, chosen string, startDepth int, budget *ExpandBudget) (allStates []string, terminals []string) {
	return ExpandCPPStatesWithBudgetMode(line, defs, blocked, chosen, startDepth, budget, false)
}

// ExpandAsmCPPStatesWithBudget expands Go-assembler preprocessor macros on line under budget.
func ExpandAsmCPPStatesWithBudget(line string, defs map[string][]MacroDef, blocked, chosen string, startDepth int, budget *ExpandBudget) (allStates []string, terminals []string) {
	return ExpandCPPStatesWithBudgetMode(line, defs, blocked, chosen, startDepth, budget, true)
}

// ExpandCPPStatesWithBudgetMode expands macros on line with the specified identifier tokenization mode.
func ExpandCPPStatesWithBudgetMode(line string, defs map[string][]MacroDef, blocked, chosen string, startDepth int, budget *ExpandBudget, asmIdentMode bool) (allStates []string, terminals []string) {
	if len(line) > MaxNonGoLogicalLineBytes {
		budget.Overflow = true
		return nil, nil
	}
	initKey := cppStateKey{text: line, blocked: blocked, chosen: chosen}
	seen := map[cppStateKey]bool{initKey: true}
	queue := []cppWorkItem{{text: line, blocked: blocked, chosen: chosen, depth: startDepth}}
	allSet := map[string]bool{}
	termSet := map[string]bool{}

	for len(queue) > 0 && !budget.Overflow {
		cur := queue[0]
		queue = queue[1:]
		if !allSet[cur.text] {
			allSet[cur.text] = true
			allStates = append(allStates, cur.text)
		}
		children, expanded := stepCPPPassMode(cur, defs, budget, asmIdentMode)
		if budget.Overflow {
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
			budget.StatesLeft--
			if budget.StatesLeft < 0 {
				budget.Overflow = true
				return nil, nil
			}
			seen[key] = true
			queue = append(queue, ch)
		}
	}
	if len(terminals) == 0 && !budget.Overflow {
		terminals = []string{line}
	}
	return allStates, terminals
}

// LineHasExpandableMacro reports whether s mentions any macro defined in defs.
func LineHasExpandableMacro(s string, defs map[string][]MacroDef) bool {
	if len(defs) == 0 {
		return false
	}
	for i := 0; i < len(s); {
		if s[i] == '"' || s[i] == '\'' {
			i = SkipQuotedLiteral(s, i)
			continue
		}
		if end, ok := ScanIdentToken(s, i, false); ok {
			tok := s[i:end]
			i = end
			if dList := defs[tok]; len(dList) > 0 && !(len(dList) == 1 && !dList[0].HasParams && dList[0].Body == tok) {
				return true
			}
			continue
		}
		i++
	}
	return false
}

// ExpandCPPLineAllChoices expands all conditional macro choices for line.
func ExpandCPPLineAllChoices(line string, defs map[string][]MacroDef) (allStates []string, primary string, overflow bool) {
	if len(line) > MaxNonGoLogicalLineBytes {
		return nil, "", true
	}
	if !LineHasExpandableMacro(line, defs) {
		return []string{line}, line, false
	}
	budget := &ExpandBudget{StatesLeft: MaxCPPExpandedStatesPerLine}
	all, terms := ExpandCPPStatesWithBudget(line, defs, "", "", 0, budget)
	if budget.Overflow {
		return nil, "", true
	}
	prim := line
	if len(terms) > 0 {
		prim = terms[0]
	}
	return all, prim, false
}

// UnquotedParenBalance returns the net open-parenthesis depth outside string/char literals.
func UnquotedParenBalance(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"', '\'':
			i = SkipQuotedLiteral(s, i) - 1
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

// TrailingFuncMacroIdentMode reports whether s ends with the name of a function-like macro in defs.
func TrailingFuncMacroIdentMode(s string, defs map[string][]MacroDef, asmIdentMode bool) bool {
	if len(defs) == 0 {
		return false
	}
	end := len(s)
	for end > 0 && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	start := end
	for start > 0 && IsASCIIIdentByte(s[start-1]) {
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
		if d.HasParams {
			return true
		}
	}
	return false
}
