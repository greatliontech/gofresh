package cprep

import (
	"slices"
	"strings"
)

func collectCStringSymbolRefs(s, selfPkg string, runtimeOut, externalOut, identOut map[string]bool) {
	if (runtimeOut == nil && externalOut == nil && identOut == nil) || strings.IndexByte(s, '"') < 0 {
		return
	}
	recordTarget := func(pkgPrefix, sym string) {
		if pkgPrefix == "" || sym == "" {
			return
		}
		if pkgPrefix == "runtime" {
			base := LeadingASCIIIdent(sym)
			if base != "" && runtimeOut != nil {
				runtimeOut["runtime."+base] = true
			}
		} else if externalOut != nil && pkgPrefix != selfPkg {
			externalOut[pkgPrefix+"."+sym] = true
		}
	}
	isSymRunByte := func(c byte) bool {
		return IsASCIIIdentByte(c) || c == '/' || c == '.' || c == '-' || c == '%'
	}
	for i := 0; i < len(s); {
		if s[i] == '\'' {
			i = SkipQuotedLiteral(s, i)
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
			CollectRuntimeIdentsAndMachOString(body, identOut)
			if unescBody := unescapeObjabiToken(body); unescBody != body {
				CollectRuntimeIdentsAndMachOString(unescBody, identOut)
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
					tIdent := LeadingASCIIIdent(body[j+2:])
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
				pkgPrefix, symPart, ok := SplitLinknameTarget(tok)
				if !ok {
					continue
				}
				pkgPrefix = unescapeObjabiToken(strings.TrimLeft(pkgPrefix, "./"))
				symPart = unescapeObjabiToken(symPart)
				var syms []string
				if strings.HasPrefix(symPart, "(*") {
					tIdent := LeadingASCIIIdent(symPart[2:])
					afterType := 2 + len(tIdent)
					if tIdent != "" && strings.HasPrefix(symPart[afterType:], ").") {
						mIdent := LeadingASCIIIdent(symPart[afterType+2:])
						if mIdent != "" {
							syms = append(syms, tIdent, tIdent+"."+mIdent)
						}
					}
				} else if first := LeadingASCIIIdent(symPart); first != "" {
					syms = append(syms, first)
					if len(symPart) > len(first) && symPart[len(first)] == '.' {
						if second := LeadingASCIIIdent(symPart[len(first)+1:]); second != "" {
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
	candidates := [2]string{text}
	numCandidates := 1
	if cNorm := NormalizeCStringLiterals(text, true); cNorm != text {
		candidates[1] = cNorm
		numCandidates = 2
	}
	for cIdx := 0; cIdx < numCandidates; cIdx++ {
		cand := candidates[cIdx]
		if identOut != nil {
			CollectRuntimeIdentsAndMachOString(cand, identOut)
		}
		if runtimeOut != nil {
			collectTextRuntimeSymbolRefs(cand, runtimeOut)
		}
		collectCStringSymbolRefs(cand, selfPkg, runtimeOut, externalOut, identOut)
		norm := collapseAsmMiddleDotAndSlashSpaces(cand)
		if norm != cand {
			if identOut != nil {
				CollectRuntimeIdentsAndMachOString(norm, identOut)
			}
			if runtimeOut != nil {
				collectTextRuntimeSymbolRefs(norm, runtimeOut)
			}
			collectCStringSymbolRefs(norm, selfPkg, runtimeOut, externalOut, identOut)
		}
		if !strings.Contains(norm, "·") {
			continue
		}
		for i := 0; i < len(norm); {
			end, hasMiddleDot, ok := scanAsmWordToken(norm, i)
			if !ok {
				i++
				continue
			}
			tok := norm[i:end]
			i = end
			if !hasMiddleDot {
				continue
			}
			pkgPrefix, symPart, _ := strings.Cut(tok, "·")
			pkgPrefix = strings.TrimLeft(pkgPrefix, "./")
			basePart, _, _ := strings.Cut(symPart, "<")
			baseSym := LeadingASCIIIdent(basePart)
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
					if secondSym := LeadingASCIIIdent(afterDot); secondSym != "" {
						externalOut[pkgPrefix+"."+baseSym+"."+secondSym] = true
					}
				}
			}
		}
	}
}

func collectExportedMacrosFromText(cleaned string, baseDefs, outDefs map[string][]MacroDef, baseUndefs, outUndefs map[string]bool) bool {
	cur := map[string][]MacroDef{}
	condDepth := 0
	sawInclude := false
	for _, rawLine := range strings.Split(cleaned, "\n") {
		line := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(line, "#") {
			continue
		}
		kw, rest, ok := CutDirectiveKeyword(line)
		if !ok {
			continue
		}
		switch kw {
		case "define":
			if name, def, _, okD := ParseDefineRest(rest); okD && name != "" {
				wasEmpty := len(cur[name]) == 0
				AppendMacroDefUnique(cur, name, def)
				if wasEmpty && condDepth > 0 {
					EnsureMacroIdentityChoice(cur, name)
				}
			}
		case "undef":
			if name := LeadingASCIIIdent(strings.TrimSpace(rest)); name != "" {
				outUndefs[name] = true
				if condDepth == 0 {
					delete(cur, name)
				} else if len(cur[name]) > 0 {
					EnsureMacroIdentityChoice(cur, name)
				}
			}
		case "include", "include_next":
			sawInclude = true
			for name, list := range baseDefs {
				wasEmpty := len(cur[name]) == 0
				for _, d := range list {
					AppendMacroDefUnique(cur, name, d)
				}
				if wasEmpty {
					EnsureMacroIdentityChoice(cur, name)
				}
			}
			for uName := range baseUndefs {
				if len(cur[uName]) > 0 {
					EnsureMacroIdentityChoice(cur, uName)
				}
			}
		case "if", "ifdef", "ifndef":
			condDepth++
		case "endif":
			if condDepth > 0 {
				condDepth--
			}
		}
	}
	for name, list := range cur {
		for _, def := range list {
			AppendMacroDefUnique(outDefs, name, def)
		}
	}
	return sawInclude
}

func scanCleanedNonGoText(cleaned, selfPkg string, baseDefs map[string][]MacroDef, baseUndefs, runtimeOut, externalOut, identOut map[string]bool) bool {
	activeDefs := map[string][]MacroDef{}
	rawLines := strings.Split(cleaned, "\n")
	expandedLines := make([]string, 0, len(rawLines))
	var nonDirective strings.Builder
	var pending string
	condDepth := 0

	expandAndExtract := func(line string) bool {
		if line == "" {
			return false
		}
		extractExpandedLineSymbols(line, selfPkg, runtimeOut, externalOut, identOut)
		if len(activeDefs) == 0 {
			expandedLines = append(expandedLines, line)
			return false
		}
		states, primary, expOverflow := expandCPPLineAllChoices(line, activeDefs)
		if expOverflow {
			return true
		}
		expandedLines = append(expandedLines, primary)
		for _, st := range states {
			if st != line {
				extractExpandedLineSymbols(st, selfPkg, runtimeOut, externalOut, identOut)
			}
		}
		return false
	}

	flushPending := func() bool {
		if pending == "" {
			return false
		}
		line := pending
		pending = ""
		return expandAndExtract(line)
	}

	for idx := 0; idx < len(rawLines); idx++ {
		line := strings.TrimSpace(rawLines[idx])
		if line == "" {
			continue
		}
		if len(line) > MaxNonGoLogicalLineBytes {
			return true
		}
		if strings.HasPrefix(line, "#") {
			if flushPending() {
				return true
			}
			kw, rest, ok := CutDirectiveKeyword(line)
			if !ok {
				continue
			}
			switch kw {
			case "define":
				if name, def, _, okD := ParseDefineRest(rest); okD && name != "" {
					if def.Body != "" && expandAndExtract(def.Body) {
						return true
					}
					wasEmpty := len(activeDefs[name]) == 0
					AppendMacroDefUnique(activeDefs, name, def)
					if wasEmpty && condDepth > 0 {
						EnsureMacroIdentityChoice(activeDefs, name)
					}
				}
			case "undef":
				if name := LeadingASCIIIdent(strings.TrimSpace(rest)); name != "" {
					if condDepth == 0 {
						delete(activeDefs, name)
					} else if len(activeDefs[name]) > 0 {
						EnsureMacroIdentityChoice(activeDefs, name)
					}
				}
			case "include", "include_next":
				for name, list := range baseDefs {
					wasEmpty := len(activeDefs[name]) == 0
					for _, d := range list {
						AppendMacroDefUnique(activeDefs, name, d)
					}
					if wasEmpty {
						EnsureMacroIdentityChoice(activeDefs, name)
					}
				}
				for uName := range baseUndefs {
					if len(activeDefs[uName]) > 0 {
						EnsureMacroIdentityChoice(activeDefs, uName)
					}
				}
			case "if", "ifdef", "ifndef":
				condDepth++
			case "endif":
				if condDepth > 0 {
					condDepth--
				}
			}
			continue
		}
		nonDirective.WriteString(line)
		nonDirective.WriteByte('\n')
		if pending == "" {
			pending = line
		} else if len(pending)+1+len(line) <= MaxNonGoLogicalLineBytes {
			pending = pending + " " + line
		} else {
			return true
		}
		if UnquotedParenBalance(pending) > 0 {
			continue
		}
		if TrailingFuncMacroIdentMode(pending, activeDefs, false) {
			peek := idx + 1
			for peek < len(rawLines) && strings.TrimSpace(rawLines[peek]) == "" {
				peek++
			}
			if peek < len(rawLines) && strings.HasPrefix(strings.TrimSpace(rawLines[peek]), "(") {
				continue
			}
		}
		if flushPending() {
			return true
		}
	}
	if flushPending() {
		return true
	}
	if nonDirective.Len() > 0 {
		extractExpandedLineSymbols(nonDirective.String(), selfPkg, runtimeOut, externalOut, identOut)
	}
	if len(expandedLines) > 1 {
		extractExpandedLineSymbols(strings.Join(expandedLines, "\n"), selfPkg, runtimeOut, externalOut, identOut)
	}
	return false
}

// ScanPreprocessedNonGoSymbolRefs preprocesses C/assembly headers and sources
// and collects runtime, cross-package, and identifier references.
func ScanPreprocessedNonGoSymbolRefs(selfPkg string, includeHeaders, pkgTexts []string, runtimeOut, externalOut, identOut map[string]bool) bool {
	var prevStrippedHdrs []string
	var prevCleanedTexts []string
	for passIdx, joinSpace := range []bool{false, true} {
		strippedHdrs := make([]string, len(includeHeaders))
		for idx, hdr := range includeHeaders {
			strippedHdrs[idx] = StripAssemblyComments(hdr, true, joinSpace)
		}
		cleanedTexts := make([]string, len(pkgTexts))
		for idx, txt := range pkgTexts {
			cleanedTexts[idx] = StripAssemblyComments(txt, true, joinSpace)
		}
		if passIdx > 0 && slices.Equal(strippedHdrs, prevStrippedHdrs) && slices.Equal(cleanedTexts, prevCleanedTexts) {
			continue
		}
		prevStrippedHdrs = strippedHdrs
		prevCleanedTexts = cleanedTexts

		baseDefs := map[string][]MacroDef{}
		baseUndefs := map[string]bool{}
		countMacroState := func(m map[string][]MacroDef, u map[string]bool) int {
			n := len(u)
			for _, list := range m {
				n += len(list)
			}
			return n
		}
		for {
			before := countMacroState(baseDefs, baseUndefs)
			sawInc := false
			for _, stripped := range strippedHdrs {
				if collectExportedMacrosFromText(stripped, baseDefs, baseDefs, baseUndefs, baseUndefs) {
					sawInc = true
				}
			}
			if !sawInc || countMacroState(baseDefs, baseUndefs) == before {
				break
			}
		}
		for _, cleaned := range cleanedTexts {
			if scanCleanedNonGoText(cleaned, selfPkg, baseDefs, baseUndefs, runtimeOut, externalOut, identOut) {
				return true
			}
		}
	}
	return false
}
