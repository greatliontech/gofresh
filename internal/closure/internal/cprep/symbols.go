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
			CollectTextRuntimeSymbolRefs(cand, runtimeOut)
		}
		collectCStringSymbolRefs(cand, selfPkg, runtimeOut, externalOut, identOut)
		norm := CollapseAsmMiddleDotAndSlashSpaces(cand)
		if norm != cand {
			if identOut != nil {
				CollectRuntimeIdentsAndMachOString(norm, identOut)
			}
			if runtimeOut != nil {
				CollectTextRuntimeSymbolRefs(norm, runtimeOut)
			}
			collectCStringSymbolRefs(norm, selfPkg, runtimeOut, externalOut, identOut)
		}
		if !strings.Contains(norm, "·") {
			continue
		}
		for i := 0; i < len(norm); {
			end, hasMiddleDot, ok := ScanAsmWordToken(norm, i)
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

func buildLogicalNonGoScanLines(cleaned string, defs map[string][]MacroDef) ([]string, string, bool) {
	rawLines := strings.Split(cleaned, "\n")
	out := make([]string, 0, len(rawLines))
	var nonDirective strings.Builder
	var pending string
	for idx := 0; idx < len(rawLines); idx++ {
		line := strings.TrimSpace(rawLines[idx])
		if line == "" {
			continue
		}
		if len(line) > MaxNonGoLogicalLineBytes {
			return nil, "", true
		}
		if strings.HasPrefix(line, "#") {
			if pending != "" {
				out = append(out, pending)
				pending = ""
			}
			if _, def, _, ok := ParseDefineDirective(line); ok && def.Body != "" {
				out = append(out, def.Body)
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
			return nil, "", true
		}
		if UnquotedParenBalance(pending) > 0 {
			continue
		}
		if TrailingFuncMacroIdentMode(pending, defs, false) {
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

		defs := map[string][]MacroDef{}
		for _, stripped := range strippedHdrs {
			CollectCPPMacrosFromText(stripped, defs)
		}
		for _, cleaned := range cleanedTexts {
			CollectCPPMacrosFromText(cleaned, defs)
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
				states, primary, expOverflow := ExpandCPPLineAllChoices(line, defs)
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
