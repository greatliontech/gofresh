package cprep

import (
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// AllowedPureAsmStandardHeaders lists the standard Go assembler headers
// provided by GOROOT/pkg/include (plus compiler-generated go_asm.h) that an
// assembly file in a pure or pure-delegate package may #include.
var AllowedPureAsmStandardHeaders = map[string]bool{
	"asm_amd64.h":   true,
	"asm_ppc64x.h":  true,
	"asm_riscv64.h": true,
	"funcdata.h":    true,
	"go_asm.h":      true,
	"textflag.h":    true,
}

// AllowedPureAsmCrossPkgSymbols lists cross-package middle-dot symbol
// references permitted inside pure and pure-delegate assembly files beyond
// AllowedPureSingleArgLinknames.
var AllowedPureAsmCrossPkgSymbols = map[string]bool{
	"runtime.cmpstring":       true,
	"runtime.memequal":        true,
	"runtime.memequal_varlen": true,
	"runtime.memmove":         true,
}

// AllowedPureLinknameTargets lists the two-argument //go:linkname and
// //go:linknamestd targets permitted inside auditset.PurePackages() and its
// transitive pure delegates beyond a package's own self-links.
var AllowedPureLinknameTargets = map[string]bool{
	"runtime.cmpstring":                      true,
	"runtime.coroswitch":                     true,
	"runtime.divideError":                    true,
	"runtime.memequal":                       true,
	"runtime.memequal_varlen":                true,
	"runtime.newcoro":                        true,
	"runtime.overflowError":                  true,
	"crypto/internal/fips140hash.sha3Unwrap": true,
}

// AllowedPureSingleArgLinknames lists the one-argument //go:linkname and
// //go:linknamestd directives permitted inside auditset.PurePackages() and its
// transitive pure delegates.
var AllowedPureSingleArgLinknames = map[string]bool{
	"bytes.Compare":                          true,
	"bytes.Equal":                            true,
	"bytes.IndexByte":                        true,
	"bytes.Repeat":                           true,
	"bytes.explode":                          true,
	"crypto/internal/fips140hash.sha3Unwrap": true,
	"crypto/subtle.setDITDisabled":           true,
	"crypto/subtle.setDITEnabled":            true,
	"internal/cpu.ARM":                       true,
	"internal/cpu.ARM64":                     true,
	"internal/cpu.HWCap":                     true,
	"internal/cpu.Loong64":                   true,
	"internal/cpu.MIPS64X":                   true,
	"internal/cpu.PPC64":                     true,
	"internal/cpu.RISCV64":                   true,
	"internal/cpu.S390X":                     true,
	"internal/cpu.X86":                       true,
	"internal/cpu.isProcessorFeaturePresent": true,
	"internal/cpu.riscvHWProbe":              true,
	"internal/cpu.sysctlEnabled":             true,
	"internal/race.Acquire":                  true,
	"internal/race.Disable":                  true,
	"internal/race.Enable":                   true,
	"internal/race.Errors":                   true,
	"internal/race.Read":                     true,
	"internal/race.ReadObjectPC":             true,
	"internal/race.ReadPC":                   true,
	"internal/race.ReadRange":                true,
	"internal/race.Release":                  true,
	"internal/race.ReleaseMerge":             true,
	"internal/race.Write":                    true,
	"internal/race.WriteObjectPC":            true,
	"internal/race.WritePC":                  true,
	"internal/race.WriteRange":               true,
	"math/big.addMulVVW":                     true,
	"math/big.addVV":                         true,
	"math/big.addVW":                         true,
	"math/big.mulAddVWW":                     true,
	"math/big.shlVU":                         true,
	"math/big.subVV":                         true,
	"math/big.subVW":                         true,
	"net/url.newError":                       true,
	"strconv.bsearch":                        true,
	"strings.IndexByte":                      true,
	"strings.clone":                          true,
	"strings.explode":                        true,
}

// AllowedAsmDirectiveKeywords lists the preprocessor directive keywords
// accepted by Go's assembler.
var AllowedAsmDirectiveKeywords = map[string]bool{
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

// StripAssemblyComments strips // and /* */ comments and optionally replaces
// string/char literals with spaces while folding backslash line continuations.
func StripAssemblyComments(src string, keepLiterals, joinContinuationWithSpace bool) string {
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
	return FoldAssemblyCommentContinuations(b.String(), joinContinuationWithSpace)
}

// FoldAssemblyCommentContinuations folds trailing backslash continuations that
// remain after comment stripping.
func FoldAssemblyCommentContinuations(s string, joinWithSpace bool) string {
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

// AsmPreprocessorOptions configures VerifyAssemblyPreprocessorPass for either
// standard-library or non-standard assembly verification.
type AsmPreprocessorOptions struct {
	NonStd             bool
	ReservedMacroName  func(string) bool
	AllowedCrossPkgSym func(string) bool
}

// VerifyAssemblyFile verifies a standard-library assembly file across both
// continuation-joining modes.
func VerifyAssemblyFile(pkgPath, name, src string, selectedHeaders map[string]bool) error {
	opts := AsmPreprocessorOptions{
		AllowedCrossPkgSym: func(target string) bool {
			return AllowedPureAsmCrossPkgSymbols[target] || AllowedPureSingleArgLinknames[target]
		},
	}
	if err := VerifyAssemblyPreprocessorPass(pkgPath, name, src, selectedHeaders, true, opts); err != nil {
		return err
	}
	if !strings.Contains(src, "\\") {
		return nil
	}
	return VerifyAssemblyPreprocessorPass(pkgPath, name, src, selectedHeaders, false, opts)
}

// VerifyAssemblyPreprocessorPass runs a single preprocessor verification pass
// over an assembly or header file, checking directive syntax, #include paths,
// #define shadowing, and middle-dot / forbidden token rules.
func VerifyAssemblyPreprocessorPass(pkgPath, name, src string, selectedHeaders map[string]bool, joinContinuationWithSpace bool, opts AsmPreprocessorOptions) error {
	isHeader := pkgPath == "" || strings.EqualFold(filepath.Ext(name), ".h")
	noComments := StripAssemblyComments(src, true, joinContinuationWithSpace)
	rawLines := strings.Split(noComments, "\n")
	definedMacros := map[string]bool{}
	condDepth := 0
	for _, rawLine := range rawLines {
		kw, rest, isDir := CutDirectiveKeyword(rawLine)
		if !isDir {
			continue
		}
		if !AllowedAsmDirectiveKeywords[kw] {
			return fmt.Errorf("%s/%s: unsupported preprocessor directive in assembly", pkgPath, name)
		}
		if opts.NonStd {
			switch kw {
			case "if", "ifdef", "ifndef":
				condDepth++
				continue
			case "elif", "else":
				if condDepth <= 0 {
					return fmt.Errorf("%s/%s: unmatched #%s", pkgPath, name, kw)
				}
				continue
			case "endif":
				if condDepth <= 0 {
					return fmt.Errorf("%s/%s: unmatched #endif", pkgPath, name)
				}
				condDepth--
				continue
			case "undef":
				uRest := strings.TrimSpace(rest)
				uName := LeadingASCIIIdent(uRest)
				if uName == "" || strings.TrimSpace(uRest[len(uName):]) != "" || (opts.ReservedMacroName != nil && opts.ReservedMacroName(uName)) {
					return fmt.Errorf("%s/%s: forbidden or malformed #undef %q", pkgPath, name, uRest)
				}
				continue
			}
		}
		if kw == "define" {
			macroName, def, afterMacroName, ok := ParseDefineRest(rest)
			if macroName == "" {
				return fmt.Errorf("%s/%s: malformed #define in assembly", pkgPath, name)
			}
			if opts.NonStd {
				if (opts.ReservedMacroName != nil && opts.ReservedMacroName(macroName)) ||
					(afterMacroName != "" && afterMacroName[0] != '(' && afterMacroName[0] != ' ' && afterMacroName[0] != '\t') {
					return fmt.Errorf("%s/%s: malformed or reserved #define %q", pkgPath, name, macroName)
				}
			}
			macroBody := def.Body
			if !ok && def.HasParams {
				macroBody = afterMacroName
			}
			if pkgPath != "" && (macroName == pkgPath || slices.Contains(strings.Split(pkgPath, "/"), macroName) || strings.Contains(pkgPath, "/"+macroName) || strings.HasPrefix(pkgPath, macroName+"/")) {
				return fmt.Errorf("%s/%s: #define %s shadows package path", pkgPath, name, macroName)
			}
			if isHeader && !def.HasParams && strings.TrimSpace(macroBody) != "" && macroName[0] >= 'a' && macroName[0] <= 'z' {
				return fmt.Errorf("%s/%s: header #define %s shadows lowercase package identifier", pkgPath, name, macroName)
			}
			definedMacros[macroName] = true
			continue
		}
		if kw != "include" {
			continue
		}
		incArg := strings.TrimSpace(rest)
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
		if !AllowedPureAsmStandardHeaders[hdr] && !selectedHeaders[hdr] {
			return fmt.Errorf("%s/%s: unapproved #include %q in assembly", pkgPath, name, hdr)
		}
	}
	if opts.NonStd && condDepth != 0 {
		return fmt.Errorf("%s/%s: unterminated conditional directive", pkgPath, name)
	}

	for _, rawLine := range rawLines {
		line := BlankQuotedLiterals(rawLine)
		trimmedClean := strings.TrimSpace(line)
		isDirectiveLine := strings.HasPrefix(trimmedClean, "#")
		if strings.Contains(trimmedClean, "#") && (!isDirectiveLine || strings.Contains(trimmedClean[1:], "#")) {
			return fmt.Errorf("%s/%s: unexpected '#' in assembly", pkgPath, name)
		}
		scanLine := line
		var macroParams map[string]bool
		isObjectDefine := false
		if isDirectiveLine {
			kw, rest, _ := CutDirectiveKeyword(trimmedClean)
			if kw == "define" && (rest == "" || rest[0] == ' ' || rest[0] == '\t') {
				_, def, rawAfterName, ok := ParseDefineRest(rest)
				if def.HasParams {
					if !ok {
						return fmt.Errorf("%s/%s: malformed function-like #define in assembly", pkgPath, name)
					}
					macroParams = map[string]bool{}
					closeIdx := strings.IndexByte(rawAfterName, ')')
					for _, p := range strings.Split(rawAfterName[1:closeIdx], ",") {
						p = strings.TrimSpace(p)
						if p != "" {
							macroParams[p] = true
						}
					}
					scanLine = rawAfterName[closeIdx+1:]
				} else {
					isObjectDefine = true
					scanLine = rawAfterName
				}
			}
		}
		if !opts.NonStd && isObjectDefine {
			trimmedBody := strings.TrimSpace(scanLine)
			lastSpace := strings.LastIndexAny(trimmedBody, " \t")
			if lastSpace > 0 {
				beforeLast := strings.TrimRight(trimmedBody[:lastSpace], " \t")
				lastTok := trimmedBody[lastSpace+1:]
				if len(beforeLast) > 0 && IsAsmWordRune(rune(beforeLast[len(beforeLast)-1])) &&
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
		stmtWordIdx := 0
		prevWord := ""
		for i := 0; i < len(scanLine); {
			if scanLine[i] == ';' {
				stmtWordIdx = 0
				prevWord = ""
				i++
				continue
			}
			end, hasMiddleDot, ok := ScanAsmWordToken(scanLine, i)
			if !ok {
				i++
				continue
			}
			start := i
			rawTok := scanLine[start:end]
			i = end

			back := start
			for back > 0 && (scanLine[back-1] == ' ' || scanLine[back-1] == '\t' || scanLine[back-1] == '\r') {
				back--
			}
			prevNonSpace := rune(0)
			if back > 0 {
				if scanLine[back-1] < 0x80 {
					prevNonSpace = rune(scanLine[back-1])
				} else {
					prevNonSpace, _ = utf8.DecodeLastRuneInString(scanLine[:back])
				}
			}
			if hasMiddleDot {
				if strings.HasSuffix(rawTok, "·") || strings.HasPrefix(rawTok, "/") || strings.HasPrefix(rawTok, "∕") ||
					prevNonSpace == '/' || prevNonSpace == '∕' || prevNonSpace == ')' ||
					strings.HasSuffix(prevWord, "/") || strings.HasSuffix(prevWord, "∕") {
					return fmt.Errorf("%s/%s: split middle-dot symbol %s in assembly", pkgPath, name, rawTok)
				}
				if (isObjectDefine || macroParams != nil) && strings.HasPrefix(rawTok, "·") && prevNonSpace == 0 {
					return fmt.Errorf("%s/%s: macro body starts with middle-dot symbol %s in assembly", pkgPath, name, rawTok)
				}
				if strings.HasPrefix(rawTok, "·") && IsAsmWordRune(prevNonSpace) {
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
						if opts.AllowedCrossPkgSym == nil || !opts.AllowedCrossPkgSym(target) {
							return fmt.Errorf("%s/%s: unapproved cross-package assembly symbol %s", pkgPath, name, rawTok)
						}
					}
				}
				if !opts.NonStd {
					stmtWordIdx++
					prevWord = rawTok
					continue
				}
			}
			if isObjectDefine || macroParams != nil {
				switch rawTok {
				case "runtime", "syscall", "os", "internal":
					if !macroParams[rawTok] {
						return fmt.Errorf("%s/%s: forbidden package token %s in #define", pkgPath, name, rawTok)
					}
				}
			}
			if !opts.NonStd {
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
					rest := strings.TrimSpace(scanLine[i:])
					if rawTok == "INT" || strings.HasPrefix(rest, "$") {
						return fmt.Errorf("%s/%s: assembly file contains software interrupt instruction", pkgPath, name)
					}
				}
			}
			stmtWordIdx++
			prevWord = rawTok
		}
	}
	return nil
}
