// Package cprep implements a deterministic C and Go-assembler preprocessor,
// Cgo preamble extractor, and non-Go symbol reference scanner.
package cprep

import (
	"bytes"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SplitLinknameTarget splits a fully qualified package.symbol linkname target.
func SplitLinknameTarget(target string) (pkgPath, sym string, ok bool) {
	slash := strings.LastIndexByte(target, '/')
	dotRel := strings.IndexByte(target[slash+1:], '.')
	if dotRel <= 0 {
		return "", "", false
	}
	dot := slash + 1 + dotRel
	pkgPath = target[:dot]
	sym = target[dot+1:]
	if sym == "" {
		return "", "", false
	}
	return pkgPath, sym, true
}

// IsASCIIIdentByte reports whether b is an ASCII identifier continuation byte.
func IsASCIIIdentByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

// LeadingASCIIIdent returns the leading ASCII identifier prefix of s, or "" if
// s does not start with a non-digit ASCII identifier character.
func LeadingASCIIIdent(s string) string {
	if len(s) == 0 || !IsASCIIIdentByte(s[0]) || (s[0] >= '0' && s[0] <= '9') {
		return ""
	}
	end := 1
	for end < len(s) && IsASCIIIdentByte(s[end]) {
		end++
	}
	return s[:end]
}

// CutDirectiveKeyword checks whether line is a preprocessor directive
// (starting with '#' after optional whitespace) and returns its leading ASCII
// directive keyword along with the unparsed remainder immediately following the
// keyword.
func CutDirectiveKeyword(line string) (kw, rest string, isDirective bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	dRest := strings.TrimSpace(trimmed[1:])
	kw = LeadingASCIIIdent(dRest)
	return kw, dRest[len(kw):], true
}

// SkipQuotedLiteralChecked advances past a quoted literal (starting at s[idx]
// where s[idx] is '"', '\'', or '`') and returns the index immediately after
// the closing quote alongside whether a closing quote was found. Backslash
// escapes are respected for '"' and '\'' literals.
func SkipQuotedLiteralChecked(s string, idx int) (int, bool) {
	if idx >= len(s) {
		return idx, false
	}
	q := s[idx]
	idx++
	if q == '`' {
		for idx < len(s) {
			if s[idx] == '`' {
				return idx + 1, true
			}
			idx++
		}
		return idx, false
	}
	for idx < len(s) {
		if s[idx] == '\\' && idx+1 < len(s) {
			idx += 2
			continue
		}
		if s[idx] == q {
			return idx + 1, true
		}
		idx++
	}
	return idx, false
}

// SkipQuotedLiteral advances past a quoted literal (starting at s[idx] where
// s[idx] is '"', '\'', or '`') and returns the index immediately after the
// closing quote (or len(s) if unterminated).
func SkipQuotedLiteral(s string, idx int) int {
	next, _ := SkipQuotedLiteralChecked(s, idx)
	return next
}

// BlankQuotedLiterals replaces each double- or single-quoted literal in s with
// a single space byte. When s contains no quote characters, s is returned
// without allocation.
func BlankQuotedLiterals(s string) string {
	if strings.IndexByte(s, '"') < 0 && strings.IndexByte(s, '\'') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '"' || s[i] == '\'' {
			q := s[i]
			b.WriteByte(' ')
			i++
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				if s[i] == q {
					i++
					break
				}
				if s[i] == '\n' {
					break
				}
				i++
			}
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// ScanIdentToken scans an identifier starting at s[pos]. When asmIdentMode is
// false, standard C/ASCII identifier rules apply ([A-Za-z_][A-Za-z0-9_]*).
// When asmIdentMode is true, cmd/asm's tokenizer rules apply
// (cmd/asm/internal/lex/tokenizer.go:isIdentRune), treating UTF-8 middle-dot
// '·' (U+00B7), division-slash '∕' (U+2215), and Unicode letters/digits as
// part of a single identifier token so #define Evil Safe never rewrites ·Evil.
func ScanIdentToken(s string, pos int, asmIdentMode bool) (int, bool) {
	if pos >= len(s) {
		return pos, false
	}
	if !asmIdentMode {
		if !IsASCIIIdentByte(s[pos]) || (s[pos] >= '0' && s[pos] <= '9') {
			return pos, false
		}
		end := pos + 1
		for end < len(s) && IsASCIIIdentByte(s[end]) {
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

// IsAsmWordRune reports whether r is a word rune in Plan 9 assembly syntax.
func IsAsmWordRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
		r == '_' || r == '.' || r == '·' || r == '/' || r == '∕' || r == '<' || r == '>'
}

// NextAsmWordRune decodes a Plan 9 assembly word rune starting at s[pos]
// without converting s to []rune.
func NextAsmWordRune(s string, pos int) (rune, int, bool) {
	if pos >= len(s) {
		return 0, 0, false
	}
	b := s[pos]
	if b < 0x80 {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') ||
			b == '_' || b == '.' || b == '/' || b == '<' || b == '>' {
			return rune(b), 1, true
		}
		return 0, 0, false
	}
	if b == 0xC2 && pos+1 < len(s) && s[pos+1] == 0xB7 {
		return '·', 2, true
	}
	if b == 0xE2 && pos+2 < len(s) && s[pos+1] == 0x88 && s[pos+2] == 0x95 {
		return '∕', 3, true
	}
	return 0, 0, false
}

// ScanAsmWordToken scans a contiguous Plan 9 assembly word token starting at
// s[pos], returning its end byte index and whether the token contains '·'.
func ScanAsmWordToken(s string, pos int) (end int, hasMiddleDot bool, ok bool) {
	r, w, ok := NextAsmWordRune(s, pos)
	if !ok {
		return pos, false, false
	}
	hasMiddleDot = r == '·'
	end = pos + w
	for end < len(s) {
		nr, nw, nok := NextAsmWordRune(s, end)
		if !nok {
			break
		}
		if nr == '·' {
			hasMiddleDot = true
		}
		end += nw
	}
	return end, hasMiddleDot, true
}

// CollectAllASCIIIdents records every contiguous ASCII identifier token in raw.
func CollectAllASCIIIdents(raw []byte, out map[string]bool) {
	for i := 0; i < len(raw); {
		if !IsASCIIIdentByte(raw[i]) {
			i++
			continue
		}
		start := i
		for i < len(raw) && IsASCIIIdentByte(raw[i]) {
			i++
		}
		out[string(raw[start:i])] = true
	}
}

// CollectRawBytesRuntimeSymbolRefs scans raw bytes for runtime.X and runtime·X symbol references.
func CollectRawBytesRuntimeSymbolRefs(raw []byte, out map[string]bool) {
	if out == nil || !bytes.Contains(raw, []byte("runtime")) {
		return
	}
	CollectTextRuntimeSymbolRefs(string(raw), out)
}

// CollectTextRuntimeSymbolRefs scans text for runtime.X and runtime·X symbol references.
func CollectTextRuntimeSymbolRefs(text string, out map[string]bool) {
	if out == nil || !strings.Contains(text, "runtime") {
		return
	}
	for _, prefix := range []string{"runtime.", "runtime\xc2\xb7"} {
		idx := 0
		for idx < len(text) {
			pos := strings.Index(text[idx:], prefix)
			if pos < 0 {
				break
			}
			start := idx + pos + len(prefix)
			end := start
			for end < len(text) && IsASCIIIdentByte(text[end]) {
				end++
			}
			if end > start {
				out["runtime."+text[start:end]] = true
			}
			idx = max(start, idx+pos+1)
		}
	}
}

// CollectRuntimeIdentsAndMachO scans data for ASCII identifiers and Mach-O leading-underscore variants.
func CollectRuntimeIdentsAndMachO(data []byte, identOut map[string]bool) {
	if identOut == nil || len(data) == 0 {
		return
	}
	CollectRuntimeIdentsAndMachOString(string(data), identOut)
}

// CollectRuntimeIdentsAndMachOString scans s for ASCII identifiers and Mach-O leading-underscore variants.
func CollectRuntimeIdentsAndMachOString(s string, identOut map[string]bool) {
	if identOut == nil || len(s) == 0 {
		return
	}
	for i := 0; i < len(s); {
		if !IsASCIIIdentByte(s[i]) {
			i++
			continue
		}
		start := i
		for i < len(s) && IsASCIIIdentByte(s[i]) {
			i++
		}
		id := s[start:i]
		identOut[id] = true
		if id[0] == '_' {
			if trimmed := strings.TrimLeft(id, "_"); trimmed != "" && (trimmed[0] < '0' || trimmed[0] > '9') {
				identOut[trimmed] = true
			}
		}
	}
}

// CollapseAsmMiddleDotAndSlashSpaces normalizes whitespace around Plan 9 middle-dot and slash separators.
func CollapseAsmMiddleDotAndSlashSpaces(s string) string {
	if !strings.Contains(s, "∕") && !strings.Contains(s, "·") && strings.IndexByte(s, '/') < 0 {
		return s
	}
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
		for end < len(rest) && IsASCIIIdentByte(rest[end]) {
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
