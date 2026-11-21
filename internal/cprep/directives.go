package cprep

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/greatliontech/gofresh/internal/auditset"
)

// ParseGoLinknameLineFields parses a single-line //go:linkname or
// //go:linknamestd directive line, returning its whitespace-split fields
// (length 2 or 3) when the directive keyword is bounded by ASCII space or tab.
func ParseGoLinknameLineFields(line string) ([]string, bool) {
	_, plain := auditset.BoundedToken(line, "//go:linkname", " \t")
	_, std := auditset.BoundedToken(line, "//go:linknamestd", " \t")
	if !plain && !std {
		return nil, false
	}
	fields := strings.Fields(line)
	if len(fields) != 2 && len(fields) != 3 {
		return nil, false
	}
	return fields, true
}

// ParseGoLinknameDirectiveComment parses a single Go comment token's raw Text
// (`//...` or `/*...*/`) for a `go:linkname` or `go:linknamestd` compiler
// directive. Go compiler directives require zero whitespace between `//` (or
// `/*`) and `go:`; `// go:linkname ...` with leading whitespace is an ordinary
// prose comment ignored by cmd/compile (`matched == false`).
//
// When the directive token matches (`matched == true`), `valid` reports whether
// the directive obeys the 1-argument (`local`) or 2-argument (`local pkg.sym`
// with an interior dot in the second argument) single-line ASCII grammar; 0 or
// >2 fields, multi-line block comments, non-ASCII separators, or a dotless
// second argument yield `matched = true, valid = false`.
func ParseGoLinknameDirectiveComment(text string) (local, target string, matched, valid bool) {
	var body string
	if line, ok := strings.CutPrefix(text, "//"); ok {
		body = line
	} else if block, ok := strings.CutPrefix(text, "/*"); ok {
		block, okSuffix := strings.CutSuffix(block, "*/")
		if !okSuffix {
			return "", "", false, false
		}
		if strings.Contains(block, "*/") {
			_, okP := auditset.BoundedToken(block, "go:linkname", " \t\r\n*")
			_, okS := auditset.BoundedToken(block, "go:linknamestd", " \t\r\n*")
			return "", "", okP || okS, false
		}
		body = block
	} else {
		return "", "", false, false
	}

	restPlain, okPlain := auditset.BoundedToken(body, "go:linkname", " \t\r\n")
	restStd, okStd := auditset.BoundedToken(body, "go:linknamestd", " \t\r\n")
	if !okPlain && !okStd {
		return "", "", false, false
	}
	rest := restPlain
	if okStd {
		rest = restStd
	}
	// Restrict separators to ASCII space and tab so non-ASCII Unicode
	// whitespace never splits directive fields differently from the byte-bound
	// directive floor.
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '\v', '\f', '\r', '\n':
			return "", "", true, false
		}
	}
	fields := strings.FieldsFunc(rest, func(r rune) bool {
		return r == ' ' || r == '\t'
	})
	// If any field still contains Unicode whitespace that strings.Fields would
	// split on, treat it as malformed.
	for _, f := range fields {
		if len(strings.Fields(f)) != 1 {
			return "", "", true, false
		}
	}
	switch len(fields) {
	case 1:
		if !token.IsIdentifier(fields[0]) {
			return "", "", true, false
		}
		return fields[0], "", true, true
	case 2:
		if !token.IsIdentifier(fields[0]) {
			return "", "", true, false
		}
		dot := strings.LastIndexByte(fields[1], '.')
		if dot <= 0 || dot+1 >= len(fields[1]) {
			return "", "", true, false
		}
		return fields[0], fields[1], true, true
	default:
		return "", "", true, false
	}
}

// ForEachGoLinknameDirective visits every //go:linkname or /*go:linkname...*/
// compiler directive across groups.
func ForEachGoLinknameDirective(groups []*ast.CommentGroup, visit func(local, target string, valid bool)) {
	if visit == nil {
		return
	}
	for _, cg := range groups {
		if cg == nil {
			continue
		}
		for _, c := range cg.List {
			if c == nil || !strings.Contains(c.Text, "go:linkname") {
				continue
			}
			local, target, matched, valid := ParseGoLinknameDirectiveComment(c.Text)
			if matched {
				visit(local, target, valid)
			}
		}
	}
}

// HasRawGoLinkname reports whether text contains a line or block go:linkname
// directive prefix.
func HasRawGoLinkname(text string) bool {
	return strings.Contains(text, "//go:linkname") || strings.Contains(text, "/*go:linkname")
}

// IsWasmImportComment reports whether a raw Go comment token text (`//...` or
// `/*...*/`) carries a `go:wasmimport` compiler directive.
func IsWasmImportComment(text string) bool {
	if line, ok := strings.CutPrefix(text, "//"); ok {
		_, okTok := auditset.BoundedToken(line, "go:wasmimport", " \t\r\n")
		return okTok
	}
	if block, ok := strings.CutPrefix(text, "/*"); ok {
		if block, okSuf := strings.CutSuffix(block, "*/"); okSuf {
			_, okTok := auditset.BoundedToken(block, "go:wasmimport", " \t\r\n")
			return okTok
		}
	}
	return false
}
