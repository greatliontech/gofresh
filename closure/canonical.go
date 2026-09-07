package closure

import (
	"crypto/sha256"
	"fmt"
	"go/scanner"
	"go/token"
	"runtime"
	"strings"

	"github.com/greatliontech/gofresh/closure/internal/cachefile"
	"github.com/greatliontech/gofresh/closure/internal/digest"
	"github.com/greatliontech/gofresh/internal/generatedmark"
)

// A compiled Go member contributes its CANONICAL FORM to the closure
// fold, not its bytes: the syntax printed in one layout with every
// comment removed except the classes the toolchain or gofresh reads as
// behavior (REQ-closure-canonical-member). Whitespace, layout, and
// other comments reach the binary only as source positions, which the
// closure judgment rules diagnostics, not behavior — so a comment-only
// or gofmt-only edit leaves every downstream identity standing, while
// any token change, and any change to a retained comment, moves it. A
// member that does not scan folds its bytes: byte-sensitivity is the
// sound direction for text the scanner refuses.

// canonicalStrategy versions the canonical form: the retained comment
// classes, the scanner mode, the attachment rule. Any change that can
// move a member's canonical digest bumps it, so persisted digests from
// the prior form refuse instead of serving — and IdentityStrategy
// (closure.go) moves with it.
const canonicalStrategy = "gofresh/canonical-member@1"

// canonicalDirName is the canonical-digest memo's store directory.
const canonicalDirName = "canonical"

// retainedComment reports whether one comment line carries behavior:
// a directive-shaped comment (`//go:…`, `//gofresh:…`, any tool's
// `//<name>:…`), a cgo `//export`, a legacy `+build` constraint in any
// spelling go/build reads (vet's buildtag check fails the build when
// it disagrees with the `//go:build` line), or the generated-file
// marker. A `//line file:N`
// directive is not directive-shaped (its name is followed by a space,
// never a colon) and so falls out by the grammar: it remaps positions,
// which the form does not carry.
func retainedComment(text string) bool {
	if strings.HasPrefix(text, "//export ") || strings.HasPrefix(text, "//export\t") {
		return true
	}
	// go/build's rule: the comment's first field after `//` is `+build`,
	// whatever the spacing.
	if fields := strings.Fields(strings.TrimPrefix(text, "//")); len(fields) > 0 && fields[0] == "+build" {
		return true
	}
	if generatedmark.IsMarker(text) {
		return true
	}
	// A directive-shaped comment in either form: gofresh's analyzer
	// reads `go:linkname` out of block comments too, so a block comment
	// carrying a directive is retained exactly as a line comment is.
	rest, ok := strings.CutPrefix(text, "//")
	if !ok {
		rest, ok = strings.CutPrefix(text, "/*")
		if !ok {
			return false
		}
		rest = strings.TrimSpace(rest)
	}
	colon := strings.IndexByte(rest, ':')
	if colon <= 0 {
		return false
	}
	for _, r := range rest[:colon] {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// canonicalDigest derives one compiled Go member's canonical digest
// from its bytes: the token stream — each token's kind and literal —
// with comments dropped except the retained classes. Every semicolon
// stays, the scanner's automatically inserted ones spelled as the
// explicit one, because the stream with its semicolons determines the
// syntax tree (`x := y` then `(z)` on the next line and `x := y(z)`
// differ exactly by one), so equal forms are equal programs modulo
// positions; a gofmt reflow moves no semicolon, and a comment edit
// outside the retained classes adds no token. A retained comment rides
// the stream at its position, so a directive's attachment (which
// declaration it precedes) is part of the form. ok is false when the
// member does not scan — the caller folds the byte digest then.
func canonicalDigest(content []byte) (string, bool) {
	fset := token.NewFileSet()
	file := fset.AddFile("", -1, len(content))
	var sc scanner.Scanner
	failed := false
	sc.Init(file, content, func(token.Position, string) { failed = true }, scanner.ScanComments)
	var items []tokenItem
	for {
		pos, tok, lit := sc.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.SEMICOLON {
			lit = ";"
		}
		line := file.Line(pos)
		end := line
		if tok == token.COMMENT {
			end = file.Line(pos + token.Pos(len(lit)-1))
		}
		items = append(items, tokenItem{tok: tok, lit: lit, line: line, end: end})
	}
	if failed {
		return "", false
	}
	hasher := sha256.New()
	lead := leadGroups(items)
	groupPending, inImportGroup := false, false
	for i, it := range items {
		if it.tok == token.COMMENT {
			if !retainedComment(it.lit) && !cgoPreamble(items, i, inImportGroup) {
				continue
			}
			// A retained comment folds with its ATTACHMENT: whether its
			// comment group is the lead group of the next token — the
			// parser's doc rule, which decides whether a directive
			// documents the declaration that follows or floats free (a
			// blank line, or a block comment closing the group on the
			// declaration's own line, is a program change with an
			// identical token stream).
			attached := 0
			if lead[i] {
				attached = 1
			}
			fmt.Fprintf(hasher, "%s\x00%d\x00%s\n", it.tok, attached, it.lit)
			continue
		}
		switch {
		case it.tok == token.IMPORT:
			// An import declaration begins; a group's parentheses
			// delimit its specs (import groups never nest).
			groupPending = next(items, i).tok == token.LPAREN
		case groupPending && it.tok == token.LPAREN:
			groupPending, inImportGroup = false, true
		case inImportGroup && it.tok == token.RPAREN:
			inImportGroup = false
		}
		fmt.Fprintf(hasher, "%s\x00%s\n", it.tok, it.lit)
	}
	sum := sha256.Sum256(hasher.Sum(nil))
	return digest.FromSum(sum), true
}

// tokenItem is one scanned token: its kind, literal, and the lines it
// starts and ends on.
type tokenItem struct {
	tok       token.Token
	lit       string
	line, end int
}

// leadGroups marks every comment whose group is the lead group of the
// token that follows, by the parser's rule: comments on consecutive
// lines form one group, and a group is the lead (doc) group of the
// next token exactly when it ends on the line before that token —
// a group ending on the token's own line is not.
func leadGroups(items []tokenItem) map[int]bool {
	lead := map[int]bool{}
	for i := 0; i < len(items); i++ {
		if items[i].tok != token.COMMENT {
			continue
		}
		// The group: this comment and every following comment on the
		// line right after the previous one's end.
		j := i
		for j+1 < len(items) && items[j+1].tok == token.COMMENT && items[j+1].line == items[j].end+1 {
			j++
		}
		if n := nextIndex(items, j); n < len(items) && items[n].line == items[j].end+1 {
			for k := i; k <= j; k++ {
				lead[k] = true
			}
		}
		i = j
	}
	return lead
}

// nextIndex returns the index of the first non-comment item after i,
// or len(items).
func nextIndex(items []tokenItem, i int) int {
	for k := i + 1; k < len(items); k++ {
		if items[k].tok != token.COMMENT {
			return k
		}
	}
	return len(items)
}

// next returns the first non-comment item after index i, or the last
// item.
func next(items []tokenItem, i int) tokenItem {
	if k := nextIndex(items, i); k < len(items) {
		return items[k]
	}
	return items[len(items)-1]
}

// cgoPreamble reports whether the comment at index i is C code: a
// comment immediately preceding `import "C"` (comments between it and
// the import included), or preceding the "C" path inside an import
// group.
func cgoPreamble(items []tokenItem, i int, inImportGroup bool) bool {
	k := nextIndex(items, i)
	if k >= len(items) {
		return false
	}
	if items[k].tok == token.IMPORT && k+1 < len(items) && items[k+1].tok == token.STRING && items[k+1].lit == `"C"` {
		return true
	}
	return inImportGroup && items[k].tok == token.STRING && items[k].lit == `"C"`
}

// canonicalFileDigest serves one compiled Go member's canonical digest
// under its byte digest: a byte-equal member costs the read and sum the
// fold already pays, a byte-moved member one parse, memoized per
// package directory like the effect scan (REQ-closure-effect-scan-memo's
// discipline).
func (h *Hasher) canonicalFileDigest(dir, byteDigest string, content []byte) string {
	if h.fileMemo != nil {
		entries, loaded := h.fileMemo.canonical[dir]
		if !loaded {
			entries = map[string]string{}
			cachefile.Load(canonicalDirName, canonicalScope(), dir, &entries)
			h.fileMemo.canonical[dir] = entries
		}
		if canon, ok := entries[byteDigest]; ok {
			return canon
		}
		if canon, ok := h.fileMemo.pendingCanonical[dir][byteDigest]; ok {
			return canon
		}
	}
	if analysisTestHooks.canonicalParse != nil {
		analysisTestHooks.canonicalParse(dir)
	}
	canon, ok := canonicalDigest(content)
	if !ok {
		canon = byteDigest
	}
	if h.fileMemo != nil {
		if h.fileMemo.pendingCanonical[dir] == nil {
			h.fileMemo.pendingCanonical[dir] = map[string]string{}
		}
		h.fileMemo.pendingCanonical[dir][byteDigest] = canon
	}
	return canon
}

// canonicalScope is the memo's scope: the strategy and the toolchain
// identity whose parser and printer produced the form.
func canonicalScope() string {
	return canonicalStrategy + " " + runtime.Version()
}
