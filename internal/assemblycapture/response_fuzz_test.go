//go:build linux && !android

package assemblycapture

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/buildflags"
)

func TestResponseEOFAndQuotedCommandGrammar(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  []string
	}{
		{"@inner.rsp\\", []string{"@inner.rsp"}},
		{"-I /owned/include\\", []string{"-I", "/owned/include"}},
		{"\\", nil},
		{"''\\", []string{""}},
		{"'tail\\'", []string{"tail\\"}},
		{"tail\\\r\nnext", []string{"tailnext"}},
	} {
		got, err := responseWords([]byte(tc.input))
		if err != nil || !slices.Equal(got, tc.want) {
			t.Fatalf("response %q = %q/%v, want %q", tc.input, got, err, tc.want)
		}
	}
	for _, words := range [][]string{{"", "two words", "single'quote", "double\"quote", "a'b\"c"}, {"'leading", "\"leading", "back\\slash", "tab\tvalue", "line\nvalue"}, {"/tmp/space 'quote/boundary", "/tmp/space 'quote/socket", "token"}} {
		joined, err := buildflags.Join(words)
		if err != nil {
			t.Fatal(err)
		}
		got, err := buildflags.Fields(joined)
		if err != nil || !slices.Equal(words, got) {
			t.Fatalf("Go command encoding %q => %q/%v", joined, got, err)
		}
	}
	for _, word := range []string{"space 'and\"quotes", "'both\"quotes", "nul\x00word"} {
		if _, err := buildflags.Join([]string{word}); err == nil {
			t.Fatalf("unrepresentable command word %q accepted", word)
		}
	}
}

// encodeResponseWord generates the supported grammar independently of the
// consumer: literal single quotes, escaped double quotes, and unquoted escapes.
// Continuations and an EOF escape are added at expansion boundaries below.
func encodeResponseWord(word string, style uint8) string {
	if style%3 == 0 && !strings.ContainsRune(word, '\'') {
		return "'" + word + "'"
	}
	if style%3 == 1 || strings.ContainsAny(word, "\r\n") {
		var b strings.Builder
		b.WriteByte('"')
		for i := 0; i < len(word); i++ {
			if strings.ContainsRune("\\\"$`", rune(word[i])) {
				b.WriteByte('\\')
			}
			b.WriteByte(word[i])
		}
		b.WriteByte('"')
		return b.String()
	}
	if word == "" {
		return "''"
	}
	var b strings.Builder
	for i := 0; i < len(word); i++ {
		if strings.ContainsRune(" \t\r\n\\'\"", rune(word[i])) {
			b.WriteByte('\\')
		}
		b.WriteByte(word[i])
	}
	return b.String()
}

func FuzzResponseGrammarBoundaries(f *testing.F) {
	f.Add("alpha\x00two words\x00", uint8(0), uint8(1))
	f.Add("quoted'\"\\tail\x00$literal`", uint8(1), uint8(3))
	f.Add("\t\r\n\x00back\\slash", uint8(2), uint8(2))
	f.Add("", uint8(0), uint8(3))
	f.Fuzz(func(t *testing.T, raw string, style, levels uint8) {
		if len(raw) > 256 {
			raw = raw[:256]
		}
		words := strings.Split(raw, "\x00")
		if len(words) > 8 {
			words = words[:8]
		}
		// A leading @ is itself an expansion directive after tokenization.
		// Keep generated leaf words ordinary; nested expansion is generated
		// explicitly, including the alternate literal-backslash file.
		for i, w := range words {
			if strings.HasPrefix(w, "@") {
				words[i] = "value" + w
			}
		}
		encoded := make([]string, len(words))
		for i, w := range words {
			encoded[i] = encodeResponseWord(w, style+uint8(i))
		}
		separator := " \\\n"
		if style&1 != 0 {
			separator = "\t\\\r\n"
		}
		text := strings.Join(encoded, separator) + "\\"
		got, err := responseWords([]byte(text))
		if err != nil || !slices.Equal(got, words) {
			t.Fatalf("grammar %q => %q/%v, want %q", text, got, err, words)
		}
		dir := t.TempDir()
		put(t, filepath.Join(dir, "leaf.rsp"), text)
		previous := "leaf.rsp"
		for i := 0; i < int(levels%3)+1; i++ {
			name := fmt.Sprintf("level%d.rsp", i)
			put(t, filepath.Join(dir, name), "@"+previous+"\\")
			put(t, filepath.Join(dir, previous+"\\"), "UNSELECTED")
			previous = name
		}
		inputs := testInputs(t, t.Context(), Limits{Bytes: 1 << 20, Tokens: 10000, Files: 100, Watches: 256})
		expanded, err := expandArgs(inputs, dir, []string{"@" + previous}, 0)
		if err != nil || !slices.Equal(expanded, words) {
			t.Fatalf("nested grammar => %q/%v, want %q", expanded, err, words)
		}
	})
}
