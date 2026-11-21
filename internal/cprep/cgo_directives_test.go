package cprep

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func TestCgoNativeFileHasRawString(t *testing.T) {
	allowed := []struct {
		name string
		text string
	}{
		{name: "ordinary_string_ending_in_R", text: `fprintf(stderr, "META_DOLLAR");`},
		{name: "single_char_R_string", text: `#define STR_R "R"`},
		{name: "escaped_backslash_before_R", text: `static const char *names[] = { "\\R", "OR", "XOR" };`},
		{name: "escaped_quotes_around_R_inside_string", text: `const char *msg = "expected \"R\" token";`},
		{name: "block_and_line_comments_with_R_quote", text: "/* See C++11 R\"(...)\" syntax or token \"OR\" */\n// returns \"ERR\" or R\"(x)\" on failure\nint ok = 1;\n"},
		{name: "char_literal_R_and_escaped_quote", text: "char c1 = 'R'; char c2 = '\"'; char c3 = '\\''; const char *s = \"ok\";\n"},
		{name: "macro_name_ending_in_R_before_quote", text: "#define STR_R\"value\"\n"},
		{name: "digit_separator_before_ordinary_string_with_quote_and_R", text: "int n = 1'000'000; int h = 0xFF'FF; const char *s = \"'R\";\n"},
		{name: "prefixed_char_literals", text: "char c1 = u8'\"'; const char *s1 = \"R\";\nchar16_t c2 = u'\"'; const char *s2 = \"R\";\nchar32_t c3 = U'\"'; const char *s3 = \"R\";\nwchar_t c4 = L'\"'; const char *s4 = \"R\";\n"},
		{name: "keyword_before_char_literal", text: "char f(void) { return'\"'; } const char *s = \"R\";\n"},
	}
	for _, tc := range allowed {
		if _, raw := stripCComments(tc.text); raw {
			t.Errorf("%s: stripCComments(%q) raw = true, want false", tc.name, tc.text)
		}
	}

	rawCases := []struct {
		name string
		text string
	}{
		{name: "plain_raw_string", text: `const char *x = R"raw(/*)raw";`},
		{name: "u8R_raw_string", text: `const char *x = u8R"raw(/*)raw";`},
		{name: "uR_raw_string", text: `const char16_t *x = uR"raw(/*)raw";`},
		{name: "UR_raw_string", text: `const char32_t *x = UR"raw(/*)raw";`},
		{name: "LR_raw_string", text: `const wchar_t *x = LR"raw(/*)raw";`},
		{name: "raw_string_after_ordinary_string_on_same_line", text: `const char *a = "META_DOLLAR"; const char *b = R"raw(/*)raw";`},
		{name: "raw_string_after_block_comment", text: `/* comment */ const char *b = R"raw(/*)raw";`},
		{name: "raw_string_after_digit_separator", text: `int n = 1'000; const char *b = R"raw(/*)raw";`},
	}
	for _, tc := range rawCases {
		if _, raw := stripCComments(tc.text); !raw {
			t.Errorf("%s: stripCComments(%q) raw = false, want true", tc.name, tc.text)
		}
	}
}

func TestRawAndEscapedCgoImportPreambleExtraction(t *testing.T) {
	for _, spell := range []struct {
		name string
		imp  string
	}{
		{"raw_single", "import `C`"},
		{"raw_grouped", "import (\n\t`C`\n)"},
		{"hex_escaped", `import "\x43"`},
		{"octal_escaped", `import "\103"`},
	} {
		t.Run(spell.name, func(t *testing.T) {
			src := "package p\n\n// #define CGO_FLAG 1\n// #include \"local.h\"\n" + spell.imp + "\n\nfunc F() int { return 1 }\n"
			if !SourceMayImportC(src) {
				t.Fatalf("SourceMayImportC(%s) = false, want true", spell.name)
			}
			preamble, err := GoCgoPreamble([]byte(src))
			if err != nil {
				t.Fatalf("GoCgoPreamble(%s): %v", spell.name, err)
			}
			if !strings.Contains(preamble, "#define CGO_FLAG 1") || !strings.Contains(preamble, `#include "local.h"`) {
				t.Fatalf("GoCgoPreamble(%s) = %q, missing preamble directives", spell.name, preamble)
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "p.go", src, parser.ParseComments)
			if err != nil {
				t.Fatalf("ParseFile(%s): %v", spell.name, err)
			}
			extracted := strings.Join(ExtractFileCgoPreambles(f), "\n")
			if !strings.Contains(extracted, "#define CGO_FLAG 1") {
				t.Fatalf("ExtractFileCgoPreambles(%s) = %q, missing #define CGO_FLAG 1", spell.name, extracted)
			}
		})
	}
}

func TestGoCompilerDirectiveScanners(t *testing.T) {
	if fields, ok := ParseGoLinknameLineFields("//go:linkname local pkg.Target"); !ok || len(fields) != 3 {
		t.Fatalf("ParseGoLinknameLineFields plain = (%v, %v)", fields, ok)
	}
	if fields, ok := ParseGoLinknameLineFields("//go:linknamestd local"); !ok || len(fields) != 2 {
		t.Fatalf("ParseGoLinknameLineFields std = (%v, %v)", fields, ok)
	}
	if _, ok := ParseGoLinknameLineFields("//go:linknameextra local pkg.Target"); ok {
		t.Fatal("ParseGoLinknameLineFields accepted unbounded prefix")
	}
	if !IsWasmImportComment("//go:wasmimport env host") || !IsWasmImportComment("/*go:wasmimport env host*/") || IsWasmImportComment("// go:wasmimport env host") {
		t.Fatal("IsWasmImportComment mismatch")
	}
}

func referenceParseGoLinkname(text string) (local, target string, matched, valid bool) {
	var body string
	isBlock := false
	switch {
	case strings.HasPrefix(text, "//"):
		body = text[2:]
	case strings.HasPrefix(text, "/*") && strings.HasSuffix(text, "*/") && len(text) >= 4:
		body = text[2 : len(text)-2]
		isBlock = true
	default:
		return "", "", false, false
	}
	if isBlock && strings.Contains(body, "*/") {
		var after string
		switch {
		case strings.HasPrefix(body, "go:linknamestd"):
			after = body[len("go:linknamestd"):]
		case strings.HasPrefix(body, "go:linkname"):
			after = body[len("go:linkname"):]
		default:
			return "", "", false, false
		}
		if after == "" || strings.ContainsRune(" \t\r\n*", rune(after[0])) {
			return "", "", true, false
		}
		return "", "", false, false
	}
	var rest string
	switch {
	case strings.HasPrefix(body, "go:linknamestd"):
		rest = body[len("go:linknamestd"):]
	case strings.HasPrefix(body, "go:linkname"):
		rest = body[len("go:linkname"):]
	default:
		return "", "", false, false
	}
	if rest != "" && rest[0] != ' ' && rest[0] != '\t' && rest[0] != '\r' && rest[0] != '\n' {
		return "", "", false, false
	}
	if strings.ContainsAny(rest, "\r\n\v\f") {
		return "", "", true, false
	}
	fields := strings.FieldsFunc(rest, func(r rune) bool { return r == ' ' || r == '\t' })
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

func TestRapidGoLinknameDirectiveParserOracle(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		opener := rapid.SampledFrom([]string{"//", "/*", "// ", "/* ", "x", ""}).Draw(rt, "opener")
		kw := rapid.SampledFrom([]string{"go:linkname", "go:linknamestd", "go:linknamex", "go:noinline", ""}).Draw(rt, "kw")
		sep := rapid.SampledFrom([]string{"", " ", "\t", "  ", "x", "\n", "*//*"}).Draw(rt, "sep")
		nArgs := rapid.IntRange(0, 3).Draw(rt, "nArgs")
		var args []string
		for range nArgs {
			arg := rapid.SampledFrom([]string{"f", "123bad", "evil*//*", "pkg.Sym", "a/b.Sym", "nodot", "x\ny"}).Draw(rt, "arg")
			args = append(args, arg)
		}
		closer := rapid.SampledFrom([]string{"", "*/", " */"}).Draw(rt, "closer")
		text := opener + kw + sep + strings.Join(args, " ") + closer

		gotLocal, gotTarget, gotMatched, gotValid := ParseGoLinknameDirectiveComment(text)
		wantLocal, wantTarget, wantMatched, wantValid := referenceParseGoLinkname(text)
		if gotMatched != wantMatched || gotValid != wantValid || gotLocal != wantLocal || gotTarget != wantTarget {
			rt.Fatalf("ParseGoLinknameDirectiveComment(%q) = (%q, %q, %v, %v), want (%q, %q, %v, %v)",
				text, gotLocal, gotTarget, gotMatched, gotValid, wantLocal, wantTarget, wantMatched, wantValid)
		}
	})
}

func FuzzParseGoLinknameDirectiveComment(f *testing.F) {
	for _, seed := range []string{
		"",
		"//" + "go:linkname",
		"//" + "go:linkname local",
		"//" + "go:linkname local runtime.nanotime",
		"//" + "go:linknamestd local runtime.nanotime",
		"//" + " go:linkname prose runtime.nanotime",
		"/*" + "go:linkname local runtime.nanotime*/",
		"/*" + "go:linknamestd local runtime.nanotime */",
		"/*" + "go:linkname unclosed runtime.nanotime",
		"/*" + "go:linkname*/",
		"/*" + "go:linkname a b.c d*/",
		"/*" + "go:linkname evil*//* runtime.getAuxv*/",
		"//" + "go:linkname 123bad runtime.getAuxv",
		"//" + "go:linkname local .leadingdot",
		"//" + "go:linkname local trailingdot.",
		"//" + "go:linkname local\nruntime.nanotime",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		l1, r1, m1, v1 := ParseGoLinknameDirectiveComment(text)
		l2, r2, m2, v2 := ParseGoLinknameDirectiveComment(text)
		if l1 != l2 || r1 != r2 || m1 != m2 || v1 != v2 {
			t.Fatalf("non-deterministic parse on %q", text)
		}
		wl, wr, wm, wv := referenceParseGoLinkname(text)
		if l1 != wl || r1 != wr || m1 != wm || v1 != wv {
			t.Fatalf("ParseGoLinknameDirectiveComment(%q) = (%q, %q, %v, %v), want (%q, %q, %v, %v)",
				text, l1, r1, m1, v1, wl, wr, wm, wv)
		}
	})
}
