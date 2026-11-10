package cprep

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeTestFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

//gofresh:pure
func TestCPreprocessorEdgeMatrix(t *testing.T) {
	// 1. Self-recursive and mutually recursive macros terminate without overflowing and preserve symbol extraction.
	defs := map[string][]MacroDef{}
	CollectCPPMacrosFromText(`
#define SELF(x) SELF(x) + x
#define MUT_A MUT_B
#define MUT_B MUT_A + runtime.nanotime
#define PASTE(a, b) a ## . ## b
#define STR(x) #x
#define VAR_STD(p, ...) p(__VA_ARGS__)
#define VAR_NAMED(p, args...) p(args)
#define MULTI runtime.nanotime
#define MULTI other.PureSym
`, defs)

	for _, tc := range []struct {
		name     string
		line     string
		wantSub  string
		overflow bool
	}{
		{"self_recursive", "SELF(targetSym)", "targetSym", false},
		{"mutually_recursive", "MUT_A", "runtime.nanotime", false},
		{"token_pasting", "PASTE(runtime, nanotime)", "runtime.nanotime", false},
		{"stringizing", "STR(  hello   \"world\"  )", `"hello \"world\""`, false},
		{"variadic_std", "VAR_STD(call, a, b, c)", "call(a, b, c)", false},
		{"variadic_named", "VAR_NAMED(call, x, y)", "call(x, y)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			states, primary, overflow := ExpandCPPLineAllChoices(tc.line, defs)
			if overflow != tc.overflow {
				t.Fatalf("ExpandCPPLineAllChoices(%q) overflow = %v, want %v", tc.line, overflow, tc.overflow)
			}
			matched := strings.Contains(primary, tc.wantSub)
			for _, st := range states {
				if strings.Contains(st, tc.wantSub) {
					matched = true
				}
			}
			if !matched {
				t.Fatalf("ExpandCPPLineAllChoices(%q) states=%v primary=%q, missing %q", tc.line, states, primary, tc.wantSub)
			}
		})
	}

	// Multi-definition macro expands all candidate branches.
	multiStates, _, multiOverflow := ExpandCPPLineAllChoices("MULTI", defs)
	if multiOverflow {
		t.Fatal("MULTI expansion unexpectedly overflowed")
	}
	hasRuntime, hasOther := false, false
	for _, st := range multiStates {
		if strings.Contains(st, "runtime.nanotime") {
			hasRuntime = true
		}
		if strings.Contains(st, "other.PureSym") {
			hasOther = true
		}
	}
	if !hasRuntime || !hasOther {
		t.Fatalf("MULTI states = %v, want both runtime.nanotime and other.PureSym", multiStates)
	}

	// 2. Budget overflow fail-closed: state explosion (MaxCPPExpandedStatesPerLine), depth limit (MaxCPPExpansionDepth),
	// and logical line byte limit (MaxNonGoLogicalLineBytes).
	blowupDefs := map[string][]MacroDef{}
	var blowupSrc strings.Builder
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&blowupSrc, "#define B%d 0\n#define B%d 1\n", i, i)
	}
	CollectCPPMacrosFromText(blowupSrc.String(), blowupDefs)
	_, _, stateOverflow := ExpandCPPLineAllChoices("B0 + B1 + B2 + B3 + B4 + B5 + B6 + B7 + B8 + B9", blowupDefs)
	if !stateOverflow {
		t.Fatal("expected state budget overflow on 2^10 multi-def combinations")
	}

	depthDefs := map[string][]MacroDef{}
	var depthSrc strings.Builder
	for i := 0; i < MaxCPPExpansionDepth+5; i++ {
		fmt.Fprintf(&depthSrc, "#define D%d(x) D%d(x)\n", i, i+1)
	}
	fmt.Fprintf(&depthSrc, "#define D%d(x) x\n", MaxCPPExpansionDepth+5)
	CollectCPPMacrosFromText(depthSrc.String(), depthDefs)
	// Nested normal-arg evaluation triggers cur.depth+1 > MaxCPPExpansionDepth.
	nestedCall := "x"
	for i := 0; i < MaxCPPExpansionDepth+3; i++ {
		nestedCall = fmt.Sprintf("D0(%s)", nestedCall)
	}
	_, _, depthOverflow := ExpandCPPLineAllChoices(nestedCall, depthDefs)
	if !depthOverflow {
		t.Fatal("expected depth budget overflow on deeply nested macro calls")
	}

	hugeLine := strings.Repeat("a", MaxNonGoLogicalLineBytes+10)
	if !ScanPreprocessedNonGoSymbolRefs("pkg", nil, []string{hugeLine}, map[string]bool{}, map[string]bool{}, map[string]bool{}) {
		t.Fatal("expected ScanPreprocessedNonGoSymbolRefs to report overflow on huge line")
	}

	// 3. C string literal normalization across prefixes, hex/octal/unicode escapes, and adjacent concatenation.
	norm := NormalizeCStringLiterals(`L"\x72\165\u006e" u8"time." u"\U0000006e" U"anotime"`, true)
	if norm != `"runtime.nanotime"` {
		t.Fatalf("NormalizeCStringLiterals = %q, want %q", norm, `"runtime.nanotime"`)
	}

	// 4. VerifyAssemblyFile forbidden instructions, split middle-dot symbols, macro-qualified symbols, and unapproved #include.
	for _, badAsm := range []struct {
		name    string
		pkgPath string
		file    string
		src     string
		wantErr string
	}{
		{"syscall_inst", "pkg/a", "asm.s", "TEXT ·F(SB), $0\n\tSYSCALL\n\tRET\n", "forbidden instruction SYSCALL"},
		{"rdtsc_inst", "pkg/a", "asm.s", "TEXT ·F(SB), $0\n\tRDTSC\n\tRET\n", "forbidden instruction RDTSC"},
		{"cntvct_inst", "pkg/a", "asm.s", "TEXT ·F(SB), $0\n\tMRS CNTVCT_EL0, R0\n\tRET\n", "forbidden instruction CNTVCT_EL0"},
		{"ta_trap", "pkg/a", "asm.s", "TEXT ·F(SB), $0\n\tTA $0x10\n\tRET\n", "raw trap instruction TA"},
		{"int_trap", "pkg/a", "asm.s", "TEXT ·F(SB), $0\n\tINT $0x80\n\tRET\n", "software interrupt instruction"},
		{"split_middledot", "pkg/a", "asm.s", "TEXT ·F(SB), $0\n\tCALL runtime ·nanotime(SB)\n\tRET\n", "split package-qualified symbol"},
		{"macro_middledot", "pkg/a", "asm.s", "#define PKG runtime\nTEXT ·F(SB), $0\n\tCALL PKG·nanotime(SB)\n\tRET\n", "forbidden package token runtime"},
		{"unapproved_include", "pkg/a", "asm.s", "#include \"secret.h\"\nTEXT ·F(SB), $0\n\tRET\n", "unapproved #include"},
		{"forbidden_path_include", "pkg/a", "asm.s", "#include \"../textflag.h\"\nTEXT ·F(SB), $0\n\tRET\n", "forbidden path in #include"},
		{"header_lowercase_define", "pkg/a", "hdr.h", "#define nanotime 1\n", "shadows lowercase package identifier"},
	} {
		t.Run(badAsm.name, func(t *testing.T) {
			err := VerifyAssemblyFile(badAsm.pkgPath, badAsm.file, badAsm.src, nil)
			if err == nil || !strings.Contains(err.Error(), badAsm.wantErr) {
				t.Fatalf("VerifyAssemblyFile(%s) error = %v, want substring %q", badAsm.name, err, badAsm.wantErr)
			}
		})
	}

	// 5. CgoEscapingIncludeWith fail-closed refusal on raw string, bare macro #include, empty #include <>, and symlink escape.
	root := t.TempDir()
	pkgDir := filepath.Join(root, "pkg")
	outsideDir := filepath.Join(root, "outside")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, outsideDir, "secret.h", "#define X 1\n")
	if err := os.Symlink(outsideDir, filepath.Join(pkgDir, "symdir")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, pkgDir, "sym.c", `#include "symdir/secret.h"`)
	lp := CgoPkgConfig{Dir: pkgDir}
	if esc, err := CgoEscapingIncludeWith(lp, []string{"sym.c"}, os.ReadFile); err != nil || esc == "" {
		t.Fatalf("CgoEscapingIncludeWith(symlink dir) = (%q, %v), want non-empty escaping path", esc, err)
	}

	writeTestFile(t, pkgDir, "macro_inc.c", "#include HEADER_MACRO\n")
	if _, err := CgoEscapingIncludeWith(lp, []string{"macro_inc.c"}, os.ReadFile); err == nil || !strings.Contains(err.Error(), "unresolved cgo include") {
		t.Fatalf("CgoEscapingIncludeWith(bare macro) error = %v, want unresolved cgo include", err)
	}

	writeTestFile(t, pkgDir, "empty_inc.c", "#include <   >\n")
	if _, err := CgoEscapingIncludeWith(lp, []string{"empty_inc.c"}, os.ReadFile); err == nil || !strings.Contains(err.Error(), "empty cgo include directive") {
		t.Fatalf("CgoEscapingIncludeWith(empty <>) error = %v, want empty cgo include directive", err)
	}

	writeTestFile(t, pkgDir, "empty_quoted_inc.c", "#include \"\"\n")
	if _, err := CgoEscapingIncludeWith(lp, []string{"empty_quoted_inc.c"}, os.ReadFile); err == nil || !strings.Contains(err.Error(), "empty cgo include directive") {
		t.Fatalf("CgoEscapingIncludeWith(empty \"\") error = %v, want empty cgo include directive", err)
	}

	// Accessing p.Dir through a symlinked ancestor directory must not falsely report
	// an in-package regular header as escaping, while still catching escaping directory symlinks.
	writeTestFile(t, pkgDir, "local.h", "#define LOCAL_OK 1\n")
	writeTestFile(t, pkgDir, "local.c", `#include "local.h"`)
	symParent := filepath.Join(root, "symparent")
	if err := os.Symlink(pkgDir, symParent); err != nil {
		t.Fatal(err)
	}
	lpSymAncestor := CgoPkgConfig{Dir: symParent}
	if esc, err := CgoEscapingIncludeWith(lpSymAncestor, []string{"local.c"}, os.ReadFile); err != nil || esc != "" {
		t.Fatalf("CgoEscapingIncludeWith(symlinked p.Dir ancestor with local.h) = (%q, %v), want (\"\", nil)", esc, err)
	}
	if esc, err := CgoEscapingIncludeWith(lpSymAncestor, []string{"sym.c"}, os.ReadFile); err != nil || esc == "" {
		t.Fatalf("CgoEscapingIncludeWith(symlinked p.Dir ancestor with escaping dir symlink) = (%q, %v), want non-empty escaping path", esc, err)
	}

	writeTestFile(t, pkgDir, "raw_str.c", "const char *s = R\"raw(/*\n#include \"../outside/secret.h\"\n*/)raw\";\n")
	if _, err := CgoEscapingIncludeWith(lp, []string{"raw_str.c"}, os.ReadFile); err == nil || !strings.Contains(err.Error(), "unsupported cgo raw string") {
		t.Fatalf("CgoEscapingIncludeWith(raw string) error = %v, want unsupported cgo raw string", err)
	}
}

//gofresh:pure
func FuzzCPreprocessor(f *testing.F) {
	f.Add("#define A B\n#define B A\nA\n")
	f.Add("#define P(x, y) x ## y\n#define S(x) #x\nP(run, time.nanotime)\nS(a \"b\" c)\n")
	f.Add("L\"\\x72\\165\\u006e\" \\\n\"time·nanotime\"\n")
	f.Add("/* comment */ #include \"hdr.h\" // line\\\ncontinuation\nTEXT ·F(SB), $0\n\tSYSCALL\n")
	f.Add("const char *s = R\"delim(/* not a comment */)delim\";\n")

	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 4096 {
			return
		}
		_ = NormalizeCStringLiterals(src, true)
		_ = NormalizeCStringLiterals(src, false)
		_ = StripAssemblyComments(src, true, true)
		_ = StripAssemblyComments(src, false, false)
		_, _ = StripCComments(src)
		_ = VerifyAssemblyFile("example.com/pkg", "fuzz.s", src, nil)

		rtOut := map[string]bool{}
		extOut := map[string]bool{}
		idOut := map[string]bool{}
		_ = ScanPreprocessedNonGoSymbolRefs("example.com/pkg", []string{src}, []string{src}, rtOut, extOut, idOut)
	})
}

//gofresh:pure
func TestDirectiveAndTokenPrimitives(t *testing.T) {
	kw, rest, isDir := CutDirectiveKeyword("  #  define FOO(a, b) (a + b)")
	if !isDir || kw != "define" || rest != " FOO(a, b) (a + b)" {
		t.Fatalf("CutDirectiveKeyword = (%q, %q, %v)", kw, rest, isDir)
	}
	if _, _, isDir := CutDirectiveKeyword("MOVQ $1, AX"); isDir {
		t.Fatal("CutDirectiveKeyword accepted non-directive")
	}

	name, def, _, ok := ParseDefineDirective("#define VAR_MACRO(x, args...) CALL x(args)")
	if !ok || name != "VAR_MACRO" || !def.HasParams || !def.Variadic || def.NamedVarParam != "args" || !reflect.DeepEqual(def.Params, []string{"x"}) || def.Body != "CALL x(args)" {
		t.Fatalf("ParseDefineDirective variadic = (%q, %+v, %v)", name, def, ok)
	}
	if _, badDef, _, ok := ParseDefineDirective("#define UNCLOSED(x, y body"); ok || !badDef.HasParams {
		t.Fatalf("ParseDefineDirective unclosed = (%+v, %v), want HasParams=true, ok=false", badDef, ok)
	}

	s := "CALL pkg∕sub· Sym<ABIInternal>(SB)"
	end, hasDot, ok := ScanAsmWordToken(s, 5)
	if !ok || !hasDot || s[5:end] != "pkg∕sub·" {
		t.Fatalf("ScanAsmWordToken = (%d, %v, %v, %q)", end, hasDot, ok, s[5:end])
	}

	blanked := BlankQuotedLiterals(`MOVQ $"hello \"world\" #1", 'x'`)
	if strings.Contains(blanked, "hello") || strings.Contains(blanked, "#1") || strings.Contains(blanked, "x") {
		t.Fatalf("BlankQuotedLiterals(%q) failed to blank literal contents", blanked)
	}
	noQuotes := "MOVQ $1, AX"
	if BlankQuotedLiterals(noQuotes) != noQuotes {
		t.Fatalf("BlankQuotedLiterals mutated quote-free string")
	}

	preamble, err := GoCgoPreamble([]byte("package p\n\n/*#include */ /*\"../cfg.h\"*/\nimport \"C\"\n"))
	if err != nil || !strings.Contains(preamble, `#include "../cfg.h"`) {
		t.Fatalf("GoCgoPreamble(adjacent block comments) = (%q, %v), want #include \"../cfg.h\" on single line", preamble, err)
	}
}
