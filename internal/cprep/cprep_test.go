package cprep

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"pgregory.net/rapid"
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
	collectCPPMacrosFromText(`
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
			states, primary, overflow := expandCPPLineAllChoices(tc.line, defs)
			if overflow != tc.overflow {
				t.Fatalf("expandCPPLineAllChoices(%q) overflow = %v, want %v", tc.line, overflow, tc.overflow)
			}
			matched := strings.Contains(primary, tc.wantSub)
			for _, st := range states {
				if strings.Contains(st, tc.wantSub) {
					matched = true
				}
			}
			if !matched {
				t.Fatalf("expandCPPLineAllChoices(%q) states=%v primary=%q, missing %q", tc.line, states, primary, tc.wantSub)
			}
		})
	}

	// Multi-definition macro expands all candidate branches.
	multiStates, _, multiOverflow := expandCPPLineAllChoices("MULTI", defs)
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
	collectCPPMacrosFromText(blowupSrc.String(), blowupDefs)
	_, _, stateOverflow := expandCPPLineAllChoices("B0 + B1 + B2 + B3 + B4 + B5 + B6 + B7 + B8 + B9", blowupDefs)
	if !stateOverflow {
		t.Fatal("expected state budget overflow on 2^10 multi-def combinations")
	}

	depthDefs := map[string][]MacroDef{}
	var depthSrc strings.Builder
	for i := 0; i < MaxCPPExpansionDepth+5; i++ {
		fmt.Fprintf(&depthSrc, "#define D%d(x) D%d(x)\n", i, i+1)
	}
	fmt.Fprintf(&depthSrc, "#define D%d(x) x\n", MaxCPPExpansionDepth+5)
	collectCPPMacrosFromText(depthSrc.String(), depthDefs)
	// Nested normal-arg evaluation triggers cur.depth+1 > MaxCPPExpansionDepth.
	nestedCall := "x"
	for i := 0; i < MaxCPPExpansionDepth+3; i++ {
		nestedCall = fmt.Sprintf("D0(%s)", nestedCall)
	}
	_, _, depthOverflow := expandCPPLineAllChoices(nestedCall, depthDefs)
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
	f.Add("#undef HDR\n#include \"hdr.h\"\n#ifdef COND\n#undef HDR\n#endif\nCALL HDR(SB)\n")

	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 4096 {
			return
		}
		_ = NormalizeCStringLiterals(src, true)
		_ = NormalizeCStringLiterals(src, false)
		_ = StripAssemblyComments(src, true, true)
		_ = StripAssemblyComments(src, false, false)
		_, _ = stripCComments(src)
		_ = VerifyAssemblyFile("example.com/pkg", "fuzz.s", src, nil)

		rtOut1, extOut1, idOut1 := map[string]bool{}, map[string]bool{}, map[string]bool{}
		ov1 := ScanPreprocessedNonGoSymbolRefs("example.com/pkg", []string{src}, []string{src}, rtOut1, extOut1, idOut1)
		rtOut2, extOut2, idOut2 := map[string]bool{}, map[string]bool{}, map[string]bool{}
		ov2 := ScanPreprocessedNonGoSymbolRefs("example.com/pkg", []string{src}, []string{src}, rtOut2, extOut2, idOut2)
		if ov1 != ov2 || !maps.Equal(rtOut1, rtOut2) || !maps.Equal(extOut1, extOut2) || !maps.Equal(idOut1, idOut2) {
			t.Fatalf("non-deterministic ScanPreprocessedNonGoSymbolRefs: (%v, %v, %v, %v) vs (%v, %v, %v, %v)",
				ov1, rtOut1, extOut1, idOut1, ov2, rtOut2, extOut2, idOut2)
		}
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

	name, def, _, ok := parseDefineDirective("#define VAR_MACRO(x, args...) CALL x(args)")
	if !ok || name != "VAR_MACRO" || !def.HasParams || !def.Variadic || def.NamedVarParam != "args" || !reflect.DeepEqual(def.Params, []string{"x"}) || def.Body != "CALL x(args)" {
		t.Fatalf("parseDefineDirective variadic = (%q, %+v, %v)", name, def, ok)
	}
	if _, badDef, _, ok := parseDefineDirective("#define UNCLOSED(x, y body"); ok || !badDef.HasParams {
		t.Fatalf("parseDefineDirective unclosed = (%+v, %v), want HasParams=true, ok=false", badDef, ok)
	}

	s := "CALL pkg∕sub· Sym<ABIInternal>(SB)"
	end, hasDot, ok := scanAsmWordToken(s, 5)
	if !ok || !hasDot || s[5:end] != "pkg∕sub·" {
		t.Fatalf("scanAsmWordToken = (%d, %v, %v, %q)", end, hasDot, ok, s[5:end])
	}

	blanked := blankQuotedLiterals(`MOVQ $"hello \"world\" #1", 'x'`)
	if strings.Contains(blanked, "hello") || strings.Contains(blanked, "#1") || strings.Contains(blanked, "x") {
		t.Fatalf("blankQuotedLiterals(%q) failed to blank literal contents", blanked)
	}
	noQuotes := "MOVQ $1, AX"
	if blankQuotedLiterals(noQuotes) != noQuotes {
		t.Fatalf("blankQuotedLiterals mutated quote-free string")
	}

	preamble, err := GoCgoPreamble([]byte("package p\n\n/*#include */ /*\"../cfg.h\"*/\nimport \"C\"\n"))
	if err != nil || !strings.Contains(preamble, `#include "../cfg.h"`) {
		t.Fatalf("GoCgoPreamble(adjacent block comments) = (%q, %v), want #include \"../cfg.h\" on single line", preamble, err)
	}
}

//gofresh:pure
func TestSequentialAndConditionalDefineUndefScopingMatrix(t *testing.T) {
	// 12 sequential blocks redefining and #undef'ing 8 register-alias macros on one multi-operand instruction line
	// (12^8 = 429,981,696 combinations if accumulated globally, 1 state per line when scoped sequentially).
	var seqAsm strings.Builder
	seqAsm.WriteString("#include \"textflag.h\"\nTEXT ·Kernel(SB), NOSPLIT, $0\n")
	for round := range 12 {
		for r := range 8 {
			fmt.Fprintf(&seqAsm, "#define X%d V%d\n", r, (round+r)%32)
		}
		seqAsm.WriteString("\tVFA X0, X1, X2, X3, X4, X5, X6, X7\n")
		for r := range 8 {
			fmt.Fprintf(&seqAsm, "#undef X%d\n", r)
		}
	}
	seqAsm.WriteString("\tRET\n")

	for _, tc := range []struct {
		name      string
		hdrs      []string
		texts     []string
		wantRT    []string
		forbidRT  []string
		wantExt   []string
		forbidExt []string
	}{
		{
			name:   "repeated_register_alias_undef_blocks_no_overflow",
			hdrs:   []string{"#define NOSPLIT 4\n"},
			texts:  []string{seqAsm.String()},
			wantRT: nil,
		},
		{
			name: "unconditional_undef_stops_stale_expansion_after_undef",
			texts: []string{
				"#define ALIAS other·ActiveBefore\n\tCALL ALIAS(SB)\n#undef ALIAS\n#define ALIAS ·localHelper\n\tCALL ALIAS(SB)\n#undef ALIAS\n",
			},
			wantExt: []string{"other.ActiveBefore"},
		},
		{
			name: "conditional_undef_preserves_prior_definition",
			texts: []string{
				"#define TARGET runtime·nanotime\n#ifdef UNKNOWN_TAG\n#undef TARGET\n#endif\n\tCALL TARGET(SB)\n",
			},
			wantRT: []string{"runtime.nanotime"},
		},
		{
			name: "conditional_redefine_accumulates_both_choices",
			texts: []string{
				"#define TARGET other·SymA\n#if SOME_EXPR\n#define TARGET runtime·nanotime\n#endif\n\tCALL TARGET(SB)\n",
			},
			wantRT:  []string{"runtime.nanotime"},
			wantExt: []string{"other.SymA"},
		},
		{
			name: "include_after_undef_restores_exported_header_macro",
			hdrs: []string{"#define HDR_SYM runtime·nanotime\n"},
			texts: []string{
				"#undef HDR_SYM\n#include \"hdr.h\"\n\tCALL HDR_SYM(SB)\n",
			},
			wantRT: []string{"runtime.nanotime"},
		},
		{
			name: "include_after_local_override_merges_exported_header_macro",
			hdrs: []string{"#define HDR_SYM runtime·nanotime\n"},
			texts: []string{
				"#define HDR_SYM ·safeLocal\n#include \"hdr.h\"\n\tCALL HDR_SYM(SB)\n",
			},
			wantRT: []string{"runtime.nanotime"},
		},
		{
			name: "chained_header_undef_then_include_propagates",
			hdrs: []string{
				"#undef CHAIN_SYM\n#include \"h1.h\"\n",
				"#define CHAIN_SYM runtime·nanotime\n",
			},
			texts: []string{
				"#undef CHAIN_SYM\n#include \"h2.h\"\n\tCALL CHAIN_SYM(SB)\n",
			},
			wantRT: []string{"runtime.nanotime"},
		},
		{
			name: "header_transient_undef_does_not_leak_unused_macro",
			hdrs: []string{
				"#define TMP_REG other·TransientUnused\n#undef TMP_REG\n#define EXPORTED_SYM other·ExportedUsed\n",
			},
			texts: []string{
				"#include \"hdr.h\"\n\tMOVQ $1, TMP_REG\n\tCALL EXPORTED_SYM(SB)\n",
			},
			wantExt:   []string{"other.ExportedUsed"},
			forbidExt: []string{"other.TransientUnused"},
		},
		{
			name: "stringify_identity_before_later_define_not_clobbered",
			texts: []string{
				"#define STR(x) #x\n#define XSTR(x) STR(x)\nextern void sneak(void) __asm__(XSTR(runtime) \".nanotime\");\n#define runtime safe\n",
			},
			wantRT: []string{"runtime.nanotime"},
		},
		{
			name: "sibling_file_define_does_not_clobber_stringify_identity",
			hdrs: []string{"#define runtime safe\n"},
			texts: []string{
				"#define STR(x) #x\n#define XSTR(x) STR(x)\n#include <stdint.h>\nextern void sneak(void) __asm__(XSTR(runtime) \".nanotime\");\n",
				"#define runtime also_safe\n",
			},
			wantRT: []string{"runtime.nanotime"},
		},
		{
			name: "header_undef_restores_overridden_stringify_identity",
			hdrs: []string{"#undef runtime\n"},
			texts: []string{
				"#define STR(x) #x\n#define XSTR(x) STR(x)\n#define runtime safe\n#include \"hdr.h\"\nextern void sneak(void) __asm__(XSTR(runtime) \".nanotime\");\n",
			},
			wantRT: []string{"runtime.nanotime"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rtOut, extOut, idOut := map[string]bool{}, map[string]bool{}, map[string]bool{}
			if ScanPreprocessedNonGoSymbolRefs("example.com/self", tc.hdrs, tc.texts, rtOut, extOut, idOut) {
				t.Fatalf("ScanPreprocessedNonGoSymbolRefs unexpectedly overflowed")
			}
			for _, sym := range tc.wantRT {
				if !rtOut[sym] {
					t.Fatalf("missing runtime symbol %q in %v", sym, rtOut)
				}
			}
			for _, sym := range tc.forbidRT {
				if rtOut[sym] {
					t.Fatalf("unexpected runtime symbol %q in %v", sym, rtOut)
				}
			}
			for _, sym := range tc.wantExt {
				if !extOut[sym] {
					t.Fatalf("missing external symbol %q in %v", sym, extOut)
				}
			}
			for _, sym := range tc.forbidExt {
				if extOut[sym] {
					t.Fatalf("unexpected external symbol %q in %v", sym, extOut)
				}
			}
		})
	}
}

func TestPropertySequentialAndConditionalMacroSymbolSoundness(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		type opKind int
		const (
			opDefine opKind = iota
			opUndef
			opInclude
			opUse
		)
		type step struct {
			kind  opKind
			cond  int // -1 for unconditional, 0..2 for #ifdef C<cond>
			macro int // 0..2 for M0..M2
			sym   int // 0..3 for ext·S0..ext·S3
		}

		hdrKind := [3]int{} // 0: absent, 1: #define, 2: #undef
		hdrSym := [3]int{}
		var hdrBuf strings.Builder
		for m := range 3 {
			hdrKind[m] = rapid.IntRange(0, 2).Draw(rt, fmt.Sprintf("hdrKind%d", m))
			hdrSym[m] = rapid.IntRange(0, 3).Draw(rt, fmt.Sprintf("hdrSym%d", m))
			switch hdrKind[m] {
			case 1:
				fmt.Fprintf(&hdrBuf, "#define M%d ext·S%d\n", m, hdrSym[m])
			case 2:
				fmt.Fprintf(&hdrBuf, "#undef M%d\n", m)
			}
		}
		siblingText := ""
		if rapid.Bool().Draw(rt, "hasSiblingRedef") {
			siblingText = "#define M0 safe0\n#define M1 safe1\n#define M2 safe2\n"
		}

		nSteps := rapid.IntRange(1, 10).Draw(rt, "nSteps")
		steps := make([]step, nSteps)
		var asmBuf strings.Builder
		asmBuf.WriteString("#define PASTE(a, b) a ## b\n#define XPASTE(a, b) PASTE(a, b)\nTEXT ·Entry(SB), $0\n")
		for i := range nSteps {
			st := step{
				kind:  opKind(rapid.IntRange(0, 3).Draw(rt, fmt.Sprintf("kind%d", i))),
				cond:  rapid.IntRange(-1, 2).Draw(rt, fmt.Sprintf("cond%d", i)),
				macro: rapid.IntRange(0, 2).Draw(rt, fmt.Sprintf("macro%d", i)),
				sym:   rapid.IntRange(0, 3).Draw(rt, fmt.Sprintf("sym%d", i)),
			}
			steps[i] = st
			if st.cond >= 0 {
				fmt.Fprintf(&asmBuf, "#ifdef C%d\n", st.cond)
			}
			switch st.kind {
			case opDefine:
				fmt.Fprintf(&asmBuf, "#define M%d ext·S%d\n", st.macro, st.sym)
			case opUndef:
				fmt.Fprintf(&asmBuf, "#undef M%d\n", st.macro)
			case opInclude:
				asmBuf.WriteString("#include \"hdr.h\"\n")
			case opUse:
				fmt.Fprintf(&asmBuf, "\tCALL M%d(SB)\n\tCALL XPASTE(ext·id_, M%d)(SB)\n", st.macro, st.macro)
			}
			if st.cond >= 0 {
				asmBuf.WriteString("#endif\n")
			}
		}
		asmBuf.WriteString("\tRET\n")

		// Concrete preprocessor oracle: evaluate all 2^3 assignments to C0..C2 where
		// each #include may resolve either to hdr.h or to an unrelated empty header.
		wantExt := map[string]bool{}
		for _, includeHitsHdr := range []bool{false, true} {
			for mask := range 8 {
				env := [3]int{-1, -1, -1}
				for _, st := range steps {
					if st.cond >= 0 && (mask&(1<<st.cond)) == 0 {
						continue
					}
					switch st.kind {
					case opDefine:
						env[st.macro] = st.sym
					case opUndef:
						env[st.macro] = -1
					case opInclude:
						if includeHitsHdr {
							for m := range 3 {
								if hdrKind[m] == 1 {
									env[m] = hdrSym[m]
								} else if hdrKind[m] == 2 {
									env[m] = -1
								}
							}
						}
					case opUse:
						if env[st.macro] >= 0 {
							wantExt[fmt.Sprintf("ext.S%d", env[st.macro])] = true
						} else {
							wantExt[fmt.Sprintf("ext.id_M%d", st.macro)] = true
						}
					}
				}
			}
		}

		texts := []string{asmBuf.String()}
		if siblingText != "" {
			texts = append(texts, siblingText)
		}
		rtOut, extOut, idOut := map[string]bool{}, map[string]bool{}, map[string]bool{}
		overflow := ScanPreprocessedNonGoSymbolRefs("example.com/self", []string{hdrBuf.String()}, texts, rtOut, extOut, idOut)
		if overflow {
			rt.Fatalf("unexpected overflow on bounded program:\n%s", asmBuf.String())
		}
		for sym := range wantExt {
			if !extOut[sym] {
				rt.Fatalf("soundness violation: concrete oracle reached %q, got extOut=%v\nhdr:\n%s\nasm:\n%s",
					sym, extOut, hdrBuf.String(), asmBuf.String())
			}
		}
	})
}
