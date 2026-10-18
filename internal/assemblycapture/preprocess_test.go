//go:build linux && !android

package assemblycapture

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func put(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}
func testInputs(t *testing.T, ctx context.Context, limits Limits) *inputSet {
	t.Helper()
	l, err := limits.normalized()
	if err != nil {
		t.Fatal(err)
	}
	s, err := newInputSet(ctx, &meter{ctx: ctx, limits: l})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.close)
	return s
}
func providerText(p Provider) string {
	var b strings.Builder
	for _, line := range p.Lines {
		b.WriteString(line.Text)
		b.WriteByte('\n')
	}
	return b.String()
}

func TestPreprocessOwnsShadowAndNestedLookup(t *testing.T) {
	root := t.TempDir()
	cwd := filepath.Join(root, "cwd")
	source := filepath.Join(root, "src", "op.s")
	inc := filepath.Join(root, "generated")
	put(t, filepath.Join(cwd, "go_asm.h"), "#define OP SETNE\n")
	put(t, filepath.Join(inc, "go_asm.h"), "#define OP SETEQ\n")
	put(t, filepath.Join(root, "src", "sub", "nested.h"), "#include \"choice.h\"\n")
	put(t, filepath.Join(root, "src", "sub", "choice.h"), "#define NESTED BAD_NESTED_DIRECTORY\n")
	put(t, filepath.Join(root, "src", "choice.h"), "#define NESTED SETEQ\n")
	put(t, source, "#include \"go_asm.h\"\n#include \"sub/nested.h\"\nTEXT ·Swap(SB), 4, $0-25\nOP result+24(FP)\nNESTED AX\nRET\n")
	s := testInputs(t, t.Context(), Limits{})
	p, lookups, err := preprocess(s, Invocation{CWD: cwd, IncludeDirs: []string{inc}}, source)
	if err != nil {
		t.Fatal(err)
	}
	text := providerText(p)
	if !strings.Contains(text, "SETNE result + 24 ( FP )") || !strings.Contains(text, "SETEQ AX") || strings.Contains(text, "BAD_NESTED_DIRECTORY") {
		t.Fatalf("wrong selected expansion:\n%s", text)
	}
	if len(lookups) != 3 || lookups[0].Selected != filepath.Join(cwd, "go_asm.h") || lookups[2].Selected != filepath.Join(root, "src", "choice.h") {
		t.Fatalf("lookup evidence: %+v", lookups)
	}
	if !slices.Contains(lookups[2].Failed, filepath.Join(cwd, "choice.h")) {
		t.Fatal("earlier failed lookup was omitted")
	}
	if err = s.validate(); err != nil {
		t.Fatal(err)
	}
	// Creating and removing an earlier candidate is invisible to a final
	// absence snapshot, but invalidates the protected action-use interval.
	put(t, filepath.Join(cwd, "choice.h"), "#define NESTED SETNE\n")
	if err = os.Remove(filepath.Join(cwd, "choice.h")); err != nil {
		t.Fatal(err)
	}
	if err = s.validate(); err == nil {
		t.Fatal("earlier shadow creation-and-restore was accepted")
	}
}

func TestPreprocessCompleteGrammarAndRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, text, want string
		refuse           bool
	}{
		{"function-macro", "#define R R11\n#define MOVE(x,y) MOVQ x, y\n#define BODY(x) MOVE(x, R); \\\nRET\n#ifdef ENABLED\nBODY($7)\n#else\nBAD\n#endif\n", "MOVQ $ 7 , R11 ;", false},
		{"undef", "#define X SETNE\n#undef X\n#ifndef X\n#define X SETEQ\n#endif\nX AL\n", "SETEQ AL", false},
		{"nested-disabled", "#ifdef ABSENT\n#ifdef ENABLED\nBAD\n#else\nBAD2\n#endif\n#else\nRET\n#endif\n", "RET", false},
		{"recursive", "#define A B\n#define B A\nA\n", "", true},
		{"conditional-expression", "#if 1\nRET\n#endif\n", "", true},
		{"include-macro", "#define NAME \"x.h\"\n#include NAME\n", "", true},
		{"hidden-directive", "#define X #define Y RET\nX\n", "", true},
		{"unclosed", "#ifdef ENABLED\nRET\n", "", true},
		{"duplicate", "#define X 1\n#define X 2\nRET\n", "", true},
		{"function-nesting", "#define A(x) MOVQ x, AX\nA((1+2)*3)\n", "MOVQ ( 1 + 2 ) * 3 , AX", false},
		{"empty-actual", "#define OP SETNE\n#define APPLY(OP) OP AL\nAPPLY()\n", "SETNE AL", false},
		{"bare-function-macro", "#define APPLY(x) x\nAPPLY\n", "", true},
		{"escaped-backslash-keeps-boundary", "#define UNUSED \\\\\nTEXT ·Other(SB),4,$0\nRET\n", "TEXT ·Other", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "a.s")
			put(t, path, tc.text)
			s := testInputs(t, t.Context(), Limits{Depth: 10})
			p, _, err := preprocess(s, Invocation{CWD: dir, Defines: []string{"ENABLED"}}, path)
			if tc.refuse {
				if err == nil {
					t.Fatalf("accepted capable unmodelled syntax: %s", providerText(p))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(providerText(p), tc.want) {
				t.Fatalf("expansion=%q want %q", providerText(p), tc.want)
			}
		})
	}
}

func TestPreprocessRefusesBudgetAndCancellation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.s")
	put(t, path, "#define A MOVQ $1, AX\nA\nA\nA\nRET\n")
	s := testInputs(t, t.Context(), Limits{Tokens: 3})
	if _, _, err := preprocess(s, Invocation{CWD: dir}, path); err == nil {
		t.Fatal("token exhaustion accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	s = testInputs(t, ctx, Limits{})
	if _, _, err := preprocess(s, Invocation{CWD: dir}, path); err != context.Canceled {
		t.Fatalf("cancel=%v", err)
	}
}

func TestResponseFilesOwnGrammarAndInputs(t *testing.T) {
	dir := t.TempDir()
	put(t, filepath.Join(dir, "one.rsp"), "-D 'VALUE=a b' @two.rsp\n")
	put(t, filepath.Join(dir, "two.rsp"), "-I \"some\\ path\" -p example.com/ops -o out.o file.s")
	s := testInputs(t, t.Context(), Limits{})
	got, err := expandArgs(s, dir, []string{"@one.rsp"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-D", "VALUE=a b", "-I", "some\\ path", "-p", "example.com/ops", "-o", "out.o", "file.s"}
	if !slices.Equal(got, want) {
		t.Fatalf("response expansion %q != %q", got, want)
	}
	if len(s.files) != 2 {
		t.Fatal("response-file ownership incomplete")
	}
	put(t, filepath.Join(dir, "one.rsp"), "@one.rsp")
	if err = s.validate(); err == nil {
		t.Fatal("response drift accepted")
	}
	fresh := testInputs(t, t.Context(), Limits{Depth: 4})
	if _, err = expandArgs(fresh, dir, []string{"@one.rsp"}, 0); err == nil {
		t.Fatal("recursive response file accepted")
	}
}
